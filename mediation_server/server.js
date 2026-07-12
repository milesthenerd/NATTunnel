const udp = require('dgram');
const tcp = require('net');
const tls = require('tls');
const http = require('http');
const fs = require('fs');
const { execSync } = require('child_process');
const { Config, MessageTypes } = require('./constants');
const { normalizeIP, formatEndpoint, isIPv6 } = require('./ip-utils');
const ConnectionManager = require('./connection-manager');
const MessageHandler = require('./message-handler');
const selfAddress = require('./self-address');
// Browser-facing NAT test (web-nat-test) is opt-in via Config.NAT_TEST_ENABLED.
// Operators who don't want to bother with coturn + nginx can leave it disabled;
// the mediation server runs perfectly with just its TCP+UDP protocol surface.
const natWebRTC = Config.NAT_TEST_ENABLED ? require('./nat-webrtc') : null;

class NATServer {
    constructor() {
        this.connectionManager = new ConnectionManager();
        this.messageHandler = new MessageHandler(this.connectionManager);

        this.tcpServer = null;
        this.udpServer = null;
        this.natTestServer1 = null;
        this.natTestServer2 = null;

        // Per-IP rate limiting for TCP connections: Map<ip, [timestamp1, timestamp2, ...]>
        this.tcpConnectionTimestamps = new Map();
        this.tcpConnectionRateLimit = {
            maxConnections: 10,      // max 10 connections
            timeWindowSeconds: 60    // in last 60 seconds
        };
    }

    start() {
        // Wire up socket removal callback so timed-out sockets trigger
        // network registry cleanup and introduction retries
        this.connectionManager.onSocketRemoved = (socket) => {
            this.messageHandler.handlePeerDisconnection(socket);
        };

        // Discover our own public v4/v6 addresses via STUN (advertised to clients in NATTestBegin
        // so a peer can NAT-test over the family it didn't use to reach mediation).
        selfAddress.start();

        this.initializeTCPServer();
        this.initializeUDPServer();
        this.initializeNATTestServers();
        if (Config.NAT_TEST_ENABLED) this.initializeHTTPSignalingServer();
        this.startTimeoutCheck();
    }

    initializeHTTPSignalingServer() {
        this.httpSignalingServer = http.createServer((req, res) => {
            if (req.method === 'OPTIONS') return natWebRTC.handleCors(res);

            if (req.method === 'GET' && req.url === '/nat-test/config') {
                return natWebRTC.handleConfig(req, res);
            }

            if (req.method === 'POST' && req.url === '/nat-test/offer') {
                return natWebRTC.handleOffer(req, res);
            }

            // /nat-test/verdict/<sessionId>
            const verdictMatch = req.url && req.url.match(/^\/nat-test\/verdict\/([a-f0-9]+)$/);
            if (req.method === 'GET' && verdictMatch) {
                return natWebRTC.handleVerdict(req, res, verdictMatch[1]);
            }

            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('not found');
        });

        // Localhost-only bind — nginx fronts this with TLS termination.
        this.httpSignalingServer.listen(Config.NAT_TEST_HTTP_PORT, '127.0.0.1', () => {
            console.log(`[NAT-webrtc] HTTP signaling listening on 127.0.0.1:${Config.NAT_TEST_HTTP_PORT}`);
        });
        this.httpSignalingServer.on('error', (err) => {
            console.error('[NAT-webrtc] HTTP signaling server error:', err);
        });
    }

    ensureTLSCert() {
        if (fs.existsSync(Config.TLS_CERT_PATH) && fs.existsSync(Config.TLS_KEY_PATH)) {
            return true; // Already exists
        }
        console.log('[TLS] No certificate found — generating self-signed cert...');
        try {
            execSync(
                `openssl req -x509 -newkey rsa:2048 -keyout "${Config.TLS_KEY_PATH}" -out "${Config.TLS_CERT_PATH}" -days 3650 -nodes -subj "/CN=mediation"`,
                { stdio: 'pipe' }
            );
            console.log(`[TLS] Self-signed cert generated: ${Config.TLS_CERT_PATH}`);
            return true;
        } catch (err) {
            console.warn(`[TLS] openssl not available — falling back to plaintext TCP. (${err.message})`);
            return false;
        }
    }

    initializeTCPServer() {
        const hasCert = this.ensureTLSCert() &&
            fs.existsSync(Config.TLS_CERT_PATH) && fs.existsSync(Config.TLS_KEY_PATH);

        if (hasCert) {
            const tlsOptions = {
                cert: fs.readFileSync(Config.TLS_CERT_PATH),
                key: fs.readFileSync(Config.TLS_KEY_PATH),
            };
            this.tcpServer = tls.createServer(tlsOptions, (socket) => {
                this.handleNewTCPConnection(socket);
            });
            console.log(`[TLS] TLS enabled using cert: ${Config.TLS_CERT_PATH}`);
        } else {
            this.tcpServer = tcp.createServer((socket) => {
                this.handleNewTCPConnection(socket);
            });
            console.log('[TLS] No cert configured — using plaintext TCP');
        }

        this.tcpServer.on('listening', () => this.logServerInfo('TCP', this.tcpServer));
        this.tcpServer.on('error', (err) => {
            // Dual-stack bind ("::") fails on hosts with IPv6 disabled — retry IPv4-only.
            if ((err.code === 'EAFNOSUPPORT' || err.code === 'EADDRNOTAVAIL') && Config.BIND_ADDRESS === '::') {
                console.warn(`TCP: IPv6 bind failed (${err.code}) — falling back to IPv4-only`);
                this.tcpServer.listen(Config.TCP_PORT, '0.0.0.0');
                return;
            }
            console.error('TCP Server Error:', err);
        });
        this.tcpServer.listen(Config.TCP_PORT, Config.BIND_ADDRESS);
    }

    initializeUDPServer() {
        this.bindDualStackSocket('Main UDP', Config.UDP_PORT, (socket) => {
            this.udpServer = socket;
            socket.on('message', (msg, info) => this.handleUDPMessage(msg, info));
            socket.on('listening', () => this.logServerInfo('Main UDP', socket));
        });
    }

    initializeNATTestServers() {
        // Primary (IP_A / default) receivers: dual-stack wildcard, handling v4 primary + all v6.
        // A probe to the SECOND IPv4 lands on the IP_B-bound sockets below instead, so the bind
        // itself discriminates which server IP a client targeted (Node UDP recv gives source only,
        // never destination). natTestServer1/2 stay the primary p1/p2 receivers.
        this.bindDualStackSocket('NAT Test 1', Config.NAT_TEST_PORT_ONE, (socket) => {
            this.natTestServer1 = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, true, 'A'));
            socket.on('listening', () => console.log(`NAT Test 1 listening on port ${Config.NAT_TEST_PORT_ONE}`));
        });
        this.bindDualStackSocket('NAT Test 2', Config.NAT_TEST_PORT_TWO, (socket) => {
            this.natTestServer2 = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, false, 'A'));
            socket.on('listening', () => console.log(`NAT Test 2 listening on port ${Config.NAT_TEST_PORT_TWO}`));
        });

        // The SECOND-IP (IP_B) sockets need the discovered public IPv4 list, which STUN populates
        // asynchronously after start(). Poll until a second IP appears, then bind IP_B:p1 / IP_B:p2
        // (IPv4-only, bound to the specific local IP). If the host only has one public IPv4, these
        // never bind and the server gracefully runs the legacy single-IP test.
        this._bindSecondIpWhenReady();
    }

    /**
     * Bind the IP_B NAT-test sockets once STUN has discovered a second public IPv4. The bind target
     * is the LOCAL IPv4 that maps to the second public IP (we discovered public IPs by binding each
     * local IPv4 in self-address; here we bind the same local IPs so the OS routes correctly). Since
     * we only stored the public list, bind to the local IP whose STUN result is the 2nd public IP —
     * for the common cloud case (public==local, no NAT) that's the public IP itself; behind 1:1 NAT
     * the operator can pin locals via env. We attempt to bind directly to publicIPv4List[1]; if that
     * fails (EADDRNOTAVAIL because the local IP differs), log and skip (legacy single-IP mode).
     */
    _bindSecondIpWhenReady(attempts = 0) {
        const list = selfAddress.publicIPv4List;
        // Wait for BOTH a second IP AND the primary (publicIPv4) to be known — we must choose an IP_B
        // that isn't the primary, so binding before the primary resolves could pick the wrong IP.
        if (!list || list.length < 2 || !selfAddress.publicIPv4) {
            // Not yet / never. Retry a bounded number of times during startup, then give up quietly.
            if (attempts < 30) setTimeout(() => this._bindSecondIpWhenReady(attempts + 1), 2000);
            else console.log('[NAT Test] No second public IPv4 (or primary) discovered — running legacy single-IP NAT test.');
            return;
        }

        // IP_B must be an IP that is NOT the advertised primary (publicIPv4 — the A-record target peers
        // send their primary NAT test to). Picking list[1] blindly is unsafe: the list is built from a
        // STUN race and may put the primary at list[1], which would bind IP_B to the very IP peers hit —
        // capturing their primary test and leaving v4 = Unknown. Explicitly choose the first non-primary
        // entry. (The MappingProbe flag also guards this at the packet level, but binding IP_B off the
        // primary is the clean structural invariant.)
        const primary = selfAddress.publicIPv4;
        const ipB = list.find(ip => ip !== primary);
        if (!ipB) {
            // All entries equal the primary (shouldn't happen — list is deduped) — no distinct 2nd IP.
            console.log('[NAT Test] No public IPv4 distinct from primary — running legacy single-IP NAT test.');
            return;
        }
        this._bindIpBoundNatSocket('NAT Test 1 (IP_B)', ipB, Config.NAT_TEST_PORT_ONE, (socket) => {
            this.natTestServer1B = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, true, 'B'));
        });
        this._bindIpBoundNatSocket('NAT Test 2 (IP_B)', ipB, Config.NAT_TEST_PORT_TWO, (socket) => {
            this.natTestServer2B = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, false, 'B'));
        });
        this.natTestIpB = ipB;
        console.log(`[NAT Test] Second IPv4 ${ipB} — bound IP_B sockets for address-dependent NAT detection.`);
    }

    /** Bind an IPv4-only UDP socket to a specific local IP:port for the second-IP NAT test. */
    _bindIpBoundNatSocket(name, ip, port, setup) {
        const socket = udp.createSocket({ type: 'udp4', reuseAddr: true });
        socket.on('error', (err) => {
            console.warn(`${name}: bind to ${ip}:${port} failed (${err.code}) — this IP won't be used for the 2nd-IP test.`);
            try { socket.close(); } catch (e) {}
        });
        socket.on('listening', () => console.log(`${name} listening on ${ip}:${port}`));
        setup(socket);
        socket.bind(port, ip);
    }

    /**
     * Binds a dual-stack UDP socket (IPv4 + IPv6 on one port). udp6 with ipv6Only:false
     * accepts v4 senders as v4-mapped addresses — message handlers normalize those back
     * to plain IPv4 via normalizeIP. Falls back to udp4 on hosts with IPv6 disabled
     * (bind failures surface as async 'error' events, hence the setup-callback shape:
     * the fallback socket replaces the failed one through the same setup path).
     */
    bindDualStackSocket(name, port, setup) {
        const createAndBind = (type) => {
            const socket = type === 'udp6'
                ? udp.createSocket({ type: 'udp6', ipv6Only: false, reuseAddr: true })
                : udp.createSocket({ type: 'udp4', reuseAddr: true });
            socket.on('error', (err) => {
                if (type === 'udp6' && (err.code === 'EAFNOSUPPORT' || err.code === 'EADDRNOTAVAIL')) {
                    console.warn(`${name}: IPv6 bind failed (${err.code}) — falling back to IPv4-only`);
                    try { socket.close(); } catch (e) { }
                    createAndBind('udp4');
                    return;
                }
                console.error(`${name} Error:`, err);
            });
            socket.on('close', () => console.log(`${name} socket closed`));
            setup(socket);
            socket.bind(port);
        };
        createAndBind('udp6');
    }

    handleNewTCPConnection(socket) {
        const clientIP = normalizeIP(socket.remoteAddress);

        // Task 4: Check TCP connection rate limit
        if (!this.checkTCPConnectionRateLimit(clientIP)) {
            console.warn(`[RateLimit] TCP connection rejected from ${clientIP} — exceeded rate limit (${this.tcpConnectionRateLimit.maxConnections} connections per ${this.tcpConnectionRateLimit.timeWindowSeconds}s)`);
            try { socket.write(Buffer.from(JSON.stringify({ error: 'Rate limit exceeded' }))); } catch (e) { }
            socket.destroy();
            return;
        }

        console.log(`New connection from ${clientIP}:${socket.remotePort}`);

        const socketInfo = this.connectionManager.addSocket(
            socket,
            clientIP,
            socket.remotePort,
            Config.DEFAULT_TIMEOUT
        );

        // Buffer for handling partial/concatenated JSON messages
        socket.dataBuffer = '';

        socket.on('data', (data) => this.handleTCPData(data, socket));

        let socketRemoved = false;
        const removeOnce = () => {
            if (socketRemoved) return;
            socketRemoved = true;
            this.connectionManager.removeSocket(socket, socketInfo.clientID);
        };

        socket.on('close', (hadError) => {
            console.log(`[Server] Socket closed for client ${socketInfo.clientID} (${socketInfo.ip}:${socketInfo.tcpPort}) - hadError: ${hadError}`);
            removeOnce();
        });

        socket.on('error', (err) => {
            console.error(`[Server] Socket error for client ${socketInfo.clientID} (${socketInfo.ip}:${socketInfo.tcpPort}): ${err.code} ${err.message}`);
            removeOnce();
        });

        // Send connected message
        socket.write(Buffer.from(JSON.stringify({ ID: MessageTypes.Connected })));
    }

    checkTCPConnectionRateLimit(clientIP) {
        const now = Date.now();
        const timeWindowMs = this.tcpConnectionRateLimit.timeWindowSeconds * 1000;

        // Initialize timestamp list for this IP if it doesn't exist
        if (!this.tcpConnectionTimestamps.has(clientIP)) {
            this.tcpConnectionTimestamps.set(clientIP, []);
        }

        const timestamps = this.tcpConnectionTimestamps.get(clientIP);

        // Remove timestamps older than the time window
        const recentTimestamps = timestamps.filter(ts => now - ts < timeWindowMs);
        this.tcpConnectionTimestamps.set(clientIP, recentTimestamps);

        // Check if we've exceeded the rate limit
        if (recentTimestamps.length >= this.tcpConnectionRateLimit.maxConnections) {
            return false; // Rate limit exceeded
        }

        // Add current connection timestamp
        recentTimestamps.push(now);
        return true; // Connection allowed
    }

    handleTCPData(data, socket) {
        // Append incoming data to buffer
        socket.dataBuffer += data.toString();

        // Try to parse complete JSON objects separated by newlines or by detecting balanced braces
        let braceCount = 0;
        let startIndex = 0;

        for (let i = 0; i < socket.dataBuffer.length; i++) {
            if (socket.dataBuffer[i] === '{') {
                if (braceCount === 0) {
                    startIndex = i;
                }
                braceCount++;
            } else if (socket.dataBuffer[i] === '}') {
                braceCount--;
                if (braceCount === 0) {
                    // Found a complete JSON object
                    const jsonStr = socket.dataBuffer.substring(startIndex, i + 1);
                    try {
                        const message = JSON.parse(jsonStr);
                        this.messageHandler.handleTCPMessage(message, socket);
                    } catch (e) {
                        console.error('Invalid JSON received:', e);
                        console.error('JSON string was:', jsonStr);
                    }
                    // Remove processed data from buffer
                    socket.dataBuffer = socket.dataBuffer.substring(i + 1);
                    i = -1; // Reset loop to parse next message
                    braceCount = 0;
                }
            }
        }

        // If buffer gets too large without finding complete JSON, clear it to prevent memory issues
        if (socket.dataBuffer.length > 10000) {
            console.error('Buffer overflow, clearing buffer');
            socket.dataBuffer = '';
        }
    }

    handleUDPMessage(msg, info) {
        const address = normalizeIP(info.address);
        // Try to correlate this UDP keepalive to a specific socket by matching
        // both IP and external port. This is needed so addUDPInfo can use localPort
        // as the dedup key — otherwise same-NAT peers (same IP) would clobber each other.
        const socketInfo = this.connectionManager.sockets.find(
            s => (s.udpIp === address || s.ip === address) &&
                (s.externalPortOne === info.port || s.externalPortTwo === info.port)
        );
        this.connectionManager.updateTimeout(socketInfo || address);
        const localPort = socketInfo ? socketInfo.localPort : null;
        this.connectionManager.addUDPInfo(address, info.port, localPort);
    }

    handleNATTestMessage(msg, info, isFirstPort, serverIp = 'A') {
        try {
            const message = JSON.parse(msg);
            if (message.ID === MessageTypes.NATTest) {
                const address = normalizeIP(info.address);
                const packetIsV6 = isIPv6(address);

                const socket = this.connectionManager.sockets.find(s => s.clientID === message.ClientID);
                if (!socket) return;

                // ANY packet arriving on the IP_B socket is a second-IP mapping probe, never a primary
                // NAT test — because IP_B is bound to a public IP that is guaranteed DISTINCT from the
                // advertised primary (see server.js _bindSecondIpWhenReady, which picks the first non-
                // primary IP, and self-address.js which pins the primary to list[0]). So a peer's PRIMARY
                // NAT test can never land here; only the deliberate SendSecondIpMappingProbe does.
                // Record p1 for address-dependent mapping detection and stop — must NOT feed the primary
                // classifier (that's the IP_A wildcard socket's job). This holds for both v2 clients
                // (MappingProbe=true) and legacy v1 clients (no flag; they reuse the shared buffer). The
                // flag is retained only as a defensive cross-check / for logging clarity.
                // (IP_B is IPv4-only by design — both server IPs are v4; v6 has no NAT to map.)
                if (serverIp === 'B') {
                    if (isFirstPort && !packetIsV6) {
                        this.connectionManager.recordSecondIpMappingPort(message.ClientID, info.port);
                    }
                    return;
                }

                // Endpoint model: the peer's v6 endpoint always lives in socket.endpointV6, and its
                // v4 endpoint always lives in udpConnectionInfo (which handleMeshJoinRequest reads to
                // build the primary `endpoint`). This holds regardless of which family the peer used
                // to reach mediation, so a dual-stack peer advertises BOTH families. NAT-type
                // detection is separate — it runs purely off the NAT-test PORTS (externalPortOne/Two
                // vs localPort in checkNATType), never off udpConnectionInfo.
                if (packetIsV6) {
                    // v6 packet → only ever populates the v6 endpoint. Never written into
                    // udpConnectionInfo (that slot is v4-only).
                    socket.endpointV6 = formatEndpoint(address, info.port);
                    console.log(`[Server] Observed IPv6 endpoint for ${message.ClientID}: ${socket.endpointV6}`);
                } else {
                    // v4 packet → populates the v4 endpoint in udpConnectionInfo, whether this peer
                    // is v4-primary or v6-primary-but-dual-stack.
                    socket.udpIp = address;
                    if (!socket.ip || socket.ip === '0.0.0.0') {
                        socket.ip = address;
                    }
                    console.log(`[Server] Adding UDP info from NAT test: ${address}:${info.port} (localPort=${socket.localPort}, tcpIp=${socket.ip})`);
                    this.connectionManager.addUDPInfo(address, info.port, socket.localPort);
                }

                // Classify NAT type PER FAMILY: each family's two test ports drive their own
                // verdict (v4 and v6 NAT behavior can differ). The packet's family selects which
                // port pair it feeds and which NATTypeResponse field the verdict is returned in.
                // A response is sent for each family once both its ports have arrived, so the two
                // verdicts are delivered independently as each family settles.
                this.connectionManager.updateNATTestPort(message.ClientID, info.port, isFirstPort, packetIsV6);
                this.connectionManager.checkNATType(
                    socket.socket,
                    socket.localPort,
                    packetIsV6 ? socket.externalPortOneV6 : socket.externalPortOne,
                    packetIsV6 ? socket.externalPortTwoV6 : socket.externalPortTwo,
                    packetIsV6
                );
            }
        } catch (e) {
            console.error('Invalid NAT test message:', e);
        }
    }

    logServerInfo(name, server) {
        const address = server.address();
        console.log(`${name} server info:`,
            `\n  Port: ${address.port}`,
            `\n  IP: ${address.address}`,
            `\n  Family: ${address.family}`
        );
    }

    startTimeoutCheck() {
        setInterval(() => {
            this.connectionManager.processTimeouts();
        }, 1000);

        // Periodic cleanup every 60 seconds to prevent unbounded memory growth
        setInterval(() => {
            this.cleanupStaleMaps();
        }, 60000);
    }

    cleanupStaleMaps() {
        const now = Date.now();

        // 1. Clean up tcpConnectionTimestamps: remove IPs with no recent connections
        const tcpTimeWindowMs = this.tcpConnectionRateLimit.timeWindowSeconds * 1000;
        for (const [ip, timestamps] of this.tcpConnectionTimestamps.entries()) {
            const recent = timestamps.filter(ts => now - ts < tcpTimeWindowMs);
            if (recent.length === 0) {
                this.tcpConnectionTimestamps.delete(ip);
            } else {
                this.tcpConnectionTimestamps.set(ip, recent);
            }
        }

        // 2. Clean up pendingIntroductions: remove entries older than 60 seconds
        for (const [peerID, pending] of this.messageHandler.pendingIntroductions.entries()) {
            if (!pending.createdAt || (now - pending.createdAt) > 60000) {
                this.messageHandler.pendingIntroductions.delete(peerID);
            }
        }

        // 3. Clean up stale currentConnectionPairs: remove pairs older than 5 minutes
        for (const [id, pair] of Object.entries(this.connectionManager.currentConnectionPairs)) {
            if (pair.connection_start_time && (now - pair.connection_start_time) > 300000) {
                delete this.connectionManager.currentConnectionPairs[id];
            }
        }
    }
}

// Prevent unhandled errors from crashing the server
process.on('uncaughtException', (err) => {
    console.error('[Server] Uncaught exception:', err);
});
process.on('unhandledRejection', (reason) => {
    console.error('[Server] Unhandled rejection:', reason);
});

// Start the server
const server = new NATServer();
server.start();