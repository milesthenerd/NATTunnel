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
        this.bindDualStackSocket('NAT Test 1', Config.NAT_TEST_PORT_ONE, (socket) => {
            this.natTestServer1 = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, true));
            socket.on('listening', () => console.log(`NAT Test 1 listening on port ${Config.NAT_TEST_PORT_ONE}`));
        });
        this.bindDualStackSocket('NAT Test 2', Config.NAT_TEST_PORT_TWO, (socket) => {
            this.natTestServer2 = socket;
            socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, false));
            socket.on('listening', () => console.log(`NAT Test 2 listening on port ${Config.NAT_TEST_PORT_TWO}`));
        });
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

    handleNATTestMessage(msg, info, isFirstPort) {
        try {
            const message = JSON.parse(msg);
            if (message.ID === MessageTypes.NATTest) {
                const address = normalizeIP(info.address);
                const packetIsV6 = isIPv6(address);

                const socket = this.connectionManager.sockets.find(s => s.clientID === message.ClientID);
                if (!socket) return;

                // Always record the observed IPv6 endpoint (used as the v6 connect candidate),
                // regardless of which family is primary. Reflects whatever port a v6 firewall or
                // NAT66 assigned — no assumption it's unrewritten.
                if (packetIsV6) {
                    socket.endpointV6 = formatEndpoint(address, info.port);
                    console.log(`[Server] Observed IPv6 endpoint for ${message.ClientID}: ${socket.endpointV6}`);
                }

                // The peer's PRIMARY family is how it reached the mediation server (its TCP
                // connection). NAT-type detection and the primary v4 endpoint are driven only by
                // NAT-test packets of that family; the other family is observation-only (its
                // endpoint is still recorded above for v6). This lets a v6-primary peer get a real
                // NAT type from its v6 probes instead of defaulting to Unknown.
                const primaryIsV6 = isIPv6(socket.ip);
                if (packetIsV6 !== primaryIsV6) {
                    return; // Secondary-family packet — endpoint noted, but doesn't drive NAT type.
                }

                this.connectionManager.updateNATTestPort(message.ClientID, info.port, isFirstPort);

                // Track the UDP source IP separately so we don't clobber the TCP IP.
                // Symmetric NAT peers may use different IPs for TCP vs UDP traffic.
                socket.udpIp = address;
                if (!socket.ip || socket.ip === '0.0.0.0') {
                    socket.ip = address;
                }

                // Add UDP info so connection requests can build this peer's primary endpoint.
                // Store the external port (as seen by the server) — the port other peers send to.
                console.log(`[Server] Adding UDP info from NAT test: ${address}:${info.port} (localPort=${socket.localPort}, tcpIp=${socket.ip})`);
                this.connectionManager.addUDPInfo(address, info.port, socket.localPort);

                this.connectionManager.checkNATType(
                    socket.socket,
                    socket.localPort,
                    socket.externalPortOne,
                    socket.externalPortTwo
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