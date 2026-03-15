const udp = require('dgram');
const tcp = require('net');
const { Config, MessageTypes } = require('./constants');
const ConnectionManager = require('./connection-manager');
const MessageHandler = require('./message-handler');

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
        this.startTimeoutCheck();
    }

    initializeTCPServer() {
        this.tcpServer = tcp.createServer((socket) => {
            this.handleNewTCPConnection(socket);
        });

        this.tcpServer.on('listening', () => this.logServerInfo('TCP', this.tcpServer));
        this.tcpServer.on('error', (err) => console.error('TCP Server Error:', err));
        this.tcpServer.listen(Config.TCP_PORT, Config.BIND_ADDRESS);
    }

    initializeUDPServer() {
        this.udpServer = this.createUDPSocket('Main UDP');
        this.udpServer.bind(Config.UDP_PORT);
    }

    initializeNATTestServers() {
        this.natTestServer1 = this.createNATTestSocket('NAT Test 1', Config.NAT_TEST_PORT_ONE, true);
        this.natTestServer2 = this.createNATTestSocket('NAT Test 2', Config.NAT_TEST_PORT_TWO, false);

        this.natTestServer1.bind(Config.NAT_TEST_PORT_ONE);
        this.natTestServer2.bind(Config.NAT_TEST_PORT_TWO);
    }

    createUDPSocket(name) {
        const socket = udp.createSocket({ type: 'udp4', reuseAddr: true });

        socket.on('error', (err) => console.error(`${name} Error:`, err));
        socket.on('message', (msg, info) => this.handleUDPMessage(msg, info));
        socket.on('listening', () => this.logServerInfo(name, socket));
        socket.on('close', () => console.log(`${name} socket closed`));

        return socket;
    }

    createNATTestSocket(name, port, isFirstPort) {
        const socket = udp.createSocket({ type: 'udp4', reuseAddr: true });

        socket.on('error', (err) => console.error(`${name} Error:`, err));
        socket.on('message', (msg, info) => this.handleNATTestMessage(msg, info, isFirstPort));
        socket.on('listening', () => console.log(`${name} listening on port ${port}`));
        socket.on('close', () => console.log(`${name} socket closed`));

        return socket;
    }

    handleNewTCPConnection(socket) {
        const clientIP = socket.remoteAddress;

        // Task 4: Check TCP connection rate limit
        if (!this.checkTCPConnectionRateLimit(clientIP)) {
            console.warn(`[RateLimit] TCP connection rejected from ${clientIP} — exceeded rate limit (${this.tcpConnectionRateLimit.maxConnections} connections per ${this.tcpConnectionRateLimit.timeWindowSeconds}s)`);
            try { socket.write(Buffer.from(JSON.stringify({ error: 'Rate limit exceeded' }))); } catch (e) { }
            socket.destroy();
            return;
        }

        console.log(`New connection from ${socket.remoteAddress}:${socket.remotePort}`);

        const socketInfo = this.connectionManager.addSocket(
            socket,
            socket.remoteAddress,
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
        // Try to correlate this UDP keepalive to a specific socket by matching
        // both IP and external port. This is needed so addUDPInfo can use localPort
        // as the dedup key — otherwise same-NAT peers (same IP) would clobber each other.
        const socketInfo = this.connectionManager.sockets.find(
            s => (s.udpIp === info.address || s.ip === info.address) &&
                (s.externalPortOne === info.port || s.externalPortTwo === info.port)
        );
        this.connectionManager.updateTimeout(socketInfo || info.address);
        const localPort = socketInfo ? socketInfo.localPort : null;
        this.connectionManager.addUDPInfo(info.address, info.port, localPort);
    }

    handleNATTestMessage(msg, info, isFirstPort) {
        try {
            const message = JSON.parse(msg);
            if (message.ID === MessageTypes.NATTest) {
                const socket = this.connectionManager.updateNATTestPort(message.ClientID, info.port, isFirstPort);
                if (socket) {
                    // Store the UDP source IP separately so we don't clobber the TCP IP.
                    // Symmetric NAT peers may use different IPs for TCP vs UDP traffic.
                    // socket.ip stays as the TCP IP (used for socket lifecycle management);
                    // socket.udpIp tracks the UDP IP (used for peer endpoint tracking).
                    socket.udpIp = info.address;
                    // If TCP and UDP IPs match, also update socket.ip (handles ::ffff: normalization)
                    if (!socket.ip || socket.ip === '0.0.0.0') {
                        socket.ip = info.address;
                    }

                    // Add UDP info for this peer so connection requests work
                    // Store the external port (as seen by the server) — this is the port
                    // that other peers need to send to. Also store localPort for lookups.
                    // For DirectMapping, external == local. For Restricted NAT, they may differ.
                    console.log(`[Server] Adding UDP info from NAT test: ${info.address}:${info.port} (localPort=${socket.localPort}, tcpIp=${socket.ip})`);
                    this.connectionManager.addUDPInfo(info.address, info.port, socket.localPort);

                    this.connectionManager.checkNATType(
                        socket.socket,
                        socket.localPort,
                        socket.externalPortOne,
                        socket.externalPortTwo
                    );
                }
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