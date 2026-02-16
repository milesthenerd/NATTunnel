const { Buffer } = require('buffer');
const { NATTypes, MessageTypes, StatusTypes, Config } = require('./constants');

class ConnectionManager {
    constructor() {
        this.sockets = [];
        this.udpConnectionInfo = [];
        this.currentConnectionPairs = {};
        this.connectionId = 1;
        // Callback fired when a socket is removed (timeout or explicit).
        // Set by the server to trigger network registry cleanup.
        this.onSocketRemoved = null;
    }

    addSocket(socket, remoteAddress, remotePort, timeout) {
        const socketInfo = {
            socket,
            ip: remoteAddress,
            tcpPort: remotePort,
            timeout,
            natType: NATTypes.Unknown,
            localPort: 0,
            externalPortOne: 0,
            externalPortTwo: 0,
            clientID: Math.random().toString(),
            isServer: false  // Track if this is a registered server
        };
        this.sockets.push(socketInfo);
        return socketInfo;
    }

    removeSocket(socket, clientID = null) {
        let index = -1;
        if (clientID) {
            index = this.sockets.findIndex(s => s.clientID === clientID);
        } else {
            index = this.sockets.findIndex(s => s.socket === socket);
        }

        if (index !== -1) {
            const socketInfo = this.sockets[index];
            // Clean up any pending connections for this client
            this.cleanupPendingConnections(socketInfo);
            // Remove associated UDP info — try by localPort first (reliable even when
            // TCP IP differs from UDP IP, e.g. symmetric NAT or proxy), then by both IPs
            if (socketInfo.localPort) {
                this.removeUDPInfoByLocalPort(socketInfo.localPort);
            }
            this.removeUDPInfo(socketInfo.ip);
            // Also clean up by UDP IP if it differs from TCP IP (symmetric NAT with split IPs)
            if (socketInfo.udpIp && socketInfo.udpIp !== socketInfo.ip) {
                this.removeUDPInfo(socketInfo.udpIp);
            }
            this.sockets.splice(index, 1);
            console.log(`Removed client ${socketInfo.clientID} (${socketInfo.ip}:${socketInfo.tcpPort})`);
            // Notify listener (network registry cleanup, introduction retries, etc.)
            if (this.onSocketRemoved && socketInfo.socket) {
                try { this.onSocketRemoved(socketInfo.socket); } catch (e) { }
            }
        }
    }

    cleanupPendingConnections(socketInfo) {
        // Find any connection pairs involving this socket and notify the other party.
        // Match by clientID (unique per peer) instead of IP address to avoid
        // accidentally cleaning up connections belonging to other peers on the same IP
        // (e.g. reconnects, per-connection tunnels, or multiple peers behind the same NAT).
        const clientID = socketInfo.clientID;
        Object.entries(this.currentConnectionPairs).forEach(([id, pair]) => {
            if (pair.server_clientID === clientID || pair.client_clientID === clientID) {
                // Find the other party in the connection by their clientID
                const otherClientID = pair.server_clientID === clientID ? pair.client_clientID : pair.server_clientID;
                const otherSocket = this.sockets.find(s => s.clientID === otherClientID);

                if (otherSocket) {
                    try {
                        otherSocket.socket.write(Buffer.from(JSON.stringify({
                            ID: MessageTypes.ConnectionTimeout,
                            Message: "Peer disconnected"
                        })));
                    } catch (e) {
                        // Other socket may already be dead
                    }
                }

                // Free up the UDP connection status for both peers
                this.udpConnectionInfo.forEach((info) => {
                    if (pair.server_info === info.ip || pair.client_info === info.ip) {
                        info.status.type = StatusTypes.Free;
                    }
                });

                // Clean up the connection pair
                delete this.currentConnectionPairs[id];
            }
        });
    }

    addUDPInfo(address, port, localPort = null) {
        const existing = this.udpConnectionInfo.find(info => info.ip === address);
        if (existing) {
            // Update the port to the most recent one observed
            existing.port = port;
            if (localPort !== null) existing.localPort = localPort;
        } else {
            this.udpConnectionInfo.push({
                ip: address,
                port,
                localPort: localPort || port,
                status: {
                    id: this.connectionId,
                    type: StatusTypes.Free
                }
            });
        }
    }

    removeUDPInfo(ip) {
        const index = this.udpConnectionInfo.findIndex(info => info.ip === ip);
        if (index !== -1) {
            this.udpConnectionInfo.splice(index, 1);
        }
    }

    removeUDPInfoByLocalPort(localPort) {
        const index = this.udpConnectionInfo.findIndex(info => info.localPort === localPort);
        if (index !== -1) {
            this.udpConnectionInfo.splice(index, 1);
        }
    }

    updateTimeout(socketInfo) {
        // Accept either a socketInfo object directly, or an IP address string for backward compatibility
        let socket = null;
        if (typeof socketInfo === 'string') {
            // Legacy: lookup by IP address
            socket = this.sockets.find(s => s.ip === socketInfo);
        } else {
            // New: socketInfo object passed directly
            socket = socketInfo;
        }

        if (socket) {
            socket.timeout = Config.DEFAULT_TIMEOUT;
        }
    }

    processTimeouts() {
        for (let i = this.sockets.length - 1; i >= 0; i--) {
            const socket = this.sockets[i];
            if (socket.natType !== NATTypes.Unknown) {
                socket.timeout--;
                if (socket.timeout <= 0) {
                    this.removeSocket(socket.socket);
                }
            }
        }
    }

    checkNATType(socket, localPort, externalPortOne, externalPortTwo) {
        let natType = NATTypes.Unknown;

        if (externalPortOne !== 0 && externalPortTwo !== 0) {
            if (localPort === externalPortOne && localPort === externalPortTwo) {
                natType = NATTypes.DirectMapping;
            } else if (externalPortOne === externalPortTwo) {
                natType = NATTypes.Restricted;
            } else {
                natType = NATTypes.Symmetric;
            }

            socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.NATTypeResponse,
                NATType: natType,
            })));

            // Store NAT type on socket info
            const socketInfo = this.sockets.find(s => s.socket === socket);
            if (socketInfo) {
                socketInfo.natType = natType;

                // Check if this socket is for a specific connection (server-side per-client tunnel)
                if (socketInfo.forConnectionID) {
                    const connectionId = socketInfo.forConnectionID;

                    // Trigger callback to send ConnectionBegin to waiting client
                    if (this.onServerTunnelReady) {
                        this.onServerTunnelReady(connectionId, socketInfo, natType);
                    }
                }
            }
        }

        return natType;
    }

    findSocketByAddress(address) {
        return this.sockets.find(s => s.ip === address);
    }

    updateNATTestPort(clientID, port, isFirstPort = true) {
        const socket = this.sockets.find(s => s.clientID === clientID);
        if (socket) {
            if (isFirstPort) {
                socket.externalPortOne = port;
            } else {
                socket.externalPortTwo = port;
            }
            return socket;
        }
        return null;
    }
}

module.exports = ConnectionManager;