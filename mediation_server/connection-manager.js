const { Buffer } = require('buffer');
const { NATTypes, MappingBehaviors, MessageTypes, StatusTypes, Config } = require('./constants');

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
            // External port observed when the client probes the SECOND server IPv4 (IP_B) port 1.
            // Compared against externalPortOne (IP_A:p1) to detect ADDRESS-dependent mapping. v4-only.
            externalPortOneB: 0,
            mappingBehavior: null,   // 'EndpointIndependent' | 'AddressDependent' | 'AddressPortDependent'
            // Separate NAT-test port pair + verdict for IPv6, so a dual-stack peer is classified
            // independently per family (v4 and v6 NAT behavior can differ).
            natTypeV6: NATTypes.Unknown,
            externalPortOneV6: 0,
            externalPortTwoV6: 0,
            clientID: Math.random().toString(),
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
            // Remove associated UDP info — prefer localPort (unique per peer, safe when
            // multiple peers share the same public IP behind the same NAT).
            // Only fall back to IP-based removal when localPort is unavailable, and even
            // then only if no other socket shares that IP (to avoid killing a same-NAT peer).
            if (socketInfo.localPort) {
                this.removeUDPInfoByLocalPort(socketInfo.localPort);
            } else {
                this.removeUDPInfo(socketInfo.ip);
            }
            // Clean up by UDP IP only if no other socket shares it
            if (socketInfo.udpIp && socketInfo.udpIp !== socketInfo.ip) {
                const otherSameIp = this.sockets.find(s => s !== socketInfo &&
                    (s.ip === socketInfo.udpIp || s.udpIp === socketInfo.udpIp));
                if (!otherSameIp) {
                    this.removeUDPInfo(socketInfo.udpIp);
                }
            }
            this.sockets.splice(index, 1);
            // Notify listener (network registry cleanup, introduction retries, etc.)
            if (this.onSocketRemoved && socketInfo.socket) {
                try { this.onSocketRemoved(socketInfo.socket); } catch (e) { }
            }
        }
    }

    cleanupPendingConnections(socketInfo) {
        // Find connection pairs involving this EXACT socket and notify the other party.
        // Match by socket reference (not clientID) because multiple per-connection tunnels
        // from the same peer share the same clientID. Matching by clientID would cascade
        // cleanup to unrelated tunnels, sending spurious ConnectionTimeout messages and
        // killing established direct connections.
        const socket = socketInfo.socket;
        Object.entries(this.currentConnectionPairs).forEach(([id, pair]) => {
            if (pair.server_socket === socket || pair.client_socket === socket) {
                // Find the other party's socket
                const otherSocket = pair.server_socket === socket ? pair.client_socket : pair.server_socket;
                const otherSocketInfo = this.sockets.find(s => s.socket === otherSocket);

                if (otherSocketInfo) {
                    try {
                        otherSocketInfo.socket.write(Buffer.from(JSON.stringify({
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
        // Key by localPort when available (unique per peer even behind the same NAT).
        // Fall back to IP-only matching for legacy keepalive messages that don't carry localPort.
        let existing = null;
        if (localPort !== null) {
            existing = this.udpConnectionInfo.find(info => info.localPort === localPort);
        } else {
            // Legacy path: match by IP, but only entries that were also created without
            // an explicit localPort (localPort === port means it was defaulted, not set by NAT test)
            existing = this.udpConnectionInfo.find(info => info.ip === address);
        }

        if (existing) {
            // Update the IP and port to the most recent ones observed
            existing.ip = address;
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

    // Classify the NAT type for one address family and, once both test ports are in, send a
    // NATTypeResponse for that family. isV6 selects which family's response field is used
    // (NATType for v4, NATTypeV6 for v6) and which socket field the verdict is stored in — so a
    // dual-stack peer gets an independent verdict per family, delivered as each family settles.
    checkNATType(socket, localPort, externalPortOne, externalPortTwo, isV6 = false) {
        let natType = NATTypes.Unknown;

        if (externalPortOne !== 0 && externalPortTwo !== 0) {
            if (localPort === externalPortOne && localPort === externalPortTwo) {
                natType = NATTypes.DirectMapping;
            } else if (externalPortOne === externalPortTwo) {
                natType = NATTypes.Restricted;
            } else {
                natType = NATTypes.Symmetric;
            }

            const socketInfo = this.sockets.find(s => s.socket === socket);

            // v4 only: fold in the second-IP MAPPING verdict if the IP_B probe already landed.
            // (v6 has no address translation, so mapping behavior is meaningful for v4 only.)
            let mappingBehavior;
            if (!isV6 && socketInfo) {
                mappingBehavior = this._classifyMapping(externalPortOne, externalPortTwo, socketInfo.externalPortOneB);
                socketInfo.mappingBehavior = mappingBehavior;
            }

            socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.NATTypeResponse,
                // v4 keeps the original NATType field (unchanged wire format); v6 uses NATTypeV6.
                ...(isV6 ? { NATTypeV6: natType } : { NATType: natType }),
                // v2 clients read MappingBehavior; v1 ignores it (additive, v4-only).
                ...(mappingBehavior !== undefined ? { MappingBehavior: mappingBehavior } : {}),
            })));

            // Store NAT type on socket info (per family).
            if (socketInfo) {
                if (isV6) socketInfo.natTypeV6 = natType;
                else socketInfo.natType = natType;
                socketInfo.natTestResponded = true;
            }
        }

        return natType;
    }

    /**
     * Classify MAPPING behavior (RFC 5780) from the three v4 observations:
     *   extA1 = external port at IP_A:p1, extA2 = at IP_A:p2, extB1 = at IP_B:p1.
     * - extA1 != extA2                  → AddressPortDependent (classic symmetric).
     * - extA1 == extA2, extB1 differs   → AddressDependent (the misclassified-as-DirectMapping case).
     * - extA1 == extA2 == extB1         → EndpointIndependent.
     * Returns Unknown until the IP_B probe (extB1) has arrived (0 = not yet), so the client's
     * later re-send with the IP_B result upgrades the verdict.
     */
    _classifyMapping(extA1, extA2, extB1) {
        if (!extA1 || !extA2) return MappingBehaviors.Unknown;
        if (extA1 !== extA2) return MappingBehaviors.AddressPortDependent;
        if (!extB1) return MappingBehaviors.Unknown; // IP_B probe not yet observed
        return extA1 === extB1 ? MappingBehaviors.EndpointIndependent : MappingBehaviors.AddressDependent;
    }

    /**
     * Record the external port observed when the client probed the SECOND server IPv4 (IP_B:p1),
     * then re-run the v4 NAT classification so the MappingBehavior verdict (which needs this value)
     * gets delivered — the IP_B probe often lands after the IP_A ports, so this is what upgrades a
     * provisional "Unknown mapping" into EndpointIndependent vs AddressDependent.
     */
    recordSecondIpMappingPort(clientID, extPort) {
        const socketInfo = this.sockets.find(s => s.clientID === clientID);
        if (!socketInfo) return;
        socketInfo.externalPortOneB = extPort;
        // Re-classify + re-send the v4 verdict now that we have the address-dependence observation.
        if (socketInfo.externalPortOne && socketInfo.externalPortTwo && socketInfo.socket) {
            this.checkNATType(socketInfo.socket, socketInfo.localPort,
                socketInfo.externalPortOne, socketInfo.externalPortTwo, false);
        }
    }

    findSocketByAddress(address) {
        return this.sockets.find(s => s.ip === address);
    }

    updateNATTestPort(clientID, port, isFirstPort = true, isV6 = false) {
        const socket = this.sockets.find(s => s.clientID === clientID);
        if (socket) {
            if (isV6) {
                if (isFirstPort) socket.externalPortOneV6 = port;
                else socket.externalPortTwoV6 = port;
            } else {
                if (isFirstPort) socket.externalPortOne = port;
                else socket.externalPortTwo = port;
            }
        }
        return socket;
    }
}

module.exports = ConnectionManager;