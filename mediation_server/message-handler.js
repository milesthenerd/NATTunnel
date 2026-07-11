const { MessageTypes, StatusTypes, Config, NATTypes, MediationProtocol } = require('./constants');
const { Buffer } = require('buffer');
const fs = require('fs');
const path = require('path');
const NetworkRegistry = require('./network-registry');
const { normalizeIP, formatEndpoint, sameFamily } = require('./ip-utils');
const selfAddress = require('./self-address');

const SECRETS_FILE = path.join(__dirname, 'network-secrets.json');

class MessageHandler {
    constructor(connectionManager) {
        this.connectionManager = connectionManager;
        this.networkRegistry = new NetworkRegistry();

        // Track pending introductions so we can retry if the introducer disconnects before acking
        // Map of newPeerID -> { newPeerInfo, otherPeers, introducerPeerID, networkID }
        this.pendingIntroductions = new Map();

        // Per-socket message rate limiting: Map<socket, [timestamp1, timestamp2, ...]>
        this.messageTimestamps = new Map();
        this.messageRateLimit = {
            maxMessages: 50,         // max 50 messages
            timeWindowSeconds: 10    // in last 10 seconds
        };
    }

    handleTCPMessage(message, socket) {
        if (!message) return;

        // Task 5: Check message rate limit per socket
        if (!this.checkMessageRateLimit(socket)) {
            console.warn(`[RateLimit] Socket from ${socket.remoteAddress}:${socket.remotePort} closed — exceeded message rate limit (${this.messageRateLimit.maxMessages} messages per ${this.messageRateLimit.timeWindowSeconds}s)`);
            socket.destroy();
            // Clean up the rate limit tracking for this socket
            this.messageTimestamps.delete(socket);
            return;
        }

        switch (message.ID) {
            case MessageTypes.NATTypeRequest:
                this.handleNATTypeRequest(message, socket);
                break;
            case MessageTypes.KeepAlive:
                this.handleKeepAlive(socket);
                break;
            case MessageTypes.ConnectionRequest:
                this.handleConnectionRequest(message, socket);
                break;
            case MessageTypes.ConnectionTimeout:
                this.handleConnectionTimeout(message.ConnectionID);
                break;
            // Mesh networking messages
            case MessageTypes.MeshJoinRequest:
                this.handleMeshJoinRequest(message, socket);
                break;
            case MessageTypes.MeshIntroduceAck:
                this.handleMeshIntroduceAck(message, socket);
                break;
            case MessageTypes.MeshPeerRemoved:
                this.handleMeshPeerRemoved(message, socket);
                break;
            case MessageTypes.MeshIPReassign:
                this.handleMeshIPReassign(message, socket);
                break;
            default:
                console.log(`[MessageHandler] Unknown message type: ${message.ID}`);
                break;
        }
    }

    checkMessageRateLimit(socket) {
        const now = Date.now();
        const timeWindowMs = this.messageRateLimit.timeWindowSeconds * 1000;

        // Initialize timestamp list for this socket if it doesn't exist
        if (!this.messageTimestamps.has(socket)) {
            this.messageTimestamps.set(socket, []);
        }

        const timestamps = this.messageTimestamps.get(socket);

        // Remove timestamps older than the time window
        const recentTimestamps = timestamps.filter(ts => now - ts < timeWindowMs);
        this.messageTimestamps.set(socket, recentTimestamps);

        // Check if we've exceeded the rate limit
        if (recentTimestamps.length >= this.messageRateLimit.maxMessages) {
            return false; // Rate limit exceeded
        }

        // Add current message timestamp
        recentTimestamps.push(now);
        return true; // Message allowed
    }

    handleKeepAlive(socket) {
        // Primary lookup: Use IP:port (most reliable for sockets behind proxies/NAT)
        const remoteIP = normalizeIP(socket.remoteAddress);
        let socketInfo = null;
        if (remoteIP && socket.remotePort) {
            socketInfo = this.connectionManager.sockets.find(s =>
                s.ip === remoteIP && s.tcpPort === socket.remotePort
            );
        }

        // Fallback: Try socket object reference
        if (!socketInfo) {
            socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
            if (socketInfo) {
                // Socket object matched, but IP:port didn't - TCP IP may have changed (proxy/CDN)
                // UDP traffic still comes from original IP, so we don't update UDP info

                // Update the stored TCP IP and port for timeout management
                socketInfo.ip = remoteIP;
                socketInfo.tcpPort = socket.remotePort;
                // Note: localPort stays the same, it's used to find UDP info later
            }
        }

        if (socketInfo) {
            this.connectionManager.updateTimeout(socketInfo);  // Pass socketInfo object directly
        }
    }

    handleNATTypeRequest(message, socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            socketInfo.localPort = message.LocalPort;
            socketInfo.localIP = message.LocalIP || null;  // LAN IP for same-NAT detection

            // Before assigning clientID, remove any OLD socket with the same clientID.
            // On reconnect, the old TCP socket's 'close' event may not have fired yet,
            // leaving a stale entry. If two sockets share the same clientID,
            // updateNATTestPort picks the first (stale) one and the NAT test silently fails.
            //
            // IMPORTANT: Skip this cleanup when the NATTypeRequest has a ConnectionID.
            // Per-connection mesh tunnels share the same clientID as the mesh mode's primary
            // TCP connection. Removing the "stale" socket would destroy the mesh mode's
            // main control connection, breaking keepalive, peer discovery, and introductions.
            if (message.ClientID && !message.ConnectionID) {
                const staleIndex = this.connectionManager.sockets.findIndex(
                    s => s.clientID === message.ClientID && s.socket !== socket
                );
                if (staleIndex !== -1) {
                    const stale = this.connectionManager.sockets[staleIndex];
                    console.log(`[MessageHandler] Removing stale socket for clientID ${message.ClientID} (${stale.ip}:${stale.tcpPort}) — peer reconnected`);
                    // Don't destroy() the stale socket — the peer may still be using it
                    // during the reconnect transition. removeSocket cleans up tracking state;
                    // the socket will close naturally when the OS detects the dead connection.
                    this.connectionManager.removeSocket(stale.socket);
                }
            }

            socketInfo.clientID = message.ClientID;

            // Reset NAT test state so checkNATType waits for fresh results (both families).
            socketInfo.externalPortOne = 0;
            socketInfo.externalPortTwo = 0;
            socketInfo.natType = NATTypes.Unknown;
            socketInfo.externalPortOneV6 = 0;
            socketInfo.externalPortTwoV6 = 0;
            socketInfo.natTypeV6 = NATTypes.Unknown;
        }

        // Check if this is a per-connection tunnel (server-side tunnel for specific client)
        if (message.ConnectionID) {
            // Mark this socket as being for a specific connection
            socketInfo.forConnectionID = message.ConnectionID;

            // Check if this ConnectionID is part of an already-coordinated mesh connection
            const pair = this.connectionManager.currentConnectionPairs[message.ConnectionID];
            if (pair && pair.client_endpoint && pair.server_endpoint) {
                // This is a mesh peer tunnel reconnecting for an already-coordinated connection
                // Skip NAT detection and send ConnectionBegin immediately with the stored info

                // Determine which peer this tunnel belongs to by matching local UDP port
                // The mesh mode and its tunnel share the same UDP client (same local port)
                // Use stored localPort values (not endpoint ports, which may be external/NAT-mapped)
                const clientLocalPort = pair.client_localPort;
                const serverLocalPort = pair.server_localPort;

                let isInitiatingPeer;
                if (message.LocalPort === clientLocalPort) {
                    // This tunnel's port matches the initiating peer's local port
                    isInitiatingPeer = true;
                } else if (message.LocalPort === serverLocalPort) {
                    isInitiatingPeer = false;
                } else {
                    console.log(`[MessageHandler] Warning: Tunnel localPort ${message.LocalPort} doesn't match client ${clientLocalPort} or server ${serverLocalPort}`);
                    // Fallback to IP-based guess
                    isInitiatingPeer = pair.client_info && socketInfo.ip.includes(pair.client_info);
                }

                // Get the REMOTE peer's endpoint from the stored connection pair
                // Initiating peer gets target's endpoint, target peer gets initiating peer's endpoint
                const peerEndpoint = isInitiatingPeer ? pair.server_endpoint : pair.client_endpoint;
                const peerNatType = isInitiatingPeer ? pair.server_natType : pair.client_natType;
                const peerMeshIP = isInitiatingPeer ? pair.server_meshIP : pair.client_meshIP;

                // Get THIS tunnel's own NAT type
                const ownNatType = isInitiatingPeer ? pair.client_natType : pair.server_natType;

                // Send ConnectionBegin immediately (include peer's mesh IP)
                socket.write(Buffer.from(JSON.stringify({
                    ID: MessageTypes.ConnectionBegin,
                    EndpointString: peerEndpoint,
                    NATType: peerNatType,  // Remote peer's NAT type
                    OwnNATType: ownNatType,  // This tunnel's own NAT type
                    ConnectionID: message.ConnectionID,
                    IsServer: false,  // In mesh mode, both are peers
                    PrivateAddressString: peerMeshIP  // Remote peer's mesh IP
                })));

                return; // Skip NAT detection
            }
        }

        // Advertise the server's own public v4/v6 addresses (auto-discovered via STUN) so the
        // client can run the NAT test over the family it did NOT use to reach mediation — needed
        // when the peer connected via a bare IP literal (no A/AAAA record to resolve for the other
        // family). Omitted when a family hasn't been discovered yet; the client then falls back to
        // DNS resolution of its configured hostname, if it has one.
        socket.write(Buffer.from(JSON.stringify({
            ID: MessageTypes.NATTestBegin,
            NATTestPortOne: Config.NAT_TEST_PORT_ONE,
            NATTestPortTwo: Config.NAT_TEST_PORT_TWO,
            ServerPublicIPv4: selfAddress.publicIPv4 || undefined,
            ServerPublicIPv6: selfAddress.publicIPv6 || undefined,
            // All public IPv4s this server has, for the two-IP RFC 5780 mapping test. [0] is the
            // primary (== ServerPublicIPv4); [1], if present, is the SECOND IP a v2 client probes to
            // detect address-dependent NAT mapping. Additive — v1 clients ignore it.
            ServerPublicIPv4List: (selfAddress.publicIPv4List && selfAddress.publicIPv4List.length > 1)
                ? selfAddress.publicIPv4List : undefined
        })));

        // Timeout: if NAT test UDP packets don't arrive within 10s, respond with Unknown
        // This prevents the client from blocking indefinitely on ReadOneTcpMessage()
        socketInfo.natTestResponded = false;
        setTimeout(() => {
            if (socketInfo && !socketInfo.natTestResponded) {
                socketInfo.natTestResponded = true;
                console.warn(`[MessageHandler] NAT test timeout for ${socketInfo.clientID} — responding with Unknown`);
                try {
                    socket.write(Buffer.from(JSON.stringify({
                        ID: MessageTypes.NATTypeResponse,
                        NATType: NATTypes.Unknown,
                    })));
                } catch (e) {
                    // Socket may have closed
                }
            }
        }, 10000);
    }

    handleConnectionRequest(message, socket) {
        // Default NATType to Unknown (-1) if missing (e.g. DirectMapping=0 may be
        // omitted by C# JsonIgnoreCondition.WhenWritingDefault)
        if (!message.hasOwnProperty('NATType')) {
            message.NATType = -1; // Unknown
        }

        const clientSocketInfo = this.connectionManager.sockets.find(s => s.socket === socket);

        // Update timeout for the requesting peer (keeps them alive)
        if (clientSocketInfo) {
            this.connectionManager.updateTimeout(clientSocketInfo);  // Pass socketInfo object directly
        }

        // Store client's NAT type from the ConnectionRequest message
        if (clientSocketInfo && message.NATType !== undefined) {
            clientSocketInfo.natType = message.NATType;
        }

        // Find target peer by PeerID in network registry
        let targetSocket;
        let targetPeer = null;  // Store target peer info for mesh connections
        let clientPeer = null;  // Store client peer info for mesh connections
        if (message.PeerID) {
            // Mesh mode: Find peer by PeerID in network registry
            targetPeer = this.networkRegistry.findPeerByID(message.PeerID);
            if (targetPeer) {
                targetSocket = this.connectionManager.sockets.find(s => s.socket === targetPeer.socket);

                // Fallback: if the registry's socket reference is stale, try finding by clientID
                if (!targetSocket) {
                    targetSocket = this.connectionManager.sockets.find(s => s.clientID === message.PeerID);
                    if (targetSocket && targetPeer) {
                        targetPeer.socket = targetSocket.socket;
                    }
                }

                clientPeer = this.networkRegistry.findPeerBySocket(socket);
            }
        }

        if (!targetSocket) {
            this.sendServerNotAvailable(socket);
            return;
        }

        // Pre-flight peer-protocol overlap check. Skip brokering if the two peers advertise
        // ranges that don't intersect — saves a full hole-punch/handshake round trip only for
        // the pair to refuse each other afterward. Clients still enforce this on receive.
        if (clientPeer && targetPeer &&
            clientPeer.peerMinVersion && clientPeer.peerMaxVersion &&
            targetPeer.peerMinVersion && targetPeer.peerMaxVersion) {
            const lo = Math.max(clientPeer.peerMinVersion, targetPeer.peerMinVersion);
            const hi = Math.min(clientPeer.peerMaxVersion, targetPeer.peerMaxVersion);
            if (hi < lo) {
                console.log(`[MessageHandler] Skipping ConnectionRequest ${clientSocketInfo.clientID} -> ${message.PeerID}: peer-protocol ranges don't overlap (v${clientPeer.peerMinVersion}-v${clientPeer.peerMaxVersion} vs v${targetPeer.peerMinVersion}-v${targetPeer.peerMaxVersion})`);
                return;
            }
        }

        // Deduplicate: if a connection pair already exists between these two peers
        // (in either direction), skip creating a new one. This happens when P_new sends
        // ConnectionRequest for peer X and peer X also TransientReconnects and sends
        // ConnectionRequest for P_new.
        if (message.PeerID && clientSocketInfo.clientID) {
            const existingPair = Object.values(this.connectionManager.currentConnectionPairs).find(pair =>
                (pair.client_clientID === clientSocketInfo.clientID && pair.server_clientID === message.PeerID) ||
                (pair.client_clientID === message.PeerID && pair.server_clientID === clientSocketInfo.clientID)
            );
            if (existingPair) {
                return;
            }
        }

        // Generate connection ID
        const connectionId = this.connectionManager.connectionId++;

        // Get client UDP info
        // First try to find by localPort (most reliable when TCP IP changes due to proxy)
        let clientUDPInfo = null;
        if (clientSocketInfo.localPort) {
            clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
                info => info.localPort === clientSocketInfo.localPort
            );
        }

        // Fallback: try to find by IP (check both TCP IP and UDP IP)
        if (!clientUDPInfo) {
            clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
                info => clientSocketInfo.ip.includes(info.ip) ||
                    (clientSocketInfo.udpIp && clientSocketInfo.udpIp.includes(info.ip))
            );
        }

        // A v6-only peer has no v4 UDP info. Tolerate that as long as it has a v6 endpoint —
        // the pairing logic below connects the two peers over whichever family both share.
        const clientPeerV6 = (clientPeer && clientPeer.endpointV6) || null;
        if (!clientUDPInfo && !clientPeerV6) {
            this.sendServerNotAvailable(socket);
            return;
        }

        // Use external port (info.port) for the endpoint — this is what the remote peer sees.
        // Null when the peer is v6-only (no v4 UDP observation).
        const clientEndpoint = clientUDPInfo ? formatEndpoint(clientUDPInfo.ip, clientUDPInfo.port) : null;

        // Store the connection pair
        // Track both clientID (for notification) and socket reference (for precise cleanup).
        // Multiple per-connection tunnels share the same clientID, so cleanupPendingConnections
        // must match by socket to avoid cascading cleanup to unrelated tunnels.
        this.connectionManager.currentConnectionPairs[connectionId] = {
            server_info: targetSocket.ip,
            client_info: clientSocketInfo.ip,
            server_connected: false,
            client_connected: false,
            server_clientID: targetSocket.clientID,
            client_clientID: clientSocketInfo.clientID,
            server_socket: targetSocket.socket,
            client_socket: socket,
            connection_start_time: Date.now()
        };

        console.log(`New connection ${connectionId}: ${clientSocketInfo.ip} -> ${targetSocket.ip}`);

        // Forward the connection request to target peer's control connection
        const targetMessage = {
            ID: MessageTypes.ConnectionRequest,
            EndpointString: clientEndpoint,
            NATType: message.NATType,  // Initiating peer's NAT type
            ConnectionID: connectionId,
            ClientID: clientSocketInfo.clientID
        };

        targetSocket.socket.write(Buffer.from(JSON.stringify(targetMessage)));

        // For mesh connections (identified by PeerID), send ConnectionBegin immediately
        // Both peers already have UDP info from mesh join - no need to wait for server tunnel
        if (message.PeerID) {

            // Get target's UDP info
            // First try by localPort (most reliable when TCP and UDP IPs differ due to proxy/CDN)
            let targetUDPInfo = null;
            if (targetSocket.localPort) {
                targetUDPInfo = this.connectionManager.udpConnectionInfo.find(
                    info => info.localPort === targetSocket.localPort
                );
            }
            // Fallback: try by IP (check both TCP IP and UDP IP)
            if (!targetUDPInfo) {
                targetUDPInfo = this.connectionManager.udpConnectionInfo.find(
                    info => targetSocket.ip.includes(info.ip) ||
                        (targetSocket.udpIp && targetSocket.udpIp.includes(info.ip))
                );
            }

            // A v6-only target has no v4 UDP info — tolerate it when it has a v6 endpoint.
            const targetV6 = (targetPeer && targetPeer.endpointV6) || null;
            if (!targetUDPInfo && !targetV6) {
                this.sendServerNotAvailable(socket);
                return;
            }

            // Use external port (info.port) for the endpoint — null when the target is v6-only.
            const targetEndpoint = targetUDPInfo ? formatEndpoint(targetUDPInfo.ip, targetUDPInfo.port) : null;

            // Prefer IPv6 when BOTH peers advertised a usable v6 endpoint: no NAT to traverse,
            // so a direct connection lands more reliably. Each side is handed the other's v6
            // endpoint. Falls through to the v4 path (including same-NAT LAN substitution) when
            // either peer lacks v6.
            const clientV6 = clientPeerV6;
            const useV6 = clientV6 && targetV6;

            let endpointForClient;
            let endpointForTarget;
            if (useV6) {
                endpointForClient = targetV6;
                endpointForTarget = clientV6;
                console.log(`[MessageHandler] Both peers have IPv6 — using v6 endpoints: ${clientV6} <-> ${targetV6}`);
            } else {
                // Detect same-NAT peers: if both share the same public IP, use LAN endpoints
                // so they connect directly over the local network (NAT hairpinning is unreliable).
                // Only substitute the LAN endpoint for a peer when the *other* peer is also on the
                // same NAT — an external peer must never receive a LAN endpoint it can't reach.
                // Requires v4 UDP info on both sides (a v6-only peer has none).
                const sameNAT = clientUDPInfo && targetUDPInfo &&
                    normalizeIP(clientUDPInfo.ip) === normalizeIP(targetUDPInfo.ip);
                const clientLANEndpoint = (sameNAT && clientSocketInfo.localIP)
                    ? formatEndpoint(clientSocketInfo.localIP, clientSocketInfo.localPort) : null;
                const targetLANEndpoint = (sameNAT && targetSocket.localIP)
                    ? formatEndpoint(targetSocket.localIP, targetSocket.localPort) : null;

                if (sameNAT && clientLANEndpoint && targetLANEndpoint) {
                    console.log(`[MessageHandler] Same-NAT detected! Using LAN endpoints: ${clientLANEndpoint} <-> ${targetLANEndpoint}`);
                }

                // Each peer gets: if the remote peer is on the same NAT and has a LAN IP, use it;
                // otherwise use the remote peer's external endpoint.
                endpointForClient = targetLANEndpoint || targetEndpoint;
                endpointForTarget = clientLANEndpoint || clientEndpoint;
            }

            // The two chosen endpoints must be the same address family — a v4 peer can't reach a
            // v6 endpoint or vice versa. Catches a v4-only peer paired with a v6-only peer, and a
            // mismatch where each has an endpoint but of different families. Relay can't bridge
            // families, so there's nothing to do.
            if (!sameFamily(endpointForClient, endpointForTarget)) {
                console.log(`[MessageHandler] Cannot connect ${clientSocketInfo.clientID} <-> ${message.PeerID} — no shared address family (v4/v6 mismatch)`);
                this.sendServerNotAvailable(socket);
                return;
            }

            // Get NAT types
            const clientNatType = message.NATType !== undefined ? message.NATType : -1;
            const targetNatType = targetSocket.natType !== undefined ? targetSocket.natType : -1;

            // ExternalEndpointString carries the endpoint the receiver can forward to peers
            // outside this LAN. Each peer is told the OTHER peer's external endpoint. When we
            // paired over v6, that's the v6 endpoint (no NAT-external distinction on v6);
            // otherwise the v4 external. May be null for a v6-only peer paired over v6.
            const targetExternalForClient = useV6 ? targetV6 : targetEndpoint;
            const clientExternalForTarget = useV6 ? clientV6 : clientEndpoint;

            // Send ConnectionBegin to initiating peer.
            // ExternalEndpointString always carries the external endpoint so the receiver
            // can cache something safe to forward to non-same-NAT peers later (e.g. when
            // acting as introducer). EndpointString may be a LAN endpoint when same-NAT.
            const clientMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: endpointForClient,
                ExternalEndpointString: targetExternalForClient,
                // Always carry the OTHER peer's v6 endpoint, independent of which family THIS
                // connection uses. A v4-connected receiver (e.g. a v4-only introducer bridging two
                // dual-stack peers) must still learn the peers' v6 endpoints so it can later
                // introduce/repair them over v6 — otherwise it only knows v4 and can't bridge a
                // pair that needs v6.
                EndpointV6String: targetV6 || undefined,
                NATType: targetNatType,
                OwnNATType: clientNatType,  // Initiating peer's own NAT type
                ConnectionID: connectionId,
                IsServer: false,
                PrivateAddressString: targetPeer ? targetPeer.meshIP : null,  // Peer's mesh IP
                PeerID: targetSocket.clientID,  // Target peer's ID so client can track pending requests
                PeerMinVersion: targetPeer ? targetPeer.peerMinVersion : undefined,
                PeerMaxVersion: targetPeer ? targetPeer.peerMaxVersion : undefined,
                IdentityPublicKey: targetPeer ? targetPeer.identityPublicKey : undefined
            };

            socket.write(Buffer.from(JSON.stringify(clientMessage)));

            // Send ConnectionBegin to target peer
            const serverMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: endpointForTarget,
                ExternalEndpointString: clientExternalForTarget,
                // Always carry the other peer's v6 endpoint (see clientMessage above).
                EndpointV6String: clientV6 || undefined,
                NATType: clientNatType,
                OwnNATType: targetNatType,  // Target peer's own NAT type
                ConnectionID: connectionId,
                IsServer: false,  // In mesh mode, both are peers (not server/client)
                PrivateAddressString: clientPeer ? clientPeer.meshIP : null,  // Initiating peer's mesh IP
                PeerID: clientSocketInfo.clientID,  // Initiating peer's ID so target can track pending requests
                PeerMinVersion: clientPeer ? clientPeer.peerMinVersion : undefined,
                PeerMaxVersion: clientPeer ? clientPeer.peerMaxVersion : undefined,
                IdentityPublicKey: clientPeer ? clientPeer.identityPublicKey : undefined
            };

            targetSocket.socket.write(Buffer.from(JSON.stringify(serverMessage)));

            // Store endpoint info for mesh peer tunnels that will connect later. Records the
            // family actually used to pair (v6 when both had it), falling back to the v4 external.
            this.connectionManager.currentConnectionPairs[connectionId].client_endpoint = clientExternalForTarget;
            this.connectionManager.currentConnectionPairs[connectionId].server_endpoint = targetExternalForClient;
            this.connectionManager.currentConnectionPairs[connectionId].client_localPort = clientSocketInfo.localPort;
            this.connectionManager.currentConnectionPairs[connectionId].server_localPort = targetSocket.localPort;
            this.connectionManager.currentConnectionPairs[connectionId].client_natType = clientNatType;
            this.connectionManager.currentConnectionPairs[connectionId].server_natType = targetNatType;
            this.connectionManager.currentConnectionPairs[connectionId].client_meshIP = clientPeer ? clientPeer.meshIP : null;
            this.connectionManager.currentConnectionPairs[connectionId].server_meshIP = targetPeer ? targetPeer.meshIP : null;

            // Mark connection as complete immediately for mesh connections
            this.connectionManager.currentConnectionPairs[connectionId].server_connected = true;
            this.connectionManager.currentConnectionPairs[connectionId].client_connected = true;
        }
    }

    handleConnectionTimeout(connectionId) {
        const pair = this.connectionManager.currentConnectionPairs[connectionId];
        if (!pair) {
            console.log(`ConnectionTimeout for unknown connection ID: ${connectionId}`);
            return;
        }

        console.log(`Connection ${connectionId} timed out`);

        // Reset connection status for both server and client IPs
        this.connectionManager.udpConnectionInfo.forEach((info, index) => {
            if (pair.server_info.includes(info.ip) || pair.client_info.includes(info.ip)) {
                info.status.type = StatusTypes.Free;
            }
        });

        // Clean up the connection pair
        delete this.connectionManager.currentConnectionPairs[connectionId];
    }

    sendServerNotAvailable(socket) {
        socket.write(Buffer.from(JSON.stringify({
            ID: MessageTypes.ServerNotAvailable
        })));
    }

    /**
     * Handles peer disconnection - removes from network registry
     */
    handlePeerDisconnection(socket) {
        const peer = this.networkRegistry.findPeerBySocket(socket);
        if (peer) {
            // Retry any pending introductions this peer was responsible for
            this.retryPendingIntroduction(peer.peerID);
            this.networkRegistry.leaveNetwork(peer.peerID);
        }

        // Clean up rate limit tracking for this socket
        this.messageTimestamps.delete(socket);
    }

    /**
     * Handles mesh network join requests
     * Peer wants to join a mesh network and discover other peers
     */
    handleMeshJoinRequest(message, socket) {
        const { NetworkID, PeerID, NATType, PrivateAddressString } = message;
        // Peer-to-peer protocol range this client supports. Grandfathered to v1
        const peerMinVersion = message.PeerMinVersion || 1;
        const peerMaxVersion = message.PeerMaxVersion || 1;
        // Stable identity public key (base64 32-byte Curve25519). Null for pre-block clients;
        // block enforcement is opt-in, so null just means their fingerprint can't be advertised.
        const identityPublicKey = message.IdentityPublicKey || null;

        if (!NetworkID) {
            console.log('[MessageHandler] MeshJoinRequest missing NetworkID');
            return;
        }

        if (!PeerID) {
            console.log('[MessageHandler] MeshJoinRequest missing PeerID');
            return;
        }

        // Protocol version check. Grandfather clients that pre-date versioning as v1.
        const clientVersion = message.ProtocolVersion || 1;
        const min = MediationProtocol.MinSupportedClientVersion;
        const max = MediationProtocol.MaxSupportedClientVersion;
        if (clientVersion < min || clientVersion > max) {
            const response = {
                ID: MessageTypes.MeshJoinResponse,
                NetworkID, PeerCount: 0, Peers: [],
                VersionError: `Client protocol version ${clientVersion} is outside supported range [${min}, ${max}]. Please update NATTunnel.`
            };
            socket.write(Buffer.from(JSON.stringify(response)));
            console.log(`[MessageHandler] Version rejected for peer ${PeerID}: client v${clientVersion} outside [${min},${max}]`);
            return;
        }

        // Authenticate: compare AuthToken hash against stored hash (or store on first join)
        const { AuthToken } = message;
        if (!AuthToken) {
            const response = {
                ID: MessageTypes.MeshJoinResponse,
                NetworkID, PeerCount: 0, Peers: [],
                AuthToken: 'Authentication required'
            };
            socket.write(Buffer.from(JSON.stringify(response)));
            console.log(`[MessageHandler] Auth failed for peer ${PeerID} on network ${NetworkID}: no token`);
            return;
        }

        // Load stored hashes from file
        let storedHashes = {};
        try {
            storedHashes = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
        } catch (e) {
            // File missing or corrupt — start fresh
        }

        if (storedHashes[NetworkID]) {
            // Network exists — validate the token
            if (AuthToken !== storedHashes[NetworkID]) {
                const response = {
                    ID: MessageTypes.MeshJoinResponse,
                    NetworkID, PeerCount: 0, Peers: [],
                    AuthToken: 'Invalid network secret'
                };
                socket.write(Buffer.from(JSON.stringify(response)));
                console.log(`[MessageHandler] Auth failed for peer ${PeerID} on network ${NetworkID}`);
                return;
            }
        } else {
            // First peer for this network — store the hash
            storedHashes[NetworkID] = AuthToken;
            try {
                fs.writeFileSync(SECRETS_FILE, JSON.stringify(storedHashes, null, 2));
                console.log(`[MessageHandler] Registered new network ${NetworkID}`);
            } catch (e) {
                console.error(`[MessageHandler] Failed to save network secret: ${e.message}`);
            }
        }

        // Get peer's endpoint from socket info
        // Try multiple lookup methods (prioritizing IP:port as most reliable):
        // 1. By remote address (IP:port) - PRIMARY
        // 2. By PeerID (clientID) - SECONDARY
        // 3. By socket object reference - FALLBACK
        let socketInfo = null;

        // Primary: Lookup by IP:port
        if (socket.remoteAddress && socket.remotePort) {
            const remoteAddr = normalizeIP(socket.remoteAddress);
            const remotePort = socket.remotePort;
            socketInfo = this.connectionManager.sockets.find(s => s.ip === remoteAddr && s.tcpPort === remotePort);
        }

        // Secondary: Lookup by clientID
        if (!socketInfo && PeerID) {
            socketInfo = this.connectionManager.sockets.find(s => s.clientID === PeerID);
        }

        // Fallback: Lookup by socket object reference
        if (!socketInfo) {
            socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
            if (socketInfo) {
                const remoteAddr = normalizeIP(socket.remoteAddress);
                if (socketInfo.ip !== remoteAddr || socketInfo.tcpPort !== socket.remotePort) {
                    socketInfo.ip = remoteAddr;
                    socketInfo.tcpPort = socket.remotePort;
                }
            }
        }

        if (!socketInfo) {
            console.log(`[MessageHandler] Socket info not found for mesh join (PeerID: ${PeerID})`);
            return;
        }

        // Update the socket's clientID to match the peer's actual GUID
        // This ensures future lookups by PeerID will work
        socketInfo.clientID = PeerID;

        // Clean up any stale sockets with the same PeerID (peer reconnected before old socket timed out).
        // Without this, the old socket stays in connectionManager.sockets and findPeerBySocket/findPeerByID
        // may return the stale entry, causing introductions to be sent to a dead socket.
        for (let i = this.connectionManager.sockets.length - 1; i >= 0; i--) {
            const s = this.connectionManager.sockets[i];
            if (s.clientID === PeerID && s.socket !== socket) {
                console.log(`[MessageHandler] Cleaning up stale socket for ${PeerID} during mesh join`);
                this.connectionManager.removeSocket(s.socket);
            }
        }

        // Update timeout for mesh peer to keep them alive
        // Mesh peers stay connected to receive peer updates and connection coordination
        this.connectionManager.updateTimeout(socketInfo);  // Pass socketInfo object directly

        // Build the peer's IPv4 endpoint from its v4 UDP NAT-test info. udpInfo presence is the
        // "peer is v4-reachable" signal: the v6 NAT test uses a separate path that never calls
        // addUDPInfo, so a v6-only peer has no udpInfo here. In that case the v4 endpoint is left
        // null — the peer is reachable only via socketInfo.endpointV6, and coordinators pair peers
        // on whichever family both share.
        let udpInfo = null;
        if (socketInfo.localPort) {
            udpInfo = this.connectionManager.udpConnectionInfo.find(
                info => info.localPort === socketInfo.localPort
            );
        }
        if (!udpInfo) {
            const peerIP = normalizeIP(socketInfo.udpIp || socketInfo.ip);
            udpInfo = this.connectionManager.udpConnectionInfo.find(
                info => peerIP === info.ip || (socketInfo.ip && socketInfo.ip.includes(info.ip)) ||
                    (socketInfo.udpIp && socketInfo.udpIp.includes(info.ip))
            );
        }
        // Only a genuine v4 UDP observation yields a v4 endpoint. Don't fall back to the TCP IP:
        // that produced a plausible-looking endpoint with the wrong (TCP) port for v6-only peers.
        const endpoint = udpInfo ? formatEndpoint(udpInfo.ip, udpInfo.port) : null;

        const { NATTypes } = require('./constants');

        try {
            // Join the network and get list of other peers
            const otherPeers = this.networkRegistry.joinNetwork(
                NetworkID,
                PeerID,
                socket,
                endpoint,
                NATType,
                PrivateAddressString,  // Mesh IP address
                socketInfo.localIP,    // LAN IP for same-NAT detection
                socketInfo.localPort,  // Local UDP port
                peerMinVersion,        // Peer-to-peer protocol range advertised by this client
                peerMaxVersion,
                identityPublicKey,     // Base64 X25519 identity pubkey for block fingerprinting
                socketInfo.endpointV6  // Publicly-observed IPv6 endpoint, or null if no v6 route
            );

            console.log(`[MessageHandler] Peer ${PeerID} joined network ${NetworkID} (${otherPeers.length} active peers)`);

            // Also check meshMembers for peers that disconnected from mediation
            // but may still be reachable via an introducer's WireGuard tunnel
            const meshMembers = this.networkRegistry.getMeshMembers(NetworkID, PeerID);

            if (otherPeers.length === 0 && meshMembers.length === 0) {
                // Truly first peer in the network — no introducer needed
                const response = {
                    ID: MessageTypes.MeshJoinResponse,
                    NetworkID: NetworkID,
                    PeerCount: 0,
                    Peers: []
                };
                socket.write(Buffer.from(JSON.stringify(response)));
                return;
            }

            // Select an introducer from ALL known peers (active + mesh members).
            // ONLY non-symmetric NAT peers can be introducers.
            // Also verify the peer's TCP socket is still alive in connectionManager.
            // Use meshMembers as the candidate pool since it includes peers that may have
            // disconnected from the network registry but still have active TCP sockets.
            const allCandidates = meshMembers.length > otherPeers.length ? meshMembers : otherPeers;

            const isEligible = (p) => {
                if (!p) return false;
                if (p.natType === NATTypes.Symmetric) return false;
                const sockInfo = this.connectionManager.sockets.find(s => s.clientID === p.peerID);
                if (!sockInfo) return false;
                // Introducer must share a peer-protocol range with the joiner. Without overlap,
                // they can never form a WireGuard tunnel to the joiner, so they can't relay
                // MeshConnectionBegin — picking them just churns the introducer role.
                if (p.peerMinVersion && p.peerMaxVersion && peerMinVersion && peerMaxVersion) {
                    const lo = Math.max(p.peerMinVersion, peerMinVersion);
                    const hi = Math.min(p.peerMaxVersion, peerMaxVersion);
                    if (hi < lo) return false;
                }
                // Introducer must share a reachable ADDRESS FAMILY with the joiner — it needs its
                // own tunnel to the joiner to relay introductions. A candidate with NO family in
                // common (e.g. v4-only candidate + v6-only joiner) can never tunnel to the joiner
                // and would defer forever. A dual-stack pair shares v4, so this stays permissive.
                const sharesV4 = !!p.endpoint && !!endpoint;
                const sharesV6 = !!p.endpointV6 && !!socketInfo.endpointV6;
                if (!sharesV4 && !sharesV6) return false;
                // Re-register them in the active network if they fell out
                // (e.g., network was deleted when it emptied, but socket is still alive)
                const activeNetwork = this.networkRegistry.networks.get(NetworkID);
                if (activeNetwork && !activeNetwork.has(p.peerID)) {
                    activeNetwork.set(p.peerID, {
                        peerID: p.peerID,
                        socket: sockInfo.socket,
                        endpoint: p.endpoint,
                        natType: p.natType,
                        meshIP: p.meshIP,
                        peerMinVersion: p.peerMinVersion,
                        peerMaxVersion: p.peerMaxVersion,
                        identityPublicKey: p.identityPublicKey,
                        endpointV6: p.endpointV6,
                        joinTime: Date.now()
                    });
                }
                return true;
            };

            // Reuse the sticky introducer when still eligible — fresh `find()` per join causes split-brain.
            let introducer = null;
            const stickyID = this.networkRegistry.getIntroducer(NetworkID);
            if (stickyID === PeerID) {
                // The JOINING peer IS the current sticky introducer (it's rejoining). Its NAT type
                // may have CHANGED since it was elected — e.g. DirectMapping last time, Symmetric
                // now (a v6-primary peer's per-family detection can surface this). If it's no longer
                // eligible, CLEAR the stale sticky so it isn't silently retained; downstream
                // election (find → self-election) then picks a valid introducer or none. Without
                // this, the `stickyID !== PeerID` guard skipped re-validation entirely and a stale
                // sticky pointing at a now-symmetric peer stuck around.
                if (NATType === NATTypes.Symmetric) {
                    console.log(`[MessageHandler] Sticky introducer ${stickyID} (self-rejoin) now Symmetric — clearing stale sticky for ${NetworkID}`);
                    this.networkRegistry.clearIntroducer(NetworkID);
                }
                // If still non-symmetric, leave the sticky as-is; self-election below re-confirms it.
            } else if (stickyID) {
                const sticky = allCandidates.find(p => p.peerID === stickyID);
                if (isEligible(sticky)) {
                    introducer = sticky;
                } else {
                    console.log(`[MessageHandler] Sticky introducer ${stickyID} no longer eligible for ${NetworkID}, re-electing`);
                    this.networkRegistry.clearIntroducer(NetworkID);
                }
            }
            if (!introducer) {
                introducer = allCandidates.find(isEligible);
            }

            // If no one else is eligible, consider the requesting peer itself. It's the
            // perfect candidate in takeover scenarios where it's the last surviving
            // non-symmetric peer. We know its NATType and TCP socket is alive (it just
            // sent us this join).
            if (!introducer && NATType !== NATTypes.Symmetric) {
                const selfSockInfo = this.connectionManager.sockets.find(s => s.clientID === PeerID);
                if (selfSockInfo) {
                    introducer = {
                        peerID: PeerID,
                        endpoint: endpoint,
                        natType: NATType,
                        meshIP: PrivateAddressString
                    };
                    console.log(`[MessageHandler] Self-electing ${PeerID} as introducer for ${NetworkID} (no other eligible candidates)`);
                }
            }

            if (!introducer) {
                // No eligible introducer (all symmetric or all disconnected).
                // Fall back to direct mediation-brokered connections for all reachable peers.
                const reachablePeers = allCandidates.filter(p => {
                    const sockInfo = this.connectionManager.sockets.find(s => s.clientID === p.peerID);
                    return !!sockInfo;
                });
                const response = {
                    ID: MessageTypes.MeshJoinResponse,
                    NetworkID: NetworkID,
                    PeerCount: reachablePeers.length,
                    Peers: reachablePeers,
                    IntroducerPeerID: null  // No introducer
                };
                socket.write(Buffer.from(JSON.stringify(response)));
                return;
            }


            // Build the list of peers the introducer should relay introductions to.
            // Use meshMembers (already fetched above) which includes disconnected peers.
            const peersToIntroduce = meshMembers.filter(p => p.peerID !== introducer.peerID);

            // Build the response peer list: use active peers, but ensure the introducer
            // is included even if it was only found via meshMembers. Skip when the introducer
            // IS the joining peer itself (self-election path): the client recognizes self-introducer
            // by IntroducerPeerID matching its own peerID, and inserting a self-entry into Peers
            // makes the client's collision check see its own mesh IP as "taken" and reassign.
            let responsePeers = [...otherPeers];
            if (introducer.peerID !== PeerID &&
                !responsePeers.find(p => p.peerID === introducer.peerID)) {
                responsePeers.push({
                    peerID: introducer.peerID,
                    endpoint: introducer.endpoint,
                    natType: introducer.natType,
                    meshIP: introducer.meshIP,
                    peerMinVersion: introducer.peerMinVersion,
                    peerMaxVersion: introducer.peerMaxVersion,
                    identityPublicKey: introducer.identityPublicKey,
                    endpointV6: introducer.endpointV6
                });
            }

            this.networkRegistry.setIntroducer(NetworkID, introducer.peerID);

            const response = {
                ID: MessageTypes.MeshJoinResponse,
                NetworkID: NetworkID,
                PeerCount: responsePeers.length,
                Peers: responsePeers,
                IntroducerPeerID: introducer.peerID
            };
            socket.write(Buffer.from(JSON.stringify(response)));

            // Always send MeshIntroduceRequest to the introducer, even if OtherPeers is empty.
            // This ensures the introducer sets isIntroducer=true and stays connected to mediation.
            {
                const introducerPeer = this.networkRegistry.findPeerByID(introducer.peerID);
                if (introducerPeer && introducerPeer.socket) {
                    const introduceRequest = {
                        ID: MessageTypes.MeshIntroduceRequest,
                        PeerID: PeerID,
                        EndpointString: endpoint,
                        NATType: NATType,
                        PrivateAddressString: PrivateAddressString,
                        LocalIP: socketInfo.localIP,      // New peer's LAN IP for same-NAT detection
                        LocalPort: socketInfo.localPort,   // New peer's local UDP port
                        PeerMinVersion: peerMinVersion,    // New peer's peer-to-peer protocol range
                        PeerMaxVersion: peerMaxVersion,
                        IdentityPublicKey: identityPublicKey,
                        EndpointV6String: socketInfo.endpointV6,  // New peer's observed IPv6 endpoint (or undefined)
                        OtherPeers: peersToIntroduce  // Peers to forward the introduction to (may be empty)
                    };
                    introducerPeer.socket.write(Buffer.from(JSON.stringify(introduceRequest)));

                    // Track this pending introduction so we can retry if the introducer disconnects
                    this.pendingIntroductions.set(PeerID, {
                        newPeerInfo: {
                            peerID: PeerID,
                            endpoint,
                            natType: NATType,
                            meshIP: PrivateAddressString,
                            localIP: socketInfo.localIP,
                            localPort: socketInfo.localPort,
                            peerMinVersion,
                            peerMaxVersion,
                            identityPublicKey,
                            endpointV6: socketInfo.endpointV6
                        },
                        peersToIntroduce,
                        introducerPeerID: introducer.peerID,
                        networkID: NetworkID,
                        createdAt: Date.now()
                    });
                } else {
                    console.log(`[MessageHandler] Introducer ${introducer.peerID} socket not available — skipping MeshIntroduceRequest`);
                }
            }

        } catch (error) {
            console.error(`[MessageHandler] Error handling mesh join: ${error.message}`);
        }
    }

    /**
     * Handles MeshIntroduceAck — introducer confirms it has sent all introduction messages over WireGuard
     */
    handleMeshIntroduceAck(message) {
        const { PeerID } = message;
        if (!PeerID) return;

        if (this.pendingIntroductions.has(PeerID)) {
            this.pendingIntroductions.delete(PeerID);
        }
    }

    /**
     * Handles MeshPeerRemoved sent by the introducer when it has declared a peer dead
     * (missed heartbeats over the mesh tunnel). Drops the peer from meshMembers
     * immediately so it stops appearing in future MeshJoinResponse rosters.
     *
     * Only the current introducer is authorized — a non-introducer claiming a peer is
     * dead could be used to evict honest peers from the network.
     */
    /**
     * Handles MeshIPReassign sent by a peer after it detected a mesh-IP collision in its
     * MeshJoinResponse and locally reassigned to a new IP. Updates the stored meshIP for that
     * peer so subsequent MeshJoinResponse rosters carry the corrected value. Without this,
     * other peers receive the original (now-stale) mesh IP and can't reach the reassigned peer.
     */
    handleMeshIPReassign(message, socket) {
        const newMeshIP = message.PrivateAddressString;
        if (!newMeshIP) return;

        const sender = this.networkRegistry.findPeerBySocket(socket);
        if (!sender) return;

        // Locate the network containing this sender.
        let senderNetworkID = null;
        for (const [networkID, network] of this.networkRegistry.networks.entries()) {
            if (network.has(sender.peerID)) {
                senderNetworkID = networkID;
                break;
            }
        }
        if (!senderNetworkID) return;

        const members = this.networkRegistry.meshMembers.get(senderNetworkID);
        const network = this.networkRegistry.networks.get(senderNetworkID);
        const oldMeshIP = sender.meshIP;
        if (members && members.has(sender.peerID)) members.get(sender.peerID).meshIP = newMeshIP;
        if (network && network.has(sender.peerID)) network.get(sender.peerID).meshIP = newMeshIP;
        console.log(`[MessageHandler] Peer ${sender.peerID} reassigned mesh IP: ${oldMeshIP} -> ${newMeshIP}`);
    }

    handleMeshPeerRemoved(message, socket) {
        const deadPeerID = message.PeerID;
        const deadMeshIP = message.PrivateAddressString;
        if (!deadPeerID && !deadMeshIP) return;

        const sender = this.networkRegistry.findPeerBySocket(socket);
        if (!sender) return;

        // Locate the network containing this sender so we can check the introducer claim.
        let senderNetworkID = null;
        for (const [networkID, network] of this.networkRegistry.networks.entries()) {
            if (network.has(sender.peerID)) {
                senderNetworkID = networkID;
                break;
            }
        }
        if (!senderNetworkID) return;

        const currentIntroducer = this.networkRegistry.getIntroducer(senderNetworkID);
        if (currentIntroducer !== sender.peerID) {
            console.log(`[MessageHandler] Ignoring MeshPeerRemoved from non-introducer ${sender.peerID} (current introducer: ${currentIntroducer})`);
            return;
        }

        // Prefer peerID lookup; fall back to meshIP scan if only the IP was provided.
        let targetPeerID = deadPeerID;
        if (!targetPeerID && deadMeshIP) {
            const members = this.networkRegistry.meshMembers.get(senderNetworkID);
            if (members) {
                for (const member of members.values()) {
                    if (member.meshIP === deadMeshIP) {
                        targetPeerID = member.peerID;
                        break;
                    }
                }
            }
        }
        if (!targetPeerID) return;

        console.log(`[MessageHandler] Introducer ${sender.peerID} declared peer ${targetPeerID} (${deadMeshIP || 'unknown IP'}) dead — removing from mesh members`);
        this.networkRegistry.removeMeshMember(targetPeerID);
    }

    /**
     * Retries a pending introduction using a different introducer.
     * Called when an introducer disconnects before sending its MeshIntroduceAck.
     *
     * Searches ALL peers in the network for a replacement introducer — not just
     * the peersToIntroduce list, which only contains peers the old introducer was
     * supposed to relay to (and may all be disconnected from mediation).
     */
    retryPendingIntroduction(disconnectedPeerID) {
        const { NATTypes } = require('./constants');

        for (const [newPeerID, pending] of this.pendingIntroductions.entries()) {
            if (pending.introducerPeerID !== disconnectedPeerID) continue;

            console.log(`[MessageHandler] Introducer ${disconnectedPeerID} disconnected — retrying introduction for ${newPeerID}`);

            // Search all peers in the network for a replacement introducer.
            // A valid introducer must be:
            //   1. Non-symmetric NAT (symmetric peers can't hole-punch on behalf of others)
            //   2. Have a live TCP socket to the mediation server
            //   3. Not be the new peer itself
            //   4. Not be the disconnected introducer
            let newIntroducer = null;
            let newIntroducerPeer = null;

            const joinerMin = pending.newPeerInfo && pending.newPeerInfo.peerMinVersion;
            const joinerMax = pending.newPeerInfo && pending.newPeerInfo.peerMaxVersion;
            const rangesOverlap = (p) => {
                if (!p.peerMinVersion || !p.peerMaxVersion || !joinerMin || !joinerMax) return true;
                return Math.min(p.peerMaxVersion, joinerMax) >= Math.max(p.peerMinVersion, joinerMin);
            };

            // First check active network peers (they have live TCP sockets by definition)
            const networkPeers = this.networkRegistry.getPeersInNetwork(pending.networkID);
            for (const p of networkPeers) {
                if (p.peerID === newPeerID || p.peerID === disconnectedPeerID) continue;
                if (p.natType === NATTypes.Symmetric) continue;
                if (!rangesOverlap(p)) continue;
                const activePeer = this.networkRegistry.findPeerByID(p.peerID);
                if (activePeer && activePeer.socket) {
                    newIntroducer = p;
                    newIntroducerPeer = activePeer;
                    break;
                }
            }

            // Also check mesh members who may have reconnected or still have a live socket
            if (!newIntroducer) {
                const meshMembers = this.networkRegistry.getMeshMembers(pending.networkID, newPeerID);
                for (const m of meshMembers) {
                    if (m.peerID === disconnectedPeerID) continue;
                    if (m.natType === NATTypes.Symmetric) continue;
                    if (!rangesOverlap(m)) continue;
                    // Check if this mesh member has a live TCP socket
                    const sockInfo = this.connectionManager.sockets.find(s => s.clientID === m.peerID);
                    if (sockInfo && sockInfo.socket) {
                        newIntroducer = m;
                        // Re-register in active network if needed
                        const activeNetwork = this.networkRegistry.networks.get(pending.networkID);
                        if (activeNetwork && !activeNetwork.has(m.peerID)) {
                            activeNetwork.set(m.peerID, {
                                peerID: m.peerID,
                                socket: sockInfo.socket,
                                endpoint: m.endpoint,
                                natType: m.natType,
                                meshIP: m.meshIP,
                                peerMinVersion: m.peerMinVersion,
                                peerMaxVersion: m.peerMaxVersion,
                                identityPublicKey: m.identityPublicKey,
                                endpointV6: m.endpointV6,
                                joinTime: Date.now()
                            });
                        }
                        newIntroducerPeer = this.networkRegistry.findPeerByID(m.peerID) || { socket: sockInfo.socket };
                        break;
                    }
                }
            }

            if (!newIntroducer || !newIntroducerPeer) {
                console.log(`[MessageHandler] No eligible replacement introducer found for ${newPeerID} in network ${pending.networkID}`);
                this.pendingIntroductions.delete(newPeerID);
                continue;
            }

            // Build updated peersToIntroduce: all mesh members except the new introducer and the new peer
            const allMembers = this.networkRegistry.getMeshMembers(pending.networkID, newPeerID);
            const remainingPeers = allMembers.filter(p => p.peerID !== newIntroducer.peerID);

            const introduceRequest = {
                ID: MessageTypes.MeshIntroduceRequest,
                PeerID: newPeerID,
                EndpointString: pending.newPeerInfo.endpoint,
                NATType: pending.newPeerInfo.natType,
                PrivateAddressString: pending.newPeerInfo.meshIP,
                LocalIP: pending.newPeerInfo.localIP,
                LocalPort: pending.newPeerInfo.localPort,
                PeerMinVersion: pending.newPeerInfo.peerMinVersion,
                PeerMaxVersion: pending.newPeerInfo.peerMaxVersion,
                IdentityPublicKey: pending.newPeerInfo.identityPublicKey,
                EndpointV6String: pending.newPeerInfo.endpointV6,
                OtherPeers: remainingPeers
            };

            console.log(`[MessageHandler] Retrying introduction for ${newPeerID} with new introducer ${newIntroducer.peerID}`);
            newIntroducerPeer.socket.write(Buffer.from(JSON.stringify(introduceRequest)));

            // Update the pending record with the new introducer
            pending.introducerPeerID = newIntroducer.peerID;
            pending.peersToIntroduce = remainingPeers;
        }
    }

    getMessageTypeName(id) {
        return Object.keys(MessageTypes).find(key => MessageTypes[key] === id) || 'Unknown';
    }
}

module.exports = MessageHandler;