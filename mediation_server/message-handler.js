const { MessageTypes, StatusTypes, Config, NATTypes } = require('./constants');
const { Buffer } = require('buffer');
const NetworkRegistry = require('./network-registry');

class MessageHandler {
    constructor(connectionManager) {
        this.connectionManager = connectionManager;
        this.networkRegistry = new NetworkRegistry();

        // Set up callback for when server tunnel completes NAT detection
        this.connectionManager.onServerTunnelReady = (connectionId, socketInfo, natType) => {
            this.handleServerTunnelReady(connectionId, socketInfo, natType);
        };

        // Track pending introductions so we can retry if the introducer disconnects before acking
        // Map of newPeerID -> { newPeerInfo, otherPeers, introducerPeerID, networkID }
        this.pendingIntroductions = new Map();
    }

    handleTCPMessage(message, socket) {
        if (!message) return;

        switch (message.ID) {
            case MessageTypes.ServerRegister:
                this.handleServerRegister(message, socket);
                break;
            case MessageTypes.NATTypeRequest:
                this.handleNATTypeRequest(message, socket);
                break;
            case MessageTypes.KeepAlive:
                this.handleKeepAlive(socket);
                break;
            case MessageTypes.ConnectionRequest:
                console.log(`[MessageHandler] Routing to handleConnectionRequest`);
                this.handleConnectionRequest(message, socket);
                break;
            case MessageTypes.ReceivedPeer:
                this.handleReceivedPeer(message);
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
            default:
                console.log(`[MessageHandler] Unknown message type: ${message.ID}`);
                break;
        }
    }

    handleKeepAlive(socket) {
        // Primary lookup: Use IP:port (most reliable for sockets behind proxies/NAT)
        let socketInfo = null;
        if (socket.remoteAddress && socket.remotePort) {
            socketInfo = this.connectionManager.sockets.find(s =>
                s.ip === socket.remoteAddress && s.tcpPort === socket.remotePort
            );
        }

        // Fallback: Try socket object reference
        if (!socketInfo) {
            socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
            if (socketInfo) {
                // Socket object matched, but IP:port didn't - TCP IP may have changed (proxy/CDN)
                // UDP traffic still comes from original IP, so we don't update UDP info

                // Update the stored TCP IP and port for timeout management
                socketInfo.ip = socket.remoteAddress;
                socketInfo.tcpPort = socket.remotePort;
                // Note: localPort stays the same, it's used to find UDP info later
            }
        }

        if (socketInfo) {
            this.connectionManager.updateTimeout(socketInfo);  // Pass socketInfo object directly
        }
    }

    handleServerRegister(message, socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            socketInfo.isServer = true;
            console.log(`Registered server: ${socketInfo.ip}:${socketInfo.tcpPort}`);
        }
    }

    handleNATTypeRequest(message, socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            socketInfo.localPort = message.LocalPort;

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
                    this.connectionManager.removeSocket(stale.socket, message.ClientID);
                }
            }

            socketInfo.clientID = message.ClientID;

            // Reset NAT test state so checkNATType waits for fresh results
            socketInfo.externalPortOne = 0;
            socketInfo.externalPortTwo = 0;
            socketInfo.natType = NATTypes.Unknown;
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
                console.log(`[MessageHandler] Mesh peer tunnel connecting for ConnectionID ${message.ConnectionID}`);
                console.log(`[MessageHandler] Tunnel LocalPort: ${message.LocalPort}`);
                console.log(`[MessageHandler] Client endpoint: ${pair.client_endpoint}, Server endpoint: ${pair.server_endpoint}`);

                // Determine which peer this tunnel belongs to by matching local UDP port
                // The mesh mode and its tunnel share the same UDP client (same local port)
                // Use stored localPort values (not endpoint ports, which may be external/NAT-mapped)
                const clientLocalPort = pair.client_localPort;
                const serverLocalPort = pair.server_localPort;

                let isInitiatingPeer;
                if (message.LocalPort === clientLocalPort) {
                    // This tunnel's port matches the initiating peer's local port
                    isInitiatingPeer = true;
                    console.log(`[MessageHandler] Tunnel belongs to initiating peer (localPort ${message.LocalPort} matches client localPort ${clientLocalPort})`);
                } else if (message.LocalPort === serverLocalPort) {
                    // This tunnel's port matches the target peer's local port
                    isInitiatingPeer = false;
                    console.log(`[MessageHandler] Tunnel belongs to target peer (localPort ${message.LocalPort} matches server localPort ${serverLocalPort})`);
                } else {
                    // Port doesn't match either - shouldn't happen, log warning
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

                console.log(`[MessageHandler] Sending remote peer endpoint: ${peerEndpoint} (NAT type: ${peerNatType}, meshIP: ${peerMeshIP}), own NAT type: ${ownNatType}`);

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

        socket.write(Buffer.from(JSON.stringify({
            ID: MessageTypes.NATTestBegin,
            NATTestPortOne: Config.NAT_TEST_PORT_ONE,
            NATTestPortTwo: Config.NAT_TEST_PORT_TWO
        })));
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

        console.log(`[MessageHandler] Connection request from ${clientSocketInfo.ip} - PeerID: ${message.PeerID || 'none'}, EndpointString: ${message.EndpointString || 'none'}`);

        // Check if this is a mesh connection request (has PeerID) or traditional client/server (has EndpointString)
        let targetSocket;
        let targetPeer = null;  // Store target peer info for mesh connections
        let clientPeer = null;  // Store client peer info for mesh connections
        if (message.PeerID) {
            // Mesh mode: Find peer by PeerID in network registry
            console.log(`[MessageHandler] Looking for peer ${message.PeerID} in network registry...`);
            targetPeer = this.networkRegistry.findPeerByID(message.PeerID);
            if (targetPeer) {
                console.log(`[MessageHandler] Found peer ${message.PeerID} at ${targetPeer.endpoint} (meshIP: ${targetPeer.meshIP})`);
                targetSocket = this.connectionManager.sockets.find(s => s.socket === targetPeer.socket);

                // Fallback: if the registry's socket reference is stale, try finding by clientID
                if (!targetSocket) {
                    console.log(`[MessageHandler] Registry socket stale for ${message.PeerID}, trying clientID lookup`);
                    targetSocket = this.connectionManager.sockets.find(s => s.clientID === message.PeerID);
                    // Update the registry's socket reference if we found the peer
                    if (targetSocket && targetPeer) {
                        targetPeer.socket = targetSocket.socket;
                        console.log(`[MessageHandler] Updated registry socket for ${message.PeerID} via clientID`);
                    }
                }

                // Also get the initiating peer's info
                clientPeer = this.networkRegistry.findPeerBySocket(socket);
                if (clientPeer) {
                    console.log(`[MessageHandler] Initiating peer meshIP: ${clientPeer.meshIP}`);
                }
            } else {
                console.log(`[MessageHandler] Peer ${message.PeerID} not found in network registry`);
            }
        } else if (message.EndpointString) {
            // Traditional client/server mode: Find server by IP
            const requestedIp = message.EndpointString;
            targetSocket = this.connectionManager.sockets.find(s =>
                requestedIp.includes(s.ip) && s.isServer
            );
        }

        if (!targetSocket) {
            console.log(`[MessageHandler] Target not found, sending ServerNotAvailable`);
            this.sendServerNotAvailable(socket);
            return;
        }

        console.log(`[MessageHandler] Target found: ${targetSocket.ip}`);

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
                console.log(`[MessageHandler] Duplicate ConnectionRequest: pair already exists between ${clientSocketInfo.clientID} and ${message.PeerID} — skipping`);
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

        if (!clientUDPInfo) {
            console.log(`[MessageHandler] No UDP info for ${clientSocketInfo.ip}, sending ServerNotAvailable`);
            this.sendServerNotAvailable(socket);
            return;
        }

        // Use external port (info.port) for the endpoint — this is what the remote peer sees
        const clientEndpoint = `${clientUDPInfo.ip}:${clientUDPInfo.port}`;

        // Store the connection pair
        this.connectionManager.currentConnectionPairs[connectionId] = {
            server_info: targetSocket.ip,
            client_info: clientSocketInfo.ip,
            server_connected: false,
            client_connected: false,
            server_clientID: targetSocket.clientID,
            client_clientID: clientSocketInfo.clientID,
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
            console.log(`[MessageHandler] Mesh connection detected - sending ConnectionBegin to both peers immediately`);

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

            if (!targetUDPInfo) {
                console.log(`[MessageHandler] No UDP info for target ${targetSocket.ip} (localPort=${targetSocket.localPort}), cannot proceed`);
                this.sendServerNotAvailable(socket);
                return;
            }

            // Use external port (info.port) for the endpoint — this is what the remote peer sees
            const targetEndpoint = `${targetUDPInfo.ip}:${targetUDPInfo.port}`;

            // Get NAT types
            const clientNatType = message.NATType !== undefined ? message.NATType : -1;
            const targetNatType = targetSocket.natType !== undefined ? targetSocket.natType : -1;

            // Send ConnectionBegin to initiating peer
            const clientMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: targetEndpoint,
                NATType: targetNatType,
                OwnNATType: clientNatType,  // Initiating peer's own NAT type
                ConnectionID: connectionId,
                IsServer: false,
                PrivateAddressString: targetPeer ? targetPeer.meshIP : null,  // Peer's mesh IP
                PeerID: targetSocket.clientID  // Target peer's ID so client can track pending requests
            };

            console.log(`[MessageHandler] Sending ConnectionBegin to initiating peer: ${clientSocketInfo.ip} -> ${targetEndpoint} (peer meshIP: ${targetPeer ? targetPeer.meshIP : 'unknown'}, ownNAT: ${clientNatType})`);
            socket.write(Buffer.from(JSON.stringify(clientMessage)));

            // Send ConnectionBegin to target peer
            const serverMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: clientEndpoint,
                NATType: clientNatType,
                OwnNATType: targetNatType,  // Target peer's own NAT type
                ConnectionID: connectionId,
                IsServer: false,  // In mesh mode, both are peers (not server/client)
                PrivateAddressString: clientPeer ? clientPeer.meshIP : null,  // Initiating peer's mesh IP
                PeerID: clientSocketInfo.clientID  // Initiating peer's ID so target can track pending requests
            };

            console.log(`[MessageHandler] Sending ConnectionBegin to target peer: ${targetSocket.ip} -> ${clientEndpoint} (peer meshIP: ${clientPeer ? clientPeer.meshIP : 'unknown'})`);
            targetSocket.socket.write(Buffer.from(JSON.stringify(serverMessage)));

            // Store endpoint info for mesh peer tunnels that will connect later
            this.connectionManager.currentConnectionPairs[connectionId].client_endpoint = clientEndpoint;
            this.connectionManager.currentConnectionPairs[connectionId].server_endpoint = targetEndpoint;
            this.connectionManager.currentConnectionPairs[connectionId].client_localPort = clientSocketInfo.localPort;
            this.connectionManager.currentConnectionPairs[connectionId].server_localPort = targetSocket.localPort;
            this.connectionManager.currentConnectionPairs[connectionId].client_natType = clientNatType;
            this.connectionManager.currentConnectionPairs[connectionId].server_natType = targetNatType;
            this.connectionManager.currentConnectionPairs[connectionId].client_meshIP = clientPeer ? clientPeer.meshIP : null;
            this.connectionManager.currentConnectionPairs[connectionId].server_meshIP = targetPeer ? targetPeer.meshIP : null;

            // Mark connection as complete immediately for mesh connections
            this.connectionManager.currentConnectionPairs[connectionId].server_connected = true;
            this.connectionManager.currentConnectionPairs[connectionId].client_connected = true;
        } else {
            // Traditional client/server mode - wait for the server-side tunnel
            // to complete NAT detection and register its UDP port

            // Set up connection timeout
            setTimeout(() => {
                const pair = this.connectionManager.currentConnectionPairs[connectionId];
                if (pair && (!pair.server_connected || !pair.client_connected)) {
                    console.log(`Connection ${connectionId} timed out`);
                    this.handleConnectionTimeout(connectionId);
                }
            }, 30000); // 30 second timeout
        }
    }

    handleServerTunnelReady(connectionId, serverSocketInfo, natType) {
        const pair = this.connectionManager.currentConnectionPairs[connectionId];
        if (!pair) {
            return;
        }

        // Update the connection pair with the actual per-client tunnel's clientID
        // (not the TunnelManager's clientID that was stored initially)
        pair.server_clientID = serverSocketInfo.clientID;

        // Get server tunnel's UDP info - use the most recent UDP info from this IP
        // Since the server tunnel just completed NAT detection, its UDP port should be the latest
        const allServerUDPInfo = this.connectionManager.udpConnectionInfo.filter(
            info => serverSocketInfo.ip.includes(info.ip)
        );

        if (allServerUDPInfo.length === 0) {
            return;
        }

        // Get the most recently added (last) entry for this IP - that's the server tunnel's port
        const serverUDPInfo = allServerUDPInfo[allServerUDPInfo.length - 1];
        const serverEndpoint = `${serverSocketInfo.ip}:${serverUDPInfo.port}`;

        // Find the waiting client
        const clientSocketInfo = this.connectionManager.sockets.find(s => s.clientID === pair.client_clientID);
        if (!clientSocketInfo) {
            return;
        }

        // Get client's UDP info
        const clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => clientSocketInfo.ip.includes(info.ip)
        );

        if (!clientUDPInfo) {
            return;
        }

        const clientEndpoint = `${clientSocketInfo.ip}:${clientUDPInfo.port}`;

        // Get client's NAT type (should be stored from ConnectionRequest)
        const clientNatType = clientSocketInfo.natType !== undefined ? clientSocketInfo.natType : -1;

        if (clientNatType === -1) {
            console.log(`Warning: Client NAT type not available for connection ${connectionId}`);
        }

        // Send ConnectionBegin to client with server's tunnel endpoint
        const clientMessage = {
            ID: MessageTypes.ConnectionBegin,
            EndpointString: serverEndpoint,
            NATType: natType,  // Server tunnel's NAT type
            ConnectionID: connectionId,
            IsServer: false
        };

        console.log(`Sending ConnectionBegin to client`);
        clientSocketInfo.socket.write(Buffer.from(JSON.stringify(clientMessage)));

        // Also send ConnectionBegin to server tunnel with client's endpoint
        const serverMessage = {
            ID: MessageTypes.ConnectionBegin,
            EndpointString: clientEndpoint,
            NATType: clientNatType,  // Client's NAT type
            ConnectionID: connectionId,
            IsServer: true
        };

        console.log(`Sending ConnectionBegin to server tunnel`);
        serverSocketInfo.socket.write(Buffer.from(JSON.stringify(serverMessage)));
    }

    handleReceivedPeer(message) {
        const pair = this.connectionManager.currentConnectionPairs[message.ConnectionID];
        if (!pair) return;

        if (message.IsServer) {
            pair.server_connected = true;
        } else {
            pair.client_connected = true;
        }

        if (pair.server_connected && pair.client_connected) {
            this.completeConnection(message.ConnectionID);
        }
    }

    completeConnection(connectionId) {
        const pair = this.connectionManager.currentConnectionPairs[connectionId];

        // Notify both server and client - use clientID to find the correct socket
        // (not IP, since there may be multiple tunnels from same IP)
        const serverSocket = this.connectionManager.sockets.find(s => s.clientID === pair.server_clientID);
        const clientSocket = this.connectionManager.sockets.find(s => s.clientID === pair.client_clientID);

        console.log(`Completing connection ${connectionId}`);

        if (serverSocket) {
            serverSocket.socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.ConnectionComplete
            })));
        }

        if (clientSocket) {
            clientSocket.socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.ConnectionComplete
            })));
        }

        // Reset connection status
        this.connectionManager.udpConnectionInfo.forEach(info => {
            if (pair.server_info.includes(info.ip) || pair.client_info.includes(info.ip)) {
                info.status.type = StatusTypes.Free;
            }
        });
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
    }

    /**
     * Handles mesh network join requests
     * Peer wants to join a mesh network and discover other peers
     */
    handleMeshJoinRequest(message, socket) {
        const { NetworkID, PeerID, NATType, PrivateAddressString } = message;

        if (!NetworkID) {
            console.log('[MessageHandler] MeshJoinRequest missing NetworkID');
            return;
        }

        if (!PeerID) {
            console.log('[MessageHandler] MeshJoinRequest missing PeerID');
            return;
        }

        console.log(`[MessageHandler] Mesh join request: Peer ${PeerID} wants to join network ${NetworkID}`);

        // Debug: Log all sockets
        console.log(`[MessageHandler] Current sockets (${this.connectionManager.sockets.length}):`);
        this.connectionManager.sockets.forEach(s => {
            console.log(`  - ${s.ip}:${s.tcpPort} clientID=${s.clientID} localPort=${s.localPort} timeout=${s.timeout}`);
        });

        // Get peer's endpoint from socket info
        // Try multiple lookup methods (prioritizing IP:port as most reliable):
        // 1. By remote address (IP:port) - PRIMARY
        // 2. By PeerID (clientID) - SECONDARY
        // 3. By socket object reference - FALLBACK
        let socketInfo = null;

        // Primary: Lookup by IP:port
        if (socket.remoteAddress && socket.remotePort) {
            const remoteAddr = socket.remoteAddress;
            const remotePort = socket.remotePort;
            socketInfo = this.connectionManager.sockets.find(s => s.ip === remoteAddr && s.tcpPort === remotePort);
            console.log(`[MessageHandler] Socket lookup by IP:port (${remoteAddr}:${remotePort}): ${socketInfo ? 'SUCCESS' : 'FAILED'}`);
        }

        // Secondary: Lookup by clientID
        if (!socketInfo && PeerID) {
            console.log(`[MessageHandler] Socket lookup by IP:port failed, trying by clientID (PeerID: ${PeerID})`);
            socketInfo = this.connectionManager.sockets.find(s => s.clientID === PeerID);
            console.log(`[MessageHandler] Socket lookup by clientID: ${socketInfo ? 'SUCCESS' : 'FAILED'}`);
        }

        // Fallback: Lookup by socket object reference
        if (!socketInfo) {
            console.log(`[MessageHandler] Socket lookup by clientID failed, trying by socket object`);
            socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
            console.log(`[MessageHandler] Socket lookup by object: ${socketInfo ? 'SUCCESS' : 'FAILED'}`);

            if (socketInfo) {
                // Socket object matched - check if IP changed
                if (socketInfo.ip !== socket.remoteAddress || socketInfo.tcpPort !== socket.remotePort) {
                    console.log(`[MessageHandler] Mesh join: Socket object matched but IP changed! Old: ${socketInfo.ip}:${socketInfo.tcpPort}, New: ${socket.remoteAddress}:${socket.remotePort}`);
                    // Update the stored IP and port
                    socketInfo.ip = socket.remoteAddress;
                    socketInfo.tcpPort = socket.remotePort;
                }
            }
        }

        if (!socketInfo) {
            console.log('[MessageHandler] ❌ ERROR: Socket info not found for mesh join after all lookup methods!');
            console.log(`[MessageHandler] PeerID: ${PeerID}`);
            console.log(`[MessageHandler] Socket remote: ${socket.remoteAddress}:${socket.remotePort}`);
            console.log(`[MessageHandler] Available sockets: ${this.connectionManager.sockets.length}`);
            this.connectionManager.sockets.forEach((s, idx) => {
                console.log(`[MessageHandler]   Socket ${idx}: clientID=${s.clientID}, ip=${s.ip}, tcpPort=${s.tcpPort}, socket===socket: ${s.socket === socket}`);
            });
            return;
        }

        console.log(`[MessageHandler] Found socket for peer ${PeerID}: ${socketInfo.ip}:${socketInfo.tcpPort}`);

        // Update the socket's clientID to match the peer's actual GUID
        // This ensures future lookups by PeerID will work
        socketInfo.clientID = PeerID;
        console.log(`[MessageHandler] Updated socket clientID to ${PeerID}`);

        // Update timeout for mesh peer to keep them alive
        // Mesh peers stay connected to receive peer updates and connection coordination
        this.connectionManager.updateTimeout(socketInfo);  // Pass socketInfo object directly

        // Use the UDP IP (where the peer actually sends UDP from) for the endpoint.
        // For symmetric NAT, the UDP IP may differ from the TCP IP.
        // Fall back to TCP IP if no UDP IP is available yet.
        let peerIP = socketInfo.udpIp || socketInfo.ip;
        // Strip ::ffff: IPv6-mapped prefix so endpoints are plain IPv4 (e.g. "1.2.3.4:PORT")
        if (peerIP && peerIP.startsWith('::ffff:')) {
            peerIP = peerIP.substring(7);
        }

        // Use the external port from UDP info (as seen by the server) — this is the port
        // other peers need to send to. For DirectMapping, external == local. For Restricted
        // NAT, the external port may differ from the local port.
        // This matches handleConnectionRequest which uses clientUDPInfo.port.
        let externalPort = socketInfo.localPort || 0;
        let udpInfo = null;
        if (socketInfo.localPort) {
            udpInfo = this.connectionManager.udpConnectionInfo.find(
                info => info.localPort === socketInfo.localPort
            );
        }
        if (!udpInfo) {
            udpInfo = this.connectionManager.udpConnectionInfo.find(
                info => peerIP === info.ip || (socketInfo.ip && socketInfo.ip.includes(info.ip)) ||
                    (socketInfo.udpIp && socketInfo.udpIp.includes(info.ip))
            );
        }
        if (udpInfo) {
            externalPort = udpInfo.port;
            console.log(`[MessageHandler] Using external port ${externalPort} for peer ${PeerID} (local: ${socketInfo.localPort})`);
        } else {
            console.log(`[MessageHandler] No UDP info for peer ${PeerID} — using localPort ${externalPort}`);
        }
        const endpoint = `${peerIP}:${externalPort}`;

        const { NATTypes } = require('./constants');

        try {
            // Join the network and get list of other peers
            const otherPeers = this.networkRegistry.joinNetwork(
                NetworkID,
                PeerID,
                socket,
                endpoint,
                NATType,
                PrivateAddressString  // Mesh IP address
            );

            console.log(`[MessageHandler] Peer ${PeerID} (${PrivateAddressString}) joined network ${NetworkID}, found ${otherPeers.length} other active peers`);

            // Also check meshMembers for peers that disconnected from mediation
            // but may still be reachable via an introducer's WireGuard tunnel
            const meshMembers = this.networkRegistry.getMeshMembers(NetworkID, PeerID);
            console.log(`[MessageHandler] Mesh members (including disconnected): ${meshMembers.length}`);
            for (const m of meshMembers) {
                console.log(`[MessageHandler]   member: ${m.peerID} meshIP=${m.meshIP} NAT=${m.natType} connected=${m.connected}`);
            }

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
            const introducer = allCandidates.find(p => {
                if (p.natType === NATTypes.Symmetric) return false;
                // Check if this peer has a live TCP socket (by clientID lookup)
                const sockInfo = this.connectionManager.sockets.find(s => s.clientID === p.peerID);
                if (!sockInfo) return false;
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
                        joinTime: Date.now()
                    });
                    console.log(`[MessageHandler] Re-added peer ${p.peerID} to active network (socket still alive)`);
                }
                return true;
            });

            if (!introducer) {
                // No eligible introducer (all symmetric or all disconnected).
                // Fall back to direct mediation-brokered connections for all reachable peers.
                const reachablePeers = allCandidates.filter(p => {
                    const sockInfo = this.connectionManager.sockets.find(s => s.clientID === p.peerID);
                    return !!sockInfo;
                });
                console.log(`[MessageHandler] No non-symmetric introducer available — falling back to direct mediation for ${reachablePeers.length}/${allCandidates.length} reachable peer(s)`);
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

            console.log(`[MessageHandler] Selected introducer for ${PeerID}: ${introducer.peerID} (NAT type: ${introducer.natType})`);

            // Build the list of peers the introducer should relay introductions to.
            // Use meshMembers (already fetched above) which includes disconnected peers.
            const peersToIntroduce = meshMembers.filter(p => p.peerID !== introducer.peerID);

            // Build the response peer list: use active peers, but ensure the introducer
            // is included even if it was only found via meshMembers
            let responsePeers = [...otherPeers];
            if (!responsePeers.find(p => p.peerID === introducer.peerID)) {
                responsePeers.push({
                    peerID: introducer.peerID,
                    endpoint: introducer.endpoint,
                    natType: introducer.natType,
                    meshIP: introducer.meshIP
                });
            }

            const response = {
                ID: MessageTypes.MeshJoinResponse,
                NetworkID: NetworkID,
                PeerCount: responsePeers.length,
                Peers: responsePeers,
                IntroducerPeerID: introducer.peerID
            };
            socket.write(Buffer.from(JSON.stringify(response)));
            console.log(`[MessageHandler] Sent MeshJoinResponse to ${PeerID} with ${responsePeers.length} peer(s) (introducer: ${introducer.peerID})`);

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
                        OtherPeers: peersToIntroduce  // Peers to forward the introduction to (may be empty)
                    };
                    console.log(`[MessageHandler] Sending MeshIntroduceRequest to introducer ${introducer.peerID} for ${peersToIntroduce.length} peer(s) (${peersToIntroduce.filter(p => !p.connected).length} disconnected)`);
                    introducerPeer.socket.write(Buffer.from(JSON.stringify(introduceRequest)));

                    // Track this pending introduction so we can retry if the introducer disconnects
                    this.pendingIntroductions.set(PeerID, {
                        newPeerInfo: {
                            peerID: PeerID,
                            endpoint,
                            natType: NATType,
                            meshIP: PrivateAddressString
                        },
                        peersToIntroduce,
                        introducerPeerID: introducer.peerID,
                        networkID: NetworkID
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
            console.log(`[MessageHandler] MeshIntroduceAck received for new peer ${PeerID} — introductions complete`);
            this.pendingIntroductions.delete(PeerID);
        } else {
            console.log(`[MessageHandler] MeshIntroduceAck for unknown peer ${PeerID} (may have already been cleared)`);
        }
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

            // First check active network peers (they have live TCP sockets by definition)
            const networkPeers = this.networkRegistry.getPeersInNetwork(pending.networkID);
            for (const p of networkPeers) {
                if (p.peerID === newPeerID || p.peerID === disconnectedPeerID) continue;
                if (p.natType === NATTypes.Symmetric) continue;
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
                                joinTime: Date.now()
                            });
                            console.log(`[MessageHandler] Re-added peer ${m.peerID} to active network for introducer retry`);
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
                OtherPeers: remainingPeers
            };

            console.log(`[MessageHandler] Sending retry MeshIntroduceRequest to new introducer ${newIntroducer.peerID} (${remainingPeers.length} peers to introduce)`);
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