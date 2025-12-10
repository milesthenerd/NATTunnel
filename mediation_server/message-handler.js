const { MessageTypes, StatusTypes, Config } = require('./constants');
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
        }
    }

    handleKeepAlive(socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            this.connectionManager.updateTimeout(socketInfo.ip);
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
            socketInfo.clientID = message.ClientID;
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

                // Determine which peer this tunnel belongs to by matching UDP port
                // The mesh mode and its tunnel share the same UDP client (same port)
                // Extract port from stored endpoints
                const clientPort = parseInt(pair.client_endpoint.split(':')[1]);
                const serverPort = parseInt(pair.server_endpoint.split(':')[1]);

                let isInitiatingPeer;
                if (message.LocalPort === clientPort) {
                    // This tunnel's port matches the initiating peer's port
                    isInitiatingPeer = true;
                    console.log(`[MessageHandler] Tunnel belongs to initiating peer (port ${message.LocalPort} matches client port ${clientPort})`);
                } else if (message.LocalPort === serverPort) {
                    // This tunnel's port matches the target peer's port
                    isInitiatingPeer = false;
                    console.log(`[MessageHandler] Tunnel belongs to target peer (port ${message.LocalPort} matches server port ${serverPort})`);
                } else {
                    // Port doesn't match either - shouldn't happen, log warning
                    console.log(`[MessageHandler] Warning: Tunnel port ${message.LocalPort} doesn't match client ${clientPort} or server ${serverPort}`);
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
        if (!message.hasOwnProperty('NATType')) return;

        const clientSocketInfo = this.connectionManager.sockets.find(s => s.socket === socket);

        // Update timeout for the requesting peer (keeps them alive)
        if (clientSocketInfo) {
            this.connectionManager.updateTimeout(clientSocketInfo.ip);
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

        // Generate connection ID
        const connectionId = this.connectionManager.connectionId++;

        // Get client UDP info
        const clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => clientSocketInfo.ip.includes(info.ip)
        );

        if (!clientUDPInfo) {
            console.log(`[MessageHandler] No UDP info for ${clientSocketInfo.ip}, sending ServerNotAvailable`);
            console.log(`[MessageHandler] Available UDP connections: ${JSON.stringify(this.connectionManager.udpConnectionInfo.map(u => u.ip))}`);
            this.sendServerNotAvailable(socket);
            return;
        }

        console.log(`[MessageHandler] Client UDP info found: ${clientSocketInfo.ip}:${clientUDPInfo.port}`);

        const clientEndpoint = `${clientSocketInfo.ip}:${clientUDPInfo.port}`;

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
            const targetUDPInfo = this.connectionManager.udpConnectionInfo.find(
                info => targetSocket.ip.includes(info.ip)
            );

            if (!targetUDPInfo) {
                console.log(`[MessageHandler] No UDP info for target ${targetSocket.ip}, cannot proceed`);
                this.sendServerNotAvailable(socket);
                return;
            }

            const targetEndpoint = `${targetSocket.ip}:${targetUDPInfo.port}`;

            // Get NAT types
            const clientNatType = message.NATType !== undefined ? message.NATType : -1;
            const targetNatType = targetSocket.natType !== undefined ? targetSocket.natType : -1;

            // Send ConnectionBegin to initiating peer
            const clientMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: targetEndpoint,
                NATType: targetNatType,
                ConnectionID: connectionId,
                IsServer: false,
                PrivateAddressString: targetPeer ? targetPeer.meshIP : null  // Peer's mesh IP
            };

            console.log(`[MessageHandler] Sending ConnectionBegin to initiating peer: ${clientSocketInfo.ip} -> ${targetEndpoint} (peer meshIP: ${targetPeer ? targetPeer.meshIP : 'unknown'})`);
            socket.write(Buffer.from(JSON.stringify(clientMessage)));

            // Send ConnectionBegin to target peer
            const serverMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: clientEndpoint,
                NATType: clientNatType,
                ConnectionID: connectionId,
                IsServer: false,  // In mesh mode, both are peers (not server/client)
                PrivateAddressString: clientPeer ? clientPeer.meshIP : null  // Initiating peer's mesh IP
            };

            console.log(`[MessageHandler] Sending ConnectionBegin to target peer: ${targetSocket.ip} -> ${clientEndpoint} (peer meshIP: ${clientPeer ? clientPeer.meshIP : 'unknown'})`);
            targetSocket.socket.write(Buffer.from(JSON.stringify(serverMessage)));

            // Store endpoint info for mesh peer tunnels that will connect later
            this.connectionManager.currentConnectionPairs[connectionId].client_endpoint = clientEndpoint;
            this.connectionManager.currentConnectionPairs[connectionId].server_endpoint = targetEndpoint;
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
        // Try multiple lookup methods:
        // 1. By socket object reference
        // 2. By PeerID (clientID)
        // 3. By remote address (IP:port)
        let socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);

        if (!socketInfo && PeerID) {
            console.log(`[MessageHandler] Socket lookup by object failed, trying by clientID (PeerID: ${PeerID})`);
            socketInfo = this.connectionManager.sockets.find(s => s.clientID === PeerID);
        }

        if (!socketInfo && socket.remoteAddress && socket.remotePort) {
            const remoteAddr = socket.remoteAddress;
            const remotePort = socket.remotePort;
            console.log(`[MessageHandler] Socket lookup by clientID failed, trying by remote address (${remoteAddr}:${remotePort})`);
            socketInfo = this.connectionManager.sockets.find(s => s.ip === remoteAddr && s.tcpPort === remotePort);
        }

        if (!socketInfo) {
            console.log('[MessageHandler] Socket info not found for mesh join');
            console.log(`[MessageHandler] PeerID: ${PeerID}`);
            console.log(`[MessageHandler] Socket remote: ${socket.remoteAddress}:${socket.remotePort}`);
            return;
        }

        console.log(`[MessageHandler] Found socket for peer ${PeerID}: ${socketInfo.ip}:${socketInfo.tcpPort}`);

        // Update the socket's clientID to match the peer's actual GUID
        // This ensures future lookups by PeerID will work
        socketInfo.clientID = PeerID;
        console.log(`[MessageHandler] Updated socket clientID to ${PeerID}`);

        // Update timeout for mesh peer to keep them alive
        // Mesh peers stay connected to receive peer updates and connection coordination
        this.connectionManager.updateTimeout(socketInfo.ip);

        const endpoint = `${socketInfo.ip}:${socketInfo.localPort || 0}`;

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

            console.log(`[MessageHandler] Peer ${PeerID} (${PrivateAddressString}) joined network ${NetworkID}, found ${otherPeers.length} other peers`);

            // Send response with list of peers
            const response = {
                ID: MessageTypes.MeshJoinResponse,
                NetworkID: NetworkID,
                PeerCount: otherPeers.length,
                Peers: otherPeers  // Array of {peerID, endpoint, natType}
            };

            socket.write(Buffer.from(JSON.stringify(response)));

        } catch (error) {
            console.error(`[MessageHandler] Error handling mesh join: ${error.message}`);
        }
    }

    getMessageTypeName(id) {
        return Object.keys(MessageTypes).find(key => MessageTypes[key] === id) || 'Unknown';
    }
}

module.exports = MessageHandler;