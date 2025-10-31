const { MessageTypes, StatusTypes, Config } = require('./constants');
const { Buffer } = require('buffer');

class MessageHandler {
    constructor(connectionManager) {
        this.connectionManager = connectionManager;

        // Set up callback for when server tunnel completes NAT detection
        this.connectionManager.onServerTunnelReady = (connectionId, socketInfo, natType) => {
            this.handleServerTunnelReady(connectionId, socketInfo, natType);
        };
    }

    handleTCPMessage(message, socket) {
        if (!message) return;

        console.log(`📨 Received TCP message with ID: ${message.ID} (${this.getMessageTypeName(message.ID)})`);

        switch (message.ID) {
            case MessageTypes.ServerRegister:
                this.handleServerRegister(message, socket);
                break;
            case MessageTypes.NATTypeRequest:
                this.handleNATTypeRequest(message, socket);
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
        }
    }

    handleServerRegister(message, socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            socketInfo.isServer = true;
            console.log(`✓ Registered server: ${socketInfo.ip}:${socketInfo.tcpPort} (clientID: ${socketInfo.clientID})`);
            console.log(`   Current isServer flag: ${socketInfo.isServer}`);
        } else {
            console.log(`⚠ Could not find socket info for server registration`);
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
            console.log(`📡 NAT type request from server tunnel for connection ${message.ConnectionID}`);
            // Mark this socket as being for a specific connection
            socketInfo.forConnectionID = message.ConnectionID;
        }

        socket.write(Buffer.from(JSON.stringify({
            ID: MessageTypes.NATTestBegin,
            NATTestPortOne: Config.NAT_TEST_PORT_ONE,
            NATTestPortTwo: Config.NAT_TEST_PORT_TWO
        })));
    }

    handleConnectionRequest(message, socket) {
        if (!message.hasOwnProperty('NATType')) return;

        const requestedIp = message.EndpointString;
        const clientSocketInfo = this.connectionManager.sockets.find(s => s.socket === socket);

        // Store client's NAT type from the ConnectionRequest message
        if (clientSocketInfo && message.NATType !== undefined) {
            clientSocketInfo.natType = message.NATType;
            console.log(`✓ Stored client NAT type: ${message.NATType} for ${clientSocketInfo.ip}`);
        }

        console.log(`🔍 Connection request for: ${requestedIp}`);
        console.log(`📋 Registered sockets:`);
        this.connectionManager.sockets.forEach(s => {
            console.log(`   - IP: ${s.ip}, isServer: ${s.isServer}, clientID: ${s.clientID}`);
        });

        // Find the registered server
        const serverSocket = this.connectionManager.sockets.find(s =>
            requestedIp.includes(s.ip) && s.isServer
        );

        if (!serverSocket) {
            this.sendServerNotAvailable(socket);
            console.log(`❌ Server not found for IP: ${requestedIp}`);
            return;
        }

        // Generate connection ID
        const connectionId = this.connectionManager.connectionId++;

        // Get client UDP info
        const clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => clientSocketInfo.ip.includes(info.ip)
        );

        if (!clientUDPInfo) {
            this.sendServerNotAvailable(socket);
            console.log(`❌ No UDP info for client: ${clientSocketInfo.ip}`);
            return;
        }

        const clientEndpoint = `${clientSocketInfo.ip}:${clientUDPInfo.port}`;

        // Store the connection pair
        this.connectionManager.currentConnectionPairs[connectionId] = {
            server_info: serverSocket.ip,
            client_info: clientSocketInfo.ip,
            server_connected: false,
            client_connected: false,
            server_clientID: serverSocket.clientID,
            client_clientID: clientSocketInfo.clientID,
            connection_start_time: Date.now()
        };

        console.log(`📨 Forwarding connection request to server ${serverSocket.ip} for client ${clientSocketInfo.ip}`);
        console.log(`   Connection ID: ${connectionId}, Client endpoint: ${clientEndpoint}`);

        // Forward the connection request to server's control connection
        const serverMessage = {
            ID: MessageTypes.ConnectionRequest,
            EndpointString: clientEndpoint,
            NATType: message.NATType,  // Client's NAT type
            ConnectionID: connectionId,
            ClientID: clientSocketInfo.clientID
        };

        console.log(`📤 Sending to server: ${JSON.stringify(serverMessage)}`);
        serverSocket.socket.write(Buffer.from(JSON.stringify(serverMessage)));

        // Don't send ConnectionBegin to client yet - wait for the server-side tunnel
        // to complete NAT detection and register its UDP port
        console.log(`⏳ Waiting for server tunnel to register UDP port for connection ${connectionId}`);

        // Set up connection timeout
        setTimeout(() => {
            const pair = this.connectionManager.currentConnectionPairs[connectionId];
            if (pair && (!pair.server_connected || !pair.client_connected)) {
                console.log(`⏱ Connection ${connectionId} timed out`);
                this.handleConnectionTimeout(connectionId);
            }
        }, 30000); // 30 second timeout
    }

    handleServerTunnelReady(connectionId, serverSocketInfo, natType) {
        console.log(`📡 Server tunnel ready for connection ${connectionId}`);

        const pair = this.connectionManager.currentConnectionPairs[connectionId];
        if (!pair) {
            console.log(`⚠ Connection ${connectionId} not found`);
            return;
        }

        // Update the connection pair with the actual per-client tunnel's clientID
        // (not the TunnelManager's clientID that was stored initially)
        pair.server_clientID = serverSocketInfo.clientID;
        console.log(`✓ Updated server_clientID to: ${serverSocketInfo.clientID}`);

        // Get server tunnel's UDP info - use the most recent UDP info from this IP
        // Since the server tunnel just completed NAT detection, its UDP port should be the latest
        const allServerUDPInfo = this.connectionManager.udpConnectionInfo.filter(
            info => serverSocketInfo.ip.includes(info.ip)
        );

        if (allServerUDPInfo.length === 0) {
            console.log(`⚠ No UDP info for server tunnel: ${serverSocketInfo.ip}`);
            return;
        }

        // Get the most recently added (last) entry for this IP - that's the server tunnel's port
        const serverUDPInfo = allServerUDPInfo[allServerUDPInfo.length - 1];
        const serverEndpoint = `${serverSocketInfo.ip}:${serverUDPInfo.port}`;
        console.log(`✓ Server tunnel endpoint: ${serverEndpoint} (from ${allServerUDPInfo.length} UDP entries)`);

        // Find the waiting client
        const clientSocketInfo = this.connectionManager.sockets.find(s => s.clientID === pair.client_clientID);
        if (!clientSocketInfo) {
            console.log(`⚠ Could not find client socket for connection ${connectionId}`);
            return;
        }

        // Get client's UDP info
        const clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => clientSocketInfo.ip.includes(info.ip)
        );

        if (!clientUDPInfo) {
            console.log(`⚠ No UDP info for client: ${clientSocketInfo.ip}`);
            return;
        }

        const clientEndpoint = `${clientSocketInfo.ip}:${clientUDPInfo.port}`;

        // Get client's NAT type (should be stored from ConnectionRequest)
        const clientNatType = clientSocketInfo.natType !== undefined ? clientSocketInfo.natType : -1;

        if (clientNatType === -1) {
            console.log(`⚠ Warning: Client NAT type not available for connection ${connectionId}`);
        }

        // Send ConnectionBegin to client with server's tunnel endpoint
        const clientMessage = {
            ID: MessageTypes.ConnectionBegin,
            EndpointString: serverEndpoint,
            NATType: natType,  // Server tunnel's NAT type
            ConnectionID: connectionId,
            IsServer: false
        };

        console.log(`📤 Sending ConnectionBegin to client: ${JSON.stringify(clientMessage)}`);
        clientSocketInfo.socket.write(Buffer.from(JSON.stringify(clientMessage)));

        // Also send ConnectionBegin to server tunnel with client's endpoint
        const serverMessage = {
            ID: MessageTypes.ConnectionBegin,
            EndpointString: clientEndpoint,
            NATType: clientNatType,  // Client's NAT type
            ConnectionID: connectionId,
            IsServer: true
        };

        console.log(`📤 Sending ConnectionBegin to server tunnel: ${JSON.stringify(serverMessage)}`);
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

        console.log(`📤 Completing connection ${connectionId}`);
        console.log(`   Server clientID: ${pair.server_clientID}, found: ${!!serverSocket}`);
        console.log(`   Client clientID: ${pair.client_clientID}, found: ${!!clientSocket}`);

        if (serverSocket) {
            serverSocket.socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.ConnectionComplete
            })));
            console.log(`   ✓ Sent ConnectionComplete to server tunnel`);
        }

        if (clientSocket) {
            clientSocket.socket.write(Buffer.from(JSON.stringify({
                ID: MessageTypes.ConnectionComplete
            })));
            console.log(`   ✓ Sent ConnectionComplete to client`);
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
            console.log(`⚠ ConnectionTimeout for unknown connection ID: ${connectionId}`);
            return;
        }

        console.log(`⏱ Connection ${connectionId} timed out - freeing server/client`);

        // Reset connection status for both server and client IPs
        this.connectionManager.udpConnectionInfo.forEach((info, index) => {
            if (pair.server_info.includes(info.ip) || pair.client_info.includes(info.ip)) {
                console.log(`  └─ Freeing ${info.ip}:${info.port} (was Busy for connection ${connectionId})`);
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

    getMessageTypeName(id) {
        return Object.keys(MessageTypes).find(key => MessageTypes[key] === id) || 'Unknown';
    }
}

module.exports = MessageHandler;