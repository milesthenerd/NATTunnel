const { MessageTypes, StatusTypes, Config } = require('./constants');
const { Buffer } = require('buffer');

class MessageHandler {
    constructor(connectionManager) {
        this.connectionManager = connectionManager;
    }

    handleTCPMessage(message, socket) {
        if (!message) return;

        switch (message.ID) {
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
                this.handleConnectionTimeout(socket);
                break;
        }
    }

    handleNATTypeRequest(message, socket) {
        const socketInfo = this.connectionManager.sockets.find(s => s.socket === socket);
        if (socketInfo) {
            socketInfo.localPort = message.LocalPort;
            socketInfo.clientID = message.ClientID;
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
        const targetSocket = this.connectionManager.sockets.find(s => requestedIp.includes(s.ip));

        if (!targetSocket) {
            this.sendServerNotAvailable(socket);
            return;
        }

        const isBusy = this.connectionManager.udpConnectionInfo.some(info =>
            requestedIp.includes(info.ip) && info.status.type === StatusTypes.Busy
        );

        if (isBusy) {
            this.sendServerNotAvailable(socket);
            return;
        }

        this.initiateConnection(socket, targetSocket, message.NATType);
    }

    initiateConnection(clientSocket, serverSocket, clientNATType) {
        const connectionId = this.connectionManager.connectionId++;
        let serverEndpoint = null;
        let clientEndpoint = null;

        // Set up server endpoint
        const serverUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => serverSocket.ip.includes(info.ip) && info.status.type !== StatusTypes.Busy
        );
        if (serverUDPInfo) {
            serverEndpoint = `${serverSocket.ip}:${serverUDPInfo.port}`;
            serverUDPInfo.status = { id: connectionId, type: StatusTypes.Busy };
        }

        // Set up client endpoint
        const clientSocketInfo = this.connectionManager.sockets.find(
            s => s.socket.remoteAddress === clientSocket.remoteAddress && s.socket === clientSocket
        );
        const clientUDPInfo = this.connectionManager.udpConnectionInfo.find(
            info => clientSocketInfo.ip.includes(info.ip) && info.status.type !== StatusTypes.Busy
        );
        if (clientUDPInfo) {
            clientEndpoint = `${clientSocketInfo.ip}:${clientUDPInfo.port}`;
            clientUDPInfo.status = { id: connectionId, type: StatusTypes.Busy };
        }

        if (serverEndpoint && clientEndpoint) {
            // Store the connection state first
            this.connectionManager.currentConnectionPairs[connectionId] = {
                server_info: serverSocket.ip,
                client_info: clientSocketInfo.ip,
                server_connected: false,
                client_connected: false,
                server_clientID: serverSocket.clientID,
                client_clientID: clientSocketInfo.clientID,
                connection_start_time: Date.now()
            };

            // Send connection info to both parties
            const serverMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: clientEndpoint,
                NATType: clientNATType,
                ConnectionID: connectionId,
                IsServer: true // Indicate this is the listening server
            };

            const clientMessage = {
                ID: MessageTypes.ConnectionBegin,
                EndpointString: serverEndpoint,
                NATType: serverSocket.natType,
                ConnectionID: connectionId,
                IsServer: false
            };

            // Send to server first to ensure it's ready
            serverSocket.socket.write(Buffer.from(JSON.stringify(serverMessage)));

            // Short delay to ensure server processes first
            setTimeout(() => {
                clientSocket.write(Buffer.from(JSON.stringify(clientMessage)));
            }, 100);

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

        // Notify both server and client
        const serverSocket = this.connectionManager.sockets.find(s => pair.server_info.includes(s.ip));
        const clientSocket = this.connectionManager.sockets.find(s => pair.client_info.includes(s.ip));

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
        if (!pair) return;

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
}

module.exports = MessageHandler;