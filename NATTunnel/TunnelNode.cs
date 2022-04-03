using NATTunnel.Common;
using NATTunnel.Common.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace NATTunnel
{
    public class TunnelNode
    {
        //TODO: currently nothing ever sets this to false
        private bool running = true;
        private Random random = new Random();
        private Thread mainLoop;
        private TcpListener tcpServer;
        private Socket udp;
        private UdpConnection connection;
        private List<Client> clients = new List<Client>();
        private Dictionary<int, Client> clientMapping = new Dictionary<int, Client>();
        private TokenBucket connectionBucket;

        public TunnelNode()
        {
            int rateBytesPerSecond = NodeOptions.UploadSpeed * 1024;
            this.connectionBucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond);
            //1 second connnection buffer
            if (NodeOptions.IsServer)
            {
                SetupUDPSocket(NodeOptions.LocalPort);
            }
            else
            {
                SetupTCPServer();
                SetupUDPSocket(0);
            }
            connection = new UdpConnection(udp, ReceiveCallback);
            mainLoop = new Thread(MainLoop) { Name = "TunnelNode-MainLoop" };
            mainLoop.Start();
        }

        public void Stop()
        {
            connection.Stop();
            tcpServer?.Stop();
            udp.Close();
        }

        private void SetupUDPSocket(int port)
        {
            udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
            udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        }

        private void SetupTCPServer()
        {
            tcpServer = new TcpListener(new IPEndPoint(IPAddress.Any, NodeOptions.LocalPort));
            tcpServer.Start();
            tcpServer.BeginAcceptTcpClient(ConnectCallback, null);
        }

        public void MainLoop()
        {
            //This is the cleanup/heartbeating loop
            while (running)
            {
                long currentTime = DateTime.UtcNow.Ticks;

                // This needs to be a for loop, as the collection gets modifed during runtime, which throws
                for (int i = 0; i < clients.Count; i++)
                {
                    var client = clients[i];
                    if (client.connected) continue;

                    if (clientMapping.ContainsKey(client.id))
                    {
                        MediationClient.Remove(clientMapping[client.id].localTCPEndpoint);
                        clientMapping.Remove(client.id);
                    }
                    clients.Remove(client);
                }

                Thread.Sleep(100);
            }
        }

        private void ConnectCallback(IAsyncResult ar)
        {
            try
            {
                TcpClient tcp = tcpServer.EndAcceptTcpClient(ar);
                int newID = random.Next();
                Client client = new Client(newID, connection, tcp, connectionBucket);
                Console.WriteLine($"New TCP Client {client.id} from {tcp.Client.RemoteEndPoint}");
                ConnectUDPClient(client);
                clients.Add(client);
                clientMapping[client.id] = client;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error accepting socket: {e}");
            }
            tcpServer.BeginAcceptTcpClient(ConnectCallback, null);
        }

        private void ConnectUDPClient(Client client)
        {
            //TODO: why 4?
            foreach (IPEndPoint endpoint in NodeOptions.Endpoints)
            {
                for (int i = 0; i < 4; i++)
                {
                    NewConnectionRequest ncr = new NewConnectionRequest(client.id, $"end{client.localTCPEndpoint}");
                    connection.Send(ncr, endpoint);
                }
            }
        }

        private void ReceiveCallback(IMessage message, IPEndPoint endpoint)
        {
            if (message is NodeMessage nodeMessage)
            {
                int clientID = nodeMessage.Id;
                if (clientMapping.ContainsKey(clientID))
                {
                    Client client = clientMapping[clientID];
                    client.lastUdpRecvTime = DateTime.UtcNow.Ticks;
                }
            }

            switch (message)
            {
                case NewConnectionRequest request:
                {
                    if (!NodeOptions.IsServer) break;

                    //Do not connect protocol-incompatible clients.
                    if (request.ProtocolVersion != Header.PROTOCOL_VERSION) return;

                    Client client = null;
                    if (!clientMapping.ContainsKey(request.Id))
                    {
                        TcpClient tcp = new TcpClient(AddressFamily.InterNetwork);
                        try
                        {
                            tcp.Connect(NodeOptions.Endpoints[0]);
                            client = new Client(request.Id, connection, tcp, connectionBucket);
                            //add mapping for local tcp client and remote IP
                            clients.Add(client);
                            clientMapping.Add(client.id, client);
                            MediationClient.Add(client.localTCPEndpoint);
                        }
                        catch
                        {
                            //TODO do something about this null bandaid
                            Disconnect dis = new Disconnect(request.Id, "TCP server is currently not running", $"end{client?.localTCPEndpoint}");
                            connection.Send(dis, endpoint);
                            return;
                        }
                    }
                    else
                        client = clientMapping[request.Id];

                    NewConnectionReply connectionReply = new NewConnectionReply(request.Id, $"end{client.localTCPEndpoint}");
                    connection.Send(connectionReply, endpoint);
                    //Clamp to the clients download speed
                    Console.WriteLine($"Client {request.Id} download rate is {request.DownloadRate}KB/s");
                    if (request.DownloadRate < NodeOptions.UploadSpeed)
                    {
                        client.bucket.rateBytesPerSecond = request.DownloadRate * 1024;
                        client.bucket.totalBytes = client.bucket.rateBytesPerSecond;
                    }
                    //Prefer IPv6
                    if ((client.udpEndpoint == null) || ((client.udpEndpoint.AddressFamily == AddressFamily.InterNetwork) && (endpoint.AddressFamily == AddressFamily.InterNetworkV6)))
                    {
                        Console.WriteLine($"Client endpoint {client.id} set to: {endpoint}");
                        client.udpEndpoint = endpoint;
                    }
                    break;
                }

                case NewConnectionReply ncr:
                {
                    if (!NodeOptions.IsServer) break;

                    if (ncr.ProtocolVersion != Header.PROTOCOL_VERSION)
                    {
                        Console.WriteLine($"Unable to connect to incompatible server, our version: {Header.PROTOCOL_VERSION}, server: {ncr.ProtocolVersion}");
                        return;
                    }

                    if (clientMapping.ContainsKey(ncr.Id))
                    {
                        Client client = clientMapping[ncr.Id];
                        //Prefer IPv6
                        if ((client.udpEndpoint == null) || ((client.udpEndpoint.AddressFamily == AddressFamily.InterNetwork) && (endpoint.AddressFamily == AddressFamily.InterNetworkV6)))
                        {
                            Console.WriteLine($"Server endpoint {client.id} set to: {endpoint}");
                            client.udpEndpoint = endpoint;
                        }
                        //Clamp to the servers download speed
                        Console.WriteLine($"Servers download rate is {ncr.DownloadRate}KB/s");
                        if (ncr.DownloadRate < NodeOptions.UploadSpeed)
                        {
                            client.bucket.rateBytesPerSecond = ncr.DownloadRate * 1024;
                            client.bucket.totalBytes = client.bucket.rateBytesPerSecond;
                        }
                    }
                    break;
                }

                case Data data:
                {
                    if (clientMapping.ContainsKey(data.Id))
                    {
                        Client client = clientMapping[data.Id];
                        //TODO: WHY IS THIS NECESSARY!?!?!?
                        client.udpEndpoint = endpoint;
                        if (client.tcp != null) client.ReceiveData(data, true);
                    }
                    break;
                }

                case Ack ack:
                {
                    if (clientMapping.ContainsKey(ack.Id))
                    {
                        Client client = clientMapping[ack.Id];
                        client.ReceiveAck(ack);
                    }
                    break;
                }

                case PingRequest pingRequest:
                {
                    if (clientMapping.ContainsKey(pingRequest.Id))
                    {
                        Client client = clientMapping[pingRequest.Id];
                        PingReply preply = new PingReply(pingRequest.Id, pingRequest.SendTime, $"end{client.localTCPEndpoint}");
                        connection.Send(preply, endpoint);
                    }
                    break;
                }
                case PingReply pingReply:
                {
                    long currentTime = DateTime.UtcNow.Ticks;
                    long timeDelta = currentTime - pingReply.SendTime;
                    int timeMs = (int)(timeDelta / TimeSpan.TicksPerMillisecond);
                    if (clientMapping.ContainsKey(pingReply.Id))
                    {
                        Client client = clientMapping[pingReply.Id];
                        client.latency = timeMs;
                    }
                    break;
                }
                case Disconnect disconnect:
                {
                    if (clientMapping.ContainsKey(disconnect.Id))
                    {
                        Client client = clientMapping[disconnect.Id];
                        client.Disconnect("Remote side requested a disconnect");
                        Console.WriteLine($"Stream {disconnect.Id} remotely disconnected because: {disconnect.Reason}");
                    }
                    break;
                }
            }
        }
    }
}