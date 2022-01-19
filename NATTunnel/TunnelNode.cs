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
        private NodeOptions options;
        private TcpListener tcpServer;
        private Socket udp;
        private UdpConnection connection;
        private List<Client> clients = new List<Client>();
        private Dictionary<int, Client> clientMapping = new Dictionary<int, Client>();
        private IPAddress[] masterServerAddresses = Dns.GetHostAddresses("DarkTunnel.godarklight.privatedns.org");
        //Master state
        private long nextMasterTime = 0;
        private TokenBucket connectionBucket;

        public TunnelNode(NodeOptions options)
        {
            int rateBytesPerSecond = options.uploadSpeed * 1024;
            this.connectionBucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond);
            //1 second connnection buffer
            this.options = options;
            if (options.isServer)
            {
                SetupUDPSocket(options.localPort);
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
            tcpServer = new TcpListener(new IPEndPoint(IPAddress.Any, options.localPort));
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

                if (options.isServer && (options.masterServerID != 0) && (currentTime > nextMasterTime))
                {
                    //Send master registers every minute
                    nextMasterTime = currentTime + DateTime.UtcNow.Ticks + TimeSpan.TicksPerMinute;
                    MasterServerPublishRequest mspr = new MasterServerPublishRequest(options.masterServerID, options.masterServerSecret, options.localPort);
                    foreach (IPAddress masterAddr in masterServerAddresses)
                        connection.Send(mspr, new IPEndPoint(masterAddr, 16702));
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
                Client client = new Client(options, newID, connection, tcp, connectionBucket);
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
            if (options.masterServerID == 0)
            {
                foreach (IPEndPoint endpoint in options.endpoints)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        NewConnectionRequest ncr = new NewConnectionRequest(client.id, options.downloadSpeed, $"end{client.localTCPEndpoint}");
                        connection.Send(ncr, endpoint);
                    }
                }
            }
            else
            {
                foreach (IPAddress addr in masterServerAddresses)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        MasterServerInfoRequest msir = new MasterServerInfoRequest(client.id);
                        connection.Send(msir, new IPEndPoint(addr, 16702));
                    }
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
                case NewConnectionRequest nc:
                {
                    if (!options.isServer) break;

                    NewConnectionReply ncr = new NewConnectionReply(nc.Id, Header.PROTOCOL_VERSION, options.downloadSpeed);
                    //Do not connect protocol-incompatible clients.
                    if (nc.ProtocolVersion != Header.PROTOCOL_VERSION) return;

                    Client client = null;
                    if (!clientMapping.ContainsKey(ncr.Id))
                    {
                        TcpClient tcp = new TcpClient(AddressFamily.InterNetwork);
                        try
                        {
                            tcp.Connect(options.endpoints[0]);
                            client = new Client(options, nc.Id, connection, tcp, connectionBucket);
                            //add mapping for local tcp client and remote IP
                            clients.Add(client);
                            clientMapping.Add(client.id, client);
                            MediationClient.Add(client.localTCPEndpoint);
                        }
                        catch
                        {
                            //TODO do something about this null bandaid
                            Disconnect dis = new Disconnect(nc.Id, "TCP server is currently not running", $"end{client?.localTCPEndpoint}");
                            connection.Send(dis, endpoint);
                            return;
                        }
                    }
                    else
                        client = clientMapping[nc.Id];

                    //TODO: is this necessary down here?
                    ncr.ep = $"end{client.localTCPEndpoint}";
                    connection.Send(ncr, endpoint);
                    //Clamp to the clients download speed
                    Console.WriteLine($"Client {nc.Id} download rate is {nc.DownloadRate}KB/s");
                    if (nc.DownloadRate < options.uploadSpeed)
                    {
                        client.bucket.rateBytesPerSecond = nc.DownloadRate * 1024;
                        client.bucket.totalBytes = client.bucket.rateBytesPerSecond;
                    }
                    //Prefer IPv6
                    //TODO: whats the order here?
                    if (client.udpEndpoint == null || (client.udpEndpoint.AddressFamily == AddressFamily.InterNetwork) && (endpoint.AddressFamily == AddressFamily.InterNetworkV6))
                    {
                        Console.WriteLine($"Client endpoint {client.id} set to: {endpoint}");
                        client.udpEndpoint = endpoint;
                    }
                    break;
                }

                case NewConnectionReply ncr:
                {
                    if (!options.isServer) break;

                    if (ncr.protocol_version != Header.PROTOCOL_VERSION)
                    {
                        Console.WriteLine($"Unable to connect to incompatible server, our version: {Header.PROTOCOL_VERSION}, server: {ncr.protocol_version}");
                        return;
                    }

                    if (clientMapping.ContainsKey(ncr.Id))
                    {
                        Client c = clientMapping[ncr.Id];
                        //Prefer IPv6
                        //TODO: whats the order hre
                        if (c.udpEndpoint == null || c.udpEndpoint.AddressFamily == AddressFamily.InterNetwork && endpoint.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            Console.WriteLine($"Server endpoint {c.id} set to: {endpoint}");
                            c.udpEndpoint = endpoint;
                        }
                        //Clamp to the servers download speed
                        Console.WriteLine($"Servers download rate is {ncr.downloadRate}KB/s");
                        if (ncr.downloadRate < options.uploadSpeed)
                        {
                            c.bucket.rateBytesPerSecond = ncr.downloadRate * 1024;
                            c.bucket.totalBytes = c.bucket.rateBytesPerSecond;
                        }
                    }
                    break;
                }

                case MasterServerInfoReply msir:
                {
                    Client client = null;
                    if (clientMapping.ContainsKey(msir.client))
                        client = clientMapping[msir.client];
                    
                    if (client == null) return;

                    //Shouldn't happen but we should probably check this.
                    if (msir.server != options.masterServerID) return;
                    
                    if (!msir.status)
                    {
                        Console.WriteLine($"Cannot connect: {msir.message}");
                        return;
                    }

                    foreach (IPEndPoint msirEndpoint in msir.endpoints)
                    {
                        for (int i = 0; i < 4; i++)
                        {
                            NewConnectionRequest ncr = new NewConnectionRequest(msir.client, options.downloadSpeed, $"end{client.localTCPEndpoint}");
                            Console.WriteLine($"MSIR connect: {msirEndpoint}");
                            connection.Send(ncr, msirEndpoint);
                        }
                    }
                    break;
                }

                case MasterServerPublishReply mspr:
                {
                    Console.WriteLine($"Publish Reply for {mspr.id}, registered {mspr.status}, {mspr.message}");
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
                case PrintConsole printConsole:
                {
                    Console.WriteLine($"Remote Message: {printConsole.Message}");
                    break;
                }
                case Disconnect disconnect:
                {
                    if (clientMapping.ContainsKey(disconnect.Id))
                    {
                        Client client = clientMapping[disconnect.Id];
                        client.Disconnect("Remote side requested a disconnect");
                        Console.WriteLine($"Stream {disconnect.Id} remotely disconnected because: {disconnect.reason}");
                    }
                    break;
                }
            }
        }
    }
}