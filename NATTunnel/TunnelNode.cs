using NATTunnel.Common;
using NATTunnel.Common.Messages;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NATTunnel.Common.Messages.Types;

namespace NATTunnel;

public class TunnelNode
{
    private bool running = true;
    private readonly Random random = new Random();
    private TcpListener tcpServer;
    private Socket udp;
    private Thread mainLoop;
    private readonly UdpConnection udpConnection;
    private readonly List<Client> clients = new List<Client>();
    private readonly Dictionary<int, Client> clientMapping = new Dictionary<int, Client>();
    private readonly TokenBucket connectionBucket;

    public TunnelNode()
    {
        int rateBytesPerSecond = NodeOptions.UploadSpeed * 1024;
        connectionBucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond);
        //1 second connection buffer
        if (NodeOptions.IsServer)
        {
            SetupUDPSocket(NodeOptions.LocalPort);
        }
        else
        {
            SetupTCPServer();
            SetupUDPSocket(0);
        }
        udpConnection = new UdpConnection(udp, ReceiveCallback);

        mainLoop = new Thread(MainLoop) { Name = "TunnelNode-MainLoop" };
        mainLoop.Start();
    }

    public void Start()
    {
        /*mainTask = new Thread(MainLoop);
        mainTask.Start();*/
    }

    public void Stop()
    {
        //running = false;
        udpConnection.Stop();
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

    private void MainLoop()
    {
        //This is the cleanup/heartbeating loop
        while (running)
        {
            // This needs to be a for loop, as the collection gets modified during runtime, which throws.
            for (int i = 0; i < clients.Count; i++)
            {
                Client client = clients[i];
                if (client.Connected) continue;

                if (clientMapping.ContainsKey(client.Id))
                {
                    MediationClient.Remove(clientMapping[client.Id].LocalTcpEndpoint);
                    clientMapping.Remove(client.Id);
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
            Client client = new Client(newID, udpConnection, tcp, connectionBucket);
            Console.WriteLine($"New TCP Client {client.Id} from {tcp.Client.RemoteEndPoint}");
            ConnectUDPClient(client);
            clients.Add(client);
            clientMapping[client.Id] = client;
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
        for (int i = 0; i < 4; i++)
        {
            NewConnectionRequest ncr = new NewConnectionRequest(client.Id, $"end{client.LocalTcpEndpoint}");
            udpConnection.Send(ncr, NodeOptions.Endpoint);
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
                client.LastUdpRecvTime = DateTime.UtcNow.Ticks;
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
                        tcp.Connect(NodeOptions.Endpoint);
                        client = new Client(request.Id, udpConnection, tcp, connectionBucket);
                        //add mapping for local tcp client and remote IP
                        clients.Add(client);
                        clientMapping.Add(client.Id, client);
                        MediationClient.Add(client.LocalTcpEndpoint);
                    }
                    catch
                    {
                        //TODO do something about this null band-aid
                        Disconnect dis = new Disconnect(request.Id, "TCP server is currently not running", $"end{client?.LocalTcpEndpoint}");
                        udpConnection.Send(dis, endpoint);
                        return;
                    }
                }
                else
                    client = clientMapping[request.Id];

                NewConnectionReply connectionReply = new NewConnectionReply(request.Id, $"end{client.LocalTcpEndpoint}");
                udpConnection.Send(connectionReply, endpoint);
                //Clamp to the clients download speed
                Console.WriteLine($"Client {request.Id} download rate is {request.DownloadRate}KB/s");
                if (request.DownloadRate < NodeOptions.UploadSpeed)
                {
                    client.Bucket.RateBytesPerSecond = request.DownloadRate * 1024;
                    client.Bucket.TotalBytes = client.Bucket.RateBytesPerSecond;
                }
                //Prefer IPv6
                if ((client.UdpEndpoint == null) || ((client.UdpEndpoint.AddressFamily == AddressFamily.InterNetwork) && (endpoint.AddressFamily == AddressFamily.InterNetworkV6)))
                {
                    Console.WriteLine($"Client endpoint {client.Id} set to: {endpoint}");
                    client.UdpEndpoint = endpoint;
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
                    if ((client.UdpEndpoint == null) || ((client.UdpEndpoint.AddressFamily == AddressFamily.InterNetwork) && (endpoint.AddressFamily == AddressFamily.InterNetworkV6)))
                    {
                        Console.WriteLine($"Server endpoint {client.Id} set to: {endpoint}");
                        client.UdpEndpoint = endpoint;
                    }
                    //Clamp to the servers download speed
                    Console.WriteLine($"Servers download rate is {ncr.DownloadRate}KB/s");
                    if (ncr.DownloadRate < NodeOptions.UploadSpeed)
                    {
                        client.Bucket.RateBytesPerSecond = ncr.DownloadRate * 1024;
                        client.Bucket.TotalBytes = client.Bucket.RateBytesPerSecond;
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
                    client.UdpEndpoint = endpoint;
                    if (client.TCPClient != null) client.ReceiveData(data);
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
                    PingReply pingReply = new PingReply(pingRequest.Id, pingRequest.SendTime, $"end{client.LocalTcpEndpoint}");
                    udpConnection.Send(pingReply, endpoint);
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
                    client.Latency = timeMs;
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