using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;
using NATTunnel.Common;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace NATTunnel;

public static class MediationClient
{
    //TODO: entire class should get reviewed and eventually split up into smaller classes
    //TODO: do we really want to have this static? Why not just a normal class, with normal constructor?
    private static readonly TcpClient tcpClient = new TcpClient();
    private static UdpClient udpClient; // set in constructor
    private static NetworkStream tcpClientStream;
    private static Task tcpClientTask;
    private static CancellationTokenSource tcpClientTaskCancellationToken = new CancellationTokenSource();
    private static Task udpClientTask;
    private static CancellationTokenSource udpClientTaskCancellationToken = new CancellationTokenSource();
    private static Task udpServerTask;
    private static CancellationTokenSource udpServerTaskCancellationToken = new CancellationTokenSource();
    private static readonly IPEndPoint endpoint;
    private static int natTestPortOne = 6511;
    private static int natTestPortTwo = 6512;
    private static readonly IPEndPoint programEndpoint;
    private static IPAddress targetPeerIp;
    private static int targetPeerPort;
    private static int localAppPort = 65535;
    private static int holePunchReceivedCount;
    private static bool connected;
    private static readonly IPAddress remoteIp;
    private static int mediationClientPort;
    private static readonly bool isServer;
    private static readonly List<IPEndPoint> connectedClients = new List<IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingLocalTCPtoRemote = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingLocalUDPtoRemote = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingRemoteUDPtoLocal = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, int> timeoutClients = new Dictionary<IPEndPoint, int>();
    private static IPEndPoint mostRecentEndPoint = new IPEndPoint(IPAddress.Loopback, 65535);
    private static NATType natType = NATType.Unknown;
    private static List<UdpClient> symmetricConnectionUdpProbes = new List<UdpClient>();
    private static int currentConnectionID = 0;
    public static IPAddress localIP = IPAddress.Parse("10.5.0.2");
    private static FrameCapture test;

    static MediationClient()
    {
        test = new FrameCapture();
        test.Start();

        try
        {
            udpClient = new UdpClient(NodeOptions.MediationClientPort);
        }
        catch (SocketException)
        {
            Console.WriteLine("Can only run one instance of NATTunnel, because every Socket can only be used once.");
            Environment.Exit(-1);
        }

        // Windows-specific udpClient switch
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // ReSharper disable once IdentifierTypo - taken from here:
            // https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_connreset-opcode-setting-i-t3
            const int SIO_UDP_CONNRESET = -1744830452;
            udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }

        endpoint = NodeOptions.MediationIp;
        programEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.LocalPort);
        remoteIp = NodeOptions.RemoteIp;
        mediationClientPort = NodeOptions.MediationClientPort;
        isServer = NodeOptions.IsServer;

        //Try to send initial msg to mediator
        try
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    public static void Send(byte[] packetData)
    {
        if(isServer)
        {
            foreach (IPEndPoint client in connectedClients)
            {
                udpClient.Send(packetData, packetData.Length, client);
            }
        }
        else
        {
            udpClient.Send(packetData, packetData.Length, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}"));
        }
    }

    public static void AddTCP(IPEndPoint localEndpoint)
    {
        if (!mappingLocalTCPtoRemote.ContainsKey(localEndpoint))
            mappingLocalTCPtoRemote.Add(localEndpoint, mostRecentEndPoint);
    }

    public static void RemoveTCP(IPEndPoint localEndpoint)
    {
        mappingLocalTCPtoRemote.Remove(localEndpoint);
    }

    public static void AddUDP(IPEndPoint localEndpoint)
    {
        if (!mappingLocalUDPtoRemote.ContainsKey(localEndpoint))
            mappingLocalUDPtoRemote.Add(localEndpoint, mostRecentEndPoint);

        if (!mappingRemoteUDPtoLocal.ContainsKey(mostRecentEndPoint))
            mappingRemoteUDPtoLocal.Add(mostRecentEndPoint, localEndpoint);
    }

    public static void RemoveUDP(IPEndPoint localEndpoint)
    {
        mappingRemoteUDPtoLocal.Remove(mappingLocalUDPtoRemote[localEndpoint]);
        mappingLocalUDPtoRemote.Remove(localEndpoint);
    }

    private static void OnTimedEvent(object source, ElapsedEventArgs e)
    {
        MediationMessage message = new MediationMessage(MediationMessageType.KeepAlive);
        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
        //If not connected to remote endpoint, send remote IP to mediator
        if (!connected || isServer)
        {
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
            Console.WriteLine("Sent");
        }
        //If connected to remote endpoint, send keep alive message
        if (connected)
        {
            if (isServer)
            {
                foreach (IPEndPoint client in connectedClients)
                {
                    udpClient.Send(sendBuffer, sendBuffer.Length, client);
                }
            }
            else
            {
                udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
            }
            Console.WriteLine("Keep alive");
        }

        foreach ((IPEndPoint key, int value) in timeoutClients)
        {
            Console.WriteLine($"time left: {value}");
            if (value >= 1)
            {
                int timeRemaining = value;
                timeRemaining--;
                timeoutClients[key] = timeRemaining;
            }
            else
            {
                Console.WriteLine($"timed out {key}");
                connectedClients.Remove(key);
                timeoutClients.Remove(key);
            }
        }
    }

    public static void Start()
    {
        //Attempt to connect to mediator
        try
        {
            tcpClient.Connect(endpoint);
        }
        //TODO: Have exception silent if can't connect? Quit program entirely?
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        //Once connected, begin listening
        if (!tcpClient.Connected)
            return;

        tcpClientStream = tcpClient.GetStream();
        tcpClientTask = new Task(TcpListenLoop);
        tcpClientTask.Start();
    }

    private static void UdpClient()
    {
        //Set client targetPeerIp to remote endpoint IP
        targetPeerIp = remoteIp;
        //Begin listening
        Task.Run(() => UdpClientListenLoop(udpClientTaskCancellationToken.Token));
        //Start timer for hole punch init and keep alive
        Timer timer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = true
        };
        timer.Elapsed += OnTimedEvent;
    }

    private static void UdpServer()
    {
        //Set client targetPeerIp to something no client will have
        targetPeerIp = IPAddress.None;
        //Begin listening
        udpServerTask = new Task(UdpServerListenLoop);
        udpServerTask.Start();
        //Start timer for hole punch init and keep alive
        Timer timer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = true
        };
        timer.Elapsed += OnTimedEvent;
    }

    private static void UdpClientListenLoop(CancellationToken token)
    {
        //Init an IPEndPoint that will be populated with the sender's info
        int randID = new Random().Next();

        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
        Console.WriteLine($"is this even starting {listenEndpoint}");
        while (!token.IsCancellationRequested)
        {
            Console.WriteLine($"ahh yes the randID for this task is {randID}");
            mostRecentEndPoint = listenEndpoint;

            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient),"udpClient.Receive(ref listenEP)");

            string receivedString = Encoding.ASCII.GetString(receiveBuffer);

            MediationMessage receivedMessage;

            byte[] tunnelData = new byte[1500];

            try
            {
                receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
                Console.WriteLine("VALID?");
                Console.WriteLine(receivedString);
            }
            catch
            {
                Console.WriteLine("INVALID MESSAGE RECEIVED, IGNORING");
                Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");
                test.Send(receiveBuffer);
                continue;
            }

            Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");

            if (Equals(listenEndpoint.Address, IPAddress.Loopback) && (listenEndpoint.Port != mediationClientPort))
            {
                localAppPort = listenEndpoint.Port;
            }

            Console.WriteLine(localAppPort);

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
                holePunchReceivedCount++;
                //TODO: random hardcoded value
                if (holePunchReceivedCount >= 5 && !connected)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.ReceivedPeer);
                    message.ConnectionID = currentConnectionID;
                    message.IsServer = isServer;
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    Console.WriteLine($"sending {message.Serialize()}");
                    tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                }
            }

            switch(receivedMessage.ID)
            {
                case MediationMessageType.HolePunchAttempt:
                {
                    Console.WriteLine("POG");
                }
                break;
                case MediationMessageType.NATTunnelData:
                {
                    tunnelData = receivedMessage.Data;
                    Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                    /*
                    IPAddress receivedIp = null;
                    int receivedPort = 0;

                    if (Equals(listenEndpoint.Address, endpoint.Address))
                    {
                        //TODO: why do we need to constantly re-get the ip on where to send stuff to?
                        string[] msgArray = tunnelData.Split(":");

                        receivedIp = IPAddress.Parse(msgArray[0]);
                        receivedPort = 0;
                        if (msgArray.Length > 1)
                            receivedPort = Int32.Parse(msgArray[1]);
                    }

                    if (Equals(receivedIp, targetPeerIp) && holePunchReceivedCount < 5)
                    {
                        //targetPeerPort = receivedPort;
                        Console.WriteLine($"targetPeerIp:{targetPeerIp}");
                        Console.WriteLine($"targetPeerPort:{targetPeerPort}");
                        if (targetPeerPort != 0)
                        {
                            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                            udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                            Console.WriteLine("punching");
                        }
                    }
                    */

                    if (connected && Equals(listenEndpoint.Address, IPAddress.Loopback))
                        //TODO: weird consistent way to crash here because targetPeerPort is 0, because it didn't into the if holePunchCount < 5 from above, because receivedIP is null
                        //https://cdn.discordapp.com/attachments/806611530438803458/933443905066790962/unknown.png
                        udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));

                    if (!connected || !Equals(listenEndpoint.Address, targetPeerIp)) continue;

                    try
                    {
                        //TODO: sometimes fails here for whatever reason
                        if (!Equals(Encoding.ASCII.GetString(tunnelData), ""))
                        {
                            Console.WriteLine("Sending to localAppPort");
                            udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(IPAddress.Loopback, localAppPort));
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
                break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                {
                    if (natType != NATType.Symmetric)
                    {
                        targetPeerIp = listenEndpoint.Address;
                        targetPeerPort = listenEndpoint.Port;
                    }
                }
                break;
            }
        }
        
        Console.WriteLine($"WHAT THE HECK IS GOING ON WHY ISN'T THIS HITTING rand {randID}");
    }

    private static void UdpServerListenLoop()
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
        while (true)
        {
            Console.WriteLine(mappingLocalTCPtoRemote.Count);
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

            string receivedString = Encoding.ASCII.GetString(receiveBuffer);

            MediationMessage receivedMessage;

            byte[] tunnelData = new byte[1500];

            try
            {
                receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
                Console.WriteLine("VALID?");
            }
            catch
            {
                Console.WriteLine("INVALID MESSAGE RECEIVED, IGNORING");
                Console.WriteLine($"length {timeoutClients.Count} and {connectedClients.Count}");
                Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", receiveBuffer.Length, listenEndpoint.Address, listenEndpoint.Port);
                test.Send(receiveBuffer);
                continue;
            }

            mostRecentEndPoint = listenEndpoint;

            foreach ((IPEndPoint key, int _) in timeoutClients)
            {
                bool exists = connectedClients.Any(value2 => Equals(key, value2));

                if (!exists)
                {
                    Console.WriteLine($"removing {key}");
                    timeoutClients.Remove(key);
                }

                Console.WriteLine($"{key} and {listenEndpoint}");
                if (key.Address.ToString() == listenEndpoint.Address.ToString())
                    timeoutClients[key] = 5;
            }

            Console.WriteLine($"length {timeoutClients.Count} and {connectedClients.Count}");
            Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", receiveBuffer.Length, listenEndpoint.Address, listenEndpoint.Port);

            if (!connectedClients.Exists(element => element.Address.ToString() == listenEndpoint.Address.ToString()) && Equals(listenEndpoint.Address, targetPeerIp))
            {
                connectedClients.Add(listenEndpoint);
                timeoutClients.Add(listenEndpoint, 5);
                Console.WriteLine("added {0}:{1} to list", listenEndpoint.Address, listenEndpoint.Port);
            }

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
                if (holePunchReceivedCount == 0) holePunchReceivedCount++;
                if (holePunchReceivedCount >= 1 && !connected)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.ReceivedPeer);
                    message.ConnectionID = currentConnectionID;
                    message.IsServer = isServer;
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    Console.WriteLine($"sending {message.Serialize()}");
                    tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                }
            }

            /*
            IPAddress receivedIp = null;
            int receivedPort = 0;
            if (Equals(receivedIp, targetPeerIp) && holePunchReceivedCount < 5)
            {
                targetPeerPort = receivedPort;
                Console.WriteLine($"targetPeerIp:{targetPeerIp}");
                Console.WriteLine($"targetPeerPort:{targetPeerPort}");
                if (targetPeerPort != 0)
                {
                    byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    Console.WriteLine("punching");
                }
            }
            */

            switch(receivedMessage.ID)
            {
                case MediationMessageType.HolePunchAttempt:
                {
                    Console.WriteLine("POG");
                }
                break;
                case MediationMessageType.NATTunnelData:
                {
                    tunnelData = receivedMessage.Data;
                    Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                    if (connected && Equals(listenEndpoint.Address, IPAddress.Loopback))
                    {
                        IPEndPoint destEndpoint = new IPEndPoint(IPAddress.Loopback, 0);

                        string receiveString = Encoding.ASCII.GetString(tunnelData);
                        int splitPos = receiveString.IndexOf("end", StringComparison.Ordinal);
                        if (splitPos > 0)
                        {
                            string[] receiveSplit = receiveString.Split("end");
                            Console.WriteLine("end");
                            if (receiveSplit.Length > 1)
                            {
                                string endpointStr = receiveSplit[1];
                                string[] endpointSplit = endpointStr.Split(":");
                                Console.WriteLine("split :");
                                if (endpointSplit.Length > 1)
                                {
                                    IPAddress address;
                                    int port;
                                    bool checkMap = true;

                                    if (!IPAddress.TryParse(endpointSplit[0], out address))
                                    {
                                        address = IPAddress.Loopback;
                                        checkMap = false;
                                    }

                                    if (!Int32.TryParse(endpointSplit[1], out port))
                                    {
                                        port = 65535;
                                        checkMap = false;
                                    }

                                    Console.WriteLine($"{address}:{port}");

                                    if (checkMap)
                                    {
                                        try
                                        {
                                            destEndpoint = mappingLocalTCPtoRemote[new IPEndPoint(address, port)];
                                        }
                                        catch (Exception e)
                                        {
                                            Console.WriteLine(e);
                                        }
                                    }
                                    Console.WriteLine("dest port");
                                    Console.WriteLine(destEndpoint);
                                    udpClient.Send(receiveBuffer, receiveBuffer.Length, destEndpoint);
                                }
                            }
                        }

                        if (NodeOptions.ConnectionType == ConnectionTypes.UDP)
                        {
                            try
                            {
                                destEndpoint = mappingLocalUDPtoRemote[new IPEndPoint(listenEndpoint.Address, listenEndpoint.Port)];
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }

                            Console.WriteLine("dest port udp");
                            Console.WriteLine(destEndpoint);
                            udpClient.Send(receiveBuffer, receiveBuffer.Length, destEndpoint);
                        }
                    }

                    if (NodeOptions.ConnectionType == ConnectionTypes.TCP)
                    {
                        foreach (IPEndPoint client in connectedClients)
                        {
                            if (!connected || !Equals(listenEndpoint.Address, client.Address)) continue;
                            Console.WriteLine("ARE WE JUST NOT HITTING THIS CONDITION????");

                            udpClient.Send(receiveBuffer, receiveBuffer.Length, programEndpoint);
                        }
                    }
                    else
                    {
                        if (!connected || Encoding.ASCII.GetString(tunnelData) == "") continue;

                        foreach (IPEndPoint client in connectedClients)
                        {
                            if (listenEndpoint.Address.ToString() != client.Address.ToString()) continue;

                            IPEndPoint destEndpoint = new IPEndPoint(IPAddress.Loopback, 65535);
                            try
                            {
                                destEndpoint = mappingRemoteUDPtoLocal[new IPEndPoint(listenEndpoint.Address, listenEndpoint.Port)];
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }

                            Console.WriteLine("udp dest endpoint");
                            Console.WriteLine(destEndpoint);

                            udpClient.Send(tunnelData, tunnelData.Length, new IPEndPoint(IPAddress.Loopback, destEndpoint.Port));
                        }
                    }
                }
                break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                {
                    if (natType != NATType.Symmetric)
                    {
                        targetPeerIp = listenEndpoint.Address;
                        targetPeerPort = listenEndpoint.Port;
                    }
                }
                break;
            }
            if (udpServerTaskCancellationToken.Token.IsCancellationRequested)
                return;
        }
    }

    private static void TcpListenLoop()
    {
        while (tcpClient.Connected)
        {
            try
            {
                byte[] receiveBuffer = new byte[tcpClient.ReceiveBufferSize];
                //TODO: sometimes fails here
                int bytesRead = tcpClientStream.Read(receiveBuffer, 0, tcpClient.ReceiveBufferSize);
                string receivedString = Encoding.ASCII.GetString(receiveBuffer, 0, bytesRead);
                MediationMessage receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
                Console.WriteLine("Received: " + receivedString);

                void PollForAvailableServer(object source, ElapsedEventArgs e)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.ConnectionRequest);
                    message.SetEndpoint(new IPEndPoint(remoteIp, IPEndPoint.MinPort));
                    message.NATType = natType;
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                }

                void TryConnect(object source, ElapsedEventArgs e)
                {
                    if(holePunchReceivedCount <= 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.HolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                }

                void TryConnectFromSymmetric(object source, ElapsedEventArgs e)
                {
                    if(holePunchReceivedCount >= 1 && holePunchReceivedCount <= 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        Console.WriteLine(udpClient.Client.LocalEndPoint);
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }

                    if(holePunchReceivedCount < 1)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        foreach (UdpClient probe in symmetricConnectionUdpProbes)
                        {
                            probe.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                        }
                    }
                }

                void TryConnectToSymmetric(object source, ElapsedEventArgs e)
                {
                    if(holePunchReceivedCount >= 1 && holePunchReceivedCount < 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }

                    if(holePunchReceivedCount < 1)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());

                        Random randPort = new Random();
                        for (int i = 0; i < 100; i++)
                        {
                            udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, randPort.Next(1024, 65536)));
                        }
                    }
                }

                //When one of the clients has holePunchReceivedCount hit 5, make it send a packet to the server to set a value indicating that it has connected - done
                //Make the other client do the same - done?
                //When server determines both clients have connected based on these packets, drop the clients from the server and let them continue communicating - maybe done?

                //Also, add flag to prevent simultaneous connection attempts based on aforementioned packets
                //Add timeouts for connection attempts to allow another client to try to connect if the previous one fails
                //Basically the server shouldn't be locked out if a client couldn't connect
                //Also add a retry if there's no connection made after a certain amount of time

                //Fix symmetric server to non-symmetric client connection?? what happened here
                //Look into tun/tap adapters on windows and linux to turn this into a tunneling vpn

                switch(receivedMessage.ID)
                {
                    case MediationMessageType.Connected:
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.NATTypeRequest);
                        message.LocalPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        Console.WriteLine(message.Serialize());
                        tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                    }
                    break;
                    case MediationMessageType.NATTestBegin:
                    {
                        natTestPortOne = receivedMessage.NATTestPortOne;
                        natTestPortTwo = receivedMessage.NATTestPortTwo;
                        MediationMessage message = new MediationMessage(MediationMessageType.NATTest);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(endpoint.Address, natTestPortOne));
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(endpoint.Address, natTestPortTwo));
                    }
                    break;
                    case MediationMessageType.NATTypeResponse:
                    {
                        Console.WriteLine(receivedMessage.NATType);
                        natType = receivedMessage.NATType;
                        if (isServer)
                        {
                            UdpServer();
                            Console.WriteLine($"Server forwarding {NodeOptions.Endpoint} to UDP port {NodeOptions.LocalPort}");
                        }
                        else
                        {
                            UdpClient();
                            Console.WriteLine($"Client forwarding TCP port {NodeOptions.LocalPort} to UDP server {NodeOptions.Endpoint}");
                            MediationMessage message = new MediationMessage(MediationMessageType.ConnectionRequest);
                            message.SetEndpoint(new IPEndPoint(remoteIp, IPEndPoint.MinPort));
                            message.NATType = natType;
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                        }
                    }
                    break;
                    case MediationMessageType.ConnectionBegin:
                    {
                        holePunchReceivedCount = 0;
                        currentConnectionID = receivedMessage.ConnectionID;
                        if (natType == NATType.Symmetric)
                        {
                            IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                            targetPeerIp = targetPeerEndpoint.Address;
                            targetPeerPort = targetPeerEndpoint.Port;

                            Timer connectionAttempt = new Timer(1000)
                            {
                                AutoReset = true,
                                Enabled = false
                            };
                            connectionAttempt.Elapsed += TryConnectFromSymmetric;
                            
                            while (symmetricConnectionUdpProbes.Count < 256)
                            {
                                UdpClient tempUdpClient = new UdpClient();
                                const int SIO_UDP_CONNRESET = -1744830452;
                                tempUdpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                                tempUdpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
                                tempUdpClient.BeginReceive(new AsyncCallback(probeReceive), null);
                                void probeReceive(IAsyncResult res)
                                {
                                    try
                                    {
                                        if(holePunchReceivedCount == 0)
                                        {
                                            IPEndPoint receivedEndpoint = new IPEndPoint(IPAddress.Any, 0);
                                            byte[] receivedBuffer = tempUdpClient.EndReceive(res, ref receivedEndpoint);
                                            byte[] shutdownBuffer = Encoding.ASCII.GetBytes("yes");

                                            if(receivedEndpoint.Address.Equals(targetPeerIp))
                                            {
                                                Console.WriteLine($"DUDE WE JUST RECEIVED A PACKET FROM ANOTHER PEER AS A SYMMETRIC NAT THIS IS INSANE!!! port {((IPEndPoint) tempUdpClient.Client.LocalEndPoint).Port}");
                                                holePunchReceivedCount++;

                                                udpClientTaskCancellationToken.Cancel();
                                                //udpClientTaskCancellationToken.Dispose();
                                                
                                                if (isServer)
                                                {
                                                    Task newUdpServerTask = new Task(UdpServerListenLoop);
                                                    newUdpServerTask.Start();
                                                    Console.WriteLine("server");
                                                }
                                                else
                                                {
                                                    //TRY DELAYING ALL OF THIS UNTIL THE ORIGINAL TASK HAS COMPLETELY DIED
                                                    tempUdpClient.Send(shutdownBuffer, shutdownBuffer.Length, new IPEndPoint(IPAddress.Loopback, 5000));
                                                    udpClient = tempUdpClient;

                                                    NodeOptions.MediationClientPort = ((IPEndPoint) udpClient.Client.LocalEndPoint).Port;
                                                    mediationClientPort = NodeOptions.MediationClientPort;
                                                    CancellationTokenSource newUdpClientTaskCancellationToken = new CancellationTokenSource();
                                                    Task.Run(() => UdpClientListenLoop(newUdpClientTaskCancellationToken.Token));
                                                    Console.WriteLine("client");
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {
                                        Console.WriteLine("who cares it still works lol");
                                    }
                                }
                                symmetricConnectionUdpProbes.Add(tempUdpClient);
                            }

                            connectionAttempt.Enabled = true;
                        }

                        if (receivedMessage.NATType == NATType.Symmetric)
                        {
                            IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                            targetPeerIp = targetPeerEndpoint.Address;
                            Timer connectionAttempt = new Timer(1000)
                            {
                                AutoReset = true,
                                Enabled = true
                            };
                            connectionAttempt.Elapsed += TryConnectToSymmetric;
                        }

                        if (natType != NATType.Symmetric && receivedMessage.NATType != NATType.Symmetric)
                        {
                            IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                            targetPeerIp = targetPeerEndpoint.Address;
                            targetPeerPort = targetPeerEndpoint.Port;
                            Timer connectionAttempt = new Timer(1000)
                            {
                                AutoReset = true,
                                Enabled = true
                            };
                            connectionAttempt.Elapsed += TryConnect;
                        }
                    }
                    break;
                    case MediationMessageType.ConnectionComplete:
                    {
                        if (isServer) {
                            holePunchReceivedCount = 5;
                            TcpClient tcpClientPassthrough = new TcpClient();

                            tcpClientPassthrough.Connect(new IPEndPoint(IPAddress.Loopback, NodeOptions.LocalPort));

                            NetworkStream tcpClientPassthroughStream = tcpClientPassthrough.GetStream();
                            Task tcpClientPassthroughThread = new Task(() => TcpListenLoopPassthrough(tcpClientPassthrough, tcpClientPassthroughStream));
                            tcpClientPassthroughThread.Start();
                            connected = true;
                        } else {
                            try
                            {
                                tcpClientStream.Close();
                                tcpClientTaskCancellationToken.Cancel();
                                tcpClient.Close();
                                tcpClientTaskCancellationToken.Dispose();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                            }
                            connected = true;
                        }
                    }
                    break;
                    case MediationMessageType.ServerNotAvailable:
                    {
                        Timer recheckAvailability = new Timer(3000)
                        {
                            AutoReset = false,
                            Enabled = true
                        };
                        recheckAvailability.Elapsed += PollForAvailableServer;
                    }
                    break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            if (tcpClientTaskCancellationToken.Token.IsCancellationRequested){
                Console.WriteLine("YOU GOTTA BE KIDDING ME");
                return;
            }
        }
    }

    private static void TcpListenLoopPassthrough(TcpClient tcpClientPassthrough, NetworkStream tcpClientPassthroughStream)
    {
        while (tcpClientPassthrough.Connected)
        {
            try
            {
                byte[] receiveBuffer = new byte[tcpClientPassthrough.ReceiveBufferSize];
                //TODO: check if read is important after tcp has been fixed
                int _ = tcpClientPassthroughStream.Read(receiveBuffer, 0, tcpClientPassthrough.ReceiveBufferSize);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}