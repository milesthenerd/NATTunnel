using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
    private static readonly UdpClient udpClient; // set in constructor
    private static NetworkStream tcpClientStream;
    private static Task tcpClientTask;
    private static readonly CancellationTokenSource tcpClientTaskCancellationToken = new CancellationTokenSource();
    private static Task udpClientTask;
    private static Task udpServerTask;
    private static readonly IPEndPoint endpoint;
    private static readonly IPEndPoint programEndpoint;
    private static IPAddress intendedIp;
    private static int intendedPort;
    private static int localAppPort = 65535;
    private static int holePunchReceivedCount;
    private static bool connected;
    private static readonly IPAddress remoteIp;
    private static readonly int mediationClientPort;
    private static readonly bool isServer;
    private static readonly List<IPEndPoint> connectedClients = new List<IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingLocalTCPtoRemote = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingLocalUDPtoRemote = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, IPEndPoint> mappingRemoteUDPtoLocal = new Dictionary<IPEndPoint, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, int> timeoutClients = new Dictionary<IPEndPoint, int>();
    private static IPEndPoint mostRecentEndPoint = new IPEndPoint(IPAddress.Loopback, 65535);

    static MediationClient()
    {
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
    }

    public static void AddTCP(IPEndPoint localEndpoint)
    {
        mappingLocalTCPtoRemote.Add(localEndpoint, mostRecentEndPoint);
    }

    public static void RemoveTCP(IPEndPoint localEndpoint)
    {
        mappingLocalTCPtoRemote.Remove(localEndpoint);
    }

    public static void AddUDP(IPEndPoint localEndpoint)
    {
        mappingLocalUDPtoRemote.Add(localEndpoint, mostRecentEndPoint);
        mappingRemoteUDPtoLocal.Add(mostRecentEndPoint, localEndpoint);
    }

    public static void RemoveUDP(IPEndPoint localEndpoint)
    {
        mappingRemoteUDPtoLocal.Remove(mappingLocalUDPtoRemote[localEndpoint]);
        mappingLocalUDPtoRemote.Remove(localEndpoint);
    }

    private static void OnTimedEvent(object source, ElapsedEventArgs e)
    {
        //If not connected to remote endpoint, send remote IP to mediator
        if (!connected || isServer)
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes(intendedIp.ToString());
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
            Console.WriteLine("Sent");
        }
        //If connected to remote endpoint, send keep alive message
        if (connected)
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("hi");
            if (isServer)
            {
                foreach (IPEndPoint client in connectedClients)
                {
                    udpClient.Send(sendBuffer, sendBuffer.Length, client);
                }
            }
            else
            {
                udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(intendedIp, intendedPort));
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

        Console.WriteLine("Connected");
        tcpClientStream = tcpClient.GetStream();
        tcpClientTask = new Task(TcpListenLoop);
        tcpClientTask.Start();

        if (isServer)
        {
            UdpServer();
            Console.WriteLine($"Server forwarding {NodeOptions.Endpoint} to UDP port {NodeOptions.LocalPort}");
        }
        else
        {
            UdpClient();
            Console.WriteLine($"Client forwarding TCP port {NodeOptions.LocalPort} to UDP server {NodeOptions.Endpoint}");
        }
    }

    private static void UdpClient()
    {
        //Set client intendedIP to remote endpoint IP
        intendedIp = remoteIp;
        //Try to send initial msg to mediator
        try
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        //Begin listening
        udpClientTask = new Task(UdpClientListenLoop);
        udpClientTask.Start();
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
        //Set client intendedIP to something no client will have
        intendedIp = IPAddress.None;
        //Try to send initial msg to mediator
        try
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
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

    private static void UdpClientListenLoop()
    {
        //Init an IPEndPoint that will be populated with the sender's info
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
        while (true)
        {
            mostRecentEndPoint = listenEndpoint;

            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient),"udpClient.Receive(ref listenEP)");

            Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");

            if (Equals(listenEndpoint.Address, IPAddress.Loopback) && (listenEndpoint.Port != mediationClientPort))
            {
                localAppPort = listenEndpoint.Port;
            }

            Console.WriteLine(localAppPort);

            if (Equals(listenEndpoint.Address, intendedIp))
            {
                Console.WriteLine("pog");
                holePunchReceivedCount++;
                //TODO: random hardcoded value
                if (holePunchReceivedCount >= 5 && !connected)
                {
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

            IPAddress receivedIp = null;
            int receivedPort = 0;

            if (Equals(listenEndpoint.Address, endpoint.Address))
            {
                //TODO: why do we need to constantly re-get the ip on where to send stuff to?
                string[] msgArray = Encoding.ASCII.GetString(receiveBuffer).Split(":");

                receivedIp = IPAddress.Parse(msgArray[0]);
                receivedPort = 0;
                if (msgArray.Length > 1)
                    receivedPort = Int32.Parse(msgArray[1]);
            }

            if (Equals(receivedIp, intendedIp) && holePunchReceivedCount < 5)
            {
                intendedPort = receivedPort;
                Console.WriteLine(intendedIp);
                Console.WriteLine(intendedPort);
                if (intendedPort != 0)
                {
                    byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(intendedIp, intendedPort));
                    Console.WriteLine("punching");
                }
            }

            if (connected && Equals(listenEndpoint.Address, IPAddress.Loopback))
                //TODO: weird consistent way to crash here because intendedPort is 0, because it didn't into the if holePunchCount < 5 from above, because receivedIP is null
                //https://cdn.discordapp.com/attachments/806611530438803458/933443905066790962/unknown.png
                udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(intendedIp, intendedPort));

            if (!connected || !Equals(listenEndpoint.Address, intendedIp)) continue;

            try
            {
                //TODO: sometimes fails here for whatever reason
                if (!Equals(Encoding.ASCII.GetString(receiveBuffer), "hi"))
                {
                    udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(IPAddress.Loopback, localAppPort));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }

    private static void UdpServerListenLoop()
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
        while (true)
        {
            Console.WriteLine(mappingLocalTCPtoRemote.Count);
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

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

            if (!Equals(listenEndpoint.Address, IPAddress.Loopback) && listenEndpoint.Port != mediationClientPort)
                localAppPort = listenEndpoint.Port;


            if (!connectedClients.Exists(element => element.Address.ToString() == listenEndpoint.Address.ToString()) && Equals(listenEndpoint.Address, intendedIp))
            {
                connectedClients.Add(listenEndpoint);
                timeoutClients.Add(listenEndpoint, 5);
                Console.WriteLine("added {0}:{1} to list", listenEndpoint.Address, listenEndpoint.Port);
            }

            if (Equals(listenEndpoint.Address, intendedIp))
            {
                Console.WriteLine("pog");
                holePunchReceivedCount++;
                if (holePunchReceivedCount >= 5 && !connected)
                {
                    TcpClient tcpClientPassthrough = new TcpClient();

                    tcpClientPassthrough.Connect(new IPEndPoint(IPAddress.Loopback, 5001));

                    NetworkStream tcpClientPassthroughStream = tcpClientPassthrough.GetStream();
                    Task tcpClientPassthroughThread = new Task(() => TcpListenLoopPassthrough(tcpClientPassthrough, tcpClientPassthroughStream));
                    tcpClientPassthroughThread.Start();
                    connected = true;
                }
            }

            IPAddress receivedIp = null;
            int receivedPort = 0;

            if (listenEndpoint.Address.ToString() == endpoint.Address.ToString())
            {
                string[] msgArray = Encoding.ASCII.GetString(receiveBuffer).Split(":");

                receivedIp = IPAddress.Parse(msgArray[0]);
                receivedPort = 0;
                if (msgArray.Length > 1) receivedPort = Int32.Parse(msgArray[1]);

                if (msgArray.Length > 2)
                {
                    string type = msgArray[2];
                    if (type == "clientreq" && !Equals(intendedIp, receivedIp) && intendedPort != receivedPort)
                    {
                        intendedIp = receivedIp;
                        intendedPort = receivedPort;
                        holePunchReceivedCount = 0;
                    }
                }
            }

            if (Equals(receivedIp, intendedIp) && holePunchReceivedCount < 5)
            {
                intendedPort = receivedPort;
                Console.WriteLine(intendedIp);
                Console.WriteLine(intendedPort);
                if (intendedPort != 0)
                {
                    byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(intendedIp, intendedPort));
                    Console.WriteLine("punching");
                }
            }

            if (connected && Equals(listenEndpoint.Address, IPAddress.Loopback))
            {
                IPEndPoint destEndpoint = new IPEndPoint(IPAddress.Loopback, 65535);

                string receiveString = Encoding.ASCII.GetString(receiveBuffer);
                int splitPos = receiveString.IndexOf("end", StringComparison.Ordinal);
                if (splitPos > 0)
                {
                    string[] receiveSplit = receiveString.Split("end");
                    if (receiveSplit.Length > 1)
                    {
                        string endpointStr = receiveSplit[1];
                        string[] endpointSplit = endpointStr.Split(":");
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

                    Console.WriteLine("dest port");
                    Console.WriteLine(destEndpoint);
                    udpClient.Send(receiveBuffer, receiveBuffer.Length, destEndpoint);
                }
            }

            if (NodeOptions.ConnectionType == ConnectionTypes.TCP)
            {
                foreach (IPEndPoint client in connectedClients)
                {
                    if (!connected || !Equals(listenEndpoint.Address, client.Address)) continue;

                    udpClient.Send(receiveBuffer, receiveBuffer.Length, programEndpoint);
                }
            }
            else
            {
                if (!connected || Encoding.ASCII.GetString(receiveBuffer) == "hi") continue;

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

                    udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(IPAddress.Loopback, destEndpoint.Port));
                }
            }
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
                Console.WriteLine("Received: " + Encoding.ASCII.GetString(receiveBuffer, 0, bytesRead));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            if (tcpClientTaskCancellationToken.Token.IsCancellationRequested)
                return;
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