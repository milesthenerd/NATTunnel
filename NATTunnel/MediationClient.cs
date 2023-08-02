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
    private static CancellationTokenSource udpClientTaskCancellationToken = new CancellationTokenSource();
    private static CancellationTokenSource udpServerTaskCancellationToken = new CancellationTokenSource();
    private static readonly IPEndPoint endpoint;
    private static int natTestPortOne = 6511;
    private static int natTestPortTwo = 6512;
    private static IPAddress targetPeerIp;
    private static int targetPeerPort;
    private static int holePunchReceivedCount;
    private static bool connected;
    private static readonly IPAddress remoteIp;
    private static readonly bool isServer;
    private static readonly List<IPEndPoint> connectedClients = new List<IPEndPoint>();
    private static readonly Dictionary<IPAddress, IPEndPoint> privateToRemote = new Dictionary<IPAddress, IPEndPoint>();
    private static readonly Dictionary<IPEndPoint, int> timeoutClients = new Dictionary<IPEndPoint, int>();
    private static NATType natType = NATType.Unknown;
    private static List<UdpClient> symmetricConnectionUdpProbes = new List<UdpClient>();
    private static int currentConnectionID = 0;
    public static IPAddress privateIP = null;
    private static FrameCapture capture;

    static MediationClient()
    {
        capture = new FrameCapture();
        capture.Start();

        try
        {
            udpClient = new UdpClient();
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
        remoteIp = NodeOptions.RemoteIp;
        isServer = NodeOptions.IsServer;
        if (isServer) privateIP = IPAddress.Parse("10.5.0.0");
        if (!isServer) privateIP = IPAddress.Parse("10.5.0.255");

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

    public static void Send(byte[] packetData, IPAddress privateAddress)
    {
        if (isServer)
        {
            if (privateToRemote.ContainsKey(privateAddress))
            {
                MediationMessage message = new MediationMessage(MediationMessageType.NATTunnelData);
                message.Data = packetData;
                message.SetPrivateAddress(privateAddress);
                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                udpClient.Send(sendBuffer, sendBuffer.Length, privateToRemote[privateAddress]);
            }
        }
        else
        {
            MediationMessage message = new MediationMessage(MediationMessageType.NATTunnelData);
            message.Data = packetData;
            message.SetPrivateAddress(privateAddress);
            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
            udpClient.Send(sendBuffer, sendBuffer.Length, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}"));
        }
    }

    public static void AddIP(IPEndPoint remoteEndpoint)
    {
        if (!privateToRemote.ContainsValue(remoteEndpoint))
            privateToRemote.Add(IPAddress.Parse($"10.5.0.{connectedClients.Count + 1}"), remoteEndpoint);
    }

    public static void RemoveIP(IPEndPoint remoteEndpoint)
    {
        privateToRemote.Remove(GetKeyFromValue(privateToRemote, remoteEndpoint));
    }

    public static IPAddress GetKeyFromValue(Dictionary<IPAddress, IPEndPoint> dict, IPEndPoint endpoint)
    {
        foreach(var pair in dict)
        {
            if(pair.Value.Equals(endpoint))
            {
                return pair.Key;
            }
        }
        return null;
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
                RemoveIP(key);
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
        Task.Run(() => UdpServerListenLoop(udpServerTaskCancellationToken.Token));
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

        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        Console.WriteLine($"is this even starting {listenEndpoint}");
        while (!token.IsCancellationRequested)
        {
            Console.WriteLine($"ahh yes the randID for this task is {randID}");

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
                //Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");
                //capture.Send(receiveBuffer);
                continue;
            }

            Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
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
                    holePunchReceivedCount++;
                    try {
                        privateIP = receivedMessage.GetPrivateAddress();
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine(e);
                    }
                    Console.WriteLine("POG");
                }
                break;
                case MediationMessageType.NATTunnelData:
                {
                    tunnelData = receivedMessage.Data;
                    IPAddress targetPrivateAddress = receivedMessage.GetPrivateAddress();
                    Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                    if (!connected) continue;
                    capture.Send(tunnelData);
                }
                break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                {
                    holePunchReceivedCount++;
                    try {
                        privateIP = receivedMessage.GetPrivateAddress();
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine(e);
                    }
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

    private static void UdpServerListenLoop(CancellationToken token)
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            Console.WriteLine(privateToRemote.Count);
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
                //Console.WriteLine($"length {timeoutClients.Count} and {connectedClients.Count}");
                //Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", receiveBuffer.Length, listenEndpoint.Address, listenEndpoint.Port);
                //capture.Send(receiveBuffer);
                continue;
            }

            foreach ((IPEndPoint key, int _) in timeoutClients)
            {
                bool exists = connectedClients.Any(value2 => Equals(key, value2));

                if (!exists)
                {
                    Console.WriteLine($"removing {key}");
                    timeoutClients.Remove(key);
                    RemoveIP(key);
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
                AddIP(listenEndpoint);
                Console.WriteLine("added {0}:{1} to list", listenEndpoint.Address, listenEndpoint.Port);
            }

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
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

            switch(receivedMessage.ID)
            {
                case MediationMessageType.HolePunchAttempt:
                {
                    if (holePunchReceivedCount == 0) holePunchReceivedCount++;
                    Console.WriteLine("POG");
                }
                break;
                case MediationMessageType.NATTunnelData:
                {
                    tunnelData = receivedMessage.Data;
                    IPAddress targetPrivateAddress = receivedMessage.GetPrivateAddress();
                    Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                    if (!connected) continue;

                    if (targetPrivateAddress.Equals(privateIP))
                    {
                        capture.Send(tunnelData);
                    }
                    else
                    {
                        Send(tunnelData, targetPrivateAddress);
                    }
                }
                break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                {
                    if (holePunchReceivedCount == 0) holePunchReceivedCount++;
                    if (natType != NATType.Symmetric)
                    {
                        targetPeerIp = listenEndpoint.Address;
                        targetPeerPort = listenEndpoint.Port;
                    }
                }
                break;
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
                        if (isServer) message.SetPrivateAddress(GetKeyFromValue(privateToRemote, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")));
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                }

                void TryConnectFromSymmetric(object source, ElapsedEventArgs e)
                {
                    if(holePunchReceivedCount >= 1 && holePunchReceivedCount < 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        if (isServer) message.SetPrivateAddress(GetKeyFromValue(privateToRemote, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")));
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
                        if (isServer) message.SetPrivateAddress(GetKeyFromValue(privateToRemote, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")));
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
                        }
                        else
                        {
                            UdpClient();
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
                                                udpServerTaskCancellationToken.Cancel();
                                                
                                                if (isServer)
                                                {
                                                    udpClient = tempUdpClient;

                                                    CancellationTokenSource newUdpServerTaskCancellationToken = new CancellationTokenSource();
                                                    Task.Run(() => UdpServerListenLoop(newUdpServerTaskCancellationToken.Token));
                                                    Console.WriteLine("server");
                                                }
                                                else
                                                {
                                                    udpClient = tempUdpClient;

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
}