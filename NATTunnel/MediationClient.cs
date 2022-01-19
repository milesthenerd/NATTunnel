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
using System.IO;

namespace NATTunnel
{
    public static class MediationClient
    {
        //TODO: entire class should get reviewed and eventually split up into smaller classes

        private static readonly TcpClient tcpClient = new TcpClient();
        private static readonly UdpClient udpClient;
        private static NetworkStream tcpClientStream;
        private static Thread tcpClientThread;
        private static Thread udpClientThread;
        private static Thread udpServerThread;
        private static readonly IPEndPoint endpoint;
        private static readonly IPEndPoint programEndpoint;
        private static IPAddress intendedIp;
        private static int intendedPort;
        private static int localAppPort;
        private static int holePunchReceivedCount;
        private static bool connected;
        private static readonly IPAddress remoteIp;
        private static readonly int mediationClientPort;
        private static readonly bool isServer;
        private static readonly List<IPEndPoint> connectedClients = new List<IPEndPoint>();
        private static readonly Dictionary<IPEndPoint, IPEndPoint> mapping = new Dictionary<IPEndPoint, IPEndPoint>();
        private static readonly Dictionary<IPEndPoint, int> timeoutClients = new Dictionary<IPEndPoint, int>();
        private static IPEndPoint mostRecentEndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 65535);

        static MediationClient()
        {
            // NodeOptions loading is done here, as MediationClient is the first thing we call and the class that relies most upon the settings.
            if (!File.Exists("config.txt") && !TryCreateNewConfig())
                Environment.Exit(-1);

            using (StreamReader sr = new StreamReader("config.txt"))
            {
                if (!NodeOptions.Load(sr))
                {
                    Console.WriteLine("Failed to load config.txt");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    Environment.Exit(-1);
                }
            }

            udpClient = new UdpClient(NodeOptions.mediationClientPort);

            // Windows-specific udpClient switch
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                const int SIO_UDP_CONNRESET = -1744830452;
                udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
            }

            endpoint = NodeOptions.mediationIP;
            programEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), NodeOptions.localPort);
            remoteIp = NodeOptions.remoteIP;
            mediationClientPort = NodeOptions.mediationClientPort;
            isServer = NodeOptions.isServer;
        }

        public static void Add(IPEndPoint localEndpoint)
        {
            mapping.Add(localEndpoint, mostRecentEndPoint);
        }

        public static void Remove(IPEndPoint localEndpoint)
        {
            mapping.Remove(localEndpoint);
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
                    foreach (var client in connectedClients)
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

            foreach ((var key, int value) in timeoutClients)
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

        public static void TrackedClient()
        {
            //Attempt to connect to mediator
            try
            {
                tcpClient.Connect(endpoint);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            //Once connected, begin listening
            if (!tcpClient.Connected)
                return;

            Console.WriteLine("Connected");
            tcpClientStream = tcpClient.GetStream();

            tcpClientThread = new Thread(TcpListenLoop);
            tcpClientThread.Start();
        }

        public static void UdpClient()
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
            udpClientThread = new Thread(UdpClientListenLoop);
            udpClientThread.Start();
            //Start timer for hole punch init and keep alive
            Timer timer = new Timer(1000)
            {
                AutoReset = true,
                Enabled = true
            };
            timer.Elapsed += OnTimedEvent;
        }

        public static void UdpServer()
        {
            //Set client intendedIP to something no client will have
            //TODO: double check that this (255.255.255.255) works the same 0.0.0.0
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
            udpServerThread = new Thread(UdpServerListenLoop);
            udpServerThread.Start();
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
                byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient),"udpClient.Receive(ref listenEP)");

                Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", receiveBuffer.Length, listenEndpoint.Address, listenEndpoint.Port);

                if (listenEndpoint.Address.ToString() == "127.0.0.1" && listenEndpoint.Port != mediationClientPort)
                {
                    localAppPort = listenEndpoint.Port;
                }

                if (Equals(listenEndpoint.Address, intendedIp))
                {
                    Console.WriteLine("pog");
                    holePunchReceivedCount++;
                    if (holePunchReceivedCount >= 5 && !connected)
                    {
                        try
                        {
                            tcpClientStream.Close();
                            tcpClientThread.Interrupt();
                            tcpClient.Close();
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

                //TODO: pretty sure this is not necessary / can be condensed
                if (connected && receivedIp.ToString() != "hi" && Equals(listenEndpoint.Address, IPAddress.Loopback))
                {
                    udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(intendedIp, intendedPort));
                    Console.WriteLine("huh");
                }

                if (!connected || receivedIp.ToString() == "hi" || !Equals(listenEndpoint.Address, intendedIp))
                    continue;

                try
                {
                    udpClient.Send(receiveBuffer, receiveBuffer.Length, new IPEndPoint(IPAddress.Parse("127.0.0.1"), localAppPort));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("huh 2");
            }
        }

        private static void UdpServerListenLoop()
        {
            IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
            while (true)
            {
                Console.WriteLine(mapping.Count);
                byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

                mostRecentEndPoint = listenEndpoint;

                foreach ((var key, int value) in timeoutClients)
                {
                    //TODO: do you want same reference, or same values?
                    bool exists = connectedClients.Any(value2 => key == value2);

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

                if (listenEndpoint.Address.ToString() != "127.0.0.1" && listenEndpoint.Port != mediationClientPort)
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
                    if (holePunchReceivedCount >= 5 && !connected) connected = true;
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

                if (connected && receivedIp.ToString() != "hi" && listenEndpoint.Address.ToString() == "127.0.0.1")
                {
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
                                string address = endpointSplit[0];
                                int port = 65535;
                                bool checkMap = true;
                                try
                                {
                                    IPAddress.Parse(address);
                                }
                                catch
                                {
                                    address = "127.0.0.1";
                                    checkMap = false;
                                }

                                try
                                {
                                    port = Int32.Parse(endpointSplit[1]);
                                }
                                catch
                                {
                                    checkMap = false;
                                }
                                Console.WriteLine($"{address}:{port}");

                                IPEndPoint destEndpoint = new IPEndPoint(IPAddress.Parse(address), port);

                                if (checkMap)
                                {
                                    try
                                    {
                                        destEndpoint = mapping[new IPEndPoint(IPAddress.Parse(address), port)];
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e);
                                    }
                                }
                                Console.WriteLine(destEndpoint);
                                udpClient.Send(receiveBuffer, receiveBuffer.Length, destEndpoint);
                            }
                        }
                    }
                }

                foreach (var client in connectedClients)
                {
                    if (!connected || receivedIp.ToString() == "hi" || listenEndpoint.Address.ToString() != client.Address.ToString())
                        continue;

                    udpClient.Send(receiveBuffer, receiveBuffer.Length, programEndpoint);
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
                    int bytesRead = tcpClientStream.Read(receiveBuffer, 0, tcpClient.ReceiveBufferSize);
                    Console.WriteLine("Received: " + Encoding.ASCII.GetString(receiveBuffer, 0, bytesRead));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        /// <summary>
        /// Tries to reate a new config.
        /// </summary>
        /// <returns>Returns <see langword="true"/> if creation was successful, <see langword="false"/> if creation was cancelled.</returns>
        private static bool TryCreateNewConfig()
        {
            Console.WriteLine("Unable to find config.txt");
            Console.WriteLine("Creating a default:");
            Console.WriteLine("c) Create a client config file");
            Console.WriteLine("s) Create a server config file");
            Console.WriteLine("Any other key: Quit");
            ConsoleKeyInfo cki = Console.ReadKey();
            switch (cki.KeyChar)
            {
                case 'c':
                {
                    NodeOptions.isServer = false;
                    NodeOptions.masterServerID = 0;
                    NodeOptions.localPort = 5001;
                    using StreamWriter sw = new StreamWriter("config.txt");
                    NodeOptions.Save(sw);
                    return true;
                }
                case 's':
                {
                    NodeOptions.isServer = true;
                    NodeOptions.endpoint = "127.0.0.1:25565";
                    NodeOptions.localPort = 5001;
                    using StreamWriter sw = new StreamWriter("config.txt");
                    NodeOptions.Save(sw);
                    return true;
                }
                default:
                {
                    Console.WriteLine("Quitting...");
                    return false;
                }
            }
        }
    }
}