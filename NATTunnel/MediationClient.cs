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
    static public class MediationClient
    {

        private static TcpClient tcpClient = new TcpClient();
        private static UdpClient udpClient;
        private static NetworkStream tcpClientStream;
        private static Thread tcpClientThread;
        private static Thread udpClientThread;
        private static Thread udpServerThread;
        private static IPEndPoint Endpoint;
        private static IPEndPoint programEndpoint;
        //TODO: consider using address for this?
        private static string intendedIP;
        private static int intendedPort;
        private static int localAppPort;
        private static int holePunchReceivedCount;
        private static bool connected;
        private static string remoteIP;
        private static int mediationClientPort;
        private static bool isServer;
        private static List<IPEndPoint> connectedClients = new List<IPEndPoint>();
        public static Dictionary<IPEndPoint, IPEndPoint> mapping = new Dictionary<IPEndPoint, IPEndPoint>();
        public static Dictionary<IPEndPoint, int> timeoutClients = new Dictionary<IPEndPoint, int>();
        public static IPEndPoint mostRecentEP = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 65535);

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

            Endpoint = NodeOptions.mediationIP;
            programEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), NodeOptions.localPort);
            remoteIP = NodeOptions.remoteIP;
            mediationClientPort = NodeOptions.mediationClientPort;
            isServer = NodeOptions.isServer;
        }

        public static void Add(IPEndPoint localEP)
        {
            mapping.Add(localEP, mostRecentEP);
        }

        public static void Remove(IPEndPoint localEP)
        {
            mapping.Remove(localEP);
        }

        private static void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            //If not connected to remote endpoint, send remote IP to mediator
            if (!connected || isServer)
            {
                byte[] sendBuffer = Encoding.ASCII.GetBytes(intendedIP);
                udpClient.Send(sendBuffer, sendBuffer.Length, Endpoint);
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
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(IPAddress.Parse(intendedIP), intendedPort));
                }
                Console.WriteLine("Keep alive");
            }

            foreach (var (key, value) in timeoutClients)
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
                tcpClient.Connect(Endpoint);
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
            intendedIP = remoteIP;
            //Try to send initial msg to mediator
            try
            {
                byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                udpClient.Send(sendBuffer, sendBuffer.Length, Endpoint);
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
            intendedIP = "0.0.0.0";
            //Try to send initial msg to mediator
            try
            {
                byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                udpClient.Send(sendBuffer, sendBuffer.Length, Endpoint);
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

        public static void UdpClientListenLoop()
        {
            //Init an IPEndPoint that will be populated with the sender's info
            IPEndPoint listenEP = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
            while (true)
            {
                byte[] recvBuffer = udpClient.Receive(ref listenEP);

                Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", recvBuffer.Length, listenEP.Address, listenEP.Port);

                if (listenEP.Address.ToString() == "127.0.0.1" && listenEP.Port != mediationClientPort)
                {
                    localAppPort = listenEP.Port;
                }

                if (listenEP.Address.ToString() == intendedIP)
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

                string receivedIP = "";
                int receivedPort = 0;

                if (listenEP.Address.ToString() == Endpoint.Address.ToString())
                {
                    string[] msgArray = Encoding.ASCII.GetString(recvBuffer).Split(":");

                    receivedIP = msgArray[0];
                    receivedPort = 0;
                    if (msgArray.Length > 1)
                        receivedPort = int.Parse(msgArray[1]);
                }

                if (receivedIP == intendedIP && holePunchReceivedCount < 5)
                {
                    intendedPort = receivedPort;
                    Console.WriteLine(intendedIP);
                    Console.WriteLine(intendedPort);
                    if (intendedPort != 0)
                    {
                        byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(IPAddress.Parse(intendedIP), intendedPort));
                        Console.WriteLine("punching");
                    }
                }

                //TODO: pretty sure this is not necessary / can be condensed
                if (connected && receivedIP != "hi" && listenEP.Address.ToString() == "127.0.0.1")
                {
                    udpClient.Send(recvBuffer, recvBuffer.Length, new IPEndPoint(IPAddress.Parse(intendedIP), intendedPort));
                    Console.WriteLine("huh");
                }

                if (!connected || receivedIP == "hi" || listenEP.Address.ToString() != intendedIP)
                    continue;

                try
                {
                    udpClient.Send(recvBuffer, recvBuffer.Length, new IPEndPoint(IPAddress.Parse("127.0.0.1"), localAppPort));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

                Console.WriteLine("huh 2");
            }
        }

        public static void UdpServerListenLoop()
        {
            IPEndPoint listenEP = new IPEndPoint(IPAddress.IPv6Any, mediationClientPort);
            while (true)
            {
                Console.WriteLine(mapping.Count);
                byte[] recvBuffer = udpClient.Receive(ref listenEP);

                mostRecentEP = listenEP;

                foreach (var (key, value) in timeoutClients)
                {
                    //TODO: do you want same reference, or same values?
                    bool exists = connectedClients.Any(value2 => key == value2);

                    if (!exists)
                    {
                        Console.WriteLine($"removing {key}");
                        timeoutClients.Remove(key);
                    }

                    Console.WriteLine($"{key} and {listenEP}");
                    if (key.Address.ToString() == listenEP.Address.ToString())
                        timeoutClients[key] = 5;
                }

                Console.WriteLine($"length {timeoutClients.Count} and {connectedClients.Count}");
                Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", recvBuffer.Length, listenEP.Address, listenEP.Port);

                if (listenEP.Address.ToString() != "127.0.0.1" && listenEP.Port != mediationClientPort)
                    localAppPort = listenEP.Port;


                if (!connectedClients.Exists(element => element.Address.ToString() == listenEP.Address.ToString()) && listenEP.Address.ToString() == intendedIP)
                {
                    connectedClients.Add(listenEP);
                    timeoutClients.Add(listenEP, 5);
                    Console.WriteLine("added {0}:{1} to list", listenEP.Address, listenEP.Port);
                }

                if (listenEP.Address.ToString() == intendedIP)
                {
                    Console.WriteLine("pog");
                    holePunchReceivedCount++;
                    if (holePunchReceivedCount >= 5 && !connected) connected = true;
                }

                string receivedIP = "";
                int receivedPort = 0;

                if (listenEP.Address.ToString() == Endpoint.Address.ToString())
                {
                    string[] msgArray = Encoding.ASCII.GetString(recvBuffer).Split(":");

                    receivedIP = msgArray[0];
                    receivedPort = 0;
                    if (msgArray.Length > 1) receivedPort = int.Parse(msgArray[1]);

                    if (msgArray.Length > 2)
                    {
                        string type = msgArray[2];
                        if (type == "clientreq" && intendedIP != receivedIP && intendedPort != receivedPort)
                        {
                            intendedIP = receivedIP;
                            intendedPort = receivedPort;
                            holePunchReceivedCount = 0;
                        }
                    }
                }


                if (receivedIP == intendedIP && holePunchReceivedCount < 5)
                {
                    intendedPort = receivedPort;
                    Console.WriteLine(intendedIP);
                    Console.WriteLine(intendedPort);
                    if (intendedPort != 0)
                    {
                        byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(IPAddress.Parse(intendedIP), intendedPort));
                        Console.WriteLine("punching");
                    }
                }

                if (connected && receivedIP != "hi" && listenEP.Address.ToString() == "127.0.0.1")
                {
                    string recvStr = Encoding.ASCII.GetString(recvBuffer);
                    int splitPos = recvStr.IndexOf("end");
                    if (splitPos > 0)
                    {
                        string[] recvSplit = recvStr.Split("end");
                        if (recvSplit.Length > 1)
                        {
                            string endpointStr = recvSplit[1];
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
                                    port = int.Parse(endpointSplit[1]);
                                }
                                catch
                                {
                                    checkMap = false;
                                }
                                Console.WriteLine($"{address}:{port}");

                                IPEndPoint destEP = new IPEndPoint(IPAddress.Parse(address), port);

                                if (checkMap)
                                {
                                    try
                                    {
                                        destEP = mapping[new IPEndPoint(IPAddress.Parse(address), port)];
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e);
                                    }
                                }
                                Console.WriteLine(destEP);
                                udpClient.Send(recvBuffer, recvBuffer.Length, destEP);
                            }
                        }
                    }
                    Console.WriteLine("huh");
                }

                foreach (var client in connectedClients)
                {
                    if (!connected || receivedIP == "hi" || listenEP.Address.ToString() != client.Address.ToString())
                        continue;

                    udpClient.Send(recvBuffer, recvBuffer.Length, programEndpoint);
                    Console.WriteLine("huh 2");
                }
            }
        }

        public static void TcpListenLoop()
        {
            while (tcpClient.Connected)
            {
                try
                {
                    byte[] recvBuffer = new byte[tcpClient.ReceiveBufferSize];
                    int bytesRead = tcpClientStream.Read(recvBuffer, 0, tcpClient.ReceiveBufferSize);
                    Console.WriteLine("Received: " + Encoding.ASCII.GetString(recvBuffer, 0, bytesRead));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        /// <summary>
        /// Creates a new config.
        /// </summary>
        /// <returns>Returns `true` if creation was successful, `false` if creation was cancelled.</returns>
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