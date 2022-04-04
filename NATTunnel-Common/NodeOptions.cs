using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace NATTunnel.Common
{
    public static class NodeOptions
    {
        //TODO: documentation needed
        /// <summary>
        /// Indicates whether the Tunnel is in a server state or client State.
        /// </summary>
        public static bool IsServer = false;

        /// <summary>
        /// Servers: Indicates the TCP server to connect to for forwarding over UDP. <br/>
        /// Clients: The UDP server to connect to.
        /// </summary>
        public static string Endpoint = "serverhost.address.example.com:26702";

        /// <summary>
        /// The public IP of the mediation server you want to conneect to.
        /// </summary>
        public static IPEndPoint MediationIp = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

        /// <summary>
        /// The public IP of the server Tunnel you want to connect to. Only used as a client.
        /// </summary>
        public static IPAddress RemoteIp = IPAddress.Loopback;

        /// <summary>
        ///
        /// </summary>
        public static readonly List<IPEndPoint> Endpoints = new List<IPEndPoint>();

        /// <summary>
        /// Servers: The UDP server port <br/>
        /// Clients: The TCP port to host the forwarded server on.
        /// </summary>
        public static int LocalPort = 0;

        /// <summary>
        ///
        /// </summary>
        public static int MediationClientPort = 5000;

        /// <summary>
        /// The upload limit in kB/s the Tunnel sends.
        /// </summary>
        public static int UploadSpeed = 512;

        /// <summary>
        /// The download limit in kB/s the Tunnel uses.
        /// </summary>
        public static int DownloadSpeed = 512;

        /// <summary>
        /// Indicates by how many milliseconds delay the Tunnel sends unacknowledged packets
        /// </summary>
        public static int MinRetransmitTime = 100;

        /// <summary>
        /// Tries to load the config file.
        /// </summary>
        /// <returns>Returns <see langword="true"/> if loading was successful, <see langword="false"/> if it wasn't.</returns>
        //TODO: this only ever returns true
        public static bool TryLoadConfig()
        {
            //TODO: this currently hardcodes the config file to $PWD/config.txt. Bad idea.
            using StreamReader streamReader = new StreamReader("config.txt");
            string currentLine;
            while ((currentLine = streamReader.ReadLine()) != null)
            {
                int splitIndex = currentLine.IndexOf("=", StringComparison.Ordinal);
                if (splitIndex <= 0) continue;

                string lhs = currentLine.Substring(0, splitIndex);
                string rhs = currentLine.Substring(splitIndex + 1);
                switch (lhs)
                {
                    case "mode":
                        IsServer = rhs == "server";
                        break;
                    case "endpoint":
                        Endpoint = rhs;
                        ResolveAddress();
                        break;
                    case "mediationIP":
                        MediationIp = IPEndPoint.Parse(rhs);
                        break;
                    case "remoteIP":
                        RemoteIp = IPAddress.Parse(rhs);
                        break;
                    case "localPort":
                        LocalPort = Int32.Parse(rhs);
                        break;
                    case "mediationClientPort":
                        MediationClientPort = Int32.Parse(rhs);
                        break;
                    case "uploadSpeed":
                        UploadSpeed = Int32.Parse(rhs);
                        break;
                    case "downloadSpeed":
                        DownloadSpeed = Int32.Parse(rhs);
                        break;
                    case "minRetransmitTime":
                        MinRetransmitTime = Int32.Parse(rhs);
                        break;
                }
            }
            return true;
        }

        /// <summary>
        /// Creates a new config file, filling it out with default values.
        /// </summary>
        public static void CreateNewConfig()
        {
            //TODO: also hardcodes the config path to $PWD/config.txt
            using StreamWriter sw = new StreamWriter("config.txt");
            sw.WriteLine("#mode: Set to server if you want to host a local server over UDP, client if you want to connect to a server over UDP");
            sw.WriteLine($"mode={(IsServer ? "server" : "client")}");
            sw.WriteLine();
            sw.WriteLine("#endpoint, servers: The TCP server to connect to for forwarding over UDP. Client: The UDP server to connect to");
            sw.WriteLine($"endpoint={Endpoint}");
            sw.WriteLine();
            sw.WriteLine("#mediationIP: The public IP and port of the mediation server you want to connect to.");
            sw.WriteLine($"mediationIP={MediationIp}");
            sw.WriteLine();
            sw.WriteLine("#remoteIP, clients: The public IP of the peer you want to connect to.");
            sw.WriteLine($"remoteIP={RemoteIp}");
            sw.WriteLine();
            sw.WriteLine("#localPort: servers: The UDP server port. client: The TCP port to host the forwarded server on.");
            sw.WriteLine($"localPort={LocalPort}");
            sw.WriteLine();
            sw.WriteLine("#mediationClientPort: The UDP mediation client port. This is the port that will have a hole punched through the NAT by the mediation server, and all traffic will pass through it.");
            sw.WriteLine($"mediationClientPort={MediationClientPort}");
            sw.WriteLine();
            sw.WriteLine("#uploadSpeed/downloadSpeed: Specify your connection limit (kB/s), this program sends at a fixed rate.");
            sw.WriteLine($"uploadSpeed={UploadSpeed}");
            sw.WriteLine($"downloadSpeed={DownloadSpeed}");
            sw.WriteLine();
            sw.WriteLine("#minRetransmitTime: How many milliseconds delay to send unacknowledged packets");
            sw.WriteLine($"minRetransmitTime={MinRetransmitTime}");
        }

        /// <summary>
        /// Resolves <see cref="Endpoint"/> as either IP address or hostname,
        /// and adds it to <see cref="Endpoints"/>.
        /// </summary>
        private static void ResolveAddress()
        {
            Endpoints.Clear();
            int splitIndex = Endpoint.LastIndexOf(":", StringComparison.Ordinal);
            string lhs = Endpoint.Substring(0, splitIndex);
            string rhs = Endpoint.Substring(splitIndex + 1);
            int port = Int32.Parse(rhs);
            if (IPAddress.TryParse(lhs, out IPAddress addr))
            {
                Endpoints.Add(new IPEndPoint(addr, port));
            }
            //Left side is probably hostname instead, so let's try to resolve it and go through + add the IPs from that
            //TODO: why not just always do that?
            else
            {
                foreach (IPAddress addr2 in Dns.GetHostAddresses(lhs))
                {
                    Endpoints.Add(new IPEndPoint(addr2, port));
                }
            }
        }
    }
}