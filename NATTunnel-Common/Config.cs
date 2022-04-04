using System;
using System.IO;
using System.Net;

namespace NATTunnel.Common
{
    /// <summary>
    /// Class to access configuration files.
    /// </summary>
	public static class Config
	{
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
                        NodeOptions.IsServer = rhs == "server";
                        break;
                    case "endpoint":
                        NodeOptions.Endpoint = rhs;
                        NodeOptions.ResolveAddress();
                        break;
                    case "mediationIP":
                        NodeOptions.MediationIp = IPEndPoint.Parse(rhs);
                        break;
                    case "remoteIP":
                        NodeOptions.RemoteIp = IPAddress.Parse(rhs);
                        break;
                    case "localPort":
                        NodeOptions.LocalPort = Int32.Parse(rhs);
                        break;
                    case "mediationClientPort":
                        NodeOptions.MediationClientPort = Int32.Parse(rhs);
                        break;
                    case "uploadSpeed":
                        NodeOptions.UploadSpeed = Int32.Parse(rhs);
                        break;
                    case "downloadSpeed":
                        NodeOptions.DownloadSpeed = Int32.Parse(rhs);
                        break;
                    case "minRetransmitTime":
                        NodeOptions.MinRetransmitTime = Int32.Parse(rhs);
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
            sw.WriteLine($"mode={(NodeOptions.IsServer ? "server" : "client")}");
            sw.WriteLine();
            sw.WriteLine("#endpoint, servers: The TCP server to connect to for forwarding over UDP. Client: The UDP server to connect to");
            sw.WriteLine($"endpoint={NodeOptions.Endpoint}");
            sw.WriteLine();
            sw.WriteLine("#mediationIP: The public IP and port of the mediation server you want to connect to.");
            sw.WriteLine($"mediationIP={NodeOptions.MediationIp}");
            sw.WriteLine();
            sw.WriteLine("#remoteIP, clients: The public IP of the peer you want to connect to.");
            sw.WriteLine($"remoteIP={NodeOptions.RemoteIp}");
            sw.WriteLine();
            sw.WriteLine("#localPort: servers: The UDP server port. client: The TCP port to host the forwarded server on.");
            sw.WriteLine($"localPort={NodeOptions.LocalPort}");
            sw.WriteLine();
            sw.WriteLine("#mediationClientPort: The UDP mediation client port. This is the port that will have a hole punched through the NAT by the mediation server, and all traffic will pass through it.");
            sw.WriteLine($"mediationClientPort={NodeOptions.MediationClientPort}");
            sw.WriteLine();
            sw.WriteLine("#uploadSpeed/downloadSpeed: Specify your connection limit (kB/s), this program sends at a fixed rate.");
            sw.WriteLine($"uploadSpeed={NodeOptions.UploadSpeed}");
            sw.WriteLine($"downloadSpeed={NodeOptions.DownloadSpeed}");
            sw.WriteLine();
            sw.WriteLine("#minRetransmitTime: How many milliseconds delay to send unacknowledged packets");
            sw.WriteLine($"minRetransmitTime={NodeOptions.MinRetransmitTime}");
        }
	}
}