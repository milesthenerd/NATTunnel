using NATTunnel.Common;
using System;

namespace NATTunnel
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            //TODO: this whole project has a bunch of obsolete console.writelines

            //TODO: the port endpoint has to be the same as the mediationclientport, as otherwise this is handled weirdly somewhere in this mess

            // NodeOptions / config file loading is done in the MediationClient constructor
            // as it is the first thing we call and the class that relies most upon the settings.
            MediationClient.TrackedClient();

            TunnelNode tunnelNode = new TunnelNode();

            if (NodeOptions.isServer)
            {
                MediationClient.UdpServer();
                Console.WriteLine($"Server forwarding {NodeOptions.endpoints[0]} to UDP port {NodeOptions.localPort}");
                if (NodeOptions.masterServerID != 0)
                    Console.WriteLine($"Server registering with master ID {NodeOptions.masterServerID}");
            }
            else
            {
                MediationClient.UdpClient();
                Console.WriteLine($"Client forwarding TCP port {NodeOptions.localPort} to UDP server {(NodeOptions.masterServerID != 0 ? NodeOptions.masterServerID : NodeOptions.endpoints[0])}");
            }

            Console.WriteLine("Press q or ctrl+c to quit.");
            bool hasConsole = true;
            bool running = true;
            Console.CancelKeyPress += (s, e) => { running = false; tunnelNode.Stop(); };
            while (running)
            {
                if (!hasConsole)
                    continue;

                try
                {
                    ConsoleKeyInfo cki = Console.ReadKey(false);
                    if (cki.KeyChar == 'q')
                        running = false;
                }
                catch (InvalidOperationException)
                {
                    Console.WriteLine("Program does not have a console, not listening for console input.");
                    hasConsole = false;
                }
            }
        }
    }
}