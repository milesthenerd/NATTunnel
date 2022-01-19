using NATTunnel.Common;
using NATTunnel.Common.Messages;
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NATTunnel.Master
{
    public class MasterServer
    {
        private Socket udp;
        private UdpConnection connection;
        private ConcurrentDictionary<int, PublishEntry> published = new ConcurrentDictionary<int, PublishEntry>();

        public MasterServer(int port)
        {
            SetupUDPSocket(port);
            connection = new UdpConnection(udp, ReceiveCallback);
        }

        public void Stop()
        {
            connection.Stop();
            udp.Close();
        }

        private void SetupUDPSocket(int port)
        {
            udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            udp.DualMode = true;
            udp.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        }

        private void ReceiveCallback(IMessage message, IPEndPoint endpoint)
        {
            switch (message)
            {
                case MasterServerInfoRequest msi:
                {
                    MasterServerInfoReply msir = new MasterServerInfoReply
                    {
                        server = msi.server,
                        client = msi.client,
                        status = false,
                        message = "ID not found"
                    };
                    if (published.TryGetValue(msi.server, out PublishEntry entry))
                    {
                        msir.status = true;
                        msir.message = "OK";
                        msir.endpoints = entry.endpoints;
                    }
                    Console.WriteLine($"MSIR: {msir.client} connecting to {msi.server}, status: {msir.message}");
                    connection.Send(msi, endpoint);
                    break;
                }
                case MasterServerPublishRequest msp:
                {
                    MasterServerPublishReply mspr = new MasterServerPublishReply
                    {
                        id = msp.Id,
                        status = false,
                        message = "ID already registered to another server"
                    };
                    if (published.TryGetValue(mspr.id, out PublishEntry entry))
                    {
                        if (msp.secret == entry.secret)
                        {
                            if (!entry.endpoints.Contains(endpoint))
                                entry.endpoints.Add(endpoint);

                            entry.lastPublishTime = DateTime.UtcNow.Ticks;
                            mspr.status = true;
                            mspr.message = "Updated OK";
                        }
                    }
                    else
                    {
                        PublishEntry entry2 = new PublishEntry
                        {
                            secret = msp.secret,
                            lastPublishTime = DateTime.UtcNow.Ticks
                        };
                        if (!entry2.endpoints.Contains(endpoint))
                            entry2.endpoints.Add(endpoint);

                        published.TryAdd(msp.Id, entry2);
                        mspr.status = true;
                        mspr.message = "Registered OK";
                    }
                    Console.WriteLine($"MSPR: {mspr.id} status {mspr.message}");
                    connection.Send(mspr, endpoint);
                    break;
                }
            }
        }
    }
}