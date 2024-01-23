using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using System.Net.NetworkInformation;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using PacketDotNet.Utils;

namespace NATTunnel;

public struct MacIpPair
{
    public string MacAddress;
    public string IpAddress;
}

public enum CaptureMode
{
    /// <summary>
    ///Normal mode, captures and handles packets destined for a private IP address
    /// </summary>
    Private,
    /// <summary>
    ///Alternative mode for capturing data packets from a public endpoint
    /// </summary>
    Public
}

public class FrameCapture
{
    private bool running = true;
    private NetworkInterface defaultInterface;
    private PhysicalAddress defaultGatewayMac;
    private IPAddress myIP;
    private LibPcapLiveDevice device;
    private CaptureMode captureMode;
    private string sourceAddress;
    private int count = 0;
    private List<IPv4Packet> fragmentPacketList = new List<IPv4Packet>();
    private List<Fragment> fragmentMessageList = new List<Fragment>();
    //ipv6 minimum mtu, even though ipv6 isn't even currently supported
    private int enforcedMTU = 1280;
    public FrameCapture(CaptureMode mode = CaptureMode.Private, string address = "10.5.0.0")
    {
        captureMode = mode;
        sourceAddress = address;
    }

    public void Start()
    {
        Task init = Task.Run(() =>
        {
            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}", ver);

            device = GetPcapDevice();

            Console.WriteLine("WHAT {0}", device);
            defaultGatewayMac = PhysicalAddress.Parse(GetMacByIp(defaultInterface.GetIPProperties().GatewayAddresses.Select(g => g?.Address).Where(a => a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6).FirstOrDefault().ToString()));

            foreach (PcapAddress address in device.Addresses)
            {
                try
                {
                    if (address.Addr.ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        myIP = address.Addr.ipAddress;
                        Console.WriteLine(myIP);
                    }
                }
                catch (Exception ec)
                {
                    Console.WriteLine(ec);
                }
            }
        });

        init.Wait();

        Task capture = Task.Run(() =>
        {
            // Open the device for capturing
            device.Open(DeviceModes.Promiscuous, -1);
            if (captureMode == CaptureMode.Private)
            {
                device.Filter = $"net {sourceAddress}/24";
            }
            else
            {
                device.Filter = $"src host {sourceAddress}";
            }

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0}...", device.Description);

            RawCapture rawPacket;

            // Capture packets using GetNextPacket()
            PacketCapture e;
            GetPacketStatus retVal;
            while (running)
            {
                if ((retVal = device.GetNextPacket(out e)) == GetPacketStatus.PacketRead)
                {
                    rawPacket = e.GetPacket();
                    var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                    // Prints the time and length of each received packet
                    var time = rawPacket.Timeval.Date;
                    var len = rawPacket.Data.Length;
                    //Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);
                    try
                    {
                        EthernetPacket eth = packet.Extract<PacketDotNet.EthernetPacket>();
                        var origEthSrc = eth.SourceHardwareAddress;
                        var origEthDest = eth.DestinationHardwareAddress;
                        //Console.WriteLine(eth);
                        IPv4Packet ip = eth.Extract<PacketDotNet.IPv4Packet>();

                        if (captureMode == CaptureMode.Private)
                        {
                            if (ip.DestinationAddress.Equals(Tunnel.privateIP) || ip.DestinationAddress.Equals(myIP)) continue;
                            eth.SourceHardwareAddress = origEthDest;
                            eth.DestinationHardwareAddress = origEthSrc;
                            eth.UpdateCalculatedValues();
                            ip.SourceAddress = Tunnel.privateIP;
                            ip.UpdateCalculatedValues();
                            ip.UpdateIPChecksum();

                            //1 = more fragments
                            if (ip.FragmentOffset > 0 || ip.FragmentFlags == 1)
                            {
                                fragmentPacketList.Insert(0, ip);
                                if (ip.FragmentFlags == 0)
                                {
                                    ushort id = ip.Id;
                                    byte[] fragmentPayloadBytes = new byte[0];
                                    for (int i = fragmentPacketList.Count - 1; i >= 0; i--)
                                    {
                                        IPv4Packet tempPacket = fragmentPacketList[i];
                                        if (tempPacket.Id == id)
                                        {
                                            fragmentPayloadBytes = fragmentPayloadBytes.Concat(tempPacket.Bytes).ToArray();
                                            fragmentPacketList.RemoveAt(i);
                                        }
                                    }

                                    int currentOffset = 0;
                                    int remainderOffset = 0;
                                    bool run = true;
                                    while (run)
                                    {
                                        if (currentOffset < fragmentPayloadBytes.Length)
                                        {
                                            Console.WriteLine(currentOffset);

                                            byte[] fragmentBytes;
                                            ushort moreFragments;

                                            if ((currentOffset + enforcedMTU) < fragmentPayloadBytes.Length)
                                            {
                                                fragmentBytes = new byte[enforcedMTU];
                                                Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, enforcedMTU);
                                                moreFragments = 1;
                                            }
                                            else
                                            {
                                                remainderOffset = fragmentPayloadBytes.Length - currentOffset;
                                                fragmentBytes = new byte[remainderOffset];
                                                Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, remainderOffset);
                                                run = false;
                                                moreFragments = 0;
                                            }

                                            Tunnel.SendFrame(fragmentBytes, ip.DestinationAddress, BitConverter.GetBytes(id), BitConverter.GetBytes((ushort)currentOffset), BitConverter.GetBytes(moreFragments));

                                            currentOffset += enforcedMTU;
                                        }
                                    }
                                }
                            }
                            else
                            {
                                Tunnel.SendFrame(ip.Bytes, ip.DestinationAddress);
                            }
                        }
                        else
                        {
                            if (!ip.DestinationAddress.Equals(myIP)) continue;
                            UdpPacket udp = ip.Extract<PacketDotNet.UdpPacket>();
                            MediationMessage receivedMessage;
                            try
                            {
                                receivedMessage = new MediationMessage();
                                Console.WriteLine(udp.PayloadData.Length);
                                receivedMessage.DeserializeBytes(udp.PayloadData);

                                switch (receivedMessage.ID)
                                {
                                    case MediationMessageType.NATTunnelData:
                                        {
                                            //Console.WriteLine(count++);
                                            IPEndPoint clientSourceEndpoint = new IPEndPoint(ip.SourceAddress, udp.SourcePort);
                                            Client c = Clients.GetClient(clientSourceEndpoint);
                                            if (TunnelOptions.IsServer)
                                            {
                                                if (c != null && c.HasSymmetricKey)
                                                {
                                                    c.ResetTimeout();
                                                    byte[] tunnelData = new byte[receivedMessage.Data.Length];
                                                    c.aes.Decrypt(receivedMessage.Nonce, receivedMessage.Data, receivedMessage.AuthTag, tunnelData);

                                                    IPAddress targetPrivateAddress = receivedMessage.GetPrivateAddress();
                                                    //Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                                                    if (!c.Connected) continue;

                                                    if (targetPrivateAddress.Equals(Tunnel.privateIP))
                                                    {
                                                        Send(tunnelData, receivedMessage.FragmentID, receivedMessage.FragmentOffset, receivedMessage.MoreFragments);
                                                    }
                                                    else
                                                    {
                                                        Tunnel.SendFrame(tunnelData, targetPrivateAddress, receivedMessage.FragmentID, receivedMessage.FragmentOffset, receivedMessage.MoreFragments);
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                if (Tunnel.serverHasSymmetricKey)
                                                {
                                                    byte[] tunnelData = new byte[receivedMessage.Data.Length];
                                                    Tunnel.aes.Decrypt(receivedMessage.Nonce, receivedMessage.Data, receivedMessage.AuthTag, tunnelData);
                                                    //Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                                                    if (!Tunnel.connected) continue;

                                                    Send(tunnelData, receivedMessage.FragmentID, receivedMessage.FragmentOffset, receivedMessage.MoreFragments);
                                                }
                                            }
                                        }
                                        break;
                                }
                            }
                            catch (Exception err)
                            {
                                //Console.WriteLine(err);
                            }
                        }
                    }
                    catch (Exception error)
                    {
                        //Console.WriteLine(error);
                    }
                }
            }
        });
    }

    public void Send(byte[] packetData, byte[] fragmentID, byte[] fragmentOffset, byte[] moreFragments)
    {
        if (BitConverter.ToUInt16(fragmentID) != 0)
        {
            fragmentMessageList.Insert(0, new Fragment(packetData, fragmentID, fragmentOffset, moreFragments));
            if (BitConverter.ToUInt16(fragmentOffset) > 0 && BitConverter.ToUInt16(moreFragments) == 0)
            {
                ushort id = BitConverter.ToUInt16(fragmentID);
                byte[] fragmentPayloadBytes = new byte[0];
                for (int i = fragmentMessageList.Count - 1; i >= 0; i--)
                {
                    Fragment tempFragment = fragmentMessageList[i];
                    if (BitConverter.ToUInt16(tempFragment.ID) == id)
                    {
                        fragmentPayloadBytes = fragmentPayloadBytes.Concat(tempFragment.Bytes).ToArray();
                        fragmentMessageList.RemoveAt(i);
                    }
                }

                byte[] tempBytes = new byte[enforcedMTU];
                Array.Copy(fragmentPayloadBytes, 0, tempBytes, 0, enforcedMTU);
                IPv4Packet tempIP = new IPv4Packet(new ByteArraySegment(tempBytes));

                int originalLength = tempIP.TotalLength;
                int currentOffset = 0;
                bool run = true;
                while (run)
                {
                    if (currentOffset < fragmentPayloadBytes.Length)
                    {
                        Console.WriteLine(currentOffset);

                        byte[] fragmentBytes;

                        if ((currentOffset + originalLength) < fragmentPayloadBytes.Length)
                        {
                            fragmentBytes = new byte[originalLength];
                            Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, originalLength);
                        }
                        else
                        {
                            int remainderOffset = fragmentPayloadBytes.Length - currentOffset;
                            fragmentBytes = new byte[remainderOffset];
                            Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, remainderOffset);
                            run = false;
                        }

                        EthernetPacket newPacket = new EthernetPacket(defaultGatewayMac, defaultInterface.GetPhysicalAddress(), EthernetType.IPv4);
                        //eth.DestinationHardwareAddress = defaultInterface.GetPhysicalAddress();
                        //eth.SourceHardwareAddress = defaultGatewayMac;
                        //eth.UpdateCalculatedValues();
                        IPv4Packet ip = new IPv4Packet(new ByteArraySegment(fragmentBytes));
                        //if(ip.DestinationAddress.Equals(Tunnel.privateIP)) continue;
                        ip.DestinationAddress = myIP;
                        ip.UpdateCalculatedValues();
                        ip.UpdateIPChecksum();

                        try
                        {
                            UdpPacket udp = ip.Extract<PacketDotNet.UdpPacket>();
                            udp.UpdateCalculatedValues();
                            udp.UpdateUdpChecksum();
                            ip.PayloadPacket = udp;
                            if (TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(udp.DestinationPort))
                            {
                                Console.WriteLine("BRO WHAT 1");
                                continue;
                            }
                            if (!TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(udp.SourcePort))
                            {
                                Console.WriteLine("BRO WHAT 1");
                                continue;
                            }
                        }
                        catch (Exception e)
                        {
                            //Console.WriteLine(e);
                        }

                        try
                        {
                            TcpPacket tcp = ip.Extract<PacketDotNet.TcpPacket>();
                            tcp.UpdateCalculatedValues();
                            tcp.UpdateTcpChecksum();
                            ip.PayloadPacket = tcp;
                            if (TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(tcp.DestinationPort))
                            {
                                Console.WriteLine("BRO WHAT 2");
                                continue;
                            }
                            if (!TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(tcp.SourcePort))
                            {
                                Console.WriteLine("BRO WHAT 2");
                                continue;
                            }
                        }
                        catch (Exception e)
                        {
                            //Console.WriteLine(e);
                        }

                        newPacket.PayloadPacket = ip;
                        newPacket.UpdateCalculatedValues();
                        device.SendPacket(newPacket);

                        currentOffset += originalLength;
                    }
                }
            }
        }
        else
        {
            EthernetPacket newPacket = new EthernetPacket(defaultGatewayMac, defaultInterface.GetPhysicalAddress(), EthernetType.IPv4);
            //eth.DestinationHardwareAddress = defaultInterface.GetPhysicalAddress();
            //eth.SourceHardwareAddress = defaultGatewayMac;
            //eth.UpdateCalculatedValues();
            IPv4Packet ip = new IPv4Packet(new ByteArraySegment(packetData));
            //if(ip.DestinationAddress.Equals(Tunnel.privateIP)) continue;
            ip.DestinationAddress = myIP;
            ip.UpdateCalculatedValues();
            ip.UpdateIPChecksum();

            try
            {
                UdpPacket udp = ip.Extract<PacketDotNet.UdpPacket>();
                udp.UpdateCalculatedValues();
                udp.UpdateUdpChecksum();
                ip.PayloadPacket = udp;
                if (TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(udp.DestinationPort))
                {
                    Console.WriteLine(udp.DestinationPort);
                    Console.WriteLine(TunnelOptions.WhitelistedPorts[0]);
                    Console.WriteLine("BRO WHAT 3");
                    return;
                }
                if (!TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(udp.SourcePort))
                {
                    Console.WriteLine(udp.DestinationPort);
                    Console.WriteLine(TunnelOptions.WhitelistedPorts[0]);
                    Console.WriteLine("BRO WHAT 3");
                    return;
                }
            }
            catch (Exception e)
            {
                //Console.WriteLine(e);
            }

            try
            {
                TcpPacket tcp = ip.Extract<PacketDotNet.TcpPacket>();
                tcp.UpdateCalculatedValues();
                tcp.UpdateTcpChecksum();
                ip.PayloadPacket = tcp;
                if (TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(tcp.DestinationPort))
                {
                    Console.WriteLine(tcp.DestinationPort);
                    Console.WriteLine(TunnelOptions.WhitelistedPorts[0]);
                    Console.WriteLine("BRO WHAT 4");
                    return;
                }
                if (!TunnelOptions.IsServer && TunnelOptions.UsingWhitelist && !TunnelOptions.WhitelistedPorts.Contains(tcp.SourcePort))
                {
                    Console.WriteLine(tcp.DestinationPort);
                    Console.WriteLine(TunnelOptions.WhitelistedPorts[0]);
                    Console.WriteLine("BRO WHAT 4");
                    return;
                }
            }
            catch (Exception e)
            {
                //Console.WriteLine(e);
            }

            newPacket.PayloadPacket = ip;
            newPacket.UpdateCalculatedValues();
            device.SendPacket(newPacket);
        }
    }

    public void Stop()
    {
        running = false;
    }

    internal LibPcapLiveDevice GetPcapDevice()
    {
        var nics = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var inf in PcapInterface.GetAllPcapInterfaces())
        {
            var friendlyName = inf.FriendlyName ?? string.Empty;
            if (friendlyName.ToLower().Contains("loopback") || friendlyName == "any")
            {
                continue;
            }
            if (friendlyName == "virbr0-nic")
            {
                continue;
            }
            var nic = nics.FirstOrDefault(ni => ni.Name == friendlyName);
            if (nic?.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }
            if (nic.GetIPProperties().GatewayAddresses.Count == 0)
            {
                continue;
            }
            using var device = new LibPcapLiveDevice(inf);
            LinkLayers link;
            try
            {
                defaultInterface = nic;
                device.Open();
                link = device.LinkType;
            }
            catch (PcapException ex)
            {
                Console.WriteLine(ex);
                continue;
            }

            if (link == LinkLayers.Ethernet)
            {
                return device;
            }
        }
        throw new InvalidOperationException("No ethernet pcap supported devices found, are you running" +
                                        " as a user with access to adapters (root on Linux)?");
    }

    public string GetMacByIp(string ip)
    {
        var pairs = this.GetMacIpPairs();

        foreach (var pair in pairs)
        {
            if (pair.IpAddress == ip)
                return pair.MacAddress;
        }

        throw new Exception($"Can't retrieve mac address from ip: {ip}");
    }

    public IEnumerable<MacIpPair> GetMacIpPairs()
    {
        System.Diagnostics.Process pProcess = new System.Diagnostics.Process();
        pProcess.StartInfo.FileName = "arp";
        pProcess.StartInfo.Arguments = "-a ";
        pProcess.StartInfo.UseShellExecute = false;
        pProcess.StartInfo.RedirectStandardOutput = true;
        pProcess.StartInfo.CreateNoWindow = true;
        pProcess.Start();

        string cmdOutput = pProcess.StandardOutput.ReadToEnd();
        string pattern = @"(?<ip>([0-9]{1,3}\.?){4})\s*(?<mac>([a-f0-9]{2}-?){6})";

        foreach (Match m in Regex.Matches(cmdOutput, pattern, RegexOptions.IgnoreCase))
        {
            yield return new MacIpPair()
            {
                MacAddress = m.Groups["mac"].Value,
                IpAddress = m.Groups["ip"].Value
            };
        }
    }
}
