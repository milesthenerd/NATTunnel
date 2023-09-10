using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Tunneling;
using PacketDotNet;
using System.Net.NetworkInformation;
using System;
using System.Diagnostics;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using PacketDotNet.Utils;
using PacketDotNet.DhcpV4;
using SharpPcap.WinDivert;

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
    private int enforcedMTU = 1280;
    public FrameCapture(CaptureMode mode = CaptureMode.Private, string address = "10.5.0.0")
    {
        captureMode = mode;
        sourceAddress = address;
    }

    public void Start()
    {
        new Task(() => {
            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}", ver);

            device = GetPcapDevice();
            defaultGatewayMac = PhysicalAddress.Parse(GetMacByIp(defaultInterface.GetIPProperties().GatewayAddresses.Select(g => g?.Address).Where(a => a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6).FirstOrDefault().ToString()));
            
            foreach(PcapAddress address in device.Addresses)
            {
                try {
                    if(address.Addr.ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        myIP = address.Addr.ipAddress;
                        Console.WriteLine(myIP);
                    }
                }
                catch(Exception ec)
                {
                    Console.WriteLine(ec);
                }
            }

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
            while (running) {
                if ((retVal = device.GetNextPacket(out e)) == GetPacketStatus.PacketRead)
                {
                    rawPacket = e.GetPacket();
                    var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                    // Prints the time and length of each received packet
                    var time = rawPacket.Timeval.Date;
                    var len = rawPacket.Data.Length;
                    //Console.WriteLine("{0}:{1}:{2},{3} Len={4}", time.Hour, time.Minute, time.Second, time.Millisecond, len);
                    try {
                        EthernetPacket eth = packet.Extract<PacketDotNet.EthernetPacket>();
                        var origEthSrc = eth.SourceHardwareAddress;
                        var origEthDest = eth.DestinationHardwareAddress;
                        //Console.WriteLine(eth);
                        IPv4Packet ip = eth.Extract<PacketDotNet.IPv4Packet>();

                        if (captureMode == CaptureMode.Private)
                        {
                            if(ip.DestinationAddress.Equals(Tunnel.privateIP) || ip.DestinationAddress.Equals(myIP)) continue;
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
                                    for (int i=fragmentPacketList.Count - 1; i>=0; i--)
                                    {
                                        IPv4Packet tempPacket = fragmentPacketList[i];
                                        if (tempPacket.Id == id)
                                        {
                                            Console.WriteLine("why?");
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
                                            Console.WriteLine("okay?");
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
                                                Console.WriteLine("built correctly?");
                                                fragmentBytes = new byte[remainderOffset];
                                                Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, remainderOffset);
                                                run = false;
                                                Console.WriteLine("is now false?");
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
                            if(!ip.DestinationAddress.Equals(myIP)) continue;
                            UdpPacket udp = ip.Extract<PacketDotNet.UdpPacket>();
                            MediationMessage receivedMessage;
                            try
                            {
                                receivedMessage = new MediationMessage();
                                Console.WriteLine(udp.PayloadData.Length);
                                receivedMessage.DeserializeBytes(udp.PayloadData);
                                
                                switch(receivedMessage.ID)
                                {
                                    case MediationMessageType.NATTunnelData:
                                    {
                                        //Console.WriteLine(count++);
                                        IPEndPoint clientSourceEndpoint = new IPEndPoint(ip.SourceAddress, udp.SourcePort);
                                        Client c = Clients.GetClient(clientSourceEndpoint);
                                        if (NodeOptions.IsServer)
                                        {
                                            if (c != null && c.HasSymmetricKey)
                                            {
                                                c.ResetTimeout();
                                                byte[] tunnelData = new byte[receivedMessage.Data.Length];
                                                c.aes.Decrypt(receivedMessage.Nonce, receivedMessage.Data, receivedMessage.AuthTag, tunnelData);

                                                IPAddress targetPrivateAddress = receivedMessage.GetPrivateAddress();
                                                //Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                                                if (!c.Connected) continue;

                                                Console.WriteLine("step 0.5?");
                                                if (targetPrivateAddress.Equals(Tunnel.privateIP))
                                                {
                                                    Console.WriteLine("step 0.9?");
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
                            catch(Exception err)
                            {
                                Console.WriteLine(err);
                            }
                        }
                    }
                    catch(Exception error) {
                        Console.WriteLine(error);
                    }
                }
            }
        }).Start();
    }

    public void Send(byte[] packetData, byte[] fragmentID, byte[] fragmentOffset, byte[] moreFragments)
    {
        if (BitConverter.ToUInt16(fragmentID) != 0)
        {
            Console.WriteLine("step 1?");
            fragmentMessageList.Insert(0, new Fragment(packetData, fragmentID, fragmentOffset, moreFragments));
            if (BitConverter.ToUInt16(fragmentOffset) > 0 && BitConverter.ToUInt16(moreFragments) == 0)
            {
                Console.WriteLine("step 2?");
                ushort id = BitConverter.ToUInt16(fragmentID);
                byte[] fragmentPayloadBytes = new byte[0];
                for (int i=fragmentMessageList.Count - 1; i>=0; i--)
                {
                    Console.WriteLine("step 3?");
                    Fragment tempFragment = fragmentMessageList[i];
                    if (BitConverter.ToUInt16(tempFragment.ID) == id)
                    {
                        Console.WriteLine("step 4?");
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
                        Console.WriteLine("step 5?");
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
                            Console.WriteLine("built correctly?");
                            fragmentBytes = new byte[remainderOffset];
                            Array.Copy(fragmentPayloadBytes, currentOffset, fragmentBytes, 0, remainderOffset);
                            run = false;
                            Console.WriteLine("is now false?");
                        }
                        
                        Console.WriteLine("step 5?");
                        EthernetPacket newPacket = new EthernetPacket(defaultGatewayMac, defaultInterface.GetPhysicalAddress(), EthernetType.IPv4);
                        //eth.DestinationHardwareAddress = defaultInterface.GetPhysicalAddress();
                        //eth.SourceHardwareAddress = defaultGatewayMac;
                        //eth.UpdateCalculatedValues();
                        IPv4Packet ip = new IPv4Packet(new ByteArraySegment(fragmentBytes));
                        Console.WriteLine(fragmentPayloadBytes.Length);
                        Console.WriteLine(ip.Protocol);
                        Console.WriteLine(ip.SourceAddress.ToString());
                        Console.WriteLine(ip.DestinationAddress.ToString());
                        Console.WriteLine(ip.Id);
                        Console.WriteLine(ip.ValidChecksum);
                        Console.WriteLine(ip.ValidIPChecksum);
                        Console.WriteLine(ip.HasPayloadData);
                        Console.WriteLine(ip.HasPayloadPacket);
                        Console.WriteLine(ip.TotalLength);
                        Console.WriteLine(ip.PayloadLength);
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
                        }
                        catch(Exception e)
                        {
                            //Console.WriteLine(e);
                        }

                        try
                        {
                            TcpPacket tcp = ip.Extract<PacketDotNet.TcpPacket>();
                            tcp.UpdateCalculatedValues();
                            tcp.UpdateTcpChecksum();
                            ip.PayloadPacket = tcp;
                        }
                        catch(Exception e)
                        {
                            //Console.WriteLine(e);
                        }

                        newPacket.PayloadPacket = ip;
                        newPacket.UpdateCalculatedValues();
                        device.SendPacket(newPacket);
                        Console.WriteLine("oh YEAH BABY LET'S GOOOOO");

                        currentOffset += originalLength;
                    }
                }
            }
        }
        else
        {
            Console.WriteLine("pls work like should?");
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
            }
            catch(Exception e)
            {
                //Console.WriteLine(e);
            }

            try
            {
                TcpPacket tcp = ip.Extract<PacketDotNet.TcpPacket>();
                tcp.UpdateCalculatedValues();
                tcp.UpdateTcpChecksum();
                ip.PayloadPacket = tcp;
            }
            catch(Exception e)
            {
                //Console.WriteLine(e);
            }

            newPacket.PayloadPacket = ip;
            newPacket.UpdateCalculatedValues();
            device.SendPacket(newPacket);
            Console.WriteLine("oh");
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

        foreach(var pair in pairs)
        {
            if(pair.IpAddress == ip)
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

        foreach(Match m in Regex.Matches(cmdOutput, pattern, RegexOptions.IgnoreCase))
        {
            yield return new MacIpPair()
            {
                MacAddress = m.Groups[ "mac" ].Value,
                IpAddress = m.Groups[ "ip" ].Value
            };
        }
    }
}
