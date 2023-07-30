using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Tunneling;
using PacketDotNet;
using System.Net.NetworkInformation;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;

namespace NATTunnel;

public struct MacIpPair
{
    public string MacAddress;
    public string IpAddress;
}

public class FrameCapture
{
    private bool running = true;
    private NetworkInterface defaultInterface;
    private PhysicalAddress defaultGatewayMac;
    private IPAddress myIP;
    private LibPcapLiveDevice device;
    public FrameCapture() {}

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
                    if(address.Addr.ipAddress.ToString().Contains("10.220"))
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
            device.Open(DeviceModes.MaxResponsiveness, 0);
            device.Filter = "net 10.5.0.0/24";

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0}...",
                device.Description);

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
                    Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
                        time.Hour, time.Minute, time.Second, time.Millisecond, len);
                    try {
                        EthernetPacket eth = packet.Extract<PacketDotNet.EthernetPacket>();
                        var origEthSrc = eth.SourceHardwareAddress;
                        var origEthDest = eth.DestinationHardwareAddress;
                        Console.WriteLine(eth);
                        IPv4Packet ip = eth.Extract<PacketDotNet.IPv4Packet>();
                        if(ip.DestinationAddress.Equals(MediationClient.localIP) || ip.DestinationAddress.Equals(myIP)) continue;
                        eth.SourceHardwareAddress = origEthDest;
                        eth.DestinationHardwareAddress = origEthSrc;
                        eth.UpdateCalculatedValues();
                        ip.SourceAddress = MediationClient.localIP;
                        ip.UpdateCalculatedValues();
                        ip.UpdateIPChecksum();
                        MediationClient.Send(eth.Bytes);
                    }
                    catch(Exception error) {
                        Console.WriteLine(error);
                    }
                }
            }
        }).Start();
    }

    public void Send(byte[] packetData)
    {
        var givenPacket = PacketDotNet.Packet.ParsePacket(LinkLayers.Ethernet, packetData);
        var newPacket = new EthernetPacket(defaultGatewayMac, defaultInterface.GetPhysicalAddress(), EthernetType.IPv4);
        //eth.DestinationHardwareAddress = defaultInterface.GetPhysicalAddress();
        //eth.SourceHardwareAddress = defaultGatewayMac;
        //eth.UpdateCalculatedValues();
        EthernetPacket eth = givenPacket.Extract<PacketDotNet.EthernetPacket>();
        IPv4Packet ip = eth.Extract<PacketDotNet.IPv4Packet>();
        //if(ip.DestinationAddress.Equals(MediationClient.localIP)) continue;
        ip.DestinationAddress = myIP;
        ip.UpdateCalculatedValues();
        ip.UpdateIPChecksum();

        try{
            UdpPacket udp = ip.Extract<PacketDotNet.UdpPacket>();
            udp.UpdateCalculatedValues();
            udp.UpdateUdpChecksum();
            ip.PayloadPacket = udp;
        }
        catch(Exception e)
        {
            Console.WriteLine(e);
        }

        try{
            TcpPacket tcp = ip.Extract<PacketDotNet.TcpPacket>();
            tcp.UpdateCalculatedValues();
            tcp.UpdateTcpChecksum();
            ip.PayloadPacket = tcp;
        }
        catch(Exception e)
        {
            Console.WriteLine(e);
        }

        newPacket.PayloadPacket = ip;
        newPacket.UpdateCalculatedValues();
        device.SendPacket(newPacket);
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
                // Semaphore CI have this interface, and it's always down
                // OperationalStatus does not detect it correctly
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
