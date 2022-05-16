using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace NATTunnel.Common;

/// <summary>
/// Possible protocols to use for application communication.
/// </summary>
public enum ConnectionTypes
{
    TCP,
    UDP
}

/// <summary>
/// Class that holds option values for various parts for NATTunnel.
/// </summary>
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
    public static IPEndPoint Endpoint = new IPEndPoint(IPAddress.Loopback, 26702);

    /// <summary>
    /// The public IP of the mediation server you want to connect to.
    /// </summary>
    public static IPEndPoint MediationIp = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

    /// <summary>
    /// The public IP of the server Tunnel you want to connect to. Only used as a client.
    /// </summary>
    public static IPAddress RemoteIp = IPAddress.Loopback;

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
    /// Indicated whether IPv6 is supported.
    /// </summary>
    public static bool IsIPv6Supported { get; }

    /// <summary>
    /// Indicates whether IPv4 is supported.
    /// </summary>
    public static bool IsIPv4Supported { get; }
    /// <summary>
    /// Indicates what protocol to use for application communication.
    /// </summary>
    public static ConnectionTypes ConnectionType = ConnectionTypes.TCP;

    // Constructor for Node options, determines whether ipv6 and ipv4 are supported.
    static NodeOptions()
    {
        NetworkInterface[] nets = NetworkInterface.GetAllNetworkInterfaces();

        foreach (NetworkInterface net in nets)
        {
            if (net.OperationalStatus != OperationalStatus.Up) continue;

            if (net.Supports(NetworkInterfaceComponent.IPv4))
                IsIPv4Supported = true;
            if (net.Supports(NetworkInterfaceComponent.IPv6))
                IsIPv6Supported = true;
        }
    }
}