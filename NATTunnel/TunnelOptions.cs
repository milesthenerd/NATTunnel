using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using Tomlyn.Model;

namespace NATTunnel;

/// <summary>
/// Class that holds option values for various parts for NATTunnel.
/// </summary>
public static class TunnelOptions
{
    //TODO: documentation needed
    /// <summary>
    /// Indicates whether the Tunnel is in a server state or client State.
    /// </summary>
    public static bool IsServer = false;

    /// <summary>
    /// The public IP of the mediation server you want to connect to.
    /// </summary>
    public static IPEndPoint MediationEndpoint = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

    /// <summary>
    /// The public IP of the server Tunnel you want to connect to. Only used as a client.
    /// </summary>
    public static IPAddress RemoteIp = IPAddress.Loopback;

    /// <summary>
    /// Indicates whether the port whitelist is in use.
    /// </summary>
    public static bool UsingWhitelist = true;

    /// <summary>
    /// The whitelisted ports.
    /// </summary>
    public static List<int> WhitelistedPorts = new List<int>();

    /// <summary>
    /// Default port number
    /// </summary>
    public static int DefaultPort = 64198;

    /// <summary>
    /// Indicated whether IPv6 is supported.
    /// </summary>
    public static bool IsIPv6Supported { get; }

    /// <summary>
    /// Indicates whether IPv4 is supported.
    /// </summary>
    public static bool IsIPv4Supported { get; }

    // Constructor for Tunnel options, determines whether ipv6 and ipv4 are supported.
    static TunnelOptions()
    {
        WhitelistedPorts.Add(DefaultPort);
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