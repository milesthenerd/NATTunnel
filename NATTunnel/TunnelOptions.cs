using System;
using System.Net;
using System.Net.NetworkInformation;

namespace NATTunnel;

/// <summary>
/// Configuration options for NATTunnel mesh networking.
/// Values are loaded from config.toml at startup.
/// </summary>
public static class TunnelOptions
{
    /// <summary>
    /// The public IP address and port of the mediation server.
    /// The mediation server coordinates NAT traversal and hole punching between peers.
    /// </summary>
    public static IPEndPoint MediationEndpoint = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

    /// <summary>
    /// Default port number
    /// </summary>
    public static int DefaultPort = 64198;

    /// <summary>
    /// Network ID for mesh networking.
    /// Peers with the same network ID can discover and connect to each other.
    /// Required in config.toml.
    /// </summary>
    public static string NetworkID = null;

    /// <summary>
    /// Persistent peer ID for mesh networking.
    /// Persisted in config.toml so the peer keeps its identity (and mesh IP) across restarts.
    /// If null, a new one will be generated and saved on first run.
    /// </summary>
    public static Guid? PeerID = null;

    /// <summary>
    /// Indicated whether IPv6 is supported.
    /// </summary>
    public static bool IsIPv6Supported { get; }

    /// <summary>
    /// Indicates whether IPv4 is supported.
    /// </summary>
    public static bool IsIPv4Supported { get; }

    static TunnelOptions()
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
