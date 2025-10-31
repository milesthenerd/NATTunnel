using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using Tomlyn.Model;

namespace NATTunnel;

/// <summary>
/// Configuration options for NATTunnel.
/// These options control tunnel behavior, connection settings, and networking parameters.
/// Values are typically loaded from a config.toml file at startup.
/// </summary>
public static class TunnelOptions
{
    /// <summary>
    /// Indicates whether this instance is running as a server or client.
    /// Server mode: Uses TunnelManager to handle multiple client connections.
    /// Client mode: Connects to a single server peer.
    /// Configured via config.toml "mode" setting ("server" or "client").
    /// </summary>
    public static bool IsServer = false;

    /// <summary>
    /// The public IP address and port of the mediation server.
    /// The mediation server coordinates NAT traversal and hole punching between peers.
    /// Format: IPAddress:Port (e.g., "sync.milesthenerd.net:6510")
    /// Configured via config.toml "mediationEndpoint" setting.
    /// Required for both server and client modes.
    /// </summary>
    public static IPEndPoint MediationEndpoint = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

    /// <summary>
    /// The public IP address of the server you want to connect to.
    /// Only used in client mode - ignored when IsServer is true.
    /// Configured via config.toml "remoteIP" setting.
    /// This helps identify which server to request connection to via the mediation server.
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