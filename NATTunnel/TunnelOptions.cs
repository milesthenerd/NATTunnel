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
    /// Shared secret for mesh network authentication.
    /// Used to compute SHA256(networkID + ":" + networkSecret) as an auth token.
    /// Required in config.toml.
    /// </summary>
    public static string NetworkSecret = null;

    /// <summary>
    /// Persistent peer ID for mesh networking.
    /// Persisted in config.toml so the peer keeps its identity (and mesh IP) across restarts.
    /// If null, a new one will be generated and saved on first run.
    /// </summary>
    public static Guid? PeerID = null;

    /// <summary>
    /// Interval for sending heartbeat messages from the introducer to all peers (in seconds).
    /// Default: 15 seconds
    /// </summary>
    public static int HeartbeatIntervalSeconds = 15;

    /// <summary>
    /// Interval for probing the introducer's health when not the introducer (in seconds).
    /// Default: 10 seconds
    /// </summary>
    public static int ProbeIntervalSeconds = 10;

    /// <summary>
    /// Timeout for removing pending connection requests that received no response (in seconds).
    /// Default: 10 seconds
    /// </summary>
    public static int StaleTimeoutSeconds = 10;

    /// <summary>
    /// Cooldown before attempting to repair a broken relay route (in seconds).
    /// Default: 60 seconds
    /// </summary>
    public static int RepairCooldownSeconds = 60;

    /// <summary>
    /// Number of consecutive missed heartbeat acks before declaring a peer dead.
    /// Default: 5 (approximately 75s with 15s heartbeat interval)
    /// </summary>
    public static int DeadThreshold = 5;

    /// <summary>
    /// Grace period after initial connections are established before disconnecting from mediation server for non-symmetric NAT (in seconds).
    /// Default: 30 seconds
    /// </summary>
    public static int GracePeriodSecondsNonSymmetric = 30;

    /// <summary>
    /// Grace period after initial connections are established before disconnecting from mediation server for symmetric NAT (in seconds).
    /// Default: 5 seconds
    /// </summary>
    public static int GracePeriodSecondsSymmetric = 5;

    /// <summary>
    /// Grace period to wait after isolation is detected before reconnecting to mediation server (in seconds).
    /// Default: 60 seconds
    /// </summary>
    public static int IsolationGracePeriodSeconds = 60;

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
