using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace NATTunnel;

/// <summary>
/// Configuration options for NATTunnel mesh networking.
/// Values are loaded from config.toml at startup.
/// </summary>
internal static class TunnelOptions
{
    /// <summary>
    /// The mediation server's hostname (or IP literal), no port — resolved lazily by the engine
    /// at connect time, NOT at config load. Deferring the DNS resolve means an unresolvable host
    /// no longer crashes daemon startup; the engine idles in a config-error state instead.
    /// </summary>
    public static string MediationHost = "sync.milesthenerd.net";

    /// <summary>The mediation server's port, paired with <see cref="MediationHost"/>.</summary>
    public static int MediationPort = 6510;

    /// <summary>
    /// The original <c>host:port</c> string the user supplied for the mediation endpoint
    /// (a DNS hostname or an IP literal). Kept for display and AAAA resolution.
    /// </summary>
    public static string MediationEndpointString = "sync.milesthenerd.net:6510";

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
    /// Persistent 32-byte Curve25519 identity private key. Separate from the WireGuard transport
    /// key — this identifies the peer across sessions and modes. Fingerprints derived from the
    /// corresponding public key (SHA-256 truncated to 8 bytes, hex) are what block lists index by.
    /// Persisted in config.toml. Generated on first run if absent.
    /// </summary>
    public static byte[] IdentityPrivateKey = null;

    /// <summary>
    /// Persistent block list — SHA-256(pubkey)[..8] hex fingerprints of peers this node refuses to
    /// connect to. Enforced locally (block is our own preference, not gossiped).
    /// </summary>
    public static HashSet<string> BlockedFingerprints = new(StringComparer.OrdinalIgnoreCase);

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
    /// Mesh subnet prefix (first two octets) for peer IP assignment.
    /// Peers get IPs in {MeshSubnet}.X.Y/16 range.
    /// Default: "10.5"
    /// </summary>
    public static string MeshSubnet = "10.5";

    /// <summary>
    /// Cooldown before attempting to repair a broken relay route (in seconds).
    /// Default: 15 seconds
    /// </summary>
    public static int RepairCooldownSeconds = 15;

    /// <summary>
    /// Number of consecutive repair attempts before escalating to mediation server fallback.
    /// Default: 3
    /// </summary>
    public static int MaxRepairAttempts = 3;

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
    /// Default: 30 seconds
    /// </summary>
    public static int IsolationGracePeriodSeconds = 30;

    /// <summary>
    /// Whether the daemon immediately attempts to join the mesh on startup. When false, it idles
    /// in Disconnected until something POSTs /connect. Default: false (idle until requested).
    /// </summary>
    public static bool AutoConnect = false;

    /// <summary>
    /// Whether to use TLS when connecting to the mediation server.
    /// Must match the server configuration. Default: false.
    /// </summary>
    public static bool TlsEnabled = true;

    /// <summary>
    /// Whether to accept self-signed TLS certificates from the mediation server.
    /// Default: true (the default server setup uses an auto-generated self-signed cert).
    /// </summary>
    public static bool TlsAllowSelfSigned = true;

    /// <summary>Whether this peer is willing to relay traffic for other pairs. Default: true.</summary>
    public static bool AllowRelayThrough = true;

    /// <summary>Operator hint about this peer's uplink capacity for relay scoring.</summary>
    public static RelayCapacity OwnRelayCapacity = RelayCapacity.Normal;

    /// <summary>WireGuard silence (in seconds) before a relayed peer probes its relay's health.</summary>
    public static int RelayHealthTimeoutSeconds = 45;

    /// <summary>New candidate must score this fraction better than the current relay to swap.</summary>
    public static double RelayReselectMinImprovement = 0.30;

    /// <summary>Minimum interval between reselections for the same pair (in seconds).</summary>
    public static int RelayReselectCooldownSeconds = 30;

    /// <summary>Per-active-route latency penalty (ms) in the relay scoring function.</summary>
    public static int RelayLoadFactorMs = 50;

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
