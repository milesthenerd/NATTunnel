using System.Net;

namespace NATTunnel;

/// <summary>
/// Immutable snapshot of the protocol-relevant options at the time a <see cref="MeshProtocolEngine"/>
/// instance starts. Decouples the engine from <see cref="TunnelOptions"/>'s daemon-wide statics.
///
/// Populated from <see cref="TunnelOptions"/> in daemon mode, and from constructor arguments
/// in the embedded library. Values reflected here MUST be reread on every reconnect cycle
/// — the daemon refreshes its snapshot via <see cref="IMeshDaemonContext.ReloadConfig"/>.
/// </summary>
internal sealed class MeshOptions
{
    // ── Mediation ──
    public IPEndPoint MediationEndpoint { get; init; }

    /// <summary>
    /// UDP port used for the peer-to-peer mesh-control channel (heartbeats, MeshConnectionBegin,
    /// MeshRelayAssignment). Daemon mode binds the well-known port 51888 since at most one
    /// daemon runs per machine. Embedded mode may run multiple processes on the same machine
    /// for tests/dev — those instances must bind separate ports.
    /// Default 51888 (daemon convention).
    /// </summary>
    public int MeshControlPort { get; init; } = MeshProtocolEngine.MeshControlPort;
    public string NetworkID { get; init; }
    public string NetworkSecret { get; init; }
    public bool TlsEnabled { get; init; }
    public bool TlsAllowSelfSigned { get; init; }
    public bool AutoConnect { get; init; }
    public string MeshSubnet { get; init; }

    // ── Heartbeat / probe / staleness ──
    public int HeartbeatIntervalSeconds { get; init; }
    public int ProbeIntervalSeconds { get; init; }
    public int DeadThreshold { get; init; }
    public int RepairCooldownSeconds { get; init; }
    public int GracePeriodSecondsNonSymmetric { get; init; }
    public int GracePeriodSecondsSymmetric { get; init; }
    public int StaleTimeoutSeconds { get; init; }
    public int IsolationGracePeriodSeconds { get; init; }
    public int MaxRepairAttempts { get; init; }

    // ── Relay ──
    public bool AllowRelayThrough { get; init; }
    public RelayCapacity OwnRelayCapacity { get; init; }
    public int RelayReselectCooldownSeconds { get; init; }
    public int RelayLoadFactorMs { get; init; }
    public double RelayReselectMinImprovement { get; init; }
    public int RelayHealthTimeoutSeconds { get; init; }

    /// <summary>
    /// Build a snapshot from the daemon-wide <see cref="TunnelOptions"/> statics. Call this
    /// every time the daemon completes a config reload so the next reconnect picks up changes.
    /// </summary>
    public static MeshOptions FromTunnelOptions() => new()
    {
        MediationEndpoint = TunnelOptions.MediationEndpoint,
        NetworkID = TunnelOptions.NetworkID,
        NetworkSecret = TunnelOptions.NetworkSecret,
        TlsEnabled = TunnelOptions.TlsEnabled,
        TlsAllowSelfSigned = TunnelOptions.TlsAllowSelfSigned,
        AutoConnect = TunnelOptions.AutoConnect,
        MeshSubnet = TunnelOptions.MeshSubnet,
        HeartbeatIntervalSeconds = TunnelOptions.HeartbeatIntervalSeconds,
        ProbeIntervalSeconds = TunnelOptions.ProbeIntervalSeconds,
        DeadThreshold = TunnelOptions.DeadThreshold,
        RepairCooldownSeconds = TunnelOptions.RepairCooldownSeconds,
        GracePeriodSecondsNonSymmetric = TunnelOptions.GracePeriodSecondsNonSymmetric,
        GracePeriodSecondsSymmetric = TunnelOptions.GracePeriodSecondsSymmetric,
        StaleTimeoutSeconds = TunnelOptions.StaleTimeoutSeconds,
        IsolationGracePeriodSeconds = TunnelOptions.IsolationGracePeriodSeconds,
        MaxRepairAttempts = TunnelOptions.MaxRepairAttempts,
        AllowRelayThrough = TunnelOptions.AllowRelayThrough,
        OwnRelayCapacity = TunnelOptions.OwnRelayCapacity,
        RelayReselectCooldownSeconds = TunnelOptions.RelayReselectCooldownSeconds,
        RelayLoadFactorMs = TunnelOptions.RelayLoadFactorMs,
        RelayReselectMinImprovement = TunnelOptions.RelayReselectMinImprovement,
        RelayHealthTimeoutSeconds = TunnelOptions.RelayHealthTimeoutSeconds,
    };
}
