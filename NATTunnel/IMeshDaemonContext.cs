using System;

namespace NATTunnel;

/// <summary>
/// Severity classification for log messages emitted by <see cref="MeshProtocolEngine"/>
/// and its supporting code. Host applications filter via <see cref="MeshConfig.MinLogLevel"/>;
/// the default (<see cref="Info"/>) keeps the library at low-noise narration plus warnings
/// and errors. Set to <see cref="Debug"/> when diagnosing protocol-level issues.
/// </summary>
public enum LogLevel
{
    /// <summary>Verbose protocol traces: heartbeat ticks, probe outcomes, per-packet detail.</summary>
    Debug = 0,
    /// <summary>Major lifecycle transitions: joined network, peer connected, role changes.</summary>
    Info = 1,
    /// <summary>Recoverable problems: handshake retries, dropped peers, repair attempts.</summary>
    Warning = 2,
    /// <summary>Failures that prevent forward progress on a connection or session.</summary>
    Error = 3,
}

/// <summary>
/// The seam that lets <see cref="MeshProtocolEngine"/> avoid hard-coding references to
/// daemon-wide statics like <see cref="Program"/> and <see cref="TunnelOptions"/>.
///
/// Two implementations:
///   - <see cref="DaemonContext"/> — passthrough to Program/TunnelOptions/Config. Used by the
///     CLI daemon when it constructs a <see cref="MeshProtocolEngine"/>.
///   - <see cref="NATTunnel.Embedded.EmbeddedContext"/> — instance-owned state for the embedded
///     library so embedded consumers don't pull in any of the daemon globals.
///
/// MeshProtocolEngine reads <see cref="Options"/> once per reconnect cycle. Mutating <see cref="DisconnectRequested"/>
/// or <see cref="ConnectRequested"/> from a non-engine thread (GUI, /connect HTTP) is supported
/// and how the daemon signals state transitions in to the engine.
/// </summary>
internal interface IMeshDaemonContext
{
    /// <summary>
    /// Logger sink with severity classification. Implementations must be safe to call from
    /// any thread — MeshProtocolEngine logs from background tasks (UDP listener, tunnel
    /// callbacks) as well as the main loop. Implementations are expected to filter on the
    /// host's configured minimum level before delivering to the user.
    /// </summary>
    void Log(LogLevel level, string message);

    /// <summary>
    /// Convenience overload defaulting to <see cref="LogLevel.Info"/>. Used by transitional
    /// callsites; new code should call the explicit-level overload.
    /// </summary>
    void Log(string message) => Log(LogLevel.Info, message);

    // ── Lifecycle signals (read by engine; written by host or GUI) ──

    /// <summary>
    /// True when the host wants the engine to wind down. Engine reads this on every loop
    /// iteration; engine also writes <c>true</c> from its own teardown paths so background
    /// tasks (UDP listener) see the same signal.
    /// </summary>
    bool ShutdownRequested { get; set; }
    bool DisconnectRequested { get; set; }
    bool ConnectRequested { get; set; }
    bool RelayHostingDisableRequested { get; set; }

    /// <summary>Current connection state; engine writes, host (HTTP / GUI) reads.</summary>
    MeshConnectionState ConnectionState { get; set; }

    // ── Options snapshot ──

    /// <summary>
    /// Snapshot of protocol-relevant options at the most recent reload. Engine re-reads this
    /// after every <see cref="ReloadConfig"/>. Immutable per snapshot — host returns a fresh
    /// MeshOptions instance after a reload.
    /// </summary>
    MeshOptions Options { get; }

    /// <summary>
    /// Reload the config from disk (daemon: TOML file; embedded: no-op) and refresh
    /// <see cref="Options"/>. Engine calls this when transitioning from idle to connecting.
    /// </summary>
    void ReloadConfig();

    /// <summary>
    /// Register a delegate the host can call to query current mesh state for status endpoints,
    /// GUI, etc. Daemon wires this into <c>Program.meshStateProvider</c>; embedded ignores it.
    /// </summary>
    void RegisterMeshStateProvider(Func<MeshState> provider);
}
