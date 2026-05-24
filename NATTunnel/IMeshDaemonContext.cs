using System;

namespace NATTunnel;

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
public interface IMeshDaemonContext
{
    /// <summary>
    /// Logger sink. Implementations must be safe to call from any thread — MeshProtocolEngine logs from
    /// background tasks (UDP listener, tunnel callbacks) as well as the main loop.
    /// </summary>
    void Log(string message);

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
