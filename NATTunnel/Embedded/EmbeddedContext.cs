using System;

namespace NATTunnel.Embedded;

/// <summary>
/// <see cref="IMeshDaemonContext"/> implementation for the embedded library. Unlike the daemon
/// <see cref="DaemonContext"/>, this version doesn't bridge to any process-wide singletons —
/// every piece of state lives on the instance.
///
/// Wiring at runtime:
///   - <see cref="Options"/> is supplied at construction (from <see cref="NATTunnel.MeshNode"/>).
///   - <see cref="ShutdownRequested"/> is flipped by <see cref="NATTunnel.MeshNode.Dispose"/> to wind the engine down.
///   - <see cref="ConnectRequested"/> is set to true at startup so MeshProtocolEngine's outer loop doesn't
///     idle-wait (embedded callers expect Start() to mean "start immediately").
///   - <see cref="ReloadConfig"/> is a no-op (no config file in embedded mode).
///   - <see cref="RegisterMeshStateProvider"/> is a no-op (no HTTP endpoint to wire it to).
///   - <see cref="Log"/> routes to the caller-supplied logger callback (if any), or Console as fallback.
/// </summary>
internal sealed class EmbeddedContext : IMeshDaemonContext
{
    private readonly Action<string> logger;

    public EmbeddedContext(MeshOptions options, Action<string> logger = null)
    {
        Options = options;
        this.logger = logger;
        // Embedded callers expect Start() to begin connecting immediately, regardless of the
        // AutoConnect option. Set ConnectRequested so the outer loop doesn't idle on first run.
        ConnectRequested = true;
    }

    private readonly object logLock = new();

    public void Log(string message)
    {
        string line = $"[{DateTime.UtcNow:HH:mm:ss}] {message}";
        if (logger != null)
        {
            try { logger(line); }
            catch { /* host's logger threw — swallow to avoid corrupting engine state */ }
            return;
        }
        // Fallback when no logger was supplied: Console.WriteLine under a lock so interleaved
        // engine threads don't garble each other's output.
        lock (logLock) { Console.WriteLine(line); }
    }

    public bool ShutdownRequested { get; set; }
    public bool DisconnectRequested { get; set; }
    public bool ConnectRequested { get; set; }
    public bool RelayHostingDisableRequested { get; set; }
    public MeshConnectionState ConnectionState { get; set; } = MeshConnectionState.Disconnected;

    public MeshOptions Options { get; }

    public void ReloadConfig()
    {
        // No-op: embedded callers supply options once at construction; no file to reload.
    }

    public void RegisterMeshStateProvider(Func<MeshState> provider)
    {
        // No-op: embedded library has no built-in HTTP/GUI endpoint to plumb this into.
    }
}
