using System;

namespace NATTunnel;

/// <summary>
/// Daemon implementation of <see cref="IMeshDaemonContext"/>: passes through to the existing
/// <see cref="Program"/> / <see cref="TunnelOptions"/> / <see cref="Config"/> singletons.
/// Constructed by the daemon's <see cref="Program.RunMeshMode"/> and handed to
/// <see cref="MeshProtocolEngine"/> in place of direct static references.
/// </summary>
internal sealed class DaemonContext : IMeshDaemonContext
{
    private MeshOptions options = MeshOptions.FromTunnelOptions();

    public void Log(string message) => Program.Log(message);

    public bool ShutdownRequested
    {
        get => Program.ShutdownRequested;
        set => Program.ShutdownRequested = value;
    }

    public bool DisconnectRequested
    {
        get => Program.DisconnectRequested;
        set => Program.DisconnectRequested = value;
    }

    public bool ConnectRequested
    {
        get => Program.ConnectRequested;
        set => Program.ConnectRequested = value;
    }

    public bool RelayHostingDisableRequested
    {
        get => Program.RelayHostingDisableRequested;
        set => Program.RelayHostingDisableRequested = value;
    }

    public MeshConnectionState ConnectionState
    {
        get => Program.ConnectionState;
        set => Program.ConnectionState = value;
    }

    public MeshOptions Options => options;

    public void ReloadConfig()
    {
        Config.TryLoadConfig();
        options = MeshOptions.FromTunnelOptions();
    }

    public void RegisterMeshStateProvider(Func<MeshState> provider)
    {
        Program.meshStateProvider = provider;
    }
}
