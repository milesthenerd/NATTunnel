# Windows Packaging

The Windows build ships as a standalone GUI executable. There's no installer or service registration; the GUI manages its own elevation via the embedded app manifest and runs the mesh engine in-process.

## Build prerequisites

- Windows 10/11 x64
- .NET 10 SDK

## Publish

There's a `win-x64` publish profile at [`NATTunnelGUI/Properties/PublishProfiles/win-x64.pubxml`](../../NATTunnelGUI/Properties/PublishProfiles/win-x64.pubxml). It produces a framework-dependent single-file executable:

```powershell
dotnet publish NATTunnelGUI -p:PublishProfile=win-x64
```

## Filesystem layout on a running install

```
<extract dir>\
  nattunnel-gui.exe         (entry point; requires admin)
  wireguard.dll             (kernel driver bridge)
  ...                       (framework-dependent .runtimeconfig.json etc.)
%APPDATA%\NATTunnel\
  config.toml               (created on first run)
  nt-<hash>.conf            (WireGuard interface config)
  nt-<hash>_keys.txt        (private + public key pair)
```

## Service lifecycle

Windows runs the mesh engine **in-process** with the GUI. There's no separate daemon process. Closing the GUI window stops the engine; reopening starts it again.

If you want the daemon to run independently of a GUI session (e.g., as a Windows Service), the codebase has scaffolding in [`NATTunnel/WireGuardService.cs`](../../NATTunnel/WireGuardService.cs) for installing one via SCM. It's not wired into the default flow — see that file's notes if you need that pattern.

## Versioning

The version is baked into the assembly via `<Version>` in [`Directory.Build.props`](../../Directory.Build.props). Bump it before publish for a release.

## Removal

There's no installer, so no uninstaller either. Users delete the extracted directory and `%APPDATA%\NATTunnel\` to clean up config and keys.
