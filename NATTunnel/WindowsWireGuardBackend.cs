using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>Windows WireGuard backend: WireGuard-NT P/Invoke + wg.exe + netsh.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsWireGuardBackend : IWireGuardBackend
{
    private readonly ConcurrentDictionary<string, IntPtr> adapters = new();

    public void CreateInterface(string interfaceName)
    {
        IntPtr adapter = WireGuardAPI.CreateAdapter(interfaceName);
        adapters[interfaceName] = adapter;
    }

    public void ConfigureInterface(string interfaceName, string configFilePath)
    {
        // wg.exe setconf rejects wg-quick fields (Address, Name, etc.); sanitize to a temp file.
        string tempConfigPath = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"wg_{interfaceName}_{Guid.NewGuid()}.conf");
        try
        {
            WireGuardConfigSanitizer.WriteWgOnlyConfig(configFilePath, tempConfigPath);
            RunWg($"setconf \"{interfaceName}\" \"{tempConfigPath}\"");
        }
        finally
        {
            if (System.IO.File.Exists(tempConfigPath))
            {
                try { System.IO.File.Delete(tempConfigPath); } catch { }
            }
        }
    }

    public void AssignIP(string interfaceName, string ipAddress, byte prefixLength)
    {
        if (!adapters.TryGetValue(interfaceName, out IntPtr adapter))
            throw new InvalidOperationException($"Interface {interfaceName} has not been created");
        WireGuardAPI.AssignIPAddress(adapter, interfaceName, ipAddress, prefixLength);
    }

    public void SetInterfaceUp(string interfaceName)
    {
        if (!adapters.TryGetValue(interfaceName, out IntPtr adapter))
            throw new InvalidOperationException($"Interface {interfaceName} has not been created");

        var enablePsi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = $"interface set interface \"{interfaceName}\" admin=enabled",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using (var p = Process.Start(enablePsi))
        {
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                string err = p.StandardError.ReadToEnd();
                Program.Log($"Warning: netsh enable failed for {interfaceName}: {err}");
            }
        }

        bool ok = WireGuardNTAPI.WireGuardSetAdapterState(
            adapter,
            WireGuardNTAPI.WIREGUARD_ADAPTER_STATE.WIREGUARD_ADAPTER_STATE_UP);
        if (!ok)
        {
            int error = Marshal.GetLastWin32Error();
            Program.Log($"Failed to set adapter state to UP (Error: {error})");
        }
    }

    public bool AddOrUpdatePeer(string interfaceName, WireGuardPeer peer)
        => WireGuardNT.AddPeerToInterface(interfaceName, peer);

    public void ApplyFullConfig(string interfaceName, string configFilePath)
    {
        if (!adapters.TryGetValue(interfaceName, out IntPtr adapter))
            throw new InvalidOperationException($"Interface {interfaceName} has not been created");
        WireGuardNT.UpdateConfiguration(adapter, configFilePath, interfaceName);
    }

    public bool EnableForwarding(string interfaceName)
    {
        // Windows requires global IPEnableRouter=1 in addition to per-interface forwarding;
        // netsh forwarding=enabled is a no-op without the registry key.
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", writable: true);
            if (key != null)
            {
                object current = key.GetValue("IPEnableRouter");
                if (current is not int i || i != 1)
                {
                    key.SetValue("IPEnableRouter", 1, Microsoft.Win32.RegistryValueKind.DWord);
                    Program.Log("[WireGuard] Set IPEnableRouter=1 (takes effect on RemoteAccess start or reboot)");
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log($"[WireGuard] Could not set IPEnableRouter: {ex.Message}");
        }

        // Start RemoteAccess service so IPEnableRouter takes effect without a reboot.
        try
        {
            var startPsi = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = "start RemoteAccess",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var sp = Process.Start(startPsi);
            sp.WaitForExit();
            // Non-zero exit usually means already running or disabled — non-fatal.
        }
        catch { }

        var psi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = $"interface ipv4 set interface \"{interfaceName}\" forwarding=enabled",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        try
        {
            using var p = Process.Start(psi);
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                string err = p.StandardError.ReadToEnd();
                Program.Log($"[WireGuard] Failed to enable forwarding on {interfaceName}: {err}");
                return false;
            }
            Program.Log($"[WireGuard] IP forwarding enabled on {interfaceName}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"[WireGuard] Error enabling forwarding: {ex.Message}");
            return false;
        }
    }

    public void DestroyInterface(string interfaceName)
    {
        if (adapters.TryRemove(interfaceName, out IntPtr adapter) && adapter != IntPtr.Zero)
        {
            try { WireGuardAPI.CloseAdapter(adapter); }
            catch (Exception ex) { Program.Log($"Warning: Error closing WireGuard adapter: {ex.Message}"); }
        }
    }

    private static void RunWg(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "wg.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            string err = p.StandardError.ReadToEnd();
            throw new Exception($"wg.exe {args} failed (exit {p.ExitCode}): {err}");
        }
    }
}
