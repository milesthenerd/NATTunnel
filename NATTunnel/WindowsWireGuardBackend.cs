using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>Windows WireGuard backend: WireGuard-NT P/Invoke (native config, no wg.exe) + netsh.</summary>
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
            // Configure natively via WireGuardSetConfiguration — no wg.exe dependency.
            if (!adapters.TryGetValue(interfaceName, out IntPtr adapter) || adapter == IntPtr.Zero)
                throw new InvalidOperationException($"Interface {interfaceName} has not been created");
            if (!WireGuardNativeConfig.ApplyConfigFile(adapter, tempConfigPath))
                throw new Exception($"Native WireGuard setconf failed for {interfaceName}");
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
                Program.Log(LogLevel.Warning, $"netsh enable failed for {interfaceName}: {err}");
            }
        }

        bool ok = WireGuardNTAPI.WireGuardSetAdapterState(
            adapter,
            WireGuardNTAPI.WIREGUARD_ADAPTER_STATE.WIREGUARD_ADAPTER_STATE_UP);
        if (!ok)
        {
            int error = Marshal.GetLastWin32Error();
            Program.Log(LogLevel.Error, $"Failed to set adapter state to UP (Error: {error})");
        }
    }

    public bool AddOrUpdatePeer(string interfaceName, WireGuardPeer peer)
    {
        // Native WireGuardSetConfiguration merge — no wg.exe dependency (removing it killed the
        // WireGuard-for-Windows install onboarding cliff and a code-execution surface).
        if (!adapters.TryGetValue(interfaceName, out IntPtr adapter) || adapter == IntPtr.Zero)
            return false;
        if (!WireGuardPeer.IsValidPublicKey(peer.PublicKey))
        {
            Program.Log(LogLevel.Debug, "Rejected invalid public key");
            return false;
        }

        var allowedIPs = ParseAllowedIPs(peer.AllowedIPs);
        // Peer's WireGuard endpoint is its per-peer loopback proxy port (see WireGuardPeer.GenerateConfigSection).
        var endpoint = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, peer.ProxyPort);
        return WireGuardNativeConfig.AddPeer(adapter, peer.PublicKey, endpoint, allowedIPs, peer.KeepAliveInterval);
    }

    /// <summary>Parse a comma-separated "ip/cidr,ip/cidr" AllowedIPs string into (address, cidr) tuples.</summary>
    private static System.Collections.Generic.List<(System.Net.IPAddress addr, int cidr)> ParseAllowedIPs(string allowedIPs)
    {
        var result = new System.Collections.Generic.List<(System.Net.IPAddress, int)>();
        if (string.IsNullOrWhiteSpace(allowedIPs)) return result;
        foreach (var entry in allowedIPs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int slash = entry.IndexOf('/');
            string ipPart = slash >= 0 ? entry.Substring(0, slash) : entry;
            int cidr = slash >= 0 && int.TryParse(entry.Substring(slash + 1), out int c) ? c
                     : (System.Net.IPAddress.TryParse(ipPart, out var probe) && probe.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32);
            if (System.Net.IPAddress.TryParse(ipPart, out var addr))
                result.Add((addr, cidr));
        }
        return result;
    }

    public void ApplyFullConfig(string interfaceName, string configFilePath)
    {
        if (!adapters.TryGetValue(interfaceName, out IntPtr adapter) || adapter == IntPtr.Zero)
            throw new InvalidOperationException($"Interface {interfaceName} has not been created");

        // Native full-config apply (no wg.exe): sanitize to wg-native fields, then apply the whole
        // interface+peer set with REPLACE_PEERS via WireGuardSetConfiguration.
        string tempConfigPath = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), $"wg_apply_{interfaceName}_{Guid.NewGuid()}.conf");
        try
        {
            WireGuardConfigSanitizer.WriteWgOnlyConfig(configFilePath, tempConfigPath);
            if (!WireGuardNativeConfig.ApplyConfigFile(adapter, tempConfigPath))
                throw new Exception($"Native WireGuard full-config apply failed for {interfaceName}");
        }
        finally
        {
            if (System.IO.File.Exists(tempConfigPath))
            {
                try { System.IO.File.Delete(tempConfigPath); } catch { }
            }
        }
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
                    Program.Log(LogLevel.Debug, "[WireGuard] Set IPEnableRouter=1 (takes effect on RemoteAccess start or reboot)");
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[WireGuard] Could not set IPEnableRouter: {ex.Message}");
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
                Program.Log(LogLevel.Error, $"[WireGuard] Failed to enable forwarding on {interfaceName}: {err}");
                return false;
            }
            Program.Log(LogLevel.Debug, $"[WireGuard] IP forwarding enabled on {interfaceName}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[WireGuard] Error enabling forwarding: {ex.Message}");
            return false;
        }
    }

    public void DestroyInterface(string interfaceName)
    {
        if (adapters.TryRemove(interfaceName, out IntPtr adapter) && adapter != IntPtr.Zero)
        {
            try { WireGuardAPI.CloseAdapter(adapter); }
            catch (Exception ex) { Program.Log(LogLevel.Error, $"Warning: Error closing WireGuard adapter: {ex.Message}"); }
        }
    }

}
