using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>Linux WireGuard backend: kernel module + `ip` and `wg` userspace tools.</summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxWireGuardBackend : IWireGuardBackend
{
    public void CreateInterface(string interfaceName)
    {
        // Sweep `nt-*` leftovers from previous runs; they share the /16 subnet and would
        // cause `ip link set up` to fail with EADDRINUSE.
        SweepStaleInterfaces(keep: interfaceName);
        TryRunIp($"link delete dev {interfaceName}", suppressErrors: true);
        RunIp($"link add dev {interfaceName} type wireguard");
        Program.Log($"Created WireGuard interface: {interfaceName}");
    }

    private static void SweepStaleInterfaces(string keep)
    {
        string output;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ip",
                Arguments = "-br link show type wireguard",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            if (p.ExitCode != 0) return;
        }
        catch { return; }

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            string name = trimmed.Split(new[] { ' ', '\t', '@' }, 2, StringSplitOptions.RemoveEmptyEntries)[0];
            if (!name.StartsWith("nt-", StringComparison.Ordinal)) continue;
            if (name == keep) continue;
            Program.Log($"Sweeping stale WireGuard interface: {name}");
            TryRunIp($"link delete dev {name}", suppressErrors: true);
        }
    }

    public void ConfigureInterface(string interfaceName, string configFilePath)
    {
        // Temp file must live under /etc/wireguard — AppArmor's `wg` profile blocks reads elsewhere.
        const string wgConfigDir = "/etc/wireguard";
        Directory.CreateDirectory(wgConfigDir);
        string tempConfigPath = Path.Combine(wgConfigDir,
            $".nattunnel_{interfaceName}_{Guid.NewGuid():N}.conf");
        try
        {
            WireGuardConfigSanitizer.WriteWgOnlyConfig(configFilePath, tempConfigPath);
            try { File.SetUnixFileMode(tempConfigPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
            RunWg($"setconf {interfaceName} {ShellQuote(tempConfigPath)}");
            Program.Log($"Applied WireGuard config to {interfaceName}");
        }
        finally
        {
            if (File.Exists(tempConfigPath))
            {
                try { File.Delete(tempConfigPath); } catch { }
            }
        }
    }

    public void AssignIP(string interfaceName, string ipAddress, byte prefixLength)
    {
        TryRunIp($"-4 address flush dev {interfaceName}", suppressErrors: true);
        RunIp($"address add {ipAddress}/{prefixLength} dev {interfaceName}");
        Program.Log($"Assigned IP {ipAddress}/{prefixLength} to {interfaceName}");
    }

    public void SetInterfaceUp(string interfaceName)
    {
        RunIp($"link set dev {interfaceName} up");
        Program.Log($"Interface {interfaceName} is up");
    }

    public bool AddOrUpdatePeer(string interfaceName, WireGuardPeer peer)
    {
        try
        {
            string args = $"set {interfaceName} peer {peer.PublicKey} " +
                          $"allowed-ips {peer.AllowedIPs} " +
                          $"endpoint 127.0.0.1:{peer.ProxyPort} " +
                          $"persistent-keepalive {peer.KeepAliveInterval}";
            RunWg(args);
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"[WireGuard] Failed to add/update peer {peer.PublicKey[..8]}...: {ex.Message}");
            return false;
        }
    }

    public void ApplyFullConfig(string interfaceName, string configFilePath)
        => ConfigureInterface(interfaceName, configFilePath);

    public bool EnableForwarding(string interfaceName)
    {
        // Global IPv4 forwarding — no per-interface equivalent on Linux. Matches wg-quick.
        try
        {
            File.WriteAllText("/proc/sys/net/ipv4/ip_forward", "1\n");
            Program.Log($"[WireGuard] IPv4 forwarding enabled (system-wide; needed for {interfaceName} relay)");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"[WireGuard] Failed to enable IPv4 forwarding: {ex.Message}");
            return false;
        }
    }

    public void DestroyInterface(string interfaceName)
    {
        TryRunIp($"link delete dev {interfaceName}", suppressErrors: true);
        Program.Log($"Destroyed WireGuard interface: {interfaceName}");
    }

    private static void RunIp(string args) => Run("ip", args);
    private static void TryRunIp(string args, bool suppressErrors) => TryRun("ip", args, suppressErrors);
    private static void RunWg(string args) => Run("wg", args);

    private static void Run(string fileName, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            throw new Exception($"{fileName} {args} failed (exit {p.ExitCode}): {stderr.Trim()}");
        }
    }

    private static void TryRun(string fileName, string args, bool suppressErrors)
    {
        try { Run(fileName, args); }
        catch when (suppressErrors) { }
    }

    private static string ShellQuote(string s) => s.Contains(' ') ? $"\"{s}\"" : s;
}
