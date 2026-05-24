using System;
using System.Diagnostics;

namespace NATTunnel;

internal static class WireGuardDynamic
{
    /// <summary>
    /// Dynamically adds a peer to a running WireGuard interface using wg set command
    /// </summary>
    public static bool AddPeerToInterface(string interfaceName, string publicKey, string endpoint, string allowedIPs, int persistentKeepalive = 5)
    {
        try
        {
            if (!WireGuardPeer.IsValidPublicKey(publicKey))
            {
                Program.Log($"Rejected invalid public key");
                return false;
            }

            // Build the wg set command
            // wg set <interface> peer <public-key> endpoint <ip>:<port> allowed-ips <ips> persistent-keepalive <interval>
            string arguments = $"set {interfaceName} peer {publicKey} endpoint {endpoint} allowed-ips {allowedIPs} persistent-keepalive {persistentKeepalive}";

            var wgProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            wgProcess.Start();
            string output = wgProcess.StandardOutput.ReadToEnd();
            string errorOutput = wgProcess.StandardError.ReadToEnd();
            wgProcess.WaitForExit();

            if (wgProcess.ExitCode != 0)
            {
                Program.Log($"wg set failed (Exit code: {wgProcess.ExitCode}): {errorOutput}");
                return false;
            }

            Program.Log($"Dynamically added peer to WireGuard interface {interfaceName}");
            if (!string.IsNullOrEmpty(output))
            {
                Program.Log($"   Output: {output}");
            }
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"Error adding peer dynamically: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Dynamically removes a peer from a running WireGuard interface using wg set command
    /// </summary>
    public static bool RemovePeerFromInterface(string interfaceName, string publicKey)
    {
        try
        {
            if (!WireGuardPeer.IsValidPublicKey(publicKey))
            {
                Program.Log($"Rejected invalid public key");
                return false;
            }

            // wg set <interface> peer <public-key> remove
            string arguments = $"set {interfaceName} peer {publicKey} remove";

            var wgProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            wgProcess.Start();
            string output = wgProcess.StandardOutput.ReadToEnd();
            string errorOutput = wgProcess.StandardError.ReadToEnd();
            wgProcess.WaitForExit();

            if (wgProcess.ExitCode != 0)
            {
                Program.Log($"wg set remove failed (Exit code: {wgProcess.ExitCode}): {errorOutput}");
                return false;
            }

            Program.Log($"Dynamically removed peer from WireGuard interface {interfaceName}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"Error removing peer dynamically: {ex.Message}");
            return false;
        }
    }
}
