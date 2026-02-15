using System;
using System.Diagnostics;

namespace NATTunnel;

public static class WireGuardDynamic
{
    /// <summary>
    /// Dynamically adds a peer to a running WireGuard interface using wg set command
    /// </summary>
    public static bool AddPeerToInterface(string interfaceName, string publicKey, string endpoint, string allowedIPs, int persistentKeepalive = 25)
    {
        try
        {
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
                Console.WriteLine($"wg set failed (Exit code: {wgProcess.ExitCode}): {errorOutput}");
                return false;
            }

            Console.WriteLine($"Dynamically added peer to WireGuard interface {interfaceName}");
            if (!string.IsNullOrEmpty(output))
            {
                Console.WriteLine($"   Output: {output}");
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error adding peer dynamically: {ex.Message}");
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
                Console.WriteLine($"wg set remove failed (Exit code: {wgProcess.ExitCode}): {errorOutput}");
                return false;
            }

            Console.WriteLine($"Dynamically removed peer from WireGuard interface {interfaceName}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error removing peer dynamically: {ex.Message}");
            return false;
        }
    }
}
