using System;
using System.IO;
using System.Text;

namespace NATTunnel;

internal static class WireGuardConfig
{
    public static bool GenerateConfig(string privateKey, string publicKey, string endpoint, int port, string allowedIPs, string interfaceName, string configPath)
    {
        // Use default interface address for server (though this method is deprecated - use GenerateInterfaceOnlyConfig instead)
        return GenerateConfig(privateKey, publicKey, endpoint, port, allowedIPs, interfaceName, configPath, "10.5.0.1/24");
    }

    /// <summary>
    /// Generates WireGuard configuration with optional custom interface address
    /// </summary>
    public static bool GenerateConfig(string privateKey, string publicKey, string endpoint, int port, string allowedIPs, string interfaceName, string configPath, string interfaceAddress)
    {
        try
        {
            var config = new StringBuilder();
            config.AppendLine("[Interface]");
            config.AppendLine($"PrivateKey = {privateKey}");
            config.AppendLine("ListenPort = 51820");
            config.AppendLine($"Address = {interfaceAddress}");
            config.AppendLine($"Name = {interfaceName}");
            config.AppendLine();
            config.AppendLine("[Peer]");
            config.AppendLine($"PublicKey = {publicKey}");
            config.AppendLine($"Endpoint = {endpoint}:{port}");
            config.AppendLine($"AllowedIPs = {allowedIPs}");
            config.AppendLine("PersistentKeepalive = 5");

            // Ensure directory exists
            var dirName = Path.GetDirectoryName(configPath);
            if (!string.IsNullOrEmpty(dirName))
            {
                Directory.CreateDirectory(dirName);
            }

            File.WriteAllText(configPath, config.ToString());
            Program.Log($"Generated WireGuard config at: {configPath}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"Failed to generate WireGuard config: {ex.Message}");
            return false;
        }
    }

    public static (string privateKey, string publicKey) GenerateKeyPair()
    {
        try
        {
            // Create process to run wg genkey
            using var genKeyProcess = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = "genkey",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            // Generate private key
            genKeyProcess.Start();
            string privateKey = genKeyProcess.StandardOutput.ReadToEnd().Trim();
            genKeyProcess.WaitForExit();

            if (genKeyProcess.ExitCode != 0)
            {
                throw new Exception("Failed to generate private key");
            }

            // Create process to generate public key
            using var pubKeyProcess = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = "pubkey",
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            // Generate public key from private key
            pubKeyProcess.Start();
            pubKeyProcess.StandardInput.WriteLine(privateKey);
            pubKeyProcess.StandardInput.Close();
            string publicKey = pubKeyProcess.StandardOutput.ReadToEnd().Trim();
            pubKeyProcess.WaitForExit();

            if (pubKeyProcess.ExitCode != 0)
            {
                throw new Exception("Failed to generate public key");
            }

            return (privateKey, publicKey);
        }
        catch (Exception ex)
        {
            Program.Log($"Failed to generate WireGuard keys: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Generates WireGuard configuration with ONLY the [Interface] section, no peers
    /// </summary>
    public static bool GenerateInterfaceOnlyConfig(string privateKey, string interfaceName, string configPath, string interfaceAddress)
    {
        try
        {
            var config = new StringBuilder();
            config.AppendLine("[Interface]");
            config.AppendLine($"PrivateKey = {privateKey}");
            config.AppendLine("ListenPort = 51820");
            config.AppendLine($"Address = {interfaceAddress}");
            config.AppendLine($"Name = {interfaceName}");
            config.AppendLine();

            // Ensure directory exists
            var dirName = Path.GetDirectoryName(configPath);
            if (!string.IsNullOrEmpty(dirName))
            {
                Directory.CreateDirectory(dirName);
            }

            File.WriteAllText(configPath, config.ToString());
            Program.Log($"Generated WireGuard interface config at: {configPath}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log($"Failed to generate WireGuard config: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Extracts the private key from the WireGuard config file and derives the public key
    /// Uses: echo (private key) | wg pubkey
    /// </summary>
    public static string GetPublicKeyFromConfig(string configPath)
    {
        try
        {
            // Read the config file
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException($"Config file not found: {configPath}");
            }

            string configContent = File.ReadAllText(configPath);

            // Extract private key from [Interface] section
            string privateKey = null;
            foreach (var line in configContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
            {
                string trimmedLine = line.Trim();
                if (trimmedLine.StartsWith("PrivateKey", StringComparison.OrdinalIgnoreCase))
                {
                    // Find the first equals sign and take everything after it
                    int equalsIdx = trimmedLine.IndexOf('=');
                    if (equalsIdx >= 0 && equalsIdx < trimmedLine.Length - 1)
                    {
                        privateKey = trimmedLine.Substring(equalsIdx + 1).Trim();
                        if (!string.IsNullOrEmpty(privateKey))
                        {
                            break;
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(privateKey))
            {
                throw new Exception("Could not find PrivateKey in config file");
            }

            // Derive public key from private key: echo (private key) | wg pubkey
            using var pubKeyProcess = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = "pubkey",
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };

            pubKeyProcess.Start();
            pubKeyProcess.StandardInput.WriteLine(privateKey);
            pubKeyProcess.StandardInput.Close();
            string publicKey = pubKeyProcess.StandardOutput.ReadToEnd().Trim();
            string errorOutput = pubKeyProcess.StandardError.ReadToEnd();
            pubKeyProcess.WaitForExit();

            if (pubKeyProcess.ExitCode != 0)
            {
                throw new Exception($"Failed to derive public key from private key. wg error: {errorOutput}");
            }

            Program.Log($"Derived public key from config: {configPath}");
            return publicKey;
        }
        catch (Exception ex)
        {
            Program.Log($"Error deriving public key from config: {ex.Message}");
            throw;
        }
    }
}