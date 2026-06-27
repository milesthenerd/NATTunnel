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
            Program.Log(LogLevel.Debug, $"Generated WireGuard config at: {configPath}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Failed to generate WireGuard config: {ex.Message}");
            return false;
        }
    }

    public static (string privateKey, string publicKey) GenerateKeyPair()
    {
        // Curve25519 X25519 keypair — same wire format as `wg genkey` / `wg pubkey`. Generated
        // in-process via the Noise library we already depend on, so no wg.exe required.
        using var kp = Noise.KeyPair.Generate();
        return (Convert.ToBase64String(kp.PrivateKey), Convert.ToBase64String(kp.PublicKey));
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
            Program.Log(LogLevel.Debug, $"Generated WireGuard interface config at: {configPath}");
            return true;
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Failed to generate WireGuard config: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Extract the private key from the [Interface] section of a WireGuard config and derive
    /// the matching public key in-process (X25519 scalar-base multiply via BouncyCastle).
    /// Replacement for the prior `wg pubkey` shell-out.
    /// </summary>
    public static string GetPublicKeyFromConfig(string configPath)
    {
        try
        {
            if (!File.Exists(configPath))
                throw new FileNotFoundException($"Config file not found: {configPath}");

            string privateKey = null;
            foreach (var line in File.ReadAllLines(configPath))
            {
                string trimmed = line.Trim();
                if (!trimmed.StartsWith("PrivateKey", StringComparison.OrdinalIgnoreCase)) continue;
                int eq = trimmed.IndexOf('=');
                if (eq < 0 || eq >= trimmed.Length - 1) continue;
                privateKey = trimmed.Substring(eq + 1).Trim();
                if (!string.IsNullOrEmpty(privateKey)) break;
            }

            if (string.IsNullOrEmpty(privateKey))
                throw new Exception("Could not find PrivateKey in config file");

            byte[] privBytes = Convert.FromBase64String(privateKey);
            if (privBytes.Length != 32)
                throw new Exception($"PrivateKey is {privBytes.Length} bytes; expected 32 (Curve25519).");

            // BouncyCastle X25519: scalar-base multiplication on Curve25519.
            var priv = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(privBytes, 0);
            return Convert.ToBase64String(priv.GeneratePublicKey().GetEncoded());
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Error deriving public key from config: {ex.Message}");
            throw;
        }
    }
}