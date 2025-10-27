using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.IO;

namespace NATTunnel;

public class WireGuardPeerManager
{
    private readonly List<WireGuardPeer> peers = new();
    private readonly string configPath;
    private readonly object configLock = new();
    private readonly int basePort;
    private readonly IPAddress baseAddress;
    private readonly bool isServer;
    private int nextPeerId = 2;  // Start at 2 since server is 10.5.0.1
    private int nextProxyPort = 51822; // Start allocating unique ports from 51822 (51821 is reserved for inbound forwarder)
    private readonly HashSet<int> allocatedPorts = new(); // Track allocated ports

    public WireGuardPeerManager(string configPath, IPAddress baseAddress, int basePort = 51820, bool isServer = false)
    {
        this.configPath = configPath;
        this.baseAddress = baseAddress;
        this.basePort = basePort;
        this.isServer = isServer;
    }

    private int AllocateProxyPort()
    {
        lock (configLock)
        {
            // Skip port 51821 as it's reserved for the inbound forwarder
            if (nextProxyPort == 51821)
            {
                nextProxyPort = 51822;
            }

            // Find next available port
            while (allocatedPorts.Contains(nextProxyPort) || nextProxyPort == 51821)
            {
                nextProxyPort++;
            }
            int port = nextProxyPort;
            allocatedPorts.Add(port);
            nextProxyPort++;
            return port;
        }
    }

    private void ReleaseProxyPort(int port)
    {
        lock (configLock)
        {
            allocatedPorts.Remove(port);
        }
    }

    public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, bool isPersistent = false)
    {
        lock (configLock)
        {
            // Check if peer with this public key already exists
            var existingPeerByKey = peers.FirstOrDefault(p => p.PublicKey == publicKey);
            if (existingPeerByKey != null)
            {
                Console.WriteLine($"⚠ Peer with public key {publicKey.Substring(0, 8)}... already exists.");
                // Always update endpoint and trigger config update (for reconnections)
                if (!existingPeerByKey.Endpoint.Equals(endpoint))
                {
                    Console.WriteLine($"  Updating endpoint: {existingPeerByKey.Endpoint} -> {endpoint}");
                    peers.Remove(existingPeerByKey);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByKey.PrivateAddress, existingPeerByKey.ConnectionId, isPersistent);
                    peers.Add(updatedPeer);
                    UpdateConfig();
                    return updatedPeer;
                }
                else
                {
                    Console.WriteLine($"  Endpoint unchanged. Updating config anyway to ensure reconnection works.");
                    UpdateConfig(); // Force config update even if endpoint didn't change
                }
                return existingPeerByKey;
            }

            // Check if peer with this endpoint already exists
            var existingPeerByEndpoint = peers.FirstOrDefault(p => p.Endpoint.Equals(endpoint));
            if (existingPeerByEndpoint != null)
            {
                Console.WriteLine($"⚠ Peer with endpoint {endpoint} already exists. Updating public key.");
                // Update public key if it changed
                if (existingPeerByEndpoint.PublicKey != publicKey)
                {
                    peers.Remove(existingPeerByEndpoint);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByEndpoint.PrivateAddress, existingPeerByEndpoint.ConnectionId, isPersistent);
                    peers.Add(updatedPeer);
                    UpdateConfig();
                    return updatedPeer;
                }
                return existingPeerByEndpoint;
            }

            // Calculate next available IP in the subnet (e.g., 10.5.0.x)
            var ipBytes = baseAddress.GetAddressBytes();
            ipBytes[3] = (byte)nextPeerId;
            var peerAddress = new IPAddress(ipBytes);

            // Allocate unique proxy port for this peer
            int proxyPort = AllocateProxyPort();

            var peer = new WireGuardPeer(publicKey, endpoint, peerAddress, nextPeerId++, isPersistent, proxyPort);
            peers.Add(peer);

            // Update WireGuard config
            UpdateConfig();

            Console.WriteLine($"✓ Added new peer {publicKey.Substring(0, 8)}... at {peerAddress} (proxy port: {proxyPort})");
            return peer;
        }
    }

    /// <summary>
    /// Adds a peer with a specific private address (for adding server with known IP)
    /// </summary>
    public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, bool isPersistent = false)
    {
        lock (configLock)
        {
            // Check if peer with this public key already exists
            var existingPeerByKey = peers.FirstOrDefault(p => p.PublicKey == publicKey);
            if (existingPeerByKey != null)
            {
                Console.WriteLine($"⚠ Peer with public key {publicKey.Substring(0, 8)}... already exists.");
                // Always update endpoint and trigger config update (for reconnections)
                if (!existingPeerByKey.Endpoint.Equals(endpoint))
                {
                    Console.WriteLine($"  Updating endpoint: {existingPeerByKey.Endpoint} -> {endpoint}");
                    peers.Remove(existingPeerByKey);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByKey.PrivateAddress, existingPeerByKey.ConnectionId, isPersistent);
                    peers.Add(updatedPeer);
                    UpdateConfig();
                    return updatedPeer;
                }
                else
                {
                    Console.WriteLine($"  Endpoint unchanged. Updating config anyway to ensure reconnection works.");
                    UpdateConfig(); // Force config update even if endpoint didn't change
                }
                return existingPeerByKey;
            }

            // Check if peer with this endpoint already exists
            var existingPeerByEndpoint = peers.FirstOrDefault(p => p.Endpoint.Equals(endpoint));
            if (existingPeerByEndpoint != null)
            {
                Console.WriteLine($"⚠ Peer with endpoint {endpoint} already exists. Updating public key.");
                if (existingPeerByEndpoint.PublicKey != publicKey)
                {
                    peers.Remove(existingPeerByEndpoint);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByEndpoint.PrivateAddress, existingPeerByEndpoint.ConnectionId, isPersistent);
                    peers.Add(updatedPeer);
                    UpdateConfig();
                    return updatedPeer;
                }
                return existingPeerByEndpoint;
            }

            // Use the specified private address
            // Find a connection ID that matches the last octet of the IP
            int connectionId = (int)privateAddress.GetAddressBytes()[3];

            // Allocate unique proxy port for this peer
            int proxyPort = AllocateProxyPort();

            var peer = new WireGuardPeer(publicKey, endpoint, privateAddress, connectionId, isPersistent, proxyPort);
            peers.Add(peer);

            // Update WireGuard config
            UpdateConfig();

            Console.WriteLine($"✓ Added new peer {publicKey.Substring(0, 8)}... at {privateAddress} (proxy port: {proxyPort})");
            return peer;
        }
    }

    public void RemovePeer(int connectionId)
    {
        lock (configLock)
        {
            var peer = peers.FirstOrDefault(p => p.ConnectionId == connectionId);
            if (peer != null)
            {
                peers.Remove(peer);
                ReleaseProxyPort(peer.ProxyPort); // Free the port for reuse
                UpdateConfig();
            }
        }
    }

    public WireGuardPeer GetPeer(int connectionId)
    {
        return peers.FirstOrDefault(p => p.ConnectionId == connectionId);
    }

    public WireGuardPeer GetPeer(IPAddress privateAddress)
    {
        return peers.FirstOrDefault(p => p.PrivateAddress.Equals(privateAddress));
    }

    public WireGuardPeer GetPeer(IPEndPoint endpoint)
    {
        return peers.FirstOrDefault(p => p.Endpoint.Equals(endpoint));
    }

    public IEnumerable<WireGuardPeer> GetAllPeers()
    {
        return peers.AsReadOnly();
    }

    private void UpdateConfig()
    {
        // Read the current config to preserve the [Interface] section
        string[] currentConfig = File.ReadAllLines(configPath);
        var interfaceSection = new List<string>();
        bool isInterfaceSection = false;

        foreach (var line in currentConfig)
        {
            if (line.Trim() == "[Interface]")
                isInterfaceSection = true;
            else if (line.Trim().StartsWith("["))
                isInterfaceSection = false;

            if (isInterfaceSection)
                interfaceSection.Add(line);
        }

        // Build the new config
        var newConfig = new StringBuilder();

        // Add the [Interface] section
        foreach (var line in interfaceSection)
            newConfig.AppendLine(line);

        newConfig.AppendLine();

        // Add each peer
        // Server uses localhost proxy endpoint, client uses real endpoint
        bool useProxy = isServer;
        foreach (var peer in peers)
        {
            newConfig.AppendLine(peer.GenerateConfigSection(useProxy));
            newConfig.AppendLine();
        }

        // Write the new config
        File.WriteAllText(configPath, newConfig.ToString());

        // Apply the configuration to the running WireGuard interface
        ApplyConfigToInterface();
    }

    private void ApplyConfigToInterface()
    {
        try
        {
            // Extract interface name from config path
            string interfaceName = Path.GetFileNameWithoutExtension(configPath);
            if (interfaceName == "wg")
                interfaceName = "NATTunnel"; // Default fallback

            // Create a temporary clean config file (wg.exe doesn't like Address/Name fields)
            string tempConfigPath = Path.Combine(Path.GetTempPath(), $"wg_{interfaceName}_{Guid.NewGuid()}.conf");

            try
            {
                var lines = File.ReadAllLines(configPath);
                var wgLines = new List<string>();
                bool inInterface = false;
                bool inPeer = false;

                wgLines.Add("[Interface]");
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();

                    if (trimmed.StartsWith("[Interface]"))
                    {
                        inInterface = true;
                        inPeer = false;
                        continue;
                    }
                    else if (trimmed.StartsWith("[Peer]"))
                    {
                        inInterface = false;
                        inPeer = true;
                        wgLines.Add("");
                        wgLines.Add("[Peer]");
                        continue;
                    }

                    if (inInterface)
                    {
                        // Only include PrivateKey and ListenPort
                        if (trimmed.StartsWith("PrivateKey") || trimmed.StartsWith("ListenPort"))
                        {
                            wgLines.Add(trimmed);
                        }
                    }
                    else if (inPeer)
                    {
                        // Include all peer fields
                        if (!string.IsNullOrWhiteSpace(trimmed))
                        {
                            wgLines.Add(trimmed);
                        }
                    }
                }

                File.WriteAllLines(tempConfigPath, wgLines);

                // Use wg.exe to reconfigure the interface
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "wg.exe",
                    Arguments = $"setconf {interfaceName} \"{tempConfigPath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    process.WaitForExit();
                    string error = process.StandardError.ReadToEnd();

                    if (process.ExitCode != 0)
                    {
                        Console.WriteLine($"⚠ Failed to apply WireGuard config: {error}");
                    }
                    else
                    {
                        Console.WriteLine($"✓ Applied WireGuard configuration with {peers.Count} peer(s)");
                    }
                }
            }
            finally
            {
                if (File.Exists(tempConfigPath))
                {
                    File.Delete(tempConfigPath);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠ Error applying WireGuard configuration: {ex.Message}");
        }
    }

    public int GetPeerCount()
    {
        return peers.Count;
    }
}