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
    private int nextPeerId = 2;  // Start at 2 since server is 10.5.0.1
    private int nextProxyPort = 51822; // Start allocating unique ports from 51822 (51821 is reserved for inbound forwarder)
    private readonly HashSet<int> allocatedPorts = new(); // Track allocated ports
    private readonly HashSet<int> allocatedPeerIds = new(); // Track allocated peer IDs for IP reuse

    public WireGuardPeerManager(string configPath, IPAddress baseAddress, int basePort = 51820)
    {
        this.configPath = configPath;
        this.baseAddress = baseAddress;
        this.basePort = basePort;
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

    private int AllocatePeerId()
    {
        lock (configLock)
        {
            // Try to reuse freed peer IDs first (starting from 2)
            for (int id = 2; id < nextPeerId; id++)
            {
                if (!allocatedPeerIds.Contains(id))
                {
                    allocatedPeerIds.Add(id);
                    return id;
                }
            }

            // No freed IDs available, allocate a new one
            int peerId = nextPeerId++;
            allocatedPeerIds.Add(peerId);
            return peerId;
        }
    }

    private void ReleasePeerId(int peerId)
    {
        lock (configLock)
        {
            allocatedPeerIds.Remove(peerId);
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
                if (!existingPeerByKey.Endpoint.Equals(endpoint))
                {
                    peers.Remove(existingPeerByKey);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByKey.PrivateAddress, existingPeerByKey.ConnectionId, existingPeerByKey.IsPersistent, existingPeerByKey.ProxyPort);
                    peers.Add(updatedPeer);
                    return updatedPeer;
                }
                return existingPeerByKey;
            }

            // Check if peer with this endpoint already exists
            var existingPeerByEndpoint = peers.FirstOrDefault(p => p.Endpoint.Equals(endpoint));
            if (existingPeerByEndpoint != null)
            {
                if (existingPeerByEndpoint.PublicKey != publicKey)
                {
                    peers.Remove(existingPeerByEndpoint);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByEndpoint.PrivateAddress, existingPeerByEndpoint.ConnectionId, existingPeerByEndpoint.IsPersistent, existingPeerByEndpoint.ProxyPort);
                    peers.Add(updatedPeer);
                    return updatedPeer;
                }
                return existingPeerByEndpoint;
            }

            var ipBytes = baseAddress.GetAddressBytes();
            int peerId = AllocatePeerId();
            ipBytes[3] = (byte)peerId;
            var peerAddress = new IPAddress(ipBytes);
            int proxyPort = AllocateProxyPort();

            var peer = new WireGuardPeer(publicKey, endpoint, peerAddress, peerId, isPersistent, proxyPort);
            peers.Add(peer);
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
                if (!existingPeerByKey.Endpoint.Equals(endpoint))
                {
                    peers.Remove(existingPeerByKey);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByKey.PrivateAddress, existingPeerByKey.ConnectionId, existingPeerByKey.IsPersistent, existingPeerByKey.ProxyPort);
                    peers.Add(updatedPeer);
                    return updatedPeer;
                }
                return existingPeerByKey;
            }

            // Check if peer with this endpoint already exists
            var existingPeerByEndpoint = peers.FirstOrDefault(p => p.Endpoint.Equals(endpoint));
            if (existingPeerByEndpoint != null)
            {
                if (existingPeerByEndpoint.PublicKey != publicKey)
                {
                    peers.Remove(existingPeerByEndpoint);
                    var updatedPeer = new WireGuardPeer(publicKey, endpoint, existingPeerByEndpoint.PrivateAddress, existingPeerByEndpoint.ConnectionId, existingPeerByEndpoint.IsPersistent, existingPeerByEndpoint.ProxyPort);
                    peers.Add(updatedPeer);
                    return updatedPeer;
                }
                return existingPeerByEndpoint;
            }

            int connectionId = (int)privateAddress.GetAddressBytes()[3];
            int proxyPort = AllocateProxyPort();
            allocatedPeerIds.Add(connectionId);

            var peer = new WireGuardPeer(publicKey, endpoint, privateAddress, connectionId, isPersistent, proxyPort);
            peers.Add(peer);
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
                ReleasePeerId(connectionId); // Free the peer ID / IP address for reuse
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

    public void RemoveAllPeers()
    {
        lock (configLock)
        {
            foreach (var peer in peers.ToList())
            {
                ReleaseProxyPort(peer.ProxyPort);
                ReleasePeerId(peer.ConnectionId);
            }
            peers.Clear();
            UpdateConfig();
        }
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

        // Add each peer (all use localhost proxy endpoint)
        foreach (var peer in peers)
        {
            newConfig.AppendLine(peer.GenerateConfigSection());
            newConfig.AppendLine();
        }

        // Write the new config
        // (WireGuardTunnel.AddPeer applies the config via WireGuardNT.UpdateConfiguration after calling this)
        File.WriteAllText(configPath, newConfig.ToString());
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
                        Console.WriteLine($"Failed to apply WireGuard config: {error}");
                    }
                    else
                    {
                        Console.WriteLine($"Applied WireGuard configuration with {peers.Count} peer(s)");
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
            Console.WriteLine($"Error applying WireGuard configuration: {ex.Message}");
        }
    }

    public int GetPeerCount()
    {
        return peers.Count;
    }
}