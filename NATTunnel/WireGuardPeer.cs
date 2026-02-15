using System;
using System.Net;

namespace NATTunnel;

public class WireGuardPeer
{
    public string PublicKey { get; private set; }
    public IPEndPoint Endpoint { get; private set; }
    public IPAddress PrivateAddress { get; private set; }
    public string AllowedIPs { get; private set; }
    public bool IsPersistent { get; private set; }
    public int ConnectionId { get; private set; }
    public int KeepAliveInterval { get; set; } = 25;
    public int ProxyPort { get; private set; } // Unique localhost port for this peer
    public DateTime LastActivity { get; set; } = DateTime.UtcNow; // Track when we last received traffic from this peer

    public WireGuardPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, int connectionId, bool isPersistent = false, int proxyPort = 0)
    {
        PublicKey = publicKey;
        Endpoint = endpoint;
        PrivateAddress = privateAddress;
        ConnectionId = connectionId;
        IsPersistent = isPersistent;
        ProxyPort = proxyPort > 0 ? proxyPort : 51822; // Default to 51822 (51821 is reserved for inbound forwarder)
        // Format allowed IPs based on private address
        AllowedIPs = $"{privateAddress}/32";
    }

    /// <summary>
    /// Reset AllowedIPs back to just this peer's own private address.
    /// Called when relay routes through this peer are being removed.
    /// </summary>
    public void ResetAllowedIPs()
    {
        AllowedIPs = $"{PrivateAddress}/32";
    }

    /// <summary>
    /// Add an additional IP to this peer's AllowedIPs (used for relay routing)
    /// </summary>
    public void AddAllowedIP(IPAddress ip)
    {
        string newEntry = $"{ip}/32";
        if (!AllowedIPs.Contains(newEntry))
        {
            AllowedIPs = $"{AllowedIPs},{newEntry}";
        }
    }

    public string GenerateConfigSection(bool useProxyEndpoint = true)
    {
        // Each peer gets their own unique localhost port for routing
        string endpoint = $"127.0.0.1:{ProxyPort}";

        return $"[Peer]\nPublicKey = {PublicKey}\nEndpoint = {endpoint}\nAllowedIPs = {AllowedIPs}\nPersistentKeepalive = {KeepAliveInterval}\n";
    }
}