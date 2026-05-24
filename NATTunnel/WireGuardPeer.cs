using System;
using System.Linq;
using System.Net;

namespace NATTunnel;

internal class WireGuardPeer
{
    public string PublicKey { get; private set; }
    public IPEndPoint Endpoint { get; private set; }
    public IPAddress PrivateAddress { get; private set; }
    public string AllowedIPs { get; private set; }
    public bool IsPersistent { get; private set; }
    public int ConnectionId { get; private set; }
    public int KeepAliveInterval { get; set; } = 5;
    public int ProxyPort { get; private set; } // Unique localhost port for this peer
    public DateTime LastActivity { get; set; } = DateTime.UtcNow; // Track when we last received traffic from this peer

    /// <summary>
    /// Validates that a WireGuard public key is valid (44-char base64 encoding 32 bytes).
    /// Prevents argument injection when the key is passed to wg.exe commands.
    /// </summary>
    public static bool IsValidPublicKey(string key)
    {
        if (string.IsNullOrEmpty(key) || key.Length != 44 || key[43] != '=')
            return false;
        // Reject any whitespace or shell metacharacters
        foreach (char c in key)
        {
            if (char.IsWhiteSpace(c) || c == '&' || c == '|' || c == ';' || c == '"' || c == '\'' || c == '`')
                return false;
        }
        try
        {
            byte[] bytes = Convert.FromBase64String(key);
            return bytes.Length == 32;
        }
        catch
        {
            return false;
        }
    }

    public WireGuardPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, int connectionId, bool isPersistent = false, int proxyPort = 0)
    {
        if (!IsValidPublicKey(publicKey))
            throw new ArgumentException($"Invalid WireGuard public key format: {publicKey?.Substring(0, Math.Min(publicKey?.Length ?? 0, 8))}...");
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
    /// Placeholder constructor for embedded-mode hosts that don't run WireGuard. Sets
    /// PublicKey to a synthetic non-validatable value — MeshProtocolEngine protocol code only reads
    /// it for logging in embedded mode. Do not call from daemon code paths.
    /// </summary>
    internal static WireGuardPeer ForEmbedded(IPEndPoint endpoint, IPAddress privateAddress, int connectionId)
    {
        var p = (WireGuardPeer)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(WireGuardPeer));
        p.PublicKey = "<embedded-no-wireguard>";
        p.Endpoint = endpoint;
        p.PrivateAddress = privateAddress;
        p.ConnectionId = connectionId;
        p.IsPersistent = false;
        p.ProxyPort = 0;
        p.KeepAliveInterval = 5;
        p.LastActivity = DateTime.UtcNow;
        p.AllowedIPs = privateAddress != null ? $"{privateAddress}/32" : "";
        return p;
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

    /// <summary>Remove one /32 entry from this peer's AllowedIPs without affecting other entries.</summary>
    public void RemoveAllowedIP(IPAddress ip)
    {
        string target = $"{ip}/32";
        var kept = AllowedIPs
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(e => e != target);
        AllowedIPs = string.Join(",", kept);
    }

    public string GenerateConfigSection(bool useProxyEndpoint = true)
    {
        // Each peer gets their own unique localhost port for routing
        string endpoint = $"127.0.0.1:{ProxyPort}";

        return $"[Peer]\nPublicKey = {PublicKey}\nEndpoint = {endpoint}\nAllowedIPs = {AllowedIPs}\nPersistentKeepalive = {KeepAliveInterval}\n";
    }
}