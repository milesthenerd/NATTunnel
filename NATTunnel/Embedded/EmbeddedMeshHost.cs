using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;

namespace NATTunnel.Embedded;

/// <summary>
/// <see cref="IMeshHost"/> implementation for the embedded library. Where the daemon-side
/// <see cref="WireGuardTunnel"/> host backs each "peer" with a real WG interface entry +
/// kernel route, this host backs each peer with a <see cref="MeshPeerProxy"/> (loopback
/// proxy + Noise transport) and an in-memory relay route table.
///
/// Mutates from multiple threads: the MeshProtocolEngine protocol loop calls peer / relay operations;
/// the shared UDP dispatcher calls <see cref="ForwardDataPacket"/>. Internal collections
/// are concurrent-safe.
/// </summary>
internal sealed class EmbeddedMeshHost : IMeshHost, IDisposable
{
    /// <summary>Peer mesh-IP → proxy. Set when MeshProtocolEngine confirms a peer (via AddPeer-equivalent).</summary>
    private readonly ConcurrentDictionary<IPAddress, MeshPeerProxy> peersByMeshIP = new();
    /// <summary>Peer connection ID → mesh IP. Lets RemovePeer(int) find the right entry.</summary>
    private readonly ConcurrentDictionary<int, IPAddress> meshIPByConnectionId = new();
    /// <summary>Mesh IP → host-assigned synthetic connection ID. Used by GetPeer() to give
    /// stable WireGuardPeer placeholders that RemovePeer(int) can correctly resolve.</summary>
    private readonly ConcurrentDictionary<IPAddress, int> connectionIdByMeshIP = new();
    private int nextSyntheticConnectionId = 1;

    /// <summary>Relay routes: relayed peer's mesh IP → gateway peer's mesh IP.</summary>
    private readonly ConcurrentDictionary<IPAddress, IPAddress> relayRoutes = new();

    /// <summary>This node's own mesh IP. Set by MeshProtocolEngine via SetClientIPAndRestart.</summary>
    public IPAddress OwnMeshIP { get; private set; }

    /// <summary>True after EnableForwarding has been called.</summary>
    public bool ForwardingEnabled { get; private set; }

    /// <summary>
    /// Called by the embedded library to associate a freshly-created MeshPeerProxy with the
    /// remote peer's mesh IP. The host allocates its own synthetic connection ID so subsequent
    /// <see cref="GetPeer"/> → <see cref="RemovePeer"/> chains resolve to the right entry.
    /// </summary>
    public void RegisterProxy(IPAddress meshIP, MeshPeerProxy proxy)
    {
        int connId = Interlocked.Increment(ref nextSyntheticConnectionId);
        peersByMeshIP[meshIP] = proxy;
        meshIPByConnectionId[connId] = meshIP;
        connectionIdByMeshIP[meshIP] = connId;
    }

    // ── IMeshHost ──

    public void SetClientIPAndRestart(string assignedIpAddress, byte prefixLength = 24)
    {
        if (IPAddress.TryParse(assignedIpAddress, out var ip)) OwnMeshIP = ip;
        // No interface to restart in embedded mode — mesh IP is just an identifier here.
    }

    public bool EnableForwarding()
    {
        ForwardingEnabled = true;
        return true;
    }

    public bool AddRelayRoute(IPAddress gatewayPeerIP, IPAddress relayedPeerIP)
    {
        if (gatewayPeerIP == null || relayedPeerIP == null) return false;
        relayRoutes[relayedPeerIP] = gatewayPeerIP;
        return true;
    }

    public void OnRelayPeerEstablished(string remotePeerID, IPAddress remoteMeshIP, IPAddress gatewayMeshIP, IPEndPoint remotePublicEndpoint)
    {
        // Forward the full peer identity to NATTunnel.MeshNode so it can build a relayed
        // MeshPeerProxy. Idempotent — duplicate fires shouldn't re-create the proxy
        // (NATTunnel.MeshNode guards on its own peer dictionary).
        try { RelayedPeerAdded?.Invoke(remotePeerID, remoteMeshIP, gatewayMeshIP, remotePublicEndpoint); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[EmbeddedMeshHost] RelayedPeerAdded handler threw: {ex.Message}"); }
    }

    public bool SendMeshControl(IPAddress destinationMeshIP, byte[] data, int length)
    {
        if (destinationMeshIP == null) return true;
        if (peersByMeshIP.TryGetValue(destinationMeshIP, out var proxy))
        {
            // MeshPeerProxy queues if handshake isn't done yet; we don't need to track failure here.
            proxy.SendMeshControl(data, length);
        }
        else
        {
            Program.Log(LogLevel.Warning, $"[EmbeddedMeshHost] SendMeshControl to {destinationMeshIP}: no proxy registered (dropping packet).");
        }
        return true;
    }

    /// <summary>
    /// Look up the MeshPeerProxy registered for a given mesh IP. Used by NATTunnel.MeshNode
    /// when constructing a relayed proxy — it needs the gateway peer's tunnel as the carrier.
    /// </summary>
    public MeshPeerProxy GetProxyByMeshIP(IPAddress meshIP)
    {
        peersByMeshIP.TryGetValue(meshIP, out var proxy);
        return proxy;
    }

    public bool RemoveRelayRouteForPeer(IPAddress relayedPeerIP)
    {
        if (relayedPeerIP == null) return false;
        return relayRoutes.TryRemove(relayedPeerIP, out _);
    }

    public List<IPAddress> RemoveRelayRoutesViaGateway(IPAddress gatewayPeerIP)
    {
        var removed = new List<IPAddress>();
        if (gatewayPeerIP == null) return removed;
        foreach (var kv in relayRoutes.ToArray())
        {
            if (kv.Value.Equals(gatewayPeerIP) && relayRoutes.TryRemove(kv.Key, out _))
                removed.Add(kv.Key);
        }
        return removed;
    }

    public Dictionary<IPAddress, IPAddress> GetRelayRoutes()
    {
        return relayRoutes.ToArray().ToDictionary(kv => kv.Key, kv => kv.Value);
    }

    public WireGuardPeer GetPeer(IPAddress privateAddress)
    {
        if (privateAddress == null) return null;
        if (!peersByMeshIP.TryGetValue(privateAddress, out _)) return null;
        connectionIdByMeshIP.TryGetValue(privateAddress, out int connId);
        return WireGuardPeer.ForEmbedded(endpoint: null, privateAddress: privateAddress, connectionId: connId);
    }

    public IEnumerable<WireGuardPeer> GetAllPeers()
    {
        foreach (var kv in peersByMeshIP.ToArray())
        {
            connectionIdByMeshIP.TryGetValue(kv.Key, out int connId);
            yield return WireGuardPeer.ForEmbedded(endpoint: null, privateAddress: kv.Key, connectionId: connId);
        }
    }

    public void RemovePeer(int connectionId)
    {
        if (meshIPByConnectionId.TryRemove(connectionId, out var meshIP))
        {
            connectionIdByMeshIP.TryRemove(meshIP, out _);
            if (peersByMeshIP.TryRemove(meshIP, out var proxy))
            {
                try { PeerRemoved?.Invoke(meshIP, proxy); }
                catch (Exception ex) { Program.Log(LogLevel.Error, $"[EmbeddedMeshHost] PeerRemoved handler threw: {ex.Message}"); }
                try { proxy.Dispose(); } catch { }
            }
        }
    }

    public void RemoveAllPeers()
    {
        foreach (var kv in peersByMeshIP.ToArray())
        {
            if (peersByMeshIP.TryRemove(kv.Key, out var proxy))
            {
                try { PeerRemoved?.Invoke(kv.Key, proxy); }
                catch (Exception ex) { Program.Log(LogLevel.Error, $"[EmbeddedMeshHost] PeerRemoved handler threw: {ex.Message}"); }
                try { proxy.Dispose(); } catch { }
            }
        }
        meshIPByConnectionId.Clear();
        connectionIdByMeshIP.Clear();
        relayRoutes.Clear();
    }

    public void ForwardDataPacket(byte[] data, IPEndPoint sourceEndpoint)
    {
        // In embedded mode, direct 0x01 data packets arrive via Tunnel.DataPacketReceived
        // wired straight to MeshPeerProxy.OnTunnelPacket — no fan-out via this host method
        // needed for direct peers. This entry point is unused in embedded mode; relay
        // forwarding uses ForwardRelayEnvelope below instead (called from NATTunnel.MeshNode
        // when a 0x02 envelope arrives on a tunnel).
    }

    /// <summary>
    /// Relay forwarding. The caller has received a 0x02-framed packet on a tunnel to a
    /// relayed-pair peer; this method peels the envelope, looks up the destination peer's
    /// direct tunnel, and forwards the inner verbatim.
    ///
    /// Wire layout:
    ///   [0]      = 0x02
    ///   [1..4]   = destination mesh IPv4 (4 bytes, big-endian network order)
    ///   [5..]    = inner packet (typically 0x01 ‖ counter ‖ ciphertext, but treated as opaque)
    /// </summary>
    /// <summary>
    /// Handle an inbound 0x02 relay envelope. Two cases:
    ///   - dst-IP matches our OwnMeshIP: deliver inner to the locally-registered MeshPeerProxy
    ///     for the source peer (so it can decrypt with the right end-to-end key).
    ///   - dst-IP is some other peer: we're the relay; forward the envelope verbatim to dst's
    ///     tunnel so the receiver's Tunnel.RelayEnvelopeReceived fires and they dispatch locally.
    /// </summary>
    public void ForwardRelayEnvelope(byte[] envelope)
    {
        if (envelope == null || envelope.Length < 1 + 4 + 4) return;
        if (envelope[0] != 0x02) return;

        // Envelope layout: [0x02] [4-byte src-mesh-IP] [4-byte dst-mesh-IP] [inner...]
        var srcMeshIP = new IPAddress(new[] { envelope[1], envelope[2], envelope[3], envelope[4] });
        var dstMeshIP = new IPAddress(new[] { envelope[5], envelope[6], envelope[7], envelope[8] });

        // Case 1: we're the destination. Deliver the inner bytes to our proxy-for-src.
        if (OwnMeshIP != null && OwnMeshIP.Equals(dstMeshIP))
        {
            if (peersByMeshIP.TryGetValue(srcMeshIP, out var srcProxy))
            {
                int innerLen = envelope.Length - 9;
                var inner = new byte[innerLen];
                Buffer.BlockCopy(envelope, 9, inner, 0, innerLen);
                srcProxy.DeliverRelayedInner(inner);
            }
            else
            {
                Program.Log(LogLevel.Warning, $"[EmbeddedMeshHost] Relay packet from {srcMeshIP} has no local proxy; dropping.");
            }
            return;
        }

        // Case 2: we're the relay. Forward verbatim through dst's tunnel.
        if (!peersByMeshIP.TryGetValue(dstMeshIP, out var dstProxy))
        {
            MaybeLogRelayDrop(dstMeshIP, "no tunnel to dst");
            return;
        }
        // Skip the send if the tunnel isn't connected yet — otherwise SendDataPacket throws
        // and we'd spam an Error log for every queued packet.
        if (!dstProxy.Tunnel.connected)
        {
            MaybeLogRelayDrop(dstMeshIP, "tunnel not connected");
            return;
        }
        try { dstProxy.Tunnel.SendDataPacket(envelope); }
        catch (Exception ex) { MaybeLogRelayDrop(dstMeshIP, $"send failed: {ex.Message}"); }
    }

    // Per-destination rate-limit for the "relay drop" warning. Cap to once per minute per destination.
    private readonly ConcurrentDictionary<IPAddress, DateTime> lastRelayDropLogAt = new();
    private static readonly TimeSpan RelayDropLogCooldown = TimeSpan.FromMinutes(1);

    private void MaybeLogRelayDrop(IPAddress dstMeshIP, string reason)
    {
        var now = DateTime.UtcNow;
        if (lastRelayDropLogAt.TryGetValue(dstMeshIP, out var last) && now - last < RelayDropLogCooldown)
            return;
        lastRelayDropLogAt[dstMeshIP] = now;
        Program.Log(LogLevel.Warning, $"[EmbeddedMeshHost] Relay forward to {dstMeshIP} dropped ({reason}); subsequent drops suppressed for {RelayDropLogCooldown.TotalSeconds:0}s.");
    }

    /// <summary>
    /// Raised when MeshProtocolEngine creates a Tunnel for a new peer. NATTunnel.MeshNode subscribes
    /// here to construct the MeshPeerProxy + start its Noise handshake.
    /// </summary>
    public event Action<Tunnel, string, string> TunnelCreated;

    /// <summary>
    /// Raised when a peer is removed (heartbeat-declared dead or graceful leave). Carries
    /// the mesh IP + the proxy reference so MeshNode can find the corresponding MeshPeer
    /// (matched by proxy reference, since the host's mesh-IP→proxy map is already cleared
    /// by the time this fires).
    /// </summary>
    public event Action<IPAddress, MeshPeerProxy> PeerRemoved;

    /// <summary>
    /// Raised when a relayed peer is established (after AddRelayRoute + OnRelayPeerEstablished).
    /// Carries the full peer identity that NATTunnel.MeshNode needs to construct a relayed
    /// MeshPeerProxy (peer ID for Noise initiator decision; mesh IPs for envelope + routing).
    /// </summary>
    public event Action<string, IPAddress, IPAddress, IPEndPoint> RelayedPeerAdded;

    public void ConfigureNewTunnel(Tunnel tunnel, string remotePeerID, string remoteMeshIP)
    {
        // No WireGuard reference to attach. Pass the tunnel + remote identity to the embedded
        // library, which constructs a MeshPeerProxy and starts the Noise handshake.
        TunnelCreated?.Invoke(tunnel, remotePeerID, remoteMeshIP);
    }

    public void Dispose()
    {
        // Dispose every registered MeshPeerProxy so loopback sockets and Noise transports
        // are released. Called from MeshProtocolEngine's finally block during shutdown.
        RemoveAllPeers();
    }
}
