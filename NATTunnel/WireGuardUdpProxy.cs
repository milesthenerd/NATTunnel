using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace NATTunnel;

/// <summary>
/// UDP proxy that intercepts WireGuard traffic and routes it through the NAT hole-punched socket
/// Now supports multiple peers with unique localhost ports
/// Inbound: Tunnel socket receives WireGuard packets → forwards to localhost:51820
/// Outbound: Listens on multiple localhost ports (one per peer) → routes via tunnel socket
/// </summary>
internal class WireGuardUdpProxy : IDisposable
{
    private UdpClient tunnelSocket;  // The hole-punched socket (shared with Tunnel.cs)
    private readonly Dictionary<int, PeerProxyListener> peerListeners; // Port -> Listener mapping
    private readonly Dictionary<IPEndPoint, int> peerEndpointToPort;   // Real endpoint -> Proxy port
    private readonly Dictionary<IPAddress, IPEndPoint> tunnelIpToPeerEndpoint; // Tunnel IP (10.5.0.x) -> Real peer endpoint
    private readonly Dictionary<IPAddress, DateTime> peerLastActivity; // Track last activity per peer IP
    private bool disposed;
    private readonly object proxyLock = new object();
    private readonly object tunnelSocketLock = new object();

    // Callback to notify when a peer is active
    public Action<IPAddress> OnPeerActivity { get; set; }

    // Shared listener on 51821 for WireGuard outbound packets (used for all peers)
    private readonly UdpClient wireguardListener;
    private readonly CancellationTokenSource cancellation;
    private readonly Task listenTask;

    // Static persistent socket for forwarding TO WireGuard with fixed source port
    private static UdpClient inboundForwarder;
    private static readonly object inboundForwarderLock = new object();

    // Inbound WireGuard packets that arrived BEFORE their peer was registered (see ForwardToWireGuard).
    // Keyed by source endpoint; replayed through the correct per-peer listener by RegisterPeer. Without this
    // they were forwarded from the shared socket's source port, which WG-NT rejects — the peer's handshake
    // INITs were effectively discarded until registration happened to complete.
    private readonly Dictionary<IPEndPoint, List<byte[]>> pendingPreRegistration = new();
    private readonly object pendingLock = new object();
    private const int MaxPendingPerEndpoint = 16;

    public WireGuardUdpProxy(UdpClient holePunchedSocket)
    {
        this.tunnelSocket = holePunchedSocket;
        this.peerListeners = new Dictionary<int, PeerProxyListener>();
        this.peerEndpointToPort = new Dictionary<IPEndPoint, int>();
        this.tunnelIpToPeerEndpoint = new Dictionary<IPAddress, IPEndPoint>();
        this.peerLastActivity = new Dictionary<IPAddress, DateTime>();
        this.cancellation = new CancellationTokenSource();

        // Create inbound forwarder on port 51821 (for forwarding FROM tunnel TO WireGuard)
        // Per-peer outbound listeners will be created on 51822, 51823, etc.
        try
        {
            wireguardListener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 51821));
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException(
                $"Cannot bind WireGuard proxy port 51821/UDP — another instance may already be running. ({ex.Message})", ex);
        }
        wireguardListener.Client.ReceiveBufferSize = 128000;
        // Same poisoning risk as the per-peer listeners: this socket also sends to 51820, so a
        // port-unreachable would otherwise fault its next receive. (inboundForwarder aliases this
        // socket, so it's covered too.) See SocketUtils.DisableUdpConnReset.
        SocketUtils.DisableUdpConnReset(wireguardListener);

        // Initialize the inbound forwarder
        lock (inboundForwarderLock)
        {
            if (inboundForwarder == null)
            {
                inboundForwarder = wireguardListener;
            }
        }

        // No shared outbound listener needed - each peer gets their own
        listenTask = Task.CompletedTask;
    }

    /// <summary>
    /// Register a peer with its tunnel IP and real endpoint
    /// Creates a dedicated listener on the peer's proxy port with a specific tunnel socket
    /// </summary>
    public void RegisterPeer(IPEndPoint peerEndpoint, int proxyPort, IPAddress tunnelIp, UdpClient peerTunnelSocket = null, Action<byte[]> icmpSend = null)
    {
        lock (proxyLock)
        {
            // Use provided socket or fall back to shared socket. For an ICMP-backed peer, icmpSend is set and
            // the listener sends WireGuard packets through it instead of the socket.
            UdpClient socketToUse = peerTunnelSocket ?? tunnelSocket;

            // Check if this tunnel IP already exists with a different endpoint
            if (tunnelIpToPeerEndpoint.TryGetValue(tunnelIp, out var oldEndpoint))
            {
                if (!oldEndpoint.Equals(peerEndpoint))
                {
                    // Endpoint changed - remove old entries
                    peerEndpointToPort.Remove(oldEndpoint);
                    peerEndpointToPort.Remove(oldEndpoint);
                }
            }

            // Add/update peer mappings
            peerEndpointToPort[peerEndpoint] = proxyPort;
            tunnelIpToPeerEndpoint[tunnelIp] = peerEndpoint;

            // Create dedicated listener for this peer if it doesn't exist
            if (!peerListeners.ContainsKey(proxyPort))
            {
                var listener = new PeerProxyListener(proxyPort, peerEndpoint, socketToUse, tunnelSocketLock, icmpSend);
                peerListeners[proxyPort] = listener;
            }
            else
            {
                // Update existing listener's endpoint AND socket
                peerListeners[proxyPort].UpdateEndpoint(peerEndpoint);
                peerListeners[proxyPort].UpdateTunnelSocket(socketToUse);
            }

            // Replay whatever arrived from this peer before registration, now that its listener exists.
            List<byte[]> replay = null;
            lock (pendingLock)
            {
                if (pendingPreRegistration.TryGetValue(peerEndpoint, out var q))
                {
                    replay = q;
                    pendingPreRegistration.Remove(peerEndpoint);
                }
            }
            if (replay != null && replay.Count > 0)
            {
                var target = peerListeners[proxyPort];
                Program.Log(LogLevel.Debug,
                    $"[Proxy] Replaying {replay.Count} pre-registration WireGuard packet(s) from {peerEndpoint} " +
                    $"through proxyPort={proxyPort}");
                foreach (var held in replay)
                    target.ForwardInboundPacket(held);
            }
        }
    }

    /// <summary>
    /// Unregister a peer and cleanup its resources
    /// </summary>
    public void UnregisterPeer(IPAddress tunnelIp)
    {
        lock (proxyLock)
        {
            if (tunnelIpToPeerEndpoint.TryGetValue(tunnelIp, out var endpoint))
            {
                // Remove from all tracking dictionaries
                tunnelIpToPeerEndpoint.Remove(tunnelIp);
                peerLastActivity.Remove(tunnelIp);

                // Drop any held pre-registration packets for this endpoint — the tunnel is going away, so
                // replaying them later would inject a dead handshake attempt, and keeping them leaks memory
                // for a peer that may never come back on this endpoint.
                lock (pendingLock) { pendingPreRegistration.Remove(endpoint); }

                if (peerEndpointToPort.TryGetValue(endpoint, out var port))
                {
                    peerEndpointToPort.Remove(endpoint);

                    // Dispose and remove the peer listener
                    if (peerListeners.TryGetValue(port, out var listener))
                    {
                        listener.Dispose();
                        peerListeners.Remove(port);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Update the tunnel socket reference (needed for symmetric NAT socket swaps)
    /// </summary>
    public void UpdateTunnelSocket(UdpClient newSocket)
    {
        lock (tunnelSocketLock)
        {
            tunnelSocket = newSocket;

            // Update all peer listeners with the new socket
            lock (proxyLock)
            {
                foreach (var listener in peerListeners.Values)
                {
                    listener.UpdateTunnelSocket(newSocket);
                }
            }
        }
    }

    /// <summary>
    /// Forwards incoming packets from peers to local WireGuard instance
    /// Uses the peer-specific proxy socket to maintain source port consistency
    /// </summary>
    public void ForwardToWireGuard(byte[] packet, IPEndPoint sourceEndpoint)
    {
        try
        {
            int proxyPort = 0;
            PeerProxyListener listener = null;
            IPAddress peerTunnelIp = null;

            lock (proxyLock)
            {
                // Try exact match first (IP + port)
                if (peerEndpointToPort.TryGetValue(sourceEndpoint, out proxyPort))
                {
                    if (peerListeners.TryGetValue(proxyPort, out listener))
                    {
                        // Find the tunnel IP for this endpoint to track activity
                        peerTunnelIp = tunnelIpToPeerEndpoint.FirstOrDefault(kvp => kvp.Value.Equals(sourceEndpoint)).Key;
                        if (peerTunnelIp != null)
                        {
                            peerLastActivity[peerTunnelIp] = DateTime.UtcNow;
                        }

                        // HANDSHAKE bytes only (1/2/3). Transport data (4) runs at thousands/sec under load and
                        // drowned every other line in the log — and this is the expected path anyway, so it has
                        // no diagnostic value there. The fallback/held paths below still log unconditionally
                        // because those ARE the anomalies.
                        if (packet.Length > 0 && packet[0] >= 1 && packet[0] <= 3)
                            Program.Log(LogLevel.Debug, $"[Proxy][fwd] EXACT src={sourceEndpoint} -> proxyPort={proxyPort} wgType={packet[0]}");

                        listener.ForwardInboundPacket(packet);

                        // Notify activity callback
                        if (peerTunnelIp != null)
                        {
                            OnPeerActivity?.Invoke(peerTunnelIp);
                        }
                        return;
                    }
                }

                // NAT may change source port, so try matching by IP address only.
                // Forward the packet via the matched listener but do NOT update the
                // registered endpoint. Updating causes flip-flopping when multiple peers
                // share the same public IP (same NAT) — even if one peer's entry was
                // removed, the surviving entry gets overwritten back and forth by packets
                // from both peers. The outbound path still uses the original registered
                // endpoint which remains valid (NAT mappings are bidirectional).
                foreach (var kvp in peerEndpointToPort)
                {
                    if (kvp.Key.Address.Equals(sourceEndpoint.Address))
                    {
                        proxyPort = kvp.Value;
                        if (peerListeners.TryGetValue(proxyPort, out listener))
                        {
                            // Track activity without modifying endpoint registration
                            peerTunnelIp = tunnelIpToPeerEndpoint.FirstOrDefault(x => x.Value.Address.Equals(sourceEndpoint.Address)).Key;
                            if (peerTunnelIp != null)
                            {
                                peerLastActivity[peerTunnelIp] = DateTime.UtcNow;
                            }

                            if (packet.Length > 0 && packet[0] >= 1 && packet[0] <= 4)
                                Program.Log(LogLevel.Debug, $"[Proxy][fwd] IP-ONLY-FALLBACK src={sourceEndpoint} registeredKey={kvp.Key} -> proxyPort={proxyPort} wgType={packet[0]}");

                            listener.ForwardInboundPacket(packet);

                            if (peerTunnelIp != null)
                            {
                                OnPeerActivity?.Invoke(peerTunnelIp);
                            }
                            return;
                        }
                    }
                }
            }

            // No peer registered yet: HOLD WG packets rather than misrouting them. Registration needs the peer's
            // public key, but the peer starts sending handshake INITs as soon as the ICMP channel is up. Sending
            // those via the shared forwarder means the wrong source port, and WG-NT discards them (it associates
            // a peer with its per-peer proxy port). Queue and replay on RegisterPeer instead.
            bool isWgProto = packet.Length > 0 && packet[0] >= 1 && packet[0] <= 4;
            if (isWgProto)
            {
                lock (pendingLock)
                {
                    if (!pendingPreRegistration.TryGetValue(sourceEndpoint, out var q))
                    {
                        q = new List<byte[]>();
                        pendingPreRegistration[sourceEndpoint] = q;
                    }
                    // Cap so a peer that never registers can't grow this without bound. WG retries, so dropping
                    // the OLDEST is right: the newest init is the one whose handshake attempt is still live.
                    if (q.Count >= MaxPendingPerEndpoint) q.RemoveAt(0);
                    q.Add(packet);
                    Program.Log(LogLevel.Debug,
                        $"[Proxy][fwd] HELD src={sourceEndpoint} wgType={packet[0]} — no peer registered yet " +
                        $"(queued {q.Count}/{MaxPendingPerEndpoint}); will replay on registration");
                }
                return;
            }

            // Non-WG traffic: unchanged best-effort path via the shared inbound forwarder on port 51821.
            lock (inboundForwarderLock)
            {
                if (inboundForwarder != null)
                {
                    inboundForwarder.Send(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, 51820));
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[Proxy] Error forwarding to WireGuard: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;

        cancellation?.Cancel();

        // Dispose all peer listeners
        lock (proxyLock)
        {
            foreach (var listener in peerListeners.Values)
            {
                listener?.Dispose();
            }
            peerListeners.Clear();
        }

        try
        {
            listenTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch { }

        lock (proxyLock)
        {
            foreach (var listener in peerListeners.Values)
            {
                listener?.Dispose();
            }
            peerListeners.Clear();
        }

        wireguardListener?.Dispose();
        cancellation?.Dispose();

        // Clear static reference so next instance can rebind the port
        lock (inboundForwarderLock)
        {
            if (inboundForwarder == wireguardListener)
                inboundForwarder = null;
        }
    }
}

/// <summary>
/// Individual listener for a single peer's proxy port
/// </summary>
internal class PeerProxyListener : IDisposable
{
    private readonly int proxyPort;
    private IPEndPoint peerEndpoint;
    private UdpClient listener;
    private UdpClient tunnelSocket;
    private readonly object tunnelSocketLock;
    private readonly CancellationTokenSource cancellation;
    private readonly Task listenTask;
    private bool disposed;
    private readonly object endpointLock = new object();
    // When set, this peer is ICMP-backed: outbound WireGuard packets are sent through the ICMP transport
    // (icmpSend) instead of the UDP tunnelSocket. Null = the normal UDP path. This is what makes ICMP a
    // true WireGuard ENCAPSULATOR in daemon mode — WG runs over ICMP exactly as it runs over UDP.
    private readonly Action<byte[]> icmpSend;

    /// <summary>
    /// Lifetime count of datagrams WireGuard-NT has handed to a peer proxy listener (i.e. WG's OUTBOUND
    /// direction, before encapsulation). Diagnostic only. Static so IcmpTransport can fold it into its
    /// per-window stats line without plumbing a reference through — there is at most one proxy per process
    /// and this is a debug counter, so precision across multiple listeners doesn't matter.
    /// </summary>
    internal static long WgToProxyPackets;

    public PeerProxyListener(int proxyPort, IPEndPoint peerEndpoint, UdpClient tunnelSocket, object tunnelSocketLock, Action<byte[]> icmpSend = null)
    {
        this.proxyPort = proxyPort;
        this.peerEndpoint = peerEndpoint;
        this.tunnelSocket = tunnelSocket;
        this.tunnelSocketLock = tunnelSocketLock;
        this.icmpSend = icmpSend;
        this.cancellation = new CancellationTokenSource();

        // Create listener for this specific port
        listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, proxyPort));
        listener.Client.ReceiveBufferSize = 128000;
        // Without this, a single ICMP port-unreachable (e.g. WireGuard-NT not yet listening on 51820)
        // permanently kills this listener's receive loop. See SocketUtils.DisableUdpConnReset.
        SocketUtils.DisableUdpConnReset(listener);

        // Start listening task
        listenTask = Task.Run(() => ListenLoop(cancellation.Token));

    }

    public void UpdateEndpoint(IPEndPoint newEndpoint)
    {
        lock (endpointLock)
        {
            peerEndpoint = newEndpoint;
        }
    }

    public void UpdateTunnelSocket(UdpClient newSocket)
    {
        lock (tunnelSocketLock)
        {
            tunnelSocket = newSocket;
        }
    }

    /// <summary>
    /// Forward an inbound packet from tunnel to WireGuard using this listener's socket
    /// This maintains source port consistency (responses come from the same port WireGuard sent to)
    /// </summary>
    public void ForwardInboundPacket(byte[] packet)
    {
        try
        {
            listener.Send(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, 51820));
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[PeerProxy:{proxyPort}] Error forwarding inbound packet: {ex.Message}");
        }
    }

    private async Task ListenLoop(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                // A receive fault must NOT kill this loop. This await used to sit outside any handler, so one
                // transient socket error (e.g. a UDP ConnectionReset from an ICMP port-unreachable when nothing
                // was listening on 51820 yet) exited the loop permanently and the peer's proxy went silently
                // deaf. Log and keep serving.
                UdpReceiveResult result;
                try
                {
                    result = await listener.ReceiveAsync(token);
                }
                catch (OperationCanceledException) { break; }   // shutdown
                catch (ObjectDisposedException) { break; }      // socket really is gone
                catch (SocketException ex)
                {
                    Program.Log(LogLevel.Warning,
                        $"[PeerProxy:{proxyPort}] Receive error ({ex.SocketErrorCode}) — continuing: {ex.Message}");
                    continue;
                }

                // Ticks once per datagram WG-NT hands us. Reported as wgOut/s: compare against attempted/s —
                // wgOut>0 with attempted=0 means we're losing frames before IcmpTransport.Send; both at 0 while
                // inbound continues means WG itself went quiet.
                Interlocked.Increment(ref WgToProxyPackets);

                // Forward packet from WireGuard to the real peer endpoint via tunnel socket
                IPEndPoint targetEndpoint;
                lock (endpointLock)
                {
                    targetEndpoint = peerEndpoint;
                }

                if (targetEndpoint != null)
                {
                    try
                    {
                        // ICMP-backed peer: encapsulate the WireGuard packet in the ICMP channel instead of a
                        // UDP send. The peer's tunnel forwards received ICMP payloads back into WireGuard, so
                        // WG runs fully over ICMP. (targetEndpoint is unused here — the ICMP transport already
                        // knows its peer.)
                        if (icmpSend != null)
                        {
                            icmpSend(result.Buffer);
                            continue;
                        }

                        UdpClient socketToUse;
                        lock (tunnelSocketLock)
                        {
                            socketToUse = tunnelSocket;
                        }

                        await socketToUse.SendAsync(result.Buffer, targetEndpoint, token);
                    }
                    catch (ObjectDisposedException)
                    {
                        // Socket was disposed (tunnel closed), stop silently
                        break;
                    }
                    catch (Exception ex)
                    {
                        Program.Log(LogLevel.Error, $"[PeerProxy:{proxyPort}] Error sending packet: {ex.Message}");
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[PeerProxy:{proxyPort}] Error in listen loop: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;

        cancellation?.Cancel();

        try
        {
            listenTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch { }

        listener?.Dispose();
        cancellation?.Dispose();
    }
}
