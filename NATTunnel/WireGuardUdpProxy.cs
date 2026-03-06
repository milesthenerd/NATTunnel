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
public class WireGuardUdpProxy : IDisposable
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
        wireguardListener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 51821));
        wireguardListener.Client.ReceiveBufferSize = 128000;

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
    public void RegisterPeer(IPEndPoint peerEndpoint, int proxyPort, IPAddress tunnelIp, UdpClient peerTunnelSocket = null)
    {
        lock (proxyLock)
        {
            // Use provided socket or fall back to shared socket
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
                var listener = new PeerProxyListener(proxyPort, peerEndpoint, socketToUse, tunnelSocketLock);
                peerListeners[proxyPort] = listener;
            }
            else
            {
                // Update existing listener's endpoint AND socket
                peerListeners[proxyPort].UpdateEndpoint(peerEndpoint);
                peerListeners[proxyPort].UpdateTunnelSocket(socketToUse);
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

            // Fallback: use the shared inbound forwarder on port 51821
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
            Console.WriteLine($"[Proxy] Error forwarding to WireGuard: {ex.Message}");
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

    public PeerProxyListener(int proxyPort, IPEndPoint peerEndpoint, UdpClient tunnelSocket, object tunnelSocketLock)
    {
        this.proxyPort = proxyPort;
        this.peerEndpoint = peerEndpoint;
        this.tunnelSocket = tunnelSocket;
        this.tunnelSocketLock = tunnelSocketLock;
        this.cancellation = new CancellationTokenSource();

        // Create listener for this specific port
        listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, proxyPort));
        listener.Client.ReceiveBufferSize = 128000;

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
            Console.WriteLine($"[PeerProxy:{proxyPort}] Error forwarding inbound packet: {ex.Message}");
        }
    }

    private async Task ListenLoop(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var result = await listener.ReceiveAsync(token);

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
                        Console.WriteLine($"[PeerProxy:{proxyPort}] Error sending packet: {ex.Message}");
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Console.WriteLine($"[PeerProxy:{proxyPort}] Error in listen loop: {ex.Message}");
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
