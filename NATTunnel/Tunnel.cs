using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections;

namespace NATTunnel;

internal class Tunnel : IDisposable
{
    //TODO: entire class should get reviewed and eventually split up into smaller classes

    // Connection constants
    private const int HOLE_PUNCH_THRESHOLD = 3;  // Number of hole punch packets required before confirming connection.
                                                 // A single stray packet from a symmetric peer can land on a probe
                                                 // whose NAT mapping expires immediately after — declaring success
                                                 // there gets us stuck with a "one-way" tunnel

    private UdpClient udpClient;
    private CancellationTokenSource udpClientTaskCancellationToken = new CancellationTokenSource();
    private readonly IPEndPoint endpoint;
    private IPAddress targetPeerIp;
    private int targetPeerPort;

    /// <summary>
    /// The post-hole-punch remote endpoint this tunnel sends to. For a direct tunnel this is
    /// the peer's NAT-translated public address. Null until hole-punching resolves
    /// targetPeerIp/Port — i.e. before <see cref="connected"/> becomes true.
    /// </summary>
    public IPEndPoint RemoteEndpoint =>
        (targetPeerIp != null && targetPeerPort > 0) ? new IPEndPoint(targetPeerIp, targetPeerPort) : null;
    private int holePunchReceivedCount;
    public bool connected;
    private NATType natType = NATType.Unknown;
    private NATType remoteNatType = NATType.Unknown;
    private List<UdpClient> symmetricConnectionUdpProbes = new List<UdpClient>();
    private int probeConnected = 0; // Atomic flag: first winning probe sets this to 1 via Interlocked.CompareExchange
    // 0 = alive, 1 = Dispose has run. Checked by timer Elapsed handlers and async receive
    // callbacks before doing socket I/O so a Dispose-during-hole-punch actually quiets the
    // network immediately instead of waiting for the next packet to throw.
    private int disposed;
    // Receive loop for the winning symmetric probe (when natType == Symmetric and a probe won).
    // Stored so Dispose can signal cancellation and await the task to exit.
    private CancellationTokenSource winningProbeCts;
    private Task winningProbeTask;
    private int currentConnectionID = 0;
    public IPAddress privateIP = null;
    private WireGuardTunnel wireguardTunnel;

    /// <summary>
    /// Raised when a non-WireGuard, non-mediation binary packet arrives from the peer.
    /// Only fires when wireguardTunnel is null (i.e., embedded/library mode, no kernel WG).
    /// The handler receives the raw packet bytes; the sender endpoint is implicit (this tunnel's peer).
    /// </summary>
    public event Action<byte[]> DataPacketReceived;

    /// <summary>
    /// Embedded mode only. Fires when a 0x02-framed relay envelope arrives. Raised on the
    /// tunnel that owns the source endpoint (i.e. the tunnel to the peer who's relaying
    /// traffic through us). The host is expected to peel the envelope, look up the
    /// destination peer's tunnel via its relay route table, and forward the inner packet.
    /// </summary>
    public event Action<byte[]> RelayEnvelopeReceived;


    private int maxConnectionTimeout = 15;
    private int symmetricConnectionTimeout = 60; // Symmetric NAT needs more time for random port spray
    private int connectionTimeout;
    private Timer initialConnectionTimer;
    private Timer connectionAttempt;
    private int retryAttempt = 0;
    private int maxRetryAttempts = 1;
    private int retryCooldown = 10;  // seconds before retrying after failure
    private bool wgKeySent = false;  // Track if we've already sent our WireGuard public key
    private SHA256 shaHashGen;
    private Guid clientID;
    private Action onConnectionFailure; // Callback for when connection fails completely
    private Action onConnectionComplete; // Callback for when connection is successfully established

    /// <summary>
    /// Fires alongside the internal onConnectionComplete callback when the tunnel transitions
    /// to the "connected" state. Multi-subscriber event so external observers (e.g. embedded
    /// mode's MeshPeerProxy waiting to start its Noise handshake) can react without needing
    /// to inject themselves into MeshProtocolEngine's onConnectionComplete closure.
    /// </summary>
    public event Action ConnectionEstablished;
    private DateTime lastActivityTime; // Track last time this tunnel had any activity
    private long totalBytesReceived = 0; // Track total bytes received for activity monitoring
    private long totalBytesSent = 0; // Track total bytes sent for activity monitoring
    private IPEndPoint meshPeerEndpoint = null; // The peer's endpoint
    private bool retryInPlace = false; // If true, retry without recreating tunnel
    private bool ownsUdpClient = true; // False when using a shared UDP client — Dispose must not close it
    private IPAddress ownMeshIP = null; // Our own mesh IP
    private IPAddress peerMeshIP = null; // Remote peer's mesh IP

    public Tunnel(Action onConnectionFailure = null, UdpClient sharedUdpClient = null, string meshPeerEndpoint = null, bool retryInPlace = false, Guid? sharedClientID = null, string ownMeshIP = null, Action onConnectionComplete = null)
    {
        connectionTimeout = maxConnectionTimeout;
        shaHashGen = SHA256.Create();
        // Use shared clientID if provided (for mesh tunnels to share ID with mesh mode)
        clientID = sharedClientID ?? Guid.NewGuid();

        this.onConnectionFailure = onConnectionFailure;
        this.onConnectionComplete = onConnectionComplete;
        this.lastActivityTime = DateTime.UtcNow;
        this.retryInPlace = retryInPlace;

        // Legacy direct-connect "check" ping target. Mesh mode drives mediation through the
        // engine, not per-Tunnel, so this stays null there; the resolved endpoint is no longer a
        // TunnelOptions static (DNS is deferred to the engine's connect loop).
        endpoint = null;

        // Set mesh IP if provided
        if (ownMeshIP != null)
        {
            this.ownMeshIP = IPAddress.Parse(ownMeshIP);
            privateIP = this.ownMeshIP;
        }

        // Parse mesh peer endpoint if provided — handles IPv4, [IPv6]:port, and v4-mapped forms
        if (meshPeerEndpoint != null && EndpointUtils.TryParseEndpoint(meshPeerEndpoint, out var parsedPeerEp))
            this.meshPeerEndpoint = parsedPeerEp;

        // Use shared UDP client if provided, otherwise create a new one
        if (sharedUdpClient != null)
        {
            udpClient = sharedUdpClient;
            ownsUdpClient = false;
        }
        else
        {
            // Bound immediately (port 0 = OS assigns ephemeral) so we have a local port
            // before WireGuard configuration.
            udpClient = SocketUtils.CreateUdpClient();
        }

        //Try to send initial msg to mediator (legacy direct-connect path only)
        try
        {
            if (endpoint != null)
            {
                byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
                udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, ex.ToString());
        }

        initialConnectionTimer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = false
        };
        initialConnectionTimer.Elapsed += ConnectionTimer;
    }

    /// <summary>
    /// Cleans up state from a previous connection attempt so a new one can start cleanly.
    /// Stops the old connectionAttempt timer and disposes symmetric NAT probe sockets.
    /// </summary>
    private void CleanupPreviousConnectionAttempt()
    {
        if (connectionAttempt != null)
        {
            connectionAttempt.Enabled = false;
            connectionAttempt.Dispose();
            connectionAttempt = null;
        }

        // Dispose and clear old symmetric NAT probes
        foreach (var probe in symmetricConnectionUdpProbes)
        {
            try { probe?.Close(); } catch { }
        }
        symmetricConnectionUdpProbes.Clear();
    }

    /// <summary>
    /// Sets the WireGuard tunnel reference so clients can restart with their assigned IP
    /// </summary>
    public void SetWireGuardTunnel(WireGuardTunnel tunnel)
    {
        wireguardTunnel = tunnel;
    }

    /// <summary>
    /// Gets the UDP client used for NAT traversal (to be shared with WireGuard proxy)
    /// </summary>
    public UdpClient GetUdpClient()
    {
        return udpClient;
    }

    /// <summary>
    /// Gets the local UDP port being used for NAT traversal/hole-punching
    /// </summary>
    public int GetLocalUdpPort()
    {
        if (udpClient?.Client?.LocalEndPoint is IPEndPoint endpoint)
        {
            return endpoint.Port;
        }
        return 51820; // Fallback to default WireGuard port
    }

    private void ConnectionTimer(object source, ElapsedEventArgs e)
    {
        if (initialConnectionTimer.Enabled)
        {
            if (connectionTimeout > 0) connectionTimeout--;
            if (connectionTimeout == 0)
            {
                connectionAttempt.Enabled = false;
                initialConnectionTimer.Enabled = false;

                // Diagnostic: how many hole-punch packets did we actually receive from the peer?
                // ZERO after a full attempt = nothing is arriving inbound → almost certainly a local
                // firewall or a restrictive NAT dropping inbound UDP from this peer (NOT a code bug;
                // DirectMapping only measures port MAPPING, never inbound FILTERING). Non-zero but
                // below threshold = packets arrive but the flow stalls (mapping/filter/timing).
                if (holePunchReceivedCount == 0)
                    Program.Log(LogLevel.Warning, $"Hole-punch to {targetPeerIp}:{targetPeerPort} received 0 packets from the peer — inbound UDP is likely being dropped by a local firewall or a restrictive NAT. Allow inbound UDP for NATTunnel peer traffic.");
                else
                    Program.Log(LogLevel.Debug, $"Hole-punch to {targetPeerIp}:{targetPeerPort} received {holePunchReceivedCount}/{HOLE_PUNCH_THRESHOLD} packets before timeout (flow stalled below threshold).");

                retryAttempt++;
                // Only advertise a retry if one will actually happen in-place; with maxRetryAttempts=1
                // there's no in-place retry (the introducer re-sends MeshConnectionBegin to drive the
                // next attempt), so don't log a "waiting to retry" that never fires.
                if (retryAttempt < maxRetryAttempts)
                    Program.Log(LogLevel.Warning, $"Connection attempt {retryAttempt} failed. Waiting {retryCooldown}s before retry...");

                if (retryAttempt < maxRetryAttempts)
                {
                    // Schedule a retry after cooldown
                    Task.Delay(retryCooldown * 1000).ContinueWith(_ =>
                    {
                        if (!connected && retryAttempt < maxRetryAttempts)
                        {
                            Program.Log(LogLevel.Debug, $"Retrying connection (attempt {retryAttempt + 1}/{maxRetryAttempts})...");

                            if (!retryInPlace)
                            {
                                onConnectionFailure?.Invoke();
                            }
                            else
                            {
                                // Mesh peer - just reset connection state and retry
                                connectionTimeout = maxConnectionTimeout;
                                holePunchReceivedCount = 0;
                                probeConnected = 0;
                                connectionAttempt.Enabled = true;
                                initialConnectionTimer.Enabled = true;
                            }
                        }
                    });
                }
                else
                {
                    Program.Log(LogLevel.Warning, $"Max connection retries ({maxRetryAttempts}) reached. Giving up.");
                    onConnectionFailure?.Invoke();
                }
            }
        }
    }

    public void Start()
    {
        // Mesh mode: don't create TCP connection
        // Mesh mode handles TCP coordination and will inject messages as needed
        // Just wait for messages to be injected from mesh mode
        // UDP receive loop will be started when ConnectionBegin is processed
    }

    /// <summary>
    /// Inject a ConnectionBegin externally (used for introducer-relayed connections where
    /// the tunnel has no TCP connection to the mediation server). Sets up the peer endpoint,
    /// NAT types, and starts hole-punching directly.
    /// Handles all NAT type combinations:
    ///   - Both non-symmetric: standard hole punch
    ///   - We're symmetric: 256 UDP probes (TryConnectFromSymmetric)
    ///   - Peer is symmetric: random port spray (TryConnectToSymmetric)
    ///   - Both symmetric: should not reach here (relay mode handles it)
    /// </summary>
    public void InjectConnectionBegin(string endpointString, NATType peerNatType, NATType ownNatType, string peerMeshIPString)
    {
        // Stop any previous connection attempt's timer and probes
        CleanupPreviousConnectionAttempt();

        remoteNatType = peerNatType;

        holePunchReceivedCount = 0;
        probeConnected = 0;
        connectionTimeout = maxConnectionTimeout;
        retryAttempt = 0;
        // Defer enabling the countdown timer until after the NAT-strategy branches below
        // have had a chance to bump connectionTimeout to symmetricConnectionTimeout.
        // Otherwise the timer can tick between here and the branch, racing connectionTimeout
        // to 0 if either was somehow ≤ 1 — and in any case, enabling early just shortens
        // the effective timeout by however long branch setup takes.

        // Store peer's mesh IP
        if (!string.IsNullOrEmpty(peerMeshIPString))
        {
            peerMeshIP = IPAddress.Parse(peerMeshIPString);
        }

        // Parse endpoint — handles IPv4, [IPv6]:port, and v4-mapped forms
        if (EndpointUtils.TryParseEndpoint(endpointString, out var parsedTargetEp))
        {
            targetPeerIp = parsedTargetEp.Address;
            targetPeerPort = parsedTargetEp.Port;
        }

        // Set our own NAT type (first time only)
        if (natType == NATType.Unknown)
        {
            natType = ownNatType;
        }

        // Choose hole-punch strategy based on NAT type combination
        if (natType == NATType.Symmetric)
        {
            // We're symmetric: create 256 UDP probe clients and send from all of them
            // Extend timeout — symmetric NAT needs more time for random port scanning
            connectionTimeout = symmetricConnectionTimeout;
            Program.Log(LogLevel.Debug, $"[Symmetric NAT] Setting up 256 probe clients (InjectConnectionBegin)");

            connectionAttempt = new Timer(1000) { AutoReset = true, Enabled = false };
            connectionAttempt.Elapsed += (source, e) =>
            {
                if (Volatile.Read(ref disposed) != 0) return;
                // Branch on whether a probe has WON, not on holePunchReceivedCount. Once a probe
                // wins, its socket (now `udpClient`) holds the NAT mapping the peer is replying to
                // — we must keep sending from THAT socket to keep the mapping fresh so the peer's
                // subsequent packets keep landing on it. If we instead kept spraying all 256 (the
                // old `count < THRESHOLD` branch, which stays true after a single-packet win),
                // the winning mapping goes stale on a per-flow-port-rewriting NAT/firewall and the
                // peer's replies stop arriving — exactly one packet gets through, then silence.
                // (This is invisible on many v4 NATs but fatal on symmetric IPv6 firewalls.)
                MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                // Don't set ConnectionID — introducer-relayed tunnels use mismatched IDs
                // (each side hashes the remote peer's ID). Source IP filtering is sufficient.
                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                if (Volatile.Read(ref probeConnected) == 0)
                {
                    // No winner yet — spray from all probes to find a path through.
                    foreach (System.Net.Sockets.UdpClient probe in symmetricConnectionUdpProbes)
                    {
                        probe.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                }
                else
                {
                    // A probe won — keep punching from ONLY the winning socket (udpClient) to keep
                    // its mapping alive and drive the peer's state machine until it also flips.
                    // No `!connected` gate: even after we flip connected locally, the peer may not
                    // have received our packets yet and still needs us to keep sending.
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                }
            };

            while (symmetricConnectionUdpProbes.Count < 256)
            {
                // Dual-stack like the main socket — v6 peers still need the firewall punched
                // even though there's no NAT to traverse.
                System.Net.Sockets.UdpClient tempUdpClient = SocketUtils.CreateUdpClient();
                var capturedProbe = tempUdpClient;
                // The initial receive is one-shot: BeginReceive fires its callback exactly once.
                // A probe whose FIRST datagram isn't from the target (stray/duplicate/noise) would
                // otherwise go deaf and could never catch the peer's real reply — and with a
                // symmetric NAT only one specific probe's external port receives that reply, so a
                // single deaf probe can lose the whole connection. Re-arm on every non-winning
                // packet so no probe stops listening until one actually wins.
                AsyncCallback probeCallback = null;
                void ArmProbe()
                {
                    try { capturedProbe.BeginReceive(probeCallback, null); }
                    catch { /* socket disposed/torn down — stop re-arming */ }
                }
                probeCallback = new AsyncCallback((IAsyncResult res) =>
                {
                    bool won = false;
                    try
                    {
                        if (Volatile.Read(ref disposed) != 0) return;
                        IPEndPoint receivedEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
                        byte[] receivedBuffer = capturedProbe.EndReceive(res, ref receivedEndpoint);
                        holePunchReceivedCount++;

                        // The probe socket is dual-stack, so a v4 sender arrives as a v4-mapped
                        // address (::ffff:a.b.c.d) that won't .Equals a plain-v4 targetPeerIp —
                        // normalize both sides before comparing so the winning probe is recognized.
                        if (EndpointUtils.Normalize(receivedEndpoint.Address).Equals(EndpointUtils.Normalize(targetPeerIp)) &&
                            Interlocked.CompareExchange(ref probeConnected, 1, 0) == 0)
                        {
                            won = true;
                            Program.Log(LogLevel.Info, $"[Symmetric NAT] Connection established on probe port {((IPEndPoint)capturedProbe.Client.LocalEndPoint).Port}");

                            // Mesh mode: DON'T replace the shared udpClient or cancel shared tokens.
                            // Instead, switch this tunnel to use the winning probe for sends,
                            // and start a private receive loop that feeds into ProcessUdpPacketBody.
                            udpClient = capturedProbe;

                            // Adopt the winning probe's remote port as this tunnel's target port.
                            // For a symmetric peer the port it actually punched from differs from
                            // the one mediation advertised (targetPeerPort). All subsequent traffic
                            // arrives from this winning port, and the post-connection envelope gates
                            // (0x01/0x02/0x20) require listenEndpoint.Port == targetPeerPort — so
                            // without this, mesh-control/data packets on the established flow would
                            // be dropped as port-mismatched even though the tunnel is up. (Data may
                            // have flowed pre-connection under the relaxed !connected gate; mesh
                            // control that starts after connection is what breaks — the introducer
                            // heartbeat acks never arrive and the introducer looks dead.)
                            targetPeerPort = EndpointUtils.Normalize(receivedEndpoint).Port;

                            // Process the packet that triggered the winning probe immediately.
                            // Without this, the first packet (e.g. WG key exchange from the
                            // non-symmetric peer) would be consumed by EndReceive but never
                            // run through ProcessUdpPacketBody, causing a deadlock where both
                            // sides stop sending and the symmetric side never completes
                            // connection establishment.
                            totalBytesReceived += receivedBuffer.Length;
                            UpdateActivity();
                            // Normalize the v4-mapped source before dispatching so downstream
                            // endpoint comparisons match plain-v4 expectations.
                            ProcessUdpPacketBody(receivedBuffer, EndpointUtils.Normalize(receivedEndpoint));

                            // Start a receive loop on the winning probe socket for this tunnel only.
                            // Stored as a field so Dispose can cancel and await it instead of
                            // letting it run until the next packet receive throws.
                            winningProbeCts = new CancellationTokenSource();
                            var capturedCts = winningProbeCts;
                            winningProbeTask = Task.Run(() =>
                            {
                                IPEndPoint probeEp = new IPEndPoint(IPAddress.IPv6Any, 0);
                                while (!capturedCts.Token.IsCancellationRequested)
                                {
                                    try
                                    {
                                        byte[] data = capturedProbe.Receive(ref probeEp);
                                        if (Volatile.Read(ref disposed) != 0) break;
                                        totalBytesReceived += data.Length;
                                        UpdateActivity();
                                        ProcessUdpPacketBody(data, EndpointUtils.Normalize(probeEp));
                                    }
                                    catch (SocketException) { break; }
                                    catch (ObjectDisposedException) { break; }
                                }
                            });
                        }
                    }
                    catch { }
                    finally
                    {
                        // If this packet didn't win (and we're still trying), re-arm so the probe
                        // keeps listening for the peer's reply instead of going deaf after one
                        // stray datagram. The winning probe doesn't re-arm here — it hands off to
                        // its dedicated winningProbeTask receive loop above.
                        if (!won && Volatile.Read(ref disposed) == 0 && Volatile.Read(ref probeConnected) == 0)
                            ArmProbe();
                    }
                });
                ArmProbe();
                symmetricConnectionUdpProbes.Add(tempUdpClient);
            }

            connectionAttempt.Enabled = true;
        }
        else if (peerNatType == NATType.Symmetric)
        {
            // Peer is symmetric: send to random ports to try to hit the peer's allocated port
            // Extend timeout — symmetric NAT needs more time for random port scanning
            connectionTimeout = symmetricConnectionTimeout;
            Program.Log(LogLevel.Debug, $"[Tunnel] Peer is symmetric — using random port spray (InjectConnectionBegin)");

            connectionAttempt = new Timer(1000) { AutoReset = true, Enabled = true };
            connectionAttempt.Elapsed += (source, e) =>
            {
                if (Volatile.Read(ref disposed) != 0) return;
                if (holePunchReceivedCount >= 1 && holePunchReceivedCount < HOLE_PUNCH_THRESHOLD)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                    // Don't set ConnectionID — source IP filtering handles cross-talk prevention
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                }

                if (holePunchReceivedCount < HOLE_PUNCH_THRESHOLD)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                    // Don't set ConnectionID — source IP filtering handles cross-talk prevention
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    Random randPort = new Random();
                    for (int i = 0; i < 100; i++)
                    {
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, randPort.Next(1024, 65536)));
                    }
                }
                else if (!connected || wireguardTunnel == null)
                {
                    // Threshold reached. Keep sending to the symmetric peer's confirmed endpoint so
                    // its winning probe keeps receiving packets and can climb to its OWN threshold.
                    // The `|| wireguardTunnel == null` (embedded) is critical: we may flip connected
                    // after just 1-2 received packets, but the symmetric peer needs ~3 to flip too.
                    // If we stop the instant WE connect, the symmetric side stalls at count=1 and
                    // never establishes — a deadlock where we think we're done and it's starved.
                    // (WG mode stops at connected because WG's own keepalives take over the flow.)
                    MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                }
            };
        }
        else
        {
            // Both non-symmetric: standard hole punch.
            // In embedded mode we keep punching after the threshold is reached so the peer's
            // restricted/port-restricted NAT sees our source and opens its inbound mapping —
            // otherwise whichever side receives the first punch flips to connected, stops
            // sending, and the other side never gets a packet through.
            connectionAttempt = new Timer(1000) { AutoReset = true, Enabled = true };
            int postThresholdTicks = 0;
            connectionAttempt.Elapsed += (source, e) =>
            {
                if (Volatile.Read(ref disposed) != 0) return;

                // Keep punching while we haven't hit our own receive threshold. CRUCIAL: even AFTER
                // reaching threshold, keep sending for a bounded window. A NAT can report
                // "DirectMapping" (port mapping is consistent to the two mediation test servers) yet
                // still be ADDRESS-RESTRICTED on inbound — it only accepts packets from an address it
                // has itself SENT to. Keep firing until both sides are above the threshold
                bool belowThreshold = holePunchReceivedCount < HOLE_PUNCH_THRESHOLD;
                if (!belowThreshold) postThresholdTicks++;
                const int PostThresholdPunchTicks = 8; // ~8s of extra punching to open a restricted peer's filter
                bool keepPunching = belowThreshold || !connected || postThresholdTicks <= PostThresholdPunchTicks;
                if (keepPunching)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.HolePunchAttempt);
                    // Don't set ConnectionID — introducer-relayed tunnels use mismatched IDs
                    // (each side hashes the remote peer's ID). Source IP filtering is sufficient.
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                }
            };
        }

        // Now that connectionTimeout reflects the chosen strategy's full budget, start counting.
        initialConnectionTimer.Enabled = true;
    }

    /// <summary>
    /// Process a single UDP packet from the shared socket (called by external dispatcher).
    /// Each packet is delivered to ALL tunnels. WireGuard packets and hole-punch messages
    /// are processed by every tunnel that matches; WireGuardPublicKeyExchange is filtered
    /// by mesh IP content so only the correct tunnel acts on it.
    /// </summary>
    public void ProcessUdpPacket(byte[] receiveBuffer, IPEndPoint listenEndpoint)
    {
        // Track activity
        totalBytesReceived += receiveBuffer.Length;
        UpdateActivity();

        ProcessUdpPacketBody(receiveBuffer, listenEndpoint);
    }

    private void UdpClientListenLoop(CancellationToken token)
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

            // Track activity
            totalBytesReceived += receiveBuffer.Length;
            UpdateActivity();

            // Dual-stack sockets report IPv4 senders as ::ffff:a.b.c.d — unwrap so the
            // endpoint comparisons downstream match plain-v4 expected endpoints.
            ProcessUdpPacketBody(receiveBuffer, EndpointUtils.Normalize(listenEndpoint));
        }

    }

    private void ProcessUdpPacketBody(byte[] receiveBuffer, IPEndPoint listenEndpoint)
    {
        // Daemon (WG) mode — bytes 1-4 are WireGuard message types; route to WG proxy.
        if (wireguardTunnel != null && receiveBuffer.Length > 0 &&
            receiveBuffer[0] != (byte)'{' && receiveBuffer[0] != (byte)'[' &&
            receiveBuffer[0] >= 1 && receiveBuffer[0] <= 4)
        {
            var proxy = wireguardTunnel.GetUdpProxy();
            if (proxy != null) proxy.ForwardToWireGuard(receiveBuffer, listenEndpoint);
            return;
        }

        // Embedded mode — route designated marker bytes to DataPacketReceived. 0x01 is the
        // encrypted data envelope; 0x10 is the Noise handshake envelope; 0x11 is the cleartext
        // cipher-negotiation hello (sent before Noise); 0x30-0x33 are the application signaling
        // envelopes (identity / unreliable / reliable / reliable-ack); 0x40 is the data-fragment
        // envelope used when MeshConfig.AutoFragment is enabled. All must come from our target
        // peer; pre-connection packets are dropped silently to avoid acting on a racing peer's
        // early traffic.
        if (wireguardTunnel == null && receiveBuffer.Length > 0 &&
            (receiveBuffer[0] == 0x01 || receiveBuffer[0] == 0x10 || receiveBuffer[0] == 0x11 ||
             receiveBuffer[0] == 0x30 || receiveBuffer[0] == 0x31 ||
             receiveBuffer[0] == 0x32 || receiveBuffer[0] == 0x33 ||
             receiveBuffer[0] == 0x40))
        {
            // Port-match tightens the IP filter so multiple tunnels pointed at the same NAT
            // (same public IP, different ports) don't send a packet to all of them. Relaxed
            // for symmetric remotes pre-connection: their port may switch mid-handshake and
            // the port-learning code at the top of ProcessUdpPacketBody needs to see those
            // packets to update targetPeerPort.
            bool portOk = listenEndpoint.Port == targetPeerPort
                          || (!connected && (natType == NATType.Symmetric || remoteNatType == NATType.Symmetric));
            if (targetPeerIp != null && Equals(listenEndpoint.Address, targetPeerIp) && portOk)
            {
                DataPacketReceived?.Invoke(receiveBuffer);
            }
            return;
        }

        // Embedded mode — 0x02 is the relay envelope. The packet was sent to us because we're
        // hosting a relay route for the destination peer in the envelope. Raise a separate
        // event so the host (EmbeddedMeshHost) can peel the envelope and forward verbatim.
        // We still gate on targetPeerIp matching the source — this filters out cross-talk.
        if (wireguardTunnel == null && receiveBuffer.Length > 0 && receiveBuffer[0] == 0x02)
        {
            // see comment at first portOk
            bool portOk = listenEndpoint.Port == targetPeerPort
                          || (!connected && (natType == NATType.Symmetric || remoteNatType == NATType.Symmetric));
            if (targetPeerIp != null && Equals(listenEndpoint.Address, targetPeerIp) && portOk)
            {
                RelayEnvelopeReceived?.Invoke(receiveBuffer);
            }
            return;
        }

        // Embedded mode — 0x20 is the mesh-control envelope. Routes through DataPacketReceived
        // alongside 0x01/0x10 so MeshPeerProxy's OnTunnelPacket switch dispatches it
        // (HandleMeshControlMessage decrypts and reinjects into MeshProtocolEngine).
        if (wireguardTunnel == null && receiveBuffer.Length > 0 && receiveBuffer[0] == 0x20)
        {
            // see comment at first portOk
            bool portOk = listenEndpoint.Port == targetPeerPort
                          || (!connected && (natType == NATType.Symmetric || remoteNatType == NATType.Symmetric));
            if (targetPeerIp != null && Equals(listenEndpoint.Address, targetPeerIp) && portOk)
            {
                DataPacketReceived?.Invoke(receiveBuffer);
            }
            return;
        }

        string receivedString = Encoding.ASCII.GetString(receiveBuffer);

        MediationMessage receivedMessage;

        try
        {
            receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
        }
        catch
        {
            return;
        }

        // Filter by ConnectionID: if the message carries a non-zero ConnectionID that doesn't
        // match this tunnel's currentConnectionID, it belongs to a different tunnel — skip it.
        // This prevents cross-talk when multiple tunnels share the same UDP socket (mesh mode).
        if (receivedMessage.ConnectionID != 0 && currentConnectionID != 0 && receivedMessage.ConnectionID != currentConnectionID)
        {
            return;
        }

        // Symmetric-NAT port switching: when the remote peer is behind a symmetric NAT, the
        // port we initially learned from mediation may differ from the one it actually uses
        // when it punches out. Update once we see traffic from a matching IP on a new port.
        //
        // Only do this for symmetric remotes — for non-symmetric peers the port is final and
        // overwriting it would let another peer behind the same NAT (same IP, different port)
        // steal this tunnel's target. Also gated on !connected so the port can't change after
        // handshake completes.
        if (!connected && natType == NATType.Symmetric &&
            Equals(listenEndpoint.Address, targetPeerIp) && listenEndpoint.Port != targetPeerPort)
        {
            targetPeerPort = listenEndpoint.Port;
        }

        // Match by IP, and also by port when known — needed to disambiguate peers
        // behind the same NAT (same public IP, different external ports).
        // Before connection: accept any port from the target IP (port may not be known yet).
        // After connection: lock to the established port to prevent cross-talk.
        if (Equals(listenEndpoint.Address, targetPeerIp) &&
            (targetPeerPort == 0 || !connected || listenEndpoint.Port == targetPeerPort))
        {
            if (holePunchReceivedCount >= HOLE_PUNCH_THRESHOLD && !connected)
            {
                connected = true;
                initialConnectionTimer.Enabled = false;
                // WG mode: disable hole-punch timer now; WG key exchange takes over.
                // Embedded mode: keep the timer running so the symmetric peer continues
                // sending hole-punches from the winning probe to the non-symmetric peer
                // until the non-symmetric peer also flips to connected. Otherwise only
                // a single hole-punch was sent (from one of 256 probes) and the peer
                // likely missed it. The timer is stopped explicitly by the embedded
                // layer once Noise XX completes end-to-end via StopHolePunching().
                if (wireguardTunnel != null)
                {
                    connectionAttempt.Enabled = false;
                }
                Program.Log(LogLevel.Info, "[Mesh] Connection established - hole punching successful!");

                // Embedded mode (no WG): hole-punch success IS the connection-complete signal.
                // WG mode defers this until after the public-key exchange below.
                if (wireguardTunnel == null)
                {
                    ConnectionEstablished?.Invoke();
                    onConnectionComplete?.Invoke();
                }

                // Send WireGuard public key to peer immediately
                if (wireguardTunnel != null && !wgKeySent)
                {
                    wgKeySent = true;
                    try
                    {
                        string configPath = wireguardTunnel.GetConfigPath();
                        string wgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);

                        MediationMessage wgMessage = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                        wgMessage.WireGuardPublicKey = wgPublicKey;
                        wgMessage.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(wgPublicKey));

                        // Include our mesh IP
                        if (ownMeshIP != null)
                        {
                            wgMessage.SetPrivateAddress(ownMeshIP);
                        }

                        byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(wgMessage.Serialize());
                        udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                    catch (Exception wgEx)
                    {
                        Program.Log(LogLevel.Error, $"[Mesh] Error sending WireGuard public key: {wgEx.Message}");
                    }
                }
            }
        }

        Program.Log(LogLevel.Debug, $"{receivedMessage.ID}: Received from {listenEndpoint.Address}:{listenEndpoint.Port}, targetPeerIp={targetPeerIp}, targetPeerPort={targetPeerPort}");
        switch (receivedMessage.ID)
        {
            case MediationMessageType.HolePunchAttempt:
                {
                    // In mesh mode with shared socket, only process if from our target peer.
                    // Without this, hole punch packets from OTHER peers would inflate our holePunchReceivedCount.
                    // Check both IP and port (when known) to disambiguate same-NAT peers.
                    if (targetPeerIp != null &&
                        (!Equals(listenEndpoint.Address, targetPeerIp) ||
                         (targetPeerPort != 0 && listenEndpoint.Port != targetPeerPort)))
                        break;
                    holePunchReceivedCount++;
                    connectionTimeout = maxConnectionTimeout;
                    try
                    {
                        privateIP = receivedMessage.GetPrivateAddress();
                    }
                    catch (Exception e)
                    {
                        Program.Log(e.ToString());
                    }
                }
                break;
            case MediationMessageType.KeepAlive:
                break;
            case MediationMessageType.WireGuardPublicKeyExchange:
                {
                    // Only process if this message is meant for THIS tunnel.
                    // All mesh tunnels share the same UDP socket, so we must filter.
                    //
                    // Filter by the mesh IP inside the message.
                    // Each tunnel knows its peerMeshIP and the message carries the sender's
                    // mesh IP in PrivateAddressString. This works even when multiple peers
                    // share the same public IP (Symmetric NAT) and ports change.
                    if (peerMeshIP != null && !string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                    {
                        var senderMeshIP = receivedMessage.GetPrivateAddress();
                        if (senderMeshIP != null && !senderMeshIP.Equals(peerMeshIP))
                            return; // Not our peer
                    }
                    else if (targetPeerIp != null && !Equals(listenEndpoint.Address, targetPeerIp))
                    {
                        return; // Wrong source IP
                    }

                    // Message contains peer's mesh IP — store it if we don't have it yet
                    if (receivedMessage.PrivateAddressString != null && !string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                    {
                        var receivedIP = receivedMessage.GetPrivateAddress();

                        if (peerMeshIP == null && receivedIP != null)
                        {
                            peerMeshIP = receivedIP;
                        }
                    }

                    if (receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))
                    {
                        var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                        var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);

                        if (hashMatches)
                        {
                            // Store peer's WireGuard public key by adding it as a peer
                            if (wireguardTunnel != null && targetPeerIp != null && targetPeerPort != 0)
                            {
                                bool peerAddedSuccessfully = false;
                                try
                                {
                                    var peerEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);
                                    IPAddress peerTunnelIp;
                                    if (peerMeshIP != null)
                                    {
                                        // Use peer's mesh IP from ConnectionBegin
                                        peerTunnelIp = peerMeshIP;
                                    }
                                    else if (!string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                                    {
                                        peerTunnelIp = IPAddress.Parse(receivedMessage.PrivateAddressString);
                                    }
                                    else
                                    {
                                        Program.Log(LogLevel.Error, $"[WG] Cannot determine peer tunnel IP");
                                        break;
                                    }

                                    // Refuse to add a peer whose key matches our own — wg.exe silently
                                    // no-ops in that case, leaving the interface peerless and every send broken.
                                    string ourWgKey = WireGuardConfig.GetPublicKeyFromConfig(wireguardTunnel.GetConfigPath());
                                    if (receivedMessage.WireGuardPublicKey == ourWgKey)
                                    {
                                        Program.Log($"[WG] Refusing to add peer with our own public key ({ourWgKey[..8]}...). " +
                                                    "Likely cause: both peers share the same keys file. Delete the *_keys.txt on one peer to regenerate.");
                                        break;
                                    }

                                    Program.Log(LogLevel.Debug, $"[WG] Adding peer: key={receivedMessage.WireGuardPublicKey.Substring(0, 8)}... ip={peerTunnelIp} endpoint={peerEndpoint}");
                                    // Add peer with their public key and tunnel IP
                                    // Pass our tunnel socket for proxy routing
                                    var serverPeer = wireguardTunnel.AddPeer(receivedMessage.WireGuardPublicKey, peerEndpoint, peerTunnelIp, true, udpClient);
                                    peerAddedSuccessfully = true;
                                    ConnectionEstablished?.Invoke();
                                    onConnectionComplete?.Invoke();

                                    // Send OUR WireGuard public key back so the peer can add us too.
                                    // Without this, the key exchange is one-directional: the peer
                                    // adds us but we never send our key, so we're missing on their side.
                                    // Only send if we haven't already sent (prevents infinite ping-pong).
                                    if (!wgKeySent)
                                    {
                                        wgKeySent = true;
                                        try
                                        {
                                            string configPath = wireguardTunnel.GetConfigPath();
                                            string ourWgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);

                                            var replyMsg = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                                            replyMsg.WireGuardPublicKey = ourWgPublicKey;
                                            replyMsg.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(ourWgPublicKey));

                                            // Include our mesh IP so peer knows our tunnel address
                                            if (ownMeshIP != null)
                                                replyMsg.SetPrivateAddress(ownMeshIP);
                                            else if (privateIP != null)
                                                replyMsg.SetPrivateAddress(privateIP);

                                            byte[] replyBuffer = Encoding.ASCII.GetBytes(replyMsg.Serialize());
                                            udpClient.Send(replyBuffer, replyBuffer.Length, peerEndpoint);
                                            Program.Log(LogLevel.Debug, $"[WG] Sent our public key back to {peerEndpoint}");
                                        }
                                        catch (Exception replyEx)
                                        {
                                            Program.Log(LogLevel.Error, $"[WG] Error sending our public key reply: {replyEx.Message}");
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Program.Log(LogLevel.Error, $"Error adding peer: {ex.Message}");
                                }

                                if (peerAddedSuccessfully)
                                {
                                    // Mark connection as complete
                                    connected = true;
                                    retryAttempt = 0;  // Reset for future connections
                                    initialConnectionTimer.Enabled = false;
                                    connectionAttempt.Enabled = false;
                                    Program.Log(LogLevel.Info, "Connection established successfully!");
                                }
                            }
                            else
                            {
                                Program.Log(LogLevel.Error, $"Cannot add peer: missing tunnel or endpoint information");
                            }
                        }
                        else
                        {
                            Program.Log(LogLevel.Error, $"WireGuard public key hash validation FAILED");
                        }
                    }
                    else
                    {
                        Program.Log(LogLevel.Debug, $"Peer's WireGuard public key is null or empty");
                    }
                }
                break;
            case MediationMessageType.NATTunnelData:
                break;
            case MediationMessageType.SymmetricHolePunchAttempt:
                {
                    // In mesh mode with shared socket, only process if from our target peer.
                    // Without this, symmetric hole punch packets from OTHER peers would corrupt
                    // this tunnel's targetPeerIp/Port (line below overwrites them with the source).
                    // Check IP always; check port too unless the remote is symmetric pre-connection
                    // (their actual outbound port differs from the mediation-reported one and the
                    // whole point of this handler is to learn it).
                    bool symmetricLearning = !connected && remoteNatType == NATType.Symmetric;
                    if (targetPeerIp != null &&
                        (!Equals(listenEndpoint.Address, targetPeerIp) ||
                         (!symmetricLearning && targetPeerPort != 0 && listenEndpoint.Port != targetPeerPort)))
                        break;
                    holePunchReceivedCount++;
                    connectionTimeout = maxConnectionTimeout;
                    try
                    {
                        var parsedPrivateIP = receivedMessage.GetPrivateAddress();
                        if (parsedPrivateIP != null)
                        {
                            privateIP = parsedPrivateIP;
                        }
                    }
                    catch (Exception e)
                    {
                        Program.Log(e.ToString());
                    }
                    if (natType != NATType.Symmetric)
                    {
                        targetPeerIp = listenEndpoint.Address;
                        targetPeerPort = listenEndpoint.Port;
                    }
                }
                break;
        }
    }

    /// <summary>
    /// Send a raw data packet to this tunnel's peer over the established UDP connection.
    /// Used in embedded mode where the host wants to push arbitrary payloads through the
    /// NAT-traversed channel rather than route them via WireGuard.
    /// </summary>
    public void SendDataPacket(byte[] data)
    {
        if (!connected || targetPeerIp == null || targetPeerPort == 0)
            throw new InvalidOperationException("Tunnel is not connected yet.");
        udpClient.Send(data, data.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
    }

    /// <summary>
    /// Embedded-mode signal that the upper layer (MeshPeerProxy) is confident the peer is
    /// fully reachable bidirectionally (e.g. its Noise handshake completed). Lets us stop
    /// the per-second SymmetricHolePunchAttempt timer that was kept running post-hole-punch
    /// to ensure the non-symmetric side received at least one of our 256 probes' packets.
    /// Once Noise handshake completes, the peer has clearly received our packets — no need
    /// to keep hammering it with hole-punches.
    /// </summary>
    public void StopHolePunching()
    {
        if (connectionAttempt != null) connectionAttempt.Enabled = false;
    }

    /// <summary>
    /// Gets the time since last activity on this tunnel
    /// </summary>
    public TimeSpan GetTimeSinceLastActivity()
    {
        return DateTime.UtcNow - lastActivityTime;
    }

    /// <summary>
    /// Gets whether this tunnel is considered active (received/sent data recently)
    /// </summary>
    public bool IsActive(TimeSpan inactivityThreshold)
    {
        return GetTimeSinceLastActivity() < inactivityThreshold;
    }

    /// <summary>
    /// Updates the last activity timestamp (called when data is received/sent)
    /// </summary>
    private void UpdateActivity()
    {
        lastActivityTime = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the connection ID for this tunnel
    /// </summary>
    public int GetConnectionID()
    {
        return currentConnectionID;
    }

    /// <summary>
    /// Gets activity statistics for this tunnel
    /// </summary>
    public (long BytesReceived, long BytesSent, DateTime LastActivity) GetActivityStats()
    {
        return (totalBytesReceived, totalBytesSent, lastActivityTime);
    }

    /// <summary>
    /// Notify tunnel that connection is complete (called by mesh mode when it receives ConnectionComplete)
    /// Only marks as connected if hole punching has already succeeded for THIS tunnel.
    /// Otherwise the broadcast from another tunnel's completion would prevent this tunnel
    /// from ever sending its WireGuard key exchange.
    /// </summary>
    public void NotifyConnectionComplete()
    {
        if (holePunchReceivedCount >= HOLE_PUNCH_THRESHOLD)
        {
            connected = true;
            initialConnectionTimer.Enabled = false;
            retryAttempt = 0;  // Reset retry counter on successful connection
        }
    }

    /// <summary>
    /// Disposes of tunnel resources properly
    /// </summary>
    public void Dispose()
    {
        // Atomic single-shot guard: subsequent Dispose calls become no-ops. Critical because
        // the timer Elapsed handlers and BeginReceive callbacks now check this flag to bail
        // before doing socket I/O — we need the flip to be observable to all of them BEFORE
        // we start closing sockets out from under them.
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;

        try
        {
            // Cancel all running tasks
            udpClientTaskCancellationToken?.Cancel();
            winningProbeCts?.Cancel();

            // Stop timers
            initialConnectionTimer?.Stop();
            initialConnectionTimer?.Dispose();
            connectionAttempt?.Stop();
            connectionAttempt?.Dispose();

            // Close UDP client only if we own it (not shared)
            if (ownsUdpClient)
            {
                udpClient?.Close();
                udpClient?.Dispose();
            }

            // Dispose symmetric NAT probe sockets
            foreach (var probe in symmetricConnectionUdpProbes)
            {
                probe?.Close();
                probe?.Dispose();
            }
            symmetricConnectionUdpProbes.Clear();

            // Briefly await the winning-probe receive loop so its thread is actually gone before
            // we return. Socket close above will already have broken it out of Receive() with
            // ObjectDisposedException; this just confirms it exited rather than letting it
            // straggle a few milliseconds after Dispose.
            try { winningProbeTask?.Wait(TimeSpan.FromMilliseconds(250)); } catch { }
            winningProbeCts?.Dispose();

            // Dispose crypto resources
            shaHashGen?.Dispose();

        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[Tunnel] Error during disposal: {ex.Message}");
        }
    }

    /// <summary>
    /// Detects the local LAN IP address by connecting a UDP socket to a public address.
    /// The OS selects the appropriate local interface without actually sending any data.
    /// Filters out VPN/tunnel-adapter addresses which use a /32 host route.
    /// </summary>
    public static IPAddress GetLanIPAddress()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530);
            var candidate = (socket.LocalEndPoint as IPEndPoint)?.Address;
            if (candidate == null) return null;
            if (IsTunnelAdapterAddress(candidate)) return null;
            return candidate;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// True if this machine has a globally-routable IPv6 source address for reaching the public
    /// internet. Used to gate the IPv6 NAT test: a machine with only a link-local/ULA/site-local
    /// v6 address (common — Windows assigns link-local to every interface) has no usable v6 path
    /// to peers, so it must NOT advertise a v6 endpoint. The connect() picks the source address
    /// the OS would actually use for a public v6 destination without sending anything; if there's
    /// no route, it throws and we return false.
    /// </summary>
    public static bool HasGlobalIPv6() => GetGlobalIPv6Candidate() != null;

    /// <summary>
    /// Returns the native global-unicast IPv6 source address the OS would use to reach the public
    /// internet, or null if none qualifies. Exposed (vs a bare bool) so callers can log exactly
    /// which address was chosen/rejected when diagnosing v6 reachability.
    /// </summary>
    public static IPAddress GetGlobalIPv6Candidate()
    {
        if (!Socket.OSSupportsIPv6) return null;
        try
        {
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, 0);
            socket.Connect("2606:4700:4700::1111", 65530); // Cloudflare public DNS (v6)
            var candidate = (socket.LocalEndPoint as IPEndPoint)?.Address;
            return IsNativeGlobalIPv6(candidate) ? candidate : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// True only for a NATIVE global-unicast IPv6 address that is actually reachable peer-to-peer.
    /// Rejects link-local/ULA/site-local AND the pseudo-global tunnel/transition ranges (Teredo,
    /// 6to4, ISATAP-style, documentation) that present as global unicast but are NOT reliably
    /// reachable inbound from other peers — advertising one of those makes a peer look v6-reachable
    /// when it isn't, so a v4-only partner gets handed an unusable v6 endpoint.
    /// </summary>
    private static bool IsNativeGlobalIPv6(IPAddress candidate)
    {
        if (candidate == null || candidate.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (candidate.IsIPv6LinkLocal || candidate.IsIPv6SiteLocal || candidate.IsIPv6UniqueLocal ||
            candidate.IsIPv6Multicast || IPAddress.IsLoopback(candidate)) return false;

        byte[] b = candidate.GetAddressBytes();
        // Global unicast is 2000::/3 — the top 3 bits are 001, i.e. first byte 0x20–0x3F.
        if ((b[0] & 0xE0) != 0x20) return false;

        // Teredo: 2001:0000::/32 (first two bytes 0x2001, next two 0x0000).
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return false;
        // 6to4: 2002::/16.
        if (b[0] == 0x20 && b[1] == 0x02) return false;
        // Documentation prefix 2001:db8::/32 — never real.
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false;

        // A native global address on a virtual tunnel adapter is still not a real peer path.
        if (IsTunnelAdapterAddress(candidate)) return false;
        return true;
    }

    /// <summary>
    /// Returns true if the given IP belongs to a network interface with a host-route netmask
    /// (/32 for IPv4, /128 for IPv6), which is how virtual tunnel adapters configure themselves.
    /// </summary>
    private static bool IsTunnelAdapterAddress(IPAddress ip)
    {
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (!ip.Equals(ua.Address)) continue;
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                        // Prefix length is NOT a reliable tunnel-adapter signal for IPv6: a /128 is
                        // perfectly normal for a real global address (SLAAC/DHCPv6 on Windows hands
                        // out /128 routinely). The caller (HasGlobalIPv6) already rejects
                        // link-local/ULA/site-local and has proven a working route via connect(),
                        // so a genuine global-unicast v6 address here is legitimate — not a tunnel.
                        return false;
                    // A /32 mask is 255.255.255.255 — convert PrefixLength to be robust across
                    // platforms that may not populate IPv4Mask reliably (Windows does, Linux mostly does).
                    if (ua.PrefixLength == 32) return true;
                    // Some platforms report the mask but not PrefixLength; check both.
                    var mask = ua.IPv4Mask;
                    if (mask != null && mask.Equals(IPAddress.Parse("255.255.255.255"))) return true;
                    return false;
                }
            }
        }
        catch { /* fall through — treat as non-tunnel on enumeration error */ }
        return false;
    }
}
