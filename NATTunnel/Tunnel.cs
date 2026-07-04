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

        endpoint = TunnelOptions.MediationEndpoint;

        // Set mesh IP if provided
        if (ownMeshIP != null)
        {
            this.ownMeshIP = IPAddress.Parse(ownMeshIP);
            privateIP = this.ownMeshIP;
        }

        // Parse mesh peer endpoint if provided
        // Format is either "1.2.3.4:PORT" or "::ffff:1.2.3.4:PORT" (IPv6-mapped)
        if (meshPeerEndpoint != null)
        {
            int lastColon = meshPeerEndpoint.LastIndexOf(':');
            if (lastColon > 0 && int.TryParse(meshPeerEndpoint.Substring(lastColon + 1), out var peerPort))
            {
                string ipPart = meshPeerEndpoint.Substring(0, lastColon);
                // Strip IPv6-mapped IPv4 prefix (::ffff:)
                if (ipPart.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
                    ipPart = ipPart.Substring(7);
                if (IPAddress.TryParse(ipPart, out var peerIp))
                    this.meshPeerEndpoint = new IPEndPoint(peerIp, peerPort);
            }
        }

        // Use shared UDP client if provided, otherwise create a new one
        if (sharedUdpClient != null)
        {
            udpClient = sharedUdpClient;
            ownsUdpClient = false;
        }
        else
        {
            udpClient = new UdpClient();
            udpClient.Client.ReceiveBufferSize = 128000;

            // Explicitly bind to a random port (0 = OS assigns ephemeral port)
            // This ensures we have a local port before WireGuard configuration
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

            // Windows-specific udpClient switch
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // ReSharper disable once IdentifierTypo - taken from here:
                // https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_connreset-opcode-setting-i-t3
                const int SIO_UDP_CONNRESET = -1744830452;
                udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
            }
        }

        //Try to send initial msg to mediator
        try
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
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

                // Start cooldown before retry
                Program.Log(LogLevel.Warning, $"Connection attempt {retryAttempt + 1} failed. Waiting {retryCooldown}s before retry...");
                retryAttempt++;

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

        // Parse endpoint — handle both "1.2.3.4:PORT" and "::ffff:1.2.3.4:PORT" formats
        string parsedIpString = null;
        int parsedPort = 0;
        int lastColon = endpointString.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(endpointString.Substring(lastColon + 1), out parsedPort))
        {
            parsedIpString = endpointString.Substring(0, lastColon);
            // Strip IPv6-mapped IPv4 prefix (::ffff:)
            if (parsedIpString.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
                parsedIpString = parsedIpString.Substring(7);
            if (IPAddress.TryParse(parsedIpString, out var parsedIp))
            {
                targetPeerIp = parsedIp;
                targetPeerPort = parsedPort;
            }
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
                if (holePunchReceivedCount < HOLE_PUNCH_THRESHOLD)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                    // Don't set ConnectionID — introducer-relayed tunnels use mismatched IDs
                    // (each side hashes the remote peer's ID). Source IP filtering is sufficient.
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    foreach (System.Net.Sockets.UdpClient probe in symmetricConnectionUdpProbes)
                    {
                        probe.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                }
                else
                {
                    // Threshold reached locally — but the non-symmetric peer may not yet have
                    // received any of our packets (only one of 256 probes "won"). Keep sending
                    // hole-punches from the winning probe (udpClient) until peer 2 confirms by
                    // bouncing a packet back; otherwise both sides stall and peer 2 times out.
                    // No `!connected` gate: even after `connected=true` locally, we still need
                    // to drive peer 2's state machine until it also flips.
                    MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                }
            };

            while (symmetricConnectionUdpProbes.Count < 256)
            {
                System.Net.Sockets.UdpClient tempUdpClient = new System.Net.Sockets.UdpClient();
                tempUdpClient.Client.ReceiveBufferSize = 128000;
                const int SIO_UDP_CONNRESET = -1744830452;
                tempUdpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                tempUdpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
                var capturedProbe = tempUdpClient;
                tempUdpClient.BeginReceive(new AsyncCallback((IAsyncResult res) =>
                {
                    try
                    {
                        if (Volatile.Read(ref disposed) != 0) return;
                        IPEndPoint receivedEndpoint = new IPEndPoint(IPAddress.Any, 0);
                        byte[] receivedBuffer = capturedProbe.EndReceive(res, ref receivedEndpoint);
                        holePunchReceivedCount++;

                        if (receivedEndpoint.Address.Equals(targetPeerIp) && Interlocked.CompareExchange(ref probeConnected, 1, 0) == 0)
                        {
                            Program.Log(LogLevel.Info, $"[Symmetric NAT] Connection established on probe port {((IPEndPoint)capturedProbe.Client.LocalEndPoint).Port}");

                            // Mesh mode: DON'T replace the shared udpClient or cancel shared tokens.
                            // Instead, switch this tunnel to use the winning probe for sends,
                            // and start a private receive loop that feeds into ProcessUdpPacketBody.
                            udpClient = capturedProbe;

                            // Process the packet that triggered the winning probe immediately.
                            // Without this, the first packet (e.g. WG key exchange from the
                            // non-symmetric peer) would be consumed by EndReceive but never
                            // run through ProcessUdpPacketBody, causing a deadlock where both
                            // sides stop sending and the symmetric side never completes
                            // connection establishment.
                            totalBytesReceived += receivedBuffer.Length;
                            UpdateActivity();
                            ProcessUdpPacketBody(receivedBuffer, receivedEndpoint);

                            // Start a receive loop on the winning probe socket for this tunnel only.
                            // Stored as a field so Dispose can cancel and await it instead of
                            // letting it run until the next packet receive throws.
                            winningProbeCts = new CancellationTokenSource();
                            var capturedCts = winningProbeCts;
                            winningProbeTask = Task.Run(() =>
                            {
                                IPEndPoint probeEp = new IPEndPoint(IPAddress.Any, 0);
                                while (!capturedCts.Token.IsCancellationRequested)
                                {
                                    try
                                    {
                                        byte[] data = capturedProbe.Receive(ref probeEp);
                                        if (Volatile.Read(ref disposed) != 0) break;
                                        totalBytesReceived += data.Length;
                                        UpdateActivity();
                                        ProcessUdpPacketBody(data, probeEp);
                                    }
                                    catch (SocketException) { break; }
                                    catch (ObjectDisposedException) { break; }
                                }
                            });
                        }
                    }
                    catch { }
                }), null);
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
                else if (!connected)
                {
                    // Threshold reached but not fully connected yet — keep sending to the
                    // symmetric peer's confirmed endpoint so its winning probe receives
                    // packets and can complete connection establishment.
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
            connectionAttempt.Elapsed += (source, e) =>
            {
                if (Volatile.Read(ref disposed) != 0) return;
                bool keepPunching = holePunchReceivedCount < HOLE_PUNCH_THRESHOLD || wireguardTunnel == null;
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

            ProcessUdpPacketBody(receiveBuffer, listenEndpoint);
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
        // encrypted data envelope; 0x10 is the Noise handshake envelope; 0x30-0x33 are the
        // application signaling envelopes (identity / unreliable / reliable / reliable-ack);
        // 0x40 is the data-fragment envelope used when MeshConfig.AutoFragment is enabled.
        // All must come from our target peer; pre-connection packets are dropped silently to
        // avoid acting on a racing peer's early traffic.
        if (wireguardTunnel == null && receiveBuffer.Length > 0 &&
            (receiveBuffer[0] == 0x01 || receiveBuffer[0] == 0x10 ||
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
    /// Returns true if the given IP belongs to a network interface with a /32 (host-route)
    /// netmask, which is how virtual tunnel adapters configure themselves.
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
