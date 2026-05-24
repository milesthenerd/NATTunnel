using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NATTunnel.Embedded;
using Noise;

namespace NATTunnel;

/// <summary>
/// Public-facing entry point for the embedded mesh library. Games and other host applications
/// construct a <see cref="MeshNode"/>, call <see cref="Start"/>, and treat each connected peer
/// as a normal UDP endpoint via <see cref="MeshPeer.LoopbackEndpoint"/>. Encryption,
/// hole-punching, introducer election, and relay forwarding are handled transparently.
///
/// Behind the scenes this drives <see cref="MeshProtocolEngine"/> (the same protocol code the
/// CLI daemon uses) via an <see cref="EmbeddedMeshHost"/> + <see cref="EmbeddedContext"/>.
///
/// Transport is end-to-end encrypted: Noise XX handshake on first contact, then
/// ChaCha20-Poly1305 per-packet thereafter (see <see cref="NoiseUdpTransport"/>).
/// </summary>
public class MeshNode : IDisposable
{
    private readonly MeshConfig config;
    private readonly string mediationHost;
    private readonly int mediationPort;

    private readonly Guid peerID;
    private readonly KeyPair staticKeyPair;

    private MeshProtocolEngine engine;
    private EmbeddedMeshHost host;
    private EmbeddedContext context;
    private UdpClient udpClient;
    private Task runTask;
    private int nextLoopbackPort;

    // Established peers, keyed by remote peer GUID. Maintained by the TunnelCreated handler.
    private readonly ConcurrentDictionary<string, MeshPeer> connectedPeers = new();

    public Guid OwnPeerID => peerID;

    /// <summary>
    /// Snapshot of the currently-connected peers. Safe to enumerate from any thread — returns
    /// a stable array taken at call time. Mutations (peer joins/leaves) won't reflect in a
    /// previously-obtained snapshot.
    /// </summary>
    public IReadOnlyCollection<MeshPeer> Peers
    {
        get
        {
            // Snapshot via .Values.ToArray() is atomic-enough — ConcurrentDictionary's Values
            // accessor synchronizes internally. The returned array is a stable view.
            return connectedPeers.Values.ToArray();
        }
    }

    /// <summary>Raised once a peer's Noise handshake completes — the loopback endpoint is now safe to send to.</summary>
    public event Action<MeshPeer> PeerConnected;

    /// <summary>
    /// Raised when a peer is declared dead (heartbeat misses) or leaves the mesh gracefully.
    /// The <see cref="MeshPeer.LoopbackEndpoint"/> stops working after this event; sends to it
    /// are silently dropped. Host should not retain references to the MeshPeer after disconnect —
    /// the same peer reconnecting gets a fresh MeshPeer + new loopback endpoint.
    /// </summary>
    public event Action<MeshPeer> PeerDisconnected;

    /// <summary>
    /// Construct a mesh node from a <see cref="MeshConfig"/>. Validates the config eagerly;
    /// throws <see cref="ArgumentException"/> if a required field is missing or malformed.
    /// </summary>
    public MeshNode(MeshConfig config)
    {
        if (config == null) throw new ArgumentNullException(nameof(config));
        config.Validate();
        this.config = config;

        // Split "host:port" into its components — mediation handshake DNS-resolves and connects.
        int colon = config.MediationEndpoint.LastIndexOf(':');
        if (colon < 0) throw new ArgumentException("MeshConfig.MediationEndpoint must be 'host:port'.");
        this.mediationHost = config.MediationEndpoint.Substring(0, colon);
        if (!int.TryParse(config.MediationEndpoint.Substring(colon + 1), out this.mediationPort) ||
            this.mediationPort <= 0 || this.mediationPort > 65535)
        {
            throw new ArgumentException("MeshConfig.MediationEndpoint port is not a valid integer.");
        }

        // Identity: persistent PeerID if supplied, otherwise fresh per session.
        this.peerID = config.PersistentPeerID ?? Guid.NewGuid();
        // Persistent static keypair: not yet supported (Noise.NET 1.0 doesn't expose a way to
        // construct a KeyPair from a raw private key, and rolling our own X25519 public-derive
        // is non-trivial without BCL Curve25519 exposed). Tracked for a future polish pass.
        if (config.PersistentStaticPrivateKey != null)
        {
            throw new NotSupportedException(
                "MeshConfig.PersistentStaticPrivateKey is reserved for a future release. " +
                "Leave it null to generate a fresh Noise static keypair each session.");
        }
        this.staticKeyPair = KeyPair.Generate();

        this.nextLoopbackPort = config.LoopbackPortRangeStart;
    }

    public void Start()
    {
        // Resolve the mediation hostname to an IP for the MeshOptions snapshot. MeshProtocolEngine expects
        // an IPEndPoint, so we do the DNS resolution here once.
        var mediationIP = Dns.GetHostAddresses(mediationHost)[0];

        // Embedded mode picks a random local UDP port for the mesh-control channel to avoid
        // colliding with a daemon on 51888 or another embedded process on the same machine.
        int meshControlPort = PickRandomFreeUdpPort();

        var options = new MeshOptions
        {
            MediationEndpoint = new IPEndPoint(mediationIP, mediationPort),
            NetworkID = config.NetworkID,
            NetworkSecret = config.NetworkSecret,
            TlsEnabled = true,
            TlsAllowSelfSigned = true,
            AutoConnect = true,
            MeshSubnet = "10.5",
            HeartbeatIntervalSeconds = (int)config.HeartbeatInterval.TotalSeconds,
            ProbeIntervalSeconds = 10,
            DeadThreshold = 5,
            RepairCooldownSeconds = 15,
            GracePeriodSecondsNonSymmetric = 30,
            GracePeriodSecondsSymmetric = 5,
            StaleTimeoutSeconds = 10,
            IsolationGracePeriodSeconds = 30,
            MaxRepairAttempts = 3,
            AllowRelayThrough = config.AllowRelayThrough,
            OwnRelayCapacity = config.OwnRelayCapacity,
            RelayReselectCooldownSeconds = 30,
            RelayLoadFactorMs = 50,
            RelayReselectMinImprovement = 0.30,
            RelayHealthTimeoutSeconds = 45,
            MeshControlPort = meshControlPort,
        };

        context = new EmbeddedContext(options, config.Logger);
        host = new EmbeddedMeshHost();
        host.TunnelCreated += OnTunnelCreated;
        host.RelayedPeerAdded += OnRelayedPeerAdded;
        host.PeerRemoved += OnPeerRemoved;

        // Open the shared UDP socket the protocol uses for hole-punching + NAT detection.
        udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        udpClient.Client.ReceiveBufferSize = 128_000;
        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            const int SIO_UDP_CONNRESET = -1744830452;
            udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }

        // Pick a mesh IP from the configured subnet using the hash-based scheme the daemon uses.
        // SHA256(peerID) → first two bytes form .X.Y in 10.5.X.Y. Collisions are resolved
        // server-side during MeshJoinRequest.
        var hash = System.Security.Cryptography.SHA256.HashData(peerID.ToByteArray());
        string meshIP = $"{options.MeshSubnet}.{hash[0]}.{hash[1]}";

        // Seed the host's OwnMeshIP eagerly. MeshProtocolEngine only calls SetClientIPAndRestart on
        // collision-reassignment, so without this the host wouldn't know its own mesh IP
        // and OnRelayedPeerAdded would refuse to build relayed proxies for lack of a src
        // identity for the 0x02 envelope. A later collision-reassignment overwrites it.
        host.SetClientIPAndRestart(meshIP);

        // Drive MeshProtocolEngine.Run on a background task. Run blocks until ShutdownRequested.
        engine = new MeshProtocolEngine();
        runTask = Task.Run(() =>
        {
            try
            {
                engine.Run(host, context, meshIP, udpClient, udpProxy: null, peerID);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Embedded] MeshProtocolEngine.Run crashed: {ex.Message}\n{ex.StackTrace}");
            }
        });
    }

    /// <summary>
    /// Fired by EmbeddedMeshHost when MeshProtocolEngine creates a Tunnel for a freshly-discovered peer.
    /// Constructs the MeshPeerProxy (loopback socket + Noise handshake state) and registers it
    /// with the host so subsequent peer lookups find it. Also wires the tunnel's relay-envelope
    /// event so this node can act as a relay for other pairs that route through us.
    /// </summary>
    private void OnTunnelCreated(Tunnel tunnel, string remotePeerID, string remoteMeshIP)
    {
        if (string.IsNullOrEmpty(remotePeerID))
        {
            // Reconnect-side tunnels without a known peer ID can't initiate Noise (no way to
            // decide initiator/responder). Skip — the protocol will eventually deliver a
            // proper tunnel with the peer ID once it learns it.
            return;
        }

        // Subscribe the tunnel's relay envelope event to the host so 0x02 packets received
        // on this tunnel get peeled + forwarded. This is what makes us act as a relay.
        tunnel.RelayEnvelopeReceived += host.ForwardRelayEnvelope;

        int loopbackPort = Interlocked.Increment(ref nextLoopbackPort) - 1;
        bool isInitiator = string.Compare(peerID.ToString(), remotePeerID, StringComparison.Ordinal) > 0;
        var proxy = new MeshPeerProxy(tunnel, loopbackPort, config.HostGamePort,
                                       staticKeyPair.PrivateKey, isInitiator, remotePeerID);

        var connected = new MeshPeer(remotePeerID, tunnel, proxy);
        connectedPeers[remotePeerID] = connected;
        proxy.HandshakeComplete += () =>
        {
            Console.WriteLine($"[Embedded] Peer ready: {remotePeerID} via {proxy.LoopbackEndpoint}");
            PeerConnected?.Invoke(connected);
        };

        IPAddress senderMeshIP = null;
        if (IPAddress.TryParse(remoteMeshIP, out var meshIpAddr))
        {
            senderMeshIP = meshIpAddr;
            host.RegisterProxy(meshIpAddr, proxy);
        }

        // Mesh-control packets arriving over this tunnel get fed back into MeshProtocolEngine's
        // mesh-control dispatcher with a synthesized remoteEndPoint so existing handlers
        // (which read .Address to identify the sender's mesh IP) keep working.
        proxy.MeshControlReceived += plaintext =>
        {
            var fakeEp = new IPEndPoint(senderMeshIP ?? IPAddress.Any, MeshProtocolEngine.MeshControlPort);
            engine?.ProcessMeshControlPacket(plaintext, fakeEp);
        };

        // Defer the Noise handshake until the tunnel finishes hole-punching. Starting earlier
        // would have the initiator's msg-1 throw because Tunnel.SendDataPacket guards on
        // `connected`. The responder side is unaffected (msg-1 is buffered until Start runs
        // via MeshPeerProxy.earlyHandshakePackets) but we may as well defer both for cleanliness.
        // If the tunnel is somehow already connected by the time we subscribe (race), the
        // event won't fire again — start the handshake immediately in that case.
        if (tunnel.connected)
        {
            proxy.Start();
        }
        else
        {
            tunnel.ConnectionEstablished += proxy.Start;
        }
    }

    /// <summary>
    /// Fired by EmbeddedMeshHost when MeshProtocolEngine establishes a relay route for a peer reachable
    /// only through a gateway. Construct a relayed MeshPeerProxy that:
    ///   - Uses the gateway's existing tunnel as its carrier (no new tunnel needed)
    ///   - Wraps outbound data with the 0x02 envelope so the gateway forwards it
    ///   - Decodes inbound from the gateway's tunnel as direct 0x01 (the gateway strips its envelope)
    /// </summary>
    private void OnRelayedPeerAdded(string remotePeerID, IPAddress remoteMeshIP, IPAddress gatewayMeshIP)
    {
        if (string.IsNullOrEmpty(remotePeerID)) return;
        // Idempotency: ignore if we already have a proxy for this peer.
        if (connectedPeers.ContainsKey(remotePeerID)) return;

        // The gateway's MeshPeerProxy already exists (direct hole-punched connection); we
        // borrow its tunnel as the carrier. If for some reason the gateway proxy isn't found,
        // bail — the relay route is incomplete.
        var gatewayProxy = host.GetProxyByMeshIP(gatewayMeshIP);
        if (gatewayProxy == null)
        {
            Console.Error.WriteLine($"[Embedded] Cannot build relayed proxy for {remotePeerID}: gateway {gatewayMeshIP} has no proxy yet");
            return;
        }

        // We need our own mesh IP to populate the envelope's src-IP field. The host learned
        // it earlier via SetClientIPAndRestart (called by MeshProtocolEngine after MeshJoinResponse).
        if (host.OwnMeshIP == null)
        {
            Console.WriteLine($"[Embedded] Cannot build relayed proxy for {remotePeerID}: own mesh IP not yet assigned");
            return;
        }

        int loopbackPort = Interlocked.Increment(ref nextLoopbackPort) - 1;
        bool isInitiator = string.Compare(peerID.ToString(), remotePeerID, StringComparison.Ordinal) > 0;
        var proxy = new MeshPeerProxy(
            gatewayProxy.Tunnel,
            loopbackPort, config.HostGamePort,
            staticKeyPair.PrivateKey, isInitiator,
            $"{remotePeerID}@relay",
            relayDestinationMeshIP: remoteMeshIP,
            ownMeshIP: host.OwnMeshIP);

        var connected = new MeshPeer(remotePeerID, gatewayProxy.Tunnel, proxy);
        connectedPeers[remotePeerID] = connected;
        proxy.HandshakeComplete += () =>
        {
            Console.WriteLine($"[Embedded] Relayed peer ready: {remotePeerID} via {proxy.LoopbackEndpoint} (gateway {gatewayMeshIP})");
            PeerConnected?.Invoke(connected);
        };

        // Register the relayed proxy under its mesh IP so cross-talk by inbound 0x01 finds the
        // right decryptor. (Direct proxies share the gateway's tunnel; multiple proxies
        // subscribe to DataPacketReceived and only one's Noise key matches.)
        host.RegisterProxy(remoteMeshIP, proxy);

        // Mesh-control packets arriving over this relayed proxy also feed back into MeshProtocolEngine.
        // remoteMeshIP is captured here so the dispatcher knows the sender's identity.
        var capturedRemoteMeshIP = remoteMeshIP;
        proxy.MeshControlReceived += plaintext =>
        {
            var fakeEp = new IPEndPoint(capturedRemoteMeshIP, MeshProtocolEngine.MeshControlPort);
            engine?.ProcessMeshControlPacket(plaintext, fakeEp);
        };

        // The gateway's tunnel is already connected (otherwise we wouldn't be relaying through it).
        // Start the Noise handshake immediately — it'll flow end-to-end through the gateway.
        proxy.Start();
    }

    /// <summary>
    /// Fired by EmbeddedMeshHost when a peer is removed (heartbeat-declared dead or graceful
    /// leave). Match the removed proxy reference to our connectedPeers entry, drop it, and
    /// raise <see cref="PeerDisconnected"/> for the host app.
    /// </summary>
    private void OnPeerRemoved(IPAddress meshIP, MeshPeerProxy removedProxy)
    {
        // connectedPeers is keyed by peer GUID, not mesh IP — scan for the entry whose proxy
        // matches the removed reference. N is small (single-digit peer counts typical).
        string foundKey = null;
        foreach (var kv in connectedPeers)
        {
            if (ReferenceEquals(kv.Value.Proxy, removedProxy)) { foundKey = kv.Key; break; }
        }
        if (foundKey != null && connectedPeers.TryRemove(foundKey, out var removed))
        {
            try { PeerDisconnected?.Invoke(removed); }
            catch (Exception ex) { Console.Error.WriteLine($"[Embedded] PeerDisconnected handler threw: {ex.Message}"); }
        }
    }

    private static int PickRandomFreeUdpPort()
    {
        // Bind a temporary UDP socket on port 0; OS assigns a free ephemeral port. Read it
        // back, close the socket, return the port to the caller. There's a brief race where
        // another process could claim the port between close and rebind, but for the embedded
        // POC it's good enough.
        using var probe = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        return ((IPEndPoint)probe.Client.LocalEndPoint).Port;
    }

    public void Dispose()
    {
        if (context != null) context.ShutdownRequested = true;
        try { runTask?.Wait(TimeSpan.FromSeconds(5)); } catch { }
        try { host?.Dispose(); } catch { }
        try { udpClient?.Dispose(); } catch { }
        try { staticKeyPair?.Dispose(); } catch { }
        foreach (var entry in connectedPeers.Values)
        {
            try { entry.Proxy.Dispose(); } catch { }
        }
        connectedPeers.Clear();
    }

    /// <summary>
    /// Public view of a connected peer. Stable for the lifetime of the connection — if the
    /// peer drops and reconnects, the host gets a fresh <see cref="MeshPeer"/> via a new
    /// <see cref="PeerConnected"/> event.
    ///
    /// The loopback endpoint is what the host app should send to / receive from in order to
    /// communicate with this peer. Transport encryption, hole-punching, and (where needed)
    /// relay forwarding are handled transparently.
    /// </summary>
    public sealed class MeshPeer
    {
        /// <summary>The remote peer's stable GUID identifier.</summary>
        public string PeerID { get; }

        /// <summary>
        /// The local loopback endpoint the host app uses to send/receive packets destined for
        /// this peer. Send to <c>LoopbackEndpoint</c> to message the peer; the library will
        /// encrypt and forward. Inbound packets from this peer arrive at the host's
        /// <see cref="MeshConfig.HostGamePort"/> with this endpoint as the apparent source.
        /// </summary>
        public IPEndPoint LoopbackEndpoint => Proxy.LoopbackEndpoint;

        // Internal handles. Not part of the public API — used by MeshNode for its own bookkeeping.
        internal Tunnel Tunnel { get; }
        internal MeshPeerProxy Proxy { get; }

        internal MeshPeer(string peerID, Tunnel tunnel, MeshPeerProxy proxy)
        {
            PeerID = peerID;
            Tunnel = tunnel;
            Proxy = proxy;
        }
    }
}
