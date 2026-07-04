using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
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
    private readonly byte[] staticPrivateKey;
    private readonly HashSet<string> blockedFingerprints;

    private MeshProtocolEngine engine;
    private EmbeddedMeshHost host;
    private EmbeddedContext context;
    private UdpClient udpClient;
    private Task runTask;
    private int nextLoopbackPort;
    // Monotonic counter for unique loopback IPs (127.x.y.z) when UseDistinctLoopbackIPs is true.
    // Starts at 1 → first IP is 127.0.1.1, then 127.0.1.2, … 127.0.255.255, 127.1.0.0, etc.
    // Wraps before reaching the loopback boundary (127.255.255.255 is reserved).
    private int nextLoopbackIPCounter;
    // 0 = alive, 1 = Dispose has started or completed. Atomic gate on Dispose() entry so a
    // racy double-Dispose doesn't tear the same resources twice, and so concurrent event
    // handlers (TunnelCreated, RelayedPeerAdded) can detect a disposed node and bail
    // before constructing a proxy that would leak.
    private int disposed;

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

    /// <summary>
    /// Look up a connected peer by its <see cref="MeshPeer.PeerID"/>. Returns false if no peer
    /// with that ID is currently connected (including: not yet handshaken, already disconnected,
    /// or never seen). O(1).
    /// </summary>
    public bool TryGetPeer(string peerID, out MeshPeer peer)
    {
        if (string.IsNullOrEmpty(peerID)) { peer = null; return false; }
        return connectedPeers.TryGetValue(peerID, out peer);
    }

    /// <summary>
    /// Look up a connected peer by its <see cref="MeshPeer.LoopbackEndpoint"/> — useful when the
    /// host transport surfaces a packet's apparent source endpoint
    /// and the host needs to map it back to a <see cref="MeshPeer"/>. O(n) over current peers.
    /// </summary>
    public bool TryGetPeerByLoopback(IPEndPoint loopbackEndpoint, out MeshPeer peer)
    {
        peer = null;
        if (loopbackEndpoint == null) return false;
        foreach (var p in connectedPeers.Values)
        {
            if (loopbackEndpoint.Equals(p.LoopbackEndpoint)) { peer = p; return true; }
        }
        return false;
    }

    /// <summary>
    /// Look up a connected peer by the IP portion of its <see cref="MeshPeer.LoopbackEndpoint"/>.
    /// Only meaningful when <see cref="MeshConfig.UseDistinctLoopbackIPs"/> is true — otherwise
    /// every peer shares 127.0.0.1 and this is ambiguous. Returns false if zero or more than one
    /// peer matches. O(n).
    /// </summary>
    public bool TryGetPeerByLoopbackIP(IPAddress loopbackIP, out MeshPeer peer)
    {
        peer = null;
        if (loopbackIP == null) return false;
        MeshPeer match = null;
        int count = 0;
        foreach (var p in connectedPeers.Values)
        {
            if (loopbackIP.Equals(p.LoopbackEndpoint.Address))
            {
                match = p;
                if (++count > 1) { peer = null; return false; }
            }
        }
        if (count == 1) { peer = match; return true; }
        return false;
    }

    /// <summary>
    /// The maximum payload size (bytes) the host app's transport should produce per UDP
    /// datagram for safe delivery across all reachable peers. Derived from
    /// <see cref="MeshConfig.PathMTU"/> minus the proxy's per-packet overhead
    /// (envelope byte + 8B counter + 16B AEAD tag = 25 bytes).
    ///
    /// Refer to this when configuring your transport to
    /// avoid producing datagrams that would be silently dropped on low-MTU paths like cellular
    /// or VPN-tunneled links. Ignore this value at your own risk if
    /// <see cref="MeshConfig.AutoFragment"/> is false.
    /// </summary>
    public int RecommendedHostMTU => config.PathMTU - 25;

    /// <summary>
    /// Raised once a peer's Noise handshake completes AND its application identity blob has been
    /// received — the loopback endpoint is safe to send to and <see cref="MeshPeer.Identity"/>
    /// reflects the remote peer's <see cref="MeshConfig.LocalIdentity"/>.
    /// </summary>
    public event Action<MeshPeer> PeerConnected;

    /// <summary>
    /// Raised when a peer is declared dead (heartbeat misses) or leaves the mesh gracefully.
    /// The <see cref="MeshPeer.LoopbackEndpoint"/> stops working after this event; sends to it
    /// are silently dropped. Host should not retain references to the MeshPeer after disconnect —
    /// the same peer reconnecting gets a fresh MeshPeer + new loopback endpoint.
    /// </summary>
    public event Action<MeshPeer> PeerDisconnected;

    /// <summary>
    /// Raised when an application message arrives from a peer (sent via
    /// <see cref="SendMessageAsync"/> or <see cref="BroadcastAsync"/> on the remote side).
    /// Fires for both reliable and unreliable sends — receivers can't distinguish, since the
    /// reliability is a sender-side concern. The payload buffer is owned by the callback;
    /// don't retain references past the handler return.
    /// </summary>
    public event Action<MeshPeer, byte[]> MessageReceived;

    /// <summary>
    /// Fires whenever a peer is blocked or unblocked via <see cref="BlockPeer"/>/<see cref="UnblockPeer"/>.
    /// Embedder subscribes to persist the updated <see cref="BlockedFingerprints"/> to storage.
    /// </summary>
    public event Action BlockListChanged;

    /// <summary>
    /// This node's own identity fingerprint (SHA-256 truncated to 8 bytes, hex, 16 chars).
    /// Users share this with peers who want to block them.
    /// </summary>
    public string Fingerprint => MeshProtocolEngine.ComputeFingerprint(
        MeshProtocolEngine.DeriveIdentityPublicKey(staticPrivateKey));

    /// <summary>
    /// Snapshot of the current block list. Iterate freely without locking.
    /// </summary>
    public IReadOnlyCollection<string> BlockedFingerprints
    {
        get { lock (blockedFingerprints) return blockedFingerprints.ToArray(); }
    }

    /// <summary>
    /// Add a peer fingerprint to the block list. Takes effect immediately — no reconnect required.
    /// Fires <see cref="BlockListChanged"/> after the update.
    /// </summary>
    public void BlockPeer(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return;
        string normalized = fingerprint.Trim().ToLowerInvariant();
        bool changed;
        lock (blockedFingerprints) changed = blockedFingerprints.Add(normalized);
        engine?.AddBlockedFingerprint(normalized);
        if (changed) try { BlockListChanged?.Invoke(); } catch { }
    }

    /// <summary>
    /// Remove a fingerprint from the block list. Fires <see cref="BlockListChanged"/> if it was present.
    /// </summary>
    public bool UnblockPeer(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return false;
        string normalized = fingerprint.Trim().ToLowerInvariant();
        bool removed;
        lock (blockedFingerprints) removed = blockedFingerprints.Remove(normalized);
        if (removed)
        {
            engine?.RemoveBlockedFingerprint(normalized);
            try { BlockListChanged?.Invoke(); } catch { }
        }
        return removed;
    }

    /// <summary>
    /// Compute the fingerprint (SHA-256(pubkey)[..8] hex) for a 32-byte Curve25519 public key.
    /// Useful for turning a peer's <see cref="MeshPeer.Identity"/> into a blockable string.
    /// </summary>
    public static string ComputeFingerprint(byte[] publicKey) =>
        MeshProtocolEngine.ComputeFingerprint(publicKey);

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
        // A bare "host" (no ':port') defaults to 6510 (the conventional mediation port).
        int colon = config.MediationEndpoint.LastIndexOf(':');
        if (colon < 0)
        {
            this.mediationHost = config.MediationEndpoint;
            this.mediationPort = 6510;
        }
        else
        {
            this.mediationHost = config.MediationEndpoint.Substring(0, colon);
            if (!int.TryParse(config.MediationEndpoint.Substring(colon + 1), out this.mediationPort) ||
                this.mediationPort <= 0 || this.mediationPort > 65535)
            {
                throw new ArgumentException("MeshConfig.MediationEndpoint port is not a valid integer.");
            }
        }

        // Identity: persistent PeerID if supplied, otherwise fresh per session.
        this.peerID = config.PersistentPeerID ?? Guid.NewGuid();
        if (config.PersistentStaticPrivateKey != null)
        {
            this.staticPrivateKey = (byte[])config.PersistentStaticPrivateKey.Clone();
        }
        else
        {
            using var kp = KeyPair.Generate();
            this.staticPrivateKey = (byte[])kp.PrivateKey.Clone();
        }

        this.blockedFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (config.PersistentBlockedFingerprints != null)
        {
            foreach (var fp in config.PersistentBlockedFingerprints)
                if (!string.IsNullOrWhiteSpace(fp))
                    this.blockedFingerprints.Add(fp.Trim().ToLowerInvariant());
        }

        this.nextLoopbackPort = config.LoopbackPortRangeStart;
    }

    public void Start()
    {
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(MeshNode));
        // Resolve the mediation hostname to an IP for the MeshOptions snapshot. MeshProtocolEngine expects
        // an IPEndPoint, so we do the DNS resolution here once. Force IPv4 — the shared UDP socket below
        // binds IPAddress.Any (IPv4), and Send() to a v6 endpoint throws WSAEAFNOSUPPORT.
        var mediationIP = Dns.GetHostAddresses(mediationHost)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
            ?? throw new InvalidOperationException(
                $"MeshConfig.MediationEndpoint '{mediationHost}' has no IPv4 address. " +
                "NATTunnel currently requires an IPv4-reachable mediation server.");

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
            DeadThreshold = config.DeadPeerThreshold,
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

        context = new EmbeddedContext(options, config.LeveledLogger, config.Logger, config.MinLogLevel);

        // Redirect any Program.Log calls from shared code (Tunnel, Symmetric NAT, etc.)
        // into the same level-filtered sink the engine uses. Without this, the daemon's
        // Console.WriteLine + rolling buffer would still fire from embedded mode and
        // spam the host's stdout. Cleared in Dispose so subsequent daemon usage (if
        // any) sees no leftover hook.
        Program.LogSink = (level, message) => context.Log(level, message);

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
                engine.Run(host, context, meshIP, udpClient, udpProxy: null, peerID, staticPrivateKey, blockedFingerprints);
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
        // Late-arriving events after Dispose has run would otherwise build a proxy that leaks
        // sockets and never gets cleaned up. Bail before allocating anything.
        if (Volatile.Read(ref disposed) != 0) return;
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

        bool isInitiator = string.Compare(peerID.ToString(), remotePeerID, StringComparison.Ordinal) > 0;
        var proxy = TryBuildProxyWithFreePort((ip, p) => new MeshPeerProxy(
            tunnel, p, config.HostGamePort,
            staticPrivateKey, isInitiator, remotePeerID,
            localIdentity: config.LocalIdentity,
            autoFragment: config.AutoFragment,
            PathMTU: config.PathMTU,
            fragmentReassemblyTimeout: config.FragmentReassemblyTimeout,
            loopbackIP: ip));
        if (proxy == null)
        {
            Console.Error.WriteLine($"[Embedded] Could not allocate a free loopback port for {remotePeerID} in range {config.LoopbackPortRangeStart}-{config.LoopbackPortRangeEnd}; dropping connection.");
            return;
        }

        var connected = new MeshPeer(remotePeerID, tunnel, proxy, isRelayed: false, publicEndpointOverride: null, remoteMeshIP: remoteMeshIP, engineFingerprintLookup: ip => engine?.GetPeerFingerprintByMeshIP(ip));
        connectedPeers[remotePeerID] = connected;
        WirePeerEvents(connected, proxy, remotePeerID, isRelayed: false, gatewayLabel: null);

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
    private void OnRelayedPeerAdded(string remotePeerID, IPAddress remoteMeshIP, IPAddress gatewayMeshIP, IPEndPoint remotePublicEndpoint)
    {
        if (Volatile.Read(ref disposed) != 0) return;
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

        bool isInitiator = string.Compare(peerID.ToString(), remotePeerID, StringComparison.Ordinal) > 0;
        var proxy = TryBuildProxyWithFreePort((ip, p) => new MeshPeerProxy(
            gatewayProxy.Tunnel,
            p, config.HostGamePort,
            staticPrivateKey, isInitiator,
            $"{remotePeerID}@relay",
            relayDestinationMeshIP: remoteMeshIP,
            ownMeshIP: host.OwnMeshIP,
            localIdentity: config.LocalIdentity,
            autoFragment: config.AutoFragment,
            PathMTU: config.PathMTU,
            fragmentReassemblyTimeout: config.FragmentReassemblyTimeout,
            loopbackIP: ip));
        if (proxy == null)
        {
            Console.Error.WriteLine($"[Embedded] Could not allocate a free loopback port for relayed {remotePeerID} in range {config.LoopbackPortRangeStart}-{config.LoopbackPortRangeEnd}; dropping relay route.");
            return;
        }

        var connected = new MeshPeer(remotePeerID, gatewayProxy.Tunnel, proxy, isRelayed: true, publicEndpointOverride: remotePublicEndpoint, remoteMeshIP: remoteMeshIP.ToString(), engineFingerprintLookup: ip => engine?.GetPeerFingerprintByMeshIP(ip));
        connectedPeers[remotePeerID] = connected;
        WirePeerEvents(connected, proxy, remotePeerID, isRelayed: true, gatewayLabel: gatewayMeshIP.ToString());

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
    /// Subscribe a freshly-built proxy's events to MeshNode-level handlers: PeerConnected fires
    /// only after BOTH handshake completion and identity arrival; MessageReceived bridges the
    /// proxy's app-message events; reliable-ack resolves the matching pending send.
    /// </summary>
    private void WirePeerEvents(MeshPeer connected, MeshPeerProxy proxy, string remotePeerID, bool isRelayed, string gatewayLabel)
    {
        // Identity-and-handshake gating: PeerConnected fires once both have arrived. Order is
        // not guaranteed — handshake-complete schedules the identity send, but identity packet
        // delivery is async and the handshake event may fire first on this side.
        int readinessFlags = 0; // bit 0 = handshake done, bit 1 = identity received
        void TryFire()
        {
            if (readinessFlags == 0b11)
            {
                if (isRelayed)
                    Console.WriteLine($"[Embedded] Relayed peer ready: {remotePeerID} via {proxy.LoopbackEndpoint} (gateway {gatewayLabel})");
                else
                    Console.WriteLine($"[Embedded] Peer ready: {remotePeerID} via {proxy.LoopbackEndpoint}");
                try { PeerConnected?.Invoke(connected); }
                catch (Exception ex) { Console.Error.WriteLine($"[Embedded] PeerConnected handler threw: {ex.Message}"); }
            }
        }

        // Interlocked.Or returns the PRE-OR value. We only want to fire on the transition that
        // sets the second bit — i.e. when the post-OR value is 0b11 but the pre-OR value wasn't.
        // Interlocked.Or returns the PRE-OR value. We only want to fire on the transition that
        // sets the second bit — i.e. when the post-OR value is 0b11 but the pre-OR value wasn't.
        proxy.HandshakeComplete += () =>
        {
            int prev = Interlocked.Or(ref readinessFlags, 0b01);
            if (prev != 0b11 && (prev | 0b01) == 0b11) TryFire();
        };
        proxy.HandshakeBroken += () =>
        {
            // Proxy gave up after too many undecryptable handshake packets — usually means the
            // remote reconnected with a fresh Noise key and our stale proxy was intercepting.
            // Drop the peer from our dictionary so MeshProtocolEngine's next reconnect attempt
            // builds a clean proxy.
            if (connectedPeers.TryRemove(remotePeerID, out var dropped) && readinessFlags == 0b11)
            {
                try { PeerDisconnected?.Invoke(dropped); }
                catch (Exception ex) { Console.Error.WriteLine($"[Embedded] PeerDisconnected handler threw: {ex.Message}"); }
            }
        };
        proxy.VersionRefused += (remoteMin, remoteMax) =>
        {
            // Record the peer as incompatible so MeshProtocolEngine's pre-flight paths
            // (ProcessDiscoveredPeers, ProcessMeshConnectionBegin, introducer-selection, etc.)
            // short-circuit future attempts against them until they advertise a new range.
            try { engine?.MarkPeerIncompatible(remotePeerID, remoteMin, remoteMax); } catch { }
        };
        proxy.IdentityReceived += identity =>
        {
            connected.Identity = identity ?? Array.Empty<byte>();
            int prev = Interlocked.Or(ref readinessFlags, 0b10);
            if (prev != 0b11 && (prev | 0b10) == 0b11) TryFire();
        };

        proxy.AppMessageReceived += payload =>
        {
            try { MessageReceived?.Invoke(connected, payload); }
            catch (Exception ex) { Console.Error.WriteLine($"[Embedded] MessageReceived handler threw: {ex.Message}"); }
        };
        proxy.AppReliableReceived += payload =>
        {
            try { MessageReceived?.Invoke(connected, payload); }
            catch (Exception ex) { Console.Error.WriteLine($"[Embedded] MessageReceived handler threw: {ex.Message}"); }
        };
        proxy.AppReliableAckReceived += seq =>
        {
            if (connected.PendingReliable.TryRemove(seq, out var tcs))
            {
                tcs.TrySetResult(true);
            }
        };
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

    /// <summary>
    /// Pre-flight probe: opens a transient TCP+TLS+UDP session to the mediation server, runs the
    /// NAT-type detection handshake, and returns the result without joining a network. Lets host
    /// apps preview the user's connectivity (e.g. warn about Symmetric NAT) before constructing
    /// a full <see cref="MeshNode"/>.
    ///
    /// All sockets opened by the probe are closed before the method returns. Safe to call
    /// multiple times. Throws <see cref="ArgumentException"/> for malformed endpoint syntax;
    /// other failures (DNS, TCP, TLS, UDP test timeout) populate
    /// <see cref="NetworkProbeResult.ErrorMessage"/> instead of throwing.
    /// </summary>
    /// <param name="mediationEndpoint">"host:port" string, matching <see cref="MeshConfig.MediationEndpoint"/>.</param>
    /// <param name="cancellationToken">Cancels the probe; the result's ErrorMessage will reflect cancellation.</param>
    public static async Task<NetworkProbeResult> ProbeNetworkAsync(
        string mediationEndpoint,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(mediationEndpoint))
            throw new ArgumentException("mediationEndpoint is required.", nameof(mediationEndpoint));

        // A bare "host" (no ':port') defaults to 6510, matching the MeshNode ctor's behavior.
        int colon = mediationEndpoint.LastIndexOf(':');
        string host;
        int port;
        if (colon < 0)
        {
            host = mediationEndpoint;
            port = 6510;
        }
        else
        {
            host = mediationEndpoint.Substring(0, colon);
            if (!int.TryParse(mediationEndpoint.Substring(colon + 1), out port) || port <= 0 || port > 65535)
                throw new ArgumentException("mediationEndpoint port must be a valid TCP port.", nameof(mediationEndpoint));
        }

        // Same IPv4-only resolve trick as Start() — the UDP socket below binds IPv4, so a v6
        // mediation endpoint would fail with WSAEAFNOSUPPORT on Send.
        IPAddress mediationIP;
        try
        {
            mediationIP = (await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false))
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        }
        catch (Exception ex)
        {
            return new NetworkProbeResult { NatType = NATType.Unknown, ErrorMessage = $"DNS resolution failed: {ex.Message}" };
        }
        if (mediationIP == null)
            return new NetworkProbeResult { NatType = NATType.Unknown, ErrorMessage = $"Mediation endpoint '{host}' has no IPv4 address." };

        var localIP = Tunnel.GetLanIPAddress();

        TcpClient tcp = null;
        SslStream tls = null;
        UdpClient udp = null;
        try
        {
            tcp = new TcpClient();
            // 5s TCP connect budget — mediation should respond promptly; longer waits suggest a routing problem.
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectCts.CancelAfter(TimeSpan.FromSeconds(5));
                await tcp.ConnectAsync(mediationIP, port, connectCts.Token).ConfigureAwait(false);
            }

            tls = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) => true);
            await tls.AuthenticateAsClientAsync(mediationIP.ToString()).ConfigureAwait(false);
            tls.ReadTimeout = 5000;

            udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            int localUdpPort = ((IPEndPoint)udp.Client.LocalEndPoint).Port;

            // Read first message ("Connected").
            string buffer = "";
            byte[] readBuf = new byte[4096];

            async Task<MediationMessage> ReadOneAsync()
            {
                while (true)
                {
                    var (m, rest) = TryExtractJson(buffer);
                    if (m != null) { buffer = rest; return m; }
                    int n = await tls.ReadAsync(readBuf.AsMemory(0, readBuf.Length), cancellationToken).ConfigureAwait(false);
                    if (n == 0) throw new IOException("Mediation server closed the connection.");
                    buffer += Encoding.ASCII.GetString(readBuf, 0, n);
                }
            }

            await ReadOneAsync().ConfigureAwait(false); // Connected

            // Send NATTypeRequest.
            var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
            {
                LocalPort = localUdpPort,
                LocalIP = localIP?.ToString(),
                ClientID = Guid.NewGuid()
            };
            byte[] natBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
            await tls.WriteAsync(natBytes.AsMemory(), cancellationToken).ConfigureAwait(false);

            var natTestBegin = await ReadOneAsync().ConfigureAwait(false);
            if (natTestBegin.ID == MediationMessageType.NATTestBegin)
            {
                var natTest = new MediationMessage(MediationMessageType.NATTest) { ClientID = natReq.ClientID };
                byte[] testBytes = Encoding.ASCII.GetBytes(natTest.Serialize());
                udp.Send(testBytes, testBytes.Length, new IPEndPoint(mediationIP, natTestBegin.NATTestPortOne));
                udp.Send(testBytes, testBytes.Length, new IPEndPoint(mediationIP, natTestBegin.NATTestPortTwo));
            }

            var natResp = await ReadOneAsync().ConfigureAwait(false);
            if (natResp.ID != MediationMessageType.NATTypeResponse)
                return new NetworkProbeResult
                {
                    MediationReachable = true,
                    NatType = NATType.Unknown,
                    LocalIP = localIP,
                    ErrorMessage = $"Mediation server returned unexpected message ID {(int)natResp.ID} instead of NATTypeResponse."
                };

            return new NetworkProbeResult
            {
                MediationReachable = true,
                NatType = natResp.NATType,
                LocalIP = localIP,
                LikelyNeedsRelay = natResp.NATType == NATType.Symmetric
            };
        }
        catch (OperationCanceledException)
        {
            return new NetworkProbeResult { NatType = NATType.Unknown, LocalIP = localIP, ErrorMessage = "Probe cancelled or timed out." };
        }
        catch (Exception ex)
        {
            return new NetworkProbeResult { NatType = NATType.Unknown, LocalIP = localIP, ErrorMessage = ex.Message };
        }
        finally
        {
            try { udp?.Dispose(); } catch { }
            try { tls?.Dispose(); } catch { }
            try { tcp?.Dispose(); } catch { }
        }
    }

    // Minimal JSON splitter mirroring MeshProtocolEngine.ExtractFirstJson — kept local so the
    // probe is self-contained and doesn't depend on the engine's internal helpers.
    private static (MediationMessage msg, string remainder) TryExtractJson(string data)
    {
        int start = data.IndexOf('{');
        if (start == -1) return (null, data);
        int braces = 0;
        for (int i = start; i < data.Length; i++)
        {
            if (data[i] == '{') braces++;
            else if (data[i] == '}')
            {
                braces--;
                if (braces == 0)
                {
                    string jsonObj = data.Substring(start, i - start + 1);
                    string rest = data.Substring(i + 1);
                    return (JsonSerializer.Deserialize<MediationMessage>(jsonObj), rest);
                }
            }
        }
        return (null, data);
    }

    /// <summary>
    /// Construct a <see cref="MeshPeerProxy"/> by walking the configured loopback port range
    /// until the bind succeeds. The proxy ctor binds the loopback socket eagerly, so a port
    /// conflict (another MeshNode in the same process, or another process on the machine using
    /// the same port) throws SocketException — we catch and try the next port.
    /// </summary>
    /// <returns>The constructed proxy, or null if no port in the range was free.</returns>
    private MeshPeerProxy TryBuildProxyWithFreePort(Func<IPAddress, int, MeshPeerProxy> factory)
    {
        int start = config.LoopbackPortRangeStart;
        int end = config.LoopbackPortRangeEnd;
        int rangeSize = end - start + 1;
        for (int i = 0; i < rangeSize; i++)
        {
            int candidate = Interlocked.Increment(ref nextLoopbackPort) - 1;
            if (candidate > end)
            {
                Interlocked.Exchange(ref nextLoopbackPort, start + 1);
                candidate = start;
            }
            IPAddress ip = config.UseDistinctLoopbackIPs ? AllocateLoopbackIP() : IPAddress.Loopback;
            try
            {
                return factory(ip, candidate);
            }
            catch (SocketException)
            {
                // Port (or ip:port) in use — try the next one.
            }
        }
        return null;
    }

    /// <summary>
    /// Allocate the next 127.x.y.z address. Starts at 127.0.1.1, walks up through 127.255.255.254,
    /// then wraps. Skips 127.0.0.0/24 to avoid 127.0.0.1 collisions with anything else the host
    /// has bound there.
    /// </summary>
    private IPAddress AllocateLoopbackIP()
    {
        // Total addressable space we're willing to use: 127.0.1.1 .. 127.255.255.254
        // That's (255*65536 + 65535 - 1) = ~16.7M slots, way more than any mesh will need.
        const uint baseOffset = 256; // skip 127.0.0.x entirely
        const uint maxOffset = 0x00FFFFFE; // 127.255.255.254
        uint n = (uint)Interlocked.Increment(ref nextLoopbackIPCounter);
        uint offset = baseOffset + (n - 1) % (maxOffset - baseOffset + 1);
        // Reconstruct 127.a.b.c
        byte a = (byte)((offset >> 16) & 0xFF);
        byte b = (byte)((offset >> 8) & 0xFF);
        byte c = (byte)(offset & 0xFF);
        return new IPAddress(new byte[] { 127, a, b, c });
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

    /// <summary>
    /// Send an application message to a single peer. With <paramref name="reliable"/> false
    /// the bytes go out via 0x31 — best-effort UDP, no ack, no retransmit, returns true as
    /// soon as the encryption succeeds. With reliable true the bytes go out via 0x32 with a
    /// sequence number, and the returned Task completes when the matching 0x33 ack arrives or
    /// throws <see cref="TimeoutException"/> after <see cref="MeshConfig.ReliableMessageTimeout"/>.
    /// </summary>
    public Task<bool> SendMessageAsync(MeshPeer peer, byte[] payload, bool reliable, CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(MeshNode));
        if (peer == null) throw new ArgumentNullException(nameof(peer));
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        if (payload.Length > MeshConfig.MaxMessageSize)
            throw new ArgumentException($"Message payload must be at most {MeshConfig.MaxMessageSize} bytes (got {payload.Length}).", nameof(payload));

        if (!reliable)
        {
            return Task.FromResult(peer.Proxy.SendAppUnreliable(payload));
        }
        return SendReliableInternalAsync(peer, payload, cancellationToken);
    }

    /// <summary>
    /// Broadcast an application message to every currently-connected peer. Snapshot at call
    /// time — late-joining peers don't receive this message. Returns when every per-peer send
    /// has resolved (or the overall token cancels).
    /// </summary>
    public Task BroadcastAsync(byte[] payload, bool reliable, CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(MeshNode));
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        var snapshot = connectedPeers.Values.ToArray();
        if (snapshot.Length == 0) return Task.CompletedTask;
        var sends = new Task[snapshot.Length];
        for (int i = 0; i < snapshot.Length; i++)
        {
            sends[i] = SendMessageAsync(snapshot[i], payload, reliable, cancellationToken);
        }
        return Task.WhenAll(sends);
    }

    private async Task<bool> SendReliableInternalAsync(MeshPeer peer, byte[] payload, CancellationToken cancellationToken)
    {
        uint seq = unchecked((uint)Interlocked.Increment(ref peer.ReliableSeqCounter));
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        peer.PendingReliable[seq] = tcs;

        try
        {
            if (!peer.Proxy.SendAppReliable(seq, payload))
            {
                peer.PendingReliable.TryRemove(seq, out _);
                return false;
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(config.ReliableMessageTimeout);

            using (timeoutCts.Token.Register(() =>
            {
                if (cancellationToken.IsCancellationRequested) tcs.TrySetCanceled(cancellationToken);
                else tcs.TrySetException(new TimeoutException($"Reliable send to {peer.PeerID} (seq {seq}) was not acked within {config.ReliableMessageTimeout.TotalSeconds}s."));
            }))
            {
                return await tcs.Task.ConfigureAwait(false);
            }
        }
        finally
        {
            peer.PendingReliable.TryRemove(seq, out _);
        }
    }

    public void Dispose()
    {
        // Atomic single-shot guard: only the first Dispose call runs the teardown. Subsequent
        // calls return immediately. Critical because the host app may race a Dispose with an
        // event-driven OnTunnelCreated and otherwise tear sockets twice.
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;

        // Set ShutdownRequested AND force-close the engine's owned client sockets so any
        // thread blocked on synchronous Receive/Write unblocks immediately.
        try { engine?.RequestShutdown(); } catch { }
        bool engineExited = false;
        try { engineExited = runTask?.Wait(TimeSpan.FromSeconds(5)) ?? true; } catch { }
        if (!engineExited)
        {
            // Engine didn't finish in 5s — log it instead of silently moving on, so a stuck
            // shutdown is visible.
            try { context?.Log(LogLevel.Warning, "[Embedded] Engine task did not exit within 5s of Dispose — background work may continue briefly."); }
            catch { }
        }

        // Snapshot+clear connectedPeers before disposing proxies so any late event delivery
        // sees an empty dictionary and bails. The disposed flag also gates OnTunnelCreated
        // and OnRelayedPeerAdded — that's the belt to this suspender.
        var peersSnapshot = connectedPeers.Values.ToArray();
        connectedPeers.Clear();
        foreach (var entry in peersSnapshot)
        {
            // Fault any in-flight reliable sends so awaiters don't hang until ReliableMessageTimeout.
            foreach (var pending in entry.PendingReliable.Values)
            {
                try { pending.TrySetException(new ObjectDisposedException(nameof(MeshNode))); }
                catch { }
            }
            entry.PendingReliable.Clear();
            try { entry.Proxy.Dispose(); } catch { }
        }

        try { host?.Dispose(); } catch { }
        try { udpClient?.Dispose(); } catch { }
        if (staticPrivateKey != null) Array.Clear(staticPrivateKey, 0, staticPrivateKey.Length);

        // Release the global Log sink we installed in the ctor so daemon usage in
        // the same process (rare but possible) doesn't keep routing into a torn-down
        // EmbeddedContext.
        Program.LogSink = null;
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

        /// <summary>
        /// The application-level identity blob the remote peer configured via
        /// <see cref="MeshConfig.LocalIdentity"/>. Always non-null by the time
        /// <see cref="MeshNode.PeerConnected"/> fires; may be zero-length if the peer didn't
        /// configure one. Use this to learn roles or other metadata about the peer before
        /// opening an application-layer connection (e.g. "I'm the game server, port 8080").
        /// </summary>
        public byte[] Identity { get; internal set; } = Array.Empty<byte>();

        /// <summary>
        /// The peer's blockable fingerprint — SHA-256(their Curve25519 identity pubkey) truncated
        /// to 8 bytes, hex-encoded, 16 characters. Pass to <see cref="MeshNode.BlockPeer"/> to
        /// block them. Null if we haven't received the peer's identity yet (rare — usually
        /// populated by the time <see cref="MeshNode.PeerConnected"/> fires, but the identity
        /// travels one-shot on UDP so it can arrive slightly later on lossy paths).
        /// </summary>
        public string Fingerprint => engineFingerprintLookup?.Invoke(remoteMeshIP);

        private readonly string remoteMeshIP;
        private readonly Func<string, string> engineFingerprintLookup;

        /// <summary>
        /// The remote peer's public (NAT-translated) IP and port.
        ///
        /// For relayed peers, this is the remote peer's public endpoint as reported by the
        /// introducer via mesh-control — not an endpoint we directly observed. May be null if
        /// the introducer didn't supply one.
        /// </summary>
        public IPEndPoint PublicEndpoint => IsRelayed ? relayedPublicEndpoint : Tunnel?.RemoteEndpoint;

        // Snapshotted introducer-supplied endpoint for relayed peers
        private readonly IPEndPoint relayedPublicEndpoint;

        /// <summary>
        /// True when this peer is reachable only via the introducer relay (typically because
        /// both sides are symmetric NAT and direct hole-punching failed).
        public bool IsRelayed { get; }

        // Internal handles. Not part of the public API — used by MeshNode for its own bookkeeping.
        internal Tunnel Tunnel { get; }
        internal MeshPeerProxy Proxy { get; }

        // Per-peer reliable-send state. Sequence numbers are allocated via Interlocked.Increment
        // on ReliableSeqCounter; the matching TaskCompletionSource is parked in PendingReliable
        // until the 0x33 ack arrives (or the timeout fires).
        internal int ReliableSeqCounter;
        internal readonly ConcurrentDictionary<uint, TaskCompletionSource<bool>> PendingReliable = new();

        internal MeshPeer(string peerID, Tunnel tunnel, MeshPeerProxy proxy, bool isRelayed, IPEndPoint publicEndpointOverride, string remoteMeshIP, Func<string, string> engineFingerprintLookup)
        {
            PeerID = peerID;
            Tunnel = tunnel;
            Proxy = proxy;
            IsRelayed = isRelayed;
            relayedPublicEndpoint = publicEndpointOverride;
            this.remoteMeshIP = remoteMeshIP;
            this.engineFingerprintLookup = engineFingerprintLookup;
        }
    }
}
