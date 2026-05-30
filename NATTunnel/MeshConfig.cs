using System;

namespace NATTunnel;

/// <summary>
/// Configuration for a <see cref="MeshNode"/>. Construct an instance, set the required
/// fields (<see cref="NetworkID"/>, <see cref="NetworkSecret"/>, <see cref="MediationEndpoint"/>,
/// <see cref="HostGamePort"/>), tweak the optional fields as needed, then pass to the
/// <see cref="MeshNode(MeshConfig)"/> constructor.
///
/// All fields are read once at <see cref="MeshNode.Start"/> time; changing them after Start
/// has no effect on the running node.
/// </summary>
public class MeshConfig
{
    // ── Required ──

    /// <summary>The mesh network identifier. Peers with the same NetworkID + NetworkSecret join the same mesh.</summary>
    public string NetworkID { get; set; }

    /// <summary>The shared secret authenticating membership in the mesh.</summary>
    public string NetworkSecret { get; set; }

    /// <summary>
    /// Mediation server endpoint as "host:port". Host may be a DNS name or IPv4 address.
    /// Example: "mediation.example.com:6510".
    /// </summary>
    public string MediationEndpoint { get; set; }

    /// <summary>
    /// Local UDP port the host app has bound to receive decrypted packets from connected peers.
    /// Each peer's <see cref="MeshNode.ConnectedPeer.LoopbackEndpoint"/> sends to this port when
    /// it receives data from that peer.
    /// </summary>
    public int HostGamePort { get; set; }

    // ── Optional ──

    /// <summary>
    /// Stable peer identity across process restarts. Null (the default) generates a fresh
    /// GUID each session — fine for ephemeral lobbies but means peers can't recognize each
    /// other across reconnects. Set this to your game's account ID for persistent identity.
    /// </summary>
    public Guid? PersistentPeerID { get; set; }

    /// <summary>
    /// Stable Curve25519 static private key (32 bytes) across process restarts. Null (the
    /// default) generates a fresh keypair each session. Pair with <see cref="PersistentPeerID"/>
    /// for full identity persistence — peers' Noise handshakes will use this for authentication.
    /// Store in your host app's secure storage; treat as a secret.
    /// </summary>
    public byte[] PersistentStaticPrivateKey { get; set; }

    /// <summary>
    /// Whether this node is willing to act as a relay for other symmetric-NAT pairs. True by
    /// default. Set false on bandwidth-constrained nodes (mobile, metered connections) so the
    /// introducer's relay picker prefers other candidates.
    /// </summary>
    public bool AllowRelayThrough { get; set; } = true;

    /// <summary>
    /// Operator hint about this node's relay capacity. Influences how the introducer's relay
    /// picker weights this node relative to others. <see cref="RelayCapacity.Normal"/> by default.
    /// </summary>
    public RelayCapacity OwnRelayCapacity { get; set; } = RelayCapacity.Normal;

    /// <summary>
    /// How often this node sends heartbeats to the introducer (and the introducer sends to peers).
    /// 5s default for embedded mode (game-like latency-sensitive use cases). Combined with
    /// <see cref="DeadPeerThreshold"/> this controls peer-down detection time:
    /// <c>HeartbeatInterval × DeadPeerThreshold</c> seconds before a hard-killed peer is declared
    /// dead and <see cref="MeshNode.PeerDisconnected"/> fires. Lower = faster detection at the
    /// cost of more traffic.
    /// </summary>
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Number of consecutive missed heartbeat acks before a peer is declared dead.
    /// 3 by default — combined with the 5s default <see cref="HeartbeatInterval"/> this gives
    /// ~15s detection latency for a hard-killed peer. Graceful disconnects (via Dispose) are
    /// detected almost immediately via the MeshPeerLeave message.
    /// </summary>
    public int DeadPeerThreshold { get; set; } = 3;

    /// <summary>
    /// Inclusive start of the loopback port range the library allocates from when binding a
    /// proxy socket per peer. Default 50100. Avoid overlapping with ports the host app uses
    /// for its own sockets (incl. <see cref="HostGamePort"/>).
    /// </summary>
    public int LoopbackPortRangeStart { get; set; } = 50100;

    /// <summary>Inclusive end of the loopback port range. Default 65535.</summary>
    public int LoopbackPortRangeEnd { get; set; } = 65535;

    /// <summary>
    /// Optional logger callback that receives both the severity and the message. Preferred
    /// over <see cref="Logger"/> because the host can route by level. Null (the default)
    /// falls through to <see cref="Logger"/>; if both are null, the library prints to
    /// <see cref="Console.WriteLine"/>.
    /// </summary>
    public Action<LogLevel, string> LeveledLogger { get; set; }

    /// <summary>
    /// Optional plain-string logger callback. Receives one line of engine output per call
    /// (timestamp / level tag / message; the caller decides routing). Kept for
    /// callers that don't want to deal with the level enum. Use <see cref="LeveledLogger"/>
    /// for structured filtering.
    /// </summary>
    public Action<string> Logger { get; set; }

    /// <summary>
    /// Minimum severity the library emits. Anything below this is dropped before reaching
    /// the configured logger callback. Default is <see cref="LogLevel.Info"/> — major
    /// lifecycle events plus warnings and errors. Set to <see cref="LogLevel.Debug"/> for
    /// verbose protocol traces, or <see cref="LogLevel.Warning"/> / <see cref="LogLevel.Error"/>
    /// to make the library silent on the happy path.
    /// </summary>
    public LogLevel MinLogLevel { get; set; } = LogLevel.Info;

    /// <summary>
    /// Maximum payload size (bytes) for <see cref="LocalIdentity"/> and for messages
    /// passed to <see cref="MeshNode.SendMessageAsync"/> / <see cref="MeshNode.BroadcastAsync"/>.
    /// Keeping it small ensures each message fits in a single Noise-encrypted UDP datagram.
    /// </summary>
    public const int MaxIdentitySize = 256;
    public const int MaxMessageSize = 4096;

    /// <summary>
    /// Optional application-level identity blob exchanged automatically with every peer as
    /// part of the post-handshake setup. Up to <see cref="MaxIdentitySize"/> bytes; null is
    /// equivalent to an empty payload. The remote peer's blob is available as
    /// <see cref="MeshPeer.Identity"/> by the time <see cref="MeshNode.PeerConnected"/>
    /// fires — use it to communicate role/identity (e.g. "I'm the game server, port 8080")
    /// before any application-layer connection is established.
    ///
    /// Set once at <see cref="MeshNode"/> construction; mutating after construction has no
    /// effect on already-connected peers. For ongoing message passing use
    /// <see cref="MeshNode.SendMessageAsync"/> instead.
    /// </summary>
    public byte[] LocalIdentity { get; set; }

    /// <summary>
    /// Timeout for reliable sends via <see cref="MeshNode.SendMessageAsync"/>. If no ack
    /// arrives within this window the awaiting Task throws <see cref="TimeoutException"/>.
    /// Default 5 seconds.
    /// </summary>
    public TimeSpan ReliableMessageTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Generate a fresh random <see cref="NetworkID"/>. Format: "net-" followed by 8 lowercase
    /// hex chars (4 bytes of CSPRNG output). Use this when seeding a config file the first time.
    /// </summary>
    public static string GenerateNetworkID()
    {
        byte[] bytes = new byte[4];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return "net-" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Generate a fresh random <see cref="NetworkSecret"/>. 32 bytes of CSPRNG output, base64-encoded.
    /// Pair with <see cref="GenerateNetworkID"/> on first launch.
    /// </summary>
    public static string GenerateNetworkSecret()
    {
        byte[] bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    internal void Validate()
    {
        if (string.IsNullOrEmpty(NetworkID)) throw new ArgumentException("MeshConfig.NetworkID is required.");
        if (string.IsNullOrEmpty(NetworkSecret)) throw new ArgumentException("MeshConfig.NetworkSecret is required.");
        if (string.IsNullOrEmpty(MediationEndpoint)) throw new ArgumentException("MeshConfig.MediationEndpoint is required.");
        if (HostGamePort <= 0 || HostGamePort > 65535) throw new ArgumentException("MeshConfig.HostGamePort must be a valid UDP port.");
        if (PersistentStaticPrivateKey != null && PersistentStaticPrivateKey.Length != 32)
            throw new ArgumentException("MeshConfig.PersistentStaticPrivateKey must be 32 bytes (Curve25519 private key).");
        if (HeartbeatInterval <= TimeSpan.Zero) throw new ArgumentException("MeshConfig.HeartbeatInterval must be positive.");
        if (DeadPeerThreshold < 1) throw new ArgumentException("MeshConfig.DeadPeerThreshold must be at least 1.");
        if (LoopbackPortRangeStart < 1 || LoopbackPortRangeStart > 65535)
            throw new ArgumentException("MeshConfig.LoopbackPortRangeStart out of range.");
        if (LoopbackPortRangeEnd < LoopbackPortRangeStart || LoopbackPortRangeEnd > 65535)
            throw new ArgumentException("MeshConfig.LoopbackPortRangeEnd must be >= LoopbackPortRangeStart and <= 65535.");
        if (LocalIdentity != null && LocalIdentity.Length > MaxIdentitySize)
            throw new ArgumentException($"MeshConfig.LocalIdentity must be at most {MaxIdentitySize} bytes (got {LocalIdentity.Length}).");
        if (ReliableMessageTimeout <= TimeSpan.Zero)
            throw new ArgumentException("MeshConfig.ReliableMessageTimeout must be positive.");
    }
}
