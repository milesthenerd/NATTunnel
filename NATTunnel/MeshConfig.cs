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
    /// Optional logger callback. Receives one line of engine output per call (timestamp /
    /// category / message; the caller decides routing — Console, file, in-game console, etc.).
    /// Null (the default) routes to <see cref="Console.WriteLine"/>.
    /// </summary>
    public Action<string> Logger { get; set; }

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
    }
}
