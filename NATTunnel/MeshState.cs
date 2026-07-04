using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NATTunnel;

/// <summary>
/// Captures the current state of the mesh network for querying by the GUI or CLI tools.
/// </summary>
public class MeshState
{
    [JsonPropertyName("networkID")]
    public string NetworkID { get; set; }

    [JsonPropertyName("ownMeshIP")]
    public string OwnMeshIP { get; set; }

    [JsonPropertyName("ownPeerID")]
    public string OwnPeerID { get; set; }

    [JsonPropertyName("isIntroducer")]
    public bool IsIntroducer { get; set; }

    [JsonPropertyName("natType")]
    public string NATType { get; set; }

    [JsonPropertyName("connectedPeers")]
    public List<ConnectedPeer> ConnectedPeers { get; set; }

    [JsonPropertyName("relayRoutes")]
    public List<RelayRoute> RelayRoutes { get; set; }

    [JsonPropertyName("introducerMeshIP")]
    public string IntroducerMeshIP { get; set; }

    [JsonPropertyName("uptimeSeconds")]
    public long UptimeSeconds { get; set; }

    [JsonPropertyName("connectionState")]
    public string ConnectionState { get; set; }

    /// <summary>Number of relay pairs this peer is currently hosting (forwarding traffic for).</summary>
    [JsonPropertyName("hostedRelayPairs")]
    public int HostedRelayPairs { get; set; }

    [JsonPropertyName("metrics")]
    public MeshMetrics Metrics { get; set; }

    /// <summary>
    /// Human-readable description of the last mesh error (auth failure, version rejection,
    /// mediation connect failure, etc.). Null when there's no notable error to surface.
    /// </summary>
    [JsonPropertyName("lastError")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string LastError { get; set; }

    /// <summary>
    /// Classification of <see cref="LastError"/> so the GUI can decide how to present it.
    /// Values: "VersionMismatch", "AuthFailure", "MediationUnreachable", "Other".
    /// </summary>
    [JsonPropertyName("lastErrorKind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string LastErrorKind { get; set; }

    /// <summary>Mediation-server wire version this daemon speaks.</summary>
    [JsonPropertyName("mediationProtocolVersion")]
    public int MediationProtocolVersion { get; set; }

    /// <summary>Peer-to-peer wire version range this daemon supports (lower bound).</summary>
    [JsonPropertyName("peerProtocolMinVersion")]
    public int PeerProtocolMinVersion { get; set; }

    /// <summary>Peer-to-peer wire version range this daemon supports (upper bound).</summary>
    [JsonPropertyName("peerProtocolMaxVersion")]
    public int PeerProtocolMaxVersion { get; set; }

    /// <summary>This node's own identity fingerprint (SHA-256(pubkey)[..8] hex). Users share this
    /// with peers who want to block them; GUIs display it as the "who am I" identifier.</summary>
    [JsonPropertyName("ownFingerprint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string OwnFingerprint { get; set; }

    /// <summary>Currently-blocked peer fingerprints. Live snapshot — the GUI's Firewall pane
    /// renders this list and posts to /blocks to mutate it.</summary>
    [JsonPropertyName("blockedFingerprints")]
    public List<string> BlockedFingerprints { get; set; } = new();

    /// <summary>Peers seen within the recently-seen window (connected now or briefly gone). Powers
    /// the Firewall pane's "known peers" list — users need a small grace window to catch a peer
    /// they want to block right after they leave.</summary>
    [JsonPropertyName("knownPeers")]
    public List<KnownPeer> KnownPeers { get; set; } = new();

    public MeshState()
    {
        ConnectedPeers = new List<ConnectedPeer>();
        RelayRoutes = new List<RelayRoute>();
        Metrics = new MeshMetrics();
    }

    /// <summary>
    /// Represents a connected peer in the mesh network.
    /// </summary>
    public class ConnectedPeer
    {
        [JsonPropertyName("meshIP")]
        public string MeshIP { get; set; }

        [JsonPropertyName("peerID")]
        public string PeerID { get; set; }

        [JsonPropertyName("natType")]
        public string NATType { get; set; }

        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }

        [JsonPropertyName("lastActivity")]
        public DateTime LastActivity { get; set; }

        [JsonPropertyName("isRelayed")]
        public bool IsRelayed { get; set; }

        [JsonPropertyName("isRelayGateway")]
        public bool IsRelayGateway { get; set; }

        [JsonPropertyName("latencyMs")]
        public long LatencyMs { get; set; } = -1;

        [JsonPropertyName("relayedVia")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RelayedVia { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>
        /// Peer-protocol version negotiated via MeshVersionHello. -1 when not yet negotiated
        /// (peer just came up, hello in flight); 0 when the peer is on a build predating the
        /// negotiation (grandfathered as v1 in feature checks).
        /// </summary>
        [JsonPropertyName("peerProtocolVersion")]
        public int PeerProtocolVersion { get; set; } = -1;

        /// <summary>
        /// SHA-256(identityPublicKey)[..8] hex. Null when the peer hasn't advertised an identity
        /// key yet (older build, or key not yet echoed through mediation). GUIs use this as the
        /// argument to the Block action.
        /// </summary>
        [JsonPropertyName("fingerprint")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Fingerprint { get; set; }
    }

    /// <summary>
    /// A peer we've seen recently — connected right now, or gone but within the recently-seen
    /// window. Populates the Firewall pane so users can block someone who was here a moment ago.
    /// </summary>
    public class KnownPeer
    {
        [JsonPropertyName("meshIP")]
        public string MeshIP { get; set; }

        [JsonPropertyName("peerID")]
        public string PeerID { get; set; }

        /// <summary>SHA-256(identityPublicKey)[..8] hex. Null if the peer's identity hasn't been
        /// echoed through mediation yet (older client) — GUI greys out the Block action in that case.</summary>
        [JsonPropertyName("fingerprint")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Fingerprint { get; set; }

        /// <summary>True when this peer currently has an active tunnel; false when they're in the
        /// grace window after disconnect. GUI can render active peers distinctly if it wants.</summary>
        [JsonPropertyName("isConnected")]
        public bool IsConnected { get; set; }
    }

    /// <summary>
    /// Represents a relay route between two peers.
    /// </summary>
    public class RelayRoute
    {
        [JsonPropertyName("sourceMeshIP")]
        public string SourceMeshIP { get; set; }

        [JsonPropertyName("destinationMeshIP")]
        public string DestinationMeshIP { get; set; }
    }

    /// <summary>
    /// Aggregated metrics for mesh health monitoring.
    /// </summary>
    public class MeshMetrics
    {
        [JsonPropertyName("tunnelsEstablished")]
        public int TunnelsEstablished { get; set; }

        [JsonPropertyName("tunnelsFailed")]
        public int TunnelsFailed { get; set; }

        [JsonPropertyName("reconnects")]
        public int Reconnects { get; set; }

        [JsonPropertyName("peersLost")]
        public int PeersLost { get; set; }

        [JsonPropertyName("heartbeatsSent")]
        public int HeartbeatsSent { get; set; }

        [JsonPropertyName("heartbeatAcksReceived")]
        public int HeartbeatAcksReceived { get; set; }

        [JsonPropertyName("heartbeatsMissed")]
        public int HeartbeatsMissed { get; set; }

        [JsonPropertyName("lastHeartbeatResponseMs")]
        public long LastHeartbeatResponseMs { get; set; }

        [JsonPropertyName("relayRoutesEstablished")]
        public int RelayRoutesEstablished { get; set; }

        [JsonPropertyName("relayRoutesRemoved")]
        public int RelayRoutesRemoved { get; set; }

        [JsonPropertyName("activeRelayRouteCount")]
        public int ActiveRelayRouteCount { get; set; }
    }
}
