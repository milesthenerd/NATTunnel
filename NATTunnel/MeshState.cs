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
