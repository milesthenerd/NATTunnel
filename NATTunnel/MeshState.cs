using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NATTunnel;

/// <summary>
/// Captures the current state of the mesh network for querying by the GUI or CLI tools.
/// </summary>
public class MeshState
{
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

    public MeshState()
    {
        ConnectedPeers = new List<ConnectedPeer>();
        RelayRoutes = new List<RelayRoute>();
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
}
