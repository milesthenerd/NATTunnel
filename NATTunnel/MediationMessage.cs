using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NATTunnel;

/// <summary>
///Class for the messages sent to and received from the mediation server
/// </summary>
internal class MediationMessage
{
    /// <summary>
    ///Message type ID
    /// </summary>
    public MediationMessageType ID { get; set; }
    /// <summary>
    ///Local port of the client's udp socket
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int LocalPort { get; set; }
    /// <summary>
    ///Local/LAN IP address of the client (for same-NAT peer detection)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string LocalIP { get; set; }
    /// <summary>
    ///NAT type of the client
    /// </summary>
    public NATType NATType { get; set; }
    /// <summary>
    ///Server's IP address and port as a string because IPEndpoint is not deserializable
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string EndpointString { get; set; }
    /// <summary>
    /// Always the external endpoint, even when EndpointString is LAN-substituted for same-NAT peers.
    /// Used by introducers to forward a peer's external address to peers on other networks.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string ExternalEndpointString { get; set; }
    /// <summary>
    ///First port for nat type detection returned by the server
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int NATTestPortOne { get; set; }
    /// <summary>
    ///Second port for nat type detection returned by the server
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int NATTestPortTwo { get; set; }
    /// <summary>
    ///ID assigned to a peer pair attempting to make a connection
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ConnectionID { get; set; }
    /// <summary>
    ///Randomly generated client ID to avoid NATs with multiple IP addresses
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public System.Guid ClientID { get; set; }
    /// <summary>
    ///The private/mesh IP of a peer
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string PrivateAddressString { get; set; }
    /// <summary>
    ///WireGuard public key (base64 encoded)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string WireGuardPublicKey { get; set; }
    /// <summary>
    ///SHA256 hash to verify that WireGuard public key is intact after being transported
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] WireGuardPublicKeyHash { get; set; }

    // Mesh networking fields
    /// <summary>
    ///Network ID for mesh networking - peers with same ID can discover each other
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string NetworkID { get; set; }
    /// <summary>
    ///Unique peer ID (GUID) for mesh networking
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string PeerID { get; set; }
    /// <summary>
    ///Number of peers in mesh network response
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int PeerCount { get; set; }
    /// <summary>
    ///List of peers in mesh network (JSON array)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public object[] Peers { get; set; }
    /// <summary>
    ///This tunnel's own NAT type (used when server skips NAT detection for mesh tunnels)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public NATType? OwnNATType { get; set; }
    /// <summary>
    ///Peer ID of the selected introducer (returned in MeshJoinResponse to tell P_new which peer to connect to first)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string IntroducerPeerID { get; set; }
    /// <summary>
    ///List of existing peers that the introducer should forward the new peer's info to (used in MeshIntroduceRequest)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public object[] OtherPeers { get; set; }
    /// <summary>
    ///When true in MeshConnectionBegin, indicates traffic should be relayed through the introducer
    ///rather than hole-punched directly (used for symmetric-to-symmetric NAT pairs)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsRelay { get; set; }
    /// <summary>
    ///Introducer's mesh IP — set in relay MeshConnectionBegin so the receiving peer knows
    ///which WireGuard peer to add the relay route through
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string IntroducerMeshIP { get; set; }
    /// <summary>
    ///List of mesh IPs this peer has active WireGuard tunnels to (used in MeshHeartbeatAck)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[] ConnectedMeshIPs { get; set; }
    /// <summary>
    /// Compact peer roster included in MeshHeartbeat by the introducer.
    /// Each entry is "meshIP|peerID|natType|endpoint" so non-introducer peers can learn about all mesh members.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[] PeerRoster { get; set; }
    /// <summary>Set on MeshHeartbeat by the sender if it currently holds the introducer role.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsIntroducer { get; set; }
    /// <summary>MeshHeartbeat: sender opts in to being a relay candidate for other pairs.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool RelayCapable { get; set; }
    /// <summary>MeshHeartbeat: number of pairs currently relaying through this peer (self-reported).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ActiveRelayRoutes { get; set; }
    /// <summary>MeshHeartbeat: operator hint about uplink capacity for relay scoring.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public RelayCapacity RelayCapacity { get; set; }
    /// <summary>
    /// MeshConnectionBegin: the peer whose WireGuard interface relays traffic for this pair.
    /// When unset on an IsRelay=true message, treat as equal to IntroducerMeshIP (back-compat).
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string RelayMeshIP { get; set; }
    /// <summary>MeshRelayAssignment / MeshRelayHealthReport: first endpoint of the relayed pair.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string PeerA { get; set; }
    /// <summary>MeshRelayAssignment / MeshRelayHealthReport: second endpoint of the relayed pair.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string PeerB { get; set; }
    /// <summary>MeshRelayAssignmentAck: whether the chosen relay successfully set up the route.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Success { get; set; }
    /// <summary>MeshRelayAssignment: when true, tear down the relay route for this pair instead of setting it up.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool Release { get; set; }
    /// <summary>MeshRelayAssignmentAck / MeshRelayHealthReport: optional failure or observation detail.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string Error { get; set; }
    /// <summary>MeshRelayHealthReport: which kind of failure the reporting peer observed.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public RelayHealthObservation Observation { get; set; }
    /// <summary>MeshRelayHealthReport: mesh IP of the reporting peer.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string Self { get; set; }
    /// <summary>MeshRelayHealthReport: mesh IP of the unreachable peer at the other end of the relay.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string Remote { get; set; }
    /// <summary>MeshRelayHealthReport: mesh IP of the currently-assigned relay being reported.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string CurrentRelay { get; set; }
    /// <summary>
    /// Authentication token: SHA256(networkID + ":" + networkSecret) as base64.
    /// Sent in MeshJoinRequest; reused for error message in MeshJoinResponse on auth failure.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string AuthToken { get; set; }
    public MediationMessage(MediationMessageType id = 0)
    {
        ID = id;
    }

    /// <summary>
    ///Serializes the message
    /// </summary>
    public string Serialize()
    {
        return JsonSerializer.Serialize<MediationMessage>(this);
    }

    /// <summary>
    ///Converts the endpoint string to an IPEndPoint and returns it
    /// </summary>
    public IPEndPoint GetEndpoint()
    {
        return IPEndPoint.Parse(EndpointString);
    }

    /// <summary>
    ///Converts an IPEndPoint to a string and sets the endpoint string to it
    /// </summary>
    public void SetEndpoint(IPEndPoint serverEndpoint)
    {
        EndpointString = serverEndpoint.ToString();
    }

    /// <summary>
    ///Converts the private address string to an IPAddress and returns it
    /// </summary>
    public IPAddress GetPrivateAddress()
    {
        if (string.IsNullOrEmpty(PrivateAddressString))
        {
            return null;
        }
        return IPAddress.Parse(PrivateAddressString);
    }

    /// <summary>
    ///Converts an IPAddress to a string and sets the private address string to it
    /// </summary>
    public void SetPrivateAddress(IPAddress privateAddress)
    {
        PrivateAddressString = privateAddress.ToString();
    }
}
/// <summary>
///Different message types sent from the mediation server
/// NOTE: Do not renumber existing values — the mediation server JS uses matching numbers.
/// </summary>
internal enum MediationMessageType
{
    /// <summary>
    ///Successful TCP connection to the mediation server
    /// </summary>
    Connected,          // 0
    /// <summary>
    ///Request mediation server for NAT type
    /// </summary>
    NATTypeRequest,     // 1
    /// <summary>
    ///Response from server permitting client to begin NAT test
    /// </summary>
    NATTestBegin,       // 2
    /// <summary>
    ///Packet sent during NAT test
    /// </summary>
    NATTest,            // 3
    /// <summary>
    ///Response from the mediation server with the discovered NAT type
    /// </summary>
    NATTypeResponse,    // 4
    /// <summary>
    ///Packet type to keep the udp connection alive
    /// </summary>
    KeepAlive,          // 5
    /// <summary>
    ///Request to begin a connection attempt with a peer
    /// </summary>
    ConnectionRequest,  // 6
    /// <summary>
    ///Response from the mediation server to begin a connection attempt
    /// </summary>
    ConnectionBegin,    // 7
    /// <summary>
    ///Response from the mediation server stating that the specified peer is not available
    /// </summary>
    ServerNotAvailable, // 8
    /// <summary>
    ///Packet sent during hole punch attempts
    /// </summary>
    HolePunchAttempt,   // 9
    /// <summary>
    ///(Legacy) Packet sent for NATTunnel data — no longer used
    /// </summary>
    NATTunnelData,      // 10
    /// <summary>
    ///Packet sent during symmetric NAT hole punch attempts
    /// </summary>
    SymmetricHolePunchAttempt, // 11
    /// <summary>
    ///Packet sent indicating connection complete
    /// </summary>
    ConnectionComplete, // 12
    /// <summary>
    ///(Legacy) Packet sent indicating received from peer — no longer used
    /// </summary>
    ReceivedPeer,       // 13
    /// <summary>
    ///Packet sent to timeout connection attempt after failed communication
    /// </summary>
    ConnectionTimeout,  // 14
    /// <summary>
    ///(Legacy) Public key request — no longer used
    /// </summary>
    PublicKeyRequest,   // 15
    /// <summary>
    ///(Legacy) Public key response — no longer used
    /// </summary>
    PublicKeyResponse,  // 16
    /// <summary>
    ///(Legacy) Symmetric key request — no longer used
    /// </summary>
    SymmetricKeyRequest, // 17
    /// <summary>
    ///(Legacy) Symmetric key response — no longer used
    /// </summary>
    SymmetricKeyResponse, // 18
    /// <summary>
    ///(Legacy) Symmetric key confirm — no longer used
    /// </summary>
    SymmetricKeyConfirm, // 19
    /// <summary>
    ///Packet sent to exchange WireGuard public keys between peers
    /// </summary>
    WireGuardPublicKeyExchange, // 20
    /// <summary>
    ///Hash of WireGuard public key for integrity verification
    /// </summary>
    WireGuardPublicKeyHash, // 21
    /// <summary>
    ///(Legacy) Server registration — no longer used
    /// </summary>
    ServerRegister,     // 22
    /// <summary>
    ///Request to join a mesh network by network ID
    /// </summary>
    MeshJoinRequest,    // 23
    /// <summary>
    ///Response containing list of peers in the mesh network
    /// </summary>
    MeshJoinResponse,   // 24
    /// <summary>
    ///Updated list of peers in the mesh network
    /// </summary>
    MeshPeerList,       // 25
    /// <summary>
    ///Message sent over WireGuard from introducer to existing peers to introduce a new peer
    /// </summary>
    MeshIntroduction,   // 26
    /// <summary>
    ///Acknowledgement of a MeshIntroduction message
    /// </summary>
    MeshIntroductionAck, // 27
    /// <summary>
    ///Sent from mediation server to the selected introducer peer via TCP
    /// </summary>
    MeshIntroduceRequest, // 28
    /// <summary>
    ///Sent from introducer to mediation server via TCP after introductions complete
    /// </summary>
    MeshIntroduceAck,   // 29
    /// <summary>
    ///Sent by introducer to both peers over WireGuard to initiate direct hole-punching
    /// </summary>
    MeshConnectionBegin, // 30
    /// <summary>
    ///Sent by introducer to each peer over WireGuard to check connectivity
    /// </summary>
    MeshHeartbeat,      // 31
    /// <summary>
    ///Response to MeshHeartbeat — contains active WireGuard tunnel list
    /// </summary>
    MeshHeartbeatAck,   // 32
    /// <summary>
    ///Sent by introducer to all peers when a peer is declared dead (no heartbeat acks)
    /// </summary>
    MeshPeerRemoved,    // 33
    /// <summary>
    ///Sent by a peer to all connected peers when shutting down gracefully
    /// </summary>
    MeshPeerLeave,      // 34
    /// <summary>Introducer → both endpoints + chosen relay: assigns the relay for a pair.</summary>
    MeshRelayAssignment,    // 35
    /// <summary>Chosen relay → introducer: confirms or rejects the assignment.</summary>
    MeshRelayAssignmentAck, // 36
    /// <summary>Relayed peer → introducer: reports that the current relay is degraded.</summary>
    MeshRelayHealthReport   // 37
    // Note: Latency ping/pong uses binary 0xFF-prefixed packets, not JSON message types
}

/// <summary>Operator hint about a peer's willingness/capacity to serve as a relay.</summary>
public enum RelayCapacity
{
    Normal = 0,
    Low = 1,
    High = 2
}

/// <summary>What kind of relay failure a peer observed before sending a health report.</summary>
internal enum RelayHealthObservation
{
    Other = 0,
    DownstreamFailed = 1,
    RelayUnreachable = 2
}

/// <summary>
/// Different NAT types that can be returned by the mediation server
/// </summary>
public enum NATType
{
    /// <summary>
    ///The NAT is either non-existant or a one-to-one mapping (easy to work with)
    /// </summary>
    DirectMapping,
    /// <summary>
    ///The NAT is either address or address + port restricted (slightly harder to work with but doable)
    /// </summary>
    Restricted,
    /// <summary>
    ///The NAT is symmetric (doable in combination with either of the above two NAT types)
    /// </summary>
    Symmetric,
    /// <summary>
    ///Before the type is defined
    /// </summary>
    Unknown = -1
}
