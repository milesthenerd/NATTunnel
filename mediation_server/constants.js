// NAT type enumeration
const NATTypes = {
    DirectMapping: 0,
    Restricted: 1,
    Symmetric: 2,
    Unknown: -1
};

// Message type enumeration
const MessageTypes = {
    Connected: 0,
    NATTypeRequest: 1,
    NATTestBegin: 2,
    NATTest: 3,
    NATTypeResponse: 4,
    KeepAlive: 5,
    ConnectionRequest: 6,
    ConnectionBegin: 7,
    ServerNotAvailable: 8,
    HolePunchAttempt: 9,
    NATTunnelData: 10,             // Legacy — no longer used
    SymmetricHolePunchAttempt: 11,
    ConnectionComplete: 12,
    ReceivedPeer: 13,               // Legacy — no longer used
    ConnectionTimeout: 14,
    PublicKeyRequest: 15,           // Legacy — no longer used
    PublicKeyResponse: 16,          // Legacy — no longer used
    SymmetricKeyRequest: 17,        // Legacy — no longer used
    SymmetricKeyResponse: 18,       // Legacy — no longer used
    SymmetricKeyConfirm: 19,        // Legacy — no longer used
    WireGuardPublicKeyExchange: 20,
    WireGuardPublicKeyHash: 21,
    ServerRegister: 22,             // Legacy — no longer used
    // Mesh networking messages
    MeshJoinRequest: 23,        // Peer wants to join a mesh network
    MeshJoinResponse: 24,       // Response with list of peers in network
    MeshPeerList: 25,           // Updated list of peers
    MeshIntroduction: 26,       // Sent over WireGuard from introducer to existing peers to introduce a new peer
    MeshIntroductionAck: 27,    // Acknowledgement of MeshIntroduction (sent back over WireGuard, optional)
    MeshIntroduceRequest: 28,   // Sent from mediation server to introducer via TCP: forward new peer info to other peers
    MeshIntroduceAck: 29,       // Sent from introducer to mediation server via TCP: introductions sent
    MeshConnectionBegin: 30,    // Sent by introducer to both peers over WireGuard: initiate direct hole-punching
    MeshHeartbeat: 31,           // Sent by introducer to each peer over WireGuard: check reachable peers
    MeshHeartbeatAck: 32         // Response to MeshHeartbeat: list of reachable mesh IPs
};

// Client status types
const StatusTypes = {
    Free: 0,
    Busy: 1
};

// Server configuration
const Config = {
    TCP_PORT: 6510,
    UDP_PORT: 6510,
    NAT_TEST_PORT_ONE: 6511,
    NAT_TEST_PORT_TWO: 6512,
    DEFAULT_TIMEOUT: 60, // seconds (increased to 60 to prevent mesh peers from timing out between discovery polls)
    BIND_ADDRESS: "0.0.0.0",
    MESH_CONTROL_PORT: 51888    // UDP port used for peer-to-peer mesh introduction messages over WireGuard
};

module.exports = {
    NATTypes,
    MessageTypes,
    StatusTypes,
    Config
};