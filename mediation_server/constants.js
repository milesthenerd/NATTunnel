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
    NATTunnelData: 10,
    SymmetricHolePunchAttempt: 11,
    ConnectionComplete: 12,
    ReceivedPeer: 13,
    ConnectionTimeout: 14,
    PublicKeyRequest: 15,
    PublicKeyResponse: 16,
    SymmetricKeyRequest: 17,
    SymmetricKeyResponse: 18,
    SymmetricKeyConfirm: 19,
    WireGuardPublicKeyExchange: 20,
    WireGuardPublicKeyHash: 21,
    ServerRegister: 22,
    // Mesh networking messages
    MeshJoinRequest: 23,        // Peer wants to join a mesh network
    MeshJoinResponse: 24,        // Response with list of peers in network
    MeshPeerList: 25            // Updated list of peers
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
    DEFAULT_TIMEOUT: 30, // seconds (increased from 10 to accommodate WireGuard initialization in mesh mode)
    BIND_ADDRESS: "0.0.0.0"
};

module.exports = {
    NATTypes,
    MessageTypes,
    StatusTypes,
    Config
};