const path = require('path');

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
    MeshHeartbeatAck: 32,        // Response to MeshHeartbeat: list of reachable mesh IPs
    MeshPeerRemoved: 33,         // Sent by introducer to all peers when a peer is declared dead
    MeshPeerLeave: 34,           // Sent by a peer to all connected peers when shutting down gracefully
    MeshRelayAssignment: 35,     // Introducer -> endpoints + chosen relay
    MeshRelayAssignmentAck: 36,  // Chosen relay -> introducer
    MeshRelayHealthReport: 37,   // Relayed peer -> introducer: relay degraded
    MeshIPReassign: 38           // Peer -> server: mesh IP changed (collision reassignment)
};

// Client status types
const StatusTypes = {
    Free: 0,
    Busy: 1
};

// Client<->mediation-server wire-format compatibility window.
// A client's `ProtocolVersion` field must be within [MIN, MAX] on MeshJoinRequest;
// otherwise the server rejects the join with `VersionError` set on the response.
const MediationProtocol = {
    MinSupportedClientVersion: 1,
    MaxSupportedClientVersion: 1
};

// Server configuration
const Config = {
    TCP_PORT: 6510,
    UDP_PORT: 6510,
    NAT_TEST_PORT_ONE: 6511,
    NAT_TEST_PORT_TWO: 6512,
    DEFAULT_TIMEOUT: 60, // seconds (increased to 60 to prevent mesh peers from timing out between discovery polls)
    // "::" binds dual-stack (IPv4 + IPv6); the server falls back to "0.0.0.0" on hosts
    // with IPv6 disabled. Override with the BIND_ADDRESS env var.
    BIND_ADDRESS: process.env.BIND_ADDRESS || "::",
    MESH_CONTROL_PORT: 51888,   // UDP port used for peer-to-peer mesh introduction messages over WireGuard

    // TLS configuration. TLS is always on.
    // Cert/key are auto-generated with openssl on first startup if not present.
    // Override paths with TLS_CERT_PATH / TLS_KEY_PATH env vars to use your own CA-signed certificate.
    TLS_CERT_PATH: process.env.TLS_CERT_PATH || path.join(__dirname, 'cert.pem'),
    TLS_KEY_PATH:  process.env.TLS_KEY_PATH  || path.join(__dirname, 'key.pem'),

    // Browser-facing NAT test (web-nat-test). Opt-in: NAT_TEST_ENABLED=1 to
    // enable. Requires coturn running on the same host plus an nginx
    // reverse-proxy fronting the HTTP signaling endpoint. See
    // DEPLOY-NAT-WEBRTC.md for the full setup.
    NAT_TEST_ENABLED: process.env.NAT_TEST_ENABLED === '1',
    NAT_TEST_HTTP_PORT: Number(process.env.NAT_TEST_HTTP_PORT) || 6515,
    NAT_TEST_STUN_URL: process.env.NAT_TEST_STUN_URL || 'stun:sync.milesthenerd.net:3478',
    NAT_TEST_TURN_URL: process.env.NAT_TEST_TURN_URL || 'turn:sync.milesthenerd.net:3478',
    NAT_TEST_TURN_USER: process.env.NAT_TEST_TURN_USER || 'nattunnel',
    NAT_TEST_TURN_PASS: process.env.NAT_TEST_TURN_PASS || '',
    NAT_TEST_ICE_PORT_MIN: Number(process.env.NAT_TEST_ICE_PORT_MIN) || 6520,
    NAT_TEST_ICE_PORT_MAX: Number(process.env.NAT_TEST_ICE_PORT_MAX) || 6540,
    NAT_TEST_DEBUG: process.env.NAT_TEST_DEBUG === '1',
};

module.exports = {
    NATTypes,
    MessageTypes,
    StatusTypes,
    Config,
    MediationProtocol
};