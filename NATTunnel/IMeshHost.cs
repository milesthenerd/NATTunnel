using System.Collections.Generic;
using System.Net;

namespace NATTunnel;

/// <summary>
/// Bridge between the mesh-protocol core (MeshProtocolEngine) and whatever real networking the
/// host has wired up (today: a WireGuard interface managed by WireGuardTunnel; eventually:
/// a userspace loopback-proxy for embedded library use).
///
/// MeshProtocolEngine never touches WireGuard directly — it goes through this interface so the
/// same protocol logic can drive either the daemon's kernel WireGuard or an embedded
/// userspace transport.
///
/// Signatures intentionally match WireGuardTunnel's existing methods so it can implement
/// this interface without any wrapper layer.
/// </summary>
internal interface IMeshHost
{
    /// <summary>Assign this peer's mesh IP and (re)configure the underlying interface.</summary>
    void SetClientIPAndRestart(string assignedIpAddress, byte prefixLength = 24);

    /// <summary>Enable IP forwarding on the underlying interface. Returns true on success.</summary>
    bool EnableForwarding();

    /// <summary>Add a relay route: traffic for <paramref name="relayedPeerIP"/> goes via <paramref name="gatewayPeerIP"/>.</summary>
    bool AddRelayRoute(IPAddress gatewayPeerIP, IPAddress relayedPeerIP);

    /// <summary>Remove the relay route targeting <paramref name="relayedPeerIP"/>, if any.</summary>
    bool RemoveRelayRouteForPeer(IPAddress relayedPeerIP);

    /// <summary>Remove every relay route whose gateway is <paramref name="gatewayPeerIP"/>.</summary>
    List<IPAddress> RemoveRelayRoutesViaGateway(IPAddress gatewayPeerIP);

    /// <summary>Current relay routes (relayedIP → gatewayIP) as known to the host.</summary>
    Dictionary<IPAddress, IPAddress> GetRelayRoutes();

    /// <summary>Look up a peer by mesh IP, or null if unknown.</summary>
    WireGuardPeer GetPeer(IPAddress privateAddress);

    /// <summary>Snapshot of all peers currently configured on the host interface.</summary>
    IEnumerable<WireGuardPeer> GetAllPeers();

    /// <summary>Remove a peer by its connection ID (used when a peer is declared dead).</summary>
    void RemovePeer(int connectionId);

    /// <summary>Remove every peer (used during disconnect cleanup).</summary>
    void RemoveAllPeers();

    /// <summary>
    /// Receive-path forward for binary data packets (WireGuard message types 1-4 in daemon mode;
    /// embedded mode dispatches to the appropriate MeshPeerProxy by source endpoint).
    /// Called from the shared UDP dispatcher when an incoming packet looks like binary data
    /// rather than JSON mesh-control.
    /// </summary>
    void ForwardDataPacket(byte[] data, IPEndPoint sourceEndpoint);

    /// <summary>
    /// Host-specific setup for a newly created Tunnel. Daemon mode wires the WireGuardTunnel
    /// reference into the Tunnel so it can perform WG key exchange. Embedded mode uses this
    /// hook to create a <see cref="Embedded.MeshPeerProxy"/> for the new peer and register
    /// it for data-path dispatch.
    /// </summary>
    /// <param name="tunnel">The Tunnel that's just been created and registered with the engine.</param>
    /// <param name="remotePeerID">Remote peer's GUID string (used by embedded mode's Noise initiator-decision logic). May be empty for reconnect-side tunnels where the peer ID isn't yet known.</param>
    /// <param name="remoteMeshIP">Remote peer's mesh IP. May be empty for early-binding tunnels.</param>
    void ConfigureNewTunnel(Tunnel tunnel, string remotePeerID, string remoteMeshIP);

    /// <summary>
    /// Fired after <see cref="AddRelayRoute"/> succeeds. Carries the full peer identity so the
    /// host can do follow-up work that AddRelayRoute's IP-only signature lacks context for.
    /// Embedded hosts use this to construct a relayed MeshPeerProxy + start its Noise handshake.
    /// Daemon hosts can ignore it.
    /// </summary>
    /// <param name="remotePublicEndpoint">
    /// Remote peer's NAT-translated public endpoint as reported by the introducer in the
    /// relay MeshConnectionBegin. Null if the introducer didn't supply one.
    /// </param>
    void OnRelayPeerEstablished(string remotePeerID, IPAddress remoteMeshIP, IPAddress gatewayMeshIP, IPEndPoint remotePublicEndpoint);

    /// <summary>
    /// Attempt to send a mesh-control packet (heartbeat, MeshConnectionBegin, MeshRelayAssignment, etc.)
    /// to the peer identified by <paramref name="destinationMeshIP"/>. Returns true if the host
    /// took responsibility for delivery (and MeshProtocolEngine should NOT fall back to its native path);
    /// false to let MeshProtocolEngine send via its own meshControlClient (the daemon-mode WG-routed path).
    /// Embedded hosts return true after encrypting + tunneling via the destination's MeshPeerProxy.
    /// Daemon hosts return false — MeshProtocolEngine's existing UDP-to-mesh-IP send path handles it.
    /// </summary>
    bool SendMeshControl(IPAddress destinationMeshIP, byte[] data, int length);
}
