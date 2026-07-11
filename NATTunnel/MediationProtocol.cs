namespace NATTunnel;

/// <summary>
/// Version constants for the client<->mediation-server protocol. Bumped when a wire-format
/// change is introduced. The server advertises a supported range; clients advertise the single
/// version they were built against. Server accepts if the client's version falls in the range,
/// else rejects with <see cref="MediationMessage.VersionError"/> set.
/// </summary>
internal static class MediationProtocol
{
    /// <summary>
    /// The matchmaking (client↔mediation) wire-format version this client was built for.
    /// v2 (2026-07-11): two-IP RFC 5780 NAT test — client probes the server's second advertised
    /// IPv4 (ServerPublicIPv4List[1]) so the server can detect address-dependent NAT mapping and
    /// deliver MappingBehavior on NATTypeResponse. Backward-compatible (the new probe/fields are
    /// additive + self-gated on the server advertising a second IP), but bumped to anchor the first
    /// substantive evolution of the mediation protocol since v1.
    /// </summary>
    public const int ClientVersion = 2;

    /// <summary>
    /// Peer-to-peer wire-format version range this build supports. Each peer sends its range
    /// in the Noise handshake payload; both sides negotiate to <c>min(their.Max, our.Max)</c>
    /// if that value is still <c>&gt;= max(their.Min, our.Min)</c>, else the pair is refused.
    /// Bumped when envelope byte semantics, fragment format, or mesh-control message shapes change.
    /// </summary>
    public const int PeerMinVersion = 1;
    public const int PeerMaxVersion = 1;
}
