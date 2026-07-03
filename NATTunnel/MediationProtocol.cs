namespace NATTunnel;

/// <summary>
/// Version constants for the client<->mediation-server protocol. Bumped when a wire-format
/// change is introduced. The server advertises a supported range; clients advertise the single
/// version they were built against. Server accepts if the client's version falls in the range,
/// else rejects with <see cref="MediationMessage.VersionError"/> set.
/// </summary>
internal static class MediationProtocol
{
    /// <summary>The matchmaking wire-format version this client was built for.</summary>
    public const int ClientVersion = 1;

    /// <summary>
    /// Peer-to-peer wire-format version range this build supports. Each peer sends its range
    /// in the Noise handshake payload; both sides negotiate to <c>min(their.Max, our.Max)</c>
    /// if that value is still <c>&gt;= max(their.Min, our.Min)</c>, else the pair is refused.
    /// Bumped when envelope byte semantics, fragment format, or mesh-control message shapes change.
    /// </summary>
    public const int PeerMinVersion = 1;
    public const int PeerMaxVersion = 1;
}
