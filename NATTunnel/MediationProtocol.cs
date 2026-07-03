namespace NATTunnel;

/// <summary>
/// Version constants for the client<->mediation-server protocol. Bumped when a wire-format
/// change is introduced. The server advertises a supported range; clients advertise the single
/// version they were built against. Server accepts if the client's version falls in the range,
/// else rejects with <see cref="MediationMessage.VersionError"/> set.
/// </summary>
internal static class MediationProtocol
{
    /// <summary>The wire-format version this client was built for.</summary>
    public const int ClientVersion = 1;
}
