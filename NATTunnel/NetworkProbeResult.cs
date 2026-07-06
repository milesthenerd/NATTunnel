using System.Net;

namespace NATTunnel;

/// <summary>
/// Result of <see cref="MeshNode.ProbeNetworkAsync(string, System.Threading.CancellationToken)"/>.
/// Lets host apps preview connectivity before constructing a full <see cref="MeshNode"/> —
/// useful for showing the user a "your network supports direct P2P" or "you'll be on relay,
/// expect higher latency" hint before they commit to joining a mesh.
/// </summary>
public sealed class NetworkProbeResult
{
    /// <summary>True if the mediation server was reachable over TCP+TLS and replied with a NAT-type response.</summary>
    public bool MediationReachable { get; init; }

    /// <summary>
    /// The IPv4 NAT type the mediation server determined. <see cref="NATType.Unknown"/> if the probe
    /// couldn't reach a verdict (e.g., mediation unreachable, UDP test packets blocked).
    /// </summary>
    public NATType NatType { get; init; }

    /// <summary>
    /// The IPv6 NAT type, or null if this machine has no usable global IPv6 (so no v6 probe ran).
    /// IPv6 and IPv4 NAT behavior can differ — a peer may be <see cref="NATType.Symmetric"/> on v4
    /// but open on v6, in which case it can still connect directly. Considered by
    /// <see cref="LikelyNeedsRelay"/>.
    /// </summary>
    public NATType? NatTypeV6 { get; init; }

    /// <summary>
    /// The local LAN IP the OS selected for outbound traffic toward the mediation server. Useful
    /// for displaying which network interface the probe used. Null if detection failed.
    /// </summary>
    public IPAddress LocalIP { get; init; }

    /// <summary>
    /// True when direct peer-to-peer is unlikely on EVERY reachable family — i.e. symmetric on IPv4
    /// AND (no usable IPv6, or symmetric on IPv6 too). A peer that's symmetric on v4 but open on v6
    /// reports false here, because it can still connect directly over IPv6. Symmetric-NAT peers pair
    /// only with non-symmetric peers directly; two symmetric peers on the same family must relay
    /// through a third party, adding a hop and consuming that peer's bandwidth.
    /// </summary>
    public bool LikelyNeedsRelay { get; init; }

    /// <summary>Human-readable error message if the probe failed. Null on success.</summary>
    public string ErrorMessage { get; init; }
}
