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
    /// The NAT type the mediation server determined. <see cref="NATType.Unknown"/> if the probe
    /// couldn't reach a verdict (e.g., mediation unreachable, UDP test packets blocked).
    /// </summary>
    public NATType NatType { get; init; }

    /// <summary>
    /// The local LAN IP the OS selected for outbound traffic toward the mediation server. Useful
    /// for displaying which network interface the probe used. Null if detection failed.
    /// </summary>
    public IPAddress LocalIP { get; init; }

    /// <summary>
    /// True when the NAT type means direct peer-to-peer is unlikely — i.e. <see cref="NATType.Symmetric"/>.
    /// Symmetric-NAT peers pair only with non-symmetric peers directly; two symmetric peers must
    /// relay through a third party, which adds a hop and consumes that peer's bandwidth.
    /// </summary>
    public bool LikelyNeedsRelay { get; init; }

    /// <summary>Human-readable error message if the probe failed. Null on success.</summary>
    public string ErrorMessage { get; init; }
}
