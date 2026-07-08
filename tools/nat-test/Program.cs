using System;
using NATTunnel;

// Usage: .\NATTest.exe sync.milesthenerd.net:6510
string endpoint = args[0];

var probe = await MeshNode.ProbeNetworkAsync(endpoint);

if (!probe.MediationReachable)
{
    Console.WriteLine($"Couldn't reach mediation: {probe.ErrorMessage}");
    return;
}

// The probe tests both address families independently. Show whichever it determined:
// a machine can be Symmetric on IPv4 but open on IPv6 (or have no IPv6 at all).
string natLine = probe.NatTypeV6.HasValue
    ? $"NAT type: IPv4 {probe.NatType}, IPv6 {probe.NatTypeV6.Value}"
    : $"NAT type: {probe.NatType} (no usable IPv6)";
Console.WriteLine($"{natLine} on {probe.LocalIP}");

if (probe.LikelyNeedsRelay)
    Console.WriteLine("Symmetric on every reachable family — you'll connect via relay (higher latency).");
else if (probe.NatType == NATType.Symmetric && probe.NatTypeV6.HasValue && probe.NatTypeV6.Value != NATType.Symmetric)
    Console.WriteLine("Symmetric on IPv4 but not on IPv6 — direct P2P should work over IPv6.");
else
    Console.WriteLine("Direct P2P should work.");