using System;
using NATTunnel;

// Usage: .\NATTest.exe sync.milesthenerd.net:6510
string endpoint = args[0];

var probe = await MeshNode.ProbeNetworkAsync(endpoint);
if (probe.LikelyNeedsRelay)
    Console.WriteLine("Symmetric NAT — you'll connect via relay (higher latency).");
else if (!probe.MediationReachable)
    Console.WriteLine($"Couldn't reach mediation: {probe.ErrorMessage}");
else
    Console.WriteLine($"NAT type: {probe.NatType} on {probe.LocalIP} — direct P2P should work.");