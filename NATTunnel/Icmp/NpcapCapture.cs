using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NATTunnel.Icmp;

/// <summary>
/// Receives inbound ICMP via Npcap (through SharpPcap/libpcap) — the UNPRIVILEGED Windows capture path.
///
/// Unlike WinDivert (whose device is admin-only at the driver level), Npcap installed WITHOUT the
/// "restrict to Administrators" option exposes a permissive device ACL, so a standard-user process can open a
/// capture handle. We do NOT bundle Npcap (its OEM redistribution license is expensive); instead this backend
/// is used only IF the user already has Npcap installed. That keeps us on the free side of Npcap's license
/// (the user's own ≤5-install free license covers their machine) and gives embedded/unprivileged hosts a
/// working ICMP path without a privileged helper.
///
/// Npcap is a passive SNIFFER (it doesn't divert), so the OS still auto-replies to the peer's echo requests.
/// That's harmless for our tagged punch protocol (the peer ignores the spurious replies) — the same way the
/// scapy-over-Npcap tests worked during research.
/// </summary>
internal sealed class NpcapCapture : IIcmpCapture
{
    private LibPcapLiveDevice _device;
    private IPAddress _peer = IPAddress.None;
    private IcmpReceiveHandler _onIcmp;
    private bool _available;
    private volatile bool _stopped;

    public bool IsAvailable => _available;

    /// <summary>
    /// Cheap check for whether Npcap/libpcap is present at all (so the factory can skip this backend fast when
    /// the user doesn't have Npcap). Does not open a device.
    /// </summary>
    public static bool IsNpcapPresent()
    {
        try { _ = LibPcapLiveDeviceList.Instance.Count; return true; }
        catch { return false; } // wpcap.dll missing / Npcap not installed
    }

    public void Start(IPAddress peer, IPAddress localSource, IcmpReceiveHandler onIcmp)
    {
        if (_device != null) throw new InvalidOperationException("NpcapCapture already started.");
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));
        _onIcmp = onIcmp ?? throw new ArgumentNullException(nameof(onIcmp));

        // IPv4 only for now (matches WinDivertCapture); v6 is a later extension.
        if (peer.AddressFamily != AddressFamily.InterNetwork) { _available = false; return; }

        LibPcapLiveDeviceList devices;
        try { devices = LibPcapLiveDeviceList.Instance; }
        catch { _available = false; return; } // Npcap not installed

        // Candidate ordering matters: the peer's ICMP arrives on the SPECIFIC adapter that owns the route to the
        // peer (localSource). Capturing any OTHER adapter — especially a virtual/Hyper-V/VMware switch that opens
        // fine but never sees WAN traffic — silently receives NOTHING (observed: Killer NIC failed to activate,
        // fallback "succeeded" on Hyper-V vEthernet → punch got no inbound → relay). So: try the localSource-
        // matched device FIRST, then ONLY other PHYSICAL adapters as fallback — never virtual ones. If nothing
        // real opens, fail unavailable (chain → RCVALL on the right iface, or relay floor) rather than capture a
        // useless virtual NIC.
        static bool IsVirtual(LibPcapLiveDevice d)
        {
            string s = ((d.Description ?? "") + " " + (d.Name ?? "")).ToLowerInvariant();
            return s.Contains("hyper-v") || s.Contains("virtual") || s.Contains("vmware") || s.Contains("vethernet") ||
                   s.Contains("loopback") || s.Contains("vbox") || s.Contains("tap") || s.Contains("tunnel") ||
                   s.Contains("wireguard") || s.Contains("wintun") || s.Contains("nt-560b6041");
        }

        var candidates = new System.Collections.Generic.List<LibPcapLiveDevice>();
        LibPcapLiveDevice match = null;
        foreach (var d in devices)
        {
            var addrs = d.Addresses?.Where(a => a.Addr?.ipAddress != null &&
                                                a.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork).ToList();
            if (addrs == null || addrs.Count == 0) continue;
            if (localSource != null && match == null && addrs.Any(a => a.Addr.ipAddress.Equals(localSource))) match = d;
            else if (!IsVirtual(d)) candidates.Add(d); // physical fallbacks only — virtual NICs can't see WAN ICMP
        }
        if (match != null) candidates.Insert(0, match); // the route-owning adapter is always the best candidate
        if (candidates.Count == 0)
        {
            NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, $"[ICMP][npcap] no usable physical IPv4 device (localSource={localSource}, devices={devices.Count}) — failing over (not capturing a virtual NIC)");
            _available = false;
            return;
        }

        foreach (var dev in candidates)
        {
            // Try PROMISCUOUS first, then NON-promiscuous. "Unable to activate the adapter (Generic)" on a NIC
            // that opened fine earlier is almost always a promiscuous-mode conflict: another capture (Wireshark)
            // holds the adapter promiscuous, or a stale handle from an unclean shutdown lingers. Killer NICs are
            // especially strict about a second promiscuous handle. We only need packets addressed to us + our BPF
            // src filter, so NON-promiscuous works fine and sidesteps the conflict.
            foreach (var mode in new[] { DeviceModes.Promiscuous, DeviceModes.None })
            {
                try
                {
                    // ★ LATENCY-CRITICAL, AND UNRESOLVED — READ BEFORE CHANGING ★
                    //
                    // libpcap BATCHES captured packets: it hands them up only when the kernel buffer fills or the
                    // read timeout expires. Our packets are tiny (~50B at ~60/s) so the buffer never fills, and every
                    // inbound packet waits out the timeout. That is measurably most of our latency: transport RTT
                    // (`[ICMP][rtt]`, a raw request→reply with no WireGuard in the path) sat at a rock-steady
                    // ~800-900ms while the send path was proven instant (~0.05ms per SendTo) and the real network
                    // RTT is ~8-40ms.
                    //
                    // The out-of-band probe (experiments/NpcapLatencyProbe — same Npcap, same SharpPcap 6.3.1, same
                    // StartCapture() path) measured send→capture-delivered latency against a host with a real ~8ms
                    // RTT, including a config that reproduces this transport's callback workload (24 synchronous raw
                    // sends inside OnPacketArrival, like the punch-time ACK hammer):
                    //     ReadTimeout=1000                          → delivered 56/56, avg 520ms  ← this config
                    //     ReadTimeout=100 + Immediate               → delivered 56/56, avg   9ms
                    //     ReadTimeout=100 + Immediate + sends-in-cb → delivered 56/56, avg   9ms
                    //     ReadTimeout=1000 + sends-in-cb            → delivered 56/56, avg 518ms
                    //
                    // This was briefly reverted to a bare ReadTimeout=1000 on the theory that Immediate mode was
                    // causing a post-handshake silence. That theory was WRONG and the next run disproved it: the
                    // silence persisted unchanged with ReadTimeout=1000. The real cause was in the transport — data
                    // was being sent as unsolicited echo REQUESTS, which a symmetric NAT drops (see IcmpTransport's
                    // matched-reply notes). The revert then sat here unnoticed, costing ~520ms of capture-delivery
                    // delay on BOTH peers in every subsequent run.
                    //
                    // Immediate mode is correct and measured: it delivers every packet at ~9ms (≈ the wire RTT),
                    // including under a callback that does 24 synchronous raw sends — the transport's own workload.
                    // The read timeout is now only a backstop for a platform that ignores immediate mode.
                    dev.Open(new DeviceConfiguration { Mode = mode, ReadTimeout = 100, Immediate = true });
                    dev.Filter = $"icmp and src host {_peer}";
                    dev.OnPacketArrival += OnPacketArrival;
                    dev.StartCapture();
                    _device = dev;
                    _available = true;
                    NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][npcap] opened '{dev.Description ?? dev.Name}' ({mode}) filter='icmp and src host {_peer}'");
                    return;
                }
                catch (Exception ex)
                {
                    NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][npcap] open failed on '{dev.Description ?? dev.Name}' ({mode}): {ex.GetType().Name}: {ex.Message}");
                    try { if (dev.Opened) dev.Close(); } catch { }
                }
            }
        }

        NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, $"[ICMP][npcap] ALL {candidates.Count} IPv4 devices failed to open — falling through");
        _available = false;
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        if (_stopped) return;
        try
        {
            var raw = e.GetPacket();
            var data = raw.Data;
            // data is a full link-layer frame. Parse: Ethernet(14) + IPv4(ihl*4) + ICMP.
            // Npcap on Ethernet delivers Ethernet frames; on some adapters (e.g. loopback) the link layer
            // differs, but for real NIC punch traffic it's Ethernet. Use the link-layer type to find the offset.
            int l2 = raw.LinkLayerType == PacketDotNet.LinkLayers.Ethernet ? 14 : 0;
            if (data.Length < l2 + 20) return;
            int ipOff = l2;
            // sanity: IPv4 version nibble
            if ((data[ipOff] >> 4) != 4) return;
            int ihl = (data[ipOff] & 0x0F) * 4;
            int icmpOff = ipOff + ihl;
            if (data.Length < icmpOff + 8) return;

            byte type = data[icmpOff];
            ushort id = (ushort)((data[icmpOff + 4] << 8) | data[icmpOff + 5]);
            ushort seq = (ushort)((data[icmpOff + 6] << 8) | data[icmpOff + 7]);
            int payloadOff = icmpOff + 8;
            int payloadLen = data.Length - payloadOff;
            if (payloadLen < 0) return;

            _onIcmp(type, id, seq, new ReadOnlySpan<byte>(data, payloadOff, payloadLen));
        }
        catch { /* a bad packet / handler must not kill capture */ }
    }

    public void Dispose()
    {
        _stopped = true;
        var d = _device;
        _device = null;
        if (d != null)
        {
            try { d.OnPacketArrival -= OnPacketArrival; } catch { }
            try { if (d.Started) d.StopCapture(); } catch { }
            try { d.Dispose(); } catch { }
        }
    }
}
