using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace NATTunnel.Icmp;

/// <summary>
/// Windows ICMP capture via the WinDivert WFP driver: a driver-installed-once alternative to a raw socket,
/// which the OS never delivers inbound type-8 echo requests to.
///
/// Opens a NETWORK-layer WinDivert handle with the filter <c>inbound and icmp and ip.SrcAddr == PEER</c> in
/// SNIFF mode; matching packets are copied and left in the stack, then parsed and handed to the transport.
/// WinDivert requires Administrator to load the driver (once); the daemon runs privileged already, and an
/// embedded integrator installs the driver via their own installer.
///
/// <see cref="IsAvailable"/> is false if the driver is missing or the open fails: the engine then falls
/// through to the next connection tier.
/// </summary>
internal sealed class WinDivertCapture : IIcmpCapture
{
    private IntPtr _handle = WinDivertNative.INVALID_HANDLE;
    private Thread _recvThread;
    private volatile bool _stopped;
    private IPAddress _peer = IPAddress.None;
    private IcmpReceiveHandler _onIcmp;
    private bool _available;

    public bool IsAvailable => _available;

    public WinDivertCapture ActiveWinDivert() => _available ? this : null;

    public void Start(IPAddress peer, IPAddress localSource, IcmpReceiveHandler onIcmp)
    {
        if (_recvThread != null) throw new InvalidOperationException("WinDivertCapture already started.");
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));
        _onIcmp = onIcmp ?? throw new ArgumentNullException(nameof(onIcmp));

        // WinDivert is IPv4/IPv6-capable but our filter + parse below is written for IPv4 ICMP (the punch's
        // primary path). IPv6 ICMPv6 capture is a later extension; for now report unavailable on v6 so the
        // engine falls through cleanly rather than mis-parsing.
        if (peer.AddressFamily != AddressFamily.InterNetwork)
        {
            _available = false;
            return;
        }

        // Filter: inbound ICMP from exactly this peer. Scoping to the peer keeps collateral (packets we must
        // re-inject) near zero. WinDivert filter language uses ip.SrcAddr and the icmp pseudo-protocol.
        string filter = $"inbound and icmp and ip.SrcAddr == {peer}";

        // MUST use SNIFF (copy-and-leave), not divert; with both peers on divert, the channel goes one-way.
        // MUST NOT add WINDIVERT_FLAG_RECV_ONLY alongside SNIFF; that combination delivers nothing at all.
        //
        // UNPRIVILEGED: opening with flags:0 asks the driver to load, which needs Administrator. A non-elevated
        // process must instead attach to an ALREADY-INSTALLED persistent service with NO_INSTALL; see
        // WinDivertServiceInstaller (run once, elevated, via tools/IcmpServiceInstaller). Try the plain open
        // first when elevated; otherwise go straight to NO_INSTALL, and fall back to it either way so an
        // elevated process on a machine that already has the service still works.
        bool elevated = WinDivertServiceInstaller.IsElevated();
        try
        {
            const ulong sniff = WinDivertNative.WINDIVERT_FLAG_SNIFF;
            if (elevated)
                _handle = WinDivertNative.WinDivertOpen(
                    filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, priority: 0, flags: sniff);

            if (!elevated || _handle == WinDivertNative.INVALID_HANDLE || _handle == IntPtr.Zero)
            {
                _handle = WinDivertNative.WinDivertOpen(
                    filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, priority: 0,
                    flags: sniff | WinDivertNative.WINDIVERT_FLAG_NO_INSTALL);
                if (_handle != WinDivertNative.INVALID_HANDLE && _handle != IntPtr.Zero)
                    NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                        $"[ICMP][windivert] opened via NO_INSTALL against the existing service (elevated={elevated})");
            }
        }
        catch (DllNotFoundException)
        {
            // Distinct from a driver-load failure: this means the native files aren't deployed.
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                $"[ICMP][windivert] WinDivert.dll not found next to {AppContext.BaseDirectory}: " +
                "WinDivert.dll and WinDivert64.sys must sit beside the running executable.");
            _available = false;
            return;
        }
        catch (Exception ex)
        {
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][windivert] open threw: {ex.GetType().Name}: {ex.Message}");
            _available = false;
            return;
        }

        if (_handle == WinDivertNative.INVALID_HANDLE || _handle == IntPtr.Zero)
        {
            // Distinguish "not elevated + service not installed" from a generic open failure; they need
            // different fixes.
            int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            if (!elevated && !WinDivertServiceInstaller.IsInstalled())
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    "[ICMP][windivert] unavailable: process is not elevated and the WinDivert service is not installed. " +
                    "Run nattunnel-icmp-service.exe install once (elevated) to enable the unprivileged ICMP path.");
            else
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][windivert] WinDivertOpen failed (elevated={elevated}, serviceInstalled={WinDivertServiceInstaller.IsInstalled()}, lastError={err})");
            _available = false;
            return;
        }

        _available = true;
        _recvThread = new Thread(RecvLoop) { IsBackground = true, Name = "IcmpWinDivertCapture" };
        _recvThread.Start();
    }

    /// <summary>
    /// Inject an ICMP packet via the WinDivert handle instead of a raw socket. Raw sockets are admin-only on
    /// Windows, so this is the only send path available to an unprivileged host (given the device DACL from
    /// WinDivertServiceInstaller). We build the IPv4 header ourselves since injection bypasses the stack;
    /// WinDivertHelperCalcChecksums fills in both checksums.
    ///
    /// Returns false if the handle is closed or the injection is rejected, so the caller can fall back.
    /// </summary>
    public bool SendIcmp(IPAddress src, IPAddress dst, byte type, ushort id, ushort seq, ReadOnlySpan<byte> payload)
    {
        var h = _handle;
        if (h == WinDivertNative.INVALID_HANDLE || h == IntPtr.Zero) return false;

        int icmpLen = 8 + payload.Length;
        int total = 20 + icmpLen;
        var pkt = new byte[total];

        // IPv4 header. Checksum (10-11) is left zero for the helper to fill.
        pkt[0] = 0x45;                                  // version 4, IHL 5
        pkt[2] = (byte)(total >> 8); pkt[3] = (byte)total;
        pkt[8] = 64;                                    // TTL
        pkt[9] = 1;                                     // protocol ICMP
        src.GetAddressBytes().CopyTo(pkt, 12);
        dst.GetAddressBytes().CopyTo(pkt, 16);

        // ICMP header + payload. Checksum (22-23) likewise left for the helper.
        pkt[20] = type;
        pkt[24] = (byte)(id >> 8); pkt[25] = (byte)id;
        pkt[26] = (byte)(seq >> 8); pkt[27] = (byte)seq;
        payload.CopyTo(new Span<byte>(pkt, 28, payload.Length));

        // IfIdx/SubIfIdx are deliberately left ZERO. Injecting outbound with an explicit interface index puts the
        // packet on the wire past the point where the host applies NAT, so it leaves carrying our private source
        // address and dies at the first upstream hop. Zero lets the stack route (and translate) it normally,
        // which is what a symmetric-NAT peer must see.
        var addr = new WinDivertNative.WinDivertAddress { Outbound = true };
        try
        {
            if (!WinDivertNative.WinDivertHelperCalcChecksums(pkt, (uint)total, IntPtr.Zero, 0))
            {
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][windivert] CalcChecksums failed for type={type} len={total} err={Marshal.GetLastWin32Error()}");
                return false;
            }
            if (!WinDivertNative.WinDivertSend(h, pkt, (uint)total, out _, ref addr))
            {
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][windivert] Send failed for type={type} id={id} seq={seq} len={total} err={Marshal.GetLastWin32Error()}");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][windivert] Send threw: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private void RecvLoop()
    {
        var packet = new byte[65535];
        var addr = new WinDivertNative.WinDivertAddress();

        while (!_stopped)
        {
            uint recvLen;
            bool ok;
            try { ok = WinDivertNative.WinDivertRecv(_handle, packet, (uint)packet.Length, out recvLen, ref addr); }
            catch (ObjectDisposedException) { break; }
            catch { continue; }
            if (!ok) continue;

            if (recvLen < 20) continue; // need at least an IPv4 header

            // Parse the IPv4 header to locate the ICMP header. Our filter guarantees this is inbound ICMP
            // from the peer, but we re-derive the offsets defensively.
            int ihl = (packet[0] & 0x0F) * 4;
            if (recvLen < ihl + 8) continue; // too short to hold an ICMP header; in SNIFF mode just ignore it

            int icmpOff = ihl;
            byte type = packet[icmpOff];
            ushort id = (ushort)((packet[icmpOff + 4] << 8) | packet[icmpOff + 5]);
            ushort seq = (ushort)((packet[icmpOff + 6] << 8) | packet[icmpOff + 7]);
            int payloadOff = icmpOff + 8;
            int payloadLen = (int)recvLen - payloadOff;

            // Deliver to the transport. Nothing to re-inject in SNIFF mode: the original packet was never
            // removed from the stack, so the OS still processes it (and still auto-replies, which is what keeps
            // our own NAT mapping open; see the flags at the open site).
            try { _onIcmp(type, id, seq, new ReadOnlySpan<byte>(packet, payloadOff, payloadLen)); }
            catch { /* a bad handler must not kill the capture loop */ }
        }
    }

    public void Dispose()
    {
        _stopped = true;
        var h = _handle;
        _handle = WinDivertNative.INVALID_HANDLE;
        if (h != WinDivertNative.INVALID_HANDLE && h != IntPtr.Zero)
        {
            try { WinDivertNative.WinDivertClose(h); } catch { }
        }
        try { _recvThread?.Join(1500); } catch { }
        _recvThread = null;
    }
}
