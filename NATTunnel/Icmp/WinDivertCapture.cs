using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace NATTunnel.Icmp;

/// <summary>
/// Windows ICMP capture via the WinDivert WFP driver — a driver-installed-once alternative to a raw socket,
/// which the OS never delivers inbound type-8 echo requests to.
///
/// Opens a NETWORK-layer WinDivert handle with the filter <c>inbound and icmp and ip.SrcAddr == PEER</c> in
/// SNIFF mode — matching packets are copied and left in the stack, then parsed and handed to the transport.
/// WinDivert requires Administrator to load the driver (once); the daemon runs privileged already, and an
/// embedded integrator installs the driver via their own installer.
///
/// <see cref="IsAvailable"/> is false if the driver is missing or the open fails — the engine then falls
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

        // MUST use SNIFF (copy-and-leave), not divert — with both peers on divert, the channel goes one-way.
        // MUST NOT add WINDIVERT_FLAG_RECV_ONLY alongside SNIFF — that combination delivers nothing at all.
        //
        // UNPRIVILEGED: opening with flags:0 asks the driver to load, which needs Administrator. A non-elevated
        // process must instead attach to an ALREADY-INSTALLED persistent service with NO_INSTALL — see
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
            // Distinct from a driver-load failure — this means the native files aren't deployed.
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                $"[ICMP][windivert] WinDivert.dll not found next to {AppContext.BaseDirectory} — " +
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
            // Distinguish "not elevated + service not installed" from a generic open failure — they need
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

            // Deliver to the transport. Nothing to re-inject in SNIFF mode — the original packet was never
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
