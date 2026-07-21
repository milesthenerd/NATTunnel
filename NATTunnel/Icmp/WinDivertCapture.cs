using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace NATTunnel.Icmp;

/// <summary>
/// Windows ICMP capture via the WinDivert WFP driver — the non-admin-at-runtime (driver-installed-once) answer
/// to "the OS eats inbound type-8 echo requests before a raw socket sees them".
///
/// Opens a NETWORK-layer WinDivert handle with the filter <c>inbound and icmp and ip.SrcAddr == PEER</c> in
/// DEFAULT (divert) mode — matching packets are REMOVED from the stack, so the OS never auto-replies to the
/// peer's punch requests (cleaner than SIO_RCVALL, which only copies). We parse the ICMP fields and hand them
/// to the transport. WinDivert requires Administrator to LOAD the driver (once); the daemon runs privileged
/// already, and an embedded integrator installs the driver via their own installer.
///
/// Availability: <see cref="IsAvailable"/> is false if the WinDivert.dll/driver is missing or the open fails
/// (no admin, driver not signed/loadable) — the engine then falls through to the next connection tier.
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

        try
        {
            _handle = WinDivertNative.WinDivertOpen(
                filter,
                WinDivertNative.WINDIVERT_LAYER_NETWORK,
                priority: 0,
                flags: 0); // default = divert (drop-and-divert): removes the packet so the OS won't auto-reply
        }
        catch (DllNotFoundException)
        {
            _available = false; // WinDivert.dll not present next to the exe
            return;
        }
        catch (Exception)
        {
            _available = false;
            return;
        }

        if (_handle == WinDivertNative.INVALID_HANDLE || _handle == IntPtr.Zero)
        {
            // Open failed — most commonly ERROR_ACCESS_DENIED (not admin) or driver not loadable.
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
            if (recvLen < ihl + 8) { Reinject(packet, recvLen, ref addr); continue; }

            int icmpOff = ihl;
            byte type = packet[icmpOff];
            ushort id = (ushort)((packet[icmpOff + 4] << 8) | packet[icmpOff + 5]);
            ushort seq = (ushort)((packet[icmpOff + 6] << 8) | packet[icmpOff + 7]);
            int payloadOff = icmpOff + 8;
            int payloadLen = (int)recvLen - payloadOff;

            // Deliver to the transport. We do NOT re-inject: this is our peer's punch/data traffic, and
            // diverting it (not re-injecting) is exactly what stops the OS ICMP handler from auto-replying to
            // the peer's echo requests. If a future need arises to be transparent to other apps, gate on a
            // tag check here and re-inject non-ours.
            try { _onIcmp(type, id, seq, new ReadOnlySpan<byte>(packet, payloadOff, payloadLen)); }
            catch { /* a bad handler must not kill the capture loop */ }
        }
    }

    /// <summary>Put a packet we captured but don't want back into the stack (inbound direction).</summary>
    private void Reinject(byte[] packet, uint len, ref WinDivertNative.WinDivertAddress addr)
    {
        try { WinDivertNative.WinDivertSend(_handle, packet, len, out _, ref addr); }
        catch { }
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
