using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace NATTunnel.Icmp;

/// <summary>
/// Receives inbound ICMP via a plain raw socket. This is the proven Phase-1 backend:
///
///   • Linux — a raw IPPROTO_ICMP socket with CAP_NET_RAW receives inbound echo requests directly, no driver.
///   • Windows — the OS eats inbound echo REQUESTS, so a raw socket needs SIO_RCVALL (promiscuous, admin) to
///     see them. We enable it when possible; if it fails (non-admin), <see cref="IsAvailable"/> reflects that
///     the type-8 receive path is unusable and the engine should fall through to the next tier (Phase 2's
///     WinDivertCapture is the non-admin/driver answer there).
///
/// Lifted from the validated experiments/IcmpBandwidth probe, made instance-based and stripped of CLI concerns.
/// </summary>
internal sealed class RawSocketCapture : IIcmpCapture
{
    private const int SIO_RCVALL = unchecked((int)0x98000001);

    private Socket _recvSock;
    private Thread _recvThread;
    private volatile bool _stopped;
    private IPAddress _peer = IPAddress.None;
    private IcmpReceiveHandler _onIcmp;

    // Set during Start() to reflect whether we could actually establish a receive path (RCVALL on Windows).
    private bool _available = true;
    public bool IsAvailable => _available;

    public void Start(IPAddress peer, IPAddress localSource, IcmpReceiveHandler onIcmp)
    {
        if (_recvThread != null) throw new InvalidOperationException("RawSocketCapture already started.");
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));
        _onIcmp = onIcmp ?? throw new ArgumentNullException(nameof(onIcmp));

        var family = peer.AddressFamily == AddressFamily.InterNetworkV6
            ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        var proto = family == AddressFamily.InterNetworkV6 ? ProtocolType.IcmpV6 : ProtocolType.Icmp;

        try
        {
            _recvSock = new Socket(family, SocketType.Raw, proto);
            // Bind to the local source that routes to the peer. On Windows SIO_RCVALL REQUIRES a real bound
            // local IP (not Any); binding here also scopes capture to the correct interface on multi-homed hosts.
            var bindAddr = localSource != null && !localSource.Equals(IPAddress.Any)
                ? localSource
                : (family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
            _recvSock.Bind(new IPEndPoint(bindAddr, 0));
        }
        catch (SocketException)
        {
            // Can't even open/bind a raw socket → no capability (non-root Linux without cap, or blocked).
            _available = false;
            _recvSock?.Dispose();
            _recvSock = null;
            return;
        }

        // Windows: enable promiscuous capture so we see inbound echo REQUESTS the OS would otherwise eat.
        // Requires admin + a real bound local IP. On Linux this is unnecessary (raw socket delivers requests).
        if (OperatingSystem.IsWindows() && family == AddressFamily.InterNetwork
            && localSource != null && !localSource.Equals(IPAddress.Any))
        {
            try
            {
                _recvSock.IOControl(SIO_RCVALL, new byte[] { 1, 0, 0, 0 }, new byte[4]);
            }
            catch (SocketException)
            {
                // RCVALL failed (almost always: not admin). On Windows without it we cannot receive inbound
                // type-8 requests, so the ICMP transport is not usable via this backend. Mark unavailable.
                _available = false;
                _recvSock.Dispose();
                _recvSock = null;
                return;
            }
        }

        _recvSock.ReceiveTimeout = 1000;
        _recvThread = new Thread(RecvLoop) { IsBackground = true, Name = "IcmpRawCapture" };
        _recvThread.Start();
    }

    private void RecvLoop()
    {
        var buf = new byte[65535];
        EndPoint from = new IPEndPoint(
            _peer.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);

        while (!_stopped)
        {
            int n;
            try { n = _recvSock.ReceiveFrom(buf, ref from); }
            catch (SocketException) { continue; }   // ReceiveTimeout tick, or transient — loop
            catch (ObjectDisposedException) { break; }

            // Only deliver packets whose source is the peer we're punching.
            if (!((IPEndPoint)from).Address.Equals(_peer)) continue;

            // Raw IPv4 recv includes the IP header; skip it. (IPv6 raw sockets deliver ICMPv6 without the
            // IPv6 header, so ihl is 0 there.)
            int ihl = _peer.AddressFamily == AddressFamily.InterNetwork ? (buf[0] & 0x0F) * 4 : 0;
            if (n < ihl + 8) continue;

            byte type = buf[ihl];
            ushort id = (ushort)((buf[ihl + 4] << 8) | buf[ihl + 5]);
            ushort seq = (ushort)((buf[ihl + 6] << 8) | buf[ihl + 7]);
            int payloadOff = ihl + 8;
            int payloadLen = n - payloadOff;

            try { _onIcmp(type, id, seq, new ReadOnlySpan<byte>(buf, payloadOff, payloadLen)); }
            catch { /* a bad handler must not kill the capture loop */ }
        }
    }

    public void Dispose()
    {
        _stopped = true;
        try { _recvSock?.Dispose(); } catch { }
        _recvSock = null;
        try { _recvThread?.Join(1500); } catch { }
        _recvThread = null;
    }
}
