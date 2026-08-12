using System;
using System.Net;

namespace NATTunnel.Icmp;

/// <summary>
/// Abstracts the platform-specific way of RECEIVING inbound ICMP echo packets from a peer.
///
/// This is the seam the transport tier's hardest platform dependency lives behind. Receiving inbound
/// ICMP type-8 echo REQUESTS on Windows requires capturing below the OS ICMP handler (which otherwise
/// eats them and auto-replies) — a kernel capture driver (WinDivert). On Linux a plain raw socket with
/// CAP_NET_RAW receives them directly, no driver.
///
/// Phase 1 ships only <see cref="RawSocketCapture"/> (the Linux-native / Windows-admin-RCVALL path lifted
/// from the proven CLI probe). Phase 2 adds a WinDivert-backed capture for the Windows driver path.
/// The transport depends only on this interface, so the capture strategy is swappable without touching the
/// punch logic.
/// </summary>
internal interface IIcmpCapture : IDisposable
{
    /// <summary>
    /// True if this capture mechanism can actually receive inbound ICMP on the current machine right now
    /// (driver present/loadable, capability granted, etc). If false, the ICMP transport is not usable and
    /// the engine must fall through to the next connection tier. Cheap to call; may probe on first use.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// The active WinDivert backend if this capture is (or wraps) one, else null. WinDivert can INJECT as well
    /// as capture, which is the only send path for an unprivileged Windows host: raw sockets are admin-only.
    /// </summary>
    WinDivertCapture ActiveWinDivert() => null;

    /// <summary>
    /// Begin capturing inbound ICMP from <paramref name="peer"/> destined to this host. The capture layer
    /// binds/opens whatever it needs (raw socket, driver handle) and, on each matching inbound ICMP packet,
    /// invokes <paramref name="onIcmp"/> with the parsed fields.
    ///
    /// The callback runs on the capture layer's own receive thread. It must be fast and non-blocking; the
    /// transport marshals real work off it.
    /// </summary>
    /// <param name="peer">Only inbound ICMP whose source IP equals this peer is delivered to the callback.</param>
    /// <param name="localSource">
    /// The local source address that routes toward the peer (resolved by the transport). Some capture
    /// backends bind to this; others ignore it.
    /// </param>
    /// <param name="onIcmp">Invoked per matching inbound ICMP packet.</param>
    void Start(IPAddress peer, IPAddress localSource, IcmpReceiveHandler onIcmp);
}

/// <summary>
/// Delivered for each inbound ICMP packet the capture layer surfaces. Fields are the already-parsed ICMP
/// header + payload (the IP header has been stripped). <paramref name="payload"/> is a slice valid only for
/// the duration of the call — copy anything you keep.
/// </summary>
/// <param name="type">ICMP type (8 = echo request, 0 = echo reply).</param>
/// <param name="id">16-bit ICMP identifier (the birthday-collision space).</param>
/// <param name="seq">16-bit ICMP sequence.</param>
/// <param name="payload">ICMP payload bytes (everything after the 8-byte ICMP header).</param>
internal delegate void IcmpReceiveHandler(byte type, ushort id, ushort seq, ReadOnlySpan<byte> payload);
