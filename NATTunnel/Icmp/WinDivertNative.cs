using System;
using System.Runtime.InteropServices;

namespace NATTunnel.Icmp;

/// <summary>
/// Minimal P/Invoke bindings for WinDivert (the WFP-based capture/divert driver) — only the surface the ICMP
/// transport's receive path needs: open a NETWORK-layer handle with an inbound-ICMP filter, receive packets,
/// re-inject them, and close. We do NOT bind the full WinDivert API.
///
/// WinDivert.dll (native) + WinDivert64.sys (signed driver) must sit next to the executable. The driver loads
/// on demand at <see cref="WinDivertOpen"/> and needs Administrator (or the daemon's LocalSystem) to load.
///
/// Reference: https://reqrypt.org/windivert-doc.html
/// </summary>
internal static class WinDivertNative
{
    private const string DLL = "WinDivert.dll";

    // WINDIVERT_LAYER
    public const short WINDIVERT_LAYER_NETWORK = 0;

    // WINDIVERT_PARAM / flags (WinDivertOpen flags)
    public const ulong WINDIVERT_FLAG_SNIFF = 0x0001;  // copy-and-divert (leave original in stack)
    public const ulong WINDIVERT_FLAG_DROP = 0x0002;   // drop matching packets, don't read them
    public const ulong WINDIVERT_FLAG_RECV_ONLY = 0x0008;
    public const ulong WINDIVERT_FLAG_NO_INSTALL = 0x0010;
    public const ulong WINDIVERT_FLAG_FRAGMENTS = 0x0020;

    /// <summary>
    /// The WINDIVERT_ADDRESS struct is 64 bytes. We only read/write the Outbound direction bit and the
    /// interface indices (needed to re-inject inbound). Layout per windivert.h:
    ///   INT64  Timestamp;
    ///   UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1,
    ///          IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:12;
    ///   UINT32 Reserved2;
    ///   union { WINDIVERT_DATA_NETWORK Network; ... } (rest, 40 bytes)
    /// We model it as a blittable 64-byte block and poke the bitfield/interface fields by offset.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 64)]
    public struct WinDivertAddress
    {
        public long Timestamp;      // offset 0
        public uint Flags;          // offset 8  (Layer:8|Event:8|Sniffed:1|Outbound:1|Loopback:1|Impostor:1|IPv6:1|...)
        public uint Reserved2;      // offset 12
        public uint IfIdx;          // offset 16 (WINDIVERT_DATA_NETWORK.IfIdx)
        public uint SubIfIdx;       // offset 20 (WINDIVERT_DATA_NETWORK.SubIfIdx)
        // remaining 40 bytes are other union data we don't touch (struct Size=64 reserves them)

        // Bit accessors for the Flags word. Layer is bits 0-7, Event 8-15, then single flag bits.
        private const int OUTBOUND_BIT = 17; // Layer(8) + Event(8) + Sniffed(1) = bit 17 is Outbound
        public bool Outbound
        {
            get => (Flags & (1u << OUTBOUND_BIT)) != 0;
            set { if (value) Flags |= (1u << OUTBOUND_BIT); else Flags &= ~(1u << OUTBOUND_BIT); }
        }
    }

    /// <summary>Opens a WinDivert handle. Returns INVALID_HANDLE_VALUE (-1) on failure; check GetLastError.</summary>
    [DllImport(DLL, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        short layer, short priority, ulong flags);

    /// <summary>Receives one matching packet into pPacket. Returns false on failure.</summary>
    [DllImport(DLL, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint recvLen, ref WinDivertAddress addr);

    /// <summary>Re-injects a packet. For inbound, set addr.Outbound=false + valid IfIdx/SubIfIdx.</summary>
    [DllImport(DLL, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle, byte[] pPacket, uint packetLen, out uint sendLen, ref WinDivertAddress addr);

    /// <summary>Sets a handle parameter (e.g. queue length/time). Optional for us.</summary>
    [DllImport(DLL, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

    [DllImport(DLL, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    public static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);
}
