using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Net;
using System.Net.Sockets;

namespace NATTunnel;

/// <summary>
/// P/Invoke bindings for WireGuard-NT (wireguard.dll). Windows-only.
/// Based on: https://git.zx2c4.com/wireguard-nt/about/
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WireGuardNTAPI
{
    // Constants
    public const int WIREGUARD_KEY_LENGTH = 32;

    // Interface flags
    public const uint WIREGUARD_INTERFACE_HAS_PUBLIC_KEY = 1 << 0;
    public const uint WIREGUARD_INTERFACE_HAS_PRIVATE_KEY = 1 << 1;
    public const uint WIREGUARD_INTERFACE_HAS_LISTEN_PORT = 1 << 2;
    public const uint WIREGUARD_INTERFACE_REPLACE_PEERS = 1 << 3;

    // Peer flags
    public const uint WIREGUARD_PEER_HAS_PUBLIC_KEY = 1 << 0;
    public const uint WIREGUARD_PEER_HAS_PRESHARED_KEY = 1 << 1;
    public const uint WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2;
    public const uint WIREGUARD_PEER_HAS_ENDPOINT = 1 << 3;
    public const uint WIREGUARD_PEER_REPLACE_ALLOWED_IPS = 1 << 4;
    public const uint WIREGUARD_PEER_REMOVE = 1 << 5;
    public const uint WIREGUARD_PEER_UPDATE_ONLY = 1 << 6;

    // Adapter states
    public enum WIREGUARD_ADAPTER_STATE
    {
        WIREGUARD_ADAPTER_STATE_DOWN = 0,
        WIREGUARD_ADAPTER_STATE_UP = 1
    }

    // Structures
    // Based on: https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h
    // typedef struct _WIREGUARD_INTERFACE
    // {
    //     WIREGUARD_INTERFACE_FLAG Flags;
    //     WORD ListenPort;
    //     BYTE PrivateKey[WIREGUARD_KEY_LENGTH];
    //     BYTE PublicKey[WIREGUARD_KEY_LENGTH];
    //     DWORD PeersCount;
    // } WIREGUARD_INTERFACE;
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct WIREGUARD_INTERFACE
    {
        public uint Flags;               // WIREGUARD_INTERFACE_FLAG (4 bytes)
        public ushort ListenPort;        // WORD (2 bytes)
        public fixed byte PrivateKey[32]; // BYTE[32] - inline array
        public fixed byte PublicKey[32];  // BYTE[32] - inline array
        public uint PeersCount;          // DWORD (4 bytes)
        // Total: 4 + 2 + 32 + 32 + 4 = 74 bytes (no padding)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WIREGUARD_PEER
    {
        public uint Flags;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
        public byte[] PublicKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WIREGUARD_KEY_LENGTH)]
        public byte[] PresharedKey;
        public ushort PersistentKeepalive;
        public SOCKADDR_INET Endpoint;
        public ulong TxBytes;
        public ulong RxBytes;
        public ulong LastHandshake;
        public uint AllowedIPsCount;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SOCKADDR_INET
    {
        [FieldOffset(0)]
        public ushort si_family;
        [FieldOffset(0)]
        public SOCKADDR_IN Ipv4;
        [FieldOffset(0)]
        public SOCKADDR_IN6 Ipv6;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKADDR_IN
    {
        public ushort sin_family;  // AF_INET = 2
        public ushort sin_port;    // Big-endian port
        public uint sin_addr;      // Big-endian IPv4 address
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKADDR_IN6
    {
        public ushort sin6_family;  // AF_INET6 = 23
        public ushort sin6_port;    // Big-endian port
        public uint sin6_flowinfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] sin6_addr;    // IPv6 address
        public uint sin6_scope_id;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct WIREGUARD_ALLOWED_IP
    {
        [FieldOffset(0)]
        public AddressFamily AddressFamily;
        [FieldOffset(4)]
        public uint V4;  // IPv4 address in network byte order
        [FieldOffset(4)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] V6;  // IPv6 address
        [FieldOffset(20)]
        public byte Cidr;
    }

    // P/Invoke declarations
    [DllImport("wireguard.dll", EntryPoint = "WireGuardCreateAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr WireGuardCreateAdapter(string name, string tunnelType, ref Guid requestedGUID);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardOpenAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr WireGuardOpenAdapter(string name);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardCloseAdapter", CallingConvention = CallingConvention.StdCall)]
    public static extern void WireGuardCloseAdapter(IntPtr adapter);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardGetAdapterLUID", CallingConvention = CallingConvention.StdCall)]
    public static extern void WireGuardGetAdapterLUID(IntPtr adapter, out ulong luid);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardSetAdapterState", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern bool WireGuardSetAdapterState(IntPtr adapter, WIREGUARD_ADAPTER_STATE state);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardGetAdapterState", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern bool WireGuardGetAdapterState(IntPtr adapter, out WIREGUARD_ADAPTER_STATE state);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardSetConfiguration", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
    public static extern bool WireGuardSetConfiguration(IntPtr adapter, IntPtr config, uint bytes);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardGetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern bool WireGuardGetConfiguration(IntPtr adapter, IntPtr config, ref uint bytes);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardGetRunningDriverVersion", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern uint WireGuardGetRunningDriverVersion();

    // Helper to convert IPEndPoint to SOCKADDR_INET
    public static SOCKADDR_INET EndPointToSockAddr(IPEndPoint endpoint)
    {
        var sockAddr = new SOCKADDR_INET();

        if (endpoint.AddressFamily == AddressFamily.InterNetwork)
        {
            sockAddr.Ipv4 = new SOCKADDR_IN
            {
                sin_family = 2, // AF_INET
                sin_port = (ushort)IPAddress.HostToNetworkOrder((short)endpoint.Port),
                sin_addr = (uint)IPAddress.HostToNetworkOrder(BitConverter.ToInt32(endpoint.Address.GetAddressBytes(), 0)),
                sin_zero = new byte[8]
            };
        }
        else if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            sockAddr.Ipv6 = new SOCKADDR_IN6
            {
                sin6_family = 23, // AF_INET6
                sin6_port = (ushort)IPAddress.HostToNetworkOrder((short)endpoint.Port),
                sin6_flowinfo = 0,
                sin6_addr = endpoint.Address.GetAddressBytes(),
                sin6_scope_id = 0
            };
        }

        return sockAddr;
    }

    // Helper to convert IPAddress to WIREGUARD_ALLOWED_IP
    public static WIREGUARD_ALLOWED_IP IPAddressToAllowedIP(IPAddress address, int cidr)
    {
        var allowedIP = new WIREGUARD_ALLOWED_IP
        {
            AddressFamily = address.AddressFamily,
            Cidr = (byte)cidr
        };

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            allowedIP.V4 = (uint)IPAddress.HostToNetworkOrder(BitConverter.ToInt32(address.GetAddressBytes(), 0));
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            allowedIP.V6 = address.GetAddressBytes();
        }

        return allowedIP;
    }
}
