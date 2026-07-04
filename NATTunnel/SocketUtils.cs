using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NATTunnel;

/// <summary>
/// Factory for the outer-transport UDP sockets. Creates dual-stack (IPv4 + IPv6) sockets when
/// the OS supports IPv6, falling back to IPv4-only otherwise. On a dual-stack socket, IPv4
/// senders appear as v4-mapped IPv6 (::ffff:a.b.c.d) — receive loops must pass source endpoints
/// through <see cref="EndpointUtils.Normalize(IPEndPoint)"/> before comparing or serializing.
/// </summary>
internal static class SocketUtils
{
    // https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_connreset-opcode-setting-i-t3
    private const int SIO_UDP_CONNRESET = -1744830452;

    /// <summary>
    /// Creates a UDP client bound to the given port (0 = ephemeral): dual-stack when IPv6 is
    /// available, IPv4-only otherwise. Applies the 128 KB receive buffer and the Windows
    /// SIO_UDP_CONNRESET fix (ICMP port-unreachable from a dead peer would otherwise fault
    /// subsequent Receive calls) that every outer socket needs.
    /// </summary>
    public static UdpClient CreateUdpClient(int port = 0)
    {
        UdpClient client;
        if (Socket.OSSupportsIPv6)
        {
            client = new UdpClient(AddressFamily.InterNetworkV6);
            client.Client.DualMode = true;
            client.Client.ReceiveBufferSize = 128000;
            client.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
        }
        else
        {
            client = new UdpClient();
            client.Client.ReceiveBufferSize = 128000;
            client.Client.Bind(new IPEndPoint(IPAddress.Any, port));
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            client.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);

        return client;
    }
}
