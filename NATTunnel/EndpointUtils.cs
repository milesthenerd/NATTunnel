using System.Net;
using System.Net.Sockets;

namespace NATTunnel;

/// <summary>
/// Helpers for parsing and formatting <c>host:port</c> endpoint strings in a way that works
/// for both IPv4 (<c>1.2.3.4:6510</c>) and IPv6 (<c>[2001:db8::1]:6510</c>) endpoints.
/// All endpoint strings that cross the wire or get compared should go through these helpers
/// instead of Split(':')/LastIndexOf(':'), which misparse IPv6 literals.
/// </summary>
internal static class EndpointUtils
{
    /// <summary>
    /// Splits an endpoint string into host and port. Accepts IPv4 (<c>a.b.c.d:port</c>),
    /// bracketed IPv6 (<c>[addr]:port</c>), and unbracketed IPv6-with-trailing-port
    /// (<c>addr:port</c> — the last colon is taken as the separator). Returned host has
    /// no brackets and v4-mapped addresses (<c>::ffff:a.b.c.d</c>) are normalized to plain IPv4.
    /// </summary>
    public static bool TrySplitHostPort(string endpoint, out string host, out int port)
    {
        host = null;
        port = 0;
        if (string.IsNullOrEmpty(endpoint)) return false;

        string hostPart;
        string portPart;
        if (endpoint[0] == '[')
        {
            int close = endpoint.IndexOf(']');
            if (close < 0 || close + 1 >= endpoint.Length || endpoint[close + 1] != ':') return false;
            hostPart = endpoint.Substring(1, close - 1);
            portPart = endpoint.Substring(close + 2);
        }
        else
        {
            int lastColon = endpoint.LastIndexOf(':');
            if (lastColon <= 0 || lastColon == endpoint.Length - 1) return false;
            hostPart = endpoint.Substring(0, lastColon);
            portPart = endpoint.Substring(lastColon + 1);
        }

        if (!int.TryParse(portPart, out port) || port < 0 || port > 65535) return false;
        host = NormalizeHost(hostPart);
        return host != null;
    }

    /// <summary>
    /// Splits a user-supplied "host[:port]" config string, applying <paramref name="defaultPort"/>
    /// when no port is present. Follows the standard convention that an unbracketed string with
    /// multiple colons is a bare IPv6 literal ("2001:db8::1"), not host:port — IPv6 literals must
    /// use brackets ("[2001:db8::1]:6510") to carry a port. Host may be a DNS name.
    /// </summary>
    public static bool TrySplitHostPortWithDefault(string input, int defaultPort, out string host, out int port)
    {
        host = null;
        port = defaultPort;
        if (string.IsNullOrWhiteSpace(input)) return false;
        input = input.Trim();

        if (input[0] == '[')
        {
            int close = input.IndexOf(']');
            if (close < 0) return false;
            host = NormalizeHost(input.Substring(1, close - 1));
            if (close == input.Length - 1) return host != null;
            if (input[close + 1] != ':') return false;
            return host != null && int.TryParse(input.Substring(close + 2), out port) && port > 0 && port <= 65535;
        }

        int firstColon = input.IndexOf(':');
        if (firstColon < 0)
        {
            host = input;
            return true;
        }
        if (input.IndexOf(':', firstColon + 1) >= 0)
        {
            // Multiple colons, no brackets: bare IPv6 literal.
            host = NormalizeHost(input);
            return IPAddress.TryParse(input, out _);
        }
        host = input.Substring(0, firstColon);
        return host.Length > 0 && int.TryParse(input.Substring(firstColon + 1), out port) && port > 0 && port <= 65535;
    }

    /// <summary>
    /// The host portion of an endpoint string (normalized, no brackets), or null if unparseable.
    /// Use for public-IP equality comparisons instead of Split(':')[0].
    /// </summary>
    public static string GetHost(string endpoint)
    {
        return TrySplitHostPort(endpoint, out string host, out _) ? host : null;
    }

    /// <summary>
    /// True if the endpoint string's host is an IPv6 literal. Used to check that two peers'
    /// chosen endpoints are the same address family before introducing them — a v4 peer can't
    /// reach a v6 endpoint or vice versa. Returns false for v4 and for unparseable input.
    /// </summary>
    public static bool IsIPv6Endpoint(string endpoint)
    {
        string host = GetHost(endpoint);
        return host != null && IPAddress.TryParse(host, out IPAddress addr) &&
               addr.AddressFamily == AddressFamily.InterNetworkV6;
    }

    /// <summary>
    /// True if both endpoints are non-empty and belong to the same address family (both v4 or
    /// both v6). Two peers can only hole-punch to each other when their endpoints match family.
    /// </summary>
    public static bool SameFamily(string a, string b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        return IsIPv6Endpoint(a) == IsIPv6Endpoint(b);
    }

    /// <summary>
    /// Parses an endpoint string into an IPEndPoint (host must be an IP literal, not a DNS name).
    /// </summary>
    public static bool TryParseEndpoint(string endpoint, out IPEndPoint result)
    {
        result = null;
        if (!TrySplitHostPort(endpoint, out string host, out int port)) return false;
        if (!IPAddress.TryParse(host, out IPAddress addr)) return false;
        result = new IPEndPoint(Normalize(addr), port);
        return true;
    }

    /// <summary>
    /// Formats an address + port as an endpoint string: IPv6 gets brackets, IPv4 doesn't.
    /// V4-mapped IPv6 addresses are unwrapped to plain IPv4 first.
    /// </summary>
    public static string Format(IPAddress address, int port)
    {
        IPAddress normalized = Normalize(address);
        return normalized.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{normalized}]:{port}"
            : $"{normalized}:{port}";
    }

    /// <summary>
    /// Formats an IPEndPoint as an endpoint string, unwrapping v4-mapped addresses.
    /// </summary>
    public static string Format(IPEndPoint endpoint) => Format(endpoint.Address, endpoint.Port);

    /// <summary>
    /// Formats a host string + port as an endpoint string, bracketing the host if it's an
    /// IPv6 literal. Use instead of $"{host}:{port}" interpolation.
    /// </summary>
    public static string Format(string host, int port)
    {
        return IPAddress.TryParse(host, out IPAddress addr) ? Format(addr, port) : $"{host}:{port}";
    }

    /// <summary>
    /// Re-serializes an endpoint string into canonical form (normalized host, brackets only
    /// for IPv6) so string equality works regardless of the sender's formatting. Returns the
    /// input unchanged if it doesn't parse.
    /// </summary>
    public static string NormalizeEndpointString(string endpoint)
    {
        if (!TrySplitHostPort(endpoint, out string host, out int port)) return endpoint;
        return IPAddress.TryParse(host, out IPAddress addr) ? Format(addr, port) : $"{host}:{port}";
    }

    /// <summary>
    /// Unwraps a v4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form so endpoints
    /// received on a dual-stack socket compare equal to ones advertised as plain IPv4.
    /// </summary>
    public static IPAddress Normalize(IPAddress address)
    {
        if (address == null) return null;
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    /// <summary>
    /// Endpoint variant of <see cref="Normalize(IPAddress)"/>. Returns the same instance when
    /// no unwrapping is needed, so it's cheap to call on every received packet.
    /// </summary>
    public static IPEndPoint Normalize(IPEndPoint endpoint)
    {
        if (endpoint == null) return null;
        return endpoint.Address.IsIPv4MappedToIPv6
            ? new IPEndPoint(endpoint.Address.MapToIPv4(), endpoint.Port)
            : endpoint;
    }

    /// <summary>
    /// Normalizes a host string: strips brackets, unwraps v4-mapped IPv6, and canonicalizes
    /// IP literals. Non-IP strings (DNS names) pass through unchanged.
    /// </summary>
    public static string NormalizeHost(string host)
    {
        if (string.IsNullOrEmpty(host)) return null;
        if (host[0] == '[' && host[host.Length - 1] == ']')
            host = host.Substring(1, host.Length - 2);
        return IPAddress.TryParse(host, out IPAddress addr) ? Normalize(addr).ToString() : host;
    }
}
