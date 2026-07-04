/**
 * IP/endpoint helpers for dual-stack operation.
 *
 * With the server sockets bound dual-stack (::), IPv4 clients show up with
 * v4-mapped addresses ("::ffff:1.2.3.4"). Every address that gets stored,
 * compared, or serialized into an endpoint string must be normalized first so
 * v4 peers keep the exact same wire format they had when the server was v4-only.
 */

/** Unwraps a v4-mapped IPv6 address ("::ffff:1.2.3.4") to plain IPv4. Idempotent. */
function normalizeIP(addr) {
    if (!addr) return addr;
    if (addr.toLowerCase().startsWith('::ffff:') && addr.includes('.')) {
        return addr.slice(7);
    }
    return addr;
}

/** Formats ip + port as an endpoint string, bracketing IPv6 ("[2001:db8::1]:6510"). */
function formatEndpoint(ip, port) {
    const n = normalizeIP(ip);
    return n.includes(':') ? `[${n}]:${port}` : `${n}:${port}`;
}

/**
 * True if the (normalized) address is a genuine IPv6 address. v4-mapped forms are
 * unwrapped first, so "::ffff:1.2.3.4" reads as IPv4, not IPv6.
 */
function isIPv6(addr) {
    if (!addr) return false;
    return normalizeIP(addr).includes(':');
}

/** True if an endpoint string ("[v6]:port" or "v4:port") is IPv6. */
function isIPv6Endpoint(endpoint) {
    if (!endpoint) return false;
    return endpoint.startsWith('[');
}

/**
 * True if both endpoint strings are non-empty and the same address family. Two peers can
 * only hole-punch to each other when their endpoints match family (v4<->v4 or v6<->v6).
 */
function sameFamily(a, b) {
    if (!a || !b) return false;
    return isIPv6Endpoint(a) === isIPv6Endpoint(b);
}

module.exports = { normalizeIP, formatEndpoint, isIPv6, isIPv6Endpoint, sameFamily };
