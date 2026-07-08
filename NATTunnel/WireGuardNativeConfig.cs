using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>
/// Builds WireGuard-NT configuration blobs by hand and calls WireGuardSetConfiguration directly,
/// so the daemon can add/remove peers WITHOUT shelling out to wg.exe (which requires WireGuard for
/// Windows to be installed — an onboarding cliff and an extra code-execution surface).
///
/// Why manual byte writes instead of [StructLayout] marshalling: the config blob is one contiguous
/// buffer — a WIREGUARD_INTERFACE header, then PeersCount WIREGUARD_PEER structs, each immediately
/// followed by its AllowedIPsCount WIREGUARD_ALLOWED_IP structs. Marshalling nested variable-length
/// arrays that way is exactly what the previous native attempt got wrong (silently — a bad layout
/// makes the driver read garbage and no-op with no error). All structs are ALIGNED(8). We lay every
/// field at its documented offset so it's byte-exact and testable.
///
/// Layout reference: https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WireGuardNativeConfig
{
    private const int KeyLength = 32;

    // Interface flags.
    private const uint INTERFACE_HAS_PUBLIC_KEY = 1u << 0;
    private const uint INTERFACE_HAS_PRIVATE_KEY = 1u << 1;
    private const uint INTERFACE_HAS_LISTEN_PORT = 1u << 2;
    private const uint INTERFACE_REPLACE_PEERS = 1u << 3;

    // Peer flags. NOTE the gap at bit 4 — REPLACE_ALLOWED_IPS is 1<<5, not 1<<4 (the old code had
    // these off by one bit, which silently corrupted every native peer op).
    private const uint PEER_HAS_PUBLIC_KEY = 1u << 0;
    private const uint PEER_HAS_PRESHARED_KEY = 1u << 1;
    private const uint PEER_HAS_PERSISTENT_KEEPALIVE = 1u << 2;
    private const uint PEER_HAS_ENDPOINT = 1u << 3;
    private const uint PEER_REPLACE_ALLOWED_IPS = 1u << 5;
    private const uint PEER_REMOVE = 1u << 6;
    private const uint PEER_UPDATE_ONLY = 1u << 7;

    // Byte-exact sizes/offsets for the ALIGNED(8) structs. Fields follow natural alignment; only
    // the struct as a whole is 8-aligned. Verified field-by-field against the C aggregate layout.
    // NOTE: in WIREGUARD_INTERFACE, ListenPort is a WORD (2-aligned), so PrivateKey (a BYTE[], 1-
    // aligned) sits at offset 6, NOT 8 — a subtle trap, since a 2-byte error here silently breaks
    // the private key and the driver no-ops.
    private const int InterfaceSize = 80;      // Flags@0 ListenPort@4 PrivateKey@6 PublicKey@38 PeersCount@72, padded to 80
    private const int IfPrivateKeyOffset = 6;
    private const int IfPublicKeyOffset = 38;
    private const int IfPeersCountOffset = 72;
    private const int PeerSize = 136;          // Flags@0 Reserved@4 PubKey@8 PSK@40 Keepalive@72 Endpoint@76 Tx@104 Rx@112 LastHs@120 AllowedIPsCount@128, padded to 136
    private const int AllowedIPSize = 24;      // Address union@0 (16) AddressFamily@16 (2) Cidr@18 (1) Flags@20 (4), padded to 24
    private const int SockaddrInetSize = 28;   // SOCKADDR_IN6: family+port+flowinfo+addr(16)+scope

    private sealed class AllowedIP
    {
        public IPAddress Address;
        public int Cidr;
    }

    /// <summary>One peer's config for a full-interface apply.</summary>
    public sealed class PeerConfig
    {
        public string PublicKeyBase64;
        public IPEndPoint Endpoint;
        public List<(IPAddress addr, int cidr)> AllowedIPs = new();
        public int KeepaliveSeconds;
    }

    /// <summary>
    /// Apply a FULL interface configuration (private key + listen port + the complete peer set),
    /// replacing any existing peers. Native equivalent of "wg setconf". Used for interface setup
    /// and for removes/relay-route changes that regenerate the whole peer list. Returns false so
    /// the caller can fall back to wg.exe.
    /// </summary>
    public static bool ApplyFullConfig(IntPtr adapter, string privateKeyBase64, ushort listenPort,
                                       IReadOnlyList<PeerConfig> peers)
    {
        if (adapter == IntPtr.Zero) return false;
        if (!TryDecodeKey(privateKeyBase64, out byte[] privKey)) return false;

        // Decode + validate every peer up front so a bad key aborts cleanly rather than half-writing.
        var decoded = new List<(byte[] pub, PeerConfig cfg)>();
        int totalAllowedIPs = 0;
        foreach (var pc in peers)
        {
            if (!TryDecodeKey(pc.PublicKeyBase64, out byte[] pub)) return false;
            decoded.Add((pub, pc));
            totalAllowedIPs += pc.AllowedIPs.Count;
        }

        int total = InterfaceSize + decoded.Count * PeerSize + totalAllowedIPs * AllowedIPSize;
        byte[] buf = new byte[total];

        // --- WIREGUARD_INTERFACE header ---
        WriteUInt32(buf, 0, INTERFACE_HAS_PRIVATE_KEY | INTERFACE_HAS_LISTEN_PORT | INTERFACE_REPLACE_PEERS);
        WriteUInt16(buf, 4, listenPort);                                  // ListenPort@4
        Buffer.BlockCopy(privKey, 0, buf, IfPrivateKeyOffset, KeyLength); // PrivateKey@6 (PublicKey@38 derived by driver)
        WriteUInt32(buf, IfPeersCountOffset, (uint)decoded.Count);        // PeersCount@72

        int off = InterfaceSize;
        foreach (var (pub, cfg) in decoded)
        {
            uint peerFlags = PEER_HAS_PUBLIC_KEY | PEER_REPLACE_ALLOWED_IPS;
            if (cfg.Endpoint != null) peerFlags |= PEER_HAS_ENDPOINT;
            if (cfg.KeepaliveSeconds > 0) peerFlags |= PEER_HAS_PERSISTENT_KEEPALIVE;

            WriteUInt32(buf, off + 0, peerFlags);
            WriteUInt32(buf, off + 4, 0);
            Buffer.BlockCopy(pub, 0, buf, off + 8, KeyLength);
            WriteUInt16(buf, off + 72, (ushort)Math.Max(0, cfg.KeepaliveSeconds));
            if (cfg.Endpoint != null) WriteSockaddrInet(buf, off + 76, cfg.Endpoint);
            WriteUInt32(buf, off + 128, (uint)cfg.AllowedIPs.Count);
            off += PeerSize;

            foreach (var (addr, cidr) in cfg.AllowedIPs)
            {
                WriteAllowedIP(buf, off, new AllowedIP { Address = addr, Cidr = cidr });
                off += AllowedIPSize;
            }
        }

        if (!CallSetConfiguration(adapter, buf)) return false;

        // Verify every intended peer is present on read-back (REPLACE_PEERS means the resulting set
        // should be exactly ours). If any is missing, or the read fails, fall back to wg.exe.
        var present = ReadPeerPublicKeys(adapter);
        if (present == null) return false;
        foreach (var (pub, cfg) in decoded)
        {
            if (!present.Contains(Convert.ToBase64String(pub))) return false;
        }
        return true;
    }

    /// <summary>
    /// Add or update a single peer without disturbing existing peers. Native equivalent of
    /// "wg set &lt;iface&gt; peer ...": omitting REPLACE_PEERS makes SetConfiguration MERGE rather
    /// than replace. Returns false on failure so the caller can fall back to wg.exe.
    /// </summary>
    public static bool AddPeer(IntPtr adapter, string publicKeyBase64, IPEndPoint endpoint,
                               IEnumerable<(IPAddress addr, int cidr)> allowedIPs, int keepaliveSeconds)
    {
        if (adapter == IntPtr.Zero) return false;
        if (!TryDecodeKey(publicKeyBase64, out byte[] pubKey)) return false;

        var ips = new List<AllowedIP>();
        foreach (var (addr, cidr) in allowedIPs)
            ips.Add(new AllowedIP { Address = addr, Cidr = cidr });

        uint peerFlags = PEER_HAS_PUBLIC_KEY | PEER_REPLACE_ALLOWED_IPS;
        if (endpoint != null) peerFlags |= PEER_HAS_ENDPOINT;
        if (keepaliveSeconds > 0) peerFlags |= PEER_HAS_PERSISTENT_KEEPALIVE;

        if (!SetSinglePeer(adapter, peerFlags, pubKey, endpoint, (ushort)Math.Max(0, keepaliveSeconds), ips))
            return false;

        // Verify the peer actually appeared. SetConfiguration can return success while silently
        // applying nothing if the layout is wrong; if the key isn't present on read-back, report
        // failure so the caller falls back to wg.exe rather than trusting a phantom write.
        var keys = ReadPeerPublicKeys(adapter);
        return keys != null && keys.Contains(publicKeyBase64);
    }

    /// <summary>Remove a single peer by public key. Native equivalent of "wg set &lt;iface&gt; peer &lt;k&gt; remove".</summary>
    public static bool RemovePeer(IntPtr adapter, string publicKeyBase64)
    {
        if (adapter == IntPtr.Zero) return false;
        if (!TryDecodeKey(publicKeyBase64, out byte[] pubKey)) return false;
        // REMOVE identifies the peer by public key; no endpoint/allowed-IPs needed.
        if (!SetSinglePeer(adapter, PEER_HAS_PUBLIC_KEY | PEER_REMOVE, pubKey, null, 0, new List<AllowedIP>()))
            return false;

        // Verify the peer is actually gone; if a read-back still shows it (or fails), fall back.
        var keys = ReadPeerPublicKeys(adapter);
        return keys != null && !keys.Contains(publicKeyBase64);
    }

    private static bool SetSinglePeer(IntPtr adapter, uint peerFlags, byte[] pubKey, IPEndPoint endpoint,
                                      ushort keepalive, List<AllowedIP> allowedIPs)
    {
        // Buffer: [interface][peer][allowed-ip...]. REPLACE_PEERS is intentionally NOT set so this
        // merges into the running config instead of wiping other peers.
        int total = InterfaceSize + PeerSize + allowedIPs.Count * AllowedIPSize;
        byte[] buf = new byte[total];

        // --- WIREGUARD_INTERFACE header ---
        // Only PeersCount is meaningful for a merge (no interface key/port changes). Flags = 0 means
        // "don't touch the interface", and PeersCount tells the driver how many peers follow.
        WriteUInt32(buf, 0, 0);                          // Flags: no interface changes
        // ListenPort@4, PrivateKey@6, PublicKey@38 left zero (unset)
        WriteUInt32(buf, IfPeersCountOffset, 1);         // PeersCount = 1

        // --- WIREGUARD_PEER ---
        int p = InterfaceSize;
        WriteUInt32(buf, p + 0, peerFlags);     // Flags
        WriteUInt32(buf, p + 4, 0);             // Reserved (must be zero)
        Buffer.BlockCopy(pubKey, 0, buf, p + 8, KeyLength);   // PublicKey@8
        // PresharedKey@40 left zero
        WriteUInt16(buf, p + 72, keepalive);    // PersistentKeepalive@72
        if (endpoint != null) WriteSockaddrInet(buf, p + 76, endpoint); // Endpoint@76 (28 bytes)
        // Tx@104 / Rx@112 / LastHandshake@120 are output-only; leave zero
        WriteUInt32(buf, p + 128, (uint)allowedIPs.Count); // AllowedIPsCount@128

        // --- WIREGUARD_ALLOWED_IP array (immediately after the peer) ---
        int a = InterfaceSize + PeerSize;
        foreach (var ip in allowedIPs)
        {
            WriteAllowedIP(buf, a, ip);
            a += AllowedIPSize;
        }

        return CallSetConfiguration(adapter, buf);
    }

    /// <summary>
    /// Parse a WireGuard config file (already sanitized to wg-native fields) and apply it natively.
    /// Reads [Interface] PrivateKey/ListenPort and each [Peer] PublicKey/Endpoint/AllowedIPs/
    /// PersistentKeepalive. Returns false (so the caller falls back to wg.exe setconf) if the file
    /// is unreadable, missing a private key, or any field fails to parse.
    /// </summary>
    public static bool ApplyConfigFile(IntPtr adapter, string configPath)
    {
        if (adapter == IntPtr.Zero) return false;
        string[] lines;
        try { lines = System.IO.File.ReadAllLines(configPath); }
        catch { return false; }

        string privateKey = null;
        ushort listenPort = 0;
        var peers = new List<PeerConfig>();
        PeerConfig current = null;
        bool inInterface = false;

        foreach (var raw in lines)
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            if (line.StartsWith("[Interface]", StringComparison.OrdinalIgnoreCase))
            {
                inInterface = true; current = null; continue;
            }
            if (line.StartsWith("[Peer]", StringComparison.OrdinalIgnoreCase))
            {
                inInterface = false;
                current = new PeerConfig();
                peers.Add(current);
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq < 0) continue;
            string key = line.Substring(0, eq).Trim();
            string val = line.Substring(eq + 1).Trim();

            if (inInterface)
            {
                if (key.Equals("PrivateKey", StringComparison.OrdinalIgnoreCase)) privateKey = val;
                else if (key.Equals("ListenPort", StringComparison.OrdinalIgnoreCase)) ushort.TryParse(val, out listenPort);
            }
            else if (current != null)
            {
                if (key.Equals("PublicKey", StringComparison.OrdinalIgnoreCase)) current.PublicKeyBase64 = val;
                else if (key.Equals("PersistentKeepalive", StringComparison.OrdinalIgnoreCase)) { if (int.TryParse(val, out int ka)) current.KeepaliveSeconds = ka; }
                else if (key.Equals("Endpoint", StringComparison.OrdinalIgnoreCase)) current.Endpoint = ParseEndpoint(val);
                else if (key.Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var entry in val.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        int slash = entry.IndexOf('/');
                        string ipPart = slash >= 0 ? entry.Substring(0, slash) : entry;
                        if (!IPAddress.TryParse(ipPart, out var addr)) continue;
                        int cidr = slash >= 0 && int.TryParse(entry.Substring(slash + 1), out int c) ? c
                                 : (addr.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
                        current.AllowedIPs.Add((addr, cidr));
                    }
                }
            }
        }

        if (string.IsNullOrEmpty(privateKey)) return false;
        return ApplyFullConfig(adapter, privateKey, listenPort, peers);
    }

    private static IPEndPoint ParseEndpoint(string s)
    {
        // Handles "127.0.0.1:51822" and "[::1]:51822". Peer endpoints are loopback-proxy ports.
        int colon = s.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(s.Substring(colon + 1), out int port)) return null;
        string host = s.Substring(0, colon).Trim('[', ']');
        return IPAddress.TryParse(host, out var addr) ? new IPEndPoint(addr, port) : null;
    }

    private static bool CallSetConfiguration(IntPtr adapter, byte[] blob)
    {
        IntPtr ptr = Marshal.AllocHGlobal(blob.Length);
        try
        {
            Marshal.Copy(blob, 0, ptr, blob.Length);
            bool ok = WireGuardNTAPI.WireGuardSetConfiguration(adapter, ptr, (uint)blob.Length);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                Program.Log(LogLevel.Debug, $"[WireGuard native] SetConfiguration failed (Win32 error {err})");
            }
            return ok;
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Debug, $"[WireGuard native] SetConfiguration threw: {ex.Message}");
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Read back the interface config and return the set of peer public keys currently on the
    /// adapter (base64). Returns null if the read fails or the returned blob can't be parsed —
    /// used to VERIFY a native write actually took, since SetConfiguration can return success while
    /// silently applying nothing if the struct layout is off (the historical failure mode). A null
    /// or unexpected result makes the caller fall back to wg.exe rather than trust a phantom write.
    /// </summary>
    private static HashSet<string> ReadPeerPublicKeys(IntPtr adapter)
    {
        if (adapter == IntPtr.Zero) return null;

        // GetConfiguration protocol: pass a buffer + its size; if too small it returns false and
        // writes the required size into `bytes`. Retry once with the requested size.
        uint size = 4096;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            IntPtr ptr = Marshal.AllocHGlobal((int)size);
            try
            {
                uint bytes = size;
                bool ok = WireGuardNTAPI.WireGuardGetConfiguration(adapter, ptr, ref bytes);
                if (!ok)
                {
                    // Too small → bytes now holds the needed size; grow and retry.
                    if (bytes > size && bytes < 16 * 1024 * 1024) { size = bytes; continue; }
                    return null;
                }
                byte[] buf = new byte[bytes];
                Marshal.Copy(ptr, buf, 0, (int)bytes);
                return ParsePeerPublicKeys(buf);
            }
            catch { return null; }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        return null;
    }

    /// <summary>Walk a GetConfiguration blob (same layout as we write) and collect peer public keys.</summary>
    private static HashSet<string> ParsePeerPublicKeys(byte[] buf)
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (buf.Length < InterfaceSize) return keys;
        uint peersCount = ReadUInt32(buf, IfPeersCountOffset);
        int off = InterfaceSize;
        for (uint i = 0; i < peersCount; i++)
        {
            if (off + PeerSize > buf.Length) return null; // truncated/misaligned → treat as parse failure
            var pub = new byte[KeyLength];
            Buffer.BlockCopy(buf, off + 8, pub, 0, KeyLength); // PublicKey@8
            keys.Add(Convert.ToBase64String(pub));
            uint aipCount = ReadUInt32(buf, off + 128);        // AllowedIPsCount@128
            off += PeerSize + (int)aipCount * AllowedIPSize;
        }
        return keys;
    }

    private static uint ReadUInt32(byte[] buf, int off)
        => (uint)(buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24));

    // WIREGUARD_ALLOWED_IP: Address union@0 (16 bytes, v4 in first 4), AddressFamily@16 (WORD),
    // Cidr@18 (BYTE), Flags@20 (DWORD).
    private static void WriteAllowedIP(byte[] buf, int off, AllowedIP ip)
    {
        byte[] addrBytes = ip.Address.GetAddressBytes();
        Buffer.BlockCopy(addrBytes, 0, buf, off, addrBytes.Length); // v4 = 4 bytes, v6 = 16 bytes
        ushort family = (ushort)(ip.Address.AddressFamily == AddressFamily.InterNetworkV6
            ? 23   // AF_INET6
            : 2);  // AF_INET
        WriteUInt16(buf, off + 16, family);
        buf[off + 18] = (byte)ip.Cidr;
        // Flags@20 = 0 (add, not remove)
    }

    // SOCKADDR_INET, 28 bytes. For v4: sin_family(2) sin_port(2, BE) sin_addr(4, BE) sin_zero(8) then
    // padding to 28. For v6: sin6_family(2) sin6_port(2, BE) sin6_flowinfo(4) sin6_addr(16) sin6_scope(4).
    private static void WriteSockaddrInet(byte[] buf, int off, IPEndPoint ep)
    {
        // zero the whole 28-byte region first (padding / sin_zero)
        for (int i = 0; i < SockaddrInetSize; i++) buf[off + i] = 0;

        ushort portBE = (ushort)IPAddress.HostToNetworkOrder((short)ep.Port);
        if (ep.AddressFamily == AddressFamily.InterNetworkV6)
        {
            WriteUInt16(buf, off + 0, 23);       // AF_INET6
            WriteUInt16(buf, off + 2, portBE);   // sin6_port (network order)
            // sin6_flowinfo@4 = 0
            Buffer.BlockCopy(ep.Address.GetAddressBytes(), 0, buf, off + 8, 16); // sin6_addr
            // sin6_scope_id@24 = 0
        }
        else
        {
            WriteUInt16(buf, off + 0, 2);        // AF_INET
            WriteUInt16(buf, off + 2, portBE);   // sin_port (network order)
            Buffer.BlockCopy(ep.Address.GetAddressBytes(), 0, buf, off + 4, 4); // sin_addr (already network order)
        }
    }

    private static bool TryDecodeKey(string base64, out byte[] key)
    {
        key = null;
        try
        {
            byte[] decoded = Convert.FromBase64String(base64);
            if (decoded.Length != KeyLength) return false;
            key = decoded;
            return true;
        }
        catch { return false; }
    }

    private static void WriteUInt16(byte[] buf, int off, ushort v)
    {
        buf[off] = (byte)(v & 0xFF);
        buf[off + 1] = (byte)((v >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] buf, int off, uint v)
    {
        buf[off] = (byte)(v & 0xFF);
        buf[off + 1] = (byte)((v >> 8) & 0xFF);
        buf[off + 2] = (byte)((v >> 16) & 0xFF);
        buf[off + 3] = (byte)((v >> 24) & 0xFF);
    }
}
