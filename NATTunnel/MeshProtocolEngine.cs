using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NATTunnel;

/// <summary>
/// Encapsulates the per-process mesh networking engine — the canonical mesh protocol
/// implementation that both the CLI daemon and the embedded library drive.
/// One instance per Run() lifetime; replaces the giant RunMeshMode local-variable closure.
/// </summary>
internal class MeshProtocolEngine
{
    // ── Constants ──
    public const int MeshControlPort = 51888;
    public const int IntroducerMissedProbeThreshold = 3;

    // ── Network resources ──
    // Note on lifecycle: tcpClient/wireguardTunnel/udpProxy get reassigned on every reconnect
    // cycle. Leaving them here means we must explicitly null/dispose them when reconnecting,
    // or we leak the previous instance. We can keep them as fields once the migration settles;
    // for now they're commented out — we'll move them after the simpler state is in place.

    /// <summary>Mesh-control UDP socket. Lifetime: created once in Run(), reused across reconnects.</summary>
    private UdpClient meshControlClient;
    private UdpClient udpClient;
    private TcpClient tcpClient;
    /// <summary>
    /// Host adapter for everything the mesh protocol needs from the underlying transport
    /// (peer add/remove, relay routes, IP forwarding). In daemon mode this is a WireGuardTunnel;
    /// embedded mode will eventually supply a different implementation.
    /// </summary>
    private IMeshHost host;
    /// <summary>
    /// Decouples this engine from the daemon-wide statics (Program/TunnelOptions/Config).
    /// Set at the start of <see cref="Run(WireGuardTunnel, string, UdpClient, WireGuardUdpProxy, Guid)"/>
    /// (default: <see cref="DaemonContext"/>) or by callers using the new context-aware overload.
    /// </summary>
    private IMeshDaemonContext context;
    private WireGuardUdpProxy udpProxy;
    private Stream stream;
    private byte[] buffer = new byte[8192];
    private string earlyTcpRemainder = "";
    private IPEndPoint endpoint;
    private string authToken;
    private MediationMessage joinResponse = null;
    private int localUdpPort;
    private byte[] hash;
    private object meshControlSendLock = new object();

    // ── Inbound message queues (producer: UDP listener task, consumer: main loop) ──
    private readonly ConcurrentQueue<MediationMessage> meshConnectionBeginQueue = new();
    private readonly ConcurrentQueue<MediationMessage> meshHeartbeatAckQueue = new();
    private readonly ConcurrentQueue<MediationMessage> meshPeerRemovedQueue = new();
    private readonly ConcurrentQueue<MediationMessage> meshPeerLeaveQueue = new();
    private readonly ConcurrentQueue<MediationMessage> meshRelayAssignmentQueue = new();
    private readonly ConcurrentQueue<MediationMessage> meshRelayHealthReportQueue = new();

    // ── Relay state (this peer's incoming side) ──
    /// <summary>Remote mesh IP → relay mesh IP for routes we're using as an endpoint.</summary>
    private readonly ConcurrentDictionary<string, string> relayedRemotes = new();
    /// <summary>Cooldown per remote to avoid spamming the introducer with health reports.</summary>
    private readonly ConcurrentDictionary<string, DateTime> lastRelayHealthReport = new();

    // ── Relay hosting (this peer as a relay for others) ──
    private readonly HashSet<string> hostedRelays = new();
    private readonly object hostedRelayLock = new();
    // Helpers HostedRelayCount/AddHostedRelay/RemoveHostedRelay live further down with the other methods.

    // ── Peer tracking ──
    private readonly ConcurrentDictionary<string, long> peerLatencyMs = new();
    private readonly ConcurrentDictionary<string, DateTime> peerLastPong = new();
    private readonly ConcurrentDictionary<string, long> pingSentTicks = new();
    private readonly ConcurrentDictionary<string, DateTime> lastHeartbeatReceivedFrom = new();
    /// <summary>When each peer's tunnel reached completedTunnelMeshIPs. Used to grace-period
    /// the heartbeat-repair logic — pings travel on a 5s timer, so peers can legitimately not
    /// yet see each other in the first ~10s after a fresh tunnel, and firing repair there would
    /// tear down a perfectly working connection.</summary>
    private readonly ConcurrentDictionary<string, DateTime> tunnelCompletedAt = new();
    /// <summary>Per-peer negotiated peer-protocol version (mesh IP → version). -1 for peers we
    /// haven't heard MeshVersionHello from yet; 0 means the peer is on an old build that predates
    /// version negotiation (grandfathered as v1 in code that checks).</summary>
    private readonly ConcurrentDictionary<string, int> peerNegotiatedVersion = new();
    /// <summary>Peers whose peer-protocol range has no overlap with ours (PeerID → their advertised
    /// range). Used to short-circuit hole-punch attempts against known-incompatible peers instead of
    /// churning on retries. Keyed by PeerID (stable across sessions) with the range as the value so
    /// a peer that upgrades and advertises a new range gets re-evaluated instead of staying blocked.
    /// Cleared on disconnect/rejoin.</summary>
    private readonly ConcurrentDictionary<string, (int min, int max)> incompatiblePeers = new();

    /// <summary>32-byte Curve25519 private key backing this node's stable identity. Set once via
    /// <see cref="Run"/>; not mutated during the session. Derived pubkey feeds <see cref="ownIdentityPublicKey"/>.</summary>
    private byte[] identityPrivateKey;
    /// <summary>32-byte Curve25519 public key computed from <see cref="identityPrivateKey"/>. Sent in
    /// join requests / MeshConnectionBegin so peers can identify each other for block filtering.</summary>
    private byte[] ownIdentityPublicKey;
    /// <summary>Peers this node has blocked, keyed by SHA-256(pubkey)[..8] hex fingerprint. Live
    /// reference — the host mutates this via <see cref="AddBlockedFingerprint"/>/<see cref="RemoveBlockedFingerprint"/>
    /// and changes take effect immediately without waiting for a reconnect.</summary>
    private HashSet<string> blockedFingerprints;
    private readonly object blockedFingerprintsLock = new();
    /// <summary>Endpoints (IP:port strings) of currently-blocked peers, cached at block time and
    /// checked in the shared UDP dispatcher so stray hole-punch packets from a blocked peer get
    /// dropped before hitting any Tunnel. Belt-and-suspenders against RemoveDeadPeer missing a
    /// tunnel whose connID isn't in peerMeshIPs.</summary>
    private readonly ConcurrentDictionary<string, bool> blockedEndpoints = new();
    /// <summary>IPs (not IP:port) of currently-blocked peers. Symmetric peers allocate a distinct
    /// external port for each destination, so a fresh reconnect attempt will arrive from an
    /// unblocked port even though the source machine is the same. Filtering by IP alone catches
    /// those stray probes at the dispatcher. Populated alongside <see cref="blockedEndpoints"/>.</summary>
    private readonly ConcurrentDictionary<string, bool> blockedIPs = new();

    /// <summary>
    /// X25519 scalar-basepoint multiply — derive a Curve25519 public key from its private half.
    /// </summary>
    internal static byte[] DeriveIdentityPublicKey(byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("Identity private key must be 32 bytes.", nameof(privateKey));
        var priv = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(privateKey, 0);
        return priv.GeneratePublicKey().GetEncoded();
    }

    /// <summary>
    /// SHA-256(pubkey) truncated to 8 bytes, hex-encoded. Human-manageable identifier for block
    /// lists — 16 chars, collision-resistant for realistic mesh sizes.
    /// </summary>
    internal static string ComputeFingerprint(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length == 0) return null;
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(publicKey, hash);
        return Convert.ToHexString(hash[..8]).ToLowerInvariant();
    }

    /// <summary>SHA-256(pubkey)[..8] hex of our own identity key, or null pre-Run.</summary>
    internal string OwnFingerprint => ownIdentityPublicKey != null ? ComputeFingerprint(ownIdentityPublicKey) : null;

    /// <summary>Fingerprint of the peer at <paramref name="meshIP"/>, or null if we don't know
    /// their identity yet (identity hasn't been echoed via mediation, or the peer is on an older
    /// build that doesn't advertise one). Live — updates as the identity is filled in.</summary>
    internal string GetPeerFingerprintByMeshIP(string meshIP)
    {
        if (string.IsNullOrEmpty(meshIP)) return null;
        if (!peerInfoByMeshIP.TryGetValue(meshIP, out var info) || string.IsNullOrEmpty(info.identityPublicKey))
            return null;
        try { return ComputeFingerprint(Convert.FromBase64String(info.identityPublicKey)); }
        catch { return null; }
    }

    /// <summary>Base64 of our own identity public key, ready to drop into <see cref="MediationMessage.IdentityPublicKey"/>. Null pre-Run.</summary>
    private string OwnIdentityPublicKeyB64 => ownIdentityPublicKey != null ? Convert.ToBase64String(ownIdentityPublicKey) : null;

    /// <summary>Mediation server's IPv6 address (AAAA record), resolved once per process.
    /// Null when the primary mediation endpoint is already v6 (the normal NAT test covers it)
    /// or when no AAAA record / hostname is available.</summary>
    private IPAddress mediationV6Address;
    private bool mediationV6Resolved;

    /// <summary>
    /// Sends the NAT test packets a second time over IPv6 so the server observes our public
    /// v6 endpoint the same way it observes v4 — including any port rewriting a v6 firewall
    /// or NAT66 middlebox does in practice. Fire-and-forget: no v6 route just means the
    /// server never sees the packets and we advertise no v6 endpoint.
    /// </summary>
    private void SendNatTestV6(byte[] natTestBuffer, int portOne, int portTwo, string serverAdvertisedV6 = null)
    {
        try
        {
            if (!mediationV6Resolved)
            {
                mediationV6Resolved = true;
                // Use the resolved endpoint (the connect loop filled it); if the primary mediation
                // connection is already v6, the normal NAT test covers it — no separate v6 probe.
                var mediationEP = endpoint;
                // Only run the v6 NAT test when this machine has a genuinely global v6 route.
                // A link-local/ULA-only machine (very common — Windows assigns link-local to
                // every NIC) can send the probe from a non-routable source; the packet may even
                // reach mediation, but the observed endpoint is useless peer-to-peer and would
                // wrongly make the peer look v6-reachable. Gate on a real global v6 source.
                if (mediationEP != null && mediationEP.Address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    var v6Source = Tunnel.GetGlobalIPv6Candidate();
                    if (v6Source == null)
                    {
                        context.Log(LogLevel.Debug, "[Mesh] No native global IPv6 route — skipping v6 NAT test");
                    }
                    // Prefer the server-advertised v6 (works for a bare v4-literal config); fall
                    // back to resolving the AAAA record of the configured hostname.
                    else if (!string.IsNullOrEmpty(serverAdvertisedV6) && IPAddress.TryParse(serverAdvertisedV6, out var advV6))
                    {
                        mediationV6Address = advV6;
                        context.Log(LogLevel.Debug, $"[Mesh] Global IPv6 source {v6Source} + server-advertised v6 {mediationV6Address} — running v6 NAT test");
                    }
                    else
                    {
                        string host = context.Options.MediationHost;
                        if (!string.IsNullOrEmpty(host) && !IPAddress.TryParse(host, out _))
                        {
                            mediationV6Address = Dns.GetHostAddresses(host)
                                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
                            if (mediationV6Address != null)
                                context.Log(LogLevel.Debug, $"[Mesh] Global IPv6 source {v6Source} + mediation AAAA present — running v6 NAT test");
                        }
                    }
                }
            }
            if (mediationV6Address == null) return;
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(mediationV6Address, portOne));
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(mediationV6Address, portTwo));
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Debug, $"[Mesh] v6 NAT test skipped: {ex.Message}");
        }
    }

    /// <summary>Mediation server's IPv4 address (A record), resolved once per process.
    /// Null when the primary mediation endpoint is already v4 (the normal NAT test covers it)
    /// or when no A record / hostname is available.</summary>
    private IPAddress mediationV4Address;
    private bool mediationV4Resolved;

    /// <summary>
    /// Mirror of <see cref="SendNatTestV6"/> for a v6-PRIMARY peer: when the peer reached mediation
    /// over IPv6, its normal NAT test only exercises v6, so the server never observes its v4
    /// endpoint and it would advertise v6-only. This resolves the mediation server's A record and
    /// sends the NAT test over v4 too, so a dual-stack peer that happens to be v6-primary still
    /// advertises BOTH families. Fire-and-forget: no v4 route just means no v4 endpoint observed.
    /// </summary>
    private void SendNatTestV4(byte[] natTestBuffer, int portOne, int portTwo, string serverAdvertisedV4 = null)
    {
        try
        {
            if (!mediationV4Resolved)
            {
                mediationV4Resolved = true;
                var mediationEP = endpoint;
                // Only relevant when the primary connection is v6 (a v4-primary peer's normal test
                // already covers v4).
                if (mediationEP != null && mediationEP.Address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    // Prefer the address the server advertised in NATTestBegin — works even for a
                    // bare v6-literal config (no DNS A record). Fall back to resolving the A record
                    // of the configured hostname, if there is one.
                    if (!string.IsNullOrEmpty(serverAdvertisedV4) && IPAddress.TryParse(serverAdvertisedV4, out var advV4))
                    {
                        mediationV4Address = advV4;
                        context.Log(LogLevel.Debug, $"[Mesh] v6-primary peer — running v4 NAT test against server-advertised v4 {mediationV4Address}");
                    }
                    else
                    {
                        string host = context.Options.MediationHost;
                        if (!string.IsNullOrEmpty(host) && !IPAddress.TryParse(host, out _))
                        {
                            mediationV4Address = Dns.GetHostAddresses(host)
                                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                            if (mediationV4Address != null)
                                context.Log(LogLevel.Debug, $"[Mesh] v6-primary peer — running v4 NAT test against mediation A record {mediationV4Address}");
                        }
                    }
                }
            }
            if (mediationV4Address == null) return;
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(mediationV4Address, portOne));
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(mediationV4Address, portTwo));
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Debug, $"[Mesh] v4 NAT test skipped: {ex.Message}");
        }
    }

    /// <summary>Snapshot of currently-blocked fingerprints. Safe to iterate without external locking.</summary>
    internal IReadOnlyCollection<string> BlockedFingerprints
    {
        get { lock (blockedFingerprintsLock) return blockedFingerprints?.ToArray() ?? Array.Empty<string>(); }
    }

    /// <summary>Add a fingerprint to the block list. Takes effect immediately on all enforcement sites
    /// and actively tears down any live tunnel to a peer that matches — user expectation is that
    /// clicking Block disconnects the peer now, not on next reconnect. Also records the peer's
    /// last-known endpoint in <see cref="blockedEndpoints"/> so the shared UDP dispatcher can drop
    /// stray packets from that source (mediation-brokered hole-punch retries, orphan tunnels, etc.).</summary>
    internal void AddBlockedFingerprint(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return;
        string normalized = fingerprint.Trim().ToLowerInvariant();
        lock (blockedFingerprintsLock) blockedFingerprints?.Add(normalized);

        // Sweep peerInfoByMeshIP for anyone matching the fingerprint, cache their endpoints for
        // packet-level dropping, and tear their tunnel down.
        var matches = new List<string>();
        foreach (var kv in peerInfoByMeshIP)
        {
            if (string.IsNullOrEmpty(kv.Value.identityPublicKey)) continue;
            try
            {
                if (ComputeFingerprint(Convert.FromBase64String(kv.Value.identityPublicKey)) == normalized)
                {
                    matches.Add(kv.Key);
                    if (!string.IsNullOrEmpty(kv.Value.endpoint))
                    {
                        blockedEndpoints[EndpointUtils.NormalizeEndpointString(kv.Value.endpoint)] = true;
                        // Also cache the source IP alone. Symmetric peers vary their external port
                        // per-destination, so subsequent hole-punch attempts land from a fresh port
                        // that the endpoint-precise blocklist doesn't cover.
                        string blockedHost = EndpointUtils.GetHost(kv.Value.endpoint);
                        if (blockedHost != null)
                            blockedIPs[blockedHost] = true;
                    }
                }
            }
            catch { }
        }
        foreach (var meshIP in matches)
        {
            context.Log(LogLevel.Info, $"[Mesh] Blocking {meshIP} — tearing down live tunnel");
            RemoveDeadPeer(meshIP);
        }
    }

    /// <summary>Set to true by <see cref="RemoveBlockedFingerprint"/> whenever an unblock happens.
    /// The primary loop picks this up and re-sends a MeshJoinRequest to mediation so the server
    /// knows to broadcast a fresh MeshIntroduceRequest for us — otherwise the previously-blocked
    /// peer stays absent from our WireGuard peer set (we tore them down at block time) and no
    /// new introduction fires until one side rejoins entirely.</summary>
    private volatile bool rediscoveryRequestedAfterUnblock;

    /// <summary>Remove a fingerprint from the block list. Also drops any cached endpoints that
    /// were pointing to the newly-unblocked peer so the dispatcher stops filtering their packets.</summary>
    internal bool RemoveBlockedFingerprint(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return false;
        string normalized = fingerprint.Trim().ToLowerInvariant();
        bool removed;
        lock (blockedFingerprintsLock) removed = blockedFingerprints?.Remove(normalized) ?? false;
        if (removed)
        {
            // Rebuild blockedEndpoints from remaining blocked fingerprints — cheaper than tracking
            // reverse mappings and safer than trying to match by fingerprint at unblock time.
            var stillBlocked = new HashSet<string>();
            lock (blockedFingerprintsLock)
            {
                if (blockedFingerprints != null)
                    foreach (var fp in blockedFingerprints) stillBlocked.Add(fp);
            }
            var keep = new HashSet<string>();
            var keepIPs = new HashSet<string>();
            foreach (var kv in peerInfoByMeshIP)
            {
                if (string.IsNullOrEmpty(kv.Value.identityPublicKey) || string.IsNullOrEmpty(kv.Value.endpoint)) continue;
                try
                {
                    string fp = ComputeFingerprint(Convert.FromBase64String(kv.Value.identityPublicKey));
                    if (stillBlocked.Contains(fp))
                    {
                        keep.Add(EndpointUtils.NormalizeEndpointString(kv.Value.endpoint));
                        string keepHost = EndpointUtils.GetHost(kv.Value.endpoint);
                        if (keepHost != null) keepIPs.Add(keepHost);
                    }
                }
                catch { }
            }
            foreach (var ep in blockedEndpoints.Keys.ToArray())
                if (!keep.Contains(ep)) blockedEndpoints.TryRemove(ep, out _);
            foreach (var ip in blockedIPs.Keys.ToArray())
                if (!keepIPs.Contains(ip)) blockedIPs.TryRemove(ip, out _);
            // Flag rediscovery so the main loop nudges mediation. We tore the unblocked peer's
            // WG registration down at block time, so nothing on our side will spontaneously
            // rebuild the tunnel — we need mediation to broadcast a fresh introduction.
            rediscoveryRequestedAfterUnblock = true;
        }
        return removed;
    }

    /// <summary>True if <paramref name="publicKey"/> resolves to a fingerprint on our block list.</summary>
    private bool IsBlocked(byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length == 0) return false;
        string fp = ComputeFingerprint(publicKey);
        lock (blockedFingerprintsLock) return blockedFingerprints != null && blockedFingerprints.Contains(fp);
    }

    /// <summary>True if the peer identified by <paramref name="publicKeyBase64"/> is blocked.</summary>
    private bool IsBlocked(string publicKeyBase64)
    {
        if (string.IsNullOrEmpty(publicKeyBase64)) return false;
        try { return IsBlocked(Convert.FromBase64String(publicKeyBase64)); }
        catch { return false; }
    }
    private readonly ConcurrentDictionary<string, (string peerID, string endpoint, NATType natType, int peerMinVersion, int peerMaxVersion, string identityPublicKey, string endpointV6)> peerInfoByMeshIP = new();

    /// <summary>Peers we've seen within the recent-past window — powers the Firewall pane's
    /// "known peers" list so users can block someone who was here a moment ago but isn't now.
    /// Keyed by mesh IP; value is (peerID, fingerprint, lastSeen). Pruned in
    /// <see cref="GetMeshState"/>. Fingerprint is cached here so the Block button stays enabled
    /// during the 15-min grace after RemoveDeadPeer clears peerInfoByMeshIP — otherwise the peer
    /// briefly appears as "no fingerprint yet" and can't be blocked in the window the user cares
    /// about most (right after they left).</summary>
    private readonly ConcurrentDictionary<string, (string peerID, string fingerprint, DateTime lastSeen)> recentlySeenPeers = new();
    private static readonly TimeSpan RecentlySeenWindow = TimeSpan.FromMinutes(15);
    private const int RecentlySeenCap = 50;

    /// <summary>Touch a peer in the recently-seen tracker whenever we cache their info. Called
    /// from all <see cref="peerInfoByMeshIP"/> write sites so peers who briefly appeared stay
    /// visible in the Firewall pane for a grace window.</summary>
    private void MarkRecentlySeen(string meshIP, string peerID)
    {
        if (string.IsNullOrEmpty(meshIP) || meshIP == this.meshIP) return;
        // Preserve any previously-cached fingerprint. We may be called from a write path that
        // doesn't have identityPublicKey (heartbeat roster fallback, ack), and losing a
        // previously-known fingerprint would disable the Block button in the Firewall pane.
        string existingFingerprint = null;
        if (recentlySeenPeers.TryGetValue(meshIP, out var prev))
            existingFingerprint = prev.fingerprint;
        // If we have a fresh identityPublicKey in peerInfoByMeshIP, compute the fingerprint from
        // that (source of truth); else keep whatever was cached.
        if (peerInfoByMeshIP.TryGetValue(meshIP, out var info) && !string.IsNullOrEmpty(info.identityPublicKey))
        {
            try { existingFingerprint = ComputeFingerprint(Convert.FromBase64String(info.identityPublicKey)); }
            catch { /* keep prior */ }
        }
        recentlySeenPeers[meshIP] = (peerID, existingFingerprint, DateTime.UtcNow);
    }

    /// <summary>Drop entries older than <see cref="RecentlySeenWindow"/> and enforce
    /// <see cref="RecentlySeenCap"/>. Called from <see cref="GetMeshState"/>.</summary>
    private void PruneRecentlySeen()
    {
        var cutoff = DateTime.UtcNow - RecentlySeenWindow;
        foreach (var kv in recentlySeenPeers)
        {
            if (kv.Value.lastSeen < cutoff) recentlySeenPeers.TryRemove(kv.Key, out _);
        }
        if (recentlySeenPeers.Count > RecentlySeenCap)
        {
            var toDrop = recentlySeenPeers
                .OrderBy(kv => kv.Value.lastSeen)
                .Take(recentlySeenPeers.Count - RecentlySeenCap)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var k in toDrop) recentlySeenPeers.TryRemove(k, out _);
        }
    }

    /// <summary>Build the Firewall pane's "known peers" list — recently-seen entries plus their
    /// fingerprint (from peerInfoByMeshIP) and current tunnel status.</summary>
    private List<MeshState.KnownPeer> BuildKnownPeers()
    {
        PruneRecentlySeen();
        // Merge sources: recentlySeenPeers (peers that appeared in the last window, including
        // ones no longer active) + peerInfoByMeshIP (all peers we currently know about, from
        // heartbeat acks / roster / connection begins). Using only recentlySeenPeers was fragile
        // because it depends on writes flowing through MarkRecentlySeen and can be aged out
        // even for peers we're actively connected to if their touch write pathway hits a lull.
        var seen = new Dictionary<string, (string peerID, bool isConnected)>();
        foreach (var kv in recentlySeenPeers)
        {
            if (kv.Key == meshIP) continue;
            seen[kv.Key] = (kv.Value.peerID, completedTunnelMeshIPs.Contains(kv.Key));
        }
        foreach (var kv in peerInfoByMeshIP)
        {
            if (kv.Key == meshIP) continue;
            if (!seen.ContainsKey(kv.Key))
                seen[kv.Key] = (kv.Value.peerID, completedTunnelMeshIPs.Contains(kv.Key));
        }
        var result = new List<MeshState.KnownPeer>();
        foreach (var kv in seen)
        {
            string peerMeshIP = kv.Key;
            string fp = null;
            // Prefer live peerInfoByMeshIP; fall back to the cached fingerprint on recentlySeenPeers
            // for peers that were just removed (RemoveDeadPeer wiped peerInfoByMeshIP but the user
            // should still be able to block them during the 15-min grace).
            if (peerInfoByMeshIP.TryGetValue(peerMeshIP, out var info) && !string.IsNullOrEmpty(info.identityPublicKey))
            {
                try { fp = ComputeFingerprint(Convert.FromBase64String(info.identityPublicKey)); }
                catch { fp = null; }
            }
            if (fp == null && recentlySeenPeers.TryGetValue(peerMeshIP, out var seenEntry))
                fp = seenEntry.fingerprint;
            result.Add(new MeshState.KnownPeer
            {
                MeshIP = peerMeshIP,
                PeerID = kv.Value.peerID,
                Fingerprint = fp,
                IsConnected = kv.Value.isConnected
            });
        }
        result.Sort((a, b) => string.Compare(a.MeshIP, b.MeshIP, StringComparison.Ordinal));
        return result;
    }
    /// <summary>LAN endpoint info parallel to peerInfoByMeshIP, used for same-LAN pair detection.</summary>
    private readonly ConcurrentDictionary<string, (string localIP, int localPort)> peerLanByMeshIP = new();
    // Initialized in Run() once `context` is available — instance field initializers can't
    // read instance fields, so these are deferred.
    private TimeSpan repairCooldown;

    // ── Relay candidate roster (introducer-side) ──
    /// <summary>Mesh IP → advertised relay state from heartbeats.</summary>
    private readonly ConcurrentDictionary<string, (bool capable, int activeRoutes, RelayCapacity capacity, DateTime lastSeen)> relayCandidates = new();
    /// <summary>Pair key → mesh IP of currently-chosen relay.</summary>
    private readonly ConcurrentDictionary<string, string> relayAssignments = new();
    /// <summary>Pair key → last reselection time, for cooldown enforcement.</summary>
    private readonly ConcurrentDictionary<string, DateTime> lastRelayReselect = new();

    // ── Engine identity (set during join, stable across reconnects within a session) ──
    private string meshIP;
    private Guid peerID;
    private bool isIntroducer;
    private NATType detectedNatType = NATType.Unknown;
    /// <summary>NAT type over IPv6, or null if the peer has no v6 / the server hasn't reported it.
    /// Detected independently of the v4 verdict (they can differ) and surfaced to the GUI.</summary>
    private NATType? detectedNatTypeV6;

    /// <summary>Applies a NATTypeResponse: stores the v4 verdict (if present) or the v6 verdict
    /// (if present). The server sends one response per family as each settles. Idempotent — a
    /// re-seen verdict is a no-op (doesn't re-log), so it's safe to call from the handshake drain
    /// AND the main message loop for the same response.</summary>
    private void ApplyNatTypeResponse(MediationMessage m)
    {
        if (m.NATTypeV6.HasValue)
        {
            if (detectedNatTypeV6 == m.NATTypeV6.Value) return;
            detectedNatTypeV6 = m.NATTypeV6.Value;
            context.Log(LogLevel.Info, $"[Mesh] NAT type detected (IPv6): {detectedNatTypeV6}");
        }
        else
        {
            if (detectedNatType == m.NATType && detectedNatType != NATType.Unknown) return;
            detectedNatType = m.NATType;
            context.Log(LogLevel.Info, $"[Mesh] NAT type detected: {detectedNatType}");
        }
    }

    /// <summary>Our NAT type for a hole-punch over the given endpoint. NAT type is a per-family
    /// property (v6 has no port-translating NAT, so it's typically Restricted/Open even when v4 is
    /// Symmetric). Passing the v4 verdict for a v6 connection makes the Tunnel run the 256-probe
    /// symmetric-NAT-traversal strategy over v6, which doesn't establish — so pick by endpoint
    /// family. Falls back to the v4 verdict if v6 was never detected.</summary>
    private NATType OwnNatTypeForEndpoint(string endpoint)
    {
        if (EndpointUtils.IsIPv6Endpoint(endpoint) && detectedNatTypeV6.HasValue)
            return detectedNatTypeV6.Value;
        return detectedNatType;
    }

    /// <summary>The remote peer's NAT type for a hole-punch over the given endpoint, chosen by
    /// family the same way as <see cref="OwnNatTypeForEndpoint"/>. Falls back to the v4 verdict
    /// when the message carries no v6 verdict.</summary>
    private static NATType RemoteNatTypeForEndpoint(string endpoint, NATType v4Type, NATType? v6Type)
    {
        if (EndpointUtils.IsIPv6Endpoint(endpoint) && v6Type.HasValue)
            return v6Type.Value;
        return v4Type;
    }

    /// <summary>
    /// Given a peer's advertised v4 and (optional) v6 endpoints from a MeshConnectionBegin, choose
    /// which one THIS node should hole-punch to. Prefer v6 only when both this node has a global v6
    /// route AND the peer advertised a v6 endpoint (same rule the coordinator uses, but applied by
    /// the receiver so it never tries a family it can't reach). Falls back to v4 otherwise.
    ///
    /// This is what lets a v4-only peer join a mesh whose existing peers paired over v6: the
    /// introducer carries BOTH endpoints, and each receiver picks the family it can actually use,
    /// instead of being handed a single (possibly wrong-family) endpoint it can't reach.
    /// </summary>
    private static string SelectReachableEndpoint(string endpointString, string v6Endpoint)
    {
        // Collect every candidate and bucket by family. endpointString may itself be a v6 literal
        // (the coordinator substitutes v6 into it on the bothHaveV6 path), so classify by content,
        // not by field name. v6Endpoint is always v6 when present.
        string v6 = null, v4 = null;
        if (!string.IsNullOrEmpty(v6Endpoint) && EndpointUtils.IsIPv6Endpoint(v6Endpoint)) v6 = v6Endpoint;
        if (!string.IsNullOrEmpty(endpointString))
        {
            if (EndpointUtils.IsIPv6Endpoint(endpointString)) v6 ??= endpointString;
            else v4 = endpointString;
        }

        // Prefer v6 only when we have a global v6 route and a v6 endpoint to punch to. Else use v4.
        // Fall back to whatever single family exists if the preferred one is absent (an empty result
        // means the peer gave us nothing reachable — downstream empty-checks handle that).
        if (v6 != null && Tunnel.HasGlobalIPv6()) return v6;
        return v4 ?? v6;
    }

    // ── Introducer probe state ──
    private string introducerMeshIP;
    private bool introducerProbeAckReceived = true;
    private DateTime lastIntroducerProbe = DateTime.UtcNow;
    private int introducerMissedProbes;
    private TimeSpan introducerProbeInterval;  // Set in Run() once context is available.

    // ── Takeover-bid state (mesh-control-only loop) ──
    // Null except while a reconnect-to-mediation bid is in-progress. Promoted from locals
    // so shared helpers like DrainInboundQueues can check whether a takeover is in-progress.
    private TcpClient reconnectedTcpClient;
    private Stream reconnectedStream;
    private DateTime? lastReconnectDiscovery;
    private DateTime? isolationDetectedAt;

    // Metrics counters for health monitoring
    private int metricTunnelsEstablished = 0;
    private int metricTunnelsFailed = 0;
    private int metricReconnects = 0;
    private int metricPeersLost = 0;
    private int metricHeartbeatsSent = 0;
    private int metricHeartbeatAcksReceived = 0;
    private int metricHeartbeatsMissed = 0;
    private long metricLastHeartbeatResponseMs = 0;
    private int metricRelayRoutesEstablished = 0;
    private int metricRelayRoutesRemoved = 0;
    private DateTime? heartbeatSentTime = null;

    // ── Per-connect tracking state ──
    // Declared here (before outer loop) so background tasks (UDP dispatcher,
    // HTTP endpoint) keep valid closure references across disconnect/reconnect.
    // Cleared on disconnect rather than re-declared.
    // Lock for collections accessed from both the main loop and tunnel callbacks
    // (onConnectionComplete/onConnectionFailure fire on background threads).
    private object meshLock = new object();
    private Dictionary<string, Tunnel> activePeerTunnels = new Dictionary<string, Tunnel>();
    private Dictionary<string, DateTime> pendingConnectionRequests = new Dictionary<string, DateTime>();
    // Tracks the last time we logged a "stale pending connection request" warning per peer,
    // so the same ghost peer doesn't spam the log every cycle. Entries persist until the peer
    // either connects or pendingConnectionRequests is cleared en masse (disconnect/rejoin).
    private Dictionary<string, DateTime> lastStaleWarningAt = new Dictionary<string, DateTime>();
    private static readonly TimeSpan StaleWarningCooldown = TimeSpan.FromMinutes(1);
    private Dictionary<int, Tunnel> activeConnectionTunnels = new Dictionary<int, Tunnel>();
    private Dictionary<int, string> connectionIDToPeerID = new Dictionary<int, string>();
    private Dictionary<int, string> peerMeshIPs = new Dictionary<int, string>();
    private int pendingTunnelCount = 0;
    private Dictionary<string, List<MediationMessage>> deferredIntroductions = new Dictionary<string, List<MediationMessage>>();
    private HashSet<string> completedTunnelMeshIPs = new HashSet<string>();
    private HashSet<string> relayedPairs = new HashSet<string>();
    private Dictionary<string, DateTime> lastRepairAttempt = new Dictionary<string, DateTime>();
    private Dictionary<string, int> repairAttemptCount = new Dictionary<string, int>();

    // Periodic peer discovery: if we're connected to mediation but have no WireGuard
    // peers (lone peer), periodically re-send MeshJoinRequest to discover new peers.
    private DateTime lastPeerDiscovery = DateTime.UtcNow;
    private TimeSpan peerDiscoveryInterval;  // Set in Run() once context is available.

    // Periodic latency ping: every peer pings all WireGuard peers to measure RTT
    private DateTime lastPingTime = DateTime.UtcNow;
    private TimeSpan pingInterval = TimeSpan.FromSeconds(5);

    // Introducer heartbeat: periodically check that all peers can reach each other
    private DateTime lastHeartbeat = DateTime.UtcNow;
    private TimeSpan heartbeatInterval;  // Set in Run() once context is available.
    // After sending heartbeats, wait this long to collect acks before processing
    private DateTime? heartbeatAckDeadline = null;
    // Collected acks for the current heartbeat round: meshIP -> set of connected mesh IPs
    private Dictionary<string, HashSet<string>> heartbeatAcks = new Dictionary<string, HashSet<string>>();
    // Track all known mesh IPs we've sent heartbeats to (for completeness checking)
    private HashSet<string> heartbeatTargets = new HashSet<string>();
    // Track consecutive heartbeat misses per peer (introducer only)
    private Dictionary<string, int> heartbeatMissCount = new Dictionary<string, int>();
    private int peerDeadThreshold;  // Set in Run() once context is available.
    // Track mesh startup time for uptime calculation in MeshState
    private DateTime meshStartTime = DateTime.UtcNow;

    // Last user-facing error the engine hit. Surfaced via MeshState so the GUI can pop a
    // dialog explaining what went wrong (version mismatch, bad secret, etc.).
    private string lastError;
    private string lastErrorKind;

    /// <summary>
    /// Resolves the mediation endpoint. Uses <see cref="MeshOptions.MediationEndpoint"/> directly
    /// when the caller pre-resolved it (embedded mode); otherwise resolves
    /// <see cref="MeshOptions.MediationHost"/> via DNS at connect time (daemon mode), preferring
    /// IPv4 with an IPv6 fallback. Returns null on failure instead of throwing — the connect loop
    /// treats that as a retryable config error (idles with lastErrorKind="ConfigError") so an
    /// unresolvable host doesn't crash the daemon and a later fix recovers without a restart.
    /// </summary>
    private IPEndPoint ResolveMediationEndpoint()
    {
        if (context.Options.MediationEndpoint != null)
            return context.Options.MediationEndpoint;

        string host = context.Options.MediationHost;
        if (string.IsNullOrEmpty(host))
        {
            lastError = "No mediation server configured.";
            lastErrorKind = "ConfigError";
            return null;
        }
        try
        {
            var addresses = Dns.GetHostAddresses(host);
            var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
            if (ip == null)
            {
                lastError = $"Mediation server '{host}' did not resolve to any IP address.";
                lastErrorKind = "ConfigError";
                return null;
            }
            return new IPEndPoint(ip, context.Options.MediationPort);
        }
        catch (Exception ex)
        {
            lastError = $"Could not resolve mediation server '{host}': {ex.Message}";
            lastErrorKind = "ConfigError";
            return null;
        }
    }

    /// <summary>
    /// Daemon entry point. Defaults to <see cref="DaemonContext"/> + the WireGuard tunnel as
    /// host. Delegates to the context-aware overload after constructing the daemon context.
    /// </summary>
    public void Run(WireGuardTunnel wireguardTunnel, string meshIP, UdpClient udpClient, WireGuardUdpProxy udpProxy, Guid peerID)
    {
        Run(wireguardTunnel, new DaemonContext(), meshIP, udpClient, udpProxy, peerID, TunnelOptions.IdentityPrivateKey, TunnelOptions.BlockedFingerprints);
    }

    /// <summary>
    /// Context-aware entry point. Embedded callers construct their own <see cref="IMeshHost"/>
    /// (<see cref="Embedded.EmbeddedMeshHost"/>) + <see cref="IMeshDaemonContext"/>
    /// (<see cref="Embedded.EmbeddedContext"/>) and call this overload. Daemon delegates here
    /// from the legacy overload above.
    /// </summary>
    public void Run(IMeshHost host, IMeshDaemonContext context, string meshIP, UdpClient udpClient, WireGuardUdpProxy udpProxy, Guid peerID, byte[] identityPrivateKey = null, HashSet<string> blockedFingerprints = null)
    {
        this.host = host;
        this.context = context;
        this.identityPrivateKey = identityPrivateKey;
        this.ownIdentityPublicKey = identityPrivateKey != null ? DeriveIdentityPublicKey(identityPrivateKey) : null;
        this.blockedFingerprints = blockedFingerprints ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Resolve TimeSpan/int fields that previously had inline initializers reading from
        // TunnelOptions statics. Field initializers can't read instance fields, so they are
        // resolved here once the context is available.
        this.repairCooldown = TimeSpan.FromSeconds(context.Options.RepairCooldownSeconds);
        this.introducerProbeInterval = TimeSpan.FromSeconds(context.Options.ProbeIntervalSeconds);
        this.peerDiscoveryInterval = TimeSpan.FromSeconds(context.Options.HeartbeatIntervalSeconds);
        this.heartbeatInterval = TimeSpan.FromSeconds(context.Options.HeartbeatIntervalSeconds);
        this.peerDeadThreshold = context.Options.DeadThreshold;

        this.meshIP = meshIP;
        this.udpClient = udpClient;
        this.udpProxy = udpProxy;
        this.peerID = peerID;

        // Register the state provider early so /status returns the engine's real state
        // (including lastError) even when the mediation handshake fails and we never reach
        // the deeper Run initialization.
        context.RegisterMeshStateProvider(GetMeshState);

        // Derive the values that used to be locals in Program.RunMeshMode.
        // localUdpPort is the UDP socket's bound port; mediation correlates incoming
        // NAT test packets by it. hash is SHA256(peerID) for mesh-IP collision resolution.
        localUdpPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;
        hash = System.Security.Cryptography.SHA256.HashData(peerID.ToByteArray());

        // Bind the mesh control UDP socket once — it survives across reconnect cycles
        // and feeds the background listener that all peers depend on. Port is configurable
        // (defaults to 51888) so multiple embedded instances on the same machine can run.
        int meshControlPort = context.Options.MeshControlPort;
        try
        {
            meshControlClient = new UdpClient(meshControlPort);
            context.Log(LogLevel.Info, $"[Mesh] Mesh control listening on UDP port {meshControlPort}");
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"[Mesh] Cannot bind mesh control port {meshControlPort}/UDP — another instance may already be running. ({ex.Message})");
            return;
        }

        // Mediation endpoint is resolved per connect attempt inside the loop below (DNS is
        // deferred so an unresolvable host idles rather than crashes).

        // Compute auth token once — doesn't depend on mediation state.
        authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(context.Options.NetworkID + ":" + context.Options.NetworkSecret)));

        StartUdpListener();

        try
        {
            // Guards to prevent re-starting one-time background tasks on reconnect
            bool udpDispatcherStarted = false;

            // === OUTER CONNECT LOOP ===
            // Wraps mediation handshake + setup loop + mesh-control loop.
            // On disconnect, we return here to idle and wait for reconnect.
            bool isFirstIteration = true;
            while (!context.ShutdownRequested)
            {
                // First iteration: if AutoConnect is off, idle until /connect arrives. Subsequent
                // iterations rely on the existing disconnect-then-idle path further below.
                if (isFirstIteration && !context.Options.AutoConnect)
                {
                    isFirstIteration = false;
                    context.ConnectionState = MeshConnectionState.Disconnected;
                    context.Log(LogLevel.Info, "[Mesh] Idle (autoConnect=false). Waiting for /connect request...");
                    while (!context.ShutdownRequested && !context.ConnectRequested)
                        System.Threading.Thread.Sleep(100);
                    context.ConnectRequested = false;
                    if (context.ShutdownRequested) break;
                }
                isFirstIteration = false;

                context.ConnectionState = MeshConnectionState.Connecting;
                context.DisconnectRequested = false;

                // Resolve the mediation endpoint now (DNS is deferred to connect time). On failure
                // — unresolvable host, bad config — idle in a Disconnected/ConfigError state the GUI
                // surfaces via /status, then retry so a corrected config recovers without a restart.
                endpoint = ResolveMediationEndpoint();
                if (endpoint == null)
                {
                    context.ConnectionState = MeshConnectionState.Disconnected;
                    context.Log(LogLevel.Error, $"[Mesh] {lastError} — retrying in 10s (fix the mediationEndpoint in config).");
                    for (int i = 0; i < 100 && !context.ShutdownRequested && !context.ConnectRequested; i++)
                        System.Threading.Thread.Sleep(100);
                    continue;
                }

                {
                    int handshakeDelay = 5;
                    for (int attempt = 1; ; attempt++)
                    {
                        if (context.ShutdownRequested) return;
                        if (context.DisconnectRequested) break;
                        try
                        {
                            // 1. TCP connect (with 5s timeout so DisconnectRequested is checked promptly).
                            // Address family must match the endpoint — the parameterless ctor is IPv4-only.
                            tcpClient = new TcpClient(endpoint.Address.AddressFamily);
                            tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                            var connectResult = tcpClient.BeginConnect(endpoint.Address, endpoint.Port, null, null);
                            bool connected = connectResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5));
                            if (!connected || context.DisconnectRequested)
                            {
                                tcpClient.Close();
                                if (context.DisconnectRequested) break;
                                throw new System.Net.Sockets.SocketException(10060); // WSAETIMEDOUT
                            }
                            tcpClient.EndConnect(connectResult);
                            if (context.Options.TlsEnabled)
                            {
                                var sslStream = new SslStream(tcpClient.GetStream(), false,
                                    context.Options.TlsAllowSelfSigned
                                        ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                                        : null);
                                sslStream.AuthenticateAsClient(endpoint.Address.ToString());
                                stream = sslStream;
                                context.Log(LogLevel.Info, $"[Mesh] TLS handshake complete (protocol: {sslStream.SslProtocol})");
                            }
                            else
                            {
                                stream = tcpClient.GetStream();
                            }
                            stream.ReadTimeout = 15000;
                            earlyTcpRemainder = "";

                            // Steps 2-4: NAT detection + MeshJoinRequest/Response. Extracted so
                            // the embedded entry point can reuse the same protocol handshake
                            // against a TCP stream it opened on its own.
                            if (!PerformProtocolHandshake())
                            {
                                // Auth or version failure. Drop into idle instead of exiting so
                                // the GUI can still poll /status and see the error we captured
                                // in lastError before the user disconnects or updates.
                                context.ConnectionState = MeshConnectionState.Disconnected;
                                try { tcpClient?.Dispose(); } catch { }
                                tcpClient = null; stream = null; earlyTcpRemainder = "";
                                while (!context.ShutdownRequested && !context.ConnectRequested)
                                    System.Threading.Thread.Sleep(100);
                                context.ConnectRequested = false;
                                context.ReloadConfig();
                                // endpoint is re-resolved at the top of the outer connect loop.
                                authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                                    Encoding.UTF8.GetBytes(context.Options.NetworkID + ":" + context.Options.NetworkSecret)));
                                // Clear the error so a fresh reconnect attempt starts clean.
                                lastError = null; lastErrorKind = null;
                                continue;
                            }
                            handshakeDelay = 5; // Reset on success
                            break;
                        }
                        catch (Exception ex) when (!context.ShutdownRequested)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Mediation handshake failed: {ex.Message}");
                            try { tcpClient?.Dispose(); } catch { }
                            tcpClient = null;
                            stream = null;
                            earlyTcpRemainder = "";
                            context.Log(LogLevel.Debug, $"[Mesh] Retrying in {handshakeDelay}s (attempt {attempt})...");
                            // Sleep in short intervals so DisconnectRequested is checked promptly
                            for (int ms = 0; ms < handshakeDelay * 1000 && !context.DisconnectRequested && !context.ShutdownRequested; ms += 100)
                                System.Threading.Thread.Sleep(100);
                            handshakeDelay = Math.Min(handshakeDelay * 2, 30);
                        }
                    }
                    if (context.ShutdownRequested) return;
                }

                // If disconnect was requested during handshake, skip to idle
                if (context.DisconnectRequested)
                {
                    context.ConnectionState = MeshConnectionState.Disconnected;
                    try { tcpClient?.Dispose(); } catch { }
                    tcpClient = null; stream = null;
                    context.Log(LogLevel.Debug, "[Mesh] Disconnected during handshake — waiting for reconnect");
                    while (!context.ShutdownRequested && !context.ConnectRequested)
                        System.Threading.Thread.Sleep(100);
                    context.ConnectRequested = false;
                    // Reload config in case settings changed while idle
                    context.ReloadConfig();
                    // endpoint is re-resolved at the top of the outer connect loop.
                    authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                        Encoding.UTF8.GetBytes(context.Options.NetworkID + ":" + context.Options.NetworkSecret)));
                    continue; // Back to outer connect loop
                }

                context.ConnectionState = MeshConnectionState.Connected;

                // Set a short poll timeout for the main loop so it doesn't block on stream.Read()
                // while still doing heartbeats, tunnel management, etc.
                // SslStream doesn't support DataAvailable, so we use timeout-based polling instead.
                stream.ReadTimeout = 100;

                // Clear per-connect tracking state (preserves closure references for background tasks)
                activePeerTunnels.Clear();
                pendingConnectionRequests.Clear();
                lastStaleWarningAt.Clear();
                activeConnectionTunnels.Clear();
                incompatiblePeers.Clear();
                connectionIDToPeerID.Clear();
                peerMeshIPs.Clear();
                pendingTunnelCount = 0;
                deferredIntroductions.Clear();
                completedTunnelMeshIPs.Clear();
                relayedPairs.Clear();
                lastRepairAttempt.Clear();
                repairAttemptCount.Clear();
                isIntroducer = false;

                // Populate peerInfoByMeshIP and introducer mesh IP from the initial MeshJoinResponse.
                // This is critical for failover: if this peer later becomes the introducer,
                // it needs to know every peer's NAT type to decide relay vs direct hole-punch.
                if (joinResponse.Peers != null)
                {
                    foreach (var peer in joinResponse.Peers)
                    {
                        var pObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                        string pid = pObj.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                        string mip = pObj.TryGetProperty("meshIP", out JsonElement mipEl) ? mipEl.GetString() : null;
                        string ep = pObj.TryGetProperty("endpoint", out JsonElement epEl) ? epEl.GetString() : null;
                        int nt = pObj.TryGetProperty("natType", out JsonElement ntEl) ? ntEl.GetInt32() : -1;
                        int pminV = pObj.TryGetProperty("peerMinVersion", out JsonElement pminEl) ? pminEl.GetInt32() : 1;
                        int pmaxV = pObj.TryGetProperty("peerMaxVersion", out JsonElement pmaxEl) ? pmaxEl.GetInt32() : 1;
                        string idPub = pObj.TryGetProperty("identityPublicKey", out JsonElement idEl) ? idEl.GetString() : null;
                        string epV6 = pObj.TryGetProperty("endpointV6", out JsonElement epV6El) ? epV6El.GetString() : null;

                        if (!string.IsNullOrEmpty(mip))
                        {
                            peerInfoByMeshIP[mip] = (pid, ep, (NATType)nt, pminV, pmaxV, idPub, epV6);
                            MarkRecentlySeen(mip, pid);
                        }

                        if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                            pid == joinResponse.IntroducerPeerID && !string.IsNullOrEmpty(mip))
                        {
                            introducerMeshIP = mip;
                            context.Log(LogLevel.Info, $"[Mesh] Introducer mesh IP: {introducerMeshIP} (peer {pid})");
                        }
                    }
                    context.Log(LogLevel.Debug, $"[Mesh] Cached {peerInfoByMeshIP.Count} peer(s) from initial join response");
                }

                // Detect mesh IP collision with an existing peer and reassign if needed.
                // The hash space is only 16 bits (~65K IPs), so collisions become probable at ~300+ peers.
                // We try successive pairs of SHA256 bytes (offset 0, 2, 4, ...) until we find a free slot.
                var takenMeshIPs = new HashSet<string>(peerInfoByMeshIP.Keys);
                if (takenMeshIPs.Contains(meshIP))
                {
                    string originalMeshIP = meshIP;
                    bool resolved = false;
                    for (int offset = 2; offset < hash.Length - 1; offset += 2)
                    {
                        byte c3 = hash[offset];
                        byte c4 = (byte)((hash[offset + 1] % 254) + 1);
                        string candidate = $"{context.Options.MeshSubnet}.{c3}.{c4}";
                        if (!takenMeshIPs.Contains(candidate))
                        {
                            meshIP = candidate;
                            resolved = true;
                            break;
                        }
                    }
                    if (resolved)
                    {
                        context.Log(LogLevel.Warning, $"[Mesh] WARNING: Mesh IP collision detected ({originalMeshIP} already taken). Reassigning to {meshIP}.");
                        host.SetClientIPAndRestart(meshIP, 16);

                        // Notify the mediation server of the reassignment. Without this the server
                        // keeps serving our original (colliding) mesh IP to other peers, who can't
                        // then reach us. Suppress send failures here — initial join already succeeded
                        // and a transient TCP hiccup shouldn't abort startup; if it persists, future
                        // reconnects will re-send PrivateAddressString in their MeshJoinRequest.
                        try
                        {
                            var reassign = new MediationMessage(MediationMessageType.MeshIPReassign)
                            {
                                PeerID = peerID.ToString(),
                                PrivateAddressString = meshIP
                            };
                            byte[] reassignBytes = Encoding.ASCII.GetBytes(reassign.Serialize());
                            stream.Write(reassignBytes, 0, reassignBytes.Length);
                            stream.Flush();
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to notify mediation of mesh IP reassignment: {ex.Message}");
                        }
                    }
                    else
                    {
                        context.Log(LogLevel.Warning, $"[Mesh] WARNING: Mesh IP collision detected ({originalMeshIP} already taken) and no free slot found in hash offsets. Keeping original IP — connectivity may be impaired.");
                    }
                }

                // Process initial peer list
                if (joinResponse.Peers != null && joinResponse.Peers.Length > 0)
                {
                    ProcessDiscoveredPeers(joinResponse.Peers);
                }
                else
                {
                    context.Log(LogLevel.Debug, "[Mesh] No other peers in network yet - waiting for others to join...");
                }

                // Keep connection alive and listen for ConnectionBegin messages
                context.Log(LogLevel.Info, "[Mesh] Mesh networking active. Waiting for connections...");
                context.Log(LogLevel.Info, "[Mesh] Press Ctrl+C to exit.");

                // Set to true when the server designates us as the introducer (via MeshIntroduceRequest
                // or via IntroducerPeerID in MeshJoinResponse). Introducers must keep the mediation
                // TCP connection alive indefinitely so the server can push future requests to us.

                // Check if the server already told us we're the introducer in the join response.
                // Also: if we're non-symmetric and no other non-symmetric peer exists in the network,
                // we'll definitely be the introducer for the next joiner — stay connected proactively.
                if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                    joinResponse.IntroducerPeerID == peerID.ToString())
                {
                    isIntroducer = true;
                    context.Log(LogLevel.Info, "[Mesh] Server designated us as the introducer in join response");
                }
                else if (detectedNatType != NATType.Symmetric && joinResponse.Peers != null)
                {
                    // Check if any other non-symmetric peer exists (who could serve as introducer instead)
                    bool otherNonSymmetricExists = false;
                    foreach (var peer in joinResponse.Peers)
                    {
                        var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                        string peerId = peerObj.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                        int natTypeInt = peerObj.TryGetProperty("natType", out JsonElement natEl) ? natEl.GetInt32() : -1;
                        if (peerId != peerID.ToString() && natTypeInt >= 0 && (NATType)natTypeInt != NATType.Symmetric)
                        {
                            otherNonSymmetricExists = true;
                            break;
                        }
                    }
                    if (!otherNonSymmetricExists)
                    {
                        isIntroducer = true;
                        context.Log(LogLevel.Info, "[Mesh] We're the only non-symmetric peer — staying connected as potential introducer");
                    }
                }

                // Set up periodic keep-alive
                var lastKeepAlive = DateTime.UtcNow;
                var keepAliveInterval = TimeSpan.FromSeconds(5); // Keep-alive is fast; not configurable

                // Track mesh startup time for uptime calculation in MeshState
                var meshStartTime = DateTime.UtcNow;

                // Grace period: once all initial connections are established, wait before
                // disconnecting to give disconnected peers time to TransientReconnect.
                DateTime? disconnectAfter = null;
                DateTime lastNotReadyLog = DateTime.MinValue;
                bool hasPeers = joinResponse.Peers != null && joinResponse.Peers.Length > 0;

                // TCP reassembly buffer — accumulates partial JSON across reads
                // Seed with any leftover from early TCP reads (e.g. ConnectionBegin
                // messages that arrived concatenated with the MeshJoinResponse)
                string tcpBuffer = earlyTcpRemainder;

                // ── Shared UDP dispatcher ─────────────────────────────────────────────────
                // All mesh Tunnel instances share the same udpClient socket. Only ONE receive
                // loop must run on it; each received packet is dispatched to ALL active tunnels
                // via ProcessUdpPacket(). Without this, multiple UdpClientListenLoop() calls
                // on the same socket race for packets and most tunnels miss most messages.
                if (!udpDispatcherStarted)
                {
                    udpDispatcherStarted = true;
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                        context.Log(LogLevel.Debug, "[Mesh] Shared UDP dispatcher started");
                        while (true)
                        {
                            try
                            {
                                byte[] data = udpClient.Receive(ref ep);
                                // Dual-stack sockets report IPv4 senders as ::ffff:a.b.c.d — unwrap
                                // so endpoint comparisons downstream match plain-v4 endpoints.
                                ep = EndpointUtils.Normalize(ep);

                                // Blocked-peer packet drop: if the source endpoint matches a peer
                                // we've blocked, discard silently. Prevents stray hole-punch retries
                                // or orphan tunnels from processing traffic after a block.
                                // Normalized so v4-mapped sources on a dual-stack socket still match
                                // block entries stored as plain IPv4.
                                string sourceEndpoint = EndpointUtils.Format(ep);
                                if (blockedEndpoints.ContainsKey(sourceEndpoint) ||
                                    blockedIPs.ContainsKey(EndpointUtils.Normalize(ep.Address).ToString()))
                                {
                                    context.Log(LogLevel.Debug, $"[Mesh] Dispatcher dropping packet from blocked source {sourceEndpoint}");
                                    continue;
                                }

                                // WireGuard packets (binary, message type 1-4): forward directly to the
                                // proxy ONCE instead of dispatching to every tunnel. This avoids O(N)
                                // duplicate forwards that degrade throughput with more peers.
                                // The `host is WireGuardTunnel` gate keeps embedded mode out of this
                                // fast path — embedded uses byte 0x01 as its encrypted-data envelope,
                                // which would match the range and get routed to a host stub that drops
                                // it. Embedded data packets need the per-tunnel fan-out below.
                                bool isWireGuard = data.Length > 0 &&
                                                  data[0] != (byte)'{' &&
                                                  data[0] != (byte)'[' &&
                                                  data[0] >= 1 && data[0] <= 4 &&
                                                  host is WireGuardTunnel;

                                if (isWireGuard)
                                {
                                    host?.ForwardDataPacket(data, ep);
                                }
                                else
                                {
                                    // JSON control packets: snapshot tunnels and dispatch for filtering
                                    Tunnel[] tunnels;
                                    lock (meshLock)
                                    {
                                        tunnels = new Tunnel[activeConnectionTunnels.Count];
                                        activeConnectionTunnels.Values.CopyTo(tunnels, 0);
                                    }

                                    foreach (var tunnel in tunnels)
                                    {
                                        try
                                        {
                                            tunnel.ProcessUdpPacket(data, ep);
                                        }
                                        catch (System.Net.Sockets.SocketException)
                                        {
                                            // Non-matching tunnel — socket not connected to this endpoint, ignore
                                        }
                                        catch (System.Security.Cryptography.CryptographicException)
                                        {
                                            // Non-matching tunnel — can't decrypt with this tunnel's key, ignore
                                        }
                                        catch (Exception ex)
                                        {
                                            context.Log(LogLevel.Error, $"[Mesh] Error dispatching packet to tunnel: {ex.Message}");
                                        }
                                    }
                                }
                            }
                            catch (SocketException)
                            {
                                // Socket closed — shutting down
                                break;
                            }
                            catch (ObjectDisposedException)
                            {
                                break;
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] UDP dispatcher error: {ex.Message}");
                            }
                        }
                    });
                } // end udpDispatcherStarted guard

                // Engine state is now ready — wire it up so the HTTP /status endpoint returns real data.
                context.RegisterMeshStateProvider(GetMeshState);

                // Track consecutive failed introducer connection retries.
                // After too many failures, break out to force a fresh mediation reconnection.
                int introducerRetryCount = 0;
                const int MaxIntroducerRetries = 5;

                // Message loop - create Tunnel instances when ConnectionBegin arrives.
                // Non-introducer peers disconnect once their initial connections are established
                // and reconnect transiently for each future introduced peer.
                // The introducer peer stays connected permanently to receive MeshIntroduceRequests.
                while (!context.ShutdownRequested && !context.DisconnectRequested)
                {
                    // Disconnect once all initial setup is done, but only if we haven't been
                    // selected as the introducer (introducers must stay connected).
                    // Use a grace period to give disconnected peers time to TransientReconnect.
                    if (!isIntroducer && tcpClient.Connected && hasPeers)
                    {
                        // Only ready to disconnect if no pending work AND at least one tunnel actually
                        // succeeded. If all connections failed and we have zero WireGuard peers, we're
                        // isolated — stay connected so the server can assign new connections.
                        if (pendingTunnelCount < 0) pendingTunnelCount = 0; // Guard against double-decrement race
                                                                            // pendingConnectionRequests = waiting for MeshConnectionBegin from server (network dependency)
                                                                            // pendingTunnelCount = WireGuard setup in progress locally — don't block mediation disconnect
                                                                            // if a tunnel callback got lost; if the peer is in activePeerTunnels it's connected enough.
                        bool noPendingWork = pendingConnectionRequests.Count == 0;
                        // A tunnel in activePeerTunnels only means the Tunnel OBJECT was created —
                        // not that its hole-punch completed. Symmetric peers can take much longer
                        // than the grace period to actually establish (the 256-probe spray needs
                        // the peer to punch back). Gating readiness on mere presence disconnected
                        // us from mediation mid-punch, so the introducer tunnel never finished and
                        // mesh-control never flowed → introducer looked dead. Require an ACTUALLY
                        // completed tunnel (completedTunnelMeshIPs is populated by onConnectionComplete).
                        bool hasEstablishedTunnels = completedTunnelMeshIPs.Count > 0;

                        // Before disconnecting, verify we have a completed tunnel specifically to the
                        // introducer. Without this, the introducer can't send us MeshConnectionBegin
                        // messages for newly joining peers, cutting us off from the rest of the network.
                        bool hasIntroducerPath = false;
                        if (hasEstablishedTunnels && !string.IsNullOrEmpty(introducerMeshIP))
                        {
                            hasIntroducerPath = completedTunnelMeshIPs.Contains(introducerMeshIP);
                        }

                        bool readyToDisconnect = noPendingWork && hasEstablishedTunnels && hasIntroducerPath;

                        if (!readyToDisconnect && disconnectAfter == null &&
                            (DateTime.UtcNow - lastNotReadyLog).TotalSeconds >= 10)
                        {
                            lastNotReadyLog = DateTime.UtcNow;
                            context.Log($"[Mesh] Not ready to disconnect: noPendingWork={noPendingWork}(pending={pendingConnectionRequests.Count},tunnels={pendingTunnelCount}), established={hasEstablishedTunnels}(count={activePeerTunnels.Count}), introducerPath={hasIntroducerPath}(introducerIP={introducerMeshIP ?? "null"},completed={completedTunnelMeshIPs.Count},introducerPeerID={joinResponse.IntroducerPeerID ?? "null"})");
                        }

                        if (readyToDisconnect && disconnectAfter == null)
                        {
                            int gracePeriod = detectedNatType != NATType.Symmetric ? context.Options.GracePeriodSecondsNonSymmetric : context.Options.GracePeriodSecondsSymmetric;
                            disconnectAfter = DateTime.UtcNow.AddSeconds(gracePeriod);
                            context.Log(LogLevel.Debug, $"[Mesh] All initial connections established — grace period started ({gracePeriod}s)");
                        }
                        else if (!readyToDisconnect && disconnectAfter != null)
                        {
                            // New connection arrived during grace period — reset timer
                            disconnectAfter = null;
                            context.Log(LogLevel.Debug, "[Mesh] New connection activity — grace period reset");
                        }
                        else if (readyToDisconnect && disconnectAfter != null && DateTime.UtcNow > disconnectAfter.Value)
                        {
                            context.Log(LogLevel.Warning, "[Mesh] Grace period elapsed — disconnecting from mediation server");
                            tcpClient.Close();
                            break;
                        }
                    }

                    // Bail if the connection dropped unexpectedly during setup
                    if (!tcpClient.Connected)
                    {
                        if (isIntroducer)
                            context.Log(LogLevel.Warning, "[Mesh] Mediation server connection lost — introducer role ended");
                        else
                            context.Log(LogLevel.Debug, "[Mesh] TCP connection to mediation server lost during setup");
                        break;
                    }

                    // Clean up stale pending connection requests: if a request has been pending
                    // for over 10s without a ConnectionBegin arriving, the target peer is likely
                    // gone (disconnected, ServerNotAvailable lost, etc.)
                    if (pendingConnectionRequests.Count > 0)
                    {
                        var staleTimeout = TimeSpan.FromSeconds(context.Options.StaleTimeoutSeconds);
                        var now = DateTime.UtcNow;
                        var staleRequests = pendingConnectionRequests
                            .Where(kvp => now - kvp.Value > staleTimeout)
                            .Select(kvp => kvp.Key)
                            .ToList();
                        foreach (var staleID in staleRequests)
                        {
                            pendingConnectionRequests.Remove(staleID);
                            // Dedupe: ghost peers (never-responding) get re-added by other loops
                            // and would otherwise log this warning every StaleTimeoutSeconds.
                            // Cap to once per StaleWarningCooldown per peer.
                            if (!lastStaleWarningAt.TryGetValue(staleID, out var lastAt) || now - lastAt > StaleWarningCooldown)
                            {
                                context.Log(LogLevel.Warning, $"[Mesh] Removed stale pending connection request for {staleID} (no response in {staleTimeout.TotalSeconds}s)");
                                lastStaleWarningAt[staleID] = now;
                            }
                        }
                    }

                    // Send periodic keep-alive to prevent timeout during setup
                    if (DateTime.UtcNow - lastKeepAlive > keepAliveInterval)
                    {
                        try
                        {
                            var keepAliveMsg = new MediationMessage(MediationMessageType.KeepAlive);
                            string keepAliveJson = keepAliveMsg.Serialize();
                            byte[] keepAliveBuffer = Encoding.ASCII.GetBytes(keepAliveJson);
                            stream.Write(keepAliveBuffer, 0, keepAliveBuffer.Length);
                            lastKeepAlive = DateTime.UtcNow;
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Keep-alive write failed, connection lost: {ex.Message}");
                            break;
                        }
                    }

                    // Periodic peer discovery: if we have no WireGuard peers and no pending
                    // connections, re-send MeshJoinRequest to discover newly available peers.
                    // Also fire immediately after an unblock so the server broadcasts a fresh
                    // MeshIntroduceRequest — we tore the unblocked peer's tunnel down at block
                    // time, and no other path rebuilds it without server participation.
                    bool triggerRediscovery = rediscoveryRequestedAfterUnblock;
                    if (triggerRediscovery) rediscoveryRequestedAfterUnblock = false;
                    if (tcpClient.Connected &&
                        (triggerRediscovery ||
                         (activePeerTunnels.Count == 0 &&
                          pendingConnectionRequests.Count == 0 && pendingTunnelCount == 0 &&
                          DateTime.UtcNow - lastPeerDiscovery > peerDiscoveryInterval)))
                    {
                        context.Log(LogLevel.Debug, triggerRediscovery
                            ? "[Mesh] Unblock detected — sending discovery request to prompt fresh introduction"
                            : "[Mesh] No active peers — sending periodic discovery request");
                        try
                        {
                            var discoveryRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
                            {
                                NetworkID = context.Options.NetworkID,
                                PeerID = peerID.ToString(),
                                NATType = detectedNatType,
                                PrivateAddressString = meshIP,
                                AuthToken = authToken,
                                ProtocolVersion = MediationProtocol.ClientVersion,
                                PeerMinVersion = MediationProtocol.PeerMinVersion,
                                PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                                IdentityPublicKey = OwnIdentityPublicKeyB64
                            };
                            string discoveryJson = discoveryRequest.Serialize();
                            byte[] discoveryBuffer = Encoding.ASCII.GetBytes(discoveryJson);
                            stream.Write(discoveryBuffer, 0, discoveryBuffer.Length);
                            stream.Flush();
                            lastPeerDiscovery = DateTime.UtcNow;
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Discovery write failed, connection lost: {ex.Message}");
                            break;
                        }
                    }

                    // Retry connecting to the introducer if we don't have a tunnel to it yet.
                    // The initial attempt may fail (e.g. hole-punch timeout) but we must stay
                    // connected to mediation and keep retrying until the introducer link is up,
                    // otherwise we can't receive MeshConnectionBegin for future peers.
                    // After MaxIntroducerRetries failures, force a full reconnection to mediation
                    // to get fresh endpoint info.
                    if (!isIntroducer && tcpClient.Connected &&
                        !string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                        !activePeerTunnels.ContainsKey(joinResponse.IntroducerPeerID) &&
                        !(introducerMeshIP != null && activePeerTunnels.ContainsKey(introducerMeshIP)) &&
                        !pendingConnectionRequests.ContainsKey(joinResponse.IntroducerPeerID) &&
                        !incompatiblePeers.ContainsKey(joinResponse.IntroducerPeerID) &&
                        pendingTunnelCount == 0)
                    {
                        introducerRetryCount++;
                        if (introducerRetryCount > MaxIntroducerRetries)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Introducer connection failed after {MaxIntroducerRetries} retries — disconnecting to force fresh mediation reconnection");
                            introducerRetryCount = 0;
                            try { tcpClient.Close(); } catch { }
                            break; // Break to mesh-control-only loop; isolation detection will reconnect
                        }

                        context.Log(LogLevel.Debug, $"[Mesh] Retrying connection to introducer {joinResponse.IntroducerPeerID} (attempt {introducerRetryCount}/{MaxIntroducerRetries})");
                        try
                        {
                            var retryReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                            {
                                PeerID = joinResponse.IntroducerPeerID,
                                NATType = detectedNatType
                            };
                            byte[] retryBuf = Encoding.ASCII.GetBytes(retryReq.Serialize());
                            stream.Write(retryBuf, 0, retryBuf.Length);
                            stream.Flush();
                            pendingConnectionRequests[joinResponse.IntroducerPeerID] = DateTime.UtcNow;
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Introducer retry write failed: {ex.Message}");
                            break;
                        }
                    }
                    // Reset retry counter when we have a working introducer tunnel
                    else if (!isIntroducer &&
                        !string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                        (activePeerTunnels.ContainsKey(joinResponse.IntroducerPeerID) ||
                         (introducerMeshIP != null && activePeerTunnels.ContainsKey(introducerMeshIP))))
                    {
                        if (introducerRetryCount > 0)
                        {
                            context.Log(LogLevel.Info, $"[Mesh] Introducer connection restored after {introducerRetryCount} retries");
                            introducerRetryCount = 0;
                        }
                    }

                    DrainInboundQueues();

                    ProbeIntroducerHealth_PrimaryLoop();

                    RunIntroducerHeartbeat(tcpClient, stream);

                    SendLatencyPingsAndHealthProbe();

                    if (!ReadAndDispatchMediationMessages(ref tcpBuffer, ref hasPeers))
                        break;

                    System.Threading.Thread.Sleep(100);
                }

                // ── Mesh-control-only loop ──────────────────────────────────────────────────────
                // Non-introducer peers reach here after disconnecting from the mediation server.
                // They are fully self-sufficient: all new connections are coordinated by the
                // introducer over WireGuard (MeshConnectionBegin messages on port 51888).
                // If all WireGuard peers are lost, reconnect to the mediation server.
                if (context.ShutdownRequested)
                {
                    PerformGracefulShutdown();
                    return;
                }
                // If disconnect was requested during setup loop, skip mesh-control and go to idle
                if (context.DisconnectRequested)
                {
                    // Fall through to disconnect handling after the mesh-control loop
                }
                else
                {

                    context.Log(LogLevel.Info, "[Mesh] Entering mesh-control-only mode (fully disconnected from mediation server)");

                    // Relay health check: periodically verify relay gateway peers are still alive.
                    // If a relay gateway's WireGuard peer has had no activity for this duration,
                    // clean up stale relay routes locally.
                    const int RelayHealthCheckIntervalMs = 10000; // Check every 10 seconds
                    const int RelayGatewayTimeoutSeconds = 120;   // Gateway considered dead after 2 minutes of inactivity
                    var lastRelayHealthCheck = DateTime.UtcNow;

                    // Isolation detection: if all WireGuard peers are dead, reconnect to mediation.
                    var lastIsolationCheck = DateTime.UtcNow;
                    var isolationCheckInterval = TimeSpan.FromSeconds(30);
                    // isolationDetectedAt, reconnectedTcpClient, reconnectedStream, lastReconnectDiscovery
                    // are now fields on MeshProtocolEngine — reset to fresh state for this loop entry.
                    isolationDetectedAt = null;
                    reconnectedTcpClient = null;
                    reconnectedStream = null;
                    lastReconnectDiscovery = null;
                    int IsolationGracePeriodSeconds = context.Options.IsolationGracePeriodSeconds; // Wait before reconnecting to avoid thrashing
                    string reconnectedTcpBuffer = ""; // Accumulates partial TCP data across reads
                    int reconnectDiscoverySeconds = context.Options.HeartbeatIntervalSeconds;
                    int reconnectDiscoveryAttempts = 0;
                    const int MaxReconnectDiscoveryAttempts = 5; // After this many re-sends, tear down and reconnect fresh

                    // Reset probe state when entering mesh-control-only loop
                    lastIntroducerProbe = DateTime.UtcNow;
                    introducerMissedProbes = 0;

                    context.Log($"[Mesh] Entering mesh-control-only loop — isIntroducer={isIntroducer}, natType={detectedNatType}, introducerMeshIP={introducerMeshIP ?? "null"}");

                    while (!context.ShutdownRequested && !context.DisconnectRequested)
                    {
                        DrainInboundQueues();

                        RunIntroducerHeartbeat(reconnectedTcpClient, reconnectedStream);

                        SendLatencyPingsAndHealthProbe();

                        // If we have a reconnected TCP connection, process incoming messages
                        if (reconnectedTcpClient != null && reconnectedTcpClient.Connected)
                        {
                            try
                            {
                                var reconnectedStreamLocal = reconnectedStream;
                                try
                                {
                                    int bytesRead = reconnectedStreamLocal.Read(buffer, 0, buffer.Length);
                                    if (bytesRead > 0)
                                        reconnectedTcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                }
                                catch (IOException) { } // read timeout — no data available this iteration
                                                        // Process any complete JSON messages accumulated in the buffer
                                if (reconnectedTcpBuffer.Length > 0)
                                {
                                    var (parsedMsg, remainder) = ExtractFirstJson(reconnectedTcpBuffer);
                                    while (parsedMsg != null)
                                    {
                                        if (parsedMsg.ID == MediationMessageType.MeshJoinResponse ||
                                            parsedMsg.ID == MediationMessageType.MeshPeerList)
                                        {
                                            if (!string.IsNullOrEmpty(parsedMsg.AuthToken))
                                            {
                                                Console.Error.WriteLine($"[Mesh] Authentication failed on reconnect: {parsedMsg.AuthToken}");
                                            }
                                            else if (parsedMsg.Peers != null && parsedMsg.Peers.Length > 0)
                                            {
                                                context.Log(LogLevel.Debug, $"[Mesh] Reconnect discovery: found {parsedMsg.Peers.Length} peer(s)");
                                                // Cache peer info for heartbeat repair (NAT type, endpoint, etc.)
                                                // Without this, the failover introducer can't detect symmetric peers
                                                // and falls back to direct hole-punching instead of relay mode.
                                                foreach (var peerObj2 in parsedMsg.Peers)
                                                {
                                                    var pe2 = JsonSerializer.Deserialize<JsonElement>(peerObj2.ToString());
                                                    string mip2 = pe2.TryGetProperty("meshIP", out JsonElement mipEl2) ? mipEl2.GetString() : null;
                                                    string ep2 = pe2.TryGetProperty("endpoint", out JsonElement epEl2) ? epEl2.GetString() : null;
                                                    int nt2 = pe2.TryGetProperty("natType", out JsonElement ntEl2) ? ntEl2.GetInt32() : -1;
                                                    string pid2 = pe2.TryGetProperty("peerID", out JsonElement pidEl2) ? pidEl2.GetString() : null;
                                                    int pminV2 = pe2.TryGetProperty("peerMinVersion", out JsonElement pminEl2) ? pminEl2.GetInt32() : 1;
                                                    int pmaxV2 = pe2.TryGetProperty("peerMaxVersion", out JsonElement pmaxEl2) ? pmaxEl2.GetInt32() : 1;
                                                    string idPub2 = pe2.TryGetProperty("identityPublicKey", out JsonElement idEl2) ? idEl2.GetString() : null;
                                                    string epV62 = pe2.TryGetProperty("endpointV6", out JsonElement epV6El2) ? epV6El2.GetString() : null;
                                                    if (!string.IsNullOrEmpty(mip2))
                                                    {
                                                        peerInfoByMeshIP[mip2] = (pid2, ep2, (NATType)nt2, pminV2, pmaxV2, idPub2, epV62);
                                                        MarkRecentlySeen(mip2, pid2);
                                                        context.Log(LogLevel.Debug, $"[Mesh] Cached peer info: {mip2} = NAT:{(NATType)nt2}, endpoint:{ep2}");
                                                    }
                                                }
                                                ProcessDiscoveredPeers(parsedMsg.Peers, reconnectedStreamLocal);
                                            }
                                        }
                                        else if (parsedMsg.ID == MediationMessageType.ConnectionBegin)
                                        {
                                            context.Log(LogLevel.Debug, $"[Mesh] Reconnect: received ConnectionBegin for connection {parsedMsg.ConnectionID}");
                                            // Mirror HandleConnectionBegin's version + block guards. Without these,
                                            // the reconnect path builds a fresh Tunnel and fires InjectConnectionBegin
                                            // (256 symmetric probe sockets) at a peer we already know we won't
                                            // connect to — pure waste, and the tunnel object hangs around until
                                            // its 60s connection timer trips onConnectionFailure.
                                            if (IsIncompatible(parsedMsg.PeerID, parsedMsg.PeerMinVersion, parsedMsg.PeerMaxVersion))
                                            {
                                                context.Log(LogLevel.Debug, $"[Mesh] Reconnect: ignoring ConnectionBegin for {parsedMsg.PeerID} — peer-protocol range v{parsedMsg.PeerMinVersion}-v{parsedMsg.PeerMaxVersion} previously refused");
                                                continue;
                                            }
                                            if (IsBlocked(parsedMsg.IdentityPublicKey))
                                            {
                                                context.Log(LogLevel.Debug, $"[Mesh] Reconnect: ignoring ConnectionBegin for {parsedMsg.PeerID} — peer fingerprint is on local block list");
                                                continue;
                                            }
                                            // Store peer's mesh IP
                                            if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                            {
                                                peerMeshIPs[parsedMsg.ConnectionID] = parsedMsg.PrivateAddressString;
                                                if (!string.IsNullOrEmpty(parsedMsg.PeerID))
                                                {
                                                    // Cache the EXTERNAL endpoint when available — EndpointString
                                                    // may be a LAN endpoint for same-NAT pairs.
                                                    string cacheEndpoint = !string.IsNullOrEmpty(parsedMsg.ExternalEndpointString)
                                                        ? parsedMsg.ExternalEndpointString
                                                        : parsedMsg.EndpointString;
                                                    peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, cacheEndpoint, parsedMsg.NATType, parsedMsg.PeerMinVersion, parsedMsg.PeerMaxVersion, parsedMsg.IdentityPublicKey, parsedMsg.EndpointV6String);
                                                    MarkRecentlySeen(parsedMsg.PrivateAddressString, parsedMsg.PeerID);
                                                }
                                            }

                                            // Clean up any existing tunnel to the same mesh IP before creating a new one.
                                            // Without this, old tunnels completing late overwrite the WireGuard peer's
                                            // endpoint with a stale address, breaking mesh control traffic.
                                            if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                            {
                                                string reconMeshIP = parsedMsg.PrivateAddressString;
                                                // Find and dispose old tunnels to this mesh IP
                                                var oldConnIDs = peerMeshIPs
                                                    .Where(kvp => kvp.Value == reconMeshIP && kvp.Key != parsedMsg.ConnectionID)
                                                    .Select(kvp => kvp.Key).ToList();
                                                foreach (var oldConnID in oldConnIDs)
                                                {
                                                    Tunnel oldTunnel = null;
                                                    lock (meshLock)
                                                    {
                                                        if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                                                            activeConnectionTunnels.Remove(oldConnID);
                                                    }
                                                    if (oldTunnel != null)
                                                    {
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect: disposing old tunnel {oldConnID} for {reconMeshIP} (superseded by {parsedMsg.ConnectionID})");
                                                        try { oldTunnel.Dispose(); } catch { }
                                                    }
                                                    peerMeshIPs.Remove(oldConnID);
                                                }
                                                // Clean up tracking for this mesh IP so the new tunnel starts fresh
                                                activePeerTunnels.Remove(reconMeshIP);
                                                completedTunnelMeshIPs.Remove(reconMeshIP);
                                                if (!string.IsNullOrEmpty(parsedMsg.PeerID))
                                                    activePeerTunnels.Remove(parsedMsg.PeerID);
                                                heartbeatMissCount.Remove(reconMeshIP);
                                            }

                                            if (!activeConnectionTunnels.ContainsKey(parsedMsg.ConnectionID))
                                            {
                                                pendingTunnelCount++;
                                                var capturedConnID = parsedMsg.ConnectionID;
                                                var capturedPeerIDStr = parsedMsg.PeerID;
                                                var capturedMeshIPStr = parsedMsg.PrivateAddressString;
                                                var reconnectTunnel = new Tunnel(
                                                    onConnectionFailure: () =>
                                                    {
                                                        lock (meshLock)
                                                        {
                                                            activeConnectionTunnels.Remove(capturedConnID);
                                                            if (!string.IsNullOrEmpty(capturedPeerIDStr)) activePeerTunnels.Remove(capturedPeerIDStr);
                                                            if (!string.IsNullOrEmpty(capturedMeshIPStr)) activePeerTunnels.Remove(capturedMeshIPStr);
                                                        }
                                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                        System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
                                                    },
                                                    sharedUdpClient: udpClient,
                                                    meshPeerEndpoint: parsedMsg.EndpointString,
                                                    retryInPlace: true,
                                                    sharedClientID: peerID,
                                                    ownMeshIP: meshIP,
                                                    onConnectionComplete: () =>
                                                    {
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect tunnel {capturedConnID} WireGuard established");
                                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                        System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                                                        string helloTarget = null;
                                                        lock (meshLock)
                                                        {
                                                            if (peerMeshIPs.TryGetValue(capturedConnID, out string cMeshIP) && !string.IsNullOrEmpty(cMeshIP))
                                                            {
                                                                completedTunnelMeshIPs.Add(cMeshIP);
                                                                tunnelCompletedAt[cMeshIP] = DateTime.UtcNow;
                                                                helloTarget = cMeshIP;
                                                            }
                                                        }
                                                        if (helloTarget != null) SendMeshVersionHello(helloTarget);
                                                    }
                                                );
                                                host?.ConfigureNewTunnel(reconnectTunnel, capturedPeerIDStr, capturedMeshIPStr);
                                                lock (meshLock) { activeConnectionTunnels[capturedConnID] = reconnectTunnel; }
                                                if (!string.IsNullOrEmpty(capturedPeerIDStr))
                                                {
                                                    pendingConnectionRequests.Remove(capturedPeerIDStr);
                                                    activePeerTunnels[capturedPeerIDStr] = reconnectTunnel;
                                                }
                                                if (!string.IsNullOrEmpty(capturedMeshIPStr))
                                                    activePeerTunnels[capturedMeshIPStr] = reconnectTunnel;
                                                var capturedMsg = parsedMsg;
                                                System.Threading.Tasks.Task.Run(() =>
                                                {
                                                    try
                                                    {
                                                        reconnectTunnel.Start();
                                                        reconnectTunnel.InjectConnectionBegin(
                                                            capturedMsg.EndpointString,
                                                            RemoteNatTypeForEndpoint(capturedMsg.EndpointString, capturedMsg.NATType, capturedMsg.NATTypeV6),
                                                            capturedMsg.OwnNATType ?? OwnNatTypeForEndpoint(capturedMsg.EndpointString),
                                                            capturedMsg.PrivateAddressString);
                                                    }
                                                    catch (Exception ex)
                                                    {
                                                        context.Log(LogLevel.Error, $"[Mesh] Reconnect tunnel error: {ex.Message}");
                                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                    }
                                                });
                                            }
                                        }
                                        else if (parsedMsg.ID == MediationMessageType.MeshIntroduceRequest)
                                        {
                                            if (IsIncompatible(parsedMsg.PeerID, parsedMsg.PeerMinVersion, parsedMsg.PeerMaxVersion) || IsBlocked(parsedMsg.IdentityPublicKey))
                                            {
                                                string reason = IsBlocked(parsedMsg.IdentityPublicKey)
                                                    ? "peer fingerprint is on local block list"
                                                    : $"peer-protocol range v{parsedMsg.PeerMinVersion}-v{parsedMsg.PeerMaxVersion} previously refused";
                                                context.Log(LogLevel.Debug, $"[Mesh] Reconnect: declining introducer role for {parsedMsg.PeerID} — {reason}");
                                                // Ack so the server clears its pending record and stops retrying us.
                                                // Without this, we get a MeshIntroduceRequest every poll interval.
                                                try
                                                {
                                                    var declineAck = new MediationMessage(MediationMessageType.MeshIntroduceAck) { PeerID = parsedMsg.PeerID };
                                                    byte[] declineAckBuf = Encoding.ASCII.GetBytes(declineAck.Serialize());
                                                    reconnectedStream.Write(declineAckBuf, 0, declineAckBuf.Length);
                                                    reconnectedStream.Flush();
                                                }
                                                catch { }
                                                continue;
                                            }
                                            isIntroducer = true;
                                            context.Log(LogLevel.Info, $"[Mesh] Reconnect: selected as introducer for {parsedMsg.PeerID}");

                                            // Cache the new peer's info for heartbeat repair.
                                            // Clear completedTunnelMeshIPs — peer is reconnecting with fresh NAT traversal.
                                            // Clear stale deferred messages — this MeshIntroduce supersedes them.
                                            if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                            {
                                                peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, parsedMsg.EndpointString, parsedMsg.NATType, parsedMsg.PeerMinVersion, parsedMsg.PeerMaxVersion, parsedMsg.IdentityPublicKey, parsedMsg.EndpointV6String);
                                                MarkRecentlySeen(parsedMsg.PrivateAddressString, parsedMsg.PeerID);
                                                completedTunnelMeshIPs.Remove(parsedMsg.PrivateAddressString);
                                                deferredIntroductions.Remove(parsedMsg.PrivateAddressString);
                                            }

                                            // Forward introductions to existing peers over WireGuard
                                            if (parsedMsg.OtherPeers != null)
                                            {
                                                foreach (var peerObj in parsedMsg.OtherPeers)
                                                {
                                                    var pe = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                                                    string exMeshIP = pe.TryGetProperty("meshIP", out JsonElement mip2) ? mip2.GetString() : null;
                                                    string exEndpoint = pe.TryGetProperty("endpoint", out JsonElement epEl2) ? epEl2.GetString() : null;
                                                    int exNatType = pe.TryGetProperty("natType", out JsonElement ntEl2) ? ntEl2.GetInt32() : -1;
                                                    string exPeerID = pe.TryGetProperty("peerID", out JsonElement pidEl2) ? pidEl2.GetString() : null;
                                                    int exPeerMinVersion = pe.TryGetProperty("peerMinVersion", out JsonElement pminEl2) ? pminEl2.GetInt32() : 1;
                                                    int exPeerMaxVersion = pe.TryGetProperty("peerMaxVersion", out JsonElement pmaxEl2) ? pmaxEl2.GetInt32() : 1;
                                                    string exIdentityPublicKey = pe.TryGetProperty("identityPublicKey", out JsonElement idEl3) ? idEl3.GetString() : null;
                                                    string exEndpointV6 = pe.TryGetProperty("endpointV6", out JsonElement epV6El3) ? epV6El3.GetString() : null;

                                                    if (string.IsNullOrEmpty(exMeshIP)) continue;

                                                    peerInfoByMeshIP[exMeshIP] = (exPeerID, exEndpoint, (NATType)exNatType, exPeerMinVersion, exPeerMaxVersion, exIdentityPublicKey, exEndpointV6);
                                                    MarkRecentlySeen(exMeshIP, exPeerID);

                                                    if (host.GetPeer(IPAddress.Parse(exMeshIP)) == null)
                                                    {
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: no WG tunnel to {exMeshIP} — skipping");
                                                        continue;
                                                    }

                                                    if (IsIncompatible(exPeerID, exPeerMinVersion, exPeerMaxVersion) ||
                                                        IsIncompatible(parsedMsg.PeerID, parsedMsg.PeerMinVersion, parsedMsg.PeerMaxVersion))
                                                    {
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: skipping pair {parsedMsg.PeerID} <-> {exPeerID} — one or both previously refused on peer-protocol range");
                                                        continue;
                                                    }
                                                    if (IsBlocked(exIdentityPublicKey) || IsBlocked(parsedMsg.IdentityPublicKey))
                                                    {
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: skipping pair {parsedMsg.PeerID} <-> {exPeerID} — one or both are on local block list");
                                                        continue;
                                                    }

                                                    // Clean up stale relay state for this pair
                                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                                    {
                                                        string sA = string.Compare(exMeshIP, parsedMsg.PrivateAddressString, StringComparison.Ordinal) < 0
                                                            ? exMeshIP : parsedMsg.PrivateAddressString;
                                                        string sB = sA == exMeshIP ? parsedMsg.PrivateAddressString : exMeshIP;
                                                        string rpKey = $"{sA}|{sB}";
                                                        if (relayedPairs.Remove(rpKey))
                                                        {
                                                            context.Log(LogLevel.Warning, $"[Mesh] Reconnect: removed stale relay pair {rpKey}");
                                                            host.RemoveRelayRouteForPeer(IPAddress.Parse(exMeshIP));
                                                            host.RemoveRelayRouteForPeer(IPAddress.Parse(parsedMsg.PrivateAddressString));
                                                        }
                                                    }

                                                    // Symmetric ↔ symmetric reconnect: pick a relay.
                                                    if (parsedMsg.NATType == NATType.Symmetric && (NATType)exNatType == NATType.Symmetric)
                                                    {
                                                        string chosenRelay = PickRelay(exMeshIP, parsedMsg.PrivateAddressString) ?? (context.Options.AllowRelayThrough ? meshIP : null);
                                                        if (string.IsNullOrEmpty(chosenRelay))
                                                        {
                                                            context.Log(LogLevel.Debug, $"[Mesh] No eligible relay for {exMeshIP} <-> {parsedMsg.PrivateAddressString} and self-relay disabled — skipping pair");
                                                            continue;
                                                        }
                                                        context.Log($"[Mesh] Reconnect: both {parsedMsg.PeerID} and {exPeerID} are symmetric — relay via {(chosenRelay == meshIP ? "self" : chosenRelay)}");

                                                        string sortA = string.Compare(exMeshIP, parsedMsg.PrivateAddressString, StringComparison.Ordinal) < 0
                                                            ? exMeshIP : parsedMsg.PrivateAddressString;
                                                        string sortB = sortA == exMeshIP ? parsedMsg.PrivateAddressString : exMeshIP;
                                                        string pairKeyR = $"{sortA}|{sortB}";

                                                        if (relayAssignments.TryGetValue(pairKeyR, out var priorR) && priorR != chosenRelay)
                                                        {
                                                            if (priorR == meshIP)
                                                            {
                                                                try
                                                                {
                                                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(exMeshIP));
                                                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(parsedMsg.PrivateAddressString));
                                                                }
                                                                catch { }
                                                                RemoveHostedRelay(pairKeyR);
                                                            }
                                                            else
                                                            {
                                                                var release = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                                                                {
                                                                    PeerA = exMeshIP,
                                                                    PeerB = parsedMsg.PrivateAddressString,
                                                                    RelayMeshIP = priorR,
                                                                    Release = true
                                                                };
                                                                try { byte[] rb = Encoding.UTF8.GetBytes(release.Serialize()); MeshSend(rb, rb.Length, new IPEndPoint(IPAddress.Parse(priorR), MeshControlPort)); } catch { }
                                                            }
                                                        }

                                                        relayAssignments[pairKeyR] = chosenRelay;

                                                        if (chosenRelay == meshIP)
                                                        {
                                                            host.EnableForwarding();
                                                            AddHostedRelay(pairKeyR);
                                                        }
                                                        else
                                                        {
                                                            var assignment = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                                                            {
                                                                PeerA = exMeshIP,
                                                                PeerB = parsedMsg.PrivateAddressString,
                                                                RelayMeshIP = chosenRelay
                                                            };
                                                            try
                                                            {
                                                                byte[] aBytes = Encoding.UTF8.GetBytes(assignment.Serialize());
                                                                MeshSend(aBytes, aBytes.Length, new IPEndPoint(IPAddress.Parse(chosenRelay), MeshControlPort));
                                                            }
                                                            catch (Exception ex2)
                                                            {
                                                                context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshRelayAssignment to {chosenRelay}: {ex2.Message}");
                                                            }
                                                        }

                                                        var relayToEx = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                        {
                                                            PeerID = parsedMsg.PeerID,
                                                            EndpointString = parsedMsg.EndpointString,
                                                            NATType = parsedMsg.NATType,
                                                            PrivateAddressString = parsedMsg.PrivateAddressString,
                                                            IsRelay = true,
                                                            IntroducerMeshIP = meshIP,
                                                            RelayMeshIP = chosenRelay,
                                                            PeerMinVersion = parsedMsg.PeerMinVersion,
                                                            PeerMaxVersion = parsedMsg.PeerMaxVersion,
                                                            IdentityPublicKey = parsedMsg.IdentityPublicKey
                                                        };
                                                        try
                                                        {
                                                            byte[] relayExBytes = Encoding.UTF8.GetBytes(relayToEx.Serialize());
                                                            MeshSend(relayExBytes, relayExBytes.Length,
                                                                new IPEndPoint(IPAddress.Parse(exMeshIP), MeshControlPort));
                                                        }
                                                        catch (Exception ex2)
                                                        {
                                                            context.Log(LogLevel.Error, $"[Mesh] Failed to send relay MeshConnectionBegin to {exMeshIP}: {ex2.Message}");
                                                        }

                                                        if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                                        {
                                                            var relayToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                            {
                                                                PeerID = exPeerID,
                                                                EndpointString = exEndpoint,
                                                                NATType = (NATType)exNatType,
                                                                PrivateAddressString = exMeshIP,
                                                                IsRelay = true,
                                                                IntroducerMeshIP = meshIP,
                                                                RelayMeshIP = chosenRelay,
                                                                PeerMinVersion = exPeerMinVersion,
                                                                PeerMaxVersion = exPeerMaxVersion,
                                                                IdentityPublicKey = exIdentityPublicKey
                                                            };

                                                            if (completedTunnelMeshIPs.Contains(parsedMsg.PrivateAddressString))
                                                            {
                                                                try
                                                                {
                                                                    byte[] relayNewBytes = Encoding.UTF8.GetBytes(relayToNew.Serialize());
                                                                    MeshSend(relayNewBytes, relayNewBytes.Length,
                                                                        new IPEndPoint(IPAddress.Parse(parsedMsg.PrivateAddressString), MeshControlPort));
                                                                }
                                                                catch (Exception ex2)
                                                                {
                                                                    context.Log(LogLevel.Error, $"[Mesh] Failed to send relay MeshConnectionBegin to {parsedMsg.PrivateAddressString}: {ex2.Message}");
                                                                }
                                                            }
                                                            else
                                                            {
                                                                if (!deferredIntroductions.ContainsKey(parsedMsg.PrivateAddressString))
                                                                    deferredIntroductions[parsedMsg.PrivateAddressString] = new List<MediationMessage>();
                                                                deferredIntroductions[parsedMsg.PrivateAddressString].Add(relayToNew);
                                                            }
                                                        }

                                                        relayedPairs.Add(pairKeyR);
                                                        lastRepairAttempt[pairKeyR] = DateTime.UtcNow;

                                                        continue;
                                                    }

                                                    // Send MeshConnectionBegin to existing peer about the new peer
                                                    var cbToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                    {
                                                        PeerID = parsedMsg.PeerID,
                                                        EndpointString = parsedMsg.EndpointString,
                                                        // Carry both families so each receiver picks the one it can reach.
                                                        // This reconnect-introducer path previously sent only v4, so a
                                                        // v6-paired mesh couldn't admit a v4 joiner (and vice versa).
                                                        EndpointV6String = parsedMsg.EndpointV6String,
                                                        ExternalEndpointString = parsedMsg.EndpointString,
                                                        NATType = parsedMsg.NATType,
                                                        NATTypeV6 = parsedMsg.NATTypeV6,
                                                        PrivateAddressString = parsedMsg.PrivateAddressString,
                                                        PeerMinVersion = parsedMsg.PeerMinVersion,
                                                        PeerMaxVersion = parsedMsg.PeerMaxVersion,
                                                        IdentityPublicKey = parsedMsg.IdentityPublicKey
                                                    };
                                                    try
                                                    {
                                                        byte[] cbBytes = Encoding.UTF8.GetBytes(cbToExisting.Serialize());
                                                        MeshSend(cbBytes, cbBytes.Length,
                                                            new IPEndPoint(IPAddress.Parse(exMeshIP), MeshControlPort));
                                                        context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {exMeshIP} about {parsedMsg.PeerID}");
                                                    }
                                                    catch (Exception ex2)
                                                    {
                                                        context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshConnectionBegin to {exMeshIP}: {ex2.Message}");
                                                    }

                                                    // Send MeshConnectionBegin to new peer about existing peer (if tunnel ready)
                                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString) &&
                                                        (!string.IsNullOrEmpty(exEndpoint) || !string.IsNullOrEmpty(exEndpointV6)))
                                                    {
                                                        var cbToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                        {
                                                            PeerID = exPeerID,
                                                            EndpointString = exEndpoint,
                                                            // Carry the existing peer's v6 endpoint. Rescues a v6-paired
                                                            // existing peer with no v4 endpoint: the joiner would otherwise
                                                            // get an empty EndpointString and never learn to reach it.
                                                            EndpointV6String = exEndpointV6,
                                                            ExternalEndpointString = exEndpoint,
                                                            NATType = (NATType)exNatType,
                                                            PrivateAddressString = exMeshIP,
                                                            PeerMinVersion = exPeerMinVersion,
                                                            PeerMaxVersion = exPeerMaxVersion,
                                                            IdentityPublicKey = exIdentityPublicKey
                                                        };

                                                        if (completedTunnelMeshIPs.Contains(parsedMsg.PrivateAddressString))
                                                        {
                                                            try
                                                            {
                                                                byte[] cbNewBytes = Encoding.UTF8.GetBytes(cbToNew.Serialize());
                                                                MeshSend(cbNewBytes, cbNewBytes.Length,
                                                                    new IPEndPoint(IPAddress.Parse(parsedMsg.PrivateAddressString), MeshControlPort));
                                                                context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
                                                            }
                                                            catch (Exception ex2)
                                                            {
                                                                context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshConnectionBegin to {parsedMsg.PrivateAddressString}: {ex2.Message}");
                                                            }
                                                        }
                                                        else
                                                        {
                                                            if (!deferredIntroductions.ContainsKey(parsedMsg.PrivateAddressString))
                                                                deferredIntroductions[parsedMsg.PrivateAddressString] = new List<MediationMessage>();
                                                            deferredIntroductions[parsedMsg.PrivateAddressString].Add(cbToNew);
                                                            context.Log(LogLevel.Debug, $"[Mesh] Reconnect introducer: deferred MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        else if (parsedMsg.ID == MediationMessageType.NATTypeResponse)
                                        {
                                            // A per-family NAT verdict (usually the v6 one arriving
                                            // after the v4 verdict was already captured in the handshake).
                                            ApplyNatTypeResponse(parsedMsg);
                                        }
                                        (parsedMsg, remainder) = ExtractFirstJson(remainder);
                                    }
                                    reconnectedTcpBuffer = remainder ?? "";
                                }

                                // Periodic keep-alive on reconnected connection
                                if (lastReconnectDiscovery != null &&
                                    (DateTime.UtcNow - lastReconnectDiscovery.Value).TotalSeconds > reconnectDiscoverySeconds)
                                {
                                    // Send keep-alive
                                    var ka = new MediationMessage(MediationMessageType.KeepAlive);
                                    byte[] kaBytes = Encoding.ASCII.GetBytes(ka.Serialize());
                                    reconnectedStreamLocal.Write(kaBytes, 0, kaBytes.Length);

                                    // Re-send discovery if still isolated
                                    var wgPeers = host.GetAllPeers();
                                    bool stillIsolated = !wgPeers.Any(p =>
                                        (DateTime.UtcNow - p.LastActivity).TotalSeconds < RelayGatewayTimeoutSeconds);
                                    if (stillIsolated && pendingTunnelCount == 0 && pendingConnectionRequests.Count == 0)
                                    {
                                        reconnectDiscoveryAttempts++;
                                        if (reconnectDiscoveryAttempts > MaxReconnectDiscoveryAttempts)
                                        {
                                            // Too many failed rediscovery attempts — tear down and reconnect fresh
                                            // so we get a new NAT test with fresh endpoint info
                                            context.Log(LogLevel.Error, $"[Mesh] {MaxReconnectDiscoveryAttempts} rediscovery attempts failed — tearing down reconnected connection to start fresh");
                                            reconnectedTcpClient.Close();
                                            reconnectedTcpClient = null;
                                            reconnectedStream = null;
                                            reconnectedTcpBuffer = "";
                                            isolationDetectedAt = null; // Will re-trigger isolation detection
                                            reconnectDiscoverySeconds = context.Options.HeartbeatIntervalSeconds;
                                            reconnectDiscoveryAttempts = 0;
                                        }
                                        else
                                        {
                                            var rediscovery = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                            {
                                                NetworkID = context.Options.NetworkID,
                                                PeerID = peerID.ToString(),
                                                NATType = detectedNatType,
                                                PrivateAddressString = meshIP,
                                                AuthToken = authToken,
                                                ProtocolVersion = MediationProtocol.ClientVersion,
                                                PeerMinVersion = MediationProtocol.PeerMinVersion,
                                                PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                                                IdentityPublicKey = OwnIdentityPublicKeyB64
                                            };
                                            byte[] rdBytes = Encoding.ASCII.GetBytes(rediscovery.Serialize());
                                            reconnectedStreamLocal.Write(rdBytes, 0, rdBytes.Length);
                                            // Exponential backoff: 15s → 30s → 60s → 60s → 60s
                                            reconnectDiscoverySeconds = Math.Min(reconnectDiscoverySeconds * 2, 60);
                                            context.Log(LogLevel.Debug, $"[Mesh] Re-sent discovery request ({reconnectDiscoveryAttempts}/{MaxReconnectDiscoveryAttempts}), next in {reconnectDiscoverySeconds}s");
                                        }
                                    }
                                    else if (!stillIsolated)
                                    {
                                        if (!isIntroducer)
                                        {
                                            // Peers recovered — close reconnected connection.
                                            context.Log(LogLevel.Debug, "[Mesh] Peers recovered — closing reconnected mediation connection");
                                            reconnectedTcpClient.Close();
                                            reconnectedTcpClient = null;
                                            reconnectedStream = null;
                                            reconnectedTcpBuffer = "";
                                            isolationDetectedAt = null;
                                        }
                                        // Reset backoff on success
                                        reconnectDiscoverySeconds = context.Options.HeartbeatIntervalSeconds;
                                        reconnectDiscoveryAttempts = 0;
                                    }
                                    lastReconnectDiscovery = DateTime.UtcNow;
                                }
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] Reconnected TCP error: {ex.Message}");
                                reconnectedTcpClient = null;
                                reconnectedStream = null;
                                reconnectedTcpBuffer = "";
                            }
                        }

                        // Isolation detection: reconnect to mediation if all WireGuard peers are dead.
                        // Also fire immediately on the unblock flag so a just-unblocked peer can
                        // reconnect without waiting for the next check window.
                        if (reconnectedTcpClient == null &&
                            (rediscoveryRequestedAfterUnblock ||
                             DateTime.UtcNow - lastIsolationCheck > isolationCheckInterval))
                        {
                            lastIsolationCheck = DateTime.UtcNow;

                            var allWgPeers = host.GetAllPeers();
                            bool hasActivePeers = allWgPeers.Any(p =>
                                (DateTime.UtcNow - p.LastActivity).TotalSeconds < RelayGatewayTimeoutSeconds);
                            // Additionally, if we have zero completedTunnelMeshIPs, we're isolated
                            // regardless of WG LastActivity. A hole-punched-but-never-completed
                            // tunnel can leave WG peer objects with fresh LastActivity (initialized
                            // to creation time) but no working WG session — hasActivePeers alone
                            // wouldn't fire and the peer sits stuck in mesh-control-only forever.
                            bool hasAnyCompletedTunnel = completedTunnelMeshIPs.Count > 0;
                            // Also treat "we lost our introducer and haven't taken over" as isolation.
                            // A non-introducer with no introducer pointer can still have working peer
                            // tunnels but is cut off from re-discovery for any new peers. Reconnect
                            // to mediation so the server can pick a fresh introducer for the network.
                            bool lostIntroducer = !isIntroducer && string.IsNullOrEmpty(introducerMeshIP);
                            // Post-unblock: force reconnect to mediation so it broadcasts a fresh
                            // introduction for the previously-blocked peer. Consume the flag here
                            // (the primary loop consumes it via its own path); the OR-write below
                            // is enough because we bypass the grace period on the very first check.
                            bool unblockRediscovery = rediscoveryRequestedAfterUnblock;
                            if (unblockRediscovery) rediscoveryRequestedAfterUnblock = false;
                            bool isIsolated = !hasAnyCompletedTunnel || !hasActivePeers || lostIntroducer || unblockRediscovery;

                            if (isIsolated && pendingTunnelCount == 0)
                            {
                                if (isolationDetectedAt == null && !unblockRediscovery)
                                {
                                    isolationDetectedAt = DateTime.UtcNow;
                                    context.Log(LogLevel.Debug, $"[Mesh] Isolation detected — no active WireGuard peers. Will reconnect in {IsolationGracePeriodSeconds}s if not resolved.");
                                }
                                // Skip the grace period when an unblock triggered this — the user
                                // just took an action expecting the tunnel to come back promptly.
                                else if (unblockRediscovery ||
                                         (isolationDetectedAt.HasValue && (DateTime.UtcNow - isolationDetectedAt.Value).TotalSeconds >= IsolationGracePeriodSeconds))
                                {
                                    context.Log(LogLevel.Debug, unblockRediscovery
                                        ? "[Mesh] Unblock detected — reconnecting to mediation server immediately"
                                        : "[Mesh] Isolation persisted — reconnecting to mediation server for peer discovery");
                                    try
                                    {
                                        var mediationEP = endpoint; // already resolved by the connect loop
                                        reconnectedTcpClient = new TcpClient(mediationEP.Address.AddressFamily);
                                        reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                                        reconnectedTcpClient.Connect(mediationEP);
                                        if (context.Options.TlsEnabled)
                                        {
                                            var sslStream = new SslStream(reconnectedTcpClient.GetStream(), false,
                                                context.Options.TlsAllowSelfSigned
                                                    ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                                                    : null);
                                            sslStream.AuthenticateAsClient(mediationEP.Address.ToString());
                                            reconnectedStream = sslStream;
                                            context.Log(LogLevel.Info, $"[Mesh] Reconnect TLS handshake complete (protocol: {sslStream.SslProtocol})");
                                        }
                                        else
                                        {
                                            reconnectedStream = reconnectedTcpClient.GetStream();
                                        }

                                        // Clear stale peer state — endpoints may have changed during isolation
                                        pendingConnectionRequests.Clear();
                                        lastStaleWarningAt.Clear();

                                        // Perform full mediation handshake (Connected → NAT test → MeshJoinRequest)
                                        reconnectedStream.ReadTimeout = 15000;
                                        string reconRemainder = "";
                                        byte[] reconBuf = new byte[4096];

                                        MediationMessage ReadReconMessage()
                                        {
                                            while (true)
                                            {
                                                var (m, r) = ExtractFirstJson(reconRemainder);
                                                if (m != null) { reconRemainder = r; return m; }
                                                int n = reconnectedStream.Read(reconBuf, 0, reconBuf.Length);
                                                if (n == 0) throw new IOException("Reconnected mediation stream closed");
                                                reconRemainder += Encoding.ASCII.GetString(reconBuf, 0, n);
                                            }
                                        }

                                        // 1. Wait for Connected message
                                        ReadReconMessage();

                                        // 2. NAT type detection (proper handshake — must complete before MeshJoinRequest)
                                        var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                                        {
                                            LocalPort = localUdpPort,
                                            LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                                            ClientID = peerID
                                        };
                                        byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                                        reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                                        // Read NATTestBegin to get the test ports
                                        var natTestBeginR = ReadReconMessage();
                                        if (natTestBeginR.ID == MediationMessageType.NATTestBegin)
                                        {
                                            // Send UDP test packets to both NAT test ports
                                            var natTestMsg = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                                            byte[] natTestBuf = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
                                            udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, natTestBeginR.NATTestPortOne));
                                            udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, natTestBeginR.NATTestPortTwo));
                                            SendNatTestV6(natTestBuf, natTestBeginR.NATTestPortOne, natTestBeginR.NATTestPortTwo, natTestBeginR.ServerPublicIPv6);
                                            SendNatTestV4(natTestBuf, natTestBeginR.NATTestPortOne, natTestBeginR.NATTestPortTwo, natTestBeginR.ServerPublicIPv4);
                                        }

                                        // Read NATTypeResponse (v6 counterpart, if any, arrives in
                                        // the reconnect dispatch loop below).
                                        var natTypeRespR = ReadReconMessage();
                                        if (natTypeRespR.ID == MediationMessageType.NATTypeResponse)
                                            ApplyNatTypeResponse(natTypeRespR);

                                        // 3. Send MeshJoinRequest for peer discovery
                                        var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                        {
                                            NetworkID = context.Options.NetworkID,
                                            PeerID = peerID.ToString(),
                                            NATType = detectedNatType,
                                            PrivateAddressString = meshIP,
                                            AuthToken = authToken,
                                            ProtocolVersion = MediationProtocol.ClientVersion,
                                            PeerMinVersion = MediationProtocol.PeerMinVersion,
                                            PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                                            IdentityPublicKey = OwnIdentityPublicKeyB64
                                        };
                                        byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                                        reconnectedStream.Write(joinBytes, 0, joinBytes.Length);
                                        reconnectedStream.Flush();

                                        reconnectedStream.ReadTimeout = 100; // poll timeout for main loop
                                        lastReconnectDiscovery = DateTime.UtcNow;
                                        context.Log(LogLevel.Debug, "[Mesh] Reconnected to mediation server — sent discovery request");
                                    }
                                    catch (Exception ex)
                                    {
                                        context.Log(LogLevel.Error, $"[Mesh] Failed to reconnect to mediation: {ex.Message}");
                                        reconnectedTcpClient = null;
                                        reconnectedStream = null;
                                        isolationDetectedAt = null; // Reset to retry later
                                    }
                                }
                            }
                            else
                            {
                                if (isolationDetectedAt != null)
                                {
                                    context.Log(LogLevel.Debug, "[Mesh] Isolation resolved — active peers detected");
                                    isolationDetectedAt = null;
                                }
                            }
                        }

                        // Relay health check: detect dead relay gateways and clean up stale routes
                        if ((DateTime.UtcNow - lastRelayHealthCheck).TotalMilliseconds >= RelayHealthCheckIntervalMs)
                        {
                            lastRelayHealthCheck = DateTime.UtcNow;
                            var relayRoutes = host.GetRelayRoutes();

                            if (relayRoutes.Count > 0)
                            {
                                // Check each relay gateway's last activity
                                var deadGateways = new HashSet<IPAddress>();
                                foreach (var gatewayIP in relayRoutes.Values.Distinct().ToList())
                                {
                                    var gatewayPeer = host.GetPeer(gatewayIP);
                                    if (gatewayPeer == null ||
                                        (DateTime.UtcNow - gatewayPeer.LastActivity).TotalSeconds > RelayGatewayTimeoutSeconds)
                                    {
                                        deadGateways.Add(gatewayIP);
                                    }
                                }

                                if (deadGateways.Count > 0)
                                {
                                    context.Log($"[Mesh] Relay gateway(s) dead: {string.Join(", ", deadGateways)} — cleaning up stale routes");

                                    foreach (var deadGateway in deadGateways)
                                    {
                                        var removedRoutes = host.RemoveRelayRoutesViaGateway(deadGateway);
                                        context.Log(LogLevel.Debug, $"[Mesh] Removed {removedRoutes.Count} relay route(s) via {deadGateway}");
                                    }
                                    // New relay assignments will come from the introducer via MeshConnectionBegin
                                }
                            }
                        }

                        ProbeIntroducerHealth_MeshControlOnly();

                        RunLocalStalenessFallback();

                        System.Threading.Thread.Sleep(100);
                    }

                } // end else (not DisconnectRequested at setup loop exit)

                // Check if this was a disconnect request (vs shutdown)
                if (context.DisconnectRequested && !context.ShutdownRequested)
                {
                    context.ConnectionState = MeshConnectionState.Disconnecting;
                    context.Log(LogLevel.Info, "[Mesh] Disconnect requested — performing graceful leave");

                    // Send MeshPeerLeave to all peers
                    try
                    {
                        var leaveMsg = new MediationMessage(MediationMessageType.MeshPeerLeave)
                        {
                            PrivateAddressString = meshIP,
                            PeerID = peerID.ToString()
                        };
                        byte[] leaveBytes = Encoding.UTF8.GetBytes(leaveMsg.Serialize());
                        foreach (var peer in host.GetAllPeers())
                        {
                            try
                            {
                                MeshSend(leaveBytes, leaveBytes.Length,
                                    new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                            }
                            catch { }
                        }
                    }
                    catch { }

                    // Remove all WireGuard peers (keeps adapter alive)
                    host.RemoveAllPeers();

                    // Clear all tracking state (use Clear() to preserve closure references)
                    activePeerTunnels.Clear();
                    pendingConnectionRequests.Clear();
                    lastStaleWarningAt.Clear();
                    activeConnectionTunnels.Clear();
                    connectionIDToPeerID.Clear();
                    peerMeshIPs.Clear();
                    completedTunnelMeshIPs.Clear();
                    relayedPairs.Clear();
                    lastRepairAttempt.Clear();
                    repairAttemptCount.Clear();
                    peerInfoByMeshIP.Clear();
                    peerLanByMeshIP.Clear();
                    peerLatencyMs.Clear();
                    peerLastPong.Clear();
                    pingSentTicks.Clear();
                    lastHeartbeatReceivedFrom.Clear();
                    deferredIntroductions.Clear();
                    lock (hostedRelayLock) hostedRelays.Clear();
                    relayAssignments.Clear();
                    lastRelayReselect.Clear();
                    relayCandidates.Clear();
                    relayedRemotes.Clear();
                    lastRelayHealthReport.Clear();
                    pendingTunnelCount = 0;
                    isIntroducer = false;
                    introducerMeshIP = null;
                    joinResponse = null;

                    // Close mediation TCP
                    try { tcpClient?.Dispose(); } catch { }
                    tcpClient = null; stream = null; earlyTcpRemainder = "";

                    context.ConnectionState = MeshConnectionState.Disconnected;
                    context.Log(LogLevel.Info, "[Mesh] Disconnected — waiting for reconnect request");

                    // Idle wait
                    while (!context.ShutdownRequested && !context.ConnectRequested)
                        System.Threading.Thread.Sleep(100);
                    context.ConnectRequested = false;

                    if (!context.ShutdownRequested)
                    {
                        context.Log(LogLevel.Debug, "[Mesh] Reconnect requested — re-entering connect loop");
                        // Reload config from disk in case settings were changed via GUI/settings
                        context.ReloadConfig();
                        // endpoint is re-resolved at the top of the outer connect loop.
                        authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                            Encoding.UTF8.GetBytes(context.Options.NetworkID + ":" + context.Options.NetworkSecret)));
                        continue; // Back to outer connect loop
                    }
                }

                // ShutdownRequested was set (e.g. by GUI) — perform graceful shutdown
                PerformGracefulShutdown();

            } // end outer connect loop

        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Error, $"[Mesh] Error: {ex.Message}");
            context.Log(ex.StackTrace);
            throw;
        }
        finally
        {
            // Signal background tasks (listener, HTTP) to stop before tearing down their sockets.
            context.ShutdownRequested = true;
            try { meshControlClient?.Dispose(); } catch { }
            try { udpProxy?.Dispose(); } catch { }
            try { (host as IDisposable)?.Dispose(); } catch { }
            try { tcpClient?.Dispose(); } catch { }
            try { udpClient?.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Mediation protocol handshake: NAT-type detection + MeshJoinRequest/MeshJoinResponse.
    /// Caller must have already established <see cref="tcpClient"/> and <see cref="stream"/>
    /// (TCP connect + optional TLS wrap). On success, <see cref="joinResponse"/> is populated.
    /// Returns false on authentication failure (fatal — caller should not retry).
    /// Throws on transport errors; daemon callers catch + retry, embedded callers propagate.
    /// </summary>
    private bool PerformProtocolHandshake()
    {
        // 1. Wait for Connected message
        ReadOneTcpMessage();

        // 2. NAT type detection
        var natTypeRequest = new MediationMessage(MediationMessageType.NATTypeRequest)
        {
            LocalPort = localUdpPort,
            LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
            ClientID = peerID
        };
        byte[] natBuffer = Encoding.ASCII.GetBytes(natTypeRequest.Serialize());
        stream.Write(natBuffer, 0, natBuffer.Length);

        var natTestBegin = ReadOneTcpMessage();
        if (natTestBegin.ID == MediationMessageType.NATTestBegin)
        {
            var natTestMsg = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
            byte[] natTestBuffer = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortOne));
            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortTwo));
            SendNatTestV6(natTestBuffer, natTestBegin.NATTestPortOne, natTestBegin.NATTestPortTwo, natTestBegin.ServerPublicIPv6);
            SendNatTestV4(natTestBuffer, natTestBegin.NATTestPortOne, natTestBegin.NATTestPortTwo, natTestBegin.ServerPublicIPv4);
        }

        // The server sends ONE NATTypeResponse PER FAMILY we probed (v4 and/or v6), in either
        // order. We need at least one verdict to proceed to join. BLOCKING-read the first response
        // (required), then DRAIN any additional responses that are already buffered WITHOUT a
        // blocking read — so we capture the second family's verdict when it arrived in the same
        // round-trip, without hanging waiting for a family that was never probed / is blocked. A
        // straggler that arrives later still gets picked up by the main message loop's
        // NATTypeResponse handler. ApplyNatTypeResponse is idempotent, so a re-seen verdict is a
        // no-op (this is what caused the earlier double-log).
        detectedNatType = NATType.Unknown;
        var firstNat = ReadOneTcpMessage();
        if (firstNat.ID == MediationMessageType.NATTypeResponse)
        {
            ApplyNatTypeResponse(firstNat);
            // Drain buffered follow-ups (non-blocking): the second family's response, if it landed
            // in the same read, is already in earlyTcpRemainder.
            while (true)
            {
                var (buffered, rest) = ExtractFirstJson(earlyTcpRemainder);
                if (buffered == null || buffered.ID != MediationMessageType.NATTypeResponse) break;
                earlyTcpRemainder = rest;
                ApplyNatTypeResponse(buffered);
            }
        }

        // 3. Join mesh network
        var joinRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
        {
            NetworkID = context.Options.NetworkID,
            PeerID = peerID.ToString(),
            NATType = detectedNatType,
            PrivateAddressString = meshIP,
            AuthToken = authToken,
            ProtocolVersion = MediationProtocol.ClientVersion,
            PeerMinVersion = MediationProtocol.PeerMinVersion,
            PeerMaxVersion = MediationProtocol.PeerMaxVersion,
            IdentityPublicKey = OwnIdentityPublicKeyB64
        };
        byte[] sendBuffer = Encoding.ASCII.GetBytes(joinRequest.Serialize());
        stream.Write(sendBuffer, 0, sendBuffer.Length);

        // Read the join response, skipping any straggler per-family NATTypeResponse that arrived
        // after the drain above but before the join response (the second family settling late).
        // Apply it so its verdict isn't lost, then keep reading for the actual join response.
        while (true)
        {
            joinResponse = ReadOneTcpMessage();
            if (joinResponse.ID != MediationMessageType.NATTypeResponse) break;
            ApplyNatTypeResponse(joinResponse);
        }
        if (!string.IsNullOrEmpty(joinResponse.VersionError))
        {
            context.Log(LogLevel.Error, $"[Mesh] Mediation server rejected protocol version: {joinResponse.VersionError}");
            lastError = joinResponse.VersionError;
            lastErrorKind = "VersionMismatch";
            return false;
        }
        if (!string.IsNullOrEmpty(joinResponse.AuthToken))
        {
            context.Log(LogLevel.Error, $"[Mesh] Authentication failed: {joinResponse.AuthToken}");
            lastError = joinResponse.AuthToken;
            lastErrorKind = "AuthFailure";
            return false;
        }

        context.Log(LogLevel.Info, $"[Mesh] Joined network! Found {joinResponse.PeerCount} other peers");
        return true;
    }

    private void StartUdpListener()
    {
        System.Threading.Tasks.Task.Run(async () =>
        {
            while (!context.ShutdownRequested)
            {
                try
                {
                    var result = await meshControlClient.ReceiveAsync();
                    ProcessMeshControlPacket(result.Buffer, result.RemoteEndPoint);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Mesh control listener error: {ex.Message}"); }
            }
        });
    }

    /// <summary>
    /// Process one mesh-control packet. Originally inlined into StartUdpListener's task body;
    /// extracted so embedded mode can inject decrypted mesh-control packets received over
    /// MeshPeerProxy tunnels (since mesh-IPs aren't OS-routable to port 51888 without WG).
    /// Embedded callers synthesize a fake remoteEndPoint from the source peer's mesh IP +
    /// the well-known MeshControlPort, so existing handlers that read remoteEndPoint.Address
    /// (to identify the sender's mesh IP) continue to work unchanged.
    /// </summary>
    public void ProcessMeshControlPacket(byte[] buffer, IPEndPoint remoteEndPoint)
    {
        try
        {
            // Fast-path: binary ping/pong (0xFF prefix) — no JSON parsing
            if (buffer.Length >= 2 && buffer[0] == 0xFF)
            {
                // Any binary control packet is proof the sender can reach us — feeds the
                // two-way liveness check that gates ProcessMeshConnectionBegin teardowns.
                // Without this, non-introducer ↔ non-introducer pairs have no source of
                // "inbound" evidence (only the introducer sends MeshHeartbeat), so any
                // re-introduce tears down a perfectly working tunnel.
                lastHeartbeatReceivedFrom[remoteEndPoint.Address.ToString()] = DateTime.UtcNow;

                if (buffer[1] == (byte)'P')
                {
                    byte[] meshIPBytes = Encoding.UTF8.GetBytes(meshIP ?? "");
                    byte[] pongPacket = new byte[2 + meshIPBytes.Length];
                    pongPacket[0] = 0xFF;
                    pongPacket[1] = (byte)'p';
                    Buffer.BlockCopy(meshIPBytes, 0, pongPacket, 2, meshIPBytes.Length);
                    MeshSend(pongPacket, pongPacket.Length, remoteEndPoint);
                }
                else if (buffer[1] == (byte)'p')
                {
                    long pongTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                    string responderIP = Encoding.UTF8.GetString(buffer, 2, buffer.Length - 2);
                    if (!string.IsNullOrEmpty(responderIP) && pingSentTicks.TryGetValue(responderIP, out long sentTicks))
                    {
                        long elapsedMs = ((pongTicks - sentTicks) * 1000) / System.Diagnostics.Stopwatch.Frequency;
                        peerLatencyMs[responderIP] = elapsedMs;
                        peerLastPong[responderIP] = DateTime.UtcNow;
                    }
                }
                return;
            }

            string json = Encoding.UTF8.GetString(buffer);
            var controlMsg = JsonSerializer.Deserialize<MediationMessage>(json);
            if (controlMsg == null) return;

            if (controlMsg.ID == MediationMessageType.MeshConnectionBegin)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received MeshConnectionBegin from {remoteEndPoint}: peer {controlMsg.PeerID} at {controlMsg.EndpointString}");
                string senderIP = remoteEndPoint.Address.ToString();
                if (string.IsNullOrEmpty(introducerMeshIP) && senderIP != meshIP)
                {
                    introducerMeshIP = senderIP;
                    context.Log(LogLevel.Info, $"[Mesh] Learned introducer mesh IP from MeshConnectionBegin: {introducerMeshIP}");
                }
                meshConnectionBeginQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshHeartbeat)
            {
                string heartbeatSenderIP = remoteEndPoint.Address.ToString();
                lastHeartbeatReceivedFrom[heartbeatSenderIP] = DateTime.UtcNow;
                if (heartbeatSenderIP != meshIP)
                {
                    bool wasCapable = relayCandidates.TryGetValue(heartbeatSenderIP, out var prevCand) && prevCand.capable;
                    relayCandidates[heartbeatSenderIP] = (controlMsg.RelayCapable, controlMsg.ActiveRelayRoutes, controlMsg.RelayCapacity, DateTime.UtcNow);
                    // Capability flipped capable→uncapable: drive reselection for any pair
                    // currently routed through this candidate. Reuses the health-report path
                    // so threshold/cooldown rules still apply, but reselection fires immediately
                    // instead of waiting for the 45s endpoint-side WG silence timeout.
                    if (isIntroducer && wasCapable && !controlMsg.RelayCapable)
                    {
                        foreach (var kv in relayAssignments)
                        {
                            if (kv.Value != heartbeatSenderIP) continue;
                            var parts = kv.Key.Split('|', 2);
                            if (parts.Length != 2) continue;
                            // Operator opted out — bypass per-pair cooldown so reselection
                            // fires on the next drain tick instead of waiting up to 120s.
                            lastRelayReselect.TryRemove(kv.Key, out _);
                            meshRelayHealthReportQueue.Enqueue(new MediationMessage(MediationMessageType.MeshRelayHealthReport)
                            {
                                PeerA = parts[0],
                                PeerB = parts[1],
                                CurrentRelay = heartbeatSenderIP,
                                Self = parts[0],
                                Remote = parts[1],
                                Observation = RelayHealthObservation.Other
                            });
                        }
                        context.Log(LogLevel.Debug, $"[Mesh] Relay {heartbeatSenderIP} dropped RelayCapable — queued reselection for affected pairs");
                    }
                }
                // Authoritative-by-claim: a heartbeat with IsIntroducer=true updates our
                // local pointer. Handles takeover where the new introducer is someone
                // other than our current one. We do NOT relinquish our own role on
                // someone else's claim — server-side election decides that.
                if (heartbeatSenderIP != meshIP && controlMsg.IsIntroducer &&
                    introducerMeshIP != heartbeatSenderIP && !isIntroducer)
                {
                    context.Log($"[Mesh] Introducer changed: {introducerMeshIP ?? "(none)"} → {heartbeatSenderIP} (heartbeat claim)");
                    introducerMeshIP = heartbeatSenderIP;
                    introducerMissedProbes = 0;
                    introducerProbeAckReceived = true;
                }
                else if (string.IsNullOrEmpty(introducerMeshIP) && heartbeatSenderIP != meshIP)
                {
                    introducerMeshIP = heartbeatSenderIP;
                    context.Log(LogLevel.Info, $"[Mesh] Learned introducer mesh IP from MeshHeartbeat: {introducerMeshIP}");
                }
                if (controlMsg.PeerRoster != null)
                {
                    var rosterIPs = new HashSet<string>();
                    foreach (var entry in controlMsg.PeerRoster)
                    {
                        var parts = entry.Split('|', 4);
                        if (parts.Length >= 3 && !string.IsNullOrEmpty(parts[0]) && parts[0] != meshIP)
                        {
                            string rMeshIP = parts[0];
                            string rPeerID = parts[1];
                            int.TryParse(parts[2], out int rNatInt);
                            string rEndpoint = parts.Length >= 4 ? parts[3] : null;
                            rosterIPs.Add(rMeshIP);
                            if (!peerInfoByMeshIP.TryGetValue(rMeshIP, out var existing) ||
                                string.IsNullOrEmpty(existing.peerID) || existing.endpoint == null)
                            {
                                // Compact roster string carries no v6 endpoint — preserve any we
                                // already learned for this peer rather than dropping it.
                                string priorV6 = existing.endpointV6;
                                peerInfoByMeshIP[rMeshIP] = (rPeerID, rEndpoint, (NATType)rNatInt, 1, 1, null, priorV6);
                                MarkRecentlySeen(rMeshIP, rPeerID);
                            }
                        }
                    }

                    // Treat the introducer's roster as authoritative — catches dropouts
                    // whose MeshPeerRemoved/MeshPeerLeave was lost on the UDP path.
                    // BUT: a brand-new peer being hole-punched won't appear in *anyone's*
                    // roster yet, since roster gossip lags tunnel-establishment. Synthesizing
                    // a removal for such a peer tears them down mid-hole-punch, causing an
                    // infinite retry loop. Guard by:
                    //   - Skipping peers we have an in-flight ConnectionRequest for.
                    //   - Skipping peers with an in-flight tunnel attempt (peerMeshIPs entry).
                    //   - Skipping peers whose tunnel just completed (recent tunnelCompletedAt).
                    if (!isIntroducer && controlMsg.IsIntroducer &&
                        !string.IsNullOrEmpty(introducerMeshIP) &&
                        heartbeatSenderIP == introducerMeshIP)
                    {
                        var rosterGrace = TimeSpan.FromSeconds(30);
                        var now2 = DateTime.UtcNow;
                        var inFlightMeshIPs = new HashSet<string>(peerMeshIPs.Values);
                        foreach (var knownIP in peerInfoByMeshIP.Keys.ToArray())
                        {
                            if (knownIP == meshIP) continue;
                            if (knownIP == introducerMeshIP) continue;
                            if (rosterIPs.Contains(knownIP)) continue;
                            string pid = peerInfoByMeshIP.TryGetValue(knownIP, out var ki) ? ki.peerID : "";
                            if (!string.IsNullOrEmpty(pid) && pendingConnectionRequests.ContainsKey(pid)) continue;
                            if (inFlightMeshIPs.Contains(knownIP)) continue;
                            if (tunnelCompletedAt.TryGetValue(knownIP, out var completedAt) &&
                                now2 - completedAt < rosterGrace) continue;
                            context.Log(LogLevel.Info, $"[Mesh] Synthesizing MeshPeerRemoved for {knownIP} — absent from introducer's roster");
                            meshPeerRemovedQueue.Enqueue(new MediationMessage(MediationMessageType.MeshPeerRemoved)
                            {
                                PrivateAddressString = knownIP,
                                PeerID = pid ?? ""
                            });
                        }
                    }
                }
                var pongCutoff = DateTime.UtcNow.AddSeconds(-30);
                var connectedIPs = peerLastPong
                    .Where(kvp => kvp.Value > pongCutoff && kvp.Key != meshIP)
                    .Select(kvp => kvp.Key)
                    .ToList();
                if (introducerMeshIP != null && !connectedIPs.Contains(introducerMeshIP))
                    connectedIPs.Add(introducerMeshIP);
                var ack = new MediationMessage(MediationMessageType.MeshHeartbeatAck)
                {
                    PeerID = peerID.ToString(),
                    PrivateAddressString = meshIP,
                    NATType = detectedNatType,
                    ConnectedMeshIPs = connectedIPs.ToArray()
                };
                byte[] ackBytes = Encoding.UTF8.GetBytes(ack.Serialize());
                MeshSend(ackBytes, ackBytes.Length, remoteEndPoint);
            }
            else if (controlMsg.ID == MediationMessageType.MeshHeartbeatAck)
            {
                string ackSourceIP = remoteEndPoint.Address.ToString();
                lastHeartbeatReceivedFrom[ackSourceIP] = DateTime.UtcNow;
                if (!string.IsNullOrEmpty(introducerMeshIP) && ackSourceIP == introducerMeshIP)
                {
                    introducerProbeAckReceived = true;
                }
                meshHeartbeatAckQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshPeerRemoved)
            {
                context.Log(LogLevel.Warning, $"[Mesh] Received MeshPeerRemoved: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) declared dead by introducer");
                meshPeerRemovedQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshPeerLeave)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received MeshPeerLeave: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) left gracefully");
                meshPeerLeaveQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshIntroduction)
            {
                // MeshIntroduction is no longer used
            }
            else if (controlMsg.ID == MediationMessageType.MeshRelayAssignment)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received MeshRelayAssignment: {controlMsg.PeerA} <-> {controlMsg.PeerB} via {controlMsg.RelayMeshIP}");
                meshRelayAssignmentQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshRelayHealthReport)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received MeshRelayHealthReport from {controlMsg.Self}: pair {controlMsg.PeerA}<->{controlMsg.PeerB} relay {controlMsg.CurrentRelay} obs={controlMsg.Observation}");
                meshRelayHealthReportQueue.Enqueue(controlMsg);
            }
            else if (controlMsg.ID == MediationMessageType.MeshVersionHello)
            {
                ProcessMeshVersionHello(controlMsg, remoteEndPoint);
            }
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Error, $"[Mesh] Mesh control packet processing error: {ex.Message}");
        }
    }

    /// <summary>
    /// Send our peer-protocol supported range to <paramref name="remoteMeshIP"/>. Called right
    /// after a tunnel comes up; the receiver picks the intersection of ranges and stores it.
    /// </summary>
    /// <summary>
    /// Returns true if we've previously refused this peer and their advertised range matches the
    /// range we refused. A range change (peer upgraded/downgraded) evicts the block so we retry.
    /// Callers that don't know a real range should pass v1/v1 (the pre-versioning-era default) so
    /// pre-negotiation peers still block if we already refused them at v1.
    /// </summary>
    /// <summary>
    /// Record a peer as version-incompatible. Used by embedded mode's Noise-payload handshake:
    /// the daemon path populates <see cref="incompatiblePeers"/> from <see cref="ProcessMeshVersionHello"/>,
    /// but embedded refuses inside <c>MeshPeerProxy</c> before any daemon-level exchange, so it
    /// has to inform the engine directly.
    /// </summary>
    internal void MarkPeerIncompatible(string peerID, int theirMin, int theirMax)
    {
        if (string.IsNullOrEmpty(peerID)) return;
        incompatiblePeers[peerID] = (theirMin, theirMax);
    }

    private bool IsIncompatible(string peerID, int theirMin, int theirMax)
    {
        if (string.IsNullOrEmpty(peerID)) return false;
        if (!incompatiblePeers.TryGetValue(peerID, out var stored)) return false;
        if (stored.min != theirMin || stored.max != theirMax)
        {
            incompatiblePeers.TryRemove(peerID, out _);
            context.Log(LogLevel.Debug, $"[Mesh] Peer {peerID} advertised new peer-protocol range v{theirMin}-v{theirMax} (was v{stored.min}-v{stored.max}) — clearing incompatibility block");
            return false;
        }
        return true;
    }

    private void SendMeshVersionHello(string remoteMeshIP)
    {
        if (string.IsNullOrEmpty(remoteMeshIP)) return;
        try
        {
            var hello = new MediationMessage(MediationMessageType.MeshVersionHello)
            {
                PeerMinVersion = MediationProtocol.PeerMinVersion,
                PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                // Piggyback our identity pubkey. The mediation-borne carriers (MeshConnectionBegin,
                // MeshIntroduceRequest, ConnectionBegin) are all one-shot UDP and can be lost;
                // MeshVersionHello is already retried on the ping loop so re-sending here fills
                // in any peers who missed the identity from the original path.
                IdentityPublicKey = OwnIdentityPublicKeyB64
            };
            byte[] bytes = Encoding.UTF8.GetBytes(hello.Serialize());
            MeshSend(bytes, bytes.Length, new IPEndPoint(IPAddress.Parse(remoteMeshIP), MeshControlPort));
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Debug, $"[Mesh] Failed to send MeshVersionHello to {remoteMeshIP}: {ex.Message}");
        }
    }

    /// <summary>
    /// Handle an incoming MeshVersionHello. Negotiates the intersection with our own range and
    /// records the peer's version. Refuses the pair (tears down the WG peer) if no overlap.
    /// </summary>
    private void ProcessMeshVersionHello(MediationMessage msg, IPEndPoint from)
    {
        string remoteMeshIP = from.Address.ToString();
        int remoteMin = msg.PeerMinVersion;
        int remoteMax = msg.PeerMaxVersion;
        int selected = Math.Min(MediationProtocol.PeerMaxVersion, remoteMax);
        int lowerBound = Math.Max(MediationProtocol.PeerMinVersion, remoteMin);
        if (selected < lowerBound)
        {
            context.Log(LogLevel.Warning, $"[Mesh] Peer {remoteMeshIP} supports peer-protocol v{remoteMin}-v{remoteMax}, we support v{MediationProtocol.PeerMinVersion}-v{MediationProtocol.PeerMaxVersion} — no overlap, removing peer");
            if (peerInfoByMeshIP.TryGetValue(remoteMeshIP, out var info) && !string.IsNullOrEmpty(info.peerID))
            {
                incompatiblePeers[info.peerID] = (remoteMin, remoteMax);
            }
            RemoveDeadPeer(remoteMeshIP);
            return;
        }
        bool alreadyNegotiated = peerNegotiatedVersion.ContainsKey(remoteMeshIP);
        peerNegotiatedVersion[remoteMeshIP] = selected;
        // Only log the negotiation the first time — otherwise a retry loop on the sender's side
        // (they're looking for something they haven't received) prints this every ping tick and
        // spams the log for as long as the loop runs.
        if (!alreadyNegotiated)
            context.Log(LogLevel.Debug, $"[Mesh] Peer {remoteMeshIP} negotiated peer-protocol v{selected}");
        // Fill in identity pubkey from the hello if we don't have one yet — the original carrier
        // (MeshConnectionBegin) can be lost on UDP, leaving peerInfoByMeshIP with no identity and
        // the Firewall pane showing "no fingerprint yet" indefinitely.
        if (!string.IsNullOrEmpty(msg.IdentityPublicKey) &&
            peerInfoByMeshIP.TryGetValue(remoteMeshIP, out var existing) &&
            string.IsNullOrEmpty(existing.identityPublicKey))
        {
            peerInfoByMeshIP[remoteMeshIP] = (existing.peerID, existing.endpoint, existing.natType, existing.peerMinVersion, existing.peerMaxVersion, msg.IdentityPublicKey, existing.endpointV6);
        }
        // Reciprocate with a short cooldown. Their retry loop may be firing because they lack our
        // identity — a one-shot reply is a stronger guarantee than "first-ever receive." The
        // cooldown prevents ping-pong spam when both sides are healthy but a stray hello arrives.
        if (ShouldReciprocateHello(remoteMeshIP))
        {
            SendMeshVersionHello(remoteMeshIP);
        }
    }

    private readonly ConcurrentDictionary<string, DateTime> lastHelloReciprocateAt = new();
    private static readonly TimeSpan HelloReciprocateCooldown = TimeSpan.FromSeconds(20);

    private bool ShouldReciprocateHello(string peerMeshIP)
    {
        var now = DateTime.UtcNow;
        if (lastHelloReciprocateAt.TryGetValue(peerMeshIP, out var last) &&
            now - last < HelloReciprocateCooldown)
            return false;
        lastHelloReciprocateAt[peerMeshIP] = now;
        return true;
    }

    // Helper method to process a MeshConnectionBegin message:
    // Create a tunnel with skipTcpConnection=true and inject the connection info
    // so the tunnel hole-punches directly without going through the mediation server.
    private void ProcessMeshConnectionBegin(MediationMessage cbMsg)
    {
        string remotePeerID = cbMsg.PeerID;
        string remoteMeshIP = cbMsg.PrivateAddressString;
        // The CB may carry both a v4 (EndpointString) and v6 (EndpointV6String) endpoint. Pick the
        // family THIS node can actually reach — prefer v6 only if we have a v6 route and the peer
        // advertised one. Without this, a v4-only peer handed a v6 endpoint (because the mesh paired
        // over v6) would key a tunnel on an unreachable family and never connect.
        string remoteEndpoint = SelectReachableEndpoint(cbMsg.EndpointString, cbMsg.EndpointV6String);
        // Pick the peer's NAT type by the family we're actually connecting over — a v6 endpoint
        // uses the v6 verdict (v6 has no symmetric NAT), not the v4 one. See OwnNatTypeForEndpoint.
        NATType remotePeerNatType = RemoteNatTypeForEndpoint(remoteEndpoint, cbMsg.NATType, cbMsg.NATTypeV6);

        if (string.IsNullOrEmpty(remotePeerID))
        {
            context.Log(LogLevel.Debug, $"[Mesh] MeshConnectionBegin missing PeerID — skipping");
            return;
        }
        if (IsIncompatible(remotePeerID, cbMsg.PeerMinVersion, cbMsg.PeerMaxVersion))
        {
            context.Log(LogLevel.Debug, $"[Mesh] Skipping MeshConnectionBegin for {remotePeerID} — peer-protocol range v{cbMsg.PeerMinVersion}-v{cbMsg.PeerMaxVersion} previously refused");
            return;
        }
        if (IsBlocked(cbMsg.IdentityPublicKey))
        {
            context.Log(LogLevel.Debug, $"[Mesh] Skipping MeshConnectionBegin for {remotePeerID} — peer fingerprint is on local block list");
            return;
        }
        // Relay mode only needs mesh IP + introducer IP, not endpoint
        if (!cbMsg.IsRelay && string.IsNullOrEmpty(remoteEndpoint))
        {
            context.Log(LogLevel.Debug, $"[Mesh] MeshConnectionBegin missing endpoint (non-relay) — skipping");
            return;
        }

        // Cache peer info for heartbeat repair — ensures the failover introducer
        // knows NAT types of peers that joined after this peer's initial connection.
        if (!string.IsNullOrEmpty(remoteMeshIP))
        {
            peerInfoByMeshIP[remoteMeshIP] = (remotePeerID, remoteEndpoint, remotePeerNatType, cbMsg.PeerMinVersion, cbMsg.PeerMaxVersion, cbMsg.IdentityPublicKey, cbMsg.EndpointV6String);
            MarkRecentlySeen(remoteMeshIP, remotePeerID);
        }

        // Skip if a connection attempt is already in progress for this peer.
        // Relay MeshConnectionBegin messages are always allowed since they just add a
        // WireGuard route and don't create tunnels.
        // Stale pending requests (> StaleTimeoutSeconds) are also allowed through.
        if (!cbMsg.IsRelay && pendingConnectionRequests.TryGetValue(remotePeerID, out var pendingTime))
        {
            if ((DateTime.UtcNow - pendingTime).TotalSeconds < context.Options.StaleTimeoutSeconds)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Ignoring MeshConnectionBegin for {remotePeerID} — connection already pending ({(int)(DateTime.UtcNow - pendingTime).TotalSeconds}s ago)");
                return;
            }
            // Stale pending request — clean up and allow the new attempt
            context.Log(LogLevel.Warning, $"[Mesh] Clearing stale pending request for {remotePeerID} ({(int)(DateTime.UtcNow - pendingTime).TotalSeconds}s old) — allowing new attempt");
            pendingConnectionRequests.Remove(remotePeerID);
        }

        bool alreadyTracked = activePeerTunnels.ContainsKey(remotePeerID) ||
            (!string.IsNullOrEmpty(remoteMeshIP) && activePeerTunnels.ContainsKey(remoteMeshIP));
        bool wasRelayed = !string.IsNullOrEmpty(remoteMeshIP) &&
            completedTunnelMeshIPs.Contains(remoteMeshIP) && !alreadyTracked;

        // If this is a relay MeshConnectionBegin for a peer that's already relayed,
        // check if the relay route still exists in WireGuard before skipping.
        // The route may have been lost (peer removed, WireGuard reset) while
        // completedTunnelMeshIPs still had the entry — let it through to re-establish.
        if (cbMsg.IsRelay && wasRelayed && !string.IsNullOrEmpty(remoteMeshIP))
        {
            var relayRoutes = host.GetRelayRoutes();
            bool routeExists = relayRoutes.TryGetValue(IPAddress.Parse(remoteMeshIP), out var currentGateway);
            string newGateway = !string.IsNullOrEmpty(cbMsg.RelayMeshIP) ? cbMsg.RelayMeshIP : cbMsg.IntroducerMeshIP;
            if (routeExists && !string.IsNullOrEmpty(newGateway) && currentGateway != null &&
                currentGateway.ToString() != newGateway)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Relay reselect for {remoteMeshIP}: gateway {currentGateway} → {newGateway}");
                host.RemoveRelayRouteForPeer(IPAddress.Parse(remoteMeshIP));
                if (host.AddRelayRoute(IPAddress.Parse(newGateway), IPAddress.Parse(remoteMeshIP)))
                {
                    relayedRemotes[remoteMeshIP] = newGateway;
                    lastRelayHealthReport.TryRemove(remoteMeshIP, out _);
                    context.Log(LogLevel.Debug, $"[Mesh] Relay reselect applied: {remoteMeshIP} now via {newGateway}");
                }
                else
                {
                    context.Log(LogLevel.Error, $"[Mesh] Relay reselect: AddRelayRoute failed for {remoteMeshIP} via {newGateway}");
                }
                return;
            }
            if (routeExists)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Ignoring duplicate relay MeshConnectionBegin for {remotePeerID} ({remoteMeshIP}) — relay route confirmed in WireGuard");
                return;
            }
            // Route is gone — clear stale tracking and let the message re-establish it
            context.Log(LogLevel.Debug, $"[Mesh] Relay route for {remoteMeshIP} missing from WireGuard — allowing re-establishment");
            completedTunnelMeshIPs.Remove(remoteMeshIP);
            wasRelayed = false;
        }

        if ((alreadyTracked || wasRelayed) && !string.IsNullOrEmpty(remoteMeshIP))
        {
            // Skip the teardown if the existing tunnel is demonstrably alive in BOTH directions:
            // - Recent pong proves we can reach them and get a reply (outbound-ok, inbound-ok on our side).
            // - Recent heartbeat/ack from them proves they can reach us (inbound-ok on our side).
            // One-way liveness can be fooled by asymmetric UDP loss (e.g. symmetric NAT mapping
            // expired inbound but outbound still holes-punches on new pings). The introducer's
            // repair MeshConnectionBegin exists precisely for this case — honour it when we can't
            // prove the peer has heard from us recently.
            var tunnelHealthyWindow = TimeSpan.FromSeconds(20);
            var now = DateTime.UtcNow;
            bool hasRecentPong = peerLastPong.TryGetValue(remoteMeshIP, out var lastPong) &&
                                 now - lastPong < tunnelHealthyWindow;
            bool hasRecentInbound = lastHeartbeatReceivedFrom.TryGetValue(remoteMeshIP, out var lastInbound) &&
                                    now - lastInbound < tunnelHealthyWindow;
            if (hasRecentPong && hasRecentInbound)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Ignoring re-introduce for {remotePeerID} ({remoteMeshIP}) — tunnel is healthy (last pong {(int)(now - lastPong).TotalSeconds}s ago, last inbound {(int)(now - lastInbound).TotalSeconds}s ago)");
                return;
            }
            if (hasRecentPong && !hasRecentInbound)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Re-introducing {remotePeerID} ({remoteMeshIP}) — outbound liveness OK but no recent inbound (last {(lastHeartbeatReceivedFrom.ContainsKey(remoteMeshIP) ? (int)(now - lastInbound).TotalSeconds + "s ago" : "never")}), asymmetric loss likely");
            }

            // Clean up the old connection (direct or relay) to allow reconnect
            context.Log(LogLevel.Debug, $"[Mesh] Peer {remotePeerID} ({remoteMeshIP}) being re-introduced — cleaning up old connection (relay={wasRelayed})");
            metricReconnects++;
            RemoveDeadPeer(remoteMeshIP);
        }

        context.Log(LogLevel.Debug, $"[Mesh] Processing MeshConnectionBegin: peer {remotePeerID} at {remoteEndpoint} (NAT: {remotePeerNatType}, meshIP: {remoteMeshIP}, relay: {cbMsg.IsRelay})");

        // Relay mode: route traffic for the remote peer through the chosen relay's tunnel.
        if (cbMsg.IsRelay && !string.IsNullOrEmpty(remoteMeshIP))
        {
            string gatewayIP = !string.IsNullOrEmpty(cbMsg.RelayMeshIP) ? cbMsg.RelayMeshIP : cbMsg.IntroducerMeshIP;
            var remoteMeshIPAddr = IPAddress.Parse(remoteMeshIP);

            if (!string.IsNullOrEmpty(gatewayIP))
            {
                var gatewayIPAddr = IPAddress.Parse(gatewayIP);
                if (host.AddRelayRoute(gatewayIPAddr, remoteMeshIPAddr))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Relay route added: {remoteMeshIP} via {gatewayIP} — peer {remotePeerID} is reachable");
                    metricRelayRoutesEstablished++;
                    relayedRemotes[remoteMeshIP] = gatewayIP;
                    // Notify host (no-op in daemon, used by embedded mode to spawn a relayed proxy).
                    IPEndPoint remotePublicEp = null;
                    if (!string.IsNullOrEmpty(remoteEndpoint))
                    {
                        try { remotePublicEp = IPEndPoint.Parse(remoteEndpoint); }
                        catch { remotePublicEp = null; }
                    }
                    host.OnRelayPeerEstablished(remotePeerID, remoteMeshIPAddr, gatewayIPAddr, remotePublicEp);
                }
                else
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to add relay route for {remoteMeshIP} via {gatewayIP}");
                }
            }
            else
            {
                context.Log(LogLevel.Error, $"[Mesh] Relay MeshConnectionBegin missing RelayMeshIP/IntroducerMeshIP — cannot set up relay route");
            }
            completedTunnelMeshIPs.Add(remoteMeshIP);
            tunnelCompletedAt[remoteMeshIP] = DateTime.UtcNow;
            SendMeshVersionHello(remoteMeshIP);
            pendingConnectionRequests.Remove(remotePeerID);
            return;
        }

        pendingConnectionRequests[remotePeerID] = DateTime.UtcNow;
        pendingTunnelCount++;
        var capturedPeerID = remotePeerID;
        var capturedMeshIP = remoteMeshIP;
        var peerTunnel = new Tunnel(
            onConnectionFailure: () =>
            {
                context.Log(LogLevel.Error, $"[Mesh] Introducer-handled tunnel for {capturedPeerID} failed — cleaning up for future retry");
                lock (meshLock)
                {
                    activeConnectionTunnels.Remove(capturedPeerID.GetHashCode());
                    pendingConnectionRequests.Remove(capturedPeerID);
                    activePeerTunnels.Remove(capturedPeerID);
                    if (!string.IsNullOrEmpty(capturedMeshIP))
                        activePeerTunnels.Remove(capturedMeshIP);
                }
                // Tell the host to drop its peer registration for this mesh IP too. Without this,
                // EmbeddedMeshHost.peersByMeshIP keeps a stale proxy entry whose underlying tunnel
                // is dead, and subsequent relay traffic logs "Tunnel is not connected yet" on
                // every packet until the heartbeat-driven RemoveDeadPeer eventually fires.
                if (!string.IsNullOrEmpty(capturedMeshIP) && IPAddress.TryParse(capturedMeshIP, out var capturedMeshIPAddr))
                {
                    var hostPeer = host.GetPeer(capturedMeshIPAddr);
                    if (hostPeer != null) host.RemovePeer(hostPeer.ConnectionId);
                }
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
            },
            sharedUdpClient: udpClient,
            meshPeerEndpoint: remoteEndpoint,
            retryInPlace: true,
            sharedClientID: peerID,
            ownMeshIP: meshIP,
            onConnectionComplete: () =>
            {
                context.Log(LogLevel.Debug, $"[Mesh] Introducer-handled tunnel for {capturedPeerID} WireGuard established");
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                lock (meshLock)
                {
                    pendingConnectionRequests.Remove(capturedPeerID);
                    if (!string.IsNullOrEmpty(capturedMeshIP))
                    {
                        completedTunnelMeshIPs.Add(capturedMeshIP);
                        tunnelCompletedAt[capturedMeshIP] = DateTime.UtcNow;
                        SendMeshVersionHello(capturedMeshIP);

                        if (deferredIntroductions.TryGetValue(capturedMeshIP, out var deferred) && deferred.Count > 0)
                        {
                            context.Log(LogLevel.Debug, $"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) for {capturedMeshIP}");
                            foreach (var deferredMsg in deferred)
                            {
                                string targetIP = !string.IsNullOrEmpty(deferredMsg.IntroducerMeshIP) && !deferredMsg.IsRelay
                                    ? deferredMsg.IntroducerMeshIP : capturedMeshIP;
                                try
                                {
                                    if (targetIP != capturedMeshIP)
                                        deferredMsg.IntroducerMeshIP = null;
                                    byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                    MeshSend(deferredBytes, deferredBytes.Length,
                                        new IPEndPoint(IPAddress.Parse(targetIP), MeshControlPort));
                                    context.Log(LogLevel.Debug, $"[Mesh] Sent deferred MeshConnectionBegin to {targetIP}");
                                }
                                catch (Exception ex)
                                {
                                    context.Log(LogLevel.Error, $"[Mesh] Failed to send deferred MeshConnectionBegin to {targetIP}: {ex.Message}");
                                }
                            }
                            deferredIntroductions.Remove(capturedMeshIP);
                        }
                    }
                }
            }
        );

        host?.ConfigureNewTunnel(peerTunnel, remotePeerID, remoteMeshIP);

        // Track the tunnel
        lock (meshLock) { activeConnectionTunnels[capturedPeerID.GetHashCode()] = peerTunnel; }
        activePeerTunnels[remotePeerID] = peerTunnel;
        if (!string.IsNullOrEmpty(remoteMeshIP))
        {
            activePeerTunnels[remoteMeshIP] = peerTunnel;
            peerMeshIPs[capturedPeerID.GetHashCode()] = remoteMeshIP;
        }

        // Start the tunnel (returns immediately since skipTcpConnection=true)
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                peerTunnel.Start();
                // Now inject the connection info to start hole-punching
                peerTunnel.InjectConnectionBegin(
                    remoteEndpoint,
                    remotePeerNatType,
                    OwnNatTypeForEndpoint(remoteEndpoint),
                    remoteMeshIP
                );
                context.Log(LogLevel.Info, $"[Mesh] Hole-punching started for {capturedPeerID} at {remoteEndpoint}");
            }
            catch (Exception ex)
            {
                context.Log(LogLevel.Error, $"[Mesh] Error starting introducer-relayed tunnel for {capturedPeerID}: {ex.Message}");
                pendingConnectionRequests.Remove(capturedPeerID);
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
            }
        });
    }

    private void PerformGracefulShutdown()
    {
        context.Log(LogLevel.Debug, "[Mesh] Graceful shutdown initiated");
        int recipientCount = 0;
        try
        {
            var leaveMsg = new MediationMessage(MediationMessageType.MeshPeerLeave)
            {
                PrivateAddressString = meshIP,
                PeerID = peerID.ToString()
            };
            byte[] leaveBytes = Encoding.UTF8.GetBytes(leaveMsg.Serialize());
            var allPeers = host.GetAllPeers();
            foreach (var peer in allPeers)
            {
                try
                {
                    MeshSend(leaveBytes, leaveBytes.Length,
                        new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                    recipientCount++;
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshPeerLeave to {peer.PrivateAddress}: {ex.Message}");
                }
            }
            context.Log(LogLevel.Debug, $"[Mesh] Sent MeshPeerLeave to {recipientCount} peer(s)");
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Error, $"[Mesh] Error sending graceful shutdown message: {ex.Message}");
        }

        // Brief drain delay before Run() returns and the finally block tears down sockets.
        // Without this, MeshPeerLeave packets sit in the kernel send queue when the socket
        // closes and get dropped — peers never learn we left, and their PeerDisconnected
        // event doesn't fire until the heartbeat-miss threshold (~75s with defaults).
        // Skip the delay when there were no recipients (no point waiting).
        if (recipientCount > 0)
        {
            try { System.Threading.Thread.Sleep(500); } catch { }
        }

        context.ShutdownRequested = true;
    }

    /// <summary>
    /// Eagerly tear down the engine: set ShutdownRequested and close the owned client sockets
    /// so any thread blocked on a synchronous Receive/Write unblocks immediately.
    /// </summary>
    internal void RequestShutdown()
    {
        if (context != null) context.ShutdownRequested = true;
        try { meshControlClient?.Close(); } catch { }
        try { tcpClient?.Close(); } catch { }
        try { reconnectedTcpClient?.Close(); } catch { }
    }

    private (MediationMessage msg, string remainder) ExtractFirstJson(string data)
    {
        int start = data.IndexOf('{');
        if (start == -1) return (null, data);
        int braces = 0;
        for (int i = start; i < data.Length; i++)
        {
            if (data[i] == '{') braces++;
            else if (data[i] == '}')
            {
                braces--;
                if (braces == 0)
                {
                    string jsonObj = data.Substring(start, i - start + 1);
                    string rest = data.Substring(i + 1);
                    return (JsonSerializer.Deserialize<MediationMessage>(jsonObj), rest);
                }
            }
        }
        return (null, data);
    }

    private MediationMessage ReadOneTcpMessage()
    {
        while (true)
        {
            var (msg, rest) = ExtractFirstJson(earlyTcpRemainder);
            if (msg != null)
            {
                earlyTcpRemainder = rest;
                return msg;
            }
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0) throw new IOException("Mediation server closed connection");
            earlyTcpRemainder += Encoding.ASCII.GetString(buffer, 0, bytesRead);
        }
    }

    private void ProcessDiscoveredPeers(object[] peers, Stream targetStream = null)
    {
        if (peers == null || peers.Length == 0) return;
        var writeStream = targetStream ?? stream;

        context.Log(LogLevel.Debug, $"[Mesh] Discovered {peers.Length} peer(s) in network:");
        foreach (var peer in peers)
        {
            var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
            string targetPeerID = peerObj.GetProperty("peerID").GetString();
            string peerEndpoint = peerObj.GetProperty("endpoint").GetString();
            string peerMeshIP = peerObj.TryGetProperty("meshIP", out JsonElement meshIPElement) ? meshIPElement.GetString() : null;
            int peerNatTypeInt = peerObj.TryGetProperty("natType", out JsonElement natEl) ? natEl.GetInt32() : -1;
            int peerMinVersion = peerObj.TryGetProperty("peerMinVersion", out JsonElement pminEl) ? pminEl.GetInt32() : 1;
            int peerMaxVersion = peerObj.TryGetProperty("peerMaxVersion", out JsonElement pmaxEl) ? pmaxEl.GetInt32() : 1;
            string peerIdentityPublicKey = peerObj.TryGetProperty("identityPublicKey", out JsonElement idElD) ? idElD.GetString() : null;

            if (targetPeerID == peerID.ToString()) continue;
            if (activePeerTunnels.ContainsKey(targetPeerID) || (peerMeshIP != null && activePeerTunnels.ContainsKey(peerMeshIP))) continue;
            if (pendingConnectionRequests.ContainsKey(targetPeerID)) continue;
            if (detectedNatType == NATType.Symmetric && (NATType)peerNatTypeInt == NATType.Symmetric) continue;
            if (IsBlocked(peerIdentityPublicKey))
            {
                context.Log(LogLevel.Debug, $"[Mesh] Skipping ConnectionRequest to {targetPeerID} — peer fingerprint is on local block list");
                continue;
            }
            // Pre-flight version check: if the mediation server echoed a range with no overlap,
            // record it now so the introducer-retry loop and other paths short-circuit too.
            {
                int lowerBound = Math.Max(MediationProtocol.PeerMinVersion, peerMinVersion);
                int upperBound = Math.Min(MediationProtocol.PeerMaxVersion, peerMaxVersion);
                if (upperBound < lowerBound)
                {
                    incompatiblePeers[targetPeerID] = (peerMinVersion, peerMaxVersion);
                }
            }
            if (IsIncompatible(targetPeerID, peerMinVersion, peerMaxVersion))
            {
                context.Log(LogLevel.Debug, $"[Mesh] Skipping ConnectionRequest to {targetPeerID} — peer-protocol range v{peerMinVersion}-v{peerMaxVersion} incompatible with ours v{MediationProtocol.PeerMinVersion}-v{MediationProtocol.PeerMaxVersion}");
                continue;
            }

            var connectionRequest = new MediationMessage(MediationMessageType.ConnectionRequest)
            {
                PeerID = targetPeerID,
                NATType = detectedNatType
            };
            byte[] connBuffer = Encoding.ASCII.GetBytes(connectionRequest.Serialize());
            writeStream.Write(connBuffer, 0, connBuffer.Length);
            writeStream.Flush();
            pendingConnectionRequests[targetPeerID] = DateTime.UtcNow;
        }
    }

    private void DrainInboundQueues()
    {
        // Process MeshConnectionBegin messages: create tunnels that hole-punch directly
        // without going through the mediation server (introducer-relayed coordination).
        while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
        {
            ProcessMeshConnectionBegin(cbMsg);
        }

        // Process peer removal notifications from the introducer
        while (meshPeerRemovedQueue.TryDequeue(out var rmMsg))
        {
            if (!string.IsNullOrEmpty(rmMsg.PrivateAddressString))
                RemoveDeadPeer(rmMsg.PrivateAddressString);
        }

        // GUI flipped off "allow relay through" — drop all hosted relay routes.
        if (context.RelayHostingDisableRequested)
        {
            context.RelayHostingDisableRequested = false;
            string[] dropped;
            lock (hostedRelayLock) { dropped = hostedRelays.ToArray(); hostedRelays.Clear(); }
            foreach (var pk in dropped)
            {
                var parts = pk.Split('|', 2);
                if (parts.Length != 2) continue;
                try
                {
                    host.RemoveRelayRouteForPeer(IPAddress.Parse(parts[0]));
                    host.RemoveRelayRouteForPeer(IPAddress.Parse(parts[1]));
                }
                catch { }
                // If we're the introducer, drive reassignment for the pairs we just stopped
                // hosting so endpoints don't wait for the 45s health timeout.
                if (isIntroducer)
                {
                    lastRelayReselect.TryRemove(pk, out _);
                    meshRelayHealthReportQueue.Enqueue(new MediationMessage(MediationMessageType.MeshRelayHealthReport)
                    {
                        PeerA = parts[0],
                        PeerB = parts[1],
                        CurrentRelay = meshIP,
                        Self = parts[0],
                        Remote = parts[1],
                        Observation = RelayHealthObservation.Other
                    });
                }
            }
            if (dropped.Length > 0)
                context.Log(LogLevel.Debug, $"[Mesh] Disabled relay hosting — dropped {dropped.Length} pair(s)");

            // Send an immediate heartbeat with RelayCapable=false so the introducer learns
            // right away and reassigns affected pairs, instead of waiting up to ProbeInterval
            // seconds for the next regular probe.
            if (!isIntroducer && !string.IsNullOrEmpty(introducerMeshIP))
            {
                try
                {
                    var probe = new MediationMessage(MediationMessageType.MeshHeartbeat)
                    {
                        RelayCapable = false,
                        RelayCapacity = context.Options.OwnRelayCapacity
                    };
                    byte[] probeBytes = Encoding.UTF8.GetBytes(probe.Serialize());
                    MeshSend(probeBytes, probeBytes.Length,
                        new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
                    context.Log(LogLevel.Debug, "[Mesh] Sent immediate heartbeat advertising RelayCapable=false");
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to send immediate opt-out heartbeat: {ex.Message}");
                }
            }
        }

        // We've been chosen as a relay for some pair — set up forwarding + ack.
        while (meshRelayAssignmentQueue.TryDequeue(out var raMsg))
        {
            if (raMsg.RelayMeshIP != meshIP)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Ignoring MeshRelayAssignment not addressed to us (RelayMeshIP={raMsg.RelayMeshIP})");
                continue;
            }
            string sortA = string.Compare(raMsg.PeerA, raMsg.PeerB, StringComparison.Ordinal) < 0 ? raMsg.PeerA : raMsg.PeerB;
            string sortB = sortA == raMsg.PeerA ? raMsg.PeerB : raMsg.PeerA;
            string pairKey = $"{sortA}|{sortB}";

            if (raMsg.Release)
            {
                try
                {
                    host.RemoveRelayRouteForPeer(IPAddress.Parse(raMsg.PeerA));
                    host.RemoveRelayRouteForPeer(IPAddress.Parse(raMsg.PeerB));
                }
                catch { }
                RemoveHostedRelay(pairKey);
                context.Log(LogLevel.Debug, $"[Mesh] Released relay for {raMsg.PeerA} <-> {raMsg.PeerB}");
                continue;
            }

            bool ok = false;
            string err = null;
            try
            {
                // The relay just needs IP forwarding + existing direct WG peers to both endpoints.
                // Don't touch AllowedIPs — adding the other endpoint's IP would steal cryptokey
                // routing from the direct peer entry and break this peer's direct connection.
                host.EnableForwarding();
                var aPeer = host.GetPeer(IPAddress.Parse(raMsg.PeerA));
                var bPeer = host.GetPeer(IPAddress.Parse(raMsg.PeerB));
                ok = aPeer != null && bPeer != null;
                if (ok)
                {
                    AddHostedRelay(pairKey);
                    context.Log(LogLevel.Debug, $"[Mesh] Hosting relay for {raMsg.PeerA} <-> {raMsg.PeerB}");
                }
                else err = $"Missing direct WG peer (aPeer={aPeer != null}, bPeer={bPeer != null})";
            }
            catch (Exception ex) { err = ex.Message; }

            if (!string.IsNullOrEmpty(introducerMeshIP))
            {
                var ack = new MediationMessage(MediationMessageType.MeshRelayAssignmentAck)
                {
                    PeerA = raMsg.PeerA,
                    PeerB = raMsg.PeerB,
                    RelayMeshIP = meshIP,
                    Success = ok,
                    Error = err
                };
                try
                {
                    byte[] ackBytes = Encoding.UTF8.GetBytes(ack.Serialize());
                    MeshSend(ackBytes, ackBytes.Length, new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
                }
                catch { }
            }
        }

        // Health reports from relayed peers — reselect if a meaningfully better candidate exists.
        while (meshRelayHealthReportQueue.TryDequeue(out var hrMsg))
        {
            if (!isIntroducer) continue;
            string pa = hrMsg.PeerA ?? hrMsg.Self;
            string pb = hrMsg.PeerB ?? hrMsg.Remote;
            if (string.IsNullOrEmpty(pa) || string.IsNullOrEmpty(pb)) continue;
            string sortA = string.Compare(pa, pb, StringComparison.Ordinal) < 0 ? pa : pb;
            string sortB = sortA == pa ? pb : pa;
            string pairKey = $"{sortA}|{sortB}";

            var cooldown = TimeSpan.FromSeconds(context.Options.RelayReselectCooldownSeconds);
            if (lastRelayReselect.TryGetValue(pairKey, out var lastSel) && DateTime.UtcNow - lastSel < cooldown)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Health report for {pairKey} within cooldown — ignored");
                continue;
            }

            string oldRelay = hrMsg.CurrentRelay;
            if (string.IsNullOrEmpty(oldRelay)) relayAssignments.TryGetValue(pairKey, out oldRelay);

            long? OldScore()
            {
                if (string.IsNullOrEmpty(oldRelay)) return null;
                long lA = peerLatencyMs.TryGetValue(oldRelay == pa ? pb : pa, out var x) ? x : long.MaxValue / 4;
                long lB = peerLatencyMs.TryGetValue(oldRelay == pb ? pa : pb, out var y) ? y : long.MaxValue / 4;
                int load = oldRelay == meshIP ? HostedRelayCount()
                           : (relayCandidates.TryGetValue(oldRelay, out var rc) ? rc.activeRoutes : 0);
                return lA + lB + (long)context.Options.RelayLoadFactorMs * load;
            }

            // Temporarily mark the old relay ineligible so PickRelay skips it.
            bool restored = false;
            (bool capable, int activeRoutes, RelayCapacity capacity, DateTime lastSeen) saved = default;
            if (!string.IsNullOrEmpty(oldRelay) && oldRelay != meshIP && relayCandidates.TryGetValue(oldRelay, out saved))
            {
                relayCandidates[oldRelay] = (false, saved.activeRoutes, saved.capacity, saved.lastSeen);
                restored = true;
            }
            string newRelay = PickRelay(pa, pb);
            if (restored) relayCandidates[oldRelay] = saved;

            if (string.IsNullOrEmpty(newRelay) || newRelay == oldRelay)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Health report for {pairKey}: no better candidate available");
                lastRelayReselect[pairKey] = DateTime.UtcNow;
                continue;
            }

            // Skip the score-improvement threshold when the old relay is no longer viable
            // (peer gone, or RelayCapable flipped false). Otherwise we'd "stay put" on a relay
            // that won't actually carry traffic.
            bool oldStillViable = !string.IsNullOrEmpty(oldRelay) &&
                (oldRelay == meshIP
                    ? context.Options.AllowRelayThrough
                    : (relayCandidates.TryGetValue(oldRelay, out var rcOld) && rcOld.capable));
            long? oldS = OldScore();
            long newS = (peerLatencyMs.TryGetValue(newRelay == pa ? pb : pa, out var nlA) ? nlA : 0)
                      + (peerLatencyMs.TryGetValue(newRelay == pb ? pa : pb, out var nlB) ? nlB : 0)
                      + (long)context.Options.RelayLoadFactorMs *
                        (newRelay == meshIP ? HostedRelayCount()
                         : (relayCandidates.TryGetValue(newRelay, out var nc) ? nc.activeRoutes : 0));
            if (oldStillViable && oldS.HasValue && newS > oldS.Value * (1.0 - context.Options.RelayReselectMinImprovement))
            {
                context.Log(LogLevel.Debug, $"[Mesh] Health report for {pairKey}: new candidate {newRelay} (score {newS}) not meaningfully better than {oldRelay} (score {oldS}) — staying put");
                lastRelayReselect[pairKey] = DateTime.UtcNow;
                continue;
            }

            context.Log($"[Mesh] Reselecting relay for {pairKey}: {oldRelay ?? "(unknown)"} → {newRelay}");
            relayAssignments[pairKey] = newRelay;
            lastRelayReselect[pairKey] = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(oldRelay) && oldRelay != newRelay)
            {
                if (oldRelay == meshIP)
                {
                    try
                    {
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(pa));
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(pb));
                    }
                    catch { }
                    RemoveHostedRelay(pairKey);
                }
                else
                {
                    var release = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                    {
                        PeerA = pa,
                        PeerB = pb,
                        RelayMeshIP = oldRelay,
                        Release = true
                    };
                    try { byte[] rb = Encoding.UTF8.GetBytes(release.Serialize()); MeshSend(rb, rb.Length, new IPEndPoint(IPAddress.Parse(oldRelay), MeshControlPort)); }
                    catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to release old relay {oldRelay}: {ex.Message}"); }
                }
            }

            if (newRelay == meshIP)
            {
                host.EnableForwarding();
                AddHostedRelay(pairKey);
            }
            else
            {
                var assign = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                {
                    PeerA = pa,
                    PeerB = pb,
                    RelayMeshIP = newRelay
                };
                try { byte[] ab = Encoding.UTF8.GetBytes(assign.Serialize()); MeshSend(ab, ab.Length, new IPEndPoint(IPAddress.Parse(newRelay), MeshControlPort)); }
                catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to dispatch MeshRelayAssignment to {newRelay}: {ex.Message}"); }
            }

            NotifyEndpoint(pa, pb, newRelay);
            NotifyEndpoint(pb, pa, newRelay);
        }

        // Process graceful peer leave notifications
        while (meshPeerLeaveQueue.TryDequeue(out var leaveMsg))
        {
            if (!string.IsNullOrEmpty(leaveMsg.PrivateAddressString))
            {
                context.Log(LogLevel.Debug, $"[Mesh] Peer {leaveMsg.PrivateAddressString} left gracefully");
                bool wasIntroducer = leaveMsg.PrivateAddressString == introducerMeshIP;
                RemoveDeadPeer(leaveMsg.PrivateAddressString);
                // Don't pre-arm takeover counters if a reconnect-to-mediation bid is already in flight
                // (mesh-control-only loop). reconnectedTcpClient is always null in the primary loop.
                if (wasIntroducer && !isIntroducer && reconnectedTcpClient == null)
                {
                    context.Log(LogLevel.Debug, "[Mesh] Introducer left gracefully — forcing immediate takeover check");
                    // Pre-arm both counters: clearing the ack flag so the probe block's
                    // first branch fires, and bumping misses one past threshold so even
                    // after the block's ++ the takeover gate trips.
                    introducerProbeAckReceived = false;
                    introducerMissedProbes = IntroducerMissedProbeThreshold;
                    lastIntroducerProbe = DateTime.UtcNow.AddSeconds(-introducerProbeInterval.TotalSeconds - 1);
                }
            }
        }
    }

    /// <summary>
    /// One introducer-heartbeat round: send heartbeats, collect acks, declare dead peers,
    /// run repair, and (if the mediation TCP is connected) request fresh ConnectionRequests
    /// for peers with no completed tunnel.
    /// `mediationClient` and `mediationStream` are the TCP client + stream the caller currently
    /// owns — the primary loop passes tcpClient/stream, the mesh-control-only loop passes
    /// reconnectedTcpClient/reconnectedStream.
    /// </summary>
    private void RunIntroducerHeartbeat(TcpClient mediationClient, Stream mediationStream)
    {
        if (isIntroducer && heartbeatAckDeadline == null &&
            DateTime.UtcNow - lastHeartbeat > heartbeatInterval)
        {
            var allPeers = host.GetAllPeers();
            heartbeatTargets.Clear();
            heartbeatAcks.Clear();

            // Build peer roster so non-introducer peers can learn about all mesh members
            var roster = new List<string>();
            foreach (var peer in allPeers)
            {
                string pip = peer.PrivateAddress.ToString();
                if (peerInfoByMeshIP.TryGetValue(pip, out var pi))
                    roster.Add($"{pip}|{pi.peerID}|{(int)pi.natType}|{pi.endpoint}");
            }
            var rosterArray = roster.Count > 0 ? roster.ToArray() : null;

            foreach (var peer in allPeers)
            {
                string peerIP = peer.PrivateAddress.ToString();
                heartbeatTargets.Add(peerIP);

                var hb = new MediationMessage(MediationMessageType.MeshHeartbeat)
                {
                    PeerRoster = rosterArray,
                    IsIntroducer = true,
                    RelayCapable = context.Options.AllowRelayThrough,
                    ActiveRelayRoutes = HostedRelayCount(),
                    RelayCapacity = context.Options.OwnRelayCapacity
                };
                try
                {
                    byte[] hbBytes = Encoding.UTF8.GetBytes(hb.Serialize());
                    MeshSend(hbBytes, hbBytes.Length,
                        new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to send heartbeat to {peerIP}: {ex.Message}");
                }
            }

            if (heartbeatTargets.Count > 1)
            {
                heartbeatAckDeadline = DateTime.UtcNow.AddSeconds(5);
                heartbeatSentTime = DateTime.UtcNow;
                metricHeartbeatsSent++;
                context.Log(LogLevel.Debug, $"[Mesh] Heartbeat sent to {heartbeatTargets.Count} peer(s), collecting acks...");
            }
            else
            {
                // 0 or 1 peers — nothing to check connectivity between
                lastHeartbeat = DateTime.UtcNow;
            }
        }

        // Collect heartbeat acks
        if (heartbeatAckDeadline == null) return;

        while (meshHeartbeatAckQueue.TryDequeue(out var ackMsg))
        {
            string ackMeshIP = ackMsg.PrivateAddressString;
            if (!string.IsNullOrEmpty(ackMeshIP) && ackMsg.ConnectedMeshIPs != null)
            {
                heartbeatAcks[ackMeshIP] = new HashSet<string>(ackMsg.ConnectedMeshIPs);
                metricHeartbeatAcksReceived++;
                // Re-populate completedTunnelMeshIPs if this peer is acking us — their heartbeat
                // ack is proof the tunnel between us is bidirectionally alive. Something else (an
                // MIR rejoin, a stale-tunnel sweep miss) may have wiped this even when the WG
                // path is healthy, and without re-adding it RepairBrokenLinks will refuse to fire
                // pair repairs against this peer indefinitely ("missing completed tunnel").
                if (!completedTunnelMeshIPs.Contains(ackMeshIP))
                {
                    completedTunnelMeshIPs.Add(ackMeshIP);
                    tunnelCompletedAt[ackMeshIP] = DateTime.UtcNow;
                }
            }
            if (!string.IsNullOrEmpty(ackMeshIP) && !string.IsNullOrEmpty(ackMsg.PeerID))
            {
                bool hasExisting = peerInfoByMeshIP.TryGetValue(ackMeshIP, out var existing);
                string existingEndpoint = hasExisting ? existing.endpoint : null;
                int existingMinV = hasExisting ? existing.peerMinVersion : 1;
                int existingMaxV = hasExisting ? existing.peerMaxVersion : 1;
                string existingIdKey = hasExisting ? existing.identityPublicKey : null;
                string existingV6 = hasExisting ? existing.endpointV6 : null;
                peerInfoByMeshIP[ackMeshIP] = (ackMsg.PeerID, existingEndpoint, ackMsg.NATType, existingMinV, existingMaxV, existingIdKey, existingV6);
                MarkRecentlySeen(ackMeshIP, ackMsg.PeerID);
            }
        }

        if (DateTime.UtcNow <= heartbeatAckDeadline.Value) return;

        if (heartbeatSentTime != null)
            metricLastHeartbeatResponseMs = (long)(DateTime.UtcNow - heartbeatSentTime.Value).TotalMilliseconds;
        context.Log(LogLevel.Debug, $"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

        var deadPeers = new List<string>();
        foreach (var ip in heartbeatTargets)
        {
            if (heartbeatAcks.ContainsKey(ip))
            {
                heartbeatMissCount[ip] = 0;
            }
            else
            {
                heartbeatMissCount.TryGetValue(ip, out int prev);
                heartbeatMissCount[ip] = prev + 1;
                metricHeartbeatsMissed++;
                context.Log(LogLevel.Warning, $"[Mesh] Peer {ip} missed heartbeat ({heartbeatMissCount[ip]}/{peerDeadThreshold})");
                if (heartbeatMissCount[ip] >= peerDeadThreshold)
                {
                    // Symmetric NAT hole-punching can take longer than the heartbeat window,
                    // so defer declaring a peer dead if its tunnel attempt is still in flight.
                    // BUT only defer while the tunnel hasn't completed yet. Once a peer is in
                    // completedTunnelMeshIPs, missed heartbeats mean the peer disappeared —
                    // not that hole-punching is slow. Without this distinction, the dead peer's
                    // stale activePeerTunnels entry would keep the defer guard alive forever
                    // (the only place that entry gets cleared is RemoveDeadPeer itself).
                    string peerPID = peerInfoByMeshIP.TryGetValue(ip, out var pi) ? pi.peerID : null;
                    bool hasPendingTunnel = (!string.IsNullOrEmpty(peerPID) && activePeerTunnels.ContainsKey(peerPID)) ||
                                            activePeerTunnels.ContainsKey(ip) ||
                                            (!string.IsNullOrEmpty(peerPID) && pendingConnectionRequests.ContainsKey(peerPID));
                    bool tunnelEverCompleted = completedTunnelMeshIPs.Contains(ip);
                    if (hasPendingTunnel && !tunnelEverCompleted)
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] Peer {ip} would be dead but tunnel still establishing — deferring removal");
                        continue;
                    }
                    deadPeers.Add(ip);
                }
            }
        }
        foreach (var deadIP in deadPeers)
        {
            metricPeersLost++;
            context.Log(LogLevel.Warning, $"[Mesh] Peer {deadIP} declared dead after {peerDeadThreshold} consecutive missed heartbeats");
            string deadPID = peerInfoByMeshIP.TryGetValue(deadIP, out var di) ? di.peerID : null;
            var removeMsg = new MediationMessage(MediationMessageType.MeshPeerRemoved)
            {
                PrivateAddressString = deadIP,
                PeerID = deadPID ?? ""
            };
            byte[] rmBytes = Encoding.UTF8.GetBytes(removeMsg.Serialize());
            foreach (var peerIP in heartbeatTargets)
            {
                if (peerIP == deadIP) continue;
                try
                {
                    MeshSend(rmBytes, rmBytes.Length,
                        new IPEndPoint(IPAddress.Parse(peerIP), MeshControlPort));
                }
                catch { }
            }
            // Notify mediation so the server can immediately drop the dead peer from its roster
            // (otherwise it sits as connected=false for 5min and pollutes future MeshJoinResponse
            // peer lists, driving stale "no completed tunnel" heartbeat retries on the introducer).
            if (mediationClient != null && mediationClient.Connected && mediationStream != null)
            {
                try
                {
                    byte[] rmTcpBytes = Encoding.ASCII.GetBytes(removeMsg.Serialize());
                    mediationStream.Write(rmTcpBytes, 0, rmTcpBytes.Length);
                    mediationStream.Flush();
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to notify mediation of dead peer {deadIP}: {ex.Message}");
                }
            }
            RemoveDeadPeer(deadIP);
        }

        var targetList = heartbeatTargets.Where(ip => !deadPeers.Contains(ip)).ToList();
        int repairCount = RepairBrokenLinks(targetList, heartbeatAcks, mediationClient, mediationStream);
        if (repairCount > 0)
            context.Log(LogLevel.Debug, $"[Mesh] Heartbeat: sent {repairCount} repair message(s)");

        // Retry ConnectionRequest for peers with no completed tunnel — only if we have
        // a live mediation TCP. Without it, mediation-brokered reconnection isn't possible.
        if (mediationClient != null && mediationClient.Connected && mediationStream != null)
        {
            foreach (var kvp in peerInfoByMeshIP)
            {
                string peerMeshIP = kvp.Key;
                if (peerMeshIP == meshIP) continue;
                if (completedTunnelMeshIPs.Contains(peerMeshIP)) continue;
                if (deadPeers.Contains(peerMeshIP)) continue;
                if (string.IsNullOrEmpty(kvp.Value.peerID)) continue;
                if (pendingConnectionRequests.ContainsKey(kvp.Value.peerID)) continue;
                if (activePeerTunnels.ContainsKey(kvp.Value.peerID) || activePeerTunnels.ContainsKey(peerMeshIP)) continue;
                if (IsIncompatible(kvp.Value.peerID, kvp.Value.peerMinVersion, kvp.Value.peerMaxVersion)) continue;
                if (IsBlocked(kvp.Value.identityPublicKey)) continue;

                context.Log(LogLevel.Debug, $"[Mesh] Heartbeat: peer {peerMeshIP} has no completed tunnel — requesting reconnection via mediation");
                try
                {
                    var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                    {
                        PeerID = kvp.Value.peerID,
                        NATType = detectedNatType
                    };
                    byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                    mediationStream.Write(reconnBuf, 0, reconnBuf.Length);
                    mediationStream.Flush();
                    pendingConnectionRequests[kvp.Value.peerID] = DateTime.UtcNow;
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to send reconnection request for {peerMeshIP}: {ex.Message}");
                }
            }
        }

        heartbeatAckDeadline = null;
        lastHeartbeat = DateTime.UtcNow;
    }

    /// <summary>
    /// Handler for a ConnectionBegin message from the mediation server: cache peer info, tear down
    /// any stale tunnel to the same mesh IP, and spin up a fresh Tunnel that hole-punches directly
    /// to this peer.
    /// </summary>
    private void HandleConnectionBegin(MediationMessage msg)
    {
        context.Log(LogLevel.Debug, $"[Mesh] *** ConnectionBegin received! ***");
        context.Log(LogLevel.Debug, $"[Mesh] ConnectionBegin: connID={msg.ConnectionID}, endpoint={msg.EndpointString}, NAT={msg.NATType}, meshIP={msg.PrivateAddressString}");

        if (IsIncompatible(msg.PeerID, msg.PeerMinVersion, msg.PeerMaxVersion))
        {
            context.Log(LogLevel.Debug, $"[Mesh] Ignoring ConnectionBegin for {msg.PeerID} — peer-protocol range v{msg.PeerMinVersion}-v{msg.PeerMaxVersion} previously refused");
            return;
        }
        if (IsBlocked(msg.IdentityPublicKey))
        {
            context.Log(LogLevel.Debug, $"[Mesh] Ignoring ConnectionBegin for {msg.PeerID} — peer fingerprint is on local block list");
            return;
        }

        if (!string.IsNullOrEmpty(msg.PrivateAddressString))
        {
            peerMeshIPs[msg.ConnectionID] = msg.PrivateAddressString;
            // Always cache the EXTERNAL endpoint: if we ever become the introducer, we must hand
            // peers an address that works from outside this LAN. EndpointString may be LAN-substituted.
            if (!string.IsNullOrEmpty(msg.PeerID))
            {
                string cacheEndpoint = !string.IsNullOrEmpty(msg.ExternalEndpointString)
                    ? msg.ExternalEndpointString
                    : msg.EndpointString;
                peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, cacheEndpoint, msg.NATType, msg.PeerMinVersion, msg.PeerMaxVersion, msg.IdentityPublicKey, msg.EndpointV6String);
                MarkRecentlySeen(msg.PrivateAddressString, msg.PeerID);
            }

            // Tear down any tunnel for the same mesh IP before creating a new one. Late-completing
            // old tunnels would otherwise overwrite the WireGuard peer's endpoint with a stale address.
            string cbMeshIP = msg.PrivateAddressString;
            var oldConnIDs = peerMeshIPs
                .Where(kvp => kvp.Value == cbMeshIP && kvp.Key != msg.ConnectionID)
                .Select(kvp => kvp.Key).ToList();
            foreach (var oldConnID in oldConnIDs)
            {
                Tunnel oldTunnel = null;
                lock (meshLock)
                {
                    if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                        activeConnectionTunnels.Remove(oldConnID);
                }
                if (oldTunnel != null)
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Disposing old tunnel {oldConnID} for {cbMeshIP} (superseded by {msg.ConnectionID})");
                    try { oldTunnel.Dispose(); } catch { }
                }
                peerMeshIPs.Remove(oldConnID);
            }
            activePeerTunnels.Remove(cbMeshIP);
            completedTunnelMeshIPs.Remove(cbMeshIP);
            if (!string.IsNullOrEmpty(msg.PeerID))
                activePeerTunnels.Remove(msg.PeerID);
        }

        if (activeConnectionTunnels.ContainsKey(msg.ConnectionID))
        {
            context.Log(LogLevel.Debug, $"[Mesh] Tunnel {msg.ConnectionID} already exists - ignoring duplicate ConnectionBegin");
            return;
        }

        pendingTunnelCount++;
        var capturedConnectionID = msg.ConnectionID;
        var capturedPeerIDForCleanup = msg.PeerID;
        var capturedMeshIPForCleanup = msg.PrivateAddressString;
        var peerTunnel = new Tunnel(
            onConnectionFailure: () =>
            {
                context.Log(LogLevel.Error, $"[Mesh] Tunnel {capturedConnectionID} failed permanently after all retries — cleaning up for future retry");
                lock (meshLock)
                {
                    activeConnectionTunnels.Remove(capturedConnectionID);
                    if (!string.IsNullOrEmpty(capturedPeerIDForCleanup))
                        activePeerTunnels.Remove(capturedPeerIDForCleanup);
                    if (!string.IsNullOrEmpty(capturedMeshIPForCleanup))
                        activePeerTunnels.Remove(capturedMeshIPForCleanup);
                }
                // Drop the host's peer registration so the proxy goes away alongside the tunnel.
                // See the matching cleanup in the introducer-relayed branch for the full rationale.
                if (!string.IsNullOrEmpty(capturedMeshIPForCleanup) && IPAddress.TryParse(capturedMeshIPForCleanup, out var capturedMeshIPAddr2))
                {
                    var hostPeer = host.GetPeer(capturedMeshIPAddr2);
                    if (hostPeer != null) host.RemovePeer(hostPeer.ConnectionId);
                }
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
            },
            sharedUdpClient: udpClient,
            meshPeerEndpoint: msg.EndpointString,
            retryInPlace: true,
            sharedClientID: peerID,
            ownMeshIP: meshIP,
            onConnectionComplete: () =>
            {
                context.Log(LogLevel.Info, $"[Mesh] Tunnel {capturedConnectionID} WireGuard connection established");
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                lock (meshLock)
                {
                    if (peerMeshIPs.TryGetValue(capturedConnectionID, out string completedMeshIP) && !string.IsNullOrEmpty(completedMeshIP))
                    {
                        completedTunnelMeshIPs.Add(completedMeshIP);
                        tunnelCompletedAt[completedMeshIP] = DateTime.UtcNow;
                        SendMeshVersionHello(completedMeshIP);
                        if (deferredIntroductions.TryGetValue(completedMeshIP, out var deferred) && deferred.Count > 0)
                        {
                            context.Log(LogLevel.Debug, $"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) for {completedMeshIP}");
                            foreach (var deferredMsg in deferred)
                            {
                                string targetIP = !string.IsNullOrEmpty(deferredMsg.IntroducerMeshIP) && !deferredMsg.IsRelay
                                    ? deferredMsg.IntroducerMeshIP : completedMeshIP;
                                try
                                {
                                    if (targetIP != completedMeshIP)
                                        deferredMsg.IntroducerMeshIP = null;
                                    byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                    MeshSend(deferredBytes, deferredBytes.Length,
                                        new IPEndPoint(IPAddress.Parse(targetIP), MeshControlPort));
                                    context.Log(LogLevel.Debug, $"[Mesh] Sent deferred MeshConnectionBegin to {targetIP}");
                                }
                                catch (Exception ex)
                                {
                                    context.Log(LogLevel.Error, $"[Mesh] Failed to send deferred MeshConnectionBegin to {targetIP}: {ex.Message}");
                                }
                            }
                            deferredIntroductions.Remove(completedMeshIP);
                        }
                    }
                }
            }
        );

        host?.ConfigureNewTunnel(peerTunnel, msg.PeerID, msg.PrivateAddressString);
        lock (meshLock) { activeConnectionTunnels[msg.ConnectionID] = peerTunnel; }
        if (!string.IsNullOrEmpty(msg.PrivateAddressString))
            activePeerTunnels[msg.PrivateAddressString] = peerTunnel;
        if (!string.IsNullOrEmpty(msg.PeerID))
        {
            pendingConnectionRequests.Remove(msg.PeerID);
            connectionIDToPeerID[msg.ConnectionID] = msg.PeerID;
            activePeerTunnels[msg.PeerID] = peerTunnel;
        }

        // Start the tunnel asynchronously. pendingTunnelCount is decremented by
        // onConnectionComplete (success) or onConnectionFailure (failure) — not here —
        // so the mediation disconnect only happens after WireGuard setup is fully done.
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                peerTunnel.Start();
                // Inject ConnectionBegin directly — preserves LAN endpoints for same-NAT peers.
                peerTunnel.InjectConnectionBegin(
                    msg.EndpointString,
                    RemoteNatTypeForEndpoint(msg.EndpointString, msg.NATType, msg.NATTypeV6),
                    OwnNatTypeForEndpoint(msg.EndpointString),
                    msg.PrivateAddressString);
            }
            catch (Exception ex)
            {
                context.Log(LogLevel.Error, $"[Mesh] Error starting tunnel {capturedConnectionID}: {ex.Message}");
                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
            }
        });
    }

    /// <summary>
    /// Handler for a MeshJoinResponse: server-authoritative introducer-role assignment, plus
    /// processing of any peers the server included in the response. Sets hasPeers=true if the
    /// response includes other mesh members.
    /// </summary>
    private void HandleMeshJoinResponse(MediationMessage msg, ref bool hasPeers)
    {
        if (!string.IsNullOrEmpty(msg.AuthToken))
        {
            Console.Error.WriteLine($"[Mesh] Authentication failed on rediscovery: {msg.AuthToken}");
            return;
        }

        // Server-authoritative role assignment.
        if (!string.IsNullOrEmpty(msg.IntroducerPeerID))
        {
            bool serverSaysWereIntroducer = msg.IntroducerPeerID == peerID.ToString();
            if (serverSaysWereIntroducer && !isIntroducer)
            {
                context.Log(LogLevel.Info, "[Mesh] Server confirmed us as new introducer (primary loop)");
                isIntroducer = true;
                introducerMeshIP = meshIP;
            }
            else if (!serverSaysWereIntroducer && isIntroducer)
            {
                context.Log(LogLevel.Info, $"[Mesh] Server picked a different introducer ({msg.IntroducerPeerID}) — relinquishing role");
                isIntroducer = false;

                // The new introducer doesn't know about relay routes we were hosting — drop them
                // and let the new introducer re-establish on demand.
                string[] droppedAtRelinquish;
                lock (hostedRelayLock) { droppedAtRelinquish = hostedRelays.ToArray(); hostedRelays.Clear(); }
                foreach (var pk in droppedAtRelinquish)
                {
                    var parts = pk.Split('|', 2);
                    if (parts.Length != 2) continue;
                    try
                    {
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(parts[0]));
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(parts[1]));
                    }
                    catch { }
                }
                relayAssignments.Clear();
                lastRelayReselect.Clear();
                relayedPairs.Clear();
                if (droppedAtRelinquish.Length > 0)
                    context.Log(LogLevel.Debug, $"[Mesh] Relinquished introducer: dropped {droppedAtRelinquish.Length} hosted relay pair(s)");
            }
            if (!serverSaysWereIntroducer && msg.Peers != null)
            {
                // Update introducerMeshIP to the server's choice.
                foreach (var peerObj in msg.Peers)
                {
                    var pe = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                    string pid = pe.TryGetProperty("peerID", out var pidEl) ? pidEl.GetString() : null;
                    string mip = pe.TryGetProperty("meshIP", out var mipEl) ? mipEl.GetString() : null;
                    if (pid == msg.IntroducerPeerID && !string.IsNullOrEmpty(mip))
                    {
                        if (introducerMeshIP != mip)
                        {
                            context.Log(LogLevel.Info, $"[Mesh] Introducer updated to {mip} per server");
                            introducerMeshIP = mip;
                            introducerMissedProbes = 0;
                            introducerProbeAckReceived = true;
                        }
                        break;
                    }
                }
            }
        }

        if (msg.Peers != null && msg.Peers.Length > 0)
        {
            hasPeers = true;
            ProcessDiscoveredPeers(msg.Peers);
        }

        lastPeerDiscovery = DateTime.UtcNow;
    }

    /// <summary>
    /// Handler for a MeshIntroduceRequest: server has chosen this peer as the introducer for
    /// a new joiner. For each existing peer in OtherPeers, dispatch MeshConnectionBegin messages
    /// (with same-LAN and symmetric-relay handling), then send MeshIntroduceAck. Returns false
    /// if the ack write fails (caller should break the loop — connection is dead).
    /// </summary>
    private bool HandleMeshIntroduceRequest(MediationMessage msg)
    {
        if (IsIncompatible(msg.PeerID, msg.PeerMinVersion, msg.PeerMaxVersion) || IsBlocked(msg.IdentityPublicKey))
        {
            string reason = IsBlocked(msg.IdentityPublicKey)
                ? "peer fingerprint is on local block list"
                : $"peer-protocol range v{msg.PeerMinVersion}-v{msg.PeerMaxVersion} previously refused";
            context.Log(LogLevel.Debug, $"[Mesh] Declining introducer role for {msg.PeerID} — {reason}");
            try
            {
                var ack = new MediationMessage(MediationMessageType.MeshIntroduceAck) { PeerID = msg.PeerID };
                byte[] ackBuffer = Encoding.ASCII.GetBytes(ack.Serialize());
                stream.Write(ackBuffer, 0, ackBuffer.Length);
                stream.Flush();
            }
            catch { }
            return true;
        }
        isIntroducer = true;
        context.Log(LogLevel.Debug, $"[Mesh] Selected as introducer for new peer {msg.PeerID}");

        // Cache the new peer's info. Clear completedTunnelMeshIPs only if the tunnel is
        // demonstrably stale — a peer whose rejoin was triggered by isolation from a *different*
        // peer (block/repair cycle) may still have a working tunnel to us, and wiping the flag
        // makes RepairBrokenLinks skip the pair repair path indefinitely with
        // "missing completed tunnel."
        if (!string.IsNullOrEmpty(msg.PrivateAddressString))
        {
            peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, msg.EndpointString, msg.NATType, msg.PeerMinVersion, msg.PeerMaxVersion, msg.IdentityPublicKey, msg.EndpointV6String);
            MarkRecentlySeen(msg.PrivateAddressString, msg.PeerID);
            if (!string.IsNullOrEmpty(msg.LocalIP))
                peerLanByMeshIP[msg.PrivateAddressString] = (msg.LocalIP, msg.LocalPort);
            var tunnelHealthyWindow = TimeSpan.FromSeconds(30);
            bool tunnelIsFresh = lastHeartbeatReceivedFrom.TryGetValue(msg.PrivateAddressString, out var lastInbound) &&
                                 DateTime.UtcNow - lastInbound < tunnelHealthyWindow;
            if (!tunnelIsFresh)
                completedTunnelMeshIPs.Remove(msg.PrivateAddressString);
            deferredIntroductions.Remove(msg.PrivateAddressString);
        }

        int introduced = 0;
        if (msg.OtherPeers != null)
        {
            foreach (var peerObj in msg.OtherPeers)
            {
                var peerElement = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                string existingPeerMeshIP = peerElement.TryGetProperty("meshIP", out JsonElement mip) ? mip.GetString() : null;
                string existingPeerEndpoint = peerElement.TryGetProperty("endpoint", out JsonElement epEl) ? epEl.GetString() : null;
                int existingPeerNatType = peerElement.TryGetProperty("natType", out JsonElement ntEl) ? ntEl.GetInt32() : -1;
                string existingPeerID = peerElement.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                string existingPeerLocalIP = peerElement.TryGetProperty("localIP", out JsonElement lipEl) ? lipEl.GetString() : null;
                int existingPeerLocalPort = peerElement.TryGetProperty("localPort", out JsonElement lpEl) ? lpEl.GetInt32() : 0;
                int existingPeerMinVersion = peerElement.TryGetProperty("peerMinVersion", out JsonElement pminEl) ? pminEl.GetInt32() : 1;
                int existingPeerMaxVersion = peerElement.TryGetProperty("peerMaxVersion", out JsonElement pmaxEl) ? pmaxEl.GetInt32() : 1;
                string existingPeerIdentityPublicKey = peerElement.TryGetProperty("identityPublicKey", out JsonElement idElP) ? idElP.GetString() : null;
                string existingPeerEndpointV6 = peerElement.TryGetProperty("endpointV6", out JsonElement epV6ElP) ? epV6ElP.GetString() : null;

                if (string.IsNullOrEmpty(existingPeerMeshIP))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Skipping peer with no mesh IP in OtherPeers list");
                    continue;
                }

                if (IsIncompatible(existingPeerID, existingPeerMinVersion, existingPeerMaxVersion) ||
                    IsIncompatible(msg.PeerID, msg.PeerMinVersion, msg.PeerMaxVersion))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Skipping introduction pair {msg.PeerID} <-> {existingPeerID} — one or both previously refused on peer-protocol range");
                    continue;
                }
                if (IsBlocked(existingPeerIdentityPublicKey) || IsBlocked(msg.IdentityPublicKey))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Skipping introduction pair {msg.PeerID} <-> {existingPeerID} — one or both are on local block list");
                    continue;
                }

                peerInfoByMeshIP[existingPeerMeshIP] = (existingPeerID, existingPeerEndpoint, (NATType)existingPeerNatType, existingPeerMinVersion, existingPeerMaxVersion, existingPeerIdentityPublicKey, existingPeerEndpointV6);
                MarkRecentlySeen(existingPeerMeshIP, existingPeerID);
                if (!string.IsNullOrEmpty(existingPeerLocalIP))
                    peerLanByMeshIP[existingPeerMeshIP] = (existingPeerLocalIP, existingPeerLocalPort);

                // OtherPeers includes all mesh members; we can only send MeshConnectionBegin
                // over WireGuard to peers we already have tunnels with.
                if (host.GetPeer(IPAddress.Parse(existingPeerMeshIP)) == null)
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Skipping peer {existingPeerID} ({existingPeerMeshIP}) — no WireGuard tunnel to this peer");
                    continue;
                }

                // Clean up stale relay state if the pair's NAT types changed.
                if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                {
                    string sortA = string.Compare(existingPeerMeshIP, msg.PrivateAddressString, StringComparison.Ordinal) < 0
                        ? existingPeerMeshIP : msg.PrivateAddressString;
                    string sortB = sortA == existingPeerMeshIP ? msg.PrivateAddressString : existingPeerMeshIP;
                    string pairKey = $"{sortA}|{sortB}";
                    if (relayedPairs.Remove(pairKey))
                    {
                        context.Log(LogLevel.Warning, $"[Mesh] Removed stale relay pair {pairKey} (NAT types changed)");
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(existingPeerMeshIP));
                        host.RemoveRelayRouteForPeer(IPAddress.Parse(msg.PrivateAddressString));
                    }
                }

                // When both peers have a usable IPv6 endpoint, connect directly over v6 regardless
                // of NAT type: v6 has no NAT to traverse, so the symmetric-relay dance is
                // unnecessary — only a mutual firewall punch is needed, which the direct path does.
                bool bothHaveV6 = !string.IsNullOrEmpty(msg.EndpointV6String) &&
                                  !string.IsNullOrEmpty(existingPeerEndpointV6);

                // Same-LAN short-circuit for symmetric pairs.
                string msgPublicIP = EndpointUtils.GetHost(msg.EndpointString);
                string exPublicIP = EndpointUtils.GetHost(existingPeerEndpoint);
                bool sameLan = !string.IsNullOrEmpty(msgPublicIP) &&
                               msgPublicIP == exPublicIP &&
                               !string.IsNullOrEmpty(msg.LocalIP) &&
                               !string.IsNullOrEmpty(existingPeerLocalIP);

                if (!bothHaveV6 && !sameLan && msg.NATType == NATType.Symmetric && (NATType)existingPeerNatType == NATType.Symmetric)
                {
                    string chosenRelay = PickRelay(existingPeerMeshIP, msg.PrivateAddressString) ?? (context.Options.AllowRelayThrough ? meshIP : null);
                    if (string.IsNullOrEmpty(chosenRelay))
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] No eligible relay for {existingPeerMeshIP} <-> {msg.PrivateAddressString} and self-relay disabled — skipping pair");
                        continue;
                    }
                    context.Log($"[Mesh] Both {msg.PeerID} and {existingPeerID} are symmetric NAT — relay via {(chosenRelay == meshIP ? "self (introducer)" : chosenRelay)}");

                    string sortA = string.Compare(existingPeerMeshIP, msg.PrivateAddressString, StringComparison.Ordinal) < 0
                        ? existingPeerMeshIP : msg.PrivateAddressString;
                    string sortB = sortA == existingPeerMeshIP ? msg.PrivateAddressString : existingPeerMeshIP;
                    string pairKey = $"{sortA}|{sortB}";

                    // Release the prior relay if the picker chose someone different.
                    if (relayAssignments.TryGetValue(pairKey, out var priorRelay) && priorRelay != chosenRelay)
                    {
                        if (priorRelay == meshIP)
                        {
                            try
                            {
                                host.RemoveRelayRouteForPeer(IPAddress.Parse(existingPeerMeshIP));
                                host.RemoveRelayRouteForPeer(IPAddress.Parse(msg.PrivateAddressString));
                            }
                            catch { }
                            RemoveHostedRelay(pairKey);
                        }
                        else
                        {
                            var release = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                            {
                                PeerA = existingPeerMeshIP,
                                PeerB = msg.PrivateAddressString,
                                RelayMeshIP = priorRelay,
                                Release = true
                            };
                            try { byte[] rb = Encoding.UTF8.GetBytes(release.Serialize()); MeshSend(rb, rb.Length, new IPEndPoint(IPAddress.Parse(priorRelay), MeshControlPort)); } catch { }
                        }
                    }

                    relayAssignments[pairKey] = chosenRelay;

                    if (chosenRelay == meshIP)
                    {
                        host.EnableForwarding();
                        AddHostedRelay(pairKey);
                    }
                    else
                    {
                        var assignment = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                        {
                            PeerA = existingPeerMeshIP,
                            PeerB = msg.PrivateAddressString,
                            RelayMeshIP = chosenRelay
                        };
                        try
                        {
                            byte[] aBytes = Encoding.UTF8.GetBytes(assignment.Serialize());
                            MeshSend(aBytes, aBytes.Length, new IPEndPoint(IPAddress.Parse(chosenRelay), MeshControlPort));
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshRelayAssignment to {chosenRelay}: {ex.Message}");
                        }
                    }

                    var relayToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                    {
                        PeerID = msg.PeerID,
                        EndpointString = msg.EndpointString,
                        NATType = msg.NATType,
                        PrivateAddressString = msg.PrivateAddressString,
                        IsRelay = true,
                        IntroducerMeshIP = meshIP,
                        RelayMeshIP = chosenRelay,
                        PeerMinVersion = msg.PeerMinVersion,
                        PeerMaxVersion = msg.PeerMaxVersion,
                        IdentityPublicKey = msg.IdentityPublicKey
                    };
                    try
                    {
                        byte[] relayExBytes = Encoding.UTF8.GetBytes(relayToExisting.Serialize());
                        MeshSend(relayExBytes, relayExBytes.Length,
                            new IPEndPoint(IPAddress.Parse(existingPeerMeshIP), MeshControlPort));
                    }
                    catch (Exception ex)
                    {
                        context.Log(LogLevel.Error, $"[Mesh] Failed to send relay MeshConnectionBegin to {existingPeerMeshIP}: {ex.Message}");
                    }

                    if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                    {
                        var relayToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                        {
                            PeerID = existingPeerID,
                            EndpointString = existingPeerEndpoint,
                            NATType = (NATType)existingPeerNatType,
                            PrivateAddressString = existingPeerMeshIP,
                            IsRelay = true,
                            IntroducerMeshIP = meshIP,
                            RelayMeshIP = chosenRelay,
                            PeerMinVersion = existingPeerMinVersion,
                            PeerMaxVersion = existingPeerMaxVersion,
                            IdentityPublicKey = existingPeerIdentityPublicKey
                        };

                        if (completedTunnelMeshIPs.Contains(msg.PrivateAddressString))
                        {
                            try
                            {
                                byte[] relayNewBytes = Encoding.UTF8.GetBytes(relayToNew.Serialize());
                                MeshSend(relayNewBytes, relayNewBytes.Length,
                                    new IPEndPoint(IPAddress.Parse(msg.PrivateAddressString), MeshControlPort));
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] Failed to send relay MeshConnectionBegin to {msg.PrivateAddressString}: {ex.Message}");
                            }
                        }
                        else
                        {
                            if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                                deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();
                            deferredIntroductions[msg.PrivateAddressString].Add(relayToNew);
                        }
                    }

                    relayedPairs.Add(pairKey);
                    lastRepairAttempt[pairKey] = DateTime.UtcNow;

                    introduced++;
                    continue;
                }

                // Hole-punch path: prefer v6 when both have it; else if both share a public IP use
                // LAN endpoints; otherwise external.
                string newPeerEndpointForExisting = msg.EndpointString;
                string existingPeerEndpointForNew = existingPeerEndpoint;

                if (bothHaveV6)
                {
                    newPeerEndpointForExisting = msg.EndpointV6String;
                    existingPeerEndpointForNew = existingPeerEndpointV6;
                    context.Log(LogLevel.Debug, $"[Mesh] Both peers have IPv6 — using v6 endpoints: {newPeerEndpointForExisting} <-> {existingPeerEndpointForNew}");
                }
                else
                {
                    string newPeerPublicIP = EndpointUtils.GetHost(msg.EndpointString);
                    string existingPeerPublicIP = EndpointUtils.GetHost(existingPeerEndpoint);

                    if (newPeerPublicIP == existingPeerPublicIP &&
                        !string.IsNullOrEmpty(msg.LocalIP) && !string.IsNullOrEmpty(existingPeerLocalIP))
                    {
                        newPeerEndpointForExisting = EndpointUtils.Format(msg.LocalIP, msg.LocalPort);
                        existingPeerEndpointForNew = EndpointUtils.Format(existingPeerLocalIP, existingPeerLocalPort);
                        context.Log(LogLevel.Debug, $"[Mesh] Same-NAT detected! Using LAN endpoints: {newPeerEndpointForExisting} <-> {existingPeerEndpointForNew}");
                    }
                }

                // Only skip the pair when BOTH endpoints are known AND they're different address
                // families (a genuine v4-only ↔ v6-only mismatch that no relay can bridge). When an
                // endpoint is merely empty/not-yet-known, do NOT skip — an endpoint can propagate
                // moments later (e.g. a symmetric peer whose external port isn't observed yet), and
                // the original behavior was to send to whichever side has an endpoint. Each
                // connBegin below is independently gated on its own endpoint being present.
                if (!string.IsNullOrEmpty(newPeerEndpointForExisting) &&
                    !string.IsNullOrEmpty(existingPeerEndpointForNew) &&
                    !EndpointUtils.SameFamily(newPeerEndpointForExisting, existingPeerEndpointForNew))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Skipping introduction pair {msg.PeerID} <-> {existingPeerID} — no shared reachable address family (v4/v6 mismatch)");
                    continue;
                }

                // ExternalEndpointString always carries the external endpoint so the receiver
                // caches something safe to forward to peers outside this LAN. When we substituted
                // v6, the external is the v6 endpoint (there's no NAT-external distinction on v6).
                string newPeerExternal = bothHaveV6 ? msg.EndpointV6String : msg.EndpointString;
                string existingPeerExternal = bothHaveV6 ? existingPeerEndpointV6 : existingPeerEndpoint;

                // Only introduce the new peer to the existing peer if we have an endpoint for the
                // new peer (restores the original always-when-present behavior).
                MediationMessage connBeginToExisting = null;
                if (!string.IsNullOrEmpty(newPeerEndpointForExisting))
                {
                    connBeginToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                    {
                        PeerID = msg.PeerID,
                        EndpointString = newPeerEndpointForExisting,
                        // Carry the new peer's v6 endpoint too (when it has one and we didn't already
                        // substitute it into EndpointString) so the receiver can pick the family it
                        // can actually reach. Lets a v6-capable existing peer choose v6 while a
                        // v4-only one falls back to EndpointString.
                        EndpointV6String = msg.EndpointV6String,
                        ExternalEndpointString = newPeerExternal,
                        NATType = msg.NATType,
                        NATTypeV6 = msg.NATTypeV6,
                        PrivateAddressString = msg.PrivateAddressString,
                        PeerMinVersion = msg.PeerMinVersion,
                        PeerMaxVersion = msg.PeerMaxVersion,
                        IdentityPublicKey = msg.IdentityPublicKey
                    };
                }

                MediationMessage connBeginToNew = null;
                if (!string.IsNullOrEmpty(msg.PrivateAddressString) &&
                    (!string.IsNullOrEmpty(existingPeerEndpointForNew) || !string.IsNullOrEmpty(existingPeerEndpointV6)))
                {
                    connBeginToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                    {
                        PeerID = existingPeerID,
                        EndpointString = existingPeerEndpointForNew,
                        // Carry the existing peer's v6 endpoint so a v6-capable new peer can pick it.
                        // Critically, this also rescues the case where the existing peer paired over
                        // v6 and has no v4 endpoint: without a v6 field the new peer would get an
                        // empty EndpointString and never learn how to reach it.
                        EndpointV6String = existingPeerEndpointV6,
                        ExternalEndpointString = existingPeerExternal,
                        NATType = (NATType)existingPeerNatType,
                        PrivateAddressString = existingPeerMeshIP,
                        PeerMinVersion = existingPeerMinVersion,
                        PeerMaxVersion = existingPeerMaxVersion,
                        IdentityPublicKey = existingPeerIdentityPublicKey
                    };
                }

                bool tunnelToNewReady = completedTunnelMeshIPs.Contains(msg.PrivateAddressString);

                if (tunnelToNewReady)
                {
                    if (connBeginToExisting != null)
                    {
                        try
                        {
                            byte[] toExistingBytes = Encoding.UTF8.GetBytes(connBeginToExisting.Serialize());
                            MeshSend(toExistingBytes, toExistingBytes.Length,
                                new IPEndPoint(IPAddress.Parse(existingPeerMeshIP), MeshControlPort));
                            context.Log(LogLevel.Debug, $"[Mesh] Sent MeshConnectionBegin to existing peer {existingPeerMeshIP} (about new peer {msg.PeerID})");
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshConnectionBegin to {existingPeerMeshIP}: {ex.Message}");
                        }
                    }

                    if (connBeginToNew != null)
                    {
                        try
                        {
                            byte[] toNewBytes = Encoding.UTF8.GetBytes(connBeginToNew.Serialize());
                            MeshSend(toNewBytes, toNewBytes.Length,
                                new IPEndPoint(IPAddress.Parse(msg.PrivateAddressString), MeshControlPort));
                            context.Log(LogLevel.Debug, $"[Mesh] Sent MeshConnectionBegin to new peer {msg.PrivateAddressString} (about existing peer {existingPeerMeshIP})");
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshConnectionBegin to {msg.PrivateAddressString}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    // Defer BOTH sides until the tunnel to the new peer completes — so hole-punching
                    // starts simultaneously on both ends.
                    if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                        deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();

                    // Reuse IntroducerMeshIP field to tag the routing target for the existing peer.
                    if (connBeginToExisting != null)
                    {
                        connBeginToExisting.IntroducerMeshIP = existingPeerMeshIP;
                        deferredIntroductions[msg.PrivateAddressString].Add(connBeginToExisting);
                    }

                    if (connBeginToNew != null)
                        deferredIntroductions[msg.PrivateAddressString].Add(connBeginToNew);

                    context.Log(LogLevel.Debug, $"[Mesh] Deferred MeshConnectionBegin for both peers (tunnel to {msg.PrivateAddressString} not yet established)");
                }

                introduced++;
            }
        }

        // Acknowledge the mediation server regardless — it cleans up the pending record.
        // If the ack write fails, the connection is dead and caller should break the loop.
        try
        {
            var ack = new MediationMessage(MediationMessageType.MeshIntroduceAck) { PeerID = msg.PeerID };
            byte[] ackBuffer = Encoding.ASCII.GetBytes(ack.Serialize());
            stream.Write(ackBuffer, 0, ackBuffer.Length);
            stream.Flush();
            int deferredCount = deferredIntroductions.TryGetValue(msg.PrivateAddressString ?? "", out var dList) ? dList.Count : 0;
            context.Log(LogLevel.Debug, $"[Mesh] Sent MeshIntroduceAck for {msg.PeerID} ({introduced} introduced, {deferredCount} deferred, completedTunnels={completedTunnelMeshIPs.Count})");
            return true;
        }
        catch (Exception ex)
        {
            context.Log(LogLevel.Error, $"[Mesh] MeshIntroduceAck write failed, connection lost: {ex.Message}");
            tcpClient.Close();
            return false;
        }
    }

    /// <summary>
    /// One iteration's worth of TCP read + JSON dispatch for the primary loop's mediation connection.
    /// Reads from `stream` into `buffer`, accumulates partial messages in tcpBuffer, parses complete
    /// JSON objects, and routes each MediationMessage to its handler. Returns false when the server
    /// closed the connection — caller should break out of the primary loop.
    /// </summary>
    private bool ReadAndDispatchMediationMessages(ref string tcpBuffer, ref bool hasPeers)
    {
        try
        {
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                context.Log(LogLevel.Debug, "[Mesh] Mediation server closed connection");
                return false;
            }
            tcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
        }
        catch (IOException) { } // read timeout — no data available this iteration

        // Process any complete JSON messages in the TCP buffer
        if (tcpBuffer.Length == 0 || !tcpBuffer.Contains('{')) return true;

        int jsonStartIndex = 0;
        while (jsonStartIndex < tcpBuffer.Length)
        {
            int jsonObjStart = tcpBuffer.IndexOf('{', jsonStartIndex);
            if (jsonObjStart == -1) break;

            int braceCount = 0;
            int jsonObjEnd = -1;
            for (int i = jsonObjStart; i < tcpBuffer.Length; i++)
            {
                if (tcpBuffer[i] == '{') braceCount++;
                else if (tcpBuffer[i] == '}')
                {
                    braceCount--;
                    if (braceCount == 0) { jsonObjEnd = i; break; }
                }
            }

            if (jsonObjEnd == -1)
            {
                // Incomplete JSON — keep the remainder in tcpBuffer for next read
                tcpBuffer = tcpBuffer.Substring(jsonObjStart);
                jsonStartIndex = 0; // signal tcpBuffer is already trimmed
                break;
            }

            string jsonObject = tcpBuffer.Substring(jsonObjStart, jsonObjEnd - jsonObjStart + 1);

            MediationMessage msg;
            try
            {
                msg = JsonSerializer.Deserialize<MediationMessage>(jsonObject);
            }
            catch (Exception parseEx)
            {
                context.Log(LogLevel.Error, $"[Mesh] Could not parse JSON object: {parseEx.Message}");
                jsonStartIndex = jsonObjEnd + 1;
                continue;
            }

            if (msg.ID == MediationMessageType.ConnectionRequest)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received connection request! ConnectionID: {msg.ConnectionID}, Endpoint: {msg.EndpointString}");
                context.Log(LogLevel.Debug, $"[Mesh] Waiting for ConnectionBegin to establish tunnel...");
            }
            else if (msg.ID == MediationMessageType.ConnectionBegin)
            {
                HandleConnectionBegin(msg);
            }
            else if (msg.ID == MediationMessageType.NATTypeResponse)
            {
                // A per-family NAT verdict arriving after the handshake — typically the v6 one
                // if it settled slower than v4. Captured for the GUI's per-family display.
                ApplyNatTypeResponse(msg);
            }
            else if (msg.ID == MediationMessageType.MeshJoinResponse)
            {
                HandleMeshJoinResponse(msg, ref hasPeers);
            }
            else if (msg.ID == MediationMessageType.MeshPeerList)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Updated peer list received: {msg.PeerCount} peers");
                if (msg.Peers != null && msg.Peers.Length > 0)
                {
                    hasPeers = true;
                    ProcessDiscoveredPeers(msg.Peers);
                }
            }
            else if (msg.ID == MediationMessageType.ConnectionComplete)
            {
                context.Log(LogLevel.Debug, $"[Mesh] Received ConnectionComplete (routing to tunnel)");
                Tunnel[] tunnelSnapshot;
                lock (meshLock)
                {
                    tunnelSnapshot = new Tunnel[activeConnectionTunnels.Count];
                    activeConnectionTunnels.Values.CopyTo(tunnelSnapshot, 0);
                }
                foreach (var t in tunnelSnapshot)
                    t.NotifyConnectionComplete();
            }
            else if (msg.ID == MediationMessageType.ServerNotAvailable)
            {
                context.Log(LogLevel.Debug, $"[Mesh] ServerNotAvailable — target peer unavailable");
                // Stale-pending cleanup handles the orphan ConnectionRequest after StaleTimeoutSeconds.
            }
            else if (msg.ID == MediationMessageType.MeshIntroduceRequest)
            {
                if (!HandleMeshIntroduceRequest(msg))
                    return false; // ack write failed → connection lost
            }

            jsonStartIndex = jsonObjEnd + 1;
        }

        // Clear consumed data from the buffer.
        if (jsonStartIndex >= tcpBuffer.Length)
            tcpBuffer = "";
        else if (jsonStartIndex > 0)
            tcpBuffer = tcpBuffer.Substring(jsonStartIndex);

        return true;
    }

    /// <summary>
    /// Mesh-control-only loop's introducer-failover probe. Differs from the primary-loop version
    /// in that there's no live mediation TCP, so to claim the introducer role this peer must
    /// reconnect to mediation, redo the NAT-detection handshake, and send a fresh MeshJoinRequest.
    /// The server's response is authoritative — we only set isIntroducer=true if the server
    /// picks us. If the server picks someone else (or "(none)"), we update our cached pointer
    /// (or null it) and retry on the next probe cycle.
    /// </summary>
    private void ProbeIntroducerHealth_MeshControlOnly()
    {
        // Symmetric peers historically didn't probe in daemon mode because mesh-control flowed
        // via WG-routed UDP — a failing tunnel was indistinguishable from a flaky one, and
        // symmetric peers couldn't take over the introducer role without re-running hole-punch
        // through mediation anyway. In embedded mode, mesh-control flows through the Noise
        // tunnel (the same one carrying game data), so a missed probe is reliable evidence the
        // peer is unreachable; and reconnecting to mediation for re-discovery is exactly what
        // we want even if mediation later picks someone else as introducer. So: probe regardless
        // of NAT type when the host isn't a daemon-style WireGuardTunnel.
        bool isEmbedded = !(host is WireGuardTunnel);
        if (isIntroducer || reconnectedTcpClient != null ||
            (!isEmbedded && detectedNatType == NATType.Symmetric) ||
            DateTime.UtcNow - lastIntroducerProbe <= introducerProbeInterval) return;

        if (string.IsNullOrEmpty(introducerMeshIP))
        {
            // No introducer pointer (server returned (none) on last takeover bid, or no
            // heartbeat has arrived yet). Pre-arm missed-probes so the takeover block
            // below fires another bid this iteration.
            introducerMissedProbes = IntroducerMissedProbeThreshold;
            introducerProbeAckReceived = false;
        }
        else if (!introducerProbeAckReceived)
        {
            introducerMissedProbes++;
            context.Log(LogLevel.Warning, $"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
        }
        else
        {
            if (introducerMissedProbes > 0)
                context.Log(LogLevel.Warning, $"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
            introducerMissedProbes = 0;
        }

        if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
        {
            // Same guard as the primary-loop variant: don't claim takeover of an introducer
            // we've blocked — we can't reach them by design, but they're likely fine for others.
            if (!string.IsNullOrEmpty(introducerMeshIP) &&
                peerInfoByMeshIP.TryGetValue(introducerMeshIP, out var introInfoMc) &&
                IsBlocked(introInfoMc.identityPublicKey))
            {
                introducerMissedProbes = 0;
                introducerProbeAckReceived = true;
                lastIntroducerProbe = DateTime.UtcNow;
                return;
            }
            // Random election delay: makes simultaneous takeover races unlikely.
            // During the wait, if a new heartbeat with IsIntroducer=true arrives from
            // a different peer, the listener updates introducerMeshIP and we abort.
            string electionTarget = introducerMeshIP;
            int delayMs = new Random().Next(0, 5000);
            context.Log(LogLevel.Warning, $"[Mesh] Introducer confirmed dead — election delay {delayMs}ms before takeover attempt");
            for (int slept = 0; slept < delayMs; slept += 100)
            {
                System.Threading.Thread.Sleep(100);
                if (context.ShutdownRequested || context.DisconnectRequested) break;
                if (introducerMeshIP != electionTarget)
                {
                    context.Log(LogLevel.Warning, "[Mesh] Election aborted — another peer became introducer during delay");
                    introducerMissedProbes = 0;
                    introducerProbeAckReceived = true;
                    break;
                }
            }
            bool takeoverAborted = introducerMeshIP != electionTarget || context.ShutdownRequested || context.DisconnectRequested;
            if (takeoverAborted)
            {
                lastIntroducerProbe = DateTime.UtcNow;
                return;
            }

            try
            {
                context.Log(LogLevel.Warning, "[Mesh] Election delay elapsed — reconnecting to mediation to claim introducer role");
                var mediationEP = endpoint; // already resolved by the connect loop
                reconnectedTcpClient = new TcpClient(mediationEP.Address.AddressFamily);
                reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                reconnectedTcpClient.Connect(mediationEP);
                if (context.Options.TlsEnabled)
                {
                    var sslStream = new SslStream(reconnectedTcpClient.GetStream(), false,
                        context.Options.TlsAllowSelfSigned
                            ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                            : null);
                    sslStream.AuthenticateAsClient(mediationEP.Address.ToString());
                    reconnectedStream = sslStream;
                    context.Log(LogLevel.Info, $"[Mesh] Takeover TLS handshake complete (protocol: {sslStream.SslProtocol})");
                }
                else
                {
                    reconnectedStream = reconnectedTcpClient.GetStream();
                }

                pendingConnectionRequests.Clear();
                lastStaleWarningAt.Clear();

                reconnectedStream.ReadTimeout = 15000;
                string reconRemainder2 = "";
                byte[] reconBuf2 = new byte[4096];

                MediationMessage ReadReconMessage2()
                {
                    while (true)
                    {
                        var (m, r) = ExtractFirstJson(reconRemainder2);
                        if (m != null) { reconRemainder2 = r; return m; }
                        int n = reconnectedStream.Read(reconBuf2, 0, reconBuf2.Length);
                        if (n == 0) throw new IOException("Reconnected mediation stream closed");
                        reconRemainder2 += Encoding.ASCII.GetString(reconBuf2, 0, n);
                    }
                }

                // 1. Wait for Connected message
                ReadReconMessage2();

                // 2. NAT type detection (full handshake)
                var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                {
                    LocalPort = localUdpPort,
                    LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                    ClientID = peerID
                };
                byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                var natTestBeginR2 = ReadReconMessage2();
                if (natTestBeginR2.ID == MediationMessageType.NATTestBegin)
                {
                    var natTestMsg2 = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                    byte[] natTestBuf2 = Encoding.ASCII.GetBytes(natTestMsg2.Serialize());
                    udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, natTestBeginR2.NATTestPortOne));
                    udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, natTestBeginR2.NATTestPortTwo));
                    SendNatTestV6(natTestBuf2, natTestBeginR2.NATTestPortOne, natTestBeginR2.NATTestPortTwo, natTestBeginR2.ServerPublicIPv6);
                    SendNatTestV4(natTestBuf2, natTestBeginR2.NATTestPortOne, natTestBeginR2.NATTestPortTwo, natTestBeginR2.ServerPublicIPv4);
                }

                var natTypeRespR2 = ReadReconMessage2();
                if (natTypeRespR2.ID == MediationMessageType.NATTypeResponse)
                    ApplyNatTypeResponse(natTypeRespR2);

                // 3. Send MeshJoinRequest. Server decides who's the introducer; we don't claim
                // the role locally until the response confirms.
                var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                {
                    NetworkID = context.Options.NetworkID,
                    PeerID = peerID.ToString(),
                    NATType = detectedNatType,
                    PrivateAddressString = meshIP,
                    AuthToken = authToken,
                    ProtocolVersion = MediationProtocol.ClientVersion,
                    PeerMinVersion = MediationProtocol.PeerMinVersion,
                    PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                    IdentityPublicKey = OwnIdentityPublicKeyB64
                };
                byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                reconnectedStream.Write(joinBytes, 0, joinBytes.Length);
                reconnectedStream.Flush();

                // 4. Wait for MeshJoinResponse and honor server's introducer choice.
                var joinResp = ReadReconMessage2();
                if (joinResp.ID == MediationMessageType.MeshJoinResponse &&
                    joinResp.IntroducerPeerID == peerID.ToString())
                {
                    isIntroducer = true;
                    introducerMeshIP = meshIP;
                    context.Log(LogLevel.Info, "[Mesh] Server confirmed us as new introducer");
                }
                else
                {
                    context.Log($"[Mesh] Server picked different introducer: {joinResp.IntroducerPeerID ?? "(none)"}");
                    string oldIntroducerMeshIP = introducerMeshIP;
                    string newIntroducerMeshIP = null;
                    if (joinResp.Peers != null && !string.IsNullOrEmpty(joinResp.IntroducerPeerID))
                    {
                        foreach (var peerObj in joinResp.Peers)
                        {
                            var pe = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                            string pid = pe.TryGetProperty("peerID", out var pidEl) ? pidEl.GetString() : null;
                            string mip = pe.TryGetProperty("meshIP", out var mipEl) ? mipEl.GetString() : null;
                            if (pid == joinResp.IntroducerPeerID && !string.IsNullOrEmpty(mip))
                            {
                                newIntroducerMeshIP = mip;
                                break;
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(newIntroducerMeshIP))
                    {
                        introducerMeshIP = newIntroducerMeshIP;
                        if (newIntroducerMeshIP != oldIntroducerMeshIP)
                            context.Log($"[Mesh] Introducer mesh IP updated: {oldIntroducerMeshIP ?? "(none)"} → {newIntroducerMeshIP}");
                    }
                    else
                    {
                        // Server chose someone we can't locate (or null). Clear our cached
                        // pointer so we don't keep probing a dead IP. Next heartbeat with
                        // IsIntroducer=true will set it correctly.
                        if (!string.IsNullOrEmpty(oldIntroducerMeshIP))
                            context.Log(LogLevel.Error, $"[Mesh] Could not locate new introducer's mesh IP — clearing cached introducer pointer (was {oldIntroducerMeshIP})");
                        introducerMeshIP = null;
                    }

                    // Drive tunnel establishment to surviving peers (including the new introducer)
                    // over the reconnected mediation stream. Without this, introducerMeshIP is set
                    // but no ConnectionRequest is ever sent, so mesh-control probes drop forever
                    // ("no proxy registered") and the peer can't rejoin the network.
                    if (joinResp.Peers != null && joinResp.Peers.Length > 0)
                        ProcessDiscoveredPeers(joinResp.Peers, reconnectedStream);
                }

                lastReconnectDiscovery = DateTime.UtcNow;
                if (string.IsNullOrEmpty(introducerMeshIP))
                {
                    // Keep missed-probes at threshold so next probe cycle retries. ProbeInterval
                    // acts as natural backoff.
                    introducerMissedProbes = IntroducerMissedProbeThreshold;
                    introducerProbeAckReceived = false;
                    context.Log(LogLevel.Debug, "[Mesh] No introducer resolved — will retry takeover on next probe cycle");
                }
                else
                {
                    introducerMissedProbes = 0;
                    introducerProbeAckReceived = true;
                }
            }
            catch (Exception ex)
            {
                context.Log(LogLevel.Error, $"[Mesh] Failed to reconnect for introducer takeover: {ex.Message}");
                try { reconnectedStream?.Dispose(); } catch { }
                try { reconnectedTcpClient?.Dispose(); } catch { }
                reconnectedTcpClient = null;
                reconnectedStream = null;
                introducerMissedProbes = 0; // Reset to retry later
            }
        }
        else if (!string.IsNullOrEmpty(introducerMeshIP))
        {
            introducerProbeAckReceived = false;
            try
            {
                var probe = new MediationMessage(MediationMessageType.MeshHeartbeat)
                {
                    RelayCapable = context.Options.AllowRelayThrough,
                    RelayCapacity = context.Options.OwnRelayCapacity
                };
                byte[] probeBytes = Encoding.UTF8.GetBytes(probe.Serialize());
                MeshSend(probeBytes, probeBytes.Length,
                    new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
            }
            catch (Exception)
            {
                // Probe send failure typically means the route to the dead introducer has been
                // pulled. The missed-probe counter will reach threshold and trigger takeover.
            }
        }

        lastIntroducerProbe = DateTime.UtcNow;
    }

    /// <summary>
    /// Primary loop's non-introducer probe: ping the introducer over mesh control. If it misses
    /// enough acks, race a random delay then send a MeshJoinRequest over the existing mediation TCP
    /// to bid for the introducer role. The server's choice (in the MeshJoinResponse handler)
    /// settles split-brain.
    /// </summary>
    private void ProbeIntroducerHealth_PrimaryLoop()
    {
        // Deliberately don't gate on completedTunnelMeshIPs — RemoveDeadPeer strips the introducer
        // from that set when MeshPeerLeave arrives, but introducerMeshIP stays set, and gating on
        // the tunnel-completed set would freeze takeover after a graceful introducer disconnect.
        // Symmetric-NAT exclusion is daemon-only (see ProbeIntroducerHealth_MeshControlOnly for why).
        bool isEmbedded = !(host is WireGuardTunnel);
        if (isIntroducer || string.IsNullOrEmpty(introducerMeshIP) ||
            (!isEmbedded && detectedNatType == NATType.Symmetric) ||
            DateTime.UtcNow - lastIntroducerProbe <= introducerProbeInterval) return;

        if (!introducerProbeAckReceived)
        {
            introducerMissedProbes++;
            context.Log(LogLevel.Warning, $"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
        }
        else
        {
            if (introducerMissedProbes > 0)
                context.Log(LogLevel.Warning, $"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
            introducerMissedProbes = 0;
        }

        if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
        {
            // If we've blocked the current introducer, we can't reach them by design — don't
            // try to take over. The introducer is likely fine from other peers' perspective;
            // us claiming would just cause split-brain. Live isolated from the block target.
            if (peerInfoByMeshIP.TryGetValue(introducerMeshIP, out var introInfo) &&
                IsBlocked(introInfo.identityPublicKey))
            {
                introducerMissedProbes = 0;
                introducerProbeAckReceived = true;
                lastIntroducerProbe = DateTime.UtcNow;
                return;
            }
            // Random election delay: with multiple eligible peers, makes simultaneous takeover
            // attempts statistically rare. During the wait, a heartbeat from a new introducer
            // (handled in the listener) updates introducerMeshIP and we abort.
            string electionTarget = introducerMeshIP;
            int delayMs = new Random().Next(0, 5000);
            context.Log(LogLevel.Warning, $"[Mesh] Introducer confirmed dead (primary loop) — election delay {delayMs}ms");
            for (int slept = 0; slept < delayMs; slept += 100)
            {
                System.Threading.Thread.Sleep(100);
                if (context.ShutdownRequested || context.DisconnectRequested) break;
                if (introducerMeshIP != electionTarget)
                {
                    context.Log(LogLevel.Warning, "[Mesh] Primary-loop election aborted — another peer became introducer during delay");
                    introducerMissedProbes = 0;
                    introducerProbeAckReceived = true;
                    break;
                }
            }
            if (introducerMeshIP == electionTarget && !context.ShutdownRequested && !context.DisconnectRequested)
            {
                context.Log(LogLevel.Warning, "[Mesh] Election delay elapsed — sending MeshJoinRequest, awaiting server's choice");
                introducerMissedProbes = 0;

                // Send MeshJoinRequest. We do NOT claim isIntroducer=true here — the MeshJoinResponse
                // handler does that only if the server picks us. Prevents split-brain when multiple
                // eligible peers race.
                try
                {
                    var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                    {
                        NetworkID = context.Options.NetworkID,
                        PeerID = peerID.ToString(),
                        NATType = detectedNatType,
                        PrivateAddressString = meshIP,
                        AuthToken = authToken,
                        ProtocolVersion = MediationProtocol.ClientVersion,
                        PeerMinVersion = MediationProtocol.PeerMinVersion,
                        PeerMaxVersion = MediationProtocol.PeerMaxVersion,
                        IdentityPublicKey = OwnIdentityPublicKeyB64
                    };
                    byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                    stream.Write(joinBytes, 0, joinBytes.Length);
                    stream.Flush();
                }
                catch (Exception ex)
                {
                    context.Log(LogLevel.Error, $"[Mesh] Failed to send takeover MeshJoinRequest: {ex.Message}");
                }
            }
        }
        else
        {
            introducerProbeAckReceived = false;
            try
            {
                var probe = new MediationMessage(MediationMessageType.MeshHeartbeat)
                {
                    RelayCapable = context.Options.AllowRelayThrough,
                    RelayCapacity = context.Options.OwnRelayCapacity
                };
                byte[] probeBytes = Encoding.UTF8.GetBytes(probe.Serialize());
                MeshSend(probeBytes, probeBytes.Length,
                    new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
            }
            catch (Exception)
            {
                // Probe send failure typically means the route to the dead introducer has been
                // pulled. The missed-probe counter will reach threshold and trigger takeover.
            }
        }

        lastIntroducerProbe = DateTime.UtcNow;
    }

    /// <summary>
    /// If a peer hasn't sent any heartbeat/ack in 5 minutes, assume it's dead and remove it locally.
    /// Catches cases where the introducer's MeshPeerRemoved was lost on the UDP path.
    /// No-op when this peer is the introducer (it's the one declaring deaths).
    /// </summary>
    private void RunLocalStalenessFallback()
    {
        if (isIntroducer) return;

        var staleThreshold = TimeSpan.FromMinutes(5);
        var now = DateTime.UtcNow;
        var stalePeers = lastHeartbeatReceivedFrom
            .Where(kvp => kvp.Key != meshIP && (now - kvp.Value) > staleThreshold)
            .Select(kvp => kvp.Key)
            .ToList();
        foreach (var staleIP in stalePeers)
        {
            context.Log(LogLevel.Debug, $"[Mesh] Peer {staleIP} has been silent for >{staleThreshold.TotalMinutes}m — removing locally");
            RemoveDeadPeer(staleIP);
        }
    }

    /// <summary>
    /// Sends one round of latency pings to all reachable mesh IPs, expires stale latency entries,
    /// and (if we have an introducer) probes relay health for any remotes reached via a non-self relay,
    /// emitting MeshRelayHealthReport when a relay's downstream looks broken.
    /// Called from both the primary loop and the mesh-control-only loop.
    /// </summary>
    private void SendLatencyPingsAndHealthProbe()
    {
        if (DateTime.UtcNow - lastPingTime <= pingInterval) return;

        byte[] pingPacket = new byte[] { 0xFF, (byte)'P' };
        var allPeers = host.GetAllPeers();
        var pingedIPs = new HashSet<string>();
        foreach (var peer in allPeers)
        {
            string peerIP = peer.PrivateAddress.ToString();
            if (pingedIPs.Add(peerIP))
            {
                pingSentTicks[peerIP] = System.Diagnostics.Stopwatch.GetTimestamp();
                try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(peer.PrivateAddress, MeshControlPort)); } catch { }
                // Retry MeshVersionHello if we haven't negotiated a version with this peer yet OR
                // if we still don't have their identity pubkey cached. The initial carriers
                // (post-tunnel hello, MeshConnectionBegin) are one-shot UDP and can be lost;
                // without a retry the peer never learns our version and the Firewall pane stays
                // "no fingerprint yet" forever.
                bool needVersion = !peerNegotiatedVersion.ContainsKey(peerIP);
                bool needIdentity = peerInfoByMeshIP.TryGetValue(peerIP, out var pinfo) &&
                                    string.IsNullOrEmpty(pinfo.identityPublicKey);
                if (needVersion || needIdentity)
                    SendMeshVersionHello(peerIP);
            }
            // Also ping any relayed IPs in this peer's AllowedIPs
            if (!string.IsNullOrEmpty(peer.AllowedIPs))
            {
                foreach (var cidr in peer.AllowedIPs.Split(',', StringSplitOptions.TrimEntries))
                {
                    string ip = cidr.Split('/')[0];
                    if (!string.IsNullOrEmpty(ip) && ip != peerIP && pingedIPs.Add(ip))
                    {
                        pingSentTicks[ip] = System.Diagnostics.Stopwatch.GetTimestamp();
                        try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(IPAddress.Parse(ip), MeshControlPort)); } catch { }
                    }
                }
            }
        }
        // Expire stale latency entries (no pong in 30s)
        var staleCutoff = DateTime.UtcNow.AddSeconds(-30);
        foreach (var kvp in peerLastPong)
        {
            if (kvp.Value < staleCutoff)
            {
                peerLatencyMs.TryRemove(kvp.Key, out _);
                peerLastPong.TryRemove(kvp.Key, out _);
            }
        }

        // Silent-tunnel sweep: fills the gap in liveness detection that only exists for
        // non-introducer ↔ non-introducer pairs. The introducer's heartbeat/ack path is the
        // authoritative detector for tunnels *it* participates in — running the sweep on those
        // would pre-empt heartbeat-based removal every time (sweep is 30s, heartbeats need
        // deadThreshold × heartbeatInterval to declare dead), which would blind the introducer's
        // roster/relay-reselection logic. So: only sweep when we're NOT the introducer AND the
        // peer being checked isn't the introducer either — that's the exact non-heartbeat gap.
        if (!isIntroducer)
        {
            var silentTunnelCutoff = TimeSpan.FromSeconds(30);
            var utcNow = DateTime.UtcNow;
            var toRemove = new List<string>();
            foreach (var completedIP in completedTunnelMeshIPs.ToArray())
            {
                if (completedIP == meshIP) continue;
                if (completedIP == introducerMeshIP) continue; // introducer probes its own liveness
                // Grace-period newly-completed tunnels — pings may not have started yet.
                if (tunnelCompletedAt.TryGetValue(completedIP, out var completedAt) &&
                    utcNow - completedAt < silentTunnelCutoff) continue;
                bool hasRecentPong = peerLastPong.TryGetValue(completedIP, out var pongAt) &&
                                     utcNow - pongAt < silentTunnelCutoff;
                if (hasRecentPong) continue;
                DateTime lastWg = DateTime.MinValue;
                try
                {
                    var wgPeer = host?.GetPeer(IPAddress.Parse(completedIP));
                    if (wgPeer != null) lastWg = wgPeer.LastActivity;
                }
                catch { }
                bool hasRecentWg = lastWg != DateTime.MinValue && utcNow - lastWg < silentTunnelCutoff;
                if (hasRecentWg) continue;
                toRemove.Add(completedIP);
            }
            foreach (var deadIP in toRemove)
            {
                context.Log(LogLevel.Warning, $"[Mesh] Tearing down silent tunnel to {deadIP} — no pong or WG activity for {(int)silentTunnelCutoff.TotalSeconds}s");
                RemoveDeadPeer(deadIP);
            }

            // Introducer-specific silent sweep. The general sweep above skips the introducer
            // because the introducer's OWN heartbeat/ack path is authoritative for tunnels it
            // participates in — but that only helps if the introducer is actually running and
            // reachable. If they're not (they blocked us, they crashed, we can't reach them for
            // any reason) our probe path either bails out (symmetric daemon peers) or its
            // takeover election kicks in but is inhibited by our own filters (e.g. we blocked
            // them). Result: the introducer's tunnel silently dies and nothing tears it down,
            // so we never hit `completedTunnelMeshIPs.Count == 0` for the isolation trigger.
            // Use a longer window (2× heartbeat interval + slack) so normal heartbeat cadence
            // doesn't false-fire it.
            if (!string.IsNullOrEmpty(introducerMeshIP) &&
                completedTunnelMeshIPs.Contains(introducerMeshIP))
            {
                var introducerSilenceWindow = TimeSpan.FromSeconds(Math.Max(60, context.Options.HeartbeatIntervalSeconds * 3));
                bool graced = tunnelCompletedAt.TryGetValue(introducerMeshIP, out var introCompletedAt) &&
                              utcNow - introCompletedAt < introducerSilenceWindow;
                bool hasRecentInbound = lastHeartbeatReceivedFrom.TryGetValue(introducerMeshIP, out var lastInbound) &&
                                        utcNow - lastInbound < introducerSilenceWindow;
                bool hasRecentPong = peerLastPong.TryGetValue(introducerMeshIP, out var introPong) &&
                                     utcNow - introPong < introducerSilenceWindow;
                if (!graced && !hasRecentInbound && !hasRecentPong)
                {
                    context.Log(LogLevel.Warning, $"[Mesh] Introducer {introducerMeshIP} silent for >{(int)introducerSilenceWindow.TotalSeconds}s — tearing down so isolation-recovery can re-discover");
                    string deadIntroducerIP = introducerMeshIP;
                    RemoveDeadPeer(deadIntroducerIP);
                    // Clear introducer pointer so isolation-recovery can pick a fresh one on
                    // reconnect. Without this, subsequent join responses may reuse the same
                    // pointer and we'd re-elect an unreachable peer.
                    if (introducerMeshIP == deadIntroducerIP) introducerMeshIP = null;
                }
            }
        }

        lastPingTime = DateTime.UtcNow;

        // Relay health probe: for each remote reached via a non-self relay, check whether
        // WG has heard from the remote recently. If silent past the timeout, look at pongs
        // to distinguish "relay is fine but remote is unreachable" (asymmetric flake →
        // report) from "relay itself is down" (also report, with a different observation).
        if (string.IsNullOrEmpty(introducerMeshIP)) return;

        var silenceCutoff = DateTime.UtcNow.AddSeconds(-context.Options.RelayHealthTimeoutSeconds);
        var pongRecentCutoff = DateTime.UtcNow.AddSeconds(-15);
        var reportCooldown = TimeSpan.FromSeconds(context.Options.RelayReselectCooldownSeconds);
        foreach (var kv in relayedRemotes)
        {
            string remote = kv.Key;
            string relay = kv.Value;
            if (relay == meshIP) continue;
            if (lastRelayHealthReport.TryGetValue(remote, out var last) && DateTime.UtcNow - last < reportCooldown)
                continue;

            DateTime wgLast = DateTime.MinValue;
            try { wgLast = host?.GetPeer(IPAddress.Parse(relay))?.LastActivity ?? DateTime.MinValue; } catch { }
            if (wgLast > silenceCutoff) continue;

            bool relayReachable = peerLastPong.TryGetValue(relay, out var relayPong) && relayPong > pongRecentCutoff;
            bool remoteReachable = peerLastPong.TryGetValue(remote, out var remotePong) && remotePong > pongRecentCutoff;
            if (remoteReachable) continue;

            RelayHealthObservation obs = relayReachable
                ? RelayHealthObservation.DownstreamFailed
                : RelayHealthObservation.RelayUnreachable;
            var report = new MediationMessage(MediationMessageType.MeshRelayHealthReport)
            {
                Self = meshIP,
                Remote = remote,
                CurrentRelay = relay,
                PeerA = meshIP,
                PeerB = remote,
                Observation = obs
            };
            try
            {
                byte[] rBytes = Encoding.UTF8.GetBytes(report.Serialize());
                MeshSend(rBytes, rBytes.Length, new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
                lastRelayHealthReport[remote] = DateTime.UtcNow;
                context.Log(LogLevel.Debug, $"[Mesh] Sent MeshRelayHealthReport: remote={remote} relay={relay} obs={obs}");
            }
            catch (Exception ex)
            {
                context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshRelayHealthReport: {ex.Message}");
            }
        }
    }

    private void MeshSend(byte[] data, int length, IPEndPoint ep)
    {
        // Let the host intercept (embedded mode tunnels mesh-control through MeshPeerProxy
        // because mesh-IPs aren't OS-routable without a WireGuard interface). If the host
        // returns true, it took responsibility for delivery. Otherwise fall back to the
        // daemon's WG-routed UDP send.
        if (host != null && host.SendMeshControl(ep.Address, data, length)) return;

        lock (meshControlSendLock)
        {
            meshControlClient.Send(data, length, ep);
        }
    }

    private int HostedRelayCount() { lock (hostedRelayLock) return hostedRelays.Count; }

    private bool AddHostedRelay(string pairKey) { lock (hostedRelayLock) return hostedRelays.Add(pairKey); }

    private bool RemoveHostedRelay(string pairKey) { lock (hostedRelayLock) return hostedRelays.Remove(pairKey); }

    private void RemoveDeadPeer(string deadMeshIP)
    {
        string deadPeerID = null;
        if (peerInfoByMeshIP.TryGetValue(deadMeshIP, out var deadInfo))
            deadPeerID = deadInfo.peerID;

        context.Log($"[Mesh] Removing dead peer {deadMeshIP} (peerID: {deadPeerID ?? "unknown"})");

        // Remove from WireGuard
        var deadIPAddr = IPAddress.Parse(deadMeshIP);
        var wgPeer = host.GetPeer(deadIPAddr);
        if (wgPeer != null)
        {
            host.RemovePeer(wgPeer.ConnectionId);
            context.Log(LogLevel.Debug, $"[Mesh] Removed WireGuard peer {deadMeshIP}");
        }

        // Remove relay routes through this peer (as gateway)
        var removedRelays = host.RemoveRelayRoutesViaGateway(deadIPAddr);
        if (removedRelays.Count > 0)
        {
            metricRelayRoutesRemoved += removedRelays.Count;
            context.Log(LogLevel.Debug, $"[Mesh] Removed {removedRelays.Count} relay route(s) via {deadMeshIP}");
        }

        // Remove relay route targeting this peer (was relayed through a gateway)
        if (host.RemoveRelayRouteForPeer(deadIPAddr))
        {
            metricRelayRoutesRemoved++;
        }

        // Clean up tracking dictionaries
        peerInfoByMeshIP.TryRemove(deadMeshIP, out _);
        peerLanByMeshIP.TryRemove(deadMeshIP, out _);
        relayCandidates.TryRemove(deadMeshIP, out _);
        completedTunnelMeshIPs.Remove(deadMeshIP);
        tunnelCompletedAt.TryRemove(deadMeshIP, out _);
        heartbeatMissCount.Remove(deadMeshIP);
        lastHeartbeatReceivedFrom.TryRemove(deadMeshIP, out _);

        if (!string.IsNullOrEmpty(deadPeerID))
        {
            activePeerTunnels.Remove(deadPeerID);
            pendingConnectionRequests.Remove(deadPeerID);
        }
        activePeerTunnels.Remove(deadMeshIP);

        // Clean up peerMeshIPs entries pointing to this mesh IP. Dispose the Tunnel before
        // forgetting it — otherwise its connectionAttempt timer and (for symmetric peers) 256
        // probe sockets keep firing forever, and each re-introduce stacks another orphan onto
        // the same target endpoint until the receiver drowns in stale hole-punch traffic.
        var meshIPKeys = peerMeshIPs.Where(kvp => kvp.Value == deadMeshIP).Select(kvp => kvp.Key).ToList();
        foreach (var key in meshIPKeys)
        {
            peerMeshIPs.Remove(key);
            Tunnel orphan = null;
            lock (meshLock)
            {
                if (activeConnectionTunnels.TryGetValue(key, out orphan))
                    activeConnectionTunnels.Remove(key);
            }
            if (orphan != null)
            {
                try { orphan.Dispose(); } catch { }
            }
        }

        // Clean up relayedPairs containing this mesh IP
        relayedPairs.RemoveWhere(pair => pair.Contains(deadMeshIP));
        lock (hostedRelayLock) hostedRelays.RemoveWhere(pair => pair.Contains(deadMeshIP));
        foreach (var k in relayAssignments.Keys.Where(k => k.Contains(deadMeshIP)).ToList())
        {
            relayAssignments.TryRemove(k, out _);
            lastRelayReselect.TryRemove(k, out _);
        }

        // Clean up latency tracking
        peerLatencyMs.TryRemove(deadMeshIP, out _);
        peerLastPong.TryRemove(deadMeshIP, out _);
        relayedRemotes.TryRemove(deadMeshIP, out _);
        lastRelayHealthReport.TryRemove(deadMeshIP, out _);
        peerNegotiatedVersion.TryRemove(deadMeshIP, out _);
    }

    // Pick the best relay for pair (a, b) from the candidate roster.
    // Returns the relay's mesh IP, or null if no eligible candidate exists.
    private string PickRelay(string a, string b)
    {
        long LoadFactorMs = context.Options.RelayLoadFactorMs;
        var staleCutoff = DateTime.UtcNow - TimeSpan.FromSeconds(30);

        // Score = sum of latencies from the relay to each endpoint + load penalty.
        // We can only directly measure latency from the introducer; that's a proxy for
        // candidate→endpoint latency (good enough since the introducer's roster is the
        // ground truth and all peers are roughly equidistant in the mesh control plane).
        // Missing latency → high default (so unmeasured candidates aren't auto-filtered).
        const long UnknownLatencyPenalty = 500;
        long? Score(string candidate, bool isSelf, int activeRoutes)
        {
            if (candidate == a || candidate == b) return null;
            long latToCandidate = isSelf ? 0
                : (peerLatencyMs.TryGetValue(candidate, out var lc) ? lc : UnknownLatencyPenalty);
            long latA = peerLatencyMs.TryGetValue(a, out var la) ? la : UnknownLatencyPenalty;
            long latB = peerLatencyMs.TryGetValue(b, out var lb) ? lb : UnknownLatencyPenalty;
            // Approximate candidate→A and candidate→B by combining introducer-to-each leg.
            return (latToCandidate + latA) + (latToCandidate + latB) + LoadFactorMs * activeRoutes;
        }

        var ranked = new List<(string ip, RelayCapacity cap, long score)>();
        foreach (var kv in relayCandidates)
        {
            string ip = kv.Key;
            var (capable, activeRoutes, capacity, lastSeen) = kv.Value;
            if (!capable) continue;
            if (lastSeen < staleCutoff) continue;
            if (!peerInfoByMeshIP.TryGetValue(ip, out var info)) continue;
            if (info.natType == NATType.Symmetric) continue;
            long? s = Score(ip, false, activeRoutes);
            if (s.HasValue) ranked.Add((ip, capacity, s.Value));
        }

        if (context.Options.AllowRelayThrough && !string.IsNullOrEmpty(meshIP) && meshIP != a && meshIP != b)
        {
            int selfActive = HostedRelayCount();
            long? s = Score(meshIP, true, selfActive);
            if (s.HasValue) ranked.Add((meshIP, context.Options.OwnRelayCapacity, s.Value));
        }

        if (ranked.Count == 0) return null;

        bool hasHighOrNormal = ranked.Any(r => r.cap != RelayCapacity.Low);
        IEnumerable<(string ip, RelayCapacity cap, long score)> pool = hasHighOrNormal
            ? ranked.Where(r => r.cap != RelayCapacity.Low)
            : ranked;

        return pool
            .OrderBy(r => r.score)
            .ThenBy(r => r.ip, StringComparer.Ordinal)
            .First().ip;
    }

    // Helper method to capture current mesh state for HTTP status endpoint
    private MeshState GetMeshState()
    {
        try
        {
            var state = new MeshState
            {
                NetworkID = context.Options.NetworkID,
                OwnMeshIP = meshIP,
                OwnPeerID = peerID.ToString(),
                IsIntroducer = isIntroducer,
                NATType = detectedNatType.ToString(),
                NATTypeV6 = detectedNatTypeV6?.ToString(),
                IntroducerMeshIP = introducerMeshIP,
                UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds,
                ConnectionState = context.ConnectionState.ToString(),
                HostedRelayPairs = HostedRelayCount(),
                LastError = lastError,
                LastErrorKind = lastErrorKind,
                MediationProtocolVersion = MediationProtocol.ClientVersion,
                PeerProtocolMinVersion = MediationProtocol.PeerMinVersion,
                PeerProtocolMaxVersion = MediationProtocol.PeerMaxVersion,
                OwnFingerprint = OwnFingerprint,
                BlockedFingerprints = BlockedFingerprints.ToList(),
                KnownPeers = BuildKnownPeers()
            };

            // Snapshot shared collections to avoid cross-thread enumeration issues
            var completedSnapshot = completedTunnelMeshIPs.ToArray();
            var relayedPairsSnapshot = relayedPairs.ToArray();
            var peerInfoSnapshot = peerInfoByMeshIP.ToArray();
            var peerInfoDict = new Dictionary<string, (string peerID, string endpoint, NATType natType, int peerMinVersion, int peerMaxVersion, string identityPublicKey, string endpointV6)>();
            foreach (var kv in peerInfoSnapshot)
                peerInfoDict[kv.Key] = kv.Value;

            // Build set of all reachable mesh IPs and track which are relay-routed.
            // A peer is "relayed" if it's only reachable via another peer's AllowedIPs.
            // A peer is a "relay gateway" if its AllowedIPs contain other peers' mesh IPs.
            var reachableMeshIPs = new HashSet<string>(completedSnapshot);
            var relayedVia = new Dictionary<string, string>(); // meshIP -> gateway meshIP
            var gatewayIPs = new HashSet<string>(); // peers that serve as relay gateways
            try
            {
                var allWgPeers = host?.GetAllPeers();
                if (allWgPeers != null)
                {
                    foreach (var wgPeer in allWgPeers)
                    {
                        string peerPrimary = wgPeer.PrivateAddress.ToString();
                        reachableMeshIPs.Add(peerPrimary);
                        // AllowedIPs is a comma-separated string like "10.5.5.152/32, 10.5.198.26/32"
                        if (!string.IsNullOrEmpty(wgPeer.AllowedIPs))
                        {
                            foreach (var cidr in wgPeer.AllowedIPs.Split(',', StringSplitOptions.TrimEntries))
                            {
                                var ip = cidr.Split('/')[0];
                                if (!string.IsNullOrEmpty(ip) && ip != peerPrimary)
                                {
                                    reachableMeshIPs.Add(ip);
                                    relayedVia[ip] = peerPrimary;
                                    gatewayIPs.Add(peerPrimary);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // Snapshot pending/active state for thread-safe status determination
            var pendingPeerIDs = new HashSet<string>(pendingConnectionRequests.Keys);
            var activePeerIDs = new HashSet<string>(activePeerTunnels.Keys);
            var completedSet = new HashSet<string>(completedSnapshot);

            // Merge all known peers: reachable (WireGuard) + known (peerInfo roster)
            var allKnownMeshIPs = new HashSet<string>(reachableMeshIPs);
            foreach (var kv in peerInfoDict)
                allKnownMeshIPs.Add(kv.Key);

            foreach (var peerMeshIP in allKnownMeshIPs)
            {
                if (peerMeshIP == meshIP) continue;

                string peerId = null;
                string endpoint = null;
                NATType natType = NATType.Unknown;
                string peerFingerprint = null;
                if (peerInfoDict.TryGetValue(peerMeshIP, out var info))
                {
                    peerId = info.peerID;
                    endpoint = info.endpoint;
                    natType = info.natType;
                    if (!string.IsNullOrEmpty(info.identityPublicKey))
                    {
                        try { peerFingerprint = ComputeFingerprint(Convert.FromBase64String(info.identityPublicKey)); }
                        catch { peerFingerprint = null; }
                    }
                }

                DateTime lastActivity = DateTime.MinValue;
                try
                {
                    var wgPeer = host?.GetPeer(IPAddress.Parse(peerMeshIP));
                    if (wgPeer != null)
                        lastActivity = wgPeer.LastActivity;
                }
                catch { }

                // Relay detection: authoritative signal is local WireGuard routing.
                // The introducer's relayedPairs is internal bookkeeping and can go stale
                // across role transitions, so don't use it for GUI status.
                bool isRelayed = relayedVia.ContainsKey(peerMeshIP);
                bool isRelayGateway = gatewayIPs.Contains(peerMeshIP);

                long latency = peerLatencyMs.TryGetValue(peerMeshIP, out var lat) ? lat : -1;

                // Determine connection status.
                // A peer is "completed" if our callback recorded it, OR if WireGuard
                // already has it as a reachable peer (callback may have been lost).
                // BUT completedTunnelMeshIPs is only cleared on RemoveDeadPeer, which fires from
                // introducer heartbeat failure or graceful leave — a silently-dead tunnel between
                // two non-introducer peers keeps the flag set forever, showing "Connected" with
                // no latency. Require some form of *recent* liveness so the UI reflects reality.
                var livenessWindow = TimeSpan.FromSeconds(20);
                var utcNow = DateTime.UtcNow;
                bool hasRecentPong = peerLastPong.TryGetValue(peerMeshIP, out var pongAt) &&
                                     utcNow - pongAt < livenessWindow;
                bool hasRecentWgActivity = lastActivity != DateTime.MinValue &&
                                           utcNow - lastActivity < livenessWindow;
                bool isLive = hasRecentPong || hasRecentWgActivity;

                string status;
                bool trackedAsCompleted = completedSet.Contains(peerMeshIP)
                    || (reachableMeshIPs.Contains(peerMeshIP) && activePeerIDs.Contains(peerMeshIP));
                bool isCompleted = trackedAsCompleted && isLive;
                bool isPending = !isCompleted && (
                    trackedAsCompleted  // marked completed but silent — treat as reconnecting
                    || (!string.IsNullOrEmpty(peerId) && pendingPeerIDs.Contains(peerId))
                    || activePeerIDs.Contains(peerMeshIP)
                    || (!string.IsNullOrEmpty(peerId) && activePeerIDs.Contains(peerId)));

                if (isCompleted)
                    status = isRelayed ? "Relayed" : "Connected";
                else if (isPending || reachableMeshIPs.Contains(peerMeshIP))
                    status = "Connecting";
                else
                    status = "Not Connected";

                var peerInfo = new MeshState.ConnectedPeer
                {
                    MeshIP = peerMeshIP,
                    PeerID = peerId ?? "Unknown",
                    NATType = natType.ToString(),
                    Endpoint = endpoint ?? "Unknown",
                    LastActivity = lastActivity,
                    IsRelayed = isRelayed,
                    IsRelayGateway = isRelayGateway,
                    LatencyMs = latency,
                    RelayedVia = relayedVia.TryGetValue(peerMeshIP, out var gw) ? gw : null,
                    Status = status,
                    PeerProtocolVersion = peerNegotiatedVersion.TryGetValue(peerMeshIP, out var pver) ? pver : -1,
                    Fingerprint = peerFingerprint
                };

                state.ConnectedPeers.Add(peerInfo);
            }

            // Populate relay routes from snapshot
            foreach (var relayPair in relayedPairsSnapshot)
            {
                var parts = relayPair.Split('|');
                if (parts.Length == 2)
                {
                    state.RelayRoutes.Add(new MeshState.RelayRoute
                    {
                        SourceMeshIP = parts[0],
                        DestinationMeshIP = parts[1]
                    });
                }
            }

            state.Metrics = new MeshState.MeshMetrics
            {
                TunnelsEstablished = metricTunnelsEstablished,
                TunnelsFailed = metricTunnelsFailed,
                Reconnects = metricReconnects,
                PeersLost = metricPeersLost,
                HeartbeatsSent = metricHeartbeatsSent,
                HeartbeatAcksReceived = metricHeartbeatAcksReceived,
                HeartbeatsMissed = metricHeartbeatsMissed,
                LastHeartbeatResponseMs = metricLastHeartbeatResponseMs,
                RelayRoutesEstablished = metricRelayRoutesEstablished,
                RelayRoutesRemoved = metricRelayRoutesRemoved,
                ActiveRelayRouteCount = relayedPairsSnapshot.Length
            };

            return state;
        }
        catch (Exception ex)
        {
            // Full ToString() so the stack trace goes to the log — the truncated .Message alone
            // was making it impossible to figure out why the state build kept throwing after some
            // uptime, and the fallback below was silently dropping KnownPeers/BlockedFingerprints
            // so the Firewall pane went blank forever.
            context.Log(LogLevel.Error, $"[Mesh] Error building mesh state: {ex}");
            // Populate the Firewall-relevant fields in the fallback too. Even when the main
            // state build fails, these are cheap to compute and safe (no cross-thread reads of
            // volatile collections beyond what's already protected). Without them the GUI's
            // Firewall pane clears entirely on the first fallback and never recovers.
            var fallback = new MeshState
            {
                NetworkID = context.Options.NetworkID,
                OwnMeshIP = meshIP,
                OwnPeerID = peerID.ToString(),
                IsIntroducer = isIntroducer,
                NATType = detectedNatType.ToString(),
                NATTypeV6 = detectedNatTypeV6?.ToString(),
                UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds,
                ConnectionState = context.ConnectionState.ToString(),
                MediationProtocolVersion = MediationProtocol.ClientVersion,
                PeerProtocolMinVersion = MediationProtocol.PeerMinVersion,
                PeerProtocolMaxVersion = MediationProtocol.PeerMaxVersion,
                OwnFingerprint = OwnFingerprint,
            };
            try { fallback.BlockedFingerprints = BlockedFingerprints.ToList(); } catch { }
            try { fallback.KnownPeers = BuildKnownPeers(); } catch { }
            return fallback;
        }
    }

    private void NotifyEndpoint(string toIP, string remoteIP, string newRelay)
    {
        if (!peerInfoByMeshIP.TryGetValue(remoteIP, out var info)) return;
        // Don't send a relay-reselect notification if either end of the pair is blocked.
        if (IsBlocked(info.identityPublicKey)) return;
        if (peerInfoByMeshIP.TryGetValue(toIP, out var toInfo) && IsBlocked(toInfo.identityPublicKey)) return;
        var cb = new MediationMessage(MediationMessageType.MeshConnectionBegin)
        {
            PeerID = info.peerID,
            EndpointString = info.endpoint,
            NATType = info.natType,
            PrivateAddressString = remoteIP,
            IsRelay = true,
            IntroducerMeshIP = meshIP,
            RelayMeshIP = newRelay,
            PeerMinVersion = info.peerMinVersion,
            PeerMaxVersion = info.peerMaxVersion,
            IdentityPublicKey = info.identityPublicKey
        };
        try { byte[] cbBytes = Encoding.UTF8.GetBytes(cb.Serialize()); MeshSend(cbBytes, cbBytes.Length, new IPEndPoint(IPAddress.Parse(toIP), MeshControlPort)); }
        catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to notify {toIP} of reselect: {ex.Message}"); }
    }

    private int RepairBrokenLinks(
                    List<string> targetList,
                    Dictionary<string, HashSet<string>> currentHeartbeatAcks,
                    System.Net.Sockets.TcpClient mediationClient,
                    Stream mediationStream)
    {
        int repairCount = 0;
        for (int i = 0; i < targetList.Count; i++)
        {
            for (int j = i + 1; j < targetList.Count; j++)
            {
                string ipA = targetList[i];
                string ipB = targetList[j];

                bool aReportsB = currentHeartbeatAcks.ContainsKey(ipA) && currentHeartbeatAcks[ipA].Contains(ipB);
                bool bReportsA = currentHeartbeatAcks.ContainsKey(ipB) && currentHeartbeatAcks[ipB].Contains(ipA);

                string sortedA = string.Compare(ipA, ipB, StringComparison.Ordinal) < 0 ? ipA : ipB;
                string sortedB = sortedA == ipA ? ipB : ipA;
                string pairKey = $"{sortedA}|{sortedB}";

                // Clear tracking for healthy pairs
                if (aReportsB && bReportsA)
                {
                    if (repairAttemptCount.Remove(pairKey))
                        lastRepairAttempt.Remove(pairKey);
                    continue;
                }
                context.Log(LogLevel.Debug, $"[Mesh] Repair check: {ipA} <-> {ipB} aReportsB={aReportsB} bReportsA={bReportsA}");

                // Skip repair if either peer is known incompatible on peer-protocol range
                // or on the local block list.
                if (peerInfoByMeshIP.TryGetValue(ipA, out var repairInfoA) &&
                    (IsIncompatible(repairInfoA.peerID, repairInfoA.peerMinVersion, repairInfoA.peerMaxVersion) ||
                     IsBlocked(repairInfoA.identityPublicKey)))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Repair skip: {ipA} is incompatible/blocked by us");
                    continue;
                }
                if (peerInfoByMeshIP.TryGetValue(ipB, out var repairInfoB) &&
                    (IsIncompatible(repairInfoB.peerID, repairInfoB.peerMinVersion, repairInfoB.peerMaxVersion) ||
                     IsBlocked(repairInfoB.identityPublicKey)))
                {
                    context.Log(LogLevel.Debug, $"[Mesh] Repair skip: {ipB} is incompatible/blocked by us");
                    continue;
                }

                if (!aReportsB || !bReportsA)
                {
                    // Grace period after tunnel establishment: latency pings travel on a 5s
                    // timer, so two peers who just connected legitimately won't yet appear in
                    // each other's MeshHeartbeatAck.ConnectedMeshIPs. Firing repair here would
                    // tear down a working tunnel via the re-introduce path.
                    var newPeerGrace = TimeSpan.FromSeconds(15);
                    bool aTooNew = tunnelCompletedAt.TryGetValue(ipA, out var aAt) &&
                                   DateTime.UtcNow - aAt < newPeerGrace;
                    bool bTooNew = tunnelCompletedAt.TryGetValue(ipB, out var bAt) &&
                                   DateTime.UtcNow - bAt < newPeerGrace;
                    if (aTooNew || bTooNew)
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] Repair skip: {ipA} <-> {ipB} within {newPeerGrace.TotalSeconds}s grace (aTooNew={aTooNew} bTooNew={bTooNew})");
                        continue;
                    }

                    // Cooldown check
                    if (lastRepairAttempt.TryGetValue(pairKey, out var lastAttempt) &&
                        DateTime.UtcNow - lastAttempt < repairCooldown)
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] Repair skip: {ipA} <-> {ipB} in cooldown ({(int)(DateTime.UtcNow - lastAttempt).TotalSeconds}s / {(int)repairCooldown.TotalSeconds}s)");
                        continue;
                    }

                    // For relayed pairs, re-assert the existing relay assignment.
                    if (relayedPairs.Contains(pairKey))
                    {
                        if (!completedTunnelMeshIPs.Contains(ipA) || !completedTunnelMeshIPs.Contains(ipB))
                            continue;

                        bool hasInfoA = peerInfoByMeshIP.TryGetValue(ipA, out var relayInfoA);
                        bool hasInfoB = peerInfoByMeshIP.TryGetValue(ipB, out var relayInfoB);
                        if (!hasInfoA || !hasInfoB) continue;

                        string assignedRelay = relayAssignments.TryGetValue(pairKey, out var ar) ? ar : null;
                        string priorRelayForRepair = assignedRelay;
                        if (string.IsNullOrEmpty(assignedRelay) ||
                            (assignedRelay != meshIP && !(relayCandidates.TryGetValue(assignedRelay, out var rc2) && rc2.capable)))
                        {
                            assignedRelay = PickRelay(ipA, ipB) ?? (context.Options.AllowRelayThrough ? meshIP : null);
                            if (string.IsNullOrEmpty(assignedRelay))
                            {
                                context.Log(LogLevel.Debug, $"[Mesh] Heartbeat: relayed pair {ipA} <-> {ipB} broken but no eligible relay — skipping");
                                continue;
                            }
                            // If we'd previously self-hosted this pair and we're switching away, release.
                            if (priorRelayForRepair == meshIP && assignedRelay != meshIP)
                            {
                                try
                                {
                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(ipA));
                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(ipB));
                                }
                                catch { }
                                RemoveHostedRelay(pairKey);
                            }
                            relayAssignments[pairKey] = assignedRelay;
                        }

                        context.Log($"[Mesh] Heartbeat: relayed pair {ipA} <-> {ipB} broken — re-asserting via {(assignedRelay == meshIP ? "self" : assignedRelay)}");

                        if (assignedRelay == meshIP)
                        {
                            host.EnableForwarding();
                            AddHostedRelay(pairKey);
                        }
                        else
                        {
                            var assign = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                            {
                                PeerA = ipA,
                                PeerB = ipB,
                                RelayMeshIP = assignedRelay
                            };
                            try
                            {
                                byte[] ab = Encoding.UTF8.GetBytes(assign.Serialize());
                                MeshSend(ab, ab.Length, new IPEndPoint(IPAddress.Parse(assignedRelay), MeshControlPort));
                            }
                            catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshRelayAssignment to {assignedRelay}: {ex.Message}"); }
                        }

                        if (!aReportsB)
                        {
                            var relayToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                            {
                                PeerID = relayInfoB.peerID ?? "",
                                EndpointString = relayInfoB.endpoint,
                                NATType = relayInfoB.natType,
                                PrivateAddressString = ipB,
                                IsRelay = true,
                                IntroducerMeshIP = meshIP,
                                RelayMeshIP = assignedRelay,
                                PeerMinVersion = relayInfoB.peerMinVersion,
                                PeerMaxVersion = relayInfoB.peerMaxVersion,
                                IdentityPublicKey = relayInfoB.identityPublicKey
                            };
                            try
                            {
                                byte[] rBytes = Encoding.UTF8.GetBytes(relayToA.Serialize());
                                MeshSend(rBytes, rBytes.Length, new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                repairCount++;
                            }
                            catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}"); }
                        }
                        if (!bReportsA)
                        {
                            var relayToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                            {
                                PeerID = relayInfoA.peerID ?? "",
                                EndpointString = relayInfoA.endpoint,
                                NATType = relayInfoA.natType,
                                PrivateAddressString = ipA,
                                IsRelay = true,
                                IntroducerMeshIP = meshIP,
                                RelayMeshIP = assignedRelay,
                                PeerMinVersion = relayInfoA.peerMinVersion,
                                PeerMaxVersion = relayInfoA.peerMaxVersion,
                                IdentityPublicKey = relayInfoA.identityPublicKey
                            };
                            try
                            {
                                byte[] rBytes = Encoding.UTF8.GetBytes(relayToB.Serialize());
                                MeshSend(rBytes, rBytes.Length, new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                repairCount++;
                            }
                            catch (Exception ex) { context.Log(LogLevel.Error, $"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}"); }
                        }

                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                        continue;
                    }

                    // Only repair if we have completed tunnels to BOTH peers.
                    // If a peer is reconnecting (e.g. NAT type changed), its completedTunnelMeshIPs
                    // entry is cleared and we should wait for the new tunnel to complete before
                    // attempting repair — otherwise we'd send stale endpoint/NAT info.
                    if (!completedTunnelMeshIPs.Contains(ipA) || !completedTunnelMeshIPs.Contains(ipB))
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] Repair skip: {ipA} <-> {ipB} — missing completed tunnel (A={completedTunnelMeshIPs.Contains(ipA)}, B={completedTunnelMeshIPs.Contains(ipB)})");
                        continue;
                    }

                    bool hasA = peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                    bool hasB = peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

                    if (!hasA || !hasB)
                    {
                        context.Log(LogLevel.Debug, $"[Mesh] Heartbeat: missing peer info for pair {ipA}(known={hasA}) <-> {ipB}(known={hasB}) — peerInfoByMeshIP has {peerInfoByMeshIP.Count} entries");
                        continue;
                    }

                    // Track attempt count for escalation
                    repairAttemptCount.TryGetValue(pairKey, out int attempts);
                    attempts++;
                    repairAttemptCount[pairKey] = attempts;

                    // If both peers have a usable v6 endpoint, they can connect DIRECTLY over v6
                    // regardless of their (v4) NAT type — v6 has no NAT to traverse, so the
                    // symmetric-relay dance is unnecessary and, in steady state, broken (both peers
                    // are off mediation, so the relay path can't be set up). Force the direct path.
                    bool repairBothHaveV6 = !string.IsNullOrEmpty(infoA.endpointV6) &&
                                            !string.IsNullOrEmpty(infoB.endpointV6);

                    bool bothSymmetric = !repairBothHaveV6 &&
                        infoA.natType == NATType.Symmetric && infoB.natType == NATType.Symmetric;
                    // Same-LAN exception: skip relay if both endpoints share a public IP and
                    // we have LAN info for both. Direct LAN connection should work even when
                    // both are symmetric.
                    string aPublicIP = EndpointUtils.GetHost(infoA.endpoint);
                    string bPublicIP = EndpointUtils.GetHost(infoB.endpoint);
                    bool sameLanPair = bothSymmetric &&
                        !string.IsNullOrEmpty(aPublicIP) && aPublicIP == bPublicIP &&
                        peerLanByMeshIP.ContainsKey(ipA) && peerLanByMeshIP.ContainsKey(ipB);
                    if (sameLanPair) bothSymmetric = false;

                    // No mediation-escalation branch. In steady state the target peers are
                    // disconnected from mediation, so the ConnectionRequest just bounces
                    // "ServerNotAvailable" — burning repair attempts without accomplishing
                    // anything. Direct MeshConnectionBegin over our WG tunnels to each peer is
                    // the actual working path and re-fires on every subsequent repair cycle.
                    if (bothSymmetric)
                    {
                        string chosenRelay = relayAssignments.TryGetValue(pairKey, out var existing) ? existing : null;
                        string priorBothSym = chosenRelay;
                        if (chosenRelay == null || !(chosenRelay == meshIP ||
                            (relayCandidates.TryGetValue(chosenRelay, out var rc) && rc.capable)))
                        {
                            chosenRelay = PickRelay(ipA, ipB) ?? (context.Options.AllowRelayThrough ? meshIP : null);
                            if (string.IsNullOrEmpty(chosenRelay))
                            {
                                context.Log(LogLevel.Debug, $"[Mesh] No eligible relay for {ipA} <-> {ipB} and self-relay disabled — skipping");
                                continue;
                            }
                            if (priorBothSym == meshIP && chosenRelay != meshIP)
                            {
                                try
                                {
                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(ipA));
                                    host.RemoveRelayRouteForPeer(IPAddress.Parse(ipB));
                                }
                                catch { }
                                RemoveHostedRelay(pairKey);
                            }
                            relayAssignments[pairKey] = chosenRelay;
                        }
                        context.Log($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected (both symmetric) — re-establishing relay via {(chosenRelay == meshIP ? "self" : chosenRelay)} (attempt {attempts})");

                        if (chosenRelay == meshIP)
                        {
                            host.EnableForwarding();
                            AddHostedRelay(pairKey);
                        }
                        else
                        {
                            var assignment = new MediationMessage(MediationMessageType.MeshRelayAssignment)
                            {
                                PeerA = ipA,
                                PeerB = ipB,
                                RelayMeshIP = chosenRelay
                            };
                            try
                            {
                                byte[] aBytes = Encoding.UTF8.GetBytes(assignment.Serialize());
                                MeshSend(aBytes, aBytes.Length, new IPEndPoint(IPAddress.Parse(chosenRelay), MeshControlPort));
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] Failed to send MeshRelayAssignment to {chosenRelay}: {ex.Message}");
                            }
                        }

                        var relayToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                        {
                            PeerID = infoB.peerID ?? "",
                            EndpointString = infoB.endpoint,
                            NATType = infoB.natType,
                            PrivateAddressString = ipB,
                            IsRelay = true,
                            IntroducerMeshIP = meshIP,
                            RelayMeshIP = chosenRelay,
                            PeerMinVersion = infoB.peerMinVersion,
                            PeerMaxVersion = infoB.peerMaxVersion,
                            IdentityPublicKey = infoB.identityPublicKey
                        };
                        try
                        {
                            byte[] rABytes = Encoding.UTF8.GetBytes(relayToA.Serialize());
                            MeshSend(rABytes, rABytes.Length,
                                new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                            repairCount++;
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}");
                        }

                        var relayToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                        {
                            PeerID = infoA.peerID ?? "",
                            EndpointString = infoA.endpoint,
                            NATType = infoA.natType,
                            PrivateAddressString = ipA,
                            IsRelay = true,
                            IntroducerMeshIP = meshIP,
                            RelayMeshIP = chosenRelay,
                            PeerMinVersion = infoA.peerMinVersion,
                            PeerMaxVersion = infoA.peerMaxVersion,
                            IdentityPublicKey = infoA.identityPublicKey
                        };
                        try
                        {
                            byte[] rBBytes = Encoding.UTF8.GetBytes(relayToB.Serialize());
                            MeshSend(rBBytes, rBBytes.Length,
                                new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                            repairCount++;
                        }
                        catch (Exception ex)
                        {
                            context.Log(LogLevel.Error, $"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                        }

                        relayedPairs.Add(pairKey);
                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                    }
                    else
                    {
                        // Non-symmetric pair — re-introduce with direct hole-punch
                        bool hasWgA = host.GetPeer(IPAddress.Parse(ipA)) != null;
                        bool hasWgB = host.GetPeer(IPAddress.Parse(ipB)) != null;
                        if (!hasWgA || !hasWgB)
                        {
                            context.Log(LogLevel.Debug, $"[Mesh] Skipping repair for {ipA} <-> {ipB} — no WireGuard tunnel to {(!hasWgA ? ipA : ipB)}");
                            continue;
                        }

                        context.Log($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected — re-introducing (attempt {attempts}{(sameLanPair ? ", same-LAN" : "")})");

                        // Prefer v6 when both peers have it (no NAT — direct connect is reliable);
                        // else for same-LAN pairs substitute LAN endpoints so peers retry over the
                        // local network instead of the public endpoints that don't hairpin.
                        // Each side is handed the *other* peer's endpoint. repairBothHaveV6 was
                        // computed above (it also gated the symmetric-relay branch out).
                        string endpointForA = repairBothHaveV6 ? infoB.endpointV6 : infoB.endpoint;
                        string endpointForB = repairBothHaveV6 ? infoA.endpointV6 : infoA.endpoint;
                        if (!repairBothHaveV6 && sameLanPair)
                        {
                            if (peerLanByMeshIP.TryGetValue(ipB, out var lanB))
                                endpointForA = EndpointUtils.Format(lanB.localIP, lanB.localPort);
                            if (peerLanByMeshIP.TryGetValue(ipA, out var lanA))
                                endpointForB = EndpointUtils.Format(lanA.localIP, lanA.localPort);
                        }

                        // Only skip when BOTH endpoints are known and of different families (a real
                        // v4↔v6 mismatch). An empty endpoint isn't a mismatch — the per-side sends
                        // below already gate on presence, and skipping the whole pair on an empty
                        // endpoint would break normal repair for a peer whose endpoint isn't cached yet.
                        if (!string.IsNullOrEmpty(endpointForA) && !string.IsNullOrEmpty(endpointForB) &&
                            !EndpointUtils.SameFamily(endpointForA, endpointForB))
                        {
                            context.Log(LogLevel.Debug, $"[Mesh] Skipping repair for {ipA} <-> {ipB} — no shared address family (v4/v6 mismatch)");
                            continue;
                        }

                        if (!string.IsNullOrEmpty(endpointForA) || !string.IsNullOrEmpty(infoB.endpointV6))
                        {
                            var cbToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                            {
                                PeerID = infoB.peerID ?? "",
                                EndpointString = endpointForA,
                                // Carry both families so peer A picks the one it can reach.
                                EndpointV6String = infoB.endpointV6,
                                NATType = infoB.natType,
                                PrivateAddressString = ipB,
                                PeerMinVersion = infoB.peerMinVersion,
                                PeerMaxVersion = infoB.peerMaxVersion,
                                IdentityPublicKey = infoB.identityPublicKey
                            };
                            try
                            {
                                byte[] cbABytes = Encoding.UTF8.GetBytes(cbToA.Serialize());
                                MeshSend(cbABytes, cbABytes.Length,
                                    new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                repairCount++;
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] Failed to send repair MeshConnectionBegin to {ipA}: {ex.Message}");
                            }
                        }

                        if (!string.IsNullOrEmpty(endpointForB) || !string.IsNullOrEmpty(infoA.endpointV6))
                        {
                            var cbToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                            {
                                PeerID = infoA.peerID ?? "",
                                EndpointString = endpointForB,
                                // Carry both families so peer B picks the one it can reach.
                                EndpointV6String = infoA.endpointV6,
                                NATType = infoA.natType,
                                PrivateAddressString = ipA,
                                PeerMinVersion = infoA.peerMinVersion,
                                PeerMaxVersion = infoA.peerMaxVersion,
                                IdentityPublicKey = infoA.identityPublicKey
                            };
                            try
                            {
                                byte[] cbBBytes = Encoding.UTF8.GetBytes(cbToB.Serialize());
                                MeshSend(cbBBytes, cbBBytes.Length,
                                    new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                repairCount++;
                            }
                            catch (Exception ex)
                            {
                                context.Log(LogLevel.Error, $"[Mesh] Failed to send repair MeshConnectionBegin to {ipB}: {ex.Message}");
                            }
                        }
                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                    }
                }
            }
        }

        // Check that each peer can reach US (the introducer).
        foreach (var ip in targetList)
        {
            if (!currentHeartbeatAcks.ContainsKey(ip))
                continue;
            if (!currentHeartbeatAcks[ip].Contains(meshIP))
            {
                context.Log(LogLevel.Error, $"[Mesh] Heartbeat: peer {ip} cannot reach introducer ({meshIP}) — requesting re-connection via mediation");
                if (mediationClient != null && mediationClient.Connected &&
                    peerInfoByMeshIP.TryGetValue(ip, out var lostPeerInfo) &&
                    !string.IsNullOrEmpty(lostPeerInfo.peerID) &&
                    !pendingConnectionRequests.ContainsKey(lostPeerInfo.peerID) &&
                    !IsIncompatible(lostPeerInfo.peerID, lostPeerInfo.peerMinVersion, lostPeerInfo.peerMaxVersion) &&
                    !IsBlocked(lostPeerInfo.identityPublicKey))
                {
                    try
                    {
                        var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                        {
                            PeerID = lostPeerInfo.peerID,
                            NATType = detectedNatType
                        };
                        byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                        mediationStream.Write(reconnBuf, 0, reconnBuf.Length);
                        mediationStream.Flush();
                        pendingConnectionRequests[lostPeerInfo.peerID] = DateTime.UtcNow;
                        repairCount++;
                    }
                    catch (Exception ex)
                    {
                        context.Log(LogLevel.Error, $"[Mesh] Failed to send re-connection request for {ip}: {ex.Message}");
                    }
                }
            }
        }

        return repairCount;
    }
}
