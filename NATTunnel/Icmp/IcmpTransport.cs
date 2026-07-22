using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NATTunnel.Icmp;

/// <summary>
/// A bidirectional ICMP hole-punch transport between two full-range-symmetric NAT peers — the direct-connect
/// path for the case UDP provably cannot punch. Lifts the validated core of experiments/IcmpBandwidth into a
/// clean, instance-based transport the mesh engine can drive as an alternative to a UDP socket.
///
/// LIFECYCLE
///   1. Construct with the peer's public endpoint (and optionally a capture backend).
///   2. Call <see cref="StartAsync"/>. It resolves the local source, opens the send socket + capture, then
///      runs the PUNCH: a full-range 16-bit-ICMP-id sweep of echo requests + hammer-ACK on hearing the peer,
///      until a bidirectional hole opens (birthday collision) or it times out.
///   3. On success, <see cref="Punched"/> fires and <see cref="IsPunched"/> flips true. From then on
///      <see cref="Send"/> carries caller bytes over the channel and <see cref="PacketReceived"/> raises
///      inbound caller bytes. On timeout, StartAsync returns false and the caller falls through to relay.
///   4. <see cref="Dispose"/> stops the sweep/keepalive, closes sockets, joins threads.
///
/// TRANSPORT MODEL (proven)
///   The channel is a LOSSY SPRAY, not a clean pipe. After the punch, both peers send data-bearing echo
///   requests across a rotating set of ~16 shared ICMP ids (a carrier CGNAT rewrites ids per-flow, so we keep
///   several holes live at once). A fraction cross each way; the receiver reassembles what lands. State is
///   bounded to ~N holes regardless of throughput → router-safe. Reliability/ordering for WireGuard-over-this
///   is the caller's concern (a thin shim or WG's own tolerance); this class delivers datagrams best-effort.
///
///   Only the proven TYPE-8 (echo request) design is implemented. The type-0 / hybrid unprivileged variants
///   were tested to destruction (strict NATs drop unsolicited type-0) and are intentionally omitted.
/// </summary>
internal sealed class IcmpTransport : IDisposable
{
    // Wire tags. CRITICAL: the data MAGIC must NOT be a prefix of the punch tags — REQTAG/ACKTAG are "ICH-REQ"/
    // "ICH-ACK", so a data marker of "ICH" made every opener match the data-frame check (StartsWith(MAGIC)),
    // flooding the receiver with bogus 11-byte "data" frames whose frame id was garbage from "-REQ"/"-ACK".
    // Use a distinct data marker ("ICD") so openers and data frames are unambiguously separable on the wire.
    private static readonly byte[] MAGIC = Encoding.ASCII.GetBytes("ICD");   // data-packet marker (distinct from tags)
    private static readonly byte[] REQTAG = Encoding.ASCII.GetBytes("ICH-REQ");
    private static readonly byte[] ACKTAG = Encoding.ASCII.GetBytes("ICH-ACK");

    private const byte ICMP_ECHO_REQUEST = 8;
    private const byte ICMP_ECHO_REPLY = 0;   // reverse-ACK is a type-0 reply, matching icmp-channel.py
    private const ushort PING_ID = 0x4a01;    // fixed id the pinger uses post-punch (like a real ping's identifier)
    private const int DATA_HEADER = 3 + 4; // MAGIC(3) + uint32 frame id
    // Hearing the peer this many times (any tagged packet) is enough to declare the hole open even without an
    // explicit ACK exchange — robustness against the two sides' punch windows not overlapping cleanly.
    private const int HEARD_TO_PUNCH = 8;

    // --- configuration (defaults are the validated values) ---
    private readonly IPEndPoint _peerEndpoint;
    private readonly IPAddress _peer;
    // CLIENT/SERVER role. The INITIAL assignment is DETERMINISTIC — derived from the peer-id ordinal by the caller
    // (MeshProtocolEngine compares the two GUIDs) so the two ends always start on opposite roles with zero
    // coordination. Purely-inferred roles ("did I hear a request recently?") let BOTH sides evaluate the same way at
    // the same moment → both became CLIENT → nobody drove the other's reply-vehicle → deadlock.
    //
    // BUT deterministic-and-complementary is not sufficient, because it can assign the roles BACKWARDS. Only ONE
    // direction's echo REQUESTS actually cross a symmetric-NAT pair (capture: 10,897 of one side's requests arrived
    // vs 97 of the other's), and which one is a property of the NAT pair, NOT of the peer-id ordering — so the coin
    // flip is wrong half the time. When it is, the channel deadlocks in a way that looks exactly like a dead capture:
    // the SERVER waits for requests that will never arrive (its data sits in _txQueue with no reply-vehicle) while
    // the CLIENT sprays requests that never land. Observed 20:06 — SERVER got ONE type-8 in 30s, retransmitted its
    // WG key 15 times unanswered, and both sides tore down.
    //
    // The role now only controls the keepalive-REQUEST RATE (how many reply-slots we hand the peer), NOT how data is
    // sent — both roles drain data as matched type-0 replies, because that is the only shape this channel delivers.
    // That makes a wrong role assignment merely suboptimal (fewer slots) instead of fatal, which is why the
    // SERVER→CLIENT promotion that used to live here was removed rather than fixed.
    private readonly bool _isPinger;
    private bool _isClient => _isPinger;
    private readonly int _lockIds;          // number of reusable holes to lock onto for the data channel
    private readonly int _rate;             // packets/sec cap (keeps holes warm; scales throughput)
    private readonly int _idWindow;         // how many recently-heard ids to keep for reverse-ack
    private readonly TimeSpan _punchTimeout;

    // --- runtime state ---
    private readonly IIcmpCapture _capture;
    private readonly ushort[] _lockSet;
    private readonly object _idLock = new();
    private readonly System.Collections.Generic.List<ushort> _heardIds = new();
    private Socket _sendSock;
    private IPAddress _localSource = IPAddress.Any;
    private IPEndPoint _sendTo;
    private Thread _sendThread;
    private volatile bool _punched;
    private volatile bool _stopped;
    private readonly object _sendLock = new();

    // rate pacing shared between punch + data send loops
    private readonly double _sendInterval;

    /// <summary>Fires once, when the bidirectional hole is confirmed open. Raised on an internal thread.</summary>
    public event Action Punched;

    /// <summary>
    /// Fires for each inbound caller datagram reassembled from the channel. The byte[] is a fresh copy the
    /// handler owns. Raised on the capture thread — keep the handler fast; marshal real work off it.
    /// </summary>
    public event Action<byte[]> PacketReceived;

    public bool IsPunched => _punched;

    /// <summary>
    /// After <see cref="StartAsync"/> returns, distinguishes WHY it may have failed:
    ///   • false  → the capture backend couldn't come up (no driver / no privilege) — the ICMP tier is not
    ///              usable on this machine at all; the engine should not retry ICMP for other peers either.
    ///   • true   → capture was fine; a false StartAsync means the PUNCH itself timed out for this pair.
    /// Lets the engine tell "ICMP unavailable here" from "this specific pair didn't punch".
    /// </summary>
    public bool CaptureAvailable { get; private set; }

    /// <summary>The peer this transport connects to.</summary>
    public IPEndPoint PeerEndpoint => _peerEndpoint;

    public IcmpTransport(
        IPEndPoint peerEndpoint,
        bool isPinger,
        IIcmpCapture capture = null,
        int lockIds = 16,
        int rate = 1500,
        int idWindow = 256,
        TimeSpan? punchTimeout = null)
    {
        _peerEndpoint = peerEndpoint ?? throw new ArgumentNullException(nameof(peerEndpoint));
        _peer = peerEndpoint.Address;
        _isPinger = isPinger;
        _lockIds = Math.Max(1, lockIds);
        _rate = Math.Max(0, rate);
        _idWindow = Math.Max(16, idWindow);
        _punchTimeout = punchTimeout ?? TimeSpan.FromSeconds(25);
        _sendInterval = _rate > 0 ? 1.0 / _rate : 0;
        _capture = capture ?? IcmpCapture.CreateDefault();

        // Both peers derive the same shared lock set by convention (ids 0x100..0x100+lockIds-1) so both
        // directions ride reusable holes once the punch establishes.
        _lockSet = new ushort[_lockIds];
        for (int i = 0; i < _lockIds; i++) _lockSet[i] = (ushort)(0x100 + i);

        // DIAGNOSTIC PROBE (env NT_ICMP_PROBE_LARGEREQ=1): after punch, send a LARGE (~200B) data-carrying echo
        // REQUEST at ~3/sec and log distinctly whether the peer receives large REQUESTS (vs only replies). This
        // isolates whether the punched hole forwards unsolicited large requests — if yes we can adopt icmptunnel's
        // model (data on the request, ~3/sec, no reply-matching); if no, requests are unreliable for our symmetric
        // case and we keep data-as-matched-reply. Off in normal operation.
        // File-gated (NOT env-gated): the GUI runs ELEVATED, and a UAC-elevated process gets a fresh environment
        // that does NOT inherit an env var set in an unelevated shell — so an env gate silently never fires. A file
        // marker next to the binary is visible regardless of elevation.
        try { _probeLargeReq = System.IO.File.Exists("nt-icmp-probe-largereq"); } catch { _probeLargeReq = false; }
    }

    private readonly bool _probeLargeReq;
    private static readonly byte[] PROBETAG = Encoding.ASCII.GetBytes("ICPROBE");  // marks probe requests (distinct from MAGIC/REQTAG/ACKTAG)

    /// <summary>
    /// Resolves the route, opens sockets/capture, and runs the punch until a hole opens or it times out.
    /// Returns true and raises <see cref="Punched"/> on success. On false, the transport is unusable for this
    /// pair and the caller should Dispose it and fall through to the next connection tier.
    /// </summary>
    public async Task<bool> StartAsync(CancellationToken ct = default)
    {
        // Resolve the local source IP that routes to the peer (a UDP connect sends no packets; it just makes
        // the OS pick the egress interface). Binding the raw send socket to this forces egress out the right
        // NIC — WARP/Tailscale-aware, the fix that made the native punch work through tunnels.
        try
        {
            using var probe = new Socket(_peer.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(_peer, 9);
            _localSource = ((IPEndPoint)probe.LocalEndPoint).Address;
        }
        catch { _localSource = _peer.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any; }

        // Send socket: raw ICMP bound to the resolved source. Sending is unprivileged on modern Windows and
        // needs only CAP_NET_RAW on Linux (which the daemon already has, or setcap grants).
        var proto = _peer.AddressFamily == AddressFamily.InterNetworkV6 ? ProtocolType.IcmpV6 : ProtocolType.Icmp;
        try
        {
            _sendSock = new Socket(_peer.AddressFamily, SocketType.Raw, proto);
            _sendSock.Bind(new IPEndPoint(_localSource, 0));
            // Send buffer sizing — BUFFERBLOAT IS LATENCY. This was 1 MB, added back when the PUNCH sprayed ~1500
            // packets/s and a small buffer starved the larger DATA packets (SendTo returned the byte count but the
            // packet never hit the wire). That firehose is gone (steady state is ~60/s), and the 1 MB buffer became
            // pure delay: we fill it faster than the NIC drains it, so every packet queues behind the backlog.
            // MEASURED: raw request→reply RTT was a rock-steady ~900ms with a real network RTT of ~40ms — i.e.
            // ~860ms of self-inflicted queueing. A small buffer can't hoard that backlog, so packets go out now.
            // (If large-packet starvation ever returns, fix it by pacing the sender, NOT by growing the buffer.)
            try { _sendSock.SendBufferSize = 64 * 1024; } catch { }
        }
        catch (SocketException)
        {
            return false; // can't send raw ICMP → transport unusable
        }
        _sendTo = new IPEndPoint(_peer, 0);

        // Receive path (platform-specific behind the capture interface).
        NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP] capture backend = {_capture.GetType().Name}, localSource = {_localSource}, peer = {_peer}");
        _capture.Start(_peer, _localSource, OnInboundIcmp);
        CaptureAvailable = _capture.IsAvailable;
        if (!CaptureAvailable)
            return false; // can't receive inbound type-8 (e.g. Windows non-admin without the driver) → fall through

        // Run the punch on a background thread; complete when the hole opens or the timeout elapses.
        var punchedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _sendThread = new Thread(() => PunchAndServe(punchedTcs)) { IsBackground = true, Name = "IcmpTransport" };
        _sendThread.Start();

        using (ct.Register(() => punchedTcs.TrySetResult(false)))
        {
            return await punchedTcs.Task.ConfigureAwait(false);
        }
    }

    // ---- the punch + ongoing data-channel maintenance, on the send thread ----
    private void PunchAndServe(TaskCompletionSource<bool> punchedTcs)
    {
        var sw = Stopwatch.StartNew();
        int idx = 0;
        double nextSend = 0;

        // PUNCH — exactly icmp-channel.py: full-range 16-bit id sweep of echo REQUESTS + reverse-ACK the recently
        // heard ids (type-0 reply, ACK-tagged), until the hole opens (a heard ACK flips _punched in OnInboundIcmp)
        // or the timeout elapses. The full-range sweep is essential: a CGNAT rewrites the id anywhere in 0-65535,
        // so a narrow window never collides. No lock-set openers — the data channel doesn't use a lock set.
        while (!_punched && !_stopped && sw.Elapsed < _punchTimeout)
        {
            SendTag(ICMP_ECHO_REQUEST, (ushort)(idx % 65536), (ushort)(idx & 0xFFFF), REQTAG);

            ushort[] recent;
            lock (_idLock)
            {
                int take = Math.Min(4, _heardIds.Count);
                recent = take > 0 ? _heardIds.GetRange(_heardIds.Count - take, take).ToArray() : Array.Empty<ushort>();
            }
            foreach (var hi in recent)
                SendTag(ICMP_ECHO_REPLY, hi, (ushort)(idx & 0xFFFF), ACKTAG);

            idx++;
            Pace(sw, ref nextSend);
        }

        if (!_punched)
        {
            punchedTcs.TrySetResult(false);
            return;
        }

        // Punch confirmed. Signal success and raise the event, then run the DATA CHANNEL.
        //
        // THE PROVEN MODEL (from icmp-channel.py, which sustains bidirectional data through these CGNATs): DON'T
        // stop the full-range sweep and DON'T switch to a fixed "lock set" — a CGNAT rewrites the ICMP id per
        // flow to an ever-changing NAT-assigned id, so a fixed set is a hole the peer's NAT never forwards, and
        // "data on heard ids" stops the spray so the holes die (both tried, both failed — proven by datacross).
        // Instead: KEEP SWEEPING THE FULL 16-BIT ID RANGE, and CARRY caller data ON the sweep packets themselves.
        // Each outbound packet is the next full-range id; if we have queued caller bytes we send a DATA frame,
        // else a REQ opener. Many holes stay live; a fraction cross carrying bytes; the receiver reassembles what
        // lands. Lossy spray, not a pipe — WireGuard's own retransmission tolerates the loss.
        punchedTcs.TrySetResult(true);
        try { Punched?.Invoke(); } catch { }

        // POST-PUNCH: replicate a NORMAL PING SESSION (icmptunnel model). The full-range sweep was ONLY needed to
        // PUNCH (birthday-hunt the CGNAT-rewritten id); post-punch it looks like a port scan (MAC-ban trigger) and
        // is unnecessary. Instead, one peer is the PINGER and one the RESPONDER:
        //   • PINGER: sends echo REQUESTS on a FIXED id with an incrementing seq (exactly like `ping`), carrying
        //     its data in the payload; a bare keepalive request when it has none. This is what keeps the flow warm.
        //   • RESPONDER: never runs this request loop — it replies REACTIVELY to the pinger's requests in
        //     OnInboundIcmp (echoing their id+seq), attaching its own queued data. So the responder's outbound is
        //     pure type-0 replies matched to real requests → the NAT forwards them like normal ping replies.
        // Net: steady-state = a single ping conversation (one id, sequential seq, request↔reply) — NAT-friendly,
        // reliable, and indistinguishable from ping (no scan pattern, no ban).
        double nextSend2 = 0;
        var sw2 = Stopwatch.StartNew();
        ushort pingSeq = 0;
        while (!_stopped)
        {
            // BOTH peers ping (symmetric). A keepalive echo REQUEST on the fixed ping id (like a real `ping`: one
            // identifier, incrementing seq) does two jobs: it keeps OUR NAT's outbound-request table populated so
            // the peer's matched data-replies are forwarded inbound to us (RFC 5508), and it gives the PEER inbound
            // requests to answer with THEIR data. Our own data is NOT sent here as requests — unsolicited inbound
            // requests are dropped by the peer's NAT (proven by the captures); data drains reactively as REPLIES in
            // OnInboundIcmp (+ the fallback below). So this loop is pure keepalive; all data rides the reply shape.
            if (_probeLargeReq)
            {
                // Probe: emit a LARGE (~200B) data-carrying REQUEST at the steady low rate. PROBETAG + pad so the
                // receiver can identify it distinctly (and it's clearly a request, not a reply). ~3/sec set below.
                var probe = new byte[200];
                PROBETAG.CopyTo(probe, 0);
                probe[7] = (byte)(pingSeq >> 8); probe[8] = (byte)pingSeq; // seq marker for visibility
                SendTag(ICMP_ECHO_REQUEST, PING_ID, pingSeq++, REQTAG); // still send the normal keepalive too
                EmitIcmp(ICMP_ECHO_REQUEST, PING_ID, pingSeq++, probe);
                PaceTo(sw2, ref nextSend2, 1.0 / 3.0); // icmptunnel cadence: ~3 large requests/sec
                continue;
            }

            // ── CLIENT/SERVER MODEL (icmptunnel/hans/ptunnel — the design proven fast) ──────────────────────────
            // Every working ICMP tunnel is client↔server: the CLIENT sends a dense stream of echo REQUESTS carrying
            // its data; the SERVER never sends requests — it only REPLIES to the client's requests, piggybacking its
            // own data on each reply. One request↔reply exchange = ONE RTT. That's why they're fast and we weren't.
            //
            // Our symmetric-NAT twist: only ONE direction's requests actually cross (whichever side won the punch —
            // capture: 10,897 of one side's requests arrived vs 97 of the other's). So roles are DISCOVERED at
            // runtime, not fixed: the side whose requests cross must be the CLIENT (its requests are the reply-
            // vehicle), the side that RECEIVES those requests must be the SERVER. Each side decides from its OWN
            // inbound-request rate — no coordination:
            //   • I'm receiving the peer's requests at a high rate  → the peer's requests reach me → I'm the SERVER.
            //     Do NOTHING in this loop; my data goes out purely via the reactive reply in OnInboundIcmp (one
            //     data-reply per inbound request = one RTT, exactly icmptunnel's server).
            //   • I'm NOT receiving the peer's requests            → mine are the ones that cross → I'm the CLIENT.
            //     Drive a dense request stream carrying my queued data (data on the request; a bare keepalive-request
            //     when idle to keep giving the server a reply-vehicle).
            // This restores the request↔reply pairing that makes real ICMP tunnels one-RTT, and drops all the slot-
            // harvesting / keepalive-reply machinery we built to fake it.
            // ROLE = DETERMINISTIC + COMPLEMENTARY (by peer id), NOT inferred from traffic. An inferred role ("did I
            // hear a request recently?") is UNSTABLE: both sides can evaluate it the same way at the same time. That
            // is exactly what happened — both flipped to CLIENT, so neither drove the other's reply-vehicle, WG key
            // resends looped forever and the tunnel deadlocked (it did NOT self-heal as I assumed). Deriving from the
            // peer-id ordinal guarantees the two ends pick OPPOSITE roles, always, with zero coordination.
            //
            // BOTH sides still send requests — only the RATE differs. The client drives densely (it is the reply-
            // vehicle generator); the server also emits a slow trickle so that if the client's requests are the ones
            // that DON'T cross this pairing, the channel still has a live request stream in the other direction and
            // can't go fully silent. Data always rides whatever we send: on our requests here, and on our replies to
            // the peer's requests in OnInboundIcmp.
            if (!_loggedServerRole)
            {
                _loggedServerRole = true;
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][role] {(_isClient ? "CLIENT (dense request driver)" : "SERVER (sparse requests; data rides replies)")}");
            }

            // (A SERVER→CLIENT "backwards role rescue" was tried here and REMOVED. It fired correctly — 20:10:04,
            //  "heard the peer for 9.4s but no inbound REQUEST" — and changed nothing, because promoting to CLIENT
            //  moved that side OFF the reactive matched-reply path and ONTO the unsolicited-request path, which is
            //  the one that doesn't deliver. The role was never the problem; the data SHAPE was. Both roles now
            //  drain data the same way (matched replies), so there is nothing for a promotion to fix.)

            // DATA GOES OUT AS MATCHED REPLIES — NEVER AS UNSOLICITED REQUESTS.
            //
            // This loop used to drain the queue as type-8 REQUESTS on the fixed PING_ID. That is the ONE shape this
            // channel provably does NOT deliver: an unsolicited inbound echo REQUEST has no outstanding entry in the
            // peer's symmetric NAT, so it is dropped (documented above, and confirmed end-to-end at 20:09-20:10 —
            // the side draining here sent its 203B WG key 15+ times and the peer received NONE of them, while the
            // side draining via the reactive reply path got its 204B key across on the FIRST try and the peer
            // declared the connection established). Same channel, same instant, opposite outcomes — the only
            // difference was request-vs-matched-reply.
            //
            // So drain onto recently-heard (id,seq) slots as type-0 REPLIES via EmitFrameRedundant, which fans each
            // frame across ~FRAME_FANOUT distinct live holes (a strict NAT forwards ~one reply per request, so
            // distinct slots — not repeat copies onto one slot — are what buys reliability). Keepalive REQUESTS are
            // still sent below; those are cheap 18B packets whose job is to keep the peer supplied with slots to
            // reply onto, and they cross fine because they don't need to carry anything.
            int sent = 0;
            for (; sent < DRAIN_PER_ITER && _txQueue.TryDequeue(out var frame); sent++)
            {
                // Prefer a REQUEST-derived slot (a live NAT entry, forwardable per RFC 5508); fall back to the most
                // recent reply-derived one for peers that receive no requests at all. Never refuse to send.
                int slot = _lastHeardReq >= 0 ? _lastHeardReq : _lastHeardAny;
                if (slot < 0)
                {
                    _txQueue.Enqueue(frame); // nothing heard from the peer yet at all — wait for the first packet
                    break;
                }
                // (A stale-slot guard was tried here — hold the frame if _lastHeardReq is older than ~2s — and it
                //  STALLED THE TUNNEL. It assumed both sides receive the peer's REQUESTS, but one side may receive
                //  none at all (21:25 run: SERVER saw req=26/13/11 while CLIENT saw req=0 for the entire run), so
                //  on that side every slot is always "stale" and the guard blocked every send: slotAge climbed to
                //  31s with qDepth 1→10 and nothing shipped. A stale slot is a low-probability delivery; refusing
                //  to send is a ZERO-probability one. Always spend the slot.)
                Interlocked.Increment(ref _txFramesSent);
                EmitFrameRedundant(frame, (ushort)(slot >> 16), (ushort)(slot & 0xFFFF));
            }
            // ALWAYS send the keepalive REQUEST — never gate it on "we had nothing else to send".
            //
            // It used to be `if (sent == 0)`, which starved the channel exactly when it was busiest. Our keepalive
            // requests are the ONLY thing that gives the PEER live (id,seq) slots to put ITS data-replies on (its
            // reactive drain in OnInboundIcmp fires only on inbound type-8). So under load we stopped supplying
            // slots at the very moment the peer had the most to send — and symmetrically it starved us. MEASURED
            // (20:37-20:39): `req=` read 261/96 in the first window and then **0 for the entire run** on both sides,
            // while data dribbled at type0=2 per 5s and WireGuard needed 15 handshake attempts over 84s to complete.
            // These are 18-byte packets; sending one per iteration alongside the data is cheap and is what keeps the
            // reverse direction alive.
            //
            // This also un-breaks the RTT probe, which lived inside the same dead branch — which is why [ICMP][rtt]
            // has never once appeared in a log despite being the instrument for the latency question.
            // KEEPALIVE REQUESTS MUST SWEEP THE ID SPACE — a fixed id never crosses.
            //
            // These were sent on a fixed PING_ID at 60/s and the peer received EXACTLY ZERO of them: `req=` reads
            // 0 in every 5s window on both sides, across every run, and a Wireshark capture filtered to
            // `icmp.type == 8` showed only 96 inbound requests out of 879,831 packets — all of them punch-phase
            // ICH-AC packets, none from steady state. The punch works precisely BECAUSE it sweeps: a symmetric
            // CGNAT rewrites our ICMP id, so only a sweep lands on an id the peer's NAT holds open. One fixed id is
            // one lottery ticket, redrawn 60 times a second against the same losing number.
            //
            // This matters far more than it looks: our requests are the ONLY source of live reply-slots for the
            // peer (its reactive drain fires on inbound type-8 only). No requests across ⇒ no live slots ⇒ both
            // sides fall back to replying onto DEAD slots harvested from replies ⇒ ~20% delivery and 800ms ping.
            //
            // Sweep at the same steady rate (no extra packets, just a moving id) so this stays ping-shaped rather
            // than scan-shaped — nothing like the 1500/s full-range punch that risks a MAC ban.
            ushort kaId = (ushort)(_kaSweep++ & 0xFFFF);
            ushort probeSeq = pingSeq;
            if (_rttSw.Elapsed.TotalSeconds >= _nextRttProbe)
            {
                _nextRttProbe = _rttSw.Elapsed.TotalSeconds + 1.0;
                _rttStamps[probeSeq] = _rttSw.ElapsedMilliseconds;
            }
            SendTag(ICMP_ECHO_REQUEST, kaId, pingSeq++, REQTAG);
            // Pace at the dense rate whenever EITHER side has traffic to move; trickle only when genuinely idle.
            //
            // The SERVER used to trickle at 4/s unless its OWN queue was non-empty. But our request rate is the
            // PEER's slot supply, so a trickling server capped the client at ~4 delivered frames/sec regardless of
            // how much the client had queued — the server has no way to know the client is backed up. Keying the
            // rate on recent DATA ACTIVITY IN EITHER DIRECTION (not just our own queue) means a busy peer gets a
            // dense slot supply from us, and a quiet channel still costs only the idle trickle.
            bool active = !_txQueue.IsEmpty ||
                          (DateTime.UtcNow - _lastDataRxUtc) < ActiveWindow ||
                          (DateTime.UtcNow - _lastDataTxUtc) < ActiveWindow;
            PaceTo(sw2, ref nextSend2, (_isClient || active) ? STEADY_INTERVAL : SERVER_TRICKLE_INTERVAL);
        }
    }

    // The SERVER still emits a slow request trickle (~4/s) so the reverse direction never goes fully silent — if the
    // client's requests turn out to be the ones this NAT pair drops, the server's trickle keeps a live request
    // stream (and therefore a reply-vehicle) in the other direction. Far below the client's dense rate so it doesn't
    // compete with the client's stream for NAT forwarding.
    private const double SERVER_TRICKLE_INTERVAL = 1.0 / 4.0;
    private DateTime _lastReqRxUtc = DateTime.MinValue;   // last time we heard a peer REQUEST (drives the promotion)
    private DateTime _firstHeardUtc = DateTime.MinValue;  // first time we heard the peer AT ALL (promotion baseline)
    private bool _loggedServerRole; // set once we've logged the role at startup


    // Steady-state keepalive-request cadence: ~60/sec. This is the ONE rate PROVEN to complete the WG handshake and
    // flow data (06:19 run: wg DATA=33 climbing). CRITICAL FINDING: HIGHER is NOT better — at 250/s the handshake
    // NEVER completed (wg DATA=0, init/resp looped forever every ~2.5s = WG REKEY_TIMEOUT retransmit). The flood of
    // keepalive-ACK replies crowds out / reorders WG's handshake completion packet so the session never confirms.
    // 60/s has few enough keepalives that the handshake's critical packets land, while still supplying plenty of
    // reply-slots. (The earlier 1888ms-at-10/s latency was a DIFFERENT bug — the stale-slot drain, now reverted —
    // NOT a slot-supply problem, so don't "fix" it by raising the rate again.) Tune cautiously around 60/s.
    private const double STEADY_INTERVAL = 1.0 / 60.0;
    private DateTime _lastDataRxUtc = DateTime.MinValue;
    private DateTime _lastDataTxUtc = DateTime.MinValue;

    // How long after the last data packet (either direction) we keep paying the dense keepalive rate. Several
    // comments referenced an "ActiveWindow" that was never actually defined — the two timestamps above were written
    // but never read, so the rate never adapted. Long enough to span a WG handshake round trip on a slow channel,
    // short enough that a truly idle tunnel drops back to the trickle quickly.
    private static readonly TimeSpan ActiveWindow = TimeSpan.FromSeconds(3);

    // TRANSPORT-LEVEL RTT probe. Settles whether the ~1s ping is OUR ICMP layer or ABOVE it (WG/proxy): the CLIENT
    // stamps the send-time of one keepalive-request per second (by seq) and measures when the SERVER's reply for
    // that exact seq comes back. That is the raw request→reply round trip with no WireGuard in the path. If this
    // reads ~40ms while the mesh ping reads ~1000ms, the ICMP transport is fine and the latency is in WG/the proxy.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<ushort, long> _rttStamps = new();
    private readonly Stopwatch _rttSw = Stopwatch.StartNew();
    private double _nextRttProbe;
    private long _rttSumMs, _rttCount;
    private double _nextRttReport = 5.0;
    // How long SendTo actually blocks (lock + kernel queue) — isolates self-inflicted send delay from wire/peer time.
    private long _sendBlockedMs, _sendBlockedCount, _sendTotal;

    private long _txFrameCounter = -1;

    // (DATA_SENDS was a redundancy factor whose comment claimed each SendData emitted "BOTH an echo request and a
    //  matched reply". It never did — SendData emits exactly ONE packet — and nothing multiplied by this constant,
    //  so every caller frame crossed the lossy channel as a SINGLE un-retried packet. Frame redundancy now comes
    //  from EmitFrameRedundant/FRAME_FANOUT, which spreads copies across DISTINCT live slots. Constant removed so
    //  the misleading claim can't be relied on again.)

    // Max frames the send-loop fallback drains per iteration (onto the refreshing _lastHeardReq). Lets a queued
    // backlog (WG handshake burst) clear in a couple of iterations instead of one-frame-per-pace (the ~50s cold
    // start). BOUNDED on purpose — a full unbounded drain onto one stale slot is the greedy-drain regression.
    private const int DRAIN_PER_ITER = 8;

    // A caller frame awaiting transmission on the sweep.
    private sealed class TxFrame { public uint Frame; public byte[] Data; }
    private readonly System.Collections.Concurrent.ConcurrentQueue<TxFrame> _txQueue = new();

    /// <summary>
    /// Queues a caller datagram for transmission over the punched channel, best-effort. No-op until
    /// <see cref="IsPunched"/>. The frame is carried on the continuous full-range sweep (see PunchAndServe),
    /// repeated across the churning id space so a copy crosses the lossy channel; the receiver de-dups by frame
    /// id. Reliability/ordering beyond "at least one copy crosses" is the caller's concern.
    /// </summary>
    public void Send(ReadOnlySpan<byte> data)
    {
        if (!_punched || _stopped) return;
        uint frame = (uint)Interlocked.Increment(ref _txFrameCounter);
        var body = data.ToArray();
        NoteSentBody(body); // remember it so we can drop the OS-reflected echo-reply copy that comes back to us
        _txQueue.Enqueue(new TxFrame { Frame = frame, Data = body });
    }

    /// <summary>byte[] overload — matches an Action&lt;byte[]&gt; delegate (e.g. the WireGuard proxy's send hook).</summary>
    public void Send(byte[] data) => Send(new ReadOnlySpan<byte>(data));

    // count of distinct times we've heard the peer during the punch (any tagged packet from them).
    private int _heardCount;
    private readonly Stopwatch _rxLogSw = Stopwatch.StartNew();
    private double _nextRxLog;

    // The (id, seq) of the most recent ECHO REQUEST we heard from the peer. Sending our data as a type-0 REPLY
    // carrying THIS exact (id, seq) makes it a matched reply to a request the peer just sent — which the peer's
    // NAT has a live conntrack entry for and WILL forward inbound. An unmatched reply (arbitrary id/seq) is
    // dropped by strict NATs (RFC 5508: they forward the reply that matches the outstanding request). This is
    // THE fix for the direction where only type-0 crosses but our data used arbitrary seqs and got dropped.
    // Ring of RECENTLY-HEARD peer echo-request (id, seq) pairs. A strict NAT forwards ~ONE reply per request
    // (RFC 5508), so each of our data replies must match a DISTINCT outstanding request — reusing one request's
    // (id, seq) for many replies gets all but one dropped. We consume a fresh heard-request per reply copy.
    private readonly System.Collections.Concurrent.ConcurrentQueue<int> _heardReqs = new();
    private int _heardReqCount;
    private const int HEARD_REQ_MAX = 512;
    private int _lastHeardReq = -1; // fallback when the ring runs dry

    private DateTime _lastHeardReqUtc = DateTime.MinValue; // when _lastHeardReq was last refreshed (staleness probe)
    private long _txFramesSent, _lastTxFramesSent;         // frames handed to EmitFrameRedundant (attempted sends)
    private uint _kaSweep;                                 // sweeping id for keepalive requests (a fixed id never crosses)
    private volatile int _lastHeardAny = -1;               // fallback slot from an inbound REPLY (used when req=0)

    private void NoteHeardReq(ushort id, ushort seq)
    {
        int v = (id << 16) | seq;
        _lastHeardReq = v;
        _lastHeardReqUtc = DateTime.UtcNow;
        NoteHeardSlot(id, seq);
    }

    /// <summary>
    /// Adds an (id, seq) to the FANOUT RING only, without promoting it to the primary reply slot.
    /// Used for inbound REPLIES: their (id,seq) is a poorer bet than a request's (the NAT entry that admitted
    /// the reply is already consumed), so it must not become `_lastHeardReq` — but it is still worth having in
    /// the ring, because EmitFrameRedundant needs SEVERAL distinct holes and a peer that receives few requests
    /// would otherwise have an almost-empty ring and send every frame down a single hole.
    /// </summary>
    private void NoteHeardSlot(ushort id, ushort seq)
    {
        int v = (id << 16) | seq;
        _heardReqs.Enqueue(v);
        if (Interlocked.Increment(ref _heardReqCount) > HEARD_REQ_MAX && _heardReqs.TryDequeue(out _))
            Interlocked.Decrement(ref _heardReqCount);
    }

    /// <summary>A distinct heard-request (id, seq) for a data reply, or the last one if the ring is empty.</summary>
    private int TakeHeardReq()
    {
        if (_heardReqs.TryDequeue(out var v)) { Interlocked.Decrement(ref _heardReqCount); return v; }
        return _lastHeardReq;
    }

    /// <summary>
    /// RELIABILITY: snapshot up to `max` of the MOST-RECENT DISTINCT heard requests WITHOUT consuming them. A frame
    /// sent as a reply onto EACH of these rides that many independent NAT holes at once — if any one hole is live,
    /// the frame crosses. This is the fix for channel-quality VARIANCE: a single (id,seq) is a coin-flip (some
    /// punched holes barely pass anything → WG handshake can't complete), but bursting one frame across N recent
    /// requests makes delivery near-certain. Unlike TakeHeardReq this does NOT dequeue — a recently-heard request
    /// is a valid outstanding NAT mapping for a short window and can back several of our replies; draining the ring
    /// (the earlier bug) left dead slots. We read newest-first from the ring's tail via a bounded copy.
    /// </summary>
    private int[] RecentHeardReqs(int max)
    {
        // ConcurrentQueue enumerates oldest→newest; we want the freshest. Copy, dedup preserving last occurrence,
        // take the newest `max`. Bounded work (ring ≤ HEARD_REQ_MAX) and off the hot path's inner loop.
        var all = _heardReqs.ToArray();
        if (all.Length == 0) return _lastHeardReq >= 0 ? new[] { _lastHeardReq } : System.Array.Empty<int>();
        var seen = new System.Collections.Generic.HashSet<int>();
        var outp = new System.Collections.Generic.List<int>(max);
        for (int i = all.Length - 1; i >= 0 && outp.Count < max; i--)
            if (seen.Add(all[i])) outp.Add(all[i]);
        return outp.ToArray();
    }

    // ---- inbound handling (on the capture thread) ----
    private void OnInboundIcmp(byte type, ushort id, ushort seq, ReadOnlySpan<byte> payload)
    {
        // Note the id we heard the peer on (for reverse-ack during the punch + the data channel's heard set).
        // NoteHeardReq(id,seq) below records (id,seq) into _lastHeardReq; our keepalive requests + data replies both
        // ride that id — the hole proven to persist the whole session (see the send loop).
        NoteHeardId(id);

        // Baseline for the backwards-role promotion: the first moment we heard the peer at all. If we're SERVER and
        // this keeps advancing while _lastReqRxUtc never does, the peer's requests aren't crossing → we must drive.
        if (_firstHeardUtc == DateTime.MinValue) _firstHeardUtc = DateTime.UtcNow;

        // TRANSPORT RTT: a reply echoing a seq we stamped = one raw request→reply round trip, no WireGuard involved.
        // Report the rolling average every 5s. If this is small (~tens of ms) while the mesh ping is ~1s, the ICMP
        // transport is NOT the bottleneck and the latency lives in WireGuard / the loopback proxy above it.
        if (type == ICMP_ECHO_REPLY && _rttStamps.TryRemove(seq, out long sentMs))
        {
            long rtt = _rttSw.ElapsedMilliseconds - sentMs;
            Interlocked.Add(ref _rttSumMs, rtt);
            long n = Interlocked.Increment(ref _rttCount);
            double now = _rttSw.Elapsed.TotalSeconds;
            if (now >= _nextRttReport)
            {
                _nextRttReport = now + 5.0;
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][rtt] transport request→reply avg={Interlocked.Read(ref _rttSumMs) / Math.Max(1, n)}ms (n={n}, last={rtt}ms) " +
                    $"| sendTo blocked: {Interlocked.Read(ref _sendBlockedMs)}ms total over {Interlocked.Read(ref _sendBlockedCount)} slow sends of {Interlocked.Read(ref _sendTotal)}");
            }
        }
        // Track the slot to put OUR data-replies on — but ONLY from inbound REQUESTS.
        //
        // This used to refresh from ANY inbound packet, which fixed a starvation bug but silently created a worse
        // one. A REQUEST's (id,seq) is a LIVE outstanding entry in our NAT's conntrack: replying to it is the one
        // shape RFC 5508 guarantees gets forwarded. A REPLY's (id,seq) is the OPPOSITE — that entry was CONSUMED
        // when the reply arrived, so answering it is answering something already matched, and most such packets are
        // dropped. MEASURED (21:08): slots=512, slotAge=0ms, qDepth=0 — the ring looked perfectly healthy while
        // DATA advanced only +2 per 5s, because every "slot" in it came from a reply and was already dead.
        //
        // So: a REQUEST refreshes the primary slot (the good, guaranteed-forwardable kind). A REPLY refreshes only a
        // SEPARATE fallback slot, used when this peer receives no requests at all — which genuinely happens: in the
        // 21:25 run the SERVER saw req=26/13/11 while the CLIENT saw req=0 for the whole run, so restricting slots
        // to requests alone left that side with nothing to send onto and the tunnel stalled outright. A reply-slot
        // is a poor slot, but a poor slot beats no slot.
        // REGRESSION FIX (cold start got ~3x slower). Restricting this to type-8 starved the FANOUT RING.
        //
        // `_heardReqs` feeds RecentHeardReqs(), which EmitFrameRedundant uses to spread each frame across
        // ~FRAME_FANOUT distinct holes. Filling it only from inbound REQUESTS means the side that receives
        // almost none (observed: req=0 for entire runs on one peer) ends up with a ring of 0-1 entries, so every
        // frame rides one hole instead of four. Steady-state throughput looks unchanged, but the WG handshake —
        // whose few critical packets need redundancy most — takes far longer to complete. That is exactly the
        // "same speed once up, 3x longer to start flowing" symptom.
        //
        // So: REQUESTS still set the primary slot (`_lastHeardReq`, the guaranteed-forwardable kind), but BOTH
        // types feed the fanout ring. A reply-derived slot is a worse bet per-hole, yet four mediocre holes beat
        // one good one for a packet that must not be lost.
        if (type == ICMP_ECHO_REQUEST) NoteHeardReq(id, seq);
        else
        {
            _lastHeardAny = (id << 16) | seq;
            NoteHeardSlot(id, seq);   // ring only — does NOT touch _lastHeardReq
        }

        // COUNT FIRST, REPORT SECOND. `_reqSeen` used to be incremented ~40 lines BELOW the ReportDeliveryStats()
        // call here, so every stats line reported the request count as of BEFORE the packet that triggered it. On a
        // peer whose inbound is almost entirely 18B keepalives (no data frames), ReportDeliveryStats is driven ONLY
        // from this rate-limited block — and since the rx-log gate (1s) and the stats gate (5s) are independent, the
        // reported delta sampled at arbitrary moments and systematically missed the request stream.
        // THAT is why one peer logged `[ICMP][rx] type=8` repeatedly while the same log line said `req=0`: the
        // requests were arriving and being counted, but the DELTA was computed at the wrong instant. Two of my own
        // counters disagreed and I trusted the wrong one for several rounds of debugging.
        if (_punched && type == ICMP_ECHO_REQUEST)
        {
            _lastReqRxUtc = DateTime.UtcNow;
            Interlocked.Increment(ref _reqSeen); // inbound type-8 = a live slot the peer just handed us
        }

        // Rate-limited RX visibility (~1/s): what TYPE + how big is the peer actually sending us? Tells us if the
        // responder is even hearing the pinger's requests, and whether the NAT rewrote the type.
        if (_punched && _rxLogSw.Elapsed.TotalSeconds >= _nextRxLog)
        {
            _nextRxLog = _rxLogSw.Elapsed.TotalSeconds + 1.0;
            bool hasMagic = payload.Length >= 3 && payload[0] == MAGIC[0] && payload[1] == MAGIC[1] && payload[2] == MAGIC[2];
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][rx] role={(_isPinger ? "P" : "R")} type={type} len={payload.Length} magic={hasMagic}");
            ReportDeliveryStats(); // tick the stats line even during a stuck handshake (so req=/wg= show without data)
        }

        // PROBE RESULT: did a LARGE unsolicited REQUEST from the peer cross the punched hole? Log type+len so we can
        // tell a large REQUEST (type 8) from a large REPLY (type 0) or the OS reflection of our own probe.
        if (_probeLargeReq && payload.Length >= 100)
        {
            bool isProbe = ContainsTag(payload, PROBETAG);
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                $"[ICMP][probe] rx LARGE type={type} len={payload.Length} probe={isProbe} " +
                $"({(type == ICMP_ECHO_REQUEST ? "REQUEST" : "reply")}) — {(type == ICMP_ECHO_REQUEST && isProbe ? "LARGE REQUEST CROSSES ✓" : "not a peer large-request")}");
        }

        // DATA-AS-MATCHED-REPLY (both roles, post-punch). The channel's ONE reliable delivery shape is an echo
        // REPLY matched to a request the receiver's NAT recently sent out (RFC 5508) — proven by the 1.1.1.1 test
        // (arbitrary large payloads cross as replies to your own requests) and the captures (unsolicited inbound
        // REQUESTS are dropped; only matched replies land). So we answer the peer's keepalive REQUESTS, echoing
        // their id+seq, carrying our queued data if any (else a keepalive reply). Both peers ping each other AND
        // both answer the other's pings with data → data rides the reply shape in BOTH directions.
        //
        // Reply to any inbound REQUEST (ICMP type-8) — NOT just REQTAG-tagged ones. THIS WAS THE THROUGHPUT BUG:
        // the old gate `ContainsTag(REQTAG)` only matched bare keepalive requests, but once data flows the peer's
        // requests CARRY DATA (MAGIC, not REQTAG) or are otherwise untagged, so we REJECTED ~60/s of perfectly good
        // live slots and answered almost none → our data couldn't get out → 2s ping. Proof it was a counting/gating
        // lie, not a dead channel: `req=0` in the counter WHILE ping still succeeded (data was crossing on the few
        // slots that leaked through) — user caught it ("they have to be arriving, look at the 2s ping"), and the
        // capture showed 60/s type-8 requests arriving the whole time. Keying on the ICMP TYPE (a request is type-8)
        // instead of our tag captures ALL of them. SAFE from the reply-to-reply amplification loop: that loop was
        // about replying to type-0 REPLIES; a type-8 is a REQUEST (the peer's NAT holds it as a live outstanding
        // slot), and replying to a request is exactly the intended request→reply flow, never a reply→reply cycle.
        if (_punched && type == ICMP_ECHO_REQUEST)
        {
            // SERVER SIDE of the client/server model (icmptunnel's server): the client's request just arrived, so
            // piggyback our queued data on the REPLY — immediately, on the capture thread. One request in → data out
            // in the same instant = ONE RTT, which is what makes real ICMP tunnels fast.
            //
            // (_lastReqRxUtc / _reqSeen are updated at the TOP of this method — count-before-report, see there.)

            // Drain up to DRAIN_PER_ITER frames onto THIS request's (id,seq). The NAT forwards ~one reply per
            // request, so extra copies here can be dropped — but a client sending a dense request stream gives us a
            // fresh slot every few ms, so the queue drains fast across successive requests. Sending a small burst
            // (rather than exactly one) lets a backlog (iperf, WG handshake) clear without waiting a request each.
            int replied = 0;
            for (; replied < DRAIN_PER_ITER && _txQueue.TryDequeue(out var frame); replied++)
                SendData(ICMP_ECHO_REPLY, id, seq, frame.Frame, frame.Data);
            if (replied == 0)
                SendTag(ICMP_ECHO_REPLY, id, seq, ACKTAG); // keepalive reply — keeps the client's flow alive
            // (Tried a MIRROR-REQUEST here — on hearing the peer's request, fire our own request on that same id to
            //  ride its hole. It did NOT work: the id we RECEIVE on is OUR NAT's inbound id, independent of the
            //  PEER's inbound id, so it can't make our unsolicited request cross to a symmetric NAT. Reverted — this
            //  is the fundamental symmetric-NAT wall, see [[project_icmp_symmetric_reply_model]].)
        }

        // During the punch, decide the hole is open. An explicit ACK is the clean signal, but the two peers
        // start their sweeps at DIFFERENT wall-clock times in the live mesh (each hits the Tier-2 branch on its
        // own discovery poll), so the ACK-tag exchange can race and one side times out while the other punched
        // (the observed split-brain). Hearing the peer AT ALL means our outbound reached them and their NAT is
        // forwarding to us on an id we can read — so establish on either an explicit ACK OR sustained hearing.
        if (!_punched)
        {
            bool ack = ContainsTag(payload, ACKTAG);
            int heard = Interlocked.Increment(ref _heardCount);
            if (ack || heard >= HEARD_TO_PUNCH)
            {
                _punched = true;
            }
            // Hammer ACKs back on the just-heard id to complete the handshake within the (bursty) window,
            // whether or not this specific packet was an ACK — hearing the peer at all means try to close it.
            // BOTH type-0 (reply) and type-8 (request) — some NATs only forward one type (matches icmp-channel.py).
            for (int i = 0; i < 12; i++)
            {
                SendTag(ICMP_ECHO_REPLY, id, seq, ACKTAG);
                SendTag(ICMP_ECHO_REQUEST, id, seq, ACKTAG);
            }
        }

        // Data frame: MAGIC + uint32 frame id + caller bytes.
        //
        // REFLECTION FILTER (critical): we carry caller data on type-8 echo REQUESTS. When our request reaches the
        // peer, their OS auto-generates a type-0 echo REPLY that copies our payload VERBATIM back to us — so the
        // sender sees its OWN data returning. We CANNOT simply reject all type-0, because on some NAT/stack pairs
        // (RCVALL directionality asymmetry) a peer's REAL data only ever arrives here as type-0. So instead we
        // reject by CONTENT: drop any inbound data frame whose exact bytes match a frame WE recently SENT (that's
        // a reflection of our own outbound); anything else is genuine peer data, whatever its ICMP type.
        if (payload.Length >= DATA_HEADER && StartsWith(payload, MAGIC))
        {
            uint frame = (uint)((payload[3] << 24) | (payload[4] << 16) | (payload[5] << 8) | payload[6]);
            int bodyLen = payload.Length - DATA_HEADER;
            if (bodyLen > 0)
            {
                var copy = payload.Slice(DATA_HEADER, bodyLen).ToArray();
                if (IsOwnSentFrame(copy))
                {
                    // Reflection of our own outbound (OS echo-reply). Ignore.
                }
                else if (MarkFrameSeen(frame))
                {
                    // De-dup by frame id: each frame is sprayed across the churning id space + reorders, so it
                    // arrives many times. Deliver each frame id exactly once (bounded seen-set).
                    // MEASUREMENT: which ICMP type actually DELIVERED this unique data frame — type-8 request
                    // (spray-and-pray to a live hole) vs type-0 reply (matched to the peer's request). Reported
                    // per ~5s window (below) so we see the type SPLIT and whether type-0 tapers over time.
                    if (type == ICMP_ECHO_REQUEST) Interlocked.Increment(ref _rxDataType8);
                    else Interlocked.Increment(ref _rxDataType0);
                    _lastDataRxUtc = DateTime.UtcNow; // real data arrived → keep the fast ping rate for ActiveWindow
                    // WG handshake progress: first byte 0x01=init 0x02=response 0x03=cookie 0x04=TRANSPORT. If we only
                    // ever see 01/02 repeating, the handshake never completes → no data → no ping. 0x04 = handshake
                    // done, real traffic flowing. Count per type so the rx-stats line shows whether we reach 0x04.
                    if (copy.Length > 0)
                    {
                        byte w = copy[0];
                        if (w == 1) Interlocked.Increment(ref _wgInit);
                        else if (w == 2) Interlocked.Increment(ref _wgResp);
                        else if (w == 4) Interlocked.Increment(ref _wgData);
                    }
                    ReportDeliveryStats();
                    try { PacketReceived?.Invoke(copy); } catch { }
                }
            }
        }
    }

    // Delivery-type measurement: how many UNIQUE inbound data frames arrived via type-8 (spray) vs type-0 (matched
    // reply), reported per ~5s window so we can see the split AND whether type-0 tapers as the reply-match ring
    // ages. This tells us if the type-8 full-range spray is load-bearing or vestigial (→ cut it, kill the ban).
    private long _rxDataType8, _rxDataType0, _lastReport8, _lastReport0;
    private long _wgInit, _wgResp, _wgData;  // WG msg-type counters: 0x01 init / 0x02 response / 0x04 transport
    private long _reqSeen, _lastReqSeen;     // inbound REQTAG requests = our deliverable-slot supply (throughput ceiling)
    private readonly Stopwatch _reportSw = Stopwatch.StartNew();
    private double _nextReport = 5.0;
    private void ReportDeliveryStats()
    {
        double now = _reportSw.Elapsed.TotalSeconds;
        if (now < _nextReport) return;
        _nextReport = now + 5.0;
        long t8 = Interlocked.Read(ref _rxDataType8), t0 = Interlocked.Read(ref _rxDataType0);
        long d8 = t8 - _lastReport8, d0 = t0 - _lastReport0;
        _lastReport8 = t8; _lastReport0 = t0;
        long rq = Interlocked.Read(ref _reqSeen); long drq = rq - _lastReqSeen; _lastReqSeen = rq;
        // req/5s = inbound REQTAG requests = HOW MANY DELIVERABLE SLOTS the peer gives us (throughput ceiling: we
        // can deliver at most one frame per request). If this is LOW (e.g. ~10/5s) that IS the latency cause — the
        // peer's requests aren't reaching us fast enough to carry our data back. wgData(0x04)>0 = handshake done.
        // SLOT DIAGNOSTICS. `req=0` across every run means the peer's steady-state echo REQUESTS never reach us, so
        // the reactive drain in OnInboundIcmp never fires and ALL our data must go out as replies onto slots we
        // learned from inbound packets. These counters answer the question that decides the next fix: how many
        // DISTINCT slots do we actually have to reply onto, and is the one we use going stale?
        //   slots     = distinct (id,seq) in the ring right now (our real fan-out width)
        //   slotAgeMs = how long ago _lastHeardReq was refreshed (large ⇒ we're replying onto a dead slot)
        //   txSent    = frames we handed to EmitFrameRedundant in this window (what we TRIED to send)
        long tx = Interlocked.Read(ref _txFramesSent); long dtx = tx - _lastTxFramesSent; _lastTxFramesSent = tx;
        double slotAgeMs = _lastHeardReqUtc == DateTime.MinValue
            ? -1 : (DateTime.UtcNow - _lastHeardReqUtc).TotalMilliseconds;
        NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
            $"[ICMP][rx-stats] last5s: type8={d8} type0={d0} req={drq}  total type0={t0}  " +
            $"wg: init={Interlocked.Read(ref _wgInit)} resp={Interlocked.Read(ref _wgResp)} DATA={Interlocked.Read(ref _wgData)}" +
            $" | slots={_heardReqCount} slotAge={slotAgeMs:F0}ms txFrames={dtx} qDepth={_txQueue.Count}");
    }

    // Hashes of caller frame bodies we've recently SENT, to detect OS-reflected copies of our own outbound.
    private readonly System.Collections.Generic.HashSet<int> _sentBodyHashes = new();
    private readonly System.Collections.Generic.Queue<int> _sentBodyOrder = new();
    private readonly object _sentLock = new();
    private const int SENT_WINDOW = 64;

    private static int BodyHash(byte[] body)
    {
        // FNV-1a over the body — stable, allocation-free, good enough to distinguish our frames from the peer's.
        unchecked { int h = (int)2166136261; foreach (var b in body) { h = (h ^ b) * 16777619; } return h; }
    }

    private void NoteSentBody(byte[] body)
    {
        int h = BodyHash(body);
        lock (_sentLock)
        {
            if (_sentBodyHashes.Add(h))
            {
                _sentBodyOrder.Enqueue(h);
                if (_sentBodyOrder.Count > SENT_WINDOW) _sentBodyHashes.Remove(_sentBodyOrder.Dequeue());
            }
        }
    }

    private bool IsOwnSentFrame(byte[] body)
    {
        int h = BodyHash(body);
        lock (_sentLock) { return _sentBodyHashes.Contains(h); }
    }

    // Recently-delivered frame ids, for spray/reorder de-dup. Bounded FIFO; returns true iff `frame` is new.
    private readonly System.Collections.Generic.HashSet<uint> _seenFrames = new();
    private readonly System.Collections.Generic.Queue<uint> _seenOrder = new();
    private readonly object _seenLock = new();
    private const int SEEN_WINDOW = 1024;

    private bool MarkFrameSeen(uint frame)
    {
        lock (_seenLock)
        {
            if (!_seenFrames.Add(frame)) return false;
            _seenOrder.Enqueue(frame);
            if (_seenOrder.Count > SEEN_WINDOW) _seenFrames.Remove(_seenOrder.Dequeue());
            return true;
        }
    }

    private void NoteHeardId(ushort id)
    {
        lock (_idLock)
        {
            _heardIds.Add(id);
            if (_heardIds.Count > _idWindow) _heardIds.RemoveAt(0);
        }
    }

    // ---- ICMP packet construction + send ----

    /// <summary>Send a tag-only control packet (REQ / ACK): ICMP payload = just the tag bytes.</summary>
    private void SendTag(byte type, ushort id, ushort seq, byte[] tag)
    {
        Span<byte> payload = stackalloc byte[tag.Length];
        tag.CopyTo(payload);
        EmitIcmp(type, id, seq, payload);
    }

    /// <summary>Send a caller data frame of the given ICMP type/id/seq: payload = MAGIC(3)+uint32 frame+bytes.
    /// The role model chooses the type: the PINGER sends type-8 REQUESTS (fixed id, incrementing seq); the
    /// RESPONDER sends type-0 REPLIES echoing the pinger's request id+seq. One packet, one type — a clean ping.</summary>
    private void SendData(byte type, ushort id, ushort seq, uint frame, ReadOnlySpan<byte> data)
    {
        var payload = new byte[DATA_HEADER + data.Length];
        payload[0] = MAGIC[0]; payload[1] = MAGIC[1]; payload[2] = MAGIC[2];
        payload[3] = (byte)(frame >> 24); payload[4] = (byte)(frame >> 16);
        payload[5] = (byte)(frame >> 8); payload[6] = (byte)frame;
        data.CopyTo(new Span<byte>(payload, DATA_HEADER, data.Length));
        _lastDataTxUtc = DateTime.UtcNow; // we're actively moving data → hold the fast ping rate for ActiveWindow
        EmitIcmp(type, id, seq, payload);
    }

    // RELIABILITY CORE: emit ONE caller frame across MANY independent holes so it crosses even when most holes are
    // bad. The channel-quality variance is the real enemy: a frame sent onto a single (id,seq) is a coin-flip
    // (some punches land on holes that barely pass anything → WG handshake never completes → init/resp loop). Here
    // we send the frame as a reply onto (a) the just-arrived request's (id,seq) — guaranteed-live — AND (b) each of
    // the most-recent DISTINCT heard requests (a valid outstanding NAT mapping for a short window). The receiver
    // de-dups by frame id, so duplicates are free; we only need ONE of the N copies to survive. This is the fix for
    // the stuck-handshake variance — critical handshake packets now ride ~FANOUT holes at once. NOTE: this SAMPLES
    // the heard-request ring (RecentHeardReqs, non-consuming) — it does NOT dequeue, so it can't drain the ring dry
    // (that was the earlier regression). Bounded fanout keeps the on-wire cost sane.
    //
    // FANOUT SIZING: this is NOT "more copies" — it's the SAME ~4-copy budget the old code already sent (DATA_SENDS),
    // just spread across DISTINCT holes instead of piling all onto ONE (id,seq) where the NAT forwarded ~one and
    // wasted the rest. If a single hole delivers ~p, N independent holes deliver 1-(1-p)^N: at p≈0.5 that's 2→75%,
    // 3→87%, 4→94% — the knee is ~4, past which it's just wasted packets. 4 it is; raise ONLY if bad-hole punches
    // still stall (and then only to ~6), lower if it reads as a flood.
    private const int FRAME_FANOUT = 4;
    private void EmitFrameRedundant(TxFrame frame, ushort liveId, ushort liveSeq)
    {
        SendData(ICMP_ECHO_REPLY, liveId, liveSeq, frame.Frame, frame.Data); // the guaranteed-live slot
        int live = (liveId << 16) | liveSeq;
        var recent = RecentHeardReqs(FRAME_FANOUT);
        foreach (var hr in recent)
        {
            if (hr == live) continue; // already sent onto the live slot
            SendData(ICMP_ECHO_REPLY, (ushort)(hr >> 16), (ushort)(hr & 0xFFFF), frame.Frame, frame.Data);
        }
    }

    /// <summary>Frames the ICMP header (type/code/id/seq/checksum) around a payload and sends it raw.</summary>
    private void EmitIcmp(byte type, ushort id, ushort seq, ReadOnlySpan<byte> payload)
    {
        var sock = _sendSock;
        if (sock == null) return;

        int total = 8 + payload.Length;
        var pkt = new byte[total];
        pkt[0] = type; pkt[1] = 0;                       // type, code
        // pkt[2..3] checksum, filled below
        pkt[4] = (byte)(id >> 8); pkt[5] = (byte)id;     // identifier
        pkt[6] = (byte)(seq >> 8); pkt[7] = (byte)seq;   // sequence
        payload.CopyTo(new Span<byte>(pkt, 8, payload.Length));

        // ICMP checksum over the whole message.
        uint sum = 0;
        for (int i = 0; i < total; i += 2)
            sum += (ushort)((pkt[i] << 8) | (i + 1 < total ? pkt[i + 1] : 0));
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        ushort cksum = (ushort)~sum;
        pkt[2] = (byte)(cksum >> 8); pkt[3] = (byte)cksum;

        try
        {
            // Measure how long the actual send blocks (lock contention + kernel/NIC queue). If this is ~0 the
            // ~900ms RTT is NOT our send path (it's the peer's turnaround / the wire); if it's large, we're
            // self-inflicting the delay here (buffer backlog or _sendLock serialization).
            long t0 = _rttSw.ElapsedMilliseconds;
            lock (_sendLock) { sock.SendTo(pkt, _sendTo); }
            long blockedMs = _rttSw.ElapsedMilliseconds - t0;
            if (blockedMs > 0)
            {
                Interlocked.Add(ref _sendBlockedMs, blockedMs);
                Interlocked.Increment(ref _sendBlockedCount);
            }
            Interlocked.Increment(ref _sendTotal);
        }
        catch (Exception ex)
        {
            // transient send failures are absorbed by the lossy-spray model; but surface failures on
            // data-sized packets (>60B) — those are the caller frames we can't afford to silently lose.
            if (total > 60)
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][tx] EmitIcmp {total}B FAILED: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void Pace(Stopwatch sw, ref double nextSend) => PaceTo(sw, ref nextSend, _sendInterval);

    // Post-punch FAST send rate (packets/sec), used ONLY while data is actively flowing (see the adaptive pacing
    // in the send loop). Much lower than the punch rate (1500) — we're no longer birthday-hunting, just keeping the
    // peer's reply-match request ring fed while a WG handshake / traffic burst moves. At rest the loop uses
    // IDLE_INTERVAL instead (a trickle), so this rate only applies for the ~seconds data is in flight. Accurate
    // because PaceTo spin-waits the sub-ms remainder (Thread.Sleep alone can't hit this rate).
    private const double POST_PUNCH_INTERVAL = 1.0 / 250.0;

    private void PaceTo(Stopwatch sw, ref double nextSend, double interval)
    {
        if (interval <= 0) return;
        nextSend += interval;
        double remain = nextSend - sw.Elapsed.TotalSeconds;
        if (remain <= 0) return;
        if (remain > 0.002) Thread.Sleep((int)((remain - 0.001) * 1000));
        while (sw.Elapsed.TotalSeconds < nextSend) Thread.SpinWait(50);
    }

    // Like PaceTo but INTERRUPTIBLE by newly-queued data: sleeps toward the deadline in short chunks and returns
    // early the instant _txQueue becomes non-empty. At a low keepalive rate (10/s → 100ms interval) a blocking pace
    // would make a ping's WG packet queued mid-sleep wait up to the full interval before the loop drains it — that
    // wait is pure added latency. Breaking out on new data lets the loop drain it immediately instead.
    private void PaceToOrData(Stopwatch sw, ref double nextSend, double interval)
    {
        if (interval <= 0) return;
        nextSend += interval;
        while (true)
        {
            if (_stopped || !_txQueue.IsEmpty) { nextSend = sw.Elapsed.TotalSeconds; return; } // new data → drain now
            double remain = nextSend - sw.Elapsed.TotalSeconds;
            if (remain <= 0) return;
            if (remain > 0.004) Thread.Sleep(2);                 // short chunk so we notice queued data within ~2ms
            else { while (sw.Elapsed.TotalSeconds < nextSend && _txQueue.IsEmpty) Thread.SpinWait(50); return; }
        }
    }

    private static bool StartsWith(ReadOnlySpan<byte> buf, byte[] tag)
    {
        if (buf.Length < tag.Length) return false;
        for (int i = 0; i < tag.Length; i++) if (buf[i] != tag[i]) return false;
        return true;
    }

    private static bool ContainsTag(ReadOnlySpan<byte> buf, byte[] tag)
    {
        int end = buf.Length - tag.Length;
        for (int i = 0; i <= end; i++)
        {
            bool m = true;
            for (int j = 0; j < tag.Length; j++) if (buf[i + j] != tag[j]) { m = false; break; }
            if (m) return true;
        }
        return false;
    }

    public void Dispose()
    {
        _stopped = true;
        try { _capture?.Dispose(); } catch { }
        try { _sendSock?.Dispose(); } catch { }
        _sendSock = null;
        try { _sendThread?.Join(1500); } catch { }
        _sendThread = null;
    }
}
