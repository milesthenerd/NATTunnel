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
    // Data MAGIC must NOT be a prefix of the punch tags (REQTAG/ACKTAG), or StartsWith(MAGIC) matches openers too.
    private static readonly byte[] MAGIC = Encoding.ASCII.GetBytes("ICD");   // data-packet marker (distinct from tags)
    private static readonly byte[] REQTAG = Encoding.ASCII.GetBytes("ICH-REQ");
    private static readonly byte[] ACKTAG = Encoding.ASCII.GetBytes("ICH-ACK");

    private const byte ICMP_ECHO_REQUEST = 8;
    private const byte ICMP_ECHO_REPLY = 0;   // reverse-ACK is a type-0 reply, matching icmp-channel.py
    private const ushort PING_ID = 0x4a01;    // fixed id the pinger uses post-punch (like a real ping's identifier)
    private const int DATA_HEADER = 3 + 4; // MAGIC(3) + uint32 frame id
    // Hearing the peer this many times (any tagged packet) is enough to declare the hole open, even with no
    // explicit ACK — the two sides' punch windows don't always overlap cleanly.
    private const int HEARD_TO_PUNCH = 8;

    // --- configuration (defaults are the validated values) ---
    private readonly IPEndPoint _peerEndpoint;
    private readonly IPAddress _peer;
    // CLIENT/SERVER role, assigned DETERMINISTICALLY by peer-id ordinal (caller compares GUIDs) so both ends start
    // on opposite roles with zero coordination. An inferred role ("did I hear a request recently?") is unstable:
    // both sides can evaluate it the same way at the same time and both become CLIENT, deadlocking.
    //
    // The initial assignment can still be backwards — only ONE direction's echo REQUESTS actually crosses a
    // symmetric-NAT pair, and which one is a property of the NAT pair, not the peer-id ordering. That's fine: role
    // only controls keepalive-REQUEST RATE (how many reply-slots we hand the peer), not how data is sent — both
    // roles drain data as matched type-0 replies, the only shape this channel reliably delivers. A wrong role is
    // merely suboptimal, not fatal.
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

        // DIAGNOSTIC PROBE: after punch, send a LARGE (~200B) data-carrying echo REQUEST at ~3/sec and log whether
        // the peer receives large REQUESTS (vs only replies). Off in normal operation.
        // File-gated, not env-gated: the GUI runs elevated, and an elevated process doesn't inherit an env var set
        // in an unelevated shell, so an env gate would silently never fire.
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
        // Resolve the local source IP that routes to the peer (UDP connect sends nothing; it just makes the OS
        // pick the egress interface). Binding the raw send socket to this forces the right NIC — WARP/Tailscale-aware.
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
            // Small send buffer on purpose — bufferbloat is latency. A 1MB buffer (sized for the old 1500/s punch
            // firehose) fills faster than the NIC drains it at today's ~60/s steady state, adding pure queueing
            // delay (measured ~860ms of self-inflicted RTT). If large-packet starvation ever returns, fix it by
            // pacing the sender, not by growing the buffer.
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

        // PUNCH: full-range 16-bit id sweep of echo REQUESTS + reverse-ACK the recently heard ids (type-0 reply,
        // ACK-tagged), until the hole opens (a heard ACK flips _punched in OnInboundIcmp) or timeout. Full range is
        // essential: a CGNAT rewrites the id anywhere in 0-65535, so a narrow window never collides.
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
        // Don't stay on the full-range sweep or switch to a fixed "lock set" post-punch — a fixed set is a hole
        // the CGNAT never forwards (it rewrites the id per flow), and stopping the sweep kills the holes. Instead,
        // post-punch uses a normal ping-session shape (see below): one fixed id, request/reply, data-as-reply.
        punchedTcs.TrySetResult(true);
        try { Punched?.Invoke(); } catch { }

        // POST-PUNCH steady state replicates a normal ping session. The full-range sweep was only needed to punch
        // (birthday-hunt the CGNAT-rewritten id); continuing it looks like a port scan (MAC-ban risk) and isn't
        // needed once a hole is open. Data rides matched type-0 replies (see OnInboundIcmp); this loop is keepalive.
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

            // CLIENT/SERVER MODEL: client drives a dense request stream (its reply-vehicle); server replies
            // reactively in OnInboundIcmp. Role is DETERMINISTIC by peer id, not inferred from traffic — an
            // inferred role is unstable (both sides can independently flip to CLIENT at once and deadlock).
            //
            // Both sides still send requests, only the rate differs: the server also trickles slowly so the
            // reverse direction never goes fully silent if it turns out to be the direction that actually crosses.
            if (!_loggedServerRole)
            {
                _loggedServerRole = true;
                NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
                    $"[ICMP][role] {(_isClient ? "CLIENT (dense request driver)" : "SERVER (sparse requests; data rides replies)")}");
            }

            // (A SERVER→CLIENT "backwards role rescue" was tried and removed — promoting to CLIENT moved that side
            //  onto the unsolicited-request path, which doesn't deliver. Role was never the problem; data shape was.)

            // DATA GOES OUT AS MATCHED REPLIES, NEVER AS UNSOLICITED REQUESTS: an unsolicited inbound echo REQUEST
            // has no outstanding entry in the peer's symmetric NAT and is dropped (RFC 5508). Drain onto recently-
            // heard (id,seq) slots as type-0 REPLIES via EmitFrameRedundant, fanning across ~FRAME_FANOUT distinct
            // live holes (a strict NAT forwards ~one reply per request, so distinct slots buy reliability, not
            // repeat copies on one slot). Keepalive REQUESTS still go out below to keep supplying the peer slots.
            Interlocked.Increment(ref _drainLoopIters);
            int sent = 0;
            for (; sent < DRAIN_PER_ITER && TryDequeueTxFrame(out var frame); sent++)
            {
                // Prefer a REQUEST-derived slot (live NAT entry, RFC 5508) while plausibly fresh. On a req=0 peer
                // _lastHeardReq is set once at punch time and never refreshes, so an unconditional preference
                // would pin us to an hours-stale slot while _lastHeardAny stays current.
                bool reqIsFresher = _lastHeardReq >= 0 &&
                    (_lastHeardAny < 0 || _lastHeardReqUtc >= _lastHeardAnyUtc - STALE_REQ_SLOT);
                long slot = reqIsFresher ? _lastHeardReq : (_lastHeardAny >= 0 ? _lastHeardAny : _lastHeardReq);
                if (slot < 0)
                {
                    // Nothing heard from the peer yet. Requeue onto the queue it CAME FROM — enqueueing
                    // unconditionally to _txQueue would demote handshake frames out of _priorityTxQueue.
                    bool wasHandshake = frame.Data.Length > 0 && frame.Data[0] >= 1 && frame.Data[0] <= 3;
                    (wasHandshake ? _priorityTxQueue : _txQueue).Enqueue(frame);
                    break;
                }
                // No "hold the frame if the slot is stale" guard here: tried it, and it stalled the tunnel
                // outright (on a req=0 peer every slot is always stale). A stale slot delivers low-probability;
                // refusing to send delivers zero.
                Interlocked.Increment(ref _txFramesSent);
                // WG handshake packets (0x01/0x02/0x03) get a wider fanout: the priority queue fixes send ORDER,
                // not delivery odds. They're tiny and rare, so the extra copies are nearly free.
                bool isHandshake = frame.Data.Length > 0 && frame.Data[0] >= 1 && frame.Data[0] <= 3;
                int fanout = isHandshake ? HANDSHAKE_FANOUT : FRAME_FANOUT;
                EmitFrameRedundant(frame, (ushort)(slot >> 16), (ushort)(slot & 0xFFFF), fanout);
            }
            // Hit the per-iteration cap with more still queued => the pacer, not the peer/NAT, stopped us this
            // iteration. High drainFull + qDepth>0 => pacing-limited; low drainFull + qDepth>0 => slot-supply-limited.
            if (sent >= DRAIN_PER_ITER && !_txQueue.IsEmpty)
                Interlocked.Increment(ref _drainFullIters);
            // ALWAYS send the keepalive REQUEST, never gated on "we had nothing else to send" — it is the ONLY
            // thing that gives the PEER live (id,seq) slots to put its data-replies on (its reactive drain in
            // OnInboundIcmp fires only on inbound type-8). Gating on idle starves the channel exactly when it's
            // busiest and symmetrically starves us back.
            //
            // MUST sweep the id space — a fixed id never crosses a symmetric CGNAT (it rewrites the id per flow,
            // same reason the punch itself must sweep). Sweep at the same steady rate so this stays ping-shaped,
            // not scan-shaped (unlike the 1500/s full-range punch, which risks a MAC ban).
            ushort kaId = (ushort)(_kaSweep++ & 0xFFFF);
            SendTag(ICMP_ECHO_REQUEST, kaId, pingSeq++, REQTAG);
            // Pace at the dense rate whenever EITHER side has traffic to move; trickle only when genuinely idle.
            // Keying on activity in either direction (not just our own queue) lets a trickling server still supply
            // a busy client with a dense slot rate — the server can't otherwise know the client is backed up.
            // An unfinished WG handshake counts as active, holding dense through the sparse gaps between retries.
            bool handshaking = !_priorityTxQueue.IsEmpty ||
                               (Interlocked.Read(ref _wgData) == 0 &&
                                (DateTime.UtcNow - _handshakeSeenUtc) < HandshakeActiveWindow);
            bool active = !_txQueue.IsEmpty ||
                          (DateTime.UtcNow - _lastDataRxUtc) < ActiveWindow ||
                          (DateTime.UtcNow - _lastDataTxUtc) < ActiveWindow;
            PaceTo(sw2, ref nextSend2, (_isClient || active || handshaking) ? STEADY_INTERVAL : SERVER_TRICKLE_INTERVAL);
        }
    }

    // Server still emits a slow request trickle so the reverse direction never goes fully silent if the client's
    // requests turn out to be the ones this NAT pair drops. Far below the client's dense rate.
    private const double SERVER_TRICKLE_INTERVAL = 1.0 / 4.0;
    // Last time we saw a WG handshake packet in either direction. Keeps the dense rate up across the gaps between
    // WG's retries, which would otherwise let the server fall back to the trickle mid-handshake.
    private DateTime _handshakeSeenUtc = DateTime.MinValue;
    private static readonly TimeSpan HandshakeActiveWindow = TimeSpan.FromSeconds(30);
    private DateTime _lastReqRxUtc = DateTime.MinValue;   // last time we heard a peer REQUEST (drives the promotion)
    private DateTime _firstHeardUtc = DateTime.MinValue;  // first time we heard the peer AT ALL (promotion baseline)
    private bool _loggedServerRole; // set once we've logged the role at startup


    // Steady-state keepalive-request cadence. DO NOT RAISE to chase throughput: at 128/s wire traffic hit ~140
    // Mbit/s of raw ICMP to carry ~28 Mbit/s payload (FRAME_FANOUT multiplies every frame) and got the connection
    // ISP-policed for hours afterward. Too-high rates also crowd out WG's handshake completion packet. Tune
    // cautiously around 60/s.
    private const double STEADY_INTERVAL = 1.0 / 60.0;
    private DateTime _lastDataRxUtc = DateTime.MinValue;
    private DateTime _lastDataTxUtc = DateTime.MinValue;

    // How long after the last data packet (either direction) we keep paying the dense keepalive rate. Long enough
    // to span a WG handshake round trip on a slow channel, short enough that idle drops back to the trickle quickly.
    private static readonly TimeSpan ActiveWindow = TimeSpan.FromSeconds(3);


    private readonly Stopwatch _rttSw = Stopwatch.StartNew();
    // Lock-wait vs syscall, split (see EmitIcmp). Reported as per-window averages in rx-stats so a degradation
    // can be attributed: lockWait spiking => _sendLock contention with the RX capture thread (fixable here);
    // syscall spiking => the kernel/NIC send path is slow (not contention); both flat => the send path is fine
    // and the delay is the peer's turnaround or the wire.
    private long _lockWaitTicks, _lastLockWaitTicks;
    private long _syscallTicks, _lastSyscallTicks;

    private long _txFrameCounter = -1;

    // (DATA_SENDS, a removed redundancy constant, never actually did what its comment claimed. Frame redundancy
    //  now comes from EmitFrameRedundant/FRAME_FANOUT, which spreads copies across DISTINCT live slots.)

    // Max frames the send-loop drains per iteration onto the refreshing _lastHeardReq. Bounded on purpose — a full
    // unbounded drain onto one stale slot is the greedy-drain regression. This is a HARD frame-rate ceiling:
    // DRAIN_PER_ITER / STEADY_INTERVAL. Raising it costs no extra wire traffic (we only emit what WG queued), so it
    // widens the drain without touching the ICMP volume that got the connection ISP-policed.
    private const int DRAIN_PER_ITER = 128;

    // Separate, SMALL cap for the reactive drain in OnInboundIcmp (see its call site) — that loop runs
    // synchronously on the Npcap capture thread once per inbound request, so a large value here stalls RX
    // processing and fights the main drain loop for _sendLock. Kept independent of DRAIN_PER_ITER on purpose:
    // the two loops have opposite cost profiles (this one blocks the packet-capture thread; DRAIN_PER_ITER
    // only paces a background send-loop thread).
    private const int RX_THREAD_DRAIN_CAP = 8;

    // A caller frame awaiting transmission on the sweep.
    private sealed class TxFrame { public uint Frame; public byte[] Data; }
    private readonly System.Collections.Concurrent.ConcurrentQueue<TxFrame> _txQueue = new();

    // BUFFERBLOAT BOUND. _txQueue was unbounded, so when WG offered frames faster than the pacer could deliver,
    // the excess accumulated as standing queue depth — ping inflated under load and TCP inside the tunnel never
    // saw a loss signal, so it kept growing its window into the buffer instead of settling at the real rate.
    //
    // Bufferbloat is SUSTAINED depth, not peak; a brief burst that drains again immediately costs little. Size
    // for bursts, not backlog. Judge changes on ping-under-load staying flat AND qDepth returning near zero
    // between bursts, not on throughput alone (throughput numbers below the bound are partly inflated by it).
    private const int TX_QUEUE_MAX = 1024;

    // WG handshake packets (first byte 0x01 init / 0x02 response / 0x03 cookie) ride this separate FIFO, drained
    // completely before _txQueue each iteration. Without it they queue behind bulk data/keepalives — a handshake
    // init can sit behind hundreds of data frames and lose the retry race before its predecessor's reply lands.
    // Tiny and rare, so this costs nothing when idle and only matters exactly when it needs to.
    private readonly System.Collections.Concurrent.ConcurrentQueue<TxFrame> _priorityTxQueue = new();

    /// <summary>
    /// Queues a caller datagram for transmission over the punched channel, best-effort. No-op until
    /// <see cref="IsPunched"/>. The frame is carried on the continuous full-range sweep (see PunchAndServe),
    /// repeated across the churning id space so a copy crosses the lossy channel; the receiver de-dups by frame
    /// id. Reliability/ordering beyond "at least one copy crosses" is the caller's concern.
    /// </summary>
    public void Send(ReadOnlySpan<byte> data)
    {
        if (!_punched || _stopped)
            return;
        uint frame = (uint)Interlocked.Increment(ref _txFrameCounter);
        var body = data.ToArray();
        NoteSentBody(body); // remember it so we can drop the OS-reflected echo-reply copy that comes back to us
        var txFrame = new TxFrame { Frame = frame, Data = body };
        // WG handshake init/response/cookie (first byte 1/2/3) jump the line — see _priorityTxQueue.
        bool isHandshake = body.Length > 0 && body[0] >= 1 && body[0] <= 3;
        if (isHandshake) _handshakeSeenUtc = DateTime.UtcNow;   // hold the dense rate while WG is negotiating
        if (isHandshake)
        {
            // NEVER bounded: handshake frames are tiny and rare, and dropping one costs a full retry round.
            _priorityTxQueue.Enqueue(txFrame);
        }
        else
        {
            // Drop the OLDEST, not this new one (see TX_QUEUE_MAX). Head-drop is what makes this work: the
            // frames TCP is actually waiting on are the newest, so discarding stale head-of-line frames turns a
            // latency problem into an immediate, honest loss signal. Tail-drop would instead punish exactly the
            // frames that would have advanced the window, and keep the stale queue intact.
            _txQueue.Enqueue(txFrame);
            while (_txQueue.Count > TX_QUEUE_MAX && _txQueue.TryDequeue(out _))
                Interlocked.Increment(ref _txQueueOverflowDrops);
        }
    }

    /// <summary>byte[] overload — matches an Action&lt;byte[]&gt; delegate (e.g. the WireGuard proxy's send hook).</summary>
    public void Send(byte[] data) => Send(new ReadOnlySpan<byte>(data));

    /// <summary>Dequeues the next frame to send, preferring _priorityTxQueue (WG handshake packets) completely
    /// before touching _txQueue (bulk data/keepalives) — see _priorityTxQueue for why.</summary>
    private bool TryDequeueTxFrame(out TxFrame frame)
        => _priorityTxQueue.TryDequeue(out frame) || _txQueue.TryDequeue(out frame);

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
    // MUST be long, packed with an UNSIGNED shift: holds (id << 16) | seq with -1 as the "nothing heard yet"
    // sentinel, so as an int any id >= 0x8000 sets the sign bit and a valid slot reads as the sentinel — the
    // drain loop's `if (slot < 0)` then re-queues every frame and emits nothing. Ids sweep, so that presented
    // as a cyclic self-healing stall and looked exactly like NAT behaviour.
    private long _lastHeardReq = -1; // fallback when the ring runs dry

    private DateTime _lastHeardReqUtc = DateTime.MinValue; // when _lastHeardReq was last refreshed (staleness probe)
    // How far behind _lastHeardAny's freshness _lastHeardReq is allowed to lag before we defer to the fresher
    // reply-derived slot. Generous on purpose (unlike the reverted ~2s refuse-to-send guard, this never blocks a
    // send — it only picks which slot — so there's no stall risk in setting it loosely).
    private static readonly TimeSpan STALE_REQ_SLOT = TimeSpan.FromSeconds(5);
    private long _txFramesSent, _lastTxFramesSent;         // frames handed to EmitFrameRedundant (attempted sends)
    private uint _kaSweep;                                 // sweeping id for keepalive requests (a fixed id never crosses)
    // Same sign-bit trap as _lastHeardReq — long, not int. On a peer receiving no type-8 requests this is the
    // ONLY usable slot source. (Not volatile: invalid on long, and a torn read costs at most one frame.)
    private long _lastHeardAny = -1;                       // fallback slot from an inbound REPLY (used when req=0)
    private DateTime _lastHeardAnyUtc = DateTime.MinValue;  // when _lastHeardAny was last refreshed (freshness compare vs _lastHeardReqUtc)

    // PACING-VS-SLOT-SUPPLY instrumentation (see ReportDeliveryStats): _drainLoopIters/_drainFullIters measure
    // whether the client drain loop (below) is pacer-capped (queue still non-empty after DRAIN_PER_ITER) or has
    // spare headroom; _wirePkts counts actual EmitIcmp calls (wire packets, = attempted frames x FRAME_FANOUT-ish).
    private long _drainLoopIters, _lastDrainLoopIters;      // while(!_stopped) iterations of the send loop
    private long _drainFullIters, _lastDrainFullIters;      // iterations where the for-loop hit DRAIN_PER_ITER with queue still non-empty
    private long _wirePkts, _lastWirePkts;                  // raw EmitIcmp calls (actual wire packets, post-fanout)
    private long _lastWgOutPackets;                         // previous PeerProxyListener.WgToProxyPackets (per-window delta)
    // Head-drops forced by TX_QUEUE_MAX. Nonzero under load is EXPECTED and healthy — it is the backpressure
    // signal doing its job. A flat zero while ping inflates means the bound is too high to be biting.
    private long _txQueueOverflowDrops, _lastTxQueueOverflowDrops;

    private void NoteHeardReq(ushort id, ushort seq)
    {
        // ((uint)id << 16) — unsigned shift, then widened to long, so ids >= 0x8000 stay POSITIVE. See the
        // sign-bit note on _lastHeardReq.
        long v = ((uint)id << 16) | seq;
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
        // The ring stores the same packed value as an int and is only ever unpacked by shifting, so the sign
        // bit is harmless there; only the sentinel-compared fields needed widening. Narrow back deliberately.
        return unchecked((int)_lastHeardReq);
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
        if (all.Length == 0)
            return _lastHeardReq >= 0 ? new[] { unchecked((int)_lastHeardReq) } : System.Array.Empty<int>();
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

        // Track the slot to put OUR data-replies on. A REQUEST's (id,seq) is a LIVE outstanding entry in our
        // NAT's conntrack — replying to it is the shape RFC 5508 guarantees gets forwarded. A REPLY's (id,seq) is
        // the opposite: that entry was already consumed, so answering it mostly gets dropped. So a REQUEST
        // refreshes the primary slot; a REPLY refreshes only a separate fallback slot (used when this peer
        // receives no requests at all — a poor slot beats no slot).
        //
        // BOTH types still feed the fanout ring (`_heardReqs`, used by RecentHeardReqs/EmitFrameRedundant):
        // restricting the ring to REQUESTS-only starves it on a peer that receives few requests, so every frame
        // rides one hole instead of several — the WG handshake in particular needs that redundancy to complete
        // quickly.
        if (type == ICMP_ECHO_REQUEST) NoteHeardReq(id, seq);
        else
        {
            _lastHeardAny = ((uint)id << 16) | seq;   // unsigned shift — see the sign-bit note on _lastHeardReq
            _lastHeardAnyUtc = DateTime.UtcNow;
            NoteHeardSlot(id, seq);   // ring only — does NOT touch _lastHeardReq
        }

        // Count _reqSeen before ReportDeliveryStats can run (below), not after — reporting before counting
        // sampled the delta at the wrong instant and systematically under-reported the request rate.
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
            // id/seq included to catch a NAT silently re-mapping mid-session (cyclic degrade/recover under pure
            // idle traffic looks exactly like that: id jumping to a new range would explain slots going stale
            // and self-healing once fresh keepalives discover the new mapping).
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP][rx] role={(_isPinger ? "P" : "R")} type={type} id={id} seq={seq} len={payload.Length} magic={hasMagic}");
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

        // DATA-AS-MATCHED-REPLY (both roles, post-punch). The channel's one reliable delivery shape is an echo
        // REPLY matched to a request the receiver's NAT recently sent out (RFC 5508); unsolicited REQUESTS are
        // dropped. So we answer the peer's REQUESTS, echoing their id+seq, carrying queued data if any.
        //
        // Reply to any inbound REQUEST (type-8), NOT just REQTAG-tagged ones — once data flows, the peer's
        // requests carry MAGIC instead of REQTAG, so gating on the tag rejected most live slots. Keying on ICMP
        // TYPE captures all of them. Safe from a reply-to-reply amplification loop: type-8 is a REQUEST, so
        // replying to it is the intended request→reply flow, never a reply→reply cycle.
        if (_punched && type == ICMP_ECHO_REQUEST)
        {
            // SERVER SIDE of the client/server model: the client's request just arrived, so piggyback our queued
            // data on the REPLY immediately, on the capture thread. One request in, data out in the same instant.
            //
            // Drain up to RX_THREAD_DRAIN_CAP frames onto THIS request's (id,seq) — a small burst rather than
            // exactly one lets a backlog (WG handshake, iperf) clear without waiting a request each.
            //
            // MUST use TryDequeueTxFrame (priority-first), not _txQueue alone, or WG handshake frames get excluded
            // from this reactive matched-reply path — the one delivery shape this channel reliably has.
            int replied = 0;
            for (; replied < RX_THREAD_DRAIN_CAP && TryDequeueTxFrame(out var frame); replied++)
                SendData(ICMP_ECHO_REPLY, id, seq, frame.Frame, frame.Data);
            if (replied == 0)
                SendTag(ICMP_ECHO_REPLY, id, seq, ACKTAG); // keepalive reply — keeps the client's flow alive
            // (A MIRROR-REQUEST was tried here — fire our own request on the peer's just-heard id to ride its
            //  hole. Doesn't work: the id we RECEIVE on is OUR NAT's inbound id, independent of the peer's, so it
            //  can't make an unsolicited request cross a symmetric NAT. The fundamental symmetric-NAT wall.)
        }

        // Decide the hole is open during the punch. An explicit ACK is the clean signal, but the two peers can
        // start sweeping at different wall-clock times, so the ACK-tag exchange can race and one side time out
        // while the other punched. Hearing the peer at all means our outbound reached them and their NAT is
        // forwarding to us — establish on either an explicit ACK OR sustained hearing.
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
        // REFLECTION FILTER: our outbound requests reach the peer's OS, which auto-generates a type-0 reply
        // copying our payload back verbatim. We can't reject all type-0 (some NAT/stack pairs only ever deliver
        // real peer data as type-0), so instead reject by CONTENT: drop any inbound data frame whose bytes match
        // one we recently sent; anything else is genuine peer data regardless of ICMP type.
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
                    Interlocked.Increment(ref _rxDropReflection);
                }
                else if (!MarkFrameSeen(frame))
                {
                    // De-dup by frame id: each frame is sprayed across the churning id space + reorders, so it
                    // arrives many times. A false here means this exact frame id was already delivered once —
                    // drop the repeat (bounded seen-set). Counted so we can tell "peer data never arrived" from
                    // "peer data arrived (repeatedly) and we're discarding the copies as duplicates".
                    Interlocked.Increment(ref _rxDropDedup);
                }
                else
                {
                    // Which ICMP type delivered this unique data frame — type-8 spray vs type-0 matched reply.
                    if (type == ICMP_ECHO_REQUEST) Interlocked.Increment(ref _rxDataType8);
                    else Interlocked.Increment(ref _rxDataType0);
                    _lastDataRxUtc = DateTime.UtcNow; // real data arrived → keep the fast ping rate for ActiveWindow
                    // WG handshake progress: 0x01=init 0x02=response 0x03=cookie 0x04=transport (handshake done).
                    if (copy.Length > 0)
                    {
                        byte w = copy[0];
                        if (w == 1) Interlocked.Increment(ref _wgInit);
                        else if (w == 2) Interlocked.Increment(ref _wgResp);
                        else if (w == 4) Interlocked.Increment(ref _wgData);
                        if (w >= 1 && w <= 3) _handshakeSeenUtc = DateTime.UtcNow; // see SERVER_TRICKLE_INTERVAL
                    }
                    ReportDeliveryStats();
                    try { PacketReceived?.Invoke(copy); } catch { }
                }
            }
        }
        else
        {
            // Not a data frame (MAGIC didn't match or payload too short) — keepalives, punch openers, probe
            // traffic. Counted so rx-stats can show inbound volume vs data volume.
            if (payload.Length < DATA_HEADER) Interlocked.Increment(ref _rxTooShort);
            else Interlocked.Increment(ref _rxNonMagic);
        }
    }

    // Delivery-type measurement: how many UNIQUE inbound data frames arrived via type-8 (spray) vs type-0 (matched
    // reply), reported per ~5s window so we can see the split AND whether type-0 tapers as the reply-match ring
    // ages. This tells us if the type-8 full-range spray is load-bearing or vestigial (→ cut it, kill the ban).
    private long _rxDataType8, _rxDataType0, _lastReport8, _lastReport0;
    private long _wgInit, _wgResp, _wgData;  // WG msg-type counters: 0x01 init / 0x02 response / 0x04 transport
    private long _reqSeen, _lastReqSeen;     // inbound REQTAG requests = our deliverable-slot supply (throughput ceiling)

    // Receive-path drop buckets. Success-only counters can't distinguish "the peer's data never arrived" from
    // "it arrived and we discarded it". These make every inbound packet fall into exactly one bucket
    // (too-short / non-magic / reflection / dedup-dropped / delivered).
    private long _rxDropReflection;   // OnInboundIcmp: payload matched a frame WE recently sent (OS echo-reflection, not peer data)
    private long _rxDropDedup;        // OnInboundIcmp: MarkFrameSeen(frame) was false — a duplicate copy of an already-delivered frame
    private long _rxNonMagic;         // OnInboundIcmp: inbound packet did not start with MAGIC (keepalive/ACK/tag traffic, not a data frame)
    private long _rxTooShort;         // OnInboundIcmp: payload shorter than DATA_HEADER, so it can't even be checked for MAGIC
    private long _lastRxDropReflection, _lastRxDropDedup, _lastRxNonMagic, _lastRxTooShort; // rx-stats per-window baselines
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
        // req/5s = inbound REQTAG requests = deliverable-slot supply from the peer (throughput ceiling: at most
        // one frame per request). slots/slotAgeMs/txSent below answer: how many distinct slots do we have to
        // reply onto, and is the one in use going stale?
        long tx = Interlocked.Read(ref _txFramesSent); long dtx = tx - _lastTxFramesSent; _lastTxFramesSent = tx;
        double slotAgeMs = _lastHeardReqUtc == DateTime.MinValue
            ? -1 : (DateTime.UtcNow - _lastHeardReqUtc).TotalMilliseconds;
        // Age of the slot we'd ACTUALLY pick right now, and which kind it is — slotAge above tracks only
        // _lastHeardReqUtc, which on a req=0 peer never refreshes and misleadingly reads as hours-stale.
        bool useReqSlot = _lastHeardReq >= 0 &&
            (_lastHeardAny < 0 || _lastHeardReqUtc >= _lastHeardAnyUtc - STALE_REQ_SLOT);
        DateTime activeUtc = useReqSlot ? _lastHeardReqUtc : _lastHeardAnyUtc;
        double activeAgeMs = activeUtc == DateTime.MinValue
            ? -1 : (DateTime.UtcNow - activeUtc).TotalMilliseconds;

        // Pacing vs slot-supply. drainFull=N/M with qDepth>0 => pacer-limited (raise DRAIN_PER_ITER); a large
        // attempted-vs-delivered gap with LOW drainFull => the peer's slot supply is the ceiling. wirePkts/s is
        // real packets on the wire, post-fanout and keepalives.
        long loopIters = Interlocked.Read(ref _drainLoopIters); long dLoopIters = loopIters - _lastDrainLoopIters; _lastDrainLoopIters = loopIters;
        long fullIters = Interlocked.Read(ref _drainFullIters); long dFullIters = fullIters - _lastDrainFullIters; _lastDrainFullIters = fullIters;
        long wire = Interlocked.Read(ref _wirePkts); long dWire = wire - _lastWirePkts; _lastWirePkts = wire;
        // Per-window averages, NOT lifetime totals: a cumulative counter climbs with volume and hides the trend.
        long lockW = Interlocked.Read(ref _lockWaitTicks); long dLockW = lockW - _lastLockWaitTicks; _lastLockWaitTicks = lockW;
        long sysT = Interlocked.Read(ref _syscallTicks); long dSysT = sysT - _lastSyscallTicks; _lastSyscallTicks = sysT;
        double lockWaitUs = dWire > 0 ? (dLockW / (double)dWire) / 10.0 : 0;  // ticks(100ns) -> us
        double syscallUs = dWire > 0 ? (dSysT / (double)dWire) / 10.0 : 0;

        // Datagrams WireGuard-NT handed the loopback proxy this window = WG's outbound rate BEFORE we
        // encapsulate. Pair it with attempted/s: wgOut/s>0 while attempted/s=0 means we're losing frames
        // between the proxy and Send(); both at 0 while inbound data continues means WG itself went quiet.
        long wgOut = Interlocked.Read(ref PeerProxyListener.WgToProxyPackets);
        long dWgOut = wgOut - _lastWgOutPackets; _lastWgOutPackets = wgOut;
        double wgOutPerSec = dWgOut / 5.0;

        long qOvf = Interlocked.Read(ref _txQueueOverflowDrops); long dQOvf = qOvf - _lastTxQueueOverflowDrops; _lastTxQueueOverflowDrops = qOvf;
        double attemptedPerSec = dtx / 5.0, deliveredType0PerSec = d0 / 5.0, wirePktsPerSec = dWire / 5.0;

        // Receive-path drop breakdown: nonMagic dominating with refl/dup near zero => the peer's data isn't
        // arriving; refl or dup climbing while deliveredType0/s stays low => it arrives and we discard it.
        long refl = Interlocked.Read(ref _rxDropReflection); long dRefl = refl - _lastRxDropReflection; _lastRxDropReflection = refl;
        long dup = Interlocked.Read(ref _rxDropDedup); long dDup = dup - _lastRxDropDedup; _lastRxDropDedup = dup;
        long nonMagic = Interlocked.Read(ref _rxNonMagic); long dNonMagic = nonMagic - _lastRxNonMagic; _lastRxNonMagic = nonMagic;
        long tooShort = Interlocked.Read(ref _rxTooShort); long dTooShort = tooShort - _lastRxTooShort; _lastRxTooShort = tooShort;

        NATTunnel.Program.Log(NATTunnel.LogLevel.Debug,
            $"[ICMP][rx-stats] last5s: type8={d8} type0={d0} req={drq}  total type0={t0}  " +
            $"wg: init={Interlocked.Read(ref _wgInit)} resp={Interlocked.Read(ref _wgResp)} DATA={Interlocked.Read(ref _wgData)}" +
            $" | slots={_heardReqCount} slotAge={slotAgeMs:F0}ms activeSlot={(useReqSlot ? "req" : "any")}/{activeAgeMs:F0}ms txFrames={dtx} qDepth={_txQueue.Count} qOvfDrop={dQOvf}" +
            $" | drainFull={dFullIters}/{dLoopIters} attempted/s={attemptedPerSec:F0} deliveredType0/s={deliveredType0PerSec:F0} wirePkts/s={wirePktsPerSec:F0}" +
            $" | lockWait={lockWaitUs:F0}us syscall={syscallUs:F0}us per send" +
            $" | rxDrop refl={dRefl} dup={dDup} nonMagic={dNonMagic} short={dTooShort}" +
            $" | wgOut/s={wgOutPerSec:F0} punched={_punched}");
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
    // bad — a frame on a single (id,seq) is a coin-flip. Sends as a reply onto (a) the just-arrived request's
    // (id,seq), guaranteed-live, AND (b) each of the most-recent distinct heard requests. Receiver de-dups by
    // frame id, so duplicates are free. SAMPLES the heard-request ring (RecentHeardReqs, non-consuming) — does
    // NOT dequeue, so it can't drain the ring dry (that was the earlier regression).
    //
    // FRAME_FANOUT=1 (no redundancy): extra copies were found to cost more in wire volume (ISP rate-limit risk)
    // than they bought in delivery — losses were correlated with volume, not independent per-copy, so fanout was
    // partly causing the drops it existed to mask. Judge changes here by delivery (loss %, handshake speed),
    // not raw Mbit/s throughput, which is insensitive to fanout.
    //
    // HANDSHAKE_FANOUT stays high regardless: those frames are rare and tiny, losing one costs a full retry
    // round, so redundancy there is nearly free.
    private const int FRAME_FANOUT = 1;
    // Wider fanout reserved for WG handshake packets (0x01/0x02/0x03) — see call site in the drain loop. These
    // are rare (a handful per connection) and small, so spending more slot attempts on them is nearly free in
    // aggregate wire volume, but meaningfully raises the odds that a full round of the handshake actually lands
    // instead of WG-NT timing out and restarting from init.
    private const int HANDSHAKE_FANOUT = 10;
    // (A stall-triggered "panic mode" — dense pacing + wider fanout — lived here. It never helped; the stall
    //  it targeted was the slot sign-bit bug (see _lastHeardReq). Removed.)
    private void EmitFrameRedundant(TxFrame frame, ushort liveId, ushort liveSeq, int fanout = FRAME_FANOUT)
    {
        SendData(ICMP_ECHO_REPLY, liveId, liveSeq, frame.Frame, frame.Data); // the guaranteed-live slot
        int live = (liveId << 16) | liveSeq;
        var recent = RecentHeardReqs(fanout);
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
        Interlocked.Increment(ref _wirePkts); // every EmitIcmp call = one real wire packet (post-fanout, incl. keepalives)

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
            //
            // Split at tick (100ns) resolution: lock-wait (contention with the RX capture thread) vs the syscall
            // itself. Those have opposite fixes, and ms resolution floored nearly every sample to 0.
            long tEnter = _rttSw.ElapsedTicks;
            long tAcquired;
            lock (_sendLock)
            {
                tAcquired = _rttSw.ElapsedTicks;
                sock.SendTo(pkt, _sendTo);
            }
            long tDone = _rttSw.ElapsedTicks;
            Interlocked.Add(ref _lockWaitTicks, tAcquired - tEnter);   // time spent waiting for the OTHER thread
            Interlocked.Add(ref _syscallTicks, tDone - tAcquired);     // time spent inside SendTo itself
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

    // Post-punch fast send rate, used only while data is actively flowing (see adaptive pacing in the send loop).
    // Much lower than the punch rate — no longer birthday-hunting, just keeping the peer's reply-match ring fed.
    private const double POST_PUNCH_INTERVAL = 1.0 / 250.0;

    private void PaceTo(Stopwatch sw, ref double nextSend, double interval)
    {
        if (interval <= 0) return;
        nextSend += interval;
        double now = sw.Elapsed.TotalSeconds;
        // Resync-on-drift: if a slow iteration pushed us more than one interval behind schedule, `nextSend +=
        // interval` alone would keep landing behind `now` forever, disabling pacing entirely (free-running loop,
        // unbounded CPU/_sendLock pressure). Clamp the debt to one interval instead of letting it compound.
        if (now - nextSend > interval) nextSend = now;
        double remain = nextSend - now;
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
        // ORDER MATTERS — this used to deadlock the process into an unkillable zombie. NpcapCapture.Dispose calls
        // StopCapture(), which blocks until the capture thread exits; that thread runs OnInboundIcmp, which does
        // a synchronous SendTo under _sendLock. If the send loop still holds _sendLock, StopCapture never returns.
        // So: signal stop, JOIN THE SEND LOOP FIRST (it releases _sendLock on exit), then tear down capture.
        // Socket disposal is deferred until after the join so an in-flight send can't fault.
        _stopped = true;
        try { _sendThread?.Join(1500); } catch { }
        _sendThread = null;
        try { _capture?.Dispose(); } catch { }
        try { _sendSock?.Dispose(); } catch { }
        _sendSock = null;
    }
}
