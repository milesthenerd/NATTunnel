// NatErrorOracle — will a NAT translate a PEER-CRAFTED ICMP error inward, turning the NAT into a
// confirmation oracle for its own external port allocation?
//
// THE IDEA (genuinely different from everything else tested)
//   Prior attempts all asked "can WE read our own external port?" — port prediction (dead: non-sequential
//   allocation), the TTL wedge (dead: our NAT UN-translates the quoted header per RFC 5508, scrubbing the value),
//   observe-and-report (needs a packet to have already landed). All fight the same 2-D problem: neither peer knows
//   its own peer-bound port, so a UDP birthday punch must collide in BOTH dimensions — minutes to half an hour.
//
//   This flips it. RFC 5508 says a NAT receiving an inbound ICMP ERROR must look up the QUOTED INNER HEADER in its
//   translation table and, on a match, rewrite it to the internal address before delivering. So:
//
//     The peer crafts an ICMP error to OUR public IP whose inner header claims
//         <our-public-ip>:<GUESSED-external-port>  →  <peer-public-ip>:<port>
//
//     • guess CORRECT → matches a live mapping → our NAT translates + delivers → WE RECEIVE IT.
//     • guess WRONG   → no matching entry      → our NAT drops it              → silence.
//
//   A yes/no ORACLE on our own external port, answered by our own NAT, driven from the peer side. And it is a
//   ONE-DIMENSIONAL search: the peer sweeps guesses at OUR port while its own port is irrelevant to the lookup.
//   Same shape as the ICMP-identifier punch that already works.
//
// THIS TOOL VALIDATES THE MECHANISM BEFORE ANY SWEEP IS BUILT.
//   A sweep is only worth writing if a KNOWN-CORRECT guess gets through. Each side automatically:
//     1. sends real UDP to the peer, so a genuine live mapping exists in both NATs;
//     2. OBSERVES the peer's real external port off that inbound traffic (no manual copying);
//     3. reports it back to the peer in-band, so each side learns ITS OWN external port;
//     4. forges an ICMP error quoting the peer's now-known-correct port, plus deliberately WRONG control ports;
//     5. listens for arrivals and reports which quotes its own NAT accepted.
//
//   Correct arrives + controls do not  → oracle real, build the sweep.
//   Everything arrives                 → NAT forwards without matching; no signal.
//   Nothing arrives                    → NAT drops peer-crafted errors; oracle dead here.
//
// USAGE — the SAME command on both machines, only --peer differs:
//   A:  dotnet run --project experiments/NatErrorOracle -- --peer <B-public-ip> --start-at <unixMillis>
//   B:  dotnet run --project experiments/NatErrorOracle -- --peer <A-public-ip> --start-at <unixMillis>
//   Get a start time ~30s out:  [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 30000
//   Omit --start-at to begin immediately (fine if you can launch both within a few seconds).
//   Run ELEVATED on both: raw ICMP is needed to receive errors (SIO_RCVALL) and to forge them.

using System.Net;
using System.Net.Sockets;
using System.Text;

string Arg(string k, string def = null)
{
    for (int i = 0; i < args.Length - 1; i++) if (args[i] == k) return args[i + 1];
    return def;
}

// ── SERVER MODE — run this on a machine with a PUBLIC IP (no NAT in front of it) ────────────────────────
//
// WHY THIS MODE EXISTS. Testing the oracle between two symmetric-NAT peers is impossible to BOOTSTRAP: to forge
// a quote naming the peer's external port you must first know that port, and learning it requires a packet to
// have already arrived — the exact deadlock the oracle is meant to break. Two runs were wasted quoting made-up
// ports (1, 30000) and reported as negatives when they measured nothing at all.
//
// A public server removes the circularity from BOTH ends:
//   • It has no NAT, so its "external port" is simply the port it bound — nothing to discover.
//   • Our packets genuinely REACH it, so it can read our external port off the IP header and TELL us.
// Then it forges an ICMP error back at us quoting that verified port (plus wrong controls), and our NAT either
// translates it inward or drops it. That isolates the ONE question — does a NAT honour RFC 5508 for an error
// arriving from an arbitrary source — with no guessing anywhere in the chain.
//
//   server:  NatErrorOracle --server [--port 51999]                (public box, ELEVATED)
//   client:  NatErrorOracle --to <server-ip> [--port 51999]        (behind the NAT, ELEVATED)
if (Array.IndexOf(args, "--server") >= 0)
{
    int sport = int.Parse(Arg("--port") ?? "51999");
    int nWrong = int.Parse(Arg("--wrong") ?? "3");
    using var su = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    // --listen-ip <ip>: bind the UDP listener to a specific address (IP-B) so the client's flow is unambiguously
    // to that IP, while --forge-from names the OTHER address (IP-A).
    var listenIp = Arg("--listen-ip") != null ? IPAddress.Parse(Arg("--listen-ip")) : IPAddress.Any;
    su.Bind(new IPEndPoint(listenIp, sport));
    su.ReceiveTimeout = 500;

    // Our own PUBLIC address — needed as the DESTINATION inside the forged quote. Binding the UDP socket to
    // IPAddress.Any means su.LocalEndPoint.Address is 0.0.0.0, and using THAT in the quote produced
    // "ICMP 0.0.0.0 udp port 51999 unreachable" on the wire (caught by tcpdump). A quote naming 0.0.0.0 can
    // never match a NAT conntrack entry, so every such run measures nothing — the packets are well-formed but
    // semantically void. Resolve a real local address instead.
    IPAddress serverPublic = IPAddress.Any;
    try
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Connect(IPAddress.Parse("1.1.1.1"), 9);   // sends nothing; just picks the egress interface
        serverPublic = ((IPEndPoint)probe.LocalEndPoint).Address;
    }
    catch { }
    if (Arg("--public-ip") != null) serverPublic = IPAddress.Parse(Arg("--public-ip"));
    if (serverPublic.Equals(IPAddress.Any))
    {
        Console.WriteLine("✗ could not determine this server's own IP. Pass it explicitly: --public-ip <ip>");
        return 1;
    }
    Console.WriteLine($"[server] our address for the forged quote: {serverPublic}" +
                      "  (if this box is itself behind NAT, pass --public-ip <real-public-ip>)");

    // --icmp-type / --icmp-code: try other error shapes. Type 3/3 and 11/0 both behave IDENTICALLY against the
    // server's own address (hit) and against a third party (miss), so the type is not what gates the boundary —
    // but a few codes are handled specially by firewalls and are worth trying:
    //   3/4  frag-needed (PMTUD). Often passed with LOOSER validation than other errors, because dropping it
    //        breaks path-MTU discovery. Carries an MTU field. Most promising untried variant.
    //   3/1  host unreachable — the gateway emits these constantly here, so the firewall clearly handles them.
    //   3/0  net unreachable.
    //   3/9,3/10,3/13 administratively prohibited.
    //   4    source quench (deprecated, likely dropped outright).
    //   12   parameter problem.
    int fType = int.Parse(Arg("--icmp-type") ?? "3");
    int fCode = int.Parse(Arg("--icmp-code") ?? (fType == 3 ? "3" : "0"));
    if (fType != 3 || fCode != 3)
        Console.WriteLine($"[server] forging ICMP type {fType} code {fCode}.");
    if (fType == 11)
    {
        Console.WriteLine("[server] forging ICMP TIME-EXCEEDED (11/0) instead of dest-unreachable (3/3).");
        Console.WriteLine("[server]   Rationale: a time-exceeded legitimately comes from an arbitrary MIDDLE router,");
        Console.WriteLine("[server]   so a NAT that source-validates errors has no reason to reject ours. A");
        Console.WriteLine("[server]   dest-unreachable is expected to come from a party to the flow — which we are not.");
    }

    Socket sraw;
    try
    {
        sraw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        // --forge-from <ip>: send the forged errors from a DIFFERENT local IP than the one the client is talking
        // to. THIS IS THE CLEAN DISCRIMINATOR. With two IPs on the box: the client keeps a live bidirectional
        // flow to IP-B (so the conntrack entry provably exists), while the errors originate from IP-A — a host
        // that is provably NOT a participant in that conversation. Every earlier run had the forger's IP equal
        // to the quoted destination, so "sender is a participant" and "entry exists" were never separated.
        var forgeFrom = Arg("--forge-from") != null ? IPAddress.Parse(Arg("--forge-from")) : IPAddress.Any;
        sraw.Bind(new IPEndPoint(forgeFrom, 0));
        if (!forgeFrom.Equals(IPAddress.Any))
            Console.WriteLine($"[server] forging FROM {forgeFrom} (must differ from the IP the client talks to, for a valid discriminator)");
    }
    catch (SocketException e)
    {
        Console.WriteLine($"✗ raw ICMP socket failed ({e.SocketErrorCode}).");
        Console.WriteLine(OperatingSystem.IsWindows()
            ? "  Windows: run as Administrator."
            : "  Linux: run with sudo, or: sudo setcap cap_net_raw+ep ./NatErrorOracle");
        return 1;
    }

    // --discard-port <n>: a second UDP listener that RECEIVES and NEVER REPLIES.
    //
    // THE CRUX TEST. Every confirmed oracle hit so far involved a flow whose destination answered, i.e. a
    // BIDIRECTIONAL conntrack entry. Two symmetric-NAT peers can never establish one — that is the original
    // deadlock — so the whole design hinges on whether a forged quote can match a ONE-WAY, never-replied flow.
    // Pointing the client's peer-flow at this port creates exactly that: packets arrive (so the entry is real
    // and continuously refreshed) but nothing ever comes back.
    //   hit  → the oracle can bootstrap a peer connection; sym↔sym UDP is solved.
    //   miss → it only confirms ports for flows that already work, which does not help.
    int discardPort = int.Parse(Arg("--discard-port") ?? "0");
    Socket sdiscard = null;
    if (discardPort > 0)
    {
        sdiscard = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sdiscard.Bind(new IPEndPoint(listenIp, discardPort));
        sdiscard.ReceiveTimeout = 5;
        Console.WriteLine($"[server] DISCARD listener on :{discardPort} — receives, never replies (one-way flow test).");
    }

    // --warm-dest <ip>: keep a REAL live flow from this server to the quoted destination while forging.
    //
    // Hypothesis this tests: the forged errors leave Hetzner (confirmed by tcpdump) but never reach the client's
    // WAN (confirmed by pfSense capture — it sees nothing). Nothing the user controls drops them. The leading
    // explanation is anti-spoofing somewhere upstream: an ICMP error claiming to report on traffic to a host the
    // SOURCE has no relationship with is the textbook signature of a spoofed error. That fits the boundary
    // exactly — quotes naming 135.181.110.176 got through because the server IS that host.
    //
    // If we give the server a genuine conversation with the quoted destination, that objection disappears and
    // the packet should stop looking spoofed. If quotes then start arriving, the filter is upstream and about
    // the source/destination relationship — NOT about the client's NAT at all, which would mean the mechanism
    // is fine and only this vantage point was unusable.
    var warmDest = Arg("--warm-dest") != null ? IPAddress.Parse(Arg("--warm-dest")) : null;
    Socket warmSock = null;
    if (warmDest != null)
    {
        warmSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        warmSock.Bind(new IPEndPoint(IPAddress.Any, 0));
        warmSock.ReceiveTimeout = 5;
        Console.WriteLine($"[server] WARM-DEST: keeping a live flow to {warmDest} so our forged quotes about it");
        Console.WriteLine($"[server]   are not obviously spoofed. Sending a keepalive there every 500ms.");
    }
    int warmReplies = 0;
    var warmSw = System.Diagnostics.Stopwatch.StartNew();
    double nextWarm = 0;

    Console.WriteLine($"[server] listening on :{sport}. Waiting for a client…");
    Console.WriteLine($"[server] (the server only SENDS raw ICMP — no SIO_RCVALL needed on either platform)");
    var buf = new byte[2048];
    var served = new HashSet<string>();
    var discardSeen = new HashSet<int>();
    ushort quoteIpId = 0x1a2b;
    bool waitIpId = Array.IndexOf(args, "--wait-ipid") >= 0;   // hold the sweep until a matched IP ID arrives
    bool haveIpId = false;
    var announcedWait = new HashSet<string>();
    while (true)
    {
        // Keep the discard socket drained. If its receive buffer fills, the kernel starts answering with REAL
        // port-unreachables — the exact artefact that once produced 19 phantom "hits" and wasted a run.
        if (sdiscard != null)
        {
            try
            {
                while (sdiscard.Available > 0)
                {
                    EndPoint _dd = new IPEndPoint(IPAddress.Any, 0);
                    sdiscard.ReceiveFrom(buf, ref _dd);
                    // Report the DISCARD flow's external port. This is a DIFFERENT NAT allocation from the one
                    // toward our main listener, and it is the only port a hinted sweep of the one-way flow can
                    // usefully centre on — an earlier run hinted the main flow's port (57740) and therefore swept
                    // a range that could never contain the answer.
                    int dp = ((IPEndPoint)_dd).Port;
                    if (discardSeen.Add(dp))
                        Console.WriteLine($"[server] ★ DISCARD-FLOW external port = {dp}  (use --hint {dp} to sweep the ONE-WAY flow)");
                }
            }
            catch (SocketException) { }
        }

        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        int n;
        try { n = su.ReceiveFrom(buf, ref from); }
        catch (SocketException) { continue; }
        var c = (IPEndPoint)from;
        string key = $"{c.Address}:{c.Port}";

        // Always tell the client the external port we see it on — this is ground truth, read off the wire.
        var reply = Encoding.ASCII.GetBytes($"YOUREXT {c.Port}");
        try { su.SendTo(reply, c); } catch { }

        // The client may ask us to quote a flow toward a THIRD PARTY rather than toward us. That is the real
        // deployment shape: the mediation server forges a quote describing the client's flow to its PEER.
        // "TARGET <ip> <port>" asks us to quote the client's flow to a THIRD PARTY on that port, rather than
        // the client->us flow. The port matters: the peer flow uses its own local/dest port, not ours.
        IPAddress quoteDst = serverPublic;
        int quoteDstPort = sport;
        // The quote must carry the SAME bytes the client is really sending, or its length/content will not match
        // the flow it claims to describe. Client sends real DNS to :53, PEERFLOW otherwise.
        byte[] quoteBody = Encoding.ASCII.GetBytes("PEERFLOW");
        // Client can pin the IP ID it stamps on its probes so our quote matches byte-for-byte.
        var msg = Encoding.ASCII.GetString(buf, 0, n);
        bool tcpQuote = false;
        if (msg.StartsWith("IPID "))
        {
            if (ushort.TryParse(msg.Substring(5).Trim(), out var qid)) { quoteIpId = qid; haveIpId = true;
                Console.WriteLine($"[server] received matched IP ID 0x{quoteIpId:x4} from client — will quote it."); }
            continue;   // control-only message, no sweep
        }
        if (msg.StartsWith("TARGETTCP "))
        {
            var parts = msg.Substring(10).Trim().Split(' ');
            if (parts.Length >= 1 && IPAddress.TryParse(parts[0], out var tpc)) quoteDst = tpc;
            if (parts.Length >= 2 && int.TryParse(parts[1], out var tppc)) quoteDstPort = tppc;
            tcpQuote = true;
        }
        else if (msg.StartsWith("TARGET "))
        {
            var parts = msg.Substring(7).Trim().Split(' ');
            if (parts.Length >= 1 && IPAddress.TryParse(parts[0], out var tp)) quoteDst = tp;
            if (parts.Length >= 2 && int.TryParse(parts[1], out var tpp)) quoteDstPort = tpp;
            if (quoteDstPort == 53)
                quoteBody = new byte[] {
                    0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                    0x01,(byte)'a', 0x0c,(byte)'r',(byte)'o',(byte)'o',(byte)'t',(byte)'-',
                    (byte)'s',(byte)'e',(byte)'r',(byte)'v',(byte)'e',(byte)'r',(byte)'s',
                    0x03,(byte)'n',(byte)'e',(byte)'t', 0x00, 0x00,0x01, 0x00,0x01 };
        }

        // --wait-ipid: in IP-ID-match mode, do NOT consume the served slot or sweep until the client has
        // reported the real IP ID. Otherwise the first TARGET (before the IPID arrives) marks the client served
        // and every later TARGET is skipped, so the matched sweep never runs.
        if (waitIpId && !haveIpId)
        {
            if (announcedWait.Add(key)) Console.WriteLine("[server] --wait-ipid: holding sweep until the client reports the real IP ID…");
            continue;
        }
        if (!served.Add(key)) continue;
        Console.WriteLine($"\n[server] client {key}  → its external port TOWARD US is {c.Port} (verified: we received it)");
        if (!quoteDst.Equals(serverPublic))
        {
            Console.WriteLine($"[server] ⚠ THIRD-PARTY MODE: quoting flows to {quoteDst}:{quoteDstPort}, NOT to us.");
            Console.WriteLine($"[server]   The client's port toward {quoteDst} is a DIFFERENT allocation that we cannot");
            Console.WriteLine($"[server]   observe — that is the whole point. Sweeping blind for it.");
        }

        // ── SWEEP MODE ──────────────────────────────────────────────────────────────────────────────────
        // The one-shot test proved a single CORRECT quote is translated inward. That is not the same as
        // proving a SWEEP works: a real implementation has to FIND the port without being told, and firing
        // thousands of unmatched errors may make the NAT start dropping them (rate limiting / conntrack
        // pressure). Testing that here — against a server that ALREADY KNOWS the answer — is strictly better
        // than testing it peer-to-peer, because we can tell a genuine hit from a false positive.
        //
        // The client keeps exactly ONE live flow to us, so exactly ONE guess should ever match. Anything else
        // reported as a hit is the NAT leaking matches, which a P2P test could never detect.
        if (Array.IndexOf(args, "--sweep") >= 0)
        {
            int width = int.Parse(Arg("--sweep-width") ?? "2000");
            int rate = int.Parse(Arg("--sweep-rate") ?? "200");
            // --sweep-full: ignore the known answer entirely and sweep the whole ephemeral range, which is what a
            // real deployment must do (it has no hint where the port is). At 2000/s that is ~32s for 64k ports.
            // In THIRD-PARTY mode we genuinely do not know the answer (the client's port toward the peer is an
            // allocation we never see), so a centred sweep is impossible — it must be full-range by necessity.
            // --hint <port>: sweep a NARROW window centred on a port supplied out-of-band, instead of the full
            // range. This exists because of conntrack lifetime, not because we need the answer:
            //
            //   An UNREPLIED UDP flow (our peer flow — the peer's NAT drops everything, so nothing ever comes
            //   back) lives ~30s in nf_conntrack (`nf_conntrack_udp_timeout`), versus 180s once a reply arrives
            //   (`udp_timeout_stream`). A full-range sweep at 1000/s takes ~65s, so for a mid-range allocation
            //   the mapping is very likely GONE before the sweep reaches it. That would make every peer-flow
            //   test fail for a reason that has nothing to do with third-party forging.
            //
            //   This is consistent with everything observed: the SERVER-flow test succeeded (the server replies,
            //   so the entry is established and long-lived) while every PEER-flow test failed (unreplied, short).
            //   A narrow window fired immediately reaches the right port in ~1s, well inside 30s.
            int hint = int.Parse(Arg("--hint") ?? "0");
            bool full = hint == 0 && (Array.IndexOf(args, "--sweep-full") >= 0 || !quoteDst.Equals(serverPublic));
            if (hint != 0)
            {
                Console.WriteLine($"[server] HINTED sweep around {hint} — testing whether a SHORT-LIVED unreplied");
                Console.WriteLine($"[server]   mapping can be hit at all, before conntrack ages it out (~30s).");
            }
            // --spread: sample `width` ports RANDOMLY across the whole range instead of a contiguous window.
            //
            // THIS IS WHAT BIRTHDAY MODE NEEDS. With N client sockets the allocations are scattered uniformly
            // over 64k (observed: 4305, 29408, 20077, 44342, 63554 …), so a CONTIGUOUS 1024-port window catches
            // ~4% of them while a RANDOM 1024-port sample catches ~98%. A centred window is the right shape only
            // when we already have a hint for one specific flow.
            bool spread = Array.IndexOf(args, "--spread") >= 0;
            int centre = hint != 0 ? hint : c.Port;
            int lo = full ? 1024 : Math.Max(1, centre - width / 2);
            int hi = full ? 65535 : Math.Min(65535, centre + width / 2);
            if (full) Console.WriteLine("[server] FULL-RANGE sweep — no hint used, exactly as a real implementation would run.");
            Console.WriteLine($"[server] SWEEP {lo}..{hi} ({hi - lo + 1} ports) at ~{rate}/s — the true answer is {c.Port}");
            Console.WriteLine($"[server] (sweeping BLIND; we know the answer only so we can verify the client's hit)");
            var swStart = DateTime.UtcNow;
            int fired = 0;
            double gap = 1000.0 / Math.Max(1, rate);
            var next = DateTime.UtcNow;

            // ORDER MATTERS, and sequential order biases the whole experiment.
            //
            // An UNREPLIED UDP mapping lives ~30s (nf_conntrack_udp_timeout) while a full-range sweep at 1000/s
            // takes ~65s. Sweeping 1024→65535 in order therefore means every port in the UPPER HALF is unreachable
            // BY CONSTRUCTION — the entry has aged out before we get there. Both real allocations observed on this
            // NAT (55898, 56298) sit squarely in that dead zone, so a sequential sweep could never have hit them.
            //
            // Random order gives every port an equal chance of being tried early, so a hit is possible wherever the
            // allocation lands. It is also what a real implementation would do, and matches how the existing ICMP
            // birthday punch already works.
            List<int> order;
            if (spread)
            {
                // Random sample of `width` distinct ports across the FULL ephemeral range.
                var pick = new HashSet<int>();
                // Seed from the client's observed port so DIFFERENT clients/runs sample DIFFERENT random ports.
                // A FIXED seed meant every re-run swept the identical 2048 ports — if they missed the target
                // allocations once, they missed every single re-run, producing a false "always fails".
                var srnd = new Random(c.Port ^ (int)(swStart.Ticks & 0x7fffffff));
                while (pick.Count < Math.Min(width, 64000)) pick.Add(srnd.Next(1024, 65536));
                order = new List<int>(pick);
                Console.WriteLine($"[server] SPREAD sweep: {order.Count} ports sampled at RANDOM across 1024..65535");
                Console.WriteLine($"[server]   (contiguous windows are wrong for birthday mode — allocations are scattered)");
            }
            else
            {
                order = new List<int>(hi - lo + 1);
                for (int g = lo; g <= hi; g++) order.Add(g);
            }
            bool randomOrder = Array.IndexOf(args, "--sequential") < 0;
            if (randomOrder)
            {
                var rnd = new Random(1337);
                for (int i = order.Count - 1; i > 0; i--)
                {
                    int j = rnd.Next(i + 1);
                    (order[i], order[j]) = (order[j], order[i]);
                }
                Console.WriteLine("[server] RANDOM order (use --sequential to force ascending). Sequential order makes");
                Console.WriteLine("[server]   the upper half unreachable when the mapping ages out mid-sweep.");
            }

            // CRITICAL: keep draining the UDP socket while sweeping. The first version blocked here for the
            // whole ~65s sweep without reading it, so the client's continued packets filled the receive buffer
            // and the LINUX KERNEL answered them with genuine ICMP port-unreachables. The client detected those
            // as "hits" — 19 of them, spaced at exactly the client's 430ms send cadence rather than the sweep's
            // 1ms — and they quoted client:51999 -> server:51999 (our own TARGET control message) instead of the
            // peer flow. Pure artefact of our own making; it invalidated the whole third-party test.
            // --sweep-repeat <seconds>: keep re-sweeping for this long. Needed for the traceroute-timing test —
            // if each target port is only error-receptive for ~30ms after a probe, a single 2s pass almost never
            // lands during a live window. Repeating for the whole session keeps re-covering the ports as they
            // cycle through their receptive windows. 0 = single pass (default).
            int sweepRepeatS = int.Parse(Arg("--sweep-repeat") ?? "0");
            var repeatStart = DateTime.UtcNow;
            int sweepPass = 0;
            do
            {
              sweepPass++;
              // Re-sample the random ports each pass so coverage COMPOUNDS across passes (spread mode only).
              if (spread && sweepPass > 1)
              {
                  var pick2 = new HashSet<int>();
                  var r2 = new Random((c.Port * sweepPass) ^ (int)(DateTime.UtcNow.Ticks & 0x7fffffff));
                  while (pick2.Count < Math.Min(width, 64000)) pick2.Add(r2.Next(1024, 65536));
                  order = new List<int>(pick2);
              }
              foreach (int guess in order)
              {
                try { while (su.Available > 0) { EndPoint _d = new IPEndPoint(IPAddress.Any, 0); su.ReceiveFrom(buf, ref _d); } } catch { }
                if (warmSock != null && warmSw.Elapsed.TotalSeconds >= nextWarm)
                {
                    nextWarm = warmSw.Elapsed.TotalSeconds + 0.5;
                    // A "warm" flow is only warm if the destination ANSWERS. Sending "WARM" to a closed port
                    // creates a one-way flow into a black hole — which is what the first two warm-dest attempts
                    // actually did (1.1.1.1:51998 is closed and Cloudflare suppresses ICMP errors; the peer's NAT
                    // drops everything). To port 53 we send a REAL DNS query so the resolver replies and the flow
                    // is genuinely bidirectional.
                    try
                    {
                        byte[] warmPkt;
                        if (quoteDstPort == 53)
                        {
                            // Minimal DNS query for "a.root-servers.net" A record.
                            warmPkt = new byte[] {
                                0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
                                0x01,(byte)'a', 0x0c,(byte)'r',(byte)'o',(byte)'o',(byte)'t',(byte)'-',
                                (byte)'s',(byte)'e',(byte)'r',(byte)'v',(byte)'e',(byte)'r',(byte)'s',
                                0x03,(byte)'n',(byte)'e',(byte)'t', 0x00, 0x00,0x01, 0x00,0x01 };
                        }
                        else warmPkt = Encoding.ASCII.GetBytes("WARM");
                        warmSock.SendTo(warmPkt, new IPEndPoint(warmDest, quoteDstPort));
                        // Drain any reply so the flow is demonstrably two-way.
                        try
                        {
                            var wrb = new byte[512];
                            EndPoint wfrom = new IPEndPoint(IPAddress.Any, 0);
                            int wn = warmSock.ReceiveFrom(wrb, ref wfrom);
                            if (wn > 0 && warmReplies++ == 0)
                                Console.WriteLine($"[server] ✓ WARM flow to {warmDest}:{quoteDstPort} is BIDIRECTIONAL ({wn}B reply)");
                        }
                        catch (SocketException) { }
                    }
                    catch { }
                }
                var gp = tcpQuote
                    ? BuildDestUnreachQuotingTcpSyn(c.Address, guess, quoteDst, quoteDstPort, 0x11223344u, fType, fCode)
                    : BuildDestUnreachQuotingUdp(c.Address, guess, quoteDst, quoteDstPort, fType, fCode, 8, quoteBody, quoteIpId);
                try { sraw.SendTo(gp, new IPEndPoint(c.Address, 0)); fired++; } catch { }
                next = next.AddMilliseconds(gap);
                var wait = (next - DateTime.UtcNow).TotalMilliseconds;
                if (wait > 1) Thread.Sleep((int)wait);
                if (fired % 500 == 0)
                    Console.WriteLine($"[server]   …{fired}/{hi - lo + 1} fired ({(DateTime.UtcNow - swStart).TotalSeconds:F1}s)");
            }
            } while (sweepRepeatS > 0 && (DateTime.UtcNow - repeatStart).TotalSeconds < sweepRepeatS);
            Console.WriteLine($"[server] SWEEP DONE: {fired} guesses over {sweepPass} pass(es) in {(DateTime.UtcNow - swStart).TotalSeconds:F1}s. " +
                              $"The client should report exactly ONE hit, on port {c.Port}.");
            Console.WriteLine("[server]   • hit on " + c.Port + " only  → sweep WORKS, and survives sustained unmatched errors");
            Console.WriteLine("[server]   • no hit at all            → the NAT rate-limited/stopped answering under load");
            Console.WriteLine("[server]   • hit on a DIFFERENT port  → false positive, the NAT leaks matches (would be");
            Console.WriteLine("[server]     invisible in a peer-to-peer test where nobody knows the right answer)");
            continue;
        }

        Console.WriteLine($"[server] forging 1 CORRECT quote + {nWrong} controls back at it…");

        var rng = new Random(20260721);
        var quotes = new List<(int p, bool ok)> { (c.Port, true) };
        for (int i = 0; i < nWrong; i++)
        {
            int w; do { w = rng.Next(1024, 65535); } while (w == c.Port);
            quotes.Add((w, false));
        }
        foreach (var (p, ok) in quotes)
        {
            // Quote: "a packet went client-public:p → server:sport and was undeliverable".
            var pkt = BuildDestUnreachQuotingUdp(c.Address, p, quoteDst, quoteDstPort, fType, fCode, 8, quoteBody, quoteIpId);
            // SELF-CHECK before sending: re-parse the bytes we are about to put on the wire and print what a
            // RECEIVER would see. A previous run emitted "ICMP 0.0.0.0 udp port 51999 unreachable" — well-formed
            // but semantically void — and it took tcpdump to notice. Verify, don't assume.
            string quoteDesc = DescribeQuote(pkt);
            try
            {
                sraw.SendTo(pkt, new IPEndPoint(c.Address, 0));
                Console.WriteLine($"[server]   quoted {c.Address}:{p} → us:{sport}  {(ok ? "★ CORRECT (verified)" : "(control)")}");
                Console.WriteLine($"[server]     on-wire quote reads: {quoteDesc}");
            }
            catch (Exception e) { Console.WriteLine($"[server]   FAILED {p}: {e.Message}"); }
            Thread.Sleep(300);
        }
        Console.WriteLine("[server] sent. Check the CLIENT's output for which quotes its NAT accepted.");
    }
}

// ── ECHO MODE — a bare UDP responder the PEER runs. ─────────────────────────────────────────────────────
//
// Purpose: turn the punch flows from SINGLE:NO_TRAFFIC into MULTIPLE:MULTIPLE in the sender's firewall.
// pfSense/pf distinguishes a half-open flow (packets out, none back) from an established one, and an
// ICMP-error correlation may only be honoured for the latter. Every oracle hit so far involved a flow whose
// destination was the forging server's own machine; the one blind test against a genuinely unrelated peer
// showed SINGLE:NO_TRAFFIC states and no hit despite a full 64k sweep. This isolates that variable: the peer
// answers, the state becomes established, and the server still cannot see the flow.
//
//   peer:  NatErrorOracle --echo --port 51998
if (Array.IndexOf(args, "--echo") >= 0)
{
    int eport = int.Parse(Arg("--port") ?? "51998");
    using var es = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    es.Bind(new IPEndPoint(IPAddress.Any, eport));
    Console.WriteLine($"[echo] listening on :{eport}, echoing every datagram back to its sender.");
    Console.WriteLine($"[echo] this makes the SENDER's firewall state established (MULTIPLE:MULTIPLE)");
    Console.WriteLine($"[echo] rather than half-open (SINGLE:NO_TRAFFIC). Ctrl-C to stop.");
    var ebuf = new byte[2048];
    long echoed = 0;
    var seenFrom = new HashSet<string>();
    while (true)
    {
        EndPoint efrom = new IPEndPoint(IPAddress.Any, 0);
        int en;
        try { en = es.ReceiveFrom(ebuf, ref efrom); }
        catch (SocketException) { continue; }
        try { es.SendTo(ebuf, en, SocketFlags.None, efrom); echoed++; } catch { }
        string k = efrom.ToString();
        if (seenFrom.Add(k))
            Console.WriteLine($"[echo] new source {k}  (total distinct: {seenFrom.Count}, echoed: {echoed})");
    }
}

// ── TCP-BIRTHDAY MODE — N half-open TCP connects. Tests whether SYN_SENT state breaks the deadlock. ────────
//
// UDP birthday failed because a forged ICMP error is only honoured if the QUOTED INNER FLOW is in the receiver's
// NAT state table (RFC 5508 REQ-4), and an unreplied UDP flow may not create a durable enough entry. TCP creates
// a SYN_SENT state the instant we send the SYN, before any reply. If the NAT correlates ICMP errors against
// SYN_SENT, the forged quote matches and we get the hit — without the connection ever completing.
//
//   client:  NatErrorOracle --tcp-birthday --to <server> --dest-ip <peer> --dest-port 51998 --sockets 64
//   server:  NatErrorOracle --server --sweep --spread ... (it forges TCP quotes once told proto=tcp)
// ── TRACEROUTE-PRIMED MODE — the user's idea. Does traceroute state accept a forged Time-Exceeded? ───────
//
// Every prior test forged an error against a PLAIN one-way UDP flow (SINGLE:NO_TRAFFIC) and it was dropped when
// the quoted destination was a third party. But a TRACEROUTE flow is different in kind: the client sends LOW-TTL
// packets, so the NAT has state it SPECIFICALLY EXPECTS a Time-Exceeded reply for — and Time-Exceeded
// legitimately arrives from arbitrary middle routers, so the NAT may accept it from ANY source. If a forged
// Time-Exceeded against a traceroute-primed flow gets through where a forged error against a plain flow did not,
// the priming is the difference and this cracks it.
//
//   client:  NatErrorOracle --traceroute --to <server> --dest-ip <peer> --dest-port 33434 --sockets 64 --ttl 5
//   server:  NatErrorOracle --server --sweep --spread --icmp-type 11 ... (forges Time-Exceeded quoting the flow)
// ── REVERSE-ORACLE — peer B forges the error, and B is ON-PATH by definition (it IS the destination). ────
//
// THE ESCAPE FROM TRANSIT FILTERING. Every forged-error test died because a third-party server is NOT on the
// path to the quoted destination, so carriers drop the error in transit. But if PEER B forges an error about
// A's flow to B, the error's source (B) IS the destination A is sending to — trivially on-path. A real router
// near B and B itself are both legitimate sources for such an error, so transit cannot filter it as off-path.
//
// A has real outbound state for A->B (A is actively sending), so A's NAT translates the error inward per
// RFC 5508 REQ-4. This combines the two things that worked separately: one-way-state matching (proven) + an
// on-path source (B is the endpoint).
//
//   role A (learns):  NatErrorOracle --reverse-a --peer <B-public> --peer-port <n> --seconds 60
//   role B (forges):  NatErrorOracle --reverse-b --peer <A-public> --peer-port <n> --seconds 60
// A sends UDP to B and listens (raw ICMP) for B's forged error quoting the flow. B receives A's packets, reads
// A's real external source port, and forges an ICMP error back to A quoting A-ext:port -> B:port.
// DUO: both peers run this simultaneously. Each keeps a live UDP flow to peer:pport, blind-forges ICMP
// port-unreachables at the peer (quoting peer-pub:<guess> -> my-pub:pport) to make the PEER's NAT reveal
// OUR external port to the peer, and listens for the peer's forged errors to discover the peer's external
// port toward us. If both HIT, both external ports are known and a normal punch follows.
// Windows forge path = Npcap L2 inject (--npcap); Linux = raw socket. Requires --my-public and --peer.
if (Array.IndexOf(args, "--reverse-duo") >= 0)
{
    var dpeer = IPAddress.Parse(Arg("--peer"));
    int pport = int.Parse(Arg("--peer-port") ?? "51998");
    int secs = int.Parse(Arg("--seconds") ?? "90");
    int rate = int.Parse(Arg("--sweep-rate") ?? "1000");
    int fType = int.Parse(Arg("--icmp-type") ?? "3");
    int fCode = int.Parse(Arg("--icmp-code") ?? "3");
    IPAddress lsrc = IPAddress.Any;
    try { using var pr = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); pr.Connect(dpeer, 9); lsrc = ((IPEndPoint)pr.LocalEndPoint).Address; } catch {}
    var mypub = Arg("--my-public") != null ? IPAddress.Parse(Arg("--my-public")) : lsrc;
    Console.WriteLine($"[DUO] local={lsrc}");
    bool useNpcap = Array.IndexOf(args, "--npcap") >= 0;
    var body = Encoding.ASCII.GetBytes("HELLO-DUO");

    // Keep-alive + listen socket, bound to the fixed port so both directions share one NAT mapping.
    const int RCV = unchecked((int)0x98000001);
    Socket icmp;
    try { icmp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp); icmp.Bind(new IPEndPoint(lsrc,0)); icmp.ReceiveTimeout=20; if (OperatingSystem.IsWindows()) icmp.IOControl(RCV, BitConverter.GetBytes(1), null); }
    catch (SocketException e) { Console.WriteLine($"✗ raw ICMP recv failed ({e.SocketErrorCode}) — run ELEVATED."); return 1; }
    var ru = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    ru.Bind(new IPEndPoint(IPAddress.Any, pport));
    int mylocal = pport;

    // Forge sender: Npcap L2 (Windows) or raw HDRINCL (Linux).
    SharpPcap.LibPcap.LibPcapLiveDevice dev = null; byte[] eth = null;
    Socket fraw = null;
    if (useNpcap)
    {
        foreach (var d in SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance)
            foreach (var a in d.Addresses)
                if (a.Addr?.ipAddress != null && a.Addr.ipAddress.Equals(lsrc)) { dev = d; break; }
        if (dev == null) { Console.WriteLine($"✗ no Npcap device bound to {lsrc}."); return 1; }
        var srcMac = dev.MacAddress; var gwMac = ResolveGatewayMac(lsrc);
        if (gwMac == null) { Console.WriteLine("✗ no gateway MAC (ping gateway once, retry)."); return 1; }
        dev.Open(new SharpPcap.DeviceConfiguration { Mode = SharpPcap.DeviceModes.None });
        eth = BuildEthHeader(srcMac, gwMac);
        Console.WriteLine($"[DUO] forge=Npcap L2 dev={dev.Description} srcMAC={srcMac} gwMAC={gwMac}");
    }
    else
    {
        try { fraw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP); fraw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true); fraw.Bind(new IPEndPoint(lsrc,0)); }
        catch (SocketException e) { Console.WriteLine($"✗ raw forge failed ({e.SocketErrorCode})."); return 1; }
        Console.WriteLine($"[DUO] forge=raw HDRINCL");
    }

    Console.WriteLine($"=== REVERSE-ORACLE DUO === me-pub={mypub} dpeer={dpeer} port={pport} rate={rate} type {fType}/{fCode} {secs}s");
    Console.WriteLine($"[DUO] keepalive me->{dpeer}:{pport} from :{mylocal}; forging dpeer-pub:<guess> -> me-pub:{pport}; listening for dpeer's error");
    var t0=DateTime.UtcNow;
    int hits=0, dforged=0, seenFromPeer=0; var rnd=new Random(0x1D0 ^ (int)(lsrc.GetAddressBytes()[3]));
    double gap=1000.0/Math.Max(1,rate);
    var stop=new bool[1];

    // DECISIVE ANTI-SELF-CONFUSION MARKERS. A's own outbound forges (seen via SIO_RCVALL) and any hairpinned copy
    // carry the shape A FORGES; a genuine hit is the copy the PEER forged and OUR NAT translated inward. To tell
    // them apart we control the QUOTED payload+inner-id: the forge quotes what the PEER's keepalive sends, so each
    // side's keepalive stamps a UNIQUE body ("KA-<lastoctet-of-my-pub>") and the forge quotes the PEER's body with
    // the PEER's chosen inner id. A packet arriving that quotes OUR-pub-as-inner-src + the PEER's body = a real
    // peer forge our NAT delivered. A loop of our own forge quotes the peer as inner-src (different) — rejected.
    var myMark   = mypub.GetAddressBytes()[3];
    var peerMark = dpeer.GetAddressBytes()[3];
    var myKaBody   = Encoding.ASCII.GetBytes($"KA-{myMark:X2}--");   // what WE send on keepalive (peer will quote it)
    var peerKaBody = Encoding.ASCII.GetBytes($"KA-{peerMark:X2}--"); // what the PEER sends (WE quote it in our forge)
    ushort myInnerId   = (ushort)(0xE000 | myMark);
    ushort peerInnerId = (ushort)(0xE000 | peerMark);
    Console.WriteLine($"[DUO] my keepalive body='{Encoding.ASCII.GetString(myKaBody)}'; my forge quotes peer body='{Encoding.ASCII.GetString(peerKaBody)}' id=0x{myInnerId:X4}");

    // Thread 1: keepalive (holds OUR NAT me->dpeer state that the dpeer's forge matches). Sends OUR unique body.
    var kaT = new Thread(() => {
        while (!stop[0] && (DateTime.UtcNow-t0).TotalSeconds<secs)
        { try { ru.SendTo(myKaBody, new IPEndPoint(dpeer,pport)); } catch {}
          while (ru.Available>0){ try { var jb=new byte[64]; EndPoint _d=new IPEndPoint(IPAddress.Any,0); ru.ReceiveFrom(jb, ref _d); } catch { break; } }
          Thread.Sleep(200); }
    }){ IsBackground=true }; kaT.Start();

    // Thread 2: blind-forge at the dpeer. Quotes what the PEER's keepalive sends (peerKaBody), stamped with OUR
    // inner id so the peer can attribute the hit to us.
    var fT = new Thread(() => {
        var next=DateTime.UtcNow;
        while (!stop[0] && (DateTime.UtcNow-t0).TotalSeconds<secs)
        {
            int guess=rnd.Next(1024,65536);
            var ic=BuildDestUnreachQuotingUdp(dpeer, guess, mypub, pport, fType, fCode, 8, peerKaBody, myInnerId);
            var ip=WrapIpv4(lsrc, dpeer, 1, 64, 0x4000, ic);
            if (useNpcap){ var fr=new byte[14+ip.Length]; eth.CopyTo(fr,0); ip.CopyTo(fr,14); try{ dev.SendPacket(fr); Interlocked.Increment(ref dforged); }catch{} }
            else { try{ fraw.SendTo(ip, new IPEndPoint(dpeer,0)); Interlocked.Increment(ref dforged); }catch{} }
            next=next.AddMilliseconds(gap); var w=(next-DateTime.UtcNow).TotalMilliseconds; if(w>1) Thread.Sleep((int)w);
        }
    }){ IsBackground=true }; fT.Start();

    // Main thread: listen for the dpeer's dforged error reaching us — TRANSLATED INWARD.
    // CRITICAL: the raw socket has SIO_RCVALL (promiscuous), so it ALSO sees OUR OWN outbound forges and any
    // untranslated inbound. A genuine hit is ONLY one the NAT un-translated: the quote's inner DST must be our
    // PRIVATE address (lsrc), because the NAT rewrites B-pub -> B-priv on the way in. A packet still showing our
    // PUBLIC inner dst was NOT translated by the NAT — it's promiscuous noise (or our own forge looping), NOT a hit.
    var buf=new byte[2048];
    while ((DateTime.UtcNow-t0).TotalSeconds<secs)
    {
        EndPoint f=new IPEndPoint(IPAddress.Any,0); int n; try{ n=icmp.ReceiveFrom(buf, ref f);}catch(SocketException){continue;}
        int ih=(buf[0]&0x0F)*4; if(n<ih+8)continue; byte rtype=buf[ih]; int emb=ih+8; if(n<emb+20+8)continue;
        int eih=(buf[emb]&0x0F)*4, eu=emb+eih; if(n<eu+8)continue;
        var esrc=new IPAddress(new[]{buf[emb+12],buf[emb+13],buf[emb+14],buf[emb+15]});
        var edst=new IPAddress(new[]{buf[emb+16],buf[emb+17],buf[emb+18],buf[emb+19]});
        ushort einnerId=(ushort)((buf[emb+4]<<8)|buf[emb+5]);
        int esp=(buf[eu]<<8)|buf[eu+1]; int edp=(buf[eu+2]<<8)|buf[eu+3];
        // Quoted payload (after inner IP+UDP headers) — the body the forger claimed we sent.
        int qpay=eu+8; string qbody = n>=qpay+8 ? Encoding.ASCII.GetString(buf, qpay, Math.Min(8, n-qpay)) : "";
        var outer=((IPEndPoint)f).Address;
        // DIAGNOSTIC: log every ICMP error whose outer src is the peer, showing the un-translated inner tuple.
        if (outer.Equals(dpeer))
        {
            if (Interlocked.Increment(ref seenFromPeer) <= 30)
                Console.WriteLine($"[DUO] rx from peer: type {rtype} innerId=0x{einnerId:X4} quote {esrc}:{esp} -> {edst}:{edp} body='{qbody}'  (HIT needs inner-src={lsrc}, i.e. NAT un-translated it)");
        }
        // Genuine translated hit — the ONE discriminator that can't be self-forged:
        //  1. outer src = peer (the forger)
        //  2. inner src = OUR PRIVATE (lsrc). We WROTE peer-pub as the inner src in our own forges; only OUR NAT,
        //     matching the quote to our real outbound flow, rewrites it to our private. A loop/hairpin of our own
        //     forge still shows peer-pub. So inner-src==lsrc is unforgeable proof the NAT translated a PEER forge.
        //  3. inner dst = peer-pub:pport
        // NOTE: we do NOT gate on inner IP id or payload — the NAT matches RFC 5508 on the 5-tuple; A's real
        // outbound packets carry A's OS-assigned id which B cannot predict, so forcing an id would never match.
        bool translated = outer.Equals(dpeer) && esrc.Equals(lsrc) && edst.Equals(dpeer) && edp==pport;
        if(translated){ hits++; Console.WriteLine($"[DUO] ★★★ HIT #{hits} at +{(DateTime.UtcNow-t0).TotalSeconds:F2}s — inner-src un-translated to OUR PRIVATE {lsrc} (quote {esrc}:{esp} -> {edst}:{edp}, id=0x{einnerId:X4}). Only our NAT matching a PEER forge does this — NOT self-forgeable. Real inbound path from peer."); }
    }
    stop[0]=true;
    Console.WriteLine($"\n=== DUO RESULT === dforged={dforged} hits={hits} icmp-errors-seen-from-peer={seenFromPeer}");
    if (hits==0 && seenFromPeer>0) Console.WriteLine("[DUO] ⚠ peer's ICMP errors ARRIVE but none translated inward (inner-src never == our private). NAT is NOT matching the quote to our outbound flow — coverage or mapping issue.");
    if (seenFromPeer==0) Console.WriteLine("[DUO] ⚠ ZERO ICMP errors seen from peer — peer's forge is not reaching our host at all (transit drop, or peer injecting on wrong iface).");
    Console.WriteLine(hits>0?"★ BIDIRECTIONAL on-path forge DELIVERED. Both sides should see hits ⇒ both external ports discoverable ⇒ punch.":"✗ No inbound hit. Check the dpeer's forge is egressing (Npcap L2 on Windows) and both keepalives are live.");
    icmp.Dispose(); if(useNpcap) dev.Close(); else fraw?.Dispose(); return 0;
}

if (Array.IndexOf(args, "--reverse-a") >= 0)
{
    var bpub = IPAddress.Parse(Arg("--peer"));
    int pport = int.Parse(Arg("--peer-port") ?? "51998");
    int secs = int.Parse(Arg("--seconds") ?? "60");
    IPAddress lsrc = IPAddress.Any;
    try { using var pr = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); pr.Connect(bpub, 9); lsrc = ((IPEndPoint)pr.LocalEndPoint).Address; } catch {}
    const int RCV = unchecked((int)0x98000001);
    Socket icmp;
    try { icmp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp); icmp.Bind(new IPEndPoint(lsrc,0)); icmp.ReceiveTimeout=50; if (OperatingSystem.IsWindows()) icmp.IOControl(RCV, BitConverter.GetBytes(1), null); }
    catch (SocketException e) { Console.WriteLine($"✗ raw ICMP failed ({e.SocketErrorCode}) — run ELEVATED."); return 1; }
    using var ru = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    ru.Bind(new IPEndPoint(IPAddress.Any, 0));
    int mylocal = ((IPEndPoint)ru.LocalEndPoint).Port;
    // DISAMBIGUATION: A's REAL keepalive payload vs the payload B FORGES must differ. A genuine forge-hit carries
    // B's forged bytes (which A never sent); a REAL port-unreachable from B's kernel (if A's UDP actually reached
    // a closed port on B) would quote A's ACTUAL sent bytes. Requiring B's marker on receive rules the kernel case
    // out. B's --reverse-b now forges payload "FORGED-BY-B--" and inner id 0xB0B0 (neither used by A's keepalive).
    var kaPayload = Encoding.ASCII.GetBytes("REAL-A-KA---");
    var forgeMark = Encoding.ASCII.GetBytes("FORGED-BY-B-");
    const ushort FORGE_ID = 0xB0B0;
    Console.WriteLine($"=== REVERSE-ORACLE role A === sending UDP to {bpub}:{pport} from local :{mylocal}, listening for B's forged error, {secs}s");
    Console.WriteLine($"[A] my real keepalive payload='REAL-A-KA---'; a genuine hit must carry B's forge marker 'FORGED-BY-B-' + id 0x{FORGE_ID:X4} (proves it's B's forge, not my kernel/loopback).");
    var t0=DateTime.UtcNow; var lastTx=DateTime.MinValue; int hits=0, ambiguous=0; var buf=new byte[2048];
    while ((DateTime.UtcNow-t0).TotalSeconds<secs)
    {
        if ((DateTime.UtcNow-lastTx).TotalMilliseconds>200){ lastTx=DateTime.UtcNow; try { ru.SendTo(kaPayload, new IPEndPoint(bpub,pport)); } catch {} }
        EndPoint f=new IPEndPoint(IPAddress.Any,0); int n; try{ n=icmp.ReceiveFrom(buf, ref f);}catch(SocketException){continue;}
        int ih=(buf[0]&0x0F)*4; if(n<ih+8)continue; byte type=buf[ih]; int emb=ih+8; if(n<emb+20+8)continue;
        int eih=(buf[emb]&0x0F)*4, eu=emb+eih; if(n<eu+8)continue;
        var esrc=new IPAddress(new[]{buf[emb+12],buf[emb+13],buf[emb+14],buf[emb+15]});
        var edst=new IPAddress(new[]{buf[emb+16],buf[emb+17],buf[emb+18],buf[emb+19]}); int edp=(buf[eu+2]<<8)|buf[eu+3];
        ushort eid=(ushort)((buf[emb+4]<<8)|buf[emb+5]);
        int qp=eu+8; string qb = n>=qp+12 ? Encoding.ASCII.GetString(buf, qp, 12) : "";
        var outer=((IPEndPoint)f).Address;
        if(outer.Equals(bpub) && edst.Equals(bpub) && edp==pport)
        {
            bool isForge = eid==FORGE_ID && qb.StartsWith("FORGED-BY-B-");
            bool isRealKernel = qb.StartsWith("REAL-A-KA");
            if (isForge) { hits++; Console.WriteLine($"[A] ★★★ HIT #{hits} at +{(DateTime.UtcNow-t0).TotalSeconds:F2}s — B's FORGE (id 0x{eid:X4}, body '{qb}') translated inward (inner-src {esrc}). UNAMBIGUOUS: A never sends these bytes. ON-PATH FORGE WORKS."); }
            else if (isRealKernel) { ambiguous++; if(ambiguous<=5) Console.WriteLine($"[A] ⚠ REAL port-unreachable (body '{qb}', id 0x{eid:X4}) — B's KERNEL answered A's UDP (port closed). NOT a forge. This means A's UDP actually reached B."); }
            else { if(hits+ambiguous<5) Console.WriteLine($"[A] ? unexpected quote body='{qb}' id=0x{eid:X4} inner-src={esrc}"); }
        }
    }
    Console.WriteLine($"\n=== REVERSE-A RESULT === hits={hits}");
    Console.WriteLine(hits>0?"★ On-path peer-forged error DELIVERED. This is the escape — B (the destination) can signal A over A's own outbound state.":"✗ No hit. Either B's forged error didn't leave B's NAT correctly, or it was still dropped. Check B's tcpdump.");
    icmp.Dispose(); return 0;
}
if (Array.IndexOf(args, "--reverse-b") >= 0)
{
    // BLIND ON-PATH FORGE. B does NOT wait to receive A's UDP (it never will — that's the deadlock).
    // B sweeps A's external port range with forged ICMP errors quoting A-pub:<guess> -> B-pub:pport, exactly
    // like the server --sweep, EXCEPT the forge originates from B — the genuine on-path destination A is sending
    // to. This is the one variable never tested: the server forge died in transit for being OFF-path to the
    // quoted dst (B). Here the forger IS the quoted dst, so the transit/RPF filter should pass it.
    var apub = IPAddress.Parse(Arg("--peer"));            // A's public IP (quoted inner SRC + outer dst)
    int pport = int.Parse(Arg("--peer-port") ?? "51998"); // the port A sends to on B (quoted inner DST port)
    int secs = int.Parse(Arg("--seconds") ?? "60");
    int rate = int.Parse(Arg("--sweep-rate") ?? "1000");
    int width = int.Parse(Arg("--sweep-width") ?? "4000");
    int fType = int.Parse(Arg("--icmp-type") ?? "3");
    int fCode = int.Parse(Arg("--icmp-code") ?? "3");
    IPAddress lsrc = IPAddress.Any;
    try { using var pr = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); pr.Connect(apub, 9); lsrc = ((IPEndPoint)pr.LocalEndPoint).Address; } catch {}
    var bpub = Arg("--my-public") != null ? IPAddress.Parse(Arg("--my-public")) : lsrc;
    // Windows silently drops crafted ICMP errors on BOTH a ProtocolType.Icmp raw socket AND HDRINCL
    // (SendTo returns success, forged=N, send-errors=0, but NOTHING egresses — proven empirically twice).
    // The Windows raw-socket stack refuses to originate crafted ICMP error messages. The only path that puts
    // arbitrary bytes on the wire is LAYER-2 INJECTION via Npcap (pcap_sendpacket) — we bypass the IP stack
    // entirely and hand the NIC a full Ethernet frame. --npcap selects it; that's the real Windows send path.
    // DISTINCT FORGE MARKER: payload + inner id that A's real keepalive never uses. Lets A prove a hit is B's
    // forge (not A's own kernel port-unreachable, not a loopback). Must match A's --reverse-a expectation.
    var body = Encoding.ASCII.GetBytes("FORGED-BY-B-");
    const ushort FORGE_ID = 0xB0B0;
    var t0=DateTime.UtcNow; int fired=0, sendErr=0; double gap=1000.0/Math.Max(1,rate); var next=DateTime.UtcNow;
    var rnd = new Random(0x5EED ^ pport);
    ushort ipId = 0x4000;

    if (Array.IndexOf(args, "--npcap") >= 0)
    {
        // Resolve egress device (whose address == lsrc), its MAC, and the gateway MAC.
        SharpPcap.LibPcap.LibPcapLiveDevice dev = null;
        foreach (var d in SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance)
            foreach (var a in d.Addresses)
                if (a.Addr?.ipAddress != null && a.Addr.ipAddress.Equals(lsrc)) { dev = d; break; }
        if (dev == null) { Console.WriteLine($"✗ no Npcap device found bound to {lsrc}. Is Npcap installed / are you elevated?"); return 1; }
        var srcMac = dev.MacAddress ?? System.Net.NetworkInformation.PhysicalAddress.Parse("00-00-00-00-00-00");
        var gwMac = ResolveGatewayMac(lsrc);
        if (gwMac == null) { Console.WriteLine("✗ could not resolve gateway MAC (ARP/neighbor cache). Ping your gateway once, then retry."); return 1; }
        dev.Open(new SharpPcap.DeviceConfiguration { Mode = SharpPcap.DeviceModes.None });
        Console.WriteLine($"=== REVERSE-ORACLE role B (BLIND FORGE, NPCAP L2) === quoting {apub}:<guess> -> {bpub}:{pport}");
        Console.WriteLine($"[B] dev={dev.Description}; srcMAC={srcMac}; gwMAC={gwMac}; outer src={lsrc}; type {fType}/{fCode}; ~{rate}/s, {secs}s");
        Console.WriteLine($"[B] injecting at L2 (bypasses Windows raw-socket ICMP restriction). Not waiting for A's UDP.");
        var eth = BuildEthHeader(srcMac, gwMac);
        while ((DateTime.UtcNow-t0).TotalSeconds<secs)
        {
            int guess = rnd.Next(1024, 65536);
            var icmp = BuildDestUnreachQuotingUdp(apub, guess, bpub, pport, fType, fCode, 8, body, FORGE_ID);
            var ip = WrapIpv4(lsrc, apub, 1, 64, ipId++, icmp);
            var frame = new byte[14 + ip.Length];
            eth.CopyTo(frame, 0); ip.CopyTo(frame, 14);
            try { dev.SendPacket(frame); fired++; } catch { sendErr++; }
            next = next.AddMilliseconds(gap);
            var wait=(next-DateTime.UtcNow).TotalMilliseconds; if(wait>1) Thread.Sleep((int)wait);
            if (fired>0 && fired%1000==0) Console.WriteLine($"[B]   …{fired} injected ({(DateTime.UtcNow-t0).TotalSeconds:F1}s)");
        }
        dev.Close();
        Console.WriteLine($"\n=== REVERSE-B RESULT (NPCAP) === injected={fired}, send-errors={sendErr}");
        Console.WriteLine("[B] Check A for a HIT, AND Wireshark on B: did the forged errors leave with B's PUBLIC source?");
        Console.WriteLine($"[B]   filter:  icmp and ip.dst == {apub}");
        return 0;
    }

    // --- socket paths (both proven NOT to egress on Windows; kept for Linux / comparison) ---
    bool hdrincl = Array.IndexOf(args, "--no-hdrincl") < 0;
    Socket raw;
    try
    {
        if (hdrincl)
        {
            raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }
        else raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        raw.Bind(new IPEndPoint(lsrc,0));
    }
    catch (SocketException e){ Console.WriteLine($"✗ raw send failed ({e.SocketErrorCode}) — run ELEVATED."); return 1; }
    Console.WriteLine($"=== REVERSE-ORACLE role B (BLIND FORGE) === quoting {apub}:<guess> -> {bpub}:{pport}, sweeping A's ext port range");
    Console.WriteLine($"[B] send path = {(hdrincl ? "HDRINCL (full outer IP built here; outer src=" + lsrc + ")" : "ProtocolType.Icmp raw")}; type {fType}/{fCode}; ~{rate}/s, width {width}, {secs}s");
    Console.WriteLine($"[B] forging BLIND — not waiting for A's UDP. A must run --reverse-a and report any hit.");
    Console.WriteLine($"[B] NOTE on Windows both socket paths silently drop crafted ICMP errors — use --npcap.");
    SocketException lastErr=null;
    while ((DateTime.UtcNow-t0).TotalSeconds<secs)
    {
        int guess = rnd.Next(1024, 65536);   // random over full ephemeral range — allocations are scattered
        var icmp = BuildDestUnreachQuotingUdp(apub, guess, bpub, pport, fType, fCode, 8, body, FORGE_ID);
        var pkt = hdrincl ? WrapIpv4(lsrc, apub, 1, 64, ipId++, icmp) : icmp;
        try { raw.SendTo(pkt, new IPEndPoint(apub, 0)); fired++; }
        catch (SocketException e){ sendErr++; lastErr=e; }
        next = next.AddMilliseconds(gap);
        var wait=(next-DateTime.UtcNow).TotalMilliseconds; if(wait>1) Thread.Sleep((int)wait);
        if (fired>0 && fired%1000==0) Console.WriteLine($"[B]   …{fired} forged ({(DateTime.UtcNow-t0).TotalSeconds:F1}s)");
    }
    Console.WriteLine($"\n=== REVERSE-B RESULT === forged={fired}, send-errors={sendErr}" + (lastErr!=null?$" (last: {lastErr.SocketErrorCode})":""));
    if (sendErr>0) Console.WriteLine("[B] ⚠ some raw sends FAILED — check elevation / route. Forged count is what actually left the socket.");
    Console.WriteLine("[B] Now check role A for a HIT, AND tcpdump on B: did the forged errors leave with B's PUBLIC source?");
    Console.WriteLine($"[B]   tcpdump filter:  icmp and dst {apub}");
    raw.Dispose(); return 0;
}

if (Array.IndexOf(args, "--traceroute") >= 0 && Arg("--to") != null)
{
    var rsrv = IPAddress.Parse(Arg("--to"));
    int rctl = int.Parse(Arg("--port") ?? "51999");
    int rn = int.Parse(Arg("--sockets") ?? "64");
    bool matchReal = Array.IndexOf(args, "--match-real") >= 0;
    if (matchReal) { rn = 1; Console.WriteLine("[trace] --match-real: forcing 1 socket so the observed IP ID and swept port are the SAME flow."); }
    var rdest = Arg("--dest-ip") != null ? IPAddress.Parse(Arg("--dest-ip")) : rsrv;
    int rdport = int.Parse(Arg("--dest-port") ?? "33434");
    int rttl = int.Parse(Arg("--ttl") ?? "5");
    int rsecs = int.Parse(Arg("--seconds") ?? "60");

    Console.WriteLine($"=== TRACEROUTE-PRIMED === {rn} low-TTL(={rttl}) sockets → {rdest}:{rdport}, control → {rsrv}:{rctl}, {rsecs}s");
    Console.WriteLine($"    Each socket sends TTL={rttl} UDP so the NAT holds state EXPECTING a Time-Exceeded reply.");
    Console.WriteLine($"    The server forges Time-Exceeded quoting the flow. If the NAT accepts it where a plain");
    Console.WriteLine($"    forged error was dropped, traceroute priming is the difference. Watch for HITs.");
    Console.WriteLine($"    ⚠ Use --icmp-type 11 on the server, and run the CLIENT UNPRIV won't detect type 11 —");
    Console.WriteLine($"      run WITHOUT --unpriv so the raw socket sees the Time-Exceeded.");

    using var rctlsock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    rctlsock.Bind(new IPEndPoint(IPAddress.Any, rctl));
    rctlsock.ReceiveTimeout = 5;
    try { rctlsock.SendTo(Encoding.ASCII.GetBytes($"TARGET {rdest} {rdport}"), new IPEndPoint(rsrv, rctl)); } catch { }

    // Raw ICMP receive so we can see Time-Exceeded (type 11) — ConnectionReset only surfaces type 3.
    IPAddress rlsrc = IPAddress.Any;
    try { using var pr = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp); pr.Connect(rdest, 9); rlsrc = ((IPEndPoint)pr.LocalEndPoint).Address; } catch { }
    const int RCVALL2 = unchecked((int)0x98000001);
    Socket ricmp = null;
    try
    {
        ricmp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        ricmp.Bind(new IPEndPoint(rlsrc, 0));
        ricmp.ReceiveTimeout = 50;
        if (OperatingSystem.IsWindows()) ricmp.IOControl(RCVALL2, BitConverter.GetBytes(1), null);
    }
    catch (SocketException e) { Console.WriteLine($"✗ raw ICMP failed ({e.SocketErrorCode}) — run ELEVATED."); return 1; }

    // N low-TTL UDP sockets. We use ORDINARY UDP sockets (the NAT assigns the external port), but we also tell
    // the server the FIXED IP ID we want it to quote. The catch: an ordinary UDP send lets the OS pick the IP ID
    // per packet, so we CANNOT force it. To make the quote match the real packet's IP ID, the probe itself must
    // be crafted with a known IP ID — which needs a raw IP socket (IP_HDRINCL). We do that here.
    const ushort FIXED_IPID = 0x4242;
    try { rctlsock.SendTo(Encoding.ASCII.GetBytes($"IPID {FIXED_IPID}"), new IPEndPoint(rsrv, rctl)); } catch { }

    var rsocks = new List<Socket>(rn);
    var rlocalPorts = new List<int>(rn);
    for (int i = 0; i < rn; i++)
    {
        try
        {
            // Bind an ordinary UDP socket to reserve a local port, but SEND via a raw IP socket that writes the
            // full IP header with our fixed IP ID and the low TTL. The reserved local port is the UDP source port.
            var hold = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            hold.Bind(new IPEndPoint(IPAddress.Any, 0));
            int lport = ((IPEndPoint)hold.LocalEndPoint).Port;
            rsocks.Add(hold); rlocalPorts.Add(lport);
        }
        catch { }
    }
    // Raw IP send socket (HDRINCL) to emit the crafted low-TTL probes with FIXED_IPID.
    Socket rawtx = null;
    try
    {
        rawtx = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
        rawtx.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        rawtx.Bind(new IPEndPoint(rlsrc, 0));
    }
    catch (SocketException e) { Console.WriteLine($"✗ raw IP send failed ({e.SocketErrorCode}) — run ELEVATED."); return 1; }

    void FireProbes()
    {
        foreach (int lport in rlocalPorts)
        {
            var pkt = BuildRawUdp(rlsrc, lport, rdest, rdport, (byte)rttl, FIXED_IPID, Encoding.ASCII.GetBytes("PEERFLOW"));
            try { rawtx.SendTo(pkt, new IPEndPoint(rdest, 0)); } catch { }
        }
    }
    FireProbes();
    Console.WriteLine($"[trace] fired {rsocks.Count} low-TTL probes (IP ID 0x{FIXED_IPID:x4}) to {rdest}:{rdport} — server will quote this exact IP ID");

    var t0r = DateTime.UtcNow; var lastR = DateTime.UtcNow; var lastCtl = DateTime.MinValue; int rhits = 0; int realTE = 0; bool matchReported = false;
    var rbuf = new byte[2048];
    while ((DateTime.UtcNow - t0r).TotalSeconds < rsecs)
    {
        if ((DateTime.UtcNow - lastCtl).TotalMilliseconds > 500)
        {
            lastCtl = DateTime.UtcNow;
            try { rctlsock.SendTo(Encoding.ASCII.GetBytes($"TARGET {rdest} {rdport}"), new IPEndPoint(rsrv, rctl)); } catch { }
        }
        // Control keepalive only occasionally — the loop's job is to keep the low-TTL probes hot.
        // Re-fire the low-TTL probes CONTINUOUSLY (~every 5ms) to keep every socket in a fresh "just-sent,
        // awaiting-Time-Exceeded" state. TIMING HYPOTHESIS: a real Time-Exceeded arrives ~10-40ms after each
        // probe and may CLOSE the state (or end its error-receptive window). At 400ms re-fire there was only a
        // ~30ms live window per 400ms cycle — the sweep almost never landed on the right port DURING it. Firing
        // every 5ms keeps the window open almost continuously, giving the sweep a real chance to collide.
        // In --match-real, STOP re-firing once we've observed and reported an IP ID — so the state stays
        // associated with that exact last packet's IP ID, which is what we told the server to quote. Otherwise
        // keep the flow hot for the timing test.
        if (!(matchReal && matchReported) && (DateTime.UtcNow - lastR).TotalMilliseconds > 5)
        {
            lastR = DateTime.UtcNow;
            FireProbes();
        }
        // Watch for any Time-Exceeded whose quote names our flow to rdest.
        EndPoint rf = new IPEndPoint(IPAddress.Any, 0);
        int rnn;
        try { rnn = ricmp.ReceiveFrom(rbuf, ref rf); } catch (SocketException) { continue; }
        int ih = (rbuf[0] & 0x0F) * 4;
        if (rnn < ih + 8) continue;
        byte itype = rbuf[ih];
        int emb = ih + 8;
        if (rnn < emb + 20 + 8) continue;
        int eih = (rbuf[emb] & 0x0F) * 4, eu = emb + eih;
        if (rnn < eu + 8) continue;
        var edst = new IPAddress(new[] { rbuf[emb+16], rbuf[emb+17], rbuf[emb+18], rbuf[emb+19] });
        int edp = (rbuf[eu+2] << 8) | rbuf[eu+3];
        var outer = ((IPEndPoint)rf).Address;
        // OBSERVE-AND-MATCH: when a REAL router Time-Exceeded arrives quoting our flow, read the inner IP ID it
        // carries (the value Windows actually stamped — we cannot pin it via HDRINCL, but we CAN read it back).
        // Report that exact IP ID to the server so its forged quote is byte-identical to the real one. This is the
        // only way to get a matched forge from a Windows client.
        bool isRealRouterTE = edst.Equals(rdest) && edp == rdport && !outer.Equals(rsrv) && !outer.Equals(IPAddress.Parse("65.109.250.41"));
        if (isRealRouterTE && !matchReported)
        {
            int innerId = (rbuf[emb+4] << 8) | rbuf[emb+5];
            // inner src port (un-translated to internal by pf) — but we want the value pf MATCHED, which we can't
            // see. Report the IP ID; the server still sweeps the external port. Matching IP ID is the new variable.
            matchReported = true;
            try { rctlsock.SendTo(Encoding.ASCII.GetBytes($"IPID {innerId}"), new IPEndPoint(rsrv, rctl)); } catch { }
            Console.WriteLine($"[trace] observed REAL Time-Exceeded inner IP ID = 0x{innerId:x4} from {outer}; told server to quote it.");
        }
        // ONLY count errors from the SERVER's IPs. A TTL=5 probe genuinely expires at a real router ~5 hops out,
        // which sends a LEGITIMATE Time-Exceeded that the NAT delivers — that proves the state accepts errors, but
        // it is not the forged test. The forged ones come from the server (65.109.250.41 / 135.181.110.176).
        bool fromServer = outer.Equals(rsrv) || outer.Equals(IPAddress.Parse("65.109.250.41"));
        bool fromRealRouter = edst.Equals(rdest) && edp == rdport && !fromServer;
        if (fromRealRouter) realTE++;
        if (edst.Equals(rdest) && edp == rdport && fromServer)
        {
            rhits++;
            Console.WriteLine($"[trace] ★★★ FORGED HIT #{rhits} at +{(DateTime.UtcNow-t0r).TotalSeconds:F2}s — Time-Exceeded from THE SERVER ({outer}) " +
                              $"quoting our flow to {edst}:{edp} was DELIVERED INWARD. The forged error passed!");
        }
    }
    Console.WriteLine($"\n=== TRACEROUTE RESULT === sockets={rsocks.Count} HITS={rhits}");
    Console.WriteLine(rhits > 0
        ? "★★★ Traceroute priming WORKS. The NAT accepted a forged Time-Exceeded against a flow it expected one for,\n" +
          "  even from a third-party source. This is the escape — a peer-bound flow can be made forge-accepting."
        : "✗ No hit. Traceroute state is NOT more permissive — the forged Time-Exceeded was dropped like any other.\n" +
          "  Same wall: the quote must match established bidirectional state, priming does not relax it.");
    foreach (var sk in rsocks) { try { sk.Dispose(); } catch { } }
    ricmp.Dispose();
    return 0;
}

if (Array.IndexOf(args, "--tcp-birthday") >= 0 && Arg("--to") != null)
{
    var tsrv = IPAddress.Parse(Arg("--to"));
    int tctl = int.Parse(Arg("--port") ?? "51999");
    int tn = int.Parse(Arg("--sockets") ?? "64");
    var tdest = Arg("--dest-ip") != null ? IPAddress.Parse(Arg("--dest-ip")) : tsrv;
    int tdport = int.Parse(Arg("--dest-port") ?? "51998");
    int tsecs = int.Parse(Arg("--seconds") ?? "60");

    Console.WriteLine($"=== TCP-BIRTHDAY === {tn} half-open SYNs → {tdest}:{tdport}, control → {tsrv}:{tctl}, {tsecs}s");
    Console.WriteLine($"    Each connect() sends a SYN and creates a SYN_SENT state immediately. The server forges");
    Console.WriteLine($"    ICMP errors quoting the TCP flow; a hit means the NAT correlated against SYN_SENT.");

    using var tctlsock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    tctlsock.Bind(new IPEndPoint(IPAddress.Any, tctl));
    tctlsock.ReceiveTimeout = 5;
    // tell the server: TCP flow, this dest.
    try { tctlsock.SendTo(Encoding.ASCII.GetBytes($"TARGETTCP {tdest} {tdport}"), new IPEndPoint(tsrv, tctl)); } catch { }

    // N non-blocking TCP sockets, each firing a SYN at the peer. connect() to an unreachable peer stays in
    // SYN_SENT and eventually errors; we watch for ConnectionReset/refused (the translated ICMP error) meanwhile.
    var tsocks = new List<Socket>(tn);
    for (int i = 0; i < tn; i++)
    {
        try
        {
            var sk = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sk.Bind(new IPEndPoint(IPAddress.Any, 0));
            sk.Blocking = false;
            try { sk.Connect(new IPEndPoint(tdest, tdport)); } catch (SocketException) { } // WouldBlock — SYN sent
            tsocks.Add(sk);
        }
        catch { }
    }
    Console.WriteLine($"[tcp] fired {tsocks.Count} SYNs — check the firewall state table for SYN_SENT entries to {tdest}:{tdport}");

    var t0t = DateTime.UtcNow; var lastResyn = DateTime.UtcNow; int thits = 0;
    while ((DateTime.UtcNow - t0t).TotalSeconds < tsecs)
    {
        try { tctlsock.SendTo(Encoding.ASCII.GetBytes($"TARGETTCP {tdest} {tdport}"), new IPEndPoint(tsrv, tctl)); } catch { }

        // Poll each socket's error state. A translated ICMP error shows as ConnectionReset/refused here.
        foreach (var sk in tsocks)
        {
            try
            {
                var err = (int)sk.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Error);
                if (err == 10054 || err == 10061)   // WSAECONNRESET / WSAECONNREFUSED
                {
                    thits++;
                    Console.WriteLine($"[tcp] ★ HIT #{thits} at +{(DateTime.UtcNow - t0t).TotalSeconds:F2}s on {((IPEndPoint)sk.LocalEndPoint).Port} — error {err}");
                }
            }
            catch { }
        }

        // Re-arm SYNs periodically: SYN_SENT sockets time out (~21s on Windows) and the OS may reuse the port.
        if ((DateTime.UtcNow - lastResyn).TotalSeconds > 15)
        {
            lastResyn = DateTime.UtcNow;
            for (int i = 0; i < tsocks.Count; i++)
            {
                try { tsocks[i].Dispose(); } catch { }
                try
                {
                    var sk = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    sk.Bind(new IPEndPoint(IPAddress.Any, 0)); sk.Blocking = false;
                    try { sk.Connect(new IPEndPoint(tdest, tdport)); } catch (SocketException) { }
                    tsocks[i] = sk;
                }
                catch { }
            }
        }
        Thread.Sleep(20);
    }
    Console.WriteLine($"\n=== TCP-BIRTHDAY RESULT === sockets={tsocks.Count} HITS={thits}");
    Console.WriteLine(thits > 0
        ? "★ The NAT correlated a forged ICMP error against a SYN_SENT state. TCP breaks the deadlock where UDP\n" +
          "  could not — a half-open connection is enough state for the oracle to match."
        : "✗ No hit. The NAT does not correlate ICMP errors against SYN_SENT (only ESTABLISHED), so TCP does not\n" +
          "  help. This is the pwnat limitation. Check the state table showed SYN_SENT entries at all.");
    foreach (var sk in tsocks) { try { sk.Dispose(); } catch { } }
    return 0;
}

// ── BIRTHDAY MODE — N sockets, small sweep. THE ACTUAL DESIGN. ──────────────────────────────────────────
//
// Searching 64k ports for ONE allocation is the wrong problem. Open N sockets and each gets its OWN NAT
// allocation, so the sweeper only has to hit ANY of them: P(hit) = 1-(1-S/65536)^N.
//     256 sockets x  512 guesses = 86%      256 sockets x 1024 guesses = 98%
//     512 sockets x 1024 guesses = 99.97%
// So ~1000 forged packets in ~1s, instead of 64k over a minute — well inside conntrack lifetime and cheap
// enough that the rate/abuse concern largely disappears. Same reasoning as the ICMP punch's id spray and the
// existing 256-probe symmetric path in Tunnel.cs.
//
//   client:  NatErrorOracle --birthday --to <server> --sockets 256 --dest-port 51998
//   server:  NatErrorOracle --server --sweep --sweep-rate 1000 --sweep-width 1024 --discard-port 51998 ...
if (Array.IndexOf(args, "--birthday") >= 0 && Arg("--to") != null)
{
    var bsrv = IPAddress.Parse(Arg("--to"));
    int bport = int.Parse(Arg("--port") ?? "51999");
    int nSock = int.Parse(Arg("--sockets") ?? "256");
    int bdest = int.Parse(Arg("--dest-port") ?? "51998");
    int bsecs = int.Parse(Arg("--seconds") ?? "60");

    // --dest-ip: where the PUNCH SOCKETS point. Defaults to the server, which is the DEGENERATE case —
    // the server then RECEIVES our packets and can read every external port straight off the wire, so its
    // "sweep" is only ever confirming ports it already knows. Every earlier birthday run was in that state.
    //
    // The premise the whole design rests on is that the server can discover a port it CANNOT see. That only
    // happens when the punch sockets target the PEER: A→B packets never reach the server, so it must sweep
    // blind. Set --dest-ip to the peer's public IP for the real test.
    var bdestIp = Arg("--dest-ip") != null ? IPAddress.Parse(Arg("--dest-ip")) : bsrv;
    bool blindTest = !bdestIp.Equals(bsrv);

    Console.WriteLine($"=== BIRTHDAY MODE === {nSock} sockets → {bdestIp}:{bdest}, control → {bsrv}:{bport}, {bsecs}s");
    Console.WriteLine(blindTest
        ? "  ★ BLIND TEST: punch sockets target the PEER, so the server CANNOT see these flows and must sweep\n" +
          "    for real. This is the only configuration that tests the actual premise."
        : "  ⚠ DEGENERATE: punch sockets target the SERVER, so it receives them and already knows every port.\n" +
          "    Its sweep proves nothing. Pass --dest-ip <peer-public-ip> for the real test.");
    Console.WriteLine($"    P(hit) with S guesses over 64k: S=512 → {(1-Math.Pow(1-512.0/65536,nSock))*100:F1}%,  " +
                      $"S=1024 → {(1-Math.Pow(1-1024.0/65536,nSock))*100:F1}%");

    // Control socket to the server (learns nothing here, but keeps the server aware of us).
    using var bctl = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    bctl.Bind(new IPEndPoint(IPAddress.Any, bport));
    bctl.ReceiveTimeout = 5;

    // N punch sockets, each CONNECTED so the OS attributes an inbound ICMP error to it (that attribution is
    // the whole unprivileged detection mechanism — an unconnected socket has the error discarded).
    var socks = new List<Socket>(nSock);
    for (int i = 0; i < nSock; i++)
    {
        try
        {
            var sk = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sk.Bind(new IPEndPoint(IPAddress.Any, 0));   // ephemeral: each gets its own NAT allocation
            sk.ReceiveTimeout = 1;
            sk.Connect(new IPEndPoint(bdestIp, bdest));
            socks.Add(sk);
        }
        catch { }
    }
    Console.WriteLine($"[birthday] opened {socks.Count} connected sockets");
    Console.WriteLine($"[birthday] NOTE: check the firewall state table for these flows. A pf/pfSense state of");
    Console.WriteLine($"[birthday]   SINGLE:NO_TRAFFIC (packets out, none back) may not be eligible for ICMP-error");
    Console.WriteLine($"[birthday]   correlation, whereas MULTIPLE:MULTIPLE (established) is. If the sweep covers");
    Console.WriteLine($"[birthday]   every port and still misses, that state distinction is the leading suspect.");

    // Tell the server what to sweep for. In the blind test it has no other way to know.
    try
    {
        var tgt = Encoding.ASCII.GetBytes($"TARGET {bdestIp} {bdest}");
        bctl.SendTo(tgt, new IPEndPoint(bsrv, bport));
    }
    catch { }

    // When the punch destination is a DNS port, send a REAL query so the resolver ANSWERS and the flow becomes
    // bidirectional. Sending "PEERFLOW" to :53 is a malformed query that Cloudflare drops silently — Wireshark
    // showed exactly that ("Unknown operation (8) … Malformed Packet") and pfSense showed 9 packets out / 0 back,
    // i.e. SINGLE:NO_TRAFFIC. So the "warm" arm of this test was not warm at all and measured nothing.
    byte[] payload;
    if (bdest == 53)
    {
        payload = new byte[] {
            0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
            0x01,(byte)'a', 0x0c,(byte)'r',(byte)'o',(byte)'o',(byte)'t',(byte)'-',
            (byte)'s',(byte)'e',(byte)'r',(byte)'v',(byte)'e',(byte)'r',(byte)'s',
            0x03,(byte)'n',(byte)'e',(byte)'t', 0x00, 0x00,0x01, 0x00,0x01 };
        Console.WriteLine("[birthday] destination port is 53 — sending REAL DNS queries so the flows are bidirectional.");
    }
    else payload = Encoding.ASCII.GetBytes("PEERFLOW");

    var t0b = DateTime.UtcNow;
    var lastTx = DateTime.MinValue;
    int hits = 0;
    long txCount = 0;

    while ((DateTime.UtcNow - t0b).TotalSeconds < bsecs)
    {
        // Keep every mapping alive, and watch every socket for the translated error.
        if ((DateTime.UtcNow - lastTx).TotalMilliseconds > 400)
        {
            lastTx = DateTime.UtcNow;
            try { bctl.SendTo(Encoding.ASCII.GetBytes($"TARGET {bdestIp} {bdest}"), new IPEndPoint(bsrv, bport)); } catch { }
            for (int i = 0; i < socks.Count; i++)
            {
                try { socks[i].Send(payload); txCount++; }
                catch (SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.ConnectionReset ||
                        se.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        hits++;
                        int lp = ((IPEndPoint)socks[i].LocalEndPoint).Port;
                        Console.WriteLine($"[birthday] ★ HIT #{hits} at +{(DateTime.UtcNow - t0b).TotalSeconds:F2}s " +
                                          $"on socket #{i} (local :{lp}) — the sweep found THIS socket's external port.");
                    }
                }
            }
        }
        // Also poll receives, since the error can surface there instead.
        for (int i = 0; i < socks.Count; i++)
        {
            try { var rb = new byte[64]; socks[i].Receive(rb); }
            catch (SocketException se)
            {
                if (se.SocketErrorCode == SocketError.ConnectionReset ||
                    se.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    hits++;
                    int lp = ((IPEndPoint)socks[i].LocalEndPoint).Port;
                    Console.WriteLine($"[birthday] ★ HIT #{hits} at +{(DateTime.UtcNow - t0b).TotalSeconds:F2}s " +
                                      $"on socket #{i} (local :{lp}) — the sweep found THIS socket's external port.");
                }
            }
        }
        Thread.Sleep(5);
    }

    Console.WriteLine($"\n=== BIRTHDAY RESULT === sockets={socks.Count} packets sent={txCount} HITS={hits}");
    Console.WriteLine(hits > 0
        ? "★ The sweep found at least one socket's external port. With N sockets a SMALL sweep suffices —\n" +
          "  this is the design: ~1000 forged packets, ~1s, instead of a 64k full-range sweep."
        : "✗ No hit. Either the sweep was too narrow for this socket count, or it never overlapped an allocation.\n" +
          "  Check the server's guess count against the table above before concluding anything.");
    foreach (var sk in socks) { try { sk.Dispose(); } catch { } }
    return 0;
}

// ── CLIENT MODE — behind the NAT, talks to the public server ────────────────────────────────────────────
if (Arg("--to") != null)
{
    var srv = IPAddress.Parse(Arg("--to"));
    int cport = int.Parse(Arg("--port") ?? "51999");
    int runFor = int.Parse(Arg("--seconds") ?? "60");

    IPAddress lsrc = IPAddress.Any;
    try
    {
        using var rt = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        rt.Connect(srv, 9);
        lsrc = ((IPEndPoint)rt.LocalEndPoint).Address;
    }
    catch { }

    // SIO_RCVALL is a WINDOWS-ONLY ioctl and throws on Linux. It is also unnecessary there: a raw ICMP socket
    // with CAP_NET_RAW (or root) already receives every inbound ICMP, including errors generated for someone
    // else's datagram. On Windows it is mandatory — without it the kernel never surfaces those errors, which
    // silently produced a false negative in an earlier probe.
    // ── HOW DO WE RECEIVE THE TRANSLATED ERROR? ─────────────────────────────────────────────────────────
    // This decides whether the whole idea can be UNPRIVILEGED. Forging needs a raw socket (admin), but if the
    // MEDIATION SERVER does the forging, neither peer needs to send ICMP at all — they only need to RECEIVE the
    // error their own NAT translates inward. So: can that be done without elevation?
    //
    //   --unpriv  : skip the raw socket entirely and rely on the UDP socket's own error reporting. On Windows a
    //               connected UDP socket surfaces an inbound ICMP port-unreachable as SocketError.ConnectionReset
    //               on the next receive; on Linux the equivalent is IP_RECVERR. Neither needs privilege.
    //               If THAT works, the peer side of this design needs no driver and no admin at all.
    //   default   : raw socket (+ SIO_RCVALL on Windows), which reads the full quote but requires elevation.
    bool unpriv = Array.IndexOf(args, "--unpriv") >= 0;
    const int RCVALL = unchecked((int)0x98000001);
    Socket crx = null;
    if (!unpriv)
    {
        try
        {
            crx = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            crx.Bind(new IPEndPoint(lsrc, 0));
            crx.ReceiveTimeout = 200;
            if (OperatingSystem.IsWindows())
            {
                crx.IOControl(RCVALL, BitConverter.GetBytes(1), null);
                Console.WriteLine("[client] SIO_RCVALL enabled (Windows) — PRIVILEGED receive path.");
            }
            else Console.WriteLine("[client] raw ICMP open (Linux — CAP_NET_RAW/root) — PRIVILEGED receive path.");
        }
        catch (SocketException e)
        {
            Console.WriteLine($"✗ raw ICMP receive setup failed ({e.SocketErrorCode}).");
            Console.WriteLine(OperatingSystem.IsWindows()
                ? "  Windows: run as Administrator, or try --unpriv to test the no-privilege receive path."
                : "  Linux: sudo, or setcap cap_net_raw+ep ./NatErrorOracle, or try --unpriv");
            return 1;
        }
    }
    else
    {
        Console.WriteLine("[client] ⚠⚠ --unpriv DETECTS TYPE 3 ONLY. Windows maps an inbound ICMP PORT-UNREACHABLE");
        Console.WriteLine("[client]    (type 3/3) to SocketError.ConnectionReset, but a TIME-EXCEEDED (type 11) produces");
        Console.WriteLine("[client]    NO socket error at all — the packet is delivered to the stack and silently ignored.");
        Console.WriteLine("[client]    So --unpriv + --icmp-type 11 is STRUCTURALLY BLIND: it will report 0 hits even while");
        Console.WriteLine("[client]    Wireshark shows the forged errors arriving AND being un-translated by the NAT.");
        Console.WriteLine("[client]    That combination produced several false 'the NAT refuses third-party quotes'");
        Console.WriteLine("[client]    conclusions. For type 11, drop --unpriv and use the raw-socket path.");
        Console.WriteLine();
        Console.WriteLine("[client] --unpriv: NO raw socket. Detecting the translated ICMP error purely via the");
        Console.WriteLine("[client]           UDP socket's error reporting (ConnectionReset / IP_RECVERR).");
        Console.WriteLine("[client]           If this detects the hit, the peer side needs NO elevation at all.");
    }

    using var cu = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    cu.Bind(new IPEndPoint(IPAddress.Any, cport));
    cu.ReceiveTimeout = 50;
    // A CONNECTED UDP socket is what makes the OS attribute an inbound ICMP error to it. Unconnected sockets
    // generally have the error discarded, which is why the unprivileged path needs Connect() even though UDP
    // is connectionless. On Windows this makes the next Receive throw ConnectionReset; on Linux SIO_UDP_CONNRESET
    // has no effect but IP_RECVERR/ECONNREFUSED serves the same role.
    if (unpriv)
    {
        try
        {
            cu.Connect(new IPEndPoint(srv, cport));
            Console.WriteLine("[client] UDP socket CONNECTED to the server (required for ICMP error attribution).");
        }
        catch (Exception e) { Console.WriteLine($"[client] connect failed: {e.Message}"); }
    }

    // --third-party <ip>: ALSO keep a live UDP flow toward a THIRD host, and tell the server to forge quotes
    // naming THAT flow instead of the client→server one.
    //
    // WHY THIS IS THE DECISIVE TEST. Everything proven so far quoted a flow to the FORGER ITSELF — the client was
    // actively exchanging UDP with the server that forged the error. The real design needs the mediation server to
    // forge a quote describing the client's flow toward a PEER, i.e. a third party the forger has nothing to do
    // with. NATs may well treat that differently (an error from a host that is not part of the quoted conversation
    // is exactly the shape anti-spoofing logic targets). If this fails, the server-forges architecture is dead and
    // the peer must forge for itself — which puts the raw-socket/elevation requirement straight back.
    var thirdParty = Arg("--third-party") != null ? IPAddress.Parse(Arg("--third-party")) : null;
    // --peer-port also selects the DESTINATION port of the third-party flow. Set it to a port that actually
    // ANSWERS (e.g. 53 against 1.1.1.1) to create a genuinely BIDIRECTIONAL conntrack entry — that is the clean
    // discriminator for the inner-tuple theory: if a forged quote works for a flow the NAT demonstrably tracks,
    // the sender's identity is irrelevant and the peer-flow failure is purely "no such entry".
    int peerPort = int.Parse(Arg("--peer-port") ?? "52000");
    Socket cu3 = null;
    if (thirdParty != null)
    {
        // A SEPARATE local port from the server-facing socket — binding both to cport threw
        // "Only one usage of each socket address" (10048). Both peers use this same fixed peer-port so they
        // aim at each other without needing to exchange it.
        cu3 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        // Local bind port must NOT equal the server-facing socket's port (10048 collision), and need not equal
        // the DESTINATION port either. --peer-local-port sets the bind; --peer-port sets where we send.
        int peerLocalPort = int.Parse(Arg("--peer-local-port") ?? (peerPort == cport ? "0" : peerPort.ToString()));
        cu3.Bind(new IPEndPoint(IPAddress.Any, peerLocalPort));
        // MUST set this. Socket.ReceiveTimeout defaults to 0 == INFINITE, so the first cu3.Receive() in the
        // loop blocked forever and the peer-flow send below never ran — the socket transmitted NOTHING for the
        // whole run. Every "third-party: no hit" result tonight was this bug, not NAT behaviour: a Wireshark
        // filter on the peer flow showed no packets from us at all (only unrelated Tailscale traffic on 41641).
        cu3.ReceiveTimeout = 20;
        if (unpriv) { try { cu3.Connect(new IPEndPoint(thirdParty, peerPort)); } catch { } }
        Console.WriteLine($"[client] THIRD-PARTY flow enabled → {thirdParty}:{peerPort} from local :{((IPEndPoint)cu3.LocalEndPoint).Port}");
        Console.WriteLine($"[client] the server will forge quotes naming THIS flow, not the client→server one.");
        Console.WriteLine();
        Console.WriteLine("[client] ⚠ IMPORTANT — THE PEER MUST BE RUNNING THE SAME COMMAND, AIMED BACK AT US.");
        Console.WriteLine("[client]   A one-way flow into a host that never answers is NOT a live mapping: symmetric");
        Console.WriteLine("[client]   NATs age out unreplied UDP conntrack in ~30s (often faster on CGNAT). If the");
        Console.WriteLine("[client]   mapping is already gone, the forged quote has nothing to match and a 'no hit'");
        Console.WriteLine("[client]   result measures mapping lifetime, NOT whether third-party forging works.");
        Console.WriteLine("[client]   This also mirrors the real deployment, where both peers punch simultaneously.");
    }

    Console.WriteLine($"[client] {lsrc}:{cport} → server {srv}:{cport}, {(unpriv ? "UNPRIV" : "raw+RCVALL")}, {runFor}s");
    int myExt = 0, accepted = 0, peerFlowRx = 0; long peerFlowTx = 0;
    var cbuf = new byte[2048];
    var ibuf = new byte[2048];
    var t0 = DateTime.UtcNow; var lastTx = DateTime.MinValue;

    while ((DateTime.UtcNow - t0).TotalSeconds < runFor)
    {
        if ((DateTime.UtcNow - lastTx).TotalMilliseconds > 400)
        {
            lastTx = DateTime.UtcNow;
            // Tell the server which flow to target. With --third-party it must quote the client→thirdParty flow.
            var hello = Encoding.ASCII.GetBytes(thirdParty == null ? "HELLO" : $"TARGET {thirdParty} {peerPort}");
            try
            {
                if (unpriv) cu.Send(hello);                                  // socket is connected
                else cu.SendTo(hello, new IPEndPoint(srv, cport));
            }
            catch (SocketException se)
            {
                // A connected socket can also surface the ICMP error on SEND rather than receive.
                if (unpriv && (se.SocketErrorCode == SocketError.ConnectionReset ||
                               se.SocketErrorCode == SocketError.ConnectionRefused))
                {
                    accepted++;
                    Console.WriteLine($"[client] ★ HIT #{accepted} at +{(DateTime.UtcNow - t0).TotalSeconds:F2}s via UNPRIVILEGED path " +
                                      $"(on send: {se.SocketErrorCode}) — NAT translated a forged error inward.");
                }
            }
        }

        EndPoint uf = new IPEndPoint(IPAddress.Any, 0);
        try
        {
            int un = unpriv ? cu.Receive(cbuf) : cu.ReceiveFrom(cbuf, ref uf);
            var txt = Encoding.ASCII.GetString(cbuf, 0, un);
            if (txt.StartsWith("YOUREXT") && myExt == 0 && int.TryParse(txt.Substring(7).Trim(), out int me))
            {
                myExt = me;
                Console.WriteLine($"[client] server says our external port is {myExt} (VERIFIED — it received our packets)");
            }
        }
        catch (SocketException se)
        {
            // THE UNPRIVILEGED DETECTION. ConnectionReset here means the OS attributed an inbound ICMP
            // port-unreachable to this socket — i.e. our NAT translated the server's forged error inward and
            // the kernel matched it to our flow. Same signal the raw socket sees, with NO elevation.
            if (unpriv && (se.SocketErrorCode == SocketError.ConnectionReset ||
                           se.SocketErrorCode == SocketError.ConnectionRefused))
            {
                accepted++;
                Console.WriteLine($"[client] ★ HIT #{accepted} at +{(DateTime.UtcNow - t0).TotalSeconds:F2}s via UNPRIVILEGED path " +
                                  $"({se.SocketErrorCode}) — our NAT translated a forged error and the OS attributed it to our socket.");
            }
        }

        // Keep the third-party mapping alive, and watch IT for the translated error. This socket — not the
        // server-facing one — is the one whose mapping the forged quote must match.
        if (cu3 != null)
        {
            // Drain anything the peer sent us. If this NEVER fires, the third-party "flow" is one-way and its
            // NAT mapping is probably long dead — which invalidates any negative result from the sweep.
            try
            {
                var rb = new byte[512];
                int rn = unpriv ? cu3.Receive(rb) : cu3.ReceiveFrom(rb, ref uf);
                if (rn > 0 && peerFlowRx++ == 0)
                    Console.WriteLine($"[client] ✓ third-party flow is BIDIRECTIONAL — peer answered ({rn}B). Mapping is genuinely live.");
            }
            catch (SocketException se3r)
            {
                if (se3r.SocketErrorCode == SocketError.ConnectionReset || se3r.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    accepted++;
                    Console.WriteLine($"[client] ★★★ HIT #{accepted} at +{(DateTime.UtcNow - t0).TotalSeconds:F2}s on the THIRD-PARTY flow " +
                                      $"({se3r.SocketErrorCode}) — NAT matched a quote for a flow to {thirdParty}, forged by an " +
                                      "outside server. THE SERVER-FORGES DESIGN WORKS.");
                }
            }

            try
            {
                var ping3 = Encoding.ASCII.GetBytes("PEERFLOW");
                if (unpriv) cu3.Send(ping3); else cu3.SendTo(ping3, new IPEndPoint(thirdParty, peerPort));
                peerFlowTx++;
            }
            catch (SocketException se3)
            {
                if (se3.SocketErrorCode == SocketError.ConnectionReset || se3.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    accepted++;
                    Console.WriteLine($"[client] ★★★ HIT #{accepted} at +{(DateTime.UtcNow - t0).TotalSeconds:F2}s on the THIRD-PARTY flow " +
                                      $"({se3.SocketErrorCode}) — our NAT matched a quote describing a flow to {thirdParty}, " +
                                      "forged by a server that is NOT part of that conversation. THE SERVER-FORGES DESIGN WORKS.");
                }
            }
        }

        if (crx == null) continue;   // --unpriv: no raw socket; detection happens in the UDP paths above

        EndPoint inf = new IPEndPoint(IPAddress.Any, 0);
        int inn;
        try { inn = crx.ReceiveFrom(ibuf, ref inf); }
        catch (SocketException) { continue; }

        int ih = (ibuf[0] & 0x0F) * 4;
        if (inn < ih + 8) continue;
        int em = ih + 8;
        if (inn < em + 20 + 8) continue;
        int eih = (ibuf[em] & 0x0F) * 4, eu = em + eih;
        if (inn < eu + 8) continue;
        if (ibuf[em + 9] != 17) continue;
        var edst = new IPAddress(new[] { ibuf[em + 16], ibuf[em + 17], ibuf[em + 18], ibuf[em + 19] });
        int esp = (ibuf[eu] << 8) | ibuf[eu + 1];
        if (!((IPEndPoint)inf).Address.Equals(srv) || !edst.Equals(srv)) continue;

        accepted++;
        // NOTE: esp is what OUR NAT delivered, i.e. the UN-translated (internal) port — so a hit always shows
        // our local port, never the guess that matched. During a sweep the guess itself is invisible to us;
        // the SERVER knows which guess it was up to. Timing correlates them: report the hit time so the server
        // side can be matched against its fire log if we ever need the exact guess.
        Console.WriteLine($"[client] ★ HIT #{accepted} at +{(DateTime.UtcNow - t0).TotalSeconds:F2}s — our NAT accepted a forged quote; " +
                          $"delivered src port={esp}" +
                          $"{(esp == cport ? "  (== our server-flow LOCAL port → NAT translated it, genuine oracle hit)"
                              : cu3 != null && esp == ((IPEndPoint)cu3.LocalEndPoint).Port
                                ? "  (== our THIRD-PARTY socket's local port → NAT translated a quote for the PEER FLOW — this is the third-party result)"
                                : "  ⚠ unrecognised local port")}");
    }

    Console.WriteLine($"\n=== RESULT ===  our verified external port: {(myExt == 0 ? "never learned" : myExt.ToString())}, forged quotes accepted: {accepted}");

    // VALIDITY GATE. Without this the run cannot be interpreted at all: if we never transmitted on the peer
    // flow there was no NAT mapping for the forged quote to match, so "no hit" says nothing about the NAT.
    // (An earlier `cu3` with no ReceiveTimeout — .NET defaults to INFINITE — blocked the loop and sent zero
    // packets for an entire run, and that was reported as a NAT negative.)
    if (thirdParty != null)
    {
        Console.WriteLine($"  peer-flow packets SENT: {peerFlowTx}, received: {peerFlowRx}");
        if (peerFlowTx == 0)
        {
            Console.WriteLine("  ✗ INVALID RUN — we sent NOTHING on the peer flow, so no mapping ever existed and the");
            Console.WriteLine("    sweep had nothing to match. This is a bug on our side, not a NAT result.");
        }
        else if (peerFlowRx == 0)
        {
            Console.WriteLine("  ⚠ one-way peer flow (peer never answered). The mapping exists but is UNREPLIED, which");
            Console.WriteLine("    conntrack ages out in ~30s — so a miss may just mean the sweep arrived too late.");
        }
    }

    if (myExt == 0)
        Console.WriteLine("✗ Never heard from the server — is it running, and is UDP :" + cport + " open to it?");
    else if (accepted == 0)
    {
        Console.WriteLine("✗ NO HIT.");
        Console.WriteLine($"  ⚠ FIRST CHECK THE SERVER LOG: a full-range sweep at 500/s takes ~129s. If this client ran");
        Console.WriteLine($"    for only {runFor}s, it EXITED BEFORE THE SWEEP FINISHED and never saw the later guesses —");
        Console.WriteLine("    that is INCONCLUSIVE, not a negative. Re-run with --seconds comfortably above the sweep time.");
        Console.WriteLine();
        if (thirdParty != null)
        {
            Console.WriteLine($"  If the sweep DID complete: the NAT refused a quote describing our flow to {thirdParty}");
            Console.WriteLine("  forged by a server outside that conversation. Since the SAME NAT accepted a quote for a");
            Console.WriteLine("  flow to the forger itself, the difference is the source of the error, not the mechanism —");
            Console.WriteLine("  i.e. the NAT validates that the error comes from a party to the quoted flow.");
            Console.WriteLine("  → The server-forges design would be dead; the PEER must forge (needs elevation there).");
        }
        else
        {
            Console.WriteLine("  If the sweep DID complete: this carrier does not honour RFC 5508 here.");
        }
    }
    else if (accepted == 1)
        Console.WriteLine("★★★ ORACLE CONFIRMED: exactly ONE quote was translated inward.\n" +
                          "  The NAT matches the quoted 5-tuple against a live mapping → a peer CAN sweep guessed\n" +
                          "  ports and detect the hit. 1-D search, same shape as the working ICMP punch.\n" +
                          "  (In --sweep mode this also means the sweep SURVIVED the unmatched-error load and did\n" +
                          "   not produce a false positive — cross-check the port against the server's log.)");
    else
        Console.WriteLine($"~ {accepted} quotes accepted.\n" +
                          "  ONE-SHOT mode: if the CONTROLS got through too, the NAT forwards errors without matching,\n" +
                          "  so every guess 'succeeds' and there is no signal to sweep on.\n" +
                          "  SWEEP mode: >1 hit means the NAT matched more than one guess — false positives, which\n" +
                          "  would make a peer sweep report the wrong port. Check the server log for which guesses.");
    crx?.Dispose();   // null in --unpriv mode (no raw socket) — was an unguarded deref
    cu3?.Dispose();
    return 0;
}

if (Arg("--peer") == null)
{
    Console.WriteLine("NatErrorOracle — is a crafted ICMP error translated inward by a NAT?");
    Console.WriteLine();
    Console.WriteLine("RECOMMENDED (no bootstrap problem — needs a public-IP box):");
    Console.WriteLine("  --server [--port n] [--wrong n]        on the PUBLIC box (root)");
    Console.WriteLine("  --to <server-ip> [--port n]            on the NATted box (elevated)");
    Console.WriteLine();
    Console.WriteLine("PEER-TO-PEER (cannot bootstrap between two symmetric NATs — see notes in source):");
    Console.WriteLine("  --peer <peer-public-ip> --peer-ext-port <n> --verified");
    Console.WriteLine("  --forge-now                            just fire forged packets, to test the send path");
    return 1;
}

var peer = IPAddress.Parse(Arg("--peer"));
int port = int.Parse(Arg("--port") ?? "51999");
bool forgeOnly = Array.IndexOf(args, "--forge-now") >= 0;
int wrongCount = int.Parse(Arg("--wrong") ?? "3");
int seconds = int.Parse(Arg("--seconds") ?? "90");
long startAt = long.Parse(Arg("--start-at") ?? "0");

// Wire tags — plain ASCII so they are obvious in a capture.
const string FlowTag = "ORACLE-FLOW";
const string RepTag = "ORACLE-YOURPORT";   // "I observed your external port as N"

IPAddress localSource = IPAddress.Any;
try
{
    using var rt = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    rt.Connect(peer, 9);
    localSource = ((IPEndPoint)rt.LocalEndPoint).Address;
}
catch { }

Console.WriteLine("=== NatErrorOracle ===");
Console.WriteLine($"local {localSource}:{port}  ↔  peer {peer}:{port}   run {seconds}s");

// ── raw ICMP: receive (needs SIO_RCVALL on Windows) and send (forging) ──────────────────────────────────
// SIO_RCVALL is MANDATORY here. Without it Windows never surfaces ICMP errors generated for someone else's
// datagram, and the probe silently sees nothing — an earlier experiment produced a confident false negative
// for exactly this reason. It also requires binding a CONCRETE local IP; IPAddress.Any is rejected.
const int SIO_RCVALL = unchecked((int)0x98000001);
Socket icmpRx, icmpTx;
try
{
    icmpRx = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
    icmpRx.Bind(new IPEndPoint(localSource, 0));
    icmpRx.ReceiveTimeout = 200;
    icmpRx.IOControl(SIO_RCVALL, BitConverter.GetBytes(1), null);

    icmpTx = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
    icmpTx.Bind(new IPEndPoint(localSource, 0));
}
catch (SocketException e)
{
    Console.WriteLine($"✗ raw ICMP setup failed ({e.SocketErrorCode}). Run ELEVATED (Administrator / root).");
    return 1;
}

// --forge-now: fire forged packets IMMEDIATELY and exit, with no discovery and no waiting.
// Exists because the main flow gates forging behind learning the peer's external port, so a run that never
// learns it sends ZERO ICMP — and "I saw nothing outgoing in Wireshark" is then ambiguous between "the forge
// is broken" and "the forge never ran". This isolates the send path so it can be confirmed on the wire.
// Capture filter on either side:  icmp && ip.addr == <peer>
if (forgeOnly)
{
    int quoted = int.Parse(Arg("--peer-ext-port") ?? "12345");
    Console.WriteLine($"[forge-now] sending 5 ICMP dest-unreach to {peer}, quoting {peer}:{quoted} → {localSource}:{port}");
    Console.WriteLine($"[forge-now] watch locally with:  icmp && ip.dst == {peer}");
    for (int i = 0; i < 5; i++)
    {
        var p = BuildDestUnreachQuotingUdp(peer, quoted, localSource, port);
        try
        {
            int sentBytes = icmpTx.SendTo(p, new IPEndPoint(peer, 0));
            Console.WriteLine($"[forge-now]   #{i + 1} SendTo returned {sentBytes} bytes (packet is {p.Length}B)");
        }
        catch (Exception e) { Console.WriteLine($"[forge-now]   #{i + 1} FAILED: {e.GetType().Name}: {e.Message}"); }
        Thread.Sleep(300);
    }
    Console.WriteLine("[forge-now] done. If Wireshark shows nothing outbound, the raw ICMP send itself is blocked");
    Console.WriteLine("            (firewall / raw-socket restriction), and the oracle test cannot proceed.");
    icmpRx.Dispose(); icmpTx.Dispose();
    return 0;
}

using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
udp.Bind(new IPEndPoint(IPAddress.Any, port));
udp.ReceiveTimeout = 50;

// Synced start so both sides have live mappings during the forge phase.
if (startAt > 0)
{
    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    if (startAt > now)
    {
        Console.WriteLine($"waiting {(startAt - now) / 1000.0:F1}s for synced start…");
        while (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < startAt) Thread.Sleep(20);
    }
}
Console.WriteLine("started.\n");

// Supplied out-of-band (see the note at the forge step): between two symmetric NATs there is no way to LEARN
// this in-band, because sending to the peer's internal port number reaches nothing.
int peerExternalPort = int.Parse(Arg("--peer-ext-port") ?? "0");
bool portIsVerified = Array.IndexOf(args, "--verified") >= 0;
if (peerExternalPort != 0)
{
    Console.WriteLine($"peer external port supplied out-of-band: {peerExternalPort}" +
                      (portIsVerified ? "  (declared VERIFIED)" : "  ⚠ NOT declared verified — see warning below"));
    if (!portIsVerified)
    {
        Console.WriteLine();
        Console.WriteLine("  ⚠⚠ WARNING: without --verified this run CANNOT produce a negative result. A guessed or");
        Console.WriteLine("     placeholder port makes the 'correct' quote just another wrong guess, so 'nothing");
        Console.WriteLine("     arrived' is the expected outcome and says NOTHING about whether the NAT honours");
        Console.WriteLine("     RFC 5508. Read the peer's REAL external port off a capture on the PEER's machine");
        Console.WriteLine($"     (Wireshark filter: udp.port == {port}, take the SOURCE port of our inbound packets)");
        Console.WriteLine("     and re-run with --verified. Round numbers like 30000 are almost never real.");
        Console.WriteLine();
    }
}
int myExternalPort = 0;        // OUR external port, as the PEER reports it
bool forged = false;
long udpSent = 0, icmpSeen = 0;
var arrivals = new List<(int quotedPort, bool wasCorrect)>();
int[] controlPorts = Array.Empty<int>();

var start = DateTime.UtcNow;
var lastFlow = DateTime.MinValue;
var lastReport = DateTime.MinValue;
var udpBuf = new byte[2048];
var icmpBuf = new byte[2048];

while ((DateTime.UtcNow - start).TotalSeconds < seconds)
{
    // 1) Keep a REAL flow alive. The oracle can only match against a live translation entry.
    if ((DateTime.UtcNow - lastFlow).TotalMilliseconds > 400)
    {
        lastFlow = DateTime.UtcNow;
        var m = Encoding.ASCII.GetBytes($"{FlowTag} {++udpSent}");
        try { udp.SendTo(m, new IPEndPoint(peer, port)); } catch { }
    }

    // 2) Tell the peer what external port we see it on, so it learns its OWN port. Repeated because the
    //    first few may be lost while the other side's mapping is still being created.
    if (peerExternalPort != 0 && (DateTime.UtcNow - lastReport).TotalMilliseconds > 700)
    {
        lastReport = DateTime.UtcNow;
        var m = Encoding.ASCII.GetBytes($"{RepTag} {peerExternalPort}");
        try { udp.SendTo(m, new IPEndPoint(peer, port)); } catch { }
    }

    // 3) Drain inbound UDP — learn the peer's external port, and our own from its report.
    while (true)
    {
        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        int n;
        try { n = udp.ReceiveFrom(udpBuf, ref from); }
        catch (SocketException) { break; }
        var fep = (IPEndPoint)from;
        if (!fep.Address.Equals(peer)) continue;

        if (peerExternalPort == 0)
        {
            peerExternalPort = fep.Port;
            Console.WriteLine($"[obs] peer's external port = {peerExternalPort}  (learned in-band — unexpected between two symmetric NATs, but usable)");
        }

        var text = Encoding.ASCII.GetString(udpBuf, 0, n);
        if (text.StartsWith(RepTag) && myExternalPort == 0 &&
            int.TryParse(text.Substring(RepTag.Length).Trim(), out int mine))
        {
            myExternalPort = mine;
            Console.WriteLine($"[obs] peer reports OUR external port = {myExternalPort}  (this is the value its forged quote must match)");
        }
    }

    // 4) Once we know the peer's external port, forge ONE correct quote + N wrong controls.
    //    Controls are essential: without them "the correct one arrived" could simply mean the NAT forwards
    //    every error it receives, which would give no usable signal during a real sweep.
    //
    //    NOTE — WHY --peer-ext-port EXISTS. The first version of this tool tried to LEARN the peer's external
    //    port by sending UDP to peer:<port> and reading the source of whatever came back. That can never work
    //    between two symmetric NATs: our packets go to the peer's INTERNAL port number, which its NAT is not
    //    listening on, so nothing ever arrives in either direction (measured: 169 and 170 packets sent, zero
    //    received, both sides). It is the same bootstrap deadlock the oracle is meant to break — the tool
    //    required, as its first step, the very fact it was built to discover.
    //    So the correct port must come from OUT OF BAND (a capture, or the already-working ICMP mesh) and be
    //    passed in with --peer-ext-port. Our own outbound UDP above still matters: it creates the live mapping
    //    in OUR NAT that the peer's forged quote has to match.
    if (!forged && peerExternalPort != 0)
    {
        forged = true;
        var rng = new Random(20260721);
        var list = new List<(int p, bool ok)> { (peerExternalPort, true) };
        var ctrl = new List<int>();
        for (int i = 0; i < wrongCount; i++)
        {
            int w; do { w = rng.Next(1024, 65535); } while (w == peerExternalPort || ctrl.Contains(w));
            ctrl.Add(w); list.Add((w, false));
        }
        controlPorts = ctrl.ToArray();

        Console.WriteLine($"[forge] sending 1 CORRECT quote ({peerExternalPort}) + {wrongCount} controls ({string.Join(",", ctrl)})");
        foreach (var (p, ok) in list)
        {
            var pkt = BuildDestUnreachQuotingUdp(peer, p, localSource, port);
            try
            {
                icmpTx.SendTo(pkt, new IPEndPoint(peer, 0));
                Console.WriteLine($"[forge]   quoted {peer}:{p} → us:{port}  {(ok ? "★ CORRECT" : "(control)")}");
            }
            catch (Exception e) { Console.WriteLine($"[forge]   FAILED {p}: {e.Message}"); }
            Thread.Sleep(250);
        }
        Console.WriteLine();
    }

    // 5) Listen for ICMP errors our own NAT let through.
    {
        EndPoint from = new IPEndPoint(IPAddress.Any, 0);
        int n;
        try { n = icmpRx.ReceiveFrom(icmpBuf, ref from); }
        catch (SocketException) { continue; }
        icmpSeen++;

        int ipHdr = (icmpBuf[0] & 0x0F) * 4;
        if (n < ipHdr + 8) continue;
        byte type = icmpBuf[ipHdr];
        int emb = ipHdr + 8;
        if (n < emb + 20 + 8) continue;
        int embIpHdr = (icmpBuf[emb] & 0x0F) * 4;
        int embUdp = emb + embIpHdr;
        if (n < embUdp + 8) continue;
        if (icmpBuf[emb + 9] != 17) continue; // quoted proto must be UDP

        var embDst = new IPAddress(new[] { icmpBuf[emb + 16], icmpBuf[emb + 17], icmpBuf[emb + 18], icmpBuf[emb + 19] });
        int embSrcPort = (icmpBuf[embUdp] << 8) | icmpBuf[embUdp + 1];
        int embDstPort = (icmpBuf[embUdp + 2] << 8) | icmpBuf[embUdp + 3];
        var outerSrc = ((IPEndPoint)from).Address;

        // A forged arrival: it came FROM the peer and its quote describes our flow toward the peer.
        if (outerSrc.Equals(peer) && embDst.Equals(peer) && embDstPort == port)
        {
            // embSrcPort is what our NAT delivered. If it translated, this is our INTERNAL port.
            bool correct = myExternalPort != 0 && (embSrcPort == port || embSrcPort == myExternalPort);
            arrivals.Add((embSrcPort, correct));
            Console.WriteLine($"[recv] ★ FORGED ICMP ACCEPTED BY OUR NAT — type={type}, quote src port={embSrcPort}" +
                              $"{(embSrcPort == port ? " (== our LOCAL port → NAT translated it, oracle behaviour!)" : "")}");
        }
    }
}

// ── verdict ─────────────────────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\n=== RESULT ===");
Console.WriteLine($"udp sent={udpSent}  icmp seen={icmpSeen}");
Console.WriteLine($"peer external port (observed by us): {(peerExternalPort == 0 ? "never learned" : peerExternalPort.ToString())}");
Console.WriteLine($"our external port (reported by peer): {(myExternalPort == 0 ? "never learned" : myExternalPort.ToString())}");
Console.WriteLine($"forged quotes accepted by our NAT: {arrivals.Count}");
Console.WriteLine();

if (peerExternalPort == 0)
{
    Console.WriteLine("✗ INCONCLUSIVE — and NOT a timing problem. No UDP can arrive here by design:");
    Console.WriteLine($"  we send to {peer}:{port}, which is the peer's INTERNAL port number. Its symmetric NAT is");
    Console.WriteLine("  not listening there, so every packet is dropped at its edge — and vice versa. Sent counts");
    Console.WriteLine("  being high with zero received is the signature of exactly that.");
    Console.WriteLine();
    Console.WriteLine("  This IS the bootstrap deadlock the oracle exists to break, so the tool cannot bootstrap");
    Console.WriteLine("  itself. Supply the peer's real external port OUT OF BAND and re-run:");
    Console.WriteLine("      --peer-ext-port <n>");
    Console.WriteLine("  Get it from a capture on the peer (Wireshark: udp.port == " + port + ", read the source port");
    Console.WriteLine("  of our inbound packets), or over the already-working ICMP mesh.");
}
else if (arrivals.Count == 0 && !portIsVerified)
{
    Console.WriteLine("✗ INCONCLUSIVE — the quoted port was NOT verified, so this proves nothing.");
    Console.WriteLine($"  We quoted {peerExternalPort}, but nothing confirmed that is the peer's real external port.");
    Console.WriteLine("  If it was a guess or a placeholder then all four quotes were wrong and silence is exactly");
    Console.WriteLine("  what we should expect — regardless of whether the NAT honours RFC 5508.");
    Console.WriteLine();
    Console.WriteLine("  To get a real answer: capture on the PEER's machine, filter udp.port == " + port + ", read the");
    Console.WriteLine("  SOURCE port of our inbound packets, and re-run with that value plus --verified.");
}
else if (arrivals.Count == 0)
{
    Console.WriteLine("✗ ORACLE DEAD HERE: the peer forged a quote naming our VERIFIED external port and our NAT");
    Console.WriteLine("  still dropped it. Peer-originated ICMP errors are not translated inward on this carrier,");
    Console.WriteLine("  so no sweep could ever get a signal. (Common: CGNATs often refuse to honour RFC 5508 for");
    Console.WriteLine("  errors arriving from an arbitrary source.)");
}
else if (arrivals.Count == 1 && arrivals[0].wasCorrect)
{
    Console.WriteLine("★★★ ORACLE CONFIRMED — exactly the CORRECT quote arrived, controls were dropped.");
    Console.WriteLine("  Our NAT matched the quoted 5-tuple against a live mapping and translated it inward.");
    Console.WriteLine("  → The peer can SWEEP guessed external ports and detect the hit. That is a 1-D search,");
    Console.WriteLine("    the same shape as the working ICMP-identifier punch, rather than the 2-D collision");
    Console.WriteLine("    that makes a UDP birthday punch take minutes to half an hour. BUILD THE SWEEP.");
}
else
{
    Console.WriteLine($"~ AMBIGUOUS: {arrivals.Count} quotes arrived (controls were {string.Join(",", controlPorts)}).");
    Console.WriteLine("  If the CONTROLS arrived too, our NAT forwards ICMP errors WITHOUT matching the quote —");
    Console.WriteLine("  every guess would 'succeed', so there is no signal to sweep on and the oracle is useless.");
    Console.WriteLine("  Re-run to confirm before drawing a conclusion.");
}

icmpRx.Dispose(); icmpTx.Dispose();
return 0;

// Builds ICMP type 3 (Destination Unreachable) code 3 (Port Unreachable) whose payload is a synthetic
// IPv4 + UDP header describing a packet that supposedly went quotedSrc:quotedSrcPort → quotedDst:quotedDstPort.
// That inner header is what the RECEIVING NAT looks up per RFC 5508 — it is the entire mechanism under test.
// ICMP error type/code used for the forged quote. Default 3/3 (dest-unreachable / port-unreachable).
//
// WHY THIS IS SELECTABLE (user's question): a dest-unreachable is semantically something the DESTINATION or a
// router near it emits — so a NAT may reasonably expect it to come FROM a party to the quoted flow, and reject
// one arriving from an unrelated third party. A TIME-EXCEEDED (11/0) has no such expectation: it is emitted by
// an arbitrary MIDDLE router that is by definition not either endpoint. If a NAT source-validates ICMP errors,
// type 11 is far more likely to survive than type 3 — which makes it the better carrier for a server-forged
// quote. `--icmp-type 11` switches to it.
// (declared as locals near the top of the file — top-level statements disallow static fields here)

// Builds an ICMP error whose quoted inner packet is a TCP SYN segment.
//
// WHY TCP: UDP is stateless, so an unreplied UDP flow may create a conntrack entry too weak for RFC 5508 REQ-4
// to match against. TCP is connection-oriented: sending a SYN creates a SYN_SENT state IMMEDIATELY, before any
// reply. If the receiver's NAT will correlate an ICMP error against a SYN_SENT state, the deadlock breaks —
// the state exists without the return path ever completing. (Open question, per the pwnat paper: some NATs
// only allow ICMP for NEW/ESTABLISHED, and SYN_SENT may not qualify. This tests exactly that.)
static byte[] BuildDestUnreachQuotingTcpSyn(IPAddress quotedSrc, int quotedSrcPort, IPAddress quotedDst,
                                            int quotedDstPort, uint seq, int icmpType = 3, int icmpCode = 3)
{
    // Inner: 20B IPv4 + 20B TCP (no options) = 40B. A real SYN quote includes at least the TCP header.
    var inner = new byte[40];
    inner[0] = 0x45;
    int ipTotal = 40;
    inner[2] = (byte)(ipTotal >> 8); inner[3] = (byte)ipTotal;
    inner[4] = 0x1a; inner[5] = 0x2b;
    inner[8] = 64;
    inner[9] = 6;                          // proto = TCP
    quotedSrc.GetAddressBytes().CopyTo(inner, 12);
    quotedDst.GetAddressBytes().CopyTo(inner, 16);
    ushort ipck = Checksum(inner, 0, 20);
    inner[10] = (byte)(ipck >> 8); inner[11] = (byte)ipck;

    // TCP header
    inner[20] = (byte)(quotedSrcPort >> 8); inner[21] = (byte)quotedSrcPort;
    inner[22] = (byte)(quotedDstPort >> 8); inner[23] = (byte)quotedDstPort;
    inner[24] = (byte)(seq >> 24); inner[25] = (byte)(seq >> 16); inner[26] = (byte)(seq >> 8); inner[27] = (byte)seq;
    // ack = 0
    inner[32] = 0x50;                      // data offset 5 (20B), no options
    inner[33] = 0x02;                      // flags = SYN
    inner[34] = 0xff; inner[35] = 0xff;    // window
    // TCP checksum over pseudo-header + header
    inner[36] = 0; inner[37] = 0;
    ushort tck = TcpChecksum(quotedSrc, quotedDst, inner, 20, 20);
    inner[36] = (byte)(tck >> 8); inner[37] = (byte)tck;

    var pkt = new byte[8 + inner.Length];
    pkt[0] = (byte)icmpType; pkt[1] = (byte)icmpCode;
    if (icmpType == 3 && icmpCode == 4) { pkt[6] = 0x05; pkt[7] = 0xDC; }
    inner.CopyTo(pkt, 8);
    ushort ck = Checksum(pkt, 0, pkt.Length);
    pkt[2] = (byte)(ck >> 8); pkt[3] = (byte)ck;
    return pkt;
}

static ushort TcpChecksum(IPAddress src, IPAddress dst, byte[] tcp, int off, int len)
{
    var pseudo = new byte[12 + len];
    src.GetAddressBytes().CopyTo(pseudo, 0);
    dst.GetAddressBytes().CopyTo(pseudo, 4);
    pseudo[8] = 0; pseudo[9] = 6;          // zero, proto
    pseudo[10] = (byte)(len >> 8); pseudo[11] = (byte)len;
    Array.Copy(tcp, off, pseudo, 12, len);
    return Checksum(pseudo, 0, pseudo.Length);
}

// Builds a full IPv4+UDP packet with an explicit IP ID and TTL, for HDRINCL raw send. Lets the client control
// the IP ID so the server can quote the EXACT value pf recorded — testing whether inner-IP-ID matching is pf's
// gate for accepting a forged ICMP error.
static byte[] BuildRawUdp(IPAddress src, int srcPort, IPAddress dst, int dstPort, byte ttl, ushort ipId, byte[] payload)
{
    int udpLen = 8 + payload.Length;
    int total = 20 + udpLen;
    var pkt = new byte[total];
    pkt[0] = 0x45;
    pkt[2] = (byte)(total >> 8); pkt[3] = (byte)total;
    pkt[4] = (byte)(ipId >> 8); pkt[5] = (byte)ipId;
    pkt[8] = ttl;
    pkt[9] = 17;
    src.GetAddressBytes().CopyTo(pkt, 12);
    dst.GetAddressBytes().CopyTo(pkt, 16);
    ushort ipck = Checksum(pkt, 0, 20);
    pkt[10] = (byte)(ipck >> 8); pkt[11] = (byte)ipck;
    pkt[20] = (byte)(srcPort >> 8); pkt[21] = (byte)srcPort;
    pkt[22] = (byte)(dstPort >> 8); pkt[23] = (byte)dstPort;
    pkt[24] = (byte)(udpLen >> 8); pkt[25] = (byte)udpLen;
    // udp checksum 0 (optional for IPv4)
    payload.CopyTo(pkt, 28);
    return pkt;
}

static byte[] BuildDestUnreachQuotingUdp(IPAddress quotedSrc, int quotedSrcPort, IPAddress quotedDst, int quotedDstPort,
                                         int icmpType = 3, int icmpCode = 3, int quotedPayloadLen = 8,
                                         byte[] quotedBody = null, ushort ipId = 0x1a2b)
{
    // ★ THE QUOTE MUST DESCRIBE A PLAUSIBLE REAL DATAGRAM ★
    //
    // The first version quoted a UDP datagram with ZERO payload: inner IP total-length = 28 (20 IP + 8 UDP) and
    // UDP length = 8. The client never sends such a packet — its keepalive is "PEERFLOW", 8 bytes — so the quote
    // described a datagram that had never existed on the wire.
    //
    // Compare a GENUINE port-unreachable captured from the server: 95 bytes on the wire = 14 eth + 20 IP + 8 ICMP
    // + 20 inner IP + 8 inner UDP + 25 bytes of the ORIGINAL PAYLOAD. Real ICMP errors quote the leading payload
    // bytes too, not just the headers. A NAT validating the quote against its conntrack entry can reasonably
    // reject one whose lengths are internally consistent but describe a packet it never forwarded.
    quotedBody ??= System.Text.Encoding.ASCII.GetBytes("PEERFLOW");
    quotedPayloadLen = quotedBody.Length;
    int udpLen = 8 + quotedPayloadLen;     // UDP header + payload
    int ipTotal = 20 + udpLen;             // IP header + UDP
    var inner = new byte[20 + udpLen];
    inner[0] = 0x45;                       // v4, IHL=5
    inner[2] = (byte)(ipTotal >> 8); inner[3] = (byte)ipTotal;
    inner[4] = (byte)(ipId >> 8); inner[5] = (byte)ipId;   // IP identification — MUST match the real probe
    // Inner TTL. For a TIME-EXCEEDED (type 11) the quoted packet is the one that DIED — its TTL reached 0/1.
    // A quote claiming TTL 64 is self-contradictory (a TTL-64 packet does not expire), and pf may validate
    // exactly this: does the quoted TTL plausibly match a packet that would generate THIS error. Real router
    // Time-Exceeded got delivered where ours didn't; inner TTL is the one field we couldn't read post-un-translate.
    inner[8] = (byte)(icmpType == 11 ? 1 : 64);
    inner[9] = 17;                         // proto = UDP
    quotedSrc.GetAddressBytes().CopyTo(inner, 12);
    quotedDst.GetAddressBytes().CopyTo(inner, 16);
    ushort ipck = Checksum(inner, 0, 20);
    inner[10] = (byte)(ipck >> 8); inner[11] = (byte)ipck;

    inner[20] = (byte)(quotedSrcPort >> 8); inner[21] = (byte)quotedSrcPort;
    inner[22] = (byte)(quotedDstPort >> 8); inner[23] = (byte)quotedDstPort;
    inner[24] = (byte)(udpLen >> 8); inner[25] = (byte)udpLen;
    inner[26] = 0; inner[27] = 0;          // UDP checksum 0 = "not computed", legal for IPv4
    // Quoted payload MUST mirror what the client actually sends. This was hardcoded to "PEERFLOW" while the
    // client had switched to real DNS queries, so every forged quote described a 36-byte PEERFLOW datagram that
    // had never existed — wrong length AND wrong bytes. The working case hid it: when the quote named the server,
    // the server's own flow really did carry PEERFLOW, so the quote happened to match reality. Any middlebox
    // validating the quote against the observed flow would reject the mismatched ones.
    for (int i = 0; i < quotedPayloadLen && i < quotedBody.Length; i++) inner[28 + i] = quotedBody[i];

    var pkt = new byte[8 + inner.Length];
    pkt[0] = (byte)icmpType;               // 3 = dest-unreachable, 11 = time-exceeded
    pkt[1] = (byte)icmpCode;               // 3 = port-unreachable, 0 = TTL exceeded / 4 = frag needed
    // Type 3 Code 4 (fragmentation needed) carries the next-hop MTU in bytes 6-7. A frag-needed with MTU 0 is
    // malformed and would be discarded, so fill a plausible value — this is the field that makes PMTUD work,
    // and PMTUD is exactly why firewalls treat 3/4 more permissively than other errors.
    if (icmpType == 3 && icmpCode == 4) { pkt[6] = 0x05; pkt[7] = 0xDC; }   // MTU 1500
    inner.CopyTo(pkt, 8);
    ushort ck = Checksum(pkt, 0, pkt.Length);
    pkt[2] = (byte)(ck >> 8); pkt[3] = (byte)ck;
    return pkt;
}

// Re-parses a finished ICMP error exactly as a receiver would, and reports both what the quote SAYS and whether
// the checksums verify. Used as a pre-send self-check so a semantically void packet (e.g. a quote naming
// 0.0.0.0) cannot go out unnoticed — that happened once and only tcpdump caught it.
static string DescribeQuote(byte[] pkt)
{
    if (pkt.Length < 8 + 28) return "TOO SHORT to contain a quote";
    bool icmpOk = Checksum(pkt, 0, pkt.Length) == 0;
    int emb = 8;
    int ihl = (pkt[emb] & 0x0F) * 4;
    bool ipOk = Checksum(pkt, emb, ihl) == 0;
    var src = new IPAddress(new[] { pkt[emb + 12], pkt[emb + 13], pkt[emb + 14], pkt[emb + 15] });
    var dst = new IPAddress(new[] { pkt[emb + 16], pkt[emb + 17], pkt[emb + 18], pkt[emb + 19] });
    int u = emb + ihl;
    int sp = (pkt[u] << 8) | pkt[u + 1], dp = (pkt[u + 2] << 8) | pkt[u + 3];
    string warn = "";
    if (src.Equals(IPAddress.Any) || dst.Equals(IPAddress.Any)) warn = "   ⚠ VOID — quote names 0.0.0.0, no NAT can match this";
    if (!icmpOk || !ipOk) warn += "   ⚠ CHECKSUM BAD";
    return $"{src}:{sp} → {dst}:{dp}  [icmp-ck {(icmpOk ? "ok" : "BAD")}, ip-ck {(ipOk ? "ok" : "BAD")}]{warn}";
}

// Build a 14-byte Ethernet header (dst gw, src us, ethertype IPv4) for L2 injection.
static byte[] BuildEthHeader(System.Net.NetworkInformation.PhysicalAddress src, System.Net.NetworkInformation.PhysicalAddress dst)
{
    var eth = new byte[14];
    dst.GetAddressBytes().CopyTo(eth, 0);
    src.GetAddressBytes().CopyTo(eth, 6);
    eth[12] = 0x08; eth[13] = 0x00;   // ethertype IPv4
    return eth;
}

[System.Runtime.InteropServices.DllImport("iphlpapi.dll", ExactSpelling = true)]
static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint macAddrLen);

// Resolve the default gateway's MAC for the interface owning localIp. Finds the gateway from the NIC's
// gateway list, then SendARP resolves (and primes) its MAC. Returns null on failure.
static System.Net.NetworkInformation.PhysicalAddress ResolveGatewayMac(IPAddress localIp)
{
    IPAddress gw = null;
    foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
    {
        var props = ni.GetIPProperties();
        bool ownsIp = false;
        foreach (var ua in props.UnicastAddresses) if (ua.Address.Equals(localIp)) ownsIp = true;
        if (!ownsIp) continue;
        foreach (var g in props.GatewayAddresses)
            if (g.Address.AddressFamily == AddressFamily.InterNetwork) { gw = g.Address; break; }
        if (gw != null) break;
    }
    if (gw == null) return null;
    try
    {
        uint gwIp = BitConverter.ToUInt32(gw.GetAddressBytes(), 0);
        var mac = new byte[6]; uint len = 6;
        if (SendARP(gwIp, 0, mac, ref len) == 0 && len == 6)
            return new System.Net.NetworkInformation.PhysicalAddress(mac);
    }
    catch { }
    return null;
}

// Wrap a finished ICMP message in a full outer IPv4 header, for HDRINCL sending on Windows (where a plain
// ProtocolType.Icmp raw socket silently drops crafted ICMP errors — SendTo succeeds but nothing egresses).
static byte[] WrapIpv4(IPAddress src, IPAddress dst, byte proto, byte ttl, ushort ipId, byte[] payload)
{
    int total = 20 + payload.Length;
    var pkt = new byte[total];
    pkt[0] = 0x45;                                  // v4, IHL=5
    pkt[2] = (byte)(total >> 8); pkt[3] = (byte)total;
    pkt[4] = (byte)(ipId >> 8); pkt[5] = (byte)ipId;
    pkt[8] = ttl;
    pkt[9] = proto;                                 // 1 = ICMP
    src.GetAddressBytes().CopyTo(pkt, 12);
    dst.GetAddressBytes().CopyTo(pkt, 16);
    ushort ipck = Checksum(pkt, 0, 20);
    pkt[10] = (byte)(ipck >> 8); pkt[11] = (byte)ipck;
    payload.CopyTo(pkt, 20);
    return pkt;
}

static ushort Checksum(byte[] b, int off, int len)
{
    uint sum = 0;
    for (int i = 0; i < len; i += 2)
        sum += (ushort)((b[off + i] << 8) | (i + 1 < len ? b[off + i + 1] : 0));
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)~sum;
}
