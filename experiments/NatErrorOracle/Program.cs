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

    int fType = 3, fCode = 3;
    if (Arg("--icmp-type") == "11")
    {
        fType = 11; fCode = 0;
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

    Console.WriteLine($"[server] listening on :{sport}. Waiting for a client…");
    Console.WriteLine($"[server] (the server only SENDS raw ICMP — no SIO_RCVALL needed on either platform)");
    var buf = new byte[2048];
    var served = new HashSet<string>();
    var discardSeen = new HashSet<int>();
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
        var msg = Encoding.ASCII.GetString(buf, 0, n);
        if (msg.StartsWith("TARGET "))
        {
            var parts = msg.Substring(7).Trim().Split(' ');
            if (parts.Length >= 1 && IPAddress.TryParse(parts[0], out var tp)) quoteDst = tp;
            if (parts.Length >= 2 && int.TryParse(parts[1], out var tpp)) quoteDstPort = tpp;
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
            var order = new List<int>(hi - lo + 1);
            for (int g = lo; g <= hi; g++) order.Add(g);
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
            foreach (int guess in order)
            {
                try { while (su.Available > 0) { EndPoint _d = new IPEndPoint(IPAddress.Any, 0); su.ReceiveFrom(buf, ref _d); } } catch { }
                var gp = BuildDestUnreachQuotingUdp(c.Address, guess, quoteDst, quoteDstPort, fType, fCode);
                try { sraw.SendTo(gp, new IPEndPoint(c.Address, 0)); fired++; } catch { }
                next = next.AddMilliseconds(gap);
                var wait = (next - DateTime.UtcNow).TotalMilliseconds;
                if (wait > 1) Thread.Sleep((int)wait);
                if (fired % 500 == 0)
                    Console.WriteLine($"[server]   …{fired}/{hi - lo + 1} fired ({(DateTime.UtcNow - swStart).TotalSeconds:F1}s)");
            }
            Console.WriteLine($"[server] SWEEP DONE: {fired} guesses in {(DateTime.UtcNow - swStart).TotalSeconds:F1}s. " +
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
            var pkt = BuildDestUnreachQuotingUdp(c.Address, p, quoteDst, quoteDstPort, fType, fCode);
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

static byte[] BuildDestUnreachQuotingUdp(IPAddress quotedSrc, int quotedSrcPort, IPAddress quotedDst, int quotedDstPort,
                                         int icmpType = 3, int icmpCode = 3, int quotedPayloadLen = 8)
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
    int udpLen = 8 + quotedPayloadLen;     // UDP header + payload
    int ipTotal = 20 + udpLen;             // IP header + UDP
    var inner = new byte[20 + udpLen];
    inner[0] = 0x45;                       // v4, IHL=5
    inner[2] = (byte)(ipTotal >> 8); inner[3] = (byte)ipTotal;
    inner[4] = 0x1a; inner[5] = 0x2b;      // id
    inner[8] = 64;                         // TTL
    inner[9] = 17;                         // proto = UDP
    quotedSrc.GetAddressBytes().CopyTo(inner, 12);
    quotedDst.GetAddressBytes().CopyTo(inner, 16);
    ushort ipck = Checksum(inner, 0, 20);
    inner[10] = (byte)(ipck >> 8); inner[11] = (byte)ipck;

    inner[20] = (byte)(quotedSrcPort >> 8); inner[21] = (byte)quotedSrcPort;
    inner[22] = (byte)(quotedDstPort >> 8); inner[23] = (byte)quotedDstPort;
    inner[24] = (byte)(udpLen >> 8); inner[25] = (byte)udpLen;
    inner[26] = 0; inner[27] = 0;          // UDP checksum 0 = "not computed", legal for IPv4
    // Quoted payload — mirror what the client actually sends so the quote matches a real datagram.
    var body = System.Text.Encoding.ASCII.GetBytes("PEERFLOW");
    for (int i = 0; i < quotedPayloadLen && i < body.Length; i++) inner[28 + i] = body[i];

    var pkt = new byte[8 + inner.Length];
    pkt[0] = (byte)icmpType;               // 3 = dest-unreachable, 11 = time-exceeded
    pkt[1] = (byte)icmpCode;               // 3 = port-unreachable, 0 = TTL exceeded in transit
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

static ushort Checksum(byte[] b, int off, int len)
{
    uint sum = 0;
    for (int i = 0; i < len; i += 2)
        sum += (ushort)((b[off + i] << 8) | (i + 1 < len ? b[off + i + 1] : 0));
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)~sum;
}
