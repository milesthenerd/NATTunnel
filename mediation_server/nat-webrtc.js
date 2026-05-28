// Browser-facing NAT detection over WebRTC.
//
// Architecture:
//   - coturn runs alongside this server, providing STUN + TURN to the BROWSER.
//   - The browser fetches /nat-test/config to get the coturn URLs + creds, then
//     constructs an RTCPeerConnection with stun: + turn: in iceServers and
//     POSTs an offer to /nat-test/offer.
//   - This server's werift RTCPeerConnection has empty iceServers — we only
//     emit host candidates on a known port range (firewall-permitted). werift's
//     TURN client is unreliable against coturn; sidestepping it removes the
//     flakiness without losing any signal.
//   - Both sides do ICE. The browser's candidates include host, srflx (via
//     coturn STUN), and possibly relay (via coturn TURN). werift attempts to
//     pair them against its host candidate.
//   - We read the verdict from the nominated pair's REMOTE candidate (the
//     browser's view), comparing it against the srflx candidate the browser
//     advertised. The two-observation-point test gives RFC 3489 semantics:
//
//       remote = host or srflx           -> direct (endpoint-independent NAT)
//       remote = relay                    -> relay (TURN was the only path)
//       remote = prflx, port == srflx     -> direct (ICE race; harmless)
//       remote = prflx, port != srflx     -> relay (symmetric NAT — the browser
//                                            used different external ports for
//                                            coturn vs us, so arbitrary peers
//                                            can't reach it on the srflx port)
//
// All sessions are short-lived: the browser POSTs an offer, polls verdict,
// closes within a few seconds. State is held in-memory per session ID.

const crypto = require('crypto');
const { RTCPeerConnection, CandidatePairState } = require('werift');
const { Config } = require('./constants');

// All NAT-test settings live in constants.js's Config block — see there for
// the env-var overrides each one supports.
const debugLog = Config.NAT_TEST_DEBUG ? (...args) => console.log(...args) : () => { };

const ICE_TIMEOUT_MS = 12_000;
const SESSION_LIFETIME_MS = 30_000;

const sessions = new Map();

/**
 * POST /nat-test/offer
 *   body:     { type: 'offer', sdp: string }
 *   response: { sessionId: string, answer: { type, sdp } }
 */
async function handleOffer(req, res) {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk;
        if (body.length > 16384) req.destroy();
    });
    req.on('end', async () => {
        try {
            const parsed = JSON.parse(body);
            if (parsed.type !== 'offer' || typeof parsed.sdp !== 'string') {
                return jsonResponse(res, 400, { error: 'expected { type: "offer", sdp }' });
            }

            const sessionId = crypto.randomBytes(12).toString('hex');

            // Empty iceServers: server emits host candidates only. The browser
            // does its own STUN/TURN gathering via the iceServers it got from
            // /nat-test/config.
            const pc = new RTCPeerConnection({
                iceServers: [],
                iceUseIpv6: false,
                icePortRange: [Config.NAT_TEST_ICE_PORT_MIN, Config.NAT_TEST_ICE_PORT_MAX],
            });

            debugLog(`[nat-webrtc/${sessionId}] new session`);
            pc.onIceCandidate.subscribe((c) => {
                if (c) debugLog(`[nat-webrtc/${sessionId}] local candidate: ${c.candidate}`);
            });

            const session = { pc, createdAt: Date.now(), verdict: null, publicIP: null, resolved: false };
            sessions.set(sessionId, session);

            pc.connectionStateChange.subscribe((state) => {
                debugLog(`[nat-webrtc/${sessionId}] connectionState: ${state}`);
                if (state === 'connected') {
                    finalizeVerdict(session);
                }
                if (state === 'failed' || state === 'disconnected') {
                    finalizeVerdict(session);
                    if (!session.resolved) {
                        session.verdict = { type: 'blocked', reason: `connection ${state}` };
                        session.resolved = true;
                    }
                }
            });

            await pc.setRemoteDescription({ type: 'offer', sdp: parsed.sdp });
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);
            await waitForGathering(pc, 4000);
            const finalSdp = pc.localDescription?.sdp || answer.sdp;

            // Hard timeout: if no verdict has resolved within ICE_TIMEOUT_MS,
            // declare blocked. Without this, the browser polls indefinitely.
            setTimeout(() => {
                if (!session.resolved) {
                    finalizeVerdict(session);
                    if (!session.resolved) {
                        session.verdict = { type: 'blocked', reason: 'ICE pairing timed out' };
                        session.resolved = true;
                    }
                }
            }, ICE_TIMEOUT_MS);

            // Session GC: drop after lifetime regardless of state.
            setTimeout(() => cleanupSession(sessionId), SESSION_LIFETIME_MS);

            jsonResponse(res, 200, {
                sessionId,
                answer: { type: answer.type, sdp: finalSdp },
            });
        } catch (err) {
            console.error('[nat-webrtc] offer error:', err);
            jsonResponse(res, 500, { error: err.message });
        }
    });
}

/**
 * GET /nat-test/verdict/<sessionId>
 *   200 -> { type: 'direct'|'relay'|'blocked', publicIP?, candidateType?, reason? }
 *   202 -> { status: 'pending' }   (browser should poll again)
 *   404 -> { error: 'session not found' }
 */
function handleVerdict(req, res, sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return jsonResponse(res, 404, { error: 'session not found' });

    if (!session.resolved) finalizeVerdict(session);
    if (!session.resolved) return jsonResponse(res, 202, { status: 'pending' });

    const result = { ...session.verdict };
    if (session.publicIP) result.publicIP = session.publicIP;
    cleanupSession(sessionId);
    jsonResponse(res, 200, result);
}

/**
 * GET /nat-test/config
 *   200 -> { iceServers: RTCIceServer[] }
 *
 * The browser uses this to populate its RTCPeerConnection's iceServers config
 * with our coturn STUN/TURN endpoints. Both sides need parity here for ICE
 * pairing to work.
 */
function handleConfig(req, res) {
    const iceServers = [{ urls: Config.NAT_TEST_STUN_URL }];
    if (Config.NAT_TEST_TURN_PASS) {
        iceServers.push({
            urls: Config.NAT_TEST_TURN_URL,
            username: Config.NAT_TEST_TURN_USER,
            credential: Config.NAT_TEST_TURN_PASS,
        });
    }
    jsonResponse(res, 200, { iceServers });
}

// Return false if address is not a public IPv4 address. This filters
// loopback (127/8), link-local (169.254/16), RFC 1918 private (10/8, 172.16/12,
// 192.168/16), RFC 6598 CGNAT (100.64/10), and 0/8.
//
// We need to filter as STUN-reported srflx candidates can carry an inner
// private address on CGNAT where the carrier-side address is in 100.64/10 or 10/8
// US mobile carriers (notably T-Mobile and Verizon) allocate these /8 blocks
// for internal CGNAT use as well
const CARRIER_SQUAT_FIRST_OCTETS = new Set([
    21, 22, 25, 26, 28, 29, 30, 33, 55,
]);

function isPublicIPv4(addr) {
    if (!addr) return false;
    if (addr.includes('.local')) return false; // mDNS-obfuscated host candidate
    const parts = addr.split('.');
    if (parts.length !== 4) return false;
    const [a, b] = parts.map((n) => parseInt(n, 10));
    if (Number.isNaN(a) || Number.isNaN(b)) return false;
    if (a === 0 || a === 127) return false;                            // this-network, loopback
    if (a === 10) return false;                                        // RFC 1918
    if (a === 172 && b >= 16 && b <= 31) return false;                 // RFC 1918
    if (a === 192 && b === 168) return false;                          // RFC 1918
    if (a === 169 && b === 254) return false;                          // link-local
    if (a === 100 && b >= 64 && b <= 127) return false;                // RFC 6598 CGNAT
    if (a >= 224) return false;                                        // multicast + reserved
    if (CARRIER_SQUAT_FIRST_OCTETS.has(a)) return false;               // CGNAT internal
    return true;
}

// Walk werift's check list and classify based on the nominated pair's remote
// candidate type. See header comment for the full mapping table.
function finalizeVerdict(session) {
    if (session.resolved) return;
    const { pc } = session;
    const transports = pc.iceTransports;
    if (!transports || transports.length === 0) return;

    let nominatedPair = null;
    let advertisedSrflx = null;
    let publicAddress = null;

    for (const transport of transports) {
        const conn = transport.connection;
        if (!conn) continue;
        for (const pair of conn.checkList) {
            const remote = pair.remoteCandidate;
            if (remote) {
                // For the publicIP display field, accept only candidates whose
                // host is a publicly-routable IPv4.
                if (!publicAddress && isPublicIPv4(remote.host)) {
                    publicAddress = remote.host;
                }
                if (remote.type === 'srflx' && !advertisedSrflx) advertisedSrflx = remote;
            }
            if (pair.state !== CandidatePairState.SUCCEEDED) continue;
            if (!nominatedPair && pair.nominated) nominatedPair = pair;
            else if (!nominatedPair) nominatedPair = pair;
        }
        if (nominatedPair && advertisedSrflx && publicAddress) break;
    }

    if (publicAddress) session.publicIP = publicAddress;
    if (!nominatedPair || !nominatedPair.remoteCandidate) return;

    const remote = nominatedPair.remoteCandidate;
    const remoteType = remote.type;

    if (remoteType === 'relay') {
        session.verdict = { type: 'relay' };
    } else if (remoteType === 'prflx') {
        // prflx with srflx same-port = harmless ICE race on endpoint-independent NAT.
        // prflx with srflx different-port = endpoint-dependent (symmetric) NAT.
        const portsDiffer =
            advertisedSrflx &&
            advertisedSrflx.host === remote.host &&
            advertisedSrflx.port !== remote.port;
        session.verdict = portsDiffer
            ? { type: 'relay', reason: 'symmetric-nat' }
            : { type: 'direct', candidateType: 'prflx' };
    } else {
        // host, srflx
        session.verdict = { type: 'direct', candidateType: remoteType };
    }
    session.resolved = true;
}

function cleanupSession(sessionId) {
    const session = sessions.get(sessionId);
    if (!session) return;
    try { session.pc.close(); } catch { }
    sessions.delete(sessionId);
}

function waitForGathering(pc, timeoutMs) {
    return new Promise((resolve) => {
        if (pc.iceGatheringState === 'complete') return resolve();
        const unsub = pc.iceGatheringStateChange.subscribe((state) => {
            if (state === 'complete') {
                try { unsub.unsubscribe?.(); } catch { }
                resolve();
            }
        });
        setTimeout(resolve, timeoutMs);
    });
}

function jsonResponse(res, status, body) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end(JSON.stringify(body));
}

function handleCors(res) {
    res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
}

module.exports = { handleOffer, handleVerdict, handleConfig, handleCors };
