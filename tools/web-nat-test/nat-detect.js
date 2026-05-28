// Browser-side NAT-type probe. Auto-runs on load, writes its findings into
// the #out <pre>. The mediation server determines the verdict from its
// own ICE check list; see mediation_server/nat-webrtc.js for the rationale.

const SIGNALING_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:6515'
    : `${window.location.protocol}//${window.location.host}`;

const POLL_INTERVAL_MS = 400;
const MAX_POLL_ATTEMPTS = 40; // ~16s

const out = () => document.getElementById('out');

window.addEventListener('DOMContentLoaded', () => {
    if (!window.RTCPeerConnection) {
        write('WebRTC not supported by this browser.', 'err');
        return;
    }
    run();
});

async function run() {
    try {
        const result = await detect();
        render(result);
    } catch (err) {
        write(`error: ${err.message || err}`, 'err');
    }
}

async function detect() {
    const configRes = await fetch(`${SIGNALING_BASE}/nat-test/config`);
    if (!configRes.ok) throw new Error(`config: HTTP ${configRes.status}`);
    const { iceServers } = await configRes.json();

    const pc = new RTCPeerConnection({ iceServers });
    pc.createDataChannel('probe');

    try {
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        await waitForGathering(pc);

        const offerRes = await fetch(`${SIGNALING_BASE}/nat-test/offer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'offer', sdp: pc.localDescription.sdp }),
        });
        if (!offerRes.ok) throw new Error(`offer: HTTP ${offerRes.status}`);
        const { sessionId, answer } = await offerRes.json();
        await pc.setRemoteDescription(answer);

        for (let i = 0; i < MAX_POLL_ATTEMPTS; i++) {
            await sleep(POLL_INTERVAL_MS);
            const res = await fetch(`${SIGNALING_BASE}/nat-test/verdict/${sessionId}`);
            if (res.status === 200) return await res.json();
            if (res.status === 404) throw new Error('session expired');
        }
        throw new Error('timed out waiting for verdict');
    } finally {
        try { pc.close(); } catch {}
    }
}

function waitForGathering(pc) {
    return new Promise((resolve) => {
        if (pc.iceGatheringState === 'complete') return resolve();
        const onChange = () => {
            if (pc.iceGatheringState === 'complete') {
                pc.removeEventListener('icegatheringstatechange', onChange);
                resolve();
            }
        };
        pc.addEventListener('icegatheringstatechange', onChange);
        setTimeout(resolve, 3000);
    });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function render(r) {
    let cls = 'ok';
    let label;
    let detail;

    if (r.type === 'direct') {
        cls = 'ok';
        label = 'direct';
        detail = 'endpoint-independent NAT; direct p2p works';
    } else if (r.type === 'relay') {
        cls = 'warn';
        label = 'relay';
        detail = r.reason === 'symmetric-nat'
            ? 'symmetric (endpoint-dependent) NAT; arbitrary p2p needs a relay'
            : 'relay-only; arbitrary p2p needs a relay';
    } else if (r.type === 'blocked') {
        cls = 'err';
        label = 'blocked';
        detail = r.reason || 'no ICE pair completed';
    } else {
        cls = 'err';
        label = 'unknown';
        detail = JSON.stringify(r);
    }

    const lines = [
        `verdict:    <span class="${cls}">${label}</span>`,
        `detail:     ${detail}`,
        `external:   ${r.publicIP || '?'}`,
    ];
    out().innerHTML = lines.join('\n');
}

function write(msg, cls) {
    if (cls) {
        out().innerHTML = `<span class="${cls}">${msg}</span>`;
    } else {
        out().textContent = msg;
    }
}
