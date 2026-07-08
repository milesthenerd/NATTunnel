/**
 * Server self-address discovery.
 *
 * The mediation server needs to advertise its own PUBLIC IPv4/IPv6 addresses to clients (so a
 * peer that reached mediation over one family can still run its NAT test over the other family —
 * see NATTestBegin in message-handler.js). The public address is NOT knowable from local interface
 * enumeration when the server is behind NAT / a port-forward / cloud 1:1 NAT — os.networkInterfaces()
 * shows only the private bind address. The only reliable automatic source is an external reflector,
 * so we send a STUN Binding request over each family and read back the XOR-MAPPED-ADDRESS.
 *
 * This works identically for a public VPS (STUN echoes the directly-assigned IP), a 1:1/elastic-IP
 * cloud NAT, and a home/office server behind a port-forwarding router (STUN echoes the router WAN IP).
 *
 * Discovery runs at startup and re-runs on an interval so a changed public IP (dynamic residential
 * IP) is picked up without a restart. PUBLIC_IPV4 / PUBLIC_IPV6 env vars, if set, override discovery.
 *
 * Uses only Node's built-in dgram — no STUN library dependency (werift is optional-only).
 */

const dgram = require('dgram');
const dns = require('dns').promises;

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_MAPPED_ADDRESS = 0x0001; // legacy fallback

// Public STUN servers, one query per family. Multiple for resilience.
const STUN_SERVERS = [
    { host: 'stun.l.google.com', port: 19302 },
    { host: 'stun.cloudflare.com', port: 3478 },
];

const REFRESH_INTERVAL_MS = 5 * 60 * 1000; // steady-state re-discovery cadence
const STARTUP_RETRY_MS = 10 * 1000;        // fast retry until the first family is discovered

class SelfAddress {
    constructor() {
        this.publicIPv4 = process.env.PUBLIC_IPV4 || null;
        this.publicIPv6 = process.env.PUBLIC_IPV6 || null;
        this._v4Overridden = !!process.env.PUBLIC_IPV4;
        this._v6Overridden = !!process.env.PUBLIC_IPV6;
        this._timer = null;
    }

    /**
     * Starts discovery: runs once immediately, then settles into a slow refresh. Until at least
     * one family is discovered (e.g. STUN failed at boot because the network wasn't up yet), it
     * retries quickly so the degraded window is short rather than a full refresh interval.
     */
    start() {
        this._discoverAll().catch(() => {});
        this._scheduleNext();
    }

    _scheduleNext() {
        // Fast retry (10s) while we have nothing yet; slow refresh (5min) once discovered.
        const haveAny = this.publicIPv4 || this.publicIPv6;
        const delay = haveAny ? REFRESH_INTERVAL_MS : STARTUP_RETRY_MS;
        this._timer = setTimeout(() => {
            this._discoverAll().catch(() => {}).finally(() => this._scheduleNext());
        }, delay);
        if (this._timer.unref) this._timer.unref();
    }

    stop() {
        if (this._timer) clearTimeout(this._timer);
        this._timer = null;
    }

    async _discoverAll() {
        // Only discover families that weren't pinned via env override.
        await Promise.all([
            this._v4Overridden ? Promise.resolve() : this._discoverFamily('udp4'),
            this._v6Overridden ? Promise.resolve() : this._discoverFamily('udp6'),
        ]);
    }

    async _discoverFamily(socketType) {
        for (const server of STUN_SERVERS) {
            try {
                const addr = await this._stunQuery(socketType, server.host, server.port);
                if (addr) {
                    if (socketType === 'udp4' && this.publicIPv4 !== addr) {
                        this.publicIPv4 = addr;
                        console.log(`[SelfAddress] Discovered public IPv4 via STUN: ${addr}`);
                    } else if (socketType === 'udp6' && this.publicIPv6 !== addr) {
                        this.publicIPv6 = addr;
                        console.log(`[SelfAddress] Discovered public IPv6 via STUN: ${addr}`);
                    }
                    return; // Got an answer for this family — done.
                }
            } catch (e) {
                // Try the next STUN server for this family.
            }
        }
        // No STUN server answered for this family — likely no route for it. Leave as-is.
    }

    /** Sends a STUN Binding request and resolves the reflected public IP (address only, no port). */
    _stunQuery(socketType, host, port) {
        return new Promise(async (resolve, reject) => {
            let resolved = false;
            const done = (val, err) => {
                if (resolved) return;
                resolved = true;
                try { socket.close(); } catch (e) {}
                clearTimeout(timeout);
                if (err) reject(err); else resolve(val);
            };

            // Resolve the STUN host to the matching family so a udp6 socket doesn't try an A record.
            let dest;
            try {
                const family = socketType === 'udp6' ? 6 : 4;
                const records = await dns.lookup(host, { family, all: true });
                dest = records.length ? records[0].address : null;
            } catch (e) {
                return done(null, e);
            }
            if (!dest) return done(null, new Error('no address for STUN host'));

            // Build a 20-byte Binding request: type, length=0, magic cookie, 12-byte transaction ID.
            // The transaction ID is LOCAL to this query (not stored on `this`) — v4 and v6 queries
            // run concurrently, so a shared instance field would get clobbered between send and
            // parse, corrupting the v6 XOR-MAPPED-ADDRESS decode (which keys off cookie||txId) and
            // yielding a garbage-but-valid-looking address.
            const req = Buffer.alloc(20);
            req.writeUInt16BE(STUN_BINDING_REQUEST, 0);
            req.writeUInt16BE(0, 2);
            req.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
            for (let i = 8; i < 20; i++) req[i] = Math.floor(Math.random() * 256);
            const txId = req.slice(8, 20);

            const socket = dgram.createSocket(socketType);
            socket.on('error', (err) => done(null, err));
            socket.on('message', (msg) => {
                try {
                    const addr = this._parseStunResponse(msg, txId);
                    done(addr);
                } catch (e) {
                    done(null, e);
                }
            });

            const timeout = setTimeout(() => done(null, new Error('STUN timeout')), 3000);

            socket.send(req, port, dest, (err) => { if (err) done(null, err); });
        });
    }

    /** Extracts the reflected IP from a STUN Binding response (XOR-MAPPED-ADDRESS preferred).
     * txId is the 12-byte transaction ID of the request this is a response to (used for the v6
     * XOR key), passed in rather than read from shared state so concurrent queries don't collide. */
    _parseStunResponse(msg, txId) {
        if (msg.length < 20) return null;
        const type = msg.readUInt16BE(0);
        if (type !== STUN_BINDING_RESPONSE) return null;
        const cookie = msg.readUInt32BE(4);

        let offset = 20;
        const end = 20 + msg.readUInt16BE(2);
        let mapped = null;
        let xorMapped = null;

        while (offset + 4 <= end && offset + 4 <= msg.length) {
            const attrType = msg.readUInt16BE(offset);
            const attrLen = msg.readUInt16BE(offset + 2);
            const valStart = offset + 4;
            if (valStart + attrLen > msg.length) break;

            if (attrType === ATTR_XOR_MAPPED_ADDRESS || attrType === ATTR_MAPPED_ADDRESS) {
                const family = msg.readUInt8(valStart + 1);
                const xor = attrType === ATTR_XOR_MAPPED_ADDRESS;
                let ip = null;
                if (family === 0x01) {
                    // IPv4: 4 bytes, XORed with the top 4 bytes of the magic cookie.
                    const b = Buffer.from(msg.slice(valStart + 4, valStart + 8));
                    if (xor) {
                        b[0] ^= (cookie >>> 24) & 0xff;
                        b[1] ^= (cookie >>> 16) & 0xff;
                        b[2] ^= (cookie >>> 8) & 0xff;
                        b[3] ^= cookie & 0xff;
                    }
                    ip = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
                } else if (family === 0x02) {
                    // IPv6: 16 bytes, XORed with the magic cookie followed by the transaction ID.
                    const b = Buffer.from(msg.slice(valStart + 4, valStart + 20));
                    if (xor) {
                        const key = Buffer.concat([
                            Buffer.from([(cookie >>> 24) & 0xff, (cookie >>> 16) & 0xff, (cookie >>> 8) & 0xff, cookie & 0xff]),
                            txId,
                        ]);
                        for (let i = 0; i < 16; i++) b[i] ^= key[i];
                    }
                    const parts = [];
                    for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(i).toString(16));
                    ip = parts.join(':');
                }
                if (xor) xorMapped = ip; else mapped = ip;
            }
            // Attributes are padded to 4-byte boundaries.
            offset = valStart + attrLen + ((4 - (attrLen % 4)) % 4);
        }
        return xorMapped || mapped;
    }
}

module.exports = new SelfAddress();
