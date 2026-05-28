# Deploying the OPTIONAL browser-facing NAT test

> **Prerequisite:** a working mediation server. See
> [README.md](README.md) for the base install (Node, ports, systemd, TLS).
> This doc layers the browser-NAT-test extension on top of that.

The static page at `/tools/web-nat-test/` lets users check whether their network
supports direct peer-to-peer or will need a relay. The verdict is determined
from WebRTC ICE: the page opens an RTCPeerConnection to the mediation server
with coturn STUN/TURN configured; ICE's nominated candidate type — combined
with a port comparison against the browser's advertised srflx candidate —
tells us whether the browser's NAT is endpoint-independent (direct works) or
endpoint-dependent (symmetric, needs a relay).

This extension adds three pieces on top of the base mediation server:

1. **coturn** — STUN + TURN server. Public on UDP/3478.
2. **mediation server** — adds an HTTP signaling endpoint on
   `127.0.0.1:6515` and gathers WebRTC host candidates on a small UDP
   port range.
3. **nginx** — terminates HTTPS for the page + signaling endpoint and
   reverse-proxies `/nat-test/*` to the mediation server.

The mediation server's WebRTC side (werift) is intentionally minimal: it
gathers only host candidates on a known port range, doesn't try to use coturn
itself, and reads the verdict from the browser-side ICE candidates that show
up in its check list.

werift is declared as an `optionalDependencies` entry in `package.json`, so
operators not running the NAT test can `npm install --omit=optional` to skip
it. If werift is missing at startup, `require('./nat-webrtc')` will throw —
but the require is guarded by `Config.NAT_TEST_ENABLED`, so a server with
the test disabled boots fine without werift on disk.

## 1. Install coturn

```bash
sudo apt update
sudo apt install -y coturn
sudo sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
```

Replace `/etc/turnserver.conf` with the minimum useful config:

```conf
# UDP port for both STUN and TURN.
listening-port=3478

# Public-facing address coturn advertises in STUN responses and TURN
# allocations. REPLACE with the VPS's public IPv4.
external-ip=YOUR.PUBLIC.IP.HERE

# Relay ports allocated to clients. Must be open in the firewall.
min-port=49152
max-port=65535

# Static long-term credentials. The static page surfaces these in the
# /nat-test/config response; treat them as a low-friction gate against
# drive-by abuse, not as real auth.
lt-cred-mech
user=nattunnel:CHANGE-ME-RANDOM-STRING

# Realm — used in credential signing; anything stable works. Should match
# the hostname clients connect to.
realm=your.hostname.here

# Logging.
no-stdout-log
syslog

# Reduce attack surface — disable features we don't need.
no-cli
no-multicast-peers
no-tcp
fingerprint
```

Reload + restart:

```bash
sudo systemctl restart coturn
sudo systemctl status coturn
```

Verify it's listening on UDP/3478:

```bash
sudo ss -lunp | grep 3478
```

Sanity check it works as a real STUN+TURN server:

```bash
sudo apt install -y coturn-utils 2>/dev/null  # may already be installed
turnutils_uclient -y -u nattunnel -w CHANGE-ME-RANDOM-STRING -p 3478 \
    YOUR.PUBLIC.IP.HERE 2>&1 | head -15
```

Expected output ends with `Total lost packets 0` — confirms TURN allocation
and echo work end-to-end.

## 2. Open firewall ports

The host firewall (ufw) AND any cloud-provider security list (OCI, AWS,
GCP, etc.) both need to allow:

```bash
sudo ufw allow 3478/udp                # coturn STUN + TURN
sudo ufw allow 49152:65535/udp         # coturn relay allocations
sudo ufw allow 6520:6540/udp           # werift's ICE host candidates
```

Cloud-provider security list: add equivalent ingress rules for the same
UDP port ranges on your firewall there as well.

## 3. nginx HTTPS termination + reverse proxy

If you don't already have nginx + a Let's Encrypt cert for the host:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo certbot --nginx -d sync.milesthenerd.net
```

After certbot creates the TLS server block, add the `/nat-test/` location
to it. Edit `/etc/nginx/sites-available/<your-site>` and inside the
`listen 443 ssl` server block, add:

```nginx
location /nat-test/ {
    proxy_pass http://127.0.0.1:6515;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 30s;
    proxy_connect_timeout 5s;
}
```

If you want the static page served from the same host, point the root at
where you'll deploy the page files:

```nginx
location / {
    root /var/www/web-nat-test;
    try_files $uri $uri/ =404;
}
```

Reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 4. Configure the mediation server

The browser NAT test is opt-in. Without `NAT_TEST_ENABLED=1`, the mediation
server skips the HTTP signaling endpoint entirely and werift isn't even
loaded — useful if you don't want to bother with coturn / nginx / TURN
credentials and just want plain peer mediation. (And if werift's optional
dependency failed to install, that's fine too.)

All NAT-test settings are part of the central `Config` block in
`constants.js`, with environment-variable overrides matching the names below.
To enable in production, add a systemd drop-in (preferred):

```bash
sudo systemctl edit mediation.service
```

Add:

```ini
[Service]
Environment=NAT_TEST_ENABLED=1
Environment=NAT_TEST_STUN_URL=stun:sync.milesthenerd.net:3478
Environment=NAT_TEST_TURN_URL=turn:sync.milesthenerd.net:3478
Environment=NAT_TEST_TURN_USER=nattunnel
Environment=NAT_TEST_TURN_PASS=CHANGE-ME-RANDOM-STRING
```

Optional overrides (defaults shown):

```ini
# HTTP signaling port (localhost-only bind). Match this in the nginx
# proxy_pass line.
Environment=NAT_TEST_HTTP_PORT=6515

# UDP port range werift uses for ICE host candidates. Must match what's
# open in the firewall + cloud security list. Range must span at least 2
# ports (werift quirk).
Environment=NAT_TEST_ICE_PORT_MIN=6520
Environment=NAT_TEST_ICE_PORT_MAX=6540

# Verbose per-session logging. Off by default — production-clean.
Environment=NAT_TEST_DEBUG=1
```

Reload + restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart mediation.service
sudo journalctl -u mediation.service -f
```

You should see:

```
[NAT-webrtc] HTTP signaling listening on 127.0.0.1:6515
```

If `NAT_TEST_ENABLED` is unset (or anything other than `1`), the
`[NAT-webrtc]` line won't appear and the `/nat-test/*` routes return as if
they don't exist. The rest of the mediation server's TCP/UDP protocol is
unaffected.

## 5. Deploy the static page

Copy the three static files to the directory nginx serves:

```bash
sudo mkdir -p /var/www/web-nat-test
sudo cp ~/NATTunnel/web-nat-test/{index.html,style.css,nat-detect.js} /var/www/web-nat-test/
sudo chown -R www-data:www-data /var/www/web-nat-test
```

## 6. NAT test

Visit `https://<your-host>/` in a browser. Should
return a verdict within ~1–3 seconds.

To verify the symmetric-NAT path returns "relay", test on a mobile carrier
hotspot (most carriers' NATs are endpoint-dependent) or a network you know
is symmetric.

## Verdict semantics

| Verdict | What it means | What NATTunnel will do |
|---|---|---|
| `direct` | Endpoint-independent NAT (full cone, restricted cone, etc.) | Hole-punch directly |
| `relay` (`symmetric-nat`) | Endpoint-dependent NAT (symmetric) | Route through a relay peer |
| `relay` (no reason) | Only ICE-relay candidates succeeded | Route through a relay peer |
| `blocked` | No ICE pair completed | NATTunnel won't work — outbound UDP probably firewalled |

## How the verdict is actually determined

This is what makes the test honest rather than approximate:

1. Browser gathers candidates via coturn:
   - `host` (mDNS-obfuscated local address)
   - `srflx` (browser's external endpoint as observed by coturn STUN — port A)
   - `relay` (a coturn TURN allocation — only used as fallback)
2. Browser advertises those in the offer SDP.
3. Browser sends ICE connectivity checks toward our werift server on its
   public IP at our known port range (6520-6540).
4. werift receives the inbound STUN binding request and notes:
   - The browser's source IP — its external IP.
   - The browser's source port — port B as the NAT mapped it specifically
     for our server.
5. werift forms a `prflx` (peer-reflexive) pair with the observed endpoint
   (it doesn't match any candidate the browser advertised, because the NAT
   mapped a different port for our destination).
6. We compare port A (srflx) and port B (prflx):
   - **Equal** → endpoint-independent NAT — verdict: `direct`.
   - **Different** → endpoint-dependent NAT (symmetric) — verdict: `relay`.

This is the RFC 3489 NAT-classification test, split across two observation
points (coturn and werift) that happen to live on the same host.

## Cost notes

- **STUN traffic**: a few hundred bytes per check. Trivial.
- **TURN traffic**: only used when ICE actually nominates a relay pair. For
  most users, ICE settles on a direct pair before relay completes. Per-test
  cost is well under 1 KB.
- **coturn idle**: minimal.

If TURN ever becomes a meaningful bandwidth burden (e.g., if this gets
embedded into a tool that runs at scale), add quotas in `turnserver.conf`:

```conf
user-quota=12      # max concurrent allocations per user
total-quota=1200   # total concurrent allocations
max-bps=500000     # per-session bandwidth cap (500 KB/s)
```

For the NAT-check use case, the defaults are fine.

## Troubleshooting

**502 from nginx on `/nat-test/*` endpoints**
- Mediation server isn't running, or isn't listening on `127.0.0.1:6515`.
  Check `sudo systemctl status mediation.service` and `ss -lntp | grep 6515`.
- On RHEL/Oracle Linux: SELinux blocks nginx from outbound to localhost.
  Run `sudo setsebool -P httpd_can_network_connect 1`.

**Verdict always "blocked"**
- Firewall blocking inbound UDP on 6520-6540. Check both `ufw status` and
  the cloud-provider security list.
- coturn isn't reachable from the browser. From outside the VPS, send a
  STUN binding request to the public IP on 3478 and verify a response.

**Mediation server crashes on startup with `Cannot find module 'timers/promises'`**
- Node version too old. werift needs Node ≥ 16. Upgrade via NodeSource:
  `curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -`.

**Verdict comes back fast as "direct" but the user is on a network you know is symmetric**
- Check `NAT_TEST_DEBUG=1` logs. The classification depends on the browser
  advertising an srflx candidate. If coturn was unreachable from the
  browser (firewall blocking the browser's outbound to your STUN port),
  no srflx is gathered and the prflx-vs-srflx port comparison can't run.
