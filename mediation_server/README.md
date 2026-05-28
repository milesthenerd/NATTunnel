# NATTunnel Mediation Server

The mediation server is the initial connection point for NATTunnel peers. It handles
NAT-type detection, peer discovery within a network, and introducer
election. Peers connect to it briefly over TCP to find each other, then
talk peer-to-peer over WireGuard or NATTunnel's embedded mode, the
mediation server doesn't relay any actual user traffic.

A NATTunnel network's clients agree on which mediation server to use by
setting the same `mediationEndpoint` in their config. By default the
project ships pointing at `sync.milesthenerd.net:6510`; if you'd rather
run your own, this doc gets you there.

## Quick start (Ubuntu 22.04+ / Debian 12+)

```bash
# Node 24 LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -
sudo apt install -y nodejs openssl

# Clone + install (werift is an optionalDependency; omit if you don't plan
# to enable the browser NAT test extension)
git clone https://github.com/milesthenerd/NATTunnel.git
cd NATTunnel/mediation_server
npm install --omit=optional

# Run in the foreground to sanity-check
node server.js
```

You should see something like:

```
[TLS] No certificate found — generating self-signed cert...
[TLS] Self-signed cert generated: /home/ubuntu/NATTunnel/mediation_server/cert.pem
[TLS] TLS enabled using cert: /home/ubuntu/NATTunnel/mediation_server/cert.pem
Main UDP server info: ...
NAT Test 1 listening on port 6511
NAT Test 2 listening on port 6512
TCP server info: ...
```

That's the entire base deploy. The rest of this doc walks through
making it persistent and reachable.

## What it needs

- **Node.js 18+** (Node 24 LTS recommended). werift requires Node 16+ if
  you enable the optional browser NAT test extension.
- **`openssl`** - only used at first launch to self-sign a TLS cert.
  If you'd rather provide your own CA-signed cert, set `TLS_CERT_PATH` and
  `TLS_KEY_PATH` to point at your files if you wish; the auto-generation step is
  skipped when both exist.
- **Three open UDP ports + one TCP port** (defaults):
  - `6510/tcp` - main control channel (TLS-wrapped)
  - `6510/udp` - main UDP channel (NAT-traversal coordination)
  - `6511/udp` - NAT-type test port 1
  - `6512/udp` - NAT-type test port 2
- **No persistent storage** beyond the TLS cert + key (auto-generated next
  to `server.js`). All peer state lives in memory; a restart drops it,
  peers reconnect.

## Firewall

Host firewall (ufw on Ubuntu/Debian):

```bash
sudo ufw allow 6510/tcp
sudo ufw allow 6510/udp
sudo ufw allow 6511/udp
sudo ufw allow 6512/udp
```

If you're on a cloud provider, their network firewall (AWS Security Groups,
OCI Security Lists, etc.) is separate from ufw and must allow the same ports. 
The cloud firewall blocks even what ufw allows unless configured.

## systemd unit

Create `/etc/systemd/system/mediation.service` (replace `ubuntu` with your
service user and adjust the path):

```ini
[Unit]
Description=NATTunnel Mediation Service
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/NATTunnel/mediation_server
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mediation.service
sudo systemctl status mediation.service
```

## TLS notes

By default the server generates a long-lived self-signed cert on first
boot (`mediation_server/cert.pem` + `key.pem`). NATTunnel's bundled
clients accept self-signed certs from their configured mediation endpoint, 
this is intentional, since `mediationEndpoint` doubles as the
trust anchor.

If you'd rather use a real CA-signed cert (e.g., from Let's Encrypt,
particularly useful if you also enable the browser NAT test extension,
which needs HTTPS):

```bash
sudo apt install -y certbot
sudo certbot certonly --standalone -d mediation.example.com
```

Then point the server at the cert via env vars:

```ini
# Add to the systemd unit's [Service] block:
Environment=TLS_CERT_PATH=/etc/letsencrypt/live/mediation.example.com/fullchain.pem
Environment=TLS_KEY_PATH=/etc/letsencrypt/live/mediation.example.com/privkey.pem
```

The Node process needs read access to those files; either run it as root
or grant the service user explicit read access.

## Configuration overrides

All settings live in `constants.js`'s `Config` block, with environment
variables taking precedence over the defaults. The base server only reads
`TLS_CERT_PATH` and `TLS_KEY_PATH`; everything else is hardcoded port
numbers and timeouts. If you need to change a base port (e.g., to run
multiple mediation servers on the same host), edit `Config` in
`constants.js` directly. There's no env-var override for port
numbers because nothing else has needed one yet.

## Client configuration

NATTunnel clients connect to the mediation server by setting
`mediationEndpoint` in their config (TOML for the daemon, `MeshConfig` for
embedded mode):

```toml
mediationEndpoint = "your-host.example.com:6510"
```

The address must be reachable via DNS from clients, and the TCP+UDP port
above (default 6510) must be open end-to-end. Clients self-resolve DNS at
startup; if your mediation host's IP changes, clients reconnect on the next
session.

## Operational notes

- **Memory**: tens of MB for a few hundred peers. Doesn't grow over time;
  peer state is cleaned up via `processTimeouts` (1s tick) and periodic
  sweeps (60s tick).
- **Logs**: stdout / stderr only.
- **Restarts**: dropping state means peers briefly fail discovery; they
  reconnect within a heartbeat cycle (~15s for embedded, ~60s for daemon).
  Plan reboots around lower-traffic times if it matters.
- **Multiple mediation servers**: each NATTunnel network picks exactly
  one. There's no failover between mediation servers in the current
  protocol. If high availability matters, run one mediation server per
  network on a host you control.

## Optional add-on: browser NAT test

If you want to give users a `https://your-host.example.com/` page that
checks their NAT type from the browser, see
[DEPLOY-NAT-WEBRTC.md](DEPLOY-NAT-WEBRTC.md). That's a separate setup
that adds coturn (STUN/TURN) and nginx (HTTPS termination + reverse proxy)
alongside this base mediation server. Skip it entirely if you don't care
for the extra fluff, the base server runs identically with the extension disabled.
