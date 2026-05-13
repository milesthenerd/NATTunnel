# NATTunnel Overview

NATTunnel creates WireGuard VPN tunnels between peers that are behind NAT, using UDP hole-punching coordinated by a central mediation server. Peers form fully decentralized mesh networks where every peer can reach every other peer.

## Architecture

The system has two layers:

1. **NAT Traversal** — UDP hole-punching and signaling via a mediation server, establishing a direct UDP path between peers despite NAT
2. **WireGuard VPN** — once the UDP path exists, a local proxy bridges WireGuard's loopback socket with the hole-punched external socket, giving WireGuard a transparent tunnel through NAT

## NAT Type Detection

When a peer connects to the mediation server, it performs NAT type detection by sending UDP packets to two different server ports. The server compares the external source ports it observes:

- **DirectMapping** — local port equals external port on both test servers (open NAT or no NAT, no restrictions)
- **Restricted** — external port is consistent across both servers but differs from local port (port-restricted cone NAT, some restrictions but practically none for traversal purposes)
- **Symmetric** — external port differs between the two test servers (each destination gets a different mapping, quite a few restrictions, but can still work with other peers and relaying)

The NAT type determines which hole-punching strategy is used.

## Hole Punching

The mediation server tells both peers each other's external UDP endpoint, then both peers simultaneously send packets to each other. The outbound packets create NAT mappings that allow the inbound packets through.

**Non-symmetric peers**: Both send `HolePunchAttempt` packets to each other's known endpoint every second. Since both NATs allocate predictable ports, this connects quickly.

**One symmetric peer**: The symmetric peer opens 256 probe sockets on different local ports and sends from all of them simultaneously. The non-symmetric peer's NAT accepts packets from any source port, so one of the 256 probes will get through. The non-symmetric peer also sprays packets to 100 random destination ports per second to find the symmetric peer's allocated port. This leverages the birthday paradox to drastically reduce connection time.

**Both symmetric**: Direct hole-punching is infeasible. In mesh mode, traffic is relayed through the introducer peer's WireGuard tunnel.

**Same-NAT peers**: If both peers share the same public IP (they're behind the same router), the server detects this and substitutes their LAN IP addresses instead — but only when the *receiving* peer is also on that NAT. External peers continue to receive the external endpoint, so a LAN endpoint is never sent to a peer that cannot reach it.

## UDP Proxy

WireGuard listens on `127.0.0.1:51820` and can't directly reach peers behind NAT. The UDP proxy bridges this gap:

- Each peer gets a unique loopback proxy port (starting at 51822; 51821 is reserved for the inbound forwarder)
- WireGuard is configured with `Endpoint = 127.0.0.1:<proxyPort>` for each peer
- **Outbound**: WireGuard sends an encrypted packet to `127.0.0.1:<proxyPort>` → the proxy listener receives it → forwards via the hole-punched UDP socket to the peer's real external endpoint
- **Inbound**: A packet arrives from a peer on the hole-punched socket → the proxy looks up which listener owns that source endpoint → forwards to WireGuard on `127.0.0.1:51820`

This makes the NAT traversal layer completely transparent to WireGuard.

## Encryption

After hole-punching succeeds, peers exchange WireGuard public keys over the UDP connection (verified with SHA-256 hashes for integrity). Once both peers have each other's keys, WireGuard handles all further encryption using its own protocol.

The mediation server's TCP control channel is always wrapped in TLS. On first startup the server auto-generates a self-signed certificate via `openssl` (`cert.pem`/`key.pem` in the server directory); operators can supply their own via the `TLS_CERT_PATH`/`TLS_KEY_PATH` environment variables. Clients default to TLS enabled and accept self-signed certificates.

## Mesh Networking

When peers share the same `networkID` in their config, they form a mesh network where every peer can reach every other peer.

### Authentication

Every mesh network requires a shared secret (`networkSecret` in the client config). When joining, the client computes `SHA256(networkID + ":" + networkSecret)` and sends the hash as an `AuthToken` in its `MeshJoinRequest`. The mediation server stores the hash on first join (in `network-secrets.json`) and validates subsequent joins against it. The server never sees the plaintext secret — only the hash. Peers with a mismatched secret are rejected before any peer discovery occurs.

### Joining a Mesh

1. A new peer connects to the mediation server and sends `MeshJoinRequest` with its network ID, peer ID, NAT type, mesh IP (derived deterministically from the peer's GUID), and auth token
2. The server validates the auth token, then responds with a list of existing peers and designates one as the **introducer**
3. The new peer hole-punches to the introducer via the mediation server and establishes a WireGuard tunnel
4. The new peer also initiates hole-punching to all other known peers via the mediation server

### Mesh IP Collision Detection

Mesh IPs are derived deterministically from the peer's GUID via SHA-256 (`meshSubnet.byte3.byte4`), so the same peer always gets the same mesh IP. With a /16 subnet this still leaves ~65K addresses, and collisions are rare but possible. After the join response, the new peer compares its candidate mesh IP against all taken IPs in the network. On collision it walks successive SHA-256 byte pairs (offset 2, 4, …) until it finds a free slot, then calls `SetClientIPAndRestart` to reassign the WireGuard interface IP before announcing itself.

### The Introducer

The introducer is the first non-symmetric NAT peer in the network. It has a persistent TCP connection to the mediation server and two responsibilities:

**Bootstrapping new peers**: When a new peer joins, the mediation server sends the introducer a `MeshIntroduceRequest`. The introducer then sends `MeshConnectionBegin` messages to both the new peer and each existing peer over their already-established WireGuard tunnels — telling them each other's endpoints so they can hole-punch directly.

**Maintaining connectivity**: The introducer sends heartbeats to all peers over WireGuard at a configurable interval (default 15 seconds). Each heartbeat includes a **peer roster** — a compact list of all known mesh members with their peer ID, NAT type, and endpoint. This ensures non-introducer peers learn about all members even if they weren't online during the initial join. Each peer responds with the list of mesh IPs it has active tunnels to. The introducer detects missing links and re-sends `MeshConnectionBegin` to repair them.

### Mediation Server Disconnect

Non-introducer peers disconnect from the mediation server's TCP connection after a configurable grace period (default 30 seconds for non-symmetric NAT, 5 seconds for symmetric NAT). All future peer introductions and connectivity repairs happen over WireGuard through the introducer, so the mediation server is only needed for initial bootstrapping.

### Introducer Failover

Non-introducer peers periodically probe the introducer with `MeshHeartbeat` packets over the mesh control UDP channel (port 51888). Probing piggybacks on the application layer rather than WireGuard's `PersistentKeepalive` because the kernel keepalive keeps the tunnel alive even after the introducer process has exited — only an application-level ack proves the introducer is actually running.

After three missed acks, the first eligible (non-symmetric) peer reconnects to the mediation server, sends a fresh `MeshJoinRequest`, and is promoted to the new introducer. The reconnection uses the same TLS handshake as the original mediation connection. The mediation server also tracks pending introductions and re-issues them through a replacement introducer if the original one disconnects mid-bootstrap.

### Isolation Detection and Recovery

If a peer detects it has lost connectivity to all mesh peers (isolation), it waits a configurable grace period (default 30 seconds) before reconnecting to the mediation server to re-bootstrap. The reconnection performs the full TLS + NAT-test + `MeshJoinRequest` handshake.

### Graceful Shutdown

When a peer shuts down cleanly (e.g., Ctrl+C, GUI Stop button, or `POST /shutdown`), it sends a `MeshPeerLeave` message to all connected peers over WireGuard. Receiving peers immediately remove the departing peer's WireGuard configuration and relay routes, avoiding the ~75-second wait for missed heartbeats to declare a peer dead.

### Relay for Symmetric-Symmetric Pairs

When two symmetric NAT peers can't hole-punch to each other, the introducer acts as a relay. Both peers add the remote peer's mesh IP to the introducer's WireGuard `AllowedIPs`, and the introducer enables IP forwarding on its WireGuard interface. Traffic between the two peers then routes through the introducer's tunnel transparently.

## Mesh Status and Control

Each peer runs a local HTTP server on `localhost:51889` that exposes:

- **`GET /status`** — JSON snapshot:
  - Own mesh IP, peer ID, NAT type, introducer status
  - Connected peers with mesh IP, peer ID, NAT type, endpoint, latency, relay status
  - Active relay routes
  - Aggregated metrics: tunnels established/failed, reconnects, peers lost, heartbeat stats, relay route counts
  - Uptime
- **`POST /shutdown`** — clean shutdown (sets `ShutdownRequested`, runs `MeshPeerLeave` broadcast and disposes resources)
- **`POST /disconnect`** — leave the mesh but keep the process running
- **`POST /connect`** — rejoin after `disconnect`

Latency is measured via binary ping/pong packets (prefixed with `0xFF`) sent over the mesh control UDP channel (port 51888), distinct from JSON message types.

## Desktop GUI

`NATTunnelGUI` is a WPF application (Windows-only) that polls the HTTP status endpoint for live mesh state. It displays peers, latency, relay routes, and the introducer flag, and exposes Connect/Disconnect/Stop buttons backed by the HTTP control endpoints.

## Mediation Server

The mediation server is a Node.js application that coordinates peer discovery and connection setup. It runs four sockets:

- **TCP (TLS)** on port 6510 — control channel for signaling messages (JSON-over-TLS); falls back to plain TCP if `openssl` is unavailable
- **UDP** on port 6510 — keepalive and initial contact
- **UDP** on ports 6511 and 6512 — NAT type detection test ports

Key components:
- **ConnectionManager** — tracks connected sockets, UDP endpoint info, active connection pairings, and timeouts
- **MessageHandler** — processes all TCP message types (NAT detection, connection requests, mesh join/introduce). Includes per-socket message rate limiting (default 50 messages per 10 seconds), per-IP TCP-connection rate limiting (default 10 new connections per 60 seconds), and network authentication via stored auth token hashes
- **NetworkRegistry** — maintains two maps per mesh network: active peers (with live TCP sockets) and all-time members (persists across disconnections so the introducer can still reach them over WireGuard)
