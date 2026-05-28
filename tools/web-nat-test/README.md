# web-nat-test

A browser-based NAT-friendliness checker. Tells the user whether
peer-to-peer apps can connect directly through their network
or will have to fall back to a relay.

## How it works

1. The page fetches `/nat-test/config` from the mediation server to get the
   coturn STUN + TURN URLs.
2. It opens an RTCPeerConnection with those iceServers and POSTs an SDP
   offer to `/nat-test/offer`.
3. The mediation server (using werift) answers with a host-only SDP — werift
   gathers a single host candidate on a known public-reachable UDP port.
4. ICE negotiates. The browser's STUN/TURN-gathered candidates pair against
   the server's host candidate.
5. The mediation server polls its ICE check list. The nominated remote
   candidate's type — combined with a port comparison against the browser's
   advertised srflx — determines the verdict.

| Remote candidate type | Port comparison | Verdict |
|---|---|---|
| `host` or `srflx` | n/a | `direct` |
| `prflx` | port matches advertised srflx (ICE race) | `direct` |
| `prflx` | port differs from advertised srflx (symmetric NAT) | `relay` |
| `relay` | n/a | `relay` |
| no pair completed | n/a | `blocked` |

The verdict is the same call NATTunnel itself would make for the user's
network, so it's a real prediction rather than a heuristic.

## Why this is honest

This DOES distinguish endpoint-independent NATs from endpoint-dependent
(symmetric) NATs — which most browser-based NAT checkers can't, because
browsers don't let you send UDP from a controllable source. We get away
with it by using TWO observation points on the server side:

- **coturn** tells the browser its external endpoint via STUN. The browser
  advertises that as its srflx candidate.
- **werift** observes the browser's external endpoint when it sends ICE
  connectivity checks to our host candidate. Endpoint-dependent NATs map
  this differently than they map the STUN request, so the port differs.

If both observation points agree on the same external port → endpoint-
independent NAT → direct works. If they disagree → endpoint-dependent NAT
→ direct won't work for arbitrary peers, even though browser-to-server did.

This is essentially the RFC 3489 NAT-type test, just achieved without
needing to send raw UDP from the browser.

## Hosting

The page is a pure static site. Cloudflare Pages, GitHub Pages, Netlify,
S3+CloudFront, plain nginx, etc. The page itself makes
HTTPS requests to the mediation server's `/nat-test/*` endpoints.

`nat-detect.js` derives the signaling URL from the page's own hostname (so
serving the page from the mediation server's domain just works as-is), with a
`localhost:6515` fallback for local development. If you host the page on a
different domain than the mediation server, you'll need to either edit
`SIGNALING_BASE` in the script or add CORS headers on the mediation
server's side (already set; should work as-is).