# web-nat-test

A browser-based NAT-friendliness checker. Tells the user whether
peer-to-peer apps can connect directly through their network
or will have to fall back to a relay.

| Remote candidate type | Port comparison | Verdict |
|---|---|---|
| `host` or `srflx` | n/a | `direct` |
| `prflx` | port matches advertised srflx (ICE race) | `direct` |
| `prflx` | port differs from advertised srflx (symmetric NAT) | `relay` |
| `relay` | n/a | `relay` |
| no pair completed | n/a | `blocked` |

Not as accurate as the test built into NATTunnel and can be wrong in some special cases.