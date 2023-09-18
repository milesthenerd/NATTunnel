This program is currently a work in progress  
  
Some games use TCP for their network transfer. There is a downside where a lost packet will "hold" back the rest of the packets after it, and it will take generally 1.2 round trip times to fix this.  
  
This program gets around this by retransmitting packets BEFORE the round trip delay, basically __trades bandwidth for latency__. In cases where it matters (~150ms+) this means you will use __3-4x the network traffic__. The good news is minecraft generally only uses 5-10kb/s, so this isn't really a concern, and is the game I had in mind when creating this.  
  
TLDR: DarkTunnel makes the game use more internet so you can play minecraft with your friends across the world.  

# NATTunnel Information

Aside from the original info above, this fork is intended to be used with an accompanying node.js script that runs on a public server and mediates udp holepunching between clients. In many cases, it allows people to connect to each other without the need for port forwarding. This can be useful for people that for some reason do not want to or are unable to use port forwarding. 

# Config Instructions

Here is an example config: 

```
#mode: Set to server if you want to allow others to connect to you, client if you want to connect to someone else
mode = "server"

#mediationEndpoint: The public IP and port of the matchmaking/holepunching server you want to connect to
mediationEndpoint = "sync.milesthenerd.net:6510"

#remoteIP: The public IP of the peer you want to connect to (unused for servers)
remoteIP = "127.0.0.1"
```

__mode__: should be set to "client" if you are a client, and "server" if you are running a NATTunnel server

__mediationEndpoit__: this should be the public IP address and port of the mediation server; set if you are a client or server

__remoteIP__: this should be the public IP address of the peer you want to connect to; only set for clients
