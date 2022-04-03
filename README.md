This program is currently a work in progress  
  
Some games use TCP for their network transfer. There is a downside where a lost packet will "hold" back the rest of the packets after it, and it will take generally 1.2 round trip times to fix this.  
  
This program gets around this by retransmitting packets BEFORE the round trip delay, basically __trades bandwidth for latency__. In cases where it matters (~150ms+) this means you will use __3-4x the network traffic__. The good news is minecraft generally only uses 5-10kb/s, so this isn't really a concern, and is the game I had in mind when creating this.  
  
TLDR: DarkTunnel makes the game use more internet so you can play minecraft with your friends across the world.  

# NATTunnel Information

Aside from the original info above, this fork is intended to be used with an accompanying node.js script that runs on a public server and mediates udp holepunching between clients. In many cases, it allows people to connect to each other without the need for port forwarding. This can be useful for people that for some reason do not want to or are unable to use port forwarding. 

# Config Instructions

Here is an example config: 

```
#mode: Set to server if you want to host a local server over UDP, client if you want to connect to a server over UDP
mode=client

#endpoint, servers: The TCP server to connect to for forwarding over UDP. Client: The UDP server to connect to
endpoint=serverhost.address.example.com:26702

#mediationIP: The public IP and port of the mediation server you are connecting to.
mediationIP=sync.milesthenerd.net:6510

#remoteIP, clients: The public IP of the peer you want to connect to.
remoteIP=127.0.0.1

#localPort: servers: The UDP server port. client: The TCP port to hose the forwarded server on.
localPort=25565

#mediationClientPort: The UDP mediation client port. This is the port that will have a hole punched through the NAT by the mediation server, and all traffic will pass through it.
mediationClientPort=5000

#uploadSpeed/downloadSpeed: Specify your connection limit (kB/s), this program sends at a fixed rate.
uploadSpeed=512
downloadSpeed=512

#minRetransmitTime: How many milliseconds delay to send unacknowledged packets
minRetransmitTime=100
```

__mode__: should be set to "client" if you are a client, and "server" if you are running a game server

__endpoint__: this should be the IP address and port that your TCP game server is running on; only used by servers and not clients

__mediationIP__: this should be the public IP address and port of the mediation server; set if you are a client or server

__remoteIP__: this should be the public IP address of the peer you want to connect to; only set for clients

__localPort__: for clients, this is the TCP port on the local machine that players will connect to in a game; for servers, this is the UDP port that TCP to UDP translation will  run on

__mediationClientPort__: for the client and the server, this is the local UDP port that all traffic will pass through

__uploadSpeed__ and __downloadSpeed__: the fixed speed rates at which data will be sent and received; set if you are a client or server

You can likely leave __localPort__, __mediationClientPort__, and the __minRetransmitTime__ options as the defaults.
