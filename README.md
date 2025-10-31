# NATTunnel Information

This program is currently a work in progress.

This is intended to be used with an accompanying node.js script that runs on a public server and mediates udp holepunching between clients. In many cases, it allows people to connect to each other without the need for port forwarding, using Wireguard to establish a VPN connection in the 10.5.0.0/24 range. This can be useful for people that for some reason do not want to or are unable to use port forwarding.

It's been tested working with a server running on a home fiber internet connection and a client running behind the restrictive CGNAT of a mobile provider.

The use of this program requires the wireguard.dll and tunnel.dll in the program directory. 

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
