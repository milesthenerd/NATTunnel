# NATTunnel

This program is currently a work in progress.

This is intended to be used to create a (mostly) decentralized peer-to-peer mesh network regardless of the NAT types that may be encountered. It's akin to tools like Hamachi and ZeroTier, but it implements some methods that are more capable of handling symmetric and CGNAT specifically, unlike these tools which often give up way too easily and simply fallback to relaying. Much of the info about how it works can be found in the OVERVIEW.md.

The only current prerequisite is the Wireguard client, which can be downloaded [here](https://www.wireguard.com/install/).

# Config Instructions

Here is an example config with the only settings you really need to care about: 

![alt text](settings_image.png)