/**
 * Network Registry for Mesh Networking
 *
 * Manages peer-to-peer mesh networks where peers with the same networkID
 * can discover and connect to each other.
 *
 * Two maps per network:
 *   - networks: active peers with live TCP sockets (used for routing messages)
 *   - meshMembers: all peers that have ever joined (persists across TCP disconnections)
 *     The introducer uses meshMembers to know which WireGuard peers to send
 *     MeshIntroduction messages to, even if those peers have disconnected from mediation.
 */

class NetworkRegistry {
    constructor() {
        // Map of networkID -> Map of peerID -> peer info (active sockets only)
        this.networks = new Map();
        // Map of networkID -> Map of peerID -> peer info (all members, persists across disconnections)
        this.meshMembers = new Map();
        // Sticky introducer per network — prevents split-brain from re-electing on every join.
        this.introducers = new Map();
    }

    getIntroducer(networkID) {
        return this.introducers.get(networkID) || null;
    }

    setIntroducer(networkID, peerID) {
        this.introducers.set(networkID, peerID);
    }

    clearIntroducer(networkID) {
        this.introducers.delete(networkID);
    }

    /**
     * Registers a peer to a network
     * @param {string} networkID - The network identifier
     * @param {string} peerID - Unique peer identifier (GUID)
     * @param {object} socket - TCP socket for control messages
     * @param {string} endpoint - Peer's external endpoint (IP:Port)
     * @param {number} natType - Peer's NAT type
     * @param {string} meshIP - Peer's mesh IP address (optional)
     * @returns {object[]} List of other peers in the same network
     */
    joinNetwork(networkID, peerID, socket, endpoint, natType, meshIP = null, localIP = null, localPort = null, peerMinVersion = 1, peerMaxVersion = 1, identityPublicKey = null, endpointV6 = null, natTypeV6 = -1) {
        if (!networkID || !peerID) {
            throw new Error('networkID and peerID are required');
        }

        // Create network if it doesn't exist
        if (!this.networks.has(networkID)) {
            this.networks.set(networkID, new Map());
            console.log(`[NetworkRegistry] Created new network: ${networkID}`);
        }
        if (!this.meshMembers.has(networkID)) {
            this.meshMembers.set(networkID, new Map());
        }

        const network = this.networks.get(networkID);
        const members = this.meshMembers.get(networkID);

        // Check if peer already exists (reconnection case)
        if (network.has(peerID)) {
            const existingPeer = network.get(peerID);
            const oldNatType = existingPeer.natType;
            console.log(`[NetworkRegistry] Peer ${peerID} rejoining network ${networkID} (NAT: ${oldNatType} -> ${natType}, endpoint: ${existingPeer.endpoint} -> ${endpoint})`);
            // Update existing peer info
            existingPeer.socket = socket;
            existingPeer.endpoint = endpoint;
            existingPeer.natType = natType;
            existingPeer.natTypeV6 = natTypeV6;
            existingPeer.meshIP = meshIP;
            existingPeer.localIP = localIP;
            existingPeer.localPort = localPort;
            existingPeer.peerMinVersion = peerMinVersion;
            existingPeer.peerMaxVersion = peerMaxVersion;
            existingPeer.identityPublicKey = identityPublicKey;
            existingPeer.endpointV6 = endpointV6;
            existingPeer.joinTime = Date.now();
        } else {
            // Add new peer
            network.set(peerID, {
                peerID,
                socket,
                endpoint,
                natType,
                natTypeV6,
                meshIP,
                localIP,
                localPort,
                peerMinVersion,
                peerMaxVersion,
                identityPublicKey,
                endpointV6,
                joinTime: Date.now()
            });
            console.log(`[NetworkRegistry] Peer ${peerID} joined network ${networkID} (meshIP: ${meshIP}, total active: ${network.size})`);
        }

        // Update mesh members (persistent record)
        members.set(peerID, {
            peerID,
            endpoint,
            natType,
            natTypeV6,
            meshIP,
            localIP,
            localPort,
            peerMinVersion,
            peerMaxVersion,
            identityPublicKey,
            endpointV6,
            connected: true,
            joinTime: Date.now()
        });

        // Return list of other active peers in the network (excluding this peer)
        const otherPeers = [];
        for (const [id, peer] of network.entries()) {
            if (id !== peerID) {
                otherPeers.push({
                    peerID: peer.peerID,
                    endpoint: peer.endpoint,
                    natType: peer.natType,
                    natTypeV6: peer.natTypeV6,
                    meshIP: peer.meshIP,
                    localIP: peer.localIP,
                    localPort: peer.localPort,
                    peerMinVersion: peer.peerMinVersion,
                    peerMaxVersion: peer.peerMaxVersion,
                    identityPublicKey: peer.identityPublicKey,
                    endpointV6: peer.endpointV6
                });
            }
        }

        return otherPeers;
    }

    /**
     * Removes a peer's active socket from the network (TCP disconnection).
     * The peer remains in meshMembers so the introducer can still relay
     * introductions to it over WireGuard.
     * @param {string} peerID - Unique peer identifier
     */
    leaveNetwork(peerID) {
        for (const [networkID, network] of this.networks.entries()) {
            if (network.has(peerID)) {
                network.delete(peerID);
                console.log(`[NetworkRegistry] Peer ${peerID} disconnected from network ${networkID} (active: ${network.size})`);

                // Mark as disconnected in mesh members (but don't remove yet)
                const members = this.meshMembers.get(networkID);
                if (members && members.has(peerID)) {
                    const member = members.get(peerID);
                    member.connected = false;
                    member.disconnectedAt = Date.now();
                    console.log(`[NetworkRegistry] Peer ${peerID} marked as disconnected in mesh members`);
                }

                if (this.introducers.get(networkID) === peerID) {
                    this.introducers.delete(networkID);
                    console.log(`[NetworkRegistry] Cleared introducer for network ${networkID} (peer ${peerID} disconnected)`);
                }

                // Clean up empty active networks (but keep meshMembers)
                if (network.size === 0) {
                    this.networks.delete(networkID);
                    console.log(`[NetworkRegistry] Removed empty active network ${networkID}`);
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Returns all mesh members for a network (connected or not), excluding a specific peer.
     * Used to build the OtherPeers list for MeshIntroduceRequest — includes peers that
     * disconnected from mediation but are still reachable over WireGuard.
     * @param {string} networkID - Network identifier
     * @param {string} excludePeerID - Peer to exclude (typically the new peer joining)
     * @returns {object[]} List of mesh members with meshIP for WireGuard routing
     */
    getMeshMembers(networkID, excludePeerID) {
        const members = this.meshMembers.get(networkID);
        if (!members) return [];

        const now = Date.now();
        const STALE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes — remove peers disconnected longer than this
        const staleIDs = [];
        // Cross-check against the active-network map: any meshMember marked connected but not
        // in the active network map (which is authoritative for "has a live socket right now")
        // had its disconnect handler skipped somehow — self-heal by treating it as disconnected.
        const activeNetwork = this.networks.get(networkID);

        const result = [];
        for (const [id, member] of members.entries()) {
            if (id === excludePeerID) continue;

            // Remove stale disconnected peers
            if (!member.connected && member.disconnectedAt && (now - member.disconnectedAt) > STALE_TIMEOUT_MS) {
                staleIDs.push(id);
                continue;
            }
            // Self-heal: catch a disconnected member that never got its disconnectedAt stamped
            // (rejoin/leaveNetwork race, or crashed peer whose socket never fired 'close').
            // Without the stamp, the stale-prune above won't fire and the peer sticks forever.
            if (!member.connected && !member.disconnectedAt) {
                console.warn(`[NetworkRegistry] Peer ${id} in ${networkID} disconnected without a timestamp — stamping now`);
                member.disconnectedAt = now;
            }
            // Self-heal: if the member claims connected: true but isn't in the active network
            // map, the socket-close handler was skipped. Mark them disconnected so the stale
            // timer eventually fires. Being conservative — only flip if the active map exists
            // and the peer is genuinely absent from it (not a race with a network we just
            // deleted for being empty).
            if (member.connected && activeNetwork && !activeNetwork.has(id)) {
                console.warn(`[NetworkRegistry] Peer ${id} in ${networkID} marked connected but absent from active network — marking disconnected`);
                member.connected = false;
                member.disconnectedAt = now;
            }

            result.push({
                peerID: member.peerID,
                endpoint: member.endpoint,
                natType: member.natType,
                natTypeV6: member.natTypeV6,
                meshIP: member.meshIP,
                localIP: member.localIP,
                localPort: member.localPort,
                peerMinVersion: member.peerMinVersion,
                peerMaxVersion: member.peerMaxVersion,
                identityPublicKey: member.identityPublicKey,
                endpointV6: member.endpointV6,
                connected: member.connected
            });
        }

        // Clean up stale entries
        for (const id of staleIDs) {
            members.delete(id);
            console.log(`[NetworkRegistry] Removed stale mesh member ${id} (disconnected > ${STALE_TIMEOUT_MS / 1000}s)`);
        }

        return result;
    }

    /**
     * Explicitly removes a peer from mesh membership (full leave, not just disconnect).
     * @param {string} peerID - Unique peer identifier
     */
    removeMeshMember(peerID) {
        for (const [networkID, members] of this.meshMembers.entries()) {
            if (members.has(peerID)) {
                members.delete(peerID);
                console.log(`[NetworkRegistry] Peer ${peerID} removed from mesh members (network: ${networkID})`);

                // Also remove from active if present
                const network = this.networks.get(networkID);
                if (network) network.delete(peerID);

                if (this.introducers.get(networkID) === peerID) {
                    this.introducers.delete(networkID);
                }

                // Clean up empty mesh member maps
                if (members.size === 0) {
                    this.meshMembers.delete(networkID);
                    console.log(`[NetworkRegistry] Removed empty mesh members for network ${networkID}`);
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Finds a peer by socket
     * @param {object} socket - TCP socket
     * @returns {object|null} Peer info or null if not found
     */
    findPeerBySocket(socket) {
        // First try direct socket reference comparison
        for (const network of this.networks.values()) {
            for (const peer of network.values()) {
                if (peer.socket === socket) {
                    return peer;
                }
            }
        }

        // Fallback: Try matching by remote address and port
        if (socket && socket.remoteAddress && socket.remotePort) {
            const remoteAddr = socket.remoteAddress;
            const remotePort = socket.remotePort;

            for (const network of this.networks.values()) {
                for (const peer of network.values()) {
                    const peerSocket = peer.socket;
                    if (peerSocket && peerSocket.remoteAddress === remoteAddr && peerSocket.remotePort === remotePort) {
                        return peer;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Finds a peer by peer ID across all networks
     * @param {string} peerID - Unique peer identifier
     * @returns {object|null} Peer info or null if not found
     */
    findPeerByID(peerID) {
        for (const network of this.networks.values()) {
            if (network.has(peerID)) {
                return network.get(peerID);
            }
        }
        return null;
    }

    /**
     * Gets all peers in a specific network
     * @param {string} networkID - Network identifier
     * @returns {object[]} List of peers
     */
    getPeersInNetwork(networkID) {
        const network = this.networks.get(networkID);
        if (!network) return [];

        return Array.from(network.values()).map(peer => ({
            peerID: peer.peerID,
            endpoint: peer.endpoint,
            natType: peer.natType,
            natTypeV6: peer.natTypeV6,
            endpointV6: peer.endpointV6,   // needed by family-aware canIntroduceNewPeer (v6 replacement path)
            peerMinVersion: peer.peerMinVersion,
            peerMaxVersion: peer.peerMaxVersion,
            identityPublicKey: peer.identityPublicKey
        }));
    }

    /**
     * Gets statistics about all networks
     * @returns {object} Network statistics
     */
    getStats() {
        const stats = {
            totalNetworks: this.networks.size,
            networks: []
        };

        for (const [networkID, network] of this.networks.entries()) {
            const members = this.meshMembers.get(networkID);
            stats.networks.push({
                networkID,
                activePeerCount: network.size,
                totalMemberCount: members ? members.size : 0
            });
        }

        return stats;
    }
}

module.exports = NetworkRegistry;
