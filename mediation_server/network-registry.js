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
    joinNetwork(networkID, peerID, socket, endpoint, natType, meshIP = null, localIP = null, localPort = null) {
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
            console.log(`[NetworkRegistry] Peer ${peerID} rejoining network ${networkID}`);
            // Update existing peer info
            const existingPeer = network.get(peerID);
            existingPeer.socket = socket;
            existingPeer.endpoint = endpoint;
            existingPeer.natType = natType;
            existingPeer.meshIP = meshIP;
            existingPeer.localIP = localIP;
            existingPeer.localPort = localPort;
            existingPeer.joinTime = Date.now();
        } else {
            // Add new peer
            network.set(peerID, {
                peerID,
                socket,
                endpoint,
                natType,
                meshIP,
                localIP,
                localPort,
                joinTime: Date.now()
            });
            console.log(`[NetworkRegistry] Peer ${peerID} joined network ${networkID} (meshIP: ${meshIP}, total active: ${network.size})`);
        }

        // Update mesh members (persistent record)
        members.set(peerID, {
            peerID,
            endpoint,
            natType,
            meshIP,
            localIP,
            localPort,
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
                    meshIP: peer.meshIP,
                    localIP: peer.localIP,
                    localPort: peer.localPort
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

        const result = [];
        for (const [id, member] of members.entries()) {
            if (id === excludePeerID) continue;

            // Remove stale disconnected peers
            if (!member.connected && member.disconnectedAt && (now - member.disconnectedAt) > STALE_TIMEOUT_MS) {
                staleIDs.push(id);
                continue;
            }

            result.push({
                peerID: member.peerID,
                endpoint: member.endpoint,
                natType: member.natType,
                meshIP: member.meshIP,
                localIP: member.localIP,
                localPort: member.localPort,
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
            natType: peer.natType
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
