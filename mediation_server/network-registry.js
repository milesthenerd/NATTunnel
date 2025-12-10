/**
 * Network Registry for Mesh Networking
 *
 * Manages peer-to-peer mesh networks where peers with the same networkID
 * can discover and connect to each other.
 */

class NetworkRegistry {
    constructor() {
        // Map of networkID -> Set of peer info objects
        // Each peer info: { peerID, socket, endpoint, natType, joinTime }
        this.networks = new Map();
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
    joinNetwork(networkID, peerID, socket, endpoint, natType, meshIP = null) {
        if (!networkID || !peerID) {
            throw new Error('networkID and peerID are required');
        }

        // Create network if it doesn't exist
        if (!this.networks.has(networkID)) {
            this.networks.set(networkID, new Map());
            console.log(`[NetworkRegistry] Created new network: ${networkID}`);
        }

        const network = this.networks.get(networkID);

        // Check if peer already exists (reconnection case)
        if (network.has(peerID)) {
            console.log(`[NetworkRegistry] Peer ${peerID} rejoining network ${networkID}`);
            // Update existing peer info
            const existingPeer = network.get(peerID);
            existingPeer.socket = socket;
            existingPeer.endpoint = endpoint;
            existingPeer.natType = natType;
            existingPeer.meshIP = meshIP;
            existingPeer.joinTime = Date.now();
        } else {
            // Add new peer
            network.set(peerID, {
                peerID,
                socket,
                endpoint,
                natType,
                meshIP,
                joinTime: Date.now()
            });
            console.log(`[NetworkRegistry] Peer ${peerID} joined network ${networkID} (meshIP: ${meshIP}, total peers: ${network.size})`);
        }

        // Return list of other peers in the network (excluding this peer)
        const otherPeers = [];
        for (const [id, peer] of network.entries()) {
            if (id !== peerID) {
                otherPeers.push({
                    peerID: peer.peerID,
                    endpoint: peer.endpoint,
                    natType: peer.natType,
                    meshIP: peer.meshIP
                });
            }
        }

        return otherPeers;
    }

    /**
     * Removes a peer from their network
     * @param {string} peerID - Unique peer identifier
     */
    leaveNetwork(peerID) {
        for (const [networkID, network] of this.networks.entries()) {
            if (network.has(peerID)) {
                network.delete(peerID);
                console.log(`[NetworkRegistry] Peer ${peerID} left network ${networkID} (remaining: ${network.size})`);

                // Clean up empty networks
                if (network.size === 0) {
                    this.networks.delete(networkID);
                    console.log(`[NetworkRegistry] Removed empty network ${networkID}`);
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
            stats.networks.push({
                networkID,
                peerCount: network.size
            });
        }

        return stats;
    }
}

module.exports = NetworkRegistry;
