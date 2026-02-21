using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Linq;
using System.Text.Json;

namespace NATTunnel;

public static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            // Normal startup
            if (!Config.CreateNewConfigPrompt())
                Environment.Exit(-1);

            if (!Config.TryLoadConfig())
            {
                Console.WriteLine("Failed to load config.toml");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                Environment.Exit(-1);
            }

            Console.WriteLine($"Starting mesh mode for network: {TunnelOptions.NetworkID}");
            RunMeshMode();
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nError occurred:");
            Console.WriteLine("=============");
            Console.WriteLine(ex.Message);
            if (ex.InnerException != null)
            {
                Console.WriteLine("\nInner Exception:");
                Console.WriteLine("===============");
                Console.WriteLine(ex.InnerException.Message);
            }
            Console.WriteLine("\nStack Trace:");
            Console.WriteLine("===========");
            Console.WriteLine(ex.StackTrace);
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// Runs the application in mesh networking mode.
    /// Peers with the same networkID can discover and connect to each other.
    /// </summary>
    private static void RunMeshMode()
    {
        try
        {
            // Load persistent peer ID or generate and save a new one
            // This ensures stable mesh IP across restarts (mesh IP is derived from peer ID)
            Guid peerID;
            if (TunnelOptions.PeerID.HasValue)
            {
                peerID = TunnelOptions.PeerID.Value;
            }
            else
            {
                peerID = Guid.NewGuid();
                TunnelOptions.PeerID = peerID;
                Config.SavePeerID(peerID);
            }
            Console.WriteLine($"[Mesh] Peer ID: {peerID}, Network: {TunnelOptions.NetworkID}");

            // For mesh mode, we DON'T initialize WireGuard tunnel yet
            // We'll create it after we know our mesh IP address and have peer information
            // This avoids the port conflict and allows proper mesh configuration

            // Create UDP client for NAT traversal (shared across all peer connections)
            var udpClient = new UdpClient();
            udpClient.Client.ReceiveBufferSize = 128000;
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

            // Windows-specific UDP client configuration
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                const int SIO_UDP_CONNRESET = -1744830452;
                udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
            }

            int localUdpPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;

            // Connect to mediation server for NAT type detection
            var endpoint = TunnelOptions.MediationEndpoint;

            var tcpClient = new TcpClient();
            tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            tcpClient.Connect(endpoint);
            var stream = tcpClient.GetStream();

            Console.WriteLine("[Mesh] Connected to mediation server");

            // Helper: extract the first complete JSON object from a string.
            // Returns the parsed message and the remaining string after that object.
            // If no complete object is found, returns null and the original string.
            (MediationMessage msg, string remainder) ExtractFirstJson(string data)
            {
                int start = data.IndexOf('{');
                if (start == -1) return (null, data);
                int braces = 0;
                for (int i = start; i < data.Length; i++)
                {
                    if (data[i] == '{') braces++;
                    else if (data[i] == '}')
                    {
                        braces--;
                        if (braces == 0)
                        {
                            string jsonObj = data.Substring(start, i - start + 1);
                            string rest = data.Substring(i + 1);
                            return (JsonSerializer.Deserialize<MediationMessage>(jsonObj), rest);
                        }
                    }
                }
                return (null, data); // Incomplete
            }

            // Read a single TCP message, accumulating reads until a complete JSON object is found.
            // Returns the parsed message and stores any leftover in earlyTcpRemainder.
            string earlyTcpRemainder = "";
            byte[] buffer = new byte[8192];
            MediationMessage ReadOneTcpMessage()
            {
                while (true)
                {
                    var (msg, rest) = ExtractFirstJson(earlyTcpRemainder);
                    if (msg != null)
                    {
                        earlyTcpRemainder = rest;
                        return msg;
                    }
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0) throw new IOException("Mediation server closed connection");
                    earlyTcpRemainder += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                }
            }

            // Wait for Connected message
            var connectedMsg = ReadOneTcpMessage();
            // Request NAT type detection
            var natTypeRequest = new MediationMessage(MediationMessageType.NATTypeRequest)
            {
                LocalPort = localUdpPort,
                LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                ClientID = peerID
            };

            string natRequestJson = natTypeRequest.Serialize();
            byte[] natBuffer = Encoding.ASCII.GetBytes(natRequestJson);
            stream.Write(natBuffer, 0, natBuffer.Length);

            // Wait for NAT test begin
            var natTestBegin = ReadOneTcpMessage();

            if (natTestBegin.ID == MediationMessageType.NATTestBegin)
            {
                // Send NAT test packets
                var natTestMsg = new MediationMessage(MediationMessageType.NATTest)
                {
                    ClientID = peerID
                };
                byte[] natTestBuffer = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
                udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortOne));
                udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortTwo));
            }

            // Wait for NAT type response
            var natTypeResponse = ReadOneTcpMessage();

            NATType detectedNatType = NATType.Unknown;
            if (natTypeResponse.ID == MediationMessageType.NATTypeResponse)
            {
                detectedNatType = natTypeResponse.NATType;
                Console.WriteLine($"[Mesh] NAT type detected: {detectedNatType}");
            }

            // Calculate mesh IP address from peer ID (deterministic, unique per peer)
            // Use hash of peer ID to generate IP in 10.5.0.0/16 range
            var peerIDBytes = peerID.ToByteArray();
            var hash = System.Security.Cryptography.SHA256.HashData(peerIDBytes);
            // Use first 2 bytes of hash for last 2 octets of IP (10.5.X.Y)
            // Skip 10.5.0.0 (network) and 10.5.255.255 (broadcast)
            byte octet3 = hash[0];
            byte octet4 = (byte)((hash[1] % 254) + 1); // 1-254 to avoid .0 and .255
            var meshIP = $"10.5.{octet3}.{octet4}";
            Console.WriteLine($"[Mesh] Assigned mesh IP: {meshIP}");

            // Send KeepAlive to prevent timeout during WireGuard initialization
            var keepAliveMsgBeforeWg = new MediationMessage(MediationMessageType.KeepAlive);
            byte[] wgKeepAliveBuffer = Encoding.ASCII.GetBytes(keepAliveMsgBeforeWg.Serialize());
            stream.Write(wgKeepAliveBuffer, 0, wgKeepAliveBuffer.Length);

            // Initialize WireGuard tunnel for mesh mode
            string interfaceName = $"NATTunnel-{TunnelOptions.NetworkID}";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";
            var wireguardTunnel = new WireGuardTunnel(interfaceName, debugMode, isRunningAsService: false, skipTunnelCreation: true);

            // Set client IP for mesh mode with /16 netmask (covers 10.5.0.0 - 10.5.255.255 for all mesh peers)
            wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
            Console.WriteLine($"[Mesh] WireGuard tunnel initialized with IP {meshIP}/16");

            // Initialize UDP proxy for mesh mode
            // The proxy will forward WireGuard traffic between the NAT-traversed peer connections and local WireGuard interface
            var udpProxy = new WireGuardUdpProxy(udpClient);
            wireguardTunnel.SetUdpProxy(udpProxy);

            // Start mesh control listener on port 51888 (receives mesh messages over WireGuard)
            // These arrive as UDP packets from other peers' mesh IPs after WireGuard tunnels are established.
            // We use thread-safe queues to bridge the listener thread into the main message loop.
            const int MeshControlPort = 51888;
            // MeshIntroduction is no longer used — the introducer sends MeshConnectionBegin instead
            var meshConnectionBeginQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshHeartbeatAckQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshControlClient = new UdpClient(MeshControlPort);
            System.Threading.Tasks.Task.Run(async () =>
            {
                while (true)
                {
                    try
                    {
                        var result = await meshControlClient.ReceiveAsync();
                        string json = Encoding.UTF8.GetString(result.Buffer);
                        var controlMsg = JsonSerializer.Deserialize<MediationMessage>(json);
                        if (controlMsg == null) continue;

                        if (controlMsg.ID == MediationMessageType.MeshConnectionBegin)
                        {
                            Console.WriteLine($"[Mesh] Received MeshConnectionBegin from {result.RemoteEndPoint}: peer {controlMsg.PeerID} at {controlMsg.EndpointString}");
                            meshConnectionBeginQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeat)
                        {
                            // Respond with our list of connected WireGuard peer mesh IPs
                            var allPeers = wireguardTunnel.GetAllPeers();
                            var connectedIPs = allPeers.Select(p => p.PrivateAddress.ToString()).ToArray();
                            var ack = new MediationMessage(MediationMessageType.MeshHeartbeatAck)
                            {
                                PeerID = peerID.ToString(),
                                PrivateAddressString = meshIP,
                                ConnectedMeshIPs = connectedIPs
                            };
                            byte[] ackBytes = Encoding.UTF8.GetBytes(ack.Serialize());
                            meshControlClient.Send(ackBytes, ackBytes.Length, result.RemoteEndPoint);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeatAck)
                        {
                            meshHeartbeatAckQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshIntroduction)
                        {
                            // MeshIntroduction is no longer used — the introducer sends MeshConnectionBegin instead
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Mesh control listener error: {ex.Message}");
                    }
                }
            });

            // Now join mesh network with REAL NAT type
            var joinRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
            {
                NetworkID = TunnelOptions.NetworkID,
                PeerID = peerID.ToString(),
                NATType = detectedNatType,
                PrivateAddressString = meshIP  // Send our mesh IP to other peers
            };

            string requestJson = joinRequest.Serialize();
            byte[] sendBuffer = Encoding.ASCII.GetBytes(requestJson);
            stream.Write(sendBuffer, 0, sendBuffer.Length);

            Console.WriteLine($"[Mesh] Sent join request for network: {TunnelOptions.NetworkID}");

            // Wait for join response
            var joinResponse = ReadOneTcpMessage();
            Console.WriteLine($"[Mesh] Joined network! Found {joinResponse.PeerCount} other peers");

            // Store active peer tunnels
            var activePeerTunnels = new Dictionary<string, Tunnel>();  // PeerID -> Tunnel
            var pendingConnectionRequests = new HashSet<string>();  // Track peers we've sent connection requests to
            var activeConnectionTunnels = new Dictionary<int, Tunnel>();  // ConnectionID -> Tunnel
            var connectionIDToPeerID = new Dictionary<int, string>();  // ConnectionID -> PeerID mapping
            var peerMeshIPs = new Dictionary<int, string>();  // ConnectionID -> Peer's mesh IP
            int pendingTunnelCount = 0;
            // Deferred MeshConnectionBegin messages for peers whose WireGuard tunnels aren't established yet.
            // Keyed by the target peer's mesh IP (the peer we want to send the message to).
            var deferredIntroductions = new Dictionary<string, List<MediationMessage>>();
            // Cache of peer info keyed by mesh IP — populated from MeshIntroduceRequest OtherPeers
            // and MeshJoinResponse, used by the introducer heartbeat to re-send MeshConnectionBegin.
            var peerInfoByMeshIP = new Dictionary<string, (string peerID, string endpoint, NATType natType)>();
            // Set of mesh IPs with fully established WireGuard tunnels (onConnectionComplete fired)
            var completedTunnelMeshIPs = new HashSet<string>();
            // Pairs of mesh IPs that are connected via relay through this introducer.
            // Stored as sorted "ipA|ipB" strings so lookup is order-independent.
            var relayedPairs = new HashSet<string>();

            // Track the introducer's mesh IP so we can detect when it goes offline.
            // Populated from MeshJoinResponse by matching IntroducerPeerID to peers list.
            string introducerMeshIP = null;
            if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) && joinResponse.Peers != null)
            {
                foreach (var peer in joinResponse.Peers)
                {
                    var pObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                    string pid = pObj.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                    string mip = pObj.TryGetProperty("meshIP", out JsonElement mipEl) ? mipEl.GetString() : null;
                    if (pid == joinResponse.IntroducerPeerID && !string.IsNullOrEmpty(mip))
                    {
                        introducerMeshIP = mip;
                        Console.WriteLine($"[Mesh] Introducer mesh IP: {introducerMeshIP} (peer {pid})");
                        break;
                    }
                }
            }


            // Helper method to process discovered peers and send connection requests
            void ProcessDiscoveredPeers(object[] peers)
            {
                if (peers == null || peers.Length == 0)
                    return;

                Console.WriteLine($"[Mesh] Discovered {peers.Length} peer(s) in network:");
                foreach (var peer in peers)
                {
                    var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                    string targetPeerID = peerObj.GetProperty("peerID").GetString();
                    string peerEndpoint = peerObj.GetProperty("endpoint").GetString();
                    string peerMeshIP = peerObj.TryGetProperty("meshIP", out JsonElement meshIPElement) ? meshIPElement.GetString() : null;
                    int peerNatTypeInt = peerObj.TryGetProperty("natType", out JsonElement natEl) ? natEl.GetInt32() : -1;

                    // Skip if this is ourselves
                    if (targetPeerID == peerID.ToString())
                        continue;

                    // Skip if we've already requested connection or have an active tunnel to this peer
                    // Check both by PeerID and by mesh IP
                    if (activePeerTunnels.ContainsKey(targetPeerID) || (peerMeshIP != null && activePeerTunnels.ContainsKey(peerMeshIP)))
                        continue;

                    if (pendingConnectionRequests.Contains(targetPeerID))
                        continue;

                    // Skip symmetric-to-symmetric: hole punching is infeasible.
                    // The introducer will handle this pair via relay MeshConnectionBegin.
                    if (detectedNatType == NATType.Symmetric && (NATType)peerNatTypeInt == NATType.Symmetric)
                        continue;

                    // Send connection request to mediation server for this peer
                    var connectionRequest = new MediationMessage(MediationMessageType.ConnectionRequest)
                    {
                        PeerID = targetPeerID,
                        NATType = detectedNatType
                    };

                    string connRequestJson = connectionRequest.Serialize();
                    byte[] connBuffer = Encoding.ASCII.GetBytes(connRequestJson);
                    stream.Write(connBuffer, 0, connBuffer.Length);
                    stream.Flush();

                    // Mark as pending so we don't send duplicate connection requests
                    pendingConnectionRequests.Add(targetPeerID);
                }
            }

            // Helper method to process a MeshConnectionBegin message:
            // Create a tunnel with skipTcpConnection=true and inject the connection info
            // so the tunnel hole-punches directly without going through the mediation server.
            void ProcessMeshConnectionBegin(MediationMessage cbMsg)
            {
                string remotePeerID = cbMsg.PeerID;
                string remoteMeshIP = cbMsg.PrivateAddressString;
                string remoteEndpoint = cbMsg.EndpointString;
                NATType remotePeerNatType = cbMsg.NATType;

                if (string.IsNullOrEmpty(remotePeerID) || string.IsNullOrEmpty(remoteEndpoint))
                {
                    Console.WriteLine($"[Mesh] MeshConnectionBegin missing PeerID or endpoint — skipping");
                    return;
                }

                // Skip if already connected or pending
                if (activePeerTunnels.ContainsKey(remotePeerID) ||
                    (!string.IsNullOrEmpty(remoteMeshIP) && activePeerTunnels.ContainsKey(remoteMeshIP)) ||
                    pendingConnectionRequests.Contains(remotePeerID))
                {
                    Console.WriteLine($"[Mesh] Ignoring MeshConnectionBegin for {remotePeerID} — already connected or pending");
                    return;
                }

                Console.WriteLine($"[Mesh] Processing MeshConnectionBegin: peer {remotePeerID} at {remoteEndpoint} (NAT: {remotePeerNatType}, meshIP: {remoteMeshIP}, relay: {cbMsg.IsRelay})");

                // Relay mode: both peers are symmetric NAT, traffic is relayed through the introducer
                if (cbMsg.IsRelay && !string.IsNullOrEmpty(remoteMeshIP))
                {
                    string introducerIP = cbMsg.IntroducerMeshIP;
                    var remoteMeshIPAddr = IPAddress.Parse(remoteMeshIP);

                    if (!string.IsNullOrEmpty(introducerIP))
                    {
                        // Add the remote peer's mesh IP to the introducer's AllowedIPs
                        // so WireGuard routes traffic for that IP through the introducer's tunnel
                        var introducerIPAddr = IPAddress.Parse(introducerIP);
                        if (wireguardTunnel.AddRelayRoute(introducerIPAddr, remoteMeshIPAddr))
                        {
                            Console.WriteLine($"[Mesh] Relay route added: {remoteMeshIP} via introducer {introducerIP} — peer {remotePeerID} is reachable");
                        }
                        else
                        {
                            Console.WriteLine($"[Mesh] Failed to add relay route for {remoteMeshIP} via introducer {introducerIP}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"[Mesh] Relay MeshConnectionBegin missing IntroducerMeshIP — cannot set up relay route");
                    }
                    pendingConnectionRequests.Remove(remotePeerID);
                    return;
                }

                pendingConnectionRequests.Add(remotePeerID);
                pendingTunnelCount++;
                var capturedPeerID = remotePeerID;
                var capturedMeshIP = remoteMeshIP;
                var peerTunnel = new Tunnel(
                    onConnectionFailure: () =>
                    {
                        Console.WriteLine($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} failed — cleaning up for future retry");
                        lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(capturedPeerID.GetHashCode()); }
                        pendingConnectionRequests.Remove(capturedPeerID);
                        activePeerTunnels.Remove(capturedPeerID);
                        if (!string.IsNullOrEmpty(capturedMeshIP))
                            activePeerTunnels.Remove(capturedMeshIP);
                        pendingTunnelCount--;
                    },
                    sharedUdpClient: udpClient,
                    meshPeerEndpoint: remoteEndpoint,
                    retryInPlace: true,
                    sharedClientID: peerID,
                    ownMeshIP: meshIP,
                    onConnectionComplete: () =>
                    {
                        Console.WriteLine($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} WireGuard established");
                        pendingTunnelCount--;
                    }
                );

                peerTunnel.SetWireGuardTunnel(wireguardTunnel);

                // Track the tunnel
                lock (activeConnectionTunnels) { activeConnectionTunnels[capturedPeerID.GetHashCode()] = peerTunnel; }
                activePeerTunnels[remotePeerID] = peerTunnel;
                if (!string.IsNullOrEmpty(remoteMeshIP))
                {
                    activePeerTunnels[remoteMeshIP] = peerTunnel;
                    peerMeshIPs[capturedPeerID.GetHashCode()] = remoteMeshIP;
                }

                // Start the tunnel (returns immediately since skipTcpConnection=true)
                System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        peerTunnel.Start();
                        // Now inject the connection info to start hole-punching
                        peerTunnel.InjectConnectionBegin(
                            remoteEndpoint,
                            remotePeerNatType,
                            detectedNatType,
                            remoteMeshIP
                        );
                        Console.WriteLine($"[Mesh] Hole-punching started for {capturedPeerID} at {remoteEndpoint}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Error starting introducer-relayed tunnel for {capturedPeerID}: {ex.Message}");
                        pendingConnectionRequests.Remove(capturedPeerID);
                        pendingTunnelCount--;
                    }
                });
            }

            // Process initial peer list
            if (joinResponse.Peers != null && joinResponse.Peers.Length > 0)
            {
                ProcessDiscoveredPeers(joinResponse.Peers);
            }
            else
            {
                Console.WriteLine("[Mesh] No other peers in network yet - waiting for others to join...");
            }

            // Keep connection alive and listen for ConnectionBegin messages
            Console.WriteLine("[Mesh] Mesh networking active. Waiting for connections...");
            Console.WriteLine("[Mesh] Press Ctrl+C to exit.");

            // Set to true when the server designates us as the introducer (via MeshIntroduceRequest
            // or via IntroducerPeerID in MeshJoinResponse). Introducers must keep the mediation
            // TCP connection alive indefinitely so the server can push future requests to us.
            bool isIntroducer = false;

            // Check if the server already told us we're the introducer in the join response.
            // Also: if we're non-symmetric and no other non-symmetric peer exists in the network,
            // we'll definitely be the introducer for the next joiner — stay connected proactively.
            if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                joinResponse.IntroducerPeerID == peerID.ToString())
            {
                isIntroducer = true;
                Console.WriteLine("[Mesh] Server designated us as the introducer in join response");
            }
            else if (detectedNatType != NATType.Symmetric && joinResponse.Peers != null)
            {
                // Check if any other non-symmetric peer exists (who could serve as introducer instead)
                bool otherNonSymmetricExists = false;
                foreach (var peer in joinResponse.Peers)
                {
                    var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                    string peerId = peerObj.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                    int natTypeInt = peerObj.TryGetProperty("natType", out JsonElement natEl) ? natEl.GetInt32() : -1;
                    if (peerId != peerID.ToString() && natTypeInt >= 0 && (NATType)natTypeInt != NATType.Symmetric)
                    {
                        otherNonSymmetricExists = true;
                        break;
                    }
                }
                if (!otherNonSymmetricExists)
                {
                    isIntroducer = true;
                    Console.WriteLine("[Mesh] We're the only non-symmetric peer — staying connected as potential introducer");
                }
            }

            // Set up periodic keep-alive
            var lastKeepAlive = DateTime.UtcNow;
            var keepAliveInterval = TimeSpan.FromSeconds(5);

            // Grace period: once all initial connections are established, wait before
            // disconnecting to give disconnected peers time to TransientReconnect.
            DateTime? disconnectAfter = null;
            bool hasPeers = joinResponse.Peers != null && joinResponse.Peers.Length > 0;

            // Periodic peer discovery: if we're connected to mediation but have no WireGuard
            // peers (lone peer), periodically re-send MeshJoinRequest to discover new peers.
            var lastPeerDiscovery = DateTime.UtcNow;
            var peerDiscoveryInterval = TimeSpan.FromSeconds(15);

            // Introducer heartbeat: periodically check that all peers can reach each other
            var lastHeartbeat = DateTime.UtcNow;
            var heartbeatInterval = TimeSpan.FromSeconds(30);
            // After sending heartbeats, wait this long to collect acks before processing
            DateTime? heartbeatAckDeadline = null;
            // Collected acks for the current heartbeat round: meshIP -> set of connected mesh IPs
            var heartbeatAcks = new Dictionary<string, HashSet<string>>();
            // Track all known mesh IPs we've sent heartbeats to (for completeness checking)
            var heartbeatTargets = new HashSet<string>();

            // TCP reassembly buffer — accumulates partial JSON across reads
            // Seed with any leftover from early TCP reads (e.g. ConnectionBegin
            // messages that arrived concatenated with the MeshJoinResponse)
            string tcpBuffer = earlyTcpRemainder;

            // ── Shared UDP dispatcher ─────────────────────────────────────────────────
            // All mesh Tunnel instances share the same udpClient socket. Only ONE receive
            // loop must run on it; each received packet is dispatched to ALL active tunnels
            // via ProcessUdpPacket(). Without this, multiple UdpClientListenLoop() calls
            // on the same socket race for packets and most tunnels miss most messages.
            System.Threading.Tasks.Task.Run(() =>
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                Console.WriteLine("[Mesh] Shared UDP dispatcher started");
                while (true)
                {
                    try
                    {
                        byte[] data = udpClient.Receive(ref ep);

                        // Take a snapshot of active tunnels to avoid locking issues
                        Tunnel[] tunnels;
                        lock (activeConnectionTunnels)
                        {
                            tunnels = new Tunnel[activeConnectionTunnels.Count];
                            activeConnectionTunnels.Values.CopyTo(tunnels, 0);
                        }

                        // Log received packets for debugging (only non-WireGuard JSON packets)
                        if (data.Length > 0 && data[0] == (byte)'{')
                        {
                            Console.WriteLine($"[Dispatcher] Received {data.Length}B from {ep.Address}:{ep.Port}, dispatching to {tunnels.Length} tunnel(s)");
                        }

                        // Dispatch to ALL active tunnels — each tunnel's ProcessUdpPacket
                        // filters internally (by mesh IP content, source IP, etc.)
                        foreach (var tunnel in tunnels)
                        {
                            try
                            {
                                tunnel.ProcessUdpPacket(data, ep);
                            }
                            catch (System.Net.Sockets.SocketException)
                            {
                                // Non-matching tunnel — socket not connected to this endpoint, ignore
                            }
                            catch (System.Security.Cryptography.CryptographicException)
                            {
                                // Non-matching tunnel — can't decrypt with this tunnel's key, ignore
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Mesh] Error dispatching packet to tunnel: {ex.Message}");
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        // Socket closed — shutting down
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] UDP dispatcher error: {ex.Message}");
                    }
                }
            });

            // Message loop - create Tunnel instances when ConnectionBegin arrives.
            // Non-introducer peers disconnect once their initial connections are established
            // and reconnect transiently for each future introduced peer.
            // The introducer peer stays connected permanently to receive MeshIntroduceRequests.
            while (true)
            {
                // Disconnect once all initial setup is done, but only if we haven't been
                // selected as the introducer (introducers must stay connected).
                // Use a grace period to give disconnected peers time to TransientReconnect.
                if (!isIntroducer && tcpClient.Connected && hasPeers)
                {
                    // Only ready to disconnect if no pending work AND at least one tunnel actually
                    // succeeded. If all connections failed and we have zero WireGuard peers, we're
                    // isolated — stay connected so the server can assign new connections.
                    bool noPendingWork = pendingConnectionRequests.Count == 0 && pendingTunnelCount == 0;
                    bool hasEstablishedTunnels = activePeerTunnels.Count > 0;

                    // Before disconnecting, verify we have a WireGuard tunnel to the introducer
                    // (or at least one non-symmetric peer). Without this, the introducer can't
                    // send us MeshConnectionBegin messages for newly joining peers.
                    bool hasIntroducerPath = false;
                    if (hasEstablishedTunnels)
                    {
                        string introducerPeerID = joinResponse.IntroducerPeerID;
                        if (!string.IsNullOrEmpty(introducerPeerID) && activePeerTunnels.ContainsKey(introducerPeerID))
                        {
                            hasIntroducerPath = true;
                        }
                        else
                        {
                            // Check if we have a tunnel to ANY peer (who might be the introducer)
                            // Any established tunnel means the introducer can reach us over WireGuard
                            hasIntroducerPath = completedTunnelMeshIPs.Count > 0;
                        }
                    }

                    bool readyToDisconnect = noPendingWork && hasEstablishedTunnels && hasIntroducerPath;

                    if (readyToDisconnect && disconnectAfter == null)
                    {
                        int gracePeriod = detectedNatType != NATType.Symmetric ? 30 : 5;
                        disconnectAfter = DateTime.UtcNow.AddSeconds(gracePeriod);
                        Console.WriteLine($"[Mesh] All initial connections established — grace period started ({gracePeriod}s)");
                    }
                    else if (!readyToDisconnect && disconnectAfter != null)
                    {
                        // New connection arrived during grace period — reset timer
                        disconnectAfter = null;
                        Console.WriteLine("[Mesh] New connection activity — grace period reset");
                    }
                    else if (readyToDisconnect && disconnectAfter != null && DateTime.UtcNow > disconnectAfter.Value)
                    {
                        Console.WriteLine("[Mesh] Grace period elapsed — disconnecting from mediation server");
                        tcpClient.Close();
                        break;
                    }
                }

                // Bail if the connection dropped unexpectedly during setup
                if (!tcpClient.Connected)
                {
                    if (isIntroducer)
                        Console.WriteLine("[Mesh] Mediation server connection lost — introducer role ended");
                    else
                        Console.WriteLine("[Mesh] TCP connection to mediation server lost during setup");
                    break;
                }

                // Send periodic keep-alive to prevent timeout during setup
                if (DateTime.UtcNow - lastKeepAlive > keepAliveInterval)
                {
                    try
                    {
                        var keepAliveMsg = new MediationMessage(MediationMessageType.KeepAlive);
                        string keepAliveJson = keepAliveMsg.Serialize();
                        byte[] keepAliveBuffer = Encoding.ASCII.GetBytes(keepAliveJson);
                        stream.Write(keepAliveBuffer, 0, keepAliveBuffer.Length);
                        lastKeepAlive = DateTime.UtcNow;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Keep-alive write failed, connection lost: {ex.Message}");
                        break;
                    }
                }

                // Periodic peer discovery: if we have no WireGuard peers and no pending
                // connections, re-send MeshJoinRequest to discover newly available peers.
                if (tcpClient.Connected && activePeerTunnels.Count == 0 &&
                    pendingConnectionRequests.Count == 0 && pendingTunnelCount == 0 &&
                    DateTime.UtcNow - lastPeerDiscovery > peerDiscoveryInterval)
                {
                    Console.WriteLine("[Mesh] No active peers — sending periodic discovery request");
                    try
                    {
                        var discoveryRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
                        {
                            NetworkID = TunnelOptions.NetworkID,
                            PeerID = peerID.ToString(),
                            NATType = detectedNatType,
                            PrivateAddressString = meshIP
                        };
                        string discoveryJson = discoveryRequest.Serialize();
                        byte[] discoveryBuffer = Encoding.ASCII.GetBytes(discoveryJson);
                        stream.Write(discoveryBuffer, 0, discoveryBuffer.Length);
                        stream.Flush();
                        lastPeerDiscovery = DateTime.UtcNow;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Discovery write failed, connection lost: {ex.Message}");
                        break;
                    }
                }

                // Process MeshConnectionBegin messages: create tunnels that hole-punch directly
                // without going through the mediation server (introducer-relayed coordination).
                while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
                {
                    ProcessMeshConnectionBegin(cbMsg);
                }

                // ── Introducer heartbeat ────────────────────────────────────────────
                // Periodically send MeshHeartbeat to all peers, collect acks, and
                // re-send MeshConnectionBegin for any missing peer-to-peer links.
                if (isIntroducer && heartbeatAckDeadline == null &&
                    DateTime.UtcNow - lastHeartbeat > heartbeatInterval)
                {
                    // Send heartbeats to all peers we have WireGuard tunnels to
                    var allPeers = wireguardTunnel.GetAllPeers();
                    heartbeatTargets.Clear();
                    heartbeatAcks.Clear();

                    foreach (var peer in allPeers)
                    {
                        string peerIP = peer.PrivateAddress.ToString();
                        heartbeatTargets.Add(peerIP);

                        var hb = new MediationMessage(MediationMessageType.MeshHeartbeat);
                        try
                        {
                            byte[] hbBytes = Encoding.UTF8.GetBytes(hb.Serialize());
                            meshControlClient.Send(hbBytes, hbBytes.Length,
                                new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to send heartbeat to {peerIP}: {ex.Message}");
                        }
                    }

                    if (heartbeatTargets.Count > 1)
                    {
                        heartbeatAckDeadline = DateTime.UtcNow.AddSeconds(5);
                        Console.WriteLine($"[Mesh] Heartbeat sent to {heartbeatTargets.Count} peer(s), collecting acks...");
                    }
                    else
                    {
                        // 0 or 1 peers — nothing to check connectivity between
                        lastHeartbeat = DateTime.UtcNow;
                    }
                }

                // Collect heartbeat acks
                if (heartbeatAckDeadline != null)
                {
                    while (meshHeartbeatAckQueue.TryDequeue(out var ackMsg))
                    {
                        string ackMeshIP = ackMsg.PrivateAddressString;
                        if (!string.IsNullOrEmpty(ackMeshIP) && ackMsg.ConnectedMeshIPs != null)
                        {
                            heartbeatAcks[ackMeshIP] = new HashSet<string>(ackMsg.ConnectedMeshIPs);
                        }
                    }

                    // Process after deadline
                    if (DateTime.UtcNow > heartbeatAckDeadline.Value)
                    {
                        Console.WriteLine($"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

                        // Check every pair of peers for missing connectivity
                        var targetList = heartbeatTargets.ToList();
                        int repairCount = 0;
                        for (int i = 0; i < targetList.Count; i++)
                        {
                            for (int j = i + 1; j < targetList.Count; j++)
                            {
                                string ipA = targetList[i];
                                string ipB = targetList[j];

                                // Check if A reports B and B reports A
                                bool aReportsB = heartbeatAcks.ContainsKey(ipA) && heartbeatAcks[ipA].Contains(ipB);
                                bool bReportsA = heartbeatAcks.ContainsKey(ipB) && heartbeatAcks[ipB].Contains(ipA);

                                // Skip pairs that are relayed through us — they won't appear
                                // in each other's WireGuard peer lists because the relay uses
                                // AllowedIPs on the introducer's peer entry, not a direct tunnel.
                                string sortedA = string.Compare(ipA, ipB, StringComparison.Ordinal) < 0 ? ipA : ipB;
                                string sortedB = sortedA == ipA ? ipB : ipA;
                                if (relayedPairs.Contains($"{sortedA}|{sortedB}"))
                                    continue;

                                if (!aReportsB && !bReportsA)
                                {
                                    peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                                    peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

                                    // Check if both are symmetric — use relay instead of direct hole-punch
                                    bool bothSymmetric = infoA.natType == NATType.Symmetric && infoB.natType == NATType.Symmetric;

                                    if (bothSymmetric)
                                    {
                                        Console.WriteLine($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected (both symmetric) — re-establishing relay");

                                        wireguardTunnel.EnableForwarding();

                                        // Send relay MeshConnectionBegin to A about B
                                        var relayToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                        {
                                            PeerID = infoB.peerID ?? "",
                                            EndpointString = infoB.endpoint,
                                            NATType = infoB.natType,
                                            PrivateAddressString = ipB,
                                            IsRelay = true,
                                            IntroducerMeshIP = meshIP
                                        };
                                        try
                                        {
                                            byte[] rABytes = Encoding.UTF8.GetBytes(relayToA.Serialize());
                                            meshControlClient.Send(rABytes, rABytes.Length,
                                                new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}");
                                        }

                                        // Send relay MeshConnectionBegin to B about A
                                        var relayToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                        {
                                            PeerID = infoA.peerID ?? "",
                                            EndpointString = infoA.endpoint,
                                            NATType = infoA.natType,
                                            PrivateAddressString = ipA,
                                            IsRelay = true,
                                            IntroducerMeshIP = meshIP
                                        };
                                        try
                                        {
                                            byte[] rBBytes = Encoding.UTF8.GetBytes(relayToB.Serialize());
                                            meshControlClient.Send(rBBytes, rBBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                                        }

                                        // Track as relayed
                                        relayedPairs.Add($"{sortedA}|{sortedB}");
                                    }
                                    else
                                    {
                                        // Non-symmetric pair — re-introduce with direct hole-punch
                                        Console.WriteLine($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected — re-introducing");

                                        // Send MeshConnectionBegin to A about B
                                        if (!string.IsNullOrEmpty(infoB.endpoint))
                                        {
                                            var cbToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                            {
                                                PeerID = infoB.peerID ?? "",
                                                EndpointString = infoB.endpoint,
                                                NATType = infoB.natType,
                                                PrivateAddressString = ipB
                                            };
                                            try
                                            {
                                                byte[] cbABytes = Encoding.UTF8.GetBytes(cbToA.Serialize());
                                                meshControlClient.Send(cbABytes, cbABytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                                repairCount++;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send repair MeshConnectionBegin to {ipA}: {ex.Message}");
                                            }
                                        }

                                        // Send MeshConnectionBegin to B about A
                                        if (!string.IsNullOrEmpty(infoA.endpoint))
                                        {
                                            var cbToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                            {
                                                PeerID = infoA.peerID ?? "",
                                                EndpointString = infoA.endpoint,
                                                NATType = infoA.natType,
                                                PrivateAddressString = ipA
                                            };
                                            try
                                            {
                                                byte[] cbBBytes = Encoding.UTF8.GetBytes(cbToB.Serialize());
                                                meshControlClient.Send(cbBBytes, cbBBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                                repairCount++;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send repair MeshConnectionBegin to {ipB}: {ex.Message}");
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (repairCount > 0)
                            Console.WriteLine($"[Mesh] Heartbeat: sent {repairCount} repair MeshConnectionBegin message(s)");

                        heartbeatAckDeadline = null;
                        lastHeartbeat = DateTime.UtcNow;
                    }
                }

                if (stream.DataAvailable)
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("[Mesh] Mediation server closed connection");
                        break;
                    }
                    tcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                }

                // Process any complete JSON messages in the TCP buffer
                // (may contain leftover from early reads or newly received data)
                if (tcpBuffer.Length > 0 && tcpBuffer.Contains('{'))
                {
                    // Handle multiple JSON objects in the buffer
                    // Split by detecting JSON object boundaries (each starts with '{' and ends with '}')
                    int jsonStartIndex = 0;
                    while (jsonStartIndex < tcpBuffer.Length)
                    {
                        // Find the start of the next JSON object
                        int jsonObjStart = tcpBuffer.IndexOf('{', jsonStartIndex);
                        if (jsonObjStart == -1) break;

                        // Find the matching closing brace by counting braces
                        int braceCount = 0;
                        int jsonObjEnd = -1;
                        for (int i = jsonObjStart; i < tcpBuffer.Length; i++)
                        {
                            if (tcpBuffer[i] == '{') braceCount++;
                            else if (tcpBuffer[i] == '}')
                            {
                                braceCount--;
                                if (braceCount == 0)
                                {
                                    jsonObjEnd = i;
                                    break;
                                }
                            }
                        }

                        if (jsonObjEnd == -1)
                        {
                            // Incomplete JSON — keep the remainder in tcpBuffer for next read
                            tcpBuffer = tcpBuffer.Substring(jsonObjStart);
                            jsonStartIndex = 0; // Signal that tcpBuffer is already trimmed
                            break;
                        }

                        // Extract and parse this JSON object
                        string jsonObject = tcpBuffer.Substring(jsonObjStart, jsonObjEnd - jsonObjStart + 1);

                        MediationMessage msg;
                        try
                        {
                            msg = JsonSerializer.Deserialize<MediationMessage>(jsonObject);
                        }
                        catch (Exception parseEx)
                        {
                            Console.WriteLine($"[Mesh] Could not parse JSON object: {parseEx.Message}");
                            jsonStartIndex = jsonObjEnd + 1;
                            continue;
                        }

                        // Process this message
                        if (msg.ID == MediationMessageType.ConnectionRequest)
                        {
                            Console.WriteLine($"[Mesh] Received connection request! ConnectionID: {msg.ConnectionID}, Endpoint: {msg.EndpointString}");
                            Console.WriteLine($"[Mesh] Waiting for ConnectionBegin to establish tunnel...");
                            // Don't create Tunnel yet - wait for ConnectionBegin with final endpoint info
                        }
                        else if (msg.ID == MediationMessageType.ConnectionBegin)
                        {
                            Console.WriteLine($"[Mesh] *** ConnectionBegin received! ***");
                            Console.WriteLine($"[Mesh] ConnectionBegin: connID={msg.ConnectionID}, endpoint={msg.EndpointString}, NAT={msg.NATType}, meshIP={msg.PrivateAddressString}");

                            // Store peer's mesh IP for later use in WireGuard key exchange
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerMeshIPs[msg.ConnectionID] = msg.PrivateAddressString;
                            }

                            // Check if we already have a tunnel for this ConnectionID
                            if (activeConnectionTunnels.ContainsKey(msg.ConnectionID))
                            {
                                Console.WriteLine($"[Mesh] Tunnel {msg.ConnectionID} already exists - ignoring duplicate ConnectionBegin");
                            }
                            else
                            {
                                // Create Tunnel instance for mesh peer connection
                                // The Tunnel will connect to mediation server which will recognize the ConnectionID
                                // and send ConnectionBegin immediately (server handles mesh connections specially)
                                pendingTunnelCount++;
                                var capturedConnectionID = msg.ConnectionID;
                                var capturedPeerIDForCleanup = msg.PeerID;
                                var capturedMeshIPForCleanup = msg.PrivateAddressString;
                                var peerTunnel = new Tunnel(
                                    onConnectionFailure: () =>
                                    {
                                        Console.WriteLine($"[Mesh] Tunnel {capturedConnectionID} failed permanently after all retries — cleaning up for future retry");
                                        lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(capturedConnectionID); }
                                        if (!string.IsNullOrEmpty(capturedPeerIDForCleanup))
                                            activePeerTunnels.Remove(capturedPeerIDForCleanup);
                                        if (!string.IsNullOrEmpty(capturedMeshIPForCleanup))
                                            activePeerTunnels.Remove(capturedMeshIPForCleanup);
                                        pendingTunnelCount--;
                                    },
                                    sharedUdpClient: udpClient,
                                    meshPeerEndpoint: msg.EndpointString,
                                    retryInPlace: true,
                                    sharedClientID: peerID,
                                    ownMeshIP: meshIP,
                                    onConnectionComplete: () =>
                                    {
                                        Console.WriteLine($"[Mesh] Tunnel {capturedConnectionID} WireGuard connection established");
                                        pendingTunnelCount--;

                                        // Check if there are deferred MeshConnectionBegin messages for this peer
                                        if (peerMeshIPs.TryGetValue(capturedConnectionID, out string completedMeshIP) && !string.IsNullOrEmpty(completedMeshIP))
                                        {
                                            completedTunnelMeshIPs.Add(completedMeshIP);
                                            if (deferredIntroductions.TryGetValue(completedMeshIP, out var deferred) && deferred.Count > 0)
                                            {
                                                Console.WriteLine($"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) to {completedMeshIP}");
                                                foreach (var deferredMsg in deferred)
                                                {
                                                    try
                                                    {
                                                        byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                                        meshControlClient.Send(deferredBytes, deferredBytes.Length,
                                                            new IPEndPoint(IPAddress.Parse(completedMeshIP), MeshControlPort));
                                                        Console.WriteLine($"[Mesh] Sent deferred MeshConnectionBegin to {completedMeshIP} (about peer {deferredMsg.PeerID})");
                                                    }
                                                    catch (Exception ex)
                                                    {
                                                        Console.WriteLine($"[Mesh] Failed to send deferred MeshConnectionBegin to {completedMeshIP}: {ex.Message}");
                                                    }
                                                }
                                                deferredIntroductions.Remove(completedMeshIP);
                                            }
                                        }
                                    }
                                );

                                // Set WireGuard tunnel reference so the peer tunnel can forward traffic
                                peerTunnel.SetWireGuardTunnel(wireguardTunnel);

                                // Track this tunnel by ConnectionID
                                lock (activeConnectionTunnels) { activeConnectionTunnels[msg.ConnectionID] = peerTunnel; }

                                // Map the peer's mesh IP to this tunnel so we can check connection status
                                if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                                {
                                    activePeerTunnels[msg.PrivateAddressString] = peerTunnel;
                                }

                                // Remove from pending by PeerID (matches the key used in Add at ProcessDiscoveredPeers)
                                if (!string.IsNullOrEmpty(msg.PeerID))
                                {
                                    pendingConnectionRequests.Remove(msg.PeerID);
                                    connectionIDToPeerID[msg.ConnectionID] = msg.PeerID;
                                    activePeerTunnels[msg.PeerID] = peerTunnel;
                                }


                                // Start the tunnel asynchronously.
                                // pendingTunnelCount is decremented by onConnectionComplete (success)
                                // or onConnectionFailure (failure) — NOT here — so the mediation
                                // disconnect only happens after WireGuard setup is fully done.
                                System.Threading.Tasks.Task.Run(() =>
                                {
                                    try
                                    {
                                        peerTunnel.Start();
                                        // Inject the ConnectionBegin directly — this preserves LAN endpoints
                                        // for same-NAT peers (the mediation server already substituted them)
                                        peerTunnel.InjectConnectionBegin(
                                            msg.EndpointString,
                                            msg.NATType,
                                            detectedNatType,
                                            msg.PrivateAddressString);
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Error starting tunnel {capturedConnectionID}: {ex.Message}");
                                        pendingTunnelCount--;
                                    }
                                });
                            }
                        }
                        else if (msg.ID == MediationMessageType.MeshJoinResponse)
                        {
                            // Update hasPeers flag and process new peers
                            if (msg.Peers != null && msg.Peers.Length > 0)
                            {
                                hasPeers = true;
                                ProcessDiscoveredPeers(msg.Peers);
                            }

                            // Reset discovery timer
                            lastPeerDiscovery = DateTime.UtcNow;
                        }
                        else if (msg.ID == MediationMessageType.MeshPeerList)
                        {
                            Console.WriteLine($"[Mesh] Updated peer list received: {msg.PeerCount} peers");

                            // Process new peers that joined the network
                            if (msg.Peers != null && msg.Peers.Length > 0)
                            {
                                hasPeers = true;
                                ProcessDiscoveredPeers(msg.Peers);
                            }
                        }
                        else if (msg.ID == MediationMessageType.ConnectionComplete)
                        {
                            Console.WriteLine($"[Mesh] Received ConnectionComplete (routing to tunnel)");

                            // Find all tunnels and notify them
                            // We don't know which ConnectionID this is for from this message alone,
                            // so we need to check all active tunnels
                            // Actually, the message might not have ConnectionID, so notify all tunnels
                            Tunnel[] tunnelSnapshot;
                            lock (activeConnectionTunnels)
                            {
                                tunnelSnapshot = new Tunnel[activeConnectionTunnels.Count];
                                activeConnectionTunnels.Values.CopyTo(tunnelSnapshot, 0);
                            }
                            foreach (var t in tunnelSnapshot)
                            {
                                t.NotifyConnectionComplete();
                            }
                        }
                        else if (msg.ID == MediationMessageType.MeshIntroduceRequest)
                        {
                            // The mediation server has selected us as the introducer for a new peer.
                            // Mark ourselves as the introducer so we never disconnect from the server.
                            // Send MeshConnectionBegin to BOTH peers so they can hole-punch directly
                            // without reconnecting to the mediation server.
                            isIntroducer = true;
                            Console.WriteLine($"[Mesh] Selected as introducer for new peer {msg.PeerID}");

                            // Cache the new peer's info for heartbeat repair
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, msg.EndpointString, msg.NATType);
                            }

                            int introduced = 0;
                            if (msg.OtherPeers != null)
                            {
                                Console.WriteLine($"[Mesh] MeshIntroduceRequest has {msg.OtherPeers.Length} peer(s) in OtherPeers:");
                                for (int i = 0; i < msg.OtherPeers.Length; i++)
                                {
                                    Console.WriteLine($"[Mesh]   OtherPeers[{i}]: {msg.OtherPeers[i]}");
                                }

                                foreach (var peerObj in msg.OtherPeers)
                                {
                                    var peerElement = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                                    string existingPeerMeshIP = peerElement.TryGetProperty("meshIP", out JsonElement mip) ? mip.GetString() : null;
                                    string existingPeerEndpoint = peerElement.TryGetProperty("endpoint", out JsonElement epEl) ? epEl.GetString() : null;
                                    int existingPeerNatType = peerElement.TryGetProperty("natType", out JsonElement ntEl) ? ntEl.GetInt32() : -1;
                                    string existingPeerID = peerElement.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                                    string existingPeerLocalIP = peerElement.TryGetProperty("localIP", out JsonElement lipEl) ? lipEl.GetString() : null;
                                    int existingPeerLocalPort = peerElement.TryGetProperty("localPort", out JsonElement lpEl) ? lpEl.GetInt32() : 0;

                                    if (string.IsNullOrEmpty(existingPeerMeshIP))
                                    {
                                        Console.WriteLine($"[Mesh] Skipping peer with no mesh IP in OtherPeers list");
                                        continue;
                                    }

                                    // Cache existing peer's info for heartbeat repair
                                    peerInfoByMeshIP[existingPeerMeshIP] = (existingPeerID, existingPeerEndpoint, (NATType)existingPeerNatType);

                                    // Check if we have a WireGuard tunnel to this peer.
                                    // OtherPeers includes all mesh members (even ones we never connected to).
                                    // We can only send MeshConnectionBegin over WireGuard to peers we have tunnels with.
                                    if (wireguardTunnel.GetPeer(IPAddress.Parse(existingPeerMeshIP)) == null)
                                    {
                                        Console.WriteLine($"[Mesh] Skipping peer {existingPeerID} ({existingPeerMeshIP}) — no WireGuard tunnel to this peer");
                                        continue;
                                    }

                                    // Check for symmetric-to-symmetric: hole punching is infeasible
                                    // Instead, relay traffic through the introducer's WireGuard interface
                                    if (msg.NATType == NATType.Symmetric && (NATType)existingPeerNatType == NATType.Symmetric)
                                    {
                                        Console.WriteLine($"[Mesh] Both {msg.PeerID} and {existingPeerID} are symmetric NAT — setting up relay through introducer");

                                        // Enable IP forwarding on our WireGuard interface so we can relay
                                        wireguardTunnel.EnableForwarding();

                                        // Send MeshConnectionBegin with IsRelay=true to existing peer
                                        var relayToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                        {
                                            PeerID = msg.PeerID,
                                            EndpointString = msg.EndpointString,
                                            NATType = msg.NATType,
                                            PrivateAddressString = msg.PrivateAddressString,
                                            IsRelay = true,
                                            IntroducerMeshIP = meshIP  // Our mesh IP so peer knows which WG peer to route through
                                        };
                                        try
                                        {
                                            byte[] relayExBytes = Encoding.UTF8.GetBytes(relayToExisting.Serialize());
                                            meshControlClient.Send(relayExBytes, relayExBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(existingPeerMeshIP), MeshControlPort));
                                            Console.WriteLine($"[Mesh] Sent relay MeshConnectionBegin to existing peer {existingPeerMeshIP}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay to {existingPeerMeshIP}: {ex.Message}");
                                        }

                                        // Send MeshConnectionBegin with IsRelay=true to new peer (deferred if tunnel not ready)
                                        if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                                        {
                                            var relayToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                            {
                                                PeerID = existingPeerID,
                                                EndpointString = existingPeerEndpoint,
                                                NATType = (NATType)existingPeerNatType,
                                                PrivateAddressString = existingPeerMeshIP,
                                                IsRelay = true,
                                                IntroducerMeshIP = meshIP
                                            };

                                            if (completedTunnelMeshIPs.Contains(msg.PrivateAddressString))
                                            {
                                                try
                                                {
                                                    byte[] relayNewBytes = Encoding.UTF8.GetBytes(relayToNew.Serialize());
                                                    meshControlClient.Send(relayNewBytes, relayNewBytes.Length,
                                                        new IPEndPoint(IPAddress.Parse(msg.PrivateAddressString), MeshControlPort));
                                                    Console.WriteLine($"[Mesh] Sent relay MeshConnectionBegin to new peer {msg.PrivateAddressString}");
                                                }
                                                catch (Exception ex)
                                                {
                                                    Console.WriteLine($"[Mesh] Failed to send relay to {msg.PrivateAddressString}: {ex.Message}");
                                                }
                                            }
                                            else
                                            {
                                                if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                                                    deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();
                                                deferredIntroductions[msg.PrivateAddressString].Add(relayToNew);
                                                Console.WriteLine($"[Mesh] Deferred relay MeshConnectionBegin to new peer {msg.PrivateAddressString}");
                                            }
                                        }

                                        // Track this pair as relayed so heartbeat doesn't try to re-introduce them
                                        string rpA = string.Compare(existingPeerMeshIP, msg.PrivateAddressString, StringComparison.Ordinal) < 0
                                            ? existingPeerMeshIP : msg.PrivateAddressString;
                                        string rpB = rpA == existingPeerMeshIP ? msg.PrivateAddressString : existingPeerMeshIP;
                                        relayedPairs.Add($"{rpA}|{rpB}");

                                        introduced++;
                                        continue;
                                    }

                                    // Detect same-NAT peers: if both share the same public IP, use LAN endpoints
                                    // so they connect directly over the local network (NAT hairpinning is unreliable)
                                    string newPeerEndpointForExisting = msg.EndpointString;
                                    string existingPeerEndpointForNew = existingPeerEndpoint;

                                    string newPeerPublicIP = msg.EndpointString?.Split(':')[0];
                                    string existingPeerPublicIP = existingPeerEndpoint?.Split(':')[0];

                                    if (newPeerPublicIP == existingPeerPublicIP &&
                                        !string.IsNullOrEmpty(msg.LocalIP) && !string.IsNullOrEmpty(existingPeerLocalIP))
                                    {
                                        newPeerEndpointForExisting = $"{msg.LocalIP}:{msg.LocalPort}";
                                        existingPeerEndpointForNew = $"{existingPeerLocalIP}:{existingPeerLocalPort}";
                                        Console.WriteLine($"[Mesh] Same-NAT detected! Using LAN endpoints: {newPeerEndpointForExisting} <-> {existingPeerEndpointForNew}");
                                    }

                                    // Send MeshConnectionBegin to existing peer: "here's the new peer's info"
                                    var connBeginToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                    {
                                        PeerID = msg.PeerID,              // New peer's ID
                                        EndpointString = newPeerEndpointForExisting,  // New peer's endpoint (LAN if same-NAT)
                                        NATType = msg.NATType,              // New peer's NAT type
                                        PrivateAddressString = msg.PrivateAddressString   // New peer's mesh IP
                                    };

                                    try
                                    {
                                        byte[] toExistingBytes = Encoding.UTF8.GetBytes(connBeginToExisting.Serialize());
                                        meshControlClient.Send(toExistingBytes, toExistingBytes.Length,
                                            new IPEndPoint(IPAddress.Parse(existingPeerMeshIP), MeshControlPort));
                                        Console.WriteLine($"[Mesh] Sent MeshConnectionBegin to existing peer {existingPeerMeshIP} (about new peer {msg.PeerID})");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Failed to send MeshConnectionBegin to {existingPeerMeshIP}: {ex.Message}");
                                    }

                                    // Send MeshConnectionBegin to new peer: "here's the existing peer's info"
                                    // But only if we already have a WireGuard tunnel to P_new — otherwise defer
                                    if (!string.IsNullOrEmpty(msg.PrivateAddressString) && !string.IsNullOrEmpty(existingPeerEndpoint))
                                    {
                                        var connBeginToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                        {
                                            PeerID = existingPeerID,           // Existing peer's ID
                                            EndpointString = existingPeerEndpointForNew,  // Existing peer's endpoint (LAN if same-NAT)
                                            NATType = (NATType)existingPeerNatType, // Existing peer's NAT type
                                            PrivateAddressString = existingPeerMeshIP         // Existing peer's mesh IP
                                        };

                                        if (completedTunnelMeshIPs.Contains(msg.PrivateAddressString))
                                        {
                                            // Tunnel to P_new is already up — send immediately
                                            try
                                            {
                                                byte[] toNewBytes = Encoding.UTF8.GetBytes(connBeginToNew.Serialize());
                                                meshControlClient.Send(toNewBytes, toNewBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(msg.PrivateAddressString), MeshControlPort));
                                                Console.WriteLine($"[Mesh] Sent MeshConnectionBegin to new peer {msg.PrivateAddressString} (about existing peer {existingPeerMeshIP})");
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send MeshConnectionBegin to {msg.PrivateAddressString}: {ex.Message}");
                                            }
                                        }
                                        else
                                        {
                                            // Tunnel to P_new not yet established — defer until onConnectionComplete
                                            if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                                                deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();
                                            deferredIntroductions[msg.PrivateAddressString].Add(connBeginToNew);
                                            Console.WriteLine($"[Mesh] Deferred MeshConnectionBegin to new peer {msg.PrivateAddressString} (WireGuard tunnel not yet established)");
                                        }
                                    }

                                    introduced++;
                                }
                            }

                            // Acknowledge the mediation server regardless — it will clean up the pending record
                            try
                            {
                                var ack = new MediationMessage(MediationMessageType.MeshIntroduceAck)
                                {
                                    PeerID = msg.PeerID
                                };
                                byte[] ackBuffer = Encoding.ASCII.GetBytes(ack.Serialize());
                                stream.Write(ackBuffer, 0, ackBuffer.Length);
                                stream.Flush();
                                Console.WriteLine($"[Mesh] Sent MeshIntroduceAck for {msg.PeerID} ({introduced} peer pair(s) connected)");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Mesh] MeshIntroduceAck write failed, connection lost: {ex.Message}");
                                tcpClient.Close();
                                break;
                            }
                        }

                        // Move past this JSON object
                        jsonStartIndex = jsonObjEnd + 1;
                    } // End while loop for parsing multiple JSON objects

                    // Clear consumed data from the buffer.
                    // If the incomplete-JSON branch set tcpBuffer to the remainder, it's already correct.
                    // Otherwise, clear everything up to jsonStartIndex.
                    if (jsonStartIndex >= tcpBuffer.Length)
                        tcpBuffer = "";
                    else if (jsonStartIndex > 0)
                        tcpBuffer = tcpBuffer.Substring(jsonStartIndex);
                }

                System.Threading.Thread.Sleep(100);
            }

            // ── Mesh-control-only loop ──────────────────────────────────────────────────────
            // Non-introducer peers reach here after disconnecting from the mediation server.
            // They are fully self-sufficient: all new connections are coordinated by the
            // introducer over WireGuard (MeshConnectionBegin messages on port 51888).
            // If all WireGuard peers are lost, reconnect to the mediation server.
            Console.WriteLine("[Mesh] Entering mesh-control-only mode (fully disconnected from mediation server)");

            // Relay health check: periodically verify relay gateway peers are still alive.
            // If a relay gateway's WireGuard peer has had no activity for this duration,
            // clean up stale relay routes locally.
            const int RelayHealthCheckIntervalMs = 10000; // Check every 10 seconds
            const int RelayGatewayTimeoutSeconds = 120;   // Gateway considered dead after 2 minutes of inactivity
            var lastRelayHealthCheck = DateTime.UtcNow;

            // Isolation detection: if all WireGuard peers are dead, reconnect to mediation.
            var lastIsolationCheck = DateTime.UtcNow;
            var isolationCheckInterval = TimeSpan.FromSeconds(30);
            DateTime? isolationDetectedAt = null;
            const int IsolationGracePeriodSeconds = 60; // Wait before reconnecting to avoid thrashing
            TcpClient reconnectedTcpClient = null;
            NetworkStream reconnectedStream = null;
            DateTime? lastReconnectDiscovery = null;
            var reconnectDiscoveryInterval = TimeSpan.FromSeconds(15);

            // Introducer failover: detect when the introducer's WireGuard tunnel is dead
            // and reconnect to mediation to become the new introducer.
            // Only non-symmetric peers are eligible to take over.
            var lastIntroducerCheck = DateTime.UtcNow;
            var introducerCheckInterval = TimeSpan.FromSeconds(30);
            DateTime? introducerDeadDetectedAt = null;
            const int IntroducerDeadGracePeriodSeconds = 90; // Wait before assuming introducer is truly dead

            while (true)
            {
                // Process MeshConnectionBegin messages (introducer-relayed, no mediation server needed)
                while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
                {
                    ProcessMeshConnectionBegin(cbMsg);
                }

                // If we have a reconnected TCP connection, process incoming messages
                if (reconnectedTcpClient != null && reconnectedTcpClient.Connected)
                {
                    try
                    {
                        var reconnectedStreamLocal = reconnectedStream;
                        if (reconnectedStreamLocal.DataAvailable)
                        {
                            int bytesRead = reconnectedStreamLocal.Read(buffer, 0, buffer.Length);
                            if (bytesRead > 0)
                            {
                                string data = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                // Parse JSON messages from the reconnected TCP stream
                                var (parsedMsg, remainder) = ExtractFirstJson(data);
                                while (parsedMsg != null)
                                {
                                    if (parsedMsg.ID == MediationMessageType.MeshJoinResponse ||
                                        parsedMsg.ID == MediationMessageType.MeshPeerList)
                                    {
                                        if (parsedMsg.Peers != null && parsedMsg.Peers.Length > 0)
                                        {
                                            Console.WriteLine($"[Mesh] Reconnect discovery: found {parsedMsg.Peers.Length} peer(s)");
                                            ProcessDiscoveredPeers(parsedMsg.Peers);
                                        }
                                    }
                                    else if (parsedMsg.ID == MediationMessageType.ConnectionBegin)
                                    {
                                        Console.WriteLine($"[Mesh] Reconnect: received ConnectionBegin for connection {parsedMsg.ConnectionID}");
                                        // Store peer's mesh IP
                                        if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                            peerMeshIPs[parsedMsg.ConnectionID] = parsedMsg.PrivateAddressString;

                                        if (!activeConnectionTunnels.ContainsKey(parsedMsg.ConnectionID))
                                        {
                                            pendingTunnelCount++;
                                            var capturedConnID = parsedMsg.ConnectionID;
                                            var capturedPeerIDStr = parsedMsg.PeerID;
                                            var capturedMeshIPStr = parsedMsg.PrivateAddressString;
                                            var reconnectTunnel = new Tunnel(
                                                onConnectionFailure: () =>
                                                {
                                                    lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(capturedConnID); }
                                                    if (!string.IsNullOrEmpty(capturedPeerIDStr)) activePeerTunnels.Remove(capturedPeerIDStr);
                                                    if (!string.IsNullOrEmpty(capturedMeshIPStr)) activePeerTunnels.Remove(capturedMeshIPStr);
                                                    pendingTunnelCount--;
                                                },
                                                sharedUdpClient: udpClient,
                                                meshPeerEndpoint: parsedMsg.EndpointString,
                                                retryInPlace: true,
                                                sharedClientID: peerID,
                                                ownMeshIP: meshIP,
                                                onConnectionComplete: () =>
                                                {
                                                    Console.WriteLine($"[Mesh] Reconnect tunnel {capturedConnID} WireGuard established");
                                                    pendingTunnelCount--;
                                                    if (peerMeshIPs.TryGetValue(capturedConnID, out string cMeshIP) && !string.IsNullOrEmpty(cMeshIP))
                                                        completedTunnelMeshIPs.Add(cMeshIP);
                                                }
                                            );
                                            reconnectTunnel.SetWireGuardTunnel(wireguardTunnel);
                                            lock (activeConnectionTunnels) { activeConnectionTunnels[capturedConnID] = reconnectTunnel; }
                                            if (!string.IsNullOrEmpty(capturedPeerIDStr))
                                            {
                                                pendingConnectionRequests.Remove(capturedPeerIDStr);
                                                activePeerTunnels[capturedPeerIDStr] = reconnectTunnel;
                                            }
                                            if (!string.IsNullOrEmpty(capturedMeshIPStr))
                                                activePeerTunnels[capturedMeshIPStr] = reconnectTunnel;
                                            System.Threading.Tasks.Task.Run(() =>
                                            {
                                                try { reconnectTunnel.Start(); }
                                                catch (Exception ex)
                                                {
                                                    Console.WriteLine($"[Mesh] Reconnect tunnel error: {ex.Message}");
                                                    pendingTunnelCount--;
                                                }
                                            });
                                        }
                                    }
                                    else if (parsedMsg.ID == MediationMessageType.MeshIntroduceRequest)
                                    {
                                        isIntroducer = true;
                                        Console.WriteLine($"[Mesh] Reconnect: selected as introducer for {parsedMsg.PeerID}");

                                        // Cache the new peer's info for heartbeat repair
                                        if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                        {
                                            peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, parsedMsg.EndpointString, parsedMsg.NATType);
                                        }

                                        // Forward introductions to existing peers over WireGuard
                                        if (parsedMsg.OtherPeers != null)
                                        {
                                            foreach (var peerObj in parsedMsg.OtherPeers)
                                            {
                                                var pe = JsonSerializer.Deserialize<JsonElement>(peerObj.ToString());
                                                string exMeshIP = pe.TryGetProperty("meshIP", out JsonElement mip2) ? mip2.GetString() : null;
                                                string exEndpoint = pe.TryGetProperty("endpoint", out JsonElement epEl2) ? epEl2.GetString() : null;
                                                int exNatType = pe.TryGetProperty("natType", out JsonElement ntEl2) ? ntEl2.GetInt32() : -1;
                                                string exPeerID = pe.TryGetProperty("peerID", out JsonElement pidEl2) ? pidEl2.GetString() : null;

                                                if (string.IsNullOrEmpty(exMeshIP)) continue;

                                                peerInfoByMeshIP[exMeshIP] = (exPeerID, exEndpoint, (NATType)exNatType);

                                                if (wireguardTunnel.GetPeer(IPAddress.Parse(exMeshIP)) == null)
                                                {
                                                    Console.WriteLine($"[Mesh] Reconnect introducer: no WG tunnel to {exMeshIP} — skipping");
                                                    continue;
                                                }

                                                // Send MeshConnectionBegin to existing peer about the new peer
                                                var cbToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                {
                                                    PeerID = parsedMsg.PeerID,
                                                    EndpointString = parsedMsg.EndpointString,
                                                    NATType = parsedMsg.NATType,
                                                    PrivateAddressString = parsedMsg.PrivateAddressString
                                                };
                                                try
                                                {
                                                    byte[] cbBytes = Encoding.UTF8.GetBytes(cbToExisting.Serialize());
                                                    meshControlClient.Send(cbBytes, cbBytes.Length,
                                                        new IPEndPoint(IPAddress.Parse(exMeshIP), MeshControlPort));
                                                    Console.WriteLine($"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {exMeshIP} about {parsedMsg.PeerID}");
                                                }
                                                catch (Exception ex2)
                                                {
                                                    Console.WriteLine($"[Mesh] Failed to send MeshConnectionBegin to {exMeshIP}: {ex2.Message}");
                                                }

                                                // Send MeshConnectionBegin to new peer about existing peer (if tunnel ready)
                                                if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString) && !string.IsNullOrEmpty(exEndpoint))
                                                {
                                                    var cbToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                    {
                                                        PeerID = exPeerID,
                                                        EndpointString = exEndpoint,
                                                        NATType = (NATType)exNatType,
                                                        PrivateAddressString = exMeshIP
                                                    };

                                                    if (completedTunnelMeshIPs.Contains(parsedMsg.PrivateAddressString))
                                                    {
                                                        try
                                                        {
                                                            byte[] cbNewBytes = Encoding.UTF8.GetBytes(cbToNew.Serialize());
                                                            meshControlClient.Send(cbNewBytes, cbNewBytes.Length,
                                                                new IPEndPoint(IPAddress.Parse(parsedMsg.PrivateAddressString), MeshControlPort));
                                                            Console.WriteLine($"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
                                                        }
                                                        catch (Exception ex2)
                                                        {
                                                            Console.WriteLine($"[Mesh] Failed to send MeshConnectionBegin to {parsedMsg.PrivateAddressString}: {ex2.Message}");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (!deferredIntroductions.ContainsKey(parsedMsg.PrivateAddressString))
                                                            deferredIntroductions[parsedMsg.PrivateAddressString] = new List<MediationMessage>();
                                                        deferredIntroductions[parsedMsg.PrivateAddressString].Add(cbToNew);
                                                        Console.WriteLine($"[Mesh] Reconnect introducer: deferred MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    (parsedMsg, remainder) = ExtractFirstJson(remainder);
                                }
                            }
                        }

                        // Periodic keep-alive on reconnected connection
                        if (lastReconnectDiscovery != null &&
                            DateTime.UtcNow - lastReconnectDiscovery.Value > reconnectDiscoveryInterval)
                        {
                            // Send keep-alive
                            var ka = new MediationMessage(MediationMessageType.KeepAlive);
                            byte[] kaBytes = Encoding.ASCII.GetBytes(ka.Serialize());
                            reconnectedStreamLocal.Write(kaBytes, 0, kaBytes.Length);

                            // Re-send discovery if still isolated
                            var wgPeers = wireguardTunnel.GetAllPeers();
                            bool stillIsolated = !wgPeers.Any(p =>
                                (DateTime.UtcNow - p.LastActivity).TotalSeconds < RelayGatewayTimeoutSeconds);
                            if (stillIsolated && pendingTunnelCount == 0 && pendingConnectionRequests.Count == 0)
                            {
                                var rediscovery = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                {
                                    NetworkID = TunnelOptions.NetworkID,
                                    PeerID = peerID.ToString(),
                                    NATType = detectedNatType,
                                    PrivateAddressString = meshIP
                                };
                                byte[] rdBytes = Encoding.ASCII.GetBytes(rediscovery.Serialize());
                                reconnectedStreamLocal.Write(rdBytes, 0, rdBytes.Length);
                                Console.WriteLine("[Mesh] Re-sent discovery request on reconnected connection");
                            }
                            else if (!stillIsolated)
                            {
                                // Peers recovered — close reconnected connection
                                Console.WriteLine("[Mesh] Peers recovered — closing reconnected mediation connection");
                                reconnectedTcpClient.Close();
                                reconnectedTcpClient = null;
                                reconnectedStream = null;
                                isolationDetectedAt = null;
                            }
                            lastReconnectDiscovery = DateTime.UtcNow;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Reconnected TCP error: {ex.Message}");
                        reconnectedTcpClient = null;
                        reconnectedStream = null;
                    }
                }

                // Isolation detection: reconnect to mediation if all WireGuard peers are dead
                if (reconnectedTcpClient == null &&
                    DateTime.UtcNow - lastIsolationCheck > isolationCheckInterval)
                {
                    lastIsolationCheck = DateTime.UtcNow;

                    var allWgPeers = wireguardTunnel.GetAllPeers();
                    bool hasActivePeers = allWgPeers.Any(p =>
                        (DateTime.UtcNow - p.LastActivity).TotalSeconds < RelayGatewayTimeoutSeconds);

                    if (!hasActivePeers && pendingTunnelCount == 0)
                    {
                        if (isolationDetectedAt == null)
                        {
                            isolationDetectedAt = DateTime.UtcNow;
                            Console.WriteLine($"[Mesh] Isolation detected — no active WireGuard peers. Will reconnect in {IsolationGracePeriodSeconds}s if not resolved.");
                        }
                        else if ((DateTime.UtcNow - isolationDetectedAt.Value).TotalSeconds >= IsolationGracePeriodSeconds)
                        {
                            Console.WriteLine("[Mesh] Isolation persisted — reconnecting to mediation server for peer discovery");
                            try
                            {
                                var mediationEP = TunnelOptions.MediationEndpoint;
                                reconnectedTcpClient = new TcpClient();
                                reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                                reconnectedTcpClient.Connect(mediationEP);
                                reconnectedStream = reconnectedTcpClient.GetStream();

                                // Wait for Connected message
                                byte[] connBuf = new byte[4096];
                                reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                // Send NAT type request (reuse known NAT type)
                                var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                                {
                                    LocalPort = localUdpPort,
                                    LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                                    ClientID = peerID
                                };
                                byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                                reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                                // Read NAT responses (NATTestBegin, send test packets, NATTypeResponse)
                                // For simplicity, just drain responses until we can send MeshJoinRequest
                                System.Threading.Thread.Sleep(1000);
                                while (reconnectedStream.DataAvailable)
                                    reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                // Send UDP packets for NAT detection
                                var natTestMsg = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                                byte[] natTestBuf = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
                                udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, 6511));
                                udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, 6512));

                                System.Threading.Thread.Sleep(1000);
                                while (reconnectedStream.DataAvailable)
                                    reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                // Send MeshJoinRequest for peer discovery
                                var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                {
                                    NetworkID = TunnelOptions.NetworkID,
                                    PeerID = peerID.ToString(),
                                    NATType = detectedNatType,
                                    PrivateAddressString = meshIP
                                };
                                byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                                reconnectedStream.Write(joinBytes, 0, joinBytes.Length);
                                reconnectedStream.Flush();

                                lastReconnectDiscovery = DateTime.UtcNow;
                                Console.WriteLine("[Mesh] Reconnected to mediation server — sent discovery request");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Mesh] Failed to reconnect to mediation: {ex.Message}");
                                reconnectedTcpClient = null;
                                reconnectedStream = null;
                                isolationDetectedAt = null; // Reset to retry later
                            }
                        }
                    }
                    else
                    {
                        if (isolationDetectedAt != null)
                        {
                            Console.WriteLine("[Mesh] Isolation resolved — active peers detected");
                            isolationDetectedAt = null;
                        }
                    }
                }

                // Relay health check: detect dead relay gateways and clean up stale routes
                if ((DateTime.UtcNow - lastRelayHealthCheck).TotalMilliseconds >= RelayHealthCheckIntervalMs)
                {
                    lastRelayHealthCheck = DateTime.UtcNow;
                    var relayRoutes = wireguardTunnel.GetRelayRoutes();

                    if (relayRoutes.Count > 0)
                    {
                        // Check each relay gateway's last activity
                        var deadGateways = new HashSet<IPAddress>();
                        foreach (var gatewayIP in relayRoutes.Values.Distinct().ToList())
                        {
                            var gatewayPeer = wireguardTunnel.GetPeer(gatewayIP);
                            if (gatewayPeer == null ||
                                (DateTime.UtcNow - gatewayPeer.LastActivity).TotalSeconds > RelayGatewayTimeoutSeconds)
                            {
                                deadGateways.Add(gatewayIP);
                            }
                        }

                        if (deadGateways.Count > 0)
                        {
                            Console.WriteLine($"[Mesh] Relay gateway(s) dead: {string.Join(", ", deadGateways)} — cleaning up stale routes");

                            foreach (var deadGateway in deadGateways)
                            {
                                var removedRoutes = wireguardTunnel.RemoveRelayRoutesViaGateway(deadGateway);
                                Console.WriteLine($"[Mesh] Removed {removedRoutes.Count} relay route(s) via {deadGateway}");
                            }
                            // New relay assignments will come from the introducer via MeshConnectionBegin
                        }
                    }
                }

                // ── Introducer failover ────────────────────────────────────────────
                // If we're non-symmetric and the introducer's WireGuard tunnel is dead,
                // reconnect to mediation to become the new introducer. Without this,
                // no one can coordinate connections for newly joining peers.
                if (!isIntroducer && reconnectedTcpClient == null &&
                    detectedNatType != NATType.Symmetric &&
                    !string.IsNullOrEmpty(introducerMeshIP) &&
                    DateTime.UtcNow - lastIntroducerCheck > introducerCheckInterval)
                {
                    lastIntroducerCheck = DateTime.UtcNow;

                    var introducerPeer = wireguardTunnel.GetPeer(IPAddress.Parse(introducerMeshIP));
                    bool introducerAlive = introducerPeer != null &&
                        (DateTime.UtcNow - introducerPeer.LastActivity).TotalSeconds < RelayGatewayTimeoutSeconds;

                    if (!introducerAlive)
                    {
                        if (introducerDeadDetectedAt == null)
                        {
                            introducerDeadDetectedAt = DateTime.UtcNow;
                            Console.WriteLine($"[Mesh] Introducer ({introducerMeshIP}) appears dead. Will take over in {IntroducerDeadGracePeriodSeconds}s if not resolved.");
                        }
                        else if ((DateTime.UtcNow - introducerDeadDetectedAt.Value).TotalSeconds >= IntroducerDeadGracePeriodSeconds)
                        {
                            Console.WriteLine("[Mesh] Introducer confirmed dead — reconnecting to mediation to take over introducer role");
                            try
                            {
                                var mediationEP = TunnelOptions.MediationEndpoint;
                                reconnectedTcpClient = new TcpClient();
                                reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                                reconnectedTcpClient.Connect(mediationEP);
                                reconnectedStream = reconnectedTcpClient.GetStream();

                                // Wait for Connected message
                                byte[] connBuf = new byte[4096];
                                reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                // NAT type detection handshake
                                var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                                {
                                    LocalPort = localUdpPort,
                                    LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                                    ClientID = peerID
                                };
                                byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                                reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                                System.Threading.Thread.Sleep(1000);
                                while (reconnectedStream.DataAvailable)
                                    reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                var natTestMsg2 = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                                byte[] natTestBuf2 = Encoding.ASCII.GetBytes(natTestMsg2.Serialize());
                                udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, 6511));
                                udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, 6512));

                                System.Threading.Thread.Sleep(1000);
                                while (reconnectedStream.DataAvailable)
                                    reconnectedStream.Read(connBuf, 0, connBuf.Length);

                                // Send MeshJoinRequest — the server will select us as the new introducer
                                // (since the old one disconnected and we're non-symmetric)
                                var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                {
                                    NetworkID = TunnelOptions.NetworkID,
                                    PeerID = peerID.ToString(),
                                    NATType = detectedNatType,
                                    PrivateAddressString = meshIP
                                };
                                byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                                reconnectedStream.Write(joinBytes, 0, joinBytes.Length);
                                reconnectedStream.Flush();

                                lastReconnectDiscovery = DateTime.UtcNow;
                                isIntroducer = true; // We're taking over
                                introducerDeadDetectedAt = null;
                                Console.WriteLine("[Mesh] Reconnected to mediation as new introducer — sent join request");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Mesh] Failed to reconnect for introducer takeover: {ex.Message}");
                                reconnectedTcpClient = null;
                                reconnectedStream = null;
                                introducerDeadDetectedAt = null; // Reset to retry later
                            }
                        }
                    }
                    else
                    {
                        if (introducerDeadDetectedAt != null)
                        {
                            Console.WriteLine("[Mesh] Introducer recovered — cancelling failover");
                            introducerDeadDetectedAt = null;
                        }
                    }
                }

                System.Threading.Thread.Sleep(100);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mesh] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            throw;
        }
    }

}