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
            // Check if running as WireGuard service
            // Per WireGuard spec: program /service <config_path> [server|client]
            if (args.Length >= 2 && args[0] == "/service")
            {
                string configPath = args[1];
                string mode = args.Length >= 3 ? args[2] : null; // Optional mode argument
                RunServiceMode(configPath, mode);
                return;
            }

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

            // Check if mesh networking is enabled
            if (!string.IsNullOrEmpty(TunnelOptions.NetworkID))
            {
                Console.WriteLine($"Starting in MESH mode for network: {TunnelOptions.NetworkID}");
                RunMeshMode();
            }
            else
            {
                // Start tunnel with WireGuard based on config (traditional client/server mode)
                string interfaceName = "NATTunnel";
                bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";

                // Pass isRunningAsService = false so it will try to install the service
                using (var tunnel = new WireGuardTunnel(TunnelOptions.IsServer, interfaceName, debugMode, isRunningAsService: false))
                {
                    Console.WriteLine("Tunnel is running...");

                    // Keep the tunnel running indefinitely
                    // The tunnel will be cleaned up by the using statement when the process exits (e.g., via Stop-Service)
                    while (true)
                    {
                        System.Threading.Thread.Sleep(1000);
                    }
                }
            }
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
                Console.WriteLine($"[Mesh] Loaded persistent peer ID: {peerID}");
            }
            else
            {
                peerID = Guid.NewGuid();
                TunnelOptions.PeerID = peerID;
                Config.SavePeerID(peerID);
                Console.WriteLine($"[Mesh] Generated new peer ID: {peerID} (saved to config)");
            }
            Console.WriteLine($"[Mesh] Network: {TunnelOptions.NetworkID}");

            // For mesh mode, we DON'T initialize WireGuard tunnel yet
            // We'll create it after we know our mesh IP address and have peer information
            // This avoids the port conflict and allows proper mesh configuration

            // Create UDP client for NAT traversal (shared across all peer connections)
            Console.WriteLine("[Mesh] Creating UDP client for NAT traversal...");
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
            Console.WriteLine($"[Mesh] UDP client bound to local port: {localUdpPort}");

            // Connect to mediation server for NAT type detection
            var endpoint = TunnelOptions.MediationEndpoint;
            Console.WriteLine($"[Mesh] Connecting to mediation server at {endpoint}...");

            var tcpClient = new TcpClient();
            tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            tcpClient.Connect(endpoint);
            var stream = tcpClient.GetStream();

            Console.WriteLine("[Mesh] Connected to mediation server");

            // Wait for Connected message
            byte[] buffer = new byte[8192];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            Console.WriteLine($"[Mesh] Received: {response}");

            // Request NAT type detection
            Console.WriteLine("[Mesh] Requesting NAT type detection...");
            var natTypeRequest = new MediationMessage(MediationMessageType.NATTypeRequest)
            {
                LocalPort = localUdpPort,
                ClientID = peerID
            };

            string natRequestJson = natTypeRequest.Serialize();
            byte[] natBuffer = Encoding.ASCII.GetBytes(natRequestJson);
            stream.Write(natBuffer, 0, natBuffer.Length);

            // Wait for NAT test begin
            bytesRead = stream.Read(buffer, 0, buffer.Length);
            response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            var natTestBegin = JsonSerializer.Deserialize<MediationMessage>(response);

            if (natTestBegin.ID == MediationMessageType.NATTestBegin)
            {
                Console.WriteLine($"[Mesh] NAT test started (ports: {natTestBegin.NATTestPortOne}, {natTestBegin.NATTestPortTwo})");

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
            bytesRead = stream.Read(buffer, 0, buffer.Length);
            response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            var natTypeResponse = JsonSerializer.Deserialize<MediationMessage>(response);

            NATType detectedNatType = NATType.Unknown;
            if (natTypeResponse.ID == MediationMessageType.NATTypeResponse)
            {
                detectedNatType = natTypeResponse.NATType;
                Console.WriteLine($"[Mesh] ✓ NAT type detected: {detectedNatType}");
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
            Console.WriteLine($"[Mesh] Sent KeepAlive before WireGuard initialization");

            // Initialize WireGuard tunnel for mesh mode
            string interfaceName = $"NATTunnel-{TunnelOptions.NetworkID}";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";
            var wireguardTunnel = new WireGuardTunnel(isServer: false, interfaceName, debugMode, isRunningAsService: false, skipTunnelCreation: true);

            // Set client IP for mesh mode with /16 netmask (covers 10.5.0.0 - 10.5.255.255 for all mesh peers)
            wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
            Console.WriteLine($"[Mesh] ✓ WireGuard tunnel initialized with IP {meshIP}/16");

            // Initialize UDP proxy for mesh mode
            // The proxy will forward WireGuard traffic between the NAT-traversed peer connections and local WireGuard interface
            var udpProxy = new WireGuardUdpProxy(udpClient);
            wireguardTunnel.SetUdpProxy(udpProxy);
            Console.WriteLine($"[Mesh] ✓ UDP proxy initialized for WireGuard traffic forwarding");

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
                Console.WriteLine($"[Mesh] Listening for mesh control messages on UDP port {MeshControlPort}");
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
                            Console.WriteLine($"[Mesh] Responded to heartbeat from {result.RemoteEndPoint} with {connectedIPs.Length} connected peer(s)");
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeatAck)
                        {
                            meshHeartbeatAckQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshIntroduction)
                        {
                            // MeshIntroduction is no longer used — the introducer sends MeshConnectionBegin instead
                            Console.WriteLine($"[Mesh] Received legacy MeshIntroduction from {result.RemoteEndPoint} — ignoring (use MeshConnectionBegin)");
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
            bytesRead = stream.Read(buffer, 0, buffer.Length);
            response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            var joinResponse = JsonSerializer.Deserialize<MediationMessage>(response);
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
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (self - skipping)");
                        continue;
                    }

                    // Skip if we've already requested connection or have an active tunnel to this peer
                    // Check both by PeerID and by mesh IP
                    if (activePeerTunnels.ContainsKey(targetPeerID) || (peerMeshIP != null && activePeerTunnels.ContainsKey(peerMeshIP)))
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (tunnel active)");
                        continue;
                    }

                    if (pendingConnectionRequests.Contains(targetPeerID))
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (connection pending)");
                        continue;
                    }

                    // Skip symmetric-to-symmetric: hole punching is infeasible.
                    // The introducer will handle this pair via relay MeshConnectionBegin.
                    if (detectedNatType == NATType.Symmetric && (NATType)peerNatTypeInt == NATType.Symmetric)
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (symmetric-to-symmetric — waiting for introducer relay)");
                        continue;
                    }

                    Console.WriteLine($"  - Peer {targetPeerID}");

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

                    Console.WriteLine($"[Mesh] Sent connection request for peer {targetPeerID}");

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
                    onConnectionFailure: () => {
                        Console.WriteLine($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} failed — cleaning up for future retry");
                        lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(capturedPeerID.GetHashCode()); }
                        pendingConnectionRequests.Remove(capturedPeerID);
                        activePeerTunnels.Remove(capturedPeerID);
                        if (!string.IsNullOrEmpty(capturedMeshIP))
                            activePeerTunnels.Remove(capturedMeshIP);
                        pendingTunnelCount--;
                    },
                    managedByTunnelManager: false,
                    connectionId: capturedPeerID.GetHashCode(),  // Use hash of PeerID as connection ID
                    sharedUdpClient: udpClient,
                    meshPeerMode: true,
                    meshPeerEndpoint: remoteEndpoint,
                    retryInPlace: true,
                    isServerOverride: false,
                    sharedClientID: peerID,
                    skipTcpConnection: true,  // No TCP to mediation — introducer relays
                    ownMeshIP: meshIP,
                    onConnectionComplete: () => {
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

            // Set to true the moment we receive a MeshIntroduceRequest — we are the designated
            // introducer and must keep the mediation TCP connection alive indefinitely so the
            // server can push future MeshIntroduceRequests to us.
            bool isIntroducer = false;

            // Set up periodic keep-alive
            var lastKeepAlive = DateTime.UtcNow;
            var keepAliveInterval = TimeSpan.FromSeconds(5);

            // Grace period: once all initial connections are established, wait before
            // disconnecting to give disconnected peers time to TransientReconnect.
            DateTime? disconnectAfter = null;
            bool hasPeers = joinResponse.Peers != null && joinResponse.Peers.Length > 0;

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
            string tcpBuffer = "";

            // ── Shared UDP dispatcher ─────────────────────────────────────────────────
            // All mesh Tunnel instances share the same udpClient socket. Only ONE receive
            // loop must run on it; each received packet is dispatched to ALL active tunnels
            // via ProcessUdpPacket(). Without this, multiple UdpClientListenLoop() calls
            // on the same socket race for packets and most tunnels miss most messages.
            System.Threading.Tasks.Task.Run(() =>
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                Console.WriteLine("[Mesh] ✓ Shared UDP dispatcher started");
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
                    bool readyToDisconnect = noPendingWork && hasEstablishedTunnels;

                    if (readyToDisconnect && disconnectAfter == null)
                    {
                        disconnectAfter = DateTime.UtcNow.AddSeconds(5);
                        Console.WriteLine("[Mesh] All initial connections established — grace period started (5s)");
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
                        Console.WriteLine("[Mesh] ⚠ Mediation server connection lost — introducer role ended");
                    else
                        Console.WriteLine("[Mesh] ⚠ TCP connection to mediation server lost during setup");
                    break;
                }

                // Send periodic keep-alive to prevent timeout during setup
                if (DateTime.UtcNow - lastKeepAlive > keepAliveInterval)
                {
                    var keepAliveMsg = new MediationMessage(MediationMessageType.KeepAlive);
                    string keepAliveJson = keepAliveMsg.Serialize();
                    byte[] keepAliveBuffer = Encoding.ASCII.GetBytes(keepAliveJson);
                    stream.Write(keepAliveBuffer, 0, keepAliveBuffer.Length);
                    lastKeepAlive = DateTime.UtcNow;
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

                                if (!aReportsB && !bReportsA)
                                {
                                    // Neither peer sees the other — look up their cached info and re-introduce
                                    Console.WriteLine($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected — re-introducing");

                                    peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                                    peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

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

                        if (repairCount > 0)
                            Console.WriteLine($"[Mesh] Heartbeat: sent {repairCount} repair MeshConnectionBegin message(s)");

                        heartbeatAckDeadline = null;
                        lastHeartbeat = DateTime.UtcNow;
                    }
                }

                if (stream.DataAvailable)
                {
                    bytesRead = stream.Read(buffer, 0, buffer.Length);

                    // Check if connection closed
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("[Mesh] ⚠ Mediation server closed connection");
                        break;
                    }

                    // Append new data to the reassembly buffer (handles TCP fragmentation)
                    tcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);

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
                            Console.WriteLine($"[Mesh]   ConnectionID: {msg.ConnectionID}");
                            Console.WriteLine($"[Mesh]   Endpoint: {msg.EndpointString}");
                            Console.WriteLine($"[Mesh]   NATType: {msg.NATType}");
                            Console.WriteLine($"[Mesh]   IsServer: {msg.IsServer}");

                            // Store peer's mesh IP for later use in WireGuard key exchange
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerMeshIPs[msg.ConnectionID] = msg.PrivateAddressString;
                                Console.WriteLine($"[Mesh]   Peer mesh IP: {msg.PrivateAddressString}");
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
                                    onConnectionFailure: () => {
                                        Console.WriteLine($"[Mesh] Tunnel {capturedConnectionID} failed permanently after all retries — cleaning up for future retry");
                                        lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(capturedConnectionID); }
                                        if (!string.IsNullOrEmpty(capturedPeerIDForCleanup))
                                            activePeerTunnels.Remove(capturedPeerIDForCleanup);
                                        if (!string.IsNullOrEmpty(capturedMeshIPForCleanup))
                                            activePeerTunnels.Remove(capturedMeshIPForCleanup);
                                        pendingTunnelCount--;
                                    },
                                    managedByTunnelManager: false,
                                    connectionId: msg.ConnectionID,
                                    sharedUdpClient: udpClient,  // Share UDP client with mesh mode (same port)
                                    meshPeerMode: true,  // This is a mesh peer-to-peer connection
                                    meshPeerEndpoint: msg.EndpointString,  // Remote peer endpoint
                                    retryInPlace: true,  // Retry in-place like server, don't recreate tunnel
                                    isServerOverride: false,  // Mesh tunnels always act as clients (both peers are equal)
                                    sharedClientID: peerID,  // Share clientID with mesh mode so server routes messages correctly
                                    skipTcpConnection: false,  // Peer tunnels create their own TCP connection
                                    ownMeshIP: meshIP,  // Pass our mesh IP so tunnel can send it in WireGuard key exchange
                                    onConnectionComplete: () => {
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

                                Console.WriteLine($"[Mesh] Created tunnel for peer connection {msg.ConnectionID}");
                                Console.WriteLine($"[Mesh] Peer endpoint: {msg.EndpointString}, Peer NAT: {msg.NATType}, Our NAT: {detectedNatType}");

                                // Start the tunnel asynchronously.
                                // pendingTunnelCount is decremented by onConnectionComplete (success)
                                // or onConnectionFailure (failure) — NOT here — so the mediation
                                // disconnect only happens after WireGuard setup is fully done.
                                System.Threading.Tasks.Task.Run(() =>
                                {
                                    try
                                    {
                                        peerTunnel.Start();
                                        Console.WriteLine($"[Mesh] Tunnel {capturedConnectionID} connected and hole-punching started");
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
                            // Update hasPeers flag
                            if (msg.Peers != null && msg.Peers.Length > 0)
                            {
                                hasPeers = true;
                                ProcessDiscoveredPeers(msg.Peers);
                            }
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
                                            PeerID               = msg.PeerID,
                                            EndpointString       = msg.EndpointString,
                                            NATType              = msg.NATType,
                                            PrivateAddressString = msg.PrivateAddressString,
                                            IsRelay              = true,
                                            IntroducerMeshIP     = meshIP  // Our mesh IP so peer knows which WG peer to route through
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
                                                PeerID               = existingPeerID,
                                                EndpointString       = existingPeerEndpoint,
                                                NATType              = (NATType)existingPeerNatType,
                                                PrivateAddressString = existingPeerMeshIP,
                                                IsRelay              = true,
                                                IntroducerMeshIP     = meshIP
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

                                        introduced++;
                                        continue;
                                    }

                                    // Send MeshConnectionBegin to existing peer: "here's the new peer's info"
                                    var connBeginToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                    {
                                        PeerID               = msg.PeerID,              // New peer's ID
                                        EndpointString       = msg.EndpointString,       // New peer's external endpoint
                                        NATType              = msg.NATType,              // New peer's NAT type
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
                                            PeerID               = existingPeerID,           // Existing peer's ID
                                            EndpointString       = existingPeerEndpoint,     // Existing peer's external endpoint
                                            NATType              = (NATType)existingPeerNatType, // Existing peer's NAT type
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
                            var ack = new MediationMessage(MediationMessageType.MeshIntroduceAck)
                            {
                                PeerID = msg.PeerID
                            };
                            byte[] ackBuffer = Encoding.ASCII.GetBytes(ack.Serialize());
                            stream.Write(ackBuffer, 0, ackBuffer.Length);
                            stream.Flush();
                            Console.WriteLine($"[Mesh] Sent MeshIntroduceAck for {msg.PeerID} ({introduced} peer pair(s) connected)");
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
            // No mediation server reconnections are needed.
            Console.WriteLine("[Mesh] Entering mesh-control-only mode (fully disconnected from mediation server)");

            // Relay health check: periodically verify relay gateway peers are still alive.
            // If a relay gateway's WireGuard peer has had no activity for this duration,
            // clean up stale relay routes locally.
            const int RelayHealthCheckIntervalMs = 10000; // Check every 10 seconds
            const int RelayGatewayTimeoutSeconds = 120;   // Gateway considered dead after 2 minutes of inactivity
            var lastRelayHealthCheck = DateTime.UtcNow;

            while (true)
            {
                // Process MeshConnectionBegin messages (introducer-relayed, no mediation server needed)
                while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
                {
                    ProcessMeshConnectionBegin(cbMsg);
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

    /// <summary>
    /// Runs the application in Windows service mode with the specified config path.
    /// This is called when Windows Service Manager starts the service with: program.exe /service "path\to\config.conf" [server|client]
    /// Per WireGuard spec, this should be minimal - just initialize and run the tunnel.
    /// </summary>
    private static void RunServiceMode(string configPath, string mode)
    {
        try
        {
            // Validate config path
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException($"Configuration file not found: {configPath}");
            }

            // Determine server/client mode
            bool isServer;
            if (!string.IsNullOrEmpty(mode))
            {
                // Use the mode passed as argument (most reliable)
                isServer = mode.Equals("server", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                // Fallback: read from config file if no mode argument provided
                string configContent = File.ReadAllText(configPath);
                isServer = configContent.Contains("mode") && configContent.Contains("\"server\"");
            }

            string interfaceName = "NATTunnel";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";

            // Create tunnel with isRunningAsService = true to skip service installation
            using (var tunnel = new WireGuardTunnel(isServer, interfaceName, debugMode, isRunningAsService: true))
            {
                // Service mode: Keep running indefinitely until stopped by Windows Service Manager
                // The tunnel will be cleaned up by the using statement when the service stops
                while (true)
                {
                    System.Threading.Thread.Sleep(1000);
                }
            }
        }
        catch (Exception ex)
        {
            // Log service errors to a file since console output won't show in Service Manager
            try
            {
                string errorLog = Path.Combine(Path.GetTempPath(), "NATTunnel_service_error.log");
                File.AppendAllText(errorLog,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] Service error: {ex.Message}\n" +
                    $"Stack trace: {ex.StackTrace}\n\n");
            }
            catch { }

            // Re-throw to exit with error code
            throw;
        }
    }
}