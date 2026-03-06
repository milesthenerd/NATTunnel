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
    /// <summary>
    /// Set to true to request graceful shutdown (used by GUI instead of Console.CancelKeyPress).
    /// </summary>
    public static volatile bool ShutdownRequested;

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
    public static void RunMeshMode()
    {
        UdpClient udpClient = null;
        TcpClient tcpClient = null;
        WireGuardTunnel wireguardTunnel = null;
        WireGuardUdpProxy udpProxy = null;
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
            udpClient = new UdpClient();
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

            tcpClient = new TcpClient();
            tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            tcpClient.Connect(endpoint);
            var stream = tcpClient.GetStream();
            stream.ReadTimeout = 15000; // 15 second timeout to prevent indefinite blocking

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
            wireguardTunnel = new WireGuardTunnel(interfaceName, debugMode, isRunningAsService: false, skipTunnelCreation: true);

            // Set client IP for mesh mode with /16 netmask (covers 10.5.0.0 - 10.5.255.255 for all mesh peers)
            wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
            Console.WriteLine($"[Mesh] WireGuard tunnel initialized with IP {meshIP}/16");

            // Initialize UDP proxy for mesh mode
            // The proxy will forward WireGuard traffic between the NAT-traversed peer connections and local WireGuard interface
            udpProxy = new WireGuardUdpProxy(udpClient);
            wireguardTunnel.SetUdpProxy(udpProxy);

            // Start mesh control listener on port 51888 (receives mesh messages over WireGuard)
            // These arrive as UDP packets from other peers' mesh IPs after WireGuard tunnels are established.
            // We use thread-safe queues to bridge the listener thread into the main message loop.
            const int MeshControlPort = 51888;
            // MeshIntroduction is no longer used — the introducer sends MeshConnectionBegin instead
            var meshConnectionBeginQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshHeartbeatAckQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshPeerRemovedQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshPeerLeaveQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            // Per-peer RTT latency in milliseconds, updated each ping cycle
            var peerLatencyMs = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();
            // Per-peer ping send timestamps for RTT calculation
            var pingSentTicks = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();
            // Track when the last MeshHeartbeat was received from the introducer.
            // Used for introducer failover: WireGuard PersistentKeepalive (5s) keeps
            // LastActivity fresh even after the introducer process dies, so we need an
            // application-level signal (heartbeats on port 51888) to detect process death.
            // Introducer's mesh IP — populated from MeshJoinResponse, used for failover probing.
            // Declared here (before mesh control listener) so the listener can check ack sources.
            string introducerMeshIP = null;
            // Active probe ack flag — set by mesh control listener when introducer responds
            bool introducerProbeAckReceived = true;
            // Track last heartbeat activity from each peer (for local staleness fallback).
            // Declared here so the mesh control listener can update it.
            var lastHeartbeatReceivedFrom = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>();
            // Introducer failover probe state — shared across primary and mesh-control-only loops.
            var lastIntroducerProbe = DateTime.UtcNow;
            var introducerProbeInterval = TimeSpan.FromSeconds(TunnelOptions.ProbeIntervalSeconds);
            int introducerMissedProbes = 0;
            const int IntroducerMissedProbeThreshold = 3; // Declare dead after 3 consecutive missed acks
            // Cache of peer info keyed by mesh IP — declared here (before mesh control listener)
            // so the listener can update it from the introducer's peer roster in heartbeats.
            // ConcurrentDictionary because it's written from the listener thread and read/written from main loop.
            var peerInfoByMeshIP = new System.Collections.Concurrent.ConcurrentDictionary<string, (string peerID, string endpoint, NATType natType)>();
            var meshControlClient = new UdpClient(MeshControlPort);
            var meshControlSendLock = new object();
            // Thread-safe wrapper for meshControlClient.Send — UdpClient is not thread-safe
            void MeshSend(byte[] data, int length, IPEndPoint endpoint)
            {
                lock (meshControlSendLock)
                {
                    meshControlClient.Send(data, length, endpoint);
                }
            }
            System.Threading.Tasks.Task.Run(async () =>
            {
                while (!ShutdownRequested)
                {
                    try
                    {
                        var result = await meshControlClient.ReceiveAsync();

                        // Fast-path: binary ping/pong (0xFF prefix) — no JSON parsing
                        if (result.Buffer.Length >= 2 && result.Buffer[0] == 0xFF)
                        {
                            if (result.Buffer[1] == (byte)'P')
                            {
                                // Ping received — respond with pong containing our mesh IP
                                byte[] meshIPBytes = Encoding.UTF8.GetBytes(meshIP ?? "");
                                byte[] pongPacket = new byte[2 + meshIPBytes.Length];
                                pongPacket[0] = 0xFF;
                                pongPacket[1] = (byte)'p';
                                Buffer.BlockCopy(meshIPBytes, 0, pongPacket, 2, meshIPBytes.Length);
                                MeshSend(pongPacket, pongPacket.Length, result.RemoteEndPoint);
                            }
                            else if (result.Buffer[1] == (byte)'p')
                            {
                                // Pong received — calculate RTT immediately in the listener thread
                                // to avoid 100ms main loop sleep skewing the measurement
                                long pongTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                                string responderIP = Encoding.UTF8.GetString(result.Buffer, 2, result.Buffer.Length - 2);
                                if (!string.IsNullOrEmpty(responderIP) && pingSentTicks.TryGetValue(responderIP, out long sentTicks))
                                {
                                    long elapsedMs = ((pongTicks - sentTicks) * 1000) / System.Diagnostics.Stopwatch.Frequency;
                                    peerLatencyMs[responderIP] = elapsedMs;
                                }
                            }
                            continue;
                        }

                        string json = Encoding.UTF8.GetString(result.Buffer);
                        var controlMsg = JsonSerializer.Deserialize<MediationMessage>(json);
                        if (controlMsg == null) continue;

                        if (controlMsg.ID == MediationMessageType.MeshConnectionBegin)
                        {
                            Console.WriteLine($"[Mesh] Received MeshConnectionBegin from {result.RemoteEndPoint}: peer {controlMsg.PeerID} at {controlMsg.EndpointString}");
                            // The sender of MeshConnectionBegin is the introducer — learn its mesh IP
                            // so the active probe mechanism can monitor it for failover.
                            string senderIP = result.RemoteEndPoint.Address.ToString();
                            if (string.IsNullOrEmpty(introducerMeshIP) && senderIP != meshIP)
                            {
                                introducerMeshIP = senderIP;
                                Console.WriteLine($"[Mesh] Learned introducer mesh IP from MeshConnectionBegin: {introducerMeshIP}");
                            }
                            meshConnectionBeginQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeat)
                        {
                            // The sender of MeshHeartbeat is the introducer — learn its mesh IP
                            string heartbeatSenderIP = result.RemoteEndPoint.Address.ToString();
                            lastHeartbeatReceivedFrom[heartbeatSenderIP] = DateTime.UtcNow;
                            if (string.IsNullOrEmpty(introducerMeshIP) && heartbeatSenderIP != meshIP)
                            {
                                introducerMeshIP = heartbeatSenderIP;
                                Console.WriteLine($"[Mesh] Learned introducer mesh IP from MeshHeartbeat: {introducerMeshIP}");
                            }
                            // Parse peer roster from introducer to learn about all mesh members
                            if (controlMsg.PeerRoster != null)
                            {
                                foreach (var entry in controlMsg.PeerRoster)
                                {
                                    var parts = entry.Split('|', 4);
                                    if (parts.Length >= 3 && !string.IsNullOrEmpty(parts[0]) && parts[0] != meshIP)
                                    {
                                        string rMeshIP = parts[0];
                                        string rPeerID = parts[1];
                                        int.TryParse(parts[2], out int rNatInt);
                                        string rEndpoint = parts.Length >= 4 ? parts[3] : null;
                                        // Only update if we don't already have info, or if we had Unknown data
                                        if (!peerInfoByMeshIP.TryGetValue(rMeshIP, out var existing) ||
                                            string.IsNullOrEmpty(existing.peerID) || existing.endpoint == null)
                                        {
                                            peerInfoByMeshIP[rMeshIP] = (rPeerID, rEndpoint, (NATType)rNatInt);
                                        }
                                    }
                                }
                            }
                            // Respond with our list of connected WireGuard peer mesh IPs
                            var allPeers = wireguardTunnel.GetAllPeers();
                            var connectedIPs = allPeers.Select(p => p.PrivateAddress.ToString()).ToArray();
                            var ack = new MediationMessage(MediationMessageType.MeshHeartbeatAck)
                            {
                                PeerID = peerID.ToString(),
                                PrivateAddressString = meshIP,
                                NATType = detectedNatType,
                                ConnectedMeshIPs = connectedIPs
                            };
                            byte[] ackBytes = Encoding.UTF8.GetBytes(ack.Serialize());
                            MeshSend(ackBytes, ackBytes.Length, result.RemoteEndPoint);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeatAck)
                        {
                            // If this ack is from the introducer, mark our probe as answered
                            string ackSourceIP = result.RemoteEndPoint.Address.ToString();
                            lastHeartbeatReceivedFrom[ackSourceIP] = DateTime.UtcNow;
                            if (!string.IsNullOrEmpty(introducerMeshIP) && ackSourceIP == introducerMeshIP)
                            {
                                introducerProbeAckReceived = true;
                            }
                            meshHeartbeatAckQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshPeerRemoved)
                        {
                            Console.WriteLine($"[Mesh] Received MeshPeerRemoved: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) declared dead by introducer");
                            meshPeerRemovedQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshPeerLeave)
                        {
                            Console.WriteLine($"[Mesh] Received MeshPeerLeave: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) left gracefully");
                            meshPeerLeaveQueue.Enqueue(controlMsg);
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

            // Register handler for graceful shutdown on Ctrl+C
            // Send MeshPeerLeave to all connected peers to allow them to clean up immediately
            // Graceful shutdown action — shared between Console.CancelKeyPress and ShutdownRequested
            void PerformGracefulShutdown()
            {
                Console.WriteLine("[Mesh] Graceful shutdown initiated");

                // Send MeshPeerLeave message to all WireGuard peers
                try
                {
                    var leaveMsg = new MediationMessage(MediationMessageType.MeshPeerLeave)
                    {
                        PrivateAddressString = meshIP,
                        PeerID = peerID.ToString()
                    };
                    byte[] leaveBytes = Encoding.UTF8.GetBytes(leaveMsg.Serialize());

                    var allPeers = wireguardTunnel.GetAllPeers();
                    foreach (var peer in allPeers)
                    {
                        try
                        {
                            MeshSend(leaveBytes, leaveBytes.Length,
                                new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to send MeshPeerLeave to {peer.PrivateAddress}: {ex.Message}");
                        }
                    }
                    Console.WriteLine($"[Mesh] Sent MeshPeerLeave to {allPeers.Count()} peer(s)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Mesh] Error sending graceful shutdown message: {ex.Message}");
                }

                ShutdownRequested = true;
            }

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true; // Prevent immediate termination
                PerformGracefulShutdown();
                Environment.Exit(0);
            };

            // Now join mesh network with REAL NAT type
            // Compute auth token: SHA256(networkID + ":" + networkSecret) as base64
            string authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                Encoding.UTF8.GetBytes(TunnelOptions.NetworkID + ":" + TunnelOptions.NetworkSecret)));

            var joinRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
            {
                NetworkID = TunnelOptions.NetworkID,
                PeerID = peerID.ToString(),
                NATType = detectedNatType,
                PrivateAddressString = meshIP,
                AuthToken = authToken
            };

            string requestJson = joinRequest.Serialize();
            byte[] sendBuffer = Encoding.ASCII.GetBytes(requestJson);
            stream.Write(sendBuffer, 0, sendBuffer.Length);

            Console.WriteLine($"[Mesh] Sent join request for network: {TunnelOptions.NetworkID}");

            // Wait for join response
            var joinResponse = ReadOneTcpMessage();
            if (!string.IsNullOrEmpty(joinResponse.AuthToken))
            {
                Console.Error.WriteLine($"[Mesh] Authentication failed: {joinResponse.AuthToken}");
                return;
            }
            Console.WriteLine($"[Mesh] Joined network! Found {joinResponse.PeerCount} other peers");

            // Clear read timeout now that handshake is complete
            stream.ReadTimeout = System.Threading.Timeout.Infinite;

            // Store active peer tunnels
            var activePeerTunnels = new Dictionary<string, Tunnel>();  // PeerID -> Tunnel
            var pendingConnectionRequests = new Dictionary<string, DateTime>();  // PeerID -> time requested
            var activeConnectionTunnels = new Dictionary<int, Tunnel>();  // ConnectionID -> Tunnel
            var connectionIDToPeerID = new Dictionary<int, string>();  // ConnectionID -> PeerID mapping
            var peerMeshIPs = new Dictionary<int, string>();  // ConnectionID -> Peer's mesh IP
            int pendingTunnelCount = 0;
            // Deferred MeshConnectionBegin messages for peers whose WireGuard tunnels aren't established yet.
            // Keyed by the target peer's mesh IP (the peer we want to send the message to).
            var deferredIntroductions = new Dictionary<string, List<MediationMessage>>();
            // peerInfoByMeshIP is declared earlier (before mesh control listener) so the
            // listener thread can update it from the introducer's peer roster in heartbeats.
            // Set of mesh IPs with fully established WireGuard tunnels (onConnectionComplete fired)
            var completedTunnelMeshIPs = new HashSet<string>();
            // Pairs of mesh IPs that are connected via relay through this introducer.
            // Stored as sorted "ipA|ipB" strings so lookup is order-independent.
            var relayedPairs = new HashSet<string>();
            var lastRepairAttempt = new Dictionary<string, DateTime>(); // "ipA|ipB" -> last repair time
            var repairCooldown = TimeSpan.FromSeconds(TunnelOptions.RepairCooldownSeconds);

            // Metrics counters for health monitoring
            int metricTunnelsEstablished = 0;
            int metricTunnelsFailed = 0;
            int metricReconnects = 0;
            int metricPeersLost = 0;
            int metricHeartbeatsSent = 0;
            int metricHeartbeatAcksReceived = 0;
            int metricHeartbeatsMissed = 0;
            long metricLastHeartbeatResponseMs = 0;
            int metricRelayRoutesEstablished = 0;
            int metricRelayRoutesRemoved = 0;
            DateTime? heartbeatSentTime = null;

            // Populate peerInfoByMeshIP and introducer mesh IP from the initial MeshJoinResponse.
            // This is critical for failover: if this peer later becomes the introducer,
            // it needs to know every peer's NAT type to decide relay vs direct hole-punch.
            if (joinResponse.Peers != null)
            {
                foreach (var peer in joinResponse.Peers)
                {
                    var pObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                    string pid = pObj.TryGetProperty("peerID", out JsonElement pidEl) ? pidEl.GetString() : null;
                    string mip = pObj.TryGetProperty("meshIP", out JsonElement mipEl) ? mipEl.GetString() : null;
                    string ep = pObj.TryGetProperty("endpoint", out JsonElement epEl) ? epEl.GetString() : null;
                    int nt = pObj.TryGetProperty("natType", out JsonElement ntEl) ? ntEl.GetInt32() : -1;

                    if (!string.IsNullOrEmpty(mip))
                    {
                        peerInfoByMeshIP[mip] = (pid, ep, (NATType)nt);
                    }

                    if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                        pid == joinResponse.IntroducerPeerID && !string.IsNullOrEmpty(mip))
                    {
                        introducerMeshIP = mip;
                        Console.WriteLine($"[Mesh] Introducer mesh IP: {introducerMeshIP} (peer {pid})");
                    }
                }
                Console.WriteLine($"[Mesh] Cached {peerInfoByMeshIP.Count} peer(s) from initial join response");
            }


            // Helper method to process discovered peers and send connection requests
            void ProcessDiscoveredPeers(object[] peers, NetworkStream targetStream = null)
            {
                if (peers == null || peers.Length == 0)
                    return;

                // Use the provided stream, or fall back to the primary loop's stream
                var writeStream = targetStream ?? stream;

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

                    if (pendingConnectionRequests.ContainsKey(targetPeerID))
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
                    writeStream.Write(connBuffer, 0, connBuffer.Length);
                    writeStream.Flush();

                    // Mark as pending so we don't send duplicate connection requests
                    pendingConnectionRequests[targetPeerID] = DateTime.UtcNow;
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

                if (string.IsNullOrEmpty(remotePeerID))
                {
                    Console.WriteLine($"[Mesh] MeshConnectionBegin missing PeerID — skipping");
                    return;
                }
                // Relay mode only needs mesh IP + introducer IP, not endpoint
                if (!cbMsg.IsRelay && string.IsNullOrEmpty(remoteEndpoint))
                {
                    Console.WriteLine($"[Mesh] MeshConnectionBegin missing endpoint (non-relay) — skipping");
                    return;
                }

                // Cache peer info for heartbeat repair — ensures the failover introducer
                // knows NAT types of peers that joined after this peer's initial connection.
                if (!string.IsNullOrEmpty(remoteMeshIP))
                {
                    peerInfoByMeshIP[remoteMeshIP] = (remotePeerID, remoteEndpoint, remotePeerNatType);
                }

                // Skip if a connection attempt is already in progress for this peer.
                // But if we have a completed (possibly dead) connection, allow the reconnect —
                // the introducer wouldn't re-introduce a peer unless something changed.
                if (pendingConnectionRequests.ContainsKey(remotePeerID))
                {
                    Console.WriteLine($"[Mesh] Ignoring MeshConnectionBegin for {remotePeerID} — connection already pending");
                    return;
                }

                bool alreadyTracked = activePeerTunnels.ContainsKey(remotePeerID) ||
                    (!string.IsNullOrEmpty(remoteMeshIP) && activePeerTunnels.ContainsKey(remoteMeshIP));

                if (alreadyTracked && !string.IsNullOrEmpty(remoteMeshIP))
                {
                    // Clean up the old connection to allow reconnect
                    Console.WriteLine($"[Mesh] Peer {remotePeerID} ({remoteMeshIP}) being re-introduced — cleaning up old connection");
                    metricReconnects++;
                    RemoveDeadPeer(remoteMeshIP);
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
                            metricRelayRoutesEstablished++;
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
                    completedTunnelMeshIPs.Add(remoteMeshIP);
                    pendingConnectionRequests.Remove(remotePeerID);
                    return;
                }

                pendingConnectionRequests[remotePeerID] = DateTime.UtcNow;
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
                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                        System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
                    },
                    sharedUdpClient: udpClient,
                    meshPeerEndpoint: remoteEndpoint,
                    retryInPlace: true,
                    sharedClientID: peerID,
                    ownMeshIP: meshIP,
                    onConnectionComplete: () =>
                    {
                        Console.WriteLine($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} WireGuard established");
                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                        pendingConnectionRequests.Remove(capturedPeerID);
                        System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                        if (!string.IsNullOrEmpty(capturedMeshIP))
                        {
                            completedTunnelMeshIPs.Add(capturedMeshIP);

                            // Flush deferred MeshConnectionBegin messages for this peer
                            if (deferredIntroductions.TryGetValue(capturedMeshIP, out var deferred) && deferred.Count > 0)
                            {
                                Console.WriteLine($"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) to {capturedMeshIP}");
                                foreach (var deferredMsg in deferred)
                                {
                                    try
                                    {
                                        byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                        MeshSend(deferredBytes, deferredBytes.Length,
                                            new IPEndPoint(IPAddress.Parse(capturedMeshIP), MeshControlPort));
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Failed to send deferred MeshConnectionBegin to {capturedMeshIP}: {ex.Message}");
                                    }
                                }
                                deferredIntroductions.Remove(capturedMeshIP);
                            }
                        }
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
                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
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
            var keepAliveInterval = TimeSpan.FromSeconds(5); // Keep-alive is fast; not configurable

            // Track mesh startup time for uptime calculation in MeshState
            var meshStartTime = DateTime.UtcNow;

            // Grace period: once all initial connections are established, wait before
            // disconnecting to give disconnected peers time to TransientReconnect.
            DateTime? disconnectAfter = null;
            bool hasPeers = joinResponse.Peers != null && joinResponse.Peers.Length > 0;

            // Periodic peer discovery: if we're connected to mediation but have no WireGuard
            // peers (lone peer), periodically re-send MeshJoinRequest to discover new peers.
            var lastPeerDiscovery = DateTime.UtcNow;
            var peerDiscoveryInterval = TimeSpan.FromSeconds(TunnelOptions.HeartbeatIntervalSeconds);

            // Periodic latency ping: every peer pings all WireGuard peers to measure RTT
            var lastPingTime = DateTime.UtcNow;
            var pingInterval = TimeSpan.FromSeconds(5);

            // Introducer heartbeat: periodically check that all peers can reach each other
            var lastHeartbeat = DateTime.UtcNow;
            var heartbeatInterval = TimeSpan.FromSeconds(TunnelOptions.HeartbeatIntervalSeconds);
            // After sending heartbeats, wait this long to collect acks before processing
            DateTime? heartbeatAckDeadline = null;
            // Collected acks for the current heartbeat round: meshIP -> set of connected mesh IPs
            var heartbeatAcks = new Dictionary<string, HashSet<string>>();
            // Track all known mesh IPs we've sent heartbeats to (for completeness checking)
            var heartbeatTargets = new HashSet<string>();
            // Track consecutive heartbeat misses per peer (introducer only)
            var heartbeatMissCount = new Dictionary<string, int>();
            int PeerDeadThreshold = TunnelOptions.DeadThreshold; // Declare dead after N consecutive missed acks

            // Helper: remove a dead peer from all local tracking structures and WireGuard
            void RemoveDeadPeer(string deadMeshIP)
            {
                string deadPeerID = null;
                if (peerInfoByMeshIP.TryGetValue(deadMeshIP, out var deadInfo))
                    deadPeerID = deadInfo.peerID;

                Console.WriteLine($"[Mesh] Removing dead peer {deadMeshIP} (peerID: {deadPeerID ?? "unknown"})");

                // Remove from WireGuard
                var deadIPAddr = IPAddress.Parse(deadMeshIP);
                var wgPeer = wireguardTunnel.GetPeer(deadIPAddr);
                if (wgPeer != null)
                {
                    wireguardTunnel.RemovePeer(wgPeer.ConnectionId);
                    Console.WriteLine($"[Mesh] Removed WireGuard peer {deadMeshIP}");
                }

                // Remove relay routes through this peer
                var removedRelays = wireguardTunnel.RemoveRelayRoutesViaGateway(deadIPAddr);
                if (removedRelays.Count > 0)
                {
                    metricRelayRoutesRemoved += removedRelays.Count;
                    Console.WriteLine($"[Mesh] Removed {removedRelays.Count} relay route(s) via {deadMeshIP}");
                }

                // Clean up tracking dictionaries
                peerInfoByMeshIP.TryRemove(deadMeshIP, out _);
                completedTunnelMeshIPs.Remove(deadMeshIP);
                heartbeatMissCount.Remove(deadMeshIP);
                lastHeartbeatReceivedFrom.TryRemove(deadMeshIP, out _);

                if (!string.IsNullOrEmpty(deadPeerID))
                {
                    activePeerTunnels.Remove(deadPeerID);
                    pendingConnectionRequests.Remove(deadPeerID);
                }
                activePeerTunnels.Remove(deadMeshIP);

                // Clean up peerMeshIPs entries pointing to this mesh IP
                var meshIPKeys = peerMeshIPs.Where(kvp => kvp.Value == deadMeshIP).Select(kvp => kvp.Key).ToList();
                foreach (var key in meshIPKeys)
                {
                    peerMeshIPs.Remove(key);
                    lock (activeConnectionTunnels) { activeConnectionTunnels.Remove(key); }
                }

                // Clean up relayedPairs containing this mesh IP
                relayedPairs.RemoveWhere(pair => pair.Contains(deadMeshIP));
            }

            // Helper method to capture current mesh state for HTTP status endpoint
            MeshState GetMeshState()
            {
                try
                {
                    var state = new MeshState
                    {
                        OwnMeshIP = meshIP,
                        OwnPeerID = peerID.ToString(),
                        IsIntroducer = isIntroducer,
                        NATType = detectedNatType.ToString(),
                        IntroducerMeshIP = introducerMeshIP,
                        UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds
                    };

                    // Snapshot shared collections to avoid cross-thread enumeration issues
                    var completedSnapshot = completedTunnelMeshIPs.ToArray();
                    var relayedPairsSnapshot = relayedPairs.ToArray();
                    var peerInfoSnapshot = peerInfoByMeshIP.ToArray();
                    var peerInfoDict = new Dictionary<string, (string peerID, string endpoint, NATType natType)>();
                    foreach (var kv in peerInfoSnapshot)
                        peerInfoDict[kv.Key] = kv.Value;

                    // Build set of all reachable mesh IPs and track which are relay-routed.
                    // A peer is "relayed" if it's only reachable via another peer's AllowedIPs.
                    // A peer is a "relay gateway" if its AllowedIPs contain other peers' mesh IPs.
                    var reachableMeshIPs = new HashSet<string>(completedSnapshot);
                    var relayedVia = new Dictionary<string, string>(); // meshIP -> gateway meshIP
                    var gatewayIPs = new HashSet<string>(); // peers that serve as relay gateways
                    try
                    {
                        var allWgPeers = wireguardTunnel?.GetAllPeers();
                        if (allWgPeers != null)
                        {
                            foreach (var wgPeer in allWgPeers)
                            {
                                string peerPrimary = wgPeer.PrivateAddress.ToString();
                                reachableMeshIPs.Add(peerPrimary);
                                // AllowedIPs is a comma-separated string like "10.5.5.152/32, 10.5.198.26/32"
                                if (!string.IsNullOrEmpty(wgPeer.AllowedIPs))
                                {
                                    foreach (var cidr in wgPeer.AllowedIPs.Split(',', StringSplitOptions.TrimEntries))
                                    {
                                        var ip = cidr.Split('/')[0];
                                        if (!string.IsNullOrEmpty(ip) && ip != peerPrimary)
                                        {
                                            reachableMeshIPs.Add(ip);
                                            relayedVia[ip] = peerPrimary;
                                            gatewayIPs.Add(peerPrimary);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }

                    foreach (var peerMeshIP in reachableMeshIPs)
                    {
                        if (peerMeshIP == meshIP) continue;

                        string peerId = null;
                        string endpoint = null;
                        NATType natType = NATType.Unknown;
                        if (peerInfoDict.TryGetValue(peerMeshIP, out var info))
                        {
                            peerId = info.peerID;
                            endpoint = info.endpoint;
                            natType = info.natType;
                        }

                        DateTime lastActivity = DateTime.MinValue;
                        try
                        {
                            var wgPeer = wireguardTunnel?.GetPeer(IPAddress.Parse(peerMeshIP));
                            if (wgPeer != null)
                                lastActivity = wgPeer.LastActivity;
                        }
                        catch { }

                        // Relay detection: check both local WireGuard routing and introducer's relayedPairs
                        bool isRelayed = relayedVia.ContainsKey(peerMeshIP)
                            || relayedPairsSnapshot.Any(pair => { var p = pair.Split('|'); return p.Length == 2 && ((p[0] == peerMeshIP && p[1] == meshIP) || (p[1] == peerMeshIP && p[0] == meshIP)); });
                        bool isRelayGateway = gatewayIPs.Contains(peerMeshIP)
                            || relayedPairsSnapshot.Any(pair => { var p = pair.Split('|'); return p.Length == 2 && (p[0] == peerMeshIP || p[1] == peerMeshIP); });

                        long latency = peerLatencyMs.TryGetValue(peerMeshIP, out var lat) ? lat : -1;

                        var peerInfo = new MeshState.ConnectedPeer
                        {
                            MeshIP = peerMeshIP,
                            PeerID = peerId ?? "Unknown",
                            NATType = natType.ToString(),
                            Endpoint = endpoint ?? "Unknown",
                            LastActivity = lastActivity,
                            IsRelayed = isRelayed,
                            IsRelayGateway = isRelayGateway,
                            LatencyMs = latency,
                            RelayedVia = relayedVia.TryGetValue(peerMeshIP, out var gw) ? gw : null
                        };

                        state.ConnectedPeers.Add(peerInfo);
                    }

                    // Populate relay routes from snapshot
                    foreach (var relayPair in relayedPairsSnapshot)
                    {
                        var parts = relayPair.Split('|');
                        if (parts.Length == 2)
                        {
                            state.RelayRoutes.Add(new MeshState.RelayRoute
                            {
                                SourceMeshIP = parts[0],
                                DestinationMeshIP = parts[1]
                            });
                        }
                    }

                    state.Metrics = new MeshState.MeshMetrics
                    {
                        TunnelsEstablished = metricTunnelsEstablished,
                        TunnelsFailed = metricTunnelsFailed,
                        Reconnects = metricReconnects,
                        PeersLost = metricPeersLost,
                        HeartbeatsSent = metricHeartbeatsSent,
                        HeartbeatAcksReceived = metricHeartbeatAcksReceived,
                        HeartbeatsMissed = metricHeartbeatsMissed,
                        LastHeartbeatResponseMs = metricLastHeartbeatResponseMs,
                        RelayRoutesEstablished = metricRelayRoutesEstablished,
                        RelayRoutesRemoved = metricRelayRoutesRemoved,
                        ActiveRelayRouteCount = relayedPairsSnapshot.Length
                    };

                    return state;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Mesh] Error building mesh state: {ex.Message}");
                    return new MeshState
                    {
                        OwnMeshIP = meshIP,
                        OwnPeerID = peerID.ToString(),
                        IsIntroducer = isIntroducer,
                        NATType = detectedNatType.ToString(),
                        UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds
                    };
                }
            }

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

                        // WireGuard packets (binary, message type 1-4): forward directly to the
                        // proxy ONCE instead of dispatching to every tunnel. This avoids O(N)
                        // duplicate forwards that degrade throughput with more peers.
                        bool isWireGuard = data.Length > 0 &&
                                          data[0] != (byte)'{' &&
                                          data[0] != (byte)'[' &&
                                          data[0] >= 1 && data[0] <= 4;

                        if (isWireGuard)
                        {
                            wireguardTunnel?.GetUdpProxy()?.ForwardToWireGuard(data, ep);
                        }
                        else
                        {
                            // JSON control packets: snapshot tunnels and dispatch for filtering
                            Tunnel[] tunnels;
                            lock (activeConnectionTunnels)
                            {
                                tunnels = new Tunnel[activeConnectionTunnels.Count];
                                activeConnectionTunnels.Values.CopyTo(tunnels, 0);
                            }

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

            // HTTP status endpoint for mesh state queries (used by GUI and CLI tools)
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var httpListener = new HttpListener();
                    httpListener.Prefixes.Add("http://localhost:51889/");
                    httpListener.Start();
                    Console.WriteLine("[Mesh] HTTP status endpoint listening on http://localhost:51889/status");

                    while (true)
                    {
                        try
                        {
                            var context = httpListener.GetContext();
                            if (context.Request.HttpMethod == "GET" && context.Request.RawUrl == "/status")
                            {
                                var meshState = GetMeshState();
                                var json = JsonSerializer.Serialize(meshState, new JsonSerializerOptions { WriteIndented = true });
                                byte[] buffer = Encoding.UTF8.GetBytes(json);

                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = buffer.Length;
                                context.Response.OutputStream.Write(buffer, 0, buffer.Length);
                                context.Response.OutputStream.Close();
                            }
                            else
                            {
                                context.Response.StatusCode = 404;
                                context.Response.OutputStream.Close();
                            }
                        }
                        catch (HttpListenerException)
                        {
                            // Listener stopped or other HTTP error
                            break;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] HTTP endpoint error: {ex.Message}");
                        }
                    }

                    httpListener.Stop();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Mesh] Failed to start HTTP status endpoint: {ex.Message}");
                }
            });

            // Message loop - create Tunnel instances when ConnectionBegin arrives.
            // Non-introducer peers disconnect once their initial connections are established
            // and reconnect transiently for each future introduced peer.
            // The introducer peer stays connected permanently to receive MeshIntroduceRequests.
            while (!ShutdownRequested)
            {
                // Disconnect once all initial setup is done, but only if we haven't been
                // selected as the introducer (introducers must stay connected).
                // Use a grace period to give disconnected peers time to TransientReconnect.
                if (!isIntroducer && tcpClient.Connected && hasPeers)
                {
                    // Only ready to disconnect if no pending work AND at least one tunnel actually
                    // succeeded. If all connections failed and we have zero WireGuard peers, we're
                    // isolated — stay connected so the server can assign new connections.
                    if (pendingTunnelCount < 0) pendingTunnelCount = 0; // Guard against double-decrement race
                    bool noPendingWork = pendingConnectionRequests.Count == 0 && pendingTunnelCount == 0;
                    bool hasEstablishedTunnels = activePeerTunnels.Count > 0;

                    // Before disconnecting, verify we have a WireGuard tunnel specifically
                    // to the introducer. Without this, the introducer can't send us
                    // MeshConnectionBegin messages for newly joining peers, cutting us off
                    // from the rest of the network.
                    bool hasIntroducerPath = false;
                    if (hasEstablishedTunnels)
                    {
                        string introducerPeerID = joinResponse.IntroducerPeerID;
                        if (!string.IsNullOrEmpty(introducerPeerID) && activePeerTunnels.ContainsKey(introducerPeerID))
                        {
                            hasIntroducerPath = true;
                        }
                        else if (!string.IsNullOrEmpty(introducerMeshIP) && completedTunnelMeshIPs.Contains(introducerMeshIP))
                        {
                            hasIntroducerPath = true;
                        }
                    }

                    bool readyToDisconnect = noPendingWork && hasEstablishedTunnels && hasIntroducerPath;

                    if (!readyToDisconnect && disconnectAfter == null &&
                        DateTime.UtcNow.Second % 10 == 0) // Log every ~10s to avoid spam
                    {
                        Console.WriteLine($"[Mesh] Not ready to disconnect: noPendingWork={noPendingWork}(pending={pendingConnectionRequests.Count},tunnels={pendingTunnelCount}), established={hasEstablishedTunnels}(count={activePeerTunnels.Count}), introducerPath={hasIntroducerPath}(introducerIP={introducerMeshIP ?? "null"},completed={completedTunnelMeshIPs.Count},introducerPeerID={joinResponse.IntroducerPeerID ?? "null"})");
                    }

                    if (readyToDisconnect && disconnectAfter == null)
                    {
                        int gracePeriod = detectedNatType != NATType.Symmetric ? TunnelOptions.GracePeriodSecondsNonSymmetric : TunnelOptions.GracePeriodSecondsSymmetric;
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

                // Clean up stale pending connection requests: if a request has been pending
                // for over 10s without a ConnectionBegin arriving, the target peer is likely
                // gone (disconnected, ServerNotAvailable lost, etc.)
                if (pendingConnectionRequests.Count > 0)
                {
                    var staleTimeout = TimeSpan.FromSeconds(TunnelOptions.StaleTimeoutSeconds);
                    var now = DateTime.UtcNow;
                    var staleRequests = pendingConnectionRequests
                        .Where(kvp => now - kvp.Value > staleTimeout)
                        .Select(kvp => kvp.Key)
                        .ToList();
                    foreach (var staleID in staleRequests)
                    {
                        pendingConnectionRequests.Remove(staleID);
                        Console.WriteLine($"[Mesh] Removed stale pending connection request for {staleID} (no response in {staleTimeout.TotalSeconds}s)");
                    }
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
                            PrivateAddressString = meshIP,
                            AuthToken = authToken
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

                // Retry connecting to the introducer if we don't have a tunnel to it yet.
                // The initial attempt may fail (e.g. hole-punch timeout) but we must stay
                // connected to mediation and keep retrying until the introducer link is up,
                // otherwise we can't receive MeshConnectionBegin for future peers.
                if (!isIntroducer && tcpClient.Connected &&
                    !string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                    !activePeerTunnels.ContainsKey(joinResponse.IntroducerPeerID) &&
                    !(introducerMeshIP != null && activePeerTunnels.ContainsKey(introducerMeshIP)) &&
                    !pendingConnectionRequests.ContainsKey(joinResponse.IntroducerPeerID) &&
                    pendingTunnelCount == 0)
                {
                    Console.WriteLine($"[Mesh] Retrying connection to introducer {joinResponse.IntroducerPeerID}");
                    try
                    {
                        var retryReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                        {
                            PeerID = joinResponse.IntroducerPeerID,
                            NATType = detectedNatType
                        };
                        byte[] retryBuf = Encoding.ASCII.GetBytes(retryReq.Serialize());
                        stream.Write(retryBuf, 0, retryBuf.Length);
                        stream.Flush();
                        pendingConnectionRequests[joinResponse.IntroducerPeerID] = DateTime.UtcNow;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Mesh] Introducer retry write failed: {ex.Message}");
                        break;
                    }
                }

                // Process MeshConnectionBegin messages: create tunnels that hole-punch directly
                // without going through the mediation server (introducer-relayed coordination).
                while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
                {
                    ProcessMeshConnectionBegin(cbMsg);
                }

                // Process peer removal notifications from the introducer
                while (meshPeerRemovedQueue.TryDequeue(out var rmMsg))
                {
                    if (!string.IsNullOrEmpty(rmMsg.PrivateAddressString))
                        RemoveDeadPeer(rmMsg.PrivateAddressString);
                }

                // Process graceful peer leave notifications
                while (meshPeerLeaveQueue.TryDequeue(out var leaveMsg))
                {
                    if (!string.IsNullOrEmpty(leaveMsg.PrivateAddressString))
                    {
                        Console.WriteLine($"[Mesh] Peer {leaveMsg.PrivateAddressString} left gracefully");
                        RemoveDeadPeer(leaveMsg.PrivateAddressString);
                    }
                }

                // ── Non-introducer failover probe (primary loop) ─────────────────────
                // If we're not the introducer and we have a known introducer mesh IP,
                // periodically probe it. If dead, take over as introducer.
                // This is needed because peers that stay connected to mediation (haven't
                // disconnected yet) would otherwise never detect a dead introducer.
                if (!isIntroducer && !string.IsNullOrEmpty(introducerMeshIP) &&
                    detectedNatType != NATType.Symmetric &&
                    completedTunnelMeshIPs.Contains(introducerMeshIP) &&
                    DateTime.UtcNow - lastIntroducerProbe > introducerProbeInterval)
                {
                    if (!introducerProbeAckReceived)
                    {
                        introducerMissedProbes++;
                        Console.WriteLine($"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
                    }
                    else
                    {
                        if (introducerMissedProbes > 0)
                            Console.WriteLine($"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
                        introducerMissedProbes = 0;
                    }

                    if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
                    {
                        Console.WriteLine("[Mesh] Introducer confirmed dead (detected in primary loop) — taking over as introducer");
                        isIntroducer = true;
                        introducerMissedProbes = 0;

                        // Re-register with mediation server as the new introducer
                        try
                        {
                            var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
                            {
                                NetworkID = TunnelOptions.NetworkID,
                                PeerID = peerID.ToString(),
                                NATType = detectedNatType,
                                PrivateAddressString = meshIP
                            };
                            byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                            stream.Write(joinBytes, 0, joinBytes.Length);
                            stream.Flush();
                            Console.WriteLine("[Mesh] Re-registered with mediation as new introducer");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to re-register as introducer: {ex.Message}");
                        }
                    }
                    else
                    {
                        // Send a new probe
                        introducerProbeAckReceived = false;
                        try
                        {
                            var probe = new MediationMessage(MediationMessageType.MeshHeartbeat);
                            byte[] probeBytes = Encoding.UTF8.GetBytes(probe.Serialize());
                            MeshSend(probeBytes, probeBytes.Length,
                                new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to send introducer probe: {ex.Message}");
                        }
                    }

                    lastIntroducerProbe = DateTime.UtcNow;
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

                    // Build peer roster so non-introducer peers can learn about all mesh members
                    var roster = new List<string>();
                    foreach (var peer in allPeers)
                    {
                        string pip = peer.PrivateAddress.ToString();
                        if (peerInfoByMeshIP.TryGetValue(pip, out var pi))
                            roster.Add($"{pip}|{pi.peerID}|{(int)pi.natType}|{pi.endpoint}");
                    }
                    var rosterArray = roster.Count > 0 ? roster.ToArray() : null;

                    foreach (var peer in allPeers)
                    {
                        string peerIP = peer.PrivateAddress.ToString();
                        heartbeatTargets.Add(peerIP);

                        var hb = new MediationMessage(MediationMessageType.MeshHeartbeat)
                        {
                            PeerRoster = rosterArray
                        };
                        try
                        {
                            byte[] hbBytes = Encoding.UTF8.GetBytes(hb.Serialize());
                            MeshSend(hbBytes, hbBytes.Length,
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
                        heartbeatSentTime = DateTime.UtcNow;
                        metricHeartbeatsSent++;
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
                            metricHeartbeatAcksReceived++;
                        }
                        // Cache peer info from heartbeat acks — this is the most reliable
                        // source since every peer responds with its NAT type on every cycle.
                        if (!string.IsNullOrEmpty(ackMeshIP) && !string.IsNullOrEmpty(ackMsg.PeerID))
                        {
                            // Preserve existing endpoint — heartbeat acks don't include it
                            string existingEndpoint = peerInfoByMeshIP.TryGetValue(ackMeshIP, out var existing) ? existing.endpoint : null;
                            peerInfoByMeshIP[ackMeshIP] = (ackMsg.PeerID, existingEndpoint, ackMsg.NATType);
                        }
                    }

                    // Process after deadline
                    if (DateTime.UtcNow > heartbeatAckDeadline.Value)
                    {
                        if (heartbeatSentTime != null)
                            metricLastHeartbeatResponseMs = (long)(DateTime.UtcNow - heartbeatSentTime.Value).TotalMilliseconds;
                        Console.WriteLine($"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

                        // Track consecutive misses per peer and remove dead ones
                        var deadPeers = new List<string>();
                        foreach (var ip in heartbeatTargets)
                        {
                            if (heartbeatAcks.ContainsKey(ip))
                            {
                                heartbeatMissCount[ip] = 0;
                            }
                            else
                            {
                                heartbeatMissCount.TryGetValue(ip, out int prev);
                                heartbeatMissCount[ip] = prev + 1;
                                metricHeartbeatsMissed++;
                                Console.WriteLine($"[Mesh] Peer {ip} missed heartbeat ({heartbeatMissCount[ip]}/{PeerDeadThreshold})");
                                if (heartbeatMissCount[ip] >= PeerDeadThreshold)
                                    deadPeers.Add(ip);
                            }
                        }
                        foreach (var deadIP in deadPeers)
                        {
                            metricPeersLost++;
                            Console.WriteLine($"[Mesh] Peer {deadIP} declared dead after {PeerDeadThreshold} consecutive missed heartbeats");
                            // Notify all remaining peers before removing locally
                            string deadPID = peerInfoByMeshIP.TryGetValue(deadIP, out var di) ? di.peerID : null;
                            var removeMsg = new MediationMessage(MediationMessageType.MeshPeerRemoved)
                            {
                                PrivateAddressString = deadIP,
                                PeerID = deadPID ?? ""
                            };
                            byte[] rmBytes = Encoding.UTF8.GetBytes(removeMsg.Serialize());
                            foreach (var peerIP in heartbeatTargets)
                            {
                                if (peerIP == deadIP) continue;
                                try
                                {
                                    MeshSend(rmBytes, rmBytes.Length,
                                        new IPEndPoint(IPAddress.Parse(peerIP), MeshControlPort));
                                }
                                catch { }
                            }
                            RemoveDeadPeer(deadIP);
                        }

                        // Check every pair of peers for missing connectivity
                        var targetList = heartbeatTargets.Where(ip => !deadPeers.Contains(ip)).ToList();
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
                                    // Cooldown: don't re-introduce the same pair repeatedly
                                    string pairKey = $"{sortedA}|{sortedB}";
                                    if (lastRepairAttempt.TryGetValue(pairKey, out var lastAttempt) &&
                                        DateTime.UtcNow - lastAttempt < repairCooldown)
                                        continue;

                                    bool hasA = peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                                    bool hasB = peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

                                    // Check if both are symmetric — use relay instead of direct hole-punch
                                    bool bothSymmetric = hasA && hasB && infoA.natType == NATType.Symmetric && infoB.natType == NATType.Symmetric;

                                    if (!hasA || !hasB)
                                        Console.WriteLine($"[Mesh] Heartbeat: missing peer info for pair {ipA}(known={hasA}) <-> {ipB}(known={hasB}) — peerInfoByMeshIP has {peerInfoByMeshIP.Count} entries");

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
                                            MeshSend(rABytes, rABytes.Length,
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
                                            MeshSend(rBBytes, rBBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                                        }

                                        // Track as relayed
                                        relayedPairs.Add($"{sortedA}|{sortedB}");
                                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
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
                                                MeshSend(cbABytes, cbABytes.Length,
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
                                                MeshSend(cbBBytes, cbBBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                                repairCount++;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send repair MeshConnectionBegin to {ipB}: {ex.Message}");
                                            }
                                        }
                                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                                    }
                                }
                            }
                        }

                        // Also check that each peer can reach US (the introducer).
                        // If a peer's ConnectedMeshIPs doesn't include our mesh IP,
                        // it lost its tunnel to us and needs a re-introduction via mediation.
                        foreach (var ip in targetList)
                        {
                            if (!heartbeatAcks.ContainsKey(ip))
                                continue; // Peer didn't respond — can't check
                            if (!heartbeatAcks[ip].Contains(meshIP))
                            {
                                Console.WriteLine($"[Mesh] Heartbeat: peer {ip} cannot reach introducer ({meshIP}) — requesting re-connection via mediation");
                                // We can't send MeshConnectionBegin over WireGuard because the
                                // tunnel is down. Instead, send a ConnectionRequest through the
                                // mediation server (if connected) to re-establish the link.
                                if (tcpClient.Connected && peerInfoByMeshIP.TryGetValue(ip, out var lostPeerInfo) &&
                                    !string.IsNullOrEmpty(lostPeerInfo.peerID) &&
                                    !pendingConnectionRequests.ContainsKey(lostPeerInfo.peerID))
                                {
                                    try
                                    {
                                        var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                                        {
                                            PeerID = lostPeerInfo.peerID,
                                            NATType = detectedNatType
                                        };
                                        byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                                        stream.Write(reconnBuf, 0, reconnBuf.Length);
                                        stream.Flush();
                                        pendingConnectionRequests[lostPeerInfo.peerID] = DateTime.UtcNow;
                                        repairCount++;
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Failed to send re-connection request for {ip}: {ex.Message}");
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

                // ── Latency ping ──────────────────────────────────────────────────
                // Periodically send binary ping (0xFF 'P') to all reachable mesh IPs.
                if (DateTime.UtcNow - lastPingTime > pingInterval)
                {
                    byte[] pingPacket = new byte[] { 0xFF, (byte)'P' };
                    var allPeers = wireguardTunnel.GetAllPeers();
                    var pingedIPs = new HashSet<string>();
                    foreach (var peer in allPeers)
                    {
                        string peerIP = peer.PrivateAddress.ToString();
                        if (pingedIPs.Add(peerIP))
                        {
                            pingSentTicks[peerIP] = System.Diagnostics.Stopwatch.GetTimestamp();
                            try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(peer.PrivateAddress, MeshControlPort)); } catch { }
                        }
                        // Also ping any relayed IPs in this peer's AllowedIPs
                        if (!string.IsNullOrEmpty(peer.AllowedIPs))
                        {
                            foreach (var cidr in peer.AllowedIPs.Split(',', StringSplitOptions.TrimEntries))
                            {
                                string ip = cidr.Split('/')[0];
                                if (!string.IsNullOrEmpty(ip) && ip != peerIP && pingedIPs.Add(ip))
                                {
                                    pingSentTicks[ip] = System.Diagnostics.Stopwatch.GetTimestamp();
                                    try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(IPAddress.Parse(ip), MeshControlPort)); } catch { }
                                }
                            }
                        }
                    }
                    lastPingTime = DateTime.UtcNow;
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
                                // Cache peer info so GetMeshState can display it
                                if (!string.IsNullOrEmpty(msg.PeerID))
                                    peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, msg.EndpointString, msg.NATType);

                                // Clean up any existing tunnel to the same mesh IP before creating a new one.
                                // Without this, old tunnels completing late overwrite the WireGuard peer's
                                // endpoint with a stale address, breaking mesh control traffic.
                                string cbMeshIP = msg.PrivateAddressString;
                                var oldConnIDs = peerMeshIPs
                                    .Where(kvp => kvp.Value == cbMeshIP && kvp.Key != msg.ConnectionID)
                                    .Select(kvp => kvp.Key).ToList();
                                foreach (var oldConnID in oldConnIDs)
                                {
                                    Tunnel oldTunnel = null;
                                    lock (activeConnectionTunnels)
                                    {
                                        if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                                            activeConnectionTunnels.Remove(oldConnID);
                                    }
                                    if (oldTunnel != null)
                                    {
                                        Console.WriteLine($"[Mesh] Disposing old tunnel {oldConnID} for {cbMeshIP} (superseded by {msg.ConnectionID})");
                                        try { oldTunnel.Dispose(); } catch { }
                                    }
                                    peerMeshIPs.Remove(oldConnID);
                                }
                                activePeerTunnels.Remove(cbMeshIP);
                                if (!string.IsNullOrEmpty(msg.PeerID))
                                    activePeerTunnels.Remove(msg.PeerID);
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
                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                        System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
                                    },
                                    sharedUdpClient: udpClient,
                                    meshPeerEndpoint: msg.EndpointString,
                                    retryInPlace: true,
                                    sharedClientID: peerID,
                                    ownMeshIP: meshIP,
                                    onConnectionComplete: () =>
                                    {
                                        Console.WriteLine($"[Mesh] Tunnel {capturedConnectionID} WireGuard connection established");
                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                        System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);

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
                                                        MeshSend(deferredBytes, deferredBytes.Length,
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
                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                    }
                                });
                            }
                        }
                        else if (msg.ID == MediationMessageType.MeshJoinResponse)
                        {
                            if (!string.IsNullOrEmpty(msg.AuthToken))
                            {
                                Console.Error.WriteLine($"[Mesh] Authentication failed on rediscovery: {msg.AuthToken}");
                            }
                            else
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
                        else if (msg.ID == MediationMessageType.ServerNotAvailable)
                        {
                            Console.WriteLine($"[Mesh] ServerNotAvailable — target peer unavailable");
                            // The mediation server couldn't establish this connection (target disconnected
                            // or missing UDP info). Remove the pending request so it doesn't block disconnect.
                            // We don't know which specific peer failed, but since this is a response to
                            // our most recent ConnectionRequest, we can't easily map it. Instead, the
                            // stale pending cleanup below will handle it after timeout.
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
                                            MeshSend(relayExBytes, relayExBytes.Length,
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
                                                    MeshSend(relayNewBytes, relayNewBytes.Length,
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
                                        MeshSend(toExistingBytes, toExistingBytes.Length,
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
                                                MeshSend(toNewBytes, toNewBytes.Length,
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
                                int deferredCount = deferredIntroductions.TryGetValue(msg.PrivateAddressString ?? "", out var dList) ? dList.Count : 0;
                                Console.WriteLine($"[Mesh] Sent MeshIntroduceAck for {msg.PeerID} ({introduced} introduced, {deferredCount} deferred, completedTunnels={completedTunnelMeshIPs.Count})");
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
            if (ShutdownRequested)
            {
                PerformGracefulShutdown();
                return;
            }

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
            int IsolationGracePeriodSeconds = TunnelOptions.IsolationGracePeriodSeconds; // Wait before reconnecting to avoid thrashing
            TcpClient reconnectedTcpClient = null;
            NetworkStream reconnectedStream = null;
            string reconnectedTcpBuffer = ""; // Accumulates partial TCP data across reads
            DateTime? lastReconnectDiscovery = null;
            var reconnectDiscoveryInterval = TimeSpan.FromSeconds(TunnelOptions.HeartbeatIntervalSeconds);

            // Reset probe state when entering mesh-control-only loop
            lastIntroducerProbe = DateTime.UtcNow;
            introducerMissedProbes = 0;

            Console.WriteLine($"[Mesh] Entering mesh-control-only loop — isIntroducer={isIntroducer}, natType={detectedNatType}, introducerMeshIP={introducerMeshIP ?? "null"}");

            while (!ShutdownRequested)
            {
                // Process MeshConnectionBegin messages (introducer-relayed, no mediation server needed)
                while (meshConnectionBeginQueue.TryDequeue(out var cbMsg))
                {
                    ProcessMeshConnectionBegin(cbMsg);
                }

                // Process peer removal notifications from the introducer
                while (meshPeerRemovedQueue.TryDequeue(out var rmMsg))
                {
                    if (!string.IsNullOrEmpty(rmMsg.PrivateAddressString))
                        RemoveDeadPeer(rmMsg.PrivateAddressString);
                }

                // Process graceful peer leave notifications
                while (meshPeerLeaveQueue.TryDequeue(out var leaveMsg))
                {
                    if (!string.IsNullOrEmpty(leaveMsg.PrivateAddressString))
                    {
                        Console.WriteLine($"[Mesh] Peer {leaveMsg.PrivateAddressString} left gracefully");
                        RemoveDeadPeer(leaveMsg.PrivateAddressString);
                    }
                }

                // ── Introducer heartbeat (failover introducer) ──────────────────────
                // Same logic as the primary introducer loop — send heartbeats, collect
                // acks, and repair missing peer-to-peer links.
                if (isIntroducer && heartbeatAckDeadline == null &&
                    DateTime.UtcNow - lastHeartbeat > heartbeatInterval)
                {
                    var allPeers = wireguardTunnel.GetAllPeers();
                    heartbeatTargets.Clear();
                    heartbeatAcks.Clear();

                    // Build peer roster for failover introducer heartbeats
                    var roster2 = new List<string>();
                    foreach (var peer in allPeers)
                    {
                        string pip = peer.PrivateAddress.ToString();
                        if (peerInfoByMeshIP.TryGetValue(pip, out var pi))
                            roster2.Add($"{pip}|{pi.peerID}|{(int)pi.natType}|{pi.endpoint}");
                    }
                    var rosterArray2 = roster2.Count > 0 ? roster2.ToArray() : null;

                    foreach (var peer in allPeers)
                    {
                        string peerIP = peer.PrivateAddress.ToString();
                        heartbeatTargets.Add(peerIP);

                        var hb = new MediationMessage(MediationMessageType.MeshHeartbeat)
                        {
                            PeerRoster = rosterArray2
                        };
                        try
                        {
                            byte[] hbBytes = Encoding.UTF8.GetBytes(hb.Serialize());
                            MeshSend(hbBytes, hbBytes.Length,
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
                        heartbeatSentTime = DateTime.UtcNow;
                        metricHeartbeatsSent++;
                        Console.WriteLine($"[Mesh] Heartbeat sent to {heartbeatTargets.Count} peer(s), collecting acks...");
                    }
                    else
                    {
                        lastHeartbeat = DateTime.UtcNow;
                    }
                }

                // Collect heartbeat acks (failover introducer)
                if (heartbeatAckDeadline != null)
                {
                    while (meshHeartbeatAckQueue.TryDequeue(out var ackMsg))
                    {
                        string ackMeshIP = ackMsg.PrivateAddressString;
                        if (!string.IsNullOrEmpty(ackMeshIP) && ackMsg.ConnectedMeshIPs != null)
                        {
                            heartbeatAcks[ackMeshIP] = new HashSet<string>(ackMsg.ConnectedMeshIPs);
                            metricHeartbeatAcksReceived++;
                        }
                        // Cache peer info from heartbeat acks — this is the most reliable
                        // source since every peer responds with its NAT type on every cycle.
                        if (!string.IsNullOrEmpty(ackMeshIP) && !string.IsNullOrEmpty(ackMsg.PeerID))
                        {
                            // Preserve existing endpoint — heartbeat acks don't include it
                            string existingEndpoint = peerInfoByMeshIP.TryGetValue(ackMeshIP, out var existing) ? existing.endpoint : null;
                            peerInfoByMeshIP[ackMeshIP] = (ackMsg.PeerID, existingEndpoint, ackMsg.NATType);
                        }
                    }

                    if (DateTime.UtcNow > heartbeatAckDeadline.Value)
                    {
                        if (heartbeatSentTime != null)
                            metricLastHeartbeatResponseMs = (long)(DateTime.UtcNow - heartbeatSentTime.Value).TotalMilliseconds;
                        Console.WriteLine($"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

                        // Track consecutive misses per peer and remove dead ones
                        var deadPeers = new List<string>();
                        foreach (var ip in heartbeatTargets)
                        {
                            if (heartbeatAcks.ContainsKey(ip))
                            {
                                heartbeatMissCount[ip] = 0;
                            }
                            else
                            {
                                heartbeatMissCount.TryGetValue(ip, out int prev);
                                heartbeatMissCount[ip] = prev + 1;
                                metricHeartbeatsMissed++;
                                Console.WriteLine($"[Mesh] Peer {ip} missed heartbeat ({heartbeatMissCount[ip]}/{PeerDeadThreshold})");
                                if (heartbeatMissCount[ip] >= PeerDeadThreshold)
                                    deadPeers.Add(ip);
                            }
                        }
                        foreach (var deadIP in deadPeers)
                        {
                            metricPeersLost++;
                            Console.WriteLine($"[Mesh] Peer {deadIP} declared dead after {PeerDeadThreshold} consecutive missed heartbeats");
                            string deadPID = peerInfoByMeshIP.TryGetValue(deadIP, out var di) ? di.peerID : null;
                            var removeMsg = new MediationMessage(MediationMessageType.MeshPeerRemoved)
                            {
                                PrivateAddressString = deadIP,
                                PeerID = deadPID ?? ""
                            };
                            byte[] rmBytes = Encoding.UTF8.GetBytes(removeMsg.Serialize());
                            foreach (var peerIP in heartbeatTargets)
                            {
                                if (peerIP == deadIP) continue;
                                try
                                {
                                    MeshSend(rmBytes, rmBytes.Length,
                                        new IPEndPoint(IPAddress.Parse(peerIP), MeshControlPort));
                                }
                                catch { }
                            }
                            RemoveDeadPeer(deadIP);
                        }

                        var targetList = heartbeatTargets.Where(ip => !deadPeers.Contains(ip)).ToList();
                        int repairCount = 0;
                        for (int i = 0; i < targetList.Count; i++)
                        {
                            for (int j = i + 1; j < targetList.Count; j++)
                            {
                                string ipA = targetList[i];
                                string ipB = targetList[j];

                                bool aReportsB = heartbeatAcks.ContainsKey(ipA) && heartbeatAcks[ipA].Contains(ipB);
                                bool bReportsA = heartbeatAcks.ContainsKey(ipB) && heartbeatAcks[ipB].Contains(ipA);

                                string sortedA = string.Compare(ipA, ipB, StringComparison.Ordinal) < 0 ? ipA : ipB;
                                string sortedB = sortedA == ipA ? ipB : ipA;
                                if (relayedPairs.Contains($"{sortedA}|{sortedB}"))
                                    continue;

                                if (!aReportsB && !bReportsA)
                                {
                                    // Cooldown: don't re-introduce the same pair repeatedly
                                    string pairKey = $"{sortedA}|{sortedB}";
                                    if (lastRepairAttempt.TryGetValue(pairKey, out var lastAttempt) &&
                                        DateTime.UtcNow - lastAttempt < repairCooldown)
                                        continue;

                                    bool hasA = peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                                    bool hasB = peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

                                    bool bothSymmetric = hasA && hasB && infoA.natType == NATType.Symmetric && infoB.natType == NATType.Symmetric;

                                    if (!hasA || !hasB)
                                        Console.WriteLine($"[Mesh] Heartbeat: missing peer info for pair {ipA}(known={hasA}) <-> {ipB}(known={hasB}) — peerInfoByMeshIP has {peerInfoByMeshIP.Count} entries");

                                    if (bothSymmetric)
                                    {
                                        Console.WriteLine($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected (both symmetric) — re-establishing relay");

                                        wireguardTunnel.EnableForwarding();

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
                                            MeshSend(rABytes, rABytes.Length,
                                                new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}");
                                        }

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
                                            MeshSend(rBBytes, rBBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                                        }

                                        relayedPairs.Add($"{sortedA}|{sortedB}");
                                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                                    }
                                    else
                                    {
                                        Console.WriteLine($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected — re-introducing");

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
                                                MeshSend(cbABytes, cbABytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                                repairCount++;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send repair MeshConnectionBegin to {ipA}: {ex.Message}");
                                            }
                                        }

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
                                                MeshSend(cbBBytes, cbBBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                                repairCount++;
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Failed to send repair MeshConnectionBegin to {ipB}: {ex.Message}");
                                            }
                                        }
                                        lastRepairAttempt[pairKey] = DateTime.UtcNow;
                                    }
                                }
                            }
                        }

                        // Also check that each peer can reach US (the introducer).
                        // If a peer's ConnectedMeshIPs doesn't include our mesh IP,
                        // it lost its tunnel to us and needs a re-introduction via mediation.
                        foreach (var ip in targetList)
                        {
                            if (!heartbeatAcks.ContainsKey(ip))
                                continue;
                            if (!heartbeatAcks[ip].Contains(meshIP))
                            {
                                Console.WriteLine($"[Mesh] Heartbeat: peer {ip} cannot reach introducer ({meshIP}) — requesting re-connection via mediation");
                                if (reconnectedTcpClient != null && reconnectedTcpClient.Connected &&
                                    peerInfoByMeshIP.TryGetValue(ip, out var lostPeerInfo) &&
                                    !string.IsNullOrEmpty(lostPeerInfo.peerID) &&
                                    !pendingConnectionRequests.ContainsKey(lostPeerInfo.peerID))
                                {
                                    try
                                    {
                                        var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                                        {
                                            PeerID = lostPeerInfo.peerID,
                                            NATType = detectedNatType
                                        };
                                        byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                                        reconnectedStream.Write(reconnBuf, 0, reconnBuf.Length);
                                        reconnectedStream.Flush();
                                        pendingConnectionRequests[lostPeerInfo.peerID] = DateTime.UtcNow;
                                        repairCount++;
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Failed to send re-connection request for {ip}: {ex.Message}");
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

                // ── Latency ping (mesh-only loop) ────────────────────────────────
                if (DateTime.UtcNow - lastPingTime > pingInterval)
                {
                    byte[] pingPacket = new byte[] { 0xFF, (byte)'P' };
                    var allPeers = wireguardTunnel.GetAllPeers();
                    var pingedIPs = new HashSet<string>();
                    foreach (var peer in allPeers)
                    {
                        string peerIP = peer.PrivateAddress.ToString();
                        if (pingedIPs.Add(peerIP))
                        {
                            pingSentTicks[peerIP] = System.Diagnostics.Stopwatch.GetTimestamp();
                            try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(peer.PrivateAddress, MeshControlPort)); } catch { }
                        }
                        if (!string.IsNullOrEmpty(peer.AllowedIPs))
                        {
                            foreach (var cidr in peer.AllowedIPs.Split(',', StringSplitOptions.TrimEntries))
                            {
                                string ip = cidr.Split('/')[0];
                                if (!string.IsNullOrEmpty(ip) && ip != peerIP && pingedIPs.Add(ip))
                                {
                                    pingSentTicks[ip] = System.Diagnostics.Stopwatch.GetTimestamp();
                                    try { MeshSend(pingPacket, pingPacket.Length, new IPEndPoint(IPAddress.Parse(ip), MeshControlPort)); } catch { }
                                }
                            }
                        }
                    }
                    lastPingTime = DateTime.UtcNow;
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
                                reconnectedTcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            }
                        }
                        // Process any complete JSON messages accumulated in the buffer
                        if (reconnectedTcpBuffer.Length > 0)
                        {
                            var (parsedMsg, remainder) = ExtractFirstJson(reconnectedTcpBuffer);
                            while (parsedMsg != null)
                            {
                                if (parsedMsg.ID == MediationMessageType.MeshJoinResponse ||
                                    parsedMsg.ID == MediationMessageType.MeshPeerList)
                                {
                                    if (!string.IsNullOrEmpty(parsedMsg.AuthToken))
                                    {
                                        Console.Error.WriteLine($"[Mesh] Authentication failed on reconnect: {parsedMsg.AuthToken}");
                                    }
                                    else if (parsedMsg.Peers != null && parsedMsg.Peers.Length > 0)
                                    {
                                        Console.WriteLine($"[Mesh] Reconnect discovery: found {parsedMsg.Peers.Length} peer(s)");
                                        // Cache peer info for heartbeat repair (NAT type, endpoint, etc.)
                                        // Without this, the failover introducer can't detect symmetric peers
                                        // and falls back to direct hole-punching instead of relay mode.
                                        foreach (var peerObj2 in parsedMsg.Peers)
                                        {
                                            var pe2 = JsonSerializer.Deserialize<JsonElement>(peerObj2.ToString());
                                            string mip2 = pe2.TryGetProperty("meshIP", out JsonElement mipEl2) ? mipEl2.GetString() : null;
                                            string ep2 = pe2.TryGetProperty("endpoint", out JsonElement epEl2) ? epEl2.GetString() : null;
                                            int nt2 = pe2.TryGetProperty("natType", out JsonElement ntEl2) ? ntEl2.GetInt32() : -1;
                                            string pid2 = pe2.TryGetProperty("peerID", out JsonElement pidEl2) ? pidEl2.GetString() : null;
                                            if (!string.IsNullOrEmpty(mip2))
                                            {
                                                peerInfoByMeshIP[mip2] = (pid2, ep2, (NATType)nt2);
                                                Console.WriteLine($"[Mesh] Cached peer info: {mip2} = NAT:{(NATType)nt2}, endpoint:{ep2}");
                                            }
                                        }
                                        ProcessDiscoveredPeers(parsedMsg.Peers, reconnectedStreamLocal);
                                    }
                                }
                                else if (parsedMsg.ID == MediationMessageType.ConnectionBegin)
                                {
                                    Console.WriteLine($"[Mesh] Reconnect: received ConnectionBegin for connection {parsedMsg.ConnectionID}");
                                    // Store peer's mesh IP
                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                    {
                                        peerMeshIPs[parsedMsg.ConnectionID] = parsedMsg.PrivateAddressString;
                                        if (!string.IsNullOrEmpty(parsedMsg.PeerID))
                                            peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, parsedMsg.EndpointString, parsedMsg.NATType);
                                    }

                                    // Clean up any existing tunnel to the same mesh IP before creating a new one.
                                    // Without this, old tunnels completing late overwrite the WireGuard peer's
                                    // endpoint with a stale address, breaking mesh control traffic.
                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                    {
                                        string reconMeshIP = parsedMsg.PrivateAddressString;
                                        // Find and dispose old tunnels to this mesh IP
                                        var oldConnIDs = peerMeshIPs
                                            .Where(kvp => kvp.Value == reconMeshIP && kvp.Key != parsedMsg.ConnectionID)
                                            .Select(kvp => kvp.Key).ToList();
                                        foreach (var oldConnID in oldConnIDs)
                                        {
                                            Tunnel oldTunnel = null;
                                            lock (activeConnectionTunnels)
                                            {
                                                if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                                                    activeConnectionTunnels.Remove(oldConnID);
                                            }
                                            if (oldTunnel != null)
                                            {
                                                Console.WriteLine($"[Mesh] Reconnect: disposing old tunnel {oldConnID} for {reconMeshIP} (superseded by {parsedMsg.ConnectionID})");
                                                try { oldTunnel.Dispose(); } catch { }
                                            }
                                            peerMeshIPs.Remove(oldConnID);
                                        }
                                        // Clean up tracking for this mesh IP so the new tunnel starts fresh
                                        activePeerTunnels.Remove(reconMeshIP);
                                        if (!string.IsNullOrEmpty(parsedMsg.PeerID))
                                            activePeerTunnels.Remove(parsedMsg.PeerID);
                                        heartbeatMissCount.Remove(reconMeshIP);
                                    }

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
                                                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                System.Threading.Interlocked.Increment(ref metricTunnelsFailed);
                                            },
                                            sharedUdpClient: udpClient,
                                            meshPeerEndpoint: parsedMsg.EndpointString,
                                            retryInPlace: true,
                                            sharedClientID: peerID,
                                            ownMeshIP: meshIP,
                                            onConnectionComplete: () =>
                                            {
                                                Console.WriteLine($"[Mesh] Reconnect tunnel {capturedConnID} WireGuard established");
                                                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
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
                                        var capturedMsg = parsedMsg;
                                        System.Threading.Tasks.Task.Run(() =>
                                        {
                                            try
                                            {
                                                reconnectTunnel.Start();
                                                reconnectTunnel.InjectConnectionBegin(
                                                    capturedMsg.EndpointString,
                                                    capturedMsg.NATType,
                                                    capturedMsg.OwnNATType ?? detectedNatType,
                                                    capturedMsg.PrivateAddressString);
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine($"[Mesh] Reconnect tunnel error: {ex.Message}");
                                                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
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
                                                MeshSend(cbBytes, cbBytes.Length,
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
                                                        MeshSend(cbNewBytes, cbNewBytes.Length,
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
                            reconnectedTcpBuffer = remainder ?? "";
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
                            else if (!stillIsolated && !isIntroducer)
                            {
                                // Peers recovered — close reconnected connection.
                                // Skip this when we're the introducer: the introducer must stay
                                // connected to mediation to coordinate new peers joining the mesh.
                                Console.WriteLine("[Mesh] Peers recovered — closing reconnected mediation connection");
                                reconnectedTcpClient.Close();
                                reconnectedTcpClient = null;
                                reconnectedStream = null;
                                reconnectedTcpBuffer = "";
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
                        reconnectedTcpBuffer = "";
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
                                    PrivateAddressString = meshIP,
                                    AuthToken = authToken
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

                // ── Introducer failover (active probe) ──────────────────────────────
                // Periodically send MeshHeartbeat to the introducer over port 51888.
                // If the introducer's NATTunnel process is alive, it responds with
                // MeshHeartbeatAck. WireGuard PersistentKeepalive (5s) keeps the tunnel
                // alive at the driver level even after the process exits, so we CANNOT
                // rely on WireGuard LastActivity — only application-level responses.
                if (!isIntroducer && reconnectedTcpClient == null &&
                    detectedNatType != NATType.Symmetric &&
                    !string.IsNullOrEmpty(introducerMeshIP) &&
                    DateTime.UtcNow - lastIntroducerProbe > introducerProbeInterval)
                {
                    // Check if the previous probe was acked
                    if (!introducerProbeAckReceived)
                    {
                        introducerMissedProbes++;
                        Console.WriteLine($"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
                    }
                    else
                    {
                        if (introducerMissedProbes > 0)
                        {
                            Console.WriteLine($"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
                        }
                        introducerMissedProbes = 0;
                    }

                    if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
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
                            introducerMissedProbes = 0;
                            Console.WriteLine("[Mesh] Reconnected to mediation as new introducer — sent join request");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to reconnect for introducer takeover: {ex.Message}");
                            reconnectedTcpClient = null;
                            reconnectedStream = null;
                            introducerMissedProbes = 0; // Reset to retry later
                        }
                    }
                    else
                    {
                        // Send a new probe to the introducer
                        introducerProbeAckReceived = false;
                        try
                        {
                            var probe = new MediationMessage(MediationMessageType.MeshHeartbeat);
                            byte[] probeBytes = Encoding.UTF8.GetBytes(probe.Serialize());
                            MeshSend(probeBytes, probeBytes.Length,
                                new IPEndPoint(IPAddress.Parse(introducerMeshIP), MeshControlPort));
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[Mesh] Failed to send introducer probe: {ex.Message}");
                        }
                    }

                    lastIntroducerProbe = DateTime.UtcNow;
                }

                // ── Local staleness fallback ─────────────────────────────────────────
                // If a peer hasn't sent any heartbeat/ack in 5 minutes, assume it's dead.
                // This catches cases where the introducer's MeshPeerRemoved was lost.
                if (!isIntroducer)
                {
                    var staleThreshold = TimeSpan.FromMinutes(5);
                    var now = DateTime.UtcNow;
                    var stalePeers = lastHeartbeatReceivedFrom
                        .Where(kvp => kvp.Key != meshIP && (now - kvp.Value) > staleThreshold)
                        .Select(kvp => kvp.Key)
                        .ToList();
                    foreach (var staleIP in stalePeers)
                    {
                        Console.WriteLine($"[Mesh] Peer {staleIP} has been silent for >{staleThreshold.TotalMinutes}m — removing locally");
                        RemoveDeadPeer(staleIP);
                    }
                }

                System.Threading.Thread.Sleep(100);
            }

            // ShutdownRequested was set (e.g. by GUI) — perform graceful shutdown
            PerformGracefulShutdown();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Mesh] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            throw;
        }
        finally
        {
            // Dispose resources so retries can rebind ports
            try { udpProxy?.Dispose(); } catch { }
            try { wireguardTunnel?.Dispose(); } catch { }
            try { tcpClient?.Dispose(); } catch { }
            try { udpClient?.Dispose(); } catch { }
        }
    }

}