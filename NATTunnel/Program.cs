using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;
using System.Text.Json;

namespace NATTunnel;

public enum MeshConnectionState { Disconnected, Connecting, Connected, Disconnecting }

public static class Program
{
    /// <summary>
    /// Set to true to request graceful shutdown (used by GUI instead of Console.CancelKeyPress).
    /// </summary>
    public static volatile bool ShutdownRequested;

    /// <summary>Current connection state, readable by GUI via HTTP.</summary>
    public static volatile MeshConnectionState ConnectionState = MeshConnectionState.Disconnected;

    /// <summary>Set to true by GUI to request disconnect (leave mesh but keep WireGuard adapter alive).</summary>
    public static volatile bool DisconnectRequested;

    /// <summary>Set to true by GUI to request reconnect after a disconnect.</summary>
    public static volatile bool ConnectRequested;

    public static void Log(string message)
    {
        Console.WriteLine($"[{DateTime.UtcNow:HH:mm:ss}] {message}");
    }

    public static void Main(string[] args)
    {
        // Normal startup
        if (!Config.CreateNewConfigPrompt())
            Environment.Exit(-1);

        if (!Config.TryLoadConfig())
        {
            Log("Failed to load config.toml");
            Log("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(-1);
        }

        try
        {
            Log($"Starting mesh mode for network: {TunnelOptions.NetworkID}");
            RunMeshMode();
        }
        catch (Exception ex)
        {
            Log($"\n[Mesh] Fatal error: {ex.Message}");
            Log(ex.StackTrace);
            Log("\nPress any key to exit...");
            Console.ReadKey();
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
        UdpClient meshControlClient = null;
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
            Log($"[Mesh] Peer ID: {peerID}, Network: {TunnelOptions.NetworkID}");

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

            // Calculate mesh IP address from peer ID (deterministic, unique per peer)
            var peerIDBytes = peerID.ToByteArray();
            var hash = System.Security.Cryptography.SHA256.HashData(peerIDBytes);
            byte octet3 = hash[0];
            byte octet4 = (byte)((hash[1] % 254) + 1); // 1-254 to avoid .0 and .255
            var meshIP = $"{TunnelOptions.MeshSubnet}.{octet3}.{octet4}";
            Log($"[Mesh] Assigned mesh IP: {meshIP}");

            // Initialize WireGuard tunnel BEFORE mediation handshake — this is expensive
            // and must NOT be recreated on mediation reconnect (causes memory leak).
            string interfaceName = $"NATTunnel-{TunnelOptions.NetworkID}";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";
            wireguardTunnel = new WireGuardTunnel(interfaceName, debugMode, isRunningAsService: false, skipTunnelCreation: true);
            wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
            Log($"[Mesh] WireGuard tunnel initialized with IP {meshIP}/16");

            // Initialize UDP proxy for mesh mode
            udpProxy = new WireGuardUdpProxy(udpClient);
            wireguardTunnel.SetUdpProxy(udpProxy);

            // Helper: extract the first complete JSON object from a string.
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

            // Read a single TCP message with timeout.
            string earlyTcpRemainder = "";
            byte[] buffer = new byte[8192];
            var endpoint = TunnelOptions.MediationEndpoint;
            Stream stream = null;

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

            // Compute auth token once — it doesn't depend on mediation state
            string authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                Encoding.UTF8.GetBytes(TunnelOptions.NetworkID + ":" + TunnelOptions.NetworkSecret)));

            // Connect to mediation, perform NAT detection, and join mesh network.
            // Retries indefinitely on failure — WireGuard is already initialized above
            // and MUST NOT be recreated (native memory leak).
            NATType detectedNatType = NATType.Unknown;
            MediationMessage joinResponse = null;

            // ── One-time mesh control resources (survive across disconnect/reconnect) ──
            const int MeshControlPort = 51888;

            // Concurrent queues for mesh control messages (producer: listener thread, consumer: main loop)
            var meshConnectionBeginQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshHeartbeatAckQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshPeerRemovedQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();
            var meshPeerLeaveQueue = new System.Collections.Concurrent.ConcurrentQueue<MediationMessage>();

            // Peer tracking dictionaries (shared between listener and main loop)
            var peerLatencyMs = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();
            var peerLastPong = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>();
            var pingSentTicks = new System.Collections.Concurrent.ConcurrentDictionary<string, long>();
            var lastHeartbeatReceivedFrom = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>();
            var peerInfoByMeshIP = new System.Collections.Concurrent.ConcurrentDictionary<string, (string peerID, string endpoint, NATType natType)>();

            // Introducer tracking state
            string introducerMeshIP = null;
            bool introducerProbeAckReceived = true;
            DateTime lastIntroducerProbe = DateTime.UtcNow;
            var introducerProbeInterval = TimeSpan.FromSeconds(TunnelOptions.ProbeIntervalSeconds);
            int introducerMissedProbes = 0;
            const int IntroducerMissedProbeThreshold = 3;

            // Bind mesh control UDP port (one-time)
            try
            {
                meshControlClient = new UdpClient(MeshControlPort);
                Log($"[Mesh] Mesh control listening on UDP port {MeshControlPort}");
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                Console.Error.WriteLine($"[Mesh] Cannot bind mesh control port {MeshControlPort}/UDP — another instance may already be running. ({ex.Message})");
                return;
            }

            // Thread-safe wrapper for meshControlClient.Send — UdpClient is not thread-safe
            object meshControlSendLock = new object();
            void MeshSend(byte[] data, int length, IPEndPoint ep)
            {
                lock (meshControlSendLock)
                {
                    meshControlClient.Send(data, length, ep);
                }
            }

            // Mesh control listener task (one-time — runs for lifetime of the process)
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
                                byte[] meshIPBytes = Encoding.UTF8.GetBytes(meshIP ?? "");
                                byte[] pongPacket = new byte[2 + meshIPBytes.Length];
                                pongPacket[0] = 0xFF;
                                pongPacket[1] = (byte)'p';
                                Buffer.BlockCopy(meshIPBytes, 0, pongPacket, 2, meshIPBytes.Length);
                                MeshSend(pongPacket, pongPacket.Length, result.RemoteEndPoint);
                            }
                            else if (result.Buffer[1] == (byte)'p')
                            {
                                long pongTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                                string responderIP = Encoding.UTF8.GetString(result.Buffer, 2, result.Buffer.Length - 2);
                                if (!string.IsNullOrEmpty(responderIP) && pingSentTicks.TryGetValue(responderIP, out long sentTicks))
                                {
                                    long elapsedMs = ((pongTicks - sentTicks) * 1000) / System.Diagnostics.Stopwatch.Frequency;
                                    peerLatencyMs[responderIP] = elapsedMs;
                                    peerLastPong[responderIP] = DateTime.UtcNow;
                                }
                            }
                            continue;
                        }

                        string json = Encoding.UTF8.GetString(result.Buffer);
                        var controlMsg = JsonSerializer.Deserialize<MediationMessage>(json);
                        if (controlMsg == null) continue;

                        if (controlMsg.ID == MediationMessageType.MeshConnectionBegin)
                        {
                            Log($"[Mesh] Received MeshConnectionBegin from {result.RemoteEndPoint}: peer {controlMsg.PeerID} at {controlMsg.EndpointString}");
                            string senderIP = result.RemoteEndPoint.Address.ToString();
                            if (string.IsNullOrEmpty(introducerMeshIP) && senderIP != meshIP)
                            {
                                introducerMeshIP = senderIP;
                                Log($"[Mesh] Learned introducer mesh IP from MeshConnectionBegin: {introducerMeshIP}");
                            }
                            meshConnectionBeginQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeat)
                        {
                            string heartbeatSenderIP = result.RemoteEndPoint.Address.ToString();
                            lastHeartbeatReceivedFrom[heartbeatSenderIP] = DateTime.UtcNow;
                            if (string.IsNullOrEmpty(introducerMeshIP) && heartbeatSenderIP != meshIP)
                            {
                                introducerMeshIP = heartbeatSenderIP;
                                Log($"[Mesh] Learned introducer mesh IP from MeshHeartbeat: {introducerMeshIP}");
                            }
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
                                        if (!peerInfoByMeshIP.TryGetValue(rMeshIP, out var existing) ||
                                            string.IsNullOrEmpty(existing.peerID) || existing.endpoint == null)
                                        {
                                            peerInfoByMeshIP[rMeshIP] = (rPeerID, rEndpoint, (NATType)rNatInt);
                                        }
                                    }
                                }
                            }
                            var pongCutoff = DateTime.UtcNow.AddSeconds(-30);
                            var connectedIPs = peerLastPong
                                .Where(kvp => kvp.Value > pongCutoff && kvp.Key != meshIP)
                                .Select(kvp => kvp.Key)
                                .ToList();
                            if (introducerMeshIP != null && !connectedIPs.Contains(introducerMeshIP))
                                connectedIPs.Add(introducerMeshIP);
                            var ack = new MediationMessage(MediationMessageType.MeshHeartbeatAck)
                            {
                                PeerID = peerID.ToString(),
                                PrivateAddressString = meshIP,
                                NATType = detectedNatType,
                                ConnectedMeshIPs = connectedIPs.ToArray()
                            };
                            byte[] ackBytes = Encoding.UTF8.GetBytes(ack.Serialize());
                            MeshSend(ackBytes, ackBytes.Length, result.RemoteEndPoint);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshHeartbeatAck)
                        {
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
                            Log($"[Mesh] Received MeshPeerRemoved: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) declared dead by introducer");
                            meshPeerRemovedQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshPeerLeave)
                        {
                            Log($"[Mesh] Received MeshPeerLeave: peer {controlMsg.PrivateAddressString} (peerID: {controlMsg.PeerID}) left gracefully");
                            meshPeerLeaveQueue.Enqueue(controlMsg);
                        }
                        else if (controlMsg.ID == MediationMessageType.MeshIntroduction)
                        {
                            // MeshIntroduction is no longer used
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"[Mesh] Mesh control listener error: {ex.Message}");
                    }
                }
            });

            // Graceful shutdown action — shared between Console.CancelKeyPress and ShutdownRequested
            void PerformGracefulShutdown()
            {
                Log("[Mesh] Graceful shutdown initiated");
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
                            Log($"[Mesh] Failed to send MeshPeerLeave to {peer.PrivateAddress}: {ex.Message}");
                        }
                    }
                    Log($"[Mesh] Sent MeshPeerLeave to {allPeers.Count()} peer(s)");
                }
                catch (Exception ex)
                {
                    Log($"[Mesh] Error sending graceful shutdown message: {ex.Message}");
                }
                ShutdownRequested = true;
            }

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                PerformGracefulShutdown();
            };

            // Guards to prevent re-starting one-time background tasks on reconnect
            bool udpDispatcherStarted = false;
            bool httpEndpointStarted = false;

            // ── Per-connect tracking state ──
            // Declared here (before outer loop) so background tasks (UDP dispatcher,
            // HTTP endpoint) keep valid closure references across disconnect/reconnect.
            // Cleared on disconnect rather than re-declared.
            // Lock for collections accessed from both the main loop and tunnel callbacks
            // (onConnectionComplete/onConnectionFailure fire on background threads).
            var meshLock = new object();
            var activePeerTunnels = new Dictionary<string, Tunnel>();
            var pendingConnectionRequests = new Dictionary<string, DateTime>();
            var activeConnectionTunnels = new Dictionary<int, Tunnel>();
            var connectionIDToPeerID = new Dictionary<int, string>();
            var peerMeshIPs = new Dictionary<int, string>();
            int pendingTunnelCount = 0;
            var deferredIntroductions = new Dictionary<string, List<MediationMessage>>();
            var completedTunnelMeshIPs = new HashSet<string>();
            var relayedPairs = new HashSet<string>();
            var lastRepairAttempt = new Dictionary<string, DateTime>();
            var repairAttemptCount = new Dictionary<string, int>();
            bool isIntroducer = false;

            // === OUTER CONNECT LOOP ===
            // Wraps mediation handshake + setup loop + mesh-control loop.
            // On disconnect, we return here to idle and wait for reconnect.
            while (!ShutdownRequested)
            {
            ConnectionState = MeshConnectionState.Connecting;
            DisconnectRequested = false;
            {
                int handshakeDelay = 5;
                for (int attempt = 1; ; attempt++)
                {
                    if (ShutdownRequested) return;
                    if (DisconnectRequested) break;
                    try
                    {
                        // 1. TCP connect (with 5s timeout so DisconnectRequested is checked promptly)
                        tcpClient = new TcpClient();
                        tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                        var connectResult = tcpClient.BeginConnect(endpoint.Address, endpoint.Port, null, null);
                        bool connected = connectResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5));
                        if (!connected || DisconnectRequested)
                        {
                            tcpClient.Close();
                            if (DisconnectRequested) break;
                            throw new System.Net.Sockets.SocketException(10060); // WSAETIMEDOUT
                        }
                        tcpClient.EndConnect(connectResult);
                        if (TunnelOptions.TlsEnabled)
                        {
                            var sslStream = new SslStream(tcpClient.GetStream(), false,
                                TunnelOptions.TlsAllowSelfSigned
                                    ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                                    : null);
                            sslStream.AuthenticateAsClient(endpoint.Address.ToString());
                            stream = sslStream;
                            Log($"[Mesh] TLS handshake complete (protocol: {sslStream.SslProtocol})");
                        }
                        else
                        {
                            stream = tcpClient.GetStream();
                        }
                        stream.ReadTimeout = 15000;
                        earlyTcpRemainder = "";

                        // 2. Wait for Connected message
                        ReadOneTcpMessage();

                        // 3. NAT type detection
                        var natTypeRequest = new MediationMessage(MediationMessageType.NATTypeRequest)
                        {
                            LocalPort = localUdpPort,
                            LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                            ClientID = peerID
                        };
                        byte[] natBuffer = Encoding.ASCII.GetBytes(natTypeRequest.Serialize());
                        stream.Write(natBuffer, 0, natBuffer.Length);

                        var natTestBegin = ReadOneTcpMessage();
                        if (natTestBegin.ID == MediationMessageType.NATTestBegin)
                        {
                            var natTestMsg = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                            byte[] natTestBuffer = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
                            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortOne));
                            udpClient.Send(natTestBuffer, natTestBuffer.Length, new IPEndPoint(endpoint.Address, natTestBegin.NATTestPortTwo));
                        }

                        var natTypeResponse = ReadOneTcpMessage();
                        if (natTypeResponse.ID == MediationMessageType.NATTypeResponse)
                        {
                            detectedNatType = natTypeResponse.NATType;
                            Log($"[Mesh] NAT type detected: {detectedNatType}");
                        }

                        // 4. Join mesh network
                        var joinRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
                        {
                            NetworkID = TunnelOptions.NetworkID,
                            PeerID = peerID.ToString(),
                            NATType = detectedNatType,
                            PrivateAddressString = meshIP,
                            AuthToken = authToken
                        };
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(joinRequest.Serialize());
                        stream.Write(sendBuffer, 0, sendBuffer.Length);

                        joinResponse = ReadOneTcpMessage();
                        if (!string.IsNullOrEmpty(joinResponse.AuthToken))
                        {
                            Console.Error.WriteLine($"[Mesh] Authentication failed: {joinResponse.AuthToken}");
                            return;
                        }

                        Log($"[Mesh] Joined network! Found {joinResponse.PeerCount} other peers");
                        handshakeDelay = 5; // Reset on success
                        break;
                    }
                    catch (Exception ex) when (!ShutdownRequested)
                    {
                        Log($"[Mesh] Mediation handshake failed: {ex.Message}");
                        try { tcpClient?.Dispose(); } catch { }
                        tcpClient = null;
                        stream = null;
                        earlyTcpRemainder = "";
                        Log($"[Mesh] Retrying in {handshakeDelay}s (attempt {attempt})...");
                        // Sleep in short intervals so DisconnectRequested is checked promptly
                        for (int ms = 0; ms < handshakeDelay * 1000 && !DisconnectRequested && !ShutdownRequested; ms += 100)
                            System.Threading.Thread.Sleep(100);
                        handshakeDelay = Math.Min(handshakeDelay * 2, 30);
                    }
                }
                if (ShutdownRequested) return;
            }

            // If disconnect was requested during handshake, skip to idle
            if (DisconnectRequested)
            {
                ConnectionState = MeshConnectionState.Disconnected;
                try { tcpClient?.Dispose(); } catch { }
                tcpClient = null; stream = null;
                Log("[Mesh] Disconnected during handshake — waiting for reconnect");
                while (!ShutdownRequested && !ConnectRequested)
                    System.Threading.Thread.Sleep(100);
                ConnectRequested = false;
                // Reload config in case settings changed while idle
                Config.TryLoadConfig();
                endpoint = TunnelOptions.MediationEndpoint;
                authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                    Encoding.UTF8.GetBytes(TunnelOptions.NetworkID + ":" + TunnelOptions.NetworkSecret)));
                continue; // Back to outer connect loop
            }

            ConnectionState = MeshConnectionState.Connected;

            // Set a short poll timeout for the main loop so it doesn't block on stream.Read()
            // while still doing heartbeats, tunnel management, etc.
            // SslStream doesn't support DataAvailable, so we use timeout-based polling instead.
            stream.ReadTimeout = 100;

            // Reset per-connect-cycle state (these survive across reconnects but need fresh values)
            introducerMeshIP = null;
            introducerProbeAckReceived = true;
            introducerMissedProbes = 0;
            lastIntroducerProbe = DateTime.UtcNow;
            // joinResponse, detectedNatType, stream, and tcpClient are all set
            // by the mediation handshake retry loop above.

            // Clear per-connect tracking state (preserves closure references for background tasks)
            activePeerTunnels.Clear();
            pendingConnectionRequests.Clear();
            activeConnectionTunnels.Clear();
            connectionIDToPeerID.Clear();
            peerMeshIPs.Clear();
            pendingTunnelCount = 0;
            deferredIntroductions.Clear();
            completedTunnelMeshIPs.Clear();
            relayedPairs.Clear();
            lastRepairAttempt.Clear();
            repairAttemptCount.Clear();
            isIntroducer = false;
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
                        Log($"[Mesh] Introducer mesh IP: {introducerMeshIP} (peer {pid})");
                    }
                }
                Log($"[Mesh] Cached {peerInfoByMeshIP.Count} peer(s) from initial join response");
            }

            // Detect mesh IP collision with an existing peer and reassign if needed.
            // The hash space is only 16 bits (~65K IPs), so collisions become probable at ~300+ peers.
            // We try successive pairs of SHA256 bytes (offset 0, 2, 4, ...) until we find a free slot.
            var takenMeshIPs = new HashSet<string>(peerInfoByMeshIP.Keys);
            if (takenMeshIPs.Contains(meshIP))
            {
                string originalMeshIP = meshIP;
                bool resolved = false;
                for (int offset = 2; offset < hash.Length - 1; offset += 2)
                {
                    byte c3 = hash[offset];
                    byte c4 = (byte)((hash[offset + 1] % 254) + 1);
                    string candidate = $"{TunnelOptions.MeshSubnet}.{c3}.{c4}";
                    if (!takenMeshIPs.Contains(candidate))
                    {
                        meshIP = candidate;
                        resolved = true;
                        break;
                    }
                }
                if (resolved)
                {
                    Log($"[Mesh] WARNING: Mesh IP collision detected ({originalMeshIP} already taken). Reassigning to {meshIP}.");
                    wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
                }
                else
                {
                    Log($"[Mesh] WARNING: Mesh IP collision detected ({originalMeshIP} already taken) and no free slot found in hash offsets. Keeping original IP — connectivity may be impaired.");
                }
            }

            // Helper method to process discovered peers and send connection requests
            void ProcessDiscoveredPeers(object[] peers, Stream targetStream = null)
            {
                if (peers == null || peers.Length == 0)
                    return;

                // Use the provided stream, or fall back to the primary loop's stream
                var writeStream = targetStream ?? stream;

                Log($"[Mesh] Discovered {peers.Length} peer(s) in network:");
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
                    Log($"[Mesh] MeshConnectionBegin missing PeerID — skipping");
                    return;
                }
                // Relay mode only needs mesh IP + introducer IP, not endpoint
                if (!cbMsg.IsRelay && string.IsNullOrEmpty(remoteEndpoint))
                {
                    Log($"[Mesh] MeshConnectionBegin missing endpoint (non-relay) — skipping");
                    return;
                }

                // Cache peer info for heartbeat repair — ensures the failover introducer
                // knows NAT types of peers that joined after this peer's initial connection.
                if (!string.IsNullOrEmpty(remoteMeshIP))
                {
                    peerInfoByMeshIP[remoteMeshIP] = (remotePeerID, remoteEndpoint, remotePeerNatType);
                }

                // Skip if a connection attempt is already in progress for this peer.
                // Relay MeshConnectionBegin messages are always allowed since they just add a
                // WireGuard route and don't create tunnels.
                // Stale pending requests (> StaleTimeoutSeconds) are also allowed through.
                if (!cbMsg.IsRelay && pendingConnectionRequests.TryGetValue(remotePeerID, out var pendingTime))
                {
                    if ((DateTime.UtcNow - pendingTime).TotalSeconds < TunnelOptions.StaleTimeoutSeconds)
                    {
                        Log($"[Mesh] Ignoring MeshConnectionBegin for {remotePeerID} — connection already pending ({(int)(DateTime.UtcNow - pendingTime).TotalSeconds}s ago)");
                        return;
                    }
                    // Stale pending request — clean up and allow the new attempt
                    Log($"[Mesh] Clearing stale pending request for {remotePeerID} ({(int)(DateTime.UtcNow - pendingTime).TotalSeconds}s old) — allowing new attempt");
                    pendingConnectionRequests.Remove(remotePeerID);
                }

                bool alreadyTracked = activePeerTunnels.ContainsKey(remotePeerID) ||
                    (!string.IsNullOrEmpty(remoteMeshIP) && activePeerTunnels.ContainsKey(remoteMeshIP));
                bool wasRelayed = !string.IsNullOrEmpty(remoteMeshIP) &&
                    completedTunnelMeshIPs.Contains(remoteMeshIP) && !alreadyTracked;

                // If this is a relay MeshConnectionBegin for a peer that's already relayed,
                // check if the relay route still exists in WireGuard before skipping.
                // The route may have been lost (peer removed, WireGuard reset) while
                // completedTunnelMeshIPs still had the entry — let it through to re-establish.
                if (cbMsg.IsRelay && wasRelayed && !string.IsNullOrEmpty(remoteMeshIP))
                {
                    var relayRoutes = wireguardTunnel.GetRelayRoutes();
                    bool routeExists = relayRoutes.ContainsKey(IPAddress.Parse(remoteMeshIP));
                    if (routeExists)
                    {
                        Log($"[Mesh] Ignoring duplicate relay MeshConnectionBegin for {remotePeerID} ({remoteMeshIP}) — relay route confirmed in WireGuard");
                        return;
                    }
                    // Route is gone — clear stale tracking and let the message re-establish it
                    Log($"[Mesh] Relay route for {remoteMeshIP} missing from WireGuard — allowing re-establishment");
                    completedTunnelMeshIPs.Remove(remoteMeshIP);
                    wasRelayed = false;
                }

                if ((alreadyTracked || wasRelayed) && !string.IsNullOrEmpty(remoteMeshIP))
                {
                    // Clean up the old connection (direct or relay) to allow reconnect
                    Log($"[Mesh] Peer {remotePeerID} ({remoteMeshIP}) being re-introduced — cleaning up old connection (relay={wasRelayed})");
                    metricReconnects++;
                    RemoveDeadPeer(remoteMeshIP);
                }

                Log($"[Mesh] Processing MeshConnectionBegin: peer {remotePeerID} at {remoteEndpoint} (NAT: {remotePeerNatType}, meshIP: {remoteMeshIP}, relay: {cbMsg.IsRelay})");

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
                            Log($"[Mesh] Relay route added: {remoteMeshIP} via introducer {introducerIP} — peer {remotePeerID} is reachable");
                            metricRelayRoutesEstablished++;
                        }
                        else
                        {
                            Log($"[Mesh] Failed to add relay route for {remoteMeshIP} via introducer {introducerIP}");
                        }
                    }
                    else
                    {
                        Log($"[Mesh] Relay MeshConnectionBegin missing IntroducerMeshIP — cannot set up relay route");
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
                        Log($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} failed — cleaning up for future retry");
                        lock (meshLock)
                        {
                            activeConnectionTunnels.Remove(capturedPeerID.GetHashCode());
                            pendingConnectionRequests.Remove(capturedPeerID);
                            activePeerTunnels.Remove(capturedPeerID);
                            if (!string.IsNullOrEmpty(capturedMeshIP))
                                activePeerTunnels.Remove(capturedMeshIP);
                        }
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
                        Log($"[Mesh] Introducer-relayed tunnel for {capturedPeerID} WireGuard established");
                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                        System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                        lock (meshLock)
                        {
                            pendingConnectionRequests.Remove(capturedPeerID);
                            if (!string.IsNullOrEmpty(capturedMeshIP))
                            {
                                completedTunnelMeshIPs.Add(capturedMeshIP);

                                if (deferredIntroductions.TryGetValue(capturedMeshIP, out var deferred) && deferred.Count > 0)
                                {
                                    Log($"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) for {capturedMeshIP}");
                                    foreach (var deferredMsg in deferred)
                                    {
                                        string targetIP = !string.IsNullOrEmpty(deferredMsg.IntroducerMeshIP) && !deferredMsg.IsRelay
                                            ? deferredMsg.IntroducerMeshIP : capturedMeshIP;
                                        try
                                        {
                                            if (targetIP != capturedMeshIP)
                                                deferredMsg.IntroducerMeshIP = null;
                                            byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                            MeshSend(deferredBytes, deferredBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(targetIP), MeshControlPort));
                                            Log($"[Mesh] Sent deferred MeshConnectionBegin to {targetIP}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Mesh] Failed to send deferred MeshConnectionBegin to {targetIP}: {ex.Message}");
                                        }
                                    }
                                    deferredIntroductions.Remove(capturedMeshIP);
                                }
                            }
                        }
                    }
                );

                peerTunnel.SetWireGuardTunnel(wireguardTunnel);

                // Track the tunnel
                lock (meshLock) { activeConnectionTunnels[capturedPeerID.GetHashCode()] = peerTunnel; }
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
                        Log($"[Mesh] Hole-punching started for {capturedPeerID} at {remoteEndpoint}");
                    }
                    catch (Exception ex)
                    {
                        Log($"[Mesh] Error starting introducer-relayed tunnel for {capturedPeerID}: {ex.Message}");
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
                Log("[Mesh] No other peers in network yet - waiting for others to join...");
            }

            // Keep connection alive and listen for ConnectionBegin messages
            Log("[Mesh] Mesh networking active. Waiting for connections...");
            Log("[Mesh] Press Ctrl+C to exit.");

            // Set to true when the server designates us as the introducer (via MeshIntroduceRequest
            // or via IntroducerPeerID in MeshJoinResponse). Introducers must keep the mediation
            // TCP connection alive indefinitely so the server can push future requests to us.

            // Check if the server already told us we're the introducer in the join response.
            // Also: if we're non-symmetric and no other non-symmetric peer exists in the network,
            // we'll definitely be the introducer for the next joiner — stay connected proactively.
            if (!string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                joinResponse.IntroducerPeerID == peerID.ToString())
            {
                isIntroducer = true;
                Log("[Mesh] Server designated us as the introducer in join response");
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
                    Log("[Mesh] We're the only non-symmetric peer — staying connected as potential introducer");
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
            DateTime lastNotReadyLog = DateTime.MinValue;
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

                Log($"[Mesh] Removing dead peer {deadMeshIP} (peerID: {deadPeerID ?? "unknown"})");

                // Remove from WireGuard
                var deadIPAddr = IPAddress.Parse(deadMeshIP);
                var wgPeer = wireguardTunnel.GetPeer(deadIPAddr);
                if (wgPeer != null)
                {
                    wireguardTunnel.RemovePeer(wgPeer.ConnectionId);
                    Log($"[Mesh] Removed WireGuard peer {deadMeshIP}");
                }

                // Remove relay routes through this peer (as gateway)
                var removedRelays = wireguardTunnel.RemoveRelayRoutesViaGateway(deadIPAddr);
                if (removedRelays.Count > 0)
                {
                    metricRelayRoutesRemoved += removedRelays.Count;
                    Log($"[Mesh] Removed {removedRelays.Count} relay route(s) via {deadMeshIP}");
                }

                // Remove relay route targeting this peer (was relayed through a gateway)
                if (wireguardTunnel.RemoveRelayRouteForPeer(deadIPAddr))
                {
                    metricRelayRoutesRemoved++;
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
                    lock (meshLock) { activeConnectionTunnels.Remove(key); }
                }

                // Clean up relayedPairs containing this mesh IP
                relayedPairs.RemoveWhere(pair => pair.Contains(deadMeshIP));

                // Clean up latency tracking
                peerLatencyMs.TryRemove(deadMeshIP, out _);
                peerLastPong.TryRemove(deadMeshIP, out _);
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
                        UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds,
                        ConnectionState = ConnectionState.ToString()
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

                    // Snapshot pending/active state for thread-safe status determination
                    var pendingPeerIDs = new HashSet<string>(pendingConnectionRequests.Keys);
                    var activePeerIDs = new HashSet<string>(activePeerTunnels.Keys);
                    var completedSet = new HashSet<string>(completedSnapshot);

                    // Merge all known peers: reachable (WireGuard) + known (peerInfo roster)
                    var allKnownMeshIPs = new HashSet<string>(reachableMeshIPs);
                    foreach (var kv in peerInfoDict)
                        allKnownMeshIPs.Add(kv.Key);

                    foreach (var peerMeshIP in allKnownMeshIPs)
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

                        // Determine connection status.
                        // A peer is "completed" if our callback recorded it, OR if WireGuard
                        // already has it as a reachable peer (callback may have been lost).
                        string status;
                        bool isCompleted = completedSet.Contains(peerMeshIP)
                            || (reachableMeshIPs.Contains(peerMeshIP) && activePeerIDs.Contains(peerMeshIP));
                        bool isPending = !isCompleted && (
                            (!string.IsNullOrEmpty(peerId) && pendingPeerIDs.Contains(peerId))
                            || activePeerIDs.Contains(peerMeshIP)
                            || (!string.IsNullOrEmpty(peerId) && activePeerIDs.Contains(peerId)));

                        if (isCompleted)
                            status = isRelayed ? "Relayed" : "Connected";
                        else if (isPending || reachableMeshIPs.Contains(peerMeshIP))
                            status = "Connecting";
                        else
                            status = "Not Connected";

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
                            RelayedVia = relayedVia.TryGetValue(peerMeshIP, out var gw) ? gw : null,
                            Status = status
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
                    Log($"[Mesh] Error building mesh state: {ex.Message}");
                    return new MeshState
                    {
                        OwnMeshIP = meshIP,
                        OwnPeerID = peerID.ToString(),
                        IsIntroducer = isIntroducer,
                        NATType = detectedNatType.ToString(),
                        UptimeSeconds = (long)(DateTime.UtcNow - meshStartTime).TotalSeconds,
                        ConnectionState = ConnectionState.ToString()
                    };
                }
            }

            // Helper: check all peer pairs for broken links and repair them.
            // Returns the number of repair messages sent.
            int RepairBrokenLinks(
                List<string> targetList,
                Dictionary<string, HashSet<string>> currentHeartbeatAcks,
                System.Net.Sockets.TcpClient mediationClient,
                Stream mediationStream)
            {
                int repairCount = 0;
                for (int i = 0; i < targetList.Count; i++)
                {
                    for (int j = i + 1; j < targetList.Count; j++)
                    {
                        string ipA = targetList[i];
                        string ipB = targetList[j];

                        bool aReportsB = currentHeartbeatAcks.ContainsKey(ipA) && currentHeartbeatAcks[ipA].Contains(ipB);
                        bool bReportsA = currentHeartbeatAcks.ContainsKey(ipB) && currentHeartbeatAcks[ipB].Contains(ipA);

                        string sortedA = string.Compare(ipA, ipB, StringComparison.Ordinal) < 0 ? ipA : ipB;
                        string sortedB = sortedA == ipA ? ipB : ipA;
                        string pairKey = $"{sortedA}|{sortedB}";

                        // Clear tracking for healthy pairs
                        if (aReportsB && bReportsA)
                        {
                            if (repairAttemptCount.Remove(pairKey))
                                lastRepairAttempt.Remove(pairKey);
                            continue;
                        }

                        if (!aReportsB || !bReportsA)
                        {
                            // Cooldown check
                            if (lastRepairAttempt.TryGetValue(pairKey, out var lastAttempt) &&
                                DateTime.UtcNow - lastAttempt < repairCooldown)
                                continue;

                            // For relayed pairs, re-establish the relay instead of hole-punching
                            if (relayedPairs.Contains(pairKey))
                            {
                                // Only re-establish if we have tunnels to both peers
                                if (!completedTunnelMeshIPs.Contains(ipA) || !completedTunnelMeshIPs.Contains(ipB))
                                    continue;

                                bool hasInfoA = peerInfoByMeshIP.TryGetValue(ipA, out var relayInfoA);
                                bool hasInfoB = peerInfoByMeshIP.TryGetValue(ipB, out var relayInfoB);
                                if (!hasInfoA || !hasInfoB) continue;

                                Log($"[Mesh] Heartbeat: relayed pair {ipA} <-> {ipB} broken (aReportsB={aReportsB}, bReportsA={bReportsA}) — re-establishing relay");

                                wireguardTunnel.EnableForwarding();

                                // Re-send relay MeshConnectionBegin to both peers
                                if (!aReportsB)
                                {
                                    var relayToA = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                    {
                                        PeerID = relayInfoB.peerID ?? "",
                                        EndpointString = relayInfoB.endpoint,
                                        NATType = relayInfoB.natType,
                                        PrivateAddressString = ipB,
                                        IsRelay = true,
                                        IntroducerMeshIP = meshIP
                                    };
                                    try
                                    {
                                        byte[] rBytes = Encoding.UTF8.GetBytes(relayToA.Serialize());
                                        MeshSend(rBytes, rBytes.Length,
                                            new IPEndPoint(IPAddress.Parse(ipA), MeshControlPort));
                                        repairCount++;
                                    }
                                    catch (Exception ex)
                                    {
                                        Log($"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}");
                                    }
                                }
                                if (!bReportsA)
                                {
                                    var relayToB = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                    {
                                        PeerID = relayInfoA.peerID ?? "",
                                        EndpointString = relayInfoA.endpoint,
                                        NATType = relayInfoA.natType,
                                        PrivateAddressString = ipA,
                                        IsRelay = true,
                                        IntroducerMeshIP = meshIP
                                    };
                                    try
                                    {
                                        byte[] rBytes = Encoding.UTF8.GetBytes(relayToB.Serialize());
                                        MeshSend(rBytes, rBytes.Length,
                                            new IPEndPoint(IPAddress.Parse(ipB), MeshControlPort));
                                        repairCount++;
                                    }
                                    catch (Exception ex)
                                    {
                                        Log($"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                                    }
                                }

                                lastRepairAttempt[pairKey] = DateTime.UtcNow;
                                continue;
                            }

                            // Only repair if we have completed tunnels to BOTH peers.
                            // If a peer is reconnecting (e.g. NAT type changed), its completedTunnelMeshIPs
                            // entry is cleared and we should wait for the new tunnel to complete before
                            // attempting repair — otherwise we'd send stale endpoint/NAT info.
                            if (!completedTunnelMeshIPs.Contains(ipA) || !completedTunnelMeshIPs.Contains(ipB))
                                continue;

                            bool hasA = peerInfoByMeshIP.TryGetValue(ipA, out var infoA);
                            bool hasB = peerInfoByMeshIP.TryGetValue(ipB, out var infoB);

                            if (!hasA || !hasB)
                            {
                                Log($"[Mesh] Heartbeat: missing peer info for pair {ipA}(known={hasA}) <-> {ipB}(known={hasB}) — peerInfoByMeshIP has {peerInfoByMeshIP.Count} entries");
                                continue;
                            }

                            // Track attempt count for escalation
                            repairAttemptCount.TryGetValue(pairKey, out int attempts);
                            attempts++;
                            repairAttemptCount[pairKey] = attempts;

                            bool bothSymmetric = infoA.natType == NATType.Symmetric && infoB.natType == NATType.Symmetric;

                            // Escalation: after MaxRepairAttempts, use mediation server for fresh NAT traversal
                            if (attempts > TunnelOptions.MaxRepairAttempts)
                            {
                                Log($"[Mesh] Repair escalation ({attempts} attempts): {ipA} <-> {ipB} — requesting fresh NAT traversal via mediation");
                                if (mediationClient != null && mediationClient.Connected)
                                {
                                    if (!string.IsNullOrEmpty(infoA.peerID) && !pendingConnectionRequests.ContainsKey(infoA.peerID))
                                    {
                                        try
                                        {
                                            var req = new MediationMessage(MediationMessageType.ConnectionRequest)
                                            {
                                                PeerID = infoA.peerID,
                                                NATType = detectedNatType
                                            };
                                            byte[] buf = Encoding.ASCII.GetBytes(req.Serialize());
                                            mediationStream.Write(buf, 0, buf.Length);
                                            mediationStream.Flush();
                                            pendingConnectionRequests[infoA.peerID] = DateTime.UtcNow;
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Mesh] Failed to send escalation ConnectionRequest for {ipA}: {ex.Message}");
                                        }
                                    }
                                    if (!string.IsNullOrEmpty(infoB.peerID) && !pendingConnectionRequests.ContainsKey(infoB.peerID))
                                    {
                                        try
                                        {
                                            var req = new MediationMessage(MediationMessageType.ConnectionRequest)
                                            {
                                                PeerID = infoB.peerID,
                                                NATType = detectedNatType
                                            };
                                            byte[] buf = Encoding.ASCII.GetBytes(req.Serialize());
                                            mediationStream.Write(buf, 0, buf.Length);
                                            mediationStream.Flush();
                                            pendingConnectionRequests[infoB.peerID] = DateTime.UtcNow;
                                            repairCount++;
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Mesh] Failed to send escalation ConnectionRequest for {ipB}: {ex.Message}");
                                        }
                                    }
                                }
                                lastRepairAttempt[pairKey] = DateTime.UtcNow;
                            }
                            else if (bothSymmetric)
                            {
                                Log($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected (both symmetric) — re-establishing relay (attempt {attempts})");

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
                                    Log($"[Mesh] Failed to send relay repair to {ipA}: {ex.Message}");
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
                                    Log($"[Mesh] Failed to send relay repair to {ipB}: {ex.Message}");
                                }

                                relayedPairs.Add(pairKey);
                                lastRepairAttempt[pairKey] = DateTime.UtcNow;
                            }
                            else
                            {
                                // Non-symmetric pair — re-introduce with direct hole-punch
                                bool hasWgA = wireguardTunnel.GetPeer(IPAddress.Parse(ipA)) != null;
                                bool hasWgB = wireguardTunnel.GetPeer(IPAddress.Parse(ipB)) != null;
                                if (!hasWgA || !hasWgB)
                                {
                                    Log($"[Mesh] Skipping repair for {ipA} <-> {ipB} — no WireGuard tunnel to {(!hasWgA ? ipA : ipB)}");
                                    continue;
                                }

                                Log($"[Mesh] Heartbeat: {ipA} <-> {ipB} disconnected — re-introducing (attempt {attempts})");

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
                                        Log($"[Mesh] Failed to send repair MeshConnectionBegin to {ipA}: {ex.Message}");
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
                                        Log($"[Mesh] Failed to send repair MeshConnectionBegin to {ipB}: {ex.Message}");
                                    }
                                }
                                lastRepairAttempt[pairKey] = DateTime.UtcNow;
                            }
                        }
                    }
                }

                // Check that each peer can reach US (the introducer).
                foreach (var ip in targetList)
                {
                    if (!currentHeartbeatAcks.ContainsKey(ip))
                        continue;
                    if (!currentHeartbeatAcks[ip].Contains(meshIP))
                    {
                        Log($"[Mesh] Heartbeat: peer {ip} cannot reach introducer ({meshIP}) — requesting re-connection via mediation");
                        if (mediationClient != null && mediationClient.Connected &&
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
                                mediationStream.Write(reconnBuf, 0, reconnBuf.Length);
                                mediationStream.Flush();
                                pendingConnectionRequests[lostPeerInfo.peerID] = DateTime.UtcNow;
                                repairCount++;
                            }
                            catch (Exception ex)
                            {
                                Log($"[Mesh] Failed to send re-connection request for {ip}: {ex.Message}");
                            }
                        }
                    }
                }

                return repairCount;
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
            if (!udpDispatcherStarted) { udpDispatcherStarted = true;
            System.Threading.Tasks.Task.Run(() =>
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                Log("[Mesh] Shared UDP dispatcher started");
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
                            lock (meshLock)
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
                                    Log($"[Mesh] Error dispatching packet to tunnel: {ex.Message}");
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
                        Log($"[Mesh] UDP dispatcher error: {ex.Message}");
                    }
                }
            });
            } // end udpDispatcherStarted guard

            // HTTP status endpoint for mesh state queries (used by GUI and CLI tools)
            if (!httpEndpointStarted) { httpEndpointStarted = true;
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var httpListener = new HttpListener();
                    httpListener.Prefixes.Add("http://localhost:51889/");
                    httpListener.Start();
                    Log("[Mesh] HTTP status endpoint listening on http://localhost:51889/status");

                    while (true)
                    {
                        try
                        {
                            var context = httpListener.GetContext();
                            var rawUrl = context.Request.RawUrl;
                            var method = context.Request.HttpMethod;

                            if (method == "GET" && rawUrl == "/status")
                            {
                                var meshState = GetMeshState();
                                var json = JsonSerializer.Serialize(meshState, new JsonSerializerOptions { WriteIndented = true });
                                byte[] buffer = Encoding.UTF8.GetBytes(json);

                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = buffer.Length;
                                context.Response.OutputStream.Write(buffer, 0, buffer.Length);
                                context.Response.OutputStream.Close();
                            }
                            else if (method == "POST" && rawUrl == "/disconnect")
                            {
                                DisconnectRequested = true;
                                byte[] resp = Encoding.UTF8.GetBytes("{\"status\":\"disconnecting\"}");
                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = resp.Length;
                                context.Response.OutputStream.Write(resp, 0, resp.Length);
                                context.Response.OutputStream.Close();
                            }
                            else if (method == "POST" && rawUrl == "/connect")
                            {
                                ConnectRequested = true;
                                byte[] resp = Encoding.UTF8.GetBytes("{\"status\":\"connecting\"}");
                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = resp.Length;
                                context.Response.OutputStream.Write(resp, 0, resp.Length);
                                context.Response.OutputStream.Close();
                            }
                            else if (method == "POST" && rawUrl == "/shutdown")
                            {
                                ShutdownRequested = true;
                                byte[] resp = Encoding.UTF8.GetBytes("{\"status\":\"shutting_down\"}");
                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = resp.Length;
                                context.Response.OutputStream.Write(resp, 0, resp.Length);
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
                            Log($"[Mesh] HTTP endpoint error: {ex.Message}");
                        }
                    }

                    httpListener.Stop();
                }
                catch (Exception ex)
                {
                    Log($"[Mesh] Failed to start HTTP status endpoint on port 51889 — another instance may already be running. ({ex.Message})");
                }
            });
            } // end httpEndpointStarted guard

            // Track consecutive failed introducer connection retries.
            // After too many failures, break out to force a fresh mediation reconnection.
            int introducerRetryCount = 0;
            const int MaxIntroducerRetries = 5;

            // Message loop - create Tunnel instances when ConnectionBegin arrives.
            // Non-introducer peers disconnect once their initial connections are established
            // and reconnect transiently for each future introduced peer.
            // The introducer peer stays connected permanently to receive MeshIntroduceRequests.
            while (!ShutdownRequested && !DisconnectRequested)
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
                    // pendingConnectionRequests = waiting for MeshConnectionBegin from server (network dependency)
                    // pendingTunnelCount = WireGuard setup in progress locally — don't block mediation disconnect
                    // if a tunnel callback got lost; if the peer is in activePeerTunnels it's connected enough.
                    bool noPendingWork = pendingConnectionRequests.Count == 0;
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
                        (DateTime.UtcNow - lastNotReadyLog).TotalSeconds >= 10)
                    {
                        lastNotReadyLog = DateTime.UtcNow;
                        Log($"[Mesh] Not ready to disconnect: noPendingWork={noPendingWork}(pending={pendingConnectionRequests.Count},tunnels={pendingTunnelCount}), established={hasEstablishedTunnels}(count={activePeerTunnels.Count}), introducerPath={hasIntroducerPath}(introducerIP={introducerMeshIP ?? "null"},completed={completedTunnelMeshIPs.Count},introducerPeerID={joinResponse.IntroducerPeerID ?? "null"})");
                    }

                    if (readyToDisconnect && disconnectAfter == null)
                    {
                        int gracePeriod = detectedNatType != NATType.Symmetric ? TunnelOptions.GracePeriodSecondsNonSymmetric : TunnelOptions.GracePeriodSecondsSymmetric;
                        disconnectAfter = DateTime.UtcNow.AddSeconds(gracePeriod);
                        Log($"[Mesh] All initial connections established — grace period started ({gracePeriod}s)");
                    }
                    else if (!readyToDisconnect && disconnectAfter != null)
                    {
                        // New connection arrived during grace period — reset timer
                        disconnectAfter = null;
                        Log("[Mesh] New connection activity — grace period reset");
                    }
                    else if (readyToDisconnect && disconnectAfter != null && DateTime.UtcNow > disconnectAfter.Value)
                    {
                        Log("[Mesh] Grace period elapsed — disconnecting from mediation server");
                        tcpClient.Close();
                        break;
                    }
                }

                // Bail if the connection dropped unexpectedly during setup
                if (!tcpClient.Connected)
                {
                    if (isIntroducer)
                        Log("[Mesh] Mediation server connection lost — introducer role ended");
                    else
                        Log("[Mesh] TCP connection to mediation server lost during setup");
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
                        Log($"[Mesh] Removed stale pending connection request for {staleID} (no response in {staleTimeout.TotalSeconds}s)");
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
                        Log($"[Mesh] Keep-alive write failed, connection lost: {ex.Message}");
                        break;
                    }
                }

                // Periodic peer discovery: if we have no WireGuard peers and no pending
                // connections, re-send MeshJoinRequest to discover newly available peers.
                if (tcpClient.Connected && activePeerTunnels.Count == 0 &&
                    pendingConnectionRequests.Count == 0 && pendingTunnelCount == 0 &&
                    DateTime.UtcNow - lastPeerDiscovery > peerDiscoveryInterval)
                {
                    Log("[Mesh] No active peers — sending periodic discovery request");
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
                        Log($"[Mesh] Discovery write failed, connection lost: {ex.Message}");
                        break;
                    }
                }

                // Retry connecting to the introducer if we don't have a tunnel to it yet.
                // The initial attempt may fail (e.g. hole-punch timeout) but we must stay
                // connected to mediation and keep retrying until the introducer link is up,
                // otherwise we can't receive MeshConnectionBegin for future peers.
                // After MaxIntroducerRetries failures, force a full reconnection to mediation
                // to get fresh endpoint info.
                if (!isIntroducer && tcpClient.Connected &&
                    !string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                    !activePeerTunnels.ContainsKey(joinResponse.IntroducerPeerID) &&
                    !(introducerMeshIP != null && activePeerTunnels.ContainsKey(introducerMeshIP)) &&
                    !pendingConnectionRequests.ContainsKey(joinResponse.IntroducerPeerID) &&
                    pendingTunnelCount == 0)
                {
                    introducerRetryCount++;
                    if (introducerRetryCount > MaxIntroducerRetries)
                    {
                        Log($"[Mesh] Introducer connection failed after {MaxIntroducerRetries} retries — disconnecting to force fresh mediation reconnection");
                        introducerRetryCount = 0;
                        try { tcpClient.Close(); } catch { }
                        break; // Break to mesh-control-only loop; isolation detection will reconnect
                    }

                    Log($"[Mesh] Retrying connection to introducer {joinResponse.IntroducerPeerID} (attempt {introducerRetryCount}/{MaxIntroducerRetries})");
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
                        Log($"[Mesh] Introducer retry write failed: {ex.Message}");
                        break;
                    }
                }
                // Reset retry counter when we have a working introducer tunnel
                else if (!isIntroducer &&
                    !string.IsNullOrEmpty(joinResponse.IntroducerPeerID) &&
                    (activePeerTunnels.ContainsKey(joinResponse.IntroducerPeerID) ||
                     (introducerMeshIP != null && activePeerTunnels.ContainsKey(introducerMeshIP))))
                {
                    if (introducerRetryCount > 0)
                    {
                        Log($"[Mesh] Introducer connection restored after {introducerRetryCount} retries");
                        introducerRetryCount = 0;
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
                        Log($"[Mesh] Peer {leaveMsg.PrivateAddressString} left gracefully");
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
                        Log($"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
                    }
                    else
                    {
                        if (introducerMissedProbes > 0)
                            Log($"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
                        introducerMissedProbes = 0;
                    }

                    if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
                    {
                        Log("[Mesh] Introducer confirmed dead (detected in primary loop) — taking over as introducer");
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
                                PrivateAddressString = meshIP,
                                AuthToken = authToken
                            };
                            byte[] joinBytes = Encoding.ASCII.GetBytes(joinReq.Serialize());
                            stream.Write(joinBytes, 0, joinBytes.Length);
                            stream.Flush();
                            Log("[Mesh] Re-registered with mediation as new introducer");
                        }
                        catch (Exception ex)
                        {
                            Log($"[Mesh] Failed to re-register as introducer: {ex.Message}");
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
                        catch (Exception)
                        {
                            // Probe send failure typically means the route to the dead introducer
                            // has been pulled. The missed-probe counter will reach threshold and
                            // we'll trigger takeover — no need to log per-attempt noise.
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
                            Log($"[Mesh] Failed to send heartbeat to {peerIP}: {ex.Message}");
                        }
                    }

                    if (heartbeatTargets.Count > 1)
                    {
                        heartbeatAckDeadline = DateTime.UtcNow.AddSeconds(5);
                        heartbeatSentTime = DateTime.UtcNow;
                        metricHeartbeatsSent++;
                        Log($"[Mesh] Heartbeat sent to {heartbeatTargets.Count} peer(s), collecting acks...");
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
                        Log($"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

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
                                Log($"[Mesh] Peer {ip} missed heartbeat ({heartbeatMissCount[ip]}/{PeerDeadThreshold})");
                                if (heartbeatMissCount[ip] >= PeerDeadThreshold)
                                {
                                    // Don't declare dead if we have a pending tunnel — symmetric NAT
                                    // hole-punching can take longer than the heartbeat window.
                                    string peerPID = peerInfoByMeshIP.TryGetValue(ip, out var pi) ? pi.peerID : null;
                                    bool hasPendingTunnel = (!string.IsNullOrEmpty(peerPID) && activePeerTunnels.ContainsKey(peerPID)) ||
                                                            activePeerTunnels.ContainsKey(ip) ||
                                                            (!string.IsNullOrEmpty(peerPID) && pendingConnectionRequests.ContainsKey(peerPID));
                                    if (hasPendingTunnel)
                                    {
                                        Log($"[Mesh] Peer {ip} would be dead but has pending tunnel — deferring removal");
                                        heartbeatMissCount[ip] = 0; // Reset so we don't immediately re-trigger
                                        continue;
                                    }
                                    deadPeers.Add(ip);
                                }
                            }
                        }
                        foreach (var deadIP in deadPeers)
                        {
                            metricPeersLost++;
                            Log($"[Mesh] Peer {deadIP} declared dead after {PeerDeadThreshold} consecutive missed heartbeats");
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

                        // Check every pair of peers for missing connectivity and repair
                        var targetList = heartbeatTargets.Where(ip => !deadPeers.Contains(ip)).ToList();
                        int repairCount = RepairBrokenLinks(targetList, heartbeatAcks, tcpClient, stream);
                        if (repairCount > 0)
                            Log($"[Mesh] Heartbeat: sent {repairCount} repair message(s)");

                        // Retry connecting to peers that are known but never got a completed tunnel.
                        // This handles the case where the initial connection attempt failed (e.g. hole-punch
                        // timeout) and the peer is stuck with no WireGuard tunnel to the introducer.
                        if (tcpClient.Connected)
                        {
                            foreach (var kvp in peerInfoByMeshIP)
                            {
                                string peerMeshIP = kvp.Key;
                                if (peerMeshIP == meshIP) continue; // Skip self
                                if (completedTunnelMeshIPs.Contains(peerMeshIP)) continue; // Already connected
                                if (deadPeers.Contains(peerMeshIP)) continue; // Just declared dead
                                if (string.IsNullOrEmpty(kvp.Value.peerID)) continue;
                                if (pendingConnectionRequests.ContainsKey(kvp.Value.peerID)) continue; // Already pending
                                if (activePeerTunnels.ContainsKey(kvp.Value.peerID) || activePeerTunnels.ContainsKey(peerMeshIP)) continue; // Tunnel in progress

                                Log($"[Mesh] Heartbeat: peer {peerMeshIP} has no completed tunnel — requesting reconnection via mediation");
                                try
                                {
                                    var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                                    {
                                        PeerID = kvp.Value.peerID,
                                        NATType = detectedNatType
                                    };
                                    byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                                    stream.Write(reconnBuf, 0, reconnBuf.Length);
                                    stream.Flush();
                                    pendingConnectionRequests[kvp.Value.peerID] = DateTime.UtcNow;
                                }
                                catch (Exception ex)
                                {
                                    Log($"[Mesh] Failed to send reconnection request for {peerMeshIP}: {ex.Message}");
                                }
                            }
                        }

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
                    // Expire stale latency entries (no pong in 30s)
                    var staleCutoff = DateTime.UtcNow.AddSeconds(-30);
                    foreach (var kvp in peerLastPong)
                    {
                        if (kvp.Value < staleCutoff)
                        {
                            peerLatencyMs.TryRemove(kvp.Key, out _);
                            peerLastPong.TryRemove(kvp.Key, out _);
                        }
                    }

                    lastPingTime = DateTime.UtcNow;
                }

                try
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        Log("[Mesh] Mediation server closed connection");
                        break;
                    }
                    tcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                }
                catch (IOException) { } // read timeout — no data available this iteration

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
                            Log($"[Mesh] Could not parse JSON object: {parseEx.Message}");
                            jsonStartIndex = jsonObjEnd + 1;
                            continue;
                        }

                        // Process this message
                        if (msg.ID == MediationMessageType.ConnectionRequest)
                        {
                            Log($"[Mesh] Received connection request! ConnectionID: {msg.ConnectionID}, Endpoint: {msg.EndpointString}");
                            Log($"[Mesh] Waiting for ConnectionBegin to establish tunnel...");
                            // Don't create Tunnel yet - wait for ConnectionBegin with final endpoint info
                        }
                        else if (msg.ID == MediationMessageType.ConnectionBegin)
                        {
                            Log($"[Mesh] *** ConnectionBegin received! ***");
                            Log($"[Mesh] ConnectionBegin: connID={msg.ConnectionID}, endpoint={msg.EndpointString}, NAT={msg.NATType}, meshIP={msg.PrivateAddressString}");

                            // Store peer's mesh IP for later use in WireGuard key exchange
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerMeshIPs[msg.ConnectionID] = msg.PrivateAddressString;
                                // Cache peer info so GetMeshState can display it.
                                // Always cache the EXTERNAL endpoint: if we ever become the introducer
                                // (or forward a MeshConnectionBegin), we must hand peers an address
                                // that works from outside this LAN. EndpointString may be LAN-substituted.
                                if (!string.IsNullOrEmpty(msg.PeerID))
                                {
                                    string cacheEndpoint = !string.IsNullOrEmpty(msg.ExternalEndpointString)
                                        ? msg.ExternalEndpointString
                                        : msg.EndpointString;
                                    peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, cacheEndpoint, msg.NATType);
                                }

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
                                    lock (meshLock)
                                    {
                                        if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                                            activeConnectionTunnels.Remove(oldConnID);
                                    }
                                    if (oldTunnel != null)
                                    {
                                        Log($"[Mesh] Disposing old tunnel {oldConnID} for {cbMeshIP} (superseded by {msg.ConnectionID})");
                                        try { oldTunnel.Dispose(); } catch { }
                                    }
                                    peerMeshIPs.Remove(oldConnID);
                                }
                                activePeerTunnels.Remove(cbMeshIP);
                                completedTunnelMeshIPs.Remove(cbMeshIP);
                                if (!string.IsNullOrEmpty(msg.PeerID))
                                    activePeerTunnels.Remove(msg.PeerID);
                            }

                            // Check if we already have a tunnel for this ConnectionID
                            if (activeConnectionTunnels.ContainsKey(msg.ConnectionID))
                            {
                                Log($"[Mesh] Tunnel {msg.ConnectionID} already exists - ignoring duplicate ConnectionBegin");
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
                                        Log($"[Mesh] Tunnel {capturedConnectionID} failed permanently after all retries — cleaning up for future retry");
                                        lock (meshLock)
                                        {
                                            activeConnectionTunnels.Remove(capturedConnectionID);
                                            if (!string.IsNullOrEmpty(capturedPeerIDForCleanup))
                                                activePeerTunnels.Remove(capturedPeerIDForCleanup);
                                            if (!string.IsNullOrEmpty(capturedMeshIPForCleanup))
                                                activePeerTunnels.Remove(capturedMeshIPForCleanup);
                                        }
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
                                        Log($"[Mesh] Tunnel {capturedConnectionID} WireGuard connection established");
                                        System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                        System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                                        lock (meshLock)
                                        {
                                            if (peerMeshIPs.TryGetValue(capturedConnectionID, out string completedMeshIP) && !string.IsNullOrEmpty(completedMeshIP))
                                            {
                                                completedTunnelMeshIPs.Add(completedMeshIP);
                                                if (deferredIntroductions.TryGetValue(completedMeshIP, out var deferred) && deferred.Count > 0)
                                                {
                                                    Log($"[Mesh] Flushing {deferred.Count} deferred MeshConnectionBegin message(s) for {completedMeshIP}");
                                                    foreach (var deferredMsg in deferred)
                                                    {
                                                        string targetIP = !string.IsNullOrEmpty(deferredMsg.IntroducerMeshIP) && !deferredMsg.IsRelay
                                                            ? deferredMsg.IntroducerMeshIP : completedMeshIP;
                                                        try
                                                        {
                                                            if (targetIP != completedMeshIP)
                                                                deferredMsg.IntroducerMeshIP = null;
                                                            byte[] deferredBytes = Encoding.UTF8.GetBytes(deferredMsg.Serialize());
                                                            MeshSend(deferredBytes, deferredBytes.Length,
                                                                new IPEndPoint(IPAddress.Parse(targetIP), MeshControlPort));
                                                            Log($"[Mesh] Sent deferred MeshConnectionBegin to {targetIP}");
                                                        }
                                                        catch (Exception ex)
                                                        {
                                                            Log($"[Mesh] Failed to send deferred MeshConnectionBegin to {targetIP}: {ex.Message}");
                                                        }
                                                    }
                                                    deferredIntroductions.Remove(completedMeshIP);
                                                }
                                            }
                                        }
                                    }
                                );

                                // Set WireGuard tunnel reference so the peer tunnel can forward traffic
                                peerTunnel.SetWireGuardTunnel(wireguardTunnel);

                                // Track this tunnel by ConnectionID
                                lock (meshLock) { activeConnectionTunnels[msg.ConnectionID] = peerTunnel; }

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
                                        Log($"[Mesh] Error starting tunnel {capturedConnectionID}: {ex.Message}");
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
                            Log($"[Mesh] Updated peer list received: {msg.PeerCount} peers");

                            // Process new peers that joined the network
                            if (msg.Peers != null && msg.Peers.Length > 0)
                            {
                                hasPeers = true;
                                ProcessDiscoveredPeers(msg.Peers);
                            }
                        }
                        else if (msg.ID == MediationMessageType.ConnectionComplete)
                        {
                            Log($"[Mesh] Received ConnectionComplete (routing to tunnel)");

                            // Find all tunnels and notify them
                            // We don't know which ConnectionID this is for from this message alone,
                            // so we need to check all active tunnels
                            // Actually, the message might not have ConnectionID, so notify all tunnels
                            Tunnel[] tunnelSnapshot;
                            lock (meshLock)
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
                            Log($"[Mesh] ServerNotAvailable — target peer unavailable");
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
                            Log($"[Mesh] Selected as introducer for new peer {msg.PeerID}");

                            // Cache the new peer's info for heartbeat repair.
                            // Also clear completedTunnelMeshIPs — the peer is reconnecting
                            // with fresh NAT traversal, so any old tunnel is stale. The new
                            // ConnectionBegin that follows will create a fresh tunnel.
                            // Clear any stale deferred messages — this MeshIntroduce supersedes them.
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerInfoByMeshIP[msg.PrivateAddressString] = (msg.PeerID, msg.EndpointString, msg.NATType);
                                completedTunnelMeshIPs.Remove(msg.PrivateAddressString);
                                deferredIntroductions.Remove(msg.PrivateAddressString);
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
                                        Log($"[Mesh] Skipping peer with no mesh IP in OtherPeers list");
                                        continue;
                                    }

                                    // Cache existing peer's info for heartbeat repair
                                    peerInfoByMeshIP[existingPeerMeshIP] = (existingPeerID, existingPeerEndpoint, (NATType)existingPeerNatType);

                                    // Check if we have a WireGuard tunnel to this peer.
                                    // OtherPeers includes all mesh members (even ones we never connected to).
                                    // We can only send MeshConnectionBegin over WireGuard to peers we have tunnels with.
                                    if (wireguardTunnel.GetPeer(IPAddress.Parse(existingPeerMeshIP)) == null)
                                    {
                                        Log($"[Mesh] Skipping peer {existingPeerID} ({existingPeerMeshIP}) — no WireGuard tunnel to this peer");
                                        continue;
                                    }

                                    // Clean up stale relay state if this pair was previously relayed
                                    // (e.g., peer reconnected with a non-Symmetric NAT type)
                                    if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                                    {
                                        string sortA = string.Compare(existingPeerMeshIP, msg.PrivateAddressString, StringComparison.Ordinal) < 0
                                            ? existingPeerMeshIP : msg.PrivateAddressString;
                                        string sortB = sortA == existingPeerMeshIP ? msg.PrivateAddressString : existingPeerMeshIP;
                                        string pairKey = $"{sortA}|{sortB}";
                                        if (relayedPairs.Remove(pairKey))
                                        {
                                            Log($"[Mesh] Removed stale relay pair {pairKey} (NAT types changed)");
                                            // Remove relay routes on the introducer's WireGuard interface
                                            wireguardTunnel.RemoveRelayRouteForPeer(IPAddress.Parse(existingPeerMeshIP));
                                            wireguardTunnel.RemoveRelayRouteForPeer(IPAddress.Parse(msg.PrivateAddressString));
                                        }
                                    }

                                    // Check for symmetric-to-symmetric: hole punching is infeasible
                                    // Instead, relay traffic through the introducer's WireGuard interface
                                    if (msg.NATType == NATType.Symmetric && (NATType)existingPeerNatType == NATType.Symmetric)
                                    {
                                        Log($"[Mesh] Both {msg.PeerID} and {existingPeerID} are symmetric NAT — setting up relay through introducer");

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
                                            Log($"[Mesh] Sent relay MeshConnectionBegin to existing peer {existingPeerMeshIP}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Mesh] Failed to send relay to {existingPeerMeshIP}: {ex.Message}");
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
                                                    Log($"[Mesh] Sent relay MeshConnectionBegin to new peer {msg.PrivateAddressString}");
                                                }
                                                catch (Exception ex)
                                                {
                                                    Log($"[Mesh] Failed to send relay to {msg.PrivateAddressString}: {ex.Message}");
                                                }
                                            }
                                            else
                                            {
                                                if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                                                    deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();
                                                deferredIntroductions[msg.PrivateAddressString].Add(relayToNew);
                                                Log($"[Mesh] Deferred relay MeshConnectionBegin to new peer {msg.PrivateAddressString}");
                                            }
                                        }

                                        // Track this pair as relayed so heartbeat doesn't try to re-introduce them
                                        string rpA = string.Compare(existingPeerMeshIP, msg.PrivateAddressString, StringComparison.Ordinal) < 0
                                            ? existingPeerMeshIP : msg.PrivateAddressString;
                                        string rpB = rpA == existingPeerMeshIP ? msg.PrivateAddressString : existingPeerMeshIP;
                                        relayedPairs.Add($"{rpA}|{rpB}");
                                        // Seed the cooldown so repair doesn't fire before pings propagate
                                        lastRepairAttempt[$"{rpA}|{rpB}"] = DateTime.UtcNow;

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
                                        Log($"[Mesh] Same-NAT detected! Using LAN endpoints: {newPeerEndpointForExisting} <-> {existingPeerEndpointForNew}");
                                    }

                                    // Build both MeshConnectionBegin messages.
                                    // ExternalEndpointString always carries the external endpoint so the
                                    // receiver caches something safe to forward to peers outside this LAN.
                                    var connBeginToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                    {
                                        PeerID = msg.PeerID,              // New peer's ID
                                        EndpointString = newPeerEndpointForExisting,  // New peer's endpoint (LAN if same-NAT)
                                        ExternalEndpointString = msg.EndpointString,  // Always external
                                        NATType = msg.NATType,              // New peer's NAT type
                                        PrivateAddressString = msg.PrivateAddressString   // New peer's mesh IP
                                    };

                                    MediationMessage connBeginToNew = null;
                                    if (!string.IsNullOrEmpty(msg.PrivateAddressString) && !string.IsNullOrEmpty(existingPeerEndpoint))
                                    {
                                        connBeginToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                        {
                                            PeerID = existingPeerID,           // Existing peer's ID
                                            EndpointString = existingPeerEndpointForNew,  // Existing peer's endpoint (LAN if same-NAT)
                                            ExternalEndpointString = existingPeerEndpoint, // Always external
                                            NATType = (NATType)existingPeerNatType, // Existing peer's NAT type
                                            PrivateAddressString = existingPeerMeshIP         // Existing peer's mesh IP
                                        };
                                    }

                                    bool tunnelToNewReady = completedTunnelMeshIPs.Contains(msg.PrivateAddressString);

                                    if (tunnelToNewReady)
                                    {
                                        // Tunnel to new peer is ready — send both sides simultaneously
                                        // so hole-punching starts at the same time
                                        try
                                        {
                                            byte[] toExistingBytes = Encoding.UTF8.GetBytes(connBeginToExisting.Serialize());
                                            MeshSend(toExistingBytes, toExistingBytes.Length,
                                                new IPEndPoint(IPAddress.Parse(existingPeerMeshIP), MeshControlPort));
                                            Log($"[Mesh] Sent MeshConnectionBegin to existing peer {existingPeerMeshIP} (about new peer {msg.PeerID})");
                                        }
                                        catch (Exception ex)
                                        {
                                            Log($"[Mesh] Failed to send MeshConnectionBegin to {existingPeerMeshIP}: {ex.Message}");
                                        }

                                        if (connBeginToNew != null)
                                        {
                                            try
                                            {
                                                byte[] toNewBytes = Encoding.UTF8.GetBytes(connBeginToNew.Serialize());
                                                MeshSend(toNewBytes, toNewBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(msg.PrivateAddressString), MeshControlPort));
                                                Log($"[Mesh] Sent MeshConnectionBegin to new peer {msg.PrivateAddressString} (about existing peer {existingPeerMeshIP})");
                                            }
                                            catch (Exception ex)
                                            {
                                                Log($"[Mesh] Failed to send MeshConnectionBegin to {msg.PrivateAddressString}: {ex.Message}");
                                            }
                                        }
                                    }
                                    else
                                    {
                                        // Tunnel to new peer not yet established — defer BOTH sides
                                        // so hole-punching starts simultaneously when the tunnel is ready
                                        if (!deferredIntroductions.ContainsKey(msg.PrivateAddressString))
                                            deferredIntroductions[msg.PrivateAddressString] = new List<MediationMessage>();

                                        // Defer the message to the existing peer (tagged with target mesh IP for routing)
                                        connBeginToExisting.IntroducerMeshIP = existingPeerMeshIP; // Reuse field to store target
                                        deferredIntroductions[msg.PrivateAddressString].Add(connBeginToExisting);

                                        if (connBeginToNew != null)
                                            deferredIntroductions[msg.PrivateAddressString].Add(connBeginToNew);

                                        Log($"[Mesh] Deferred MeshConnectionBegin for both peers (tunnel to {msg.PrivateAddressString} not yet established)");
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
                                Log($"[Mesh] Sent MeshIntroduceAck for {msg.PeerID} ({introduced} introduced, {deferredCount} deferred, completedTunnels={completedTunnelMeshIPs.Count})");
                            }
                            catch (Exception ex)
                            {
                                Log($"[Mesh] MeshIntroduceAck write failed, connection lost: {ex.Message}");
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
            // If disconnect was requested during setup loop, skip mesh-control and go to idle
            if (DisconnectRequested)
            {
                // Fall through to disconnect handling after the mesh-control loop
            }
            else
            {

            Log("[Mesh] Entering mesh-control-only mode (fully disconnected from mediation server)");

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
            Stream reconnectedStream = null;
            string reconnectedTcpBuffer = ""; // Accumulates partial TCP data across reads
            DateTime? lastReconnectDiscovery = null;
            int reconnectDiscoverySeconds = TunnelOptions.HeartbeatIntervalSeconds;
            int reconnectDiscoveryAttempts = 0;
            const int MaxReconnectDiscoveryAttempts = 5; // After this many re-sends, tear down and reconnect fresh

            // Reset probe state when entering mesh-control-only loop
            lastIntroducerProbe = DateTime.UtcNow;
            introducerMissedProbes = 0;

            Log($"[Mesh] Entering mesh-control-only loop — isIntroducer={isIntroducer}, natType={detectedNatType}, introducerMeshIP={introducerMeshIP ?? "null"}");

            while (!ShutdownRequested && !DisconnectRequested)
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
                        Log($"[Mesh] Peer {leaveMsg.PrivateAddressString} left gracefully");
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
                            Log($"[Mesh] Failed to send heartbeat to {peerIP}: {ex.Message}");
                        }
                    }

                    if (heartbeatTargets.Count > 1)
                    {
                        heartbeatAckDeadline = DateTime.UtcNow.AddSeconds(5);
                        heartbeatSentTime = DateTime.UtcNow;
                        metricHeartbeatsSent++;
                        Log($"[Mesh] Heartbeat sent to {heartbeatTargets.Count} peer(s), collecting acks...");
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
                        Log($"[Mesh] Heartbeat ack collection complete: {heartbeatAcks.Count}/{heartbeatTargets.Count} responded");

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
                                Log($"[Mesh] Peer {ip} missed heartbeat ({heartbeatMissCount[ip]}/{PeerDeadThreshold})");
                                if (heartbeatMissCount[ip] >= PeerDeadThreshold)
                                {
                                    string peerPID = peerInfoByMeshIP.TryGetValue(ip, out var pi) ? pi.peerID : null;
                                    bool hasPendingTunnel = (!string.IsNullOrEmpty(peerPID) && activePeerTunnels.ContainsKey(peerPID)) ||
                                                            activePeerTunnels.ContainsKey(ip) ||
                                                            (!string.IsNullOrEmpty(peerPID) && pendingConnectionRequests.ContainsKey(peerPID));
                                    if (hasPendingTunnel)
                                    {
                                        Log($"[Mesh] Peer {ip} would be dead but has pending tunnel — deferring removal");
                                        heartbeatMissCount[ip] = 0;
                                        continue;
                                    }
                                    deadPeers.Add(ip);
                                }
                            }
                        }
                        foreach (var deadIP in deadPeers)
                        {
                            metricPeersLost++;
                            Log($"[Mesh] Peer {deadIP} declared dead after {PeerDeadThreshold} consecutive missed heartbeats");
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
                        int repairCount = RepairBrokenLinks(targetList, heartbeatAcks, reconnectedTcpClient, reconnectedStream);
                        if (repairCount > 0)
                            Log($"[Mesh] Heartbeat: sent {repairCount} repair message(s)");

                        // Retry connecting to peers that are known but never got a completed tunnel.
                        if (reconnectedTcpClient != null && reconnectedTcpClient.Connected)
                        {
                            foreach (var kvp in peerInfoByMeshIP)
                            {
                                string peerMeshIP = kvp.Key;
                                if (peerMeshIP == meshIP) continue;
                                if (completedTunnelMeshIPs.Contains(peerMeshIP)) continue;
                                if (deadPeers.Contains(peerMeshIP)) continue;
                                if (string.IsNullOrEmpty(kvp.Value.peerID)) continue;
                                if (pendingConnectionRequests.ContainsKey(kvp.Value.peerID)) continue;
                                if (activePeerTunnels.ContainsKey(kvp.Value.peerID) || activePeerTunnels.ContainsKey(peerMeshIP)) continue;

                                Log($"[Mesh] Heartbeat: peer {peerMeshIP} has no completed tunnel — requesting reconnection via mediation");
                                try
                                {
                                    var reconnReq = new MediationMessage(MediationMessageType.ConnectionRequest)
                                    {
                                        PeerID = kvp.Value.peerID,
                                        NATType = detectedNatType
                                    };
                                    byte[] reconnBuf = Encoding.ASCII.GetBytes(reconnReq.Serialize());
                                    reconnectedStream.Write(reconnBuf, 0, reconnBuf.Length);
                                    reconnectedStream.Flush();
                                    pendingConnectionRequests[kvp.Value.peerID] = DateTime.UtcNow;
                                }
                                catch (Exception ex)
                                {
                                    Log($"[Mesh] Failed to send reconnection request for {peerMeshIP}: {ex.Message}");
                                }
                            }
                        }

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
                    // Expire stale latency entries (no pong in 30s)
                    var staleCutoff = DateTime.UtcNow.AddSeconds(-30);
                    foreach (var kvp in peerLastPong)
                    {
                        if (kvp.Value < staleCutoff)
                        {
                            peerLatencyMs.TryRemove(kvp.Key, out _);
                            peerLastPong.TryRemove(kvp.Key, out _);
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
                        try
                        {
                            int bytesRead = reconnectedStreamLocal.Read(buffer, 0, buffer.Length);
                            if (bytesRead > 0)
                                reconnectedTcpBuffer += Encoding.ASCII.GetString(buffer, 0, bytesRead);
                        }
                        catch (IOException) { } // read timeout — no data available this iteration
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
                                        Log($"[Mesh] Reconnect discovery: found {parsedMsg.Peers.Length} peer(s)");
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
                                                Log($"[Mesh] Cached peer info: {mip2} = NAT:{(NATType)nt2}, endpoint:{ep2}");
                                            }
                                        }
                                        ProcessDiscoveredPeers(parsedMsg.Peers, reconnectedStreamLocal);
                                    }
                                }
                                else if (parsedMsg.ID == MediationMessageType.ConnectionBegin)
                                {
                                    Log($"[Mesh] Reconnect: received ConnectionBegin for connection {parsedMsg.ConnectionID}");
                                    // Store peer's mesh IP
                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                    {
                                        peerMeshIPs[parsedMsg.ConnectionID] = parsedMsg.PrivateAddressString;
                                        if (!string.IsNullOrEmpty(parsedMsg.PeerID))
                                        {
                                            // Cache the EXTERNAL endpoint when available — EndpointString
                                            // may be a LAN endpoint for same-NAT pairs.
                                            string cacheEndpoint = !string.IsNullOrEmpty(parsedMsg.ExternalEndpointString)
                                                ? parsedMsg.ExternalEndpointString
                                                : parsedMsg.EndpointString;
                                            peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, cacheEndpoint, parsedMsg.NATType);
                                        }
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
                                            lock (meshLock)
                                            {
                                                if (activeConnectionTunnels.TryGetValue(oldConnID, out oldTunnel))
                                                    activeConnectionTunnels.Remove(oldConnID);
                                            }
                                            if (oldTunnel != null)
                                            {
                                                Log($"[Mesh] Reconnect: disposing old tunnel {oldConnID} for {reconMeshIP} (superseded by {parsedMsg.ConnectionID})");
                                                try { oldTunnel.Dispose(); } catch { }
                                            }
                                            peerMeshIPs.Remove(oldConnID);
                                        }
                                        // Clean up tracking for this mesh IP so the new tunnel starts fresh
                                        activePeerTunnels.Remove(reconMeshIP);
                                        completedTunnelMeshIPs.Remove(reconMeshIP);
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
                                                lock (meshLock)
                                                {
                                                    activeConnectionTunnels.Remove(capturedConnID);
                                                    if (!string.IsNullOrEmpty(capturedPeerIDStr)) activePeerTunnels.Remove(capturedPeerIDStr);
                                                    if (!string.IsNullOrEmpty(capturedMeshIPStr)) activePeerTunnels.Remove(capturedMeshIPStr);
                                                }
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
                                                Log($"[Mesh] Reconnect tunnel {capturedConnID} WireGuard established");
                                                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                                System.Threading.Interlocked.Increment(ref metricTunnelsEstablished);
                                                lock (meshLock)
                                                {
                                                    if (peerMeshIPs.TryGetValue(capturedConnID, out string cMeshIP) && !string.IsNullOrEmpty(cMeshIP))
                                                        completedTunnelMeshIPs.Add(cMeshIP);
                                                }
                                            }
                                        );
                                        reconnectTunnel.SetWireGuardTunnel(wireguardTunnel);
                                        lock (meshLock) { activeConnectionTunnels[capturedConnID] = reconnectTunnel; }
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
                                                Log($"[Mesh] Reconnect tunnel error: {ex.Message}");
                                                System.Threading.Interlocked.Decrement(ref pendingTunnelCount);
                                            }
                                        });
                                    }
                                }
                                else if (parsedMsg.ID == MediationMessageType.MeshIntroduceRequest)
                                {
                                    isIntroducer = true;
                                    Log($"[Mesh] Reconnect: selected as introducer for {parsedMsg.PeerID}");

                                    // Cache the new peer's info for heartbeat repair.
                                    // Clear completedTunnelMeshIPs — peer is reconnecting with fresh NAT traversal.
                                    // Clear stale deferred messages — this MeshIntroduce supersedes them.
                                    if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                    {
                                        peerInfoByMeshIP[parsedMsg.PrivateAddressString] = (parsedMsg.PeerID, parsedMsg.EndpointString, parsedMsg.NATType);
                                        completedTunnelMeshIPs.Remove(parsedMsg.PrivateAddressString);
                                        deferredIntroductions.Remove(parsedMsg.PrivateAddressString);
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
                                                Log($"[Mesh] Reconnect introducer: no WG tunnel to {exMeshIP} — skipping");
                                                continue;
                                            }

                                            // Clean up stale relay state for this pair
                                            if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                            {
                                                string sA = string.Compare(exMeshIP, parsedMsg.PrivateAddressString, StringComparison.Ordinal) < 0
                                                    ? exMeshIP : parsedMsg.PrivateAddressString;
                                                string sB = sA == exMeshIP ? parsedMsg.PrivateAddressString : exMeshIP;
                                                string rpKey = $"{sA}|{sB}";
                                                if (relayedPairs.Remove(rpKey))
                                                {
                                                    Log($"[Mesh] Reconnect: removed stale relay pair {rpKey}");
                                                    wireguardTunnel.RemoveRelayRouteForPeer(IPAddress.Parse(exMeshIP));
                                                    wireguardTunnel.RemoveRelayRouteForPeer(IPAddress.Parse(parsedMsg.PrivateAddressString));
                                                }
                                            }

                                            // Check for symmetric-to-symmetric: relay through introducer
                                            if (parsedMsg.NATType == NATType.Symmetric && (NATType)exNatType == NATType.Symmetric)
                                            {
                                                Log($"[Mesh] Reconnect: both {parsedMsg.PeerID} and {exPeerID} are symmetric — setting up relay");
                                                wireguardTunnel.EnableForwarding();

                                                // Send relay MeshConnectionBegin to existing peer
                                                var relayToEx = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                {
                                                    PeerID = parsedMsg.PeerID,
                                                    EndpointString = parsedMsg.EndpointString,
                                                    NATType = parsedMsg.NATType,
                                                    PrivateAddressString = parsedMsg.PrivateAddressString,
                                                    IsRelay = true,
                                                    IntroducerMeshIP = meshIP
                                                };
                                                try
                                                {
                                                    byte[] relayExBytes = Encoding.UTF8.GetBytes(relayToEx.Serialize());
                                                    MeshSend(relayExBytes, relayExBytes.Length,
                                                        new IPEndPoint(IPAddress.Parse(exMeshIP), MeshControlPort));
                                                    Log($"[Mesh] Reconnect: sent relay MeshConnectionBegin to {exMeshIP}");
                                                }
                                                catch (Exception ex2)
                                                {
                                                    Log($"[Mesh] Failed to send relay to {exMeshIP}: {ex2.Message}");
                                                }

                                                // Send relay MeshConnectionBegin to new peer (deferred if tunnel not ready)
                                                if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString))
                                                {
                                                    var relayToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                    {
                                                        PeerID = exPeerID,
                                                        EndpointString = exEndpoint,
                                                        NATType = (NATType)exNatType,
                                                        PrivateAddressString = exMeshIP,
                                                        IsRelay = true,
                                                        IntroducerMeshIP = meshIP
                                                    };

                                                    if (completedTunnelMeshIPs.Contains(parsedMsg.PrivateAddressString))
                                                    {
                                                        try
                                                        {
                                                            byte[] relayNewBytes = Encoding.UTF8.GetBytes(relayToNew.Serialize());
                                                            MeshSend(relayNewBytes, relayNewBytes.Length,
                                                                new IPEndPoint(IPAddress.Parse(parsedMsg.PrivateAddressString), MeshControlPort));
                                                            Log($"[Mesh] Reconnect: sent relay MeshConnectionBegin to {parsedMsg.PrivateAddressString}");
                                                        }
                                                        catch (Exception ex2)
                                                        {
                                                            Log($"[Mesh] Failed to send relay to {parsedMsg.PrivateAddressString}: {ex2.Message}");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (!deferredIntroductions.ContainsKey(parsedMsg.PrivateAddressString))
                                                            deferredIntroductions[parsedMsg.PrivateAddressString] = new List<MediationMessage>();
                                                        deferredIntroductions[parsedMsg.PrivateAddressString].Add(relayToNew);
                                                        Log($"[Mesh] Reconnect: deferred relay MeshConnectionBegin to {parsedMsg.PrivateAddressString}");
                                                    }
                                                }

                                                // Track as relayed pair
                                                string rpA2 = string.Compare(exMeshIP, parsedMsg.PrivateAddressString, StringComparison.Ordinal) < 0
                                                    ? exMeshIP : parsedMsg.PrivateAddressString;
                                                string rpB2 = rpA2 == exMeshIP ? parsedMsg.PrivateAddressString : exMeshIP;
                                                relayedPairs.Add($"{rpA2}|{rpB2}");
                                                // Seed the cooldown so repair doesn't fire before pings propagate
                                                lastRepairAttempt[$"{rpA2}|{rpB2}"] = DateTime.UtcNow;

                                                continue;
                                            }

                                            // Send MeshConnectionBegin to existing peer about the new peer
                                            var cbToExisting = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                            {
                                                PeerID = parsedMsg.PeerID,
                                                EndpointString = parsedMsg.EndpointString,
                                                ExternalEndpointString = parsedMsg.EndpointString,
                                                NATType = parsedMsg.NATType,
                                                PrivateAddressString = parsedMsg.PrivateAddressString
                                            };
                                            try
                                            {
                                                byte[] cbBytes = Encoding.UTF8.GetBytes(cbToExisting.Serialize());
                                                MeshSend(cbBytes, cbBytes.Length,
                                                    new IPEndPoint(IPAddress.Parse(exMeshIP), MeshControlPort));
                                                Log($"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {exMeshIP} about {parsedMsg.PeerID}");
                                            }
                                            catch (Exception ex2)
                                            {
                                                Log($"[Mesh] Failed to send MeshConnectionBegin to {exMeshIP}: {ex2.Message}");
                                            }

                                            // Send MeshConnectionBegin to new peer about existing peer (if tunnel ready)
                                            if (!string.IsNullOrEmpty(parsedMsg.PrivateAddressString) && !string.IsNullOrEmpty(exEndpoint))
                                            {
                                                var cbToNew = new MediationMessage(MediationMessageType.MeshConnectionBegin)
                                                {
                                                    PeerID = exPeerID,
                                                    EndpointString = exEndpoint,
                                                    ExternalEndpointString = exEndpoint,
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
                                                        Log($"[Mesh] Reconnect introducer: sent MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
                                                    }
                                                    catch (Exception ex2)
                                                    {
                                                        Log($"[Mesh] Failed to send MeshConnectionBegin to {parsedMsg.PrivateAddressString}: {ex2.Message}");
                                                    }
                                                }
                                                else
                                                {
                                                    if (!deferredIntroductions.ContainsKey(parsedMsg.PrivateAddressString))
                                                        deferredIntroductions[parsedMsg.PrivateAddressString] = new List<MediationMessage>();
                                                    deferredIntroductions[parsedMsg.PrivateAddressString].Add(cbToNew);
                                                    Log($"[Mesh] Reconnect introducer: deferred MeshConnectionBegin to {parsedMsg.PrivateAddressString} about {exPeerID}");
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
                            (DateTime.UtcNow - lastReconnectDiscovery.Value).TotalSeconds > reconnectDiscoverySeconds)
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
                                reconnectDiscoveryAttempts++;
                                if (reconnectDiscoveryAttempts > MaxReconnectDiscoveryAttempts)
                                {
                                    // Too many failed rediscovery attempts — tear down and reconnect fresh
                                    // so we get a new NAT test with fresh endpoint info
                                    Log($"[Mesh] {MaxReconnectDiscoveryAttempts} rediscovery attempts failed — tearing down reconnected connection to start fresh");
                                    reconnectedTcpClient.Close();
                                    reconnectedTcpClient = null;
                                    reconnectedStream = null;
                                    reconnectedTcpBuffer = "";
                                    isolationDetectedAt = null; // Will re-trigger isolation detection
                                    reconnectDiscoverySeconds = TunnelOptions.HeartbeatIntervalSeconds;
                                    reconnectDiscoveryAttempts = 0;
                                }
                                else
                                {
                                    var rediscovery = new MediationMessage(MediationMessageType.MeshJoinRequest)
                                    {
                                        NetworkID = TunnelOptions.NetworkID,
                                        PeerID = peerID.ToString(),
                                        NATType = detectedNatType,
                                        PrivateAddressString = meshIP,
                                        AuthToken = authToken
                                    };
                                    byte[] rdBytes = Encoding.ASCII.GetBytes(rediscovery.Serialize());
                                    reconnectedStreamLocal.Write(rdBytes, 0, rdBytes.Length);
                                    // Exponential backoff: 15s → 30s → 60s → 60s → 60s
                                    reconnectDiscoverySeconds = Math.Min(reconnectDiscoverySeconds * 2, 60);
                                    Log($"[Mesh] Re-sent discovery request ({reconnectDiscoveryAttempts}/{MaxReconnectDiscoveryAttempts}), next in {reconnectDiscoverySeconds}s");
                                }
                            }
                            else if (!stillIsolated)
                            {
                                if (!isIntroducer)
                                {
                                    // Peers recovered — close reconnected connection.
                                    Log("[Mesh] Peers recovered — closing reconnected mediation connection");
                                    reconnectedTcpClient.Close();
                                    reconnectedTcpClient = null;
                                    reconnectedStream = null;
                                    reconnectedTcpBuffer = "";
                                    isolationDetectedAt = null;
                                }
                                // Reset backoff on success
                                reconnectDiscoverySeconds = TunnelOptions.HeartbeatIntervalSeconds;
                                reconnectDiscoveryAttempts = 0;
                            }
                            lastReconnectDiscovery = DateTime.UtcNow;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"[Mesh] Reconnected TCP error: {ex.Message}");
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
                            Log($"[Mesh] Isolation detected — no active WireGuard peers. Will reconnect in {IsolationGracePeriodSeconds}s if not resolved.");
                        }
                        else if ((DateTime.UtcNow - isolationDetectedAt.Value).TotalSeconds >= IsolationGracePeriodSeconds)
                        {
                            Log("[Mesh] Isolation persisted — reconnecting to mediation server for peer discovery");
                            try
                            {
                                var mediationEP = TunnelOptions.MediationEndpoint;
                                reconnectedTcpClient = new TcpClient();
                                reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                                reconnectedTcpClient.Connect(mediationEP);
                                if (TunnelOptions.TlsEnabled)
                                {
                                    var sslStream = new SslStream(reconnectedTcpClient.GetStream(), false,
                                        TunnelOptions.TlsAllowSelfSigned
                                            ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                                            : null);
                                    sslStream.AuthenticateAsClient(mediationEP.Address.ToString());
                                    reconnectedStream = sslStream;
                                    Log($"[Mesh] Reconnect TLS handshake complete (protocol: {sslStream.SslProtocol})");
                                }
                                else
                                {
                                    reconnectedStream = reconnectedTcpClient.GetStream();
                                }

                                // Clear stale peer state — endpoints may have changed during isolation
                                pendingConnectionRequests.Clear();

                                // Perform full mediation handshake (Connected → NAT test → MeshJoinRequest)
                                reconnectedStream.ReadTimeout = 15000;
                                string reconRemainder = "";
                                byte[] reconBuf = new byte[4096];

                                MediationMessage ReadReconMessage()
                                {
                                    while (true)
                                    {
                                        var (m, r) = ExtractFirstJson(reconRemainder);
                                        if (m != null) { reconRemainder = r; return m; }
                                        int n = reconnectedStream.Read(reconBuf, 0, reconBuf.Length);
                                        if (n == 0) throw new IOException("Reconnected mediation stream closed");
                                        reconRemainder += Encoding.ASCII.GetString(reconBuf, 0, n);
                                    }
                                }

                                // 1. Wait for Connected message
                                ReadReconMessage();

                                // 2. NAT type detection (proper handshake — must complete before MeshJoinRequest)
                                var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                                {
                                    LocalPort = localUdpPort,
                                    LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                                    ClientID = peerID
                                };
                                byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                                reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                                // Read NATTestBegin to get the test ports
                                var natTestBeginR = ReadReconMessage();
                                if (natTestBeginR.ID == MediationMessageType.NATTestBegin)
                                {
                                    // Send UDP test packets to both NAT test ports
                                    var natTestMsg = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                                    byte[] natTestBuf = Encoding.ASCII.GetBytes(natTestMsg.Serialize());
                                    udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, natTestBeginR.NATTestPortOne));
                                    udpClient.Send(natTestBuf, natTestBuf.Length, new IPEndPoint(mediationEP.Address, natTestBeginR.NATTestPortTwo));
                                }

                                // Read NATTypeResponse
                                var natTypeRespR = ReadReconMessage();
                                if (natTypeRespR.ID == MediationMessageType.NATTypeResponse)
                                {
                                    detectedNatType = natTypeRespR.NATType;
                                    Log($"[Mesh] Reconnect NAT type: {detectedNatType}");
                                }

                                // 3. Send MeshJoinRequest for peer discovery
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

                                reconnectedStream.ReadTimeout = 100; // poll timeout for main loop
                                lastReconnectDiscovery = DateTime.UtcNow;
                                Log("[Mesh] Reconnected to mediation server — sent discovery request");
                            }
                            catch (Exception ex)
                            {
                                Log($"[Mesh] Failed to reconnect to mediation: {ex.Message}");
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
                            Log("[Mesh] Isolation resolved — active peers detected");
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
                            Log($"[Mesh] Relay gateway(s) dead: {string.Join(", ", deadGateways)} — cleaning up stale routes");

                            foreach (var deadGateway in deadGateways)
                            {
                                var removedRoutes = wireguardTunnel.RemoveRelayRoutesViaGateway(deadGateway);
                                Log($"[Mesh] Removed {removedRoutes.Count} relay route(s) via {deadGateway}");
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
                        Log($"[Mesh] Introducer ({introducerMeshIP}) missed probe ack ({introducerMissedProbes}/{IntroducerMissedProbeThreshold})");
                    }
                    else
                    {
                        if (introducerMissedProbes > 0)
                        {
                            Log($"[Mesh] Introducer ({introducerMeshIP}) responded — resetting missed probe count");
                        }
                        introducerMissedProbes = 0;
                    }

                    if (introducerMissedProbes >= IntroducerMissedProbeThreshold)
                    {
                        Log("[Mesh] Introducer confirmed dead — reconnecting to mediation to take over introducer role");
                        try
                        {
                            var mediationEP = TunnelOptions.MediationEndpoint;
                            reconnectedTcpClient = new TcpClient();
                            reconnectedTcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                            reconnectedTcpClient.Connect(mediationEP);
                            if (TunnelOptions.TlsEnabled)
                            {
                                var sslStream = new SslStream(reconnectedTcpClient.GetStream(), false,
                                    TunnelOptions.TlsAllowSelfSigned
                                        ? (RemoteCertificateValidationCallback)((sender, cert, chain, errors) => true)
                                        : null);
                                sslStream.AuthenticateAsClient(mediationEP.Address.ToString());
                                reconnectedStream = sslStream;
                                Log($"[Mesh] Takeover TLS handshake complete (protocol: {sslStream.SslProtocol})");
                            }
                            else
                            {
                                reconnectedStream = reconnectedTcpClient.GetStream();
                            }

                            // Clear stale peer state
                            pendingConnectionRequests.Clear();

                            // Perform full mediation handshake
                            reconnectedStream.ReadTimeout = 15000;
                            string reconRemainder2 = "";
                            byte[] reconBuf2 = new byte[4096];

                            MediationMessage ReadReconMessage2()
                            {
                                while (true)
                                {
                                    var (m, r) = ExtractFirstJson(reconRemainder2);
                                    if (m != null) { reconRemainder2 = r; return m; }
                                    int n = reconnectedStream.Read(reconBuf2, 0, reconBuf2.Length);
                                    if (n == 0) throw new IOException("Reconnected mediation stream closed");
                                    reconRemainder2 += Encoding.ASCII.GetString(reconBuf2, 0, n);
                                }
                            }

                            // 1. Wait for Connected message
                            ReadReconMessage2();

                            // 2. NAT type detection (proper handshake)
                            var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
                            {
                                LocalPort = localUdpPort,
                                LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
                                ClientID = peerID
                            };
                            byte[] natReqBytes = Encoding.ASCII.GetBytes(natReq.Serialize());
                            reconnectedStream.Write(natReqBytes, 0, natReqBytes.Length);

                            var natTestBeginR2 = ReadReconMessage2();
                            if (natTestBeginR2.ID == MediationMessageType.NATTestBegin)
                            {
                                var natTestMsg2 = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
                                byte[] natTestBuf2 = Encoding.ASCII.GetBytes(natTestMsg2.Serialize());
                                udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, natTestBeginR2.NATTestPortOne));
                                udpClient.Send(natTestBuf2, natTestBuf2.Length, new IPEndPoint(mediationEP.Address, natTestBeginR2.NATTestPortTwo));
                            }

                            var natTypeRespR2 = ReadReconMessage2();
                            if (natTypeRespR2.ID == MediationMessageType.NATTypeResponse)
                            {
                                detectedNatType = natTypeRespR2.NATType;
                                Log($"[Mesh] Reconnect NAT type: {detectedNatType}");
                            }

                            // 3. Send MeshJoinRequest — the server will select us as the new introducer
                            // (since the old one disconnected and we're non-symmetric)
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
                            isIntroducer = true; // We're taking over
                            introducerMissedProbes = 0;
                            Log("[Mesh] Reconnected to mediation as new introducer — sent join request");
                        }
                        catch (Exception ex)
                        {
                            Log($"[Mesh] Failed to reconnect for introducer takeover: {ex.Message}");
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
                        catch (Exception)
                        {
                            // Probe send failure typically means the route to the dead introducer
                            // has been pulled. The missed-probe counter will reach threshold and
                            // we'll trigger takeover — no need to log per-attempt noise.
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
                        Log($"[Mesh] Peer {staleIP} has been silent for >{staleThreshold.TotalMinutes}m — removing locally");
                        RemoveDeadPeer(staleIP);
                    }
                }

                System.Threading.Thread.Sleep(100);
            }

            } // end else (not DisconnectRequested at setup loop exit)

            // Check if this was a disconnect request (vs shutdown)
            if (DisconnectRequested && !ShutdownRequested)
            {
                ConnectionState = MeshConnectionState.Disconnecting;
                Log("[Mesh] Disconnect requested — performing graceful leave");

                // Send MeshPeerLeave to all peers
                try
                {
                    var leaveMsg = new MediationMessage(MediationMessageType.MeshPeerLeave)
                    {
                        PrivateAddressString = meshIP,
                        PeerID = peerID.ToString()
                    };
                    byte[] leaveBytes = Encoding.UTF8.GetBytes(leaveMsg.Serialize());
                    foreach (var peer in wireguardTunnel.GetAllPeers())
                    {
                        try
                        {
                            MeshSend(leaveBytes, leaveBytes.Length,
                                new IPEndPoint(peer.PrivateAddress, MeshControlPort));
                        }
                        catch { }
                    }
                }
                catch { }

                // Remove all WireGuard peers (keeps adapter alive)
                wireguardTunnel.RemoveAllPeers();

                // Clear all tracking state (use Clear() to preserve closure references)
                activePeerTunnels.Clear();
                pendingConnectionRequests.Clear();
                activeConnectionTunnels.Clear();
                connectionIDToPeerID.Clear();
                peerMeshIPs.Clear();
                completedTunnelMeshIPs.Clear();
                relayedPairs.Clear();
                lastRepairAttempt.Clear();
                repairAttemptCount.Clear();
                peerInfoByMeshIP.Clear();
                peerLatencyMs.Clear();
                peerLastPong.Clear();
                pingSentTicks.Clear();
                lastHeartbeatReceivedFrom.Clear();
                deferredIntroductions.Clear();
                pendingTunnelCount = 0;
                isIntroducer = false;
                introducerMeshIP = null;
                joinResponse = null;

                // Close mediation TCP
                try { tcpClient?.Dispose(); } catch { }
                tcpClient = null; stream = null; earlyTcpRemainder = "";

                ConnectionState = MeshConnectionState.Disconnected;
                Log("[Mesh] Disconnected — waiting for reconnect request");

                // Idle wait
                while (!ShutdownRequested && !ConnectRequested)
                    System.Threading.Thread.Sleep(100);
                ConnectRequested = false;

                if (!ShutdownRequested)
                {
                    Log("[Mesh] Reconnect requested — re-entering connect loop");
                    // Reload config from disk in case settings were changed via GUI/settings
                    Config.TryLoadConfig();
                    // Refresh local variables that were captured from TunnelOptions at startup
                    endpoint = TunnelOptions.MediationEndpoint;
                    authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
                        Encoding.UTF8.GetBytes(TunnelOptions.NetworkID + ":" + TunnelOptions.NetworkSecret)));
                    continue; // Back to outer connect loop
                }
            }

            // ShutdownRequested was set (e.g. by GUI) — perform graceful shutdown
            PerformGracefulShutdown();

            } // end outer connect loop

        }
        catch (Exception ex)
        {
            Log($"[Mesh] Error: {ex.Message}");
            Log(ex.StackTrace);
            throw;
        }
        finally
        {
            // Dispose resources so retries can rebind ports
            try { meshControlClient?.Dispose(); } catch { }
            try { udpProxy?.Dispose(); } catch { }
            try { wireguardTunnel?.Dispose(); } catch { }
            try { tcpClient?.Dispose(); } catch { }
            try { udpClient?.Dispose(); } catch { }
        }
    }

}