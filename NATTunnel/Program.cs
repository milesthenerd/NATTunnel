using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
            // Generate unique peer ID for this instance
            var peerID = Guid.NewGuid();
            Console.WriteLine($"[Mesh] Peer ID: {peerID}");
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
            var activeConnectionTunnels = new Dictionary<int, Tunnel>();  // ConnectionID -> Tunnel
            var peerMeshIPs = new Dictionary<int, string>();  // ConnectionID -> Peer's mesh IP

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
                    string endpoint = peerObj.GetProperty("endpoint").GetString();

                    // Skip if this is ourselves
                    if (targetPeerID == peerID.ToString())
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (self - skipping)");
                        continue;
                    }

                    // Skip if we've already requested connection to this peer
                    if (activePeerTunnels.ContainsKey(targetPeerID))
                    {
                        Console.WriteLine($"  - Peer {targetPeerID} (already connected)");
                        continue;
                    }

                    Console.WriteLine($"  - Peer {targetPeerID}");
                    Console.WriteLine($"    Endpoint: {endpoint}");

                    // NAT Type might not be present in older peer objects
                    if (peerObj.TryGetProperty("natType", out JsonElement natTypeElement))
                    {
                        Console.WriteLine($"    NAT Type: {natTypeElement.GetInt32()}");
                    }

                    // Send connection request to mediation server for this peer
                    var connectionRequest = new MediationMessage(MediationMessageType.ConnectionRequest)
                    {
                        PeerID = targetPeerID,
                        NATType = detectedNatType
                    };

                    string connRequestJson = connectionRequest.Serialize();
                    byte[] connBuffer = Encoding.ASCII.GetBytes(connRequestJson);
                    stream.Write(connBuffer, 0, connBuffer.Length);

                    Console.WriteLine($"[Mesh] Sent connection request for peer {targetPeerID}");

                    // Mark this peer as being connected to (even though connection not complete yet)
                    activePeerTunnels[targetPeerID] = null;  // Will be populated with Tunnel instance later
                }
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

            // Set up periodic keep-alive and peer polling
            var lastKeepAlive = DateTime.UtcNow;
            var keepAliveInterval = TimeSpan.FromSeconds(5);  // Send keep-alive every 5 seconds
            var lastPeerPoll = DateTime.UtcNow;
            var peerPollInterval = TimeSpan.FromSeconds(10);  // Poll for new peers every 10 seconds
            bool hasPeers = joinResponse.Peers != null && joinResponse.Peers.Length > 0;

            // Message loop - create Tunnel instances when ConnectionBegin arrives
            while (true)
            {
                // Check if TCP connection is still alive
                if (!tcpClient.Connected)
                {
                    Console.WriteLine("[Mesh] ⚠ TCP connection to mediation server lost");
                    break;
                }

                // Send periodic keep-alive to prevent timeout
                if (DateTime.UtcNow - lastKeepAlive > keepAliveInterval)
                {
                    var keepAliveMsg = new MediationMessage(MediationMessageType.KeepAlive);
                    string keepAliveJson = keepAliveMsg.Serialize();
                    byte[] keepAliveBuffer = Encoding.ASCII.GetBytes(keepAliveJson);
                    stream.Write(keepAliveBuffer, 0, keepAliveBuffer.Length);
                    lastKeepAlive = DateTime.UtcNow;
                    Console.WriteLine("[Mesh] Sent keep-alive to mediation server");
                }

                // Poll for new peers periodically to discover peers that join later
                if (DateTime.UtcNow - lastPeerPoll > peerPollInterval)
                {
                    // Request updated peer list from mediation server
                    // Include our mesh IP so the server can share it with other peers
                    var pollRequest = new MediationMessage(MediationMessageType.MeshJoinRequest)
                    {
                        NetworkID = TunnelOptions.NetworkID,
                        PeerID = peerID.ToString(),
                        NATType = detectedNatType,
                        PrivateAddressString = meshIP  // Include mesh IP for new peers
                    };

                    string pollJson = pollRequest.Serialize();
                    byte[] pollBuffer = Encoding.ASCII.GetBytes(pollJson);
                    stream.Write(pollBuffer, 0, pollBuffer.Length);
                    lastPeerPoll = DateTime.UtcNow;
                    Console.WriteLine("[Mesh] Polling for new peers in network...");
                }

                // Check for new messages from mediation server
                if (stream.DataAvailable)
                {
                    bytesRead = stream.Read(buffer, 0, buffer.Length);

                    // Check if connection closed
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("[Mesh] ⚠ Mediation server closed connection");
                        break;
                    }

                    response = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    Console.WriteLine($"[Mesh] Received message: {response}");

                    // Handle multiple JSON objects in the same buffer
                    // Split by detecting JSON object boundaries (each starts with '{' and ends with '}')
                    int jsonStartIndex = 0;
                    while (jsonStartIndex < response.Length)
                    {
                        // Find the start of the next JSON object
                        int jsonObjStart = response.IndexOf('{', jsonStartIndex);
                        if (jsonObjStart == -1) break;

                        // Find the matching closing brace by counting braces
                        int braceCount = 0;
                        int jsonObjEnd = -1;
                        for (int i = jsonObjStart; i < response.Length; i++)
                        {
                            if (response[i] == '{') braceCount++;
                            else if (response[i] == '}')
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
                            Console.WriteLine("[Mesh] ⚠ Incomplete JSON object in buffer");
                            break;
                        }

                        // Extract and parse this JSON object
                        string jsonObject = response.Substring(jsonObjStart, jsonObjEnd - jsonObjStart + 1);

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
                            Console.WriteLine($"[Mesh] Connection initiated! ConnectionID: {msg.ConnectionID}, Endpoint: {msg.EndpointString}");

                            // Store peer's mesh IP for later use in WireGuard key exchange
                            if (!string.IsNullOrEmpty(msg.PrivateAddressString))
                            {
                                peerMeshIPs[msg.ConnectionID] = msg.PrivateAddressString;
                                Console.WriteLine($"[Mesh] Peer mesh IP: {msg.PrivateAddressString}");
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
                                var peerTunnel = new Tunnel(
                                    onConnectionFailure: () => {
                                        // Only called after all retries are exhausted
                                        Console.WriteLine($"[Mesh] Tunnel {msg.ConnectionID} failed permanently after all retries");
                                        activeConnectionTunnels.Remove(msg.ConnectionID);
                                        // TODO: Could implement reconnection logic here (create new tunnel with new ConnectionRequest)
                                    },
                                    managedByTunnelManager: false,
                                    connectionId: msg.ConnectionID,
                                    sharedUdpClient: udpClient,  // Share UDP client with mesh mode (same port)
                                    meshPeerMode: false,
                                    meshPeerEndpoint: null,
                                    retryInPlace: true,  // Retry in-place like server, don't recreate tunnel
                                    isServerOverride: false,  // Mesh tunnels always act as clients (both peers are equal)
                                    sharedClientID: peerID,  // Share clientID with mesh mode so server routes messages correctly
                                    skipTcpConnection: false,  // Peer tunnels create their own TCP connection
                                    ownMeshIP: meshIP  // Pass our mesh IP so tunnel can send it in WireGuard key exchange
                                );

                                // Set WireGuard tunnel reference so the peer tunnel can forward traffic
                                peerTunnel.SetWireGuardTunnel(wireguardTunnel);

                                // Track this tunnel by ConnectionID
                                activeConnectionTunnels[msg.ConnectionID] = peerTunnel;

                                Console.WriteLine($"[Mesh] Created tunnel for peer connection {msg.ConnectionID}");
                                Console.WriteLine($"[Mesh] Peer endpoint: {msg.EndpointString}, Peer NAT: {msg.NATType}, Our NAT: {detectedNatType}");

                                // Start the tunnel asynchronously
                                // It will connect to mediation server, send NATTypeRequest with ConnectionID,
                                // server will recognize it's a mesh connection and send ConnectionBegin immediately
                                System.Threading.Tasks.Task.Run(() =>
                                {
                                    try
                                    {
                                        peerTunnel.Start();
                                        Console.WriteLine($"[Mesh] Tunnel {msg.ConnectionID} connected and hole-punching started");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"[Mesh] Error starting tunnel {msg.ConnectionID}: {ex.Message}");
                                    }
                                });
                            }
                        }
                        else if (msg.ID == MediationMessageType.MeshJoinResponse)
                        {
                            Console.WriteLine($"[Mesh] Peer poll response: {msg.PeerCount} peers in network");

                            // Update hasPeers flag
                            if (msg.Peers != null && msg.Peers.Length > 0)
                            {
                                hasPeers = true;
                                ProcessDiscoveredPeers(msg.Peers);
                            }
                            else
                            {
                                Console.WriteLine("[Mesh] Still no peers in network - will retry in 10 seconds");
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
                            foreach (var kvp in activeConnectionTunnels)
                            {
                                Console.WriteLine($"[Mesh] Notifying tunnel {kvp.Key} of connection complete");
                                kvp.Value.NotifyConnectionComplete();
                            }
                        }

                        // Move to next JSON object
                        jsonStartIndex = jsonObjEnd + 1;
                    } // End while loop for parsing multiple JSON objects
                }


                System.Threading.Thread.Sleep(100);
            }

            Console.WriteLine("[Mesh] Exiting mesh mode - connection terminated");
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