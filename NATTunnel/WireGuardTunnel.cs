using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NATTunnel
{
    public class WireGuardTunnel : IDisposable
    {
        private readonly string configFilePath;
        private readonly string interfaceName;
        private readonly WireGuardPeerManager peerManager;
        private readonly IWireGuardBackend backend = WireGuardBackend.Instance;
        private bool disposedValue;
        private bool tunnelStarted;
        private readonly bool debugMode;
        private readonly bool isRunningAsService;
        private readonly bool skipTunnelCreation; // For mesh mode: don't create a Tunnel
        private WireGuardUdpProxy udpProxy;
        private byte[] privateKey;
        private byte[] publicKey;
        private CancellationTokenSource packetLoopCancellation;
        private string clientAssignedIP; // Track client's assigned IP (null until assigned)
        private byte clientPrefixLength = 24; // Default /24, can be changed for mesh mode (/16)
        private Tunnel tunnel; // Instance of the Tunnel class (for clients)
        // Track relay routes: relayedIP -> gatewayIP (so we can remove/migrate them on introducer change)
        private readonly Dictionary<IPAddress, IPAddress> relayRoutes = new Dictionary<IPAddress, IPAddress>();

        /// <summary>
        /// Get the UDP proxy instance for forwarding packets
        /// </summary>
        public WireGuardUdpProxy GetUdpProxy() => udpProxy;

        /// <summary>
        /// Set the UDP proxy instance (used in mesh mode to inject the proxy after initialization)
        /// </summary>
        public void SetUdpProxy(WireGuardUdpProxy proxy)
        {
            udpProxy = proxy;

            // Set up activity tracking callback
            if (udpProxy != null)
            {
                udpProxy.OnPeerActivity = (tunnelIp) =>
                {
                    // Update last activity timestamp for the peer
                    var peer = peerManager.GetAllPeers().FirstOrDefault(p => p.PrivateAddress.Equals(tunnelIp));
                    if (peer != null)
                    {
                        peer.LastActivity = DateTime.UtcNow;
                    }
                };
            }
        }

        public WireGuardTunnel(string interfaceName, bool debugMode = false, bool isRunningAsService = false, bool skipTunnelCreation = false)
        {
            this.interfaceName = interfaceName;
            this.debugMode = debugMode;
            this.isRunningAsService = isRunningAsService;
            this.skipTunnelCreation = skipTunnelCreation;

            try
            {
                Program.Log($"Creating new WireGuard tunnel (Interface: {interfaceName})");
                if (debugMode)
                {
                    Program.Log(">>> DEBUG MODE ENABLED - Skipping service installation");
                }
                if (isRunningAsService)
                {
                    Program.Log(">>> SERVICE MODE ENABLED - Skipping service installation (already managed by Windows Service Manager)");
                }

                // Set up base config path — named after the interface so multiple instances
                // on the same machine don't share/overwrite each other's config and keys.
                configFilePath = EnsureConfigPath(interfaceName);
                Program.Log($"Base config path: {configFilePath}");

                // Set up persistent keys file path (stored separately from config)
                string keysFilePath = Path.Combine(Path.GetDirectoryName(configFilePath), $"{interfaceName}_keys.txt");

                // Generate or reuse WireGuard keys
                string privateKeyBase64;
                string publicKeyBase64;

                // Try to load keys from dedicated keys file first (most reliable)
                if (File.Exists(keysFilePath))
                {
                    try
                    {
                        Program.Log($"Loading existing WireGuard keys from {keysFilePath}...");
                        string[] keyLines = File.ReadAllLines(keysFilePath);
                        if (keyLines.Length >= 2)
                        {
                            privateKeyBase64 = keyLines[0].Trim();
                            publicKeyBase64 = keyLines[1].Trim();
                            Program.Log("Loaded existing WireGuard keys from keys file");
                        }
                        else
                        {
                            throw new InvalidDataException("Keys file doesn't contain both keys");
                        }
                    }
                    catch (Exception ex)
                    {
                        Program.Log($"Could not load keys from keys file: {ex.Message}");
                        Program.Log("Generating new keys...");
                        var (privKey, pubKey) = WireGuardConfig.GenerateKeyPair();
                        privateKeyBase64 = privKey;
                        publicKeyBase64 = pubKey;
                    }
                }
                else if (File.Exists(configFilePath))
                {
                    // Fallback: try to extract from config file
                    try
                    {
                        Program.Log("Loading existing WireGuard keys from config...");
                        privateKeyBase64 = ExtractPrivateKeyFromConfig(configFilePath);
                        publicKeyBase64 = WireGuardConfig.GetPublicKeyFromConfig(configFilePath);
                        Program.Log("Loaded existing WireGuard keys from config");
                    }
                    catch (Exception ex)
                    {
                        Program.Log($"Could not load keys from config: {ex.Message}");
                        Program.Log("Generating new keys...");
                        var (privKey, pubKey) = WireGuardConfig.GenerateKeyPair();
                        privateKeyBase64 = privKey;
                        publicKeyBase64 = pubKey;
                    }
                }
                else
                {
                    // No existing keys - generate new keypair
                    Program.Log("Generating new WireGuard keys...");
                    var (privKey, pubKey) = WireGuardConfig.GenerateKeyPair();
                    privateKeyBase64 = privKey;
                    publicKeyBase64 = pubKey;
                }

                // ALWAYS save keys to dedicated file for future runs
                try
                {
                    File.WriteAllLines(keysFilePath, new[] { privateKeyBase64, publicKeyBase64 });
                    Program.Log($"Keys saved to {keysFilePath}");
                }
                catch (Exception ex)
                {
                    Program.Log($"Warning: Could not save keys file: {ex.Message}");
                }

                // Decode base64 keys to binary for WireGuard API
                this.privateKey = Convert.FromBase64String(privateKeyBase64);
                this.publicKey = Convert.FromBase64String(publicKeyBase64);

                Program.Log("Generating/updating WireGuard config...");

                // Use placeholder IP until mesh mode assigns the real mesh IP
                string interfaceAddress = "10.5.0.254/24";

                // Generate config with ONLY the [Interface] section
                // Peers will be added dynamically by WireGuardPeerManager
                WireGuardConfig.GenerateInterfaceOnlyConfig(
                    privateKeyBase64,
                    interfaceName,
                    configFilePath,
                    interfaceAddress);

                Program.Log($"WireGuard config: {configFilePath}");
                Program.Log($"WireGuard will listen on port: 51820 (localhost only)");

                // Initialize peer manager
                Program.Log("Initializing peer manager...");
                var baseAddress = IPAddress.Parse("10.5.0.0");
                peerManager = new WireGuardPeerManager(configFilePath, baseAddress, 51820);

                // Initialize the tunnel (skip in debug mode or if already running as service)
                if (!debugMode && !isRunningAsService)
                {
                    InitializeTunnel();
                }
                else if (isRunningAsService)
                {
                    Program.Log(">>> Service mode: Bringing up WireGuard interface...");
                    BringUpWireGuardInterface();
                    tunnelStarted = true;
                }
            }
            catch (Exception ex)
            {
                Program.Log($"Error during tunnel creation: {ex.Message}");
                Program.Log($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        private static string EnsureConfigPath(string configName)
        {
            // Remove any existing extensions
            configName = Path.GetFileNameWithoutExtension(configName);

            // Add .conf extension
            configName = configName + ".conf";

            // If not rooted, combine with base directory
            if (!Path.IsPathRooted(configName))
            {
                configName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, configName);
            }

            return configName;
        }

        /// <summary>
        /// Extracts the private key from an existing WireGuard config file
        /// </summary>
        private static string ExtractPrivateKeyFromConfig(string configPath)
        {
            try
            {
                if (!File.Exists(configPath))
                {
                    throw new FileNotFoundException($"Config file not found: {configPath}");
                }

                string configContent = File.ReadAllText(configPath);

                // Extract private key from [Interface] section
                foreach (var line in configContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None))
                {
                    // Trim line and check if it contains PrivateKey (handle spaces)
                    string trimmedLine = line.Trim();
                    if (trimmedLine.StartsWith("PrivateKey", StringComparison.OrdinalIgnoreCase))
                    {
                        // Find the first equals sign and take everything after it
                        int equalsIdx = trimmedLine.IndexOf('=');
                        if (equalsIdx >= 0 && equalsIdx < trimmedLine.Length - 1)
                        {
                            string privateKey = trimmedLine.Substring(equalsIdx + 1).Trim();
                            if (!string.IsNullOrEmpty(privateKey))
                            {
                                Program.Log("Extracted private key from config");
                                return privateKey;
                            }
                        }
                    }
                }

                throw new Exception("Could not find PrivateKey in config file");
            }
            catch (Exception ex)
            {
                Program.Log($"Error extracting private key from config: {ex.Message}");
                throw;
            }
        }

        private void InitializeTunnel()
        {
            try
            {
                Program.Log("Initializing WireGuard tunnel");
                Program.Log($"Using config path: {configFilePath}");

                // Check elevation first
                Program.Log("Checking for administrative privileges...");
                bool elevated = IsElevated();
                Program.Log($"Running with administrative privileges: {elevated}");

                if (!elevated)
                {
                    Program.Log("Attempting to restart with administrative privileges...");
                    RestartElevated();
                    return;
                }

                // Bring up the WireGuard interface directly
                Program.Log("Bringing up WireGuard interface...");
                BringUpWireGuardInterface();

                tunnelStarted = true;
                Program.Log("WireGuard tunnel initialized successfully");
            }
            catch (Exception ex)
            {
                Program.Log($"Error during tunnel initialization: {ex.Message}");
                Program.Log($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        private void BringUpWireGuardInterface()
        {
            try
            {
                Program.Log($"Bringing up WireGuard interface: {interfaceName}");

                backend.CreateInterface(interfaceName);

                Program.Log("Configuring WireGuard interface...");
                backend.ConfigureInterface(interfaceName, configFilePath);

                // Placeholder IP; mesh mode will reassign with the real mesh IP shortly.
                string assignedIp = "10.5.0.254";
                Program.Log($"Assigning IP address {assignedIp}/24 to interface...");
                backend.AssignIP(interfaceName, assignedIp, 24);

                Program.Log("Bringing WireGuard interface up...");
                backend.SetInterfaceUp(interfaceName);

                System.Threading.Thread.Sleep(1000);

                // Verify interface status
                Program.Log("Checking WireGuard interface status...");
                var statusPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "wg",
                    Arguments = $"show {interfaceName}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var statusProcess = System.Diagnostics.Process.Start(statusPsi))
                {
                    statusProcess.WaitForExit();
                    string output = statusProcess.StandardOutput.ReadToEnd();
                    string error = statusProcess.StandardError.ReadToEnd();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        Program.Log($"WireGuard status:\n{output}");
                    }
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        Program.Log($"WireGuard status error: {error}");
                    }
                }

                // Initialize tunnel based on mode
                if (!skipTunnelCreation)
                {
                    Program.Log("Initializing Tunnel...");
                    tunnel = new Tunnel(onConnectionFailure: HandleConnectionFailure);
                    tunnel.SetWireGuardTunnel(this);

                    // Start the mediation tunnel to connect to the mediation server
                    Program.Log("Starting mediation tunnel connection...");
                    tunnel.Start();

                    // Start UDP proxy to forward WireGuard traffic bidirectionally
                    Program.Log("Starting WireGuard UDP proxy...");
                    udpProxy = new WireGuardUdpProxy(tunnel.GetUdpClient());
                }
                else
                {
                    // Mesh mode: Don't create a tunnel, mesh mode will create its own peer tunnels
                    Program.Log("[Mesh] WireGuard initialized without creating Tunnel (mesh mode will manage peer tunnels)");
                    // UDP proxy will be created later when needed
                    udpProxy = null;
                }

                // Set up activity tracking callback (only if udpProxy was created)
                if (udpProxy != null)
                {
                    udpProxy.OnPeerActivity = (tunnelIp) =>
                    {
                        // Update last activity timestamp for the peer
                        var peer = peerManager.GetAllPeers().FirstOrDefault(p => p.PrivateAddress.Equals(tunnelIp));
                        if (peer != null)
                        {
                            peer.LastActivity = DateTime.UtcNow;
                        }
                    };
                }

                // Start a task to periodically reset peer endpoints to their correct proxy ports
                // This prevents WireGuard's endpoint roaming from breaking the proxy
                Task.Run(async () =>
                {
                    while (tunnelStarted)
                    {
                        await Task.Delay(5000); // Every 5 seconds

                        foreach (var peer in peerManager.GetAllPeers())
                        {
                            try
                            {
                                // Use the peer's specific proxy port, not the shared 51821
                                var resetPsi = new System.Diagnostics.ProcessStartInfo
                                {
                                    FileName = "wg",
                                    Arguments = $"set {interfaceName} peer {peer.PublicKey} endpoint 127.0.0.1:{peer.ProxyPort}",
                                    UseShellExecute = false,
                                    RedirectStandardError = true,
                                    CreateNoWindow = true
                                };
                                using var proc = System.Diagnostics.Process.Start(resetPsi);
                                proc.WaitForExit();
                                if (proc.ExitCode != 0)
                                {
                                    var err = proc.StandardError.ReadToEnd();
                                    Program.Log($"[Endpoint Reset] Failed for peer {peer.PublicKey.Substring(0, 8)}: {err}");
                                }
                            }
                            catch (Exception ex)
                            {
                                Program.Log($"[Endpoint Reset] Error: {ex.Message}");
                            }
                        }
                    }
                });

                // Peer health monitoring is now handled by TunnelManager
                // which tracks actual tunnel activity (including keepalives)
                // This WireGuard-specific check was too aggressive and removed active peers
                // Leaving code commented for reference
                /*
                // Start peer health monitoring task
                // Removes peers that haven't sent WireGuard traffic in 10 minutes
                // Note: This is based on WireGuard handshake activity, not tunnel keepalives
                if (TunnelOptions.IsServer)
                {
                    Task.Run(async () =>
                    {
                        while (tunnelStarted)
                        {
                            await Task.Delay(30000); // Check every 30 seconds

                            var now = DateTime.UtcNow;
                            // Increased timeout from 120s to 600s (10 minutes) to avoid premature removal
                            // WireGuard handshakes can be infrequent even with active traffic
                            var inactivePeers = peerManager.GetAllPeers()
                                .Where(p => !p.IsPersistent && (now - p.LastActivity).TotalSeconds > 600)
                                .ToList();

                            foreach (var peer in inactivePeers)
                            {
                                Program.Log($"[Health] Removing inactive peer {peer.PrivateAddress} (last activity: {(now - peer.LastActivity).TotalSeconds:F0}s ago)");

                                // Remove from WireGuard
                                try
                                {
                                    var removePsi = new System.Diagnostics.ProcessStartInfo
                                    {
                                        FileName = "wg",
                                        Arguments = $"set {interfaceName} peer {peer.PublicKey} remove",
                                        UseShellExecute = false,
                                        RedirectStandardError = true,
                                        CreateNoWindow = true
                                    };
                                    using var proc = System.Diagnostics.Process.Start(removePsi);
                                    proc.WaitForExit();
                                }
                                catch (Exception ex)
                                {
                                    Program.Log($"[Health] Error removing peer from WireGuard: {ex.Message}");
                                }

                                // Remove from proxy
                                udpProxy?.UnregisterPeer(peer.PrivateAddress);

                                // Remove from peer manager
                                peerManager.RemovePeer(peer.ConnectionId);
                            }
                        }
                    });
                }
                */

                // Check interface connectivity status (Windows-only diagnostic)
                Task.Run(async () =>
                {
                    await Task.Delay(3000); // Wait 3 seconds for everything to settle
                    Program.Log("\n[Status Check] Verifying WireGuard interface connectivity...");
                    if (OperatingSystem.IsWindows())
                    {
                        var psi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "netsh",
                            Arguments = $"interface ipv4 show interfaces",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };
                        using var proc = System.Diagnostics.Process.Start(psi);
                        var output = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit();
                        var lines = output.Split('\n');
                        foreach (var line in lines)
                        {
                            if (line.Contains(interfaceName))
                            {
                                Program.Log($"[Status Check] Interface: {line.Trim()}");
                            }
                        }
                    }

                    // Also check WireGuard status
                    var wgPsi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "wg",
                        Arguments = "show",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };
                    using var wgProc = System.Diagnostics.Process.Start(wgPsi);
                    var wgOutput = wgProc.StandardOutput.ReadToEnd();
                    wgProc.WaitForExit();
                    Program.Log($"[Status Check] WireGuard status:\n{wgOutput}");
                });

                tunnelStarted = true;
                Program.Log("   WireGuard-NT tunnel initialized successfully");
                Program.Log("   All WireGuard crypto is handled by the kernel driver");
                Program.Log("   UDP proxy bridges WireGuard (localhost:51820) with NAT-traversed peers");
            }
            catch (Exception ex)
            {
                Program.Log($"Error bringing up WireGuard interface: {ex.Message}");
                Program.Log($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        private bool IsElevated()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return true; // Non-Windows platforms handled differently
            }

            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Update the UDP proxy's tunnel socket (needed for symmetric NAT socket swaps)
        /// </summary>
        public void UpdateProxyTunnelSocket(System.Net.Sockets.UdpClient newSocket)
        {
            if (udpProxy != null)
            {
                udpProxy.UpdateTunnelSocket(newSocket);
            }
        }

        private void RestartElevated()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return; // Non-Windows platforms handled differently
            }

            var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            var args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                UseShellExecute = true,
                WorkingDirectory = AppContext.BaseDirectory,
                FileName = exePath,
                Arguments = string.Join(" ", args),
                CreateNoWindow = false,
                Verb = "runas"
            };

            try
            {
                System.Diagnostics.Process.Start(startInfo);
                Environment.Exit(0); // Exit current non-elevated process
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // User cancelled the UAC dialog
                throw new Exception("Administrative privileges are required to run the WireGuard tunnel.");
            }
        }

        public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, bool isPersistent = false)
        {
            return AddPeer(publicKey, endpoint, isPersistent, null);
        }

        public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, bool isPersistent, UdpClient tunnelSocket)
        {
            var peer = peerManager.AddPeer(publicKey, endpoint, isPersistent);
            Program.Log($"Added peer dynamically: {publicKey.Substring(0, 8)}... -> {peer.PrivateAddress} (proxy port: {peer.ProxyPort}, total peers: {peerManager.GetPeerCount()})");

            // Register peer with UDP proxy for outbound routing WITH tunnel IP for multi-peer support
            // Pass the specific tunnel socket for this peer (critical for multi-tunnel architecture)
            if (udpProxy != null)
            {
                udpProxy.RegisterPeer(endpoint, peer.ProxyPort, peer.PrivateAddress, tunnelSocket);
            }
            else
            {
                Program.Log($"udpProxy is null — cannot register peer {peer.PrivateAddress} with proxy");
            }

            // Update config file for persistence (used on restart)
            RegenerateConfigWithPeers();

            // Use "wg set" to add this single peer without tearing down existing sessions.
            // Falls back to full setconf if wg set fails.
            if (tunnelStarted)
            {
                if (!backend.AddOrUpdatePeer(interfaceName, peer))
                {
                    // Fallback: full config reload
                    backend.ApplyFullConfig(interfaceName, configFilePath);
                }
            }
            else
            {
                Program.Log($"Skipped WireGuard config update: tunnelStarted={tunnelStarted}");
            }

            return peer;
        }

        /// <summary>
        /// Regenerates the WireGuard config file with all current peers
        /// </summary>
        private void RegenerateConfigWithPeers()
        {
            try
            {
                var config = new System.Text.StringBuilder();

                // [Interface] section
                config.AppendLine("[Interface]");
                config.AppendLine($"PrivateKey = {Convert.ToBase64String(privateKey)}");
                config.AppendLine("ListenPort = 51820");

                // Use assigned IP if available (for clients), otherwise use role-based default
                string assignedIp;
                if (!string.IsNullOrEmpty(clientAssignedIP))
                {
                    assignedIp = clientAssignedIP;
                }
                else
                {
                    // Use placeholder IP for clients until server assigns actual IP
                    assignedIp = "10.5.0.254";
                }

                config.AppendLine($"Address = {assignedIp}/{clientPrefixLength}");
                config.AppendLine($"Name = {interfaceName}");
                config.AppendLine();

                // [Peer] sections
                // Both server and client use localhost proxy endpoint (127.0.0.1:51821)
                // The proxy forwards to the real NAT-traversed endpoints
                bool useProxy = true; // Always use proxy endpoint
                foreach (var peer in peerManager.GetAllPeers())
                {
                    config.Append(peer.GenerateConfigSection(useProxy));
                    config.AppendLine();
                }

                File.WriteAllText(configFilePath, config.ToString());
            }
            catch (Exception ex)
            {
                Program.Log($"Error regenerating config: {ex.Message}");
            }
        }

        public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, bool isPersistent = false)
        {
            return AddPeer(publicKey, endpoint, privateAddress, isPersistent, null);
        }

        public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, bool isPersistent, UdpClient tunnelSocket)
        {
            var peer = peerManager.AddPeer(publicKey, endpoint, privateAddress, isPersistent);
            Program.Log($"Added peer dynamically: {publicKey.Substring(0, 8)}... -> {privateAddress} (proxy port: {peer.ProxyPort}, total peers: {peerManager.GetPeerCount()})");

            // Register peer with UDP proxy for outbound routing WITH tunnel IP for multi-peer support
            // Pass the specific tunnel socket for this peer (critical for multi-tunnel architecture)
            if (udpProxy != null)
            {
                udpProxy.RegisterPeer(endpoint, peer.ProxyPort, peer.PrivateAddress, tunnelSocket);
            }
            else
            {
                Program.Log($"udpProxy is null — cannot register peer {peer.PrivateAddress} with proxy");
            }

            // Update config file for persistence (used on restart)
            RegenerateConfigWithPeers();

            // Use "wg set" to add this single peer without tearing down existing sessions.
            // Falls back to full setconf if wg set fails.
            if (tunnelStarted)
            {
                if (!backend.AddOrUpdatePeer(interfaceName, peer))
                {
                    // Fallback: full config reload
                    backend.ApplyFullConfig(interfaceName, configFilePath);
                }
            }
            else
            {
                Program.Log($"Skipped WireGuard config update: tunnelStarted={tunnelStarted}");
            }

            return peer;
        }

        /// <summary>
        /// Add a relay route: traffic destined for relayedPeerIP will be routed through
        /// the existing WireGuard peer at gatewayPeerIP. Used for symmetric-to-symmetric relay
        /// where the introducer forwards traffic between two peers.
        /// </summary>
        public bool AddRelayRoute(IPAddress gatewayPeerIP, IPAddress relayedPeerIP)
        {
            var gatewayPeer = peerManager.GetPeer(gatewayPeerIP);
            if (gatewayPeer == null)
            {
                Program.Log($"[WireGuard] Cannot add relay route: no peer found for gateway {gatewayPeerIP}");
                return false;
            }

            // If a relay route already exists for this IP via a different gateway, remove the old one first
            if (relayRoutes.TryGetValue(relayedPeerIP, out var oldGateway) && !oldGateway.Equals(gatewayPeerIP))
            {
                Program.Log($"[WireGuard] Migrating relay route for {relayedPeerIP}: {oldGateway} -> {gatewayPeerIP}");
                var oldGatewayPeer = peerManager.GetPeer(oldGateway);
                if (oldGatewayPeer != null)
                {
                    oldGatewayPeer.ResetAllowedIPs();
                    if (tunnelStarted)
                        backend.AddOrUpdatePeer(interfaceName, oldGatewayPeer);
                }
            }

            gatewayPeer.AddAllowedIP(relayedPeerIP);
            relayRoutes[relayedPeerIP] = gatewayPeerIP;
            Program.Log($"[WireGuard] Added relay route: {relayedPeerIP}/32 via {gatewayPeerIP} (peer {gatewayPeer.PublicKey.Substring(0, 8)}...)");

            // Apply the updated AllowedIPs to the running interface
            if (tunnelStarted)
            {
                if (!backend.AddOrUpdatePeer(interfaceName, gatewayPeer))
                {
                    // Fallback: full config reload
                    backend.ApplyFullConfig(interfaceName, configFilePath);
                }
            }

            // Update config file for persistence
            RegenerateConfigWithPeers();
            return true;
        }

        /// <summary>
        /// Remove all relay routes that go through a specific gateway peer.
        /// Called when the introducer disconnects and relay routes need to be cleaned up.
        /// The WireGuard peer entry for the gateway is reset to only its own IP in AllowedIPs.
        /// </summary>
        public List<IPAddress> RemoveRelayRoutesViaGateway(IPAddress gatewayPeerIP)
        {
            var removed = new List<IPAddress>();
            var toRemove = new List<IPAddress>();

            foreach (var kvp in relayRoutes)
            {
                if (kvp.Value.Equals(gatewayPeerIP))
                    toRemove.Add(kvp.Key);
            }

            if (toRemove.Count == 0)
                return removed;

            foreach (var relayedIP in toRemove)
            {
                relayRoutes.Remove(relayedIP);
                removed.Add(relayedIP);
            }

            // Reset the gateway peer's AllowedIPs back to just its own IP
            var gatewayPeer = peerManager.GetPeer(gatewayPeerIP);
            if (gatewayPeer != null)
            {
                gatewayPeer.ResetAllowedIPs();
                Program.Log($"[WireGuard] Removed {removed.Count} relay route(s) via {gatewayPeerIP}, reset AllowedIPs to {gatewayPeer.AllowedIPs}");

                // Apply to running interface
                if (tunnelStarted)
                {
                    if (!backend.AddOrUpdatePeer(interfaceName, gatewayPeer))
                    {
                        backend.ApplyFullConfig(interfaceName, configFilePath);
                    }
                }
                RegenerateConfigWithPeers();
            }

            return removed;
        }

        /// <summary>
        /// Remove a specific relay route by destination IP.
        /// Returns true if a route was removed.
        /// </summary>
        public bool RemoveRelayRouteForPeer(IPAddress relayedPeerIP)
        {
            if (!relayRoutes.TryGetValue(relayedPeerIP, out var gatewayPeerIP))
                return false;

            relayRoutes.Remove(relayedPeerIP);

            // Reset the gateway peer's AllowedIPs back to just its own IP
            var gatewayPeer = peerManager.GetPeer(gatewayPeerIP);
            if (gatewayPeer != null)
            {
                gatewayPeer.ResetAllowedIPs();
                Program.Log($"[WireGuard] Removed relay route for {relayedPeerIP} (was via {gatewayPeerIP})");

                if (tunnelStarted)
                {
                    if (!backend.AddOrUpdatePeer(interfaceName, gatewayPeer))
                    {
                        backend.ApplyFullConfig(interfaceName, configFilePath);
                    }
                }
                RegenerateConfigWithPeers();
            }

            return true;
        }

        /// <summary>
        /// Get all relay routes currently tracked (relayedIP -> gatewayIP)
        /// </summary>
        public Dictionary<IPAddress, IPAddress> GetRelayRoutes()
        {
            return new Dictionary<IPAddress, IPAddress>(relayRoutes);
        }

        public void RemovePeer(int connectionId)
        {
            var peer = peerManager.GetPeer(connectionId);
            if (peer != null)
            {
                Program.Log($"Removed peer: {peer.PublicKey.Substring(0, 8)}...");
            }
            peerManager.RemovePeer(connectionId);

            // Apply the updated peer set to the live interface so the kernel state matches the
            // in-memory peerManager. Without this the kernel keeps stale peer entries forever.
            if (tunnelStarted)
            {
                RegenerateConfigWithPeers();
                backend.ApplyFullConfig(interfaceName, configFilePath);
            }
        }

        /// <summary>
        /// Enable IP forwarding on the WireGuard interface so it can relay traffic between peers.
        /// Required for symmetric-to-symmetric NAT relay through the introducer.
        /// </summary>
        public bool EnableForwarding() => backend.EnableForwarding(interfaceName);

        public WireGuardPeer GetPeer(int connectionId) => peerManager.GetPeer(connectionId);
        public WireGuardPeer GetPeer(IPAddress privateAddress) => peerManager.GetPeer(privateAddress);
        public WireGuardPeer GetPeer(IPEndPoint endpoint) => peerManager.GetPeer(endpoint);
        public IEnumerable<WireGuardPeer> GetAllPeers() => peerManager.GetAllPeers();

        public void RemoveAllPeers()
        {
            peerManager.RemoveAllPeers();

            // Clear relay routes
            relayRoutes.Clear();

            // Apply the updated peer set to the live interface so the kernel state matches the
            // in-memory peerManager. Without this the kernel keeps stale peer entries forever.
            if (tunnelStarted)
            {
                RegenerateConfigWithPeers();
                backend.ApplyFullConfig(interfaceName, configFilePath);
            }
        }
        public int GetPeerCount() => peerManager.GetPeerCount();
        public string GetConfigPath() => configFilePath;

        /// <summary>
        /// For clients: Updates the tunnel with the assigned private IP address
        /// </summary>
        public void SetClientIPAndRestart(string assignedIpAddress, byte prefixLength = 24)
        {
            try
            {
                Program.Log($"Client updating tunnel configuration with IP: {assignedIpAddress}/{prefixLength}");

                // Store the assigned IP and prefix length for config generation
                clientAssignedIP = assignedIpAddress;
                clientPrefixLength = prefixLength;

                // Extra IP cleanup via PowerShell on Windows — WireGuard-NT reassignment has
                // historically missed edge cases. Linux's `ip address flush` already handles this.
                if (OperatingSystem.IsWindows())
                {
                    Program.Log($"Checking existing IP addresses on interface {interfaceName}...");
                    try
                    {
                        var listPsi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-NoProfile -Command \"Get-NetIPAddress -InterfaceAlias '{interfaceName}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };

                        using (var listProc = System.Diagnostics.Process.Start(listPsi))
                        {
                            if (listProc != null)
                            {
                                var existingIPs = listProc.StandardOutput.ReadToEnd();
                                listProc.WaitForExit();
                                Program.Log($"Existing IPs on {interfaceName}: {existingIPs.Trim()}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Program.Log($"Could not list IPs: {ex.Message}");
                    }

                    Program.Log($"Removing all existing IP addresses from interface {interfaceName}...");
                    try
                    {
                        var deletePsPsi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-NoProfile -Command \"Get-NetIPAddress -InterfaceAlias '{interfaceName}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        using (var deleteProc = System.Diagnostics.Process.Start(deletePsPsi))
                        {
                            if (deleteProc != null)
                            {
                                var output = deleteProc.StandardOutput.ReadToEnd();
                                var error = deleteProc.StandardError.ReadToEnd();
                                deleteProc.WaitForExit();
                                Program.Log($"PowerShell IP removal completed (exit code: {deleteProc.ExitCode})");
                                if (!string.IsNullOrWhiteSpace(output)) Program.Log($"Output: {output}");
                                if (!string.IsNullOrWhiteSpace(error)) Program.Log($"Error: {error}");
                            }
                        }

                        System.Threading.Thread.Sleep(1000);  // Wait for system to process removal
                    }
                    catch (Exception cleanupEx)
                    {
                        Program.Log($"Warning: Could not cleanup old IPs via PowerShell: {cleanupEx.Message}");
                    }
                }

                // Update the interface IP through the backend (don't regenerate keys!)
                Program.Log($"Updating interface IP...");
                backend.AssignIP(interfaceName, assignedIpAddress, prefixLength);

                // Update the config file to reflect the new IP (keep existing keys and peers)
                RegenerateConfigWithPeers();

                // Force WireGuard-NT to reload config
                Program.Log($"Reloading WireGuard-NT configuration...");
                backend.ApplyFullConfig(interfaceName, configFilePath);

                Program.Log($"Client tunnel updated with IP {assignedIpAddress}/{prefixLength}");
            }
            catch (Exception ex)
            {
                Program.Log($"Error updating tunnel: {ex.Message}");
                throw;
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    try
                    {
                        // Stop UDP proxy first
                        if (udpProxy != null)
                        {
                            Program.Log("Stopping UDP proxy...");
                            udpProxy.Dispose();
                            udpProxy = null;
                        }

                        // Stop packet processing loop (if active)
                        if (packetLoopCancellation != null)
                        {
                            Program.Log("Cancelling packet loop...");
                            packetLoopCancellation.Cancel();
                            packetLoopCancellation.Dispose();
                            packetLoopCancellation = null;
                        }

                        // Linux's systemd unit handles lifecycle itself — only Windows needs SCM cleanup.
                        if (tunnelStarted)
                        {
                            if (OperatingSystem.IsWindows())
                            {
                                WireGuardService.UninstallService(interfaceName);
                                Program.Log("WireGuard service uninstalled");
                            }
                            tunnelStarted = false;
                        }

                        // DON'T delete config file - keep it for reconnection
                        // The config will be reused or regenerated on next startup
                        Program.Log("Config file preserved for reconnection");
                    }
                    catch (Exception ex)
                    {
                        Program.Log($"Warning: Error during cleanup: {ex.Message}");
                    }
                }

                try
                {
                    backend.DestroyInterface(interfaceName);
                }
                catch (Exception ex)
                {
                    Program.Log($"Warning: Error closing WireGuard interface: {ex.Message}");
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Handles connection failure by recreating the Tunnel instance
        /// </summary>
        private void HandleConnectionFailure()
        {
            Program.Log("[WireGuardTunnel] Connection failure detected, recreating tunnel instance...");

            // Dispose old tunnel
            tunnel = null; // Let GC handle cleanup

            // Wait a bit before recreating
            Task.Delay(2000).Wait();

            // Create new tunnel instance
            tunnel = new Tunnel(onConnectionFailure: HandleConnectionFailure);
            tunnel.SetWireGuardTunnel(this);
            tunnel.Start();

            // Update UDP proxy to use new tunnel's UDP client
            if (udpProxy != null)
            {
                udpProxy = new WireGuardUdpProxy(tunnel.GetUdpClient());
            }

            Program.Log("[WireGuardTunnel] Tunnel instance recreated successfully");
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}