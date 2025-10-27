using System;
using System.Runtime.InteropServices;
using System.Net;
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
        private bool disposedValue;
        private bool tunnelStarted;
        private readonly bool debugMode;
        private readonly bool isRunningAsService;
        private WireGuardUdpProxy udpProxy;
        private IntPtr wireguardAdapter = IntPtr.Zero;
        private IntPtr wintunSession = IntPtr.Zero;
        private byte[] privateKey;
        private byte[] publicKey;
        private CancellationTokenSource packetLoopCancellation;
        private Task packetProcessingTask;
        private string clientAssignedIP; // Track client's assigned IP (null until assigned)

        /// <summary>
        /// Get the UDP proxy instance for forwarding packets
        /// </summary>
        public WireGuardUdpProxy GetUdpProxy() => udpProxy;

        public WireGuardTunnel(bool isServer, string interfaceName, bool debugMode = false, bool isRunningAsService = false)
        {
            this.interfaceName = interfaceName;
            this.debugMode = debugMode;
            this.isRunningAsService = isRunningAsService;

            try
            {
                Console.WriteLine($"Creating new WireGuard tunnel (Server: {isServer}, Interface: {interfaceName})");
                if (debugMode)
                {
                    Console.WriteLine(">>> DEBUG MODE ENABLED - Skipping service installation");
                }
                if (isRunningAsService)
                {
                    Console.WriteLine(">>> SERVICE MODE ENABLED - Skipping service installation (already managed by Windows Service Manager)");
                }

                // Set up base config path
                configFilePath = EnsureConfigPath("wg");
                Console.WriteLine($"Base config path: {configFilePath}");

                // Generate or reuse WireGuard keys
                string privateKeyBase64;
                string publicKeyBase64;

                if (File.Exists(configFilePath))
                {
                    // Config already exists - extract the existing private key and derive public key
                    Console.WriteLine("Loading existing WireGuard keys from config...");
                    privateKeyBase64 = ExtractPrivateKeyFromConfig(configFilePath);
                    publicKeyBase64 = WireGuardConfig.GetPublicKeyFromConfig(configFilePath);
                    Console.WriteLine("✓ Loaded existing WireGuard keys");
                }
                else
                {
                    // Config doesn't exist - generate new keypair
                    Console.WriteLine("Generating new WireGuard keys...");
                    var (privKey, pubKey) = WireGuardConfig.GenerateKeyPair();
                    privateKeyBase64 = privKey;
                    publicKeyBase64 = pubKey;
                }

                // Decode base64 keys to binary for WireGuard API
                this.privateKey = Convert.FromBase64String(privateKeyBase64);
                this.publicKey = Convert.FromBase64String(publicKeyBase64);

                Console.WriteLine("Generating/updating WireGuard config...");

                // Determine interface address based on role
                string interfaceAddress = isServer ? "10.5.0.1/24" : "10.5.0.2/24";

                // Generate config with ONLY the [Interface] section
                // Peers will be added dynamically by WireGuardPeerManager
                WireGuardConfig.GenerateInterfaceOnlyConfig(
                    privateKeyBase64,
                    interfaceName,
                    configFilePath,
                    interfaceAddress);

                Console.WriteLine($"WireGuard config: {configFilePath}");
                Console.WriteLine($"WireGuard will listen on port: 51820 (localhost only)");

                // Initialize peer manager
                Console.WriteLine("Initializing peer manager...");
                var baseAddress = IPAddress.Parse("10.5.0.0");
                peerManager = new WireGuardPeerManager(configFilePath, baseAddress, 51820, TunnelOptions.IsServer);

                // Initialize the tunnel (skip in debug mode or if already running as service)
                if (!debugMode && !isRunningAsService)
                {
                    InitializeTunnel();
                }
                else if (isRunningAsService)
                {
                    Console.WriteLine(">>> Service mode: Bringing up WireGuard interface...");
                    BringUpWireGuardInterface();
                    tunnelStarted = true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during tunnel creation: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
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
                                Console.WriteLine("✓ Extracted private key from config");
                                return privateKey;
                            }
                        }
                    }
                }

                throw new Exception("Could not find PrivateKey in config file");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error extracting private key from config: {ex.Message}");
                throw;
            }
        }

        private void InitializeTunnel()
        {
            try
            {
                Console.WriteLine("Initializing WireGuard tunnel");
                Console.WriteLine($"Using config path: {configFilePath}");

                // Check elevation first
                Console.WriteLine("Checking for administrative privileges...");
                bool elevated = IsElevated();
                Console.WriteLine($"Running with administrative privileges: {elevated}");

                if (!elevated)
                {
                    Console.WriteLine("Attempting to restart with administrative privileges...");
                    RestartElevated();
                    return;
                }

                // Bring up the WireGuard interface directly
                Console.WriteLine("Bringing up WireGuard interface...");
                BringUpWireGuardInterface();

                tunnelStarted = true;
                Console.WriteLine("WireGuard tunnel initialized successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during tunnel initialization: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        private void BringUpWireGuardInterface()
        {
            try
            {
                Console.WriteLine($"Bringing up WireGuard-NT interface: {interfaceName}");

                // Create/Open WireGuard-NT adapter
                wireguardAdapter = WireGuardAPI.CreateAdapter(interfaceName);

                // Get adapter LUID for IP configuration
                WireGuardNTAPI.WireGuardGetAdapterLUID(wireguardAdapter, out ulong luid);
                Console.WriteLine($"✓ Adapter LUID: {luid}");

                // Configure WireGuard-NT with interface settings (private key, listen port)
                Console.WriteLine("Configuring WireGuard-NT interface...");
                ConfigureWireGuardNT();

                // Assign IP address to the interface based on role
                string assignedIp = TunnelOptions.IsServer ? "10.5.0.1" : "10.5.0.2";
                Console.WriteLine($"Assigning IP address {assignedIp}/24 to interface...");
                WireGuardAPI.AssignIPAddress(wireguardAdapter, interfaceName, assignedIp, 24);

                // Enable the interface using netsh (WireGuard adapters don't have a SetAdapterState API)
                Console.WriteLine("Enabling WireGuard-NT interface...");
                var enablePsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"interface set interface \"{interfaceName}\" admin=enabled",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    Verb = "runas"
                };

                using (var enableProcess = System.Diagnostics.Process.Start(enablePsi))
                {
                    enableProcess.WaitForExit();
                    if (enableProcess.ExitCode != 0)
                    {
                        string error = enableProcess.StandardError.ReadToEnd();
                        Console.WriteLine($"⚠ Warning: Failed to enable interface via netsh: {error}");
                        Console.WriteLine("   Interface may already be enabled or will auto-enable with configuration");
                    }
                    else
                    {
                        Console.WriteLine("✓ WireGuard-NT interface enabled");
                    }
                }

                // Force the WireGuard adapter to UP state using WireGuard-NT API
                Console.WriteLine("Setting WireGuard adapter state to UP...");
                bool adapterStateSet = WireGuardNTAPI.WireGuardSetAdapterState(
                    wireguardAdapter,
                    WireGuardNTAPI.WIREGUARD_ADAPTER_STATE.WIREGUARD_ADAPTER_STATE_UP
                );

                if (adapterStateSet)
                {
                    Console.WriteLine("✓ WireGuard adapter set to UP state");
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"⚠ Failed to set adapter state to UP (Error: {error})");
                }

                // Brief delay to allow interface to come up
                System.Threading.Thread.Sleep(1000);

                // Verify interface status
                Console.WriteLine("Checking WireGuard interface status...");
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
                        Console.WriteLine($"WireGuard status:\n{output}");
                    }
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        Console.WriteLine($"⚠ WireGuard status error: {error}");
                    }
                }

                // Register this tunnel with the Clients class so it can add peers
                Clients.SetWireGuardTunnel(this);

                // Also register with Tunnel so clients can restart with assigned IP
                Tunnel.SetWireGuardTunnel(this);

                // Start the mediation tunnel to connect to the mediation server
                Console.WriteLine("Starting mediation tunnel connection...");
                Tunnel.Start();

                // Start UDP proxy to forward WireGuard traffic bidirectionally
                Console.WriteLine("Starting WireGuard UDP proxy...");
                udpProxy = new WireGuardUdpProxy(Tunnel.GetUdpClient());

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
                                    Console.WriteLine($"[Endpoint Reset] Failed for peer {peer.PublicKey.Substring(0, 8)}: {err}");
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[Endpoint Reset] Error: {ex.Message}");
                            }
                        }
                    }
                });

                // Check interface connectivity status
                Task.Run(async () =>
                {
                    await Task.Delay(3000); // Wait 3 seconds for everything to settle
                    Console.WriteLine("\n[Status Check] Verifying WireGuard interface connectivity...");
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
                            Console.WriteLine($"[Status Check] Interface: {line.Trim()}");
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
                    Console.WriteLine($"[Status Check] WireGuard status:\n{wgOutput}");
                });

                tunnelStarted = true;
                Console.WriteLine("✅ WireGuard-NT tunnel initialized successfully");
                Console.WriteLine("   All WireGuard crypto is handled by the kernel driver");
                Console.WriteLine("   UDP proxy bridges WireGuard (localhost:51820) with NAT-traversed peers");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error bringing up WireGuard interface: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        /// <summary>
        /// Configures WireGuard-NT interface with private key and listen port using wg.exe
        /// </summary>
        private void ConfigureWireGuardNT()
        {
            try
            {
                Console.WriteLine($"Configuring WireGuard interface using wg.exe...");

                // Create a temporary config file with only WireGuard-native fields
                // wg.exe doesn't understand Address, Name, etc. - those are wg-quick extensions
                string tempConfigPath = Path.Combine(Path.GetTempPath(), $"wg_{interfaceName}_{Guid.NewGuid()}.conf");

                try
                {
                    // Read the original config and extract only PrivateKey, ListenPort, and [Peer] sections
                    var lines = File.ReadAllLines(configFilePath);
                    var wgLines = new List<string>();
                    bool inInterface = false;
                    bool inPeer = false;

                    wgLines.Add("[Interface]");
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();

                        if (trimmed.StartsWith("[Interface]"))
                        {
                            inInterface = true;
                            inPeer = false;
                            continue;
                        }
                        else if (trimmed.StartsWith("[Peer]"))
                        {
                            inInterface = false;
                            inPeer = true;
                            wgLines.Add("");
                            wgLines.Add("[Peer]");
                            continue;
                        }

                        if (inInterface)
                        {
                            // Only include PrivateKey and ListenPort
                            if (trimmed.StartsWith("PrivateKey") || trimmed.StartsWith("ListenPort"))
                            {
                                wgLines.Add(trimmed);
                            }
                        }
                        else if (inPeer)
                        {
                            // Include all peer fields
                            if (!string.IsNullOrWhiteSpace(trimmed))
                            {
                                wgLines.Add(trimmed);
                            }
                        }
                    }

                    File.WriteAllLines(tempConfigPath, wgLines);
                    Console.WriteLine($"Created temporary WireGuard config: {tempConfigPath}");

                    // Use wg.exe to configure the interface
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "wg.exe",
                        Arguments = $"setconf {interfaceName} \"{tempConfigPath}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (var process = System.Diagnostics.Process.Start(psi))
                    {
                        process.WaitForExit();
                        string output = process.StandardOutput.ReadToEnd();
                        string error = process.StandardError.ReadToEnd();

                        if (process.ExitCode != 0)
                        {
                            Console.WriteLine($"wg.exe error output: {error}");
                            throw new Exception($"Failed to configure WireGuard interface (wg.exe exit code: {process.ExitCode})");
                        }

                        if (!string.IsNullOrWhiteSpace(output))
                        {
                            Console.WriteLine($"wg.exe output: {output}");
                        }
                    }

                    Console.WriteLine("✓ WireGuard interface configured successfully");
                }
                finally
                {
                    // Clean up temporary config file
                    if (File.Exists(tempConfigPath))
                    {
                        File.Delete(tempConfigPath);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error configuring WireGuard-NT: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// OLD: Configures WireGuard-NT interface with private key using low-level API (doesn't work - Error 87)
        /// </summary>
        /*
        private void ConfigureWireGuardNT_OLD()
        {
            try
            {
                // Ensure private key is exactly 32 bytes
                if (privateKey == null || privateKey.Length != 32)
                {
                    throw new Exception($"Private key must be exactly 32 bytes (got {privateKey?.Length ?? 0})");
                }

                Console.WriteLine($"[DEBUG] Configuring with:");
                Console.WriteLine($"  Private Key: {Convert.ToBase64String(privateKey).Substring(0, 8)}... ({privateKey.Length} bytes)");
                Console.WriteLine($"  Private Key (hex): {BitConverter.ToString(privateKey).Replace("-", " ")}");
                Console.WriteLine($"  Peers Count: 0");

                // Build configuration structure - use ONLY HAS_PRIVATE_KEY flag like the official example
                // Official example: .Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY, .PeersCount = 1
                // NO LISTEN_PORT or PUBLIC_KEY flags!
                int size = 74; // Just the interface structure with no peers
                IntPtr configPtr = Marshal.AllocHGlobal(size);
                try
                {
                    uint flags = WireGuardNTAPI.WIREGUARD_INTERFACE_HAS_PRIVATE_KEY; // ONLY private key flag
                    ushort listenPort = 0; // NOT SET - let driver choose
                    uint peersCount = 0;
                    
                    // Write structure manually to ensure exact layout
                    int offset = 0;
                    
                    // Flags (4 bytes)
                    Marshal.WriteInt32(configPtr, offset, (int)flags);
                    offset += 4;
                    
                    // ListenPort (2 bytes)
                    Marshal.WriteInt16(configPtr, offset, (short)listenPort);
                    offset += 2;
                    
                    // PrivateKey (32 bytes)
                    Marshal.Copy(privateKey, 0, IntPtr.Add(configPtr, offset), 32);
                    offset += 32;
                    
                    // PublicKey (32 bytes) - NOT SET, leave as zeros (driver derives it)
                    byte[] zeroKey = new byte[32];
                    Marshal.Copy(zeroKey, 0, IntPtr.Add(configPtr, offset), 32);
                    offset += 32;
                    
                    // PeersCount (4 bytes)
                    Marshal.WriteInt32(configPtr, offset, (int)peersCount);
                    offset += 4;

                    Console.WriteLine($"[DEBUG] Manual structure size: {size} bytes (offset check: {offset})");
                    Console.WriteLine($"[DEBUG] Flags: 0x{flags:X}");
                    Console.WriteLine($"[DEBUG] Dumping entire {size}-byte config:");
                    for (int i = 0; i < size; i++)
                    {
                        byte b = Marshal.ReadByte(configPtr, i);
                        Console.Write($"{b:X2} ");
                        if ((i + 1) % 16 == 0) Console.WriteLine();
                    }
                    Console.WriteLine();

                    // Apply configuration
                    Console.WriteLine($"[DEBUG] Calling WireGuardSetConfiguration(adapter={wireguardAdapter}, config={configPtr}, size={size})");
                    
                    // Check adapter state before configuration
                    WireGuardNTAPI.WireGuardGetAdapterState(wireguardAdapter, out var stateBefore);
                    Console.WriteLine($"[DEBUG] Adapter state before config: {stateBefore}");
                    
                    bool success = WireGuardNTAPI.WireGuardSetConfiguration(wireguardAdapter, configPtr, (uint)size);
                    
                    if (!success)
                    {
                        int error = Marshal.GetLastWin32Error();
                        Console.WriteLine($"[DEBUG] WireGuardSetConfiguration failed with error {error}");
                        
                        // Error 87 = ERROR_INVALID_PARAMETER
                        if (error == 87)
                        {
                            Console.WriteLine($"[DEBUG] ERROR_INVALID_PARAMETER");
                            Console.WriteLine($"[DEBUG] Dumping first 16 bytes of config:");
                            for (int i = 0; i < Math.Min(16, size); i++)
                            {
                                byte b = Marshal.ReadByte(configPtr, i);
                                Console.Write($"{b:X2} ");
                            }
                            Console.WriteLine();
                        }
                        
                        throw new Exception($"Failed to set WireGuard-NT configuration (Error: {error})");
                    }

                    Console.WriteLine("✓ WireGuard-NT interface configured with private key and listen port 51820");
                }
                finally
                {
                    Marshal.FreeHGlobal(configPtr);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error configuring WireGuard-NT: {ex.Message}");
                throw;
            }
        }
        */

        /// <summary>
        /// Main packet processing loop - reads packets from Wintun and forwards them
        /// NOTE: With WireGuard-NT, packet processing is handled by the kernel driver
        /// This method is no longer needed but kept for reference
        /// </summary>
        private void PacketProcessingLoop(CancellationToken cancellationToken)
        {
            Console.WriteLine("Packet processing loop running...");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        // Use WintunGetReadPacket for reading individual packets from Wintun
                        // This is the standard Wintun API approach
                        IntPtr packetPtr = WireGuardAPI.GetReadPacket(wintunSession, out uint packetSize);

                        if (packetPtr != IntPtr.Zero && packetSize > 0)
                        {
                            try
                            {
                                // Read packet data
                                byte[] packetData = new byte[packetSize];
                                Marshal.Copy(packetPtr, packetData, 0, (int)packetSize);

                                // Uncomment for debugging packet reception:
                                // Console.WriteLine($"Received packet from Wintun: {packetSize} bytes");

                                // TODO: Forward packet through mediation tunnel
                                // This would involve:
                                // 1. Parse the IP packet using PacketDotNet
                                // 2. Encrypt it with peer's symmetric key
                                // 3. Send via UDP to the peer through Tunnel.cs

                                // For now, just log receipt
                                // In production, you'd call something like:
                                // Tunnel.ForwardPacketToPeer(packetData);
                            }
                            finally
                            {
                                // Always release the packet back to Wintun
                                WireGuardAPI.ReleaseReadPacket(wintunSession, packetPtr);
                            }
                        }
                        else
                        {
                            // No packet available, wait a bit
                            Thread.Sleep(1);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!cancellationToken.IsCancellationRequested)
                        {
                            Console.WriteLine($"Error in packet processing loop: {ex.Message}");
                            Thread.Sleep(100); // Back off on error
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Packet processing loop terminated with error: {ex.Message}");
            }
            finally
            {
                Console.WriteLine("Packet processing loop stopped");
            }
        }

        /// <summary>
        /// Sends a packet through the Wintun tunnel
        /// </summary>
        public void SendPacket(byte[] packetData)
        {
            if (wintunSession == IntPtr.Zero)
            {
                Console.WriteLine("⚠ Cannot send packet: Wintun session not initialized");
                return;
            }

            try
            {
                // Allocate write packet buffer using standard Wintun API
                IntPtr packet = WireGuardAPI.AllocateWritePacket(wintunSession, (uint)packetData.Length);

                if (packet != IntPtr.Zero)
                {
                    // Copy packet data to the buffer
                    Marshal.Copy(packetData, 0, packet, packetData.Length);

                    // Commit the packet to send it
                    WireGuardAPI.CommitWritePacket(wintunSession, packet);

                    Console.WriteLine($"Sent packet through Wintun: {packetData.Length} bytes");
                }
                else
                {
                    Console.WriteLine("⚠ Failed to allocate write packet buffer");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending packet: {ex.Message}");
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
            var peer = peerManager.AddPeer(publicKey, endpoint, isPersistent);
            Console.WriteLine($"✓ Added peer dynamically: {publicKey.Substring(0, 8)}... -> {peer.PrivateAddress} (proxy port: {peer.ProxyPort})");

            // Register peer with UDP proxy for outbound routing WITH tunnel IP for multi-peer support
            if (udpProxy != null)
            {
                udpProxy.RegisterPeer(endpoint, peer.ProxyPort, peer.PrivateAddress);
            }

            // Regenerate config file with new peer
            Console.WriteLine($"[DEBUG] Regenerating config file with peer(s)");
            RegenerateConfigWithPeers();

            // Debug: Show what was written to config
            Console.WriteLine($"[DEBUG] Config file contents after adding peer:");
            var configLines = File.ReadAllLines(configFilePath);
            foreach (var line in configLines)
            {
                Console.WriteLine($"  {line}");
            }

            // Update WireGuard-NT configuration dynamically
            if (tunnelStarted && wireguardAdapter != IntPtr.Zero)
            {
                Console.WriteLine($"[DEBUG] Updating WireGuard-NT with new peer configuration");
                WireGuardNT.UpdateConfiguration(wireguardAdapter, configFilePath, interfaceName);

                // Try to trigger WireGuard to send a packet immediately by setting keepalive to 1 second
                Console.WriteLine("[DEBUG] Attempting to trigger immediate WireGuard keepalive...");
                Task.Run(async () =>
                {
                    await Task.Delay(1000); // Wait for config to apply
                    try
                    {
                        var triggerPsi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "wg",
                            Arguments = $"set {interfaceName} peer {publicKey} persistent-keepalive 1",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };
                        using var proc = System.Diagnostics.Process.Start(triggerPsi);
                        var err = proc.StandardError.ReadToEnd();
                        proc.WaitForExit();
                        if (proc.ExitCode == 0)
                        {
                            Console.WriteLine($"[DEBUG] Set keepalive to 1 second to trigger immediate packet");
                        }
                        else
                        {
                            Console.WriteLine($"[DEBUG] Failed to set keepalive: {err}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[DEBUG] Error triggering keepalive: {ex.Message}");
                    }
                });
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
                    Console.WriteLine($"[DEBUG] Using client assigned IP: {assignedIp}");
                }
                else
                {
                    assignedIp = TunnelOptions.IsServer ? "10.5.0.1" : "10.5.0.2";
                    Console.WriteLine($"[DEBUG] Using default IP: {assignedIp}");
                }

                config.AppendLine($"Address = {assignedIp}/24");
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
                var peerCount = peerManager.GetAllPeers().ToList().Count;
                Console.WriteLine($"[DEBUG] Regenerated config with {peerCount} peer(s)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠ Error regenerating config: {ex.Message}");
            }
        }

        public WireGuardPeer AddPeer(string publicKey, IPEndPoint endpoint, IPAddress privateAddress, bool isPersistent = false)
        {
            var peer = peerManager.AddPeer(publicKey, endpoint, privateAddress, isPersistent);
            Console.WriteLine($"✓ Added peer dynamically: {publicKey.Substring(0, 8)}... -> {privateAddress} (proxy port: {peer.ProxyPort})");

            // Register peer with UDP proxy for outbound routing WITH tunnel IP for multi-peer support
            if (udpProxy != null)
            {
                udpProxy.RegisterPeer(endpoint, peer.ProxyPort, peer.PrivateAddress);
            }

            // Update WireGuard-NT configuration dynamically
            if (tunnelStarted && wireguardAdapter != IntPtr.Zero)
            {
                Console.WriteLine($"[DEBUG] Updating WireGuard-NT with new peer configuration");
                WireGuardNT.UpdateConfiguration(wireguardAdapter, configFilePath);
            }

            return peer;
        }

        public void RemovePeer(int connectionId)
        {
            var peer = peerManager.GetPeer(connectionId);
            if (peer != null)
            {
                Console.WriteLine($"✓ Removed peer: {peer.PublicKey.Substring(0, 8)}...");
            }
            peerManager.RemovePeer(connectionId);

            // Update WireGuard-NT configuration dynamically
            if (tunnelStarted && wireguardAdapter != IntPtr.Zero)
            {
                Console.WriteLine($"[DEBUG] Updating WireGuard-NT with updated peer list");
                WireGuardNT.UpdateConfiguration(wireguardAdapter, configFilePath);
            }
        }

        public WireGuardPeer GetPeer(int connectionId) => peerManager.GetPeer(connectionId);
        public WireGuardPeer GetPeer(IPAddress privateAddress) => peerManager.GetPeer(privateAddress);
        public WireGuardPeer GetPeer(IPEndPoint endpoint) => peerManager.GetPeer(endpoint);
        public IEnumerable<WireGuardPeer> GetAllPeers() => peerManager.GetAllPeers();
        public int GetPeerCount() => peerManager.GetPeerCount();
        public string GetConfigPath() => configFilePath;

        /// <summary>
        /// For clients: Updates the tunnel with the assigned private IP address
        /// </summary>
        public void SetClientIPAndRestart(string assignedIpAddress, byte prefixLength = 24)
        {
            try
            {
                Console.WriteLine($"Client updating tunnel configuration with IP: {assignedIpAddress}/{prefixLength}");

                // Store the assigned IP for config generation
                clientAssignedIP = assignedIpAddress;

                // CRITICAL: First, list and remove ALL existing IP addresses from the interface
                Console.WriteLine($"Checking existing IP addresses on interface {interfaceName}...");
                try
                {
                    // First, show what IPs exist
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
                            Console.WriteLine($"Existing IPs on {interfaceName}: {existingIPs.Trim()}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Could not list IPs: {ex.Message}");
                }

                Console.WriteLine($"Removing all existing IP addresses from interface {interfaceName}...");
                try
                {
                    // Remove all IPs using PowerShell cmdlet
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
                            Console.WriteLine($"PowerShell IP removal completed (exit code: {deleteProc.ExitCode})");
                            if (!string.IsNullOrWhiteSpace(output)) Console.WriteLine($"Output: {output}");
                            if (!string.IsNullOrWhiteSpace(error)) Console.WriteLine($"Error: {error}");
                        }
                    }

                    System.Threading.Thread.Sleep(1000);  // Wait for system to process removal
                }
                catch (Exception cleanupEx)
                {
                    Console.WriteLine($"Warning: Could not cleanup old IPs via PowerShell: {cleanupEx.Message}");
                }

                // Update the interface IP via netsh (don't regenerate keys!)
                Console.WriteLine($"Updating interface IP via netsh...");
                WireGuardAPI.AssignIPAddress(wireguardAdapter, interfaceName, assignedIpAddress, prefixLength);

                // Update the config file to reflect the new IP (keep existing keys and peers)
                RegenerateConfigWithPeers();

                // Force WireGuard-NT to reload config
                Console.WriteLine($"Reloading WireGuard-NT configuration...");
                WireGuardNT.UpdateConfiguration(wireguardAdapter, configFilePath);

                Console.WriteLine($"✓ Client tunnel updated with IP {assignedIpAddress}/{prefixLength}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating tunnel: {ex.Message}");
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
                            Console.WriteLine("Stopping UDP proxy...");
                            udpProxy.Dispose();
                            udpProxy = null;
                        }

                        // Stop packet processing loop
                        if (packetLoopCancellation != null)
                        {
                            Console.WriteLine("Stopping packet processing loop...");
                            packetLoopCancellation.Cancel();

                            if (packetProcessingTask != null)
                            {
                                try
                                {
                                    packetProcessingTask.Wait(5000); // Wait up to 5 seconds
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Warning: Error waiting for packet loop: {ex.Message}");
                                }
                            }

                            packetLoopCancellation.Dispose();
                            packetLoopCancellation = null;
                        }

                        // Stop WireGuard service but keep config for reconnection
                        if (tunnelStarted)
                        {
                            // Uninstall the service
                            WireGuardService.UninstallService(interfaceName);
                            tunnelStarted = false;
                            Console.WriteLine("WireGuard service uninstalled");
                        }

                        // DON'T delete config file - keep it for reconnection
                        // The config will be reused or regenerated on next startup
                        Console.WriteLine("✓ Config file preserved for reconnection");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Error during cleanup: {ex.Message}");
                    }
                }

                // Close WireGuard adapter if it's open
                if (wireguardAdapter != IntPtr.Zero)
                {
                    try
                    {
                        // End the Wintun session first
                        if (wintunSession != IntPtr.Zero)
                        {
                            WireGuardAPI.EndWintunSession(wintunSession);
                            wintunSession = IntPtr.Zero;
                        }

                        WireGuardAPI.CloseAdapter(wireguardAdapter);
                        wireguardAdapter = IntPtr.Zero;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Error closing WireGuard adapter: {ex.Message}");
                    }
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}