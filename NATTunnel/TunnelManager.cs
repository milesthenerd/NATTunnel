using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NATTunnel
{
    /// <summary>
    /// Manages multiple tunnel instances on a server.
    /// Maintains a persistent control connection to the mediation server and
    /// creates individual tunnel instances for each client connection.
    /// </summary>
    public class TunnelManager : IDisposable
    {
        private readonly WireGuardTunnel wireguardTunnel;
        private readonly bool isServer;
        private readonly IPEndPoint mediationEndpoint;
        private readonly UdpClient sharedUdpClient;  // Shared UDP client from registration tunnel

        // Control connection to mediation server (persistent)
        private TcpClient controlTcpClient;
        private NetworkStream controlStream;
        private Task controlListenerTask;
        private CancellationTokenSource controlCancellation;

        // Active tunnels (one per client connection)
        private Dictionary<int, Tunnel> activeTunnels = new Dictionary<int, Tunnel>();
        private object tunnelsLock = new object();

        // Health check and cleanup
        private Timer healthCheckTimer;
        private readonly TimeSpan inactivityTimeout = TimeSpan.FromMinutes(5); // Remove tunnels inactive for 5+ minutes
        private readonly TimeSpan healthCheckInterval = TimeSpan.FromSeconds(30); // Check every 30 seconds

        private bool isRunning = false;
        private bool disposedValue = false;

        public TunnelManager(WireGuardTunnel wireguardTunnel, bool isServer, UdpClient sharedUdpClient)
        {
            this.wireguardTunnel = wireguardTunnel;
            this.isServer = isServer;
            this.mediationEndpoint = TunnelOptions.MediationEndpoint;
            this.sharedUdpClient = sharedUdpClient;

            if (!isServer)
            {
                throw new InvalidOperationException("TunnelManager is only for server mode. Clients should use Tunnel directly.");
            }
        }

        /// <summary>
        /// Starts the tunnel manager and establishes control connection to mediation server
        /// </summary>
        public void Start()
        {
            if (isRunning)
            {
                Console.WriteLine("[TunnelManager] Already running");
                return;
            }

            Console.WriteLine("[TunnelManager] Starting tunnel manager...");

            try
            {
                // Establish control connection to mediation server
                controlTcpClient = new TcpClient();
                controlTcpClient.Connect(mediationEndpoint);
                controlStream = controlTcpClient.GetStream();

                Console.WriteLine($"[TunnelManager] ✓ Control connection established to {mediationEndpoint}");

                // Start control message listener
                controlCancellation = new CancellationTokenSource();
                controlListenerTask = Task.Run(() => ControlMessageLoop(controlCancellation.Token));

                // Register as server with mediation server
                MediationMessage registerMsg = new MediationMessage(MediationMessageType.ServerRegister);
                string serialized = registerMsg.Serialize();
                Console.WriteLine($"[TunnelManager] 📤 Sending ServerRegister message: {serialized}");
                byte[] sendBuffer = Encoding.ASCII.GetBytes(serialized);
                controlStream.Write(sendBuffer, 0, sendBuffer.Length);

                Console.WriteLine("[TunnelManager] ✓ Registered as server with mediation server");

                // Start health check timer for tunnel cleanup
                healthCheckTimer = new Timer(PerformHealthCheck, null,
                    (int)healthCheckInterval.TotalMilliseconds,
                    (int)healthCheckInterval.TotalMilliseconds);
                Console.WriteLine($"[TunnelManager] ✓ Health check timer started (interval: {healthCheckInterval.TotalSeconds}s, timeout: {inactivityTimeout.TotalMinutes}min)");

                isRunning = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TunnelManager] ⚠ Failed to start: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Control message loop - listens for coordination messages from mediation server
        /// </summary>
        private void ControlMessageLoop(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[8192];

            try
            {
                Console.WriteLine("[TunnelManager] Control message loop started");

                while (!cancellationToken.IsCancellationRequested && controlTcpClient.Connected)
                {
                    if (!controlStream.DataAvailable)
                    {
                        Thread.Sleep(10);
                        continue;
                    }

                    int bytesRead = controlStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("[TunnelManager] Control connection closed by server");
                        break;
                    }

                    string messageJson = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    Console.WriteLine($"[TunnelManager] Control message: {messageJson}");

                    try
                    {
                        MediationMessage message = JsonSerializer.Deserialize<MediationMessage>(messageJson);
                        HandleControlMessage(message);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[TunnelManager] Error parsing control message: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TunnelManager] Control loop error: {ex.Message}");
            }
            finally
            {
                Console.WriteLine("[TunnelManager] Control message loop ended");
            }
        }

        /// <summary>
        /// Handles coordination messages from mediation server
        /// </summary>
        private void HandleControlMessage(MediationMessage message)
        {
            Console.WriteLine($"[TunnelManager] 📨 Received control message ID: {message.ID}");

            switch (message.ID)
            {
                case MediationMessageType.ConnectionRequest:
                    // A client wants to connect - spin up a dedicated tunnel for this connection
                    Console.WriteLine($"[TunnelManager] ✓ Processing ConnectionRequest");
                    HandleConnectionRequest(message);
                    break;

                case MediationMessageType.ConnectionTimeout:
                    // A connection timed out - clean up the tunnel
                    HandleConnectionTimeout(message);
                    break;

                case MediationMessageType.KeepAlive:
                    // Keep-alive from mediation server
                    Console.WriteLine("[TunnelManager] Keep-alive received");
                    break;

                default:
                    Console.WriteLine($"[TunnelManager] Unhandled control message type: {message.ID}");
                    break;
            }
        }

        /// <summary>
        /// Handles incoming connection request by creating a dedicated tunnel instance
        /// </summary>
        private void HandleConnectionRequest(MediationMessage message)
        {
            Console.WriteLine($"[TunnelManager] Connection request received (ConnectionID: {message.ConnectionID})");
            Console.WriteLine($"[TunnelManager]   Client: {message.EndpointString}, NAT: {message.NATType}");

            try
            {
                // Create a fully independent tunnel instance for this client connection
                // Each tunnel will establish its own TCP connection, do NAT detection, and handle coordination
                Tunnel tunnel = new Tunnel(
                    onConnectionFailure: () => HandleTunnelFailure(message.ConnectionID),
                    managedByTunnelManager: false,  // Fully independent
                    connectionId: message.ConnectionID,
                    sharedUdpClient: null  // Each tunnel gets its own UDP socket
                );
                tunnel.SetWireGuardTunnel(wireguardTunnel);

                // Store the tunnel
                lock (tunnelsLock)
                {
                    activeTunnels[message.ConnectionID] = tunnel;
                }

                Console.WriteLine($"[TunnelManager] Created independent tunnel instance for connection {message.ConnectionID}");

                // Start the tunnel - it will handle everything (TCP connection, NAT detection, coordination, hole punching)
                Task.Run(() =>
                {
                    try
                    {
                        tunnel.Start();
                        Console.WriteLine($"[TunnelManager] Tunnel {message.ConnectionID} started successfully");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[TunnelManager] Error starting tunnel {message.ConnectionID}: {ex.Message}");
                        RemoveTunnel(message.ConnectionID);
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TunnelManager] Error creating tunnel for connection {message.ConnectionID}: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles connection timeout by cleaning up the associated tunnel
        /// </summary>
        private void HandleConnectionTimeout(MediationMessage message)
        {
            Console.WriteLine($"[TunnelManager] Connection {message.ConnectionID} timed out");
            RemoveTunnel(message.ConnectionID);
        }

        /// <summary>
        /// Handles tunnel failure by cleaning up and removing it
        /// </summary>
        private void HandleTunnelFailure(int connectionId)
        {
            Console.WriteLine($"[TunnelManager] Tunnel {connectionId} failed");
            RemoveTunnel(connectionId);
        }

        /// <summary>
        /// Removes a tunnel from the active tunnels dictionary
        /// </summary>
        private void RemoveTunnel(int connectionId)
        {
            lock (tunnelsLock)
            {
                if (activeTunnels.TryGetValue(connectionId, out Tunnel tunnel))
                {
                    // Clean up the tunnel (dispose resources)
                    try
                    {
                        tunnel.Dispose();
                        Console.WriteLine($"[TunnelManager] Removed and disposed tunnel {connectionId}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[TunnelManager] Error disposing tunnel {connectionId}: {ex.Message}");
                    }

                    activeTunnels.Remove(connectionId);
                    Console.WriteLine($"[TunnelManager] Tunnel {connectionId} removed. Active tunnels: {activeTunnels.Count}");
                }
            }
        }

        /// <summary>
        /// Gets the number of active tunnel connections
        /// </summary>
        public int GetActiveTunnelCount()
        {
            lock (tunnelsLock)
            {
                return activeTunnels.Count;
            }
        }

        /// <summary>
        /// Gets all active connection IDs
        /// </summary>
        public int[] GetActiveConnectionIds()
        {
            lock (tunnelsLock)
            {
                return activeTunnels.Keys.ToArray();
            }
        }

        /// <summary>
        /// Performs periodic health check on all active tunnels and removes inactive ones
        /// </summary>
        private void PerformHealthCheck(object state)
        {
            try
            {
                List<int> inactiveTunnels = new List<int>();

                lock (tunnelsLock)
                {
                    foreach (var kvp in activeTunnels)
                    {
                        int connectionId = kvp.Key;
                        Tunnel tunnel = kvp.Value;

                        var timeSinceActivity = tunnel.GetTimeSinceLastActivity();
                        var stats = tunnel.GetActivityStats();

                        // Check if tunnel has been inactive for too long
                        if (timeSinceActivity > inactivityTimeout)
                        {
                            Console.WriteLine($"[TunnelManager] 🔍 Tunnel {connectionId} inactive for {timeSinceActivity.TotalMinutes:F1} minutes");
                            Console.WriteLine($"[TunnelManager]    Stats: {stats.BytesReceived} bytes received, {stats.BytesSent} bytes sent");
                            Console.WriteLine($"[TunnelManager]    Last activity: {stats.LastActivity:yyyy-MM-dd HH:mm:ss} UTC");
                            inactiveTunnels.Add(connectionId);
                        }
                    }
                }

                // Remove inactive tunnels (outside the lock to avoid deadlock)
                foreach (int connectionId in inactiveTunnels)
                {
                    Console.WriteLine($"[TunnelManager] ⚠ Removing inactive tunnel {connectionId} (no activity for {inactivityTimeout.TotalMinutes} minutes)");
                    RemoveTunnel(connectionId);
                }

                // Log status if we have active tunnels
                int activeCount = GetActiveTunnelCount();
                if (activeCount > 0)
                {
                    Console.WriteLine($"[TunnelManager] 💓 Health check complete. Active tunnels: {activeCount}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TunnelManager] ⚠ Error during health check: {ex.Message}");
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Console.WriteLine("[TunnelManager] Disposing...");

                    // Stop health check timer
                    healthCheckTimer?.Dispose();

                    // Stop control connection
                    controlCancellation?.Cancel();
                    controlListenerTask?.Wait(TimeSpan.FromSeconds(5));
                    controlStream?.Close();
                    controlTcpClient?.Close();

                    // Clean up all active tunnels
                    lock (tunnelsLock)
                    {
                        foreach (var kvp in activeTunnels)
                        {
                            try
                            {
                                Console.WriteLine($"[TunnelManager] Disposing tunnel {kvp.Key}");
                                kvp.Value.Dispose();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[TunnelManager] Error disposing tunnel {kvp.Key}: {ex.Message}");
                            }
                        }
                        activeTunnels.Clear();
                    }

                    Console.WriteLine("[TunnelManager] ✓ Disposed");
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
