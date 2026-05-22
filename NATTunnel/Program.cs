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

    /// <summary>Set when AllowRelayThrough flips false; engine drops hosted relay routes on next tick.</summary>
    public static volatile bool RelayHostingDisableRequested;

    /// <summary>Bounded ring of recent log lines, served by GET /logs.</summary>
    private const int MaxLogLines = 500;
    private static readonly System.Collections.Concurrent.ConcurrentQueue<(long Seq, string Line)> RecentLogs = new();
    private static long logSeq;

    /// <summary>Populated by RunMeshMode once engine state exists; GET /status uses this.</summary>
    internal static Func<MeshState> meshStateProvider = () => new MeshState
    {
        ConnectionState = "Disconnected",
        NetworkID = TunnelOptions.NetworkID,
        OwnMeshIP = null,
        OwnPeerID = null,
        NATType = null,
        UptimeSeconds = 0,
    };

    public static void Log(string message)
    {
        string line = $"[{DateTime.UtcNow:HH:mm:ss}] {message}";
        Console.WriteLine(line);
        long seq = System.Threading.Interlocked.Increment(ref logSeq);
        RecentLogs.Enqueue((seq, line));
        while (RecentLogs.Count > MaxLogLines && RecentLogs.TryDequeue(out _)) { }
    }

    /// <summary>Short deterministic interface name "nt-XXXXXXXX"; fits Linux's 15-byte IFNAMSIZ limit.</summary>
    public static string BuildInterfaceName(string networkID)
    {
        byte[] hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(networkID ?? ""));
        return "nt-" + Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
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
        WireGuardTunnel wireguardTunnel = null;
        WireGuardUdpProxy udpProxy = null;
        try
        {
            // Start the HTTP control/status endpoint first so the GUI can fetch logs
            // (and serve `/status` etc.) immediately, before any of the slow setup below.
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
                                var meshState = meshStateProvider();
                                var json = JsonSerializer.Serialize(meshState, new JsonSerializerOptions { WriteIndented = true });
                                byte[] buffer = Encoding.UTF8.GetBytes(json);

                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = buffer.Length;
                                context.Response.OutputStream.Write(buffer, 0, buffer.Length);
                                context.Response.OutputStream.Close();
                            }
                            else if (method == "GET" && rawUrl != null && rawUrl.StartsWith("/logs"))
                            {
                                long since = 0;
                                int qIdx = rawUrl.IndexOf("since=", StringComparison.Ordinal);
                                if (qIdx >= 0) long.TryParse(rawUrl[(qIdx + 6)..].Split('&')[0], out since);

                                var snapshot = RecentLogs.ToArray();
                                var newLines = new List<string>(snapshot.Length);
                                long latest = since;
                                foreach (var entry in snapshot)
                                {
                                    if (entry.Seq > latest) latest = entry.Seq;
                                    if (entry.Seq > since) newLines.Add(entry.Line);
                                }
                                var payload = JsonSerializer.Serialize(new { latestSeq = latest, lines = newLines });
                                byte[] buffer = Encoding.UTF8.GetBytes(payload);

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
                            else if (method == "GET" && rawUrl == "/config")
                            {
                                var snapshot = new ConfigSnapshot
                                {
                                    MediationEndpoint = TunnelOptions.MediationEndpoint?.ToString(),
                                    NetworkID = TunnelOptions.NetworkID,
                                    NetworkSecret = TunnelOptions.NetworkSecret,
                                    MeshSubnet = TunnelOptions.MeshSubnet,
                                    HeartbeatIntervalSeconds = TunnelOptions.HeartbeatIntervalSeconds,
                                    ProbeIntervalSeconds = TunnelOptions.ProbeIntervalSeconds,
                                    StaleTimeoutSeconds = TunnelOptions.StaleTimeoutSeconds,
                                    RepairCooldownSeconds = TunnelOptions.RepairCooldownSeconds,
                                    DeadThreshold = TunnelOptions.DeadThreshold,
                                    GracePeriodSecondsNonSymmetric = TunnelOptions.GracePeriodSecondsNonSymmetric,
                                    GracePeriodSecondsSymmetric = TunnelOptions.GracePeriodSecondsSymmetric,
                                    IsolationGracePeriodSeconds = TunnelOptions.IsolationGracePeriodSeconds,
                                    PeerID = TunnelOptions.PeerID?.ToString(),
                                    AllowRelayThrough = TunnelOptions.AllowRelayThrough,
                                    RelayCapacity = TunnelOptions.OwnRelayCapacity.ToString(),
                                    RelayHealthTimeoutSeconds = TunnelOptions.RelayHealthTimeoutSeconds,
                                    RelayReselectCooldownSeconds = TunnelOptions.RelayReselectCooldownSeconds,
                                    RelayLoadFactorMs = TunnelOptions.RelayLoadFactorMs,
                                    RelayReselectMinImprovement = TunnelOptions.RelayReselectMinImprovement,
                                };
                                byte[] buffer = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot));
                                context.Response.ContentType = "application/json";
                                context.Response.ContentLength64 = buffer.Length;
                                context.Response.OutputStream.Write(buffer, 0, buffer.Length);
                                context.Response.OutputStream.Close();
                            }
                            else if (method == "POST" && rawUrl == "/config")
                            {
                                string body;
                                using (var reader = new System.IO.StreamReader(context.Request.InputStream, Encoding.UTF8))
                                    body = reader.ReadToEnd();
                                try
                                {
                                    var snapshot = JsonSerializer.Deserialize<ConfigSnapshot>(body);
                                    if (snapshot == null) throw new Exception("Empty payload");

                                    TunnelOptions.HeartbeatIntervalSeconds = snapshot.HeartbeatIntervalSeconds;
                                    TunnelOptions.ProbeIntervalSeconds = snapshot.ProbeIntervalSeconds;
                                    TunnelOptions.StaleTimeoutSeconds = snapshot.StaleTimeoutSeconds;
                                    TunnelOptions.RepairCooldownSeconds = snapshot.RepairCooldownSeconds;
                                    TunnelOptions.DeadThreshold = snapshot.DeadThreshold;
                                    TunnelOptions.GracePeriodSecondsNonSymmetric = snapshot.GracePeriodSecondsNonSymmetric;
                                    TunnelOptions.GracePeriodSecondsSymmetric = snapshot.GracePeriodSecondsSymmetric;
                                    TunnelOptions.IsolationGracePeriodSeconds = snapshot.IsolationGracePeriodSeconds;
                                    bool wasAllowingRelay = TunnelOptions.AllowRelayThrough;
                                    TunnelOptions.AllowRelayThrough = snapshot.AllowRelayThrough;
                                    if (wasAllowingRelay && !snapshot.AllowRelayThrough)
                                        RelayHostingDisableRequested = true;
                                    if (Enum.TryParse<RelayCapacity>(snapshot.RelayCapacity ?? "", true, out var parsedCap))
                                        TunnelOptions.OwnRelayCapacity = parsedCap;
                                    if (snapshot.RelayHealthTimeoutSeconds > 0) TunnelOptions.RelayHealthTimeoutSeconds = snapshot.RelayHealthTimeoutSeconds;
                                    if (snapshot.RelayReselectCooldownSeconds > 0) TunnelOptions.RelayReselectCooldownSeconds = snapshot.RelayReselectCooldownSeconds;
                                    if (snapshot.RelayLoadFactorMs > 0) TunnelOptions.RelayLoadFactorMs = snapshot.RelayLoadFactorMs;
                                    if (snapshot.RelayReselectMinImprovement > 0) TunnelOptions.RelayReselectMinImprovement = snapshot.RelayReselectMinImprovement;

                                    Config.SaveAllSettings(
                                        snapshot.MediationEndpoint ?? "",
                                        snapshot.NetworkID ?? "",
                                        snapshot.NetworkSecret ?? "",
                                        snapshot.MeshSubnet ?? "",
                                        snapshot.HeartbeatIntervalSeconds,
                                        snapshot.ProbeIntervalSeconds,
                                        snapshot.StaleTimeoutSeconds,
                                        snapshot.RepairCooldownSeconds,
                                        snapshot.DeadThreshold,
                                        snapshot.GracePeriodSecondsNonSymmetric,
                                        snapshot.GracePeriodSecondsSymmetric,
                                        snapshot.IsolationGracePeriodSeconds,
                                        TunnelOptions.AllowRelayThrough,
                                        TunnelOptions.OwnRelayCapacity.ToString(),
                                        TunnelOptions.RelayHealthTimeoutSeconds,
                                        TunnelOptions.RelayReselectCooldownSeconds,
                                        TunnelOptions.RelayLoadFactorMs,
                                        TunnelOptions.RelayReselectMinImprovement);

                                    Config.TryLoadConfig();
                                    byte[] resp = Encoding.UTF8.GetBytes("{\"status\":\"saved\"}");
                                    context.Response.ContentType = "application/json";
                                    context.Response.ContentLength64 = resp.Length;
                                    context.Response.OutputStream.Write(resp, 0, resp.Length);
                                    context.Response.OutputStream.Close();
                                }
                                catch (Exception ex)
                                {
                                    context.Response.StatusCode = 400;
                                    byte[] resp = Encoding.UTF8.GetBytes($"{{\"error\":\"{ex.Message}\"}}");
                                    context.Response.ContentType = "application/json";
                                    context.Response.ContentLength64 = resp.Length;
                                    context.Response.OutputStream.Write(resp, 0, resp.Length);
                                    context.Response.OutputStream.Close();
                                }
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
            string interfaceName = BuildInterfaceName(TunnelOptions.NetworkID);
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";
            wireguardTunnel = new WireGuardTunnel(interfaceName, debugMode, isRunningAsService: false, skipTunnelCreation: true);
            wireguardTunnel.SetClientIPAndRestart(meshIP, 16);
            Log($"[Mesh] WireGuard tunnel initialized with IP {meshIP}/16");

            // Initialize UDP proxy for mesh mode
            udpProxy = new WireGuardUdpProxy(udpClient);
            wireguardTunnel.SetUdpProxy(udpProxy);

            // Connect to mediation, perform NAT detection, and join mesh network.
            // Retries indefinitely on failure — WireGuard is already initialized above
            // and MUST NOT be recreated (native memory leak).

            MeshEngine engine = new MeshEngine();
            engine.Run(wireguardTunnel, meshIP, udpClient, udpProxy, peerID);

        }
        catch (Exception ex)
        {
            Log($"[Mesh] Error: {ex.Message}");
        }
        finally
        {
            udpClient?.Close();
            wireguardTunnel?.Dispose();
            udpProxy?.Dispose();
            Log("[Mesh] Cleaned up resources, exiting.");
        }
    }
}
