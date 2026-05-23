using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Noise;

namespace NATTunnel.Embedded;

/// <summary>
/// Embeddable mesh node without any WireGuard. Each connected peer gets a
/// <see cref="MeshPeerProxy"/> exposing a localhost endpoint the host app can treat as the peer.
///
/// </summary>
public class MeshNodeEmbedded : IDisposable
{
    private readonly string mediationHost;
    private readonly int mediationPort;
    private readonly string networkID;
    private readonly string networkSecret;
    private readonly int hostGamePort;
    private readonly int loopbackPortBase;

    private readonly Guid peerID = Guid.NewGuid();
    // Static Curve25519 keypair for this node. Ephemeral per process (Phase 3 — Phase 5
    // may persist to disk). Lifetime tied to MeshNodeEmbedded; Dispose releases it.
    private readonly KeyPair staticKeyPair = KeyPair.Generate();
    private UdpClient udpClient;
    private TcpClient tcpClient;
    private Stream stream;
    private string earlyTcpRemainder = "";
    private byte[] readBuffer = new byte[8192];
    private string authToken;
    private NATType detectedNatType = NATType.Unknown;
    private CancellationTokenSource cts;

    private int nextLoopbackPort;
    // Tracks pending ConnectionRequest → ConnectionBegin pairs by peer ID.
    private readonly ConcurrentDictionary<string, PendingPeer> pendingPeers = new();
    // Established peers, keyed by remote peer GUID.
    private readonly ConcurrentDictionary<string, ConnectedPeer> connectedPeers = new();

    public Guid OwnPeerID => peerID;

    /// <summary>Raised once a peer's tunnel is fully connected and a MeshPeerProxy is ready.</summary>
    public event Action<ConnectedPeer> PeerConnected;

    public MeshNodeEmbedded(string mediationHost, int mediationPort, string networkID, string networkSecret,
                            int hostGamePort, int loopbackPortBase = 50100)
    {
        this.mediationHost = mediationHost;
        this.mediationPort = mediationPort;
        this.networkID = networkID;
        this.networkSecret = networkSecret;
        this.hostGamePort = hostGamePort;
        this.loopbackPortBase = loopbackPortBase;
        nextLoopbackPort = loopbackPortBase;
    }

    public void Start()
    {
        cts = new CancellationTokenSource();
        // Open shared UDP socket (used for hole-punching to all peers and for NAT detection probes).
        udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        udpClient.Client.ReceiveBufferSize = 128_000;
        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            const int SIO_UDP_CONNRESET = -1744830452;
            udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }

        DoHandshake();

        // Background loop: pump TCP messages from mediation.
        _ = Task.Run(() => TcpReadLoop(cts.Token));

        // Background loop: shared UDP dispatcher — fan out each incoming packet to whichever
        // tunnel(s) want it. Tunnel's own filtering (by source IP/port) decides who consumes.
        _ = Task.Run(() => SharedUdpDispatcher(cts.Token));
    }

    private void DoHandshake()
    {
        // 1. TCP connect
        tcpClient = new TcpClient();
        tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        tcpClient.Connect(mediationHost, mediationPort);

        // 2. TLS wrap (mirroring TunnelOptions defaults: TLS on, accept self-signed)
        var sslStream = new SslStream(tcpClient.GetStream(), false,
            (sender, cert, chain, errors) => true);
        sslStream.AuthenticateAsClient(mediationHost);
        stream = sslStream;
        stream.ReadTimeout = 15_000;

        // 3. Receive Connected
        ReadOneMessage();

        // 4. NAT type detection
        int localUdpPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;
        var natReq = new MediationMessage(MediationMessageType.NATTypeRequest)
        {
            LocalPort = localUdpPort,
            LocalIP = Tunnel.GetLanIPAddress()?.ToString(),
            ClientID = peerID
        };
        WriteMessage(natReq);

        var natTestBegin = ReadOneMessage();
        if (natTestBegin.ID == MediationMessageType.NATTestBegin)
        {
            var probe = new MediationMessage(MediationMessageType.NATTest) { ClientID = peerID };
            byte[] probeBytes = Encoding.ASCII.GetBytes(probe.Serialize());
            var mediationIP = Dns.GetHostAddresses(mediationHost)[0];
            udpClient.Send(probeBytes, probeBytes.Length, new IPEndPoint(mediationIP, natTestBegin.NATTestPortOne));
            udpClient.Send(probeBytes, probeBytes.Length, new IPEndPoint(mediationIP, natTestBegin.NATTestPortTwo));
        }

        var natResp = ReadOneMessage();
        if (natResp.ID == MediationMessageType.NATTypeResponse)
        {
            detectedNatType = natResp.NATType;
            Console.WriteLine($"[Embedded] NAT type: {detectedNatType}");
        }

        // 5. Mesh join
        authToken = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(networkID + ":" + networkSecret)));
        var joinReq = new MediationMessage(MediationMessageType.MeshJoinRequest)
        {
            NetworkID = networkID,
            PeerID = peerID.ToString(),
            NATType = detectedNatType,
            PrivateAddressString = $"127.0.0.{Math.Abs(peerID.GetHashCode()) % 254 + 1}",  // dummy mesh IP
            AuthToken = authToken
        };
        WriteMessage(joinReq);

        var joinResp = ReadOneMessage();
        if (!string.IsNullOrEmpty(joinResp.AuthToken))
            throw new InvalidOperationException($"Auth failed: {joinResp.AuthToken}");

        Console.WriteLine($"[Embedded] Joined network '{networkID}', {joinResp.PeerCount} other peer(s)");

        // 6. For each existing peer, send ConnectionRequest.
        if (joinResp.Peers != null)
        {
            foreach (var peer in joinResp.Peers)
            {
                var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                string targetPeerID = peerObj.GetProperty("peerID").GetString();
                if (targetPeerID == peerID.ToString()) continue;
                RequestConnectionTo(targetPeerID);
            }
        }

        stream.ReadTimeout = 100; // short timeout for polling-style reads
    }

    private void RequestConnectionTo(string targetPeerID)
    {
        if (pendingPeers.ContainsKey(targetPeerID) || connectedPeers.ContainsKey(targetPeerID)) return;
        Console.WriteLine($"[Embedded] Requesting connection to {targetPeerID}");
        pendingPeers[targetPeerID] = new PendingPeer(targetPeerID);

        var req = new MediationMessage(MediationMessageType.ConnectionRequest)
        {
            PeerID = targetPeerID,
            NATType = detectedNatType
        };
        WriteMessage(req);
    }

    private void TcpReadLoop(CancellationToken token)
    {
        string buffer = earlyTcpRemainder;
        while (!token.IsCancellationRequested)
        {
            try
            {
                int bytesRead = stream.Read(readBuffer, 0, readBuffer.Length);
                if (bytesRead == 0) { Console.WriteLine("[Embedded] Mediation closed"); break; }
                buffer += Encoding.ASCII.GetString(readBuffer, 0, bytesRead);
            }
            catch (IOException) { continue; }  // poll timeout
            catch (Exception ex) { Console.WriteLine($"[Embedded] TCP read error: {ex.Message}"); break; }

            // Parse out complete JSON objects.
            while (true)
            {
                var (msg, rest) = ExtractFirstJson(buffer);
                if (msg == null) break;
                buffer = rest;
                HandleMediationMessage(msg);
            }
        }
    }

    private void HandleMediationMessage(MediationMessage msg)
    {
        switch (msg.ID)
        {
            case MediationMessageType.ConnectionBegin:
                HandleConnectionBegin(msg);
                break;
            case MediationMessageType.MeshPeerList:
            case MediationMessageType.MeshJoinResponse:
                // New peers appeared — initiate connections.
                if (msg.Peers != null)
                {
                    foreach (var peer in msg.Peers)
                    {
                        var peerObj = JsonSerializer.Deserialize<JsonElement>(peer.ToString());
                        string targetPeerID = peerObj.GetProperty("peerID").GetString();
                        if (targetPeerID == peerID.ToString()) continue;
                        RequestConnectionTo(targetPeerID);
                    }
                }
                break;
            case MediationMessageType.ServerNotAvailable:
                Console.WriteLine("[Embedded] Mediation says target peer unavailable");
                break;
        }
    }

    private void HandleConnectionBegin(MediationMessage msg)
    {
        string targetPeerID = msg.PeerID;
        Console.WriteLine($"[Embedded] ConnectionBegin for peer {targetPeerID} at {msg.EndpointString} (NAT {msg.NATType})");

        if (!pendingPeers.TryRemove(targetPeerID, out _))
        {
            Console.WriteLine($"[Embedded] (no pending entry for {targetPeerID}, accepting anyway)");
        }

        int loopbackPort = Interlocked.Increment(ref nextLoopbackPort) - 1;

        var tunnel = new Tunnel(
            onConnectionFailure: () =>
            {
                Console.WriteLine($"[Embedded] Tunnel to {targetPeerID} failed");
                connectedPeers.TryRemove(targetPeerID, out _);
            },
            sharedUdpClient: udpClient,
            meshPeerEndpoint: msg.EndpointString,
            retryInPlace: true,
            sharedClientID: peerID,
            ownMeshIP: null,
            onConnectionComplete: () =>
            {
                Console.WriteLine($"[Embedded] Tunnel to {targetPeerID} connected, starting Noise handshake");
                if (connectedPeers.TryGetValue(targetPeerID, out var entry))
                {
                    entry.Proxy.Start();
                }
            });

        // No SetWireGuardTunnel — this is the magic that turns Tunnel into "embedded mode."
        // DataPacketReceived will fire instead of WG proxy forwarding.

        Task.Run(() =>
        {
            try
            {
                tunnel.Start();
                tunnel.InjectConnectionBegin(msg.EndpointString, msg.NATType, detectedNatType, msg.PrivateAddressString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Embedded] Failed to start tunnel: {ex.Message}");
            }
        });

        // Initiator is whichever side has the lexically larger peer-ID GUID. Deterministic,
        // no extra coordination needed — both sides reach the same conclusion independently.
        bool isInitiator = string.Compare(peerID.ToString(), targetPeerID, StringComparison.Ordinal) > 0;
        var proxy = new MeshPeerProxy(tunnel, loopbackPort, hostGamePort,
                                       staticKeyPair.PrivateKey, isInitiator, targetPeerID);
        var connected = new ConnectedPeer(targetPeerID, tunnel, proxy);
        connectedPeers[targetPeerID] = connected;
        proxy.HandshakeComplete += () => PeerConnected?.Invoke(connected);
    }

    private void SharedUdpDispatcher(CancellationToken token)
    {
        var ep = new IPEndPoint(IPAddress.Any, 0);
        while (!token.IsCancellationRequested)
        {
            try
            {
                byte[] data = udpClient.Receive(ref ep);
                foreach (var entry in connectedPeers.Values)
                    entry.Tunnel.ProcessUdpPacket(data, ep);
            }
            catch (SocketException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex) { Console.WriteLine($"[Embedded] UDP dispatcher: {ex.Message}"); }
        }
    }

    // ── Helpers ──

    private void WriteMessage(MediationMessage msg)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(msg.Serialize());
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
    }

    private MediationMessage ReadOneMessage()
    {
        while (true)
        {
            var (msg, rest) = ExtractFirstJson(earlyTcpRemainder);
            if (msg != null) { earlyTcpRemainder = rest; return msg; }
            int n = stream.Read(readBuffer, 0, readBuffer.Length);
            if (n == 0) throw new IOException("Mediation closed");
            earlyTcpRemainder += Encoding.ASCII.GetString(readBuffer, 0, n);
        }
    }

    private static (MediationMessage msg, string remainder) ExtractFirstJson(string data)
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
                    string obj = data.Substring(start, i - start + 1);
                    string rest = data.Substring(i + 1);
                    try { return (JsonSerializer.Deserialize<MediationMessage>(obj), rest); }
                    catch { return (null, data); }
                }
            }
        }
        return (null, data);
    }

    public void Dispose()
    {
        cts?.Cancel();
        foreach (var entry in connectedPeers.Values)
        {
            try { entry.Proxy.Dispose(); } catch { }
            try { entry.Tunnel.Dispose(); } catch { }
        }
        try { stream?.Dispose(); } catch { }
        try { tcpClient?.Dispose(); } catch { }
        try { udpClient?.Dispose(); } catch { }
        try { staticKeyPair?.Dispose(); } catch { }
    }

    private sealed class PendingPeer
    {
        public string PeerID { get; }
        public PendingPeer(string peerID) { PeerID = peerID; }
    }

    public sealed class ConnectedPeer
    {
        public string PeerID { get; }
        public Tunnel Tunnel { get; }
        public MeshPeerProxy Proxy { get; }
        public IPEndPoint LoopbackEndpoint => Proxy.LoopbackEndpoint;

        internal ConnectedPeer(string peerID, Tunnel tunnel, MeshPeerProxy proxy)
        {
            PeerID = peerID;
            Tunnel = tunnel;
            Proxy = proxy;
        }
    }
}
