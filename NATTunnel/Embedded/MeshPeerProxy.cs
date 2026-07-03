using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Noise;

namespace NATTunnel.Embedded;

/// <summary>
/// Per-peer loopback proxy with Noise_XX_25519_ChaChaPoly_SHA256 handshake and explicit-nonce
/// ChaCha20-Poly1305 transport (see <see cref="NoiseUdpTransport"/> for the reason — Noise.NET's
/// built-in Transport assumes a reliable channel and breaks on UDP loss/reorder).
///
/// The host game treats <see cref="LoopbackEndpoint"/> as a normal remote UDP endpoint — sends
/// datagrams to it, receives replies from it. The proxy:
///   1. Runs a Noise XX handshake over the underlying <see cref="Tunnel"/> the moment the
///      tunnel reports `connected`.
///   2. On handshake completion, promotes the Noise transport keys into a UDP-safe AEAD layer,
///      raises <see cref="HandshakeComplete"/>, and starts shuttling game payloads.
///
/// Wire format:
///   - 0x10 ‖ Noise handshake message
///   - 0x01 ‖ 8-byte counter ‖ ChaCha20-Poly1305 ciphertext ‖ 16-byte tag
///
/// Handshake initiator is decided by lexical peer-ID comparison: the side with the
/// larger GUID string is initiator. This avoids both peers trying to send msg-1 at once.
/// </summary>
internal sealed class MeshPeerProxy : IDisposable
{
    public const byte EnvelopeNoiseHandshake = 0x10;
    public const byte EnvelopeData = 0x01;
    /// <summary>Relay envelope. Format: [0x02] [4-byte src-mesh-IPv4] [4-byte dst-mesh-IPv4] [inner].</summary>
    public const byte EnvelopeRelay = 0x02;
    public const int RelayEnvelopeHeaderSize = 1 + 4 + 4;
    /// <summary>
    /// Mesh-control envelope: [0x20] [counter ‖ ChaCha20-Poly1305(plaintext-JSON)]. Carries
    /// MeshProtocolEngine's heartbeats / MeshConnectionBegin / MeshRelayAssignment between embedded peers,
    /// since mesh-IPs aren't OS-routable to port 51888 without a WireGuard interface.
    /// </summary>
    public const byte EnvelopeMeshControl = 0x20;
    /// <summary>
    /// Application identity envelope: [0x30] [counter ‖ ChaCha20-Poly1305(raw bytes)].
    /// Sent automatically by each side immediately after the Noise handshake completes
    /// to carry the application's <see cref="MeshConfig.LocalIdentity"/> blob (possibly
    /// zero-length). PeerConnected is gated on receiving this from the remote side.
    /// </summary>
    public const byte EnvelopeIdentity = 0x30;
    /// <summary>
    /// Application unreliable message envelope: [0x31] [counter ‖ ChaCha20-Poly1305(payload)].
    /// Best-effort delivery; no ack, no retransmit, no ordering guarantees beyond what UDP
    /// provides. Used by <see cref="MeshNode.SendMessageAsync"/> with reliable=false.
    /// </summary>
    public const byte EnvelopeAppUnreliable = 0x31;
    /// <summary>
    /// Application reliable message envelope: [0x32] [counter ‖ ChaCha20-Poly1305(seq(4) ‖ payload)].
    /// Sender retains a TaskCompletionSource keyed on the 4-byte sequence number and resolves
    /// it when the matching 0x33 ack arrives. Retransmits on a backoff until either acked or
    /// the configured timeout expires.
    /// </summary>
    public const byte EnvelopeAppReliable = 0x32;
    /// <summary>
    /// Application reliable-ack envelope: [0x33] [counter ‖ ChaCha20-Poly1305(seq(4))].
    /// Receiver sends back when a 0x32 message arrives, regardless of whether the application
    /// handler ran successfully — ack semantics are "I received this," not "I processed this."
    /// </summary>
    public const byte EnvelopeAppReliableAck = 0x33;

    /// <summary>
    /// Application data fragment envelope: [0x40] [counter ‖ ChaCha20-Poly1305(
    ///   [msgID (4 BE)] [fragIndex (1)] [fragCount (1)] [payload]
    /// )]. Used only when <see cref="MeshConfig.AutoFragment"/> is true and a single host-game
    /// packet exceeds the configured PathMTU after accounting for envelope/counter/tag
    /// overhead. The receiver reassembles by msgID and delivers the concatenated payload to
    /// the host's loopback once all fragments arrive (or discards after
    /// FragmentReassemblyTimeout if any fragment is lost).
    /// </summary>
    public const byte EnvelopeDataFragment = 0x40;

    // Buffer big enough for any Noise message; spec max is 65535.
    private const int MaxNoiseMessage = 65535;

    private readonly Tunnel tunnel;
    private readonly UdpClient loopbackSocket;
    private readonly IPEndPoint hostGameEndpoint;
    private readonly byte[] staticPrivateKey;
    private readonly bool isInitiator;
    private readonly string peerLabel;
    // Application identity blob this side sends to the peer post-handshake. Always non-null;
    // an empty array means the application didn't configure a LocalIdentity.
    private readonly byte[] localIdentity;
    // Non-null when this proxy is in "relayed" mode: outbound bytes get wrapped with
    // 0x02 ‖ 4-byte src-mesh-IP ‖ 4-byte dst-mesh-IP before being sent through tunnel
    // (the gateway's tunnel, not a direct tunnel to the destination peer). Null for direct-mode.
    private readonly byte[] relayDstMeshIPBytes;
    private readonly byte[] relaySrcMeshIPBytes;

    private CancellationTokenSource cts;
    private HandshakeState handshakeState;
    private NoiseUdpTransport transport;
    private readonly object sendLock = new();
    private volatile bool handshakeDone;
    private volatile bool started;
    // Buffer for Noise handshake packets that arrive before Start() runs (peer may complete
    // its hole-punch and send msg-1 before we declare our tunnel connected). Flushed on Start().
    private readonly ConcurrentQueue<byte[]> earlyHandshakePackets = new();
    // Buffer for outbound mesh-control packets queued before the Noise handshake completed.
    // Drained from CompleteHandshake. Without this, MeshProtocolEngine silently loses every mesh-control
    // packet sent during the ~1s gap between tunnel-connected and noise-complete (which is
    // exactly when MeshProtocolEngine is most eager to send MeshConnectionBegin / MeshRelayAssignment).
    private readonly ConcurrentQueue<byte[]> pendingMeshControl = new();
    // Cached last-sent handshake message for retransmit (UDP can lose msg-1/msg-2/msg-3).
    private byte[] lastSentHandshakeFrame;
    private Timer handshakeRetransmitTimer;

    // Fragmentation/reassembly state. See MeshConfig.AutoFragment for why; see
    // EnvelopeDataFragment for the on-wire format.
    private readonly bool autoFragment;
    private readonly int fragmentPayloadBudget;
    private readonly TimeSpan fragmentReassemblyTimeout;
    private long nextFragmentMessageId;
    // Reassembly: msgID → in-progress assembly. Capped at a small size and GC'd on the
    // reassembly timeout so a missing fragment can't leak memory.
    private readonly ConcurrentDictionary<uint, FragmentAssembly> fragmentReassembly = new();

    private sealed class FragmentAssembly
    {
        public byte[][] Fragments;
        public int ReceivedCount;
        public DateTime FirstSeen;
    }

    /// <summary>The loopback endpoint the host game sends to when talking to this peer.</summary>
    public IPEndPoint LoopbackEndpoint { get; }

    /// <summary>
    /// The Tunnel this proxy sends through. For a direct-mode proxy this is the peer's own
    /// hole-punched tunnel; for a relayed-mode proxy this is the relay peer's tunnel (and
    /// outbound bytes get wrapped with the 0x02 envelope before being sent).
    /// </summary>
    public Tunnel Tunnel => tunnel;

    /// <summary>Raised when Noise handshake completes and the proxy is ready to carry game data.</summary>
    public event Action HandshakeComplete;

    /// <summary>
    /// Raised once the peer's identity blob has been received and decrypted. Payload is the
    /// raw bytes the remote peer set as <see cref="MeshConfig.LocalIdentity"/> (zero-length
    /// if the remote peer didn't set one). MeshNode uses this to gate PeerConnected.
    /// </summary>
    public event Action<byte[]> IdentityReceived;

    /// <summary>Raised when an unreliable application message (0x31) arrives and decrypts.</summary>
    public event Action<byte[]> AppMessageReceived;

    /// <summary>Raised when a reliable application message (0x32) arrives and decrypts. Payload is the application bytes; the sequence number is handled internally (ack is auto-sent).</summary>
    public event Action<byte[]> AppReliableReceived;

    /// <summary>Raised when a reliable-ack (0x33) arrives. Payload is the 4-byte sequence number being acked.</summary>
    public event Action<uint> AppReliableAckReceived;

    /// <summary>
    /// Raised when a 0x20-framed mesh-control packet arrives and decrypts. Payload is the
    /// plaintext JSON bytes that MeshProtocolEngine's mesh-control listener would normally read from
    /// the meshControlClient UDP socket.
    /// </summary>
    public event Action<byte[]> MeshControlReceived;

    /// <summary>
    /// Raised when this proxy gives up because it received too many consecutive undecryptable
    /// packets during the handshake phase. MeshNode reacts by forgetting this peer 
    /// so a fresh proxy can be built on the next connection attempt.
    /// </summary>
    public event Action HandshakeBroken;

    // Counter for consecutive handshake read failures. Reset on any successful handshake read.
    // After HandshakeFailureThreshold misses we declare the proxy broken and tear ourselves down.
    private int consecutiveHandshakeFailures;
    private const int HandshakeFailureThreshold = 15;

    // Handshake message counters — used to decide when we include the peer-version payload
    // in Noise messages. Only msg 1 (initiator) and msg 2 (responder) carry a version.
    private int handshakeMessagesSent;
    private int handshakeMessagesReceived;

    /// <summary>The negotiated peer protocol version once handshake completes. -1 pre-handshake.</summary>
    public int NegotiatedPeerVersion { get; private set; } = -1;

    /// <summary>
    /// Construct a proxy for one peer.
    /// </summary>
    /// <param name="tunnel">
    /// Tunnel that carries this peer's traffic. For a direct peer this is the peer's own
    /// hole-punched Tunnel. For a relayed peer this is the *gateway* peer's Tunnel, and
    /// <paramref name="relayDestinationMeshIP"/> must be non-null.
    /// </param>
    /// <param name="loopbackPort">Local loopback port the host game treats as the peer's address.</param>
    /// <param name="hostGamePort">Local loopback port the host game has bound to receive from this peer.</param>
    /// <param name="staticPrivateKey">This node's 32-byte Curve25519 static private key.</param>
    /// <param name="isInitiator">True if this side opens the handshake (lexically larger peer ID wins).</param>
    /// <param name="peerLabel">Short human label for logs (typically the remote peer's GUID).</param>
    /// <param name="relayDestinationMeshIP">
    /// For relayed-mode proxies: the destination peer's mesh IPv4 (4 bytes, network order).
    /// Outbound data gets wrapped with 0x02 ‖ src-mesh-IP ‖ this ‖ inner before sending through
    /// <paramref name="tunnel"/>. Null for direct-mode proxies.
    /// </param>
    /// <param name="ownMeshIP">
    /// This node's own mesh IP. Required for relayed-mode proxies (placed in the envelope's
    /// src-mesh-IP field so the destination can dispatch to the right inbound proxy). Ignored
    /// for direct-mode proxies.
    /// </param>
    /// <param name="localIdentity">
    /// Optional application-level identity blob to send to this peer once Noise completes.
    /// Defaults to an empty array (the wire format always carries an identity envelope; an
    /// empty blob is sent if the application didn't configure one).
    /// </param>
    /// <param name="autoFragment">
    /// If true, plaintexts from the loopback socket larger than the per-packet payload budget
    /// derived from <paramref name="PathMTU"/> are split into multiple 0x40 fragment packets,
    /// reassembled on the receiving side. Off by default — only useful for transports that
    /// don't do their own MTU-aware fragmentation.
    /// </param>
    /// <param name="PathMTU">
    /// Conservative path MTU in bytes. Outbound encrypted UDP datagrams never exceed this.
    /// Per-fragment payload budget is <c>PathMTU - 31</c> (1B envelope + 8B counter + 6B
    /// frag header + 16B AEAD tag). Only meaningful when <paramref name="autoFragment"/> is true.
    /// </param>
    /// <param name="fragmentReassemblyTimeout">
    /// How long the receiver keeps a partially-assembled message before discarding it.
    /// </param>
    public MeshPeerProxy(Tunnel tunnel, int loopbackPort, int hostGamePort,
                         byte[] staticPrivateKey, bool isInitiator, string peerLabel,
                         IPAddress relayDestinationMeshIP = null,
                         IPAddress ownMeshIP = null,
                         byte[] localIdentity = null,
                         bool autoFragment = false,
                         int PathMTU = 1200,
                         TimeSpan fragmentReassemblyTimeout = default,
                         IPAddress loopbackIP = null)
    {
        this.tunnel = tunnel ?? throw new ArgumentNullException(nameof(tunnel));
        this.staticPrivateKey = staticPrivateKey ?? throw new ArgumentNullException(nameof(staticPrivateKey));
        this.isInitiator = isInitiator;
        this.peerLabel = peerLabel ?? "?";
        // Normalize null -> empty so the wire-format codepath doesn't have to special-case null.
        this.localIdentity = localIdentity ?? Array.Empty<byte>();
        this.autoFragment = autoFragment;
        // Per-fragment plaintext budget: PathMTU minus envelope(1) + counter(8) + tag(16) =
        // 25 bytes of crypto overhead, minus 6 bytes of fragment header (msgID 4 + idx 1 + cnt 1).
        // Clamp to a sane minimum so a misconfigured tiny PathMTU doesn't produce
        // negative-or-zero budgets that would never make progress.
        this.fragmentPayloadBudget = Math.Max(64, PathMTU - 31);
        this.fragmentReassemblyTimeout = fragmentReassemblyTimeout == default
            ? TimeSpan.FromSeconds(2) : fragmentReassemblyTimeout;
        // Cache the 4-byte big-endian form once so the hot send path doesn't reallocate.
        this.relayDstMeshIPBytes = relayDestinationMeshIP?.GetAddressBytes();
        if (this.relayDstMeshIPBytes != null && this.relayDstMeshIPBytes.Length != 4)
            throw new ArgumentException("Relay destination mesh IP must be IPv4 (4 bytes).", nameof(relayDestinationMeshIP));
        if (this.relayDstMeshIPBytes != null)
        {
            if (ownMeshIP == null)
                throw new ArgumentException("ownMeshIP is required for relayed-mode proxies.", nameof(ownMeshIP));
            this.relaySrcMeshIPBytes = ownMeshIP.GetAddressBytes();
            if (this.relaySrcMeshIPBytes.Length != 4)
                throw new ArgumentException("ownMeshIP must be IPv4 (4 bytes).", nameof(ownMeshIP));
        }

        LoopbackEndpoint = new IPEndPoint(loopbackIP ?? IPAddress.Loopback, loopbackPort);
        hostGameEndpoint = new IPEndPoint(IPAddress.Loopback, hostGamePort);
        loopbackSocket = new UdpClient(LoopbackEndpoint);

        tunnel.DataPacketReceived += OnTunnelPacket;
    }

    /// <summary>Begin the Noise handshake; once complete, start carrying data.</summary>
    public void Start()
    {
        cts = new CancellationTokenSource();

        var protocol = new Protocol(
            HandshakePattern.XX,
            CipherFunction.ChaChaPoly,
            HashFunction.Sha256);
        handshakeState = protocol.Create(initiator: isInitiator, s: staticPrivateKey);
        started = true;

        // Retransmit the most recently sent handshake message every second until the
        // handshake completes. UDP can drop any of the three messages, and without this
        // a single loss permanently stalls the handshake.
        handshakeRetransmitTimer = new Timer(_ => RetransmitHandshake(), null, 1000, 1000);

        // Drain any handshake packets that arrived before Start() ran.
        while (earlyHandshakePackets.TryDequeue(out var early))
        {
            HandleHandshakeMessage(early.AsSpan());
            if (handshakeDone) return;
        }

        // Initiator sends msg-1 immediately; responder waits for it.
        if (isInitiator && !handshakeDone)
        {
            SendNoiseMessage();
        }
    }

    private void RetransmitHandshake()
    {
        if (handshakeDone || lastSentHandshakeFrame == null) return;
        try { SendThroughTunnel(lastSentHandshakeFrame); }
        catch { /* tunnel may be gone */ }
    }

    /// <summary>
    /// Send <paramref name="inner"/> through the underlying tunnel. For direct-mode proxies
    /// the inner is forwarded verbatim. For relayed-mode proxies it is wrapped with the
    /// 0x02 ‖ src-IP ‖ dst-IP envelope first.
    /// </summary>
    private void SendThroughTunnel(byte[] inner)
    {
        if (relayDstMeshIPBytes == null)
        {
            tunnel.SendDataPacket(inner);
            return;
        }

        var framed = new byte[RelayEnvelopeHeaderSize + inner.Length];
        framed[0] = EnvelopeRelay;
        Buffer.BlockCopy(relaySrcMeshIPBytes, 0, framed, 1, 4);
        Buffer.BlockCopy(relayDstMeshIPBytes, 0, framed, 5, 4);
        Buffer.BlockCopy(inner, 0, framed, RelayEnvelopeHeaderSize, inner.Length);
        tunnel.SendDataPacket(framed);
    }

    private static void WriteUInt32BE(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)((value >> 24) & 0xFF);
        buf[offset + 1] = (byte)((value >> 16) & 0xFF);
        buf[offset + 2] = (byte)((value >> 8) & 0xFF);
        buf[offset + 3] = (byte)(value & 0xFF);
    }

    private static uint ReadUInt32BE(byte[] buf, int offset)
        => ((uint)buf[offset] << 24) | ((uint)buf[offset + 1] << 16) | ((uint)buf[offset + 2] << 8) | buf[offset + 3];

    private void SendNoiseMessage()
    {
        // Decide the Noise payload. Msg 1 (initiator's first send) and msg 2 (responder's
        // only send) carry our peer protocol range; msg 3 has none. Track by counter so
        // this stays correct regardless of who's who.
        byte[] payload = null;
        bool isFirstSend = handshakeMessagesSent == 0;
        if (isFirstSend)
        {
            payload = new byte[8];
            WriteUInt32BE(payload, 0, (uint)MediationProtocol.PeerMinVersion);
            WriteUInt32BE(payload, 4, (uint)MediationProtocol.PeerMaxVersion);
        }

        var buf = new byte[MaxNoiseMessage];
        var (bytesWritten, _, t) = handshakeState.WriteMessage(payload, buf);
        handshakeMessagesSent++;

        var framed = new byte[bytesWritten + 1];
        framed[0] = EnvelopeNoiseHandshake;
        Buffer.BlockCopy(buf, 0, framed, 1, bytesWritten);

        lastSentHandshakeFrame = framed;
        try { SendThroughTunnel(framed); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[Noise/{peerLabel}] handshake send failed: {ex.Message}"); }

        if (t != null) CompleteHandshake(t);
    }

    /// <summary>
    /// Deliver an inner packet (just the envelope-stripped bytes — already starts with 0x01
    /// or 0x10) to this proxy as if it had arrived directly on its tunnel. Called by
    /// EmbeddedMeshHost.ForwardRelayEnvelope on the destination node when a relay-forwarded
    /// envelope arrives.
    /// </summary>
    public void DeliverRelayedInner(byte[] inner)
    {
        OnTunnelPacket(inner);
    }

    private void OnTunnelPacket(byte[] framed)
    {
        if (framed == null || framed.Length < 1) return;

        switch (framed[0])
        {
            case EnvelopeNoiseHandshake:
                if (!started)
                {
                    // Peer raced ahead of our Start() — buffer for replay.
                    var copy = new byte[framed.Length - 1];
                    Buffer.BlockCopy(framed, 1, copy, 0, copy.Length);
                    earlyHandshakePackets.Enqueue(copy);
                }
                else
                {
                    HandleHandshakeMessage(framed.AsSpan(1));
                }
                break;
            case EnvelopeData:
                HandleDataMessage(framed.AsSpan(1));
                break;
            case EnvelopeMeshControl:
                HandleMeshControlMessage(framed.AsSpan(1));
                break;
            case EnvelopeIdentity:
                HandleIdentityMessage(framed.AsSpan(1));
                break;
            case EnvelopeAppUnreliable:
                HandleAppUnreliableMessage(framed.AsSpan(1));
                break;
            case EnvelopeAppReliable:
                HandleAppReliableMessage(framed.AsSpan(1));
                break;
            case EnvelopeAppReliableAck:
                HandleAppReliableAckMessage(framed.AsSpan(1));
                break;
            case EnvelopeDataFragment:
                HandleDataFragmentMessage(framed.AsSpan(1));
                break;
        }
    }

    private void HandleMeshControlMessage(ReadOnlySpan<byte> body)
    {
        if (!handshakeDone || transport == null) return;

        var plaintextBuf = new byte[MaxNoiseMessage];
        int read = transport.Decrypt(body, plaintextBuf);
        if (read < 0)
        {
            // Silently drop. When multiple proxies share a tunnel (direct + relayed-via-this-peer),
            // each one tries to decrypt every 0x20 packet that arrives. Only the proxy whose Noise
            // keys match the source peer succeeds; the others fail. That's the design — failed
            // decrypts here are expected noise, not errors.
            return;
        }
        var plaintext = new byte[read];
        Buffer.BlockCopy(plaintextBuf, 0, plaintext, 0, read);
        try { MeshControlReceived?.Invoke(plaintext); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] MeshControlReceived handler threw: {ex.Message}"); }
    }

    /// <summary>
    /// Encrypt the given mesh-control JSON bytes via this peer's Noise transport and send
    /// them through the underlying tunnel with the 0x20 envelope. If the handshake hasn't
    /// completed yet, the packet is queued and sent automatically when the handshake finishes.
    /// Returns true unconditionally — the caller (MeshProtocolEngine) doesn't have retry logic and would
    /// otherwise lose mesh-control packets during the ~1s tunnel-connected-but-noise-not-done
    /// window. (That window is exactly when MeshProtocolEngine is most eager to send MeshConnectionBegin
    /// and MeshRelayAssignment to a freshly-connected peer.)
    /// </summary>
    public bool SendMeshControl(byte[] plaintext, int length)
    {
        if (!handshakeDone || transport == null)
        {
            // Queue a defensive copy — caller may reuse its buffer.
            var copy = new byte[length];
            Buffer.BlockCopy(plaintext, 0, copy, 0, length);
            pendingMeshControl.Enqueue(copy);
            return true;
        }
        return TryEncryptAndSendMeshControl(plaintext.AsSpan(0, length));
    }

    private bool TryEncryptAndSendMeshControl(ReadOnlySpan<byte> plaintext)
    {
        return TryEncryptAndSend(EnvelopeMeshControl, plaintext, "mesh-control");
    }

    /// <summary>
    /// Common encrypted-send path: [envelope (1)] [counter (8)] [ciphertext (n)] [tag (16)].
    /// Used by mesh-control, identity, and the application message envelopes.
    /// </summary>
    private bool TryEncryptAndSend(byte envelopeByte, ReadOnlySpan<byte> plaintext, string label)
    {
        var framed = new byte[1 + NoiseUdpTransport.CounterSize + plaintext.Length + NoiseUdpTransport.TagSize];
        framed[0] = envelopeByte;

        int written;
        lock (sendLock)
        {
            if (transport == null) return false;
            written = transport.Encrypt(plaintext, framed.AsSpan(1));
        }
        if (written != framed.Length - 1) return false;

        try { SendThroughTunnel(framed); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] {label} send failed: {ex.Message}"); return false; }
        return true;
    }

    /// <summary>
    /// Decrypt a 0x30/0x31/0x32/0x33 inbound envelope body. Returns null on failure (replay,
    /// auth mismatch, or pre-handshake delivery). Caller dispatches the plaintext.
    /// </summary>
    private byte[] TryDecryptInner(ReadOnlySpan<byte> body)
    {
        if (!handshakeDone || transport == null) return null;
        var buf = new byte[MaxNoiseMessage];
        int read = transport.Decrypt(body, buf);
        if (read < 0) return null;
        var plaintext = new byte[read];
        Buffer.BlockCopy(buf, 0, plaintext, 0, read);
        return plaintext;
    }

    private void HandleIdentityMessage(ReadOnlySpan<byte> body)
    {
        var plaintext = TryDecryptInner(body);
        if (plaintext == null) return;
        try { IdentityReceived?.Invoke(plaintext); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] IdentityReceived handler threw: {ex.Message}"); }
    }

    private void HandleAppUnreliableMessage(ReadOnlySpan<byte> body)
    {
        var plaintext = TryDecryptInner(body);
        if (plaintext == null) return;
        try { AppMessageReceived?.Invoke(plaintext); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] AppMessageReceived handler threw: {ex.Message}"); }
    }

    private void HandleAppReliableMessage(ReadOnlySpan<byte> body)
    {
        var plaintext = TryDecryptInner(body);
        if (plaintext == null || plaintext.Length < 4) return;

        // Layout: [seq (4 BE)] [payload]
        uint seq = (uint)((plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3]);
        var payload = new byte[plaintext.Length - 4];
        Buffer.BlockCopy(plaintext, 4, payload, 0, payload.Length);

        // Always ack the receive, even if the application handler throws — ack semantics
        // are "I received this," not "I processed this successfully."
        var ackPayload = new byte[4];
        ackPayload[0] = (byte)(seq >> 24);
        ackPayload[1] = (byte)(seq >> 16);
        ackPayload[2] = (byte)(seq >> 8);
        ackPayload[3] = (byte)seq;
        TryEncryptAndSend(EnvelopeAppReliableAck, ackPayload, "app-reliable-ack");

        try { AppReliableReceived?.Invoke(payload); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] AppReliableReceived handler threw: {ex.Message}"); }
    }

    private void HandleAppReliableAckMessage(ReadOnlySpan<byte> body)
    {
        var plaintext = TryDecryptInner(body);
        if (plaintext == null || plaintext.Length != 4) return;
        uint seq = (uint)((plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3]);
        try { AppReliableAckReceived?.Invoke(seq); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] AppReliableAckReceived handler threw: {ex.Message}"); }
    }

    /// <summary>
    /// Send an unreliable application message (0x31). Returns false if the Noise transport
    /// isn't established yet or encryption failed; otherwise true (the bytes are on the wire
    /// but UDP delivery is not guaranteed).
    /// </summary>
    public bool SendAppUnreliable(ReadOnlySpan<byte> payload)
    {
        return TryEncryptAndSend(EnvelopeAppUnreliable, payload, "app-unreliable");
    }

    /// <summary>
    /// Send a reliable application message (0x32) with the given sequence number. The caller
    /// (MeshNode) tracks the seq -> TaskCompletionSource mapping and resolves it when a
    /// matching 0x33 ack arrives via <see cref="AppReliableAckReceived"/>.
    /// </summary>
    public bool SendAppReliable(uint seq, ReadOnlySpan<byte> payload)
    {
        // Layout: [seq (4 BE)] [payload]
        var inner = new byte[4 + payload.Length];
        inner[0] = (byte)(seq >> 24);
        inner[1] = (byte)(seq >> 16);
        inner[2] = (byte)(seq >> 8);
        inner[3] = (byte)seq;
        payload.CopyTo(inner.AsSpan(4));
        return TryEncryptAndSend(EnvelopeAppReliable, inner, "app-reliable");
    }

    private void DrainPendingMeshControl()
    {
        while (pendingMeshControl.TryDequeue(out var queued))
        {
            TryEncryptAndSendMeshControl(queued);
        }
    }

    private void HandleHandshakeMessage(ReadOnlySpan<byte> body)
    {
        if (handshakeDone || handshakeState == null) return;

        var payloadBuf = new byte[MaxNoiseMessage];
        try
        {
            var (bytesRead, _, t) = handshakeState.ReadMessage(body, payloadBuf);
            consecutiveHandshakeFailures = 0;

            // Msg 1 (received by responder) and msg 2 (received by initiator) carry the peer's
            // supported version range. Msg 3 (received by responder) has none. Track by counter.
            bool isFirstReceive = handshakeMessagesReceived == 0;
            handshakeMessagesReceived++;
            if (isFirstReceive)
            {
                if (bytesRead < 8)
                {
                    Program.Log(LogLevel.Warning, $"[Noise/{peerLabel}] handshake msg missing peer version payload — tearing down proxy");
                    try { Dispose(); } catch { }
                    try { HandshakeBroken?.Invoke(); } catch { }
                    return;
                }
                int remoteMin = (int)ReadUInt32BE(payloadBuf, 0);
                int remoteMax = (int)ReadUInt32BE(payloadBuf, 4);
                int selected = Math.Min(MediationProtocol.PeerMaxVersion, remoteMax);
                int lowerBound = Math.Max(MediationProtocol.PeerMinVersion, remoteMin);
                if (selected < lowerBound)
                {
                    Program.Log(LogLevel.Warning, $"[Noise/{peerLabel}] peer supports v{remoteMin}-v{remoteMax}, we support v{MediationProtocol.PeerMinVersion}-v{MediationProtocol.PeerMaxVersion} — no overlap, refusing pair");
                    try { Dispose(); } catch { }
                    try { HandshakeBroken?.Invoke(); } catch { }
                    return;
                }
                NegotiatedPeerVersion = selected;
            }

            if (t != null)
            {
                CompleteHandshake(t);
                return;
            }
            // Handshake not yet finished — send our next message.
            SendNoiseMessage();
        }
        catch (Exception ex)
        {
            int fails = Interlocked.Increment(ref consecutiveHandshakeFailures);
            Program.Log(LogLevel.Error, $"[Noise/{peerLabel}] handshake read failed ({fails}/{HandshakeFailureThreshold}): {ex.Message}");
            if (fails >= HandshakeFailureThreshold)
            {
                Program.Log(LogLevel.Warning, $"[Noise/{peerLabel}] handshake wedged after {fails} consecutive failures — tearing down proxy");
                try { Dispose(); } catch { }
                try { HandshakeBroken?.Invoke(); } catch { }
            }
        }
    }

    private void CompleteHandshake(Transport noiseTransport)
    {
        // Promote Noise's internal Transport to our explicit-nonce UDP-safe transport.
        // The original Noise Transport is disposed inside FromNoiseTransport.
        transport = NoiseUdpTransport.FromNoiseTransport(noiseTransport, isInitiator);
        handshakeDone = true;

        try { handshakeRetransmitTimer?.Dispose(); } catch { }
        handshakeRetransmitTimer = null;
        handshakeState?.Dispose();
        handshakeState = null;
        Program.Log(LogLevel.Info, $"[Noise/{peerLabel}] handshake complete ({(isInitiator ? "initiator" : "responder")})");

        // Now safe to start carrying game payloads.
        _ = Task.Run(() => LoopbackReceiveLoop(cts.Token));

        // Flush any mesh-control packets queued during the tunnel-connected-but-noise-not-done
        // window. MeshProtocolEngine often sends MeshConnectionBegin / MeshRelayAssignment as soon as the
        // tunnel reports connected, but Noise isn't ready yet so those packets piled up here.
        DrainPendingMeshControl();

        // Send our application identity blob (may be empty if the caller didn't configure one).
        // MeshNode gates PeerConnected on the IdentityReceived event for the peer's blob, so
        // both sides exchange this once at startup. Failures here aren't fatal — the peer just
        // won't see our identity, and MeshNode will treat that as the empty case after a timeout.
        TryEncryptAndSend(EnvelopeIdentity, localIdentity, "identity");

        // Noise completing end-to-end means the peer is reachable bidirectionally — no longer
        // need the per-second SymmetricHolePunchAttempt timer that was kept running post-hole-punch
        // to ensure the non-symmetric side got at least one of our probes' packets. Stop it now
        // so we're not spamming the peer with hole-punches forever.
        // (Skip on relayed-mode proxies — they don't own the gateway's tunnel and shouldn't
        // disable hole-punching for an unrelated direct connection.)
        if (relayDstMeshIPBytes == null)
        {
            try { tunnel.StopHolePunching(); } catch { }
        }

        HandshakeComplete?.Invoke();
    }

    private void HandleDataMessage(ReadOnlySpan<byte> body)
    {
        if (!handshakeDone || transport == null) return;  // pre-handshake data is dropped silently

        var plaintextBuf = new byte[MaxNoiseMessage];
        int read = transport.Decrypt(body, plaintextBuf);
        if (read < 0)
        {
            // Replay, too-old, or auth failure. Silent drop is correct here — these can
            // happen normally on UDP (duplicate retransmits, reordered late packets) and
            // logging would spam. Real auth failures are rare and indicate either a bug
            // or active tampering; both warrant a separate alert pathway, not this hot path.
            return;
        }

        try { loopbackSocket.Send(plaintextBuf, read, hostGameEndpoint); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] deliver-to-host failed: {ex.Message}"); }
    }

    /// <summary>
    /// Decrypt a 0x40-framed fragment, place it in its message's reassembly slot, and if all
    /// fragments have arrived, concatenate + deliver to the host's loopback. Incomplete
    /// messages are GC'd by <see cref="ReapStaleFragmentAssemblies"/> after the configured
    /// timeout. Receive-side reassembly works whether or not this side has AutoFragment
    /// enabled — the wire format only depends on the sender's setting.
    /// </summary>
    private void HandleDataFragmentMessage(ReadOnlySpan<byte> body)
    {
        var plaintext = TryDecryptInner(body);
        if (plaintext == null || plaintext.Length < 6) return;

        uint msgId = (uint)((plaintext[0] << 24) | (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3]);
        int fragIndex = plaintext[4];
        int fragCount = plaintext[5];
        if (fragCount == 0 || fragIndex >= fragCount) return; // malformed

        int chunkLen = plaintext.Length - 6;
        var chunk = new byte[chunkLen];
        Buffer.BlockCopy(plaintext, 6, chunk, 0, chunkLen);

        var assembly = fragmentReassembly.GetOrAdd(msgId, _ => new FragmentAssembly
        {
            Fragments = new byte[fragCount][],
            FirstSeen = DateTime.UtcNow
        });

        // Defensive: fragCount mismatch across fragments of the same msgId means the sender
        // either has a bug or this is a stale msgId from a previous wraparound. Drop.
        if (assembly.Fragments.Length != fragCount) return;

        // Idempotent on duplicate fragment delivery (UDP can dup).
        if (assembly.Fragments[fragIndex] != null) return;
        assembly.Fragments[fragIndex] = chunk;
        int received = Interlocked.Increment(ref assembly.ReceivedCount);
        if (received < fragCount)
        {
            ReapStaleFragmentAssemblies();
            return;
        }

        // All fragments present. Concatenate and deliver.
        int totalLen = 0;
        foreach (var f in assembly.Fragments) totalLen += f.Length;
        var full = new byte[totalLen];
        int dst = 0;
        foreach (var f in assembly.Fragments)
        {
            Buffer.BlockCopy(f, 0, full, dst, f.Length);
            dst += f.Length;
        }
        fragmentReassembly.TryRemove(msgId, out _);
        try { loopbackSocket.Send(full, full.Length, hostGameEndpoint); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] reassembled-deliver-to-host failed: {ex.Message}"); }
    }

    /// <summary>
    /// Walk the reassembly table and drop entries older than the configured timeout. Called
    /// opportunistically from the fragment receive path — no dedicated timer needed because
    /// fragments only accumulate when fragments are arriving.
    /// </summary>
    private void ReapStaleFragmentAssemblies()
    {
        var cutoff = DateTime.UtcNow - fragmentReassemblyTimeout;
        foreach (var kv in fragmentReassembly)
        {
            if (kv.Value.FirstSeen < cutoff)
                fragmentReassembly.TryRemove(kv.Key, out _);
        }
    }

    /// <summary>
    /// Encrypt a plaintext data payload with the per-peer Noise transport and send it as
    /// a 0x01-framed UDP datagram through the underlying tunnel. Used by the fast-path
    /// (whole-packet) send and by anywhere else that wants to emit a single non-fragmented
    /// data envelope.
    /// </summary>
    private void EncryptAndSendData(byte[] plaintext)
    {
        // Envelope (1) + counter (8) + ciphertext (plaintext.Length) + tag (16)
        var framed = new byte[1 + NoiseUdpTransport.CounterSize + plaintext.Length + NoiseUdpTransport.TagSize];
        framed[0] = EnvelopeData;

        int written;
        lock (sendLock)
        {
            if (transport == null) return;
            written = transport.Encrypt(plaintext, framed.AsSpan(1));
        }

        if (written != framed.Length - 1)
        {
            Program.Log(LogLevel.Error, $"[Noise/{peerLabel}] unexpected ciphertext size {written} vs {framed.Length - 1}");
            return;
        }

        try { SendThroughTunnel(framed); }
        catch (Exception ex) { Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] tunnel send failed: {ex.Message}"); }
    }

    private async Task LoopbackReceiveLoop(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try { result = await loopbackSocket.ReceiveAsync(token); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }

                byte[] plaintext = result.Buffer;

                // Fast path: small enough to fit in one Noise-encrypted UDP datagram, or
                // AutoFragment is disabled (caller is on the hook for keeping packets small).
                if (!autoFragment || plaintext.Length <= fragmentPayloadBudget)
                {
                    EncryptAndSendData(plaintext);
                    continue;
                }

                // Slow path: split into N fragments and send each as its own 0x40-framed
                // encrypted UDP datagram. Each fragment carries [msgID(4) ‖ idx(1) ‖ count(1) ‖ chunk].
                int budget = fragmentPayloadBudget;
                int fragCount = (plaintext.Length + budget - 1) / budget;
                if (fragCount > 255)
                {
                    Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] packet of {plaintext.Length} bytes needs {fragCount} fragments (>255 max); dropping. Increase PathMTU or chunk at the host.");
                    continue;
                }
                uint msgId = unchecked((uint)Interlocked.Increment(ref nextFragmentMessageId));
                for (int i = 0; i < fragCount; i++)
                {
                    int offset = i * budget;
                    int chunkLen = Math.Min(budget, plaintext.Length - offset);
                    var fragPlaintext = new byte[6 + chunkLen];
                    fragPlaintext[0] = (byte)(msgId >> 24);
                    fragPlaintext[1] = (byte)(msgId >> 16);
                    fragPlaintext[2] = (byte)(msgId >> 8);
                    fragPlaintext[3] = (byte)msgId;
                    fragPlaintext[4] = (byte)i;
                    fragPlaintext[5] = (byte)fragCount;
                    Buffer.BlockCopy(plaintext, offset, fragPlaintext, 6, chunkLen);
                    TryEncryptAndSend(EnvelopeDataFragment, fragPlaintext, "data-fragment");
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"[MeshPeerProxy/{peerLabel}] loopback loop crashed: {ex.Message}");
        }
    }

    public void Dispose()
    {
        tunnel.DataPacketReceived -= OnTunnelPacket;
        cts?.Cancel();
        try { handshakeRetransmitTimer?.Dispose(); } catch { }
        try { loopbackSocket?.Dispose(); } catch { }
        try { handshakeState?.Dispose(); } catch { }
        try { transport?.Dispose(); } catch { }
    }
}
