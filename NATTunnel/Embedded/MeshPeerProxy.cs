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
public sealed class MeshPeerProxy : IDisposable
{
    public const byte EnvelopeNoiseHandshake = 0x10;
    public const byte EnvelopeData = 0x01;

    // Buffer big enough for any Noise message; spec max is 65535.
    private const int MaxNoiseMessage = 65535;

    private readonly Tunnel tunnel;
    private readonly UdpClient loopbackSocket;
    private readonly IPEndPoint hostGameEndpoint;
    private readonly byte[] staticPrivateKey;
    private readonly bool isInitiator;
    private readonly string peerLabel;

    private CancellationTokenSource cts;
    private HandshakeState handshakeState;
    private NoiseUdpTransport transport;
    private readonly object sendLock = new();
    private volatile bool handshakeDone;
    private volatile bool started;
    // Buffer for Noise handshake packets that arrive before Start() runs (peer may complete
    // its hole-punch and send msg-1 before we declare our tunnel connected). Flushed on Start().
    private readonly ConcurrentQueue<byte[]> earlyHandshakePackets = new();
    // Cached last-sent handshake message for retransmit (UDP can lose msg-1/msg-2/msg-3).
    private byte[] lastSentHandshakeFrame;
    private Timer handshakeRetransmitTimer;

    /// <summary>The loopback endpoint the host game sends to when talking to this peer.</summary>
    public IPEndPoint LoopbackEndpoint { get; }

    /// <summary>Raised when Noise handshake completes and the proxy is ready to carry game data.</summary>
    public event Action HandshakeComplete;

    /// <summary>
    /// Construct a proxy for one peer.
    /// </summary>
    /// <param name="tunnel">Established Tunnel to the remote peer.</param>
    /// <param name="loopbackPort">Local loopback port the host game treats as the peer's address.</param>
    /// <param name="hostGamePort">Local loopback port the host game has bound to receive from this peer.</param>
    /// <param name="staticPrivateKey">This node's 32-byte Curve25519 static private key.</param>
    /// <param name="isInitiator">True if this side opens the handshake (lexically larger peer ID wins).</param>
    /// <param name="peerLabel">Short human label for logs (typically the remote peer's GUID).</param>
    public MeshPeerProxy(Tunnel tunnel, int loopbackPort, int hostGamePort,
                         byte[] staticPrivateKey, bool isInitiator, string peerLabel)
    {
        this.tunnel = tunnel ?? throw new ArgumentNullException(nameof(tunnel));
        this.staticPrivateKey = staticPrivateKey ?? throw new ArgumentNullException(nameof(staticPrivateKey));
        this.isInitiator = isInitiator;
        this.peerLabel = peerLabel ?? "?";
        LoopbackEndpoint = new IPEndPoint(IPAddress.Loopback, loopbackPort);
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
            SendNoiseMessage(null);
        }
    }

    private void RetransmitHandshake()
    {
        if (handshakeDone || lastSentHandshakeFrame == null) return;
        try { tunnel.SendDataPacket(lastSentHandshakeFrame); }
        catch { /* tunnel may be gone */ }
    }

    private void SendNoiseMessage(byte[] payload)
    {
        var buf = new byte[MaxNoiseMessage];
        var (bytesWritten, _, t) = handshakeState.WriteMessage(payload, buf);

        var framed = new byte[bytesWritten + 1];
        framed[0] = EnvelopeNoiseHandshake;
        Buffer.BlockCopy(buf, 0, framed, 1, bytesWritten);

        lastSentHandshakeFrame = framed;
        try { tunnel.SendDataPacket(framed); }
        catch (Exception ex) { Console.Error.WriteLine($"[Noise/{peerLabel}] handshake send failed: {ex.Message}"); }

        if (t != null) CompleteHandshake(t);
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
        }
    }

    private void HandleHandshakeMessage(ReadOnlySpan<byte> body)
    {
        if (handshakeDone || handshakeState == null) return;

        var payloadBuf = new byte[MaxNoiseMessage];
        try
        {
            var (_, _, t) = handshakeState.ReadMessage(body, payloadBuf);
            if (t != null)
            {
                CompleteHandshake(t);
                return;
            }
            // Handshake not yet finished — send our next message.
            SendNoiseMessage(null);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Noise/{peerLabel}] handshake read failed: {ex.Message}");
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
        Console.WriteLine($"[Noise/{peerLabel}] handshake complete ({(isInitiator ? "initiator" : "responder")})");

        // Now safe to start carrying game payloads.
        _ = Task.Run(() => LoopbackReceiveLoop(cts.Token));
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
        catch (Exception ex) { Console.Error.WriteLine($"[MeshPeerProxy/{peerLabel}] deliver-to-host failed: {ex.Message}"); }
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
                // Envelope (1) + counter (8) + ciphertext (plaintext.Length) + tag (16)
                var framed = new byte[1 + NoiseUdpTransport.CounterSize + plaintext.Length + NoiseUdpTransport.TagSize];
                framed[0] = EnvelopeData;

                int written;
                lock (sendLock)
                {
                    if (transport == null) continue;
                    written = transport.Encrypt(plaintext, framed.AsSpan(1));
                }

                if (written != framed.Length - 1)
                {
                    Console.Error.WriteLine($"[Noise/{peerLabel}] unexpected ciphertext size {written} vs {framed.Length - 1}");
                    continue;
                }

                try { tunnel.SendDataPacket(framed); }
                catch (Exception ex) { Console.Error.WriteLine($"[MeshPeerProxy/{peerLabel}] tunnel send failed: {ex.Message}"); }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[MeshPeerProxy/{peerLabel}] loopback loop crashed: {ex.Message}");
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
