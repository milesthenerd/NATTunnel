using System;
using System.Reflection;
using System.Security.Cryptography;
using Noise;

namespace NATTunnel.Embedded;

/// <summary>
/// Post-handshake AEAD transport with explicit per-packet nonces, suitable for UDP. Noise.NET's
/// built-in <see cref="Transport"/> assumes a reliable in-order channel — any packet loss or
/// reorder permanently desyncs its internal nonce counter. WireGuard, DTLS, and QUIC all solve
/// this by putting the nonce on the wire; we do the same.
///
/// Wire format for each data packet (the body after the 0x01 envelope byte):
///   [8 bytes: big-endian uint64 counter] [N bytes: ChaCha20-Poly1305 ciphertext incl. 16B tag]
///
/// The 12-byte AEAD nonce is `00 00 00 00 ‖ counter` (4-byte zero prefix + counter big-endian),
/// matching the construction used by WireGuard / Noise spec section 11.5.
///
/// Replay protection: a sliding 64-bit window tracks recently-seen counters. Packets with a
/// counter ≤ (highest - 64) are rejected as too-old; counters within the window must not have
/// been seen before. This is the standard WireGuard anti-replay design.
/// </summary>
public sealed class NoiseUdpTransport : IDisposable
{
    public const int CounterSize = 8;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    private const int ReplayWindowSize = 64;

    private readonly ChaCha20Poly1305 sendCipher;
    private readonly ChaCha20Poly1305 recvCipher;
    private ulong sendCounter;

    // Replay window: bitmap of last 64 counters relative to highestReceivedCounter.
    private ulong highestReceivedCounter;
    private ulong replayWindow;

    private NoiseUdpTransport(byte[] sendKey, byte[] recvKey)
    {
        sendCipher = new ChaCha20Poly1305(sendKey);
        recvCipher = new ChaCha20Poly1305(recvKey);
    }

    /// <summary>
    /// Extracts the two transport cipher keys from a completed Noise <see cref="Transport"/>
    /// via reflection and constructs an explicit-nonce AEAD transport. Disposes the original
    /// Noise Transport — the caller should not use it after calling this.
    /// </summary>
    public static NoiseUdpTransport FromNoiseTransport(Transport noiseTransport, bool isInitiator)
    {
        // Noise.NET layout: Transport<CipherType> has private CipherState c1, c2.
        // For initiator: c1 = send, c2 = recv. For responder: c1 = recv, c2 = send.
        // CipherState has a private byte[] k.
        Type transportType = noiseTransport.GetType();
        FieldInfo c1Field = transportType.GetField("c1", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: c1 not found.");
        FieldInfo c2Field = transportType.GetField("c2", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: c2 not found.");

        object c1 = c1Field.GetValue(noiseTransport)
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: c1 was null.");
        object c2 = c2Field.GetValue(noiseTransport)
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: c2 was null (XX is two-way).");

        byte[] c1Key = ExtractKey(c1);
        byte[] c2Key = ExtractKey(c2);

        byte[] sendKey = isInitiator ? c1Key : c2Key;
        byte[] recvKey = isInitiator ? c2Key : c1Key;

        try { noiseTransport.Dispose(); } catch { }

        return new NoiseUdpTransport(sendKey, recvKey);
    }

    private static byte[] ExtractKey(object cipherState)
    {
        FieldInfo kField = cipherState.GetType().GetField("k", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: CipherState.k not found.");
        byte[] k = kField.GetValue(cipherState) as byte[]
            ?? throw new InvalidOperationException("Noise.NET internal layout changed: CipherState.k was null.");
        // Copy — Noise.NET zeros its k on Dispose.
        var copy = new byte[k.Length];
        Buffer.BlockCopy(k, 0, copy, 0, k.Length);
        return copy;
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and writes [counter ‖ ciphertext ‖ tag] into
    /// <paramref name="destination"/>. Returns the number of bytes written.
    /// Destination must be at least plaintext.Length + 8 + 16 bytes.
    /// </summary>
    public int Encrypt(ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        int required = plaintext.Length + CounterSize + TagSize;
        if (destination.Length < required)
            throw new ArgumentException($"destination too small (need {required}, got {destination.Length})");

        ulong counter = unchecked(sendCounter++);
        WriteCounterBigEndian(counter, destination);

        Span<byte> nonce = stackalloc byte[NonceSize];
        BuildNonce(counter, nonce);

        var ciphertext = destination.Slice(CounterSize, plaintext.Length);
        var tag = destination.Slice(CounterSize + plaintext.Length, TagSize);
        sendCipher.Encrypt(nonce, plaintext, ciphertext, tag);

        return required;
    }

    /// <summary>
    /// Decrypts [counter ‖ ciphertext ‖ tag] from <paramref name="source"/>, writes plaintext to
    /// <paramref name="destination"/>. Returns plaintext length, or -1 if the packet is a replay
    /// or fails authentication.
    /// </summary>
    public int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        if (source.Length < CounterSize + TagSize) return -1;

        ulong counter = ReadCounterBigEndian(source);
        if (!CheckAndUpdateReplayWindow(counter, commit: false)) return -1;

        Span<byte> nonce = stackalloc byte[NonceSize];
        BuildNonce(counter, nonce);

        int ctLen = source.Length - CounterSize - TagSize;
        var ciphertext = source.Slice(CounterSize, ctLen);
        var tag = source.Slice(CounterSize + ctLen, TagSize);

        try { recvCipher.Decrypt(nonce, ciphertext, tag, destination.Slice(0, ctLen)); }
        catch (AuthenticationTagMismatchException) { return -1; }
        catch (CryptographicException) { return -1; }

        // Auth succeeded — now commit the counter to the replay window.
        CheckAndUpdateReplayWindow(counter, commit: true);
        return ctLen;
    }

    private static void BuildNonce(ulong counter, Span<byte> nonce)
    {
        // 4-byte zero prefix + 8-byte big-endian counter. Matches WireGuard / Noise rev34 §11.5.
        nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
        WriteCounterBigEndian(counter, nonce.Slice(4));
    }

    private static void WriteCounterBigEndian(ulong counter, Span<byte> destination)
    {
        destination[0] = (byte)(counter >> 56);
        destination[1] = (byte)(counter >> 48);
        destination[2] = (byte)(counter >> 40);
        destination[3] = (byte)(counter >> 32);
        destination[4] = (byte)(counter >> 24);
        destination[5] = (byte)(counter >> 16);
        destination[6] = (byte)(counter >> 8);
        destination[7] = (byte)counter;
    }

    private static ulong ReadCounterBigEndian(ReadOnlySpan<byte> source)
    {
        return ((ulong)source[0] << 56) | ((ulong)source[1] << 48) |
               ((ulong)source[2] << 40) | ((ulong)source[3] << 32) |
               ((ulong)source[4] << 24) | ((ulong)source[5] << 16) |
               ((ulong)source[6] << 8) | source[7];
    }

    /// <summary>
    /// Anti-replay sliding-window check (RFC 6479-style). When commit=false, returns whether
    /// the counter would be accepted without changing state. When commit=true (called only
    /// after AEAD auth succeeds), updates the window to record this counter as seen.
    /// </summary>
    private bool CheckAndUpdateReplayWindow(ulong counter, bool commit)
    {
        if (counter > highestReceivedCounter)
        {
            if (!commit) return true;
            ulong shift = counter - highestReceivedCounter;
            replayWindow = shift >= ReplayWindowSize ? 1UL : (replayWindow << (int)shift) | 1UL;
            highestReceivedCounter = counter;
            return true;
        }

        ulong distance = highestReceivedCounter - counter;
        if (distance >= ReplayWindowSize) return false;  // too old

        ulong bit = 1UL << (int)distance;
        if ((replayWindow & bit) != 0) return false;  // already seen
        if (commit) replayWindow |= bit;
        return true;
    }

    public void Dispose()
    {
        try { sendCipher?.Dispose(); } catch { }
        try { recvCipher?.Dispose(); } catch { }
    }
}
