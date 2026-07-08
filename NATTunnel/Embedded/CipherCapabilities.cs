using System.Security.Cryptography;
using Noise;

namespace NATTunnel.Embedded;

/// <summary>
/// Cipher capability advertisement + negotiation for the embedded Noise handshake. Peers exchange
/// a 1-byte bitmask (before Noise starts, in the clear) so each side can pick the same AEAD:
/// ChaCha20-Poly1305 when both support it, else AES-GCM. This exists because the BCL
/// ChaCha20Poly1305 is unavailable on some platforms (older Windows 10 / Server without CNG
/// ChaCha), and a peer on such a box must fall back to AES-GCM for BOTH handshake and transport.
/// The negotiation is bound into the Noise prologue so a MITM can't tamper the advertised bits.
/// </summary>
internal static class CipherCapabilities
{
    // Bit flags in the advertised capability byte.
    public const byte ChaChaBit = 0x01;
    public const byte AesGcmBit = 0x02;

    /// <summary>
    /// This node's capability byte. AES-GCM is always advertised (BCL AesGcm has near-universal
    /// support via AES-NI and is our guaranteed fallback). ChaCha is advertised only when the BCL
    /// ChaCha20Poly1305 is available on this platform. We use the BCL's own IsSupported as the
    /// gate: even though the transport now uses BouncyCastle's managed ChaCha (always available),
    /// the Noise.NET HANDSHAKE cipher is BCL-backed, so ChaCha is only usable end-to-end when the
    /// BCL supports it here.
    /// </summary>
    public static byte LocalCapabilities()
    {
        byte caps = AesGcmBit;
        if (ChaCha20Poly1305.IsSupported)
            caps |= ChaChaBit;
        return caps;
    }

    /// <summary>
    /// Deterministic cipher selection from both peers' capability bytes. Must return the same
    /// result on both sides so initiator and responder agree without a round-trip: prefer ChaCha
    /// when both support it, else AES-GCM. (AES-GCM is always advertised, so the AES-GCM path is
    /// the guaranteed common ground.)
    /// </summary>
    public static NegotiatedCipher Select(byte localCaps, byte remoteCaps)
    {
        bool bothChaCha = (localCaps & ChaChaBit) != 0 && (remoteCaps & ChaChaBit) != 0;
        return bothChaCha ? NegotiatedCipher.ChaCha20Poly1305 : NegotiatedCipher.AesGcm;
    }

    /// <summary>The Noise.NET cipher function for a negotiated choice.</summary>
    public static CipherFunction ToNoiseCipher(NegotiatedCipher cipher)
        => cipher == NegotiatedCipher.ChaCha20Poly1305 ? CipherFunction.ChaChaPoly : CipherFunction.AesGcm;

    /// <summary>
    /// The Noise prologue binding the negotiation: both capability bytes in a fixed order
    /// (initiator's first, then responder's) so any tampering with the cleartext exchange changes
    /// the handshake hash on exactly one side and breaks the handshake. Both peers must build this
    /// identically — hence the fixed initiator-then-responder ordering regardless of who computes it.
    /// </summary>
    public static byte[] BuildPrologue(byte initiatorCaps, byte responderCaps)
        => new byte[] { initiatorCaps, responderCaps };
}
