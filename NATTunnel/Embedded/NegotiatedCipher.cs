namespace NATTunnel.Embedded;

/// <summary>
/// The AEAD cipher a peer pair agreed on for their Noise handshake and data transport.
/// ChaCha20-Poly1305 is preferred (fast in software, no hardware dependency); AES-GCM is the
/// fallback for platforms whose BCL lacks ChaCha20Poly1305 (older Windows 10 / Server without
/// CNG ChaCha). Both are TLS 1.3 AEADs at the same security level — the choice is about
/// portability, not strength. The transport cipher MUST match the handshake cipher, since a
/// peer that can't do ChaCha in the handshake can't decrypt ChaCha data either.
/// </summary>
internal enum NegotiatedCipher
{
    ChaCha20Poly1305,
    AesGcm,
}
