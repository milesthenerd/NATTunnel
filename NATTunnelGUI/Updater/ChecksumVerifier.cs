using System;
using System.IO;
using System.Security.Cryptography;

namespace NATTunnelGUI.Updater;

/// <summary>
/// Update verifier: confirms a downloaded artifact's
/// SHA-256 hash matches the expected hash published alongside the release.
/// </summary>
public sealed class ChecksumVerifier : IUpdateVerifier
{
    private readonly string expectedSha256Hex;

    /// <param name="expectedSha256Hex">The expected lowercase hex SHA-256 (64 chars) from the release's
    /// published checksum. If null/blank, verification always fails closed (nothing to compare against).</param>
    public ChecksumVerifier(string? expectedSha256Hex)
    {
        this.expectedSha256Hex = (expectedSha256Hex ?? string.Empty).Trim().ToLowerInvariant();
    }

    public VerifyResult Verify(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return new VerifyResult(VerifyStatus.Error, "File to verify does not exist.");
        if (expectedSha256Hex.Length != 64)
            return new VerifyResult(VerifyStatus.Error, "No valid expected SHA-256 to compare against.");

        string actual;
        try
        {
            using var stream = File.OpenRead(filePath);
            byte[] hash = SHA256.HashData(stream);
            actual = Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            return new VerifyResult(VerifyStatus.Error, $"Could not hash the file: {ex.Message}");
        }

        // Fixed-time compare avoids leaking hash bytes via timing. Both are 64-char hex here.
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(actual),
                System.Text.Encoding.ASCII.GetBytes(expectedSha256Hex)))
        {
            return new VerifyResult(VerifyStatus.Mismatch,
                $"SHA-256 mismatch (expected {expectedSha256Hex[..12]}…, got {actual[..12]}…).");
        }

        return new VerifyResult(VerifyStatus.Trusted, $"sha256:{actual[..12]}…");
    }
}
