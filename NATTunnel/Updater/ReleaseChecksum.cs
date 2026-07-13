using System;
using System.IO;
using System.Security.Cryptography;

namespace NATTunnel.Updater;

/// <summary>
/// Dependency-free primitives for integrity-checking a downloaded release artifact against the
/// SHA-256 hashes published in a release's <c>SHA256SUMS</c> file.
/// </summary>
public static class ReleaseChecksum
{
    /// <summary>Compute the lowercase-hex SHA-256 of a file. Throws only on IO errors.</summary>
    public static string HashFile(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Verify that the file at <paramref name="filePath"/> hashes to <paramref name="expectedSha256Hex"/>.
    /// Fails closed: false if the expected hash is missing/malformed, the file is unreadable, or the
    /// hashes differ.
    /// </summary>
    public static bool Verify(string filePath, string expectedSha256Hex)
    {
        string expected = (expectedSha256Hex ?? string.Empty).Trim().ToLowerInvariant();
        if (expected.Length != 64) return false;
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;

        string actual;
        try { actual = HashFile(filePath); }
        catch { return false; }

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(actual),
            System.Text.Encoding.ASCII.GetBytes(expected));
    }

    /// <summary>
    /// Parse a <c>SHA256SUMS</c> file body (standard <c>sha256sum</c> format: "&lt;hex&gt;  &lt;filename&gt;"
    /// per line, filename optionally prefixed with '*' for binary mode) and return the lowercase-hex
    /// hash for <paramref name="assetName"/>. Null if the asset isn't listed or the body is unparseable.
    /// </summary>
    public static string ExpectedHashFor(string sha256SumsBody, string assetName)
    {
        if (string.IsNullOrEmpty(sha256SumsBody) || string.IsNullOrEmpty(assetName)) return null;
        foreach (var line in sha256SumsBody.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            var parts = trimmed.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            string fname = parts[^1].TrimStart('*');
            if (string.Equals(fname, assetName, StringComparison.OrdinalIgnoreCase))
                return parts[0].ToLowerInvariant();
        }
        return null;
    }
}
