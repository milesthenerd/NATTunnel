namespace NATTunnelGUI.Updater;

/// <summary>Outcome of verifying a downloaded update binary before it is allowed to run.</summary>
public enum VerifyStatus
{
    /// <summary>The download passed verification — safe to apply.</summary>
    Trusted,
    /// <summary>The download did not match what the release published (checksum mismatch, or — for a
    /// future signature-based verifier — an unsigned/tampered/untrusted binary). Reject.</summary>
    Mismatch,
    /// <summary>Verification could not run (no expected value to compare, file missing, unexpected error).</summary>
    Error
}

public readonly record struct VerifyResult(VerifyStatus Status, string? Detail)
{
    /// <summary>The ONLY status that permits applying an update.</summary>
    public bool IsTrusted => Status == VerifyStatus.Trusted;
}

/// <summary>
/// Verifies a downloaded update binary before it is allowed to run
/// </summary>
public interface IUpdateVerifier
{
    /// <summary>Verify the file at <paramref name="filePath"/>. MUST return a non-Trusted status
    /// (never throw) on any failure — callers treat anything but Trusted as "do not apply".</summary>
    VerifyResult Verify(string filePath);
}
