using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace NATTunnelGUI.Updater;

/// <summary>Progress phases reported to the UI during an update.</summary>
public enum InstallPhase { Downloading, Verifying, Extracting, Applying, Failed }

public readonly record struct InstallProgress(InstallPhase Phase, double Fraction, string? Message);

/// <summary>
/// Downloads, integrity-verifies, and applies an update, then relaunches. Flow:
///   1. Download the platform asset (win-x64 .zip / linux-x64 .tar.gz) to a temp file.
///   2. Download SHA256SUMS, find this asset's line, verify the download via <see cref="ChecksumVerifier"/>.
///   3. Extract the archive; locate the new nattunnel-gui executable.
///   4. Self-replace the running executable (Windows: rename-current-to-.bak then move new in;
///      Linux: overwrite in place — a running ELF's file can be replaced) and relaunch, then exit.
///
/// Verification is MANDATORY: if the checksum can't be fetched or doesn't match, the update is aborted
/// and nothing is applied. Best-effort otherwise — returns false with a message instead of throwing.
/// </summary>
public sealed class UpdateInstaller : IDisposable
{
    private const string ExeName = "nattunnel-gui.exe";     // Windows executable name (AssemblyName)
    private const string ExeNameLinux = "nattunnel-gui";     // Linux has no extension
    private const string UserAgent = "NATTunnel-Updater";

    private readonly HttpClient http;

    public UpdateInstaller()
    {
        // Longer timeout than the check client — the asset is ~35MB.
        http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
    }

    public void Dispose() => http.Dispose();

    /// <summary>
    /// Run the full download → verify → apply → relaunch sequence. On success this RELAUNCHES the app
    /// and the caller should exit; on failure returns false (nothing applied) with the reason in the
    /// final progress Message. Never throws.
    /// </summary>
    public async Task<bool> DownloadVerifyAndApplyAsync(
        UpdateChecker.UpdateInfo info, IProgress<InstallProgress> progress, CancellationToken ct = default)
    {
        // In-app apply is Windows-only for now
        if (!OperatingSystem.IsWindows())
        {
            progress.Report(new(InstallPhase.Failed, 0,
                "In-app update isn't supported on this platform yet — update via your package manager or GitHub."));
            return false;
        }
        if (string.IsNullOrEmpty(info.PlatformAssetUrl) || string.IsNullOrEmpty(info.PlatformAssetName))
        {
            progress.Report(new(InstallPhase.Failed, 0, "No downloadable update asset for this platform."));
            return false;
        }
        if (string.IsNullOrEmpty(info.ChecksumsUrl))
        {
            progress.Report(new(InstallPhase.Failed, 0, "Release has no checksums — refusing to apply an unverified update."));
            return false;
        }

        string workDir = Path.Combine(Path.GetTempPath(), "nattunnel-update-" + Guid.NewGuid().ToString("N")[..8]);
        string archivePath = Path.Combine(workDir, info.PlatformAssetName);
        try
        {
            Directory.CreateDirectory(workDir);

            // 1. Download the archive.
            progress.Report(new(InstallPhase.Downloading, 0, "Downloading update…"));
            if (!await DownloadFileAsync(info.PlatformAssetUrl, archivePath, progress, ct).ConfigureAwait(false))
            {
                progress.Report(new(InstallPhase.Failed, 0, "Download failed."));
                return false;
            }

            // 2. Verify integrity against the published checksum. ABORT if it doesn't match.
            progress.Report(new(InstallPhase.Verifying, 1, "Verifying download…"));
            string? expected = await FetchExpectedHashAsync(info.ChecksumsUrl, info.PlatformAssetName, ct).ConfigureAwait(false);
            if (expected == null)
            {
                progress.Report(new(InstallPhase.Failed, 1, "Could not read the checksum for this asset — aborting."));
                return false;
            }
            var verdict = new ChecksumVerifier(expected).Verify(archivePath);
            if (!verdict.IsTrusted)
            {
                progress.Report(new(InstallPhase.Failed, 1, $"Integrity check failed: {verdict.Detail}"));
                return false;
            }

            // 3. Extract and find the new executable.
            progress.Report(new(InstallPhase.Extracting, 1, "Extracting…"));
            string extractDir = Path.Combine(workDir, "unpacked");
            Directory.CreateDirectory(extractDir);
            if (!Extract(archivePath, extractDir))
            {
                progress.Report(new(InstallPhase.Failed, 1, "Could not extract the update archive."));
                return false;
            }
            string exeName = OperatingSystem.IsWindows() ? ExeName : ExeNameLinux;
            string? newExe = Directory.EnumerateFiles(extractDir, exeName, SearchOption.AllDirectories).FirstOrDefault();
            if (newExe == null)
            {
                progress.Report(new(InstallPhase.Failed, 1, $"Update archive did not contain {exeName}."));
                return false;
            }

            // 4. Swap the running executable and relaunch.
            progress.Report(new(InstallPhase.Applying, 1, "Applying update…"));
            string currentExe = Environment.ProcessPath
                ?? throw new InvalidOperationException("Cannot determine current executable path.");
            ApplyAndRelaunch(currentExe, newExe);
            return true; // caller should now exit; the relaunched process takes over.
        }
        catch (OperationCanceledException)
        {
            progress.Report(new(InstallPhase.Failed, 0, "Update cancelled."));
            return false;
        }
        catch (Exception ex)
        {
            progress.Report(new(InstallPhase.Failed, 0, $"Update failed: {ex.Message}"));
            return false;
        }
        finally
        {
            // Best-effort cleanup of the download/extract scratch (not the applied files).
            try { if (Directory.Exists(workDir)) Directory.Delete(workDir, recursive: true); } catch { }
        }
    }

    private async Task<bool> DownloadFileAsync(string url, string destPath, IProgress<InstallProgress> progress, CancellationToken ct)
    {
        using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return false;

        long? total = resp.Content.Headers.ContentLength;
        await using var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var dst = File.Create(destPath);
        var buffer = new byte[81920];
        long read = 0;
        int n;
        while ((n = await src.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            await dst.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
            read += n;
            double frac = total is > 0 ? Math.Min(1.0, (double)read / total.Value) : 0;
            progress.Report(new(InstallPhase.Downloading, frac, "Downloading update…"));
        }
        return true;
    }

    /// <summary>Fetch SHA256SUMS and return the lowercase hex hash for <paramref name="assetName"/>.
    /// Standard sha256sum format: "&lt;hex&gt;  &lt;filename&gt;" per line. Null if not found.</summary>
    private async Task<string?> FetchExpectedHashAsync(string checksumsUrl, string assetName, CancellationToken ct)
    {
        try
        {
            string text = await http.GetStringAsync(checksumsUrl, ct).ConfigureAwait(false);
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0) continue;
                // Split on whitespace: [0]=hash, [last]=filename (may be prefixed with '*' for binary mode).
                var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                string fname = parts[^1].TrimStart('*');
                if (string.Equals(fname, assetName, StringComparison.OrdinalIgnoreCase))
                    return parts[0].ToLowerInvariant();
            }
        }
        catch { /* fall through to null → caller aborts */ }
        return null;
    }

    private static bool Extract(string archivePath, string extractDir)
    {
        try
        {
            if (archivePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                ZipFile.ExtractToDirectory(archivePath, extractDir);
                return true;
            }
            if (archivePath.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase))
            {
                // Shell out to tar — present on every Linux; avoids a third-party tar/gzip dependency.
                var psi = new ProcessStartInfo("tar", $"-xzf \"{archivePath}\" -C \"{extractDir}\"")
                {
                    UseShellExecute = false,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi);
                p!.WaitForExit();
                return p.ExitCode == 0;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>Replace the running executable with the new one and relaunch. On Windows a
    /// running exe can't be OVERWRITTEN but CAN be RENAMED, so we move the current one aside to .bak,
    /// then move the new one into its place.
    /// On Linux a running binary's file can be replaced directly (the kernel holds the open inode).</summary>
    private static void ApplyAndRelaunch(string currentExe, string newExe)
    {
        string dir = Path.GetDirectoryName(currentExe)!;
        string bak = currentExe + ".bak";

        if (OperatingSystem.IsWindows())
        {
            if (File.Exists(bak)) File.Delete(bak);          // clear a stale backup from a prior update
            File.Move(currentExe, bak);                       // rename the running exe out of the way
            File.Copy(newExe, currentExe, overwrite: false);  // drop the new exe into the original path
        }
        else
        {
            // Linux: overwrite in place, then ensure it's executable.
            File.Copy(newExe, currentExe, overwrite: true);
            try { Process.Start(new ProcessStartInfo("chmod", $"+x \"{currentExe}\"") { UseShellExecute = false })?.WaitForExit(); }
            catch { /* best-effort; the copy usually preserves the mode anyway */ }
        }

        // Relaunch the freshly-installed executable. The caller exits after this returns, freeing the
        // old process; the .bak (Windows) can be cleaned up by the next launch.
        Process.Start(new ProcessStartInfo(currentExe) { UseShellExecute = true, WorkingDirectory = dir });
    }
}
