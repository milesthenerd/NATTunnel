using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NATTunnel.Updater;

/// <summary>
/// Daemon-side self-update for Linux (nattunneld). Unlike the GUI updater (which swaps a single
/// in-process exe on Windows), the daemon is a root systemd service that must update BOTH the daemon
/// and GUI binaries and coordinate a relay-aware kill first.
/// </summary>
public sealed class DaemonUpdater : IDisposable
{
    private const string ReleasesLatestUrl = "https://api.github.com/repos/milesthenerd/NATTunnel/releases/latest";
    private const string UserAgent = "NATTunnel-Daemon-Updater";
    private const string LinuxAssetToken = "linux-x64";
    private const string LinuxAssetExt = ".tar.gz";
    private const string ChecksumsAsset = "SHA256SUMS";

    private readonly HttpClient http;
    private readonly Action<string> log;

    /// <param name="log">Sink for progress/diagnostic lines (wire to the daemon's log).</param>
    public DaemonUpdater(Action<string> log)
    {
        this.log = log ?? (_ => { });
        http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    }

    public void Dispose() => http.Dispose();

    public sealed record Result(bool Ok, string Message);

    // Install directories (Linux .deb/.rpm/tar layout). The daemon replaces BOTH full publish trees.
    private const string DaemonInstallDir = "/usr/lib/nattunnel";
    private const string GuiInstallDir = "/usr/lib/nattunnel-gui";
    // Marker written just before the update-exit; the freshly-relaunched daemon deletes it once it's
    // healthy. If it's still present at startup, the previous update's relaunch didn't come up clean.
    private const string UpdateMarkerPath = "/etc/nattunnel/update-in-progress";

    /// <summary>
    /// Full self-update pipeline: find a newer release → download the linux tarball → verify SHA-256
    /// against SHA256SUMS → extract → relay-aware drain → swap BOTH install dirs (with rename-based
    /// rollback if the copy fails) → exit so systemd (Restart=always) relaunches at the new version.
    /// On success this does not return normally — it drains and exits the process.
    /// </summary>
    /// <param name="currentVersion">Running daemon version ("X.Y.Z"), for the newer-than check.</param>
    /// <param name="hostedRelayCount">How many relay pairs we host right now (drain gate).</param>
    /// <param name="requestGracefulDrain">Triggers the daemon's graceful MeshPeerLeave broadcast so
    /// dependent peers re-route before we go down.</param>
    /// <param name="exitProcess">Exits the process (systemd Restart=always then relaunches the new
    /// binary). Separate param so callers/tests can substitute; production passes Environment.Exit.</param>
    public async Task<Result> RunAsync(
        string currentVersion,
        Func<int> hostedRelayCount,
        Action requestGracefulDrain,
        Action exitProcess,
        CancellationToken ct = default)
    {
        try
        {
            // 1. Query the latest release.
            log("[Update] Checking GitHub for a newer release…");
            using var resp = await http.GetAsync(ReleasesLatestUrl, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new Result(false, $"GitHub API returned {(int)resp.StatusCode}.");

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var root = doc.RootElement;
            if (IsTrue(root, "draft") || IsTrue(root, "prerelease"))
                return new Result(false, "Latest release is a draft/prerelease — skipping.");

            string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
            if (!IsNewer(tag, currentVersion, out string latestNorm))
                return new Result(true, $"Already up to date (running {currentVersion}, latest {latestNorm}).");

            // 2. Locate the linux asset + checksums.
            (string assetUrl, string assetName) = FindAsset(root, LinuxAssetToken, LinuxAssetExt);
            string checksumsUrl = FindAssetUrl(root, ChecksumsAsset);
            if (assetUrl == null || checksumsUrl == null)
                return new Result(false, "Release is missing the linux asset or SHA256SUMS.");

            // 3. Download the tarball.
            string workDir = Path.Combine(Path.GetTempPath(), "nattunneld-update-" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(workDir);
            string archivePath = Path.Combine(workDir, assetName);
            log($"[Update] Downloading {assetName}…");
            if (!await DownloadAsync(assetUrl, archivePath, ct).ConfigureAwait(false))
                return new Result(false, "Download failed.");

            // 4. Verify integrity — ABORT on any mismatch.
            log("[Update] Verifying checksum…");
            string sums = await http.GetStringAsync(checksumsUrl, ct).ConfigureAwait(false);
            string expected = ReleaseChecksum.ExpectedHashFor(sums, assetName);
            if (expected == null)
                return new Result(false, "Checksum for the asset was not found in SHA256SUMS.");
            if (!ReleaseChecksum.Verify(archivePath, expected))
                return new Result(false, "Checksum mismatch — refusing to apply.");
            log("[Update] Checksum verified.");

            // 5. Extract the tarball and locate the two publish trees inside it.
            log("[Update] Extracting…");
            string extractDir = Path.Combine(workDir, "unpacked");
            Directory.CreateDirectory(extractDir);
            if (!Extract(archivePath, extractDir))
                return new Result(false, "Could not extract the update archive.");
            string newRoot = FindTarRoot(extractDir);
            if (newRoot == null || !File.Exists(Path.Combine(newRoot, "nattunneld")) || !File.Exists(Path.Combine(newRoot, "nattunnel-gui")))
                return new Result(false, "Update archive did not contain the expected nattunneld + nattunnel-gui binaries.");

            // 6. Relay-aware drain BEFORE the swap: if we carry relay traffic for other peers, broadcast
            //    a graceful leave so they re-route while our old binary is still running and reachable.
            int relays = hostedRelayCount();
            if (relays > 0)
            {
                log($"[Update] Hosting {relays} relay pair(s) — draining (graceful leave) before restart…");
                requestGracefulDrain();
                await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            }
            else
            {
                log("[Update] No hosted relays — no drain needed.");
            }

            // 7. SAFETY GUARD: only self-update a real packaged install.
            if (!RunningFromExpectedInstall())
                return new Result(false,
                    $"Refusing to self-update: this daemon isn't running from {DaemonInstallDir} " +
                    $"(process path: {Environment.ProcessPath}). Update via your package manager instead.");

            // 8. Swap BOTH install dirs. We need the daemon's assembled files under DaemonInstallDir and
            //    the GUI's under GuiInstallDir. The tar has them flat together, so stage each subset.
            log("[Update] Swapping installed binaries…");
            string stageDaemon = Path.Combine(workDir, "stage-daemon");
            string stageGui = Path.Combine(workDir, "stage-gui");
            StagePublishSubset(newRoot, stageDaemon, "nattunneld");
            StagePublishSubset(newRoot, stageGui, "nattunnel-gui");

            if (!TrySwapDir(DaemonInstallDir, stageDaemon, out string swapErr))
                return new Result(false, $"Daemon binary swap failed: {swapErr}");
            if (!TrySwapDir(GuiInstallDir, stageGui, out swapErr))
            {
                // GUI swap failed — roll the daemon dir back so we don't relaunch a version-split pair.
                log($"[Update] GUI swap failed ({swapErr}); rolling back daemon dir.");
                RollbackDir(DaemonInstallDir);
                return new Result(false, $"GUI binary swap failed (daemon rolled back): {swapErr}");
            }

            // 8. Mark update-in-progress so the relaunched daemon (or a later launch) can tell a prior
            //    update's relaunch didn't come up clean, then drain + exit. systemd (Restart=always)
            //    relaunches the NEW binary.
            log($"[Update] Update to {latestNorm} applied — draining and restarting…");
            try { Directory.CreateDirectory(Path.GetDirectoryName(UpdateMarkerPath)!); File.WriteAllText(UpdateMarkerPath, latestNorm); } catch { }
            requestGracefulDrain();
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
            log("[Update] Exiting for systemd restart.");
            exitProcess();
            return new Result(true, $"Updated to {latestNorm}; restarting."); // normally unreached
        }
        catch (OperationCanceledException)
        {
            return new Result(false, "Update cancelled.");
        }
        catch (Exception ex)
        {
            return new Result(false, $"Update error: {ex.Message}");
        }
    }

    private async Task<bool> DownloadAsync(string url, string dest, CancellationToken ct)
    {
        using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return false;
        await using var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var dst = File.Create(dest);
        await src.CopyToAsync(dst, ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>True if this daemon process is actually the binary installed at DaemonInstallDir, so a
    /// self-update would overwrite the install we're really running </summary>
    private static bool RunningFromExpectedInstall()
    {
        try
        {
            string procPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(procPath)) return false;
            // Resolve symlinks so /usr/bin/nattunneld → /usr/lib/nattunnel/nattunneld compares correctly.
            string resolved = new FileInfo(procPath).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? procPath;
            string dir = Path.GetDirectoryName(resolved);
            return string.Equals(
                Path.TrimEndingDirectorySeparator(dir ?? ""),
                Path.TrimEndingDirectorySeparator(DaemonInstallDir),
                StringComparison.Ordinal);
        }
        catch { return false; }
    }

    /// <summary>Extract a .tar.gz by shelling out to `tar`.</summary>
    private static bool Extract(string archivePath, string extractDir)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("tar", $"-xzf \"{archivePath}\" -C \"{extractDir}\"")
            { UseShellExecute = false, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi);
            p!.WaitForExit();
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    /// <summary>The tar wraps everything in a single "nattunnel_ver/" dir; return that inner dir
    /// (or the extract dir itself if the binaries are already at the top level).</summary>
    private static string FindTarRoot(string extractDir)
    {
        if (File.Exists(Path.Combine(extractDir, "nattunneld"))) return extractDir;
        foreach (var sub in Directory.EnumerateDirectories(extractDir))
            if (File.Exists(Path.Combine(sub, "nattunneld"))) return sub;
        return null;
    }

    /// <summary>Copy just one executable's publish files (the exe + its sidecar DLLs/configs) from the
    /// flat tar root into a clean staging dir.
    private static void StagePublishSubset(string tarRoot, string stageDir, string keepExe)
    {
        string otherExe = keepExe == "nattunneld" ? "nattunnel-gui" : "nattunneld";
        if (Directory.Exists(stageDir)) Directory.Delete(stageDir, true);
        Directory.CreateDirectory(stageDir);
        foreach (var file in Directory.EnumerateFiles(tarRoot))
        {
            string name = Path.GetFileName(file);
            if (name == otherExe) continue; // don't ship the sibling exe into this tree
            // Skip packaging extras that aren't part of the installed runtime dir.
            if (name is "install.sh" or "uninstall.sh" or "nattunnel.service" or "nattunnel.desktop") continue;
            File.Copy(file, Path.Combine(stageDir, name), overwrite: true);
        }
    }

    /// <summary>Replace an install dir with a staged new one: rename current → .bak,
    /// then copy the staged tree into place. On copy failure, restore the .bak. Leaves the .bak behind
    /// on success (a healthy relaunch cleans it up via <see cref="ClearUpdateArtifacts"/>).</summary>
    private bool TrySwapDir(string installDir, string stageDir, out string error)
    {
        error = null;
        string bak = installDir + ".bak";
        try
        {
            if (Directory.Exists(bak)) Directory.Delete(bak, true);   // stale from a prior update
            if (Directory.Exists(installDir)) Directory.Move(installDir, bak);
            Directory.CreateDirectory(installDir);
            foreach (var file in Directory.EnumerateFiles(stageDir))
            {
                string dest = Path.Combine(installDir, Path.GetFileName(file));
                File.Copy(file, dest, overwrite: true);
            }
            // Preserve the exec bits on the two entry-point binaries (File.Copy drops mode on Linux).
            MakeExecutable(Path.Combine(installDir, "nattunneld"));
            MakeExecutable(Path.Combine(installDir, "nattunnel-gui"));
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            RollbackDir(installDir); // restore from .bak if we got as far as renaming it
            return false;
        }
    }

    /// <summary>Restore an install dir from its .bak (used when a swap fails partway).</summary>
    private static void RollbackDir(string installDir)
    {
        string bak = installDir + ".bak";
        try
        {
            if (!Directory.Exists(bak)) return;
            if (Directory.Exists(installDir)) Directory.Delete(installDir, true);
            Directory.Move(bak, installDir);
        }
        catch { /* best-effort; if this fails the operator must reinstall */ }
    }

    private static void MakeExecutable(string path)
    {
        if (!File.Exists(path)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("chmod", $"+x \"{path}\"") { UseShellExecute = false })?.WaitForExit(); }
        catch { }
    }

    /// <summary>Called on daemon startup: if an update marker is present, this launch IS the post-update
    /// relaunch and we've come up successfully — so clear the marker and delete the leftover .bak dirs.
    /// </summary>
    public static void ClearUpdateArtifacts(Action<string> log = null)
    {
        try
        {
            if (!File.Exists(UpdateMarkerPath)) return;
            log?.Invoke("[Update] Post-update launch is healthy — cleaning up backups.");
            File.Delete(UpdateMarkerPath);
            foreach (var dir in new[] { DaemonInstallDir + ".bak", GuiInstallDir + ".bak" })
                if (Directory.Exists(dir)) { try { Directory.Delete(dir, true); } catch { } }
        }
        catch { /* best-effort cleanup */ }
    }

    private static bool IsTrue(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.True;

    /// <summary>True if <paramref name="tag"/> parses to a version strictly greater than
    /// <paramref name="current"/>. Compares on Major.Minor.Build; strips a leading 'v' and any
    /// pre-release suffix. <paramref name="latestNorm"/> gets the normalized latest string for logs.</summary>
    internal static bool IsNewer(string tag, string current, out string latestNorm)
    {
        latestNorm = "?";
        var latest = ParseVersion(tag);
        var cur = ParseVersion(current);
        if (latest == null) return false;
        latestNorm = $"{latest.Major}.{latest.Minor}.{latest.Build}";
        if (cur == null) return true; // can't read our own version → treat any release as newer
        return latest > cur;
    }

    private static Version ParseVersion(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (s.StartsWith("v", StringComparison.OrdinalIgnoreCase)) s = s.Substring(1);
        int dash = s.IndexOf('-');
        if (dash >= 0) s = s.Substring(0, dash);
        return Version.TryParse(s, out var v)
            ? new Version(v.Major, v.Minor, v.Build < 0 ? 0 : v.Build)
            : null;
    }

    private static (string url, string name) FindAsset(JsonElement release, string token, string ext)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return (null, null);
        foreach (var a in assets.EnumerateArray())
        {
            string name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (name == null) continue;
            if (name.Contains(token, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                return (a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null, name);
        }
        return (null, null);
    }

    private static string FindAssetUrl(JsonElement release, string exactName)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return null;
        foreach (var a in assets.EnumerateArray())
        {
            string name = a.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (string.Equals(name, exactName, StringComparison.OrdinalIgnoreCase))
                return a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
        }
        return null;
    }
}
