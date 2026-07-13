using System;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace NATTunnelGUI;

public sealed class UpdateChecker : IDisposable
{
    // Unauthenticated GitHub API: 60 req/hr/IP — far more than a startup + few-hourly poll needs.
    // A User-Agent header is REQUIRED by the GitHub API or it returns 403.
    private const string ReleasesLatestUrl = "https://api.github.com/repos/milesthenerd/NATTunnel/releases/latest";
    private const string UserAgent = "NATTunnel-Updater";

    private readonly HttpClient http;

    public UpdateChecker()
    {
        // Own client (not MainWindow's localhost one) — GitHub needs a longer timeout + a UA header.
        http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    }

    public void Dispose() => http.Dispose();

    /// <summary>
    /// The result of a check. <see cref="UpdateAvailable"/> is the only field the button needs;
    /// the rest populate the modal. All null/false on any failure or when already up to date.
    /// </summary>
    public sealed record UpdateInfo(
        bool UpdateAvailable,
        Version? CurrentVersion,
        Version? LatestVersion,
        string? LatestTag,
        string? ReleaseNotes,
        string? PlatformAssetUrl,   // the download for THIS OS (win-x64 zip / linux-x64 tar.gz)
        string? PlatformAssetName,
        string? ChecksumsUrl,       // the SHA256SUMS asset, for integrity-verifying the download
        string? ReleasePageUrl);

    /// <summary>The running build's version, read from THIS assembly (the GUI exe)
    public static Version CurrentVersion()
    {
        var v = typeof(UpdateChecker).Assembly.GetName().Version ?? new Version(0, 0, 0);
        // Normalize to 3 components so comparison against a vX.Y.Z tag is apples-to-apples.
        return new Version(v.Major, v.Minor, v.Build < 0 ? 0 : v.Build);
    }

    /// <summary>
    /// Query GitHub for the latest release and decide whether it is newer than the running build.
    /// </summary>
    public async Task<UpdateInfo> CheckAsync()
    {
        var current = CurrentVersion();
        var none = new UpdateInfo(false, current, null, null, null, null, null, null, null);

        try
        {
            using var resp = await http.GetAsync(ReleasesLatestUrl).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return none; // 403 rate-limit, 404 no releases yet, etc. — treat as "no update".

            await using var stream = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream).ConfigureAwait(false);
            var root = doc.RootElement;

            // /releases/latest already excludes drafts + prereleases, but double-check defensively.
            if (root.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True) return none;
            if (root.TryGetProperty("prerelease", out var pre) && pre.ValueKind == JsonValueKind.True) return none;

            string? tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
            var latest = ParseTagVersion(tag);
            if (latest == null) return none; // unparseable tag → don't claim an update.

            if (latest <= current)
                return new UpdateInfo(false, current, latest, tag, null, null, null, null, null);

            // Newer. Pull the release notes + the per-platform asset + checksums for the apply step.
            string? notes = root.TryGetProperty("body", out var b) ? b.GetString() : null;
            // Prefer GitHub's own release page URL over constructing one from the tag — handles any
            // tag-naming edge case the release page might not map to /releases/tag/<tag> cleanly.
            string? pageUrl = root.TryGetProperty("html_url", out var h) ? h.GetString() : null;
            (string? url, string? name) = FindPlatformAsset(root);
            string? checksumsUrl = FindAssetUrlByName(root, "SHA256SUMS");

            return new UpdateInfo(true, current, latest, tag, notes, url, name, checksumsUrl, pageUrl);
        }
        catch
        {
            // Offline, DNS failure, timeout, JSON shape change — all resolve to "no update".
            return none;
        }
    }

    /// <summary>Parse a release tag like "vx.x.x" into a 3-part Version. Null if unparseable.</summary>
    internal static Version? ParseTagVersion(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag)) return null;
        string s = tag.Trim();
        if (s.StartsWith("v", StringComparison.OrdinalIgnoreCase)) s = s.Substring(1);
        // Drop any pre-release/build suffix (e.g. "1.6.0-rc1" → "1.6.0") — we only compare release cores.
        int dash = s.IndexOf('-');
        if (dash >= 0) s = s.Substring(0, dash);
        return Version.TryParse(s, out var v)
            ? new Version(v.Major, v.Minor, v.Build < 0 ? 0 : v.Build)
            : null;
    }

    /// <summary>Locate the release asset for the CURRENT OS: the win-x64 zip on Windows, the
    /// linux-x64 tar.gz on Linux. Returns (null,null) on any other OS or if no match — the caller
    /// treats a missing asset as "can't auto-update, offer manual".</summary>
    private static (string? url, string? name) FindPlatformAsset(JsonElement release)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return (null, null);

        // Match the CI asset names: nattunnel-gui-<ver>-win-x64.zip / nattunnel_<ver>_linux-x64.tar.gz
        bool win = OperatingSystem.IsWindows();
        string ridToken = win ? "win-x64" : "linux-x64";
        string ext = win ? ".zip" : ".tar.gz";
        if (!win && !OperatingSystem.IsLinux()) return (null, null); // macOS/other: no auto-update asset

        foreach (var asset in assets.EnumerateArray())
        {
            string? name = asset.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (name == null) continue;
            if (name.Contains(ridToken, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                string? url = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                return (url, name);
            }
        }
        return (null, null);
    }

    /// <summary>Find the download URL of the asset whose name exactly equals <paramref name="assetName"/>
    /// (e.g. "SHA256SUMS"). Null if absent.</summary>
    private static string? FindAssetUrlByName(JsonElement release, string assetName)
    {
        if (!release.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            return null;
        foreach (var asset in assets.EnumerateArray())
        {
            string? name = asset.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (string.Equals(name, assetName, StringComparison.OrdinalIgnoreCase))
                return asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
        }
        return null;
    }
}
