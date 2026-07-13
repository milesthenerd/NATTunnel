using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using NATTunnelGUI.Updater;

namespace NATTunnelGUI;

/// <summary>
/// The "update available" modal. Shows the new version + release notes and, when a downloadable asset
/// and checksum exist for this platform, offers "Update Now" — which downloads, integrity-verifies
/// (SHA-256 against the release's SHA256SUMS), applies the swap, and relaunches. "View on GitHub" is
/// always available as the manual fallback.
/// </summary>
public partial class UpdateWindow : Window
{
    private readonly UpdateChecker.UpdateInfo info;
    private bool installing;

    // Parameterless ctor for the XAML designer / loader; real use goes through the info ctor.
    public UpdateWindow() : this(null) { }

    public UpdateWindow(UpdateChecker.UpdateInfo? updateInfo)
    {
        InitializeComponent();
        info = updateInfo ?? new UpdateChecker.UpdateInfo(false, null, null, null, null, null, null, null, null);

        string current = info.CurrentVersion?.ToString(3) ?? "?";
        string latest = info.LatestVersion?.ToString(3) ?? (info.LatestTag ?? "?");
        VersionSummary.Text = $"You have v{current}. Version {info.LatestTag ?? ("v" + latest)} is available.";

        ReleaseNotesText.Text = string.IsNullOrWhiteSpace(info.ReleaseNotes)
            ? "(No release notes provided.)"
            : info.ReleaseNotes;

        // "Update Now" behaves differently per platform:
        //   • Windows: the GUI does the swap in-process. Needs a platform asset+checksum.
        //   • Linux: the GUI can't touch the root systemd daemon, so it asks the DAEMON to self-update via
        //     POST /update; the daemon downloads/verifies/drains/swaps both binaries and restarts.
        bool haveAsset = !string.IsNullOrEmpty(info.PlatformAssetUrl) && !string.IsNullOrEmpty(info.ChecksumsUrl);
        bool canInstall = OperatingSystem.IsWindows() ? haveAsset : OperatingSystem.IsLinux();
        UpdateNowButton.IsEnabled = canInstall;
        ApplyHint.Text = OperatingSystem.IsWindows()
            ? (canInstall ? "Downloads, verifies, and restarts."
                          : "No verified download for this platform — use “View on GitHub”.")
            : OperatingSystem.IsLinux()
                ? "Asks the daemon to update itself and restart."
                : "Update via your package manager, or “View on GitHub”.";
    }

    private void ViewOnGitHub_Click(object? sender, RoutedEventArgs e)
    {
        // Prefer GitHub's own release-page URL; fall back to one built from the tag, then to the
        // releases list. (html_url avoids tag-naming edge cases in the constructed URL.)
        string url = !string.IsNullOrEmpty(info.ReleasePageUrl) ? info.ReleasePageUrl
            : !string.IsNullOrEmpty(info.LatestTag) ? $"https://github.com/milesthenerd/NATTunnel/releases/tag/{info.LatestTag}"
            : "https://github.com/milesthenerd/NATTunnel/releases";
        OpenUrl(url);
    }

    private async void UpdateNow_Click(object? sender, RoutedEventArgs e)
    {
        if (installing) return;
        installing = true;
        UpdateNowButton.IsEnabled = false;
        CloseButton.IsEnabled = false;
        InstallProgress.IsVisible = true;

        if (OperatingSystem.IsLinux())
        {
            await TriggerDaemonUpdate();
            return;
        }

        var progress = new Progress<InstallProgress>(p =>
        {
            // Progress callbacks may arrive off the UI thread — marshal.
            Dispatcher.UIThread.Post(() =>
            {
                InstallProgress.Value = p.Fraction;
                ApplyHint.Text = p.Message ?? p.Phase.ToString();
            });
        });

        using var installer = new UpdateInstaller();
        bool ok = await installer.DownloadVerifyAndApplyAsync(info, progress);

        if (ok)
        {
            // The new executable was launched. Shut this instance down so the file swap settles and the
            // relaunched process takes over. Closing the main window runs its normal shutdown path.
            Dispatcher.UIThread.Post(() =>
            {
                if (Application.Current?.ApplicationLifetime is
                    Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                {
                    desktop.Shutdown();
                }
                else
                {
                    Environment.Exit(0);
                }
            });
        }
        else
        {
            // Failure message is already in ApplyHint via the progress callback. Re-enable controls.
            installing = false;
            InstallProgress.IsVisible = false;
            CloseButton.IsEnabled = true;
            UpdateNowButton.IsEnabled = true;
        }
    }

    /// <summary>Linux: the GUI can't swap the root daemon, so it asks the daemon to self-update via
    /// POST /update. The daemon downloads/verifies/drains/swaps both binaries and restarts itself; the
    /// GUI just fires the request and reports that it started (the daemon does the rest out-of-band).</summary>
    private async Task TriggerDaemonUpdate()
    {
        InstallProgress.IsIndeterminate = true;
        ApplyHint.Text = "Asking the daemon to update…";
        try
        {
            using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var resp = await client.PostAsync("http://localhost:51889/update", null);
            if (resp.StatusCode == System.Net.HttpStatusCode.Accepted)
            {
                ApplyHint.Text = "Daemon is updating and will restart shortly. You can close this window.";
                CloseButton.IsEnabled = true;
            }
            else
            {
                ApplyHint.Text = $"Daemon refused the update ({(int)resp.StatusCode}).";
                ResetAfterFailure();
            }
        }
        catch (Exception ex)
        {
            ApplyHint.Text = $"Couldn't reach the daemon: {ex.Message}";
            ResetAfterFailure();
        }
    }

    private void ResetAfterFailure()
    {
        installing = false;
        InstallProgress.IsVisible = false;
        InstallProgress.IsIndeterminate = false;
        CloseButton.IsEnabled = true;
        UpdateNowButton.IsEnabled = true;
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();

    private static void OpenUrl(string url)
    {
        try
        {
            // UseShellExecute lets the OS open the default browser cross-platform.
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // Opening a browser is best-effort; nothing actionable if the shell refuses.
        }
    }
}
