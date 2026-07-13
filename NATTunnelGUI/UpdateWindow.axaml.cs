using System;
using System.Diagnostics;
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

        // "Update Now" needs: a platform download, a checksum to verify it, AND a platform whose in-app
        // apply is supported (Windows only for now — on Linux the root systemd daemon can't be swapped
        // by the user-space GUI; those users update via package manager / GitHub).
        bool haveAsset = !string.IsNullOrEmpty(info.PlatformAssetUrl) && !string.IsNullOrEmpty(info.ChecksumsUrl);
        bool canInstall = haveAsset && OperatingSystem.IsWindows();
        UpdateNowButton.IsEnabled = canInstall;
        ApplyHint.Text = canInstall
            ? "Downloads, verifies, and restarts."
            : OperatingSystem.IsWindows()
                ? "No verified download for this platform — use “View on GitHub”."
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
