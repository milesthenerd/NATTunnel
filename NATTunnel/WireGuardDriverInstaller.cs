using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>
/// First-run driver installation for daemon mode. The WireGuard-NT kernel driver is required
/// but zx2c4 doesn't distribute it standalone — it ships only inside the WireGuard for Windows
/// installer. This helper acquires that installer (bundled or downloaded from the official URL)
/// and silent-installs it on first launch.
///
/// Acquisition order:
///   1. <c>wireguard-installer.exe</c> next to the running binary (offline-friendly).
///   2. <c>%LOCALAPPDATA%\NATTunnel\wireguard-installer.exe</c> from a prior download.
///   3. Fresh download from <see cref="OfficialInstallerUrl"/> into the cache directory.
///
/// Before launching, the binary's Authenticode signature is verified and the signing cert's
/// subject is checked against <see cref="ExpectedPublisher"/>. On any failure we refuse to
/// launch — the user can still install WireGuard for Windows manually.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WireGuardDriverInstaller
{
    private const string InstallerFileName = "wireguard-installer.exe";
    /// <summary>zx2c4's stable "latest installer" URL. Redirects to the current versioned EXE.</summary>
    private const string OfficialInstallerUrl = "https://download.wireguard.com/windows-client/wireguard-installer.exe";
    /// <summary>Substring expected in the signing certificate's Subject. WireGuard's installer
    /// is signed by "WireGuard LLC". A mismatch means we downloaded the wrong file (DNS poisoning,
    /// mirror compromise, etc.) and we refuse to run it.</summary>
    private const string ExpectedPublisher = "WireGuard LLC";

    /// <summary>True iff the WireGuard kernel driver is loaded in this process.</summary>
    public static bool IsDriverLoaded()
    {
        try { return WireGuardNTAPI.WireGuardGetRunningDriverVersion() > 0; }
        catch { return false; }
    }

    /// <summary>
    /// Resolve the absolute path to wg.exe from a standard WireGuard for Windows install,
    /// or null if not present. WG4W installs to %ProgramFiles%\WireGuard\wg.exe and doesn't
    /// add the directory to PATH.
    /// </summary>
    public static string TryFindWgExe()
    {
        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        })
        {
            if (string.IsNullOrEmpty(folder)) continue;
            string candidate = Path.Combine(folder, "WireGuard", "wg.exe");
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    /// <summary>True if a complete WireGuard for Windows install (kernel driver + user-space tools) is present.</summary>
    public static bool IsFullyInstalled() => IsDriverLoaded() && TryFindWgExe() != null;

    private static void TrySuppressManagerService()
    {
        try
        {
            RunSc("config WireGuardManager start= disabled");
            RunSc("stop WireGuardManager");
            foreach (var proc in Process.GetProcessesByName("wireguard"))
            {
                try { proc.Kill(); } catch { }
                proc.Dispose();
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Debug, $"TrySuppressManagerService: {ex.Message}");
        }
    }

    private static void RunSc(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        p?.WaitForExit(5_000);
    }

    /// <summary><c>%LOCALAPPDATA%\NATTunnel\wireguard-installer.exe</c>. Created on demand.</summary>
    private static string CachedInstallerPath()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string dir = Path.Combine(root, "NATTunnel");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, InstallerFileName);
    }

    /// <summary>
    /// Download the official installer into the cache dir if not already present. Verifies the
    /// resulting file's Authenticode signature + publisher subject before returning the path.
    /// Returns null on any failure (network, signature, etc.).
    /// </summary>
    private static string TryAcquireInstaller()
    {
        string cached = CachedInstallerPath();
        if (File.Exists(cached) && AuthenticodeVerifier.VerifyFile(cached, ExpectedPublisher))
            return cached;

        try
        {
            Program.Log(LogLevel.Info, $"Downloading WireGuard installer from {OfficialInstallerUrl} ...");
            string tmp = cached + ".part";
            if (File.Exists(tmp)) File.Delete(tmp);

            using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) })
            {
                using var stream = http.GetStreamAsync(OfficialInstallerUrl).GetAwaiter().GetResult();
                using var fs = File.Create(tmp);
                stream.CopyTo(fs);
            }

            if (File.Exists(cached)) File.Delete(cached);
            File.Move(tmp, cached);
            Program.Log(LogLevel.Debug, $"Downloaded {new FileInfo(cached).Length} bytes to {cached}.");
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"WireGuard installer download failed: {ex.Message}");
            return null;
        }

        if (!AuthenticodeVerifier.VerifyFile(cached, ExpectedPublisher))
        {
            Program.Log(LogLevel.Error, $"Downloaded WireGuard installer failed signature verification; refusing to run. Path: {cached}");
            try { File.Delete(cached); } catch { /* best-effort */ }
            return null;
        }

        return cached;
    }

    /// <summary>
    /// Attempt to silently install WireGuard for Windows from <paramref name="installerPath"/>.
    /// Triggers one UAC prompt; the install itself shows no UI. Returns true if the driver is
    /// loaded after install completes.
    /// </summary>
    private static bool TryInstall(string installerPath)
    {
        try
        {
            Program.Log(LogLevel.Info, $"Running WireGuard installer silently: {installerPath}");
            var psi = new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = "/S",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var p = Process.Start(psi);
            if (p == null)
            {
                Program.Log(LogLevel.Error, "Process.Start returned null for WireGuard installer.");
                return false;
            }
            if (!p.WaitForExit(120_000))
            {
                Program.Log(LogLevel.Error, "WireGuard installer did not exit within 120s; aborting wait.");
                return false;
            }
            if (p.ExitCode != 0)
            {
                Program.Log(LogLevel.Error, $"WireGuard installer exited with code {p.ExitCode}.");
                return false;
            }
            bool ok = IsDriverLoaded();
            if (ok) Program.Log(LogLevel.Info, "WireGuard driver installed and loaded.");
            else Program.Log(LogLevel.Warning, "WireGuard installer reported success but driver still not loaded — a reboot may be required.");
            TrySuppressManagerService();
            return ok;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Program.Log(LogLevel.Warning, "WireGuard driver install cancelled (UAC declined).");
            return false;
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"WireGuard driver install threw: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Try to install the driver. Order: bundled installer (sig-verify) → cached/downloaded
    /// installer (sig-verify) → silent install. Returns true if the driver is loaded after.
    /// </summary>
    public static bool TryInstallDriver()
    {
        string installer = TryAcquireInstaller();
        if (installer == null) return false;
        return TryInstall(installer);
    }
}
