#nullable enable
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NATTunnel.Icmp;

/// <summary>
/// Installs / removes WinDivert as a PERSISTENT Windows kernel-driver service so that UNPRIVILEGED processes
/// can later open capture handles (<c>WinDivertOpen</c>) at runtime.
///
/// WHY THIS EXISTS: WinDivert's default on-demand load needs Administrator EVERY time it must start the driver,
/// and it self-deregisters when the last handle closes — so a plain unprivileged app on a machine where nothing
/// installed the driver cannot use ICMP capture. Registering WinDivert as a standing service ONCE (elevated, at
/// install time) with a permissive device ACL fixes that: afterward, the unprivileged host process opens handles
/// via <c>WinDivertOpen(..., WINDIVERT_FLAG_NO_INSTALL)</c> against the already-running service.
///
/// This is the enabler for the EMBEDDED opt-in ICMP path. Daemon mode doesn't need it (the daemon self-elevates
/// for WireGuard, so it can load WinDivert on demand). An embedded integrator runs this once from their installer
/// (via the bundled nattunnel-icmp-service.exe tool) or through MeshNode's install helper.
///
/// Requires Administrator to install/uninstall (creating a kernel-driver service is privileged). Returns a clear
/// result so callers can surface accurate status.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WinDivertServiceInstaller
{
    /// <summary>The service name WinDivert uses by default. WinDivertOpen looks for exactly this.</summary>
    public const string ServiceName = "WinDivert";

    // --- advapi32 SCM P/Invoke (mirrors the pattern in WireGuardService.cs) ---
    // string? on the optional params: SCM APIs accept null for machine/database/group/deps/account/password.
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateServiceW(
        IntPtr scm, string serviceName, string displayName, uint desiredAccess, uint serviceType,
        uint startType, uint errorControl, string binaryPath, string? loadOrderGroup, IntPtr tagId,
        string? dependencies, string? startName, string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartServiceW(IntPtr service, uint numArgs, string[]? args);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ControlService(IntPtr service, uint control, ref SERVICE_STATUS status);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode,
                    dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_KERNEL_DRIVER = 0x00000001;
    private const uint SERVICE_DEMAND_START = 0x00000003; // driver started on first open
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const int ERROR_SERVICE_EXISTS = 1073;
    private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    public enum Result { Installed, AlreadyInstalled, Uninstalled, NotInstalled, NotAdministrator, DriverFileMissing, Failed }

    /// <summary>True if the current process is elevated (required to install/uninstall).</summary>
    public static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>
    /// True if the WinDivert service is already registered (so unprivileged opens will work). Cheap, no admin.
    /// </summary>
    public static bool IsInstalled()
    {
        IntPtr scm = OpenSCManagerW(null, null, 0x0001 /*SC_MANAGER_CONNECT*/);
        if (scm == IntPtr.Zero) return false;
        try
        {
            IntPtr svc = OpenServiceW(scm, ServiceName, 0x0001 /*SERVICE_QUERY_CONFIG-ish read*/ );
            if (svc == IntPtr.Zero) return false;
            CloseServiceHandle(svc);
            return true;
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>
    /// Registers WinDivert64.sys (located next to <paramref name="driverDir"/> or the current assembly) as a
    /// persistent demand-start kernel-driver service, then starts it. After this, unprivileged processes can
    /// open capture handles. Idempotent: returns AlreadyInstalled if the service exists.
    /// </summary>
    public static Result Install(string? driverDir = null)
    {
        if (!IsElevated()) return Result.NotAdministrator;
        if (IsInstalled()) { StartIfNeeded(); return Result.AlreadyInstalled; }

        string? sysPath = ResolveDriverPath(driverDir);
        if (sysPath == null || !File.Exists(sysPath)) return Result.DriverFileMissing;

        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return Result.Failed;
        try
        {
            IntPtr svc = CreateServiceW(
                scm, ServiceName, ServiceName,
                SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                sysPath, null, IntPtr.Zero, null, null, null);

            if (svc == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_SERVICE_EXISTS) { StartIfNeeded(); return Result.AlreadyInstalled; }
                return Result.Failed;
            }

            // Start it now so the device exists immediately. (Demand-start also auto-starts on first
            // WinDivertOpen, but starting here makes the install verifiable.)
            StartServiceW(svc, 0, null);
            CloseServiceHandle(svc);
            return Result.Installed;
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Stops and removes the WinDivert service. Requires admin.</summary>
    public static Result Uninstall()
    {
        if (!IsElevated()) return Result.NotAdministrator;

        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return Result.Failed;
        try
        {
            IntPtr svc = OpenServiceW(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return Result.NotInstalled;
            try
            {
                var st = new SERVICE_STATUS();
                ControlService(svc, SERVICE_CONTROL_STOP, ref st); // best-effort stop
                return DeleteService(svc) ? Result.Uninstalled : Result.Failed;
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StartIfNeeded()
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return;
        try
        {
            IntPtr svc = OpenServiceW(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return;
            StartServiceW(svc, 0, null); // no-op if already running
            CloseServiceHandle(svc);
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Locate WinDivert64.sys — explicit dir, else next to this assembly (where the .csproj copies it).</summary>
    private static string? ResolveDriverPath(string? driverDir)
    {
        if (!string.IsNullOrEmpty(driverDir))
        {
            string p = Path.Combine(driverDir, "WinDivert64.sys");
            if (File.Exists(p)) return p;
        }
        string baseDir = AppContext.BaseDirectory;
        string local = Path.Combine(baseDir, "WinDivert64.sys");
        return File.Exists(local) ? local : null;
    }
}
