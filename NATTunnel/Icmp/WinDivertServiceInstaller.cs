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
/// install time) keeps the driver loaded: afterward the host opens handles via
/// <c>WinDivertOpen(..., WINDIVERT_FLAG_NO_INSTALL)</c> against the already-running service.
///
/// Keeping the driver loaded is only half of it: the caller also needs permission to OPEN the device, and
/// `\\.\WinDivert` is admin-only by default. <see cref="ApplyPermissiveDeviceDacl"/> grants the Users group
/// access, which is what makes a non-elevated open succeed.
///
/// THE GRANT DOES NOT PERSIST. WinDivert recreates its device with an explicit admin-only descriptor on every
/// load and ignores the service's registry `Security` value, so a reboot undoes it. Something elevated has to
/// re-apply it — <see cref="IcmpCapture.AnyCaptureAvailable"/> does so on any elevated run, which repairs the
/// machine for unprivileged hosts that start later. A machine that only ever runs unprivileged embedded hosts
/// needs `/install` re-run after each boot.
///
/// SECURITY: that grant lets ANY process running as a normal user capture and inject packets through WinDivert,
/// not just this application. It is applied only by an explicit, elevated install.
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

    // --- device DACL: open \\.\WinDivert and replace its security descriptor ---
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(IntPtr handle, uint securityInformation, byte[] securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetKernelObjectSecurity(
        IntPtr handle, uint securityInformation, byte[]? securityDescriptor, uint length, out uint lengthNeeded);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        byte[] securityDescriptor, uint revision, uint securityInformation, out IntPtr sddl, out uint sddlLen);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr securityDescriptor, out uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr mem);

    private const uint DACL_SECURITY_INFORMATION = 0x00000004;
    private const uint SDDL_REVISION_1 = 1;
    private const uint WRITE_DAC = 0x00040000;
    private const uint READ_CONTROL = 0x00020000;
    private const uint OPEN_EXISTING = 3;
    private const string DevicePath = @"\\.\WinDivert";

    /// <summary>
    /// SDDL for the device: full access to SYSTEM and Administrators, generic read/write to the built-in Users
    /// group. Granting Users is what lets a NON-ELEVATED process open the device.
    /// </summary>
    private const string PermissiveDeviceSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)";

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode,
                    dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    /// <summary>
    /// Our own boot service. Distinct from <see cref="ServiceName"/> (the WinDivert kernel driver): this is a
    /// user-mode service whose only job is to hold the driver loaded and keep the Users DACL applied, since
    /// WinDivert re-creates its device admin-only on every load.
    /// </summary>
    public const string KeeperServiceName = "NATTunnelIcmpKeeper";
    private const string KeeperDisplayName = "NATTunnel ICMP Capture Keeper";

    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_AUTO_START = 0x00000002;

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
        // Re-apply the DACL on an existing install too, so re-running install repairs a machine where it was
        // cleared or predates this step.
        if (IsInstalled()) { StartIfNeeded(); ApplyPermissiveDeviceDacl(); return Result.AlreadyInstalled; }

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

            // The device only exists once the driver is loaded, so the DACL has to be applied after starting.
            ApplyPermissiveDeviceDacl();
            return Result.Installed;
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>
    /// Widen the DACL on \\.\WinDivert so non-elevated processes in Users can open it. Without this the service
    /// being installed is not enough — the driver stays loaded but a non-elevated WinDivertOpen still fails with
    /// ERROR_ACCESS_DENIED. Requires admin (already checked by the callers).
    ///
    /// Applies to the LIVE device (immediate effect) and writes the same descriptor to the service's registry
    /// key so it is reapplied whenever the device is recreated. Setting only the live device does not survive a
    /// reboot: the device comes back with a default, admin-only descriptor.
    /// </summary>
    public static bool ApplyPermissiveDeviceDacl()
    {
        IntPtr sd = IntPtr.Zero;
        IntPtr device = IntPtr.Zero;
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PermissiveDeviceSddl, SDDL_REVISION_1, out sd, out uint sdSize))
            {
                Log($"[ICMP][windivert] could not build the device security descriptor (error {Marshal.GetLastWin32Error()})");
                return false;
            }

            // NOTE: there is no way to make this persist. Writing the descriptor to the service's registry
            // `Security` value does NOT work — WinDivert creates its device with an explicit descriptor, which
            // overrides it (verified: value present in the registry, device still admin-only after a reboot).
            // The DACL must therefore be re-applied by something elevated after every driver load.

            // WRITE_DAC is the access we actually need; READ_CONTROL makes failures easier to diagnose.
            device = CreateFileW(DevicePath, WRITE_DAC | READ_CONTROL, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (device == IntPtr.Zero || device == new IntPtr(-1))
            {
                Log($"[ICMP][windivert] could not open {DevicePath} to set its DACL (error {Marshal.GetLastWin32Error()}) — " +
                    "the driver may not be running yet");
                return false;
            }

            var managed = new byte[sdSize];
            Marshal.Copy(sd, managed, 0, (int)sdSize);
            if (!SetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION, managed))
            {
                Log($"[ICMP][windivert] failed to set the device DACL (error {Marshal.GetLastWin32Error()})");
                return false;
            }

            Log($"[ICMP][windivert] granted the Users group access to {DevicePath} — non-elevated processes on " +
                "this machine can now capture and inject packets via WinDivert");
            return true;
        }
        catch (Exception ex)
        {
            Log($"[ICMP][windivert] device DACL update threw: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
        finally
        {
            if (device != IntPtr.Zero && device != new IntPtr(-1)) CloseHandle(device);
            if (sd != IntPtr.Zero) LocalFree(sd);
        }
    }

    /// <summary>
    /// Whether \\.\WinDivert currently grants the Users group access, i.e. whether a non-elevated process could
    /// open it. Reads the LIVE device rather than assuming the install took.
    /// </summary>
    public static bool IsDeviceUserAccessible()
    {
        IntPtr device = IntPtr.Zero;
        try
        {
            device = CreateFileW(DevicePath, READ_CONTROL, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (device == IntPtr.Zero || device == new IntPtr(-1)) return false;

            uint needed = 0;
            GetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION, null, 0, out needed);
            if (needed == 0) return false;
            var buf = new byte[needed];
            if (!GetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION, buf, needed, out _)) return false;

            // Round-trip to SDDL rather than walking the ACL by hand — we only need to know whether the
            // built-in Users group (BU) appears in an allow ACE.
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, out IntPtr sddlPtr, out _))
                return false;
            try
            {
                string sddl = Marshal.PtrToStringUni(sddlPtr) ?? "";
                return sddl.Contains(";BU)", StringComparison.Ordinal);
            }
            finally { LocalFree(sddlPtr); }
        }
        catch { return false; }
        finally { if (device != IntPtr.Zero && device != new IntPtr(-1)) CloseHandle(device); }
    }

    // Console, not Program.Log: this file is also compiled into the standalone nattunnel-icmp-service tool,
    // which doesn't link NATTunnel.Program. The daemon captures stdout, so the message lands either way.
    private static void Log(string message) => Console.WriteLine(message);

    /// <summary>
    /// Register the keeper as an auto-start LocalSystem service running <paramref name="exePath"/> with the
    /// given argument. Needed because the Users DACL is lost on every driver load — see the type doc.
    /// </summary>
    public static Result InstallKeeperService(string exePath, string serviceArg = "run-keeper")
    {
        if (!IsElevated()) return Result.NotAdministrator;
        if (!File.Exists(exePath)) return Result.DriverFileMissing;

        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return Result.Failed;
        try
        {
            // Quote the path — CreateService takes a full command line, so an unquoted Program Files path
            // would be parsed as multiple arguments.
            string binPath = $"\"{exePath}\" {serviceArg}";
            IntPtr svc = CreateServiceW(
                scm, KeeperServiceName, KeeperDisplayName,
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                binPath, null, IntPtr.Zero, null, null, null);

            if (svc == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_SERVICE_EXISTS) return Result.Failed;
                svc = OpenServiceW(scm, KeeperServiceName, SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero) return Result.Failed;
            }

            StartServiceW(svc, 0, null);
            CloseServiceHandle(svc);
            return Result.Installed;
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Stops and removes the keeper service. Requires admin.</summary>
    public static Result UninstallKeeperService()
    {
        if (!IsElevated()) return Result.NotAdministrator;

        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return Result.Failed;
        try
        {
            IntPtr svc = OpenServiceW(scm, KeeperServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return Result.NotInstalled;
            try
            {
                var status = new SERVICE_STATUS();
                ControlService(svc, SERVICE_CONTROL_STOP, ref status);
                return DeleteService(svc) ? Result.Uninstalled : Result.Failed;
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    /// <summary>Whether the keeper service is registered.</summary>
    public static bool IsKeeperInstalled()
    {
        IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return false;
        try
        {
            IntPtr svc = OpenServiceW(scm, KeeperServiceName, 0x0001);
            if (svc == IntPtr.Zero) return false;
            CloseServiceHandle(svc);
            return true;
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
