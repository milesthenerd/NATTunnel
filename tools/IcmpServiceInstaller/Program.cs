using NATTunnel.Icmp;

// nattunnel-icmp-service — installs/removes the persistent WinDivert kernel-driver service that lets an
// UNPRIVILEGED embedded host use the ICMP transport. An integrator runs this ONCE from their installer.
//
//   nattunnel-icmp-service /install     register the WinDivert driver + the boot keeper service (idempotent)
//   nattunnel-icmp-service /uninstall   stop + remove both
//   nattunnel-icmp-service /status      report install + device-accessibility state (no admin needed)
//   nattunnel-icmp-service run-keeper   SCM entry point for the keeper service — not for interactive use
//
// The keeper exists because WinDivert re-creates its device admin-only on every driver load, so a DACL applied
// at install time does not survive a reboot. See KeeperService.
//
// The manifest requests admin, so a bare double-click self-elevates; an installer calling it from an
// already-elevated step gets no extra prompt. Exit code 0 = success, non-zero = failure (for installer checks).

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("This tool is Windows-only. On Linux, grant CAP_NET_RAW via setcap instead.");
    return 3;
}

string cmd = args.Length > 0 ? args[0].TrimStart('/', '-').ToLowerInvariant() : "status";

switch (cmd)
{
    case "run-keeper":
        // SCM entry point. Blocks until the service is stopped.
        System.ServiceProcess.ServiceBase.Run(new NATTunnel.IcmpServiceInstaller.KeeperService());
        return 0;

    case "install":
    {
        var r = WinDivertServiceInstaller.Install();
        Console.WriteLine(r switch
        {
            WinDivertServiceInstaller.Result.Installed        => "WinDivert driver service installed and started.",
            WinDivertServiceInstaller.Result.AlreadyInstalled => "WinDivert driver service was already installed.",
            WinDivertServiceInstaller.Result.NotAdministrator => "ERROR: must run elevated (Administrator) to install a kernel-driver service.",
            WinDivertServiceInstaller.Result.DriverFileMissing=> "ERROR: WinDivert64.sys not found next to this tool.",
            _                                                  => "ERROR: failed to install the WinDivert service."
        });
        if (r is not (WinDivertServiceInstaller.Result.Installed or WinDivertServiceInstaller.Result.AlreadyInstalled))
            return 1;

        // The keeper is what makes it survive a reboot — without it the DACL is gone on the next boot.
        string exe = Environment.ProcessPath ?? "";
        var k = WinDivertServiceInstaller.InstallKeeperService(exe);
        Console.WriteLine(k switch
        {
            WinDivertServiceInstaller.Result.Installed        => $"Keeper service '{WinDivertServiceInstaller.KeeperServiceName}' installed and started.\n" +
                                                                 "Unprivileged ICMP direct-connect is available and will survive reboots.\n" +
                                                                 "NOTE: while installed, any local user can capture and inject packets via WinDivert.",
            WinDivertServiceInstaller.Result.NotAdministrator => "ERROR: must run elevated to install the keeper service.",
            WinDivertServiceInstaller.Result.DriverFileMissing=> "ERROR: could not resolve this executable's path for the service registration.",
            _                                                  => "ERROR: failed to install the keeper service — the DACL will not survive a reboot."
        });
        return k is WinDivertServiceInstaller.Result.Installed ? 0 : 1;
    }
    case "uninstall":
    {
        // Keeper first — it holds a handle that keeps the driver loaded.
        var k = WinDivertServiceInstaller.UninstallKeeperService();
        if (k is WinDivertServiceInstaller.Result.Uninstalled)
            Console.WriteLine($"Keeper service '{WinDivertServiceInstaller.KeeperServiceName}' stopped and removed.");

        var r = WinDivertServiceInstaller.Uninstall();
        Console.WriteLine(r switch
        {
            WinDivertServiceInstaller.Result.Uninstalled      => "WinDivert service stopped and removed.",
            WinDivertServiceInstaller.Result.NotInstalled     => "WinDivert service was not installed. Nothing to do.",
            WinDivertServiceInstaller.Result.NotAdministrator => "ERROR: must run elevated (Administrator) to remove a kernel-driver service.",
            _                                                  => "ERROR: failed to remove the WinDivert service."
        });
        return r is WinDivertServiceInstaller.Result.Uninstalled or WinDivertServiceInstaller.Result.NotInstalled ? 0 : 1;
    }
    case "status":
    {
        // The service being installed is NOT sufficient on its own — the device DACL has to allow non-elevated
        // opens too. Report them separately so an installed but inaccessible device isn't mistaken for working.
        bool installed = WinDivertServiceInstaller.IsInstalled();
        if (!installed)
        {
            Console.WriteLine("WinDivert service: NOT installed — ICMP direct-connect needs this service, or an elevated host.");
            return 2;
        }
        bool accessible = WinDivertServiceInstaller.IsDeviceUserAccessible();
        bool keeper = WinDivertServiceInstaller.IsKeeperInstalled();
        Console.WriteLine($"WinDivert driver service: INSTALLED");
        Console.WriteLine($"Device accessible to Users: {(accessible ? "YES" : "NO")}");
        Console.WriteLine($"Keeper service ({WinDivertServiceInstaller.KeeperServiceName}): {(keeper ? "INSTALLED" : "NOT installed")}");
        if (accessible && keeper)
            Console.WriteLine("Unprivileged ICMP direct-connect is available and will survive reboots.");
        else if (accessible)
            Console.WriteLine("Unprivileged ICMP works now, but WILL BREAK ON REBOOT without the keeper — re-run '/install' elevated.");
        else
            Console.WriteLine("Unprivileged ICMP is NOT available — re-run '/install' elevated.");
        return accessible && keeper ? 0 : 2;
    }
    default:
        Console.WriteLine("usage: nattunnel-icmp-service /install | /uninstall | /status");
        return 3;
}
