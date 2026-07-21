using NATTunnel.Icmp;

// nattunnel-icmp-service — installs/removes the persistent WinDivert kernel-driver service that lets an
// UNPRIVILEGED embedded host use the ICMP transport. An integrator runs this ONCE from their installer.
//
//   nattunnel-icmp-service /install     register + start the WinDivert service (idempotent)
//   nattunnel-icmp-service /uninstall   stop + remove the service
//   nattunnel-icmp-service /status      report whether it's installed (no admin needed)
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
    case "install":
    {
        var r = WinDivertServiceInstaller.Install();
        Console.WriteLine(r switch
        {
            WinDivertServiceInstaller.Result.Installed        => "WinDivert service installed and started. Unprivileged apps can now use ICMP direct-connect.",
            WinDivertServiceInstaller.Result.AlreadyInstalled => "WinDivert service was already installed. Nothing to do.",
            WinDivertServiceInstaller.Result.NotAdministrator => "ERROR: must run elevated (Administrator) to install a kernel-driver service.",
            WinDivertServiceInstaller.Result.DriverFileMissing=> "ERROR: WinDivert64.sys not found next to this tool.",
            _                                                  => "ERROR: failed to install the WinDivert service."
        });
        return r is WinDivertServiceInstaller.Result.Installed or WinDivertServiceInstaller.Result.AlreadyInstalled ? 0 : 1;
    }
    case "uninstall":
    {
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
        bool installed = WinDivertServiceInstaller.IsInstalled();
        Console.WriteLine(installed
            ? "WinDivert service: INSTALLED — unprivileged ICMP direct-connect is available."
            : "WinDivert service: NOT installed — ICMP direct-connect needs this service, or an elevated host.");
        return installed ? 0 : 2;
    }
    default:
        Console.WriteLine("usage: nattunnel-icmp-service /install | /uninstall | /status");
        return 3;
}
