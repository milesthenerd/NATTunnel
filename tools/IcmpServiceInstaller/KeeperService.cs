using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using NATTunnel.Icmp;

namespace NATTunnel.IcmpServiceInstaller;

/// <summary>
/// Keeps unprivileged WinDivert access working across reboots.
///
/// WinDivert creates its device with an admin-only descriptor on every driver load and ignores the service's
/// registry `Security` value, so a DACL applied at install time is gone after a reboot. This service runs as
/// LocalSystem at boot and does two things:
///
///   1. Holds a WinDivert handle open for its whole lifetime, so the driver never unloads and the device object
///      (with our DACL) never goes away. Demand-start would otherwise unload it when the last handle closes.
///   2. Applies the Users DACL once the driver is up.
///
/// SECURITY: while this runs, any local user can capture and inject packets via WinDivert. That is the point —
/// it is what unprivileged embedded hosts need — but it is a real, permanent widening of the machine's attack
/// surface. Uninstall it when unprivileged ICMP is no longer wanted.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class KeeperService : ServiceBase
{
    private IntPtr _handle = WinDivertNativeShim.INVALID_HANDLE;

    public KeeperService() => ServiceName = WinDivertServiceInstaller.KeeperServiceName;

    protected override void OnStart(string[] args)
    {
        // A filter that matches nothing real: we only want the handle open to pin the driver, not to receive
        // traffic. "false" is a valid WinDivert filter and keeps the queue permanently empty.
        _handle = WinDivertNativeShim.WinDivertOpen("false", 0 /* NETWORK */, 0, WinDivertNativeShim.FLAG_SNIFF);

        if (_handle == WinDivertNativeShim.INVALID_HANDLE || _handle == IntPtr.Zero)
        {
            // Non-fatal: applying the DACL is still worth attempting, and the next boot retries.
            EventLogWrite($"could not pin the WinDivert driver (error {Marshal.GetLastWin32Error()}); " +
                          "the DACL may be lost when the driver next unloads");
        }

        if (WinDivertServiceInstaller.ApplyPermissiveDeviceDacl())
            EventLogWrite("WinDivert device opened to the Users group; unprivileged ICMP capture is available.");
        else
            EventLogWrite("failed to apply the WinDivert device DACL; unprivileged ICMP capture will not work.");
    }

    protected override void OnStop()
    {
        var h = _handle;
        _handle = WinDivertNativeShim.INVALID_HANDLE;
        if (h != WinDivertNativeShim.INVALID_HANDLE && h != IntPtr.Zero)
            try { WinDivertNativeShim.WinDivertClose(h); } catch { }
    }

    private void EventLogWrite(string message)
    {
        try { EventLog.WriteEntry($"[NATTunnel ICMP keeper] {message}"); } catch { }
    }
}

/// <summary>
/// Minimal WinDivert P/Invoke for the keeper. Separate from NATTunnel's internal bindings because this tool is
/// compiled standalone and only needs open/close.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WinDivertNativeShim
{
    public static readonly IntPtr INVALID_HANDLE = new(-1);
    public const ulong FLAG_SNIFF = 0x0001;

    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter, short layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);
}
