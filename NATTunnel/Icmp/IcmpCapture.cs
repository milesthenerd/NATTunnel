using System;

namespace NATTunnel.Icmp;

/// <summary>
/// Selects the right <see cref="IIcmpCapture"/> backend for the current platform, in preference order.
///
///   • Windows:
///       1. <see cref="WinDivertCapture"/> — bundled WFP driver. Works when the process is ELEVATED (the
///          daemon self-elevates for WireGuard; the GUI is requireAdministrator). No user action, free to ship.
///          WinDivert's device is admin-only at the driver level, so this path needs elevation.
///       2. <see cref="NpcapCapture"/> — used only IF the user has Npcap installed (non-restricted). This is
///          the UNPRIVILEGED path for an embedded/non-elevated host. We don't bundle Npcap (its OEM redist
///          license is costly); the user provides it, which keeps us license-clean.
///       3. <see cref="RawSocketCapture"/> — SIO_RCVALL last resort (needs admin; mostly redundant with #1).
///   • Linux / other — <see cref="RawSocketCapture"/>: a raw ICMP socket with CAP_NET_RAW receives type-8
///     directly, no driver.
///
/// Each returned backend reports <see cref="IIcmpCapture.IsAvailable"/> after <c>Start</c>; the transport
/// checks it and falls through to the next connection tier when false.
/// </summary>
internal static class IcmpCapture
{
    /// <summary>
    /// Create the preferred capture backend for this platform. Does not open anything yet — the transport
    /// calls <see cref="IIcmpCapture.Start"/>.
    /// </summary>
    public static IIcmpCapture CreateDefault()
    {
        if (OperatingSystem.IsWindows())
            return new WindowsCaptureChain();

        // Linux, macOS (best-effort), etc. — raw socket path.
        return new RawSocketCapture();
    }

    /// <summary>
    /// True if SOME ICMP-capture backend is available on this machine right now — used for capability
    /// advertisement (the IcmpCapable flag) without committing to a specific peer. Cheap; may probe.
    /// </summary>
    public static bool AnyCaptureAvailable()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Linux/other: can we open a raw ICMP socket at all? (cap_net_raw / root)
            try
            {
                using var s = new System.Net.Sockets.Socket(
                    System.Net.Sockets.AddressFamily.InterNetwork,
                    System.Net.Sockets.SocketType.Raw,
                    System.Net.Sockets.ProtocolType.Icmp);
                return true;
            }
            catch { return false; }
        }

        bool elevated = WinDivertServiceInstaller.IsElevated();

        // Repair path for machines whose WinDivert service predates the keeper: the DACL is lost on every driver
        // load, and without the keeper nothing re-applies it. Skipped when the keeper is installed, since it
        // already handles this at boot.
        if (elevated
            && WinDivertServiceInstaller.IsInstalled()
            && !WinDivertServiceInstaller.IsKeeperInstalled()
            && !WinDivertServiceInstaller.IsDeviceUserAccessible())
        {
            WinDivertServiceInstaller.ApplyPermissiveDeviceDacl();
        }

        // In order of what actually grants capture:
        //  - elevated            → WinDivert loads on demand
        //  - Npcap installed     → unprivileged sniff path
        //  - WinDivert SERVICE   → unprivileged too, IF the device DACL is currently open to Users
        return elevated
            || NpcapCapture.IsNpcapPresent()
            || (WinDivertServiceInstaller.IsInstalled() && WinDivertServiceInstaller.IsDeviceUserAccessible());
    }

    /// <summary>
    /// Windows composite: try WinDivert (bundled, needs elevation) → Npcap (user-installed, unprivileged) →
    /// raw socket + SIO_RCVALL (admin fallback), using the first that comes up available. Presents as a single
    /// <see cref="IIcmpCapture"/> so the transport doesn't branch.
    /// </summary>
    private sealed class WindowsCaptureChain : IIcmpCapture
    {
        private IIcmpCapture _active;

        /// <summary>Test switch: force WinDivert before Npcap, to exercise it on a machine where Npcap would
        /// otherwise always win.</summary>
        private const bool PreferWinDivertForTesting = false;

        public bool IsAvailable => _active?.IsAvailable ?? false;

        public void Start(System.Net.IPAddress peer, System.Net.IPAddress localSource, IcmpReceiveHandler onIcmp)
        {
#pragma warning disable CS0162
            if (PreferWinDivertForTesting)
            {
                var wdFirst = new WinDivertCapture();
                wdFirst.Start(peer, localSource, onIcmp);
                if (wdFirst.IsAvailable)
                {
                    _active = wdFirst;
                    NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, "[ICMP] active capture = WinDivertCapture (PreferWinDivertForTesting is ON — not the shipping order)");
                    return;
                }
                wdFirst.Dispose();
                NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, "[ICMP] WinDivert did not come up (PreferWinDivertForTesting) — falling through to the normal chain");
            }
#pragma warning restore CS0162

            // 1) Npcap — most robust when installed: captures at the NDIS filter layer, so it reliably delivers
            //    the peer's real inbound ICMP (unlike RCVALL, which is egress-only on some multi-adapter stacks).
            bool npcapPresent = NpcapCapture.IsNpcapPresent();
            if (npcapPresent)
            {
                // Retry briefly: right after boot the Npcap service or the device's IPv4 may not be ready yet.
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    var np = new NpcapCapture();
                    np.Start(peer, localSource, onIcmp);
                    if (np.IsAvailable) { _active = np; NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP] active capture = NpcapCapture (attempt {attempt + 1})"); return; }
                    np.Dispose();
                    if (attempt < 2) System.Threading.Thread.Sleep(300);
                }
                // Npcap installed but wouldn't start — fall through to RCVALL, but warn: RCVALL can be
                // egress-only on some stacks, which silently half-breaks the tunnel.
                NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, "[ICMP] Npcap is INSTALLED but failed to start capture " +
                    "after retries — falling back to SIO_RCVALL. If the tunnel connects one-way only, the Npcap service " +
                    "likely isn't running (start it / restart) — RCVALL is egress-only on some stacks.");
            }

            // 2) WinDivert — bundled driver, no user install, deterministic (unlike RCVALL's egress-only quirk),
            //    and the only unprivileged option when the service is installed but Npcap isn't. Skipped when
            //    neither elevated nor service-installed, since the open would just fail.
            if (WinDivertServiceInstaller.IsElevated() || WinDivertServiceInstaller.IsInstalled())
            {
                var wd2 = new WinDivertCapture();
                wd2.Start(peer, localSource, onIcmp);
                if (wd2.IsAvailable) { _active = wd2; NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, "[ICMP] active capture = WinDivertCapture"); return; }
                wd2.Dispose();
            }

            // 3) Raw socket + SIO_RCVALL — no-install fallback (needs admin). Works on clean single-NIC boxes;
            //    may capture egress-only on quirky stacks (install Npcap there).
            var raw = new RawSocketCapture();
            raw.Start(peer, localSource, onIcmp);
            if (raw.IsAvailable)
            {
                _active = raw;
                NATTunnel.Program.Log(npcapPresent ? NATTunnel.LogLevel.Warning : NATTunnel.LogLevel.Debug,
                    $"[ICMP] active capture = RawSocketCapture (RCVALL){(npcapPresent ? " — Npcap present but unused, see warning above" : "")}");
                return;
            }
            raw.Dispose();

            _active = null; // nothing came up
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, "[ICMP] NO capture backend available");
        }

        public void Dispose() => _active?.Dispose();
    }
}
