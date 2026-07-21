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

        // Windows: elevated (WinDivert/RCVALL will work) OR Npcap present (unprivileged path).
        return WinDivertServiceInstaller.IsElevated() || NpcapCapture.IsNpcapPresent();
    }

    /// <summary>
    /// Windows composite: try WinDivert (bundled, needs elevation) → Npcap (user-installed, unprivileged) →
    /// raw socket + SIO_RCVALL (admin fallback), using the first that comes up available. Presents as a single
    /// <see cref="IIcmpCapture"/> so the transport doesn't branch.
    /// </summary>
    private sealed class WindowsCaptureChain : IIcmpCapture
    {
        private IIcmpCapture _active;

        public bool IsAvailable => _active?.IsAvailable ?? false;

        public void Start(System.Net.IPAddress peer, System.Net.IPAddress localSource, IcmpReceiveHandler onIcmp)
        {
            // 1) Npcap — the MOST ROBUST inbound path when installed. It captures at the NDIS filter layer (same
            //    as Wireshark/scapy), so it reliably delivers the peer's REAL inbound ICMP. Preferred over RCVALL
            //    because SIO_RCVALL has a box-specific directionality quirk: on some multi-adapter/polluted Win
            //    stacks RCVALL delivers only EGRESS (our own outbound looped back as type-0), never the peer's
            //    inbound — so the punch's data channel silently receives nothing real. Npcap has no such quirk.
            bool npcapPresent = NpcapCapture.IsNpcapPresent();
            if (npcapPresent)
            {
                // Retry briefly: right after boot/process start the Npcap service or the device's IPv4 address may
                // not be ready yet, so the first open can fail or pick the wrong NIC. A couple of short retries
                // makes the capture path deterministic instead of racing into the broken RCVALL fallback.
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    var np = new NpcapCapture();
                    np.Start(peer, localSource, onIcmp);
                    if (np.IsAvailable) { _active = np; NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, $"[ICMP] active capture = NpcapCapture (attempt {attempt + 1})"); return; }
                    np.Dispose();
                    if (attempt < 2) System.Threading.Thread.Sleep(300);
                }
                // Npcap installed but wouldn't start after retries. Fall through to RCVALL but WARN loudly: on
                // boxes where RCVALL captures egress-only, this silently half-breaks the tunnel (receives our own
                // outbound, never the peer). Ensure the Npcap service is running / restart usually fixes it.
                NATTunnel.Program.Log(NATTunnel.LogLevel.Warning, "[ICMP] Npcap is INSTALLED but failed to start capture " +
                    "after retries — falling back to SIO_RCVALL. If the tunnel connects one-way only, the Npcap service " +
                    "likely isn't running (start it / restart) — RCVALL is egress-only on some stacks.");
            }

            // 2) Raw socket + SIO_RCVALL — no-install fallback (needs admin, which the daemon/GUI have). Works on
            //    clean single-NIC boxes; may capture egress-only on quirky stacks (install Npcap there).
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

            // 3) WinDivert — bundled WFP driver, works when elevated. Last resort.
            var wd = new WinDivertCapture();
            wd.Start(peer, localSource, onIcmp);
            if (wd.IsAvailable) { _active = wd; NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, "[ICMP] active capture = WinDivertCapture"); return; }
            wd.Dispose();

            _active = null; // nothing came up
            NATTunnel.Program.Log(NATTunnel.LogLevel.Debug, "[ICMP] NO capture backend available");
        }

        public void Dispose() => _active?.Dispose();
    }
}
