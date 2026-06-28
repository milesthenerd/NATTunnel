#!/bin/sh
# NATTunnel install script for the framework-dependent tar.gz distribution. Mirrors the deb
# package's behavior: copies binaries to /usr/lib, symlinks them onto PATH, installs the
# systemd unit, enables + starts the service.
#
# Must be run as root. Re-runnable (idempotent symlinks + systemctl).

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must be run as root (try: sudo ./install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Prereq checks. We don't install these for the user — they're distro-specific — but we tell
# them what's missing so the failure isn't silent at first run.
missing=""
if ! command -v dotnet >/dev/null 2>&1; then
    missing="$missing dotnet-runtime-9.0"
fi
if ! command -v wg >/dev/null 2>&1; then
    missing="$missing wireguard-tools"
fi
if [ -n "$missing" ]; then
    echo "Missing prerequisites:$missing"
    echo "Install with your distro's package manager"
    echo "Continuing the NATTunnel install — these must be installed before nattunneld will run."
fi

install -d /usr/lib/nattunnel
install -d /usr/lib/nattunnel-gui

if [ -f "$SCRIPT_DIR/nattunneld" ]; then
    install -m 0755 "$SCRIPT_DIR/nattunneld" /usr/lib/nattunnel/nattunneld
    # Copy any sidecar runtime files (.so, .pdb, .deps.json, .runtimeconfig.json).
    find "$SCRIPT_DIR" -maxdepth 1 -type f ! -name nattunneld ! -name nattunnel-gui \
        ! -name install.sh ! -name uninstall.sh ! -name nattunnel.service \
        ! -name nattunnel.desktop ! -name README* ! -name LICENSE* \
        -exec install -m 0644 {} /usr/lib/nattunnel/ \;
    ln -sf /usr/lib/nattunnel/nattunneld /usr/bin/nattunneld
    echo "Installed nattunneld → /usr/bin/nattunneld"
fi

if [ -f "$SCRIPT_DIR/nattunnel-gui" ]; then
    install -m 0755 "$SCRIPT_DIR/nattunnel-gui" /usr/lib/nattunnel-gui/nattunnel-gui
    find "$SCRIPT_DIR" -maxdepth 1 -type f ! -name nattunneld ! -name nattunnel-gui \
        ! -name install.sh ! -name uninstall.sh ! -name nattunnel.service \
        ! -name nattunnel.desktop ! -name README* ! -name LICENSE* \
        -exec install -m 0644 {} /usr/lib/nattunnel-gui/ \;
    ln -sf /usr/lib/nattunnel-gui/nattunnel-gui /usr/bin/nattunnel-gui
    echo "Installed nattunnel-gui → /usr/bin/nattunnel-gui"
fi

if [ -f "$SCRIPT_DIR/nattunnel.service" ]; then
    install -m 0644 "$SCRIPT_DIR/nattunnel.service" /etc/systemd/system/nattunnel.service
    systemctl daemon-reload
    systemctl enable --now nattunnel.service
    echo "Enabled and started nattunnel.service"
fi

if [ -f "$SCRIPT_DIR/nattunnel.desktop" ]; then
    install -m 0644 "$SCRIPT_DIR/nattunnel.desktop" /usr/share/applications/nattunnel.desktop
    update-desktop-database /usr/share/applications 2>/dev/null || true
    echo "Installed desktop entry"
fi

echo "Done. Check status with: systemctl status nattunnel"
