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

# Prereq checks. Unlike a .deb/.rpm (which auto-resolve dependencies), the tar can't install these —
# so we detect what's missing and tell the user. The daemon needs the .NET runtime + wireguard-tools;
# the GUI additionally needs a few X11/font shared libs. Package names vary by distro; we list the
# Debian/Ubuntu names as a guide.
missing=""
if ! command -v dotnet >/dev/null 2>&1; then
    missing="$missing dotnet-runtime-9.0(or-newer)"
fi
if ! command -v wg >/dev/null 2>&1; then
    missing="$missing wireguard-tools"
fi
if ! command -v ip >/dev/null 2>&1; then
    missing="$missing iproute2"
fi
if [ -n "$missing" ]; then
    echo "Missing prerequisites (install with your distro's package manager):$missing"
    echo "The GUI also needs X11/font libs: libx11-6 libice6 libsm6 libfontconfig1 (Debian/Ubuntu names)."
    echo "Continuing the NATTunnel install — the daemon prerequisites above must be present before nattunneld will run."
fi

install -d /usr/lib/nattunnel
install -d /usr/lib/nattunnel-gui

if [ -f "$SCRIPT_DIR/nattunneld" ]; then
    install -m 0755 "$SCRIPT_DIR/nattunneld" /usr/lib/nattunnel/nattunneld
    # libsodium.so is Noise.NET's native crypto lib and is REQUIRED — the daemon crashes at startup
    # ("Noise.Libsodium type initializer threw") without it. Copy it explicitly and verify, rather
    # than relying on a fragile find-with-exclusions that could silently skip it.
    if [ -f "$SCRIPT_DIR/libsodium.so" ]; then
        install -m 0644 "$SCRIPT_DIR/libsodium.so" /usr/lib/nattunnel/libsodium.so
    else
        echo "ERROR: libsodium.so missing from the package — the daemon will not run." >&2
        exit 1
    fi
    # Any other loose runtime sidecars (.so/.deps.json/.runtimeconfig.json) that may exist alongside.
    for f in "$SCRIPT_DIR"/*.deps.json "$SCRIPT_DIR"/*.runtimeconfig.json; do
        [ -f "$f" ] && install -m 0644 "$f" /usr/lib/nattunnel/
    done
    ln -sf /usr/lib/nattunnel/nattunneld /usr/bin/nattunneld
    echo "Installed nattunneld → /usr/bin/nattunneld"
fi

if [ -f "$SCRIPT_DIR/nattunnel-gui" ]; then
    install -m 0755 "$SCRIPT_DIR/nattunnel-gui" /usr/lib/nattunnel-gui/nattunnel-gui
    # Same libsodium.so requirement for the GUI (also uses Noise.NET crypto).
    if [ -f "$SCRIPT_DIR/libsodium.so" ]; then
        install -m 0644 "$SCRIPT_DIR/libsodium.so" /usr/lib/nattunnel-gui/libsodium.so
    else
        echo "ERROR: libsodium.so missing from the package — the GUI will not run." >&2
        exit 1
    fi
    for f in "$SCRIPT_DIR"/*.deps.json "$SCRIPT_DIR"/*.runtimeconfig.json; do
        [ -f "$f" ] && install -m 0644 "$f" /usr/lib/nattunnel-gui/
    done
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
