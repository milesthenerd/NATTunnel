#!/usr/bin/env bash
# Build a .deb bundling the daemon (nattunneld) and the GUI (nattunnel-gui).
# Run on a Debian/Ubuntu machine with `dpkg-deb` available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$PACKAGING_DIR/../.." && pwd)"
CLI_PUBLISH="$REPO_DIR/NATTunnelCLI/bin/Release/net9.0/linux-x64/publish"
GUI_PUBLISH="$REPO_DIR/NATTunnelGUI/bin/Release/net9.0/linux-x64/publish"
VERSION="${VERSION:-$(grep -oP '(?<=<Version>)[^<]+' "$REPO_DIR/Directory.Build.props" | head -1)}"
VERSION="${VERSION:-1.0.0}"
ARCH="amd64"
PKG_NAME="nattunnel_${VERSION}_${ARCH}"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: dpkg-deb not found. Install dpkg-dev: apt install dpkg-dev" >&2
    exit 1
fi

for dir in "$CLI_PUBLISH" "$GUI_PUBLISH"; do
    if [[ ! -d "$dir" ]]; then
        echo "ERROR: publish output missing at $dir" >&2
        echo "Run on a build host:" >&2
        echo "  dotnet publish NATTunnelCLI -r linux-x64 --no-self-contained -c Release -p:DebugType=None -p:DebugSymbols=false" >&2
        echo "  dotnet publish NATTunnelGUI -r linux-x64 --no-self-contained -c Release -p:DebugType=None -p:DebugSymbols=false" >&2
        exit 1
    fi
done

echo "Staging files in $STAGING..."

install -m 0755 -d "$STAGING/DEBIAN"
install -m 0755 -d "$STAGING/usr/lib/nattunnel"
install -m 0755 -d "$STAGING/usr/lib/nattunnel-gui"
install -m 0755 -d "$STAGING/usr/share/applications"
install -m 0755 -d "$STAGING/lib/systemd/system"

# Daemon
cp -r "$CLI_PUBLISH"/. "$STAGING/usr/lib/nattunnel/"
chmod 0755 "$STAGING/usr/lib/nattunnel/nattunneld"

# GUI
cp -r "$GUI_PUBLISH"/. "$STAGING/usr/lib/nattunnel-gui/"
chmod 0755 "$STAGING/usr/lib/nattunnel-gui/nattunnel-gui"

# Desktop entry
install -m 0644 "$SCRIPT_DIR/nattunnel.desktop" "$STAGING/usr/share/applications/nattunnel.desktop"

# systemd unit
install -m 0644 "$PACKAGING_DIR/nattunnel.service" "$STAGING/lib/systemd/system/nattunnel.service"

# Control file with version substituted
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/control.in" > "$STAGING/DEBIAN/control"

# Maintainer scripts
install -m 0755 "$SCRIPT_DIR/postinst" "$STAGING/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/prerm" "$STAGING/DEBIAN/prerm"
install -m 0755 "$SCRIPT_DIR/postrm" "$STAGING/DEBIAN/postrm"

OUTPUT_DIR="$REPO_DIR/dist"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/$PKG_NAME.deb"

echo "Building $OUTPUT_FILE..."
dpkg-deb --root-owner-group --build "$STAGING" "$OUTPUT_FILE"

echo ""
echo "Built: $OUTPUT_FILE"
echo "Install with: sudo apt install $OUTPUT_FILE"
