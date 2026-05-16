#!/usr/bin/env bash
# Build a .deb package from the published Linux CLI artifact.
# Run on a Debian/Ubuntu machine with `dpkg-deb` available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$PACKAGING_DIR/../.." && pwd)"
PUBLISH_DIR="$REPO_DIR/NATTunnelCLI/bin/Release/net10.0/linux-x64/publish"
VERSION="${VERSION:-1.0.0}"
ARCH="amd64"
PKG_NAME="nattunnel_${VERSION}_${ARCH}"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: dpkg-deb not found. Install dpkg-dev: apt install dpkg-dev" >&2
    exit 1
fi

if [[ ! -d "$PUBLISH_DIR" ]]; then
    echo "ERROR: publish output missing at $PUBLISH_DIR" >&2
    echo "Run: dotnet publish NATTunnelCLI -r linux-x64 --self-contained -c Release" >&2
    exit 1
fi

echo "Staging files in $STAGING..."

# Filesystem layout inside the package
install -m 0755 -d "$STAGING/DEBIAN"
install -m 0755 -d "$STAGING/usr/lib/nattunnel"
install -m 0755 -d "$STAGING/lib/systemd/system"

# Binary payload
cp -r "$PUBLISH_DIR"/. "$STAGING/usr/lib/nattunnel/"
chmod 0755 "$STAGING/usr/lib/nattunnel/nattunneld"

# systemd unit
install -m 0644 "$PACKAGING_DIR/nattunnel.service" "$STAGING/lib/systemd/system/nattunnel.service"

# Control file with version substituted
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/control.in" > "$STAGING/DEBIAN/control"

# Maintainer scripts
install -m 0755 "$SCRIPT_DIR/postinst" "$STAGING/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/prerm" "$STAGING/DEBIAN/prerm"
install -m 0755 "$SCRIPT_DIR/postrm" "$STAGING/DEBIAN/postrm"

# Build the .deb
OUTPUT_DIR="$REPO_DIR/dist"
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/$PKG_NAME.deb"

echo "Building $OUTPUT_FILE..."
dpkg-deb --root-owner-group --build "$STAGING" "$OUTPUT_FILE"

echo ""
echo "Built: $OUTPUT_FILE"
echo "Install with: sudo apt install $OUTPUT_FILE"
