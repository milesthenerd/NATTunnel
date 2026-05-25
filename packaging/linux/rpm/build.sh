#!/usr/bin/env bash
# Build a .rpm bundling the daemon (nattunneld) and the GUI (nattunnel-gui).
# Run on a Fedora/RHEL machine with `rpmbuild` available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$PACKAGING_DIR/../.." && pwd)"
CLI_PUBLISH="$REPO_DIR/NATTunnelCLI/bin/Release/net9.0/linux-x64/publish"
GUI_PUBLISH="$REPO_DIR/NATTunnelGUI/bin/Release/net9.0/linux-x64/publish"
VERSION="${VERSION:-$(grep -oP '(?<=<Version>)[^<]+' "$REPO_DIR/Directory.Build.props" | head -1)}"
VERSION="${VERSION:-1.0.0}"

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "ERROR: rpmbuild not found. Install rpm-build: dnf install rpm-build" >&2
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

# rpmbuild wants a specific directory layout under ~/rpmbuild by default. We override
# with --define so everything stays under a temp dir.
RPM_TOP="$(mktemp -d)"
trap 'rm -rf "$RPM_TOP"' EXIT
mkdir -p "$RPM_TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}

BUILDROOT="$RPM_TOP/BUILDROOT/nattunnel-$VERSION-1.x86_64"

echo "Staging files in $BUILDROOT..."
install -m 0755 -d "$BUILDROOT/usr/bin"
install -m 0755 -d "$BUILDROOT/usr/lib/nattunnel"
install -m 0755 -d "$BUILDROOT/usr/lib/nattunnel-gui"
install -m 0755 -d "$BUILDROOT/usr/share/applications"
install -m 0755 -d "$BUILDROOT/lib/systemd/system"

# Daemon
cp -r "$CLI_PUBLISH"/. "$BUILDROOT/usr/lib/nattunnel/"
chmod 0755 "$BUILDROOT/usr/lib/nattunnel/nattunneld"
ln -sf /usr/lib/nattunnel/nattunneld "$BUILDROOT/usr/bin/nattunneld"

# GUI
cp -r "$GUI_PUBLISH"/. "$BUILDROOT/usr/lib/nattunnel-gui/"
chmod 0755 "$BUILDROOT/usr/lib/nattunnel-gui/nattunnel-gui"
ln -sf /usr/lib/nattunnel-gui/nattunnel-gui "$BUILDROOT/usr/bin/nattunnel-gui"

# Desktop entry
install -m 0644 "$SCRIPT_DIR/../deb/nattunnel.desktop" "$BUILDROOT/usr/share/applications/nattunnel.desktop"

# systemd unit
install -m 0644 "$PACKAGING_DIR/nattunnel.service" "$BUILDROOT/lib/systemd/system/nattunnel.service"

# Generate the spec with version substituted
SPEC_FILE="$RPM_TOP/SPECS/nattunnel.spec"
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/nattunnel.spec.in" > "$SPEC_FILE"

echo "Running rpmbuild..."
rpmbuild \
    --define "_topdir $RPM_TOP" \
    --define "_buildrootdir $RPM_TOP/BUILDROOT" \
    --buildroot "$BUILDROOT" \
    -bb "$SPEC_FILE"

OUTPUT_DIR="$REPO_DIR/dist"
mkdir -p "$OUTPUT_DIR"
RPM_FILE=$(find "$RPM_TOP/RPMS" -name '*.rpm' | head -1)
cp "$RPM_FILE" "$OUTPUT_DIR/"

echo ""
echo "Built: $OUTPUT_DIR/$(basename "$RPM_FILE")"
echo "Install with: sudo dnf install $OUTPUT_DIR/$(basename "$RPM_FILE")"
