#!/bin/sh
# Build the framework-dependent Linux tarball distribution. Mirrors the Windows zip:
# just the binaries + DLLs + install script. User needs dotnet-runtime + wireguard-tools.
#
# Run from repo root or from packaging/linux/. Outputs nattunnel-version-linux-x64.tar.gz.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RID="${RID:-linux-x64}"
VERSION="${VERSION:-$(grep -oP '(?<=<Version>)[^<]+' "$REPO_ROOT/Directory.Build.props" | head -1)}"
VERSION="${VERSION:-1.0.0}"
STAGE="$REPO_ROOT/packaging/linux/stage/nattunnel_${VERSION}"
OUT="$REPO_ROOT/nattunnel_${VERSION}_${RID}.tar.gz"

echo "Building for $RID (version $VERSION)"

rm -rf "$STAGE"
mkdir -p "$STAGE"

dotnet publish "$REPO_ROOT/NATTunnelCLI" -p:PublishProfile=$RID
dotnet publish "$REPO_ROOT/NATTunnelGUI" -p:PublishProfile=$RID

cp "$REPO_ROOT/NATTunnelCLI/bin/Publish/$RID/"* "$STAGE/"
cp "$REPO_ROOT/NATTunnelGUI/bin/Publish/$RID/"* "$STAGE/"

cp "$SCRIPT_DIR/nattunnel.service" "$STAGE/"
cp "$SCRIPT_DIR/nattunnel.desktop" "$STAGE/"
cp "$SCRIPT_DIR/install.sh" "$STAGE/"
cp "$SCRIPT_DIR/uninstall.sh" "$STAGE/"

if [ -f "$REPO_ROOT/LICENCE" ]; then cp "$REPO_ROOT/LICENCE" "$STAGE/"; fi
if [ -f "$REPO_ROOT/README.md" ]; then cp "$REPO_ROOT/README.md" "$STAGE/"; fi

chmod +x "$STAGE/nattunneld" "$STAGE/nattunnel-gui" "$STAGE/install.sh" "$STAGE/uninstall.sh"

tar -czf "$OUT" -C "$(dirname "$STAGE")" "$(basename "$STAGE")"

echo "Wrote $OUT"
ls -lh "$OUT"
