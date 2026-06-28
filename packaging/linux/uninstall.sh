#!/bin/sh
# Reverse of install.sh. Stops the service, removes binaries and symlinks.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must be run as root (try: sudo ./uninstall.sh)" >&2
    exit 1
fi

systemctl disable --now nattunnel.service 2>/dev/null || true
rm -f /etc/systemd/system/nattunnel.service
systemctl daemon-reload 2>/dev/null || true

rm -f /usr/bin/nattunneld /usr/bin/nattunnel-gui
rm -rf /usr/lib/nattunnel /usr/lib/nattunnel-gui
rm -f /usr/share/applications/nattunnel.desktop
update-desktop-database /usr/share/applications 2>/dev/null || true

echo "Done."
