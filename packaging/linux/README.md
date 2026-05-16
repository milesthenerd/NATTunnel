# Linux Packaging

Build scripts for `.deb` (Debian/Ubuntu) and `.rpm` (Fedora/RHEL) packages of `nattunneld`.

## Layout

| Path | Purpose |
|---|---|
| [`nattunnel.service`](nattunnel.service) | systemd unit installed at `/lib/systemd/system/nattunnel.service` |
| [`deb/`](deb/) | `.deb` package metadata + build script |
| [`rpm/`](rpm/) | `.rpm` spec file + build script |

## Build prerequisites

On a build machine (Linux, with .NET 10 SDK):

```bash
dotnet publish NATTunnelCLI -r linux-x64 --self-contained -c Release
```

This produces the self-contained binary at `NATTunnelCLI/bin/Release/net10.0/linux-x64/publish/`. Both package builds consume that directory.

## Build `.deb`

On Debian/Ubuntu (or any system with `dpkg-deb`):

```bash
sudo apt install dpkg-dev
bash packaging/linux/deb/build.sh
```

Output: `dist/nattunnel_<version>_amd64.deb`.

Install: `sudo apt install ./dist/nattunnel_<version>_amd64.deb`

## Build `.rpm`

On Fedora/RHEL (or any system with `rpmbuild`):

```bash
sudo dnf install rpm-build
bash packaging/linux/rpm/build.sh
```

Output: `dist/nattunnel-<version>-1.x86_64.rpm`.

Install: `sudo dnf install ./dist/nattunnel-<version>-1.x86_64.rpm`

## Versioning

Both build scripts pick up `VERSION` from the environment (default `1.0.0`). For releases:

```bash
VERSION=1.1.0 bash packaging/linux/deb/build.sh
VERSION=1.1.0 bash packaging/linux/rpm/build.sh
```

Match this to the `<Version>` in [`NATTunnelCLI.csproj`](../../NATTunnelCLI/NATTunnelCLI.csproj).

## Filesystem layout (installed by either package)

```
/usr/bin/nattunneld               -> /usr/lib/nattunnel/nattunneld   (symlink)
/usr/lib/nattunnel/                                                  (self-contained runtime)
/lib/systemd/system/nattunnel.service                                (systemd unit)
/etc/nattunnel/config.toml                                           (created on first run)
```

## Service lifecycle

After install, the service is **not started or enabled automatically**. Admin must edit `/etc/nattunnel/config.toml` (or let the daemon generate one on first run) before starting:

```bash
sudo systemctl start nattunnel                  # generates config on first run
sudo systemctl stop nattunnel                   # so you can edit it
sudo $EDITOR /etc/nattunnel/config.toml         # set networkID, mediation endpoint, etc.
sudo systemctl enable --now nattunnel           # enable + start
sudo journalctl -u nattunnel -f                 # follow logs
```

## Removal

```bash
sudo apt remove nattunnel        # keeps /etc/nattunnel
sudo apt purge nattunnel         # also drops /etc/nattunnel
```

Equivalent on Fedora:

```bash
sudo dnf remove nattunnel        # drops /etc/nattunnel on removal (no purge concept)
```
