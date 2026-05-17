# Linux Packaging

Build scripts for `.deb` (Debian/Ubuntu) and `.rpm` (Fedora/RHEL) packages bundling both the daemon (`nattunneld`) and the desktop GUI (`nattunnel-gui`).

## Layout

| Path | Purpose |
|---|---|
| [`nattunnel.service`](nattunnel.service) | systemd unit installed at `/lib/systemd/system/nattunnel.service` |
| [`deb/`](deb/) | `.deb` package metadata + build script |
| [`rpm/`](rpm/) | `.rpm` spec file + build script |

## Build prerequisites

On a build machine (Linux, with .NET 10 SDK):

```bash
dotnet publish NATTunnelCLI -r linux-x64 --no-self-contained -c Release -p:DebugType=None -p:DebugSymbols=false
dotnet publish NATTunnelGUI -r linux-x64 --no-self-contained -c Release -p:DebugType=None -p:DebugSymbols=false
```

The packagers consume both publish dirs and bundle them under `/usr/lib/nattunnel/` and `/usr/lib/nattunnel-gui/`. Framework-dependent publish keeps the package small, the `dotnet-runtime-10.0` package supplies the runtime.

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

Match this to the `<Version>` in [`Directory.Build.props`](../../Directory.Build.props).

## Filesystem layout (installed by either package)

```
/usr/bin/nattunneld              -> /usr/lib/nattunnel/nattunneld       (symlink)
/usr/bin/nattunnel-gui           -> /usr/lib/nattunnel-gui/nattunnel-gui (symlink)
/usr/lib/nattunnel/                                                     (daemon runtime)
/usr/lib/nattunnel-gui/                                                 (GUI runtime)
/usr/share/applications/nattunnel.desktop                               (app menu entry)
/lib/systemd/system/nattunnel.service                                   (systemd unit)
/etc/nattunnel/config.toml                                              (created on first run)
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
