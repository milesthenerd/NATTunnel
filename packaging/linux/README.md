# Linux Packaging

NATTunnel ships on Linux as a single `.tar.gz` bundling both the daemon (`nattunneld`) and the desktop GUI (`nattunnel-gui`), installed by a script.

## Layout

| Path | Purpose |
|---|---|
| [`nattunnel.service`](nattunnel.service) | systemd unit (`Restart=always`, so the self-update's replace-and-exit relaunches cleanly) |
| [`build-tar.sh`](build-tar.sh) | publishes both projects + assembles the release tarball |
| [`install.sh`](install.sh) | installs the tarball's contents (copies binaries, symlinks onto PATH, installs + starts the service) |
| [`uninstall.sh`](uninstall.sh) | removes the install |

## Build the tarball

On a build machine (Linux, .NET 9 SDK):

```bash
sh packaging/linux/build-tar.sh
```

This runs `dotnet publish` for `NATTunnelCLI` + `NATTunnelGUI` via the `linux-x64` profile (which force-copies `libsodium.so` loose next to each exe — Noise.NET's native crypto), then tars the staged files. Output: `nattunnel_<version>_linux-x64.tar.gz` at the repo root. Version comes from `<Version>` in [`Directory.Build.props`](../../Directory.Build.props).

## Install

```bash
tar -xzf nattunnel_<version>_linux-x64.tar.gz
cd nattunnel_<version>
sudo ./install.sh
```

Unlike a `.deb`/`.rpm`, the tar can't auto-resolve dependencies — `install.sh` detects and reports what's missing. Prerequisites: the **.NET 9 runtime** and **wireguard-tools** (+ `iproute2`) for the daemon; the GUI also needs X11/font libs (`libx11-6 libice6 libsm6 libfontconfig1` on Debian/Ubuntu). Install those with your distro's package manager first.

## Filesystem layout (installed)

```
/usr/bin/nattunneld              -> /usr/lib/nattunnel/nattunneld        (symlink)
/usr/bin/nattunnel-gui           -> /usr/lib/nattunnel-gui/nattunnel-gui (symlink)
/usr/lib/nattunnel/                                                      (daemon runtime + libsodium.so)
/usr/lib/nattunnel-gui/                                                  (GUI runtime + libsodium.so)
/usr/share/applications/nattunnel.desktop                               (app menu entry)
/etc/systemd/system/nattunnel.service                                   (systemd unit)
/etc/nattunnel/config.toml                                              (created on first run)
```

## Removal

```bash
sudo ./uninstall.sh
```
