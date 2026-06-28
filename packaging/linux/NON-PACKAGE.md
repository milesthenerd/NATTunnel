Build commands for linux binary:

```bash
dotnet publish NATTunnelGUI -p:PublishProfile=linux-x64
dotnet publish NATTunnelCLI -p:PublishProfile=linux-x64
```

Stage into a single directory:

```bash
mkdir -p stage/nattunnel
cp NATTunnelCLI/bin/Publish/linux-x64/* stage/nattunnel/
cp NATTunnelGUI/bin/Publish/linux-x64/* stage/nattunnel/
cp packaging/linux/nattunnel.service stage/nattunnel/
cp packaging/linux/install.sh packaging/linux/uninstall.sh stage/nattunnel/
cp packaging/linux/deb/nattunnel.desktop stage/nattunnel/
chmod +x stage/nattunnel/install.sh stage/nattunnel/uninstall.sh
chmod +x stage/nattunnel/nattunneld stage/nattunnel/nattunnel-gui
```

Tar the dir:

```bash
tar -czf nattunnel-linux-x64.tar.gz -C stage nattunnel
```

To install:

```bash
tar xzf nattunnel-linux-x64.tar.gz
cd nattunnel
sudo ./install.sh
```