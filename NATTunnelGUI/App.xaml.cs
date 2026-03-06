using System;
using System.Threading.Tasks;
using System.Windows;
using NATTunnel;

namespace NATTunnelGUI;

public partial class App : Application
{
    private Task meshTask;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Load config
        if (!Config.CreateNewConfigPrompt())
        {
            MessageBox.Show("Failed to create config file.", "NATTunnel", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        if (!Config.TryLoadConfig())
        {
            MessageBox.Show("Failed to load config.toml. Please check your configuration.", "NATTunnel", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        // Start mesh engine on background thread
        meshTask = Task.Run(() =>
        {
            try
            {
                Program.RunMeshMode();
            }
            catch (Exception ex)
            {
                Dispatcher.BeginInvoke(() =>
                {
                    MessageBox.Show($"Mesh engine error: {ex.Message}", "NATTunnel", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }
        });
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        Program.ShutdownRequested = true;

        // Wait for graceful shutdown (MeshPeerLeave etc.)
        if (meshTask != null)
        {
            await Task.WhenAny(meshTask, Task.Delay(3000));
        }

        base.OnExit(e);
    }
}
