using System;
using System.Net.Http;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using NATTunnel;

namespace NATTunnelGUI;

public partial class App : Application
{
    private Task? meshTask;
    private bool engineInProcess;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Synchronous probe so Avalonia's lifecycle isn't waiting on an awaitable here —
            // returning early from this method leaves MainWindow unassigned and the app invisible.
            bool daemonAlreadyRunning = IsDaemonReachable();
            Console.Error.WriteLine($"[GUI] daemonAlreadyRunning={daemonAlreadyRunning}, IsLinux={OperatingSystem.IsLinux()}");

            if (!daemonAlreadyRunning)
            {
                if (OperatingSystem.IsLinux())
                {
                    Console.Error.WriteLine("[GUI] Daemon not running. Start it with: sudo systemctl start nattunnel");
                    Environment.Exit(1);
                    return;
                }

                if (!Config.CreateNewConfigPrompt())
                {
                    Console.Error.WriteLine("[GUI] Failed to create config file.");
                    Environment.Exit(1);
                    return;
                }
                if (!Config.TryLoadConfig())
                {
                    Console.Error.WriteLine("[GUI] Failed to load config.toml.");
                    Environment.Exit(1);
                    return;
                }

                engineInProcess = true;
                meshTask = Task.Run(() =>
                {
                    try { Program.RunMeshMode(); }
                    catch (Exception ex)
                    {
                        Dispatcher.UIThread.Post(() => Console.Error.WriteLine($"[GUI] Mesh engine error: {ex}"));
                    }
                });
            }

            desktop.MainWindow = new MainWindow();
            desktop.ShutdownRequested += OnShutdownRequested;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static bool IsDaemonReachable()
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(500) };
            using var resp = http.GetAsync("http://localhost:51889/status").GetAwaiter().GetResult();
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private async void OnShutdownRequested(object? sender, ShutdownRequestedEventArgs e)
    {
        if (!engineInProcess) return;

        Program.ShutdownRequested = true;
        if (meshTask != null)
            await Task.WhenAny(meshTask, Task.Delay(3000));
    }
}
