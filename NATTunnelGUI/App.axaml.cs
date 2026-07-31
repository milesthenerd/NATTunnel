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
                        try { Program.Log(LogLevel.Error, $"[GUI] Mesh engine failed to start: {ex}"); } catch { }
                        try
                        {
                            string crashPath = System.IO.Path.Combine(
                                System.AppContext.BaseDirectory, "nattunnel-startup-error.log");
                            System.IO.File.AppendAllText(crashPath,
                                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Mesh engine failed to start:{Environment.NewLine}{ex}{Environment.NewLine}{Environment.NewLine}");
                        }
                        catch { /* last-resort diagnostic; never let it mask the original failure */ }
                        Console.Error.WriteLine($"[GUI] Mesh engine error: {ex}");
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
            if (!resp.IsSuccessStatusCode) return false;

            // A 200 is NOT enough. Port 51889 is hardcoded, so any unrelated local service answering there
            // used to be mistaken for our own engine: we'd skip starting the engine entirely and then poll
            // that stranger forever, presenting an empty log panel and "engine isn't responding". Require the
            // service marker from MeshState so we only ever adopt a real NATTunnel endpoint.
            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("service", out var svc) &&
                   svc.ValueKind == System.Text.Json.JsonValueKind.String &&
                   svc.GetString() == "nattunnel";
        }
        catch
        {
            // Includes malformed/non-JSON responses from whatever else holds the port — correctly "not ours".
            return false;
        }
    }

    private async void OnShutdownRequested(object? sender, ShutdownRequestedEventArgs e)
    {
        if (!engineInProcess) return;

        Program.ShutdownRequested = true;
        if (meshTask != null)
            await Task.WhenAny(meshTask, Task.Delay(3000));

        // LAST RESORT: guarantee the process actually dies. A wedged native thread (Npcap/WireGuard-NT driver
        // calls) can keep the process alive after the UI closes — it then still holds port 51889, so the next
        // launch finds the port taken and reports "the engine isn't responding". Worse, that zombie ignores
        // `taskkill /F`. A managed exit can't always dislodge a thread stuck in a driver, but Environment.Exit
        // skips finalizers/cleanup that would otherwise wait on it, which is exactly what we want here.
        // Fire-and-forget on a background timer so it can't interfere with a normal, prompt shutdown.
        _ = Task.Run(async () =>
        {
            await Task.Delay(4000);
            Environment.Exit(0);
        });
    }
}
