using System;
using System.Threading;
using NATTunnel;

namespace NATTunnel.CLI;

/// <summary>Headless entry point; loads config and runs the mesh engine.</summary>
public static class CliProgram
{
    public static int Main(string[] args)
    {
        if (!Config.CreateNewConfigPrompt())
        {
            Console.Error.WriteLine("Failed to create config file.");
            return 1;
        }
        if (!Config.TryLoadConfig())
        {
            Console.Error.WriteLine("Failed to load config.toml. Check the file and try again.");
            return 1;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            NATTunnel.Program.Log("[CLI] Ctrl+C received — shutting down...");
            NATTunnel.Program.ShutdownRequested = true;
            e.Cancel = true;
        };

        // systemctl stop → SIGTERM → ProcessExit on Linux.
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            NATTunnel.Program.Log("[CLI] Process exit signal received — shutting down...");
            NATTunnel.Program.ShutdownRequested = true;
        };

        try
        {
            NATTunnel.Program.RunMeshMode();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[CLI] Fatal: {ex}");
            return 1;
        }
    }
}
