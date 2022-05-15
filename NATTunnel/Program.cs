using NATTunnel.Common;
using System;

namespace NATTunnel;

internal static class Program
{
    /// <summary>
    /// Indicates whether NATTunnel should be running.
    /// </summary>
    private static bool running = true;

    public static void Main()
    {
        //TODO: theres a weird bug where sometimes the server needs to be restarted for whatever reason

        // If the config file does not exist, and we couldn't create a config, exit cleanly.
        if (!Config.CreateNewConfigPrompt())
            Environment.Exit(-1);

        if (!Config.TryLoadConfig())
        {
            Console.WriteLine("Failed to load config.txt");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(-1);
        }

        TunnelNode tunnelNode = new TunnelNode();
        tunnelNode.Start();

        MediationClient.Start();

        Console.WriteLine("Press Q or CTRL+C to quit.");
        bool hasConsole = true;
        //TODO: close mediationClient when shutting down.
        Console.CancelKeyPress += (_, _) => { Shutdown(tunnelNode); };
        while (running)
        {
            if (!hasConsole)
                continue;

            try
            {
                ConsoleKeyInfo cki = Console.ReadKey();
                if (cki.KeyChar == 'q')
                {
                    Shutdown(tunnelNode);
                }
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("Program does not have a console, not listening for console input.");
                hasConsole = false;
            }
        }
    }

    private static void Shutdown(TunnelNode tunnelNode)
    {
        Console.WriteLine("Quitting...");
        running = false;
        tunnelNode.Stop();
    }
}