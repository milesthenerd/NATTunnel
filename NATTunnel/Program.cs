using System;

namespace NATTunnel;

internal static class Program
{
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

        Tunnel.Start();

        Console.WriteLine("Press any key to quit");
        while (Console.In.Peek() != -1)
        {

        }
        Console.WriteLine("NATTunnel exited.");
    }
}