using System;
using System.IO;

namespace NATTunnel;

public static class Program
{
    public static void Main(string[] args)
    {
        try
        {
            // Check if running as WireGuard service
            // Per WireGuard spec: program /service <config_path> [server|client]
            if (args.Length >= 2 && args[0] == "/service")
            {
                string configPath = args[1];
                string mode = args.Length >= 3 ? args[2] : null; // Optional mode argument
                RunServiceMode(configPath, mode);
                return;
            }

            // Normal startup
            if (!Config.CreateNewConfigPrompt())
                Environment.Exit(-1);

            if (!Config.TryLoadConfig())
            {
                Console.WriteLine("Failed to load config.toml");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                Environment.Exit(-1);
            }

            // Start tunnel with WireGuard based on config
            string interfaceName = "NATTunnel";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";

            // Pass isRunningAsService = false so it will try to install the service
            using (var tunnel = new WireGuardTunnel(TunnelOptions.IsServer, interfaceName, debugMode, isRunningAsService: false))
            {
                Console.WriteLine("Tunnel is running...");

                // Keep the tunnel running indefinitely
                // The tunnel will be cleaned up by the using statement when the process exits (e.g., via Stop-Service)
                while (true)
                {
                    System.Threading.Thread.Sleep(1000);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nError occurred:");
            Console.WriteLine("=============");
            Console.WriteLine(ex.Message);
            if (ex.InnerException != null)
            {
                Console.WriteLine("\nInner Exception:");
                Console.WriteLine("===============");
                Console.WriteLine(ex.InnerException.Message);
            }
            Console.WriteLine("\nStack Trace:");
            Console.WriteLine("===========");
            Console.WriteLine(ex.StackTrace);
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// Runs the application in Windows service mode with the specified config path.
    /// This is called when Windows Service Manager starts the service with: program.exe /service "path\to\config.conf" [server|client]
    /// Per WireGuard spec, this should be minimal - just initialize and run the tunnel.
    /// </summary>
    private static void RunServiceMode(string configPath, string mode)
    {
        try
        {
            // Validate config path
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException($"Configuration file not found: {configPath}");
            }

            // Determine server/client mode
            bool isServer;
            if (!string.IsNullOrEmpty(mode))
            {
                // Use the mode passed as argument (most reliable)
                isServer = mode.Equals("server", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                // Fallback: read from config file if no mode argument provided
                string configContent = File.ReadAllText(configPath);
                isServer = configContent.Contains("mode") && configContent.Contains("\"server\"");
            }

            string interfaceName = "NATTunnel";
            bool debugMode = Environment.GetEnvironmentVariable("WIREGUARD_DEBUG") == "1";

            // Create tunnel with isRunningAsService = true to skip service installation
            using (var tunnel = new WireGuardTunnel(isServer, interfaceName, debugMode, isRunningAsService: true))
            {
                // Service mode: Keep running indefinitely until stopped by Windows Service Manager
                // The tunnel will be cleaned up by the using statement when the service stops
                while (true)
                {
                    System.Threading.Thread.Sleep(1000);
                }
            }
        }
        catch (Exception ex)
        {
            // Log service errors to a file since console output won't show in Service Manager
            try
            {
                string errorLog = Path.Combine(Path.GetTempPath(), "NATTunnel_service_error.log");
                File.AppendAllText(errorLog,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] Service error: {ex.Message}\n" +
                    $"Stack trace: {ex.StackTrace}\n\n");
            }
            catch { }

            // Re-throw to exit with error code
            throw;
        }
    }
}