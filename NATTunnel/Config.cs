using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Tomlyn;
using Tomlyn.Model;

namespace NATTunnel;

/// <summary>
/// Class to access configuration files.
/// </summary>
public static class Config
{
    #region Config Options

    /// <summary>
    /// Text string for "mediationEndpoint" in the config.
    /// </summary>
    private const string MediationEndpoint = "mediationEndpoint";

    /// <summary>
    /// Text string for "networkID" in the config (for mesh networking).
    /// </summary>
    private const string NetworkID = "networkID";

    /// <summary>
    /// Text string for "peerID" in the config (persistent mesh peer identity).
    /// </summary>
    private const string PeerID = "peerID";

    #endregion

    /// <summary>
    /// Tries to load the config file.
    /// </summary>
    /// <returns>Returns <see langword="true"/> if loading was successful, <see langword="false"/> if it wasn't.</returns>
    public static bool TryLoadConfig()
    {
        string configString = File.ReadAllText(GetConfigFilePath());

        TomlTable model = Toml.ToModel(configString);

        Console.WriteLine(Toml.FromModel(model));

        try
        {
            //If no port is specified, error out
            string endpointString = (string)model[MediationEndpoint];
            int colonIndex = endpointString.IndexOf(':');
            if (colonIndex <= 0)
            {
                Console.Error.WriteLine($"{MediationEndpoint} must have a port specified!");
                return false;
            }

            string ip = endpointString[..colonIndex];
            string port = endpointString[(colonIndex + 1)..];
            int portForMediationIP;

            if (!Int32.TryParse(port, out portForMediationIP))
            {
                Console.Error.WriteLine($"Invalid port for {MediationEndpoint}!");
                return false;
            }

            //Try to parse mediationEndpoint with DNS lookup
            TunnelOptions.MediationEndpoint = new IPEndPoint(GetIPFromDnsResolve(ip), portForMediationIP);
        }
        catch
        {
            //Throw error if parsing fails
            Console.Error.WriteLine($"Failed to parse the {MediationEndpoint}!");
            return false;
        }

        // Parse required networkID
        try
        {
            if (!model.ContainsKey(NetworkID) || string.IsNullOrEmpty((string)model[NetworkID]))
            {
                Console.Error.WriteLine($"{NetworkID} is required in config.toml!");
                return false;
            }
            TunnelOptions.NetworkID = (string)model[NetworkID];
            Console.WriteLine($"[Config] Mesh networking enabled for network: {TunnelOptions.NetworkID}");
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Failed to parse {NetworkID}: {e.Message}");
            return false;
        }

        // Parse optional peerID (persistent mesh identity)
        try
        {
            if (model.ContainsKey(PeerID))
            {
                string peerIDString = (string)model[PeerID];
                if (Guid.TryParse(peerIDString, out Guid parsedPeerID))
                {
                    TunnelOptions.PeerID = parsedPeerID;
                    Console.WriteLine($"[Config] Loaded persistent peer ID: {parsedPeerID}");
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"[Config] Warning: Failed to parse {PeerID}: {e.Message}");
        }

        return true;
    }

    /// <summary>
    /// Saves the peer ID to config.toml so it persists across restarts.
    /// Appends the peerID line if not present, or updates it if it already exists.
    /// </summary>
    public static void SavePeerID(Guid peerID)
    {
        string configPath = GetConfigFilePath();
        if (configPath == null || !File.Exists(configPath)) return;

        string[] lines = File.ReadAllLines(configPath);
        bool found = false;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].TrimStart().StartsWith(PeerID + " ") || lines[i].TrimStart().StartsWith(PeerID + "="))
            {
                lines[i] = $"{PeerID} = \"{peerID}\"";
                found = true;
                break;
            }
        }

        if (found)
        {
            File.WriteAllLines(configPath, lines);
        }
        else
        {
            File.AppendAllText(configPath, $"\n\n#{PeerID}: Persistent mesh peer identity (auto-generated, do not edit)\n{PeerID} = \"{peerID}\"\n");
        }
    }

    /// <summary>
    /// Helper method that resolves a DNS and returns the correct IPvX ip depending on what's supported.
    /// </summary>
    /// <param name="dns">The dns to resolve and get the ip from.</param>
    /// <returns>An IPv6 ip of IPv6 is supported, otherwise an IPv4 ip.</returns>
    private static IPAddress GetIPFromDnsResolve(string dns)
    {
        IPAddress[] ips = Dns.GetHostAddresses(dns);
        IPAddress ipToReturn = null;

        // If we support ipv6, return the first ipv6 ip (if it exists), otherwise return the first ipv4 ip.
        if (TunnelOptions.IsIPv6Supported)
            ipToReturn = ips.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetworkV6);

        ipToReturn ??= ips.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork);

        if (ipToReturn is null)
            throw new ArgumentException($"DNS {dns} could not be resolved to neither an IPv6 nor an IPv4 Address.");

        return ipToReturn;
    }

    /// <summary>
    /// Creates a new config file with mesh networking defaults.
    /// </summary>
    public static void CreateNewConfig()
    {
        String defaultConfigString = $@"#{MediationEndpoint}: The public IP and port of the matchmaking/holepunching server you want to connect to
{MediationEndpoint} = ""{TunnelOptions.MediationEndpoint}""

#{NetworkID}: The network identifier for mesh networking. Peers with the same networkID can discover and connect to each other.
{NetworkID} = """"";

        using StreamWriter sw = new StreamWriter(GetConfigFilePath());
        sw.WriteLine(defaultConfigString);
    }

    /// <summary>
    /// Prompts in the console to create a new config file.
    /// </summary>
    /// <param name="exitOnExistingConfig">Whether to exit if the config file already exists, instead of erroring.</param>
    /// <returns><see langword="true"/> if a config file was created or
    /// the file exists and <paramref name="exitOnExistingConfig"/> is <see langword="true"/>.
    /// <see langword="false"/> if the user quit out.</returns>
    public static bool CreateNewConfigPrompt(bool exitOnExistingConfig = true)
    {
        bool doesFileExist = File.Exists(GetConfigFilePath());
        if (doesFileExist && exitOnExistingConfig)
            return true;

        if (!doesFileExist)
            Console.WriteLine("Unable to find config.toml");
        Console.WriteLine("Creating default mesh networking config...");
        CreateNewConfig();
        Console.WriteLine("Config created. Please edit config.toml to set your networkID, then restart.");
        return true;
    }

    /// <summary>
    /// The file path to where the config.txt for NATTunnel is located, depending on the OS.
    /// </summary>
    /// <returns>The file path to where the config.txt is located for a known OS, <see langword="null"/> for an unknown OS.</returns>
    public static string GetConfigFilePath()
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
        {
            string natTunnelDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "/NATTunnel";
            Directory.CreateDirectory(natTunnelDir);
            return natTunnelDir + "/config.toml";
        }

        // Special case for macos, because the applicationData folder is currently bugged on macos+.net
        if (OperatingSystem.IsMacOS())
        {
            string natTunnelDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/Library/Application Support/NATTunnel";
            Directory.CreateDirectory(natTunnelDir);
            return natTunnelDir + "/config.toml";
        }

        return null;
    }
}
