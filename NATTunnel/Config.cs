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
    /// Text string for "mode" in the config.
    /// </summary>
    private const string Mode = "mode";

    /// <summary>
    /// Text string for "client" in the config.
    /// </summary>
    private const string Client = "client";

    /// <summary>
    /// Text string for "server" in the config.
    /// </summary>
    private const string Server = "server";

    /// <summary>
    /// Text string for "mediationEndpoint" in the config.
    /// </summary>
    private const string MediationEndpoint = "mediationEndpoint";

    /// <summary>
    /// Text string for "remoteIP" in the config.
    /// </summary>
    private const string RemoteIp = "remoteIP";

    /// <summary>
    /// Text string for "usingWhitelist" in the config.
    /// </summary>
    private const string UsingWhitelist = "usingWhitelist";

    /// <summary>
    /// Text string for "whitelistedPorts" in the config.
    /// </summary>
    private const string WhitelistedPorts = "whitelistedPorts";

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
            //If mode is not valid, exit
            if (!(model[Mode].Equals(Server) || model[Mode].Equals(Client)))
            {
                Console.Error.WriteLine($"Unknown option '{model[Mode]}' for {Mode}!");
                return false;
            }
            //If valid, set IsServer
            TunnelOptions.IsServer = (string)model[Mode] == Server;
        }
        catch
        {
            Console.Error.WriteLine($"Something went wrong reading the {Mode} field!");
            return false;
        }

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

        // If the IP can't be resolved, error out
        try
        {
            TunnelOptions.RemoteIp = GetIPFromDnsResolve((string)model[RemoteIp]);
        }
        catch
        {
            Console.Error.WriteLine($"Could not resolve '{RemoteIp}' to an IP address!");
            return false;
        }

        try
        {
            //If usingWhitelist is not valid, exit
            TunnelOptions.UsingWhitelist = (bool)model[UsingWhitelist];
        }
        catch
        {
            Console.Error.WriteLine($"Something went wrong reading the {UsingWhitelist} field!");
            return false;
        }

        //Try to parse whitelist into TomlArray
        try
        {
            TunnelOptions.WhitelistedPorts = ((TomlArray)model[WhitelistedPorts]).Select(i => Convert.ToInt32(i)).ToList();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            Console.Error.WriteLine($"Failed to parse the {WhitelistedPorts} field! Make sure all entered values are numbers!");
            return false;
        }

        return true;
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
    /// Creates a new config file, filling it out with default values.
    /// </summary>
    public static void CreateNewConfig()
    {
        //Yes this looks weird but it's what works
        String defaultConfigString = $@"#{Mode}: Set to server if you want to allow others to connect to you, client if you want to connect to someone else
{Mode} = ""{(TunnelOptions.IsServer ? Server : Client)}""

#{MediationEndpoint}: The public IP and port of the matchmaking/holepunching server you want to connect to
{MediationEndpoint} = ""{TunnelOptions.MediationEndpoint}""

#{RemoteIp}: The public IP of the peer you want to connect to (unused for servers)
{RemoteIp} = ""{TunnelOptions.RemoteIp}""

#{UsingWhitelist}: Set true if you want to only expose a defined list of ports, false if you want to allow access to all ports
{UsingWhitelist} = true

#{WhitelistedPorts}: Array of whitelisted ports. If you want to define several, write it like an array such as [64198, 50000, 62415]
{WhitelistedPorts} = [{TunnelOptions.DefaultPort}]";

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
        Console.WriteLine("Creating a default:");
        Console.WriteLine("c) Create a client config file");
        Console.WriteLine("s) Create a server config file");
        Console.WriteLine("Any other key: Quit");
        ConsoleKeyInfo cki = Console.ReadKey();
        switch (cki.KeyChar)
        {
            case 'c':
                {
                    TunnelOptions.IsServer = false;
                    CreateNewConfig();
                    return true;
                }
            case 's':
                {
                    TunnelOptions.IsServer = true;
                    CreateNewConfig();
                    return true;
                }
            default:
                {
                    Console.WriteLine("Quitting...");
                    return false;
                }
        }
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