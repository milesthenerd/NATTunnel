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
    /// Text string for "networkSecret" in the config (shared secret for mesh authentication).
    /// </summary>
    private const string NetworkSecret = "networkSecret";

    /// <summary>
    /// Text string for "peerID" in the config (persistent mesh peer identity).
    /// </summary>
    private const string PeerID = "peerID";

    /// <summary>
    /// Text string for "heartbeatInterval" in the config (introducer heartbeat interval in seconds).
    /// </summary>
    private const string HeartbeatInterval = "heartbeatInterval";

    /// <summary>
    /// Text string for "probeInterval" in the config (introducer probe interval in seconds).
    /// </summary>
    private const string ProbeInterval = "probeInterval";

    /// <summary>
    /// Text string for "staleTimeout" in the config (pending connection stale timeout in seconds).
    /// </summary>
    private const string StaleTimeout = "staleTimeout";

    /// <summary>
    /// Text string for "repairCooldown" in the config (relay repair cooldown in seconds).
    /// </summary>
    private const string RepairCooldown = "repairCooldown";

    /// <summary>
    /// Text string for "deadThreshold" in the config (consecutive missed acks before declaring peer dead).
    /// </summary>
    private const string DeadThreshold = "deadThreshold";

    /// <summary>
    /// Text string for "gracePeriod" in the config (grace period before disconnect for non-symmetric NAT in seconds).
    /// </summary>
    private const string GracePeriodSeconds = "gracePeriod";

    /// <summary>
    /// Text string for "gracePeriodSymmetric" in the config (grace period before disconnect for symmetric NAT in seconds).
    /// </summary>
    private const string GracePeriodSecondsSymmetric = "gracePeriodSymmetric";

    /// <summary>
    /// Text string for "isolationGracePeriod" in the config (isolation grace period in seconds).
    /// </summary>
    private const string IsolationGracePeriod = "isolationGracePeriod";
    private const string MeshSubnet = "meshSubnet";
    private const string TlsEnabled = "tlsEnabled";
    private const string TlsAllowSelfSigned = "tlsAllowSelfSigned";

    #endregion

    /// <summary>
    /// Tries to load the config file.
    /// </summary>
    /// <returns>Returns <see langword="true"/> if loading was successful, <see langword="false"/> if it wasn't.</returns>
    public static bool TryLoadConfig()
    {
        string configString = File.ReadAllText(GetConfigFilePath());

        TomlTable model = Toml.ToModel(configString);

        // Log config without secrets
        var configLog = Toml.FromModel(model);
        if (model.ContainsKey("networkSecret"))
        {
            string secretValue = (string)model["networkSecret"];
            if (!string.IsNullOrEmpty(secretValue))
                configLog = configLog.Replace(secretValue, "********");
        }
        Program.Log(configLog);

        // Ensure config has all new timeout/interval fields with defaults if missing
        EnsureConfigFieldsExist();

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

        // Parse networkID — auto-generate and persist if missing/empty so a fresh
        // config doesn't block startup.
        try
        {
            string networkID = model.ContainsKey(NetworkID) ? (string)model[NetworkID] : null;
            if (string.IsNullOrEmpty(networkID))
            {
                networkID = GenerateNetworkID();
                SetConfigValue(NetworkID, $"\"{networkID}\"");
                Program.Log($"[Config] No {NetworkID} found — generated and saved: {networkID}");
            }
            TunnelOptions.NetworkID = networkID;
            Program.Log($"[Config] Mesh networking enabled for network: {TunnelOptions.NetworkID}");
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Failed to parse {NetworkID}: {e.Message}");
            return false;
        }

        // Parse networkSecret — auto-generate and persist if missing/empty.
        try
        {
            string networkSecret = model.ContainsKey(NetworkSecret) ? (string)model[NetworkSecret] : null;
            if (string.IsNullOrEmpty(networkSecret))
            {
                networkSecret = GenerateNetworkSecret();
                SetConfigValue(NetworkSecret, $"\"{networkSecret}\"");
                Program.Log($"[Config] No {NetworkSecret} found — generated and saved a random secret");
            }
            TunnelOptions.NetworkSecret = networkSecret;
            Program.Log($"[Config] Network secret loaded");
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Failed to parse {NetworkSecret}: {e.Message}");
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
                    Program.Log($"[Config] Loaded persistent peer ID: {parsedPeerID}");
                }
            }
        }
        catch (Exception e)
        {
            Program.Log($"[Config] Warning: Failed to parse {PeerID}: {e.Message}");
        }

        // Parse optional timeout and interval settings
        TryParseConfigInt(model, HeartbeatInterval, (val) => TunnelOptions.HeartbeatIntervalSeconds = val);
        TryParseConfigInt(model, ProbeInterval, (val) => TunnelOptions.ProbeIntervalSeconds = val);
        TryParseConfigInt(model, StaleTimeout, (val) => TunnelOptions.StaleTimeoutSeconds = val);
        TryParseConfigInt(model, RepairCooldown, (val) => TunnelOptions.RepairCooldownSeconds = val);
        TryParseConfigInt(model, DeadThreshold, (val) => TunnelOptions.DeadThreshold = val);
        TryParseConfigInt(model, GracePeriodSeconds, (val) => TunnelOptions.GracePeriodSecondsNonSymmetric = val);
        TryParseConfigInt(model, GracePeriodSecondsSymmetric, (val) => TunnelOptions.GracePeriodSecondsSymmetric = val);
        TryParseConfigInt(model, IsolationGracePeriod, (val) => TunnelOptions.IsolationGracePeriodSeconds = val);

        if (model.ContainsKey(MeshSubnet))
            TunnelOptions.MeshSubnet = (string)model[MeshSubnet];

        if (model.ContainsKey(TlsEnabled) && model[TlsEnabled] is bool tlsEnabled)
            TunnelOptions.TlsEnabled = tlsEnabled;

        if (model.ContainsKey(TlsAllowSelfSigned) && model[TlsAllowSelfSigned] is bool tlsAllowSelfSigned)
            TunnelOptions.TlsAllowSelfSigned = tlsAllowSelfSigned;

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
    /// Saves all current settings back to config.toml using line-level replacement.
    /// </summary>
    public static void SaveAllSettings(
        string mediationEndpoint,
        string networkID,
        string networkSecret,
        string meshSubnet,
        int heartbeatInterval,
        int probeInterval,
        int staleTimeout,
        int repairCooldown,
        int deadThreshold,
        int gracePeriod,
        int gracePeriodSymmetric,
        int isolationGracePeriod)
    {
        string configPath = GetConfigFilePath();
        if (configPath == null || !File.Exists(configPath)) return;

        string[] lines = File.ReadAllLines(configPath);

        SetConfigLine(ref lines, MediationEndpoint, $"\"{mediationEndpoint}\"");
        SetConfigLine(ref lines, NetworkID, $"\"{networkID}\"");
        SetConfigLine(ref lines, NetworkSecret, $"\"{networkSecret}\"");
        SetConfigLine(ref lines, MeshSubnet, $"\"{meshSubnet}\"");
        SetConfigLine(ref lines, HeartbeatInterval, heartbeatInterval.ToString());
        SetConfigLine(ref lines, ProbeInterval, probeInterval.ToString());
        SetConfigLine(ref lines, StaleTimeout, staleTimeout.ToString());
        SetConfigLine(ref lines, RepairCooldown, repairCooldown.ToString());
        SetConfigLine(ref lines, DeadThreshold, deadThreshold.ToString());
        SetConfigLine(ref lines, GracePeriodSeconds, gracePeriod.ToString());
        SetConfigLine(ref lines, GracePeriodSecondsSymmetric, gracePeriodSymmetric.ToString());
        SetConfigLine(ref lines, IsolationGracePeriod, isolationGracePeriod.ToString());

        File.WriteAllLines(configPath, lines);
    }

    private static void SetConfigLine(ref string[] lines, string key, string formattedValue)
    {
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].TrimStart().StartsWith(key + " ") || lines[i].TrimStart().StartsWith(key + "="))
            {
                lines[i] = $"{key} = {formattedValue}";
                return;
            }
        }
        // Not found — append
        Array.Resize(ref lines, lines.Length + 1);
        lines[^1] = $"{key} = {formattedValue}";
    }

    /// <summary>
    /// Sets a single config key in the on-disk config.toml, replacing the existing line
    /// if present or appending it otherwise.
    /// </summary>
    private static void SetConfigValue(string key, string formattedValue)
    {
        string configPath = GetConfigFilePath();
        if (configPath == null || !File.Exists(configPath)) return;

        string[] lines = File.ReadAllLines(configPath);
        SetConfigLine(ref lines, key, formattedValue);
        File.WriteAllLines(configPath, lines);
    }

    /// <summary>
    /// Generates a short, human-readable random network ID.
    /// </summary>
    private static string GenerateNetworkID()
    {
        // 8 hex chars from a cryptographically strong RNG — enough to be unique without being unwieldy.
        byte[] bytes = new byte[4];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return "net-" + Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Generates a strong random network secret (base64-encoded 32 bytes).
    /// </summary>
    private static string GenerateNetworkSecret()
    {
        byte[] bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
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
{NetworkID} = """"

#{NetworkSecret}: Shared secret for mesh network authentication. All peers and the mediation server must use the same secret.
{NetworkSecret} = """"

# Mesh networking timeouts and intervals (all in seconds unless noted)
# These control the timing behavior of the mesh network protocol.

# Introducer heartbeat interval: how often the introducer sends heartbeats to all peers to verify connectivity
{HeartbeatInterval} = {TunnelOptions.HeartbeatIntervalSeconds}

# Introducer probe interval: how often non-introducer peers probe the introducer's health
{ProbeInterval} = {TunnelOptions.ProbeIntervalSeconds}

# Stale connection timeout: how long to wait for a response to a connection request before removing it
{StaleTimeout} = {TunnelOptions.StaleTimeoutSeconds}

# Relay repair cooldown: minimum time between attempts to repair a broken relay route
{RepairCooldown} = {TunnelOptions.RepairCooldownSeconds}

# Dead peer threshold: number of consecutive missed heartbeat acks before declaring a peer dead
{DeadThreshold} = {TunnelOptions.DeadThreshold}

# Grace period (non-symmetric NAT): seconds to wait after initial setup before disconnecting from mediation
{GracePeriodSeconds} = {TunnelOptions.GracePeriodSecondsNonSymmetric}

# Grace period (symmetric NAT): seconds to wait after initial setup before disconnecting from mediation
{GracePeriodSecondsSymmetric} = {TunnelOptions.GracePeriodSecondsSymmetric}

# Isolation grace period: seconds to wait after detecting isolation before attempting to reconnect to mediation
{IsolationGracePeriod} = {TunnelOptions.IsolationGracePeriodSeconds}
";

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
            Program.Log("Unable to find config.toml");
        Program.Log("Creating default mesh networking config...");
        CreateNewConfig();
        Program.Log("Config created. Please edit config.toml to set your networkID, then restart.");
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

    /// <summary>
    /// Helper method to parse an optional integer config value with a callback to set the TunnelOptions field.
    /// </summary>
    private static void TryParseConfigInt(TomlTable model, string key, Action<int> setValue)
    {
        try
        {
            if (model.ContainsKey(key))
            {
                object value = model[key];
                if (value is long longValue)
                {
                    int intValue = (int)longValue;
                    setValue(intValue);
                    Program.Log($"[Config] Loaded {key}: {intValue}");
                }
                else if (value is int intValue2)
                {
                    setValue(intValue2);
                    Program.Log($"[Config] Loaded {key}: {intValue2}");
                }
            }
        }
        catch (Exception e)
        {
            Program.Log($"[Config] Warning: Failed to parse {key}: {e.Message}");
        }
    }

    /// <summary>
    /// Ensures that the config file contains all required timeout/interval fields.
    /// If any fields are missing, they are added with their default values.
    /// </summary>
    private static void EnsureConfigFieldsExist()
    {
        string configPath = GetConfigFilePath();
        if (configPath == null || !File.Exists(configPath))
            return;

        string[] lines = File.ReadAllLines(configPath);
        bool modified = false;

        // Check for networkSecret field
        bool secretExists = lines.Any(line => line.TrimStart().StartsWith(NetworkSecret + " ") || line.TrimStart().StartsWith(NetworkSecret + "="));
        if (!secretExists)
        {
            Array.Resize(ref lines, lines.Length + 2);
            lines[lines.Length - 2] = $"# Shared secret for mesh network authentication";
            lines[lines.Length - 1] = $"{NetworkSecret} = \"\"";
            modified = true;
        }

        // Check for each timeout/interval field and add if missing
        var fieldsToCheck = new[]
        {
            (key: HeartbeatInterval, value: TunnelOptions.HeartbeatIntervalSeconds, comment: "Introducer heartbeat interval (seconds)"),
            (key: ProbeInterval, value: TunnelOptions.ProbeIntervalSeconds, comment: "Introducer probe interval (seconds)"),
            (key: StaleTimeout, value: TunnelOptions.StaleTimeoutSeconds, comment: "Stale connection timeout (seconds)"),
            (key: RepairCooldown, value: TunnelOptions.RepairCooldownSeconds, comment: "Relay repair cooldown (seconds)"),
            (key: DeadThreshold, value: TunnelOptions.DeadThreshold, comment: "Dead peer threshold (missed heartbeats)"),
            (key: GracePeriodSeconds, value: TunnelOptions.GracePeriodSecondsNonSymmetric, comment: "Grace period for non-symmetric NAT (seconds)"),
            (key: GracePeriodSecondsSymmetric, value: TunnelOptions.GracePeriodSecondsSymmetric, comment: "Grace period for symmetric NAT (seconds)"),
            (key: IsolationGracePeriod, value: TunnelOptions.IsolationGracePeriodSeconds, comment: "Isolation grace period (seconds)")
        };

        foreach (var field in fieldsToCheck)
        {
            // Check if field already exists
            bool fieldExists = lines.Any(line => line.TrimStart().StartsWith(field.key + " ") || line.TrimStart().StartsWith(field.key + "="));
            if (!fieldExists)
            {
                // Add comment line and field with default value (two separate lines)
                Array.Resize(ref lines, lines.Length + 2);
                lines[lines.Length - 2] = $"# {field.comment}";
                lines[lines.Length - 1] = $"{field.key} = {field.value}";
                modified = true;
            }
        }

        if (modified)
        {
            File.WriteAllLines(configPath, lines);
            Program.Log("[Config] Added missing timeout/interval fields to config.toml with defaults");
        }
    }
}
