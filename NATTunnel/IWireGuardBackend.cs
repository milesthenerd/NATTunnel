namespace NATTunnel;

/// <summary>Platform abstraction for managing a WireGuard interface.</summary>
public interface IWireGuardBackend
{
    /// <summary>Create or open the WireGuard interface. Must be called first.</summary>
    void CreateInterface(string interfaceName);

    /// <summary>Apply [Interface] + [Peer] sections from the config file to the live interface.</summary>
    void ConfigureInterface(string interfaceName, string configFilePath);

    /// <summary>Assign an IPv4 address; existing IPv4 addresses on the interface are cleared first.</summary>
    void AssignIP(string interfaceName, string ipAddress, byte prefixLength);

    /// <summary>Bring the interface administratively up.</summary>
    void SetInterfaceUp(string interfaceName);

    /// <summary>Add or update a single peer without disturbing others. False = caller should fall back to <see cref="ApplyFullConfig"/>.</summary>
    bool AddOrUpdatePeer(string interfaceName, WireGuardPeer peer);

    /// <summary>Replace the live peer set with the one in the config file.</summary>
    void ApplyFullConfig(string interfaceName, string configFilePath);

    /// <summary>Enable IPv4 forwarding for symmetric-to-symmetric relay through this interface.</summary>
    bool EnableForwarding(string interfaceName);

    /// <summary>Tear down the interface and release backend-held resources.</summary>
    void DestroyInterface(string interfaceName);
}

/// <summary>Factory for the platform-appropriate <see cref="IWireGuardBackend"/>.</summary>
public static class WireGuardBackend
{
    private static IWireGuardBackend instance;
    private static readonly object initLock = new();

    public static IWireGuardBackend Instance
    {
        get
        {
            if (instance != null) return instance;
            lock (initLock)
            {
                if (instance != null) return instance;
                if (System.OperatingSystem.IsWindows())
                    instance = new WindowsWireGuardBackend();
                else if (System.OperatingSystem.IsLinux())
                    instance = new LinuxWireGuardBackend();
                else
                    throw new System.PlatformNotSupportedException(
                        "NATTunnel currently supports Windows and Linux only.");
                return instance;
            }
        }
    }
}
