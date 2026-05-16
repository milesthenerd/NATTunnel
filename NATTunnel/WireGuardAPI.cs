using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Net;
using System.Net.NetworkInformation;

namespace NATTunnel;

/// <summary>
/// P/Invoke bindings for wintun.dll and wireguard.dll. Windows-only.
/// Based on Wintun reference: https://git.zx2c4.com/wintun/about/
/// </summary>
[SupportedOSPlatform("windows")]
public static class WireGuardAPI
{
    // Constants
    private const uint WGDEVICE_HAS_PRIVATE_KEY = 0x00000001;
    private const uint WGDEVICE_HAS_PUBLIC_KEY = 0x00000002;
    private const uint WGDEVICE_HAS_FLAGS = 0x00000004;
    private const uint WGDEVICE_HAS_LISTEN_PORT = 0x00000008;
    private const uint WGDEVICE_HAS_ERRNO = 0x00000010;
    private const uint WGDEVICE_REPLACE_PEERS = 0x00000020;

    private const uint WGPEER_HAS_PUBLIC_KEY = 0x00000001;
    private const uint WGPEER_HAS_PRESHARED_KEY = 0x00000002;
    private const uint WGPEER_HAS_ENDPOINT = 0x00000004;
    private const uint WGPEER_HAS_PERSISTENT_KEEPALIVE = 0x00000008;
    private const uint WGPEER_HAS_ALLOWEDIPS = 0x00000010;
    private const uint WGPEER_REPLACE_ALLOWEDIPS = 0x00000020;
    private const uint WGPEER_REMOVE = 0x00000040;

    // IPHLPAPI constants
    private const uint NL_DAD_STATE_TENTATIVE = 1;
    private const uint NL_DAD_STATE_DUPLICATE = 2;
    private const uint NL_DAD_STATE_DEPRECATED = 3;
    private const uint NL_DAD_STATE_PREFERRED = 4;

    // Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct WireGuardAllowedIP
    {
        public ushort Family;
        public byte Cidr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Address;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WireGuardPeer
    {
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PresharedKey;
        public uint AllowedIPsCount;
        public IntPtr AllowedIPs;
        public long RxBytes;
        public long TxBytes;
        public long LastHandshakeNano;
        public uint PersistentKeepaliveInterval;
        public IntPtr Next;
        public uint Endpoint_Family;
        public ushort Endpoint_Port;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Endpoint_Address;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WireGuardDevice
    {
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PrivateKey;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PublicKey;
        public uint ListenPort;
        public uint Errno;
        public IntPtr Peers;
        public uint PeersCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_IPINTERFACE_ROW
    {
        public byte Family;
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public uint MaxReassemblySize;
        public ulong InterfaceIdentifier;
        public ulong BaseReachableTime;
        public ulong RetransmitTime;
        public uint DadTransmits;
        public uint IgmpLevel;
        public uint AdvertisingEnabled;
        public uint ForwardingEnabled;
        public uint WeakHostSend;
        public uint WeakHostReceive;
        public uint UseNeighborUnreachabilityDetection;
        public uint ManagedAddressConfigurationSupported;
        public uint OtherStatefulConfigurationSupported;
        public uint AdvertiseDefaultRoute;
        public uint AdvertiseMobileIPv6PrefixFlag;
        public uint RouterDiscoveryBehavior;
        public uint DhcpV6ClientLuid;
        public uint ConnectionType;
        public uint NetworkGuid;
        public ulong ConnectionSpeed;
        public uint IpVersion;
        public uint Ipv6AddressEditingEnabled;
        public uint AdvancedDadTransmitCount;
        public uint NlMtu;
        public uint Ipv6Only;
        public uint AdvertiseRouterFlag;
        public uint NdIsRouter;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SOCKADDR_IN
    {
        public ushort sin_family;
        public ushort sin_port;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UNICASTIPADDRESS_ROW
    {
        public byte Address_Family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Address_Ipv4;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Address_Ipv6;
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public byte PrefixOrigin;
        public byte SuffixOrigin;
        public byte ValidLifetime;
        public byte PreferredLifetime;
        public byte OnLinkPrefixLength;
        public byte SkipAsSource;
        public byte DadState;
        public uint ScopeId;
        public long CreationTimeStamp;
    }

    // P/Invoke declarations for wireguard.dll
    [DllImport("wireguard.dll", EntryPoint = "WireGuardOpenAdapter", CallingConvention = CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr WireGuardOpenAdapter(string name);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardCloseAdapter", CallingConvention = CallingConvention.StdCall)]
    private static extern void WireGuardCloseAdapter(IntPtr adapter);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardSetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern bool WireGuardSetConfiguration(IntPtr adapter, ref WireGuardDevice config);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardGetConfiguration", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr WireGuardGetConfiguration(IntPtr adapter, ref uint len);

    [DllImport("wireguard.dll", EntryPoint = "WireGuardFreeConfiguration", CallingConvention = CallingConvention.StdCall)]
    private static extern void WireGuardFreeConfiguration(IntPtr config);

    // P/Invoke declarations for IPHLPAPI
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetUnicastIpAddressTable(byte family, out IntPtr table);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint CreateUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint DeleteUnicastIpAddressEntry(ref MIB_UNICASTIPADDRESS_ROW row);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern void FreeMibTable(IntPtr memory);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint ConvertInterfaceGuidToLuid(ref Guid InterfaceGuid, out ulong InterfaceLuid);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint ConvertInterfaceNameToLuidW(string interfaceName, out ulong interfaceLuid);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIfTable2(out IntPtr table);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_IF_ROW2
    {
        public ulong InterfaceLuid;
        public uint InterfaceIndex;
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Alias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Description;
        public uint PhysicalAddressLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PhysicalAddress;
        public uint Mtu;
        public uint Type;
        public uint OperStatus;
        public uint AdminStatus;
        public uint MediaConnectState;
        public Guid NetworkGuid;
        public uint ConnectionType;
        public uint TransmitLinkSpeed;
        public uint ReceiveLinkSpeed;
        public ulong InOctets;
        public ulong InUcastPkts;
        public ulong InNUcastPkts;
        public ulong InDiscards;
        public ulong InErrors;
        public ulong InUnknownProtos;
        public ulong InUcastOctets;
        public ulong InMulticastOctets;
        public ulong InBroadcastOctets;
        public ulong OutOctets;
        public ulong OutUcastPkts;
        public ulong OutNUcastPkts;
        public ulong OutDiscards;
        public ulong OutErrors;
        public ulong OutUcastOctets;
        public ulong OutMulticastOctets;
        public ulong OutBroadcastOctets;
        public ulong OutErrors2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_IF_TABLE2
    {
        public uint NumEntries;
        public IntPtr Table;
    }

    /// <summary>
    /// Creates a WireGuard adapter using Wintun
    /// </summary>
    public static IntPtr CreateAdapter(string interfaceName)
    {
        try
        {
            Program.Log($"Creating WireGuard-NT adapter: {interfaceName}");

            // Try to open existing WireGuard-NT adapter first
            IntPtr adapter = WireGuardNTAPI.WireGuardOpenAdapter(interfaceName);

            if (adapter != IntPtr.Zero)
            {
                Program.Log($"Opened existing WireGuard-NT adapter at: {adapter}");
                return adapter;
            }

            int error = Marshal.GetLastWin32Error();
            Program.Log($"WireGuard-NT adapter not found (Error: {error}), creating new adapter...");

            // Create a new WireGuard-NT adapter
            // Generate a deterministic GUID based on the interface name
            Guid guid = Guid.NewGuid();  // In production, use deterministic GUID
            adapter = WireGuardNTAPI.WireGuardCreateAdapter(interfaceName, "WireGuard", ref guid);

            if (adapter == IntPtr.Zero)
            {
                error = Marshal.GetLastWin32Error();
                throw new Exception($"Failed to create WireGuard-NT adapter '{interfaceName}' (Error: {error}). " +
                    $"Make sure wireguard.dll is installed alongside the application.");
            }

            Program.Log($"Created WireGuard-NT adapter at: {adapter}");

            // Check driver version
            uint version = WireGuardNTAPI.WireGuardGetRunningDriverVersion();
            if (version > 0)
            {
                Program.Log($"WireGuard-NT driver version: {version}");
            }

            return adapter;
        }
        catch (Exception ex)
        {
            Program.Log($"Error in CreateAdapter: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Configures the WireGuard interface with private key and listen port
    /// Note: With Wintun, we primarily use WireGuard tools for configuration.
    /// This method attempts configuration but continues even if it fails.
    /// </summary>
    public static void ConfigureAdapter(IntPtr adapter, byte[] privateKey, ushort listenPort)
    {
        try
        {
            Program.Log($"Configuring Wintun adapter with listen port: {listenPort}");

            // Try to configure using WireGuard API
            // Note: This may fail with Wintun adapters as they're managed differently
            var device = new WireGuardDevice
            {
                Flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
                PrivateKey = new byte[32],
                ListenPort = listenPort,
                Peers = IntPtr.Zero,
                PeersCount = 0
            };

            // Copy private key
            if (privateKey.Length != 32)
                throw new ArgumentException("Private key must be exactly 32 bytes");

            Array.Copy(privateKey, device.PrivateKey, 32);

            // Try to configure via WireGuard API (may not work with Wintun)
            if (WireGuardSetConfiguration(adapter, ref device))
            {
                Program.Log("Adapter configured via WireGuard API successfully");
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                Program.Log($"WireGuard configuration failed (Error: {error}). This is expected for Wintun adapters.");
                Program.Log("Configuration will be handled via WireGuard config file instead.");
            }
        }
        catch (Exception ex)
        {
            Program.Log($"Configuration error (non-fatal): {ex.Message}");
            // Don't throw - configuration can be handled other ways
        }
    }

    /// <summary>
    /// Converts CIDR prefix length to subnet mask
    /// </summary>
    private static string GetSubnetMask(byte prefixLength)
    {
        // Convert CIDR prefix to subnet mask
        // e.g., /24 = 255.255.255.0
        uint mask = prefixLength == 0 ? 0 : ~(uint.MaxValue >> prefixLength);
        return $"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}";
    }

    /// <summary>
    /// Calculates the network address from an IP and prefix length
    /// </summary>
    private static string GetNetworkAddress(string ipAddress, byte prefixLength)
    {
        try
        {
            var addr = System.Net.IPAddress.Parse(ipAddress);
            var bytes = addr.GetAddressBytes();

            // bytes are already in big-endian (network order)
            // Calculate network address by zeroing out host bits
            int byteIndex = prefixLength / 8;
            int bitIndex = prefixLength % 8;

            // Copy bytes up to the boundary
            var networkBytes = new byte[4];
            Array.Copy(bytes, networkBytes, byteIndex);

            // If there are remaining bits in the next byte, mask them
            if (byteIndex < 4)
            {
                byte mask = (byte)(0xFF << (8 - bitIndex));
                networkBytes[byteIndex] = (byte)(bytes[byteIndex] & mask);
            }

            // Convert back to IP address string
            var networkAddr = new System.Net.IPAddress(networkBytes);
            return networkAddr.ToString();
        }
        catch
        {
            return ipAddress;
        }
    }

    /// <summary>
    /// Adds a subnet route for the interface to make it active
    /// </summary>
    private static void AddSubnetRoute(string interfaceName, string ipAddress, byte prefixLength)
    {
        try
        {
            var networkAddr = GetNetworkAddress(ipAddress, prefixLength);
            var subnetMask = GetSubnetMask(prefixLength);

            Program.Log($"Adding route: {networkAddr} mask {subnetMask} via interface {interfaceName}...");

            // Try to get the interface index for the route command
            string interfaceSpec = $"IF \"{interfaceName}\"";

            try
            {
                // Get the interface index
                var getIndexPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"(Get-NetAdapter -Name '{interfaceName}').ifIndex\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var getIndexProc = System.Diagnostics.Process.Start(getIndexPsi))
                {
                    var indexOutput = getIndexProc.StandardOutput.ReadToEnd().Trim();
                    getIndexProc.WaitForExit();

                    if (!string.IsNullOrEmpty(indexOutput) && int.TryParse(indexOutput, out int ifIndex))
                    {
                        interfaceSpec = $"IF {ifIndex}";
                        Program.Log($"Using interface index: {ifIndex}");
                    }
                }
            }
            catch
            {
                // Fall back to interface name
            }

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "route",
                Arguments = $"add {networkAddr} mask {subnetMask} {ipAddress} {interfaceSpec}",
                UseShellExecute = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                CreateNoWindow = true,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
            };

            using (var proc = System.Diagnostics.Process.Start(psi))
            {
                proc.WaitForExit(5000);
                if (proc.ExitCode == 0)
                {
                    Program.Log($"Successfully added route");
                    // Give system time to process route and transition address state
                    System.Threading.Thread.Sleep(3000);
                }
                else
                {
                    Program.Log($"Route addition returned code: {proc.ExitCode}");
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log($"Failed to add route: {ex.Message}");
        }
    }

    /// <summary>
    /// Attempts to assign IP address via IPHLPAPI (most reliable for Wintun TUN devices)
    /// </summary>
    private static bool AssignIPViaIPHLPAPI(IntPtr adapter, string interfaceName, string ipAddress, byte prefixLength)
    {
        try
        {
            Program.Log("Attempting to extract interface LUID...");

            ulong interfaceLuid = 0;

            // Try to get LUID directly from WireGuard adapter
            try
            {
                WireGuardNTAPI.WireGuardGetAdapterLUID(adapter, out interfaceLuid);
                if (interfaceLuid != 0)
                {
                    Program.Log($"Got LUID from WireGuard adapter: {interfaceLuid}");
                }
                else
                {
                    Program.Log("WireGuardGetAdapterLUID returned 0, trying NetworkInterface enumeration...");

                    // Fallback: Try to find the interface by name through NetworkInterface
                    var ni = NetworkInterface.GetAllNetworkInterfaces()
                        .FirstOrDefault(x => x.Name == interfaceName);

                    if (ni != null)
                    {
                        // Try to extract LUID via reflection from NetworkInterface
                        var niType = ni.GetType();
                        var luidField = niType.GetProperty("Luid",
                            System.Reflection.BindingFlags.Instance |
                            System.Reflection.BindingFlags.NonPublic |
                            System.Reflection.BindingFlags.IgnoreCase);

                        if (luidField != null)
                        {
                            var luidObj = luidField.GetValue(ni);
                            if (luidObj is ulong luidValue && luidValue != 0)
                            {
                                interfaceLuid = luidValue;
                                Program.Log($"Extracted LUID via reflection: {interfaceLuid}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Program.Log($"Failed to get LUID from WireGuard adapter: {ex.Message}");
            }

            if (interfaceLuid == 0)
            {
                Program.Log("Could not obtain interface LUID");
                return false;
            }

            // Now add the IP address using IPHLPAPI
            Program.Log("Adding IP address via CreateUnicastIpAddressEntry...");

            // First, try to delete any existing IP addresses on this interface
            Program.Log("Cleaning up any existing IP addresses on the interface...");
            try
            {
                DeleteExistingIPAddresses(interfaceLuid);
            }
            catch (Exception ex)
            {
                Program.Log($"Warning: Failed to clean up existing IPs: {ex.Message}");
                // Continue anyway - the new IP assignment might overwrite
            }

            var row = new MIB_UNICASTIPADDRESS_ROW();
            row.Address_Family = 2; // AF_INET for IPv4
            row.InterfaceLuid = interfaceLuid;
            row.OnLinkPrefixLength = prefixLength;

            // Parse the IP address and store it in the IPv4 field
            var ipParts = ipAddress.Split('/')[0].Split('.');
            if (ipParts.Length == 4)
            {
                row.Address_Ipv4 = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    if (byte.TryParse(ipParts[i], out byte part))
                    {
                        row.Address_Ipv4[i] = part;
                    }
                }
            }

            uint result = CreateUnicastIpAddressEntry(ref row);

            if (result == 0)
            {
                Program.Log("Successfully created IP address entry via IPHLPAPI");
                return true;
            }
            else
            {
                Program.Log($"CreateUnicastIpAddressEntry failed with error: {result}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Program.Log($"IPHLPAPI IP assignment exception: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Deletes all existing IPv4 addresses from the specified interface
    /// </summary>
    private static void DeleteExistingIPAddresses(ulong interfaceLuid)
    {
        try
        {
            IntPtr table = IntPtr.Zero;
            uint result = GetUnicastIpAddressTable(2, out table); // 2 = AF_INET (IPv4)

            if (result != 0)
            {
                Program.Log($"GetUnicastIpAddressTable failed with error: {result}");
                return;
            }

            try
            {
                // Read the table
                var tableStruct = Marshal.PtrToStructure<MIB_UNICASTIPADDRESS_TABLE>(table);
                int rowSize = Marshal.SizeOf<MIB_UNICASTIPADDRESS_ROW>();

                for (int i = 0; i < tableStruct.NumEntries; i++)
                {
                    IntPtr rowPtr = IntPtr.Add(table, 4 + (i * rowSize)); // 4 bytes for NumEntries
                    var row = Marshal.PtrToStructure<MIB_UNICASTIPADDRESS_ROW>(rowPtr);

                    // Check if this row belongs to our interface
                    if (row.InterfaceLuid == interfaceLuid && row.Address_Family == 2)
                    {
                        // Delete this address
                        var deleteRow = row; // Copy the row
                        uint deleteResult = DeleteUnicastIpAddressEntry(ref deleteRow);

                        if (deleteResult == 0)
                        {
                            var ipAddr = $"{row.Address_Ipv4[0]}.{row.Address_Ipv4[1]}.{row.Address_Ipv4[2]}.{row.Address_Ipv4[3]}";
                            Program.Log($"Deleted existing IP: {ipAddr}");
                        }
                        else
                        {
                            Program.Log($"Failed to delete IP, error: {deleteResult}");
                        }
                    }
                }
            }
            finally
            {
                if (table != IntPtr.Zero)
                {
                    FreeMibTable(table);
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log($"Exception while deleting existing IPs: {ex.Message}");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UNICASTIPADDRESS_TABLE
    {
        public uint NumEntries;
        // Followed by NumEntries of MIB_UNICASTIPADDRESS_ROW
    }

    /// <summary>
    /// Assigns an IP address to the WireGuard/Wintun interface
    /// </summary>
    public static void AssignIPAddress(IntPtr adapter, string interfaceName, string ipAddress, byte prefixLength)
    {
        try
        {
            Program.Log($"Assigning IP address {ipAddress}/{prefixLength} to interface {interfaceName}");

            // Wait a moment for the interface to be fully registered in the system
            System.Threading.Thread.Sleep(3000);

            // For Wintun TUN interfaces, try IPHLPAPI first (most reliable for TUN devices)
            Program.Log("Attempting IPHLPAPI-based IP assignment (primary method for Wintun TUN)...");

            if (AssignIPViaIPHLPAPI(adapter, interfaceName, ipAddress, prefixLength))
            {
                Program.Log($"Successfully assigned IP {ipAddress}/{prefixLength} via IPHLPAPI");
                System.Threading.Thread.Sleep(2000);  // Give system time to stabilize

                // Now add a route to ensure the interface is active
                var ipAddr = ipAddress.Split('/')[0];
                Program.Log($"Adding route for subnet {GetNetworkAddress(ipAddr, prefixLength)}/{prefixLength}...");
                AddSubnetRoute(interfaceName, ipAddr, prefixLength);

                return;
            }
            else
            {
                Program.Log("IPHLPAPI IP assignment failed, trying fallback methods...");
            }

            // Fallback: Try PowerShell
            try
            {
                Program.Log($"Configuring IP via PowerShell (fallback)...");

                var ipAddr = ipAddress.Split('/')[0];
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"" +
                        $"New-NetIPAddress -InterfaceAlias '{interfaceName}' -IPAddress '{ipAddr}' -PrefixLength {prefixLength} -ErrorAction Stop | Out-Null; " +
                        $"Write-Host 'Success'\"",
                    UseShellExecute = true,  // Important: inherit admin context
                    RedirectStandardOutput = false,
                    RedirectStandardError = false,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.WaitForExit(10000);
                    Program.Log($"PowerShell exit code: {proc.ExitCode}");

                    if (proc.ExitCode == 0)
                    {
                        Program.Log($"Successfully assigned IP {ipAddress}/{prefixLength} via PowerShell");
                        System.Threading.Thread.Sleep(2000);  // Give system time to stabilize

                        // Now add a route to ensure the interface is active
                        Program.Log($"Adding route for subnet {GetNetworkAddress(ipAddress.Split('/')[0], prefixLength)}/{prefixLength}...");
                        AddSubnetRoute(interfaceName, ipAddress.Split('/')[0], prefixLength);

                        return;
                    }
                    else
                    {
                        Program.Log($"PowerShell IP assignment failed with exit code {proc.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                Program.Log($"PowerShell approach failed: {ex.Message}");
            }

            // Fallback: Try netsh if PowerShell fails
            try
            {
                Program.Log($"Configuring IP via netsh (fallback)...");

                var ipAddr = ipAddress.Split('/')[0];
                var subnetMask = GetSubnetMask(prefixLength);

                // First, remove all existing addresses from the interface
                Program.Log($"Removing existing addresses from interface {interfaceName}...");
                var deleteAllPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"interface ipv4 delete address \"{interfaceName}\" all",
                    UseShellExecute = true,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                using (var deleteProc = System.Diagnostics.Process.Start(deleteAllPsi))
                {
                    deleteProc.WaitForExit(5000);
                    Program.Log($"netsh delete exit code: {deleteProc.ExitCode}");
                }

                System.Threading.Thread.Sleep(500);  // Brief wait after deletion

                // Now add the new address
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"interface ipv4 add address name=\"{interfaceName}\" addr={ipAddr} mask={subnetMask}",
                    UseShellExecute = true,  // Important: inherit admin context
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    Program.Log($"netsh exit code: {proc.ExitCode}");

                    if (proc.ExitCode == 0 || proc.ExitCode == 5010)  // 5010 = address already exists
                    {
                        Program.Log($"Successfully assigned IP {ipAddress}/{prefixLength} via netsh");
                        System.Threading.Thread.Sleep(2000);  // Give system time to stabilize

                        // Now add a route to ensure the interface is active
                        Program.Log($"Adding route for subnet {GetNetworkAddress(ipAddr, prefixLength)}/{prefixLength}...");
                        AddSubnetRoute(interfaceName, ipAddr, prefixLength);

                        return;
                    }
                    else
                    {
                        Program.Log($"netsh IP assignment returned code: {proc.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                Program.Log($"netsh approach failed: {ex.Message}");
            }

            // Fallback to netsh if PowerShell fails
            try
            {
                Program.Log($"Configuring IP via netsh (fallback)...");

                var ipAddr = ipAddress.Split('/')[0];
                var subnetMask = GetSubnetMask(prefixLength);

                // First, remove all existing addresses from the interface
                Program.Log($"Removing existing addresses from interface {interfaceName}...");
                var deleteAllPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"interface ipv4 delete address name=\"{interfaceName}\" all",
                    UseShellExecute = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                using (var deleteProc = System.Diagnostics.Process.Start(deleteAllPsi))
                {
                    deleteProc.WaitForExit(5000);
                    Program.Log($"netsh delete exit code: {deleteProc.ExitCode}");
                }

                System.Threading.Thread.Sleep(500);  // Brief wait after deletion

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"interface ipv4 add address name=\"{interfaceName}\" addr={ipAddr} mask={subnetMask}",
                    UseShellExecute = true,  // Important: inherit admin context
                    RedirectStandardOutput = false,
                    RedirectStandardError = false,
                    CreateNoWindow = true,
                    WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
                };

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    Program.Log($"netsh exit code: {proc.ExitCode}");

                    if (proc.ExitCode == 0 || proc.ExitCode == 5010)  // 5010 = address already exists
                    {
                        Program.Log($"Successfully assigned IP {ipAddress}/{prefixLength} via netsh");
                        System.Threading.Thread.Sleep(2000);

                        // Add route for the subnet
                        Program.Log($"Adding route for subnet {GetNetworkAddress(ipAddr, prefixLength)}/{prefixLength}...");
                        AddSubnetRoute(interfaceName, ipAddr, prefixLength);

                        return;
                    }
                    else
                    {
                        Program.Log($"netsh IP assignment returned code: {proc.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                Program.Log($"netsh approach failed: {ex.Message}");
            }

            // Fallback to IPHLPAPI method
            Program.Log("Attempting IPHLPAPI-based IP assignment as fallback...");

            ulong interfaceLuid = 0;

            // First, try to get LUID directly from the WireGuard adapter handle
            try
            {
                Program.Log("Attempting to get LUID from WireGuard adapter...");
                WireGuardNTAPI.WireGuardGetAdapterLUID(adapter, out interfaceLuid);
                if (interfaceLuid != 0)
                {
                    Program.Log($"Successfully got LUID from adapter: {interfaceLuid}");
                }
                else
                {
                    Program.Log("WireGuardGetAdapterLUID returned 0, will try other methods");
                }
            }
            catch (Exception ex)
            {
                Program.Log($"WireGuardGetAdapterLUID failed: {ex.Message}, will use other methods");
            }

            // If we didn't get LUID from adapter, try using .NET's NetworkInterface to extract it via reflection
            if (interfaceLuid == 0)
            {
                Program.Log("Attempting to extract LUID from NetworkInterface object...");
                int maxRetries = 5;
                int retryCount = 0;

                while (retryCount < maxRetries && interfaceLuid == 0)
                {
                    try
                    {
                        var allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                        Program.Log($"Found {allInterfaces.Length} network interfaces");

                        foreach (var ni in allInterfaces)
                        {
                            // Look for our interface - check both name and description
                            if (ni.Name.Contains(interfaceName) || ni.Description.Contains(interfaceName))
                            {
                                Program.Log($"Found matching interface: {ni.Name}");

                                // Try to extract LUID using multiple methods
                                bool luidFound = false;

                                // Method 1: Try to get the interface GUID and convert via ConvertInterfaceGuidToLuid
                                try
                                {
                                    Program.Log($"  Attempting to get interface GUID...");
                                    var guidProp = ni.GetType().GetProperty("Id",
                                        System.Reflection.BindingFlags.Instance |
                                        System.Reflection.BindingFlags.Public);

                                    if (guidProp != null)
                                    {
                                        var guidObj = guidProp.GetValue(ni);
                                        if (guidObj is Guid interfaceGuid)
                                        {
                                            Program.Log($"  Found interface GUID: {interfaceGuid}");
                                            uint result = ConvertInterfaceGuidToLuid(ref interfaceGuid, out interfaceLuid);
                                            if (result == 0 && interfaceLuid != 0)
                                            {
                                                Program.Log($"  Successfully converted GUID to LUID: {interfaceLuid}");
                                                luidFound = true;
                                            }
                                            else
                                            {
                                                Program.Log($"  ConvertInterfaceGuidToLuid failed (Error: {result})");
                                            }
                                        }
                                    }
                                }
                                catch (Exception guidEx)
                                {
                                    Program.Log($"  GUID extraction failed: {guidEx.Message}");
                                }

                                if (luidFound && interfaceLuid != 0)
                                    break;

                                // Method 2: Try reflection to extract LUID property directly
                                try
                                {
                                    string[] luidPropertyNames = { "Luid", "_ipv4LoopbackLuid", "_luid" };
                                    var niType = ni.GetType();

                                    foreach (string propName in luidPropertyNames)
                                    {
                                        var field = niType.GetProperty(propName,
                                            System.Reflection.BindingFlags.Instance |
                                            System.Reflection.BindingFlags.NonPublic |
                                            System.Reflection.BindingFlags.IgnoreCase);

                                        if (field != null)
                                        {
                                            Program.Log($"  Trying property: {propName}");
                                            var luidObj = field.GetValue(ni);
                                            if (luidObj != null)
                                            {
                                                if (luidObj is ulong luidValue && luidValue != 0)
                                                {
                                                    interfaceLuid = luidValue;
                                                    Program.Log($"  Successfully extracted LUID via property '{propName}': {interfaceLuid}");
                                                    luidFound = true;
                                                    break;
                                                }
                                                else if (luidObj is long luidLong && luidLong != 0)
                                                {
                                                    interfaceLuid = (ulong)luidLong;
                                                    Program.Log($"  Successfully extracted LUID via property '{propName}' (as long): {interfaceLuid}");
                                                    luidFound = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                catch (Exception reflEx)
                                {
                                    Program.Log($"  Reflection attempt failed: {reflEx.Message}");
                                }

                                if (luidFound && interfaceLuid != 0)
                                    break;

                                // Method 3: Fallback to name-based conversion
                                Program.Log($"  Attempting ConvertInterfaceNameToLuidW for: {ni.Name}");
                                uint nameResult = ConvertInterfaceNameToLuidW(ni.Name, out interfaceLuid);
                                if (nameResult == 0 && interfaceLuid != 0)
                                {
                                    Program.Log($"  Successfully got LUID from name: {interfaceLuid}");
                                    luidFound = true;
                                    break;
                                }
                                else
                                {
                                    Program.Log($"  ConvertInterfaceNameToLuidW failed (Error: {nameResult})");
                                }
                            }
                        }

                        if (interfaceLuid != 0)
                            break;

                        retryCount++;
                        if (retryCount < maxRetries)
                        {
                            Program.Log($"LUID not obtained yet (attempt {retryCount}/{maxRetries}), retrying in 2s...");
                            System.Threading.Thread.Sleep(2000);
                        }
                    }
                    catch (Exception ex)
                    {
                        retryCount++;
                        Program.Log($"Error during interface extraction (attempt {retryCount}/{maxRetries}): {ex.Message}");
                        if (retryCount < maxRetries)
                            System.Threading.Thread.Sleep(2000);
                    }
                }
            }

            if (interfaceLuid == 0)
            {
                throw new Exception($"Failed to find interface LUID - interface may not be fully initialized or driver may not be loaded");
            }

            // Create address entry
            var row = new MIB_UNICASTIPADDRESS_ROW();
            row.Address_Family = 2; // AF_INET for IPv4
            row.InterfaceLuid = interfaceLuid;
            row.OnLinkPrefixLength = prefixLength;
            row.DadState = (byte)NL_DAD_STATE_PREFERRED;
            row.ValidLifetime = 0xFF;
            row.PreferredLifetime = 0xFF;
            row.SkipAsSource = 0;

            // Parse IP address
            IPAddress addr = IPAddress.Parse(ipAddress);
            byte[] addressBytes = addr.GetAddressBytes();
            row.Address_Ipv4 = new byte[4];
            Array.Copy(addressBytes, row.Address_Ipv4, 4);

            // Create the unicast IP address entry
            uint createResult = CreateUnicastIpAddressEntry(ref row);
            if (createResult != 0)
            {
                // Error 5023 (MIB_E_INVALID_DATA) is expected if address already exists, which is OK
                if (createResult == 5023)
                {
                    Program.Log("IP address already assigned to interface");
                }
                else
                {
                    throw new Exception($"Failed to assign IP address (Error: {createResult})");
                }
            }

            Program.Log($"IP address {ipAddress}/{prefixLength} assigned successfully");
        }
        catch (Exception ex)
        {
            Program.Log($"Error assigning IP address: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Closes a WireGuard adapter
    /// </summary>
    public static void CloseAdapter(IntPtr adapter)
    {
        if (adapter != IntPtr.Zero)
        {
            Program.Log("Closing WireGuard adapter");
            WireGuardCloseAdapter(adapter);
        }
    }
}
