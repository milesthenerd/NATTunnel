using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Security.Principal;
using Microsoft.Win32;

namespace NATTunnel;

[SupportedOSPlatform("windows")]
internal class WireGuardService
{
    // Windows Service API
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateServiceW(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfig2W(
        IntPtr hService,
        uint dwInfoLevel,
        IntPtr lpInfo);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(
        string lpMachineName,
        string lpDatabaseName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr OpenServiceW(
        IntPtr hSCManager,
        string lpServiceName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr hService);

    // Constants
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_AUTO_START = 0x00000002;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_CONFIG_SERVICE_SID_INFO = 0x0000000D;

    // Service SID Info
    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_SID_INFO
    {
        public uint dwServiceSidType;
    }
    private const uint SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001;

    public static bool InstallService(string interfaceName, string configPath)
    {
        try
        {
            // Generate service name and display name
            // Use $ in both service name and display name per WireGuard spec
            string serviceName = "WireGuardTunnel$NATTunnel";
            string displayName = "WireGuardTunnel$NATTunnel";

            Program.Log(LogLevel.Debug, $"Service name: {serviceName}");
            Program.Log(LogLevel.Debug, $"Display name: {displayName}");

            // Get full path to executable
            string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
            Program.Log(LogLevel.Debug, $"Executable path: {exePath}");
            Program.Log(LogLevel.Debug, $"Executable exists: {System.IO.File.Exists(exePath)}");
            Program.Log(LogLevel.Debug, $"Config path: {configPath}");
            Program.Log(LogLevel.Debug, $"Config exists: {System.IO.File.Exists(configPath)}");

            // Format binary path for service installation
            // Pass the config file path and server mode flag as per WireGuard spec
            // Format: program.exe /service "config_path" [server|client]
            string modeArg = interfaceName.Contains("server") ? "server" : "client";
            string binaryPath = $"\"{exePath}\" /service \"{configPath}\" {modeArg}";
            Program.Log(LogLevel.Debug, $"Binary path: {binaryPath}");

            // Validate the binary path is not too long (Windows has limits)
            if (binaryPath.Length > 2048)
            {
                throw new Exception($"Binary path is too long: {binaryPath.Length} characters (max 2048)");
            }

            // Validate service name length (max 256 characters)
            if (serviceName.Length > 256)
            {
                throw new Exception($"Service name is too long: {serviceName.Length} characters");
            }

            // Before attempting to create, properly delete any existing service with this name
            // Use sc.exe which handles the Windows API correctly
            Program.Log(LogLevel.Debug, "Checking for and removing any existing service via sc.exe...");
            try
            {
                // First, stop the service if it's running
                var stopPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"stop \"{serviceName}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(stopPsi))
                {
                    process.WaitForExit(5000);
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    if (!string.IsNullOrEmpty(output) && !output.Contains("does not exist"))
                        Program.Log(LogLevel.Debug, $"SC stop output: {output.Trim()}");
                }

                // Wait a moment after stopping
                System.Threading.Thread.Sleep(500);

                // Then delete the service
                var deletePsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = $"delete \"{serviceName}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(deletePsi))
                {
                    process.WaitForExit(5000);
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    if (!string.IsNullOrEmpty(output) && !output.Contains("does not exist"))
                        Program.Log(LogLevel.Debug, $"SC delete output: {output.Trim()}");
                }

                System.Threading.Thread.Sleep(1500); // Wait for cleanup to complete
            }
            catch (Exception ex)
            {
                Program.Log(LogLevel.Warning, $"SC.exe cleanup warning: {ex.Message}");
            }

            // Open Service Control Manager
            IntPtr scmHandle = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception($"Failed to open Service Control Manager (Error: {Marshal.GetLastWin32Error()})");
            }

            try
            {
                // Check if service already exists and remove it first
                Program.Log(LogLevel.Debug, $"Checking if service already exists...");

                // First try OpenServiceW
                IntPtr existingServiceHandle = OpenServiceW(scmHandle, serviceName, SERVICE_ALL_ACCESS);
                if (existingServiceHandle != IntPtr.Zero)
                {
                    Program.Log(LogLevel.Debug, $"Service already exists: {serviceName}. Removing old service...");
                    CloseServiceHandle(existingServiceHandle);

                    // Try to uninstall the old service with retry logic
                    int uninstallRetries = 5;
                    bool uninstallSuccess = false;
                    while (uninstallRetries > 0 && !uninstallSuccess)
                    {
                        uninstallSuccess = UninstallService(interfaceName);
                        if (!uninstallSuccess)
                        {
                            Program.Log(LogLevel.Error, $"Attempt to uninstall service failed, retrying... ({uninstallRetries - 1} attempts remaining)");
                            System.Threading.Thread.Sleep(1500); // Wait longer between retries
                            uninstallRetries--;
                        }
                    }

                    if (!uninstallSuccess)
                    {
                        Program.Log(LogLevel.Error, $"Warning: Could not uninstall old service after retries, but continuing...");
                    }

                    // Wait longer for service to be fully removed from registry
                    System.Threading.Thread.Sleep(2500);

                    // Double-check that the service is gone
                    existingServiceHandle = OpenServiceW(scmHandle, serviceName, SERVICE_ALL_ACCESS);
                    if (existingServiceHandle != IntPtr.Zero)
                    {
                        Program.Log(LogLevel.Warning, $"Warning: Service still exists after uninstall. It may be pending deletion or requires reboot.");
                        CloseServiceHandle(existingServiceHandle);
                        System.Threading.Thread.Sleep(3000); // Give Windows significant time
                    }
                }
                else
                {
                    // If OpenServiceW fails, check registry directly to see if service exists
                    int openError = Marshal.GetLastWin32Error();
                    if (openError != 1060) // If it's not "service doesn't exist"
                    {
                        Program.Log(LogLevel.Error, $"OpenServiceW returned error {openError} (not 1060), service may still exist");

                        // Try registry check
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        {
                            try
                            {
                                using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}"))
                                {
                                    if (key != null)
                                    {
                                        Program.Log(LogLevel.Debug, $"Service {serviceName} exists in registry - attempting delete...");
                                        // Try to force delete via UninstallService
                                        int regRetries = 3;
                                        while (regRetries > 0 && !UninstallService(interfaceName))
                                        {
                                            Program.Log(LogLevel.Error, $"Registry delete attempt {4 - regRetries} failed, retrying...");
                                            System.Threading.Thread.Sleep(2000);
                                            regRetries--;
                                        }
                                        System.Threading.Thread.Sleep(2000);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Program.Log(LogLevel.Warning, $"Registry check warning: {ex.Message}");
                            }
                        }
                    }
                }

                // Create the service
                IntPtr serviceHandle = IntPtr.Zero;
                Program.Log(LogLevel.Debug, "Calling CreateServiceW...");

                // Test: Try creating service without arguments first to diagnose Error 1073
                Program.Log(LogLevel.Debug, "First attempt: Creating service with full binary path...");

                // Dependencies: WireGuard service depends on Nsi and TcpIp for proper interface creation
                // Format: null-terminated multi-string "Nsi\0TcpIp\0"
                string dependencies = "Nsi\0TcpIp\0";

                bool success = CreateServiceW(
                    scmHandle,
                    serviceName,
                    displayName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binaryPath,
                    null,
                    IntPtr.Zero,
                    dependencies,
                    null,
                    null);

                // If that fails with 1073, try just the exe path
                if (!success)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    if (errorCode == 1073) // ERROR_INVALID_NAME
                    {
                        Program.Log(LogLevel.Error, "Got Error 1073 - trying with just executable path (no arguments)...");
                        string exeOnlyPath = $"\"{exePath}\"";
                        Program.Log(LogLevel.Debug, $"Trying binary path: {exeOnlyPath}");

                        success = CreateServiceW(
                            scmHandle,
                            serviceName,
                            displayName,
                            SERVICE_ALL_ACCESS,
                            SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_AUTO_START,
                            SERVICE_ERROR_NORMAL,
                            exeOnlyPath,
                            null,
                            IntPtr.Zero,
                            dependencies,
                            null,
                            null);
                    }
                }

                if (!success)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Program.Log(LogLevel.Error, $"CreateServiceW failed with error: {errorCode}");
                    throw new Exception($"Failed to create service (Error: {errorCode})");
                }

                Program.Log(LogLevel.Debug, "Service created successfully");

                // Wait for service to be fully registered (Windows needs significant time for SCM update)
                // The $ character may require extra time
                System.Threading.Thread.Sleep(3000);

                // Close and reopen SCM handle to force refresh
                CloseServiceHandle(scmHandle);
                scmHandle = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
                if (scmHandle == IntPtr.Zero)
                {
                    throw new Exception($"Failed to reopen Service Control Manager (Error: {Marshal.GetLastWin32Error()})");
                }

                // Get handle to created service with retry logic
                serviceHandle = IntPtr.Zero;
                int retries = 10;
                while (serviceHandle == IntPtr.Zero && retries > 0)
                {
                    serviceHandle = OpenServiceW(scmHandle, serviceName, SERVICE_ALL_ACCESS);
                    if (serviceHandle == IntPtr.Zero)
                    {
                        int errorCode = Marshal.GetLastWin32Error();
                        if (retries > 1)
                        {
                            Program.Log(LogLevel.Error, $"Failed to open service (Error: {errorCode}), retrying... ({retries - 1} attempts remaining)");
                            System.Threading.Thread.Sleep(1500); // Wait 1.5 seconds between retries
                        }
                        retries--;
                    }
                }
                if (serviceHandle == IntPtr.Zero)
                {
                    throw new Exception($"Failed to open service (Error: {Marshal.GetLastWin32Error()})");
                }

                try
                {
                    // Wait a bit longer before trying to set SID - service needs time to fully initialize
                    System.Threading.Thread.Sleep(500);

                    // Close the SCM handle and reopen for SID configuration
                    CloseServiceHandle(scmHandle);
                    scmHandle = IntPtr.Zero;

                    // Reopen SCM for service SID configuration
                    scmHandle = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
                    if (scmHandle == IntPtr.Zero)
                    {
                        Program.Log(LogLevel.Error, "Warning: Could not reopen Service Control Manager for SID configuration");
                    }
                    else
                    {
                        // Try to set unrestricted SID with retry logic
                        var sidInfo = new SERVICE_SID_INFO { dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED };
                        IntPtr sidInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sidInfo));
                        try
                        {
                            Marshal.StructureToPtr(sidInfo, sidInfoPtr, false);

                            // Try setting SID up to 3 times
                            int sidRetries = 3;
                            while (sidRetries > 0)
                            {
                                success = ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_SERVICE_SID_INFO, sidInfoPtr);
                                if (success)
                                {
                                    Program.Log(LogLevel.Debug, "Service SID configured successfully");
                                    break;
                                }
                                else
                                {
                                    int errorCode = Marshal.GetLastWin32Error();
                                    Program.Log(LogLevel.Error, $"Failed to set service SID (Error: {errorCode}), attempt {4 - sidRetries}");
                                    if (sidRetries > 1)
                                    {
                                        System.Threading.Thread.Sleep(200);
                                    }
                                    sidRetries--;
                                }
                            }

                            if (!success)
                            {
                                Program.Log(LogLevel.Error, "Warning: Could not set service SID via API, trying registry approach...");
                                // Fallback: try setting via registry directly
                                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                                {
                                    try
                                    {
                                        string regPath = $@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{serviceName}";
                                        using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", true))
                                        {
                                            if (key != null)
                                            {
                                                // Set the service SID type via registry
                                                key.SetValue("ServiceSidType", SERVICE_SID_TYPE_UNRESTRICTED, RegistryValueKind.DWord);
                                                Program.Log(LogLevel.Debug, "Service SID configured successfully via registry");
                                            }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Program.Log(LogLevel.Error, $"Warning: Registry approach also failed: {ex.Message}");
                                    }
                                }
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(sidInfoPtr);
                        }
                    }

                    // Store config path in registry for the service to retrieve
                    // Do this after successfully opening the service handle
                    StoreConfigPathInRegistry(serviceName, configPath);
                }
                finally
                {
                    CloseServiceHandle(serviceHandle);
                }

                Program.Log(LogLevel.Debug, $"Successfully installed service: {serviceName}");
                return true;
            }
            finally
            {
                CloseServiceHandle(scmHandle);
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Failed to install service: {ex.Message}");
            return false;
        }
    }

    public static bool UninstallService(string interfaceName)
    {
        try
        {
            // Generate service name (must match InstallService format)
            // Use $ in service name per WireGuard spec
            string serviceName = "WireGuardTunnel$NATTunnel";

            Program.Log(LogLevel.Debug, $"Attempting to uninstall service: {serviceName}");

            // Open Service Control Manager
            IntPtr scmHandle = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Program.Log(LogLevel.Error, $"Failed to open Service Control Manager (Error: {errorCode})");
                return false;
            }

            try
            {
                // Open service
                IntPtr serviceHandle = OpenServiceW(scmHandle, serviceName, SERVICE_ALL_ACCESS);
                if (serviceHandle == IntPtr.Zero)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    if (errorCode == 1060) // ERROR_SERVICE_DOES_NOT_EXIST
                    {
                        Program.Log(LogLevel.Debug, $"Service {serviceName} does not exist (already deleted)");
                        return true;
                    }
                    Program.Log(LogLevel.Error, $"Failed to open service (Error: {errorCode})");
                    return false;
                }

                try
                {
                    // Delete service
                    if (!DeleteService(serviceHandle))
                    {
                        int errorCode = Marshal.GetLastWin32Error();
                        Program.Log(LogLevel.Error, $"Failed to delete service (Error: {errorCode})");
                        // Error 1072 means service is marked for deletion, which is okay
                        if (errorCode == 1072) // ERROR_SERVICE_MARKED_FOR_DELETE
                        {
                            Program.Log(LogLevel.Debug, $"Service is marked for deletion (will be removed on next reboot)");
                            return true;
                        }
                        return false;
                    }

                    Program.Log(LogLevel.Debug, $"Successfully uninstalled service: {serviceName}");
                    return true;
                }
                finally
                {
                    CloseServiceHandle(serviceHandle);
                }
            }
            finally
            {
                CloseServiceHandle(scmHandle);
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Error uninstalling service: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Store the config path in the Windows registry for the service to retrieve.
    /// This works around issues passing arguments through the service binary path.
    /// </summary>
    private static void StoreConfigPathInRegistry(string serviceName, string configPath)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        try
        {
            string regPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters";
            Program.Log(LogLevel.Debug, $"Storing config path in registry: {regPath}");

            // Try to create or open the Parameters subkey
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(regPath))
            {
                if (key != null)
                {
                    key.SetValue("ConfigPath", configPath, RegistryValueKind.String);
                    Program.Log(LogLevel.Debug, $"Stored config path in registry: {configPath}");
                }
                else
                {
                    Program.Log(LogLevel.Error, "Warning: Could not create service Parameters registry key");
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Program.Log(LogLevel.Warning, $"Warning: Access denied writing to registry - {ex.Message}");
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Warning: Failed to store config path in registry: {ex.Message}");
        }
    }

    /// <summary>
    /// Retrieve the config path from the Windows registry.
    /// This is called by the service when it starts.
    /// </summary>
    public static string GetConfigPathFromRegistry(string serviceName)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return null;

        try
        {
            // Check the Parameters subkey first
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters"))
            {
                if (key != null)
                {
                    object value = key.GetValue("ConfigPath");
                    if (value != null && value is string configPath)
                    {
                        Program.Log(LogLevel.Debug, $"Retrieved config path from registry: {configPath}");
                        return configPath;
                    }
                }
            }

            // Fall back to checking the service key directly
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}"))
            {
                if (key != null)
                {
                    object value = key.GetValue("ConfigPath");
                    if (value != null && value is string configPath)
                    {
                        Program.Log(LogLevel.Debug, $"Retrieved config path from service registry: {configPath}");
                        return configPath;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Program.Log(LogLevel.Error, $"Warning: Failed to retrieve config path from registry: {ex.Message}");
        }
        return null;
    }
}

