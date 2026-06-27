using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NATTunnel;

/// <summary>
/// Minimal Authenticode signature verification via WinVerifyTrust. Used to gate execution
/// of binaries we download (the WireGuard for Windows installer) — Windows will already
/// re-check the signature via SmartScreen + UAC, but verifying programmatically lets us
/// fail with a clear log message before launching the process, and lets us refuse to run
/// anything that doesn't carry a trusted publisher signature at all.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AuthenticodeVerifier
{
    // WinTrust constants
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // pointer to WINTRUST_FILE_INFO
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);

    /// <summary>
    /// Verify that <paramref name="filePath"/> carries a valid Authenticode signature that
    /// chains to a trusted root. Returns true only when WinVerifyTrust returns 0 (success).
    /// Optional <paramref name="expectedSubjectSubstring"/> additionally checks that the
    /// signing certificate's subject contains that string — for the WireGuard installer
    /// you'd pass something like "WireGuard LLC".
    /// </summary>
    public static bool VerifyFile(string filePath, string expectedSubjectSubstring = null)
    {
        IntPtr fileInfoPtr = IntPtr.Zero;
        var data = default(WINTRUST_DATA);
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
            };

            int hr = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);
            if (hr != 0)
            {
                Program.Log(LogLevel.Warning, $"AuthenticodeVerifier: WinVerifyTrust failed for {filePath} (HRESULT 0x{hr:X8}).");
                return false;
            }

            if (!string.IsNullOrEmpty(expectedSubjectSubstring))
            {
                try
                {
#pragma warning disable SYSLIB0057
                    var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                    if (cert.Subject?.Contains(expectedSubjectSubstring, StringComparison.OrdinalIgnoreCase) != true)
                    {
                        Program.Log(LogLevel.Warning, $"AuthenticodeVerifier: signature is valid but subject '{cert.Subject}' does not contain expected substring '{expectedSubjectSubstring}'.");
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    Program.Log(LogLevel.Warning, $"AuthenticodeVerifier: could not read signing certificate of {filePath}: {ex.Message}");
                    return false;
                }
            }
            return true;
        }
        finally
        {
            if (data.cbStruct != 0)
            {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);
            }
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
        }
    }
}
