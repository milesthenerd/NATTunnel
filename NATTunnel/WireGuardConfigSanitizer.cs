using System.Collections.Generic;
using System.IO;

namespace NATTunnel;

/// <summary>Strips wg-quick fields (Address, Name, DNS, MTU, …) so `wg setconf` accepts the file.</summary>
internal static class WireGuardConfigSanitizer
{
    public static void WriteWgOnlyConfig(string sourceConfigPath, string destConfigPath)
    {
        var lines = File.ReadAllLines(sourceConfigPath);
        var wgLines = new List<string> { "[Interface]" };
        bool inInterface = false;
        bool inPeer = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("[Interface]"))
            {
                inInterface = true;
                inPeer = false;
                continue;
            }
            if (trimmed.StartsWith("[Peer]"))
            {
                inInterface = false;
                inPeer = true;
                wgLines.Add("");
                wgLines.Add("[Peer]");
                continue;
            }

            if (inInterface)
            {
                if (trimmed.StartsWith("PrivateKey") || trimmed.StartsWith("ListenPort"))
                    wgLines.Add(trimmed);
            }
            else if (inPeer)
            {
                if (!string.IsNullOrWhiteSpace(trimmed))
                    wgLines.Add(trimmed);
            }
        }

        File.WriteAllLines(destConfigPath, wgLines);
    }
}
