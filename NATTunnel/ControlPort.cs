using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace NATTunnel;

/// <summary>
/// Locates the engine's control HTTP endpoint. The engine prefers 51889 but falls back to a free port when
/// something else holds it, then publishes the port in memory (in-process GUI) and in a file (GUI attaching
/// to a separate engine, e.g. the Linux systemd daemon).
/// </summary>
public static class ControlPort
{
    public const int Default = 51889;

    private static volatile int bound;

    public static string FilePath => OperatingSystem.IsLinux()
        ? "/run/nattunnel/control-port"
        : Path.Combine(AppContext.BaseDirectory, "control-port");

    /// <summary>Port in use: this process's engine if running, else the published file, else the default.</summary>
    public static int Current
    {
        get
        {
            int p = bound;
            if (p > 0) return p;
            try
            {
                if (int.TryParse(File.ReadAllText(FilePath).Trim(), out p) && p > 0 && p <= 65535) return p;
            }
            catch { }
            return Default;
        }
    }

    public static string BaseUrl => $"http://localhost:{Current}";

    /// <summary>
    /// Bind the control listener. Throws if the default port is taken AND another instance of this exe is
    /// running: that is a live or zombie engine, and starting a second one would claim the drivers twice.
    /// </summary>
    internal static HttpListener Bind()
    {
        if (TryStart(Default, out var listener, out var defaultError)) return Publish(listener, Default);

        if (OtherInstanceRunning())
            throw new InvalidOperationException(
                $"Control port {Default} is in use and another NATTunnel instance is running.", defaultError);

        for (int i = 0; i < 5; i++)
        {
            int port = FreeLoopbackTcpPort();
            if (TryStart(port, out listener, out _))
            {
                Program.Log(LogLevel.Warning, $"[Mesh] Control port {Default} unavailable ({defaultError?.Message}); using {port}.");
                return Publish(listener, port);
            }
        }
        throw new InvalidOperationException($"Could not bind a control port (default {Default} unavailable).", defaultError);
    }

    private static bool TryStart(int port, out HttpListener listener, out Exception error)
    {
        listener = new HttpListener();
        listener.Prefixes.Add($"http://localhost:{port}/");
        try
        {
            listener.Start();
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            listener.Close();
            listener = null;
            error = ex;
            return false;
        }
    }

    private static HttpListener Publish(HttpListener listener, int port)
    {
        bound = port;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
            File.WriteAllText(FilePath, port.ToString());
        }
        catch (Exception ex)
        {
            // In-process GUI still works; only an external GUI would miss a non-default port.
            Program.Log(LogLevel.Warning, $"[Mesh] Could not write {FilePath}: {ex.Message}");
        }
        return listener;
    }

    private static bool OtherInstanceRunning()
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            foreach (var p in Process.GetProcessesByName(self.ProcessName))
            {
                using (p)
                    if (p.Id != self.Id) return true;
            }
        }
        catch { }
        return false;
    }

    private static int FreeLoopbackTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
