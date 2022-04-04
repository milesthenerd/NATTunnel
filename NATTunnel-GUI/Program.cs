using Gtk;
using System;

namespace NATTunnel.GUI;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Application.Init();

        var app = new Application("org.TCPTunnel3_GUI.TCPTunnel3_GUI", GLib.ApplicationFlags.None);
        app.Register(GLib.Cancellable.Current);

        var win = new MainWindow();
        app.AddWindow(win);

        win.Show();
        Application.Run();
    }
}