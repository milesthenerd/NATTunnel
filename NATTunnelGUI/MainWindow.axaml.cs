using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using NATTunnel;

namespace NATTunnelGUI;

public partial class MainWindow : Window
{
    private const int PollIntervalMs = 1000;
    private const int MaxLogChars = 200_000;

    private readonly DispatcherTimer pollTimer;
    private readonly HttpClient httpClient;
    private bool isConnected;
    private bool isConnecting;
    private long latestLogSeq;
    private bool autoConnectTried;
    // Suppress reverting to a plain "Disconnected" UI while the daemon is still spinning up
    // its real state (and answering /status with its initial Disconnected placeholder).
    private bool waitingForRealState;
    // Track the last error text we already popped a dialog for, so the same error doesn't
    // spam the user on every /status poll.
    private string? lastShownError;

    public MainWindow()
    {
        InitializeComponent();

        Title = $"NATTunnel {GetAppVersion()}";

        NetworkNameText.Text = "-";
        LogTextBox.Text = "Starting...\n";

        httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(PollIntervalMs) };
        pollTimer.Tick += async (_, _) => await Poll();
        pollTimer.Start();

        // Kick off the first poll immediately so the user sees something within ~1s of launch
        // instead of waiting a full polling interval before any UI updates.
        _ = Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(Poll);
    }

    private async System.Threading.Tasks.Task Poll()
    {
        await PollStatus();
        await PollLogs();
    }

    private async System.Threading.Tasks.Task PollStatus()
    {
        try
        {
            string json = await httpClient.GetStringAsync("http://localhost:51889/status");
            var state = JsonSerializer.Deserialize<MeshState>(json);
            if (state == null) return;

            // Daemon has moved past its idle placeholder once it reports anything besides Disconnected.
            if (state.ConnectionState != "Disconnected") waitingForRealState = false;

            switch (state.ConnectionState)
            {
                case "Connected":
                    StatusDot.Fill = (IBrush)this.FindResource("StatusGreenBrush")!;
                    StatusText.Text = "Connected";
                    ConnectButton.Content = "Disconnect";
                    ConnectButton.IsEnabled = true;
                    isConnected = true;
                    isConnecting = false;
                    break;
                case "Connecting":
                    StatusDot.Fill = (IBrush)this.FindResource("StatusYellowBrush")!;
                    StatusText.Text = "Connecting...";
                    ConnectButton.Content = "Cancel";
                    ConnectButton.IsEnabled = true;
                    isConnected = false;
                    isConnecting = true;
                    break;
                case "Disconnected":
                    if (!autoConnectTried)
                    {
                        // First time we see Disconnected on launch: auto-fire /connect and
                        // optimistically show Connecting. Suppress further "Disconnected"
                        // overwrites until the daemon reports a real non-Disconnected state.
                        autoConnectTried = true;
                        waitingForRealState = true;
                        _ = httpClient.PostAsync("http://localhost:51889/connect", null);
                    }
                    if (waitingForRealState)
                    {
                        StatusDot.Fill = (IBrush)this.FindResource("StatusYellowBrush")!;
                        StatusText.Text = "Connecting...";
                        ConnectButton.Content = "Cancel";
                        ConnectButton.IsEnabled = true;
                        isConnected = false;
                        isConnecting = true;
                    }
                    else
                    {
                        StatusDot.Fill = (IBrush)this.FindResource("StatusRedBrush")!;
                        StatusText.Text = "Disconnected";
                        ConnectButton.Content = "Connect";
                        ConnectButton.IsEnabled = true;
                        isConnected = false;
                        isConnecting = false;
                    }
                    break;
                case "Disconnecting":
                    StatusDot.Fill = (IBrush)this.FindResource("StatusYellowBrush")!;
                    StatusText.Text = "Disconnecting...";
                    ConnectButton.IsEnabled = false;
                    isConnected = false;
                    isConnecting = false;
                    break;
                default:
                    StatusDot.Fill = (IBrush)this.FindResource("StatusYellowBrush")!;
                    StatusText.Text = state.ConnectionState ?? "Unknown";
                    ConnectButton.IsEnabled = true;
                    break;
            }

            MeshIPText.Text = state.OwnMeshIP ?? "-";
            PeerIDText.Text = state.OwnPeerID ?? "-";
            NATTypeText.Text = state.NATType ?? "-";
            RoleText.Text = state.IsIntroducer ? "Introducer" : "Peer";
            UptimeText.Text = FormatUptime(state.UptimeSeconds);
            NetworkNameText.Text = state.NetworkID ?? "-";

            if (!state.IsIntroducer && !string.IsNullOrEmpty(state.IntroducerMeshIP))
            {
                IntroducerLabel.IsVisible = true;
                IntroducerText.IsVisible = true;
                IntroducerText.Text = state.IntroducerMeshIP;
            }
            else
            {
                IntroducerLabel.IsVisible = false;
                IntroducerText.IsVisible = false;
            }

            if (state.HostedRelayPairs > 0)
            {
                RelayHostingLabel.IsVisible = true;
                RelayHostingText.IsVisible = true;
                StopRelayingButton.IsVisible = true;
                RelayHostingText.Text = state.HostedRelayPairs == 1
                    ? "Carrying 1 pair"
                    : $"Carrying {state.HostedRelayPairs} pairs";
            }
            else
            {
                RelayHostingLabel.IsVisible = false;
                RelayHostingText.IsVisible = false;
                StopRelayingButton.IsVisible = false;
            }

            PeerCountHeader.Text = $"Peers ({state.ConnectedPeers?.Count ?? 0})";
            var peerItems = new List<PeerDisplayItem>();
            if (state.ConnectedPeers != null)
            {
                foreach (var peer in state.ConnectedPeers)
                {
                    peerItems.Add(new PeerDisplayItem
                    {
                        MeshIP = peer.MeshIP ?? "-",
                        PeerID = peer.PeerID ?? "-",
                        PeerIDShort = TruncateGuid(peer.PeerID),
                        NATType = peer.NATType ?? "-",
                        Endpoint = peer.Endpoint ?? "-",
                        LatencyDisplay = peer.LatencyMs >= 0 ? $"{peer.LatencyMs}ms" : "-",
                        StatusDisplay = peer.Status ?? (peer.IsRelayed ? "Relayed" : "Direct"),
                        PeerVersionDisplay = peer.PeerProtocolVersion > 0 ? $"v{peer.PeerProtocolVersion}" : "-",
                    });
                }
            }
            PeerListView.ItemsSource = peerItems;

            // Surface newly-reported daemon errors as a modal dialog. When the daemon clears
            // its error (e.g. on reconnect attempt), reset our latch so the same error text
            // popping up again fires the dialog again.
            if (string.IsNullOrEmpty(state.LastError))
            {
                lastShownError = null;
            }
            else if (state.LastError != lastShownError)
            {
                lastShownError = state.LastError;
                string title = state.LastErrorKind switch
                {
                    "VersionMismatch" => "NATTunnel Update Required",
                    "AuthFailure" => "Authentication Failed",
                    _ => "NATTunnel Error"
                };
                _ = DialogHelpers.ShowInfoAsync(this, title, state.LastError);
            }
        }
        catch
        {
            StatusDot.Fill = (IBrush)this.FindResource("StatusRedBrush")!;
            StatusText.Text = "Engine not running";
            ConnectButton.IsEnabled = false;
        }
    }

    private async System.Threading.Tasks.Task PollLogs()
    {
        try
        {
            string json = await httpClient.GetStringAsync($"http://localhost:51889/logs?since={latestLogSeq}");
            using var doc = JsonDocument.Parse(json);
            long newLatest = doc.RootElement.GetProperty("latestSeq").GetInt64();

            // Daemon restart detection: if its seq dropped below ours, the buffer reset.
            if (newLatest < latestLogSeq) latestLogSeq = 0;

            var lines = doc.RootElement.GetProperty("lines");
            if (lines.GetArrayLength() == 0) return;

            var sb = new System.Text.StringBuilder();
            foreach (var line in lines.EnumerateArray())
                sb.AppendLine(line.GetString());

            LogTextBox.Text += sb.ToString();
            if (LogTextBox.Text.Length > MaxLogChars)
                LogTextBox.Text = LogTextBox.Text[^MaxLogChars..];

            LogTextBox.CaretIndex = LogTextBox.Text.Length;
            latestLogSeq = newLatest;
        }
        catch (Exception ex)
        {
            // PollStatus already surfaces daemon-unreachable. Anything else here is a real bug.
            Console.Error.WriteLine($"[GUI] PollLogs failed: {ex}");
        }
    }

    private async void ConnectDisconnect_Click(object? sender, RoutedEventArgs e)
    {
        ConnectButton.IsEnabled = false;
        try
        {
            string endpoint = (isConnected || isConnecting) ? "/disconnect" : "/connect";
            await httpClient.PostAsync($"http://localhost:51889{endpoint}", null);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[GUI] Failed to send command: {ex.Message}");
        }
    }

    private void Settings_Click(object? sender, RoutedEventArgs e)
    {
        var settingsWindow = new SettingsWindow();
        settingsWindow.ShowDialog(this);
    }

    private async void StopRelaying_Click(object? sender, RoutedEventArgs e)
    {
        StopRelayingButton.IsEnabled = false;
        try
        {
            string getJson = await httpClient.GetStringAsync("http://localhost:51889/config");
            var snap = JsonSerializer.Deserialize<NATTunnel.ConfigSnapshot>(getJson);
            if (snap == null) return;
            snap.AllowRelayThrough = false;
            string payload = JsonSerializer.Serialize(snap);
            using var content = new System.Net.Http.StringContent(payload, System.Text.Encoding.UTF8, "application/json");
            await httpClient.PostAsync("http://localhost:51889/config", content);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[GUI] Failed to disable relay hosting: {ex.Message}");
        }
        finally
        {
            StopRelayingButton.IsEnabled = true;
        }
    }

    private async void Stop_Click(object? sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        ConnectButton.IsEnabled = false;
        SettingsButton.IsEnabled = false;
        StatusText.Text = "Stopping...";
        try { await httpClient.PostAsync("http://localhost:51889/shutdown", null); }
        catch { }
        Close();
    }

    private static string TruncateGuid(string? guid)
        => string.IsNullOrEmpty(guid) ? "-" : (guid.Length > 8 ? guid[..8] : guid);

    private static string FormatUptime(long seconds)
    {
        if (seconds < 60) return $"{seconds}s";
        if (seconds < 3600) return $"{seconds / 60}m {seconds % 60}s";
        return $"{seconds / 3600}h {seconds % 3600 / 60}m";
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        pollTimer.Stop();
        // Windows: GUI owns the daemon, shut it down. Linux: systemd owns it, just disconnect.
        string endpoint = OperatingSystem.IsLinux() ? "/disconnect" : "/shutdown";
        try { httpClient.PostAsync($"http://localhost:51889{endpoint}", null).Wait(500); } catch { }
        httpClient.Dispose();
        base.OnClosing(e);
    }

    private static string GetAppVersion() =>
        $"v{System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "?"}";
}

public class PeerDisplayItem
{
    public string? MeshIP { get; set; }
    public string? PeerID { get; set; }
    public string? PeerIDShort { get; set; }
    public string? NATType { get; set; }
    public string? Endpoint { get; set; }
    public string? LatencyDisplay { get; set; }
    public string? StatusDisplay { get; set; }
    public string? PeerVersionDisplay { get; set; }
}
