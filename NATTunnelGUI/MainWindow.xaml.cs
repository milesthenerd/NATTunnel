using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using NATTunnel;

namespace NATTunnelGUI;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer pollTimer;
    private readonly HttpClient httpClient;
    private bool wasConnected;

    public MainWindow()
    {
        InitializeComponent();

        // Redirect console output to log panel
        var writer = new GuiTextWriter(LogTextBox);
        Console.SetOut(writer);
        Console.SetError(writer);

        // Show network name from config
        NetworkNameText.Text = TunnelOptions.NetworkID ?? "-";

        // Set up status polling
        httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        pollTimer.Tick += PollStatus;
        pollTimer.Start();
    }

    private async void PollStatus(object sender, EventArgs e)
    {
        try
        {
            string json = await httpClient.GetStringAsync("http://localhost:51889/status");
            var state = JsonSerializer.Deserialize<MeshState>(json);

            if (state == null) return;

            if (!wasConnected)
            {
                wasConnected = true;
                StatusDot.Fill = (System.Windows.Media.Brush)FindResource("StatusGreenBrush");
                StatusText.Text = "Connected";
            }

            // Update sidebar
            MeshIPText.Text = state.OwnMeshIP ?? "-";
            PeerIDText.Text = TruncateGuid(state.OwnPeerID);
            NATTypeText.Text = state.NATType ?? "-";
            RoleText.Text = state.IsIntroducer ? "Introducer" : "Peer";
            UptimeText.Text = FormatUptime(state.UptimeSeconds);

            if (!state.IsIntroducer && !string.IsNullOrEmpty(state.IntroducerMeshIP))
            {
                IntroducerLabel.Visibility = Visibility.Visible;
                IntroducerText.Visibility = Visibility.Visible;
                IntroducerText.Text = state.IntroducerMeshIP;
            }
            else
            {
                IntroducerLabel.Visibility = Visibility.Collapsed;
                IntroducerText.Visibility = Visibility.Collapsed;
            }

            // Update peer list
            PeerCountHeader.Text = $"Peers ({state.ConnectedPeers?.Count ?? 0})";
            var peerItems = new List<PeerDisplayItem>();
            if (state.ConnectedPeers != null)
            {
                foreach (var peer in state.ConnectedPeers)
                {
                    peerItems.Add(new PeerDisplayItem
                    {
                        MeshIP = peer.MeshIP ?? "-",
                        PeerIDShort = TruncateGuid(peer.PeerID),
                        NATType = peer.NATType ?? "-",
                        Endpoint = peer.Endpoint ?? "-",
                        LatencyDisplay = peer.LatencyMs >= 0 ? $"{peer.LatencyMs}ms" : "-",
                        StatusDisplay = peer.IsRelayed ? "Relayed" : "Direct"
                    });
                }
            }
            PeerListView.ItemsSource = peerItems;

            // Update metrics
            if (state.Metrics != null)
            {
                var m = state.Metrics;
                MetricsTunnels.Text = $"Tunnels: {m.TunnelsEstablished}/{m.TunnelsEstablished + m.TunnelsFailed}";
                MetricsHeartbeats.Text = $"HB: {m.HeartbeatAcksReceived}/{m.HeartbeatsSent}";
                MetricsReconnects.Text = m.Reconnects > 0 ? $"Reconnects: {m.Reconnects}" : "";
            }
        }
        catch
        {
            if (wasConnected)
            {
                wasConnected = false;
                StatusDot.Fill = (System.Windows.Media.Brush)FindResource("StatusRedBrush");
                StatusText.Text = "Disconnected";
            }
            else
            {
                StatusText.Text = "Connecting...";
            }
        }
    }

    private static string TruncateGuid(string guid)
    {
        if (string.IsNullOrEmpty(guid)) return "-";
        return guid.Length > 8 ? guid[..8] : guid;
    }

    private static string FormatUptime(long seconds)
    {
        if (seconds < 60) return $"{seconds}s";
        if (seconds < 3600) return $"{seconds / 60}m {seconds % 60}s";
        return $"{seconds / 3600}h {seconds % 3600 / 60}m";
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        pollTimer.Stop();
        httpClient.Dispose();
        base.OnClosing(e);
    }
}

/// <summary>
/// Display model for peer list items.
/// </summary>
public class PeerDisplayItem
{
    public string MeshIP { get; set; }
    public string PeerIDShort { get; set; }
    public string NATType { get; set; }
    public string Endpoint { get; set; }
    public string LatencyDisplay { get; set; }
    public string StatusDisplay { get; set; }
}
