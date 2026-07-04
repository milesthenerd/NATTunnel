using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using NATTunnel;

namespace NATTunnelGUI;

public partial class FirewallWindow : Window
{
    private const int PollIntervalMs = 1000;
    private const string StatusUrl = "http://localhost:51889/status";
    private const string BlocksUrl = "http://localhost:51889/blocks";

    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private readonly DispatcherTimer pollTimer;

    public FirewallWindow()
    {
        InitializeComponent();
        pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(PollIntervalMs) };
        pollTimer.Tick += async (_, _) => await Refresh();
        pollTimer.Start();
        _ = Dispatcher.UIThread.InvokeAsync(Refresh);
    }

    private async Task Refresh()
    {
        try
        {
            string json = await http.GetStringAsync(StatusUrl);
            var state = JsonSerializer.Deserialize<MeshState>(json);
            if (state == null) return;

            OwnFingerprintText.Text = string.IsNullOrEmpty(state.OwnFingerprint) ? "-" : state.OwnFingerprint;

            var blocked = new HashSet<string>(state.BlockedFingerprints ?? new List<string>(), StringComparer.OrdinalIgnoreCase);

            var known = new List<KnownPeerItem>();
            if (state.KnownPeers != null)
            {
                foreach (var kp in state.KnownPeers)
                {
                    bool hasFingerprint = !string.IsNullOrEmpty(kp.Fingerprint);
                    bool isAlreadyBlocked = hasFingerprint && blocked.Contains(kp.Fingerprint);
                    known.Add(new KnownPeerItem
                    {
                        MeshIP = kp.MeshIP ?? "-",
                        Fingerprint = kp.Fingerprint,
                        FingerprintDisplay = hasFingerprint ? kp.Fingerprint : "(no fingerprint yet)",
                        FingerprintForeground = hasFingerprint
                            ? (IBrush)this.FindResource("TextSecondaryBrush")!
                            : (IBrush)this.FindResource("TextSecondaryBrush")!,
                        CanBlock = hasFingerprint && !isAlreadyBlocked,
                    });
                }
            }
            KnownPeersList.ItemsSource = known;
            KnownPeersHeader.Text = $"KNOWN PEERS ({known.Count})";

            var blockedList = new List<BlockedItem>();
            foreach (var fp in blocked)
                blockedList.Add(new BlockedItem { Fingerprint = fp });
            BlockedList.ItemsSource = blockedList;
            BlockedHeader.Text = $"BLOCKED ({blockedList.Count})";
        }
        catch
        {
            // Daemon unreachable — leave the last-good render in place.
        }
    }

    private async void CopyFingerprint_Click(object? sender, RoutedEventArgs e)
    {
        string fp = OwnFingerprintText.Text ?? "";
        if (string.IsNullOrWhiteSpace(fp) || fp == "-") return;
        try
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard != null) await clipboard.SetTextAsync(fp);
        }
        catch { }
    }

    private async void BlockPeer_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string fingerprint && !string.IsNullOrWhiteSpace(fingerprint))
        {
            try
            {
                string body = JsonSerializer.Serialize(new { fingerprint });
                using var content = new StringContent(body, Encoding.UTF8, "application/json");
                await http.PostAsync(BlocksUrl, content);
                await Refresh();
            }
            catch { }
        }
    }

    private async void UnblockPeer_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string fingerprint && !string.IsNullOrWhiteSpace(fingerprint))
        {
            try
            {
                await http.DeleteAsync($"{BlocksUrl}/{Uri.EscapeDataString(fingerprint)}");
                await Refresh();
            }
            catch { }
        }
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        pollTimer.Stop();
        http.Dispose();
        base.OnClosing(e);
    }
}

public class KnownPeerItem
{
    public string? MeshIP { get; set; }
    public string? Fingerprint { get; set; }
    public string? FingerprintDisplay { get; set; }
    public IBrush? FingerprintForeground { get; set; }
    public bool CanBlock { get; set; }
}

public class BlockedItem
{
    public string? Fingerprint { get; set; }
}
