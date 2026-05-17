using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using NATTunnel;

namespace NATTunnelGUI;

public partial class SettingsWindow : Window
{
    private const string ConfigUrl = "http://localhost:51889/config";

    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private string? originalMediationEndpoint;
    private string? originalNetworkID;
    private string? originalNetworkSecret;
    private string? originalMeshSubnet;

    public SettingsWindow()
    {
        InitializeComponent();
        _ = LoadCurrentSettings();
    }

    private async Task LoadCurrentSettings()
    {
        ConfigSnapshot? snap;
        try
        {
            string json = await http.GetStringAsync(ConfigUrl);
            snap = JsonSerializer.Deserialize<ConfigSnapshot>(json);
        }
        catch (Exception ex)
        {
            await DialogHelpers.ShowInfoAsync(this, "Error", $"Could not load settings from daemon: {ex.Message}");
            Close();
            return;
        }
        if (snap == null) { Close(); return; }

        MediationEndpointBox.Text = snap.MediationEndpoint ?? "";
        NetworkIDBox.Text = snap.NetworkID ?? "";
        NetworkSecretBox.Text = snap.NetworkSecret ?? "";
        MeshSubnetBox.Text = snap.MeshSubnet ?? "10.5";

        originalMediationEndpoint = MediationEndpointBox.Text;
        originalNetworkID = NetworkIDBox.Text;
        originalNetworkSecret = NetworkSecretBox.Text;
        originalMeshSubnet = MeshSubnetBox.Text;

        HeartbeatBox.Text = snap.HeartbeatIntervalSeconds.ToString();
        ProbeBox.Text = snap.ProbeIntervalSeconds.ToString();
        StaleTimeoutBox.Text = snap.StaleTimeoutSeconds.ToString();
        RepairCooldownBox.Text = snap.RepairCooldownSeconds.ToString();
        DeadThresholdBox.Text = snap.DeadThreshold.ToString();
        GracePeriodBox.Text = snap.GracePeriodSecondsNonSymmetric.ToString();
        GracePeriodSymBox.Text = snap.GracePeriodSecondsSymmetric.ToString();
        IsolationGraceBox.Text = snap.IsolationGracePeriodSeconds.ToString();

        PeerIDBox.Text = string.IsNullOrEmpty(snap.PeerID) || snap.PeerID == "00000000-0000-0000-0000-000000000000"
            ? "(not yet assigned)"
            : snap.PeerID;
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e) => Close();

    private async void Save_Click(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(MediationEndpointBox.Text))
        {
            await DialogHelpers.ShowInfoAsync(this, "Validation Error", "Mediation Server is required.");
            return;
        }
        if (string.IsNullOrWhiteSpace(NetworkIDBox.Text))
        {
            await DialogHelpers.ShowInfoAsync(this, "Validation Error", "Network ID is required.");
            return;
        }
        if (string.IsNullOrWhiteSpace(NetworkSecretBox.Text))
        {
            await DialogHelpers.ShowInfoAsync(this, "Validation Error", "Network Secret is required.");
            return;
        }

        var (okHb, heartbeat) = await TryParsePositiveInt(HeartbeatBox.Text, "Heartbeat Interval");
        if (!okHb) return;
        var (okPr, probe) = await TryParsePositiveInt(ProbeBox.Text, "Probe Interval");
        if (!okPr) return;
        var (okSt, staleTimeout) = await TryParsePositiveInt(StaleTimeoutBox.Text, "Stale Timeout");
        if (!okSt) return;
        var (okRc, repairCooldown) = await TryParsePositiveInt(RepairCooldownBox.Text, "Repair Cooldown");
        if (!okRc) return;
        var (okDt, deadThreshold) = await TryParsePositiveInt(DeadThresholdBox.Text, "Dead Threshold");
        if (!okDt) return;
        var (okGp, gracePeriod) = await TryParsePositiveInt(GracePeriodBox.Text, "Grace Period");
        if (!okGp) return;
        var (okGs, gracePeriodSym) = await TryParsePositiveInt(GracePeriodSymBox.Text, "Grace Period (Sym.)");
        if (!okGs) return;
        var (okIg, isolationGrace) = await TryParsePositiveInt(IsolationGraceBox.Text, "Isolation Grace Period");
        if (!okIg) return;

        var snap = new ConfigSnapshot
        {
            MediationEndpoint = MediationEndpointBox.Text,
            NetworkID = NetworkIDBox.Text,
            NetworkSecret = NetworkSecretBox.Text,
            MeshSubnet = MeshSubnetBox.Text,
            HeartbeatIntervalSeconds = heartbeat,
            ProbeIntervalSeconds = probe,
            StaleTimeoutSeconds = staleTimeout,
            RepairCooldownSeconds = repairCooldown,
            DeadThreshold = deadThreshold,
            GracePeriodSecondsNonSymmetric = gracePeriod,
            GracePeriodSecondsSymmetric = gracePeriodSym,
            IsolationGracePeriodSeconds = isolationGrace,
        };

        try
        {
            string payload = JsonSerializer.Serialize(snap);
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var resp = await http.PostAsync(ConfigUrl, content);
            resp.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            await DialogHelpers.ShowInfoAsync(this, "Error", $"Failed to save config to daemon: {ex.Message}");
            return;
        }

        bool needsReconnect =
            MediationEndpointBox.Text != originalMediationEndpoint ||
            NetworkIDBox.Text != originalNetworkID ||
            NetworkSecretBox.Text != originalNetworkSecret ||
            MeshSubnetBox.Text != originalMeshSubnet;

        if (needsReconnect)
        {
            bool yes = await DialogHelpers.ShowYesNoAsync(this, "Settings Changed",
                "Network settings have changed. A reconnect is required for these to take effect.\n\nReconnect now?");
            if (yes)
                await TriggerReconnect();
        }

        Close();
    }

    private async Task TriggerReconnect()
    {
        try
        {
            await http.PostAsync("http://localhost:51889/disconnect", null);
            await Task.Delay(500);
            await http.PostAsync("http://localhost:51889/connect", null);
        }
        catch
        {
            // Daemon unreachable — settings still applied to its in-memory state via /config.
        }
    }

    private async Task<(bool ok, int value)> TryParsePositiveInt(string? text, string fieldName)
    {
        if (!int.TryParse(text, out int value) || value <= 0)
        {
            await DialogHelpers.ShowInfoAsync(this, "Validation Error", $"{fieldName} must be a positive integer.");
            return (false, 0);
        }
        return (true, value);
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        http.Dispose();
        base.OnClosing(e);
    }
}
