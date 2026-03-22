using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using NATTunnel;

namespace NATTunnelGUI;

public partial class SettingsWindow : Window
{
    // Track original network settings to detect changes requiring reconnect
    private string originalMediationEndpoint;
    private string originalNetworkID;
    private string originalNetworkSecret;
    private string originalMeshSubnet;

    public SettingsWindow()
    {
        InitializeComponent();
        LoadCurrentSettings();
    }

    private void LoadCurrentSettings()
    {
        // Network settings
        MediationEndpointBox.Text = TunnelOptions.MediationEndpoint?.ToString() ?? "";
        NetworkIDBox.Text = TunnelOptions.NetworkID ?? "";
        NetworkSecretBox.Password = TunnelOptions.NetworkSecret ?? "";
        MeshSubnetBox.Text = TunnelOptions.MeshSubnet ?? "10.5";

        // Store originals for change detection
        originalMediationEndpoint = MediationEndpointBox.Text;
        originalNetworkID = NetworkIDBox.Text;
        originalNetworkSecret = NetworkSecretBox.Password;
        originalMeshSubnet = MeshSubnetBox.Text;

        // Timing settings
        HeartbeatBox.Text = TunnelOptions.HeartbeatIntervalSeconds.ToString();
        ProbeBox.Text = TunnelOptions.ProbeIntervalSeconds.ToString();
        StaleTimeoutBox.Text = TunnelOptions.StaleTimeoutSeconds.ToString();
        RepairCooldownBox.Text = TunnelOptions.RepairCooldownSeconds.ToString();
        DeadThresholdBox.Text = TunnelOptions.DeadThreshold.ToString();
        GracePeriodBox.Text = TunnelOptions.GracePeriodSecondsNonSymmetric.ToString();
        GracePeriodSymBox.Text = TunnelOptions.GracePeriodSecondsSymmetric.ToString();
        IsolationGraceBox.Text = TunnelOptions.IsolationGracePeriodSeconds.ToString();

        // Peer ID (read-only)
        PeerIDBox.Text = TunnelOptions.PeerID?.ToString() ?? "(not yet assigned)";
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        // Validate required fields
        if (string.IsNullOrWhiteSpace(MediationEndpointBox.Text))
        {
            MessageBox.Show("Mediation Server is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(NetworkIDBox.Text))
        {
            MessageBox.Show("Network ID is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(NetworkSecretBox.Password))
        {
            MessageBox.Show("Network Secret is required.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Validate timing parameters
        if (!TryParsePositiveInt(HeartbeatBox.Text, "Heartbeat Interval", out int heartbeat)) return;
        if (!TryParsePositiveInt(ProbeBox.Text, "Probe Interval", out int probe)) return;
        if (!TryParsePositiveInt(StaleTimeoutBox.Text, "Stale Timeout", out int staleTimeout)) return;
        if (!TryParsePositiveInt(RepairCooldownBox.Text, "Repair Cooldown", out int repairCooldown)) return;
        if (!TryParsePositiveInt(DeadThresholdBox.Text, "Dead Threshold", out int deadThreshold)) return;
        if (!TryParsePositiveInt(GracePeriodBox.Text, "Grace Period", out int gracePeriod)) return;
        if (!TryParsePositiveInt(GracePeriodSymBox.Text, "Grace Period (Sym.)", out int gracePeriodSym)) return;
        if (!TryParsePositiveInt(IsolationGraceBox.Text, "Isolation Grace Period", out int isolationGrace)) return;

        // Apply timing parameters immediately (they're read from TunnelOptions each loop iteration)
        TunnelOptions.HeartbeatIntervalSeconds = heartbeat;
        TunnelOptions.ProbeIntervalSeconds = probe;
        TunnelOptions.StaleTimeoutSeconds = staleTimeout;
        TunnelOptions.RepairCooldownSeconds = repairCooldown;
        TunnelOptions.DeadThreshold = deadThreshold;
        TunnelOptions.GracePeriodSecondsNonSymmetric = gracePeriod;
        TunnelOptions.GracePeriodSecondsSymmetric = gracePeriodSym;
        TunnelOptions.IsolationGracePeriodSeconds = isolationGrace;

        // Save all settings to config.toml
        try
        {
            Config.SaveAllSettings(
                MediationEndpointBox.Text,
                NetworkIDBox.Text,
                NetworkSecretBox.Password,
                MeshSubnetBox.Text,
                heartbeat, probe, staleTimeout, repairCooldown,
                deadThreshold, gracePeriod, gracePeriodSym, isolationGrace);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save config: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        // Check if network settings changed (requires reconnect)
        bool needsReconnect =
            MediationEndpointBox.Text != originalMediationEndpoint ||
            NetworkIDBox.Text != originalNetworkID ||
            NetworkSecretBox.Password != originalNetworkSecret ||
            MeshSubnetBox.Text != originalMeshSubnet;

        if (needsReconnect)
        {
            var result = MessageBox.Show(
                "Network settings have changed. A reconnect is required for these to take effect.\n\nReconnect now?",
                "Settings Changed",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                // Reload config so TunnelOptions picks up the new network settings
                Config.TryLoadConfig();
                await TriggerReconnect();
            }
        }

        Close();
    }

    private static async Task TriggerReconnect()
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        try
        {
            await client.PostAsync("http://localhost:51889/disconnect", null);
            await Task.Delay(500);
            await client.PostAsync("http://localhost:51889/connect", null);
        }
        catch
        {
            // Engine not running — settings will apply on next start
        }
    }

    private static bool TryParsePositiveInt(string text, string fieldName, out int value)
    {
        if (!int.TryParse(text, out value) || value <= 0)
        {
            MessageBox.Show($"{fieldName} must be a positive integer.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            value = 0;
            return false;
        }
        return true;
    }
}
