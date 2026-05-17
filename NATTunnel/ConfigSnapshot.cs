using System.Text.Json.Serialization;

namespace NATTunnel;

/// <summary>JSON-serializable snapshot of editable TunnelOptions, served by GET/POST /config.</summary>
public class ConfigSnapshot
{
    [JsonPropertyName("mediationEndpoint")]
    public string MediationEndpoint { get; set; }

    [JsonPropertyName("networkID")]
    public string NetworkID { get; set; }

    [JsonPropertyName("networkSecret")]
    public string NetworkSecret { get; set; }

    [JsonPropertyName("meshSubnet")]
    public string MeshSubnet { get; set; }

    [JsonPropertyName("heartbeatIntervalSeconds")]
    public int HeartbeatIntervalSeconds { get; set; }

    [JsonPropertyName("probeIntervalSeconds")]
    public int ProbeIntervalSeconds { get; set; }

    [JsonPropertyName("staleTimeoutSeconds")]
    public int StaleTimeoutSeconds { get; set; }

    [JsonPropertyName("repairCooldownSeconds")]
    public int RepairCooldownSeconds { get; set; }

    [JsonPropertyName("deadThreshold")]
    public int DeadThreshold { get; set; }

    [JsonPropertyName("gracePeriodSecondsNonSymmetric")]
    public int GracePeriodSecondsNonSymmetric { get; set; }

    [JsonPropertyName("gracePeriodSecondsSymmetric")]
    public int GracePeriodSecondsSymmetric { get; set; }

    [JsonPropertyName("isolationGracePeriodSeconds")]
    public int IsolationGracePeriodSeconds { get; set; }

    [JsonPropertyName("peerID")]
    public string PeerID { get; set; }
}
