using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NATTunnel.Common;

/// <summary>
///Class for the messages sent to and received from the mediation server
/// </summary>
public class MediationMessage
{
    /// <summary>
    ///Message type ID
    /// </summary>
    public MediationMessageType ID { get; set; }
    /// <summary>
    ///Local port of the client's udp socket
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int LocalPort { get; set; }
    /// <summary>
    ///NAT type of the client
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public NATType NATType { get; set; }
    /// <summary>
    ///Server's IP address and port as a string becaause IPEndpoint is not deserializable
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string EndpointString { get; set; }
    public MediationMessage(MediationMessageType id)
    {
        ID = id;
    }

    public string Serialize()
    {
        return JsonSerializer.Serialize<MediationMessage>(this);
    }

    public IPEndPoint GetEndpoint()
    {
        return IPEndPoint.Parse(EndpointString);
    }

    public void SetEndpoint(IPEndPoint serverEndpoint)
    {
        EndpointString = serverEndpoint.ToString();
    }
}
/// <summary>
///Different message types sent from the mediation server
/// </summary>
public enum MediationMessageType
{
    /// <summary>
    ///Successful TCP connection to the mediation server
    /// </summary>
    Connected,
    /// <summary>
    ///Request mediation server for NAT type
    /// </summary>
    NATTypeRequest,
    /// <summary>
    ///Response from server permitting client to begin NAT test
    /// </summary>
    NATTestBegin,
    /// <summary>
    ///Packet sent during NAT test
    /// </summary>
    NATTest,
    /// <summary>
    ///Response from the mediation server with the discovered NAT type
    /// </summary>
    NATTypeResponse,
    /// <summary>
    ///Packet type to keep the udp connection alive
    /// </summary>
    KeepAlive,
    /// <summary>
    ///Request from a NATTunnel client to begin a connection attempt with a NATTunnel server
    /// </summary>
    ConnectionRequest,
    /// <summary>
    ///Reponse from the mediation server to begin a connection attempt with a NATTunnel server
    /// </summary>
    ConnectionBegin,
    /// <summary>
    ///Response from the mediation server stating that the specified NATTunnel server is not available
    /// </summary>
    ServerNotAvailable,
    /// <summary>
    ///Packet sent during hole punch attempts
    /// </summary>
    HolePunchAttempt
}

/// <summary>
/// Different NAT types that can be returned by the mediation server
/// </summary>
public enum NATType
{
    /// <summary>
    ///The NAT is either non-existant or a one-to-one mapping (easy to work with)
    /// </summary>
    DirectMapping,
    /// <summary>
    ///The NAT is either address or address + port restricted (slightly harder to work with but doable)
    /// </summary>
    Restricted,
    /// <summary>
    ///The NAT is symmetric (doable in combination with either of the above two NAT types)
    /// </summary>
    Symmetric,
    /// <summary>
    ///Before the type is defined
    /// </summary>
    Unknown = -1
}