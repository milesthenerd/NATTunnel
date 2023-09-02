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
    /// <summary>
    ///NATTunnel data included within the packet
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] Data { get; set; }
    /// <summary>
    ///First port for nat type detection returned by the server
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int NATTestPortOne { get; set; }
    /// <summary>
    ///Second port for nat type detection returned by the server
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int NATTestPortTwo { get; set; }
    /// <summary>
    ///ID assigned to a server/client pair attempting to make a connection
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int ConnectionID { get; set; }
    /// <summary>
    ///Whether or not the peer sending the packet is a NATTunnel server
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsServer { get; set; }
    /// <summary>
    ///The private IP of a client
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string PrivateAddressString { get; set; }
    /// <summary>
    ///Public key modulus
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] Modulus { get; set; }
    /// <summary>
    ///Public key exponent
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] Exponent { get; set; }
    /// <summary>
    ///Symmetric key
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] SymmetricKey { get; set; }
    /// <summary>
    ///One-time use value
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] Nonce { get; set; }
    /// <summary>
    ///Authentication tag generated when encrypting with AES-GCM
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] ModulusHash { get; set; }
    /// <summary>
    ///SHA256 hash to verify that public key modulus is intact after being transported
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] ExponentHash { get; set; }
    /// <summary>
    ///SHA256 hash to verify that public key exponent is intact after being transported
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] SymmetricKeyHash { get; set; }
    /// <summary>
    ///SHA256 hash to verify that symmetric key is intact after being transported
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public byte[] AuthTag { get; set; }
    public MediationMessage(MediationMessageType id)
    {
        ID = id;
    }

    /// <summary>
    ///Serializes the message
    /// </summary>
    public string Serialize()
    {
        return JsonSerializer.Serialize<MediationMessage>(this);
    }

    /// <summary>
    ///Converts the endpoint string to an IPEndPoint and returns it
    /// </summary>
    public IPEndPoint GetEndpoint()
    {
        return IPEndPoint.Parse(EndpointString);
    }

    /// <summary>
    ///Converts an IPEndPoint to a string and sets the endpoint string to it
    /// </summary>
    public void SetEndpoint(IPEndPoint serverEndpoint)
    {
        EndpointString = serverEndpoint.ToString();
    }

    /// <summary>
    ///Converts the private address string to an IPAddress and returns it
    /// </summary>
    public IPAddress GetPrivateAddress()
    {
        return IPAddress.Parse(PrivateAddressString);
    }

    /// <summary>
    ///Converts an IPAddress to a string and sets the private address string to it
    /// </summary>
    public void SetPrivateAddress(IPAddress privateAddress)
    {
        PrivateAddressString = privateAddress.ToString();
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
    HolePunchAttempt,
    /// <summary>
    ///Packet sent for normal NATTunnel data between clients and servers
    /// </summary>
    NATTunnelData,
    /// <summary>
    ///Packet sent during symmetric NAT hole punch attempts
    /// </summary>
    SymmetricHolePunchAttempt,
    /// <summary>
    ///Packet sent indicating NATTunnel client/server pair have reached each other
    /// </summary>
    ConnectionComplete,
    /// <summary>
    ///Packet sent indicating NATTunnel client/server received from peer
    /// </summary>
    ReceivedPeer,
    /// <summary>
    ///Packet sent to timeout connection attempt after failed communication
    /// </summary>
    ConnectionTimeout,
    /// <summary>
    ///Packet sent to peer requesting public key
    /// </summary>
    PublicKeyRequest,
    /// <summary>
    ///Packet sent to peer containing public key
    /// </summary>
    PublicKeyResponse,
    /// <summary>
    ///Encrypted packet sent to peer requesting symmetric key
    /// </summary>
    SymmetricKeyRequest,
    /// <summary>
    ///Encrypted packet sent to peer containing symmetric key
    /// </summary>
    SymmetricKeyResponse,
    /// <summary>
    ///Packet sent to confirm server received client's symmetric key
    /// </summary>
    SymmetricKeyConfirm
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