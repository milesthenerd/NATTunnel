namespace NATTunnel.Common;

//Class for the messages sent to and received from the mediation server
public class MediationMessage
{
    public MediationMessageType ID { get; set; }
    public int LocalPort { get; set; }
    public NATType NATType { get; set; }
    public MediationMessage(MediationMessageType id, int localPort=0)
    {
        ID = id;
        LocalPort = localPort;
    }
}

//Different message types sent from the mediation server
public enum MediationMessageType
{
    //Successful TCP connection to the mediation server
    Connected = 0,
    //Request mediation server for NAT type
    NATTypeRequest = 1,
    //Response from server permitting client to begin NAT test
    NATTestBegin = 2,
    //Packet sent during NAT test
    NATTest = 3,
    //Response from the mediation server with the discovered NAT type
    NATTypeResponse = 4
}

//Different NAT types that can be returned by the mediation server
public enum NATType
{
    //Before the type is defined
    Unknown = -1,
    //The NAT is either non-existant or a one-to-one mapping (easy to work with)
    DirectMapping = 0,
    //The NAT is either address or address + port restricted (slightly harder to work with but doable)
    Restricted = 1,
    //The NAT is symmetric (doable in combination with either of the above two NAT types)
    Symmetric = 2
}