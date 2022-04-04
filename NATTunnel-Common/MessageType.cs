namespace NATTunnel.Common;

public enum MessageType
{
    //"heartbeat" is not used, "Ack"s do the job of keeping the UDP connection alive
    //TODO remove then?
    Heartbeat = 0,
    Disconnect = 1,
    NewConnectionRequest = 10,
    NewConnectionReply = 11,
    PingRequest = 20,
    PingReply = 21,
    Data = 30,
    Ack = 31
}