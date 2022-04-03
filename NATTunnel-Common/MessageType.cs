namespace NATTunnel.Common
{
    public enum MessageType
    {
        //HEARTBEAT is not used, ACKs do the job of keeping the UDP connection alive
        HEARTBEAT = 0,
        DISCONNECT = 1,
        NEW_CONNECTION_REQUEST = 10,
        NEW_CONNECTION_REPLY = 11,
        PING_REQUEST = 20,
        PING_REPLY = 21,
        DATA = 30,
        ACK = 31
    }
}