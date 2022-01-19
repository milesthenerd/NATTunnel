using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.PING_REQUEST)]
    public class PingRequest : NodeMessage
    {
        public long sendTime;
        public string ep;

        public PingRequest()
        {
            Id = 0;
            sendTime = 0;
            ep = "";
        }

        public PingRequest(int id, long sendTime, string ep)
        {
            this.Id = id;
            this.sendTime = sendTime;
            this.ep = ep;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(sendTime);
            writer.Write(ep);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            sendTime = reader.ReadInt64();
            ep = reader.ReadString();
        }
    }
}