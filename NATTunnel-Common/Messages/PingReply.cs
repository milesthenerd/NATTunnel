using System;
using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.PING_REPLY)]
    public class PingReply : NodeMessage
    {
        public long sendTime;
        public string ep;

        public PingReply()
        {
            Id = 0;
            sendTime = 0;
            ep = "";
        }

        public PingReply(int id, long sendTime, string ep)
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