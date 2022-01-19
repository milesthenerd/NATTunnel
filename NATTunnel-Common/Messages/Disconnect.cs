using System;
using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.DISCONNECT)]
    public class Disconnect : NodeMessage
    {
        public string reason;
        public string ep;

        public Disconnect()
        {
            Id = 0;
            reason = "";
            ep = "";
        }

        public Disconnect(int id, string reason, string ep)
        {
            this.Id = id;
            this.reason = reason;
            this.ep = ep;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(reason);
            writer.Write(ep);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            reason = reader.ReadString();
            ep = reader.ReadString();
        }
    }
}