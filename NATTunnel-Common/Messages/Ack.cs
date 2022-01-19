using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.ACK)]
    public class Ack : NodeMessage
    {
        public long streamAck;
        public string ep;

        public Ack()
        {
            Id = 0;
            streamAck = 0;
            ep = "";
        }

        public Ack(int id, long streamAck, string ep)
        {
            this.Id = id;
            this.streamAck = streamAck;
            this.ep = ep;
        }

        public int GetID()
        {
            return Id;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(streamAck);
            writer.Write(ep);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            streamAck = reader.ReadInt64();
            ep = reader.ReadString();
        }
    }
}