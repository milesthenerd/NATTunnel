using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.DATA)]
    public class Data : NodeMessage
    {
        public long streamPos;
        public long streamAck;
        public byte[] tcpData;
        public string ep;

        public Data()
        {
            Id = 0;
            streamAck = 0;
            ep = "";
        }

        public Data(int id, long streamPos, long streamAck, byte[] tcpData, string ep)
        {
            this.Id = id;
            this.streamPos = streamPos;
            this.streamAck = streamAck;
            this.tcpData = tcpData;
            this.ep = ep;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(streamPos);
            writer.Write(streamAck);
            writer.Write((short)tcpData.Length);
            writer.Write(tcpData);
            writer.Write(ep);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            streamPos = reader.ReadInt64();
            streamAck = reader.ReadInt64();
            int length = reader.ReadInt16();
            tcpData = reader.ReadBytes(length);
            ep = reader.ReadString();
        }
    }
}