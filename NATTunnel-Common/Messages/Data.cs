using System;
using System.IO;

namespace NATTunnel.Common.Messages
{
    // TODO: documentation
    [MessageTypeAttribute(MessageType.DATA)]
    public class Data : NodeMessage
    {
        public long StreamPos { get; private set; }
        public long StreamAck { get; private set; }
        public byte[] TCPData { get; private set; }
        public string Endpoint { get; private set; }

        public Data()
        {
            Id = 0;
            StreamPos = 0;
            StreamAck = 0;
            TCPData = Array.Empty<byte>();
            Endpoint = "";
        }

        public Data(int id, long streamPos, long streamAck, byte[] TCPData, string endpoint)
        {
            Id = id;
            StreamPos = streamPos;
            StreamAck = streamAck;
            this.TCPData = TCPData;
            Endpoint = endpoint;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(StreamPos);
            writer.Write(StreamAck);
            writer.Write((short)TCPData.Length);
            writer.Write(TCPData);
            writer.Write(Endpoint);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            StreamPos = reader.ReadInt64();
            StreamAck = reader.ReadInt64();
            int length = reader.ReadInt16();
            TCPData = reader.ReadBytes(length);
            Endpoint = reader.ReadString();
        }
    }
}