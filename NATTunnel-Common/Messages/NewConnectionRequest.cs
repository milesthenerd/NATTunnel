using System;
using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.NEW_CONNECTION_REQUEST)]
    public class NewConnectionRequest : NodeMessage
    {
        public int protocol_version;
        public int downloadRate;
        public string ep;

        public NewConnectionRequest()
        {
            Id = 0;
            protocol_version = 0;
            downloadRate = 0;
            ep = "";
        }

        public NewConnectionRequest(int id, int protocol_version, int downloadRate, string ep)
        {
            this.Id = id;
            this.protocol_version = protocol_version;
            this.downloadRate = downloadRate;
            this.ep = ep;
        }
        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(protocol_version);
            writer.Write(downloadRate);
            writer.Write(ep);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            protocol_version = reader.ReadInt32();
            downloadRate = reader.ReadInt32();
            ep = reader.ReadString();
        }
    }
}