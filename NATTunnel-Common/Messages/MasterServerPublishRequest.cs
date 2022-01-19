using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.MASTER_SERVER_PUBLISH_REQUEST)]
    public class MasterServerPublishRequest : NodeMessage
    {
        public int secret;
        public int localPort;

        public MasterServerPublishRequest()
        {
            Id = 0;
            secret = 0;
            localPort = 0;
        }

        public MasterServerPublishRequest(int id, int secret, int localPort)
        {
            this.Id = id;
            this.secret = secret;
            this.localPort = localPort;
        }

        public void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(secret);
            writer.Write(localPort);
        }
        public void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            secret = reader.ReadInt32();
            localPort = reader.ReadInt32();
        }
    }
}