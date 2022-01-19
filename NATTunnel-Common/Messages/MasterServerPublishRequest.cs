using System.IO;

namespace NATTunnel.Common.Messages
{
    // TODO: Documentation
    [MessageTypeAttribute(MessageType.MASTER_SERVER_PUBLISH_REQUEST)]
    public class MasterServerPublishRequest : NodeMessage
    {
        public int Secret { get; private set; }
        public int LocalPort { get; private set; } //TODO: unused?

        // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
        public MasterServerPublishRequest() : this(0, 0, 0) { }

        public MasterServerPublishRequest(int id, int secret, int localPort)
        {
            Id = id;
            Secret = secret;
            LocalPort = localPort;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(Secret);
            writer.Write(LocalPort);
        }

        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            Secret = reader.ReadInt32();
            LocalPort = reader.ReadInt32();
        }
    }
}