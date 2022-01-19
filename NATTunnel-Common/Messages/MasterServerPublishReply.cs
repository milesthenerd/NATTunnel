using System.IO;

namespace NATTunnel.Common.Messages
{
    // TODO: Documentation
    [MessageTypeAttribute(MessageType.MASTER_SERVER_PUBLISH_REPLY)]
    public class MasterServerPublishReply : NodeMessage
    {
        // TODO: why is status a boolean!?
        public bool Status { get; private set; }
        public string Message { get; private set; }

        // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
        public MasterServerPublishReply() : this(0, false, "") { }

        public MasterServerPublishReply(int id, bool status, string message)
        {
            Id = id;
            Status = status;
            Message = message;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(Status);
            writer.Write(Message);
        }

        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            Status = reader.ReadBoolean();
            Message = reader.ReadString();
        }
    }
}