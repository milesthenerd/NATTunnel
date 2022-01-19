using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.MASTER_PRINT_CONSOLE)]
    public class PrintConsole : NodeMessage
    {
        public string message;

        public int GetID()
        {
            return Id;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(message);
        }
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            message = reader.ReadString();
        }
    }
}