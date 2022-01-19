using System.IO;

namespace NATTunnel.Common.Messages
{
    /// <summary>
    /// Class for encapsulating messages between tunnel clients.
    /// </summary>
    [MessageTypeAttribute(MessageType.MASTER_PRINT_CONSOLE)]
    public class PrintConsole : NodeMessage
    {
        /// <summary>
        /// The message to be sent/received.
        /// </summary>
        public string message;
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