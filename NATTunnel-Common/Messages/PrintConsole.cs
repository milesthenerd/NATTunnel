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
        public string Message { get; private set; }
        
        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(Message);
        }
        
        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            Message = reader.ReadString();
        }
    }
}