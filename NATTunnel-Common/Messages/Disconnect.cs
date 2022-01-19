using System;
using System.IO;

namespace NATTunnel.Common.Messages
{
    /// <summary>
    /// Class to signal a disconnect.
    /// </summary>
    [MessageTypeAttribute(MessageType.DISCONNECT)]
    public class Disconnect : NodeMessage
    {
        /// <summary>
        /// The reason for this disconnect.
        /// </summary>
        public string Reason { get; private set; }

        /// <summary>
        /// The endpoint.
        /// </summary>
        public string Endpoint { get; private set; } // TODO: source or destination???

        public Disconnect()
        {
            Id = 0;
            Reason = "";
            Endpoint = "";
        }

        public Disconnect(int id, string reason, string endpoint)
        {
            Id = id;
            Reason = reason;
            Endpoint = endpoint;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(Reason);
            writer.Write(Endpoint);
        }

        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            Reason = reader.ReadString();
            Endpoint = reader.ReadString();
        }
    }
}