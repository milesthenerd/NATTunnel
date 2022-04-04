using System.IO;

namespace NATTunnel.Common.Messages
{
    /// <summary>
    /// Class for data acknowledgement.
    /// </summary>
    [MessageTypeAttribute(MessageType.Ack)]
    public class Ack : NodeMessage
    {
        // TODO: Documentation
        public long StreamAck { get; private set; }

        /// <summary>
        /// The endpoint.
        /// </summary>
        public string Endpoint { get; private set; }

        // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
        public Ack() : this(0, 0, "") { }

        public Ack(int id, long streamAck, string endpoint)
        {
            Id = id;
            StreamAck = streamAck;
            Endpoint = endpoint;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(StreamAck);
            writer.Write(Endpoint);
        }

        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            StreamAck = reader.ReadInt64();
            Endpoint = reader.ReadString();
        }
    }
}