using System.IO;

namespace NATTunnel.Common.Messages
{
    /// <summary>
    /// Class for responding to a <see cref="NewConnectionRequest"/>.
    /// </summary>
    [MessageTypeAttribute(MessageType.NEW_CONNECTION_REPLY)]
    public class NewConnectionReply : NodeMessage
    {
        /// <summary>
        /// The protocol version.
        /// </summary>
        public int ProtocolVersion { get; private set; } = Header.PROTOCOL_VERSION;

        /// <summary>
        /// The maximum acceptable download rate in kB per second.
        /// </summary>
        public int DownloadRate { get; private set; } = NodeOptions.downloadSpeed;

        /// <summary>
        /// The endpoint.
        /// </summary>
        public string Endpoint { get; private set; } // TODO: Source or destination? Also, unused?

        public NewConnectionReply()
        {
            Id = 0;
            Endpoint = "";
        }

        public NewConnectionReply(int id, string endpoint = "")
        {
            this.Id = id;
            this.Endpoint = endpoint;
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(Id);
            writer.Write(ProtocolVersion);
            writer.Write(DownloadRate);
            writer.Write(Endpoint);
        }

        public override void Deserialize(BinaryReader reader)
        {
            Id = reader.ReadInt32();
            ProtocolVersion = reader.ReadInt32();
            DownloadRate = reader.ReadInt32();
            Endpoint = reader.ReadString();
        }
    }
}