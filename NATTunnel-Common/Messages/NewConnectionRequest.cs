using System.IO;

namespace NATTunnel.Common.Messages
{
    [MessageTypeAttribute(MessageType.NEW_CONNECTION_REQUEST)]
    public class NewConnectionRequest : NodeMessage
    {
        /// <summary>
        /// The protocol version of this <see cref="NewConnectionRequest"/>.
        /// </summary>
        public int ProtocolVersion { get; private set; } = Header.PROTOCOL_VERSION;

        /// <summary>
        /// The maximum acceptable download rate in kB per second.
        /// </summary>
        public int DownloadRate { get; private set; } = NodeOptions.downloadSpeed; // TODO: Load directly from config instead of waiting for instantiation?

        /// <summary>
        /// The endpoint of this <see cref="NewConnectionRequest"/>.
        /// </summary>
        public string Endpoint { get; private set; } // TODO: Source or destination?

        public NewConnectionRequest()
        {
            Id = 0;
            DownloadRate = 0;
            Endpoint = "";
        }

        public NewConnectionRequest(int id, int downloadRate, string ep)
        {
            this.Id = id;
            this.DownloadRate = downloadRate;
            this.Endpoint = ep;
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