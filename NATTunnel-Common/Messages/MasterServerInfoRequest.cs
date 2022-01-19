using System.IO;

namespace NATTunnel.Common.Messages
{
    // TODO: Documentation
    [MessageTypeAttribute(MessageType.MASTER_SERVER_INFO_REQUEST)]
    public class MasterServerInfoRequest : IMessage
    {
        /// <summary>
        /// The ID of the server for this request.
        /// </summary>
        public int Server { get; private set; }

        /// <summary>
        /// The ID of the client for this request.
        /// </summary>
        public int Client { get; private set; }

        public MasterServerInfoRequest()
        {
            Server = 0;
            Client = 0;
        }

        public MasterServerInfoRequest(int server = 0, int client = 0)
        {
            Server = server;
            Client = client;
        }

        public void Serialize(BinaryWriter writer)
        {
            writer.Write(Server);
            writer.Write(Client);
        }

        public void Deserialize(BinaryReader reader)
        {
            Server = reader.ReadInt32();
            Client = reader.ReadInt32();
        }
    }
}