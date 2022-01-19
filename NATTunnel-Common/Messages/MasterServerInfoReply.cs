using System.Collections.Generic;
using System.IO;
using System.Net;

namespace NATTunnel.Common.Messages
{
    // TODO: Documentation
    [MessageTypeAttribute(MessageType.MASTER_SERVER_INFO_REPLY)]
    public class MasterServerInfoReply : IMessage
    {
        /// <summary>
        /// The ID of the server for this reply.
        /// </summary>
        public int Server { get; private set; }

        /// <summary>
        /// The ID of the server for this reply.
        /// </summary>
        public int Client { get; private set; }

        public bool Status { get; private set; }

        /// <summary>
        /// The message for this reply.
        /// </summary>
        public string Message { get; private set; }
        
        /// <summary>
        /// The list of <see cref="IPEndPoint"/>s for this reply.
        /// </summary>
        public List<IPEndPoint> Endpoints { get; private set; }

        public MasterServerInfoReply()
        {
            Server = 0;
            Client = 0;
            Status = false;
            Message = "";
            Endpoints = new List<IPEndPoint>();
        }

        public MasterServerInfoReply(int server, int client, bool status, string message) : this(server, client, status, message, new List<IPEndPoint>()) { }

        public MasterServerInfoReply(int server, int client, bool status, string message, List<IPEndPoint> endpoints)
        {
            Server = server;
            Client = client;
            Status = status;
            Message = message;
            Endpoints = endpoints;
        }

        public void Serialize(BinaryWriter writer)
        {
            writer.Write(Server);
            writer.Write(Client);
            writer.Write(Status);
            writer.Write(Message);
            writer.Write(Endpoints.Count);

            // Serialize the endpoints list
            foreach (IPEndPoint endpoint in Endpoints)
            {
                writer.Write(endpoint.Address.ToString());
                writer.Write(endpoint.Port);
            }
        }

        public void Deserialize(BinaryReader reader)
        {
            Endpoints.Clear();
            Server = reader.ReadInt32();
            Client = reader.ReadInt32();
            Status = reader.ReadBoolean();
            Message = reader.ReadString();
            int endpointNum = reader.ReadInt32();

            // Deserialize the endpoints list
            for (int i = 0; i < endpointNum; i++)
            {
                IPAddress address = IPAddress.Parse(reader.ReadString());
                int port = reader.ReadInt32();
                IPEndPoint endpoint = new IPEndPoint(address, port);
                Endpoints.Add(endpoint);
            }
        }
    }
}