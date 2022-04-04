using System;
using System.IO;

namespace NATTunnel.Common.Messages.Types;

// TODO: documentation
[MessageType(MessageType.Data)]
public class Data : NodeMessage
{
    public long StreamPos { get; private set; }
    public long StreamAck { get; private set; }
    public byte[] TCPData { get; private set; }

    /// <summary>
    /// The endpoint.
    /// </summary>
    public string Endpoint { get; private set; }

    // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
    // ReSharper disable once UnusedMember.Global
    public Data() : this(0, 0, 0, Array.Empty<byte>(), "") { }

    public Data(int id, long streamPos, long streamAck, byte[] tcpData, string endpoint)
    {
        Id = id;
        StreamPos = streamPos;
        StreamAck = streamAck;
        TCPData = tcpData;
        Endpoint = endpoint;
    }

    public override void Serialize(BinaryWriter writer)
    {
        writer.Write(Id);
        writer.Write(StreamPos);
        writer.Write(StreamAck);
        writer.Write((short)TCPData.Length);
        writer.Write(TCPData);
        writer.Write(Endpoint);
    }
    public override void Deserialize(BinaryReader reader)
    {
        Id = reader.ReadInt32();
        StreamPos = reader.ReadInt64();
        StreamAck = reader.ReadInt64();
        int length = reader.ReadInt16();
        TCPData = reader.ReadBytes(length);
        Endpoint = reader.ReadString();
    }
}