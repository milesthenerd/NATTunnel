using System;
using System.IO;

namespace NATTunnel.Common.Messages.Types;

// TODO: documentation
[MessageType(MessageType.PassthroughData)]
public class PassthroughData : NodeMessage
{
    public byte[] UDPPassthroughData { get; private set; }

    /// <summary>
    /// The endpoint.
    /// </summary>
    public string Endpoint { get; private set; }

    // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
    // ReSharper disable once UnusedMember.Global
    public PassthroughData() : this(0, Array.Empty<byte>(), "") { }

    public PassthroughData(int id, byte[] udpPassthroughData, string endpoint)
    {
        Id = id;
        UDPPassthroughData = UDPPassthroughData;
        Endpoint = endpoint;
    }

    public override void Serialize(BinaryWriter writer)
    {
        writer.Write(Id);
        writer.Write((short)UDPPassthroughData.Length);
        writer.Write(UDPPassthroughData);
        writer.Write(Endpoint);
    }
    public override void Deserialize(BinaryReader reader)
    {
        Id = reader.ReadInt32();
        int length = reader.ReadInt16();
        UDPPassthroughData = reader.ReadBytes(length);
        Endpoint = reader.ReadString();
    }
}