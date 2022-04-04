using System.IO;

namespace NATTunnel.Common.Messages.Types;

/// <summary>
/// Class for responding to a <see cref="PingRequest"/>.
/// </summary>
[MessageType(MessageType.PingReply)]
public class PingReply : NodeMessage
{
    /// <summary>
    /// The time this <see cref="PingReply"/> was sent.
    /// </summary>
    public long SendTime { get; private set; }

    /// <summary>
    /// The endpoint of this <see cref="PingReply"/>.
    /// </summary>
    public string Endpoint { get; private set; } // TODO: Origin or target? Also TODO: Never used?

    // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
    // ReSharper disable once UnusedMember.Global
    public PingReply() : this(0, 0, "") { }

    public PingReply(int id, long sendTime, string endpoint)
    {
        Id = id;
        SendTime = sendTime;
        Endpoint = endpoint;
    }

    public override void Serialize(BinaryWriter writer)
    {
        writer.Write(Id);
        writer.Write(SendTime);
        writer.Write(Endpoint);
    }

    public override void Deserialize(BinaryReader reader)
    {
        Id = reader.ReadInt32();
        SendTime = reader.ReadInt64();
        Endpoint = reader.ReadString();
    }
}