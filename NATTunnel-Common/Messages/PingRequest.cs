using System.IO;

namespace NATTunnel.Common.Messages;

/// <summary>
/// Class for requesting a <see cref="PingReply"/>.
/// </summary>
[MessageTypeAttribute(MessageType.PingRequest)]
public class PingRequest : NodeMessage
{
    /// <summary>
    /// The time this <see cref="PingRequest"/> was sent.
    /// </summary>
    public long SendTime { get; private set; }

    /// <summary>
    /// The endpoint of this <see cref="PingRequest"/>.
    /// </summary>
    public string Endpoint { get; private set; } // TODO: Is this origin or target???  Also TODO: Never used?

    // Base constructor is called in Header.DeframeMessage() via Activator.CreateInstance
    // ReSharper disable once UnusedMember.Global
    public PingRequest() : this(0, 0, "") { }

    public PingRequest(int id, long sendTime, string endpoint)
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