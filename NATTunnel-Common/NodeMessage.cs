using System.IO;

namespace NATTunnel.Common;

public abstract class NodeMessage : IMessage
{
    public int Id;
    public abstract void Deserialize(BinaryReader reader);
    public abstract void Serialize(BinaryWriter writer);
}