using System;

namespace NATTunnel.Common
{
    public class MessageTypeAttribute : Attribute
    {
        public readonly MessageType Type;
        public MessageTypeAttribute(MessageType type)
        {
            Type = type;
        }
    }
}
