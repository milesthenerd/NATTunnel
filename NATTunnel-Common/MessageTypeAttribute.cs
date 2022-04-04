using System;

namespace NATTunnel.Common
{
    public class MessageTypeAttribute : Attribute
    {
        public MessageType Type;
        public MessageTypeAttribute(MessageType type)
        {
            Type = type;
        }
    }
}
