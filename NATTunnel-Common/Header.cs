using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using NATTunnel.Common.Messages;

//This class is currently not thread safe.

namespace NATTunnel.Common;

public static class Header
{
    public const int PROTOCOL_VERSION = 1;
    private static bool loaded = false;
    private static readonly Dictionary<MessageType, Type> messageTypeToType = new Dictionary<MessageType, Type>();
    private static readonly Dictionary<Type, MessageType> typeToMessageType = new Dictionary<Type, MessageType>();
    private static readonly byte[] buildBytes = new byte[1496];
    private static readonly byte[] sendBytes = new byte[1500];

    public static byte[] FrameMessage(IMessage message)
    {
        if (!loaded)
        {
            loaded = true;
            Load();
        }

        using MemoryStream memoryStream = new MemoryStream(buildBytes);
        //TODO: why leave the stream open?
        using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream, System.Text.Encoding.UTF8, true))
            message.Serialize(binaryWriter);

        short type = (short)typeToMessageType[message.GetType()];
        short length = (short)memoryStream.Position;
        BitConverter.GetBytes(type).CopyTo(sendBytes, 4);
        BitConverter.GetBytes(length).CopyTo(sendBytes, 6);
        if (length > 0)
            Array.Copy(buildBytes, 0, sendBytes, 8, length);
        return sendBytes;
    }

    public static IMessage DeframeMessage(BinaryReader br)
    {
        if (!loaded)
        {
            loaded = true;
            Load();
        }
        if (br.ReadByte() != 'D' || br.ReadByte() != 'T' || br.ReadByte() != '0' || br.ReadByte() != '1')
            return null;

        short type = br.ReadInt16();
        short length = br.ReadInt16();

        if (!Enum.IsDefined(typeof(MessageType), (int)type) || (length != (br.BaseStream.Length - 8)))
            return null;

        Type messageType = messageTypeToType[(MessageType)type];
        IMessage message = (IMessage)Activator.CreateInstance(messageType);
        if ((message != null) && (length > 0))
            message.Deserialize(br);

        return message;
    }

    public static void Load()
    {
        //Only need to write this once
        sendBytes[0] = (byte)'D';
        sendBytes[1] = (byte)'T';
        sendBytes[2] = (byte)'0';
        sendBytes[3] = (byte)'1';

        //Find all message types
        foreach (Type t in Assembly.GetExecutingAssembly().GetExportedTypes())
        {
            MessageTypeAttribute mta = t.GetCustomAttribute<MessageTypeAttribute>();
            if (mta == null)
                continue;
            typeToMessageType[t] = mta.Type;
            messageTypeToType[mta.Type] = t;
        }
    }
}