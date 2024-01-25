using System.Net;
using System.Security.Cryptography;

namespace NATTunnel;

public class IPFragment
{
    public byte[] Bytes;
    public byte[] ID;
    public byte[] Offset;
    public byte[] MoreFragments;

    public IPFragment(byte[] bytes, byte[] id, byte[] offset, byte[] moreFragments)
    {
        Bytes = bytes;
        ID = id;
        Offset = offset;
        MoreFragments = moreFragments;
    }
}