using System.Collections.Generic;
using NATTunnel.Common.Messages.Types;

namespace NATTunnel;

public class FutureDataStore
{
    private readonly SortedList<long, Data> futureData = new SortedList<long, Data>();

    public void StoreData(Data d)
    {
        if (!futureData.ContainsKey(d.StreamPos))
        {
            futureData.Add(d.StreamPos, d);
        }
        else
        {
            Data test = futureData[d.StreamPos];
            if (d.TCPData.Length > test.TCPData.Length)
                futureData[d.StreamPos] = d;
        }
    }

    public Data GetData(long currentReceivedPosition)
    {
        //Deletes all data from the past
        SetReceivePos(currentReceivedPosition);

        if (futureData.Count <= 0) return null;

        Data candidate = futureData.Values[0];
        if (candidate.StreamPos > currentReceivedPosition) return null;

        //We have current data!
        futureData.Remove(candidate.StreamPos);
        return candidate;
    }

    private void SetReceivePos(long currentReceivedPosition)
    {
        while (futureData.Count > 0)
        {
            Data d = futureData.Values[0];
            if ((d.StreamPos + d.TCPData.Length) <= currentReceivedPosition)
                futureData.Remove(d.StreamPos);
            else
                return;
        }
    }
}