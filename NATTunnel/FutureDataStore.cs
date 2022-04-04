using NATTunnel.Common.Messages;
using System.Collections.Generic;

namespace NATTunnel
{
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

        public Data GetData(long currentRecvPos)
        {
            //Deletes all data from the past
            SetReceivePos(currentRecvPos);

            if (futureData.Count <= 0) return null;

            Data candidate = futureData.Values[0];
            if (candidate.StreamPos > currentRecvPos) return null;

            //We have current data!
            futureData.Remove(candidate.StreamPos);
            return candidate;
        }

        private void SetReceivePos(long currentRecvPos)
        {
            while (futureData.Count > 0)
            {
                Data d = futureData.Values[0];
                if ((d.StreamPos + d.TCPData.Length) <= currentRecvPos)
                    futureData.Remove(d.StreamPos);
                else
                    return;
            }
        }
    }
}