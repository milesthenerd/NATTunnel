using NATTunnel.Common;
using NATTunnel.Common.Messages;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using NATTunnel.Common.Messages.Types;

namespace NATTunnel;

public class Client
{
    public bool Connected = true;
    public readonly int Id;
    public long LastUdpRecvTime = DateTime.UtcNow.Ticks;
    //TODO: assigned but not used. Safe to be removed?
    public long LastUdpSendTime;
    public long LastUdpPingTime;
    public long LastUdpSendAckTime;
    public TcpClient TCPClient;
    public IPEndPoint UdpEndpoint;
    public readonly byte[] Buffer = new byte[1500];
    public readonly StreamRingBuffer TxQueue = new StreamRingBuffer(16 * 1024 * 1024);
    public readonly FutureDataStore FutureDataStore = new FutureDataStore();
    public readonly TokenBucket Bucket;
    private long currentRecvPos;
    private long currentSendPos;
    private long lastWriteResetTime;
    private long lastUdpRecvAckTime;
    private const long TIMEOUT = 10 * TimeSpan.TicksPerSecond;
    private const long PING = 2 * TimeSpan.TicksPerSecond;
    private const long ACK_TIME = 10 * TimeSpan.TicksPerMillisecond;
    private readonly UdpConnection UDPConnection;
    private long ackSafe;
    private Thread clientThread;
    public readonly AutoResetEvent SendEvent = new AutoResetEvent(false);
    public int Latency;
    public readonly IPEndPoint LocalTcpEndpoint;
    public readonly IPEndPoint PassthroughLocalUDPEndpoint;
    public readonly UdpConnection UDPPassthroughConnection;

    public Client(int clientID, UdpConnection udpConnection, UdpConnection udpPassthroughConnection, Socket udpPassthroughClient, TcpClient tcpClient, TokenBucket parentBucket)
    {
        Id = clientID;
        TCPClient = tcpClient;
        UDPConnection = udpConnection;
        UDPPassthroughConnection = udpPassthroughConnection;
        LocalTcpEndpoint = (IPEndPoint)tcpClient.Client.LocalEndPoint;
        PassthroughLocalUDPEndpoint = (IPEndPoint)udpPassthroughClient.LocalEndPoint;

        tcpClient.NoDelay = true;
        tcpClient.GetStream().BeginRead(Buffer, 0, Buffer.Length, TCPReceiveCallback, null);

        int rateBytesPerSecond = NodeOptions.UploadSpeed * 1024;
        Bucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond, parentBucket);

        clientThread = new Thread(Loop) { Name = $"ClientThread-{Id}" };
        clientThread.Start();
    }

    public void Loop()
    {
        while (Connected)
        {
            long currentTime = DateTime.UtcNow.Ticks;

            //Disconnect if we hit the timeout
            if ((currentTime - LastUdpRecvTime) > TIMEOUT)
                Disconnect("UDP Receive Timeout");

            //Only do the following if we are connected
            if (UdpEndpoint == null) continue;

            CheckPing();
            SendData();

            //Send buffered TCP data to the UDP server
            if (TxQueue.AvailableRead != 0) continue;

            //Ran out of TCP data
            SendEvent.WaitOne(100);
        }
    }

    private void CheckPing()
    {
        long currentTime = DateTime.UtcNow.Ticks;
        if ((currentTime - LastUdpPingTime) <= PING) return;

        LastUdpPingTime = currentTime;
        PingRequest pr = new PingRequest(Id, currentTime, $"end{LocalTcpEndpoint}");
        UDPConnection.Send(pr, UdpEndpoint);
    }

    private void SendAck(bool force)
    {
        long currentTime = DateTime.UtcNow.Ticks;
        //Send acks to let the other side know we have received data.
        if (!force && ((currentTime - LastUdpSendAckTime) <= ACK_TIME)) return;

        LastUdpSendTime = currentTime;
        LastUdpSendAckTime = currentTime;
        Ack ack = new Ack(Id, currentRecvPos, $"end{LocalTcpEndpoint}");

        UDPConnection.Send(ack, UdpEndpoint);
    }

    public void ReceiveAck(Ack ack)
    {
        if (ack.StreamAck <= ackSafe) return;

        lastUdpRecvAckTime = DateTime.UtcNow.Ticks;
        ackSafe = ack.StreamAck;
    }

    private void SendData()
    {
        long currentTime = DateTime.UtcNow.Ticks;

        //MarkFree is not thread safe with Read
        if (TxQueue.StreamReadPos < ackSafe)
            TxQueue.MarkFree(ackSafe);


        //Don't send old data.
        if (currentSendPos < TxQueue.StreamReadPos)
        {
            lastWriteResetTime = currentTime;
            currentSendPos = TxQueue.StreamReadPos;
        }

        //If we don't have much data to send let's jump back to the unack'd position to send earlier than the RTT
        float dataToSend = TxQueue.AvailableRead / (float)Bucket.RateBytesPerSecond;
        //TODO: random hardcoded value?
        if (dataToSend < 0.2f || (Latency < NodeOptions.MinRetransmitTime))
        {
            if ((currentTime - lastWriteResetTime) > (NodeOptions.MinRetransmitTime * TimeSpan.TicksPerMillisecond))
            {
                lastWriteResetTime = currentTime;
                currentSendPos = TxQueue.StreamReadPos;
            }
        }
        else
        {
            //We have a lot of data to send, so let's wait for Ack's to stop changing before doing a position reset.
            if ((currentTime - lastUdpRecvAckTime) > (50 * TimeSpan.TicksPerMillisecond))
            {
                //Bias to let the acks flow again, and also build up data in the remote buffer
                lastWriteResetTime = currentTime;
                lastUdpRecvAckTime = currentTime + (4 * Latency * TimeSpan.TicksPerMillisecond);
                currentSendPos = TxQueue.StreamReadPos;
            }
        }

        //Ran out of bytes to send and Rate limit
        long bytesToWrite = TxQueue.StreamWritePos - currentSendPos;
        if (bytesToWrite == 0 || Bucket.CurrentBytes < 500)
        {
            Thread.Sleep(10);
            return;
        }

        //Clamp to 1250 byte packets
        //TODO: Look into changing this MTU to something that will fit more connections, like 500-1000
        const int upperLimit = 1250;
        bytesToWrite = bytesToWrite.LimitTo(upperLimit);

        //Send data
        Data data = new Data(Id, currentSendPos, currentRecvPos, new byte[bytesToWrite], $"end{LocalTcpEndpoint}");
        TxQueue.Read(data.TCPData, 0, currentSendPos, (int)bytesToWrite);
        LastUdpSendAckTime = currentTime;
        LastUdpSendTime = currentTime;
        UDPConnection.Send(data, UdpEndpoint);
        currentSendPos += bytesToWrite;
        Bucket.Take((int)bytesToWrite);
    }

    public void ReceiveData(Data data)
    {
        if (data.StreamAck > ackSafe)
        {
            lastUdpRecvAckTime = DateTime.UtcNow.Ticks;
            ackSafe = data.StreamAck;
        }

        //Data from the past
        if ((data.StreamPos + data.TCPData.Length) <= currentRecvPos)
        {
            if ((data.StreamPos + data.TCPData.Length) == currentRecvPos)
                SendAck(true);

            return;
        }

        //Data in the future
        if (data.StreamPos > currentRecvPos)
        {
            FutureDataStore.StoreData(data);
            return;
        }

        //Exact packet we need, include partial matches
        int offset = (int)(currentRecvPos - data.StreamPos);
        TCPClient.GetStream().Write(data.TCPData, offset, data.TCPData.Length - offset);
        currentRecvPos += data.TCPData.Length - offset;

        //Handle out of order data
        Data future;
        while ((future = FutureDataStore.GetData(currentRecvPos)) != null)
        {
            offset = (int)(currentRecvPos - future.StreamPos);
            TCPClient.GetStream().Write(future.TCPData, offset, future.TCPData.Length - offset);
            currentRecvPos += future.TCPData.Length - offset;
        }
        SendAck(false);
    }

    public void ReceivePassthroughData(PassthroughData passthroughData, IPEndPoint mediationClientEndpoint)
    {
        UDPPassthroughConnection.Send(passthroughData, mediationClientEndpoint);
    }

    public void TCPReceiveCallback(IAsyncResult ar)
    {
        try
        {
            // TODO: Crashes here when other end of tunnel disconnects. It shouldn't tho, retest.
            int bytesRead = TCPClient.GetStream().EndRead(ar);

            if (bytesRead == 0)
            {
                Disconnect("TCP connection was closed.");
                return;
            }

            TxQueue.Write(Buffer, 0, bytesRead);
            SendEvent.Set();
            //If our txqueue is full we need to wait before we can write to it.
            while (TxQueue.AvailableWrite < Buffer.Length)
            {
                if (!Connected) return;

                Thread.Sleep(10);
            }
            TCPClient.GetStream().BeginRead(Buffer, 0, Buffer.Length, TCPReceiveCallback, null);
        }
        catch
        {
            Disconnect("TCP connection was closed.");
        }
    }

    public void Disconnect(string reason)
    {
        if (!Connected) return;

        Connected = false;
        Console.WriteLine($"Disconnected stream {Id}");
        try
        {
            TCPClient.Close();
            TCPClient = null;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Exception during disconnecting: {e.Message}: {e.StackTrace}");
        }

        if (reason == null || UdpEndpoint == null) return;

        Disconnect dis = new Disconnect(Id, reason, $"end{LocalTcpEndpoint}");
        UDPConnection.Send(dis, UdpEndpoint);
    }
}