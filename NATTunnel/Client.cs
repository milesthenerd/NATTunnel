using NATTunnel.Common;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NATTunnel.Common.Messages.Types;

namespace NATTunnel;

public class Client
{
    public bool Connected = true;
    public readonly int Id;
    public long LastUdpReceivedTime = DateTime.UtcNow.Ticks;
    private long LastUdpPingTime;
    private long LastUdpSendAckTime;
    public TcpClient TCPClient;
    public IPEndPoint UdpEndpoint;
    private readonly byte[] Buffer = new byte[1500];
    private readonly StreamRingBuffer TxQueue = new StreamRingBuffer(16 * 1024 * 1024);
    private readonly FutureDataStore FutureDataStore = new FutureDataStore();
    public readonly TokenBucket Bucket;
    private long currentReceivedPos;
    private long currentSendPos;
    private long lastWriteResetTime;
    private long lastUdpReceivedAckTime;
    private const long TIMEOUT = 10 * TimeSpan.TicksPerSecond;
    private const long PING = 2 * TimeSpan.TicksPerSecond;
    private const long ACK_TIME = 10 * TimeSpan.TicksPerMillisecond;
    private readonly UdpConnection udpConnection;
    private long ackSafe;
    private readonly Task clientThread;
    public readonly AutoResetEvent SendEvent = new AutoResetEvent(false);
    public int Latency;
    public readonly IPEndPoint LocalTcpEndpoint;
    public readonly IPEndPoint PassthroughLocalUDPEndpoint;

    public Client(int clientID, UdpConnection udpConnection, Socket udpPassthroughClient, TcpClient tcpClient, TokenBucket parentBucket)
    {
        Id = clientID;
        TCPClient = tcpClient;
        this.udpConnection = udpConnection;
        LocalTcpEndpoint = (IPEndPoint)tcpClient.Client.LocalEndPoint;
        PassthroughLocalUDPEndpoint = (IPEndPoint)udpPassthroughClient.LocalEndPoint;

        tcpClient.NoDelay = true;
        tcpClient.GetStream().BeginRead(Buffer, 0, Buffer.Length, TCPReceiveCallback, null);

        int rateBytesPerSecond = NodeOptions.UploadSpeed * 1024;
        Bucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond, parentBucket);

        clientThread = new Task(Loop);
    }

    public void Start()
    {
        clientThread.Start();
    }

    private void Loop()
    {
        while (Connected)
        {
            long currentTime = DateTime.UtcNow.Ticks;

            //Disconnect if we hit the timeout
            if (NodeOptions.ConnectionType == ConnectionTypes.TCP)
            {
                if ((currentTime - LastUdpReceivedTime) > TIMEOUT)
                    Disconnect("UDP Receive Timeout");
            }

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
        udpConnection.Send(pr, UdpEndpoint);
    }

    private void SendAck(bool force)
    {
        long currentTime = DateTime.UtcNow.Ticks;
        //Send acks to let the other side know we have received data.
        if (!force && ((currentTime - LastUdpSendAckTime) <= ACK_TIME)) return;

        LastUdpSendAckTime = currentTime;
        Ack ack = new Ack(Id, currentReceivedPos, $"end{LocalTcpEndpoint}");

        udpConnection.Send(ack, UdpEndpoint);
    }

    public void ReceiveAck(Ack ack)
    {
        if (ack.StreamAck <= ackSafe) return;

        lastUdpReceivedAckTime = DateTime.UtcNow.Ticks;
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
            if ((currentTime - lastUdpReceivedAckTime) > (50 * TimeSpan.TicksPerMillisecond))
            {
                //Bias to let the acks flow again, and also build up data in the remote buffer
                lastWriteResetTime = currentTime;
                lastUdpReceivedAckTime = currentTime + (4 * Latency * TimeSpan.TicksPerMillisecond);
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

        //Clamp to 1000 byte packets
        //TODO: Look into changing this MTU to something that will fit more connections, like 500-1000
        const int upperLimit = 1000;
        bytesToWrite = bytesToWrite.LimitTo(upperLimit);

        //Send data
        Data data = new Data(Id, currentSendPos, currentReceivedPos, new byte[bytesToWrite], $"end{LocalTcpEndpoint}");
        TxQueue.Read(data.TCPData, 0, currentSendPos, (int)bytesToWrite);
        LastUdpSendAckTime = currentTime;
        udpConnection.Send(data, UdpEndpoint);
        currentSendPos += bytesToWrite;
        Bucket.Take((int)bytesToWrite);
    }

    public void ReceiveData(Data data)
    {
        if (data.StreamAck > ackSafe)
        {
            lastUdpReceivedAckTime = DateTime.UtcNow.Ticks;
            ackSafe = data.StreamAck;
        }

        //Data from the past
        if ((data.StreamPos + data.TCPData.Length) <= currentReceivedPos)
        {
            if ((data.StreamPos + data.TCPData.Length) == currentReceivedPos)
                SendAck(true);

            return;
        }

        //Data in the future
        if (data.StreamPos > currentReceivedPos)
        {
            FutureDataStore.StoreData(data);
            return;
        }

        //Exact packet we need, include partial matches
        int offset = (int)(currentReceivedPos - data.StreamPos);
        TCPClient.GetStream().Write(data.TCPData, offset, data.TCPData.Length - offset);
        currentReceivedPos += data.TCPData.Length - offset;

        //Handle out of order data
        Data future;
        while ((future = FutureDataStore.GetData(currentReceivedPos)) != null)
        {
            offset = (int)(currentReceivedPos - future.StreamPos);
            TCPClient.GetStream().Write(future.TCPData, offset, future.TCPData.Length - offset);
            currentReceivedPos += future.TCPData.Length - offset;
        }
        SendAck(false);
    }

    private void TCPReceiveCallback(IAsyncResult ar)
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
            //If our txQueue is full we need to wait before we can write to it.
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
        Console.WriteLine(reason);
        try
        {
            TCPClient.Close();
            TCPClient = null;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Exception during disconnecting: {e.Message}: {e.StackTrace}");
        }

        if (reason is null || UdpEndpoint is null) return;

        Disconnect dis = new Disconnect(Id, reason, $"end{LocalTcpEndpoint}");
        udpConnection.Send(dis, UdpEndpoint);
    }
}