using NATTunnel.Common;
using NATTunnel.Common.Messages;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace NATTunnel
{
    public class Client
    {
        public bool connected = true;
        public int id;
        public long lastUdpRecvTime = DateTime.UtcNow.Ticks;
        public long lastUdpSendTime;
        public long lastUdpPingTime;
        public long lastUdpSendAckTime;
        public TcpClient tcp;
        public IPEndPoint udpEndpoint;
        public byte[] buffer = new byte[1500];
        public StreamRingBuffer txQueue = new StreamRingBuffer(16 * 1024 * 1024);
        public FutureDataStore futureDataStore = new FutureDataStore();
        public TokenBucket bucket;
        private long currentRecvPos;
        private long currentSendPos;
        private long lastWriteResetTime;
        private long lastUdpRecvAckTime;
        private const long TIMEOUT = 10 * TimeSpan.TicksPerSecond;
        private const long PING = 2 * TimeSpan.TicksPerSecond;
        private const long ACK_TIME = 10 * TimeSpan.TicksPerMillisecond;
        private UdpConnection connection;
        private long ackSafe;
        private Thread clientThread;
        public AutoResetEvent sendEvent = new AutoResetEvent(false);
        public int latency;
        public IPEndPoint localTCPEndpoint;

        public Client(int clientID, UdpConnection connection, TcpClient tcp, TokenBucket parentBucket)
        {
            this.id = clientID;
            this.tcp = tcp;
            this.connection = connection;
            this.localTCPEndpoint = (IPEndPoint)tcp.Client.LocalEndPoint;

            tcp.NoDelay = true;
            tcp.GetStream().BeginRead(buffer, 0, buffer.Length, TCPReceiveCallback, null);

            int rateBytesPerSecond = NodeOptions.uploadSpeed * 1024;
            bucket = new TokenBucket(rateBytesPerSecond, rateBytesPerSecond, parentBucket);

            clientThread = new Thread(Loop);
            clientThread.Name = $"ClientThread-{id}";
            clientThread.Start();
        }

        public void Loop()
        {
            while (connected)
            {
                long currentTime = DateTime.UtcNow.Ticks;

                //Disconnect if we hit the timeout
                if ((currentTime - lastUdpRecvTime) > TIMEOUT)
                    Disconnect("UDP Receive Timeout");

                //Only do the following if we are connected
                if (udpEndpoint == null) continue;

                CheckPing();
                SendData();

                //Send buffered TCP data to the UDP server
                if (txQueue.AvailableRead != 0) continue;

                //Ran out of TCP data
                sendEvent.WaitOne(100);
            }
        }

        private void CheckPing()
        {
            long currentTime = DateTime.UtcNow.Ticks;
            if ((currentTime - lastUdpPingTime) <= PING) return;

            lastUdpPingTime = currentTime;
            PingRequest pr = new PingRequest(id, currentTime, $"end{localTCPEndpoint}");
            connection.Send(pr, udpEndpoint);
        }

        private void SendAck(bool force)
        {
            long currentTime = DateTime.UtcNow.Ticks;
            //Send acks to let the other side know we have received data.
            if (!force && (currentTime - lastUdpSendAckTime) <= ACK_TIME) return;

            lastUdpSendTime = currentTime;
            lastUdpSendAckTime = currentTime;
            Ack ack = new Ack(id, currentRecvPos, $"end{localTCPEndpoint}");

            connection.Send(ack, udpEndpoint);
        }

        public void ReceiveAck(Ack ack)
        {
            if (ack.streamAck <= ackSafe) return;

            lastUdpRecvAckTime = DateTime.UtcNow.Ticks;
            ackSafe = ack.streamAck;
        }

        private void SendData()
        {
            long currentTime = DateTime.UtcNow.Ticks;

            //MarkFree is not thread safe with Read
            if (txQueue.StreamReadPos < ackSafe)
                txQueue.MarkFree(ackSafe);


            //Don't send old data.
            if (currentSendPos < txQueue.StreamReadPos)
            {
                lastWriteResetTime = currentTime;
                currentSendPos = txQueue.StreamReadPos;
            }

            //If we don't have much data to send let's jump back to the unack'd position to send earlier than the RTT
            float dataToSend = txQueue.AvailableRead / (float)(bucket.rateBytesPerSecond);
            if (dataToSend < 0.2f || (latency < NodeOptions.minRetransmitTime))
            {
                if ((currentTime - lastWriteResetTime) > (NodeOptions.minRetransmitTime * TimeSpan.TicksPerMillisecond))
                {
                    lastWriteResetTime = currentTime;
                    currentSendPos = txQueue.StreamReadPos;
                }
            }
            else
            {
                //We have a lot of data to send, so let's wait for ACK's to stop changing before doing a position reset.
                if ((currentTime - lastUdpRecvAckTime) > (50 * TimeSpan.TicksPerMillisecond))
                {
                    //Bias to let the acks flow again, and also build up data in the remote buffer
                    lastWriteResetTime = currentTime;
                    lastUdpRecvAckTime = currentTime + (4 * latency * TimeSpan.TicksPerMillisecond);
                    currentSendPos = txQueue.StreamReadPos;
                }
            }

            //Ran out of bytes to send and Rate limit
            long bytesToWrite = txQueue.StreamWritePos - currentSendPos;
            if (bytesToWrite == 0 || bucket.currentBytes < 500)
            {
                Thread.Sleep(10);
                return;
            }

            //Clamp to 500 byte packets
            const int upperLimit = 1250;
            if (bytesToWrite > upperLimit)
                bytesToWrite = upperLimit;

            //Send data
            Data data = new Data(id, currentSendPos, currentRecvPos, new byte[bytesToWrite], $"end{localTCPEndpoint}");
            txQueue.Read(data.TCPData, 0, currentSendPos, (int)bytesToWrite);
            lastUdpSendAckTime = currentTime;
            lastUdpSendTime = currentTime;
            connection.Send(data, udpEndpoint);
            currentSendPos += bytesToWrite;
            bucket.Take((int)bytesToWrite);
        }

        //TODO: fromUDP is unused
        public void ReceiveData(Data data, bool fromUDP)
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
                futureDataStore.StoreData(data);
                return;
            }

            //Exact packet we need, include partial matches
            int offset = (int)(currentRecvPos - data.StreamPos);
            tcp.GetStream().Write(data.TCPData, offset, data.TCPData.Length - offset);
            currentRecvPos += data.TCPData.Length - offset;

            //Handle out of order data
            Data future;
            while ((future = futureDataStore.GetData(currentRecvPos)) != null)
            {
                offset = (int)(currentRecvPos - future.StreamPos);
                tcp.GetStream().Write(future.TCPData, offset, future.TCPData.Length - offset);
                currentRecvPos += future.TCPData.Length - offset;
            }
            SendAck(false);
        }

        public void TCPReceiveCallback(IAsyncResult ar)
        {
            try
            {
                int bytesRead = tcp.GetStream().EndRead(ar);
                if (bytesRead == 0)
                {
                    Disconnect("TCP connection was closed.");
                    return;
                }

                txQueue.Write(buffer, 0, bytesRead);
                sendEvent.Set();
                //If our txqueue is full we need to wait before we can write to it.
                while (txQueue.AvailableWrite < buffer.Length)
                {
                    if (!connected) return;

                    Thread.Sleep(10);
                }
                tcp.GetStream().BeginRead(buffer, 0, buffer.Length, TCPReceiveCallback, null);
            }
            catch
            {
                Disconnect("TCP connection was closed.");
            }
        }

        public void Disconnect(string reason)
        {
            if (!connected) return;

            connected = false;
            Console.WriteLine($"Disconnected stream {id}");
            try
            {
                tcp.Close();
                tcp = null;
            }
            catch { }

            if (reason == null || udpEndpoint == null) return;

            Disconnect dis = new Disconnect(id, reason, $"end{localTCPEndpoint}");
            connection.Send(dis, udpEndpoint);
        }
    }
}