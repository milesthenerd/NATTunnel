using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace NATTunnel.Common;

public class UdpConnection
{
    private bool running = true;
    private readonly Socket udpSocket;
    //TODO: use of the threads?
    private readonly Thread recvThread;
    private readonly Thread sendThread;
    private readonly AutoResetEvent autoResetEvent = new AutoResetEvent(false);
    private readonly Action<IMessage, IPEndPoint> receiveCallback;
    private readonly ConcurrentQueue<Tuple<IMessage, IPEndPoint>> sendMessages = new ConcurrentQueue<Tuple<IMessage, IPEndPoint>>();

    public UdpConnection(Socket udpSocket, Action<IMessage, IPEndPoint> receiveCallback)
    {
        this.udpSocket = udpSocket;
        this.receiveCallback = receiveCallback;
        recvThread = new Thread(ReceiveLoop) { Name = "UdpConnection-Receive" };
        recvThread.Start();
        sendThread = new Thread(SendLoop) { Name = "UdpConnection-Send" };
        sendThread.Start();
    }

    public void Stop()
    {
        running = false;
        recvThread.Join();
        sendThread.Join();
    }

    private void ReceiveLoop()
    {
        byte[] recvBuffer = new byte[1500];
        int receivedBytes;
        EndPoint recvEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (running)
        {
            if (!udpSocket.Poll(5000, SelectMode.SelectRead))
                continue;

            try
            {
                receivedBytes = udpSocket.ReceiveFrom(recvBuffer, ref recvEndpoint);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error receiving: {e}");
                continue;
            }
            using MemoryStream ms = new MemoryStream(recvBuffer, 0, receivedBytes, false);
            using BinaryReader br = new BinaryReader(ms);
            IMessage receivedMessage = Header.DeframeMessage(br);
            receiveCallback(receivedMessage, (IPEndPoint)recvEndpoint);
        }
    }

    private void SendLoop()
    {
        while (running)
        {
            autoResetEvent.WaitOne(100);
            while (sendMessages.TryDequeue(out Tuple<IMessage, IPEndPoint> sendMessage))
            {
                byte[] sendBytes = Header.FrameMessage(sendMessage.Item1);
                int sendSize = 8 + BitConverter.ToInt16(sendBytes, 6);
                try
                {
                    udpSocket.SendTo(sendBytes, 0, sendSize, SocketFlags.None, sendMessage.Item2);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending: {e}");
                }
            }
        }
    }

    public void Send(IMessage message, IPEndPoint endpoint)
    {
        sendMessages.Enqueue(new Tuple<IMessage, IPEndPoint>(message, endpoint));
        autoResetEvent.Set();
    }
}