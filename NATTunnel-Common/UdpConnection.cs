using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NATTunnel.Common.Messages;

namespace NATTunnel.Common;

public class UdpConnection
{
    //TODO: make this work properly so it quits out everything else.
    /// <summary>
    /// A <see cref="CancellationTokenSource"/> that indicates whether the <see cref="UdpConnection"/> should still run.
    /// </summary>
    private readonly CancellationTokenSource running = new CancellationTokenSource();
    private readonly Socket udpSocket;
    private readonly Task receiveThread;
    private readonly Task sendThread;
    private readonly AutoResetEvent autoResetEvent = new AutoResetEvent(false);
    private readonly Action<IMessage, IPEndPoint> receiveCallback;
    private readonly ConcurrentQueue<Tuple<IMessage, IPEndPoint>> sendMessages = new ConcurrentQueue<Tuple<IMessage, IPEndPoint>>();


    public UdpConnection(Socket udpSocket, Action<IMessage, IPEndPoint> receiveCallback, bool passthrough = false)
    {
        this.udpSocket = udpSocket;
        this.receiveCallback = receiveCallback;
        if (passthrough)
        {
            receiveThread = new Task(ReceivePassthroughLoop);
            sendThread = new Task(SendLoop);
        }
        else
        {
            receiveThread = new Task(ReceiveLoop);
            sendThread = new Task(SendLoop);
        }
    }

    public void Start()
    {
        receiveThread.Start();
        sendThread.Start();
    }

    public void Stop()
    {
        running.Cancel();
        receiveThread.Wait();
        sendThread.Wait();
        running.Dispose();
    }

    private void ReceiveLoop()
    {
        byte[] receivedBuffer = new byte[1500];
        EndPoint receivedEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!running.Token.IsCancellationRequested)
        {
            if (!udpSocket.Poll(5000, SelectMode.SelectRead))
                continue;

            int receivedBytes;
            try
            {
                receivedBytes = udpSocket.ReceiveFrom(receivedBuffer, ref receivedEndpoint);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error receiving: {e}");
                continue;
            }
            using MemoryStream ms = new MemoryStream(receivedBuffer, 0, receivedBytes, false);
            using BinaryReader br = new BinaryReader(ms);
            IMessage receivedMessage = Header.DeframeMessage(br);
            receiveCallback(receivedMessage, (IPEndPoint)receivedEndpoint);
        }
    }

    private void ReceivePassthroughLoop()
    {
        byte[] receivedBuffer = new byte[1500];
        EndPoint receivedEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!running.Token.IsCancellationRequested)
        {
            IPEndPoint receivedIPEndpoint;
            int receivedBytes;
            try
            {
                receivedBytes = udpSocket.ReceiveFrom(receivedBuffer, ref receivedEndpoint);
                receivedIPEndpoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)receivedEndpoint).Port);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error receiving: {e}");
                continue;
            }

            // Use SendTo directly to local UDP process if it's coming from mediationClientPort

            if (Equals(receivedIPEndpoint.Address, IPAddress.Loopback) && Equals(receivedIPEndpoint.Port, NodeOptions.MediationClientPort))
            {
                EndPoint programEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.LocalPort);
                udpSocket.SendTo(receivedBuffer, 0, receivedBytes, SocketFlags.None, programEndpoint);
            }

            //////////////////////////////////////////////////////////////////////////////////

            if (Equals(receivedIPEndpoint.Address, IPAddress.Loopback) && !Equals(receivedIPEndpoint.Port, NodeOptions.MediationClientPort))
            {
                EndPoint mediationClientEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.MediationClientPort);
                udpSocket.SendTo(receivedBuffer, 0, receivedBytes, SocketFlags.None, mediationClientEndpoint);
            }
        }
    }

    private void SendLoop()
    {
        while (!running.Token.IsCancellationRequested)
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