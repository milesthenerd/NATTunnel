using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using NATTunnel.Common.Messages;

namespace NATTunnel.Common;

public class UdpConnection
{
    public bool Running = true;
    private readonly Socket udpSocket;
    //TODO: use of the threads?
    private readonly Thread recvThread;
    private readonly Thread sendThread;
    private readonly AutoResetEvent autoResetEvent = new AutoResetEvent(false);
    private readonly Action<IMessage, IPEndPoint> receiveCallback;
    private readonly ConcurrentQueue<Tuple<IMessage, IPEndPoint>> sendMessages = new ConcurrentQueue<Tuple<IMessage, IPEndPoint>>();


    public UdpConnection(Socket udpSocket, Action<IMessage, IPEndPoint> receiveCallback, bool passthrough=false)
    {
        this.udpSocket = udpSocket;
        this.receiveCallback = receiveCallback;
        if (passthrough)
        {
            recvThread = new Thread(ReceivePassthroughLoop) { Name = "UdpConnection-PassthroughReceive" };
            recvThread.Start();
            sendThread = new Thread(SendLoop) { Name = "UdpConnection-Send" };
            sendThread.Start();
        }
        else
        {
            recvThread = new Thread(ReceiveLoop) { Name = "UdpConnection-Receive" };
            recvThread.Start();
            sendThread = new Thread(SendLoop) { Name = "UdpConnection-Send" };
            sendThread.Start();
        }
    }

    public void Stop()
    {
        Running = false;
        recvThread.Join();
        sendThread.Join();
    }

    private void ReceiveLoop()
    {
        byte[] recvBuffer = new byte[1500];
        int receivedBytes;
        EndPoint recvEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (Running)
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

    private void ReceivePassthroughLoop()
    {
        byte[] recvBuffer = new byte[1500];
        int receivedBytes;
        EndPoint recvEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (Running)
        {
            IPEndPoint recvIPEndpoint;
            try
            {
                receivedBytes = udpSocket.ReceiveFrom(recvBuffer, ref recvEndpoint);
                recvIPEndpoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)recvEndpoint).Port);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error receiving: {e}");
                continue;
            }

            //Use SendTo directly to local UDP process if it's coming from mediationClientPort

            if (Equals(recvIPEndpoint.Address, IPAddress.Loopback) && Equals(recvIPEndpoint.Port, NodeOptions.MediationClientPort))
            {
                EndPoint programEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.LocalPort);
                udpSocket.SendTo(recvBuffer, 0, receivedBytes, SocketFlags.None, programEndpoint);
            }

            //////////////////////////////////////////////////////////////////////////////////

            if (Equals(recvIPEndpoint.Address, IPAddress.Loopback) && !Equals(recvIPEndpoint.Port, NodeOptions.MediationClientPort))
            {
                EndPoint mediationClientEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.MediationClientPort);
                udpSocket.SendTo(recvBuffer, 0, receivedBytes, SocketFlags.None, mediationClientEndpoint);
            }
        }
    }

    private void SendLoop()
    {
        while (Running)
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