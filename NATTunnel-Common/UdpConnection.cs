using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using NATTunnel.Common.Messages;
using NATTunnel.Common.Messages.Types;

namespace NATTunnel.Common;

public class UdpConnection
{
    public bool running = true;
    private readonly Socket udpSocket;
    //TODO: use of the threads?
    private readonly Thread recvThread;
    private readonly Thread sendThread;
    private readonly AutoResetEvent autoResetEvent = new AutoResetEvent(false);
    private readonly Action<IMessage, IPEndPoint> receiveCallback;
    private readonly ConcurrentQueue<Tuple<IMessage, IPEndPoint>> sendMessages = new ConcurrentQueue<Tuple<IMessage, IPEndPoint>>();
    private readonly IPEndPoint RemoteEndpoint;
    private readonly int ID;

    public UdpConnection(Socket udpSocket, Action<IMessage, IPEndPoint> receiveCallback, IPEndPoint remoteEndpoint = null, int id=0, bool passthrough=false)
    {
        this.udpSocket = udpSocket;
        this.receiveCallback = receiveCallback;
        this.RemoteEndpoint = remoteEndpoint;
        this.ID = id;
        if (NodeOptions.ConnectionType.Equals("udp") && passthrough)
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

    private void ReceivePassthroughLoop()
    {
        //Use SendTo directly to local UDP process if it's coming from mediationClientPort
        //////////////////////////////////////////////////////////////////////////////////
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

            if (Equals(((IPEndPoint)recvEndpoint).Address, IPAddress.Loopback) && !Equals(((IPEndPoint)recvEndpoint).Port, NodeOptions.MediationClientPort))
            {
                //Wrap in Data type and send to mediationClientPort if it's coming from local UDP process - working on it
                //Send received buffer with the callback and tell the client to construct a Data instance using the info it has - need to recreate TCPReceiveCallback but for UDP passthrough in the Client class before constructing Data (done?)
                //Have the client send that Data to mediationClientPort and hopefully it will handle the rest from there with a couple tweaks
                //Those tweaks are changing mappingUDP and mappingTCP to mappingLocalTCPToRemote and mappingRemoteTCPToLocal for example, and changing the mediation udp server to send stuff from remote IPs to the correct local IP
                IPEndPoint mediationClientEndpoint = new IPEndPoint(IPAddress.Loopback, NodeOptions.MediationClientPort);
                PassthroughData passthroughData = new PassthroughData(ID, recvBuffer, $"end{(IPEndPoint)udpSocket.LocalEndPoint}");
                receiveCallback((IMessage)passthroughData, mediationClientEndpoint);
            }
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