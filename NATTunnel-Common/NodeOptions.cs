using System;
using System.Collections.Generic;
using System.Net;

namespace NATTunnel.Common;

/// <summary>
/// Class that holds option values for various parts for NATTunnel.
/// </summary>
public static class NodeOptions
{
    //TODO: documentation needed
    /// <summary>
    /// Indicates whether the Tunnel is in a server state or client State.
    /// </summary>
    public static bool IsServer = false;

    /// <summary>
    /// Servers: Indicates the TCP server to connect to for forwarding over UDP. <br/>
    /// Clients: The UDP server to connect to.
    /// </summary>
    //TODO: not being used properly?
    //public static IPEndPoint Endpoint = new IPEndPoint(IPAddress.Loopback, 26702);

    /// <summary>
    /// The public IP of the mediation server you want to connect to.
    /// </summary>
    public static IPEndPoint MediationIp = new IPEndPoint(IPAddress.Parse("150.136.166.80"), 6510);

    /// <summary>
    /// The public IP of the server Tunnel you want to connect to. Only used as a client.
    /// </summary>
    public static IPAddress RemoteIp = IPAddress.Loopback;

    /// <summary>
    ///
    /// </summary>
    public static readonly List<IPEndPoint> Endpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, 26702)};

    /// <summary>
    /// Servers: The UDP server port <br/>
    /// Clients: The TCP port to host the forwarded server on.
    /// </summary>
    public static int LocalPort = 0;

    /// <summary>
    ///
    /// </summary>
    public static int MediationClientPort = 5000;

    /// <summary>
    /// The upload limit in kB/s the Tunnel sends.
    /// </summary>
    public static int UploadSpeed = 512;

    /// <summary>
    /// The download limit in kB/s the Tunnel uses.
    /// </summary>
    public static int DownloadSpeed = 512;

    /// <summary>
    /// Indicates by how many milliseconds delay the Tunnel sends unacknowledged packets
    /// </summary>
    public static int MinRetransmitTime = 100;
}