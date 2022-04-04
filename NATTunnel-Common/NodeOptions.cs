using System;
using System.Collections.Generic;
using System.Net;

namespace NATTunnel.Common;

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
    //TODO: make this an IPEndPoint?
    public static string Endpoint = "serverhost.address.example.com:26702";

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
    public static readonly List<IPEndPoint> Endpoints = new List<IPEndPoint>();

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


    /// <summary>
    /// Resolves <see cref="Endpoint"/> as either IP address or hostname,
    /// and adds it to <see cref="Endpoints"/>.
    /// </summary>
    public static void ResolveAddress()
    {
        Endpoints.Clear();
        //TODO: handle splitIndex being -1
        int splitIndex = Endpoint.LastIndexOf(":", StringComparison.Ordinal);
        string leftSide = Endpoint.Substring(0, splitIndex);
        string rightSide = Endpoint.Substring(splitIndex + 1);
        int port = Int32.Parse(rightSide);
        if (IPAddress.TryParse(leftSide, out IPAddress address))
        {
            Endpoints.Add(new IPEndPoint(address, port));
        }
        //Left side is probably hostname instead, so let's try to resolve it and go through + add the IPs from that
        //TODO: why not just always do that?
        else
        {
            foreach (IPAddress address2 in Dns.GetHostAddresses(leftSide))
            {
                Endpoints.Add(new IPEndPoint(address2, port));
            }
        }
    }
}