using System.Net;

namespace NATTunnel.Common;

public class Client
{
    private readonly IPEndPoint Endpoint;
    private readonly IPAddress PrivateAddress;
    public bool Connected = false;
    private int MaxTimeout = 5;
    public int Timeout = 5;
    public readonly int ConnectionID;

    public Client(IPEndPoint endpoint, IPAddress privateAddress, int connectionID)
    {
        Endpoint = endpoint;
        PrivateAddress = privateAddress;
        ConnectionID = connectionID;
    }

    public IPEndPoint GetEndPoint()
    {
        return Endpoint;
    }

    public IPAddress GetPrivateAddress()
    {
        return PrivateAddress;
    }

    public void Tick()
    {
        int reducedTime = Timeout;
        reducedTime--;
        Timeout = reducedTime;
    }

    public void ResetTimeout()
    {
        Timeout = MaxTimeout;
    }
}