using System.Net;

namespace NATTunnel.Common;

public class Client
{
    private IPEndPoint Endpoint;
    private IPAddress PrivateAddress;
    public bool Connected = false;
    private int MaxTimeout = 5;
    public int Timeout = 5;

    public Client(IPEndPoint endpoint, IPAddress privateAddress)
    {
        Endpoint = endpoint;
        PrivateAddress = privateAddress;
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