using System.Net;
using System.Security.Cryptography;

namespace NATTunnel.Common;

public class Client
{
    private readonly IPEndPoint Endpoint;
    private readonly IPAddress PrivateAddress;
    public bool Connected = false;
    private int MaxTimeout = 5;
    public int Timeout = 5;
    public readonly int ConnectionID;
    public RSA rsa = RSA.Create();
    public RSAParameters rsaKeyInfo = new RSAParameters();

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

    public void ImportRSA(byte[] modulus, byte[] exponent)
    {
        rsaKeyInfo.Modulus = modulus;
        rsaKeyInfo.Exponent = exponent;
        rsa.ImportParameters(rsaKeyInfo);
    }
}