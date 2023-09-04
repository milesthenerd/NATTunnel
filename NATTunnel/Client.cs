using System.Net;
using System.Security.Cryptography;

namespace NATTunnel;

public class Client
{
    private readonly IPEndPoint Endpoint;
    private readonly IPAddress PrivateAddress;
    public bool Connected = false;
    private int MaxTimeout = 20;
    public int Timeout = 20;
    public readonly int ConnectionID;
    public RSA rsa = RSA.Create();
    public RSAParameters RsaKeyInfo = new RSAParameters();
    public AesGcm aes;
    public bool HasPublicKey = false;
    public bool HasSymmetricKey = false;
    public FrameCapture capture;

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
        RsaKeyInfo.Modulus = modulus;
        RsaKeyInfo.Exponent = exponent;
        rsa.ImportParameters(RsaKeyInfo);
        HasPublicKey = true;
    }

    public void ImportAes(byte[] key)
    {
        aes = new AesGcm(key);
        HasSymmetricKey = true;
    }
}