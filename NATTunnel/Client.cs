using System.Net;
using System.Security.Cryptography;

namespace NATTunnel;

public class Client
{
    private readonly IPEndPoint Endpoint;
    private IPAddress PrivateAddress; // Changed from readonly to allow updates for reconnections
    public bool Connected = false;
    private int MaxTimeout = 20;
    public int Timeout = 20;
    public readonly int ConnectionID;
    public RSA rsa = RSA.Create();
    public RSAParameters RsaKeyInfo = new RSAParameters();
    public AesGcm aes;
    public bool HasPublicKey = false;
    public bool HasSymmetricKey = false;
    public string WireGuardPublicKey = null;  // Base64-encoded WireGuard public key
    public bool HasWireGuardPublicKey = false;

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

    public IPEndPoint GetWireGuardEndPoint()
    {
        // WireGuard uses port 51820, not the mediation/hole punch port
        return new IPEndPoint(Endpoint.Address, 51820);
    }

    public IPAddress GetPrivateAddress()
    {
        return PrivateAddress;
    }

    public void SetPrivateAddress(IPAddress privateAddress)
    {
        PrivateAddress = privateAddress;
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
        aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        HasSymmetricKey = true;
    }

    public void ImportWireGuardPublicKey(string publicKey)
    {
        WireGuardPublicKey = publicKey;
        HasWireGuardPublicKey = true;
    }
}