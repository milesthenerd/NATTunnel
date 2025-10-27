using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Collections;
using System.IO;

namespace NATTunnel;

public static class Tunnel
{
    //TODO: entire class should get reviewed and eventually split up into smaller classes
    //TODO: do we really want to have this static? Why not just a normal class, with normal constructor?
    private static readonly TcpClient tcpClient = new TcpClient();
    private static UdpClient udpClient; // set in constructor
    private static NetworkStream tcpClientStream;
    private static Task tcpClientTask;
    private static CancellationTokenSource tcpClientTaskCancellationToken = new CancellationTokenSource();
    private static CancellationTokenSource udpClientTaskCancellationToken = new CancellationTokenSource();
    private static CancellationTokenSource udpServerTaskCancellationToken = new CancellationTokenSource();
    private static readonly IPEndPoint endpoint;
    private static int natTestPortOne = 6511;
    private static int natTestPortTwo = 6512;
    private static IPAddress targetPeerIp;
    private static int targetPeerPort;
    private static int holePunchReceivedCount;
    public static bool connected;
    private static readonly IPAddress remoteIp;
    private static readonly bool isServer;
    private static NATType natType = NATType.Unknown;
    private static List<UdpClient> symmetricConnectionUdpProbes = new List<UdpClient>();
    private static int currentConnectionID = 0;
    public static IPAddress privateIP = null;
    private static WireGuardTunnel wireguardTunnel;
    private static int maxConnectionTimeout = 15;
    private static int connectionTimeout = maxConnectionTimeout;
    private static Timer initialConnectionTimer;
    private static Timer connectionAttempt;
    private static int retryAttempt = 0;
    private static int maxRetryAttempts = 5;
    private static int retryCooldown = 10;  // seconds before retrying after failure
    private static bool clientIPAssigned = false;  // Track if we've already assigned the client IP
    private static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
    private static RSAParameters rsaKeyInfo = rsa.ExportParameters(false);
    private static byte[] keyModulus = rsaKeyInfo.Modulus;
    private static byte[] keyExponent = rsaKeyInfo.Exponent;
    private static RSA rsaServer = RSA.Create();
    private static RSAParameters rsaKeyInfoServer = new RSAParameters();
    public static AesGcm aes;
    public static bool hasServerPublicKey = false;
    public static bool serverHasSymmetricKey = false;
    private static byte[] symmetricKey = new byte[32];
    private static SHA256 shaHashGen = SHA256.Create();
    private static Guid clientID = Guid.NewGuid();

    static Tunnel()
    {
        RandomNumberGenerator.Fill(symmetricKey);

        aes = new AesGcm(symmetricKey, AesGcm.TagByteSizes.MaxSize);

        endpoint = TunnelOptions.MediationEndpoint;
        remoteIp = TunnelOptions.RemoteIp;
        isServer = TunnelOptions.IsServer;
        if (isServer) privateIP = IPAddress.Parse("10.5.0.0");
        if (!isServer) privateIP = IPAddress.Parse("10.5.0.255");

        // Note: WireGuardTunnel is now initialized externally in WireGuardTunnel.InitializeTunnel()
        // to avoid duplicate initialization

        udpClient = new UdpClient();
        udpClient.Client.ReceiveBufferSize = 128000;

        // Explicitly bind to a random port (0 = OS assigns ephemeral port)
        // This ensures we have a local port before WireGuard configuration
        udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

        // Windows-specific udpClient switch
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // ReSharper disable once IdentifierTypo - taken from here:
            // https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_connreset-opcode-setting-i-t3
            const int SIO_UDP_CONNRESET = -1744830452;
            udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }

        Console.WriteLine($"UDP client bound to local port: {((IPEndPoint)udpClient.Client.LocalEndPoint).Port}");

        //Try to send initial msg to mediator
        try
        {
            byte[] sendBuffer = Encoding.ASCII.GetBytes("check");
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }

        initialConnectionTimer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = false
        };
        initialConnectionTimer.Elapsed += ConnectionTimer;
    }

    /// <summary>
    /// Sets the WireGuard tunnel reference so clients can restart with their assigned IP
    /// </summary>
    public static void SetWireGuardTunnel(WireGuardTunnel tunnel)
    {
        wireguardTunnel = tunnel;
        Console.WriteLine("✓ WireGuard tunnel reference set in Tunnel");
    }

    /// <summary>
    /// Gets the UDP client used for NAT traversal (to be shared with WireGuard proxy)
    /// </summary>
    public static UdpClient GetUdpClient()
    {
        return udpClient;
    }

    /// <summary>
    /// Gets the local UDP port being used for NAT traversal/hole-punching
    /// </summary>
    public static int GetLocalUdpPort()
    {
        if (udpClient?.Client?.LocalEndPoint is IPEndPoint endpoint)
        {
            return endpoint.Port;
        }
        return 51820; // Fallback to default WireGuard port
    }

    /// <summary>
    /// Gets the next available IP address in the 10.5.0.0/24 subnet
    /// Server is 10.5.0.1, clients get 10.5.0.2 - 10.5.0.254
    /// </summary>
    private static IPAddress GetNextAvailableIP()
    {
        // Server IP is always 10.5.0.1
        const byte serverIpHost = 1;

        // Get all currently used IPs
        var usedIps = new HashSet<byte>();
        usedIps.Add(serverIpHost);  // Reserve server IP

        // Add all client IPs that are currently connected
        foreach (var client in Clients.GetAll())
        {
            var ipBytes = client.GetPrivateAddress().GetAddressBytes();
            usedIps.Add(ipBytes[3]);  // Get the host byte
        }

        // Find first available IP (2-254)
        for (byte host = 2; host < 255; host++)
        {
            if (!usedIps.Contains(host))
            {
                Console.WriteLine($"Assigning IP: 10.5.0.{host}");
                return IPAddress.Parse($"10.5.0.{host}");
            }
        }

        // Fallback - shouldn't happen unless we have 253 clients
        Console.WriteLine("⚠ WARNING: No available IPs in subnet! Falling back to 10.5.0.2");
        return IPAddress.Parse("10.5.0.2");
    }

    public static void Ping(IPEndPoint privateAddressEndpoint, Client client = null)
    {
        if (isServer)
        {
            if (client != null)
            {
                if (client.HasSymmetricKey)
                {
                    MediationMessage message = new MediationMessage(MediationMessageType.KeepAlive);
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, privateAddressEndpoint);
                }
            }
        }
        else
        {
            if (serverHasSymmetricKey)
            {
                MediationMessage message = new MediationMessage(MediationMessageType.KeepAlive);
                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                udpClient.Send(sendBuffer, sendBuffer.Length, privateAddressEndpoint);
            }
        }
    }

    public static void Send(byte[] packetData, IPEndPoint endpoint, IPAddress privateAddress, byte[] fragmentID, byte[] fragmentOffset, byte[] moreFragments, Client client = null)
    {
        byte[] fID = fragmentID;
        byte[] fOffset = fragmentOffset;
        byte[] fMore = moreFragments;

        if (isServer)
        {
            if (client != null)
            {
                if (client.HasSymmetricKey)
                {
                    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                    RandomNumberGenerator.Fill(nonce);
                    byte[] encryptedData = new byte[packetData.Length];
                    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                    client.aes.Encrypt(nonce, packetData, encryptedData, tag);

                    MediationMessage message = new MediationMessage(MediationMessageType.NATTunnelData);
                    message.Data = encryptedData;
                    message.Nonce = nonce;
                    message.AuthTag = tag;
                    message.FragmentID = fID;
                    message.FragmentOffset = fOffset;
                    message.MoreFragments = fMore;
                    message.SetPrivateAddress(privateAddress);
                    byte[] encryptedPacket = message.SerializeBytes();
                    udpClient.Send(encryptedPacket, encryptedPacket.Length, endpoint);
                }
            }
        }
        else
        {
            if (serverHasSymmetricKey)
            {
                byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);
                byte[] encryptedData = new byte[packetData.Length];
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                aes.Encrypt(nonce, packetData, encryptedData, tag);
                MediationMessage message = new MediationMessage(MediationMessageType.NATTunnelData);
                message.Data = encryptedData;
                message.Nonce = nonce;
                message.AuthTag = tag;
                message.FragmentID = fID;
                message.FragmentOffset = fOffset;
                message.MoreFragments = fMore;
                message.SetPrivateAddress(privateAddress);
                byte[] encryptedPacket = message.SerializeBytes();
                udpClient.Send(encryptedPacket, encryptedPacket.Length, endpoint);
            }
        }
    }

    public static void SendFrame(byte[] packetData, IPAddress privateAddress, byte[] fragmentID = null, byte[] fragmentOffset = null, byte[] moreFragments = null)
    {
        if (isServer)
        {
            Client client = Clients.GetClient(privateAddress);
            if (client != null)
            {
                Send(packetData, client.GetEndPoint(), privateAddress, fragmentID, fragmentOffset, moreFragments, client);
            }
        }
        else
        {
            Send(packetData, IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}"), privateAddress, fragmentID, fragmentOffset, moreFragments);
        }
    }

    private static void OnTimedEvent(object source, ElapsedEventArgs e)
    {
        MediationMessage message = new MediationMessage(MediationMessageType.KeepAlive);
        message.ClientID = clientID;
        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
        //If not connected to remote endpoint, send remote IP to mediator
        if (!connected || isServer)
        {
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
            Console.WriteLine("Sent");
        }
        //If connected to remote endpoint, send keep alive message
        if (isServer)
        {
            foreach (Client client in Clients.GetAll())
            {
                if (client.Connected)
                {
                    udpClient.Send(sendBuffer, sendBuffer.Length, client.GetEndPoint());
                    Ping(new IPEndPoint(client.GetPrivateAddress(), 0), client);
                }
            }
        }
        else
        {
            if (connected)
            {
                udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                Ping(IPEndPoint.Parse("10.5.0.0:0")); //yes this is hardcoded, just cry about it until full p2p
                Console.WriteLine("Keep alive");
            }
        }

        //Removal must be deferred to prevent an exception when iterating a modified list
        bool deferredRemoval = false;
        Client deferredClient = null;
        foreach (Client client in Clients.GetAll())
        {
            Console.WriteLine($"time left: {client.Timeout}");
            if (client.Timeout >= 1)
            {
                client.Tick();
            }
            else
            {
                Console.WriteLine($"timed out {client.GetEndPoint()}/{client.GetPrivateAddress()}");
                deferredRemoval = true;
                deferredClient = client;
            }
        }

        if (deferredRemoval)
        {
            Clients.Remove(deferredClient);
        }
    }

    private static void ConnectionTimer(object source, ElapsedEventArgs e)
    {
        if (initialConnectionTimer.Enabled)
        {
            if (connectionTimeout > 0) connectionTimeout--;
            Console.WriteLine($"connectionTimeout: {connectionTimeout}");
            if (connectionTimeout == 0)
            {
                MediationMessage message = new MediationMessage(MediationMessageType.ConnectionTimeout);
                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                Console.WriteLine($"sending {message.Serialize()}");
                tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                connectionAttempt.Enabled = false;
                initialConnectionTimer.Enabled = false;

                // Start cooldown before retry
                Console.WriteLine($"⚠ Connection attempt {retryAttempt + 1} failed. Waiting {retryCooldown}s before retry...");
                retryAttempt++;

                if (retryAttempt < maxRetryAttempts)
                {
                    // Schedule a retry after cooldown
                    Task.Delay(retryCooldown * 1000).ContinueWith(_ =>
                    {
                        if (!connected && retryAttempt < maxRetryAttempts)
                        {
                            Console.WriteLine($"🔄 Retrying connection (attempt {retryAttempt + 1}/{maxRetryAttempts})...");
                            connectionTimeout = maxConnectionTimeout;
                            holePunchReceivedCount = 0;
                            connectionAttempt.Enabled = true;
                            initialConnectionTimer.Enabled = true;
                        }
                    });
                }
                else
                {
                    Console.WriteLine($"❌ Max connection retries ({maxRetryAttempts}) reached. Giving up.");
                }
            }
        }
    }

    public static void Start()
    {
        //Attempt to connect to mediator
        try
        {
            tcpClient.Connect(endpoint);
        }
        //TODO: Have exception silent if can't connect? Quit program entirely?
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        //Once connected, begin listening
        if (!tcpClient.Connected)
            return;

        tcpClientStream = tcpClient.GetStream();
        tcpClientTask = new Task(TcpListenLoop);
        tcpClientTask.Start();
    }

    private static void UdpClient()
    {
        //Set client targetPeerIp to remote endpoint IP
        targetPeerIp = remoteIp;
        //Begin listening
        Task.Run(() => UdpClientListenLoop(udpClientTaskCancellationToken.Token));
        //Start timer for hole punch init and keep alive
        Timer timer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = true
        };
        timer.Elapsed += OnTimedEvent;
    }

    private static void UdpServer()
    {
        //Set client targetPeerIp to something no client will have
        targetPeerIp = IPAddress.None;
        //Begin listening
        Task.Run(() => UdpServerListenLoop(udpServerTaskCancellationToken.Token));
        //Start timer for hole punch init and keep alive
        Timer timer = new Timer(1000)
        {
            AutoReset = true,
            Enabled = true
        };
        timer.Elapsed += OnTimedEvent;
    }

    private static void UdpClientListenLoop(CancellationToken token)
    {
        //Init an IPEndPoint that will be populated with the sender's info
        int randID = new Random().Next();

        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

            // Check if this is a WireGuard packet (binary, not JSON)
            // WireGuard packets start with message type (1-4) and don't contain '{' or '['
            bool looksLikeWireGuard = receiveBuffer.Length > 0 &&
                                     receiveBuffer[0] != (byte)'{' &&
                                     receiveBuffer[0] != (byte)'[' &&
                                     receiveBuffer[0] >= 1 && receiveBuffer[0] <= 4;

            if (looksLikeWireGuard && wireguardTunnel != null)
            {
                // Forward to WireGuard via proxy
                var proxy = wireguardTunnel.GetUdpProxy();
                if (proxy != null)
                {
                    proxy.ForwardToWireGuard(receiveBuffer, listenEndpoint);
                }
                continue;
            }

            string receivedString = Encoding.ASCII.GetString(receiveBuffer);

            MediationMessage receivedMessage;

            try
            {
                receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
                //Console.WriteLine("VALID?");
                Console.WriteLine(receivedString);
            }
            catch
            {
                Console.WriteLine("Handled by FrameCapture");
                continue;
            }

            Console.WriteLine($"Received UDP: {receiveBuffer.Length} bytes from {listenEndpoint.Address}:{listenEndpoint.Port}");

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
                //TODO: random hardcoded value
                if (holePunchReceivedCount >= 5 && !connected)
                {
                    MediationMessage _message = new MediationMessage(MediationMessageType.ReceivedPeer);
                    _message.ConnectionID = currentConnectionID;
                    _message.IsServer = isServer;
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(_message.Serialize());
                    Console.WriteLine($"sending {_message.Serialize()}");
                    tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                }
            }

            MediationMessage message;

            switch (receivedMessage.ID)
            {
                case MediationMessageType.HolePunchAttempt:
                    {
                        holePunchReceivedCount++;
                        connectionTimeout = maxConnectionTimeout;
                        try
                        {
                            privateIP = receivedMessage.GetPrivateAddress();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                        Console.WriteLine("POG");
                    }
                    break;
                case MediationMessageType.KeepAlive:
                    if (!hasServerPublicKey)
                    {
                        message = new MediationMessage(MediationMessageType.PublicKeyRequest);
                        byte[] _sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(_sendBuffer, _sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                    break;
                case MediationMessageType.PublicKeyRequest:
                    message = new MediationMessage(MediationMessageType.PublicKeyResponse);
                    message.Modulus = keyModulus;
                    message.Exponent = keyExponent;
                    message.ModulusHash = shaHashGen.ComputeHash(message.Modulus);
                    message.ExponentHash = shaHashGen.ComputeHash(message.Exponent);
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                    udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    break;
                case MediationMessageType.PublicKeyResponse:
                    if (StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.ModulusHash, shaHashGen.ComputeHash(receivedMessage.Modulus)) &&
                        StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.ExponentHash, shaHashGen.ComputeHash(receivedMessage.Exponent)))
                    {
                        rsaKeyInfoServer.Modulus = receivedMessage.Modulus;
                        rsaKeyInfoServer.Exponent = receivedMessage.Exponent;
                        rsaServer.ImportParameters(rsaKeyInfoServer);
                        hasServerPublicKey = true;
                    }
                    break;
                case MediationMessageType.SymmetricKeyRequest:
                    {
                        message = new MediationMessage(MediationMessageType.SymmetricKeyResponse);
                        message.SymmetricKey = rsaServer.Encrypt(symmetricKey, RSAEncryptionPadding.Pkcs1);
                        message.SymmetricKeyHash = shaHashGen.ComputeHash(message.SymmetricKey);
                        byte[] _s = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(_s, _s.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                    break;
                case MediationMessageType.SymmetricKeyConfirm:
                    {
                        serverHasSymmetricKey = true;

                        // Client: restart WireGuard tunnel with the assigned IP now that connection is confirmed
                        if (!isServer && !clientIPAssigned && wireguardTunnel != null && privateIP != null)
                        {
                            Console.WriteLine($"Symmetric key confirmed! Client has IP: {privateIP}");
                            clientIPAssigned = true;

                            // Client: derive and send WireGuard public key to server
                            Console.WriteLine($"[DEBUG] Client attempting to send WireGuard public key to server at {targetPeerIp}:{targetPeerPort}");
                            try
                            {
                                string configPath = wireguardTunnel.GetConfigPath();
                                string clientWgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);

                                Console.WriteLine($"[DEBUG] Client derived public key: {clientWgPublicKey.Substring(0, 8)}...");

                                message = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                                message.WireGuardPublicKey = clientWgPublicKey;
                                message.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(clientWgPublicKey));
                                byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(message.Serialize());

                                var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);
                                udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, serverEndpoint);

                                Console.WriteLine($"✓ Client sent WireGuard public key ({wgKeyBuffer.Length} bytes) to server at {serverEndpoint}");
                            }
                            catch (Exception wgEx)
                            {
                                Console.WriteLine($"⚠ Error sending WireGuard public key: {wgEx.Message}");
                                Console.WriteLine($"   Stack trace: {wgEx.StackTrace}");
                            }

                            // Update client tunnel with assigned IP (CRITICAL for multi-peer support)
                            try
                            {
                                Console.WriteLine($"Updating client WireGuard interface with assigned IP: {privateIP}");
                                wireguardTunnel.SetClientIPAndRestart(privateIP.ToString());
                                Console.WriteLine("✓ Client WireGuard tunnel updated with assigned IP");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"⚠ Could not update tunnel with assigned IP: {ex.Message}");
                            }
                        }
                    }
                    break;
                case MediationMessageType.WireGuardPublicKeyExchange:
                    {
                        // Client: receive server's WireGuard public key
                        Console.WriteLine($"[DEBUG] Client received WireGuardPublicKeyExchange message");
                        Console.WriteLine($"[DEBUG] Message has public key: {(receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))}");
                        Console.WriteLine($"[DEBUG] wireguardTunnel != null: {wireguardTunnel != null}");
                        Console.WriteLine($"[DEBUG] targetPeerIp != null: {targetPeerIp != null}, targetPeerPort: {targetPeerPort}");

                        if (receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))
                        {
                            var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                            var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);
                            Console.WriteLine($"[DEBUG] Server public key hash validation: {(hashMatches ? "PASSED" : "FAILED")}");

                            if (hashMatches)
                            {
                                Console.WriteLine($"✓ Client received server's WireGuard public key: {receivedMessage.WireGuardPublicKey.Substring(0, 8)}...");

                                // Store server's WireGuard public key by adding it as a peer
                                if (wireguardTunnel != null && targetPeerIp != null && targetPeerPort != 0)
                                {
                                    try
                                    {
                                        // Use the actual NAT-traversed endpoint established by mediation
                                        var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);

                                        Console.WriteLine($"[DEBUG] Adding server as peer with endpoint: {serverEndpoint}");

                                        // Add server as a peer with its public key and known tunnel IP (10.5.0.1)
                                        var serverTunnelIp = IPAddress.Parse("10.5.0.1");
                                        var serverPeer = wireguardTunnel.AddPeer(receivedMessage.WireGuardPublicKey, serverEndpoint, serverTunnelIp, true);
                                        Console.WriteLine($"✓ Added server as WireGuard peer: {serverEndpoint} -> {serverPeer.PrivateAddress}");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"⚠ Error adding server as WireGuard peer: {ex.Message}");
                                        Console.WriteLine($"   Stack trace: {ex.StackTrace}");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"⚠ Cannot add server peer: wireguardTunnel={wireguardTunnel != null}, targetPeerIp={targetPeerIp}, targetPeerPort={targetPeerPort}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"⚠ Server WireGuard public key hash validation FAILED");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"⚠ Server's WireGuard public key is null or empty");
                        }
                    }
                    break;
                case MediationMessageType.NATTunnelData:
                    {
                        /*
                        Console.WriteLine("mah");
                        if (serverHasSymmetricKey)
                        {
                            byte[] tunnelData = new byte[receivedMessage.Data.Length];
                            aes.Decrypt(receivedMessage.Nonce, receivedMessage.Data, receivedMessage.AuthTag, tunnelData);
                            Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                            if (!connected) continue;
                            capture.Send(tunnelData);
                        }
                        */
                    }
                    break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                    {
                        holePunchReceivedCount++;
                        connectionTimeout = maxConnectionTimeout;
                        try
                        {
                            privateIP = receivedMessage.GetPrivateAddress();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                        }
                        if (natType != NATType.Symmetric)
                        {
                            targetPeerIp = listenEndpoint.Address;
                            targetPeerPort = listenEndpoint.Port;
                        }
                    }
                    break;
            }
        }

        Console.WriteLine($"WHAT THE HECK IS GOING ON WHY ISN'T THIS HITTING rand {randID}");
    }

    private static void UdpServerListenLoop(CancellationToken token)
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            Console.WriteLine(Clients.Count);
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

            // Check if this is a WireGuard packet (binary, not JSON)
            // WireGuard packets start with message type (1-4) and don't contain '{' or '['
            bool looksLikeWireGuard = receiveBuffer.Length > 0 &&
                                     receiveBuffer[0] != (byte)'{' &&
                                     receiveBuffer[0] != (byte)'[' &&
                                     receiveBuffer[0] >= 1 && receiveBuffer[0] <= 4;

            if (looksLikeWireGuard && wireguardTunnel != null)
            {
                // Forward to local WireGuard via proxy's inbound forwarder
                var proxy = wireguardTunnel.GetUdpProxy();
                if (proxy != null)
                {
                    proxy.ForwardToWireGuard(receiveBuffer, listenEndpoint);
                }
                continue;
            }

            string receivedString = Encoding.ASCII.GetString(receiveBuffer);

            MediationMessage receivedMessage;

            try
            {
                receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);
                //Console.WriteLine("VALID?");
                Console.WriteLine(receivedString);
            }
            catch
            {
                Console.WriteLine("Handled by FrameCapture");
                continue;
            }

            Console.WriteLine($"length {Clients.Count}");
            Console.WriteLine("Received UDP: {0} bytes from {1}:{2}", receiveBuffer.Length, listenEndpoint.Address, listenEndpoint.Port);

            if (Clients.GetClient(listenEndpoint) == null && Equals(listenEndpoint.Address, targetPeerIp))
            {
                if (Clients.GetClient(currentConnectionID) != null) continue;
                Client client = new Client(listenEndpoint, GetNextAvailableIP(), currentConnectionID);
                Clients.Add(client);
                Console.WriteLine("added {0}:{1} to list", listenEndpoint.Address, listenEndpoint.Port);
            }

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
                if (holePunchReceivedCount >= 1 && !Clients.GetClient(listenEndpoint).Connected)
                {
                    MediationMessage _message = new MediationMessage(MediationMessageType.ReceivedPeer);
                    _message.ConnectionID = currentConnectionID;
                    _message.IsServer = isServer;
                    byte[] sendBuffer = Encoding.ASCII.GetBytes(_message.Serialize());
                    Console.WriteLine($"sending {_message.Serialize()}");
                    tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                }
            }

            Client c = Clients.GetClient(listenEndpoint);
            MediationMessage message;

            if (c != null)
                c.ResetTimeout();

            switch (receivedMessage.ID)
            {
                case MediationMessageType.HolePunchAttempt:
                    {
                        if (holePunchReceivedCount == 0) holePunchReceivedCount++;
                        connectionTimeout = maxConnectionTimeout;
                        Console.WriteLine("POG");
                    }
                    break;
                case MediationMessageType.KeepAlive:
                    if (c != null)
                    {
                        if (!c.HasPublicKey)
                        {
                            message = new MediationMessage(MediationMessageType.PublicKeyRequest);
                            byte[] _sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            udpClient.Send(_sendBuffer, _sendBuffer.Length, c.GetEndPoint());
                        }

                        if (c.HasPublicKey && !c.HasSymmetricKey)
                        {
                            message = new MediationMessage(MediationMessageType.SymmetricKeyRequest);
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            udpClient.Send(sendBuffer, sendBuffer.Length, c.GetEndPoint());
                        }
                    }
                    break;
                case MediationMessageType.PublicKeyRequest:
                    if (c != null)
                    {
                        message = new MediationMessage(MediationMessageType.PublicKeyResponse);
                        message.Modulus = keyModulus;
                        message.Exponent = keyExponent;
                        message.ModulusHash = shaHashGen.ComputeHash(message.Modulus);
                        message.ExponentHash = shaHashGen.ComputeHash(message.Exponent);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, c.GetEndPoint());
                    }
                    break;
                case MediationMessageType.PublicKeyResponse:
                    if (c != null && !c.HasSymmetricKey)
                    {
                        if (StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.ModulusHash, shaHashGen.ComputeHash(receivedMessage.Modulus)) &&
                            StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.ExponentHash, shaHashGen.ComputeHash(receivedMessage.Exponent)))
                        {
                            c.ImportRSA(receivedMessage.Modulus, receivedMessage.Exponent);
                        }
                    }
                    break;
                case MediationMessageType.SymmetricKeyResponse:
                    {
                        if (c != null && !c.HasSymmetricKey)
                        {
                            if (StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.SymmetricKeyHash, shaHashGen.ComputeHash(receivedMessage.SymmetricKey)))
                            {
                                c.ImportAes(rsa.Decrypt(receivedMessage.SymmetricKey, RSAEncryptionPadding.Pkcs1));
                                message = new MediationMessage(MediationMessageType.SymmetricKeyConfirm);
                                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                udpClient.Send(sendBuffer, sendBuffer.Length, c.GetEndPoint());

                                // Server: restart WireGuard tunnel with the client's assigned IP
                                if (isServer && wireguardTunnel != null)
                                {
                                    Console.WriteLine($"Client symmetric key received. Will add peer after receiving public key: {c.GetPrivateAddress()}");
                                    // Note: Peer will be added when we receive the WireGuard public key
                                }
                            }
                        }
                    }
                    break;
                case MediationMessageType.WireGuardPublicKeyExchange:
                    {
                        if (isServer)
                        {
                            // Server: receive client's WireGuard public key
                            Console.WriteLine($"[DEBUG] Server received WireGuardPublicKeyExchange from {listenEndpoint}");
                            Console.WriteLine($"[DEBUG] Client lookup: c={c}, c.HasWireGuardPublicKey={c?.HasWireGuardPublicKey}");

                            if (c == null)
                            {
                                Console.WriteLine($"⚠ Cannot add WireGuard peer: Client not found for endpoint {listenEndpoint}");
                            }
                            else if (c.HasWireGuardPublicKey)
                            {
                                Console.WriteLine($"⚠ Client {c.GetEndPoint()} already has WireGuard public key, skipping");
                            }
                            else if (c != null && !c.HasWireGuardPublicKey)
                            {
                                var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                                var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);
                                Console.WriteLine($"[DEBUG] Hash validation: {(hashMatches ? "PASSED" : "FAILED")}");

                                if (hashMatches)
                                {
                                    c.ImportWireGuardPublicKey(receivedMessage.WireGuardPublicKey);
                                    Console.WriteLine($"✓ Imported client WireGuard public key: {receivedMessage.WireGuardPublicKey.Substring(0, 8)}...");

                                    // Add client as WireGuard peer using their actual public key and NAT-traversed endpoint
                                    if (wireguardTunnel != null)
                                    {
                                        try
                                        {
                                            // Use the client's received public key and actual NAT-traversed endpoint
                                            Console.WriteLine($"[DEBUG] Adding WireGuard peer:");
                                            Console.WriteLine($"[DEBUG]   Public Key: {c.WireGuardPublicKey.Substring(0, 16)}...");
                                            Console.WriteLine($"[DEBUG]   Endpoint: {c.GetEndPoint()}");

                                            var peer = wireguardTunnel.AddPeer(c.WireGuardPublicKey, c.GetEndPoint());
                                            Console.WriteLine($"✓ Added client as WireGuard peer: {c.GetEndPoint()} -> {peer.PrivateAddress}");
                                            Console.WriteLine($"[INFO] WireGuard will send encrypted UDP packets to {c.GetEndPoint()}");
                                            Console.WriteLine($"[INFO] Client must also add server as peer with endpoint pointing here");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"⚠ Error adding client as WireGuard peer: {ex.Message}");
                                            Console.WriteLine($"   Stack trace: {ex.StackTrace}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"⚠ Cannot add peer: wireguardTunnel is null");
                                    }

                                    // Server: derive public key from its config file private key
                                    // echo (private key) | wg pubkey
                                    string serverWgPublicKey = null;
                                    if (wireguardTunnel != null)
                                    {
                                        try
                                        {
                                            string configPath = wireguardTunnel.GetConfigPath();
                                            serverWgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);
                                            Console.WriteLine($"✓ Derived server public key: {serverWgPublicKey.Substring(0, 8)}...");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"⚠ Error deriving server public key from config: {ex.Message}");
                                        }
                                    }

                                    if (!string.IsNullOrEmpty(serverWgPublicKey))
                                    {
                                        message = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                                        message.WireGuardPublicKey = serverWgPublicKey;
                                        message.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(serverWgPublicKey));
                                        byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                        udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, c.GetEndPoint());

                                        Console.WriteLine($"✓ WireGuard keys exchanged with client {c.GetEndPoint()}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"⚠ Server public key is empty, cannot send to client");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"⚠ WireGuard public key hash validation FAILED for client {c.GetEndPoint()}");
                                }
                            }
                        }
                        else
                        {
                            // Client: receive server's WireGuard public key
                            Console.WriteLine($"[DEBUG] Client received WireGuardPublicKeyExchange message");
                            Console.WriteLine($"[DEBUG] Message has public key: {(receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))}");
                            Console.WriteLine($"[DEBUG] wireguardTunnel != null: {wireguardTunnel != null}");
                            Console.WriteLine($"[DEBUG] targetPeerIp != null: {targetPeerIp != null}, targetPeerPort: {targetPeerPort}");

                            if (receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))
                            {
                                var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                                var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);
                                Console.WriteLine($"[DEBUG] Server public key hash validation: {(hashMatches ? "PASSED" : "FAILED")}");

                                if (hashMatches)
                                {
                                    Console.WriteLine($"✓ Client received server's WireGuard public key: {receivedMessage.WireGuardPublicKey.Substring(0, 8)}...");

                                    // Store server's WireGuard public key by adding it as a peer
                                    if (wireguardTunnel != null && targetPeerIp != null && targetPeerPort != 0)
                                    {
                                        try
                                        {
                                            // Use the actual NAT-traversed endpoint established by mediation
                                            var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);

                                            Console.WriteLine($"[DEBUG] Adding server as peer with endpoint: {serverEndpoint}");

                                            // Add server as a peer with its public key
                                            var serverPeer = wireguardTunnel.AddPeer(receivedMessage.WireGuardPublicKey, serverEndpoint, isPersistent: true);
                                            Console.WriteLine($"✓ Added server as WireGuard peer: {serverEndpoint} -> {serverPeer.PrivateAddress}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"⚠ Error adding server as WireGuard peer: {ex.Message}");
                                            Console.WriteLine($"   Stack trace: {ex.StackTrace}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"⚠ Cannot add server peer: wireguardTunnel={wireguardTunnel != null}, targetPeerIp={targetPeerIp}, targetPeerPort={targetPeerPort}");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"⚠ Server WireGuard public key hash validation FAILED");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"⚠ Server's WireGuard public key is null or empty");
                            }
                        }
                    }
                    break;
                case MediationMessageType.NATTunnelData:
                    {
                        /*
                        Console.WriteLine("mah");
                        if (c != null && c.HasSymmetricKey)
                        {
                            byte[] tunnelData = new byte[receivedMessage.Data.Length];
                            c.aes.Decrypt(receivedMessage.Nonce, receivedMessage.Data, receivedMessage.AuthTag, tunnelData);

                            Packet givenPacket = PacketDotNet.Packet.ParsePacket(LinkLayers.Ethernet, tunnelData);
                            EthernetPacket eth = givenPacket.Extract<PacketDotNet.EthernetPacket>();
                            IPv4Packet ip = eth.Extract<PacketDotNet.IPv4Packet>();

                            IPAddress targetPrivateAddress = ip.DestinationAddress;
                            Console.WriteLine(Encoding.ASCII.GetString(tunnelData));

                            if (!Clients.GetClient(listenEndpoint).Connected) continue;

                            if (targetPrivateAddress.Equals(privateIP))
                            {
                                capture.Send(tunnelData);
                            }
                            else
                            {
                                SendFrame(tunnelData, targetPrivateAddress);
                            }
                        }
                        */
                    }
                    break;
                case MediationMessageType.SymmetricHolePunchAttempt:
                    {
                        if (holePunchReceivedCount == 0) holePunchReceivedCount++;
                        connectionTimeout = maxConnectionTimeout;
                        if (natType != NATType.Symmetric)
                        {
                            targetPeerIp = listenEndpoint.Address;
                            targetPeerPort = listenEndpoint.Port;
                        }
                    }
                    break;
            }
        }
    }

    private static void TcpListenLoop()
    {
        while (tcpClient.Connected)
        {
            try
            {
                byte[] receiveBuffer = new byte[tcpClient.ReceiveBufferSize];
                //TODO: sometimes fails here
                int bytesRead = tcpClientStream.Read(receiveBuffer, 0, tcpClient.ReceiveBufferSize);
                string receivedString = Encoding.ASCII.GetString(receiveBuffer, 0, bytesRead);
                Console.WriteLine("Received: " + receivedString);
                MediationMessage receivedMessage = JsonSerializer.Deserialize<MediationMessage>(receivedString);

                void PollForAvailableServer(object source, ElapsedEventArgs e)
                {
                    if (!connected)
                    {
                        if (initialConnectionTimer.Enabled && connectionTimeout <= 0)
                        {
                            MediationMessage message = new MediationMessage(MediationMessageType.ConnectionRequest);
                            message.SetEndpoint(new IPEndPoint(remoteIp, IPEndPoint.MinPort));
                            message.NATType = natType;
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                        }
                        else
                        {
                            if (!initialConnectionTimer.Enabled)
                            {
                                MediationMessage message = new MediationMessage(MediationMessageType.ConnectionRequest);
                                message.SetEndpoint(new IPEndPoint(remoteIp, IPEndPoint.MinPort));
                                message.NATType = natType;
                                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                            }
                        }
                    }
                }

                void TryConnect(object source, ElapsedEventArgs e)
                {
                    if (holePunchReceivedCount >= 1 && holePunchReceivedCount < 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.HolePunchAttempt);
                        if (Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")) != null)
                        {
                            if (isServer) message.SetPrivateAddress(Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")).GetPrivateAddress());
                        }
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }

                    if (holePunchReceivedCount < 1)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.HolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }
                }

                void TryConnectFromSymmetric(object source, ElapsedEventArgs e)
                {
                    if (holePunchReceivedCount >= 1 && holePunchReceivedCount < 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        if (Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")) != null)
                        {
                            if (isServer) message.SetPrivateAddress(Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")).GetPrivateAddress());
                        }
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        Console.WriteLine(udpClient.Client.LocalEndPoint);
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }

                    if (holePunchReceivedCount < 1)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        foreach (UdpClient probe in symmetricConnectionUdpProbes)
                        {
                            probe.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                        }
                    }
                }

                void TryConnectToSymmetric(object source, ElapsedEventArgs e)
                {
                    if (holePunchReceivedCount >= 1 && holePunchReceivedCount < 5)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        if (Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")) != null)
                        {
                            if (isServer) message.SetPrivateAddress(Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")).GetPrivateAddress());
                        }
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                    }

                    if (holePunchReceivedCount < 1)
                    {
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());

                        Random randPort = new Random();
                        for (int i = 0; i < 100; i++)
                        {
                            udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, randPort.Next(1024, 65536)));
                        }
                    }
                }

                //Also, add flag to prevent simultaneous connection attempts based on aforementioned packets
                //Add timeouts for connection attempts to allow another client to try to connect if the previous one fails
                //Basically the server shouldn't be locked out if a client couldn't connect
                //Also add a retry if there's no connection made after a certain amount of time

                switch (receivedMessage.ID)
                {
                    case MediationMessageType.Connected:
                        {
                            MediationMessage message = new MediationMessage(MediationMessageType.NATTypeRequest);
                            message.LocalPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;
                            message.ClientID = clientID;
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            Console.WriteLine(message.Serialize());
                            tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                        }
                        break;
                    case MediationMessageType.NATTestBegin:
                        {
                            natTestPortOne = receivedMessage.NATTestPortOne;
                            natTestPortTwo = receivedMessage.NATTestPortTwo;
                            MediationMessage message = new MediationMessage(MediationMessageType.NATTest);
                            message.ClientID = clientID;
                            byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(endpoint.Address, natTestPortOne));
                            udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(endpoint.Address, natTestPortTwo));
                        }
                        break;
                    case MediationMessageType.NATTypeResponse:
                        {
                            Console.WriteLine(receivedMessage.NATType);
                            natType = receivedMessage.NATType;
                            if (isServer)
                            {
                                UdpServer();
                            }
                            else
                            {
                                UdpClient();
                                MediationMessage message = new MediationMessage(MediationMessageType.ConnectionRequest);
                                message.SetEndpoint(new IPEndPoint(remoteIp, IPEndPoint.MinPort));
                                message.NATType = natType;
                                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                            }
                        }
                        break;
                    case MediationMessageType.ConnectionBegin:
                        {
                            holePunchReceivedCount = 0;
                            connectionTimeout = maxConnectionTimeout;
                            initialConnectionTimer.Enabled = true;
                            currentConnectionID = receivedMessage.ConnectionID;
                            if (natType == NATType.Symmetric)
                            {
                                IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                                targetPeerIp = targetPeerEndpoint.Address;
                                targetPeerPort = targetPeerEndpoint.Port;

                                connectionAttempt = new Timer(1000)
                                {
                                    AutoReset = true,
                                    Enabled = false
                                };
                                connectionAttempt.Elapsed += TryConnectFromSymmetric;

                                while (symmetricConnectionUdpProbes.Count < 256)
                                {
                                    UdpClient tempUdpClient = new UdpClient();
                                    tempUdpClient.Client.ReceiveBufferSize = 128000;
                                    const int SIO_UDP_CONNRESET = -1744830452;
                                    tempUdpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                                    tempUdpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
                                    tempUdpClient.BeginReceive(new AsyncCallback(probeReceive), null);
                                    void probeReceive(IAsyncResult res)
                                    {
                                        try
                                        {
                                            IPEndPoint receivedEndpoint = new IPEndPoint(IPAddress.Any, 0);
                                            byte[] receivedBuffer = tempUdpClient.EndReceive(res, ref receivedEndpoint);
                                            holePunchReceivedCount++;

                                            if (receivedEndpoint.Address.Equals(targetPeerIp) && holePunchReceivedCount == 1)
                                            {
                                                Console.WriteLine($"DUDE WE JUST RECEIVED A PACKET FROM ANOTHER PEER AS A SYMMETRIC NAT THIS IS INSANE!!! port {((IPEndPoint)tempUdpClient.Client.LocalEndPoint).Port}");

                                                udpClientTaskCancellationToken.Cancel();
                                                udpServerTaskCancellationToken.Cancel();

                                                if (isServer)
                                                {
                                                    udpClient = tempUdpClient;

                                                    // Update WireGuard proxy with new socket
                                                    if (wireguardTunnel != null)
                                                    {
                                                        wireguardTunnel.UpdateProxyTunnelSocket(tempUdpClient);
                                                    }

                                                    CancellationTokenSource newUdpServerTaskCancellationToken = new CancellationTokenSource();
                                                    Task.Run(() => UdpServerListenLoop(newUdpServerTaskCancellationToken.Token));
                                                    Console.WriteLine("server");
                                                }
                                                else
                                                {
                                                    udpClient = tempUdpClient;

                                                    // Update WireGuard proxy with new socket
                                                    if (wireguardTunnel != null)
                                                    {
                                                        wireguardTunnel.UpdateProxyTunnelSocket(tempUdpClient);
                                                    }

                                                    CancellationTokenSource newUdpClientTaskCancellationToken = new CancellationTokenSource();
                                                    Task.Run(() => UdpClientListenLoop(newUdpClientTaskCancellationToken.Token));
                                                    Console.WriteLine("client");
                                                }
                                            }
                                        }
                                        catch
                                        {
                                            Console.WriteLine("who cares it still works lol");
                                        }
                                    }
                                    symmetricConnectionUdpProbes.Add(tempUdpClient);
                                }

                                connectionAttempt.Enabled = true;
                            }

                            if (receivedMessage.NATType == NATType.Symmetric)
                            {
                                IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                                targetPeerIp = targetPeerEndpoint.Address;
                                connectionAttempt = new Timer(1000)
                                {
                                    AutoReset = true,
                                    Enabled = true
                                };
                                connectionAttempt.Elapsed += TryConnectToSymmetric;
                            }

                            if (natType != NATType.Symmetric && receivedMessage.NATType != NATType.Symmetric)
                            {
                                IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                                targetPeerIp = targetPeerEndpoint.Address;
                                targetPeerPort = targetPeerEndpoint.Port;
                                connectionAttempt = new Timer(1000)
                                {
                                    AutoReset = true,
                                    Enabled = true
                                };
                                connectionAttempt.Elapsed += TryConnect;
                            }
                        }
                        break;
                    case MediationMessageType.ConnectionComplete:
                        {
                            if (isServer)
                            {
                                holePunchReceivedCount = 5;
                                Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")).Connected = true;
                                initialConnectionTimer.Enabled = false;
                                Console.WriteLine("Completed");
                            }
                            else
                            {
                                try
                                {
                                    tcpClientStream.Close();
                                    tcpClientTaskCancellationToken.Cancel();
                                    tcpClient.Close();
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e);
                                }
                                connected = true;
                                initialConnectionTimer.Enabled = false;
                                retryAttempt = 0;  // Reset retry counter on successful connection
                                Console.WriteLine("✓ Connection established. Retry counter reset.");
                                Console.WriteLine("Completed");
                            }
                        }
                        break;
                    case MediationMessageType.ServerNotAvailable:
                        {
                            Timer recheckAvailability = new Timer(3000)
                            {
                                AutoReset = false,
                                Enabled = true
                            };
                            recheckAvailability.Elapsed += PollForAvailableServer;
                        }
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            if (tcpClientTaskCancellationToken.Token.IsCancellationRequested)
            {
                Console.WriteLine("YOU GOTTA BE KIDDING ME");
                return;
            }
        }
    }
}