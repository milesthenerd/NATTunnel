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

public class Tunnel : IDisposable
{
    //TODO: entire class should get reviewed and eventually split up into smaller classes

    // Connection constants
    private const int HOLE_PUNCH_THRESHOLD = 5;  // Number of hole punch packets required before confirming connection

    private TcpClient tcpClient = new TcpClient();
    private UdpClient udpClient;
    private NetworkStream tcpClientStream;
    private Task tcpClientTask;
    private CancellationTokenSource tcpClientTaskCancellationToken = new CancellationTokenSource();
    private CancellationTokenSource udpClientTaskCancellationToken = new CancellationTokenSource();
    private CancellationTokenSource udpServerTaskCancellationToken = new CancellationTokenSource();
    private readonly IPEndPoint endpoint;
    private int natTestPortOne = 6511;
    private int natTestPortTwo = 6512;
    private IPAddress targetPeerIp;
    private int targetPeerPort;
    private int holePunchReceivedCount;
    public bool connected;
    private readonly IPAddress remoteIp;
    private readonly bool isServer;
    private NATType natType = NATType.Unknown;
    private List<UdpClient> symmetricConnectionUdpProbes = new List<UdpClient>();
    private int currentConnectionID = 0;
    public IPAddress privateIP = null;
    private WireGuardTunnel wireguardTunnel;
    private int maxConnectionTimeout = 15;
    private int connectionTimeout;
    private Timer initialConnectionTimer;
    private Timer connectionAttempt;
    private int retryAttempt = 0;
    private int maxRetryAttempts = 5;
    private int retryCooldown = 10;  // seconds before retrying after failure
    private bool clientIPAssigned = false;  // Track if we've already assigned the client IP
    private RSACryptoServiceProvider rsa;
    private RSAParameters rsaKeyInfo;
    private byte[] keyModulus;
    private byte[] keyExponent;
    private RSA rsaServer;
    private RSAParameters rsaKeyInfoServer;
    public AesGcm aes;
    public bool hasServerPublicKey = false;
    public bool serverHasSymmetricKey = false;
    private byte[] symmetricKey;
    private SHA256 shaHashGen;
    private Guid clientID;
    private Action onConnectionFailure; // Callback for when connection fails completely
    private bool isManagedByTunnelManager; // True if this tunnel is managed by TunnelManager
    private int assignedConnectionID; // Connection ID assigned by TunnelManager (for server-side)
    private DateTime lastActivityTime; // Track last time this tunnel had any activity
    private long totalBytesReceived = 0; // Track total bytes received for activity monitoring
    private long totalBytesSent = 0; // Track total bytes sent for activity monitoring
    private bool meshPeerMode = false; // True if this is a mesh peer-to-peer connection
    private IPEndPoint meshPeerEndpoint = null; // The peer's endpoint in mesh mode
    private bool retryInPlace = false; // If true, retry like server (don't recreate tunnel)
    private bool skipTcpConnection = false; // If true, don't create TCP connection (mesh tunnels managed by mesh mode)
    private IPAddress ownMeshIP = null; // Our own mesh IP (for mesh mode)
    private IPAddress peerMeshIP = null; // Remote peer's mesh IP (for mesh mode)

    public Tunnel(Action onConnectionFailure = null, bool managedByTunnelManager = false, int connectionId = 0, UdpClient sharedUdpClient = null, bool meshPeerMode = false, string meshPeerEndpoint = null, bool retryInPlace = false, bool? isServerOverride = null, Guid? sharedClientID = null, bool skipTcpConnection = false, string ownMeshIP = null)
    {
        // Initialize all fields that need initialization
        connectionTimeout = maxConnectionTimeout;
        rsa = new RSACryptoServiceProvider();
        rsaKeyInfo = rsa.ExportParameters(false);
        keyModulus = rsaKeyInfo.Modulus;
        keyExponent = rsaKeyInfo.Exponent;
        rsaServer = RSA.Create();
        rsaKeyInfoServer = new RSAParameters();
        symmetricKey = new byte[32];
        shaHashGen = SHA256.Create();
        // Use shared clientID if provided (for mesh tunnels to share ID with mesh mode)
        // Otherwise generate a new one
        clientID = sharedClientID ?? Guid.NewGuid();

        this.onConnectionFailure = onConnectionFailure;
        this.isManagedByTunnelManager = managedByTunnelManager;
        this.assignedConnectionID = connectionId;
        this.lastActivityTime = DateTime.UtcNow; // Initialize activity tracking
        this.meshPeerMode = meshPeerMode;
        this.retryInPlace = retryInPlace;
        this.skipTcpConnection = skipTcpConnection;

        RandomNumberGenerator.Fill(symmetricKey);

        aes = new AesGcm(symmetricKey, AesGcm.TagByteSizes.MaxSize);

        endpoint = TunnelOptions.MediationEndpoint;
        remoteIp = TunnelOptions.RemoteIp;
        // Use override if provided, otherwise use global setting
        isServer = isServerOverride ?? TunnelOptions.IsServer;

        // Set mesh IP if provided, otherwise use default client/server IPs
        if (ownMeshIP != null)
        {
            this.ownMeshIP = IPAddress.Parse(ownMeshIP);
            privateIP = this.ownMeshIP;  // Use mesh IP as our private IP
        }
        else
        {
            if (isServer) privateIP = IPAddress.Parse("10.5.0.0");
            if (!isServer) privateIP = IPAddress.Parse("10.5.0.255");
        }

        // Parse mesh peer endpoint if provided
        if (meshPeerMode && meshPeerEndpoint != null)
        {
            var parts = meshPeerEndpoint.Split(':');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var peerIp) && int.TryParse(parts[1], out var peerPort))
            {
                this.meshPeerEndpoint = new IPEndPoint(peerIp, peerPort);
            }
        }

        // Note: WireGuardTunnel is now initialized externally in WireGuardTunnel.InitializeTunnel()
        // to avoid duplicate initialization

        // Use shared UDP client if provided (for server-side tunnels managed by TunnelManager)
        // Otherwise create a new one
        if (sharedUdpClient != null)
        {
            udpClient = sharedUdpClient;
            Console.WriteLine($"[Tunnel] Using shared UDP client on port {((IPEndPoint)udpClient.Client.LocalEndPoint).Port}");
        }
        else
        {
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
    public void SetWireGuardTunnel(WireGuardTunnel tunnel)
    {
        wireguardTunnel = tunnel;
        Console.WriteLine("WireGuard tunnel reference set in Tunnel");
    }

    /// <summary>
    /// Initializes a managed tunnel with connection information from mediation server
    /// </summary>
    public void InitializeManagedConnection(string clientEndpoint, NATType clientNatType)
    {
        if (!isManagedByTunnelManager)
        {
            throw new InvalidOperationException("InitializeManagedConnection can only be called on managed tunnels");
        }

        Console.WriteLine($"[Tunnel {assignedConnectionID}] Initializing connection to client at {clientEndpoint}");

        // Parse client endpoint
        string[] parts = clientEndpoint.Split(':');
        if (parts.Length == 2 && IPAddress.TryParse(parts[0], out IPAddress clientIp) && int.TryParse(parts[1], out int clientPort))
        {
            targetPeerIp = clientIp;
            targetPeerPort = clientPort;
            // Store client's NAT type if needed for hole punching logic

            Console.WriteLine($"[Tunnel {assignedConnectionID}] Target peer: {targetPeerIp}:{targetPeerPort}, NAT type: {clientNatType}");

            // Server already knows its own NAT type from registration tunnel
            // Start hole punching immediately
            StartHolePunching();
        }
        else
        {
            Console.WriteLine($"[Tunnel {assignedConnectionID}] ⚠ Failed to parse client endpoint: {clientEndpoint}");
        }
    }

    /// <summary>
    /// Starts hole punching for managed tunnels
    /// </summary>
    private void StartHolePunching()
    {
        Console.WriteLine($"[Tunnel {assignedConnectionID}] Starting hole punching to {targetPeerIp}");
        // Timer will be set up by UdpServer() which is called in Start()
    }

    /// <summary>
    /// Gets the UDP client used for NAT traversal (to be shared with WireGuard proxy)
    /// </summary>
    public UdpClient GetUdpClient()
    {
        return udpClient;
    }

    /// <summary>
    /// Gets the local UDP port being used for NAT traversal/hole-punching
    /// </summary>
    public int GetLocalUdpPort()
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
    private IPAddress GetNextAvailableIP()
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

    public void Ping(IPEndPoint privateAddressEndpoint, Client client = null)
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

    public void Send(byte[] packetData, IPEndPoint endpoint, IPAddress privateAddress, byte[] fragmentID, byte[] fragmentOffset, byte[] moreFragments, Client client = null)
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

    public void SendFrame(byte[] packetData, IPAddress privateAddress, byte[] fragmentID = null, byte[] fragmentOffset = null, byte[] moreFragments = null)
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

    private void OnTimedEvent(object source, ElapsedEventArgs e)
    {
        MediationMessage message = new MediationMessage(MediationMessageType.KeepAlive);
        message.ClientID = clientID;
        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());

        //If not connected to remote endpoint, send remote IP to mediator
        if (!connected || isServer)
        {
            udpClient.Send(sendBuffer, sendBuffer.Length, endpoint);
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

    private void ConnectionTimer(object source, ElapsedEventArgs e)
    {
        if (initialConnectionTimer.Enabled)
        {
            if (connectionTimeout > 0) connectionTimeout--;
            Console.WriteLine($"connectionTimeout: {connectionTimeout}");
            if (connectionTimeout == 0)
            {
                MediationMessage message = new MediationMessage(MediationMessageType.ConnectionTimeout);
                message.ConnectionID = currentConnectionID;  // Include connection ID so server knows which connection timed out
                byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                Console.WriteLine($"sending {message.Serialize()}");
                tcpClientStream.Write(sendBuffer, 0, sendBuffer.Length);
                connectionAttempt.Enabled = false;
                initialConnectionTimer.Enabled = false;

                // Start cooldown before retry
                Console.WriteLine($"Connection attempt {retryAttempt + 1} failed. Waiting {retryCooldown}s before retry...");
                retryAttempt++;

                if (retryAttempt < maxRetryAttempts)
                {
                    // Schedule a retry after cooldown
                    Task.Delay(retryCooldown * 1000).ContinueWith(_ =>
                    {
                        if (!connected && retryAttempt < maxRetryAttempts)
                        {
                            Console.WriteLine($"Retrying connection (attempt {retryAttempt + 1}/{maxRetryAttempts})...");

                            // Clients recreate tunnel instance, servers (and retryInPlace tunnels) reset state
                            if (!isServer && !retryInPlace)
                            {
                                Console.WriteLine($"Creating new tunnel instance with fresh connection ID...");
                                onConnectionFailure?.Invoke();
                            }
                            else
                            {
                                // Server or mesh peer - just reset connection state and retry
                                Console.WriteLine($"Resetting connection state and retrying...");
                                connectionTimeout = maxConnectionTimeout;
                                holePunchReceivedCount = 0;
                                connectionAttempt.Enabled = true;
                                initialConnectionTimer.Enabled = true;
                            }
                        }
                    });
                }
                else
                {
                    Console.WriteLine($"❌ Max connection retries ({maxRetryAttempts}) reached. Giving up.");
                    // Invoke failure callback if we've exhausted retries
                    if (!isServer)
                    {
                        onConnectionFailure?.Invoke();
                    }
                }
            }
        }
    }

    public void Start()
    {
        // If this tunnel is managed by TunnelManager, skip TCP connection and NAT detection
        // The TunnelManager handles coordination with mediation server
        if (isManagedByTunnelManager)
        {
            Console.WriteLine($"[Tunnel {assignedConnectionID}] Starting as managed tunnel (server-side)");
            // Just start the UDP server listen loop - no NAT detection needed
            UdpServer();
            return;
        }

        // If skipTcpConnection is true (mesh mode), don't create TCP connection
        // Mesh mode handles TCP coordination and will inject messages as needed
        if (skipTcpConnection)
        {
            Console.WriteLine($"[Tunnel {assignedConnectionID}] Starting in mesh mode (no TCP connection)");
            // Just wait for messages to be injected from mesh mode
            // UDP receive loop will be started when ConnectionBegin is processed
            return;
        }

        //Attempt to connect to mediator
        try
        {
            tcpClient.Connect(endpoint);
        }
        catch (Exception e)
        {
            Console.WriteLine($"⚠ Failed to connect to mediation server at {endpoint}");
            Console.WriteLine($"   Error: {e.Message}");

            // For managed tunnels (server-side), notify TunnelManager of failure
            if (isManagedByTunnelManager && onConnectionFailure != null)
            {
                Console.WriteLine($"[Tunnel {assignedConnectionID}] Notifying TunnelManager of connection failure");
                onConnectionFailure();
            }
            // For standalone tunnels, this is fatal - return early
            return;
        }

        //Once connected, begin listening
        if (!tcpClient.Connected)
        {
            Console.WriteLine("⚠ TCP connection failed - cannot proceed");
            return;
        }

        tcpClientStream = tcpClient.GetStream();
        tcpClientTask = new Task(TcpListenLoop);
        tcpClientTask.Start();
    }

    private void UdpClient()
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

    private void UdpServer()
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

    private void UdpClientListenLoop(CancellationToken token)
    {
        //Init an IPEndPoint that will be populated with the sender's info
        int randID = new Random().Next();
        Console.WriteLine($"[UdpClientListenLoop] STARTED with randID={randID}, udpClient.LocalEndPoint={((IPEndPoint)udpClient.Client.LocalEndPoint).Port}");

        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");
            Console.WriteLine($"[UdpClientListenLoop {randID}] Received {receiveBuffer.Length} bytes from {listenEndpoint}");

            // Track activity
            totalBytesReceived += receiveBuffer.Length;
            UpdateActivity();

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

            // Update target peer port if we're receiving from the correct IP but different port (Symmetric NAT port switching)
            if (Equals(listenEndpoint.Address, targetPeerIp) && listenEndpoint.Port != targetPeerPort)
            {
                targetPeerPort = listenEndpoint.Port;
            }

            if (Equals(listenEndpoint.Address, targetPeerIp))
            {
                Console.WriteLine("pog");
                if (holePunchReceivedCount >= HOLE_PUNCH_THRESHOLD && !connected)
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
                    else if (hasServerPublicKey && !serverHasSymmetricKey)
                    {
                        message = new MediationMessage(MediationMessageType.SymmetricKeyRequest);
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
                    udpClient.Send(sendBuffer, sendBuffer.Length, listenEndpoint);
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
                        udpClient.Send(_s, _s.Length, listenEndpoint);
                    }
                    break;
                case MediationMessageType.SymmetricKeyResponse:
                    {
                        if (StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.SymmetricKeyHash, shaHashGen.ComputeHash(receivedMessage.SymmetricKey)))
                        {
                            byte[] decryptedKey = rsa.Decrypt(receivedMessage.SymmetricKey, RSAEncryptionPadding.Pkcs1);
                            aes?.Dispose();
                            aes = new AesGcm(decryptedKey, AesGcm.TagByteSizes.MaxSize);
                            serverHasSymmetricKey = true;

                            message = new MediationMessage(MediationMessageType.SymmetricKeyConfirm);
                            byte[] confirmBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                            udpClient.Send(confirmBuffer, confirmBuffer.Length, listenEndpoint);
                        }
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

                            // Client: derive and send WireGuard public key to peer
                            try
                            {
                                string configPath = wireguardTunnel.GetConfigPath();
                                string clientWgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);

                                message = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                                message.WireGuardPublicKey = clientWgPublicKey;
                                message.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(clientWgPublicKey));

                                // Include our mesh IP so peer knows what IP to use when adding us
                                if (privateIP != null)
                                {
                                    message.SetPrivateAddress(privateIP);
                                    Console.WriteLine($"Sending our mesh IP: {privateIP}");
                                }

                                byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(message.Serialize());

                                var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);
                                udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, serverEndpoint);

                                Console.WriteLine($"Sent WireGuard public key to peer");
                            }
                            catch (Exception wgEx)
                            {
                                Console.WriteLine($"Error sending WireGuard public key: {wgEx.Message}");
                            }
                        }
                    }
                    break;
                case MediationMessageType.WireGuardPublicKeyExchange:
                    {
                        // Client: receive peer's WireGuard public key

                        // In client/server mode: Server may have corrected our IP
                        // In mesh mode: Message contains peer's mesh IP (don't overwrite our own!)
                        if (receivedMessage.PrivateAddressString != null && !string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                        {
                            var receivedIP = receivedMessage.GetPrivateAddress();

                            // Only update our own IP in client/server mode (when we don't have mesh IPs set)
                            if (ownMeshIP == null && peerMeshIP == null && receivedIP != null && !receivedIP.Equals(privateIP))
                            {
                                // Client/server mode: Server is assigning us an IP
                                Console.WriteLine($"Server assigned IP {receivedIP}");
                                privateIP = receivedIP;
                            }
                            else if (peerMeshIP == null && receivedIP != null)
                            {
                                // Mesh mode: This is the peer's mesh IP, store it
                                peerMeshIP = receivedIP;
                                Console.WriteLine($"Received peer's mesh IP in WireGuard exchange: {peerMeshIP}");
                            }
                        }

                        if (receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))
                        {
                            var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                            var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);

                            if (hashMatches)
                            {
                                Console.WriteLine($"Received peer's WireGuard public key");

                                // FIRST: Update client tunnel with the final confirmed IP (client/server mode only)
                                // In mesh mode, skip this since our IP is already set correctly
                                if (ownMeshIP == null && wireguardTunnel != null && privateIP != null)
                                {
                                    try
                                    {
                                        // Client/server mode uses /24 netmask (server controls 10.5.0.0/24 subnet)
                                        wireguardTunnel.SetClientIPAndRestart(privateIP.ToString(), 24);
                                        Console.WriteLine("Updated tunnel with confirmed IP");
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Could not update tunnel IP: {ex.Message}");
                                    }
                                }
                                else if (ownMeshIP != null)
                                {
                                    Console.WriteLine($"Mesh mode: Skipping IP update (already set to {privateIP})");
                                }

                                // SECOND: Store server's WireGuard public key by adding it as a peer
                                Console.WriteLine($"[AddPeer] Pre-check: wireguardTunnel={(wireguardTunnel != null ? "set" : "NULL")}, targetPeerIp={targetPeerIp}, targetPeerPort={targetPeerPort}");
                                if (wireguardTunnel != null && targetPeerIp != null && targetPeerPort != 0)
                                {
                                    bool peerAddedSuccessfully = false;
                                    try
                                    {
                                        // Use the actual NAT-traversed endpoint established by mediation
                                        var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);

                                        // Determine peer's tunnel IP
                                        // In mesh mode, use the stored peer mesh IP from ConnectionBegin
                                        // In client/server mode, use hardcoded 10.5.0.1 or message's PrivateAddressString
                                        Console.WriteLine($"[AddPeer] Determining tunnel IP: peerMeshIP={(peerMeshIP != null ? peerMeshIP.ToString() : "null")}, ownMeshIP={(ownMeshIP != null ? ownMeshIP.ToString() : "null")}, messagePrivateAddr={(receivedMessage.PrivateAddressString ?? "null")}");
                                        IPAddress serverTunnelIp;
                                        if (peerMeshIP != null)
                                        {
                                            // Mesh mode: Use peer's mesh IP from ConnectionBegin
                                            serverTunnelIp = peerMeshIP;
                                            Console.WriteLine($"[AddPeer] Using peer's mesh IP from ConnectionBegin: {serverTunnelIp}");
                                        }
                                        else if (!string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                                        {
                                            // Client/server mode: Server-assigned IP from message
                                            serverTunnelIp = IPAddress.Parse(receivedMessage.PrivateAddressString);
                                            Console.WriteLine($"Using server-assigned IP from message: {serverTunnelIp}");
                                        }
                                        else
                                        {
                                            // Fallback: Hardcoded server IP
                                            serverTunnelIp = IPAddress.Parse("10.5.0.1");
                                            Console.WriteLine($"Using hardcoded server IP: {serverTunnelIp}");
                                        }

                                        // Add peer with their public key and tunnel IP
                                        // Pass our tunnel socket for proxy routing
                                        var serverPeer = wireguardTunnel.AddPeer(receivedMessage.WireGuardPublicKey, serverEndpoint, serverTunnelIp, true, udpClient);
                                        Console.WriteLine($"Added peer: {serverPeer.PrivateAddress}");
                                        peerAddedSuccessfully = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Error adding server as peer: {ex.Message}");
                                    }

                                    // THIRD: Send ConnectionComplete to signal we're done with setup
                                    if (peerAddedSuccessfully)
                                    {
                                        try
                                        {
                                            message = new MediationMessage(MediationMessageType.ReceivedPeer);
                                            message.ConnectionID = currentConnectionID;
                                            message.IsServer = false;
                                            byte[] completeBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                            tcpClientStream.Write(completeBuffer, 0, completeBuffer.Length);

                                            // Mark connection as complete
                                            connected = true;
                                            retryAttempt = 0;  // Reset for future connections
                                            initialConnectionTimer.Enabled = false;
                                            connectionAttempt.Enabled = false;
                                            Console.WriteLine("Connection established successfully!");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Error sending connection complete: {ex.Message}");
                                        }
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Cannot add server peer: missing tunnel or endpoint information");
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
                            var parsedPrivateIP = receivedMessage.GetPrivateAddress();
                            if (parsedPrivateIP != null)
                            {
                                privateIP = parsedPrivateIP;
                            }
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

    private void UdpServerListenLoop(CancellationToken token)
    {
        IPEndPoint listenEndpoint = new IPEndPoint(IPAddress.IPv6Any, 0);
        while (!token.IsCancellationRequested)
        {
            Console.WriteLine(Clients.Count);
            byte[] receiveBuffer = udpClient.Receive(ref listenEndpoint) ?? throw new ArgumentNullException(nameof(udpClient), "udpClient.Receive(ref listenEP)");

            // Track activity
            totalBytesReceived += receiveBuffer.Length;
            UpdateActivity();

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
                Console.WriteLine($"[UdpServer] Added client {listenEndpoint} with ConnectionID: {currentConnectionID}");
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

                                // Mesh mode (both peers are clients): Send our WireGuard key after symmetric key exchange
                                if (!isServer && !clientIPAssigned && wireguardTunnel != null && privateIP != null && ownMeshIP != null)
                                {
                                    clientIPAssigned = true;

                                    try
                                    {
                                        string configPath = wireguardTunnel.GetConfigPath();
                                        string clientWgPublicKey = WireGuardConfig.GetPublicKeyFromConfig(configPath);

                                        message = new MediationMessage(MediationMessageType.WireGuardPublicKeyExchange);
                                        message.WireGuardPublicKey = clientWgPublicKey;
                                        message.WireGuardPublicKeyHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(clientWgPublicKey));
                                        message.SetPrivateAddress(privateIP);

                                        byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                        udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, c.GetEndPoint());
                                    }
                                    catch (Exception wgEx)
                                    {
                                        Console.WriteLine($"Error sending WireGuard public key: {wgEx.Message}");
                                    }
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

                                if (hashMatches)
                                {
                                    c.ImportWireGuardPublicKey(receivedMessage.WireGuardPublicKey);
                                    Console.WriteLine($"Imported client WireGuard public key");

                                    // Add client as WireGuard peer using their actual public key and NAT-traversed endpoint
                                    if (wireguardTunnel != null)
                                    {
                                        try
                                        {
                                            // Use the client's received public key and actual NAT-traversed endpoint
                                            // Pass our tunnel socket for proxy routing
                                            var peer = wireguardTunnel.AddPeer(c.WireGuardPublicKey, c.GetEndPoint(), false, udpClient);

                                            // CRITICAL: Update client's IP to match what peer manager assigned
                                            // This handles reconnections where an existing peer is reused with its old IP
                                            if (!peer.PrivateAddress.Equals(c.GetPrivateAddress()))
                                            {
                                                Console.WriteLine($"Updating client IP to {peer.PrivateAddress} (peer reused)");
                                                c.SetPrivateAddress(peer.PrivateAddress);
                                            }

                                            Console.WriteLine($"Added client peer: {peer.PrivateAddress}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Error adding client as peer: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Cannot add peer: tunnel not initialized");
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
                                        // Send the client's assigned IP (might be different from what they initially got if reconnecting)
                                        message.SetPrivateAddress(c.GetPrivateAddress());
                                        byte[] wgKeyBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                                        udpClient.Send(wgKeyBuffer, wgKeyBuffer.Length, c.GetEndPoint());

                                        Console.WriteLine($"WireGuard keys exchanged with client");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Server public key is empty, cannot send to client");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"WireGuard public key hash validation failed");
                                }
                            }
                        }
                        else
                        {
                            // Client: receive server's WireGuard public key

                            if (receivedMessage.WireGuardPublicKey != null && !receivedMessage.WireGuardPublicKey.Equals(""))
                            {
                                var expectedHash = shaHashGen.ComputeHash(Encoding.UTF8.GetBytes(receivedMessage.WireGuardPublicKey));
                                var hashMatches = StructuralComparisons.StructuralEqualityComparer.Equals(receivedMessage.WireGuardPublicKeyHash, expectedHash);

                                if (hashMatches)
                                {
                                    Console.WriteLine($"Received server's WireGuard public key");

                                    // Store server's WireGuard public key by adding it as a peer
                                    if (wireguardTunnel != null && targetPeerIp != null && targetPeerPort != 0)
                                    {
                                        try
                                        {
                                            // Use the actual NAT-traversed endpoint established by mediation
                                            var serverEndpoint = new IPEndPoint(targetPeerIp, targetPeerPort);

                                            // Add server as a peer with its public key
                                            // Pass our tunnel socket for proxy routing
                                            var serverPeer = wireguardTunnel.AddPeer(receivedMessage.WireGuardPublicKey, serverEndpoint, isPersistent: true, tunnelSocket: udpClient);
                                            Console.WriteLine($"Added server peer: {serverPeer.PrivateAddress}");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Error adding server as peer: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Cannot add server peer: missing tunnel or endpoint information");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Server WireGuard public key hash validation failed");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Server's WireGuard public key is invalid");
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

    private void TcpListenLoop()
    {
        while (tcpClient.Connected)
        {
            try
            {
                byte[] receiveBuffer = new byte[tcpClient.ReceiveBufferSize];
                //TODO: sometimes fails here
                int bytesRead = tcpClientStream.Read(receiveBuffer, 0, tcpClient.ReceiveBufferSize);

                // Check if connection closed or no data received
                if (bytesRead == 0)
                {
                    Console.WriteLine("TCP connection closed by mediation server");
                    break; // Exit the listen loop
                }

                string receivedString = Encoding.ASCII.GetString(receiveBuffer, 0, bytesRead);

                // Skip empty or whitespace-only messages
                if (string.IsNullOrWhiteSpace(receivedString))
                {
                    continue;
                }

                Console.WriteLine("Received: " + receivedString);

                // Define local functions for message processing (only defined once per iteration)

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
                    Console.WriteLine($"[TryConnectFromSymmetric] Called. holePunchReceivedCount={holePunchReceivedCount}, probes={symmetricConnectionUdpProbes.Count}");

                    // For symmetric NAT, ALWAYS send from all 256 probes until connection is confirmed
                    // Don't switch to shared client just because we received packets - we need to keep
                    // sending from all probes so the remote peer can receive from the successful probe
                    if (holePunchReceivedCount < HOLE_PUNCH_THRESHOLD)
                    {
                        Console.WriteLine($"[TryConnectFromSymmetric] Sending from {symmetricConnectionUdpProbes.Count} probe clients to {targetPeerIp}:{targetPeerPort}");
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        foreach (UdpClient probe in symmetricConnectionUdpProbes)
                        {
                            probe.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
                        }
                        Console.WriteLine($"[TryConnectFromSymmetric] Sent from all {symmetricConnectionUdpProbes.Count} probes");
                    }
                    else
                    {
                        // Connection confirmed - send from shared client
                        Console.WriteLine($"[TryConnectFromSymmetric] Connection confirmed, sending from shared UDP client");
                        MediationMessage message = new MediationMessage(MediationMessageType.SymmetricHolePunchAttempt);
                        if (Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")) != null)
                        {
                            if (isServer) message.SetPrivateAddress(Clients.GetClient(IPEndPoint.Parse($"{targetPeerIp}:{targetPeerPort}")).GetPrivateAddress());
                        }
                        byte[] sendBuffer = Encoding.ASCII.GetBytes(message.Serialize());
                        udpClient.Send(sendBuffer, sendBuffer.Length, new IPEndPoint(targetPeerIp, targetPeerPort));
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

                // Handle multiple JSON objects in the same buffer
                // Split by detecting JSON object boundaries (each starts with '{' and ends with '}')
                int jsonStartIndex = 0;
                while (jsonStartIndex < receivedString.Length)
                {
                    // Find the start of the next JSON object
                    int jsonObjStart = receivedString.IndexOf('{', jsonStartIndex);
                    if (jsonObjStart == -1) break;

                    // Find the matching closing brace by counting braces
                    int braceCount = 0;
                    int jsonObjEnd = -1;
                    for (int i = jsonObjStart; i < receivedString.Length; i++)
                    {
                        if (receivedString[i] == '{') braceCount++;
                        else if (receivedString[i] == '}')
                        {
                            braceCount--;
                            if (braceCount == 0)
                            {
                                jsonObjEnd = i;
                                break;
                            }
                        }
                    }

                    if (jsonObjEnd == -1)
                    {
                        Console.WriteLine("⚠ Incomplete JSON object in buffer (should not happen with TCP)");
                        break;
                    }

                    // Extract and parse this JSON object
                    string jsonObject = receivedString.Substring(jsonObjStart, jsonObjEnd - jsonObjStart + 1);

                    MediationMessage receivedMessage;
                    try
                    {
                        receivedMessage = JsonSerializer.Deserialize<MediationMessage>(jsonObject);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error parsing JSON: {ex.Message}");
                        jsonStartIndex = jsonObjEnd + 1;
                        continue;
                    }

                    // Process this message
                    switch (receivedMessage.ID)
                    {
                        case MediationMessageType.Connected:
                            {
                                MediationMessage message = new MediationMessage(MediationMessageType.NATTypeRequest);
                                message.LocalPort = ((IPEndPoint)udpClient.Client.LocalEndPoint).Port;
                                message.ClientID = clientID;
                                // Include connection ID if this tunnel is for a specific connection (server-side per-client tunnel)
                                if (assignedConnectionID != 0)
                                {
                                    message.ConnectionID = assignedConnectionID;
                                }
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
                                retryAttempt = 0;  // Reset retry counter for new connection attempt
                                initialConnectionTimer.Enabled = true;
                                currentConnectionID = receivedMessage.ConnectionID;

                                // Store peer's mesh IP for WireGuard peer addition
                                if (!string.IsNullOrEmpty(receivedMessage.PrivateAddressString))
                                {
                                    peerMeshIP = IPAddress.Parse(receivedMessage.PrivateAddressString);
                                }

                                // For mesh tunnels, server skips NAT detection and sends our NAT type in OwnNATType field
                                if (receivedMessage.OwnNATType.HasValue && natType == NATType.Unknown)
                                {
                                    natType = receivedMessage.OwnNATType.Value;

                                    // Start UDP listening if not already started (mesh tunnels skip NATTypeResponse)
                                    if (!isServer && !udpClientTaskCancellationToken.IsCancellationRequested)
                                    {
                                        UdpClient();
                                    }
                                }

                                if (natType == NATType.Symmetric)
                                {
                                    Console.WriteLine($"[Symmetric NAT] Our NAT is Symmetric, setting up 256 probe clients");
                                    IPEndPoint targetPeerEndpoint = receivedMessage.GetEndpoint();
                                    targetPeerIp = targetPeerEndpoint.Address;
                                    targetPeerPort = targetPeerEndpoint.Port;
                                    Console.WriteLine($"[Symmetric NAT] Target peer: {targetPeerIp}:{targetPeerPort}");

                                    connectionAttempt = new Timer(1000)
                                    {
                                        AutoReset = true,
                                        Enabled = false
                                    };
                                    connectionAttempt.Elapsed += TryConnectFromSymmetric;
                                    Console.WriteLine($"[Symmetric NAT] Created timer with TryConnectFromSymmetric handler");

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

                                    Console.WriteLine($"[Symmetric NAT] Created {symmetricConnectionUdpProbes.Count} probe UDP clients");
                                    connectionAttempt.Enabled = true;
                                    Console.WriteLine($"[Symmetric NAT] Timer enabled, will send from all {symmetricConnectionUdpProbes.Count} probes");
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
                                Console.WriteLine($"[ConnectionComplete] Received. currentConnectionID = {currentConnectionID}, isServer = {isServer}");
                                if (isServer)
                                {
                                    holePunchReceivedCount = 5;
                                    // Look up client by connection ID instead of endpoint
                                    // (endpoint may have changed for Symmetric NAT after hole punching)
                                    Console.WriteLine($"[ConnectionComplete] Looking up client by ConnectionID: {currentConnectionID}");
                                    Console.WriteLine($"[ConnectionComplete] Total clients in list: {Clients.Count}");
                                    var client = Clients.GetClient(currentConnectionID);
                                    if (client != null)
                                    {
                                        client.Connected = true;
                                        initialConnectionTimer.Enabled = false;
                                        Console.WriteLine($"✓ Connection {currentConnectionID} marked complete for client at {client.GetEndPoint()}");
                                        Console.WriteLine("Completed");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"⚠ Cannot mark connection complete: Client with ConnectionID {currentConnectionID} not found");
                                        Console.WriteLine($"   (Was looking for endpoint: {targetPeerIp}:{targetPeerPort})");
                                        Console.WriteLine($"   Current clients:");
                                        foreach (var c in Clients.GetAll())
                                        {
                                            Console.WriteLine($"     - ConnectionID: {c.ConnectionID}, Endpoint: {c.GetEndPoint()}");
                                        }
                                    }
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
                                    Console.WriteLine("Connection established. Retry counter reset.");
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

                    // Move to next JSON object in buffer
                    jsonStartIndex = jsonObjEnd + 1;
                } // End of while loop for processing multiple JSON objects

            } // End of try block
            catch (IOException ioEx) when (ioEx.InnerException is SocketException socketEx &&
                                          (socketEx.SocketErrorCode == SocketError.ConnectionAborted ||
                                           socketEx.SocketErrorCode == SocketError.ConnectionReset))
            {
                // Connection was closed during restart - this is expected
                Console.WriteLine("[TcpListenLoop] Connection closed during restart (expected)");
                break;  // Exit loop cleanly
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

    /// <summary>
    /// Gets the time since last activity on this tunnel
    /// </summary>
    public TimeSpan GetTimeSinceLastActivity()
    {
        return DateTime.UtcNow - lastActivityTime;
    }

    /// <summary>
    /// Gets whether this tunnel is considered active (received/sent data recently)
    /// </summary>
    public bool IsActive(TimeSpan inactivityThreshold)
    {
        return GetTimeSinceLastActivity() < inactivityThreshold;
    }

    /// <summary>
    /// Updates the last activity timestamp (called when data is received/sent)
    /// </summary>
    private void UpdateActivity()
    {
        lastActivityTime = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the connection ID for this tunnel (used by TunnelManager)
    /// </summary>
    public int GetConnectionID()
    {
        return currentConnectionID != 0 ? currentConnectionID : assignedConnectionID;
    }

    /// <summary>
    /// Gets activity statistics for this tunnel
    /// </summary>
    public (long BytesReceived, long BytesSent, DateTime LastActivity) GetActivityStats()
    {
        return (totalBytesReceived, totalBytesSent, lastActivityTime);
    }

    /// <summary>
    /// Notify tunnel that connection is complete (called by mesh mode when it receives ConnectionComplete)
    /// </summary>
    public void NotifyConnectionComplete()
    {
        Console.WriteLine($"[Tunnel {assignedConnectionID}] NotifyConnectionComplete called");
        connected = true;
        initialConnectionTimer.Enabled = false;
        retryAttempt = 0;  // Reset retry counter on successful connection
        Console.WriteLine($"[Tunnel {assignedConnectionID}] Connection marked complete");
    }

    /// <summary>
    /// Disposes of tunnel resources properly
    /// </summary>
    public void Dispose()
    {
        try
        {
            // Cancel all running tasks
            tcpClientTaskCancellationToken?.Cancel();
            udpClientTaskCancellationToken?.Cancel();
            udpServerTaskCancellationToken?.Cancel();

            // Stop timers
            initialConnectionTimer?.Stop();
            initialConnectionTimer?.Dispose();
            connectionAttempt?.Stop();
            connectionAttempt?.Dispose();

            // Close network streams
            tcpClientStream?.Close();
            tcpClientStream?.Dispose();

            // Close clients
            tcpClient?.Close();
            tcpClient?.Dispose();

            // Don't dispose udpClient if it's shared (managed by TunnelManager)
            if (!isManagedByTunnelManager)
            {
                udpClient?.Close();
                udpClient?.Dispose();
            }

            // Dispose symmetric NAT probe sockets
            foreach (var probe in symmetricConnectionUdpProbes)
            {
                probe?.Close();
                probe?.Dispose();
            }
            symmetricConnectionUdpProbes.Clear();

            // Dispose crypto resources
            rsa?.Dispose();
            rsaServer?.Dispose();
            aes?.Dispose();
            shaHashGen?.Dispose();

            Console.WriteLine($"[Tunnel] Disposed tunnel {GetConnectionID()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Tunnel] Error during disposal: {ex.Message}");
        }
    }
}
