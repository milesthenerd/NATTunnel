using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NATTunnel.Embedded;

// POC test app.
//
// Usage: embedded-poc-test <mediationHost> <mediationPort> <networkID> <networkSecret>
//
// Behavior:
//   1. Start a MeshNodeEmbedded, do the mediation handshake + mesh join.
//   2. Bind a host UDP socket on a known loopback port (default 51000) — this is where the
//      "game" lives. Any inbound datagram is echoed back to the sender.
//   3. When a peer connects, spawn a sender that pings that peer's LoopbackEndpoint every
//      second. Replies come back to the host UDP socket via the proxy.
//
// Two instances of this app, pointed at the same mediation server with the same networkID,
// should discover each other and exchange pings.

if (args.Length < 4)
{
    Console.Error.WriteLine("Usage: embedded-poc-test <mediationHost> <mediationPort> <networkID> <networkSecret>");
    return 1;
}

string mediationHost = args[0];
int mediationPort = int.Parse(args[1]);
string networkID = args[2];
string networkSecret = args[3];
const int hostGamePort = 51000;

Console.WriteLine($"[Test] mediation={mediationHost}:{mediationPort} network={networkID}");

// Host-side UDP socket. Anything received here came from a remote mesh peer via a MeshPeerProxy.
var hostSocket = new UdpClient(new IPEndPoint(IPAddress.Loopback, hostGamePort));
Console.WriteLine($"[Test] Host game socket listening on 127.0.0.1:{hostGamePort}");

// Echo loop: any inbound datagram gets echoed back to the sender.
_ = Task.Run(async () =>
{
    try
    {
        while (true)
        {
            var result = await hostSocket.ReceiveAsync();
            string text = Encoding.UTF8.GetString(result.Buffer);
            Console.WriteLine($"[Test/Recv] from {result.RemoteEndPoint}: {text}");

            // Echo back.
            byte[] reply = Encoding.UTF8.GetBytes($"echo: {text}");
            hostSocket.Send(reply, reply.Length, result.RemoteEndPoint);
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[Test] echo loop crashed: {ex.Message}");
    }
});

// Boot the mesh node.
using var node = new MeshNodeEmbedded(
    mediationHost: mediationHost,
    mediationPort: mediationPort,
    networkID: networkID,
    networkSecret: networkSecret,
    hostGamePort: hostGamePort);

node.PeerConnected += peer =>
{
    Console.WriteLine($"[Test] Peer connected: {peer.PeerID} via {peer.LoopbackEndpoint}");

    // Send a ping every 2 seconds.
    _ = Task.Run(async () =>
    {
        int counter = 0;
        try
        {
            while (true)
            {
                counter++;
                byte[] msg = Encoding.UTF8.GetBytes($"ping #{counter} from {node.OwnPeerID}");
                hostSocket.Send(msg, msg.Length, peer.LoopbackEndpoint);
                Console.WriteLine($"[Test/Send] → {peer.LoopbackEndpoint}: ping #{counter}");
                await Task.Delay(2000);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Test] sender crashed: {ex.Message}");
        }
    });
};

node.Start();
Console.WriteLine($"[Test] My peer ID: {node.OwnPeerID}");
Console.WriteLine("[Test] Press Ctrl+C to exit.");

// Block until interrupted.
var exitEvent = new ManualResetEventSlim(false);
Console.CancelKeyPress += (_, e) => { e.Cancel = true; exitEvent.Set(); };
exitEvent.Wait();
Console.WriteLine("[Test] Shutting down.");
return 0;
