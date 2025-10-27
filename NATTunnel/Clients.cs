using System;
using System.Collections.Generic;
using System.Net;

namespace NATTunnel;

public static class Clients
{
    private static List<Client> ClientList = new List<Client>();
    public static int Count = ClientList.Count;
    private static WireGuardTunnel wireguardTunnel;

    public static void SetWireGuardTunnel(WireGuardTunnel tunnel)
    {
        wireguardTunnel = tunnel;
    }

    public static List<Client> GetAll()
    {
        return ClientList;
    }
    public static Client GetClient(IPEndPoint endpoint)
    {
        int clientIndex = ClientList.FindIndex(c => c.GetEndPoint().Equals(endpoint));
        if (!clientIndex.Equals(-1))
        {
            return ClientList.Find(c => c.GetEndPoint().Equals(endpoint));
        }
        return null;
    }

    public static Client GetClient(IPAddress privateAddress)
    {
        int clientIndex = ClientList.FindIndex(c => c.GetPrivateAddress().Equals(privateAddress));
        if (!clientIndex.Equals(-1))
        {
            return ClientList.Find(c => c.GetPrivateAddress().Equals(privateAddress));
        }
        return null;
    }

    public static Client GetClient(int connectionID)
    {
        int clientIndex = ClientList.FindIndex(c => c.ConnectionID.Equals(connectionID));
        if (!clientIndex.Equals(-1))
        {
            return ClientList.Find(c => c.ConnectionID.Equals(connectionID));
        }
        return null;
    }

    public static void Add(Client client)
    {
        int clientIndex = ClientList.FindIndex(c => c.Equals(client));
        if (clientIndex.Equals(-1))
        {
            ClientList.Add(client);
            Count = ClientList.Count;

            // Add the client as a WireGuard peer if WireGuard tunnel is available
            // Note: Peer will be added later when we receive the client's WireGuard public key
            // This ensures we use the correct public key from the client, not a generated one

            //client.capture = new FrameCapture(CaptureMode.Public, client.GetEndPoint().Address.ToString());
            //client.capture.Start();
        }
    }

    public static void Remove(Client client)
    {
        int clientIndex = ClientList.FindIndex(c => c.Equals(client));
        if (!clientIndex.Equals(-1))
        {
            //client.capture.Stop();
            ClientList.Remove(ClientList.Find(c => c.Equals(client)));
            Count = ClientList.Count;
        }
    }
}