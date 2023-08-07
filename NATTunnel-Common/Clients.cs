using System.Collections.Generic;
using System.Net;

namespace NATTunnel.Common;

public static class Clients
{
    private static List<Client> ClientList = new List<Client>();
    public static int Count = ClientList.Count;

    public static List<Client> GetAll()
    {
        return ClientList;
    }
    public static Client GetClient(IPEndPoint endpoint)
    {
        int clientIndex = ClientList.FindIndex(c => c.GetEndPoint().Equals(endpoint));
        if(!clientIndex.Equals(-1))
        {
            return ClientList.Find(c => c.GetEndPoint().Equals(endpoint));
        }
        return null;
    }

    public static Client GetClient(IPAddress privateAddress)
    {
        int clientIndex = ClientList.FindIndex(c => c.GetPrivateAddress().Equals(privateAddress));
        if(!clientIndex.Equals(-1))
        {
            return ClientList.Find(c => c.GetPrivateAddress().Equals(privateAddress));
        }
        return null;
    }

    public static void Add(Client client)
    {
        int clientIndex = ClientList.FindIndex(c => c.Equals(client));
        if(clientIndex.Equals(-1))
        {
            ClientList.Add(client);
            Count = ClientList.Count;
        }
    }

    public static void Remove(Client client)
    {
        int clientIndex = ClientList.FindIndex(c => c.Equals(client));
        if(!clientIndex.Equals(-1))
        {
            ClientList.Remove(ClientList.Find(c => c.Equals(client)));
            Count = ClientList.Count;
        }
    }
}