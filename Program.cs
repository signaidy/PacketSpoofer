using System;
using System.Net;

class Program
{
    static void Main(string[] args)
    {
        string sourceIp = GetValidIP("origen");
        string destIp = GetValidIP("destino");

        Console.WriteLine($"IP de origen válida: {sourceIp}");
        Console.WriteLine($"IP de destino válida: {destIp}");
    }

    static string GetValidIP(string tipo)
    {
        string ip;
        bool isValid = false;

        do
        {
            Console.WriteLine($"Ingrese la IP de {tipo}:");
            ip = Console.ReadLine();
            isValid = IsValidIP(ip);
            
            if (!isValid)
            {
                Console.WriteLine($"La IP de {tipo} '{ip}' no es válida. Inténtalo de nuevo.");
            }
        } while (!isValid);

        return ip;
    }

    static bool IsValidIP(string ip)
    {
        if (IPAddress.TryParse(ip, out IPAddress address))
        {
            // Comprobar si es IPv4 o IPv6
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                Console.WriteLine($"{ip} es una dirección IPv4.");
                return true;
            }
            else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                Console.WriteLine($"{ip} es una dirección IPv6.");
                return true;
            }
        }

        return false;
    }
}
