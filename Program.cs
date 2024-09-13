using System;
using System.Net;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Ingrese la IP de origen:");
        string sourceIp = Console.ReadLine();
        
        Console.WriteLine("Ingrese la IP de destino:");
        string destIp = Console.ReadLine();

        // Validar IP de origen
        if (IsValidIP(sourceIp))
        {
            Console.WriteLine($"La IP de origen '{sourceIp}' es válida.");
        }
        else
        {
            Console.WriteLine($"La IP de origen '{sourceIp}' no es válida. Por favor ingrese una IP válida.");
            return;
        }

        // Validar IP de destino
        if (IsValidIP(destIp))
        {
            Console.WriteLine($"La IP de destino '{destIp}' es válida.");
        }
        else
        {
            Console.WriteLine($"La IP de destino '{destIp}' no es válida. Por favor ingrese una IP válida.");
            return;
        }
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

        // Si llega aquí, no es una IP válida
        return false;
    }
}
