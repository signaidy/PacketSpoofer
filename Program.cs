using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string sourceIp = GetValidIP("origen", null);
        string destIp = GetValidIP("destino", sourceIp);

        if (IPAddress.TryParse(sourceIp, out IPAddress srcAddress) && IPAddress.TryParse(destIp, out IPAddress dstAddress))
        {
            if (srcAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                Console.WriteLine("Creando paquete IPv4...");
                byte[] packet = CreateIPv4Packet(srcAddress, dstAddress);
                SendPacket(packet, AddressFamily.InterNetwork);
            }
            else if (srcAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine("Creando paquete IPv6...");
                byte[] packet = CreateIPv6Packet(srcAddress, dstAddress);
                SendPacket(packet, AddressFamily.InterNetworkV6);
            }
        }
    }

    static string GetValidIP(string tipo, string previousIp)
    {
        string ip;
        bool isValid = false;

        do
        {
            Console.WriteLine($"Ingrese la IP de {tipo} (escriba 'back' para regresar o 'exit' para salir):");
            ip = Console.ReadLine();

            if (ip.ToLower() == "exit")
            {
                Console.WriteLine("Saliendo del programa...");
                Environment.Exit(0);
            }
            else if (ip.ToLower() == "back" && previousIp != null)
            {
                Console.WriteLine("Regresando a la opción anterior...");
                return null;
            }

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
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                Console.WriteLine($"{ip} es una dirección IPv4.");
                return true;
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine($"{ip} es una dirección IPv6.");
                return true;
            }
        }

        return false;
    }

    static byte[] CreateIPv4Packet(IPAddress sourceIp, IPAddress destIp)
    {
        byte[] packet = new byte[20 + 20]; // 20 bytes header IP + 20 bytes header TCP

        // Header IPv4
        packet[0] = 0x45; // Version (4 bits) + IHL (4 bits)
        packet[8] = 64;   // TTL
        packet[9] = 6;    // Protocolo TCP

        // Direcciones IP
        Array.Copy(sourceIp.GetAddressBytes(), 0, packet, 12, 4); // IP origen
        Array.Copy(destIp.GetAddressBytes(), 0, packet, 16, 4);   // IP destino

        // Añadimos el encabezado TCP manualmente
        CreateTCPHeader(packet, 20, 12345, 80); // Puerto origen 12345, puerto destino 80

        return packet;
    }

    static byte[] CreateIPv6Packet(IPAddress sourceIp, IPAddress destIp)
    {
        byte[] packet = new byte[40 + 20]; // 40 bytes header IP + 20 bytes header TCP

        // Header IPv6
        packet[0] = 0x60; // Version (4 bits) + Traffic Class (8 bits)

        // Hop limit
        packet[7] = 64;

        // Direcciones IP
        Array.Copy(sourceIp.GetAddressBytes(), 0, packet, 8, 16);  // IP origen
        Array.Copy(destIp.GetAddressBytes(), 0, packet, 24, 16);   // IP destino

        // Añadimos el encabezado TCP manualmente
        CreateTCPHeader(packet, 40, 12345, 80); // Puerto origen 12345, puerto destino 80

        return packet;
    }

    static void CreateTCPHeader(byte[] packet, int offset, ushort sourcePort, ushort destPort)
    {
        // Puerto de origen (16 bits)
        packet[offset] = (byte)(sourcePort >> 8);
        packet[offset + 1] = (byte)(sourcePort & 0xFF);

        // Puerto de destino (16 bits)
        packet[offset + 2] = (byte)(destPort >> 8);
        packet[offset + 3] = (byte)(destPort & 0xFF);

        // Número de secuencia (32 bits, valor fijo para este ejemplo)
        packet[offset + 4] = 0;
        packet[offset + 5] = 0;
        packet[offset + 6] = 0;
        packet[offset + 7] = 1;

        // Número de acuse de recibo (32 bits, valor fijo para este ejemplo)
        packet[offset + 8] = 0;
        packet[offset + 9] = 0;
        packet[offset + 10] = 0;
        packet[offset + 11] = 0;

        // Offset de datos (4 bits) + Flags TCP (8 bits)
        packet[offset + 12] = 0x50; // Offset de datos = 5 (sin opciones)
        packet[offset + 13] = 0x02; // Bandera SYN

        // Ventana (16 bits, valor fijo)
        packet[offset + 14] = 0xFF;
        packet[offset + 15] = 0xFF;

        // Checksum (16 bits, valor fijo)
        packet[offset + 16] = 0;
        packet[offset + 17] = 0;

        // Puntero urgente (16 bits, valor fijo)
        packet[offset + 18] = 0;
        packet[offset + 19] = 0;
    }

    static void SendPacket(byte[] packet, AddressFamily addressFamily)
    {
        Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Tcp);

        if (addressFamily == AddressFamily.InterNetwork)
        {
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 80);
            socket.SendTo(packet, endPoint);
        }
        else if (addressFamily == AddressFamily.InterNetworkV6)
        {
            IPEndPoint endPoint = new IPEndPoint(IPAddress.IPv6Loopback, 80);
            socket.SendTo(packet, endPoint);
        }

        Console.WriteLine("Paquete enviado.");
    }
}
