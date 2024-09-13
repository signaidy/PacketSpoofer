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

        // Puertos de origen y destino
        int sourcePort = 12345;
        int destPort = 80; // Puerto HTTP

        // Crea el paquete TCP/IP
        byte[] packet = CreateTcpIpPacket(sourceIp, destIp, sourcePort, destPort);

        // Envío del paquete
        SendRawPacket(packet, destIp);
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
                return null;
            }

            isValid = IPAddress.TryParse(ip, out IPAddress address);
            if (!isValid)
            {
                Console.WriteLine($"La IP de {tipo} '{ip}' no es válida. Inténtalo de nuevo.");
            }
        } while (!isValid);

        return ip;
    }

    static byte[] CreateTcpIpPacket(string sourceIp, string destIp, int sourcePort, int destPort)
    {
        byte[] packet = new byte[40]; // Tamaño de encabezados IP + TCP (20 bytes cada uno)

        // Llenar la cabecera IP
        packet[0] = 0x45; // Versión IPv4 y longitud de cabecera (5 palabras)
        packet[1] = 0x00; // Tipo de servicio
        packet[2] = 0x00; // Longitud total del paquete (más adelante)
        packet[3] = 0x28; // Longitud total
        packet[4] = 0x1C; // Identificación
        packet[5] = 0x46; // Identificación
        packet[6] = 0x40; // Flags
        packet[7] = 0x00; // Fragment offset
        packet[8] = 0x40; // TTL (64)
        packet[9] = 0x06; // Protocolo (TCP)
        packet[10] = 0x00; // Checksum (será calculado más adelante)
        packet[11] = 0x00;

        // IP Origen
        Array.Copy(IPAddress.Parse(sourceIp).GetAddressBytes(), 0, packet, 12, 4);

        // IP Destino
        Array.Copy(IPAddress.Parse(destIp).GetAddressBytes(), 0, packet, 16, 4);

        // Llenar la cabecera TCP
        Array.Copy(BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)sourcePort)), 0, packet, 20, 2); // Puerto origen
        Array.Copy(BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder((short)destPort)), 0, packet, 22, 2); // Puerto destino
        Array.Copy(BitConverter.GetBytes((uint)0), 0, packet, 24, 4); // Número de secuencia
        Array.Copy(BitConverter.GetBytes((uint)0), 0, packet, 28, 4); // Número de confirmación
        packet[32] = 0x50; // Offset de datos y reservado
        packet[33] = 0x02; // Flags (SYN)
        packet[34] = 0x71; // Tamaño de ventana
        packet[35] = 0x10;
        packet[36] = 0x00; // Checksum (será calculado más adelante)
        packet[37] = 0x00;
        packet[38] = 0x00; // Puntero urgente
        packet[39] = 0x00;

        // Calcula el checksum (omitiendo en este ejemplo, lo haremos luego si es necesario)
        return packet;
    }

    static void SendRawPacket(byte[] packet, string destIp)
    {
        // Crea un socket RAW
        Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        sock.Bind(new IPEndPoint(IPAddress.Parse(destIp), 0));  // Vincula el socket

        // Configura el socket para incluir encabezados IP en los datos enviados
        sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

        IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse(destIp), 0);
        sock.SendTo(packet, endPoint);

        Console.WriteLine("Paquete TCP/IP enviado.");
    }
}
