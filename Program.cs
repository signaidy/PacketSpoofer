using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string sourceIp = GetValidIP("origen", null);
        if (sourceIp == null) return; // Usuario eligió 'exit'

        string destIp = GetValidIP("destino", sourceIp);
        if (destIp == null) return; // Usuario eligió 'back' o 'exit'

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
        byte[] ipHeader = new byte[20];
        byte[] tcpHeader = new byte[20];
        byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];

        // Construcción del Encabezado IPv4
        ipHeader[0] = 0x45; // Version (4 bits) + IHL (4 bits)
        ipHeader[1] = 0x00; // Tipo de Servicio
        ipHeader[2] = 0x00; // Longitud Total (Se actualizará más adelante)
        ipHeader[3] = 0x28; // Longitud Total = 40 bytes (20 IP + 20 TCP)

        ipHeader[4] = 0x00; // Identificación
        ipHeader[5] = 0x00;

        ipHeader[6] = 0x40; // Flags (No fragmentar) + Fragment Offset
        ipHeader[7] = 0x00;

        ipHeader[8] = 64;    // TTL
        ipHeader[9] = 6;     // Protocolo TCP

        // Checksum IPv4 (inicialmente 0, se calculará después)
        ipHeader[10] = 0x00;
        ipHeader[11] = 0x00;

        // Direcciones IP
        Array.Copy(sourceIp.GetAddressBytes(), 0, ipHeader, 12, 4); // IP origen
        Array.Copy(destIp.GetAddressBytes(), 0, ipHeader, 16, 4);   // IP destino

        // Calcula el checksum IPv4
        ushort ipChecksum = CalculateChecksum(ipHeader, ipHeader.Length);
        ipHeader[10] = (byte)(ipChecksum >> 8);
        ipHeader[11] = (byte)(ipChecksum & 0xFF);

        // Construcción del Encabezado TCP
        ushort sourcePort = 12345;
        ushort destPort = 80;
        tcpHeader[0] = (byte)(sourcePort >> 8);
        tcpHeader[1] = (byte)(sourcePort & 0xFF);
        tcpHeader[2] = (byte)(destPort >> 8);
        tcpHeader[3] = (byte)(destPort & 0xFF);

        // Número de secuencia
        tcpHeader[4] = 0x00;
        tcpHeader[5] = 0x00;
        tcpHeader[6] = 0x00;
        tcpHeader[7] = 0x01;

        // Número de acuse de recibo
        tcpHeader[8] = 0x00;
        tcpHeader[9] = 0x00;
        tcpHeader[10] = 0x00;
        tcpHeader[11] = 0x00;

        // Offset de datos (5) + Reservado + Flags (SYN)
        tcpHeader[12] = 0x50; // Data offset = 5 (20 bytes), reservados
        tcpHeader[13] = 0x02; // Flags: SYN

        // Ventana
        tcpHeader[14] = 0xFF;
        tcpHeader[15] = 0xFF;

        // Checksum TCP (inicialmente 0, se calculará después)
        tcpHeader[16] = 0x00;
        tcpHeader[17] = 0x00;

        // Puntero urgente
        tcpHeader[18] = 0x00;
        tcpHeader[19] = 0x00;

        // Construir el paquete completo (IP + TCP)
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

        // Calcula el checksum TCP
        ushort tcpChecksum = CalculateTcpChecksum(ipHeader, tcpHeader);
        tcpHeader[16] = (byte)(tcpChecksum >> 8);
        tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

        // Actualizar el checksum en el paquete
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

        return packet;
    }

    static byte[] CreateIPv6Packet(IPAddress sourceIp, IPAddress destIp)
    {
        byte[] ipHeader = new byte[40];
        byte[] tcpHeader = new byte[20];
        byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];
        ushort payloadLength = (ushort)tcpHeader.Length;

        // Construcción del Encabezado IPv6
        ipHeader[0] = 0x60; // Version (4 bits) + Traffic Class (8 bits superiores)
        ipHeader[1] = 0x00; // Traffic Class (8 bits inferiores)
        ipHeader[2] = 0x00; // Flow Label
        ipHeader[3] = 0x00;

        // Longitud del Payload (TCP Header)
        ipHeader[4] = (byte)(payloadLength >> 8);  // Parte alta
        ipHeader[5] = (byte)(payloadLength & 0xFF);  // Parte baja

        // Protocolo TCP (Next Header) y Hop Limit
        ipHeader[6] = 0x06; // TCP (Next Header)
        ipHeader[7] = 0x40; // Hop Limit (64)

        // Direcciones IP
        Array.Copy(sourceIp.GetAddressBytes(), 0, ipHeader, 8, 16);  // IP origen
        Array.Copy(destIp.GetAddressBytes(), 0, ipHeader, 24, 16);   // IP destino

        // Construcción del Encabezado TCP
        ushort sourcePort = 12345;
        ushort destPort = 80;
        tcpHeader[0] = (byte)(sourcePort >> 8);
        tcpHeader[1] = (byte)(sourcePort & 0xFF);
        tcpHeader[2] = (byte)(destPort >> 8);
        tcpHeader[3] = (byte)(destPort & 0xFF);

        // Número de secuencia
        tcpHeader[4] = 0x00;
        tcpHeader[5] = 0x00;
        tcpHeader[6] = 0x00;
        tcpHeader[7] = 0x01;

        // Número de acuse de recibo
        tcpHeader[8] = 0x00;
        tcpHeader[9] = 0x00;
        tcpHeader[10] = 0x00;
        tcpHeader[11] = 0x00;

        // Offset de datos (5) + Reservado + Flags (SYN)
        tcpHeader[12] = 0x50; // Data offset = 5 (20 bytes), reservados
        tcpHeader[13] = 0x02; // Flags: SYN

        // Ventana
        tcpHeader[14] = 0xFF;
        tcpHeader[15] = 0xFF;

        // Checksum TCP (inicialmente 0, se calculará después)
        tcpHeader[16] = 0x00;
        tcpHeader[17] = 0x00;

        // Puntero urgente
        tcpHeader[18] = 0x00;
        tcpHeader[19] = 0x00;

        // Construir el paquete completo (IP + TCP)
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

        // Calcula el checksum TCP
        ushort tcpChecksum = CalculateTcpv6Checksum(ipHeader, tcpHeader);
        tcpHeader[16] = (byte)(tcpChecksum >> 8);
        tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

        // Actualizar el checksum en el paquete
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);

        return packet;
    }

    static ushort CalculateChecksum(byte[] data, int length)
    {
        uint sum = 0;
        int i;

        // Sumar cada palabra de 16 bits
        for (i = 0; i < length - 1; i += 2)
        {
            ushort word = BitConverter.ToUInt16(data, i);
            sum += word;
        }

        // Si hay un byte sobrante, sumarlo
        if (length % 2 == 1)
        {
            ushort word = (ushort)(data[length - 1] << 8);
            sum += word;
        }

        // Sumar el acarreo
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Retornar el complemento a uno
        return (ushort)~sum;
    }

    static ushort CalculateTcpChecksum(byte[] ipHeader, byte[] tcpHeader)
    {
        // Pseudo-encabezado para IPv4
        byte[] pseudoHeader = new byte[12];
        Array.Copy(ipHeader, 12, pseudoHeader, 0, 8); // IP origen y destino
        pseudoHeader[8] = 0x00; // Zeros
        pseudoHeader[9] = 0x06; // Protocolo TCP
        ushort tcpLength = (ushort)tcpHeader.Length;
        pseudoHeader[10] = (byte)(tcpLength >> 8);
        pseudoHeader[11] = (byte)(tcpLength & 0xFF);

        // Concatenar pseudo-encabezado y encabezado TCP
        byte[] checksumData = new byte[pseudoHeader.Length + tcpHeader.Length];
        Array.Copy(pseudoHeader, 0, checksumData, 0, pseudoHeader.Length);
        Array.Copy(tcpHeader, 0, checksumData, pseudoHeader.Length, tcpHeader.Length);

        return CalculateChecksum(checksumData, checksumData.Length);
    }

    static ushort CalculateTcpv6Checksum(byte[] ipHeader, byte[] tcpHeader)
    {
        // Pseudo-encabezado para IPv6
        byte[] pseudoHeader = new byte[36]; // 16 bytes origen + 16 bytes destino + 4 bytes
        Array.Copy(ipHeader, 8, pseudoHeader, 0, 32); // IP origen y destino
        pseudoHeader[32] = 0x00; // Zeros
        pseudoHeader[33] = 0x00;
        pseudoHeader[34] = 0x00;
        pseudoHeader[35] = 0x06; // Protocolo TCP

        ushort tcpLength = (ushort)tcpHeader.Length;
        pseudoHeader[36] = (byte)(tcpLength >> 8);
        pseudoHeader[37] = (byte)(tcpLength & 0xFF);
        pseudoHeader[38] = 0x00; // Reservado
        pseudoHeader[39] = 0x00;

        // Concatenar pseudo-encabezado y encabezado TCP
        byte[] checksumData = new byte[pseudoHeader.Length + tcpHeader.Length];
        Array.Copy(pseudoHeader, 0, checksumData, 0, pseudoHeader.Length);
        Array.Copy(tcpHeader, 0, checksumData, pseudoHeader.Length, tcpHeader.Length);

        return CalculateChecksum(checksumData, checksumData.Length);
    }

    static void SendPacket(byte[] packet, AddressFamily addressFamily)
    {
        try
        {
            Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);

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
        catch (SocketException ex)
        {
            Console.WriteLine($"Error al enviar el paquete: {ex.Message}");
        }
    }
}
