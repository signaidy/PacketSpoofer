using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Linq;
using System.Net.NetworkInformation;
class Program
{
    static void Main(string[] args)
    {
        string payloadText = "You've been hacked by Carlos: <malicious Malware noises and crypto stealing>";
        byte[] payload = Encoding.ASCII.GetBytes(payloadText);
        string sourceIp = GetValidIP("origen", null);
        if (sourceIp == null) return; // Usuario eligió 'exit'

        string destIp = GetValidIP("destino", sourceIp);
        if (destIp == null) return; // Usuario eligió 'back' o 'exit'

        if (IPAddress.TryParse(sourceIp, out IPAddress srcAddress) && IPAddress.TryParse(destIp, out IPAddress dstAddress))
        {
            if (srcAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                Console.WriteLine("Creando paquete IPv4...");
                byte[] packet = CreateIPv4Packet(srcAddress, dstAddress, payload);
                SendPacket(packet, AddressFamily.InterNetwork, dstAddress);
            }
            else if (srcAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine("Creando paquete IPv6...");
                byte[] packet = CreateIPv6Packet(srcAddress, dstAddress);
                SendPacket(packet, AddressFamily.InterNetworkV6, dstAddress);
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

    static byte[] CreateIPv4Packet(IPAddress sourceIp, IPAddress destIp, byte[] payload)
    {
        byte[] ipHeader = new byte[20];
        byte[] tcpHeader = new byte[20];
        byte[] packet = new byte[ipHeader.Length + tcpHeader.Length + payload.Length];

        // Construcción del Encabezado IPv4
        ipHeader[0] = 0x45; // Versión (4 bits) + IHL (4 bits)
        ipHeader[1] = 0x00; // Tipo de Servicio

        // Longitud total del paquete (IP + TCP + Payload)
        ushort totalLength = (ushort)(ipHeader.Length + tcpHeader.Length + payload.Length);
        ipHeader[2] = (byte)(totalLength >> 8);
        ipHeader[3] = (byte)(totalLength & 0xFF);

        ipHeader[4] = 0x00; // Identificación
        ipHeader[5] = 0x00;

        ipHeader[6] = 0x40; // Flags (No fragmentar) + Fragment Offset
        ipHeader[7] = 0x00;

        ipHeader[8] = 64;   // TTL
        ipHeader[9] = 6;    // Protocolo TCP (6 para TCP)

        // Checksum IPv4 (se calculará más tarde)
        ipHeader[10] = 0x00;
        ipHeader[11] = 0x00;

        // Direcciones IP
        Array.Copy(sourceIp.GetAddressBytes(), 0, ipHeader, 12, 4); // IP origen
        Array.Copy(destIp.GetAddressBytes(), 0, ipHeader, 16, 4);   // IP destino

        // Calcular el checksum IPv4
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

        // Offset de datos (5) + Flags (SYN)
        tcpHeader[12] = 0x50; // Data offset = 5 (20 bytes)
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

        // Construir el paquete completo (IP + TCP + Payload)
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);
        Array.Copy(payload, 0, packet, ipHeader.Length + tcpHeader.Length, payload.Length);

        // Calcular el checksum TCP utilizando el pseudo-encabezado
        ushort tcpChecksum = CalculateTcpChecksum(ipHeader, tcpHeader, payload);
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

    static ushort CalculateTcpChecksum(byte[] ipHeader, byte[] tcpHeader, byte[] payload)
    {
        // Pseudo-encabezado para IPv4
        byte[] pseudoHeader = new byte[12];
        Array.Copy(ipHeader, 12, pseudoHeader, 0, 8); // IP origen y destino
        pseudoHeader[8] = 0x00; // Zeros
        pseudoHeader[9] = 0x06; // Protocolo TCP
        ushort tcpLength = (ushort)(tcpHeader.Length + payload.Length);
        pseudoHeader[10] = (byte)(tcpLength >> 8);
        pseudoHeader[11] = (byte)(tcpLength & 0xFF);

        // Concatenar pseudo-encabezado, encabezado TCP y payload
        byte[] checksumData = new byte[pseudoHeader.Length + tcpHeader.Length + payload.Length];
        Array.Copy(pseudoHeader, 0, checksumData, 0, pseudoHeader.Length);
        Array.Copy(tcpHeader, 0, checksumData, pseudoHeader.Length, tcpHeader.Length);
        Array.Copy(payload, 0, checksumData, pseudoHeader.Length + tcpHeader.Length, payload.Length);

        return CalculateChecksum(checksumData, checksumData.Length);
    }

    static ushort CalculateTcpv6Checksum(byte[] ipHeader, byte[] tcpHeader)
    {
        // Pseudo-encabezado para IPv6
        byte[] pseudoHeader = new byte[40]; // 16 bytes origen + 16 bytes destino + 4 bytes +4 bytes porque sino no corre xd
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

    static void SendPacket(byte[] packet, AddressFamily addressFamily, IPAddress destinationIp)
    {
        try
        {
            Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);

            // Verifica si la IP proporcionada es IPv4 o IPv6
            if (addressFamily == AddressFamily.InterNetwork) // IPv4
            {
                IPEndPoint endPoint = new IPEndPoint(destinationIp, 80);
                int bytesSent = socket.SendTo(packet, endPoint);
                Console.WriteLine($"Paquetes enviados: {bytesSent} bytes a {destinationIp}.");
            }
            else if (addressFamily == AddressFamily.InterNetworkV6) // IPv6
            {
                IPEndPoint endPoint = new IPEndPoint(destinationIp, 80);
                int bytesSent = socket.SendTo(packet, endPoint);
                Console.WriteLine($"Paquetes enviados: {bytesSent} bytes a {destinationIp}.");
            }

            Console.WriteLine("Paquete enviado.");
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"Error al enviar el paquete: {ex.Message}");
        }
    }
}
