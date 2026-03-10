# PacketSpoofer

Console app in C# (.NET 8) that crafts and sends raw TCP packets with spoofed source/destination IPs for IPv4/IPv6.

## Important

Use only in authorized lab environments. Sending spoofed traffic to networks you do not own or manage can be illegal.

## Requirements

- .NET SDK 8.0+
- Windows
- Administrator privileges (raw sockets usually require elevated permissions)

## Build

```powershell
dotnet build PacketSpoofer.sln
```

## Run

```powershell
dotnet run --project PacketSpoofer.csproj
```

The program will ask for:

- Source IP (`origen`)
- Destination IP (`destino`)

Special commands while entering IPs:

- `exit`: quit the program
- `back`: return from destination input

## Current behavior

- IPv4 path builds `IP + TCP + payload` packet and attempts to send it.
- IPv6 path builds `IP + TCP + payload` packet and attempts to send it.
- Packet bytes are printed after send attempt.

## Troubleshooting

- `SocketException` / permission errors:
  - Open terminal as Administrator.
  - Confirm local policy/OS allows raw sockets for your scenario.

## Project files

- `Program.cs`: packet construction, checksums, send logic, console UI
- `PacketSpoofer.csproj`: .NET project config
- `PacketSpoofer.sln`: Visual Studio solution
