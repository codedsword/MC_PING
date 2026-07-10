# mc_ping

Minimal Minecraft server status pinger written as a module for a bigger project(work in progress)in one C file.

Connects to a Minecraft server, performs the **Handshake → Status Request** protocol flow and prints the server's version, player count, MOTD and favicon info.

## Features

- Lightweight - no dependencies except **libc** and **cJSON**
- Cross-architecture Linux compatible (x86, x86_64, ARM, AArch64, etc.)
- Works on Termux (Android)
- Optional raw JSON dump to file
- Optional full favicon Base64 output

## Dependencies

The only dependencies are:

- A working Linux system (obviously)
- GLibc
- cJSON

## Build

Using `make`:

```sh
make
```

Or manually:

```sh
gcc -O2 -Wall -o mc_ping mc_ping.c -lcjson
```

## Usage

```sh
./mc_ping [-h] [-o <file>] [-b] <host> <port> <protocol_version>
```

## Options

| Flag | Description |
|------|-------------|
| `-h` | Show help message |
| `-o <file>` | Dump raw JSON to `<file>` |
| `-b` | Print full favicon Base64 |

## Examples

```sh
# Ping Hypixel (1.21)
./mc_ping hypixel.net 25565 767

# Ping a local server and save the JSON
./mc_ping -o status.json localhost 25565 767

# Show full favicon data
./mc_ping -b mc.example.com 25565 767

# Show help
./mc_ping -h
```

## Protocol Versions

| Version | Protocol |
|---------|---------:|
| 1.21 | 767 |
| 1.20.5 | 766 |
| 1.20.4 | 765 |
| 1.20.2 | 764 |
| 1.20 / 1.20.1 | 763 |
| 1.19.4 | 762 |

**Full list:** <https://minecraft.wiki/w/Protocol_version_numbers>