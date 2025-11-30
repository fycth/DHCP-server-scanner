# DHCP Server Scanner

<p align="center">
  <strong>Discover rogue DHCP servers on your network in seconds</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#example">Example</a> •
  <a href="#license">License</a>
</p>

---

A lightweight cross-platform command-line utility that scans your local network for DHCP servers. Useful for network diagnostics, security audits, and detecting unauthorized DHCP servers that could cause network issues.

## Features

- **Cross-platform** — Works on Linux and macOS
- Fast network scanning for DHCP servers
- Displays server MAC address, IP, and offered configuration
- Shows DNS servers, gateway, subnet mask, and proposed IP
- Minimal dependencies — pure C, no external libraries
- Lightweight and portable

## Supported Platforms

| Platform | Implementation |
|----------|----------------|
| Linux    | Raw sockets (`PF_PACKET`) |
| macOS    | BPF (Berkeley Packet Filter) |

## Installation

### Prerequisites

- Linux or macOS operating system
- GCC compiler (or Clang on macOS)
- Make
- Root privileges (required for raw packet access)

### Build

```bash
git clone https://github.com/fycth/DHCP-server-scanner.git
cd DHCP-server-scanner
make
```

The build system automatically detects your platform and compiles the appropriate implementation.

To verify the detected platform:

```bash
make info
```

The compiled binaries will be available in the `bin/` directory.

## Usage

```bash
sudo ./bin/dhcpd-detector-release -i <interface> [-t <timeout>]
```

### Options

| Option | Description |
|--------|-------------|
| `-i, --iface` | Network interface to scan (required) |
| `-t, --timeout` | Timeout in seconds (default: 3) |
| `-h, --help` | Show help message |
| `--version` | Show version |

### Quick Start

**Linux:**
```bash
# Scan on eth0 interface
sudo ./bin/dhcpd-detector-release -i eth0

# Scan on wlan0 with 10 second timeout
sudo ./bin/dhcpd-detector-release -i wlan0 -t 10
```

**macOS:**
```bash
# Scan on en0 interface (usually Wi-Fi or Ethernet)
sudo ./bin/dhcpd-detector-release -i en0

# Scan on en1 with 10 second timeout
sudo ./bin/dhcpd-detector-release -i en1 -t 10
```

> **Note:** Root privileges are required to send and receive raw network packets.

## Example

```
$ sudo ./bin/dhcpd-detector-release -i eth0

<----- DHCP scan started ----->
DHCP server MAC: 78e7d1f7c56e
DHCP: Received msgtype = 2
Server host name: router.local
Boot filename:
DHCP server IP 192.168.1.1
DHCP relay IP 0.0.0.0
DHCP next server IP 192.168.1.1
proposed MASK: 255.255.255.0
proposed GW: 192.168.1.1
proposed DNS 0: 8.8.8.8
proposed DNS 1: 8.8.4.4
proposed IP: 192.168.1.105
<----- stopped ----->
```

## Use Cases

- **Network Troubleshooting** — Verify your DHCP server is responding correctly
- **Security Audits** — Detect rogue DHCP servers on your network
- **IT Administration** — Quickly identify DHCP server configuration
- **Learning** — Understand DHCP protocol in action

## Technical Details

The scanner works by:
1. Sending a DHCP Discover broadcast packet on the specified interface
2. Listening for DHCP Offer responses from any servers on the network
3. Parsing and displaying the offered configuration

On Linux, this uses raw sockets (`PF_PACKET`). On macOS, where raw UDP sockets cannot send custom packets, the scanner uses BPF (Berkeley Packet Filter) to access the network at the data link layer.

## License

This project is licensed under the BSD License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with C and raw sockets
</p>
