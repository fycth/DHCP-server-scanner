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
- Shows comprehensive DHCP options:
  - DNS servers, gateway, subnet mask
  - Domain name and hostname
  - Lease time (human-readable)
  - NTP servers, WINS servers
  - Vendor class identifier
  - Static routes (CIDR format)
  - PXE boot options (TFTP server, bootfile)
- **List available interfaces** — Shows only interfaces suitable for DHCP scanning
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
| `-l, --list` | List available network interfaces for DHCP scanning |
| `-i, --iface` | Network interface to scan (required) |
| `-t, --timeout` | Timeout in seconds (default: 3) |
| `-h, --help` | Show help message |
| `-V, --version` | Show version |

### Quick Start

**List available interfaces:**
```bash
./bin/dhcpd-detector-release -l
```

Output:
```
Available interfaces for DHCP scanning:

INTERFACE    MAC                IP
---------    -----------------  ---------------
en0          62:e7:27:25:07:7f  192.168.0.23
eth0         00:1a:2b:3c:4d:5e  192.168.1.100
```

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

> **Note:** Root privileges are required to send and receive raw network packets. The `-l` option does not require root.

## Example

```
$ sudo ./bin/dhcpd-detector-release -i eth0

<----- DHCP scan started ----->
DHCP server MAC: 78e7d1f7c56e
DHCP: Received msgtype = 2
Server host name: router.local
DHCP server IP: 192.168.1.1
Offered IP: 192.168.1.105
Subnet mask: 255.255.255.0
Broadcast: 192.168.1.255
Gateway: 192.168.1.1
DNS server 1: 8.8.8.8
DNS server 2: 8.8.4.4
Domain name: home.local
Lease time: 1d 0h 0m 0s (86400 seconds)
NTP server 1: 192.168.1.1
Vendor class: MSFT 5.0
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
