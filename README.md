DHCP-server-scanner
===================

Unix console utility that implements DHCP client functionality to scan DHCP servers

To compile it you need 'cmake' utility installed

How to compile: just do './cmake.sh'

How to use: 'bin/dhcpd-detector-release -i eth0'

Example of response:

<----- DHCP scan started ----->

DHCP server MAC: 78e7d1f7c56e

DHCP: Received msgtype = 2

DHCP server IP 172.24.153.1

proposed mask: 255.255.255.0

proposed gateway: 172.24.153.1

proposed dns: 8.8.8.8

proposed ip: 172.24.153.79

<----- stopped ----->

P.S. this is very basic functionality project and it doesn't support full DHCP protocol features
