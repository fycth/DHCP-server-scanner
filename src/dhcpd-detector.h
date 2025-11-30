
/*
 * author: Andrey Sergienko <andrey.sergienko@gmail.com>
 * http://www.erazer.org
*/

#ifndef __DHCPD_DETECTOR_H_INCLUDED__
#define __DHCPD_DETECTOR_H_INCLUDED__

#define VERSION "1.0"

#define PCKT_LEN 8192
#define RECV_BUFFER_SIZE 1024
#define MAX_RECV_ATTEMPTS 3
#define MAX_DHCP_OPT_ITERATIONS 512

typedef struct bootp_header {
    unsigned char	op;		///< Message op-code / message type
    unsigned char	htype;		///< Hardware address type   (Ethernet=1)
    unsigned char	hlen;		///< Hardware address length (Ethernet=6 byte MAC addr)
    unsigned char	hops;		///< hop count (client set to zero)
    unsigned int	xid;		///< Transaction ID (randomly chosen by client, must remain same)
    unsigned short	secs;		///< Seconds elapsed since DHCP negotiation began (filled by client)
    unsigned short	flags;		///< Flags
    unsigned int    ciaddr;		///< Client IP address (filled only if already bound, renewing, or rebinding)
    unsigned int    yiaddr;		///< 'Your' IP address (client)
    unsigned int    siaddr;		///< Server IP address
    unsigned int    giaddr;		///< Gateway IP address
    unsigned char	chaddr[16];	///< Client Hardware Address
    unsigned char	sname[64];	///< Server Host Name
    unsigned char	file[128];	///< Boot file name (null-term string)
} bootp_header_t;

typedef struct dhcp_header {
    bootp_header_t bootp;
    unsigned int cookie;
    unsigned char options[];
} dhcp_header_t;

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define BOOTP_BROADCAST 32768L

#define HTYPE_ETHER 1
#define HTYPE_LEN 6

#define DHCP_HEADER_LEN 240

/* DHCP Options */
#define DHO_PAD 0
#define DHO_SUBNET_MASK 1
#define DHO_ROUTERS 3
#define DHO_NAME_SERVERS 5
#define DHO_DOMAIN_NAME_SERVERS 6
#define DHO_HOST_NAME 12
#define DHO_DOMAIN_NAME 15
#define DHO_BROADCAST_ADDRESS 28
#define DHO_NTP_SERVERS 42
#define DHO_NETBIOS_NAME_SERVERS 44
#define DHO_NETBIOS_NODE_TYPE 46
#define DHO_DHCP_REQUESTED_ADDRESS 50
#define DHO_DHCP_LEASE_TIME 51
#define DHO_DHCP_MESSAGE_TYPE 53
#define DHO_DHCP_SERVER_IDENTIFIER 54
#define DHO_DHCP_PARAMETER_REQUEST_LIST 55
#define DHO_VENDOR_CLASS_ID 60
#define DHO_DHCP_CLIENT_IDENTIFIER 61
#define DHO_TFTP_SERVER_NAME 66
#define DHO_BOOTFILE_NAME 67
#define DHO_CLASSLESS_STATIC_ROUTES 121
#define DHO_END 255

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

#define COOKIE 0x63825363

#endif

