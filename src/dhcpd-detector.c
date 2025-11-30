/*
 * DHCP Server Scanner
 * Detects DHCP servers on the local network
 *
 * Copyright (c) 2011-2025 Andrii Serhiienko <andrii@serhiienko.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dhcpd-detector.h"
#include "platform.h"

/* Function prototypes */
int dhcp_parse(dhcp_header_t *packet, uint32_t xid);
unsigned char dhcp_get_opt(unsigned char *options, unsigned char optcode,
                           unsigned char optlen, void *optvalptr);
void usage(const char *myname);
void print_mac(unsigned char *mac);
void print_ip(const char *label, unsigned int ip);

/* Global variables */
volatile sig_atomic_t running = 1;

static void signal_handler(int signum)
{
    (void)signum;
    running = 0;
}

/* Command line options */
static struct option long_options[] = {
    {"help",    no_argument,       NULL, 'h'},
    {"version", no_argument,       NULL, 'V'},
    {"iface",   required_argument, NULL, 'i'},
    {"timeout", required_argument, NULL, 't'},
    {NULL,      0,                 NULL,  0 }
};

/*------------------------------------
 main function
------------------------------------*/

int main(int argc, char *argv[])
{
    platform_ctx_t *ctx = NULL;
    const char *iface = NULL;
    int timeout = 3;
    unsigned char mymac[ETH_ALEN];
    unsigned char mip[16];
    uint32_t xid;
    unsigned char recv_buf[RECV_BUFFER_SIZE];
    unsigned char src_mac[ETH_ALEN];
    int counter;
    int res;
    int opt;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    srand(time(NULL));

    while ((opt = getopt_long(argc, argv, "hVi:t:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;

        case 'V':
            printf("DHCPD-Detector version %s\n", VERSION);
            return 0;

        case 'i':
            iface = optarg;
            break;

        case 't': {
            char *endptr;
            long val = strtol(optarg, &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > INT_MAX) {
                fprintf(stderr, "Error: Invalid timeout value '%s'\n", optarg);
                return 1;
            }
            timeout = (int)val;
            break;
        }

        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!iface) {
        fprintf(stderr, "Error: Interface is required (-i option)\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Initialize platform */
    ctx = platform_init(iface);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize on interface %s\n", iface);
        return 1;
    }

    /* Get interface info */
    if (platform_get_mac(ctx, mymac) < 0) {
        fprintf(stderr, "Failed to get MAC address\n");
        platform_cleanup(ctx);
        return 1;
    }

    platform_get_ip(ctx, (char *)mip, sizeof(mip));

    printf("<----- DHCP scan started ----->\n");

    /* Generate transaction ID */
    xid = (uint32_t)rand();

    /* Send DHCP Discover */
    if (platform_send_dhcp_discover(ctx, mymac, xid) < 0) {
        fprintf(stderr, "Failed to send DHCP Discover\n");
        platform_cleanup(ctx);
        return 1;
    }

    /* Receive responses */
    counter = MAX_RECV_ATTEMPTS;
    while (counter && running) {
        memset(recv_buf, 0, sizeof(recv_buf));
        memset(src_mac, 0, sizeof(src_mac));

        res = platform_receive(ctx, recv_buf, sizeof(recv_buf),
                               timeout, src_mac);

        if (res < 0) {
            fprintf(stderr, "Receive error\n");
            break;
        }

        if (res == 0) {
            fprintf(stderr, "Timeout waiting for DHCP response\n");
            break;
        }

        /* Parse response */
        size_t dhcp_len;
        unsigned char *dhcp_data = platform_parse_dhcp_response(
            recv_buf, res, mymac, &dhcp_len);

        if (dhcp_data) {
            printf("DHCP server MAC: ");
            print_mac(src_mac);

            dhcp_parse((dhcp_header_t *)dhcp_data, xid);
        }

        counter--;
    }

    platform_cleanup(ctx);

    printf("<----- stopped ----->\n");

    return 0;
}

/*
  printout MAC address in human-readable format
 */
void print_mac(unsigned char *mac)
{
    int i;
    for (i = 0; i < 6; i++)
        printf("%02x", mac[i]);
    printf("\n");
}

/*
  printout IP address in human-readable format (host byte order)
 */
void print_ip(const char *label, unsigned int ip)
{
    printf("%s%d.%d.%d.%d\n", label,
           (ip >> 24) & 0xff,
           (ip >> 16) & 0xff,
           (ip >> 8) & 0xff,
           ip & 0xff);
}

/*
  format lease time as human-readable string
 */
static void format_lease_time(unsigned int seconds, char *buf, size_t buf_len)
{
    unsigned int days = seconds / 86400;
    unsigned int hours = (seconds % 86400) / 3600;
    unsigned int mins = (seconds % 3600) / 60;
    unsigned int secs = seconds % 60;

    if (days > 0)
        snprintf(buf, buf_len, "%ud %uh %um %us", days, hours, mins, secs);
    else if (hours > 0)
        snprintf(buf, buf_len, "%uh %um %us", hours, mins, secs);
    else if (mins > 0)
        snprintf(buf, buf_len, "%um %us", mins, secs);
    else
        snprintf(buf, buf_len, "%us", secs);
}

/*
  parse DHCP packet and printout it
 */
int dhcp_parse(dhcp_header_t *packet, uint32_t xid)
{
    unsigned char msgtype;
    unsigned int val;
    unsigned char cnt;
    unsigned char tmp;
    unsigned char valc[255];
    char strbuf[256];

    unsigned int dhcp_server_ip;
    unsigned int dhcp_netmask;
    unsigned int dhcp_gateway_ip = 0;

    /* check that this is a DHCP response */
    if (packet->bootp.op != BOOTREPLY ||
        packet->bootp.htype != HTYPE_ETHER ||
        packet->bootp.hlen != HTYPE_LEN ||
        ntohl(packet->cookie) != COOKIE ||
        packet->bootp.xid != xid)
        return -1;

    dhcp_get_opt(packet->options, DHO_DHCP_MESSAGE_TYPE, 1, &msgtype);

    printf("DHCP: Received msgtype = %d\n", msgtype);

    /* BOOTP header fields */
    if (packet->bootp.sname[0] != '\0')
        printf("Server host name: %s\n", packet->bootp.sname);
    if (packet->bootp.file[0] != '\0')
        printf("Boot filename: %s\n", packet->bootp.file);

    if (msgtype == DHCPOFFER) {
        /* get server IP */
        val = 0;
        dhcp_get_opt(packet->options, DHO_DHCP_SERVER_IDENTIFIER, 4, &val);
        if (val == 0)
            val = packet->bootp.siaddr;
        dhcp_server_ip = ntohl(val);
        print_ip("DHCP server IP: ", dhcp_server_ip);

        /* get DHCP relay */
        if (packet->bootp.giaddr != 0)
            print_ip("DHCP relay IP: ", ntohl(packet->bootp.giaddr));

        /* get next DHCP server IP */
        if (packet->bootp.siaddr != 0)
            print_ip("Next server IP: ", ntohl(packet->bootp.siaddr));

        /* get our ip */
        print_ip("Offered IP: ", ntohl(packet->bootp.yiaddr));

        /* get netmask */
        val = 0;
        dhcp_get_opt(packet->options, DHO_SUBNET_MASK, 4, &val);
        dhcp_netmask = htonl(val);
        if (dhcp_netmask == 0)
            dhcp_netmask = 0xffffff00;
        print_ip("Subnet mask: ", dhcp_netmask);

        /* get broadcast address */
        val = 0;
        if (dhcp_get_opt(packet->options, DHO_BROADCAST_ADDRESS, 4, &val) > 0)
            print_ip("Broadcast: ", ntohl(val));

        /* get gateway */
        val = 0;
        dhcp_get_opt(packet->options, DHO_ROUTERS, 4, &val);
        if (val != 0)
            dhcp_gateway_ip = htonl(val);
        print_ip("Gateway: ", dhcp_gateway_ip);

        /* get dns servers */
        memset(valc, 0, sizeof(valc));
        tmp = dhcp_get_opt(packet->options, DHO_DOMAIN_NAME_SERVERS, 255, valc) / 4;
        for (cnt = 0; cnt < tmp; cnt++) {
            char dns_label[32];
            snprintf(dns_label, sizeof(dns_label), "DNS server %d: ", cnt + 1);
            print_ip(dns_label, htonl(*(unsigned int *)(valc + cnt * 4)));
        }

        /* get domain name */
        memset(strbuf, 0, sizeof(strbuf));
        if (dhcp_get_opt(packet->options, DHO_DOMAIN_NAME, 255, strbuf) > 0)
            printf("Domain name: %s\n", strbuf);

        /* get host name */
        memset(strbuf, 0, sizeof(strbuf));
        if (dhcp_get_opt(packet->options, DHO_HOST_NAME, 255, strbuf) > 0)
            printf("Host name: %s\n", strbuf);

        /* get lease time */
        val = 0;
        if (dhcp_get_opt(packet->options, DHO_DHCP_LEASE_TIME, 4, &val) > 0) {
            format_lease_time(ntohl(val), strbuf, sizeof(strbuf));
            printf("Lease time: %s (%u seconds)\n", strbuf, ntohl(val));
        }

        /* get NTP servers */
        memset(valc, 0, sizeof(valc));
        tmp = dhcp_get_opt(packet->options, DHO_NTP_SERVERS, 255, valc) / 4;
        for (cnt = 0; cnt < tmp; cnt++) {
            char ntp_label[32];
            snprintf(ntp_label, sizeof(ntp_label), "NTP server %d: ", cnt + 1);
            print_ip(ntp_label, htonl(*(unsigned int *)(valc + cnt * 4)));
        }

        /* get NetBIOS/WINS name servers */
        memset(valc, 0, sizeof(valc));
        tmp = dhcp_get_opt(packet->options, DHO_NETBIOS_NAME_SERVERS, 255, valc) / 4;
        for (cnt = 0; cnt < tmp; cnt++) {
            char wins_label[32];
            snprintf(wins_label, sizeof(wins_label), "WINS server %d: ", cnt + 1);
            print_ip(wins_label, htonl(*(unsigned int *)(valc + cnt * 4)));
        }

        /* get NetBIOS node type */
        val = 0;
        if (dhcp_get_opt(packet->options, DHO_NETBIOS_NODE_TYPE, 1, &val) > 0) {
            const char *node_type;
            switch (val & 0xFF) {
                case 1: node_type = "B-node (broadcast)"; break;
                case 2: node_type = "P-node (point-to-point)"; break;
                case 4: node_type = "M-node (mixed)"; break;
                case 8: node_type = "H-node (hybrid)"; break;
                default: node_type = "Unknown"; break;
            }
            printf("NetBIOS node type: %s\n", node_type);
        }

        /* get TFTP server name */
        memset(strbuf, 0, sizeof(strbuf));
        if (dhcp_get_opt(packet->options, DHO_TFTP_SERVER_NAME, 255, strbuf) > 0)
            printf("TFTP server: %s\n", strbuf);

        /* get bootfile name (option 67) */
        memset(strbuf, 0, sizeof(strbuf));
        if (dhcp_get_opt(packet->options, DHO_BOOTFILE_NAME, 255, strbuf) > 0)
            printf("Bootfile name: %s\n", strbuf);

        /* get vendor class identifier */
        memset(strbuf, 0, sizeof(strbuf));
        if (dhcp_get_opt(packet->options, DHO_VENDOR_CLASS_ID, 255, strbuf) > 0)
            printf("Vendor class: %s\n", strbuf);

        /* get classless static routes (option 121) */
        memset(valc, 0, sizeof(valc));
        tmp = dhcp_get_opt(packet->options, DHO_CLASSLESS_STATIC_ROUTES, 255, valc);
        if (tmp > 0) {
            printf("Static routes:\n");
            unsigned char *p = valc;
            unsigned char *end = valc + tmp;
            while (p < end) {
                unsigned char mask_bits = *p++;
                unsigned char mask_bytes = (mask_bits + 7) / 8;
                unsigned int dest = 0;
                unsigned int gateway_rt;

                if (p + mask_bytes + 4 > end)
                    break;

                /* read destination (only significant bytes) */
                for (cnt = 0; cnt < mask_bytes && cnt < 4; cnt++)
                    dest |= ((unsigned int)p[cnt]) << (24 - cnt * 8);
                p += mask_bytes;

                /* read gateway */
                memcpy(&gateway_rt, p, 4);
                p += 4;

                printf("  %d.%d.%d.%d/%d via %d.%d.%d.%d\n",
                       (dest >> 24) & 0xff,
                       (dest >> 16) & 0xff,
                       (dest >> 8) & 0xff,
                       dest & 0xff,
                       mask_bits,
                       gateway_rt & 0xff,
                       (gateway_rt >> 8) & 0xff,
                       (gateway_rt >> 16) & 0xff,
                       (gateway_rt >> 24) & 0xff);
            }
        }
    }

    return 0;
}

/*
  get an option from DHCP packet
 */
unsigned char dhcp_get_opt(unsigned char *options, unsigned char optcode,
                           unsigned char optlen, void *optvalptr)
{
    unsigned char i;
    int max_iterations = MAX_DHCP_OPT_ITERATIONS;

    while (max_iterations-- > 0) {
        /* skip pad characters */
        if (*options == DHO_PAD)
            options++;

        /* break if end reached */
        else if (*options == DHO_END)
            break;

        /* check for desired option */
        else if (*options == optcode) {
            /* found desired option - limit size to actual option length */
            optlen = (optlen < *(options + 1)) ? optlen : *(options + 1);

            /* copy contents of option */
            for (i = 0; i < optlen; i++)
                *(((unsigned char *)optvalptr) + i) = *(options + i + 2);

            /* return length of option */
            return *(options + 1);
        } else {
            /* skip to next option */
            options++;
            options += *options;
            options++;
        }
    }

    /* failed to find desired option */
    return 0;
}

/*
  short help on how to use this program
 */
void usage(const char *myname)
{
    printf("Usage: %s -i <interface> [-t <timeout>]\n\n", myname);
    printf("Options:\n");
    printf("  -h, --help       Show this help message\n");
    printf("  -V, --version    Show version\n");
    printf("  -i, --iface      Network interface to scan (required)\n");
    printf("  -t, --timeout    Timeout in seconds (default: 3)\n");
}
