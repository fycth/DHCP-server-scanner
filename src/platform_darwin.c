/*
 * macOS/Darwin platform implementation using BPF (Berkeley Packet Filter)
 *
 * Copyright (c) 2011-2025 Andrii Serhiienko
 */

#ifdef __APPLE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "platform.h"
#include "dhcpd-detector.h"
#include "pseudo.h"
#include "sum.h"

struct platform_ctx {
    char iface[IFNAMSIZ];
    int bpf_fd;
    unsigned int bpf_buf_len;
    unsigned char mac[ETH_ALEN];
    unsigned char *read_buf;
};

/* Open an available BPF device */
static int open_bpf_device(void)
{
    char dev[32];
    int fd;
    int i;

    for (i = 0; i < 255; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
        if (fd >= 0)
            return fd;
        if (errno != EBUSY)
            continue;
    }

    fprintf(stderr, "open_bpf_device: no available BPF device\n");
    return -1;
}

/* Get MAC address using getifaddrs */
static int get_mac_addr(const char *iface, unsigned char *mac)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_dl *sdl;
    int found = 0;

    if (getifaddrs(&ifap) < 0) {
        fprintf(stderr, "get_mac_addr: getifaddrs failed\n");
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_LINK)
            continue;
        if (strcmp(ifa->ifa_name, iface) != 0)
            continue;

        sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        if (sdl->sdl_alen == ETH_ALEN) {
            memcpy(mac, LLADDR(sdl), ETH_ALEN);
            found = 1;
            break;
        }
    }

    freeifaddrs(ifap);

    if (!found) {
        fprintf(stderr, "get_mac_addr: interface %s not found\n", iface);
        return -1;
    }

    return 0;
}

platform_ctx_t *platform_init(const char *iface)
{
    platform_ctx_t *ctx;
    struct ifreq ifr;
    unsigned int buf_len;
    int immediate = 1;
    int hdrcmplt = 1;
    struct timeval tv;

    ctx = calloc(1, sizeof(platform_ctx_t));
    if (!ctx) {
        fprintf(stderr, "platform_init: calloc failed\n");
        return NULL;
    }

    strncpy(ctx->iface, iface, IFNAMSIZ - 1);
    ctx->bpf_fd = -1;

    /* Get MAC address */
    if (get_mac_addr(iface, ctx->mac) < 0) {
        free(ctx);
        return NULL;
    }

    /* Open BPF device */
    ctx->bpf_fd = open_bpf_device();
    if (ctx->bpf_fd < 0) {
        free(ctx);
        return NULL;
    }

    /* Get buffer length */
    if (ioctl(ctx->bpf_fd, BIOCGBLEN, &buf_len) < 0) {
        fprintf(stderr, "platform_init: BIOCGBLEN failed\n");
        close(ctx->bpf_fd);
        free(ctx);
        return NULL;
    }
    ctx->bpf_buf_len = buf_len;

    /* Allocate read buffer */
    ctx->read_buf = malloc(buf_len);
    if (!ctx->read_buf) {
        fprintf(stderr, "platform_init: malloc read buffer failed\n");
        close(ctx->bpf_fd);
        free(ctx);
        return NULL;
    }

    /* Bind to interface */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(ctx->bpf_fd, BIOCSETIF, &ifr) < 0) {
        fprintf(stderr, "platform_init: BIOCSETIF failed for %s\n", iface);
        free(ctx->read_buf);
        close(ctx->bpf_fd);
        free(ctx);
        return NULL;
    }

    /* Set immediate mode - return packets as soon as they arrive */
    if (ioctl(ctx->bpf_fd, BIOCIMMEDIATE, &immediate) < 0) {
        fprintf(stderr, "platform_init: BIOCIMMEDIATE failed\n");
        free(ctx->read_buf);
        close(ctx->bpf_fd);
        free(ctx);
        return NULL;
    }

    /* Set header complete - we provide full Ethernet header */
    if (ioctl(ctx->bpf_fd, BIOCSHDRCMPLT, &hdrcmplt) < 0) {
        fprintf(stderr, "platform_init: BIOCSHDRCMPLT failed\n");
        free(ctx->read_buf);
        close(ctx->bpf_fd);
        free(ctx);
        return NULL;
    }

    /* Set read timeout */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (ioctl(ctx->bpf_fd, BIOCSRTIMEOUT, &tv) < 0) {
        fprintf(stderr, "platform_init: BIOCSRTIMEOUT failed\n");
        /* Non-fatal, continue */
    }

    /* Install BPF filter for DHCP responses (UDP port 68) */
    struct bpf_insn dhcp_filter[] = {
        /* Check Ethernet type is IP (0x0800) */
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0800, 0, 7),
        /* Check IP protocol is UDP (17) */
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 5),
        /* Check source port is 67 (DHCP server) */
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 34),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 3),
        /* Check dest port is 68 (DHCP client) */
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 36),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 68, 0, 1),
        /* Accept packet */
        BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
        /* Reject packet */
        BPF_STMT(BPF_RET + BPF_K, 0),
    };

    struct bpf_program prog = {
        .bf_len = sizeof(dhcp_filter) / sizeof(dhcp_filter[0]),
        .bf_insns = dhcp_filter,
    };

    if (ioctl(ctx->bpf_fd, BIOCSETF, &prog) < 0) {
        fprintf(stderr, "platform_init: BIOCSETF failed (non-fatal)\n");
        /* Non-fatal, continue without filter */
    }

    return ctx;
}

void platform_cleanup(platform_ctx_t *ctx)
{
    if (!ctx) return;

    if (ctx->read_buf)
        free(ctx->read_buf);
    if (ctx->bpf_fd >= 0)
        close(ctx->bpf_fd);

    free(ctx);
}

int platform_get_mac(platform_ctx_t *ctx, unsigned char *mac)
{
    memcpy(mac, ctx->mac, ETH_ALEN);
    return 0;
}

int platform_get_ip(platform_ctx_t *ctx, char *ip, size_t ip_len)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    int found = 0;

    if (getifaddrs(&ifap) < 0)
        return -1;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, ctx->iface) != 0)
            continue;

        sa = (struct sockaddr_in *)ifa->ifa_addr;
        snprintf(ip, ip_len, "%s", inet_ntoa(sa->sin_addr));
        found = 1;
        break;
    }

    freeifaddrs(ifap);
    return found ? 0 : -1;
}

unsigned int platform_get_ifindex(platform_ctx_t *ctx)
{
    return if_nametoindex(ctx->iface);
}

int platform_send_dhcp_discover(platform_ctx_t *ctx, unsigned char *mac, uint32_t xid)
{
    unsigned char frame[1500];
    unsigned char *p = frame;
    struct ip *ip_hdr;
    struct udphdr *udp_hdr;
    struct _DHCPHeader *dhcp;
    unsigned char *options;
    int count = 0;
    int ip_len, udp_len, total_len;
    PseudoHeader pseudo;
    unsigned char pseudo_buf[1500];
    ssize_t sent;

    memset(frame, 0, sizeof(frame));

    /* Ethernet header */
    memset(p, 0xff, ETH_ALEN);           /* Destination: broadcast */
    p += ETH_ALEN;
    memcpy(p, mac, ETH_ALEN);            /* Source: our MAC */
    p += ETH_ALEN;
    *p++ = 0x08;                          /* EtherType: IPv4 */
    *p++ = 0x00;

    /* IP header */
    ip_hdr = (struct ip *)p;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = IPTOS_LOWDELAY;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 16;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = INADDR_ANY;
    ip_hdr->ip_dst.s_addr = INADDR_BROADCAST;
    p += sizeof(struct ip);

    /* UDP header */
    udp_hdr = (struct udphdr *)p;
    udp_hdr->uh_sport = htons(68);       /* DHCP client port */
    udp_hdr->uh_dport = htons(67);       /* DHCP server port */
    p += sizeof(struct udphdr);

    /* DHCP packet */
    dhcp = (struct _DHCPHeader *)p;
    dhcp->bootp.op = BOOTREQUEST;
    dhcp->bootp.htype = HTYPE_ETHER;
    dhcp->bootp.hlen = HTYPE_LEN;
    dhcp->bootp.hops = 0;
    dhcp->bootp.xid = xid;
    dhcp->bootp.secs = 0;
    dhcp->bootp.flags = htons(0x8000);   /* Broadcast flag */
    dhcp->bootp.ciaddr = 0;
    dhcp->bootp.yiaddr = 0;
    dhcp->bootp.siaddr = 0;
    dhcp->bootp.giaddr = 0;
    memcpy(dhcp->bootp.chaddr, mac, ETH_ALEN);
    dhcp->cookie = htonl(COOKIE);

    /* DHCP options */
    options = dhcp->options;

    /* Message type: DISCOVER */
    *options++ = DHO_DHCP_MESSAGE_TYPE;
    *options++ = 1;
    *options++ = DHCPDISCOVER;
    count += 3;

    /* Client identifier */
    *options++ = DHO_DHCP_CLIENT_IDENTIFIER;
    *options++ = 7;
    *options++ = 1;  /* Ethernet */
    memcpy(options, mac, ETH_ALEN);
    options += ETH_ALEN;
    count += 9;

    /* Parameter request list */
    *options++ = DHO_DHCP_PARAMETER_REQUEST_LIST;
    *options++ = 4;
    *options++ = DHO_SUBNET_MASK;
    *options++ = DHO_ROUTERS;
    *options++ = DHO_DOMAIN_NAME_SERVERS;
    *options++ = DHO_DOMAIN_NAME;
    count += 6;

    /* End */
    *options++ = DHO_END;
    count += 1;

    /* Calculate lengths */
    udp_len = sizeof(struct udphdr) + DHCP_HEADER_LEN + count;
    ip_len = sizeof(struct ip) + udp_len;
    total_len = 14 + ip_len;  /* 14 = Ethernet header */

    /* Set IP length and checksum */
    ip_hdr->ip_len = htons(ip_len);
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ComputeChecksum((unsigned char *)ip_hdr, sizeof(struct ip));

    /* Set UDP length and checksum */
    udp_hdr->uh_ulen = htons(udp_len);

    /* Calculate UDP checksum with pseudo header */
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.source_ip = ip_hdr->ip_src.s_addr;
    pseudo.dest_ip = ip_hdr->ip_dst.s_addr;
    pseudo.reserved = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.udp_length = htons(udp_len);

    memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
    memcpy(pseudo_buf + sizeof(pseudo), udp_hdr, udp_len);
    udp_hdr->uh_sum = ComputeChecksum(pseudo_buf, sizeof(pseudo) + udp_len);

    /* Send via BPF */
    sent = write(ctx->bpf_fd, frame, total_len);
    if (sent < 0) {
        fprintf(stderr, "platform_send_dhcp_discover: write failed: %s\n", strerror(errno));
        return -1;
    }

    if (sent != total_len) {
        fprintf(stderr, "platform_send_dhcp_discover: short write %zd/%d\n", sent, total_len);
        return -1;
    }

    return 0;
}

int platform_receive(platform_ctx_t *ctx, unsigned char *buf, size_t buf_len,
                     int timeout_sec, unsigned char *src_mac)
{
    fd_set rfds;
    struct timeval tv;
    int ret;
    ssize_t n;
    struct bpf_hdr *bh;
    unsigned char *pkt;
    size_t pkt_len;

    FD_ZERO(&rfds);
    FD_SET(ctx->bpf_fd, &rfds);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    ret = select(ctx->bpf_fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        if (errno == EINTR)
            return 0;
        fprintf(stderr, "platform_receive: select error\n");
        return -1;
    }

    if (ret == 0)
        return 0;  /* Timeout */

    n = read(ctx->bpf_fd, ctx->read_buf, ctx->bpf_buf_len);
    if (n < 0) {
        if (errno == EINTR)
            return 0;
        fprintf(stderr, "platform_receive: read error\n");
        return -1;
    }

    if (n == 0)
        return 0;

    /* Parse BPF header */
    bh = (struct bpf_hdr *)ctx->read_buf;
    pkt = ctx->read_buf + bh->bh_hdrlen;
    pkt_len = bh->bh_caplen;

    if (pkt_len > buf_len)
        pkt_len = buf_len;

    memcpy(buf, pkt, pkt_len);

    /* Extract source MAC */
    if (src_mac && pkt_len >= 14) {
        memcpy(src_mac, pkt + 6, ETH_ALEN);
    }

    return pkt_len;
}

unsigned char *platform_parse_dhcp_response(unsigned char *buf, size_t len,
                                            unsigned char *our_mac,
                                            size_t *dhcp_len)
{
    struct ether_header *eth;
    struct ip *ip_hdr;
    struct udphdr *udp_hdr;

    if (len < sizeof(struct ether_header))
        return NULL;

    eth = (struct ether_header *)buf;

    /* Check if packet is for us (unicast) or broadcast */
    if (memcmp(eth->ether_dhost, our_mac, ETH_ALEN) != 0) {
        /* Check for broadcast */
        unsigned char bcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        if (memcmp(eth->ether_dhost, bcast, ETH_ALEN) != 0)
            return NULL;
    }

    /* Check if IP packet */
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return NULL;

    buf += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);

    if (len < sizeof(struct ip))
        return NULL;

    ip_hdr = (struct ip *)buf;

    /* Check IP version */
    if (ip_hdr->ip_v != 4)
        return NULL;

    /* Check protocol is UDP */
    if (ip_hdr->ip_p != IPPROTO_UDP)
        return NULL;

    buf += ip_hdr->ip_hl * 4;
    len -= ip_hdr->ip_hl * 4;

    if (len < sizeof(struct udphdr))
        return NULL;

    udp_hdr = (struct udphdr *)buf;

    /* Check ports: src=67, dst=68 */
    if (ntohs(udp_hdr->uh_sport) != 67 || ntohs(udp_hdr->uh_dport) != 68)
        return NULL;

    buf += sizeof(struct udphdr);
    len -= sizeof(struct udphdr);

    if (dhcp_len)
        *dhcp_len = len;

    return buf;
}

#endif /* __APPLE__ */
