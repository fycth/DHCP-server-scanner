/*
 * Linux platform implementation using raw sockets
 *
 * Copyright (c) 2011-2025 Andrii Serhiienko
 */

#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "platform.h"
#include "dhcpd-detector.h"
#include "pseudo.h"
#include "sum.h"

struct platform_ctx {
    char iface[IFNAMSIZ];
    int send_sock;
    int recv_sock;
    unsigned int ifindex;
    unsigned char mac[ETH_ALEN];
};

/* Helper: perform ioctl on interface */
static int iface_ioctl(const char *iface_name, unsigned long request, struct ifreq *ifr)
{
    int sock;

    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_name, iface_name, IFNAMSIZ - 1);
    ifr->ifr_name[IFNAMSIZ - 1] = '\0';

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "iface_ioctl: socket failed\n");
        return -1;
    }

    if (ioctl(sock, request, ifr) < 0) {
        fprintf(stderr, "iface_ioctl: ioctl failed\n");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

platform_ctx_t *platform_init(const char *iface)
{
    platform_ctx_t *ctx;
    struct sockaddr_in s_addr;
    struct sockaddr_ll bindaddr;
    struct ifreq ifr;
    int res;

    ctx = calloc(1, sizeof(platform_ctx_t));
    if (!ctx) {
        fprintf(stderr, "platform_init: calloc failed\n");
        return NULL;
    }

    strncpy(ctx->iface, iface, IFNAMSIZ - 1);
    ctx->send_sock = -1;
    ctx->recv_sock = -1;

    /* Get interface info */
    if (platform_get_mac(ctx, ctx->mac) < 0) {
        free(ctx);
        return NULL;
    }

    ctx->ifindex = platform_get_ifindex(ctx);
    if (ctx->ifindex == 0) {
        free(ctx);
        return NULL;
    }

    /* Create send socket */
    ctx->send_sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ctx->send_sock < 0) {
        fprintf(stderr, "platform_init: send socket failed\n");
        free(ctx);
        return NULL;
    }

    res = 1;
    if (setsockopt(ctx->send_sock, SOL_SOCKET, SO_BROADCAST, &res, sizeof(res)) < 0) {
        fprintf(stderr, "platform_init: setsockopt SO_BROADCAST failed\n");
        close(ctx->send_sock);
        free(ctx);
        return NULL;
    }

    if (setsockopt(ctx->send_sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        fprintf(stderr, "platform_init: setsockopt SO_BINDTODEVICE failed\n");
        close(ctx->send_sock);
        free(ctx);
        return NULL;
    }

    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_BROADCAST;
    s_addr.sin_port = htons(67);

    if (bind(ctx->send_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
        fprintf(stderr, "platform_init: bind send socket failed\n");
        close(ctx->send_sock);
        free(ctx);
        return NULL;
    }

    /* Create receive socket */
    ctx->recv_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->recv_sock < 0) {
        fprintf(stderr, "platform_init: recv socket failed\n");
        close(ctx->send_sock);
        free(ctx);
        return NULL;
    }

    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_protocol = htons(ETH_P_IP);
    bindaddr.sll_halen = ETH_ALEN;
    memcpy(bindaddr.sll_addr, ctx->mac, ETH_ALEN);
    bindaddr.sll_ifindex = ctx->ifindex;

    if (bind(ctx->recv_sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0) {
        fprintf(stderr, "platform_init: bind recv socket failed\n");
        close(ctx->send_sock);
        close(ctx->recv_sock);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void platform_cleanup(platform_ctx_t *ctx)
{
    if (!ctx) return;

    if (ctx->send_sock >= 0)
        close(ctx->send_sock);
    if (ctx->recv_sock >= 0)
        close(ctx->recv_sock);

    free(ctx);
}

int platform_get_mac(platform_ctx_t *ctx, unsigned char *mac)
{
    struct ifreq ifr;

    if (iface_ioctl(ctx->iface, SIOCGIFHWADDR, &ifr) < 0) {
        memset(mac, 0, ETH_ALEN);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

int platform_get_ip(platform_ctx_t *ctx, char *ip, size_t ip_len)
{
    struct ifreq ifr;
    struct sockaddr_in *sa;

    if (iface_ioctl(ctx->iface, SIOCGIFADDR, &ifr) < 0) {
        return -1;
    }

    sa = (struct sockaddr_in *)&ifr.ifr_addr;
    snprintf(ip, ip_len, "%s", inet_ntoa(sa->sin_addr));
    return 0;
}

unsigned int platform_get_ifindex(platform_ctx_t *ctx)
{
    struct ifreq ifr;

    if (iface_ioctl(ctx->iface, SIOCGIFINDEX, &ifr) < 0) {
        return 0;
    }

    return ifr.ifr_ifindex;
}

int platform_send_dhcp_discover(platform_ctx_t *ctx, unsigned char *mac, uint32_t xid)
{
    unsigned char buffer[PCKT_LEN];
    unsigned char buf[256];
    struct sockaddr_in raddr;
    struct ip *ip_header;
    struct udphdr *udp_header;
    struct _DHCPHeader *packet;
    unsigned char *options;
    int count = 0;
    int segment_len, header_len;
    unsigned char *hdr;
    PseudoHeader *pseudo_header;
    int one = 1;

    memset(buffer, 0, sizeof(buffer));
    memset(buf, 0, sizeof(buf));
    memset(&raddr, 0, sizeof(raddr));

    ip_header = (struct ip *)buffer;
    udp_header = (struct udphdr *)(buffer + sizeof(struct ip));
    packet = (struct _DHCPHeader *)(buffer + sizeof(struct ip) + sizeof(struct udphdr));

    raddr.sin_family = AF_INET;
    raddr.sin_addr.s_addr = INADDR_BROADCAST;
    raddr.sin_port = htons(67);

    /* Build IP header */
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = IPTOS_LOWDELAY;
    ip_header->ip_id = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_off = 0;
    inet_pton(AF_INET, "0.0.0.0", &ip_header->ip_src);
    inet_pton(AF_INET, "255.255.255.255", &ip_header->ip_dst);
    ip_header->ip_sum = 0;

    /* Build UDP header */
    udp_header->source = htons(68);
    udp_header->dest = htons(67);
    udp_header->check = htons(0);

    /* Build DHCP packet */
    options = packet->options;

    packet->bootp.op = BOOTREQUEST;
    packet->bootp.htype = HTYPE_ETHER;
    packet->bootp.hlen = HTYPE_LEN;
    packet->bootp.hops = 0;
    packet->bootp.xid = xid;
    packet->bootp.secs = 0;
    packet->bootp.flags = 0;
    packet->bootp.ciaddr = 0;
    packet->bootp.yiaddr = 0;
    packet->bootp.siaddr = 0;
    packet->bootp.giaddr = 0;
    memcpy(&packet->bootp.chaddr, mac, ETH_ALEN);
    packet->cookie = ntohl(COOKIE);

    /* Add DHCP options */
    buf[0] = DHCPDISCOVER;
    count += 2 + 1;
    *options++ = DHO_DHCP_MESSAGE_TYPE;
    *options++ = 1;
    *options++ = buf[0];

    buf[0] = 1; /* Ethernet */
    memcpy(&buf[1], mac, ETH_ALEN);
    count += 2 + 7;
    *options++ = DHO_DHCP_CLIENT_IDENTIFIER;
    *options++ = 7;
    memcpy(options, buf, 7);
    options += 7;

    buf[0] = DHO_SUBNET_MASK;
    buf[1] = DHO_ROUTERS;
    buf[2] = DHO_DOMAIN_NAME_SERVERS;
    buf[3] = DHO_DOMAIN_NAME;
    count += 2 + 4;
    *options++ = DHO_DHCP_PARAMETER_REQUEST_LIST;
    *options++ = 4;
    memcpy(options, buf, 4);
    options += 4;

    count++;
    *options++ = DHO_END;

    /* Set lengths */
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN);
    udp_header->len = htons(sizeof(struct udphdr) + count + DHCP_HEADER_LEN);

    /* Calculate checksums */
    ip_header->ip_sum = ComputeChecksum((unsigned char *)ip_header, ip_header->ip_hl * 4);

    segment_len = (sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN) - ip_header->ip_hl * 4;
    header_len = sizeof(PseudoHeader) + segment_len;

    hdr = malloc(header_len);
    if (!hdr) {
        fprintf(stderr, "platform_send_dhcp_discover: malloc failed\n");
        return -1;
    }

    pseudo_header = (PseudoHeader *)hdr;
    pseudo_header->source_ip = ip_header->ip_src.s_addr;
    pseudo_header->dest_ip = ip_header->ip_dst.s_addr;
    pseudo_header->reserved = 0;
    pseudo_header->protocol = ip_header->ip_p;
    pseudo_header->udp_length = htons(segment_len);

    memcpy(hdr + sizeof(PseudoHeader), udp_header, 8);
    memcpy(hdr + sizeof(PseudoHeader) + 8, packet, count + DHCP_HEADER_LEN);
    udp_header->check = ComputeChecksum(hdr, header_len);
    free(hdr);

    /* Set IP_HDRINCL */
    if (setsockopt(ctx->send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "platform_send_dhcp_discover: setsockopt IP_HDRINCL failed\n");
        return -1;
    }

    /* Send packet */
    if (sendto(ctx->send_sock, buffer,
               sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN,
               0, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
        fprintf(stderr, "platform_send_dhcp_discover: sendto failed\n");
        return -1;
    }

    return 0;
}

int platform_receive(platform_ctx_t *ctx, unsigned char *buf, size_t buf_len,
                     int timeout_sec, unsigned char *src_mac)
{
    struct sockaddr_in raddr;
    socklen_t addrlen;
    fd_set recfd, errfd;
    struct timeval timeout;
    int retval, res;

    FD_ZERO(&recfd);
    FD_ZERO(&errfd);
    FD_SET(ctx->recv_sock, &recfd);
    FD_SET(ctx->recv_sock, &errfd);

    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    retval = select(ctx->recv_sock + 1, &recfd, NULL, &errfd, &timeout);

    if (FD_ISSET(ctx->recv_sock, &errfd)) {
        fprintf(stderr, "platform_receive: socket error\n");
        return -1;
    }

    if (retval < 0) {
        if (errno == EINTR)
            return 0;
        fprintf(stderr, "platform_receive: select error\n");
        return -1;
    }

    if (!FD_ISSET(ctx->recv_sock, &recfd)) {
        return 0; /* Timeout */
    }

    addrlen = sizeof(struct sockaddr_in);
    res = recvfrom(ctx->recv_sock, buf, buf_len, 0, (struct sockaddr *)&raddr, &addrlen);

    if (res < 0) {
        fprintf(stderr, "platform_receive: recvfrom error\n");
        return -1;
    }

    /* Extract source MAC from Ethernet header */
    if (res >= 14 && src_mac) {
        memcpy(src_mac, buf + 6, ETH_ALEN);
    }

    return res;
}

unsigned char *platform_parse_dhcp_response(unsigned char *buf, size_t len,
                                            unsigned char *our_mac,
                                            size_t *dhcp_len)
{
    struct ether_header {
        unsigned char dst[ETH_ALEN];
        unsigned char src[ETH_ALEN];
        uint16_t type;
    } *eth;
    struct ip *ip_hdr;
    struct udphdr *udp_hdr;

    if (len < sizeof(struct ether_header))
        return NULL;

    eth = (struct ether_header *)buf;

    /* Check if packet is for us */
    if (memcmp(eth->dst, our_mac, ETH_ALEN) != 0)
        return NULL;

    /* Check if IP packet */
    if (ntohs(eth->type) != 0x0800)
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

    /* Check ports: src=67 (DHCP server), dst=68 (DHCP client) */
    if (ntohs(udp_hdr->source) != 67 || ntohs(udp_hdr->dest) != 68)
        return NULL;

    buf += sizeof(struct udphdr);
    len -= sizeof(struct udphdr);

    if (dhcp_len)
        *dhcp_len = len;

    return buf;
}

#endif /* __linux__ */
