/*
 * Platform abstraction layer for cross-platform raw packet operations
 * Supports Linux (raw sockets) and macOS (BPF)
 *
 * Copyright (c) 2011-2025 Andrii Serhiienko
 */

#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#include <stdint.h>

/* Ethernet address length */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Platform context - opaque structure */
typedef struct platform_ctx platform_ctx_t;

/*
 * Initialize platform-specific networking
 * Returns: pointer to context on success, NULL on failure
 */
platform_ctx_t *platform_init(const char *iface);

/*
 * Clean up platform resources
 */
void platform_cleanup(platform_ctx_t *ctx);

/*
 * Get MAC address of interface
 * Returns: 0 on success, -1 on failure
 */
int platform_get_mac(platform_ctx_t *ctx, unsigned char *mac);

/*
 * Get IP address of interface
 * Returns: 0 on success, -1 on failure
 */
int platform_get_ip(platform_ctx_t *ctx, char *ip, size_t ip_len);

/*
 * Get interface index
 * Returns: index on success, 0 on failure
 */
unsigned int platform_get_ifindex(platform_ctx_t *ctx);

/*
 * Send DHCP discover packet
 * Returns: 0 on success, -1 on failure
 */
int platform_send_dhcp_discover(platform_ctx_t *ctx, unsigned char *mac, uint32_t xid);

/*
 * Receive packet with timeout
 * Returns: bytes received on success, 0 on timeout, -1 on error
 */
int platform_receive(platform_ctx_t *ctx, unsigned char *buf, size_t buf_len,
                     int timeout_sec, unsigned char *src_mac);

/*
 * Check if received packet is a DHCP response for us
 * Returns: pointer to DHCP payload if valid, NULL otherwise
 */
unsigned char *platform_parse_dhcp_response(unsigned char *buf, size_t len,
                                            unsigned char *our_mac,
                                            size_t *dhcp_len);

/*
 * Interface information structure
 */
typedef struct iface_info {
    char name[16];              /* Interface name */
    unsigned char mac[ETH_ALEN]; /* MAC address */
    char ip[16];                /* IPv4 address (dotted decimal) */
    int has_ip;                 /* Has IPv4 address assigned */
    struct iface_info *next;    /* Linked list */
} iface_info_t;

/*
 * List network interfaces suitable for DHCP scanning
 * Filters: UP, BROADCAST, !LOOPBACK, !POINTOPOINT
 * Returns: linked list of interfaces, NULL if none found
 * Caller must free with platform_free_iface_list()
 */
iface_info_t *platform_list_interfaces(void);

/*
 * Free interface list returned by platform_list_interfaces()
 */
void platform_free_iface_list(iface_info_t *list);

#endif /* __PLATFORM_H__ */
