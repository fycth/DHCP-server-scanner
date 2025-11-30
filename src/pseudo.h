
/*
 * author: Andrey Sergienko <andrey.sergienko@gmail.com>
 * http://www.erazer.org
*/

#ifndef __PSEUDO_H__
#define __PSEUDO_H__

#include <stdint.h>

/* pseudo_header_t struct used to calculate UDP checksum */
typedef struct pseudo_header {
    uint32_t source_ip;
    uint32_t dest_ip;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short int udp_length;
} pseudo_header_t;

#endif
