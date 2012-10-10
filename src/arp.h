
/*
 * author: Andrey Sergienko <andrey.sergienko@gmail.com>
 * http://www.erazer.org
*/

#ifndef __ARP_INCLUDED__
#define __ARP_INCLUDED__

struct _eth2
{
    unsigned char dst_mac[ETH_ALEN];
    unsigned char src_mac[ETH_ALEN];
    unsigned short type;
} pack_eth2;

#endif
