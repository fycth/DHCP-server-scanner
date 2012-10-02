
#ifndef __ARP_INCLUDED__
#define __ARP_INCLUDED__

struct _eth2
{
    unsigned char dst_mac[ETH_ALEN];
    unsigned char src_mac[ETH_ALEN];
    unsigned short type[2];
} pack_eth2;

					    
#define MAC_HDR_ETHER 1
			    
#define MAC_PR_IP 0x800
#define MAC_PR_ARP 0x806
				    
#define MAC_OP_REQUEST 1
#define MAC_OP_REPLY 2
					    
#define ETH_NULL "\x00\x00\x00\x00\x00\x00"
#define ETH_BCAST "\xff\xff\xff\xff\xff\xff"
					    
#endif
				    