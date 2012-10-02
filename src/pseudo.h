
#ifndef __PSEUDO_H__
#define __PSEUDO_H__

//PseudoHeader struct used to calculate UDP checksum.
typedef struct PseudoHeader{    
    unsigned long int source_ip;
    unsigned long int dest_ip;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short int udp_length;
}PseudoHeader;

#endif
