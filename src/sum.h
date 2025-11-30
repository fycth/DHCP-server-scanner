
#ifndef __SUM_H__
#define __SUM_H__

#define u_int32_t unsigned int

static inline unsigned short ComputeChecksum(unsigned char *data, int len)
{
    long sum = 0;  /* assume 32 bit long, 16 bit short */
    unsigned short *temp = (unsigned short *)data;

    while(len > 1){
        sum += *temp++;
        if(sum & 0x80000000)   /* if high order bit set, fold */
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if(len)       /* take care of left over byte */
        sum += (unsigned short) *((unsigned char *)temp);

    while(sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

#endif

