
#ifndef __SUM_H__
#define __SUM_H__

#define u_int32_t unsigned int

unsigned short csum(unsigned short *buf, int nwords)
{       //
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
};

unsigned short ComputeChecksum(unsigned char *data, int len)
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



u_int32_t checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
    int i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (nbytes & ~1U); i += 2)
    {
	sum += (u_int16_t)ntohs(*((u_int16_t *)(buf + i)));
	if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }

/*
 * If there's a single byte left over, checksum it, too.
 * Network byte order is big-endian, so the remaining byte is
 * the high byte.
 */
    if (i < nbytes)
    {
	sum += buf[i] << 8;
	if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }

    return (sum);
};

u_int32_t wrapsum(u_int32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
};

#endif

