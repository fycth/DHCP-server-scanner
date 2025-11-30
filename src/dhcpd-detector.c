/*
 * author: Andrey Sergienko <andrey.sergienko@gmail.com>
 * http://www.erazer.org
*/

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <byteswap.h>
#include <sys/select.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dhcpd-detector.h"
#include "arp.h"
#include "gopt.h"
#include "sum.h"
#include "pseudo.h"

int talker(int sock);
int listener(int sock);
void getmac(unsigned char *, unsigned char *);
unsigned int getip(unsigned char *, unsigned char *);
unsigned int getifindex(unsigned char *);
unsigned char* dhcpsetopt(unsigned char* options, unsigned char optcode, unsigned char optlen, void* optvalptr);
int dhcparse(struct _DHCPHeader * packet);
unsigned char dhcpgetopt(unsigned char* options, unsigned char optcode, unsigned char optlen, void* optvalptr);
void usage(char * myname);
int getsock();
int getsock2();
void print_mac(unsigned char *);
void print_ip(const char *label, unsigned int ip);

unsigned int ifindex;
unsigned int xid;

unsigned char mip[16];
unsigned char * iface;
int i_timeout = 3;
const char * s_timeout;
void * gopts;
int sock;

unsigned char mymac[ETH_ALEN];

/*------------------------------------
 main function
------------------------------------*/

int main(int argc, char *argv[])
{
    int lsock;

    srand(time(NULL));

    gopts = gopt_sort(&argc,(const char **)argv,(const void *)gopt_start(
	   gopt_option('h',0,gopt_shorts('h','?'),gopt_longs("help")),
	   gopt_option('z',0,gopt_shorts(0),gopt_longs("version")),
	   gopt_option('i',GOPT_ARG,gopt_shorts('i'),gopt_longs("iface")),
	   gopt_option('t',GOPT_ARG,gopt_shorts('t'),gopt_longs("timeout"))
    ));

    /*
	-h, -? --help - help
	--version - version
	-i, --iface - interface to work with
	-t, --timeout - timeout in secs
    */

    if (gopt(gopts,'h'))
    {
        usage(argv[0]);
        gopt_free(gopts);
        exit(0);
    };

    if (gopt(gopts,'z'))
    {
        printf("\n\nDHCPD-Detector version %s\n\n",VERSION);
        gopt_free(gopts);
        exit(0);
    };
    
    if (gopt_arg(gopts,'t',&s_timeout))
    {
        char *endptr;
        long val = strtol(s_timeout, &endptr, 10);
        if (*endptr != '\0' || val <= 0 || val > INT_MAX)
            {
                fprintf(stderr, "Time value is incorrect\n");
                gopt_free(gopts);
                exit(1);
            };
        i_timeout = (int)val;
    };

    if (gopt_arg(gopts,'i',(const char **)&iface) && strcmp(iface,"-"))
    {
        getmac(iface,mymac);
        getip(iface,mip);
        ifindex = getifindex(iface);

        sock = getsock();
        if (-1 == sock)
        {
            gopt_free(gopts);
            exit(1);
        };

        lsock = getsock2();
        if (-1 == lsock)
        {
            close(sock);
            gopt_free(gopts);
            exit(1);
        };

        printf("%s\n","<----- DHCP scan started ----->");

        if (talker(sock))
            {
                fprintf(stderr, "something error in talker\n");
                close(sock);
                close(lsock);
                gopt_free(gopts);
                exit(1);
            };

        listener(lsock);

        close(sock);
        close(lsock);

        gopt_free(gopts);

        printf("%s\n","<----- stopped ----->");

        return 0;
    };
        
    usage(argv[0]);
    gopt_free(gopts);
    
    return 0;
}

int talker(int sock)
{
    struct sockaddr_in raddr, saddr;
  
    unsigned char buffer[PCKT_LEN];
    unsigned char buf[256];
    int res;
    int count;
    struct _DHCPHeader *packet = (struct _DHCPHeader *) (buffer + sizeof(struct ip) + sizeof(struct udphdr));
    unsigned char * options;

    struct ip *ip_header = (struct ip *) buffer;
    struct udphdr *udp_header = (struct udphdr *) (buffer + sizeof(struct ip));

    int one = 1;
    const int *val = &one;

    int segment_len;
    int header_len;
    unsigned char *hdr;
    PseudoHeader *pseudo_header;

    memset(buf,0,sizeof(buf));
    memset(buffer,0,sizeof(buffer));
    memset(&raddr, 0, sizeof raddr);
    memset(&saddr, 0, sizeof saddr);

    count = 0;
    
    raddr.sin_family = AF_INET;
    raddr.sin_addr.s_addr = INADDR_BROADCAST;
    raddr.sin_port = htons(67);

    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = IPTOS_LOWDELAY;
    ip_header->ip_id = 0;
    ip_header->ip_ttl = 16;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_off = 0;
    inet_pton(AF_INET,"0.0.0.0",&ip_header->ip_src);
    inet_pton(AF_INET,"255.255.255.255",&ip_header->ip_dst);
    ip_header->ip_sum = 0;
 
    udp_header->source = htons(68);
    udp_header->dest = htons(67);
    udp_header->check = htons(0);

    options = packet->options;

    xid = (unsigned int)rand();

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

    memcpy(&packet->bootp.chaddr,mymac,ETH_ALEN);
    packet->cookie = ntohl(COOKIE);
    
    buf[0] = DHCPDISCOVER;

    count += 2 + 1;
    options = dhcpsetopt(options,DHO_DHCP_MESSAGE_TYPE,1,buf);
    memcpy(&buf[1],&packet->bootp.chaddr,6);

    count += 2 + 7;
    options = dhcpsetopt(options,DHO_DHCP_CLIENT_IDENTIFIER,7,buf);
    buf[0] = DHO_SUBNET_MASK;
    buf[1] = DHO_ROUTERS;
    buf[2] = DHO_DOMAIN_NAME_SERVERS;
    buf[3] = DHO_DOMAIN_NAME;
    
    count += 2 + 4;
    options = dhcpsetopt(options,DHO_DHCP_PARAMETER_REQUEST_LIST,4, buf);
    
    count++;
    options = dhcpsetopt(options, DHO_END, 0, 0);

    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN);

    udp_header->len = htons(sizeof(struct udphdr) + count + DHCP_HEADER_LEN);
    
    /* Calculate the checksum for integrity */
    ip_header->ip_sum = ComputeChecksum((unsigned char *)ip_header, ip_header->ip_hl*4);

    /* Find the size of the TCP Header + Data */
    segment_len = (sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN) - ip_header->ip_hl*4; 

    /* Total length over which TCP checksum will be computed */
    header_len = sizeof(PseudoHeader) + segment_len;

    hdr = (unsigned char *)malloc(header_len);
    if (hdr == NULL)
    {
        fprintf(stderr, "malloc failed in talker()\n");
        return 1;
    }
    pseudo_header = (PseudoHeader *)hdr;
    pseudo_header->source_ip = ip_header->ip_src.s_addr;
    pseudo_header->dest_ip = ip_header->ip_dst.s_addr;
    pseudo_header->reserved = 0;
    pseudo_header->protocol = ip_header->ip_p;
    pseudo_header->udp_length = htons(segment_len);

    memcpy((hdr + sizeof(PseudoHeader)), (void *)udp_header, 8);
    memcpy((hdr + sizeof(PseudoHeader) + 8), packet, count + DHCP_HEADER_LEN);
    udp_header->check = ComputeChecksum(hdr, header_len);

    free(hdr);

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        fprintf(stderr, "setsockopt() error\n");
        return 1;
    }

    res = sendto(sock,buffer,(sizeof(struct ip) + sizeof(struct udphdr) + count + DHCP_HEADER_LEN),0,(struct sockaddr *)&raddr,sizeof(raddr));

    if (-1 == res) return 1;

    return 0;
}

int listener(int sock)
{
    struct sockaddr_in raddr;
    struct ip *ihdr;
    struct udphdr *uhdr;
    char buf[RECV_BUFFER_SIZE];
    int res;
    char * b;
    struct timeval timeout;
    fd_set recfd, errfd;
    int retval;
    int counter = MAX_RECV_ATTEMPTS;
    socklen_t addrlen;
    struct _eth2 * pe;

    while (counter)
        {
            memset(buf,0,sizeof(buf));

            FD_ZERO(&recfd);
            FD_ZERO(&errfd);
    
            FD_SET(sock, &recfd);
            FD_SET(sock, &errfd);
    
            timeout.tv_sec = i_timeout;
            timeout.tv_usec = 0;

            retval = select(sock+1,&recfd,NULL,&errfd,&timeout);

            if (FD_ISSET(sock,&errfd))
                {
                    fprintf(stderr, "Socket listener problem\n");
                    return 1;
                };

            if (-1 == retval) 
                {
                    fprintf(stderr, "select error\n");
                    return 1;
                }

            if (!FD_ISSET(sock,&recfd))
                {

                    fprintf(stderr, "listener Timeout\n");
                    return 0;
                };

            addrlen = sizeof(struct sockaddr_in);
            res = recvfrom(sock,buf,RECV_BUFFER_SIZE,0,(struct sockaddr *)&raddr,&addrlen);

            if (-1 == res)
                {
                    fprintf(stderr, "Error when recvfrom\n");
                    return 1;
                };

            pe = (struct _eth2 *)buf;

            if (memcmp(pe->dst_mac, mymac, ETH_ALEN) == 0)
                {
                    /* packet type should be IP - 0x0800 */
                    if (pe->type != htons(0x0800)) continue;

                    /* get IP header */
                    ihdr = (struct ip *)(buf + sizeof(struct _eth2));

                    /* IP version should be 4 */
                    if (ihdr->ip_v != 4) continue;

                    /* protocol type should be UDP */
                    if (ihdr->ip_p != IPPROTO_UDP) continue;

                    /* get UDP header (ip_hl is a number of 32-bit words) */
                    uhdr = (struct udphdr *)((char *)ihdr + ihdr->ip_hl * 4);

                    /* src port should be 67 and dest port should be 68 */
                    if (ntohs(uhdr->source) != 67 || ntohs(uhdr->dest) != 68) continue;

                    /* go to UDP payload - it should be bootstrap protocol response */
                    b = (char *)uhdr + 8;

                    printf("DHCP server MAC: ");
                    print_mac(pe->src_mac);
                    
                    dhcparse((struct _DHCPHeader *)b);
                }
            counter--;
        }    
    
    return 0;
}

/*
  printout MAC address in human-readable format
 */
void print_mac(unsigned char *mac)
{
    int i;
    for (i = 0; i < 6; i++) printf("%2.2x",mac[i]);
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
  get network interface MAC address
 */
void getmac(unsigned char * iname, unsigned char * hwaddr)
{
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        fprintf(stderr, "getmac socket fail\n");
        memset(hwaddr, 0, 6);
        return;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (char *)iname, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        fprintf(stderr, "getmac ioctl fail\n");
        close(sock);
        memset(hwaddr, 0, 6);
        return;
    }

    close(sock);

    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
}

/*
  convert network interface name to network interface index
 */
unsigned int getifindex(unsigned char *iface)
{
    struct ifreq ifr;
    signed int tmpsock;
	
    memset(&ifr, 0x0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, (char *)iface, IF_NAMESIZE-1);
    ifr.ifr_name[IF_NAMESIZE-1] = '\0';

    if((tmpsock = socket(AF_INET,SOCK_STREAM,0))< 0)
    {
        fprintf(stderr, "getifindex tmpsock fail\n");
        return 0;
    }

    if(ioctl(tmpsock, SIOCGIFINDEX, &ifr)< 0)
    {
        close(tmpsock);
        fprintf(stderr, "getifindex ioctl fail\n");
        return 0;
    }
										
    close(tmpsock);
    return ifr.ifr_ifindex;
}

/*
  get IP address on a network interface
 */
unsigned int getip(unsigned char * iface, unsigned char * ip)
{
    struct ifreq ifr;
    signed int tmpsock;
    struct sockaddr_in * sa;
	
    memset(&ifr, 0x0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, (char *)iface, IF_NAMESIZE-1);
    ifr.ifr_name[IF_NAMESIZE-1] = '\0';

    if((tmpsock = socket(AF_INET,SOCK_STREAM,0))< 0)
    {
        fprintf(stderr, "getip tmpsock fail\n");
        return 0;
    }

    if(ioctl(tmpsock, SIOCGIFADDR, &ifr)< 0)
    {
        close(tmpsock);
        fprintf(stderr, "getip ioctl fail\n");
        return 0;
    }
										
    close(tmpsock);
    sa = (struct sockaddr_in *)&ifr.ifr_addr;
    snprintf((char *)ip, 16, "%s", inet_ntoa(sa->sin_addr));
    
    return 1;
}

/*
  set a DHCP option
 */									
unsigned char* dhcpsetopt(unsigned char* options, unsigned char optcode, unsigned char optlen, void* optvalptr)
{
    unsigned char *src = (unsigned char *)optvalptr;

    /* use current options address as write point
       set optcode */
    *options++ = optcode;

    /* set optlen */
    *options++ = optlen;

    /* copy in argument/data */
    while(optlen--) *options++ = *src++;

    /* write end marker */
    *options = DHO_END;

    /* return address of end marker, to be used as a future write point */
    return options;
}

/*
  parse DHCP packet and printout it
 */
int dhcparse(struct _DHCPHeader * packet)
{
    unsigned char	msgtype;
    unsigned int	val;
    unsigned char cnt;
    unsigned char tmp;
    unsigned char valc[255];

    unsigned int DhcpServerIP;
    unsigned int DhcpNetmask;
    unsigned int DhcpGatewayIP = 0;

    /* check that this is a DHCP response */

    if(packet->bootp.op != BOOTREPLY ||
       packet->bootp.htype != HTYPE_ETHER ||
       packet->bootp.hlen != HTYPE_LEN ||
       ntohl(packet->cookie) != COOKIE ||
       packet->bootp.xid != xid)
        return -1;

    dhcpgetopt(packet->options, DHO_DHCP_MESSAGE_TYPE, 1, &msgtype);
    
    printf("DHCP: Received msgtype = %d\n", msgtype);

    printf("Server host name: %s\n",packet->bootp.sname);
    printf("Boot filename: %s\n",packet->bootp.file);

    if (msgtype == DHCPOFFER)
    {
        /* get server IP */
        val = 0;
        dhcpgetopt(packet->options,DHO_DHCP_SERVER_IDENTIFIER,4,&val);
        if (val == 0) val = packet->bootp.siaddr;
        DhcpServerIP = ntohl(val);
        print_ip("DHCP server IP ", DhcpServerIP);

        /* get DHCP relay */
        print_ip("DHCP relay IP ", ntohl(packet->bootp.giaddr));

        /* get next DHCP server IP */
        print_ip("DHCP next server IP ", ntohl(packet->bootp.siaddr));

        /* get netmask */
        val = 0;
        dhcpgetopt(packet->options, DHO_SUBNET_MASK, 4, &val);
        DhcpNetmask = htonl(val);
        if(DhcpNetmask == 0) DhcpNetmask = 0xffffff00;
        print_ip("proposed MASK: ", DhcpNetmask);

        /* get gateway */
        val = 0;
        dhcpgetopt(packet->options, DHO_ROUTERS, 4, &val);
        if(val != 0) DhcpGatewayIP = htonl(val);
        print_ip("proposed GW: ", DhcpGatewayIP);

        /* get dns */
        tmp = dhcpgetopt(packet->options, DHO_DOMAIN_NAME_SERVERS, 255, &valc) / 4;
        for (cnt = 0; cnt < tmp; cnt++)
            {
                char dns_label[32];
                snprintf(dns_label, sizeof(dns_label), "proposed DNS %d: ", cnt);
                print_ip(dns_label, htonl(*(unsigned int *)(valc + cnt * 4)));
            }

        /* get our ip */
        print_ip("proposed IP: ", ntohl(packet->bootp.yiaddr));
    };

    return 0;
}

/*
  get an option from DHCP packet
 */
unsigned char dhcpgetopt(unsigned char* options, unsigned char optcode, unsigned char optlen, void* optvalptr)
{
    unsigned char i;
    int max_iterations = MAX_DHCP_OPT_ITERATIONS;

    while (max_iterations-- > 0)
    {
        /* skip pad characters */
        if(*options == DHO_PAD) options++;

        /* break if end reached */
        else if(*options == DHO_END) break;

        /* check for desired option */
        else if(*options == optcode)
            {
                /* found desired option
                   limit size to actual option length */
                optlen = (optlen < *(options+1)) ? optlen : *(options+1);

                /* if(*(options+1) < optlen)
                   optlen = *(options+1);
                   copy contents of option */
                for(i = 0; i < optlen; i++) *(((unsigned char*)optvalptr)+i) = *(options+i+2);

                /* return length of option */
                return *(options+1);
            }
        else
            {
                /* skip to next option */
                options++;
                options+=*options;
                options++;
            };
    };

    /* failed to find desired option */
    return 0;
}

/*
  short help on how to use this program
 */
void usage(char * myname)
{
    printf("\n\nUsage: %s [-h] [--version] <-i interface> [-t timeout]\n",myname);
    printf("-h,--help\thelp\n-i,--iface\tnetwork interface to detect on\n-t,--timeout\ttimeout in secs\n\n");
}

/*
  creates socket for sender (talker)
 */
int getsock()
{
    int sock, res;
    struct sockaddr_in s_addr;

    sock = socket(PF_INET,SOCK_RAW,IPPROTO_UDP);
    if (-1 == sock)
    {
        fprintf(stderr, "Error creating socket\n");
        return -1;
    };

    res = 1;
    res = setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(const char *)&res,sizeof(res));
    if (-1 == res)
    {
        close(sock);
        fprintf(stderr, "Error when setsockopt\n");
        return -1;
    };

    res = setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,iface,strlen(iface));
    if (-1 == res)
    {
        close(sock);
        fprintf(stderr, "Error when setsockopt bind to device\n");
        return -1;
    };

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_BROADCAST;
    s_addr.sin_port = htons(67);

    if((bind(sock, (struct sockaddr *)&s_addr, sizeof(s_addr)))== -1)
    {
        close(sock);
        fprintf(stderr, "Error binding raw socket to interface\n");
        return -1;
    }

    return sock;
}

/*
  creates socket for listener
 */
int getsock2()
{
    int s;
    struct sockaddr_ll bindaddr;
    unsigned char hw[16];

      if((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) 
          {
              fprintf(stderr, "socket(PF_PACKET) failed\n");
              return -1;
          }

    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_protocol = htons(ETH_P_IP);
    bindaddr.sll_halen = ETH_ALEN;
    getmac(iface,hw);

    memcpy(bindaddr.sll_addr, hw, ETH_ALEN);
    bindaddr.sll_ifindex = ifindex;

    if (bind(s, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0)
        {
            fprintf(stderr, "Cannot bind raw socket to interface\n");
            return -1;
        }

    return s;
}

