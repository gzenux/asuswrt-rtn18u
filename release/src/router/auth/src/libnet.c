
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "config.h"

#include "libnet.h"
#include <net/if.h>
#if (__GLIBC__)
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#else
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#endif

#include "bpf.h"

struct libnet_link_int *
libnet_open_link_interface(char *device, char *ebuf)
{
    register struct libnet_link_int *l;
    struct ifreq ifr;


    l = (struct libnet_link_int *)malloc(sizeof (*l));
    if (l == NULL)
    {
        sprintf(ebuf, "malloc: %s", strerror(errno));
        return (NULL);
    }
    memset(l, 0, sizeof (*l));


    //l->fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
    // sc_yang , modify to avoid every packet copy
    l->fd = socket(PF_INET, SOCK_PACKET, 0);
    if (l->fd == -1)
    {
        sprintf(ebuf, "socket: %s", strerror(errno));
        goto bad;
    }


    memset(&ifr, 0, sizeof (ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(l->fd, SIOCGIFHWADDR, &ifr) < 0 )
    {
        sprintf(ebuf, "SIOCGIFHWADDR: %s", strerror(errno));
        goto bad;
    }

    switch (ifr.ifr_hwaddr.sa_family)
    {
        case ARPHRD_ETHER:
        case ARPHRD_METRICOM:

            l->linktype = DLT_EN10MB;
            l->linkoffset = 0xe;
            break;
        case ARPHRD_SLIP:
        case ARPHRD_CSLIP:
        case ARPHRD_SLIP6:
        case ARPHRD_CSLIP6:
        case ARPHRD_PPP:
            l->linktype = DLT_RAW;
            break;
        default:
            sprintf(ebuf, "unknown physical layer type 0x%x",
                ifr.ifr_hwaddr.sa_family);
        goto bad;
    }
    return (l);

bad:
    if (l->fd >= 0)
    {
        close(l->fd);
    }
    free(l);
    return (NULL);
}
int
libnet_write_link_layer(struct libnet_link_int *l, const char *device,
            u_char *buf, int len)
{
    int c;

    struct sockaddr sa;

    memset(&sa, 0, sizeof (sa));

    strncpy(sa.sa_data, device, sizeof (sa.sa_data));

    c = sendto(l->fd, buf, len, 0, (struct sockaddr *)&sa, sizeof (sa));
    if (c != len)
    {
#if (__DEBUG)
        libnet_error(LIBNET_ERR_WARNING,
            "write_link_layer: %d bytes written (%s)\n", c,
            strerror(errno));
#endif
    }
    return (c);
}


int
libnet_close_link_interface(struct libnet_link_int *l)
{
    if (close(l->fd) == 0)
    {
        return (1);
    }
    else
    {
        return (-1);
    }
}


struct ether_addr *
libnet_get_hwaddr(struct libnet_link_int *l, const char *device, char *ebuf)
{
    int fd;
    struct ifreq ifr;
    struct ether_addr *eap;
    /*
     *  XXX - non-re-entrant!
     */
    static struct ether_addr ea;

    /*
     *  Create dummy socket to perform an ioctl upon.
     */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        sprintf(ebuf, "get_hwaddr: %s", strerror(errno));
        return (NULL);
    }

    memset(&ifr, 0, sizeof(ifr));
    eap = &ea;
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if (ioctl(fd, SIOCGIFHWADDR, (char *)&ifr) < 0)
    {
        close(fd);
        sprintf(ebuf, "get_hwaddr: %s", strerror(errno));
        return (NULL);
    }
    memcpy(eap, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(fd);
    return (eap);
}



#ifndef COMPACK_SIZE
int
libnet_in_cksum(u_short *addr, int len)
{
    int sum;
    int nleft;
    u_short ans;
    u_short *w;

    sum = 0;
    ans = 0;
    nleft = len;
    w = addr;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *)(&ans) = *(u_char *)w;
        sum += ans;
    }
    return (sum);
}
#endif


#ifndef COMPACK_SIZE
int
libnet_do_checksum(u_char *buf, int protocol, int len)
{
    struct libnet_ip_hdr *iph_p;
    int ip_hl;
    int sum;

    sum = 0;
    iph_p = (struct libnet_ip_hdr *)buf;
    ip_hl = iph_p->ip_hl << 2;

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_TCP:
        {
            struct libnet_tcp_hdr *tcph_p =
                (struct libnet_tcp_hdr *)(buf + ip_hl);

#if (STUPID_SOLARIS_CHECKSUM_BUG)
            tcph_p->th_sum = tcph_p->th_off << 2;
            return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */

            tcph_p->th_sum = 0;
            sum = libnet_in_cksum((u_short *)&iph_p->ip_src, 8);
            sum += ntohs(IPPROTO_TCP + len);
            sum += libnet_in_cksum((u_short *)tcph_p, len);
            tcph_p->th_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_UDP:
        {
            struct libnet_udp_hdr *udph_p =
                (struct libnet_udp_hdr *)(buf + ip_hl);

            udph_p->uh_sum = 0;
            sum = libnet_in_cksum((u_short *)&iph_p->ip_src, 8);
            sum += ntohs(IPPROTO_UDP + len);
            sum += libnet_in_cksum((u_short *)udph_p, len);
            udph_p->uh_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_ICMP:
        {
            struct libnet_icmp_hdr *icmph_p =
                (struct libnet_icmp_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            sum = libnet_in_cksum((u_short *)icmph_p, len);
            icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_IGMP:
        {
            struct libnet_igmp_hdr *igmph_p =
                (struct libnet_igmp_hdr *)(buf + ip_hl);

            igmph_p->igmp_sum = 0;
            sum = libnet_in_cksum((u_short *)igmph_p, len);
            igmph_p->igmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_OSPF:
        {
            struct libnet_ospf_hdr *oh_p =
                (struct libnet_ospf_hdr *)(buf + ip_hl);

            u_char *payload = (u_char *)(buf + ip_hl + LIBNET_AUTH_H + 
                        sizeof(oh_p));
            u_char *tbuf = (u_char *)malloc(sizeof(oh_p) + sizeof(payload));
            if (tbuf == NULL)
            {
                return (-1);
            }
            oh_p->ospf_cksum = 0;
            sum += libnet_in_cksum((u_short *)tbuf, sizeof(tbuf));
            oh_p->ospf_cksum = LIBNET_CKSUM_CARRY(sum);
            free(tbuf);
            break;
        }
        case IPPROTO_OSPF_LSA:
        {
            /*
             *  Reworked fletcher checksum taken from RFC 1008.
             */
            int c0, c1;
            struct libnet_lsa_hdr *lsa_p = (struct libnet_lsa_hdr *)buf;
            u_char *p, *p1, *p2, *p3;

            c0 = 0;
            c1 = 0;

            lsa_p->lsa_cksum[0] = 0;
            lsa_p->lsa_cksum[1] = 0;    /* zero out checksum */

            p = buf;
            p1 = buf;
            p3 = buf + len;             /* beginning and end of buf */

            while (p1 < p3)
            {
                p2 = p1 + LIBNET_MODX;
                if (p2 > p3)
                {
                    p2 = p3;
                }
  
                for (p = p1; p < p2; p++)
                {
                    c0 += (*p);
                    c1 += c0;
                }

                c0 %= 255;
                c1 %= 255;      /* modular 255 */
 
                p1 = p2;
            }

            lsa_p->lsa_cksum[0] = (((len - 17) * c0 - c1) % 255);
            if (lsa_p->lsa_cksum[0] <= 0)
            {
                lsa_p->lsa_cksum[0] += 255;
            }

            lsa_p->lsa_cksum[1] = (510 - c0 - lsa_p->lsa_cksum[0]);
            if (lsa_p->lsa_cksum[1] > 255)
            {
                lsa_p->lsa_cksum[1] -= 255;
            }
            break;
        }
        case IPPROTO_IP:
        {
            iph_p->ip_sum = 0;
            sum = libnet_in_cksum((u_short *)iph_p, len);
            iph_p->ip_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_VRRP:
        {
            struct libnet_vrrp_hdr *vrrph_p =
                (struct libnet_vrrp_hdr *)(buf + ip_hl);

            vrrph_p->vrrp_sum = 0;
            sum = libnet_in_cksum((u_short *)vrrph_p, len);
            vrrph_p->vrrp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        default:
        {
#if (__DEBUG)
            libnet_error(LN_ERR_CRITICAL, "do_checksum: UNSUPP protocol %d\n",
                    protocol);
#endif
            return (-1);
        }
    }
    return (1);
}


u_short
libnet_ip_check(u_short *addr, int len)
{
    int sum;

    sum = libnet_in_cksum(addr, len);
    return (LIBNET_CKSUM_CARRY(sum));
}

#endif
u_long
libnet_get_ipaddr(struct libnet_link_int *l, const char *device, char *ebuf)
{
    struct ifreq ifr;
    register struct sockaddr_in *sin;
    int fd;

    /*
     *  Create dummy socket to perform an ioctl upon.
     */
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        sprintf(ebuf, "socket: %s", strerror(errno));
        return (0);
    }

    memset(&ifr, 0, sizeof(ifr));
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(fd, SIOCGIFADDR, (char*) &ifr) < 0)
    {
        close(fd);
        return(0);
    }
    close(fd);
    return (ntohl(sin->sin_addr.s_addr));
}
