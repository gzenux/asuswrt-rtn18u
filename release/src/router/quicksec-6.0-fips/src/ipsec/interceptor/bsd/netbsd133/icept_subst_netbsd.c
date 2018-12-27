/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Replacement functions for certain NetBSD 1.3 kernel functions.  These
   replacements attach the packet interceptor into the kernel.
*/

/*      $NetBSD: ip_output.c,v 1.40.2.1 1998/05/09 03:33:00 mycroft Exp $ */

/*
 * Copyright (c) 1982, 1986, 1988, 1993
 * The Regents of the University of California. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_output.c 8.3 (Berkeley) 1/21/94
 */

/*      $NetBSD: ip_input.c,v 1.53.2.1 1998/05/09 03:33:00 mycroft Exp $ */

/*
 * Copyright (c) 1982, 1986, 1988, 1993
 * The Regents of the University of California. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_input.c  8.2 (Berkeley) 1/4/94
 */

/*-
 * Copyright (c) 1982, 1986, 1988, 1993
 * The Regents of the University of California. All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Public Access Networks Corporation ("Panix").  It was developed under
 * contract to Panix by Eric Haszlakiewicz and Thor Lancelot Simon.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the NetBSD
 *      Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sshincludes.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "icept_internal.h"
#include "icept_attach.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/route.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#ifdef vax
#include <machine/mtpr.h>
#endif

#include <machine/stdarg.h>

/************************************************************************
 * ip_output replacement
 ************************************************************************/

/* This is an internal function for ip_output
 *
 * Insert IP options into preformed packet.
 * Adjust IP destination as required for IP source routing,
 * as indicated by a non-zero in_addr at the start of the options.
 */
static struct mbuf *
ssh_interceptor_ip_insertoptions(m, opt, phlen)
        register struct mbuf *m;
        struct mbuf *opt;
        int *phlen;
{
        register struct ipoption *p = mtod(opt, struct ipoption *);
        struct mbuf *n;
        register struct ip *ip = mtod(m, struct ip *);
        unsigned optlen;

        optlen = opt->m_len - sizeof(p->ipopt_dst);
        if (optlen + (u_int16_t)ip->ip_len > IP_MAXPACKET)
                return (m);             /* should really fail */
        if (!in_nullhost(p->ipopt_dst))
                ip->ip_dst = p->ipopt_dst;
        if (m->m_flags & M_EXT || m->m_data - optlen < m->m_pktdat) {
                MGETHDR(n, M_DONTWAIT, MT_HEADER);
                if (n == 0)
                        return (m);
                n->m_pkthdr.len = m->m_pkthdr.len + optlen;
                m->m_len -= sizeof(struct ip);
                m->m_data += sizeof(struct ip);
                n->m_next = m;
                m = n;
                m->m_len = optlen + sizeof(struct ip);
                m->m_data += max_linkhdr;
                bcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
        } else {
                m->m_data -= optlen;
                m->m_len += optlen;
                m->m_pkthdr.len += optlen;
                ovbcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
        }
        ip = mtod(m, struct ip *);
        bcopy((caddr_t)p->ipopt_list, (caddr_t)(ip + 1), (unsigned)optlen);
        *phlen = sizeof(struct ip) + optlen;
        ip->ip_len += optlen;
        return (m);
}


/* INTERNAL FUNCTION FOR ssh_interceptor_ip_output
 *
 * Routine called from ip_output() to loop back a copy of an IP multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
static void
ssh_interceptor_ip_mloopback(ifp, m, dst)
        struct ifnet *ifp;
        register struct mbuf *m;
        register struct sockaddr_in *dst;
{
        register struct ip *ip;
        struct mbuf *copym;

        copym = m_copy(m, 0, M_COPYALL);
        if (copym != NULL) {
                /*
                 * We don't bother to fragment if the IP length is greater
                 * than the interface's MTU.  Can this possibly matter?
                 */
                ip = mtod(copym, struct ip *);
                ip->ip_len = htons((u_int16_t)ip->ip_len);
                ip->ip_off = htons((u_int16_t)ip->ip_off);
                ip->ip_sum = 0;
                ip->ip_sum = in_cksum(copym, ip->ip_hl << 2);
                (void) looutput(ifp, copym, sintosa(dst), NULL);
        }
}

/* from ip_output.c,v 1.40.2.1
 *
 * IP output.  The packet in mbuf chain m contains a skeletal IP
 * header (with len, off, ttl, proto, tos, src, dst).
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int
#if __STDC__
ssh_interceptor_ip_output(struct mbuf *m0, ...)
#else
ssh_interceptor_ip_output(m0, va_alist)
        struct mbuf *m0;
        va_dcl
#endif
{
        register struct ip *ip;
        register struct ifnet *ifp;
        register struct mbuf *m = m0;
        register int hlen = sizeof (struct ip);
        int len, error = 0;
        struct route iproute;
        struct sockaddr_in *dst;
        struct in_ifaddr *ia;
        struct mbuf *opt;
        struct route *ro;
        int flags, s;
        int *mtu_p;
        struct ip_moptions *imo;
        va_list ap;
#ifdef PFIL_HOOKS
        struct packet_filter_hook *pfh;
        struct mbuf *m1;
        int rv;
#endif /* PFIL_HOOKS */

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_ip_output\n");
#endif

        va_start(ap, m0);
        opt = va_arg(ap, struct mbuf *);
        ro = va_arg(ap, struct route *);
        flags = va_arg(ap, int);
        imo = va_arg(ap, struct ip_moptions *);
        if (flags & IP_RETURNMTU)
                mtu_p = va_arg(ap, int *);
        else
                mtu_p = NULL;
        va_end(ap);

#ifdef  DIAGNOSTIC
        if ((m->m_flags & M_PKTHDR) == 0)
                panic("ip_output no HDR");
#endif
        if (opt) {
                m = ssh_interceptor_ip_insertoptions(m, opt, &len);
                hlen = len;
        }
        ip = mtod(m, struct ip *);
        /*
         * Fill in IP header.
         */
        if ((flags & (IP_FORWARDING|IP_RAWOUTPUT)) == 0) {
                ip->ip_v = IPVERSION;
                ip->ip_off &= IP_DF;
                ip->ip_id = htons(ip_id++);
                ip->ip_hl = hlen >> 2;
                ipstat.ips_localout++;
        } else {
                hlen = ip->ip_hl << 2;
        }
        /*
         * Route packet.
         */
        if (ro == 0) {
                ro = &iproute;
                bzero((caddr_t)ro, sizeof (*ro));
        }
        dst = satosin(&ro->ro_dst);
        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up.  If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
            !in_hosteq(dst->sin_addr, ip->ip_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                dst->sin_family = AF_INET;
                dst->sin_len = sizeof(*dst);
                dst->sin_addr = ip->ip_dst;
        }
        /*
         * If routing to interface only,
         * short circuit routing lookup.
         */
        if (flags & IP_ROUTETOIF) {
                if ((ia = ifatoia(ifa_ifwithladdr(sintosa(dst)))) == 0) {
                        ipstat.ips_noroute++;
                        error = ENETUNREACH;
                        goto bad;
                }
                ifp = ia->ia_ifp;
                ip->ip_ttl = 1;
        } else {
                if (ro->ro_rt == 0)
                        rtalloc(ro);
                if (ro->ro_rt == 0) {
                        ipstat.ips_noroute++;
                        error = EHOSTUNREACH;
                        goto bad;
                }
                ia = ifatoia(ro->ro_rt->rt_ifa);
                ifp = ro->ro_rt->rt_ifp;
                ro->ro_rt->rt_use++;
                if (ro->ro_rt->rt_flags & RTF_GATEWAY)
                        dst = satosin(ro->ro_rt->rt_gateway);
        }
        if (IN_MULTICAST(ip->ip_dst.s_addr)) {
                struct in_multi *inm;

                m->m_flags |= M_MCAST;
                /*
                 * IP destination address is multicast.  Make sure "dst"
                 * still points to the address in "ro".  (It may have been
                 * changed to point to a gateway address, above.)
                 */
                dst = satosin(&ro->ro_dst);
                /*
                 * See if the caller provided any multicast options
                 */
                if (imo != NULL) {
                        ip->ip_ttl = imo->imo_multicast_ttl;
                        if (imo->imo_multicast_ifp != NULL)
                                ifp = imo->imo_multicast_ifp;
                } else
                        ip->ip_ttl = IP_DEFAULT_MULTICAST_TTL;
                /*
                 * Confirm that the outgoing interface supports multicast.
                 */
                if ((ifp->if_flags & IFF_MULTICAST) == 0) {
                        ipstat.ips_noroute++;
                        error = ENETUNREACH;
                        goto bad;
                }
                /*
                 * If source address not specified yet, use an address
                 * of outgoing interface.
                 */
                if (in_nullhost(ip->ip_src)) {
                        register struct in_ifaddr *ia;

                        IFP_TO_IA(ifp, ia);
                        ip->ip_src = ia->ia_addr.sin_addr;
                }

                IN_LOOKUP_MULTI(ip->ip_dst, ifp, inm);
                if (inm != NULL &&
                   (imo == NULL || imo->imo_multicast_loop)) {
                        /*
                         * If we belong to the destination multicast group
                         * on the outgoing interface, and the caller did not
                         * forbid loopback, loop back a copy.
                         */
                        ssh_interceptor_ip_mloopback(ifp, m, dst);
                }
#ifdef MROUTING
                else {
                        /*
                         * If we are acting as a multicast router, perform
                         * multicast forwarding as if the packet had just
                         * arrived on the interface to which we are about
                         * to send.  The multicast forwarding function
                         * recursively calls this function, using the
                         * IP_FORWARDING flag to prevent infinite recursion.
                         *
                         * Multicasts that are looped back by ip_mloopback(),
                         * above, will be forwarded by the ip_input() routine,
                         * if necessary.
                         */
                        extern struct socket *ip_mrouter;

                        if (ip_mrouter && (flags & IP_FORWARDING) == 0) {
                                if (ip_mforward(m, ifp) != 0) {
                                        m_freem(m);
                                        goto done;
                                }
                        }
                }
#endif
                /*
                 * Multicasts with a time-to-live of zero may be looped-
                 * back, above, but must not be transmitted on a network.
                 * Also, multicasts addressed to the loopback interface
                 * are not sent -- the above call to ip_mloopback() will
                 * loop back a copy if this host actually belongs to the
                 * destination group on the loopback interface.
                 */
                if (ip->ip_ttl == 0 || (ifp->if_flags & IFF_LOOPBACK) != 0) {
                        m_freem(m);
                        goto done;
                }

                goto sendit;
        }
        /*
         * If source address not specified yet, use address
         * of outgoing interface.
         */
        if (in_nullhost(ip->ip_src))
                ip->ip_src = ia->ia_addr.sin_addr;
        /*
         * Look for broadcast address and
         * and verify user is allowed to send
         * such a packet.
         */
        if (in_broadcast(dst->sin_addr, ifp)) {
                if ((ifp->if_flags & IFF_BROADCAST) == 0) {
                        error = EADDRNOTAVAIL;
                        goto bad;
                }
                if ((flags & IP_ALLOWBROADCAST) == 0) {
                        error = EACCES;
                        goto bad;
                }
                /* don't allow broadcast messages to be fragmented */
                if ((u_int16_t)ip->ip_len > ifp->if_mtu) {
                        error = EMSGSIZE;
                        goto bad;
                }
                m->m_flags |= M_BCAST;
        } else
                m->m_flags &= ~M_BCAST;

#ifdef PFIL_HOOKS
        /*
         * Run through list of hooks for output packets.
         */
        m1 = m;
        for (pfh = pfil_hook_get(PFIL_OUT); pfh; pfh = pfh->pfil_link.tqe_next)
                if (pfh->pfil_func) {
                        rv = pfh->pfil_func(ip, hlen, ifp, 1, &m1);
                        if (rv) {
                                error = EHOSTUNREACH;
                                goto done;
                        }
                        m = m1;
                        if (m == NULL)
                                goto done;
                        ip = mtod(m, struct ip *);
                }
#endif /* PFIL_HOOKS */

 sendit:

        /********************************************************************
         * We are now ready to send the packet.  However, instead of sending,
         * pass it to the SSH packet interceptor code.
         *******************************************************************/

        /* Release the route if appropriate. */
        if (ro == &iproute && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }

        /* Fix up various fields of the packet. */
        ip->ip_len = htons((u_int16_t)ip->ip_len);
        ip->ip_off = htons((u_int16_t)ip->ip_off);
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(m, hlen);

        /* Pass the packet to the interceptor.  This call will perform
           m_freem(m).  Make sure we are at splsoftnet. */
        s = splsoftnet();
        ssh_interceptor_receive(SSH_PROTOCOL_IP4, SSH_ICEPT_F_FROM_PROTOCOL,
                                ifp, NULL, 0, m);
        splx(s);
        return 0;

 bad:
        m_freem(m);
 done:
        if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }
        return (error);

}

/* Send a packet received from the interceptor down to the network.  The
   packet is ready for sending, with all fields in network byte order and
   checksum computed.  This function will call m_freem(m) to free the
   mbuf chain. */

void ssh_interceptor_mbuf_send_to_network(protocol, ifp, mediahdr,
                                          mediahdr_len, m)
     SshInterceptorProtocol protocol;
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        register struct ip *ip;
        struct route *ro;
        struct sockaddr_in *dst;
        struct in_ifaddr *ia;
        int error = 0;
        struct route iproute;

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_mbuf_send_to_network\n");
#endif

        /* Sanity check: mbuf should contain at least ip header. */
        if (m->m_pkthdr.len < sizeof(struct ip))
          {
            printf("ssh_interceptor_mbuf_send_to_network: mbuf too short\n");
            m_freem(m);
            return;
          }

        ip = mtod(m, struct ip *);

        /* Convert packet len and offset back to host byte order. */
        ip->ip_len = ntohs((u_int16_t)ip->ip_len);
        ip->ip_off = ntohs((u_int16_t)ip->ip_off);

        /* Sanity check: mbuf should contain the entire packet, and
           nothing else. */
        if (m->m_pkthdr.len != ip->ip_len)
          {
            printf("ssh_interceptor_mbuf_send_to_network: bad mbuf len %d vs. %d\n",
                   m->m_pkthdr.len, ip->ip_len);
            m_freem(m);
            return;
          }

        /* Sanity check: ip header should not be longer than packet. */
        if ((ip->ip_hl << 2) > ip->ip_len)
          {
            printf("ssh_interceptor_mbuf_send_to_network: hlen too large\n");
            m_freem(m);
            return;
          }

        /* We must route the packet again, as any work done before entering
           the interceptor was lost. */

        /*
         * Route packet.
         */
        ro = &iproute;
        bzero((caddr_t)ro, sizeof (*ro));
        dst = satosin(&ro->ro_dst);
        /*
         * If there is a cached route,
         * check that it is to the same destination
         * and is still up.  If not, free it and try again.
         */
        if (ro->ro_rt && ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
            !in_hosteq(dst->sin_addr, ip->ip_dst))) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = (struct rtentry *)0;
        }
        if (ro->ro_rt == 0) {
                dst->sin_family = AF_INET;
                dst->sin_len = sizeof(*dst);
                dst->sin_addr = ip->ip_dst;
        }
        /*
         * If routing to interface only,
         * short circuit routing lookup.
         */
        if (ro->ro_rt == 0)
                rtalloc(ro);
        if (ro->ro_rt == 0) {
                ipstat.ips_noroute++;
                error = EHOSTUNREACH;
                goto bad;
        }
        ia = ifatoia(ro->ro_rt->rt_ifa);

        /* Sanity check; not sure if this can happen except when there
           is a bug in the routing interface.  This check must not be
           done for multicast packets.  */
        if (!IN_MULTICAST(ip->ip_dst.s_addr) && ifp != ro->ro_rt->rt_ifp)
          {
            printf("SSH interceptor: ifp %s (%d) different from "
                   "route ifp %s (%d)\n",
                   ifp->if_xname, ifp->if_index - 1,
                   ro->ro_rt->rt_ifp->if_xname,
                   ro->ro_rt->rt_ifp->if_index - 1);
            ifp = ro->ro_rt->rt_ifp;
          }

        ro->ro_rt->rt_use++;
        if (ro->ro_rt->rt_flags & RTF_GATEWAY)
                dst = satosin(ro->ro_rt->rt_gateway);

        if (IN_MULTICAST(ip->ip_dst.s_addr)) {
                /*
                 * IP destination address is multicast.  Make sure "dst"
                 * still points to the address in "ro".  (It may have been
                 * changed to point to a gateway address, above.)
                 */
                dst = satosin(&ro->ro_dst);
        }


        /*
         * If small enough for interface, can just send directly.
         */
        if ((u_int16_t)ip->ip_len <= ifp->if_mtu) {
                ip->ip_len = htons((u_int16_t)ip->ip_len);
                ip->ip_off = htons((u_int16_t)ip->ip_off);
                /* Note: checksum should already be valid, as the packet
                   is coming from the code above interceptor.
                   ip->ip_sum = 0;
                   ip->ip_sum = in_cksum(m, hlen); */
                error = (*ifp->if_output)(ifp, m, sintosa(dst), ro->ro_rt);
                goto done;
        }
        /*
         * Too large for interface; fragment if possible.
         * Must be able to put at least 8 bytes per fragment.
         */
        if (ip->ip_off & IP_DF) {
                error = EMSGSIZE;
                ipstat.ips_cantfrag++;
                goto bad;
        }

    {
        int hlen, len, off;
        int mhlen, firstlen;
        struct mbuf *m0, **mnext = &m->m_nextpkt;
        struct ip *mhip;

        /*
         * Loop through length of segment after first fragment,
         * make new header and copy data of each part and link onto chain.
         */
        m0 = m;
        mhlen = sizeof (struct ip);
        hlen = ip->ip_hl << 2;
        len = (ifp->if_mtu - hlen) &~ 7;
        firstlen = len;
        for (off = hlen + len; off < (u_int16_t)ip->ip_len; off += len) {
                MGETHDR(m, M_DONTWAIT, MT_HEADER);
                if (m == 0) {
                        error = ENOBUFS;
                        ipstat.ips_odropped++;
                        goto sendorfree;
                }
                *mnext = m;
                mnext = &m->m_nextpkt;
                m->m_data += max_linkhdr;
                mhip = mtod(m, struct ip *);
                *mhip = *ip;
                if (hlen > sizeof (struct ip)) {
                        mhlen = ip_optcopy(ip, mhip) + sizeof (struct ip);
                        mhip->ip_hl = mhlen >> 2;
                }
                m->m_len = mhlen;
                mhip->ip_off = ((off - hlen) >> 3) + (ip->ip_off & ~IP_MF);
                if (ip->ip_off & IP_MF)
                        mhip->ip_off |= IP_MF;
                if (off + len >= (u_int16_t)ip->ip_len)
                        len = (u_int16_t)ip->ip_len - off;
                else
                        mhip->ip_off |= IP_MF;
                mhip->ip_len = htons((u_int16_t)(len + mhlen));
                m->m_next = m_copy(m0, off, len);
                if (m->m_next == 0) {
                        error = ENOBUFS;        /* ??? */
                        ipstat.ips_odropped++;
                        goto sendorfree;
                }
                m->m_pkthdr.len = mhlen + len;
                m->m_pkthdr.rcvif = (struct ifnet *)0;
                mhip->ip_off = htons((u_int16_t)mhip->ip_off);
                mhip->ip_sum = 0;
                mhip->ip_sum = in_cksum(m, mhlen);
                ipstat.ips_ofragments++;
        }
        /*
         * Update first fragment by trimming what's been copied out
         * and updating header, then send each fragment (in order).
         */
        m = m0;
        m_adj(m, hlen + firstlen - (u_int16_t)ip->ip_len);
        m->m_pkthdr.len = hlen + firstlen;
        ip->ip_len = htons((u_int16_t)m->m_pkthdr.len);
        ip->ip_off = htons((u_int16_t)(ip->ip_off | IP_MF));
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(m, hlen);
sendorfree:
        for (m = m0; m; m = m0) {
                m0 = m->m_nextpkt;
                m->m_nextpkt = 0;
                if (error == 0)
                        error = (*ifp->if_output)(ifp, m, sintosa(dst),
                            ro->ro_rt);
                else
                        m_freem(m);
        }

        if (error == 0)
                ipstat.ips_fragmented++;
    }
done:
        if (ro == &iproute && ro->ro_rt) {
                RTFREE(ro->ro_rt);
                ro->ro_rt = 0;
        }
        return;
bad:
        m_freem(m);
        goto done;
}

/*********************************************************************
 * ipintr replacement.
 *********************************************************************/

/* Based on ipintr in ip_input.c,v 1.53.2.1
 *
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void ssh_interceptor_ipintr()
{
        register struct ip *ip = NULL;
        register struct mbuf *m;
        int hlen = 0, len, s;
#ifdef PFIL_HOOKS
        struct packet_filter_hook *pfh;
        struct mbuf *m0;
        int rv;
#endif /* PFIL_HOOKS */

next:
        /*
         * Get next datagram off input queue and get IP header
         * in first mbuf.
         */
        s = splimp();
        IF_DEQUEUE(&ipintrq, m);
        splx(s);
        if (m == 0)
                return;
#ifdef  DIAGNOSTIC
        if ((m->m_flags & M_PKTHDR) == 0)
                panic("ssh_interceptor_ipintr no HDR");
#endif
        /*
         * If no IP addresses have been set yet but the interfaces
         * are receiving, can't do anything with incoming packets yet.
         */
        if (in_ifaddr.tqh_first == 0)
                goto bad;
        ipstat.ips_total++;
        if (m->m_len < sizeof (struct ip) &&
            (m = m_pullup(m, sizeof (struct ip))) == 0) {
                ipstat.ips_toosmall++;
                goto next;
        }
        ip = mtod(m, struct ip *);
        if (ip->ip_v != IPVERSION) {
                ipstat.ips_badvers++;
                goto bad;
        }
        hlen = ip->ip_hl << 2;
        if (hlen < sizeof(struct ip)) { /* minimum header length */
                ipstat.ips_badhlen++;
                goto bad;
        }
        if (hlen > m->m_len) {
                if ((m = m_pullup(m, hlen)) == 0) {
                        ipstat.ips_badhlen++;
                        goto next;
                }
                ip = mtod(m, struct ip *);
        }
        if (in_cksum(m, hlen) != 0) {
                ipstat.ips_badsum++;
                goto bad;
        }
        /*
         * Convert fields to host representation.
         */
        NTOHS(ip->ip_len);
        NTOHS(ip->ip_id);
        NTOHS(ip->ip_off);
        len = ip->ip_len;

        /*
         * Check that the amount of data in the buffers
         * is as at least much as the IP header would have us expect.
         * Trim mbufs if longer than we expect.
         * Drop packet if shorter than we expect.
         */
        if (m->m_pkthdr.len < len) {
                ipstat.ips_tooshort++;
                goto bad;
        }
        if (m->m_pkthdr.len > len) {
                if (m->m_len == m->m_pkthdr.len) {
                        m->m_len = len;
                        m->m_pkthdr.len = len;
                } else
                        m_adj(m, len - m->m_pkthdr.len);
        }

#ifdef PFIL_HOOKS
        /*
         * Run through list of hooks for input packets.
         */
        m0 = m;
        for (pfh = pfil_hook_get(PFIL_IN); pfh; pfh = pfh->pfil_link.tqe_next)
                if (pfh->pfil_func) {
                        rv = pfh->pfil_func(ip, hlen, m->m_pkthdr.rcvif, 0, &m0);
                        if (rv)
                                goto next;
                        m = m0;
                        if (m == NULL)
                                goto next;
                        ip = mtod(m, struct ip *);
                }
#endif /* PFIL_HOOKS */

        /* Restore the packet header to network byte order. */
        HTONS(ip->ip_len);
        HTONS(ip->ip_id);
        HTONS(ip->ip_off);

        /* Pass the packet to the interceptor.  This call will perform
           m_freem(m).  Make sure we are at splsoftnet. */
        s = splsoftnet();
        ssh_interceptor_receive(SSH_PROTOCOL_IP4, 0, m->m_pkthdr.rcvif,
                                NULL, 0, m);
        splx(s);
        goto next;

bad:
        m_freem(m);
        return;
}

/* Processes an ethernet packet coming from the interceptor and going
   up to the protocol.  This will call m_freem(m).  */

void ssh_interceptor_mbuf_send_to_protocol(protocol, ifp, mediahdr,
                                           mediahdr_len, m)
     SshInterceptorProtocol protocol;
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        register struct ip *ip;
        register struct ipq *fp;
        register struct in_ifaddr *ia;
        struct ipqent *ipqe;
        int hlen = 0, mff, len;

        extern int ip_nhops;
        extern int ip_directedbcast;
        extern int ipforwarding;
        extern struct protosw inetsw[];
        extern u_char ip_protox[];

#ifdef SSH_INTERCEPTOR_DEBUG
        printf("ssh_interceptor_mbuf_send_to_protocol\n");
#endif

        ip = mtod(m, struct ip *);
        NTOHS(ip->ip_len);
        NTOHS(ip->ip_id);
        NTOHS(ip->ip_off);
        len = ip->ip_len;
        hlen = ip->ip_hl << 2;

        if (hlen > len || len > m->m_pkthdr.len)
          {
            printf("ssh_interceptor_mbuf_send_to_protocol: bad len %d hlen %d pkthdr.len %d\n",
                   (int)len, (int)hlen, (int)m->m_pkthdr.len);
            m_freem(m);
            return;
          }

        /*
         * Process options and, if not destined for us,
         * ship it on.  ip_dooptions returns 1 when an
         * error was detected (causing an icmp message
         * to be sent and the original packet to be freed).
         */
        ip_nhops = 0;           /* for source routed packets */
        if (hlen > sizeof (struct ip) && ip_dooptions(m))
          return; /* ip_dooptions has freed m. */

        /*
         * Check our list of addresses, to see if the packet is for us.
         */
        for (ia = in_ifaddr.tqh_first; ia; ia = ia->ia_list.tqe_next) {
                if (in_hosteq(ip->ip_dst, ia->ia_addr.sin_addr))
                        goto ours;
                if (((ip_directedbcast == 0) || (ip_directedbcast &&
                    ia->ia_ifp == m->m_pkthdr.rcvif)) &&
                    (ia->ia_ifp->if_flags & IFF_BROADCAST)) {
                        if (in_hosteq(ip->ip_dst, ia->ia_broadaddr.sin_addr) ||
                            in_hosteq(ip->ip_dst, ia->ia_netbroadcast) ||
                            /*
                             * Look for all-0's host part (old broadcast addr),
                             * either for subnet or net.
                             */
                            ip->ip_dst.s_addr == ia->ia_subnet ||
                            ip->ip_dst.s_addr == ia->ia_net)
                                goto ours;
                }

                /*
                 * An interface with IP address zero accepts
                 * all packets that arrive on that interface.
                 */
                if ((ia->ia_ifp == m->m_pkthdr.rcvif) &&
                    in_nullhost(ia->ia_addr.sin_addr))
                        goto ours;
        }
        if (IN_MULTICAST(ip->ip_dst.s_addr)) {
                struct in_multi *inm;
#ifdef MROUTING
                extern struct socket *ip_mrouter;

                if (m->m_flags & M_EXT) {
                        if ((m = m_pullup(m, hlen)) == 0) {
                                ipstat.ips_toosmall++;
                                return;
                        }
                        ip = mtod(m, struct ip *);
                }

                if (ip_mrouter) {
                        /*
                         * If we are acting as a multicast router, all
                         * incoming multicast packets are passed to the
                         * kernel-level multicast forwarding function.
                         * The packet is returned (relatively) intact; if
                         * ip_mforward() returns a non-zero value, the packet
                         * must be discarded, else it may be accepted below.
                         *
                         * (The IP ident field is put in the same byte order
                         * as expected when ip_mforward() is called from
                         * ip_output().)
                         */
                        ip->ip_id = htons(ip->ip_id);
                        if (ip_mforward(m, m->m_pkthdr.rcvif) != 0) {
                                ipstat.ips_cantforward++;
                                m_freem(m);
                                return;
                        }
                        ip->ip_id = ntohs(ip->ip_id);

                        /*
                         * The process-level routing demon needs to receive
                         * all multicast IGMP packets, whether or not this
                         * host belongs to their destination groups.
                         */
                        if (ip->ip_p == IPPROTO_IGMP)
                                goto ours;
                        ipstat.ips_forward++;
                }
#endif
                /*
                 * See if we belong to the destination multicast group on the
                 * arrival interface.
                 */
                IN_LOOKUP_MULTI(ip->ip_dst, m->m_pkthdr.rcvif, inm);
                if (inm == NULL) {
                        ipstat.ips_cantforward++;
                        m_freem(m);
                        return;
                }
                goto ours;
        }
        if (ip->ip_dst.s_addr == INADDR_BROADCAST ||
            in_nullhost(ip->ip_dst))
                goto ours;

        /*
         * Not for us; forward if possible and desirable.
         */
        if (ipforwarding == 0) {
                ipstat.ips_cantforward++;
                m_freem(m);
        } else
                ip_forward(m, 0);
        return;

ours:
        /*
         * If offset or IP_MF are set, must reassemble.
         * Otherwise, nothing need be done.
         * (We could look in the reassembly queue to see
         * if the packet was previously fragmented,
         * but it's not worth the time; just let them time out.)
         */
        if (ip->ip_off & ~(IP_DF|IP_RF)) {
                /*
                 * Look for queue of fragments
                 * of this datagram.
                 */
                for (fp = ipq.lh_first; fp != NULL; fp = fp->ipq_q.le_next)
                        if (ip->ip_id == fp->ipq_id &&
                            in_hosteq(ip->ip_src, fp->ipq_src) &&
                            in_hosteq(ip->ip_dst, fp->ipq_dst) &&
                            ip->ip_p == fp->ipq_p)
                                goto found;
                fp = 0;
found:

                /*
                 * Adjust ip_len to not reflect header,
                 * set ipqe_mff if more fragments are expected,
                 * convert offset of this to bytes.
                 */
                ip->ip_len -= hlen;
                mff = (ip->ip_off & IP_MF) != 0;
                if (mff) {
                        /*
                         * Make sure that fragments have a data length
                         * that's a non-zero multiple of 8 bytes.
                         */
                        if (ip->ip_len == 0 || (ip->ip_len & 0x7) != 0) {
                                ipstat.ips_badfrags++;
                                goto bad;
                        }
                }
                ip->ip_off <<= 3;

                /*
                 * If datagram marked as having more fragments
                 * or if this is not the first fragment,
                 * attempt reassembly; if it succeeds, proceed.
                 */
                if (mff || ip->ip_off) {
                        ipstat.ips_fragments++;
                        MALLOC(ipqe, struct ipqent *, sizeof (struct ipqent),
                            M_IPQ, M_NOWAIT);
                        if (ipqe == NULL) {
                                ipstat.ips_rcvmemdrop++;
                                goto bad;
                        }
                        ipqe->ipqe_mff = mff;
                        ipqe->ipqe_m = m;
                        ipqe->ipqe_ip = ip;
                        m = ip_reass(ipqe, fp);
                        if (m == 0)
                          return;
                        ipstat.ips_reassembled++;
                        ip = mtod(m, struct ip *);
                } else
                        if (fp)
                                ip_freef(fp);
        } else
                ip->ip_len -= hlen;

        /*
         * Switch out to protocol's input routine.
         */
        ipstat.ips_delivered++;
        (*inetsw[ip_protox[ip->ip_p]].pr_input)(m, hlen);
        return;
bad:
        m_freem(m);
        return;
}

/* This function is attached to be called after any call to ifioctl.
   Such calls are a potential indication of interface status or parameters
   changing. */

void ssh_interceptor_after_ifioctl()
{
  int s;

  s = splsoftnet();
  ssh_interceptor_notify_interface_change();
  splx(s);
}

/* Returns the substitutions to be made on this platform. */

SshAttachRec *ssh_get_substitutions()
{
  static SshAttachRec sub[] =
  {
    { SSH_ATTACH_REPLACE, ipintr, ssh_interceptor_ipintr },
    { SSH_ATTACH_REPLACE, ip_output, ssh_interceptor_ip_output },
    { SSH_ATTACH_AFTER, ifioctl, ssh_interceptor_after_ifioctl },
    { SSH_ATTACH_END }
  };

  return sub;
}

int ssh_interceptor_iftype(struct ifnet *ifp)
{
  return SSH_INTERCEPTOR_MEDIA_PLAIN;
}

const char *ssh_ident_attach = "NetBSD 1.3 IP-level";

int ssh_interceptor_spl()
{
  return splsoftnet();
}
