/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This module performs the magic of attaching and deattaching the
   interceptor from the TCP/IP stack.  This version takes media headers
   in order to allow testing the pseudo-ip.  Currently only ethernet
   interfaces are supported.
*/

#define INET

/*      $NetBSD: if_ethersubr.c,v 1.26 1997/10/02 19:41:59 is Exp $     */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
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
 *      @(#)if_ethersubr.c      8.1 (Berkeley) 6/10/93
 */

#include "sshincludes.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "icept_internal.h"
#include "icept_attach.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>

#include <machine/cpu.h>

#define time time_if_h
#include <net/if.h>
#undef time

#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <net/if_ether.h>

#include <netinet/in.h>
#ifdef INET
#include <netinet/in_var.h>
#endif
#include <netinet/if_inarp.h>

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#ifdef ISO
#include <netiso/argo_debug.h>
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_snpac.h>
#endif

#ifdef LLC
#include <netccitt/dll.h>
#include <netccitt/llc_var.h>
#endif

#if defined(LLC) && defined(CCITT)
extern struct ifqueue pkintrq;
#endif

#ifdef NETATALK
#include <netatalk/at.h>
#include <netatalk/at_var.h>
#include <netatalk/at_extern.h>


#define llc_snap_org_code llc_un.type_snap.org_code
#define llc_snap_ether_type llc_un.type_snap.ether_type

extern u_char   at_org_code[3];
extern u_char   aarp_org_code[3];
#endif /* NETATALK */

#include "sshincludes.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "icept_internal.h"
#include "icept_attach.h"

extern u_char   etherbroadcastaddr[6];
#define senderr(e) { error = (e); goto bad;}

#define SIN(x) ((struct sockaddr_in *)x)

/*
 * Ethernet output routine.
 * Encapsulate a packet of type family for the local net.
 * Assumes that ifp is actually pointer to ethercom structure.
 */
int
ssh_interceptor_ether_output(ifp, m0, dst, rt0)
        register struct ifnet *ifp;
        struct mbuf *m0;
        struct sockaddr *dst;
        struct rtentry *rt0;
{
        u_int16_t etype;
        int error = 0, s;
        u_char edst[6];
        register struct mbuf *m = m0;
        register struct rtentry *rt;
        struct mbuf *mcopy = (struct mbuf *)0;
        struct ether_header *eh, ehd;
#ifdef INET
        struct arphdr *ah;
#endif /* INET */
#ifdef NETATALK
        struct at_ifaddr *aa;
#endif /* NETATALK */

        if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
                senderr(ENETDOWN);
        ifp->if_lastchange = time;
        if ((rt = rt0) != NULL) {
                if ((rt->rt_flags & RTF_UP) == 0) {
                        if ((rt0 = rt = rtalloc1(dst, 1)) != NULL)
                                rt->rt_refcnt--;
                        else
                                senderr(EHOSTUNREACH);
                }
                if (rt->rt_flags & RTF_GATEWAY) {
                        if (rt->rt_gwroute == 0)
                                goto lookup;
                        if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
                                rtfree(rt); rt = rt0;
                        lookup: rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1);
                                if ((rt = rt->rt_gwroute) == 0)
                                        senderr(EHOSTUNREACH);
                        }
                }
                if (rt->rt_flags & RTF_REJECT)
                        if (rt->rt_rmx.rmx_expire == 0 ||
                            time.tv_sec < rt->rt_rmx.rmx_expire)
                                senderr(rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
        }
        switch (dst->sa_family) {

#ifdef INET
        case AF_INET:
                if (m->m_flags & M_BCAST)
                        bcopy((caddr_t)etherbroadcastaddr, (caddr_t)edst,
                                sizeof(edst));

                else if (m->m_flags & M_MCAST) {
                        ETHER_MAP_IP_MULTICAST(&SIN(dst)->sin_addr,
                            (caddr_t)edst)

                } else if (!arpresolve(ifp, rt, m, dst, edst))
                        return (0);     /* if not yet resolved */
                /* If broadcasting on a simplex interface, loopback a copy */
                if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX))
                        mcopy = m_copy(m, 0, (int)M_COPYALL);
                etype = htons(ETHERTYPE_IP);
                break;

        case AF_ARP:
                ah = mtod(m, struct arphdr *);
                if (m->m_flags & M_BCAST)
                        bcopy((caddr_t)etherbroadcastaddr, (caddr_t)edst,
                                sizeof(edst));
                else
                        bcopy((caddr_t)ar_tha(ah),
                                (caddr_t)edst, sizeof(edst));

                ah->ar_hrd = htons(ARPHRD_ETHER);

                switch(ntohs(ah->ar_op)) {
                case ARPOP_REVREQUEST:
                case ARPOP_REVREPLY:
                        etype = htons(ETHERTYPE_REVARP);
                        break;

                case ARPOP_REQUEST:
                case ARPOP_REPLY:
                default:
                        etype = htons(ETHERTYPE_ARP);
                }

                break;
#endif
#ifdef NETATALK
    case AF_APPLETALK:
                if (!aarpresolve(ifp, m, (struct sockaddr_at *)dst, edst)) {
#ifdef NETATALKDEBUG
                        printf("aarpresolv failed\n");
#endif /* NETATALKDEBUG */
                        return (0);
                }
                /*
                 * ifaddr is the first thing in at_ifaddr
                 */
                aa = (struct at_ifaddr *) at_ifawithnet(
                    (struct sockaddr_at *)dst, ifp);
                if (aa == NULL)
                    goto bad;

                /*
                 * In the phase 2 case, we need to prepend an mbuf for the
                 * llc header.  Since we must preserve the value of m,
                 * which is passed to us by value, we m_copy() the first
                 * mbuf, and use it for our llc header.
                 */
                if (aa->aa_flags & AFA_PHASE2) {
                        struct llc llc;

                        M_PREPEND(m, sizeof(struct llc), M_WAIT);
                        llc.llc_dsap = llc.llc_ssap = LLC_SNAP_LSAP;
                        llc.llc_control = LLC_UI;
                        bcopy(at_org_code, llc.llc_snap_org_code,
                            sizeof(llc.llc_snap_org_code));
                        llc.llc_snap_ether_type = htons(ETHERTYPE_AT);
                        bcopy(&llc, mtod(m, caddr_t), sizeof(struct llc));
                        etype = htons(m->m_pkthdr.len);
                } else {
                        etype = htons(ETHERTYPE_AT);
                }
                break;
#endif /* NETATALK */
#ifdef NS
        case AF_NS:
                etype = htons(ETHERTYPE_NS);
                bcopy((caddr_t)&(((struct sockaddr_ns *)dst)->sns_addr.x_host),
                    (caddr_t)edst, sizeof (edst));
                if (!bcmp((caddr_t)edst, (caddr_t)&ns_thishost, sizeof(edst)))
                        return (looutput(ifp, m, dst, rt));
                /* If broadcasting on a simplex interface, loopback a copy */
                if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX))
                        mcopy = m_copy(m, 0, (int)M_COPYALL);
                break;
#endif
#ifdef  ISO
        case AF_ISO: {
                int     snpalen;
                struct  llc *l;
                register struct sockaddr_dl *sdl;

                if (rt && (sdl = (struct sockaddr_dl *)rt->rt_gateway) &&
                    sdl->sdl_family == AF_LINK && sdl->sdl_alen > 0) {
                        bcopy(LLADDR(sdl), (caddr_t)edst, sizeof(edst));
                } else {
                        error = iso_snparesolve(ifp, (struct sockaddr_iso *)dst,
                                                (char *)edst, &snpalen);
                        if (error)
                                goto bad; /* Not Resolved */
                }
                /* If broadcasting on a simplex interface, loopback a copy */
                if (*edst & 1)
                        m->m_flags |= (M_BCAST|M_MCAST);
                if ((m->m_flags & M_BCAST) && (ifp->if_flags & IFF_SIMPLEX) &&
                    (mcopy = m_copy(m, 0, (int)M_COPYALL))) {
                        M_PREPEND(mcopy, sizeof (*eh), M_DONTWAIT);
                        if (mcopy) {
                                eh = mtod(mcopy, struct ether_header *);
                                bcopy((caddr_t)edst,
                                      (caddr_t)eh->ether_dhost, sizeof (edst));
                                bcopy(LLADDR(ifp->if_sadl),
                                      (caddr_t)eh->ether_shost, sizeof (edst));
                        }
                }
                M_PREPEND(m, 3, M_DONTWAIT);
                if (m == NULL)
                        return (0);
                etype = htons(m->m_pkthdr.len);
                l = mtod(m, struct llc *);
                l->llc_dsap = l->llc_ssap = LLC_ISO_LSAP;
                l->llc_control = LLC_UI;
#ifdef ARGO_DEBUG
                if (argo_debug[D_ETHER]) {
                        int i;
                        printf("unoutput: sending pkt to: ");
                        for (i=0; i<6; i++)
                                printf("%x ", edst[i] & 0xff);
                        printf("\n");
                }
#endif
                } break;
#endif /* ISO */
#ifdef  LLC
/*      case AF_NSAP: */
        case AF_CCITT: {
                register struct sockaddr_dl *sdl =
                        (struct sockaddr_dl *) rt -> rt_gateway;

                if (sdl && sdl->sdl_family == AF_LINK
                    && sdl->sdl_alen > 0) {
                        bcopy(LLADDR(sdl), (char *)edst,
                                sizeof(edst));
                } else goto bad; /* Not a link interface ? Funny ... */
                if ((ifp->if_flags & IFF_SIMPLEX) && (*edst & 1) &&
                    (mcopy = m_copy(m, 0, (int)M_COPYALL))) {
                        M_PREPEND(mcopy, sizeof (*eh), M_DONTWAIT);
                        if (mcopy) {
                                eh = mtod(mcopy, struct ether_header *);
                                bcopy((caddr_t)edst,
                                      (caddr_t)eh->ether_dhost, sizeof (edst));
                                bcopy(LLADDR(ifp->if_sadl),
                                      (caddr_t)eh->ether_shost, sizeof (edst));
                        }
                }
                etype = htons(m->m_pkthdr.len);
#ifdef LLC_DEBUG
                {
                        int i;
                        register struct llc *l = mtod(m, struct llc *);

                        printf("ether_output: sending LLC2 pkt to: ");
                        for (i=0; i<6; i++)
                                printf("%x ", edst[i] & 0xff);
                        printf(" len 0x%x dsap 0x%x ssap 0x%x control 0x%x\n",
                            m->m_pkthdr.len, l->llc_dsap & 0xff, l->llc_ssap &0xff,
                            l->llc_control & 0xff);

                }
#endif /* LLC_DEBUG */
                } break;
#endif /* LLC */

        case AF_UNSPEC:
                eh = (struct ether_header *)dst->sa_data;
                bcopy((caddr_t)eh->ether_dhost, (caddr_t)edst, sizeof (edst));
                /* AF_UNSPEC doesn't swap the byte order of the ether_type. */
                etype = eh->ether_type;
                break;

        default:
                printf("%s: can't handle af%d\n", ifp->if_xname,
                        dst->sa_family);
                senderr(EAFNOSUPPORT);
        }

        if (mcopy)
                (void) looutput(ifp, mcopy, dst, rt);

        /*
         * Add local net header.  If no space in first mbuf,
         * allocate another.
         */
        bcopy((caddr_t)&etype,(caddr_t)&ehd.ether_type,
              sizeof(ehd.ether_type));
        bcopy((caddr_t)edst, (caddr_t)ehd.ether_dhost, sizeof (edst));
        bcopy(LLADDR(ifp->if_sadl), (caddr_t)ehd.ether_shost,
              sizeof(ehd.ether_shost));

        /* Pass the packet to the interceptor.  This will call
           m_freem(m) eventually.  Indicate that the packet is coming
           from a protocol.  Make sure we are at splsoftnet. */
        s = ssh_interceptor_spl();
        ssh_interceptor_receive(SSH_PROTOCOL_ETHERNET,
                                SSH_ICEPT_F_FROM_PROTOCOL, ifp, &ehd,
                                sizeof(ehd), m);
        splx(s);

        return 0;

bad:
        if (m)
                m_freem(m);
        return (error);
}

/* Processes an ethernet packet coming from the interceptor and going down to
   network. This will call m_freem(m). */

void
ssh_interceptor_mbuf_send_to_network(protocol, ifp, mediahdr, mediahdr_len, m)
     SshInterceptorProtocol protocol;
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        int s;
        register struct ether_header *eh = mediahdr;

        if (mediahdr_len != sizeof(*eh))
          {
            printf("ssh_interceptor_mbuf_send_to_network: bad hdr len %d\n",
                   mediahdr_len);
            m_freem(m);
            return;
          }

        /* Prepend the ethernet packet into the mbuf. */
        M_PREPEND(m, sizeof (struct ether_header), M_DONTWAIT);
        if (m == 0) {
                IF_DROP(&ifp->if_snd);
                return;
        }
        *mtod(m, struct ether_header *) = *eh;

        s = splimp();
        /*
         * Queue message on interface, and start output if interface
         * not yet active.
         */
        if (IF_QFULL(&ifp->if_snd)) {
                IF_DROP(&ifp->if_snd);
                splx(s);
                m_freem(m);
                return;
        }
        ifp->if_obytes += m->m_pkthdr.len;
        IF_ENQUEUE(&ifp->if_snd, m);
        if ((ifp->if_flags & IFF_OACTIVE) == 0)
                (*ifp->if_start)(ifp);
        if (m->m_flags & M_MCAST)
                ifp->if_omcasts++;
        splx(s);
}

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
void
ssh_interceptor_ether_input(ifp, eh, m)
        struct ifnet *ifp;
        register struct ether_header *eh;
        struct mbuf *m;
{
        int s;

        if ((ifp->if_flags & IFF_UP) == 0) {
                m_freem(m);
                return;
        }
        ifp->if_lastchange = time;
        ifp->if_ibytes += m->m_pkthdr.len + sizeof (*eh);

        /* Pass the packet to the interceptor.  This will call
           m_freem(m) eventually. Indicate that the packet is coming
           from the network.  Make sure we are at splsoftnet. */
        s = ssh_interceptor_spl();
        ssh_interceptor_receive(SSH_PROTOCOL_ETHERNET, 0, ifp, eh,
                                sizeof(*eh), m);
        splx(s);
}

/*  Processes an ethernet packet coming from the interceptor and going
 * up to the protocol.  This will call m_freem(m).
 */
void
ssh_interceptor_mbuf_send_to_protocol(protocol, ifp, mediahdr, mediahdr_len, m)
     SshInterceptorProtocol protocol;
     struct ifnet *ifp;
     void *mediahdr;
     size_t mediahdr_len;
     struct mbuf *m;
{
        register struct ifqueue *inq;
        u_int16_t etype;
        int s;
        register struct ether_header *eh = mediahdr;
#if defined (ISO) || defined (LLC) || defined(NETATALK)
        register struct llc *l;
#endif

        if (mediahdr_len != sizeof(*eh))
          {
            printf("ssh_interceptor_mbuf_send_to_network: bad hdr len %d\n",
                   mediahdr_len);
            m_freem(m);
            return;
          }

        if (eh->ether_dhost[0] & 1) {
                if (bcmp((caddr_t)etherbroadcastaddr, (caddr_t)eh->ether_dhost,
                    sizeof(etherbroadcastaddr)) == 0)
                        m->m_flags |= M_BCAST;
                else
                        m->m_flags |= M_MCAST;
        }
        if (m->m_flags & (M_BCAST|M_MCAST))
                ifp->if_imcasts++;

        etype = ntohs(eh->ether_type);
        switch (etype) {
#ifdef INET
        case ETHERTYPE_IP:
                schednetisr(NETISR_IP);
                inq = &ipintrq;
                break;

        case ETHERTYPE_ARP:
                schednetisr(NETISR_ARP);
                inq = &arpintrq;
                break;

        case ETHERTYPE_REVARP:
                revarpinput(m); /* queue? */
                return;
#endif
#ifdef NS
        case ETHERTYPE_NS:
                schednetisr(NETISR_NS);
                inq = &nsintrq;
                break;

#endif
#ifdef NETATALK
        case ETHERTYPE_AT:
                schednetisr(NETISR_ATALK);
                inq = &atintrq1;
                break;
        case ETHERTYPE_AARP:
                /* probably this should be done with a NETISR as well */
                aarpinput(ifp, m);
                return;
#endif /* NETATALK */
        default:
#if defined (ISO) || defined (LLC) || defined (NETATALK)
                if (etype > ETHERMTU)
                        goto dropanyway;
                l = mtod(m, struct llc *);
                switch (l->llc_dsap) {
#ifdef NETATALK
                case LLC_SNAP_LSAP:
                        switch (l->llc_control) {
                        case LLC_UI:
                                if (l->llc_ssap != LLC_SNAP_LSAP) {
                                        goto dropanyway;
                                }

                                if (Bcmp(&(l->llc_snap_org_code)[0],
                                    at_org_code, sizeof(at_org_code)) == 0 &&
                                    ntohs(l->llc_snap_ether_type) ==
                                    ETHERTYPE_AT) {
                                        inq = &atintrq2;
                                        m_adj(m, sizeof(struct llc));
                                        schednetisr(NETISR_ATALK);
                                        break;
                                }

                                if (Bcmp(&(l->llc_snap_org_code)[0],
                                    aarp_org_code,
                                    sizeof(aarp_org_code)) == 0 &&
                                    ntohs(l->llc_snap_ether_type) ==
                                    ETHERTYPE_AARP) {
                                        m_adj( m, sizeof(struct llc));
                                        aarpinput(ifp, m);
                                    return;
                                }

                        default:
                                goto dropanyway;
                        }
                        break;
#endif /* NETATALK */
#ifdef  ISO
                case LLC_ISO_LSAP:
                        switch (l->llc_control) {
                        case LLC_UI:
                                /* LLC_UI_P forbidden in class 1 service */
                                if ((l->llc_dsap == LLC_ISO_LSAP) &&
                                    (l->llc_ssap == LLC_ISO_LSAP)) {
                                        /* LSAP for ISO */
                                        if (m->m_pkthdr.len > etype)
                                                m_adj(m, etype - m->m_pkthdr.len);
                                        m->m_data += 3;
                                        m->m_len -= 3;
                                        m->m_pkthdr.len -= 3;
                                        M_PREPEND(m, sizeof *eh, M_DONTWAIT);
                                        if (m == 0)
                                                return;
                                        *mtod(m, struct ether_header *) = *eh;
#ifdef ARGO_DEBUG
                                        if (argo_debug[D_ETHER])
                                                printf("clnp packet");
#endif
                                        schednetisr(NETISR_ISO);
                                        inq = &clnlintrq;
                                        break;
                                }
                                goto dropanyway;

                        case LLC_XID:
                        case LLC_XID_P:
                                if (m->m_len < 6)
                                        goto dropanyway;
                                l->llc_window = 0;
                                l->llc_fid = 9;
                                l->llc_class = 1;
                                l->llc_dsap = l->llc_ssap = 0;
                                /* Fall through to */
                        case LLC_TEST:
                        case LLC_TEST_P:
                        {
                                struct sockaddr sa;
                                register struct ether_header *eh2;
                                int i;
                                u_char c = l->llc_dsap;

                                l->llc_dsap = l->llc_ssap;
                                l->llc_ssap = c;
                                if (m->m_flags & (M_BCAST | M_MCAST))
                                        bcopy(LLADDR(ifp->if_sadl),
                                              (caddr_t)eh->ether_dhost, 6);
                                sa.sa_family = AF_UNSPEC;
                                sa.sa_len = sizeof(sa);
                                eh2 = (struct ether_header *)sa.sa_data;
                                for (i = 0; i < 6; i++) {
                                        eh2->ether_shost[i] = c =
                                            eh->ether_dhost[i];
                                        eh2->ether_dhost[i] =
                                            eh->ether_dhost[i] =
                                            eh->ether_shost[i];
                                        eh->ether_shost[i] = c;
                                }
                                ifp->if_output(ifp, m, &sa, NULL);
                                return;
                        }
                        default:
                                m_freem(m);
                                return;
                        }
                        break;
#endif /* ISO */
#ifdef LLC
                case LLC_X25_LSAP:
                {
                        if (m->m_pkthdr.len > etype)
                                m_adj(m, etype - m->m_pkthdr.len);
                        M_PREPEND(m, sizeof(struct sdl_hdr) , M_DONTWAIT);
                        if (m == 0)
                                return;
                        if ( !sdl_sethdrif(ifp, eh->ether_shost, LLC_X25_LSAP,
                                            eh->ether_dhost, LLC_X25_LSAP, 6,
                                            mtod(m, struct sdl_hdr *)))
                                panic("ETHER cons addr failure");
                        mtod(m, struct sdl_hdr *)->sdlhdr_len = etype;
#ifdef LLC_DEBUG
                                printf("llc packet\n");
#endif /* LLC_DEBUG */
                        schednetisr(NETISR_CCITT);
                        inq = &llcintrq;
                        break;
                }
#endif /* LLC */
                dropanyway:
                default:
                        m_freem(m);
                        return;
                }
#else /* ISO || LLC  || NETATALK*/
            m_freem(m);
            return;
#endif /* ISO || LLC || NETATALK*/
        }

        s = splimp();
        if (IF_QFULL(inq)) {
                IF_DROP(inq);
                m_freem(m);
        } else
                IF_ENQUEUE(inq, m);
        splx(s);
}

/* This function is attached to be called after any call to ifioctl.
   Such calls are a potential indication of interface status or parameters
   changing. */

void ssh_interceptor_after_ifioctl()
{
  int s;

  s = ssh_interceptor_spl();
  ssh_interceptor_notify_interface_change();
  splx(s);
}

/* Returns the substitutions to be made on this platform. */

SshAttachRec *ssh_get_substitutions()
{
  static SshAttachRec sub[] =
  {
    { SSH_ATTACH_REPLACE, ether_output, ssh_interceptor_ether_output },
    { SSH_ATTACH_REPLACE, ether_input, ssh_interceptor_ether_input },
    { SSH_ATTACH_AFTER, ifioctl, ssh_interceptor_after_ifioctl },
    { SSH_ATTACH_END }
  };

  return sub;
}

int ssh_interceptor_iftype(struct ifnet *ifp)
{
  if (ifp->if_output == ether_output)
    return SSH_INTERCEPTOR_MEDIA_ETHERNET;

  return SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
}

const char *ssh_ident_attach = "NetBSD 1.3 ethernet";

int ssh_interceptor_spl()
{
  return splnet();
}
