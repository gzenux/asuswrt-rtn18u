/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   NetBSD (and possibly other systems providing packet filter)
   interceptor attachment routines.

   : for netbsd 2.0.2 and netbsd 3.0 on i386 platform you will
   need to manually do

   cp $syssrc/arch/@arch/include/pic.h to /usr/include/machine
   cp $sysscr/arch/x86/include/pic.h to /usr/include/x86

   Also the compilation requires system source tree. The default is to
   look from /usr/src/sys, but this can be changed with --with-kernel-headers
   configure option.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "icept_internal.h"
#include "icept_chardev.h"
#include "ip_cksum.h"

#ifndef SSH_IPSEC_SEND_IS_SYNC
# error "This interceptor has synchronous send, enable SSH_IPSEC_SEND_IS_SYNC"
#endif /* SSH_IPSEC_SEND_IS */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/pfil.h>
#include <netinet/ip_var.h>
#ifdef WITH_IPV6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* WITH_IPV6 */

#define SSH_DEBUG_MODULE "SshInterceptor"

/* Packet filter heads */
#if SSH_NetBSD < 300
void ssh_attach_ifioctl(void);
void ssh_detach_ifioctl(void);
#else /* SSH_NetBSD < 300 */
extern struct pfil_head if_pfil;
#endif /* SSH_NetBSD < 300 */

extern struct pfil_head inet_pfil_hook;
extern struct pfil_head inet6_pfil_hook;

#if SSH_NetBSD > 299
/* This function gets called from the packet filter when interface
   status changes. The mp indicates type of change. */static int
icept_if_hook(void *context, struct mbuf **mp, struct ifnet *ifp, int dir)
{
  int s;

  s = ssh_interceptor_spl();
  ssh_interceptor_notify_interface_change();
  splx(s);

  return 0;
}
#endif /* SSH_NetBSD > 299 */

/* This routine hooks into the packet filter IP level and passes the packets
   from adapter/protocol to IPSEC application. After the packets arrive from
   IPSEC, they will end up here second time - now attached with a tag
   indicating they have been processed. */
static int
icept_inet_hook(void *context, struct mbuf **mp, struct ifnet *ifp, int dir,
		SshInterceptorProtocol protocol)
{
  struct mbuf *m = *mp;
  struct m_tag *mtag;
  int s;

  SSH_DEBUG(SSH_D_LOWSTART,
	    ("%sv%d (flags=0x%x) len = 0x%lx",
	     dir == PFIL_IN ? "I" :"O",
	     protocol == SSH_PROTOCOL_IP4 ? 4 : 6,
	     m->m_pkthdr.csum_flags,
	     m->m_pkthdr.len));

  /* Check if we have already done processing for this packet on this
     direction. If so, pass it out from the packet filter. If not, the
     pass it to the security engine. */

  if (dir == PFIL_IN)
    {
      if ((mtag = m_tag_find(m, PACKET_TAG_IPSEC_IN_DONE, NULL)) != NULL)
	{
	  SSH_DEBUG(SSH_D_LOWOK, ("Input packet already input processed"));
	  return 0;
	}
    }
  else if (dir == PFIL_OUT)
    {
      if ((mtag = m_tag_find(m, PACKET_TAG_IPSEC_OUT_DONE, NULL)) != NULL)
	{
	  SSH_DEBUG(SSH_D_LOWOK, ("Output packet already output processed"));

	  /* Prevent fragmentation by lying that we can segment offload. */
#ifdef M_CSUM_TSOv4
#if 0
	  /* This line broke the netbsd interceptor on the 4.99.3 version. If
	     this was done then the in_cksum started to print out the "cksum:
	     out of data" errors for each packet we were sending out. Inbound
	     packets went ok, but all outbound packets were truncated before
	     given to the in_cksum. */
	  m->m_pkthdr.csum_flags |= M_CSUM_TSOv4;
#endif
#endif
	  return 0;
	}

      /* When we enter this routine, the checksum has not yet been calculated
	 The engine expects this so we'll do it ourselves. */
      if (protocol == SSH_PROTOCOL_IP4)
	{
	  SshUInt16 hlen, sum;
	  unsigned char *ucp;

	  if ((m = m_pullup(m, SSH_IPH4_HDRLEN)) == NULL)
	    goto bad;

	  ucp = mtod(m, unsigned char *);

	  hlen = 4 * SSH_IPH4_HLEN(ucp);

	  SSH_IPH4_SET_CHECKSUM(ucp, 0);
	  sum = ssh_ip_cksum(ucp, hlen);
	  SSH_IPH4_SET_CHECKSUM(ucp, sum);
	  m->m_pkthdr.csum_flags &= ~M_CSUM_IPv4;

	  if (m->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4))
	    {
	      in_delayed_cksum(m);
	      m->m_pkthdr.csum_flags &= ~(M_CSUM_TCPv4|M_CSUM_UDPv4);
	    }
	}
    }

  s = ssh_interceptor_spl();
  ssh_interceptor_receive(protocol,
			  dir == PFIL_OUT ? SSH_ICEPT_F_FROM_PROTOCOL : 0,
			  ifp,
			  NULL, 0,  /* media header */
			  m);
  splx(s);

 bad:
  /* Indicate packet as stolen. */
  *mp = NULL;
  return 0;
}

static int
icept_inet4_hook(void *context, struct mbuf **mp, struct ifnet *ifp, int dir)
{
  return icept_inet_hook(context, mp, ifp, dir, SSH_PROTOCOL_IP4);
}


#ifdef WITH_IPV6
static int
icept_inet6_hook(void *context, struct mbuf **mp, struct ifnet *ifp, int dir)
{
  return icept_inet_hook(context, mp, ifp, dir, SSH_PROTOCOL_IP6);
}
#endif /* WITH_IPV6 */

/* Attach packet filter functions. */
void ssh_attach_substitutions(void)
{
#ifdef PFIL_IFNET
  pfil_add_hook(icept_if_hook, NULL, PFIL_IFADDR|PFIL_IFNET, &if_pfil);
#endif
#if SSH_NetBSD < 300
  ssh_attach_ifioctl();
#endif /* SSH_NetBSD < 300 */

  pfil_add_hook(icept_inet4_hook, NULL, PFIL_ALL, &inet_pfil_hook);
#ifdef WITH_IPV6
  pfil_add_hook(icept_inet6_hook, NULL, PFIL_ALL, &inet6_pfil_hook);
#endif /* WITH_IPV6 */
}

/* Detach packet filter functions. This call expects that the caller
   has assured that there are no packets being out from the
   interceptor at the time of call. */
void ssh_detach_substitutions(void)
{
#ifdef PFIL_IFNET
  pfil_remove_hook(icept_if_hook, NULL, PFIL_IFADDR|PFIL_IFNET, &if_pfil);
#endif
#if SSH_NetBSD < 300
  ssh_detach_ifioctl();
#endif /* SSH_NetBSD < 300 */
  pfil_remove_hook(icept_inet4_hook, NULL, PFIL_ALL, &inet_pfil_hook);
#ifdef WITH_IPV6
  pfil_remove_hook(icept_inet6_hook, NULL, PFIL_ALL, &inet6_pfil_hook);
#endif /* WITH_IPV6 */
}

const char *ssh_ident_attach = "NetBSD PFIL";

int ssh_interceptor_iftype(struct ifnet *ifp)
{
  return SSH_INTERCEPTOR_MEDIA_PLAIN;
}

int ssh_interceptor_spl(void)
{
  return splnet();
}


int ip_output(struct mbuf *m0, ...);
void ip_input(struct mbuf *m);

#ifdef WITH_IPV6
void ip6_input(struct mbuf *m);
#endif /* WITH_IPV6 */

void
ssh_interceptor_mbuf_send_to_network(SshInterceptorProtocol protocol,
				     struct ifnet *ifp,
				     void *mediahdr, size_t mediahdr_len,
				     struct mbuf *m)
{
  struct m_tag *mtag;

  SSH_DEBUG(SSH_D_LOWSTART, ("Send to NET, len = 0x%lx",
			     m->m_pkthdr.len));

  SSH_ASSERT(mediahdr_len == 0);

  /* Indicate that we want to see rest of that packets for this
     flow. */
  m->m_flags &= ~(M_CANFASTFWD);

  /* Packets from protocol are fed to adapter and from adapter are fed
     to protocol. On the way we mark the packets as seen. */
  if ((mtag =
       m_tag_get(PACKET_TAG_IPSEC_OUT_DONE, sizeof(int), M_NOWAIT))
      == NULL)
    {
      goto bad;
    }

  m_tag_prepend(m, mtag);

  if (protocol == SSH_PROTOCOL_IP4)
    ip_output(m,
	      (struct mbuf *)NULL,
	      (struct route *)NULL,
	      IP_RAWOUTPUT,
	      (struct ip_moptions *)NULL,
	      (struct socket *)NULL);
#ifdef WITH_IPV6
  else if (protocol == SSH_PROTOCOL_IP6)
    ip6_output(m,
	       (struct ip6_pktopts *)NULL,
	       (struct route_in6 *)NULL,
	       IPV6_FORWARDING,
	       (struct ip6_moptions *)NULL,
	       (struct socket *)NULL,
	       (struct ifnet **)NULL);
#endif /* WITH_IPV6 */
  else
    goto bad;
  return;

 bad:
  m_freem(m);

}

void
ssh_interceptor_mbuf_send_to_protocol(SshInterceptorProtocol protocol,
				      struct ifnet *ifp,
				      void *mediahdr, size_t mediahdr_len,
				      struct mbuf *m)
{
  struct m_tag *mtag;

  SSH_DEBUG(SSH_D_LOWSTART, ("Send to STACK"));

  /* Indicate that we want to see rest of that packets for this
     flow. */
  m->m_flags &= ~(M_CANFASTFWD);

  /* Packets from protocol are fed to adapter and from adapter are fed
     to protocol. On the way we mark the packets as seen. */
  if ((mtag =
       m_tag_get(PACKET_TAG_IPSEC_IN_DONE, sizeof(int), M_NOWAIT))
      == NULL)
    {
      goto bad;
    }

  m_tag_prepend(m, mtag);

  if (protocol == SSH_PROTOCOL_IP4)
    ip_input(m);
#ifdef WITH_IPV6
  else if (protocol == SSH_PROTOCOL_IP6)
    ip6_input(m);
#endif /* WITH_IPV6 */
  else
    goto bad;
  return;

 bad:
  m_freem(m);
}

#if SSH_NetBSD < 300

#include "icept_attach.h"

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
SshAttachRec *ssh_get_substitutions(void)
{
  static SshAttachRec sub[] =
  {
    { SSH_ATTACH_AFTER, ifioctl, ssh_interceptor_after_ifioctl },
    { SSH_ATTACH_END }
  };
  return sub;
}

#endif /* SSH_NetBSD < 300 */
