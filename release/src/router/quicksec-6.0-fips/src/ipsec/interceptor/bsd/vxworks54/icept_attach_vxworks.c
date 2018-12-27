/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Attach to the VxWorks MUX layer, and intercept and dispatch
   packets through the VxWorks MUX layer.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "ipsec_params.h"
#include "kernel_timeouts.h"
#include "interceptor.h"
#include "icept_internal.h"
#include "icept_attach.h"
#include "engine.h"
#include "engine_hwaccel.h"
#include "icept_vxworks.h"
#include "kernel_mutex.h"
#include "sshglobals.h"

#include <types/vxParams.h>
#include <mqueue.h>
#include <net/systm.h>
#include <net/mbuf.h>
#include <errno.h>
#include <net/protosw.h>
#include <sys/socket.h>
#include <net/socketvar.h>

#include <net/if.h>
#include <net/route.h>
#if VXWORKS_NETVER < 55100
#include <net/if_subr.h>
#endif /* VXWORKS_NETVER */

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/if_ether.h>

#include <netBufLib.h>
#include <muxLib.h>
#include <end.h>
#include <endLib.h>
#include <ifLib.h>
#include <netLib.h>
#include "icept_mbuf_vxworks.h"
#include "sshdebug.h"
#if VXWORKS_NETVER >= 55100
#include <private/muxLibP.h>
#endif /*  VXWORKS_NETVER >= 55100 */

#ifdef VLAN_TAG
#include <dlink/vlanTagLib.h>
#include <private/vlanTagLibP.h>
#endif /* VLAN_TAG */

#ifdef SSH_GLOBALS_EMULATION
#include "taskVarLib.h"
#endif /* SSH_GLOBALS_EMULATION */

#if VXWORKS_NETVER < 55100

/* Pre-5.5.1 network stacks */

#define SSH_VX_FIRSTIF (ifnet)
#define SSH_VX_NEXTIF(ifp) ((ifp)->if_next)
#define SSH_VX_MAXIFS 32

#define SSH_VX_IFLLADDR(ifp) (&((struct arpcom *)ifp)->ac_enaddr)

#define SSH_VX_IPINPUT(m) \
  do_protocol_with_type(SSH_ETHERTYPE_IP, m, \
			(struct arpcom *)ifp, m->m_pkthdr.len)
#define SSH_VX_ARPINPUT(m) \
  do_protocol_with_type(SSH_ETHERTYPE_ARP, m, \
			(struct arpcom *)ifp, m->m_pkthdr.len)

#define SSH_VX_RTALLOC1(dst, rep) rtalloc1(dst, rep)
#define SSH_VX_IFRESOLVE(ifp, rt, m, dst, buf) \
  ifp->if_resolve(NULL, m, dst, ifp, rt, buf)

unsigned long tickGet (void);
#define SSH_VX_TICKS tickGet()

#elif VXWORKS_NETVER < 55122

/* Network stacks at least 5.5.1 but earlier than 5.5.1, PNE 2.2 */

#if VXWORKS_NETVER != 55111
#define SSH_VX_FIRSTIF (ifnet)
#define SSH_VX_NEXTIF(ifp) ((ifp)->if_next)
#define SSH_VX_MAXIFS 32
#else /* VXWORKS_NETVER */
#define SSH_VX_FIRSTIF (TAILQ_FIRST(&ifnet))
#define SSH_VX_NEXTIF(ifp) (TAILQ_NEXT((ifp), if_link))
#define SSH_VX_MAXIFS 32
#endif /* VXWORKS_NETVER */

#define SSH_VX_IFLLADDR(ifp) (&((struct arpcom *)ifp)->ac_enaddr)

#define SSH_VX_IPINPUT(m) ipintr(m)
#define SSH_VX_ARPINPUT(m)  arpintr(m)

#if VXWORKS_NETVER < 55100
#define SSH_VX_RTALLOC1(dst, rep) rtalloc1(dst, rep)
#else /* VXWORKS_NETVER */
#define SSH_VX_RTALLOC1(dst, rep) rtalloc1(dst, rep, 0UL)
#endif /* VXWORKS_NETVER */

#define SSH_VX_IFRESOLVE(ifp, rt, m, dst, buf) \
  ifp->if_resolve(NULL, m, dst, ifp, rt, buf)

unsigned long tickGet (void);
#define SSH_VX_TICKS tickGet()

#else /* VXWORKS_NETVER */

/* Network stack 5.5.1, PNE 2.2 or later */

#define SSH_VX_FIRSTIF (TAILQ_FIRST(&ifnet_head))
#define SSH_VX_NEXTIF(ifp) (TAILQ_NEXT((ifp), if_link))
#ifndef VIRTUAL_STACK
extern int if_indexlim;
#endif /* VIRTUAL_STACK */
#define SSH_VX_MAXIFS (if_indexlim + 2)

#ifdef VIRTUAL_STACK
#undef ifnet_addrs
#define SSH_VX_IFLLADDR(ifp) \
  (LLADDR((struct sockaddr_dl *)((VS_IF *)vsTbl[ifp->vsNum]->pIfGlobals)->\
                                 ifnet_addrs[ifp->if_index - 1]->ifa_addr))
#else /* VIRTUAL_STACK */
#define SSH_VX_IFLLADDR(ifp) \
  (LLADDR((struct sockaddr_dl *)ifnet_addrs[ifp->if_index - 1]->ifa_addr))
#endif /* VIRTUAL_STACK */

void ip_input(struct mbuf *m);
#define SSH_VX_IPINPUT(m) ip_input(m)
void in_arpinput(struct mbuf *m);
#define SSH_VX_ARPINPUT(m) in_arpinput(m)

#define SSH_VX_RTALLOC1(dst, rep) rtalloc1(dst, rep, 0UL)
#define SSH_VX_IFRESOLVE(ifp, rt, m, dst, buf) \
  (ifp->if_resolve(ifp, rt, m, dst, buf, NULL, NULL))

#if defined(WITH_IPV6) && defined(INET6)
void ip6_input(struct mbuf *m);
#define SSH_VX_IP6INPUT(m) ip6_input(m)
#define SSH_VX_IF6RESOLVE(ifp, rt, m, dst, buf) \
  (ifp->if6_resolve(&((struct arpcom *)ifp)->ac_if, rt, m, dst, buf, NULL))
#endif /* WITH_IPV6 && INET6 */

extern unsigned long netGtfSeconds;
#define SSH_VX_TICKS netGtfSeconds

#endif /* VXWORKS_NETVER */

/* IANA-MIB interface types for ethernet-style interfaces (used in
   ifp->if_type) */
#define SSH_IFTYPE_ethernetCsmacd	  6
#define SSH_IFTYPE_fastEther	 	 62
#define SSH_IFTYPE_gigabitEthernet	117
#define SSH_IFTYPE_iso88023Csmacd	  7
#define SSH_IFTYPE_iso88024TokenBus	  8
#define SSH_IFTYPE_iso88025TokenRing	  9
#define SSH_IFTYPE_iso88026Man		 10
#define SSH_IFTYPE_fddi			 15

/* Return nonzero if interface uses ethernet-style addressing and
   ARP/NDP. */
SSH_FASTTEXT
static inline int ssh_vx_is_etherif(struct ifnet *ifp)
{
  if (SSH_PREDICT_TRUE(ifp->if_type == SSH_IFTYPE_gigabitEthernet))
    return 1;

  switch (ifp->if_type)
    {
    case SSH_IFTYPE_ethernetCsmacd:
    case SSH_IFTYPE_fastEther:
    case SSH_IFTYPE_iso88023Csmacd:
    case SSH_IFTYPE_iso88024TokenBus:
    case SSH_IFTYPE_iso88025TokenRing:
    case SSH_IFTYPE_iso88026Man:
    case SSH_IFTYPE_fddi:
      return 1;
    default:
      return 0;
    }
}

#ifdef SSHDIST_IPSEC_HWACCEL
#include "sshpcihw.h"
#endif /* SSHDIST_IPSEC_HWACCEL */

#define SSH_DEBUG_MODULE "IceptAttachVxworks"

#ifdef VIRTUAL_STACK
SshVxEngine ssh_engines;
#else /* VIRTUAL_STACK */
SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */

int ssh_net_id;

#ifdef VIRTUAL_STACK
SshVxInterface ssh_vx_interfaces_per_vs[VSNUM_MAX];
#else /* VIRTUAL_STACK */
SshVxInterface ssh_vx_interfaces;
#endif /* VIRTUAL_STACK */
int ssh_vx_interfaces_num;

#define SSH_ICEPT_IFERR(ifp, msg) \
  SSH_DEBUG(SSH_D_ERROR, ("%s%d: " msg, ifp->if_name, ifp->if_unit))

/* interceptor loaded flag */
static int quicksec_loaded;

/* counters for tracking the number of pending netJob messages */
static unsigned ssh_netjobs_submitted;  /* updated by other than tNetTask */
static unsigned ssh_netjobs_processed; /* updated by tNetTask */
/* max difference of the counters above */
#define SSH_NETJOBS_MAX 20

/* Align packet start to 2-byte boundary. Packets coming from
   interceptor and engine are usually 4-byte aligned. Sometimes they
   are not however. Make sure packets are at least 2 byte aligned,
   otherwise network driver may cause alignment exception on most
   RISC processors */
#if CPU==MIPS32 || CPU_FAMILY==ARM
Boolean ssh_interceptor_packet_align2(struct mbuf *m)
{
  int move_bytes;

  /* Ensure first mbuf has data */
  SSH_ASSERT((m->m_flags & M_EXT) && m->m_len);

  if ((m->m_flags & M_EXT) == 0 || m->m_len == 0)
    return FALSE; /* don't know how to handle, drop the packet */

  move_bytes = M_LEADINGSPACE(m) & 0x01;
  if (move_bytes)
    {
      m->m_data -= move_bytes;
      memmove(m->m_data, m->m_data+move_bytes, m->m_len);
    }

  return TRUE;
}
#endif

/* Align packet start to 2-byte offset from 4-boundary. Packets coming from
   interceptor and engine are usually properly aligned. Make sure they are
   as VxWorks IP-stack assumes so. This is not a problem with CPUs that support
   unaligned access (x86) but causes exception on most RISC processors */
#if CPU==MIPS32 || CPU_FAMILY==ARM
Boolean ssh_interceptor_packet_align_2_offs(struct mbuf *m)
{
  int alignment;

  /* Ensure first mbuf has data */
  SSH_ASSERT((m->m_flags & M_EXT) && m->m_len);

  if ((m->m_flags & M_EXT) == 0 || m->m_len == 0)
    return FALSE; /* don't know how to handle, drop the packet */

  alignment = ((long)m->m_data) & 0x03;
  if (alignment == 2)
    return TRUE;

  {
    /* Try to use leading space */
    const unsigned char lead_sub[4]={2,3,0,1};
    int offset = lead_sub[alignment];
    if (M_LEADINGSPACE(m) >= offset)
      {
        m->m_data -= offset;
        memmove(m->m_data, m->m_data+offset, m->m_len);
        return TRUE;
      }
  }

  {
    /* Try to use trailing space */
    const unsigned char trail_add[4]={2,1,0,3};
    CL_POOL *cl_pool=CL_BUF_TO_CL_POOL(m->m_extBuf);
    int offset = trail_add[alignment];
    if (cl_pool->clSize - M_LEADINGSPACE(m) - m->m_len >= offset)
      {
        m->m_data += offset;
        memmove(m->m_data, m->m_data-offset, m->m_len);
        return TRUE;
      }
  }
   /* There should always be room in the packet since engine does not add
      any bytes to packets destined to local stack. Something unexpected,
      drop the packet */
  return FALSE;
}
#endif

/* PCD 1.1. Packets coming from Windriver stack have back pointer to mbuf
   stored in cluster buffer. We will not maintain it. In addition m_extSize has
   been reduced by sizeof(struct mbuf *). This function will adjust m_extSize
   back to correct value in order to M_TRAILINGSPACE macro to work properly.*/
#if VXWORKS_NETVER == 55111
void ssh_vx_set_ext_size(struct mbuf *m)
{
  while (m)
    {
      if (M_HASCL(m))
          m->m_extSize = CL_BUF_TO_CL_POOL(m->m_extBuf)->clSize;
      m = m->m_next;
    }
}
#endif

/* Make len bytes of packet contiguous. Return NULL and free buffer if
   the packet is too short or allocation fails. */
SSH_FASTTEXT
static struct mbuf *ssh_interceptor_mbuf_flatten(struct mbuf *m, int len)
{
  if (SSH_PREDICT_FALSE(m->m_pkthdr.len < len))
    {
      m_freem(m);
      return NULL;
    }

  if (SSH_PREDICT_FALSE(m->m_len < len) &&
      SSH_PREDICT_FALSE(!(m = m_pullup(m, len))))
    return NULL;

  return m;
}

/* Send an intercepted and processed packet to a network interface. */
SSH_FASTTEXT
void ssh_interceptor_mbuf_send_to_network(SshInterceptorProtocol protocol,
					  struct ifnet *ifp,
					  void *mediahdr,
                                          size_t mediahdr_len,
					  struct mbuf *m)
{
  SshVxInterface vxif;
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(WITH_IPV6) && defined(INET6)
    struct sockaddr_in6 sin6;
#endif /* defined(WITH_IPV6) && defined(INET6) */
  } dst;
  SshUInt8 *p;

  vxif = SSH_VX_INTERFACE(ifp->vsNum, ifp->if_index);
  if (SSH_PREDICT_FALSE(vxif->ifp != ifp))
    {
      SSH_ICEPT_IFERR(ifp, "interface attachment not ok, dropping packet");
      m_freem(m);
      return;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("%s:%d, len=%d, flags=%x",
                              ifp->if_name,
                              ifp->if_unit,
                              m->m_pkthdr.len,
                              m->m_flags));

  /* Send the packet using the original ifp->if_output(). If the
     packet is an IP packet (in the case of a non-ethernet interface),
     get the destination IP address from the packet. If the packet is
     an ethernet packet (IP or ARP packet to an ethernet-style
     interface), take the ethernet header from the packet and use it
     as an AF_UNSPEC destination address (this will bypass address
     resolution in the original ifp->if_output() routine). */

  if (SSH_PREDICT_FALSE(protocol == SSH_PROTOCOL_IP4))
    {
      if (!(m = ssh_interceptor_mbuf_flatten(m, SSH_IPH4_HDRLEN)))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot pullup IPv4 header");
	  return;
	}
      p = mtod(m, SshUInt8 *);
      dst.sin.sin_len = sizeof dst.sin;
      dst.sin.sin_family = AF_INET;
      dst.sin.sin_port = 0;
      memcpy(&dst.sin.sin_addr, p + SSH_IPH4_OFS_DST, SSH_IPH4_ADDRLEN);
      memset(&dst.sin.sin_zero, 0, sizeof dst.sin.sin_zero);
      vxif->old_if_output(ifp, m, &dst.sa, NULL);
      return;
    }
#if defined(WITH_IPV6) && defined(INET6)
  else if (SSH_PREDICT_FALSE(protocol == SSH_PROTOCOL_IP6))
    {
      if (!(m = ssh_interceptor_mbuf_flatten(m, SSH_IPH6_HDRLEN)))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot pullup IPv6 header");
	  return;
	}
      p = mtod(m, SshUInt8 *);
      dst.sin6.sin6_len = sizeof dst.sin6;
      dst.sin6.sin6_family = AF_INET6;
      dst.sin6.sin6_port = 0;
      dst.sin6.sin6_flowinfo = 0;
      memcpy(&dst.sin6.sin6_addr, p + SSH_IPH6_OFS_DST, SSH_IPH6_ADDRLEN);
      dst.sin6.sin6_scope_id = 0;
      vxif->old_if_output(ifp, m, &dst.sa, NULL);
      return;
    }
#endif /* WITH_IPV6 && INET6 */
  else if (SSH_PREDICT_TRUE(protocol == SSH_PROTOCOL_ETHERNET))
    {
#ifdef VLAN_TAG
      if (SSH_PREDICT_TRUE(!ifp->pTagData))
	{
#endif /* VLAN_TAG */
	  /* Send ethernet frames directly to driver. */
	  if (SSH_PREDICT_FALSE(muxSend(vxif->mux_cookie, m) != OK))
	    m_freem(m);
	  return;
#ifdef VLAN_TAG
	}
      if (!(m = ssh_interceptor_mbuf_flatten(m, SSH_ETHERH_HDRLEN)))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot pullup ethernet header");
	  m_freem(m);
	  return;
	}
      p = mtod(m, SshUInt8 *);
      dst.sa.sa_len = sizeof dst.sa;
      dst.sa.sa_family = AF_UNSPEC;
      memcpy(dst.sa.sa_data, p, SSH_ETHERH_HDRLEN);
#if VXWORKS_NETVER < 55122
      /* Earlier stacks want ethertype in the wrong byte order */
      ((struct ether_header *)dst.sa.sa_data)->ether_type = \
	ntohs(((struct ether_header *)dst.sa.sa_data)->ether_type);
#endif /* VXWORKS_NETVER < 55122 */
      m_adj(m, SSH_ETHERH_HDRLEN);
      vxif->old_if_output(ifp, m, &dst.sa, NULL);
      return;
#endif /* VLAN_TAG */
    }
  else
    {
      SSH_ICEPT_IFERR(ifp, "dropping non-IP packet");
      m_freem(m);
      return;
    }
}

/* Send an intercepted and processed packet to the protocol stack. */
void ssh_interceptor_mbuf_send_to_protocol(SshInterceptorProtocol protocol,
					   struct ifnet *ifp,
					   void *mediahdr,
                                           size_t mediahdr_len,
					   struct mbuf *m)
{
  struct ether_header *eh;
  int type;
  int s;

  SSH_DEBUG(SSH_D_LOWSTART, ("%s:%d, len=%d, flags=%x",
                              ifp->if_name,
                              ifp->if_unit,
                              m->m_pkthdr.len,
                              m->m_flags));

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("sending to protocol"),
                    m->m_data,
                    m->m_len);

  switch (protocol)
    {
    case SSH_PROTOCOL_IP4:
      type = SSH_ETHERTYPE_IP;
      break;
#if defined(WITH_IPV6) && defined(INET6)
    case SSH_PROTOCOL_IP6:
      type = SSH_ETHERTYPE_IPv6;
      break;
#endif /* WITH_IPV6 && INET6 */
    case SSH_PROTOCOL_ETHERNET:
      /* Remove ethernet header. */
      if (!(m = ssh_interceptor_mbuf_flatten(m, SSH_ETHERH_HDRLEN)))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot pullup ethernet header");
	  return;
	}
      eh = mtod(m, struct ether_header *);
      type = ntohs(eh->ether_type);
      m_adj(m, SSH_ETHERH_HDRLEN);
      break;
    default:
      SSH_ICEPT_IFERR(ifp, "dropping non-IP packet");
      m_freem(m);
      return;
    }

#if CPU == MIPS32 || CPU_FAMILY == ARM
  /* Make sure packet is aligned as IP stack assumes so */
  if (protocol != SSH_PROTOCOL_ETHERNET &&
      !ssh_interceptor_packet_align_2_offs(m))
    {
      SSH_ICEPT_IFERR(ifp, "cannot align buffer");
      m_freem(m);
      return;
    }
#endif

  s = splnet();

#ifdef VIRTUAL_STACK
  /* Switch virtual stack so that IP runs in context
     of correct virtual stack. */
  myStackNum = ifp->vsNum;
#endif /* VIRTUAL_STACK */

  switch (type)
    {
    case SSH_ETHERTYPE_IP:
      SSH_VX_IPINPUT(m);
      break;
#if defined(WITH_IPV6) && defined(INET6)
    case SSH_ETHERTYPE_IPv6:
      SSH_VX_IP6INPUT(m);
      break;
#endif /* WITH_IPV6 && INET6 */
    case SSH_ETHERTYPE_ARP:
      SSH_VX_ARPINPUT(m);
      break;
    default:
      SSH_ICEPT_IFERR(ifp, "dropping non-IP packet");
      m_freem(m);
      break;
    }

  splx(s);
}

SSH_FASTTEXT
void ssh_interceptor_receive_wrap(int protocol,
                                  unsigned int flags,
                                  struct ifnet *ifp,
                                  int mediahdr_len,
                                  struct mbuf *m)
{
  ssh_netjobs_processed++;

  if (SSH_PREDICT_FALSE(mediahdr_len))
    {
      void *mediahdr = mtod(m, void *);
      m_adj(m, mediahdr_len);
      ssh_interceptor_receive(protocol, flags, ifp, mediahdr, mediahdr_len, m);
    }
  else
    {
      ssh_interceptor_receive(protocol, flags, ifp, NULL, 0, m);
    }
}

/* Execute any SNARF handlers bound after the one corresponding to pCookie. */
#if VXWORKS_NETVER < 55100
static BOOL ssh_icept_complete_snarf(void *pCookie,
				     long type,
				     M_BLK_ID m,
				     LL_HDR_INFO *pLinkHdrInfo)
{
  return FALSE;
}
#elif VXWORKS_NETVER < 55111
static BOOL ssh_icept_complete_snarf(void *pCookie,
				     long type,
				     M_BLK_ID m,
				     LL_HDR_INFO *pLinkHdrInfo)
{
  MUX_BIND_ENTRY *binding = (MUX_BIND_ENTRY *)pCookie;
  END_OBJ *end = binding->pEnd;
  NET_PROTOCOL *proto;
  int i;

  /* Scan to the protocol entry matching pCookie. */
  proto = (NET_PROTOCOL *)end->protocols.node.next;
  for (i = end->snarfCount; i; i--)
    {
      if (proto->pNptCookie == binding)
	break;
      proto = (NET_PROTOCOL *)proto->node.next;
    }

  /* Verify that we indeed found it. */
  if (i == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("interface attachment not ok, dropping packet"));
      m_freem(m);
      return TRUE;
    }

  /* Run any remaining SNARF handlers and bail out if packet is consumed. */
  proto = (NET_PROTOCOL *)proto->node.next;
  for (i--; i; i--)
    {
      if (proto->stackRcvRtn(proto->pNptCookie, type, m,
			     pLinkHdrInfo, proto->pSpare))
        return TRUE;
      proto = (NET_PROTOCOL *)proto->node.next;
    }

  return FALSE;
}
#elif VXWORKS_NETVER < 55122 && VXWORKS_NETVER != 55111
static BOOL ssh_icept_complete_snarf(void *pCookie,
				     long type,
				     M_BLK_ID m,
				     LL_HDR_INFO *pLinkHdrInfo)
{
  PROTOCOL_BINDING *binding = (PROTOCOL_BINDING *)pCookie;
  END_OBJ *end = binding->pEnd;
  PROTO_INFO *pinfo = end->protocols;
  PROTO_ENTRY *proto;

  /* Scan to the protocol entry matching pCookie. */
  for (proto = pinfo->pSnarf; proto != pinfo->pTyped; proto++)
    if (SSH_PREDICT_TRUE(proto->pBinding == binding))
      break;

  /* Verify that we indeed found it. */
  if (SSH_PREDICT_FALSE(proto == pinfo->pTyped))
    {
      SSH_DEBUG(SSH_D_ERROR, ("interface attachment not ok, dropping packet"));
      m_freem(m);
      return TRUE;
    }

  /* Run any remaining SNARF handlers and bail out if packet is consumed. */
  proto++;
  while (1)
    {
      /* Optimize for the case we are the only SNARF handler. */
      if (SSH_PREDICT_TRUE(proto == pinfo->pTyped))
	break;

      if (proto->rr.endRcv(proto->pBinding, type, m,
			   pLinkHdrInfo, proto->recvRtnArg))
        return TRUE;

      proto++;
    }

  return FALSE;
}
#else /* VXWORKS_NETVER */
SSH_FASTTEXT
static BOOL ssh_icept_complete_snarf(void *pCookie,
				     long type,
				     M_BLK_ID m,
				     LL_HDR_INFO *pLinkHdrInfo)
{
  PROTOCOL_BINDING *binding = (PROTOCOL_BINDING *)pCookie;
  END_OBJ *end = binding->pEnd;
  PROTO_ENTRY *proto;

  /* Scan to the protocol entry matching pCookie. */
  for (proto = end->pSnarf; proto != end->pTyped; proto++)
    if (SSH_PREDICT_TRUE(proto->pBinding == binding))
      break;

  /* Verify that we indeed found it. */
  if (SSH_PREDICT_FALSE(proto == end->pTyped))
    {
      SSH_DEBUG(SSH_D_ERROR, ("interface attachment not ok, dropping packet"));
      m_freem(m);
      return TRUE;
    }

  /* Run any remaining SNARF handlers and bail out if packet is consumed. */
  proto++;
  while (1)
    {
      /* Optimize for the case we are the only SNARF handler. */
      if (SSH_PREDICT_TRUE(proto == end->pTyped))
	break;

      if (proto->rr.endRcv(proto->pBinding, type, m,
			   pLinkHdrInfo, proto->recvRtnArg))
        return TRUE;

      proto++;
    }

  return FALSE;
}
#endif /* VXWORKS_NETVER */

/* Process and remove link header from packet. Return the modified
   buffer, or NULL on failure. */
SSH_FASTTEXT
static M_BLK_ID ssh_icept_process_link_header(M_BLK_ID m,
					      LL_HDR_INFO *pLinkHdrInfo,
					      struct ifnet *ifp,
					      END_OBJ *end)
{
  int offset;
  int mac_offset;

#ifdef VLAN_TAG
    if ((ifp->pTagData != NULL) &&
        (((VLAN_TAG_DATA *)ifp->pTagData)->pVlanTagHdrCheck(m, ifp) == ERROR))
      goto badframe;
#endif /* VLAN_TAG */

    mac_offset = 0;

    if (SSH_PREDICT_TRUE(ifp->if_type == SSH_IFTYPE_gigabitEthernet))
      goto ssh_iftype_gigabitethernet;

    switch (ifp->if_type)
      {
      case SSH_IFTYPE_iso88025TokenRing:
	mac_offset = 1;
	/* fall through */
      case SSH_IFTYPE_iso88024TokenBus:
	mac_offset += 1;
	/* fall through */
      ssh_iftype_gigabitethernet:
      case SSH_IFTYPE_ethernetCsmacd:
      case SSH_IFTYPE_fastEther:
      case SSH_IFTYPE_gigabitEthernet:
      case SSH_IFTYPE_iso88023Csmacd:
      case SSH_IFTYPE_iso88026Man:
      case SSH_IFTYPE_fddi:

	if (SSH_PREDICT_FALSE(m->mBlkHdr.mLen < SSH_ETHERH_ADDRLEN))
	  goto badframe;

	/* Set multicast or broadcast flag and ensure that unicast
	   frames destined to other stations do not get through in
	   promiscuous mode. */
	if (SSH_PREDICT_FALSE(
	      SSH_ETHER_IS_MULTICAST(m->mBlkHdr.mData + mac_offset)))
	  {
	    if (memcmp(etherbroadcastaddr, m->mBlkHdr.mData,
		       sizeof etherbroadcastaddr) == 0)
	      m->mBlkHdr.mFlags |= M_BCAST;
	    else
	      m->mBlkHdr.mFlags |= M_MCAST;
	  }
	else if (SSH_PREDICT_FALSE((ifp->if_flags & IFF_PROMISC)))
	  {
	    char *haddr;
	    size_t haddrlen;
#if VXWORKS_NETVER < 55100
	    haddr = end->mib2Tbl.ifPhysAddress.phyAddress;
	    haddrlen = end->mib2Tbl.ifPhysAddress.addrLength;
#else /* VXWORKS_NETVER < 55100 */
	    if (end->flags & END_MIB_2233)
	      {
		haddr = END_ALT_HADDR(end);
		haddrlen = END_ALT_HADDR_LEN(end);
	      }
	    else
	      {
		haddr = END_HADDR(end);
		haddrlen = END_HADDR_LEN(end);
	      }
#endif /* VXWORKS_NETVER < 55100 */
	    if (memcmp(haddr, m->mBlkHdr.mData, haddrlen))
	      goto end;
	  }
	break;
      default:
	break;
      }

    offset = pLinkHdrInfo->dataOffset;
    m->mBlkPktHdr.len -= offset;

    /* Remove link header and free any empty buffers resulting from
       this. */
    if (SSH_PREDICT_FALSE(m->mBlkHdr.mLen <= offset))
      {
	M_BLK_ID first_to_keep, last_to_free;
	first_to_keep = m;
	do
	  {
	    offset -= first_to_keep->mBlkHdr.mLen;
	    last_to_free = first_to_keep;
	    first_to_keep = first_to_keep->mBlkHdr.mNext;
	    if (first_to_keep == NULL)
	      goto badframe;
	  }
	while (first_to_keep->mBlkHdr.mLen <= offset);

	M_COPY_PKTHDR(first_to_keep, m);
	last_to_free->mBlkHdr.mNext = NULL;
	netMblkClChainFree (m);
	m = first_to_keep;
      }
    m->mBlkHdr.mData += offset;
    m->mBlkHdr.mLen -= offset;

    m->mBlkPktHdr.rcvif = ifp;
    return (m);

badframe:
#if VXWORKS_NETVER < 55100
    end->mib2Tbl.ifInErrors++;
#else /* VXWORKS_NETVER < 55100 */
    if (end->flags & END_MIB_2233)
      end->pMib2Tbl->m2CtrUpdateRtn(end->pMib2Tbl, M2_ctrId_ifInErrors, 1);
    else
      end->mib2Tbl.ifInErrors++;
#endif /* VXWORKS_NETVER < 55100 */

end:
    if (m != NULL)
      netMblkClChainFree (m);

    return NULL;
}

/* MUX receive handler */
SSH_FASTTEXT
static BOOL ssh_icept_from_network(void *pCookie,
				   long type,
				   M_BLK_ID m,
				   LL_HDR_INFO *pLinkHdrInfo,
				   void *pSpare)
{
  struct ether_header eh;
  SshVxInterface vxif = (SshVxInterface)pSpare;
  struct ifnet *ifp;
  int protocol;

  /* Do not intercept non-IP protocols */
  if (SSH_PREDICT_FALSE(type != SSH_ETHERTYPE_IP)
      && type != SSH_ETHERTYPE_ARP
#if defined(WITH_IPV6) && defined(INET6)
      && type != SSH_ETHERTYPE_IPv6
#endif /* WITH_IPV6 && INET6 */
      )
    return FALSE;

  /* Before intercepting, run any SNARF handlers installed after us. */
  if (ssh_icept_complete_snarf(pCookie, type, m, pLinkHdrInfo))
    return TRUE;

  if (SSH_PREDICT_FALSE(!(ifp = vxif->ifp)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("interface attachment not ok, dropping packet"));
      m_freem(m);
      return TRUE;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("%s:%d, len=%d, flags=%x",
                              ifp->if_name,
                              ifp->if_unit,
                              m->m_pkthdr.len,
                              m->m_flags));

#ifdef DEBUG_LIGHT
  vxif->icept_from_network++;
#endif /* DEBUG_LIGHT */

  if (SSH_PREDICT_FALSE((ifp->if_flags & IFF_UP) == 0)) {
    m_freem(m);
    return TRUE;
  }

  /* Packets from ethernet-style interfaces need to be have an
     ethernet header when they are intercepted. Save information for
     that before processing link header. */
  if (SSH_PREDICT_TRUE(ssh_vx_is_etherif(ifp)))
    {
      SshUInt8 *p;
      SSH_ASSERT(pLinkHdrInfo->destSize == SSH_ETHERH_ADDRLEN);
      SSH_ASSERT(pLinkHdrInfo->srcSize == SSH_ETHERH_ADDRLEN);
      /* Link header has already been processed once to get
	 pLinkHdrInfo so it should be contiguous. */
      if (SSH_PREDICT_FALSE(m->m_len < pLinkHdrInfo->dataOffset))
	{
	  SSH_ICEPT_IFERR(ifp, "dropping packet with non-contig link header");
	  m_freem(m);
	  return TRUE;
	}
      p = mtod(m, SshUInt8 *);
      memcpy(eh.ether_dhost,p+pLinkHdrInfo->destAddrOffset,SSH_ETHERH_ADDRLEN);
      memcpy(eh.ether_shost, p+pLinkHdrInfo->srcAddrOffset,SSH_ETHERH_ADDRLEN);
      eh.ether_type = htons(type);
    }

  /* Consume link header information (including 802.1Q tag) and update
     IP counters. */
  if (SSH_PREDICT_FALSE(
	!(m = ssh_icept_process_link_header(m, pLinkHdrInfo, ifp, vxif->end))))
    return TRUE;

  /* Set the interception protocol. For etherne-style interfaces, add
     a contiguous ethernet header and set protocol to ethernet. */
  if (SSH_PREDICT_TRUE(ssh_vx_is_etherif(ifp)))
    {
      M_PREPEND(m, SSH_ETHERH_HDRLEN, M_DONTWAIT);
      if (SSH_PREDICT_FALSE(!m) ||
	  SSH_PREDICT_FALSE(
	    !(m = ssh_interceptor_mbuf_flatten(m, SSH_ETHERH_HDRLEN))))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot prepend ethernet header");
	  return TRUE;
	}
      memcpy(mtod(m, void *), &eh, sizeof eh);
      protocol =  SSH_PROTOCOL_ETHERNET;
    }
  else if (type == SSH_ETHERTYPE_IP)
    {
      protocol = SSH_PROTOCOL_IP4;
    }
#if defined(WITH_IPV6) && defined(INET6)
  else if (type == SSH_ETHERTYPE_IPv6)
    {
      protocol = SSH_PROTOCOL_IP6;
    }
#endif /* WITH_IPV6 && INET6 */
  else
    {
      SSH_ICEPT_IFERR(ifp, "dropping ARP packet on non-ARP interface");
      m_freem(m);
      return TRUE;
    }

  /* Avoid executing engine code from other tasks than tNetTask */
  if (SSH_PREDICT_FALSE(ssh_net_id != taskIdSelf()))
    {
      /* discard packet if too many messages pending */
      if (ssh_netjobs_submitted - ssh_netjobs_processed >= SSH_NETJOBS_MAX)
        {
          m_freem(m);
          return(TRUE);
        }
      if (netJobAdd((FUNCPTR)ssh_interceptor_receive_wrap,
                    protocol, 0, (int)ifp, 0, (int)m) != OK)
        {
          /* netJobAdd failed - packet can be safely dropped */
          m_freem(m);
          return(TRUE);
        }
      ssh_netjobs_submitted++;
      return(TRUE);
    }

  ssh_interceptor_receive(protocol, 0, ifp, NULL, 0, m);
  return(TRUE);
}

/* Convert a given route into a route to a directly connected next
   hop. Functionality originally from BSD ether_output(). */
static struct rtentry *ssh_icept_nexthop_route(struct sockaddr *dst,
					       struct rtentry *rt0)
{
  struct rtentry *rt;

  rt = rt0;
  if (!(rt->rt_flags & RTF_UP))
    {
      rt0 = rt = SSH_VX_RTALLOC1(dst, 1);
      if (rt0)
	{
	  RTFREE(rt0);
	}
      else
	{
	  return NULL;
	}
    }
  if (rt->rt_flags & RTF_GATEWAY)
    {
      if (!rt->rt_gwroute)
	goto lookup;
      rt = rt->rt_gwroute;
      if (!(rt->rt_flags & RTF_UP))
	{
	  RTFREE(rt);
	  rt = rt0;
	lookup:
	  rt->rt_gwroute = SSH_VX_RTALLOC1(rt->rt_gateway, 1);
	  rt = rt->rt_gwroute;
	  if (!(rt = rt->rt_gwroute))
	    return NULL;
	}
    }
  if (rt->rt_flags & RTF_REJECT)
    {
      if (rt->rt_rmx.rmx_expire == 0 || SSH_VX_TICKS < rt->rt_rmx.rmx_expire)
	return NULL;
    }
  return rt;
}

/* Replacement for ifp->if_output(). For IPv4/IPv6 packets, dst
   contains the destination IP address. For ARP packets, dst is of
   type AF_UNSPEC and contains an ethernet header. */
static int ssh_icept_from_protocol(struct ifnet *ifp,
				   struct mbuf *m,
				   struct sockaddr *dst,
				   struct rtentry *rt)
{
  SshVxInterface vxif;
  struct ether_header eh;
  unsigned int flags = 0;
  int protocol;

  vxif = SSH_VX_INTERFACE(ifp->vsNum, ifp->if_index);
  if (vxif->ifp != ifp)
    {
      SSH_ICEPT_IFERR(ifp, "interface attachment not ok, dropping packet");
      m_freem(m);
      return EHOSTUNREACH;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("%s:%d, len=%d, flags=%x",
                              ifp->if_name,
                              ifp->if_unit,
                              m->m_pkthdr.len,
                              m->m_flags));

  /* Intercept IP protocols (IPv4, ARP and IPv6) and pass others to
     the original ifp->if_output(). Note: ARP packets come with
     AF_UNSPEC and have the ethernet header in dst->sa_data. */
  switch (dst->sa_family)
    {
    case AF_INET:
      /* If possible, resolve ethernet addresses and make the packet
	 an ethernet one. */
      if (ssh_vx_is_etherif(ifp) && ifp->if_resolve)
	{
	  if (rt && !(rt = ssh_icept_nexthop_route(dst, rt)))
	    {
	      m_freem(m);
	      return EHOSTUNREACH;
	    }
	  if (!SSH_VX_IFRESOLVE(ifp, rt, m, dst, &eh.ether_dhost))
	    {
	      /* Packet was taken by resolve and will be resent later */
	      return 0;
	    }
	  memcpy(eh.ether_shost, SSH_VX_IFLLADDR(ifp), SSH_ETHERH_ADDRLEN);
	  eh.ether_type = htons(SSH_ETHERTYPE_IP);
	  protocol = SSH_PROTOCOL_ETHERNET;
	}
      else
	{
	  /* Omit ethernet header */
	  protocol = SSH_PROTOCOL_IP4;
	}
      break;
#if defined(WITH_IPV6) && defined(INET6)
    case AF_INET6:
      /* If possible, resolve ethernet addresses and make the packet
	 an ethernet one. */
      if (ssh_vx_is_etherif(ifp) && ifp->if6_resolve)
	{
	  if (rt && !(rt = ssh_icept_nexthop_route(dst, rt)))
	    {
	      m_freem(m);
	      return EHOSTUNREACH;
	    }
	  if (!SSH_VX_IF6RESOLVE(ifp, rt, m, dst, &eh.ether_dhost))
	    {
	      /* Packet was taken by resolve and will be resent later */
	      return 0;
	    }
	  memcpy(eh.ether_shost, SSH_VX_IFLLADDR(ifp), SSH_ETHERH_ADDRLEN);
	  eh.ether_type = htons(SSH_ETHERTYPE_IPv6);
	  protocol = SSH_PROTOCOL_ETHERNET;
	}
      else
	{
	  /* Omit ethernet header */
	  protocol = SSH_PROTOCOL_IP6;
	}
      break;
#endif /* WITH_IPV6 && INET6 */
    case AF_UNSPEC:
      /* Ethernet header is in dst->sa_data. Intercept ARP, pass
         others through to the original ifp->if_output().
         The header has ethernet destination address and ethernet type
         filled in, but source mac field needs to be filled ourself. */
      memcpy(&eh, dst->sa_data, sizeof eh);
      memcpy(eh.ether_shost, SSH_VX_IFLLADDR(ifp), SSH_ETHERH_ADDRLEN);
#if VXWORKS_NETVER < 55122
      /* Earlier stacks give ethertype in the wrong byte order */
      if (eh.ether_type == SSH_ETHERTYPE_ARP)
	{
	  eh.ether_type = htons(eh.ether_type);
	  protocol = SSH_PROTOCOL_ETHERNET;
	}
      else
	{
	  return vxif->old_if_output(ifp, m, dst, rt);
	}
#else /* VXWORKS_NETVER < 55122 */
      if (ntohs(eh.ether_type) == SSH_ETHERTYPE_ARP)
	  protocol = SSH_PROTOCOL_ETHERNET;
      else
	  return vxif->old_if_output(ifp, m, dst, rt);
#endif /* VXWORKS_NETVER < 55122 */
      break;
    default:
      /* Not AF_INET, AF_INET6 or AF_UNSPEC, pass to the original
	 ifp->if_output() */
      return vxif->old_if_output(ifp, m, dst, rt);
    }

#ifdef DEBUG_LIGHT
  vxif->icept_from_protocol++;
#endif /* DEBUG_LIGHT */

  /* Equip the packet with a contiguous ethernet header if needed */
  if (protocol == SSH_PROTOCOL_ETHERNET)
    {
      M_PREPEND(m, SSH_ETHERH_HDRLEN, M_DONTWAIT);
      if (!m || !(m = ssh_interceptor_mbuf_flatten(m, SSH_ETHERH_HDRLEN)))
	{
	  SSH_ICEPT_IFERR(ifp, "cannot prepend header to ARP packet");
	  return ENOBUFS;
	}
      memcpy(mtod(m, void *), &eh, sizeof eh);
    }

  flags |= SSH_ICEPT_F_FROM_PROTOCOL;

  /* Avoid executing engine code from other tasks than tNetTask */
  if (ssh_net_id != taskIdSelf())
    {
      /* discard packet if too many messages pending */
      if (ssh_netjobs_submitted - ssh_netjobs_processed >= SSH_NETJOBS_MAX)
        {
          m_freem(m);
          return EHOSTUNREACH;
        }
      if (netJobAdd((FUNCPTR)ssh_interceptor_receive_wrap,
                    protocol, flags, (int)ifp, 0, (int)m) != OK)
        {
          /* netJobAdd failed - packet can be safely dropped */
          m_freem(m);
          return EHOSTUNREACH;
        }
      ssh_netjobs_submitted++;
      return 0;
    }

  ssh_interceptor_receive(protocol, flags, ifp, NULL, 0, m);
  return 0;
}

/* Ethernet-style links will be intercepted using an ethernet header,
   others without any media header. */
int ssh_interceptor_iftype(struct ifnet *ifp)
{
  if (ssh_vx_is_etherif(ifp))
    return SSH_INTERCEPTOR_MEDIA_ETHERNET;
  else
    return SSH_INTERCEPTOR_MEDIA_PLAIN;
}

/* Unhook an interface from the interceptor. */
void ssh_icept_detach_interface_vxworks(SshVxInterface vxif)
{
  int s;

  s = splnet();

  /* Unbind SNARF handlers */
  if (vxif->mux_cookie)
    {
      if (muxUnbind(vxif->mux_cookie, MUX_PROTO_SNARF,
		    ssh_icept_from_network) == ERROR)
	SSH_DEBUG(SSH_D_ERROR, ("cannot unbind SNARF protocol"));
    }

  /* Restore interface output routine. */
  if (vxif->ifp)
    vxif->ifp->if_output = vxif->old_if_output;

  memset(vxif, 0, sizeof *vxif);
  splx(s);
  return;
}

/* MUX shutdown handler */
static STATUS ssh_icept_stack_shutdown_rtn(void *pCookie, void * pSpare)
{
  SshVxInterface vxif = (SshVxInterface)pSpare;

  ssh_icept_detach_interface_vxworks(vxif);
  return(OK);
}

/* MUX error handler */
static void ssh_icept_stack_error_rtn(
  END_OBJ *pEnd, END_ERR *pError, void *pSpare)
{
  if (pError->errCode == END_ERR_FLAGS)
    ssh_interceptor_notify_interface_change();
}

/* Hook an END-type interface to the interceptor by replacing
   ifp->if_output() and binding a SNARF handler. */
Boolean ssh_icept_attach_interface_vxworks(struct ifnet *ifp)
{
  END_OBJ *end;
  SshVxInterface vxif;
  int s;

  s = splnet();

  if (!(end = endFindByName (ifp->if_name, ifp->if_unit)))
    {
      /* Not and END interface (loopback or NPT-type driver) */
      goto fail;
    }

  SSH_ASSERT(ifp->if_index < ssh_vx_interfaces_num);
  vxif = SSH_VX_INTERFACE(ifp->vsNum, ifp->if_index);
  if (vxif->ifp)
    {
      SSH_ICEPT_IFERR(ifp, "already attached");
      goto fail;
    }
  memset(vxif, 0, sizeof *vxif);
  vxif->ifp = ifp;
  vxif->end = end;

  /* Replace interface output routine */
  vxif->old_if_output = ifp->if_output;
#ifdef VIRTUAL_STACK
  vxif->vsNum = ifp->vsNum;
#endif /* VIRTUAL_STACK */
  ifp->if_output = ssh_icept_from_protocol;

  /* Try to bind the snarf protocol for capturing incoming packets */
  if (!(vxif->mux_cookie = muxBind(ifp->if_name, ifp->if_unit,
				   ssh_icept_from_network,
				   ssh_icept_stack_shutdown_rtn,
				   NULL,
				   ssh_icept_stack_error_rtn,
				   MUX_PROTO_SNARF,
				   "SSH",
				   vxif)))
    {
      SSH_ICEPT_IFERR(ifp, "cannot bind SNARF protocol");
      ifp->if_output = vxif->old_if_output;
      memset(vxif, 0, sizeof *vxif);
      goto fail;
    }

  splx(s);
  return TRUE;

 fail:
  splx(s);
  return FALSE;
}

/* Try attaching to additional interfaces (in tNetTask context). */
void ssh_vxworks_attach_interfaces_job(void)
{
  struct ifnet *ifp;
  SshVxInterface vxif;
  int s, nifs, i;
#ifdef VIRTUAL_STACK
  int ll;
#undef myStackNum
#define myStackNum ll
#endif /* VIRTUAL_STACK */

  /* Quit if the SshVxInterface table has been unloaded. */
  if (ssh_vx_interfaces_num == 0)
    return;

  nifs = 0;
  s = splnet();

#ifdef VIRTUAL_STACK

  for(ll = 0; ll < VSNUM_MAX; ll++)
    {
      if (!vsTbl[myStackNum]) continue;
#endif /* VIRTUAL_STACK */

#ifdef VIRTUAL_STACK
      SSH_DEBUG(SSH_D_NICETOKNOW, ("attaching interfaces: stack=%d, t=%p",
				   myStackNum, taskIdSelf()));
#else /* VIRTUAL_STACK */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("attaching interfaces: t=%p",
				   taskIdSelf()));
#endif /* VIRTUAL_STACK */

  /* Count interfaces */
  for (ifp = SSH_VX_FIRSTIF; ifp; ifp = SSH_VX_NEXTIF(ifp))
    {
      if (ifp->if_index >= nifs)
	nifs = ifp->if_index + 1;
    }

#ifdef VIRTUAL_STACK
    }
  for(ll = 0; ll < VSNUM_MAX; ll++)
    {
      if (!vsTbl[myStackNum]) continue;
#endif /* VIRTUAL_STACK */


  /* Clear possible stale entries and make sure any MUX handlers are
     unbound. */
  for (i = nifs; i < ssh_vx_interfaces_num; i++)
    {
	  vxif = SSH_VX_INTERFACE(ll, i);
      if (vxif->ifp)
	{
	  vxif->ifp = NULL;
	  ssh_icept_detach_interface_vxworks(vxif);
	}
    }

#ifdef VIRTUAL_STACK
    }
  for(ll = 0; ll < VSNUM_MAX; ll++)
    {
      if (!vsTbl[myStackNum]) continue;
#endif /* VIRTUAL_STACK */


  /* Try to attach interfaces that are not already attached. This will
     fail e.g. for loopback interfaces but that does not matter. Also
     look for reused if_indexes and reattach them. */
  for (ifp = SSH_VX_FIRSTIF; ifp; ifp = SSH_VX_NEXTIF(ifp))
    {
	  vxif = SSH_VX_INTERFACE(ll, ifp->if_index);
      if (!vxif->ifp)
	{
	  SSH_DEBUG(SSH_D_HIGHSTART, ("attaching %s%d, idx=%d",
				      ifp->if_name, ifp->if_unit,
				      ifp->if_index));
	  ssh_icept_attach_interface_vxworks(ifp);
	}
      else if (vxif->ifp != ifp)
	{
	  /* Clear stale interface pointer and call detach routine to
	     unbind mux handlers. */
	  SSH_DEBUG(SSH_D_HIGHSTART, ("attaching %s%d (if_index %d reused)",
				      ifp->if_name, ifp->if_unit,
				      ifp->if_index));
	  vxif->ifp = NULL;
	  ssh_icept_detach_interface_vxworks(vxif);
	  ssh_icept_attach_interface_vxworks(ifp);
	}
    }

#ifdef VIRTUAL_STACK
    }
#undef myStackNum
#endif /* VIRTUAL_STACK */

  splx(s);

  return;
}

/* Try attaching to additional interfaces. */
void ssh_vxworks_attach_interfaces(void)
{
  if (netJobAdd((FUNCPTR)ssh_vxworks_attach_interfaces_job, 0, 0, 0, 0, 0))
    SSH_DEBUG(SSH_D_ERROR, ("cannot schedule interface update"));
}

/* Detach all interfaces. */
void ssh_vxworks_detach_interfaces(void)
{
  int i;
#ifdef VIRTUAL_STACK
  int ll;
#endif /* VIRTUAL_STACK */


  SSH_DEBUG(SSH_D_NICETOKNOW, ("detaching interfaces"));

#ifdef VIRTUAL_STACK
  for(ll = 0; ll < VSNUM_MAX; ll++)
#endif /* VIRTUAL_STACK */
  for (i = 0; i < ssh_vx_interfaces_num; i++)
      ssh_icept_detach_interface_vxworks(SSH_VX_INTERFACE(ll, i));
  return;
}

/* Global initialization for all vxworks engines. */
void ssh_main_vxworks_first(void)
{
  /* Store the tNetTask id, for possible thread synchronization */
  ssh_net_id = taskIdSelf();

  /* Initialize sshglobals. */
#ifdef SSH_GLOBALS_EMULATION
  {
    extern void *ssh_globals;
    taskVarAdd(taskIdSelf(), (int *)(void *)&ssh_globals);
    ssh_global_init();
  }
#endif /* SSH_GLOBALS_EMULATION */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  ssh_vxworks_virtual_adapter_init();
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Allocate private interface data. */
#ifdef VIRTUAL_STACK
  {
    int i;
    for(i=0; i<VSNUM_MAX; i++)
      {
	ssh_vx_interfaces_per_vs[i] =
	  ssh_xcalloc(SSH_VX_MAXIFS,
		      sizeof ssh_vx_interfaces_per_vs[0][0]);
      }
  }

  ssh_vx_interfaces_num = SSH_VX_MAXIFS;
#else /* VIRTUAL_STACK */
  ssh_vx_interfaces = ssh_xcalloc(SSH_VX_MAXIFS, sizeof ssh_vx_interfaces[0]);
  ssh_vx_interfaces_num = SSH_VX_MAXIFS;
#endif /* VIRTUAL_STACK */

  /* Init timer */
  ssh_vx_kernel_timeout_init();
}

/* The main program for single VxWorks IPSec engine, this code is executed
   on the tNetTask level as is all other engine code. When called
   by quicksec() ssh_main_vxworks() attaches the interfaces to
   the SSH IPSec interceptor and starts the SSH IPSec engine */
void ssh_main_vxworks(int i1, int i2, int i3, int i4, int i5)
{
#ifdef VIRTUAL_STACK
  SshVxEngine vxe;
  SshEngine ssh_engine;
#endif /* VIRTUAL_STACK */

  /* Conditionally execute global initialization */
#ifdef VIRTUAL_STACK
  if (ssh_engines == NULL)
    ssh_main_vxworks_first();
#else /* VIRTUAL_STACK */
  ssh_main_vxworks_first();
#endif /* VIRTUAL_STACK */

  /* Start the engine */
  SSH_ASSERT(SSH_ENGINE_BY_MACHINE_CONTEXT((void*)i1) == NULL);
#ifdef VIRTUAL_STACK
  vxe = ssh_malloc(sizeof(*vxe));
  if (!vxe)
    {
      semGive((void*)i2);
      return;
    }
#endif /* VIRTUAL_STACK */
  ssh_engine = ssh_engine_start(ssh_send_to_ipm, (void*)i1,
				SSH_IPSEC_ENGINE_FLAGS);
#ifdef VIRTUAL_STACK
  if (!ssh_engine)
    {
      ssh_free(vxe);
      /* Notice. Some mallocs are not freed yet on this error situation... */
      semGive((void*)i2);
      return;
    }
  vxe->machine_context = (void*)i1;
  vxe->engine = ssh_engine;
  vxe->next = ssh_engines;
  ssh_engines = vxe;
#endif /* VIRTUAL_STACK */

  /* Initialize the character device for communication between
     the SSH IPSec engine and the policymanager */
  ssh_vx_dev_init((void*)i1);

#ifdef SSHDIST_IPSEC_HWACCEL
  ssh_hwaccel_init();
#endif /* SSHDIST_IPSEC_HWACCEL */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("done starting the interceptor"));

  /* Release the wait semaphore */
  semGive((void*)i2);
}

/* quicksec() - the main startup function for SSH IPSec engine.
   This function is usually called from the VxWorks shell or
   from the usrConfig.c file /Tornado/target/config/all/usrConfig.c
   during VxWorks OS bootup, this function initiates the SSH IPSec
   for VxWorks and wraps the execution to the VxWorks tNetTask */
int quicksec(void *machine_context)
{
  /* This semaphore blocks quicksec() init function call until tNetTask
     has finished its init job */
  SEMAPHORE *vx_icept_sem;

  /* Prevent multiple (but not re-entrant) loads */
  if (quicksec_loaded)
    {
      SSH_DEBUG(SSH_D_ERROR, ("quicksec already loaded"));
      return FALSE;
    }

  /* Create and take the init wait semaphore */
  vx_icept_sem = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  semTake(vx_icept_sem, WAIT_FOREVER);

  /* Run SSH IPSec interceptor functions from the vxworks tNetTask */
  if (netJobAdd((FUNCPTR)ssh_main_vxworks, (int)machine_context,
		(int)vx_icept_sem,0,0,0) != OK)
    {
      /* netJobAdd failed, cannot initiate SSH IPSec, check
         your VxWorks configuration */
      semGive(vx_icept_sem);
      semDelete(vx_icept_sem);
      return FALSE;
    }

  /* Now block here, until everything is done by tNetTask */
  semTake(vx_icept_sem, WAIT_FOREVER);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("continuing startup..."));

  /* We are done, free the lock */
  semDelete(vx_icept_sem);

  quicksec_loaded = 1;
  return TRUE;
}

/* Dummy stub to make the linker include all the necessary parts */
extern int ssh_init_vxworks(const unsigned char *policy);
void foo(void)
{
  ssh_init_vxworks(NULL);
}

/* Direct all output to the serial line, view with terminal software */
int sshserial(void)
{
  int fd;

  fd = open("/tyCo/0",2,0);
  ioctl(fd,FIOBAUDRATE,115200);
  ioGlobalStdSet(0,fd);
  ioGlobalStdSet(1,fd);
  ioGlobalStdSet(2,fd);

  return fd;
}


/* Uninitialization for parts common to VxWorks IPSec engines. */
void ssh_unload_vxworks_last(void)
{
  /* uninit timeouts */
  ssh_vx_kernel_timeout_uninit();

  /* Detach interfaces from the interceptor */
  ssh_vxworks_detach_interfaces();

  /* deallocate private interface data */
#ifdef VIRTUAL_STACK
    {
      int i;
      for(i=0; i<VSNUM_MAX; i++)
	{
	  ssh_xfree(ssh_vx_interfaces_per_vs[i]);
	  ssh_vx_interfaces_per_vs[i] = 0;
	}
    }
#else /* VIRTUAL_STACK */
  ssh_xfree(ssh_vx_interfaces);
#endif /* VIRTUAL_STACK */
  ssh_vx_interfaces_num = 0;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  ssh_vxworks_virtual_adapter_uninit();
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Get rid of global variables allocated for tNetTask. */
  ssh_global_uninit();
}

/* The unload program for (single) VxWorks IPSec engine, this code is executed
   on the tNetTask level as is all other engine code. */
void ssh_unload_vxworks(int i1, int i2, int i3, int i4, int i5)
{
#ifdef VIRTUAL_STACK
  SshVxEngine vxe;
  SshVxEngine old_vxe = (SshVxEngine)&ssh_engines;
  SshEngine ssh_engine;

  vxe = ssh_engines;
  while (vxe)
    {
      if (!strcmp((const void*)i1, vxe->machine_context)) break;
      old_vxe = vxe;
      vxe = vxe->next;
    }

  if (!vxe)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("no such ssh_engine"));
      goto end;
    }

  i1 = (int)vxe->machine_context;
  ssh_engine = vxe->engine;
#endif /* VIRTUAL_STACK */

#ifdef SSHDIST_IPSEC_HWACCEL
  ssh_hwaccel_uninit();
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Uninitialize the character device for communication between
     the SSH IPSec engine and the policymanager */
  if (!ssh_vx_dev_uninit((const void*)i1))
    goto end;

  /* Stop the engine */
  ssh_engine_stop(ssh_engine);
#ifdef VIRTUAL_STACK
  old_vxe->next = vxe->next;
  ssh_free(vxe);
#else /* VIRTUAL_STACK */
  ssh_engine = NULL;
#endif /* VIRTUAL_STACK */

  /* Conditionally execute global uninitialization */
#ifdef VIRTUAL_STACK
  if (ssh_engines == NULL)
    ssh_unload_vxworks_last();
#else /* VIRTUAL_STACK */
  ssh_unload_vxworks_last();
#endif /* VIRTUAL_STACK */

 end:
  semGive((void*)i2);
}

/* quicksec_unload() - the unload function for SSH IPSec engine.
   This function is usually called from the VxWorks shell or
   from the usrConfig.c file /Tornado/target/config/all/usrConfig.c */
int quicksec_unload(void *machine_context)
{
  /* This semaphore blocks quicksec_unload() until tNetTask
     has finished its unload job */
  SEMAPHORE *vx_icept_sem;

  /* Prevent multiple (but not re-entrant) unloads */
  if (!quicksec_loaded)
    {
      SSH_DEBUG(SSH_D_ERROR, ("quicksec not loaded"));
      return FALSE;
    }

  /* Create and take the unload wait semaphore */
  vx_icept_sem = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  semTake(vx_icept_sem, WAIT_FOREVER);

  /* Run interceptor functions from the vxworks tNetTask */
  if (netJobAdd((FUNCPTR)ssh_unload_vxworks, (int)machine_context,
                (int)vx_icept_sem, 0, 0, 0) != OK)
    {
      /* netJobAdd failed */
      semGive(vx_icept_sem);
      semDelete(vx_icept_sem);
      return FALSE;
    }

  /* Now block here, until everything is done by tNetTask */
  semTake(vx_icept_sem, WAIT_FOREVER);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("shutdown done"));

  /* We are done, free the lock */
  semDelete(vx_icept_sem);

  quicksec_loaded = 0;
  return TRUE;
}


/* The getuid() function returns the real user ID of  the  cal-
   ling  process. The real user ID identifies the person who is
   logged in. */
uid_t getuid(void)
{
  /* zero is reserved for the root user */
  return 0;
}

uid_t geteuid(void)
{
  return 0;
}

#ifdef DEBUG_LIGHT
/* dumps mbuf statistics - debug light mode only */
void ssh_vx_dump(void)
{
  SshVxInterface vxif;
  struct ifnet *ifp;
  int i;

#ifdef VIRTUAL_STACK
  int ll;

  for(ll = 0; ll < VSNUM_MAX; ll++)
#endif /* VIRTUAL_STACK */
  for (i = 0; i < ssh_vx_interfaces_num; i++)
    {
	vxif = SSH_VX_INTERFACE(ll, i);
      if (!(ifp = vxif->ifp))
	continue;

	printf("-----------------------------------------------------------\n"
	       );
      printf("IF %s:%d statistics\n", ifp->if_name, ifp->if_unit);
      printf("  packets intercepted network=%d, protocol=%d\n",
             vxif->icept_from_network, vxif->icept_from_protocol);
    }
}
#endif /* DEBUG_LIGHT */

#ifdef DEBUG_LIGHT
#ifdef VIRTUAL_STACK
void ssh_dump_engines(void)
{
  SshVxEngine vxe = ssh_engines;
  while (vxe)
    {
      printf("Engine: %p : mc=%p:%s\n",
	     vxe->engine,
	     vxe->machine_context, (char*)(vxe->machine_context));
      vxe = vxe->next;
    }

}
#endif /* VIRTUAL_STACK */
#endif /* DEBUG_LIGHT */
