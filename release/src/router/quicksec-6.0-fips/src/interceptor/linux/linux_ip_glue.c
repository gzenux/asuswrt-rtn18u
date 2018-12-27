/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "linux_internal.h"
#include "linux_vrf.h"

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS

#define SSH_DEBUG_MODULE "SshInterceptorIpGlue"

extern SshInterceptor ssh_interceptor_context;

/********************* Prototypes for packet handling hooks *****************/

static unsigned int
ssh_interceptor_packet_in_ipv4(SshNfHooknum hooknum,
                               SshHookSkb *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn) (struct sk_buff *));

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static unsigned int
ssh_interceptor_packet_in_ipv6(SshNfHooknum hooknum,
                               SshHookSkb *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn) (struct sk_buff *));
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
static unsigned int
ssh_interceptor_packet_in_arp(SshNfHooknum hooknum,
                              SshHookSkb *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn) (struct sk_buff *));
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

static unsigned int
ssh_interceptor_packet_out(int pf,
                           unsigned int hooknum,
                           SshHookSkb *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn) (struct sk_buff *));

static unsigned int
ssh_interceptor_packet_out_ipv4(SshNfHooknum hooknum,
                                SshHookSkb *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn) (struct sk_buff *));

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static unsigned int
ssh_interceptor_packet_out_ipv6(SshNfHooknum hooknum,
                                SshHookSkb *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn) (struct sk_buff *));
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

static void
ssh_interceptor_send_internal(SshInterceptor interceptor,
                              SshInterceptorPacket pp,
                              size_t media_header_len);

/********** Definition of netfilter hooks to register **********************/

struct SshLinuxHooksRec
{
  const char *name;        /* Name of hook */
  Boolean is_registered;   /* Has this hook been registered? */
  Boolean is_mandatory;    /* If the registration fails,
                              abort initialization? */
  int pf;                  /* Protocol family */
  int hooknum;             /* Hook id */
  int priority;            /* Netfilter priority of hook */

  /* Actual hook function */
  unsigned int (*hookfn)(SshNfHooknum hooknum,
                         SshHookSkb *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *));

  struct nf_hook_ops *ops; /* Pointer to storage for nf_hook_ops
                              to store the netfilter hook configuration
                              and state */
};

struct nf_hook_ops ssh_nf_in4, ssh_nf_out4;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
struct nf_hook_ops ssh_nf_in_arp;
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
struct nf_hook_ops ssh_nf_in6, ssh_nf_out6;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

static struct SshLinuxHooksRec ssh_nf_hooks[] =
{
  { "ipv4 in",
    FALSE, TRUE, PF_INET, SSH_NF_IP_PRE_ROUTING,  SSH_NF_IP_PRI_FIRST,
    ssh_interceptor_packet_in_ipv4,  &ssh_nf_in4 },
  { "ipv4 out",
    FALSE, TRUE, PF_INET, SSH_NF_IP_POST_ROUTING, SSH_NF_IP_PRI_FIRST,
    ssh_interceptor_packet_out_ipv4, &ssh_nf_out4 },

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  { "arp in",
    FALSE, TRUE, SSH_NFPROTO_ARP, NF_ARP_IN, 1,
    ssh_interceptor_packet_in_arp, &ssh_nf_in_arp },
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  { "ipv6 in",
    FALSE, TRUE, PF_INET6, SSH_NF_IP6_PRE_ROUTING, SSH_NF_IP6_PRI_FIRST,
    ssh_interceptor_packet_in_ipv6, &ssh_nf_in6 },
  { "ipv6 out",
    FALSE, TRUE, PF_INET6, SSH_NF_IP6_POST_ROUTING, SSH_NF_IP6_PRI_FIRST,
    ssh_interceptor_packet_out_ipv6, &ssh_nf_out6 },
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

  { NULL,
    0, 0, 0, 0, 0,
    NULL_FNPTR, NULL },
};


/******************************** Module parameters *************************/

/* Module parameters. Default values. These can be overrided at the
   loading of the module from the command line. These set the priority
   for netfilter hooks. */

static int in_priority = SSH_NF_IP_PRI_FIRST;
static int out_priority = SSH_NF_IP_PRI_FIRST;
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static int in6_priority = SSH_NF_IP6_PRI_FIRST;
static int out6_priority = SSH_NF_IP6_PRI_FIRST;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

MODULE_PARM_DESC(in_priority, "Netfilter hook priority at IPv4 PREROUTING");
MODULE_PARM_DESC(out_priority, "Netfilter hook priority at IPv4 POSTROUTING");
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
MODULE_PARM_DESC(in6_priority, "Netfilter hook priority at IPv6 PREROUTING");
MODULE_PARM_DESC(out6_priority, "Netfilter hook priority at IPv6 POSTROUTING");
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

module_param(in_priority, int, 0444);
module_param(out_priority, int, 0444);
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
module_param(in6_priority, int, 0444);
module_param(out6_priority, int, 0444);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */


/********************** Recursion Elimination ********************************/












































/* Linux Interceptor recursion elimination logic needs to solve two
   separate problems.

   Firstly, the Interceptor must protect against deadlocks in the system
   protocol stack that may be caused by the Engine replying synchronously
   to an outbound packet from the system protocol stack. Consider the
   following two scenarios:

   1. The system protocol stack sends out a packet, which is intercepted
   at the outbound netfilter hook (ssh_interceptor_packet_out_finish())
   and passed to the Engine. The Engine generates a reply packet (for
   example a TCP RST or ICMP error) and sends it to the system protocol
   stack via ssh_interceptor_send().

   2. A packet from the network is intercepted at the inbound netfilter
   hook (ssh_interceptor_packet_in_finish()) and passed to the Engine.
   The Engine forwards the packet and sends it to the system protocol
   stack via ssh_interceptor_send(). The system protocol stack replies
   synchronously with a reply packet. The reply packet is intercepted at
   the outbound netfilter hook and passed to Engine. The Engine generates
   a reply packet (like in scenarion 1) and sends it to the system
   protocol stack via ssh_interceptor_send().

   In both scenarios the Engine generated reply packet may cause a
   deadlock in the system protocol stack, because the stack assumes that
   sending outbound packets never causes recursive calls back to the stack.

   The linux Interceptor send queue recursion elimination logic solves
   this problem. In the above scenario 1. the Engine generated reply
   packet is inserted into the Interceptor global async send queue, which
   is processed asynchronously from a timeout where the packet is sent to
   system protocol stack. In scenario 2. the recursion is eliminated so
   that the Engine generated reply packet is sent to protocol stack after
   the processing of the original inbound packet has completed (that is in
   the inbound netfilter hook function).

   Secondly, the Interceptor must minimize the impact of stack usage caused
   by the Engine processing. This is achieved by queueing packets destined
   to local stack in ssh_interceptor_send() and by performing the actual
   sending from the Interceptor entry point (the inbound or outbound
   netfilter hook function, or timeout or ipm channel callback). This part
   of stack minimization is implemented by the linux Interceptor send queue
   recursion elimination logic.

   Further measures to minimize stack height are implemented by the linux
   Interceptor engine queue recursion elimination logic. This logic
   eliminates recursive calls to the interceptor at the outbound netfilter
   hook by queueing outbound packets for delayed Engine processing and
   processing the engine queue in the interceptor entry point (inbound
   netfilter hook, timeout or ipm channel callback).

   The send queue recursion elimination logic MUST always be enabled if the
   Engine does not implement asynchronous sending (that is if
   SSH_IPSEC_SEND_IS_SYNC is undefined). The engine queue recursion
   elimination should only be needed when stack height must be limited. */

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
#ifdef SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION
static void
interceptor_engine_queue_put(SshCpuContext cpu_ctx,
                             SshInterceptorInternalPacket ipp)
{
  SSH_ASSERT(ipp != NULL);

  /* Packets may be added to engine queue only while processing
     the send queue. */
  SSH_ASSERT(cpu_ctx->in_send == 1);

  /* Assert that the packet is not in any list. */
  SSH_ASSERT(ipp->list_status == 0);

  SSH_DEBUG(SSH_D_LOWOK, ("Adding packet %p to engine queue, queue length %d",
                          ipp, cpu_ctx->engine_queue_len + 1));

  ipp->packet.next = NULL;
  if (cpu_ctx->engine_queue_tail != NULL)
    {
      SSH_ASSERT(cpu_ctx->engine_queue_head != NULL);
      SSH_ASSERT(cpu_ctx->engine_queue_len > 0);

      /* Insert to tail. */
      cpu_ctx->engine_queue_tail->next = (SshInterceptorPacket) ipp;
      cpu_ctx->engine_queue_tail = (SshInterceptorPacket) ipp;
    }
  else
    {
      SSH_ASSERT(cpu_ctx->engine_queue_head == NULL);
      SSH_ASSERT(cpu_ctx->engine_queue_len == 0);

      /* Insert to head. */
      cpu_ctx->engine_queue_head = (SshInterceptorPacket) ipp;
      cpu_ctx->engine_queue_tail = (SshInterceptorPacket) ipp;
    }

#ifdef DEBUG_LIGHT
  ipp->list_status |= SSH_INTERCEPTOR_PACKET_IN_ENGINE_QUEUE;
  cpu_ctx->engine_queue_len++;
  SSH_ASSERT(cpu_ctx->engine_queue_len <= 1000);
#endif /* DEBUG_LIGHT */
}

static SshInterceptorInternalPacket
interceptor_engine_queue_get(SshCpuContext cpu_ctx)
{
  SshInterceptorInternalPacket ipp;

  if (cpu_ctx->engine_queue_head == NULL)
    {
      SSH_ASSERT(cpu_ctx->engine_queue_tail == NULL);
      SSH_ASSERT(cpu_ctx->engine_queue_len == 0);
      return NULL;
    }

  ipp = (SshInterceptorInternalPacket) cpu_ctx->engine_queue_head;
  cpu_ctx->engine_queue_head = ipp->packet.next;

  if (ipp == (SshInterceptorInternalPacket) cpu_ctx->engine_queue_tail)
    {
      SSH_ASSERT(cpu_ctx->engine_queue_head == NULL);
      SSH_ASSERT(cpu_ctx->engine_queue_len == 1);
      cpu_ctx->engine_queue_tail = NULL;
    }

#ifdef DEBUG_LIGHT
  /* Assert that the packet was only in the engine queue. */
  SSH_ASSERT(ipp->list_status == SSH_INTERCEPTOR_PACKET_IN_ENGINE_QUEUE);
  ipp->list_status &= ~SSH_INTERCEPTOR_PACKET_IN_ENGINE_QUEUE;
  SSH_ASSERT(cpu_ctx->engine_queue_len > 0);
  cpu_ctx->engine_queue_len--;
#endif /* DEBUG_LIGHT */

  return ipp;
}
#endif /* SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION */

static void
interceptor_send_queue_put(SshCpuContext cpu_ctx,
                           SshInterceptorPacket pp,
                           size_t media_header_len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SSH_ASSERT(ipp != NULL);

  /* Packets may be added to send queue only while executing an engine call. */
  SSH_ASSERT(cpu_ctx->in_engine == 1);

  /* Assert that the packet is not in any list. */
  SSH_ASSERT(ipp->list_status == 0);

  SSH_DEBUG(SSH_D_LOWOK, ("Adding packet %p to send queue, queue length %d",
                          ipp, cpu_ctx->send_queue_len + 1));

  ipp->packet.next = NULL;
  ipp->media_header_len = media_header_len;

  if (cpu_ctx->send_queue_tail != NULL)
    {
      SSH_ASSERT(cpu_ctx->send_queue_head != NULL);
      SSH_ASSERT(cpu_ctx->send_queue_len > 0);

      /* Insert to tail. */
      cpu_ctx->send_queue_tail->next = pp;
      cpu_ctx->send_queue_tail = pp;
    }
  else
    {
      SSH_ASSERT(cpu_ctx->send_queue_head == NULL);
      SSH_ASSERT(cpu_ctx->send_queue_len == 0);

      /* Insert to head. */
      cpu_ctx->send_queue_head = pp;
      cpu_ctx->send_queue_tail = pp;
    }

#ifdef DEBUG_LIGHT
  ipp->list_status |= SSH_INTERCEPTOR_PACKET_IN_SEND_QUEUE;
  cpu_ctx->send_queue_len++;
  SSH_ASSERT(cpu_ctx->send_queue_len <= 1000);
#endif /* DEBUG_LIGHT */
}

static SshInterceptorInternalPacket
interceptor_send_queue_get(SshCpuContext cpu_ctx)
{
  SshInterceptorInternalPacket ipp;

  if (cpu_ctx->send_queue_head == NULL)
    {
      SSH_ASSERT(cpu_ctx->send_queue_tail == NULL);
      SSH_ASSERT(cpu_ctx->send_queue_len == 0);
      return NULL;
    }

  ipp = (SshInterceptorInternalPacket) cpu_ctx->send_queue_head;
  cpu_ctx->send_queue_head = ipp->packet.next;

  if (ipp == (SshInterceptorInternalPacket) cpu_ctx->send_queue_tail)
    {
      SSH_ASSERT(cpu_ctx->send_queue_head == NULL);
      SSH_ASSERT(cpu_ctx->send_queue_len == 1);
      cpu_ctx->send_queue_tail = NULL;
    }

#ifdef DEBUG_LIGHT
  /* Assert that the packet was only in the send queue. */
  SSH_ASSERT(ipp->list_status == SSH_INTERCEPTOR_PACKET_IN_SEND_QUEUE);
  ipp->list_status &= ~SSH_INTERCEPTOR_PACKET_IN_SEND_QUEUE;
  SSH_ASSERT(cpu_ctx->send_queue_len > 0);
  cpu_ctx->send_queue_len--;
#endif /* DEBUG_LIGHT */

  return ipp;
}

static void
interceptor_async_send_queue_process(void *context)
{
  SshInterceptor interceptor = context;
  SshCpuContext cpu_ctx;
  SshInterceptorInternalPacket ipp;

  SSH_DEBUG(SSH_D_LOWOK, ("Processing async send queue"));

  SSH_ASSERT(in_softirq());
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  /* Move the global asynch send queue to cpu context, the send queue
     in cpu context will be processed after all timeouts have been
     executed. */
  ssh_kernel_mutex_lock(interceptor->async_send_queue_lock);
  while (interceptor->async_send_queue != NULL)
    {
      ipp = (SshInterceptorInternalPacket) interceptor->async_send_queue;
      interceptor->async_send_queue = ipp->packet.next;

#ifdef DEBUG_LIGHT
      /* Assert that the packet was only in the async send queue. */
      SSH_ASSERT(ipp->list_status
                 == SSH_INTERCEPTOR_PACKET_IN_ASYNC_SEND_QUEUE);
      ipp->list_status &= ~SSH_INTERCEPTOR_PACKET_IN_ASYNC_SEND_QUEUE;
#endif /* DEBUG_LIGHT */

      interceptor_send_queue_put(cpu_ctx, &ipp->packet, ipp->media_header_len);
    }
  interceptor->async_send_queue_tail = NULL;
  ssh_kernel_mutex_unlock(interceptor->async_send_queue_lock);
}

void
interceptor_packet_queue_process(SshInterceptor interceptor,
                                 SshCpuContext cpu_ctx,
                                 Boolean async_to_stack)
{
  SshInterceptorInternalPacket ipp;
  Boolean schedule_async_send_timeout = FALSE;

  /* Stack breaker part 1 of 2: Send out packets that were queued for sending
     while executing an engine call (inbound or outbound packet, or timeout
     or ipm callback). */
  ipp = interceptor_send_queue_get(cpu_ctx);
  while (ipp != NULL)
    {
      /* Do not send packets synchronously towards stack if we are
         processing the packet queue in ssh_interceptor_packet_out_finish()
         as this could cause a deadlock in the system protocol stack. */
      if (async_to_stack == TRUE
          && (ipp->packet.flags & SSH_PACKET_FROMPROTOCOL) == 0)
        {
          /* Add packet to tail of asynch send list. */
          SSH_DEBUG(SSH_D_LOWOK, ("Adding packet %p to asynch send queue",
                                  ipp));

#ifdef DEBUG_LIGHT
          SSH_ASSERT(ipp->list_status == 0);
          ipp->list_status |= SSH_INTERCEPTOR_PACKET_IN_ASYNC_SEND_QUEUE;
#endif /* DEBUG_LIGHT */

          ssh_kernel_mutex_lock(interceptor->async_send_queue_lock);
          if (interceptor->async_send_queue_tail == NULL)
            {
              SSH_ASSERT(interceptor->async_send_queue == NULL);
              interceptor->async_send_queue = (SshInterceptorPacket) ipp;
              interceptor->async_send_queue_tail = (SshInterceptorPacket) ipp;
              schedule_async_send_timeout = TRUE;
            }
          else
            {
              SSH_ASSERT(interceptor->async_send_queue != NULL);
              interceptor->async_send_queue_tail->next =
                (SshInterceptorPacket) ipp;
              interceptor->async_send_queue_tail = (SshInterceptorPacket) ipp;
            }
          ipp->packet.next = NULL;
          ssh_kernel_mutex_unlock(interceptor->async_send_queue_lock);
        }

      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Sending packet %p from send queue: queue length %d",
                     ipp, cpu_ctx->send_queue_len));

          SSH_ASSERT(cpu_ctx->in_send == 0);
          cpu_ctx->in_send = 1;
          ssh_interceptor_send_internal(interceptor,
                                        (SshInterceptorPacket) ipp,
                                        ipp->media_header_len);
          SSH_ASSERT(cpu_ctx->in_send == 1);
          cpu_ctx->in_send = 0;
        }

#ifdef SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION
      /* Stack breaker part 2 of 2: Process packets that were queued for
         processing in the outbound netfilter hook while sending the
         queued packet above. Note that these packets may generate new
         packets that are added to the send queue. Note also that packets
         are added to the engine queue only when cpu is processing the send
         queue, (that cpu_ctx->is in_send == 1). Otherwise no packets can
         enter the engine queue. */
      ipp = interceptor_engine_queue_get(cpu_ctx);
      while (ipp != NULL)
        {
#ifdef DEBUG_LIGHT
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Processing packet %p from engine queue: queue length %d",
                     ipp, cpu_ctx->engine_queue_len));
          if (ssh_interceptor_packet_hexdump(ipp) == FALSE)
            {
              SSH_LINUX_STATISTICS(interceptor,
                                   { interceptor->stats.num_errors++; });
              goto next;
            }
#endif /* DEBUG_LIGHT */

          /* Pass the packet to engine. */
          SSH_ASSERT(cpu_ctx->in_engine == 0);
          cpu_ctx->in_engine = 1;

          SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, ipp);

          SSH_ASSERT(cpu_ctx->in_engine == 1);
          cpu_ctx->in_engine = 0;

#ifdef DEBUG_LIGHT
        next:
#endif  /* DEBUG_LIGHT */
          /* Process the next packet from engine queue. */
          ipp = interceptor_engine_queue_get(cpu_ctx);
        }
#endif /* SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION */

      /* Process the next packet from send queue. */
      ipp = interceptor_send_queue_get(cpu_ctx);
    }

  /* Assert that all packets have been processes from both send queue and
     engine queue. */
  SSH_ASSERT(cpu_ctx->send_queue_head == NULL);
#ifdef SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION
  SSH_ASSERT(cpu_ctx->engine_queue_head == NULL);
#endif /* SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION */

  /* If packets were added to an empty asynch packet list, then schedule
     a timeout for processing the list. */
  if (schedule_async_send_timeout == TRUE)
    ssh_kernel_timeout_register(0, 1,
                                interceptor_async_send_queue_process,
                                interceptor);
}

#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

/************* Utility functions ********************************************/

/* Map a SshInterceptorProtocol to a skbuff protocol id */
static unsigned short
ssh_proto_to_skb_proto(SshInterceptorProtocol protocol)
{
  /* If support for other than IPv6, IPv4 and ARP
     inside the engine on Linux are to be supported, their
     protocol types must be added here. */
  switch (protocol)
    {
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case SSH_PROTOCOL_IP6:
      return __constant_htons(ETH_P_IPV6);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    case SSH_PROTOCOL_ARP:
      return __constant_htons(ETH_P_ARP);

    case SSH_PROTOCOL_IP4:
      return __constant_htons(ETH_P_IP);

    default:
      SSH_DEBUG(SSH_D_ERROR, ("Unknown protocol %d", protocol));
      return 0;
    }
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Map ethernet type to a skbuff protocol id */
static unsigned short
ssh_ethertype_to_skb_proto(SshInterceptorProtocol protocol,
                           size_t media_header_len,
                           unsigned char *media_header)
{
  SshUInt16 ethertype;

  if (protocol != SSH_PROTOCOL_ETHERNET)
    return ssh_proto_to_skb_proto(protocol);

  SSH_ASSERT(media_header_len >= SSH_ETHERH_HDRLEN);
  ethertype = SSH_GET_16BIT(media_header + SSH_ETHERH_OFS_TYPE);

  /* If support for other than IPv6, IPv4 and ARP
     inside the engine on Linux are to be supported, their
     ethernet types must be added here. */
  switch (ethertype)
    {
    case SSH_ETHERTYPE_IPv6:
      return __constant_htons(ETH_P_IPV6);

    case SSH_ETHERTYPE_ARP:
      return __constant_htons(ETH_P_ARP);

    case SSH_ETHERTYPE_IP:
      return __constant_htons(ETH_P_IP);

    default:
      SSH_DEBUG(SSH_D_ERROR, ("Unknown ethertype 0x%x", ethertype));
      return 0;
    }
}

/* Return the pointer to start of ethernet header */
static struct ethhdr *ssh_get_eth_hdr(const struct sk_buff *skb)
{
  return eth_hdr(skb);
}

#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/**************** Packet reception and sending *****************************/

/* Utility macro for printing sk_buff->pkt_type */
#define SSH_LINUX_SKB_PKT_TYPE_RENDER(pkt_type)                 \
  ((pkt_type) == PACKET_HOST ? "PACKET_HOST" :                  \
   ((pkt_type) == PACKET_BROADCAST ? "PACKET_BROADCAST" :       \
    ((pkt_type) == PACKET_MULTICAST ? "PACKET_MULTICAST" :      \
     ((pkt_type) == PACKET_OTHERHOST ? "PACKET_OTHERHOST" :     \
      ((pkt_type) == PACKET_OUTGOING ? "PACKET_OUTGOING" :      \
       ((pkt_type) == PACKET_LOOPBACK ? "PACKET_LOOPBACK" :     \
        ((pkt_type) == PACKET_FASTROUTE ? "PACKET_FASTROUTE" :  \
         "<unknown packet type>")))))))

/**************** Inbound packet interception ******************************/


/* Common code for ssh_interceptor_packet_in_finish_ipv4()
   and ssh_interceptor_packet_in_finish_ipv6().

   If SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE is set, then
   this function is called as the okfn() from the netfilter
   infrastructure after inbound netfilter hook iteration.
   Otherwise this function is called directly from the inbound
   netfilter hookfn().
*/

static inline int
ssh_interceptor_packet_in_finish(struct sk_buff *skbp,
                                 SshInterceptorProtocol protocol)
{
  SshInterceptorInternalPacket ipp;
  SshInterceptor interceptor;
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  SshCpuContext cpu_ctx;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
  int ifnum_in;

  interceptor = ssh_interceptor_context;

  SSH_ASSERT(skbp->dev != NULL);
  ifnum_in = skbp->dev->ifindex;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("incoming packet length %d proto 0x%x [%s] iface %d [%s]",
             skbp->len, ntohs(skbp->protocol),
             (protocol == SSH_PROTOCOL_IP4 ? "ipv4" :
              (protocol == SSH_PROTOCOL_IP6 ? "ipv6" :
               (protocol == SSH_PROTOCOL_ETHERNET ? "ethernet" : "unknown"))),
             ifnum_in, skbp->dev->name));

  SSH_ASSERT(in_irq() == 0);
  SSH_ASSERT(in_softirq());

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Unwrap ethernet header. This is needed by the engine currently
     due to some sillyness in the ARP/IPv6 ND handling. */
  if (SSH_SKB_GET_MACHDR(skbp) != NULL)
    {
      size_t media_header_len = skbp->data - SSH_SKB_GET_MACHDR(skbp);

      if (media_header_len == SSH_ETHERH_HDRLEN
          || media_header_len == SSH_SNAPH_HDRLEN)
        {
          skb_push(skbp, media_header_len);
          protocol = SSH_PROTOCOL_ETHERNET;
        }
    }
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Encapsulate the skb into a new packet. Note that ip_rcv()
     performs IP header checksum computation, so we do not
     need to. */
  ipp = ssh_interceptor_packet_alloc_header(interceptor,
                          SSH_PACKET_FROMADAPTER
                          |SSH_PACKET_IP4HDRCKSUMOK,
                          protocol,
                          ifnum_in,
                          SSH_INTERCEPTOR_INVALID_IFNUM,
                          skbp,
                          SSH_LINUX_PACKET_ALLOC_FLAG_PKT_FROM_SYSTEM
                          | SSH_LINUX_PACKET_ALLOC_FLAG_FREE_ORGINAL_ON_COPY);

  if (unlikely(ipp == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("encapsulation failed, packet dropped"));

      /* Free sk_buff and return error */
      dev_kfree_skb_any(skbp);
      SSH_LINUX_STATISTICS(interceptor, { interceptor->stats.num_errors++; });
      return -EPERM;
    }

#ifdef DEBUG_LIGHT
  ipp->skb->dev = NULL;

  if (ssh_interceptor_packet_hexdump(ipp) == FALSE)
    {
      SSH_LINUX_STATISTICS(interceptor, { interceptor->stats.num_errors++; });
      return -EPERM;
    }
#endif /* DEBUG_LIGHT */

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_fastpath_bytes_in += (SshUInt64) ipp->skb->len;
    interceptor->stats.num_fastpath_packets_in++;
  });

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Mark that cpu is executing an engine call. */
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  SSH_ASSERT(cpu_ctx->in_engine == 0);
  cpu_ctx->in_engine = 1;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  /* Pass the packet to then engine. Which eventually will call
     ssh_interceptor_send. */
  SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, ipp);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Mark that engine call has completed and process packets that were
     queued while in engine call. */
  SSH_ASSERT(cpu_ctx->in_engine == 1);
  cpu_ctx->in_engine = 0;
  SSH_DEBUG(SSH_D_LOWOK, ("Processing packet queue"));
  interceptor_packet_queue_process(interceptor, cpu_ctx, FALSE);
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  /* Return ok */
  return 0;
}


#ifdef SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE

static inline int
ssh_interceptor_packet_in_finish_ipv4(struct sk_buff *skbp)
{
  return ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_IP4);
}

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static inline int
ssh_interceptor_packet_in_finish_ipv6(struct sk_buff *skbp)
{
  return ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_IP6);
}
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#endif /* SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE */


/* ssh_interceptor_packet_in() is the common code for
   inbound netfilter hooks ssh_interceptor_packet_in_ipv4(),
   ssh_interceptor_packet_in_ipv6(), and ssh_interceptor_packet_in_arp().

   This function must only be called from softirq context, or
   with softirqs disabled. This function MUST NOT be called
   from a hardirq (as then it could pre-empt itself on the same CPU). */

static inline unsigned int
ssh_interceptor_packet_in(int pf,
                          unsigned int hooknum,
                          SshHookSkb *skb,
                          const struct net_device *in,
                          const struct net_device *out,
                          int (*okfn) (struct sk_buff *))
{
  SshInterceptor interceptor;
  struct sk_buff *skbp = SSH_HOOK_SKB_PTR(skb);

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_PCKDMP,
            ("IN 0x%04x/0x%x iface (%s[%d]->%s[%d]) length %d "
             "%s dst 0x%08x dev (%s[%d]) skb [%s%s%s%s]",
             htons(skbp->protocol),
             pf,
             (in ? in->name : "<none>"),
             (in ? in->ifindex : -1),
             (out ? out->name : "<none>"),
             (out ? out->ifindex : -1),
             skbp->len,
             SSH_LINUX_SKB_PKT_TYPE_RENDER(skbp->pkt_type),
             skb_dst(skbp),
             (skbp->dev ? skbp->dev->name : "<none>"),
             (skbp->dev ? skbp->dev->ifindex : -1),
             (skb_shared(skbp) ? "shared " : ""),
             (skb_cloned(skbp) ? "cloned " : ""),
             (skb_is_nonlinear(skbp) ? "non-linear " : ""),
             (skb_shinfo(skbp)->frag_list ? "fragmented" : "")
             ));

  interceptor = ssh_interceptor_context;

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_bytes_in += (SshUInt64) skbp->len;
    interceptor->stats.num_packets_in++;
  });

































  /* If the device is to loopback, pass the packet through. */






  if (in->flags & IFF_LOOPBACK)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }

  /* The linux stack makes a copy of each locally generated
     broadcast / multicast packet. The original packet will
     be sent to network as any packet. The copy will be marked
     as PACKET_LOOPBACK and looped back to local stack.
     So we let the copy continue back to local stack. */
  if (skbp->pkt_type == PACKET_LOOPBACK)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }

  /* Quicksec code relies on skb->dev to be set.
     If packet has been processed by AF_PACKET (what tcpdump uses),
     then skb->dev has been cleared, and we must reset it here. */
  SSH_ASSERT(skbp->dev == NULL || skbp->dev == in);
  if (skbp->dev == NULL)
    {
      skbp->dev = (struct net_device *) in;
      /* Increment refcount of skbp->dev. */
      dev_hold(skbp->dev);
    }

#ifdef SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE

  /* Traverse lower priority netfilter hooks. */
  switch (pf)
    {
    case PF_INET:
      SSH_ASSERT(hooknum == SSH_NF_IP_PRE_ROUTING);
      NF_HOOK_THRESH(PF_INET, SSH_NF_IP_PRE_ROUTING, skbp,
                     (struct net_device *) in, (struct net_device *) out,
                     ssh_interceptor_packet_in_finish_ipv4,
                     ssh_nf_in4.priority + 1);
      return NF_STOLEN;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      SSH_ASSERT(hooknum == SSH_NF_IP6_PRE_ROUTING);
      NF_HOOK_THRESH(PF_INET6, SSH_NF_IP6_PRE_ROUTING, skbp,
                     (struct net_device *) in, (struct net_device *) out,
                     ssh_interceptor_packet_in_finish_ipv6,
                     ssh_nf_in6.priority + 1);
      return NF_STOLEN;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_NFPROTO_ARP:
      /* There is no point in looping ARP packets,
         just continue packet processing, and return NF_STOLEN. */
      ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_ETHERNET);
      return NF_STOLEN;
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    default:
      SSH_NOTREACHED;
      return NF_DROP;
    }

#else /* SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE */

  /* Continue packet processing ssh_interceptor_packet_in_finish() */
  switch (pf)
    {
    case PF_INET:
      ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_IP4);
      return NF_STOLEN;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_IP6);
      return NF_STOLEN;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_NFPROTO_ARP:
      ssh_interceptor_packet_in_finish(skbp, SSH_PROTOCOL_ETHERNET);
      return NF_STOLEN;
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    default:
      SSH_NOTREACHED;
      return NF_DROP;
    }

#endif /* SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE */

  SSH_NOTREACHED;
  return NF_DROP;
}

/* Netfilter hookfn() wrapper function for IPv4 packets. */
static unsigned int
ssh_interceptor_packet_in_ipv4(SshNfHooknum hooknum,
                               SshHookSkb *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn) (struct sk_buff *))
{









  return ssh_interceptor_packet_in(PF_INET, SSH_GET_HOOKNUM(hooknum),
                                   skb, in, out, okfn);

}

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
/* Netfilter nf_hookfn() wrapper function for IPv6 packets. */
static unsigned int
ssh_interceptor_packet_in_ipv6(SshNfHooknum hooknum,
                               SshHookSkb *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn) (struct sk_buff *))
{









  return ssh_interceptor_packet_in(PF_INET6, SSH_GET_HOOKNUM(hooknum),
                                   skb, in, out, okfn);

}
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* Netfilter nf_hookfn() wrapper function for ARP packets. */
static unsigned int
ssh_interceptor_packet_in_arp(SshNfHooknum hooknum,
                              SshHookSkb *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn) (struct sk_buff *))
{










  return ssh_interceptor_packet_in(SSH_NFPROTO_ARP, SSH_GET_HOOKNUM(hooknum),
                                   skb, in, out, okfn);

}
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/**************** Outbound packet interception *****************************/


/* Common code for ssh_interceptor_packet_out_finish_ipv4()
   and ssh_interceptor_packet_out_finish_ipv6().

   If SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE is set, then
   this function is called as the okfn() function from the
   netfilter infrastructure after the outbound hook iteration.
   Otherwise, this function is called directly from the outbound
   netfilter hookfn().

   This function must only be called from softirq context or
   from an exception. It will disable softirqs for the engine
   processing. This function MUST NOT be called
   from a hardirq (as then it could pre-empt itself
   on the same CPU). */
static inline int
ssh_interceptor_packet_out_finish(struct sk_buff *skbp,
                                  SshInterceptorProtocol protocol)
{
  SshInterceptorInternalPacket ipp;
  SshInterceptor interceptor;
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  SshCpuContext cpu_ctx;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
  int ifnum_in;
  SshUInt32 flags = 0;

  SSH_ASSERT(skbp->dev != NULL);
  ifnum_in = skbp->dev->ifindex;

  interceptor = ssh_interceptor_context;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("outgoing packet length %d proto 0x%x [%s] iface %d [%s]",
             skbp->len, ntohs(skbp->protocol),
             (protocol == SSH_PROTOCOL_IP4 ? "ipv4" :
              (protocol == SSH_PROTOCOL_IP6 ? "ipv6" :
               (protocol == SSH_PROTOCOL_ETHERNET ? "ethernet" : "unknown"))),
             ifnum_in, skbp->dev->name));

  local_bh_disable();
  SSH_ASSERT(in_softirq());
  SSH_ASSERT(in_irq() == 0);

  flags = SSH_PACKET_FROMPROTOCOL;

#ifdef LINUX_FRAGMENTATION_AFTER_NF6_POST_ROUTING
  /* Is this a local packet which is allowed to be fragmented? */
  if (protocol == SSH_PROTOCOL_IP6 && SSH_SKB_IS_LOCAL_DF_ALLOWED(skbp) == 1)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Local packet, fragmentation allowed."));
      flags |= SSH_PACKET_FRAGMENTATION_ALLOWED;
    }
#endif /* LINUX_FRAGMENTATION_AFTER_NF6_POST_ROUTING */

  /* Is this a local packet which is allowed to be fragmented? */
  if (protocol == SSH_PROTOCOL_IP4 && SSH_SKB_IS_LOCAL_DF_ALLOWED(skbp) == 1)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Local packet, fragmentation allowed."));
      flags |= SSH_PACKET_FRAGMENTATION_ALLOWED;
    }

  /* Encapsulate the skb into a new packet. This function
     holds packet_lock during freelist manipulation. */
  ipp = ssh_interceptor_packet_alloc_header(interceptor,
                           flags,
                           protocol,
                           ifnum_in,
                           SSH_INTERCEPTOR_INVALID_IFNUM,
                           skbp,
                           SSH_LINUX_PACKET_ALLOC_FLAG_PKT_FROM_SYSTEM
                           | SSH_LINUX_PACKET_ALLOC_FLAG_FREE_ORGINAL_ON_COPY);
  if (unlikely(ipp == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("encapsulation failed, packet dropped"));

      local_bh_enable();

      /* Free sk_buff and return error */
      dev_kfree_skb_any(skbp);
      SSH_LINUX_STATISTICS(interceptor, { interceptor->stats.num_errors++; });
      return -EPERM;
    }

#ifdef DEBUG_LIGHT
  ipp->skb->dev = NULL;

  if (ssh_interceptor_packet_hexdump(ipp) == FALSE)
    {
      /* Iteration failed, pp is already freed. */
      local_bh_enable();
      SSH_LINUX_STATISTICS(interceptor, { interceptor->stats.num_errors++; });
      return -EPERM;
    }
#endif /* DEBUG_LIGHT */

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_fastpath_bytes_out += (SshUInt64) ipp->skb->len;
    interceptor->stats.num_fastpath_packets_out++;
  });

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

#ifdef SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION
  /* Queue packet for later engine processing if this is a recursive call,
     that is, if this cpu is processing the send queue in the inbound
     netfilter hook, timeout callback or ipm callback. This is done only
     to reduce maximum stack height.

     Note that in linux sending to network never generates recursive calls
     to the inbound netfilter hook because netif_rx() is always asynchronous.
     Therefore this check needs to be done only here in the outbound
     netfilter hook. */
  if (cpu_ctx->in_send == 1)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Recursive call to interceptor via outbound netfilter hook"));
      interceptor_engine_queue_put(cpu_ctx, ipp);
      local_bh_enable();
      /* Everything is ok. */
      return 0;
    }
#endif /* SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION */

  /* Mark that this cpu is executing an engine call. Note that this may be a
     recursive call originating from inbound netfilter hook, timeout callback
     or ipm channel callback (in which case cpu_ctx->in_send is set). */
  SSH_ASSERT(cpu_ctx->in_engine == 0);
  cpu_ctx->in_engine = 1;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  /* Pass the packet to engine. */
  SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, ipp);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Mark that the engine call has completed. */
  SSH_ASSERT(cpu_ctx->in_engine == 1);
  cpu_ctx->in_engine = 0;

  /* Process packet queues if this was not a recursive call. */
  if (cpu_ctx->in_send == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Processing packet queue"));
      interceptor_packet_queue_process(interceptor, cpu_ctx, TRUE);
    }
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  local_bh_enable();

  /* Return ok */
  return 0;
}

#ifdef SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE

static inline int
ssh_interceptor_packet_out_finish_ipv4(struct sk_buff *skbp)
{
  return ssh_interceptor_packet_out_finish(skbp, SSH_PROTOCOL_IP4);
}

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static inline int
ssh_interceptor_packet_out_finish_ipv6(struct sk_buff *skbp)
{
  return ssh_interceptor_packet_out_finish(skbp, SSH_PROTOCOL_IP6);
}
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */
#endif /* SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE */

/* ssh_interceptor_packet_out() is the common code for
   outbound netfilter hook ssh_interceptor_packet_out_ipv4()
   and ssh_interceptor_packet_out_ipv6().

   Netfilter does not provide a clean way of intercepting ALL packets
   being sent via an output chain after all other filters are processed.
   Therefore this hook is registered first, and then if
   SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE is set the packet is
   sent back to SSH_NF_IP_POST_ROUTING hook with (*okfn)()
   pointing to the actual interception function. If
   SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE is not set, then
   all following netfilter hook functions in SSH_NF_IP_POST_ROUTING hook
   are skipped.

   This function must only be called from softirq context or
   from an exception. It will disable softirqs for the engine
   processing. This function MUST NOT be called
   from a hardirq (as then it could pre-empt itself
   on the same CPU). */

static inline unsigned int
ssh_interceptor_packet_out(int pf,
                           unsigned int hooknum,
                           SshHookSkb *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn) (struct sk_buff *))
{
  SshInterceptor interceptor;
  struct sk_buff *skbp = SSH_HOOK_SKB_PTR(skb);

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_PCKDMP,
            ("OUT 0x%04x/0x%x iface (%s[%d]->%s[%d]) length %d "
             "%s dst 0x%08x dev (%s[%d]) skb [%s%s%s%s]",
             htons(skbp->protocol),
             pf,
             (in ? in->name : "<none>"),
             (in ? in->ifindex : -1),
             (out ? out->name : "<none>"),
             (out ? out->ifindex : -1),
             skbp->len,
             SSH_LINUX_SKB_PKT_TYPE_RENDER(skbp->pkt_type),
             skb_dst(skbp),
             (skbp->dev ? skbp->dev->name : "<none>"),
             (skbp->dev ? skbp->dev->ifindex : -1),
             (skb_shared(skbp) ? "shared " : ""),
             (skb_cloned(skbp) ? "cloned " : ""),
             (skb_is_nonlinear(skbp) ? "non-linear " : ""),
             (skb_shinfo(skbp)->frag_list ? "fragmented" : "")
             ));

  interceptor = ssh_interceptor_context;

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_packets_out++;
    interceptor->stats.num_bytes_out += (SshUInt64) skbp->len;
  });

































  /* If the device is to loopback, pass the packet through. */






  if (out->flags & IFF_LOOPBACK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("loopback packet passed through"));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("length %d dumping %d bytes",
                         (int) skbp->len, (int) skb_headlen(skbp)),
                        skbp->data, skb_headlen(skbp));
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }

  /* Linux network stack creates a copy of locally generated broadcast
     and multicast packets, and sends the copies to local stack using
     'ip_dev_loopback_xmit' or 'ip6_dev_loopback_xmit' as the NFHOOK
     okfn. Intercept the original packets and let the local copies go
     through. */
  if (pf == PF_INET &&
      okfn != interceptor->nf->linux_fn.ip_finish_output)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("local IPv4 broadcast loopback packet passed through"));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("length %d dumping %d bytes",
                         (int) skbp->len, (int) skb_headlen(skbp)),
                        skbp->data, skb_headlen(skbp));
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  if (pf == PF_INET6 &&
      okfn != interceptor->nf->linux_fn.ip6_output_finish)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("local IPv6 broadcast loopback packet passed through"));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("length %d dumping %d bytes",
                         (int) skbp->len, (int) skb_headlen(skbp)),
                        skbp->data, skb_headlen(skbp));
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifdef LINUX_IP_ONLY_PASSTHROUGH_NDISC
  if (pf == PF_INET6 &&
      skbp->sk == dev_net(skbp->dev)->ipv6.ndisc_sk)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Neighbour discovery packet passed through"));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("length %d dumping %d bytes",
                         (int) skbp->len, (int) skb_headlen(skbp)),
                        skbp->data, skb_headlen(skbp));
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_passthrough++; });
      return NF_ACCEPT;
    }
#endif /* LINUX_IP_ONLY_PASSTHROUGH_NDISC */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

  /* Assert that we are about to intercept the packet from
     the correct netfilter hook on the correct path. */
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  SSH_ASSERT(okfn == interceptor->nf->linux_fn.ip_finish_output ||
             okfn == interceptor->nf->linux_fn.ip6_output_finish);
#else /* SSH_LINUX_INTERCEPTOR_IPV6 */
  SSH_ASSERT(okfn == interceptor->nf->linux_fn.ip_finish_output);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifdef SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE

  /* Traverse lower priority netfilter hooks. */
  switch (pf)
    {
    case PF_INET:
      SSH_ASSERT(hooknum == SSH_NF_IP_POST_ROUTING);
      NF_HOOK_THRESH(PF_INET, SSH_NF_IP_POST_ROUTING, skbp,
                     (struct net_device *) in, (struct net_device *) out,
                     ssh_interceptor_packet_out_finish_ipv4,
                     ssh_nf_out4.priority + 1);
      return NF_STOLEN;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      SSH_ASSERT(hooknum == SSH_NF_IP6_POST_ROUTING);
      NF_HOOK_THRESH(PF_INET6, SSH_NF_IP6_POST_ROUTING, skbp,
                     (struct net_device *) in, (struct net_device *) out,
                     ssh_interceptor_packet_out_finish_ipv6,
                     ssh_nf_out6.priority + 1);
      return NF_STOLEN;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    default:
      SSH_NOTREACHED;
      return NF_DROP;
    }

#else /* SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE */

  /* Continue packet processing in ssh_interceptor_packet_out_finish() */
  switch (pf)
    {
    case PF_INET:
      SSH_ASSERT(hooknum == SSH_NF_IP_POST_ROUTING);
      ssh_interceptor_packet_out_finish(skbp, SSH_PROTOCOL_IP4);
      return NF_STOLEN;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      SSH_ASSERT(hooknum == SSH_NF_IP6_POST_ROUTING);
      ssh_interceptor_packet_out_finish(skbp, SSH_PROTOCOL_IP6);
      return NF_STOLEN;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    default:
      SSH_NOTREACHED;
      return NF_DROP;
    }
#endif /* SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE */

  SSH_NOTREACHED;
  return NF_DROP;
}

/* Netfilter nf_hookfn() wrapper function for IPv4 packets. */
static unsigned int
ssh_interceptor_packet_out_ipv4(SshNfHooknum hooknum,
                                SshHookSkb *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn) (struct sk_buff *))
{









  return ssh_interceptor_packet_out(PF_INET, SSH_GET_HOOKNUM(hooknum),
                                    skb, in, out, okfn);

}

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
/* Netfilter nf_hookfn() wrapper function for IPv6 packets. */
static unsigned int
ssh_interceptor_packet_out_ipv6(SshNfHooknum hooknum,
                                SshHookSkb *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn) (struct sk_buff *))
{
  struct sk_buff *skbp = SSH_HOOK_SKB_PTR(skb);











  if (skbp->dev == NULL)
    skbp->dev = skb_dst(skbp)->dev;
  return ssh_interceptor_packet_out(PF_INET6, SSH_GET_HOOKNUM(hooknum),
                                    skb, in, out, okfn);

}
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */


/**************** Sending packets ******************************************/

/* Netfilter okfn() for sending packets to network after
   SSH_NF_IP_FORWARD hook traversal. This function is also called for
   packets which have the SSH_PACKET_UNMODIFIED flag set. Packets sent
   to network via this function may cause a recursive call to outbound
   netfilter hooks. */
static inline int
ssh_interceptor_send_to_network(int pf, struct sk_buff *skbp)
{
  skbp->pkt_type = PACKET_OUTGOING;

#ifdef CONFIG_NETFILTER_DEBUG
#endif /* CONFIG_NETFILTER_DEBUG */

  SSH_LINUX_STATISTICS(ssh_interceptor_context,
  {
    ssh_interceptor_context->stats.num_packets_sent++;
    ssh_interceptor_context->stats.num_bytes_sent += (SshUInt64) skbp->len;
  });





#ifdef SSH_LINUX_NF_POST_ROUTING_AFTER_ENGINE
  /* Traverse lower priority netfilter hooks. */
  switch (pf)
    {
    case PF_INET:
      SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP_POST_ROUTING", skbp));
      return NF_HOOK_THRESH(PF_INET, SSH_NF_IP_POST_ROUTING, skbp,
                            NULL, skbp->dev,
                            ssh_interceptor_context->nf->
                            linux_fn.ip_finish_output,
                            ssh_nf_out4.priority + 1);

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      SSH_DEBUG(SSH_D_LOWOK,
                ("Passing skb 0x%p to NF_IP6_POST_ROUTING", skbp));
      return NF_HOOK_THRESH(PF_INET6, SSH_NF_IP6_POST_ROUTING, skbp,
                            NULL, skbp->dev,
                            ssh_interceptor_context->nf->
                            linux_fn.ip6_output_finish,
                            ssh_nf_out6.priority + 1);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    default:
      break;
    }

#else /* SSH_LINUX_NF_POST_ROUTING_AFTER_ENGINE */
  /* Pass packet to output path. */
  switch (pf)
    {
    case PF_INET:
      SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip_finish_output", skbp));
      return (*ssh_interceptor_context->nf->linux_fn.ip_finish_output)(skbp);

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case PF_INET6:
      SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip6_output_finish", skbp));
      return (*ssh_interceptor_context->nf->linux_fn.ip6_output_finish)(skbp);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    default:
      break;
    }
#endif /* SSH_LINUX_NF_POST_ROUTING_AFTER_ENGINE */

  SSH_NOTREACHED;
  dev_kfree_skb_any(skbp);
  return -EPERM;
}

static inline int
ssh_interceptor_send_to_network_ipv4(struct sk_buff *skbp)
{
  return ssh_interceptor_send_to_network(PF_INET, skbp);
}

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
static inline int
ssh_interceptor_send_to_network_ipv6(struct sk_buff *skbp)
{
  return ssh_interceptor_send_to_network(PF_INET6, skbp);
}
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

/* ssh_interceptor_send_internal() sends a packet to the network or to the
   protocol stacks.  This will eventually free the packet by calling
   ssh_interceptor_packet_free.  The packet header should not be
   touched once this function has been called.

   ssh_interceptor_send() function for both media level and IP level
   interceptor. This grabs a packet with media layer headers attached
   and sends it to the interface defined by 'pp->ifnum_out'. */
static void
ssh_interceptor_send_internal(SshInterceptor interceptor,
                              SshInterceptorPacket pp,
                              size_t media_header_len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  struct net_device *dev = NULL;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifdef SSH_LINUX_NF_FORWARD_AFTER_ENGINE
  struct net_device *in_dev = NULL;
#endif /* SSH_LINUX_NF_FORWARD_AFTER_ENGINE */
#endif /*SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  unsigned char *neth;
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  size_t offset;
  SshUInt8 ipproto;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

  SSH_INTERCEPTOR_STACK_MARK();

#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("sending packet to %s, "
             "length %d flags 0x%08x ifnum_out %d protocol %s[0x%x]"
             " routing instance=%d",
             ((pp->flags & SSH_PACKET_FROMPROTOCOL) ? "network" :
              ((pp->flags & SSH_PACKET_FROMADAPTER) ? "stack" :
               "nowhere")),
             ipp->skb->len, pp->flags, pp->ifnum_out,
             (pp->protocol == SSH_PROTOCOL_IP4 ? "ipv4" :
              (pp->protocol == SSH_PROTOCOL_IP6 ? "ipv6" :
               (pp->protocol == SSH_PROTOCOL_ARP ? "arp" :
                (pp->protocol == SSH_PROTOCOL_ETHERNET ? "ethernet" :
                 "unknown")))),
             pp->protocol, pp->routing_instance_id));

  if (ssh_interceptor_packet_hexdump(ipp) == FALSE)
    {
      pp = NULL;
      goto error;
    }
#endif /* DEBUG_LIGHT */

  /* Assert correct context */
  SSH_ASSERT(in_irq() == 0);
  SSH_ASSERT(in_softirq());

  /* Require that any references to previous devices
     were released by the entrypoint hooks. */
  SSH_ASSERT(ipp->skb->dev == NULL);

  /* Map 'pp->ifnum_out' to a net_device.
     This will dev_hold() the net_device. */
  dev = ssh_interceptor_ifnum_to_netdev(interceptor, pp->ifnum_out);
  if (dev == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Interface %d has disappeared, dropping packet 0x%p",
                 pp->ifnum_out, ipp->skb));
      goto error;
    }
  ipp->skb->dev = dev;

  /* Try to set the VRF into skbuff. It is ok to fail, since all the packets
     do not have sockets assigned and then we just pass the packet with
     device information set. */
  if (ssh_skb_set_vrf_by_id(ipp->skb, pp->routing_instance_id) < 0)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Failed to set SKB VRF information in send (%d), relying on"
               "device information.", pp->routing_instance_id));

  /* Verify that packet has enough headroom to be sent out via `skb->dev'. */
  ipp->skb =
    ssh_interceptor_packet_verify_headroom(ipp->skb, media_header_len);
  if (ipp->skb == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Could not add headroom to skbp, dropping packet 0x%p",
                 ipp->skb));
      goto error;
    }

#ifdef INTERCEPTOR_IP_ALIGNS_PACKETS
  /* Align IP header to word boundary. */
  if (!ssh_interceptor_packet_align(pp, media_header_len))
    {
      pp = NULL;
      goto error;
    }
#endif /* INTERCEPTOR_IP_ALIGNS_PACKETS */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
#ifdef SSH_LINUX_FWMARK_EXTENSION_SELECTOR
  /* Copy the linux nfmark from the extension slot indexed by
     SSH_LINUX_FWMARK_EXTENSION_SELECTOR. */
  SSH_SKB_MARK(ipp->skb) = pp->extension[SSH_LINUX_FWMARK_EXTENSION_SELECTOR];
#endif /* SSH_LINUX_FWMARK_EXTENSION_SELECTOR */
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Check if the engine has cleared the SSH_PACKET_HWCKSUM flag.

     This means that for packets going to stack, the skb->csum in undefined
     and the stack needs to calculate and verify the checksum from packet data.
     For packets going to network, the checksum in packet data has been
     calculated and the nic driver does not need to do anything.

     Note that if SSH_PACKET_HWCKSUM is set, then the engine has not modified
     packet data as far as checksumming is considered and the skb->ip_summed
     specifies in more detail what the stack or nic driver should do with
     skb->csum. See linux_packet.c for cases where SSH_PACKET_HWCKSUM is set
     for a packet. */
  if ((pp->flags & SSH_PACKET_HWCKSUM) == 0)
    ipp->skb->ip_summed = CHECKSUM_NONE;

  /* Clear control buffer, as packet contents might have changed. */
  if ((pp->flags & SSH_PACKET_UNMODIFIED) == 0)
    memset(ipp->skb->cb, 0, sizeof(ipp->skb->cb));





  /* Send to network */
  if (pp->flags & SSH_PACKET_FROMPROTOCOL)
    {
      /* Network header pointer is required by tcpdump. */
      SSH_SKB_SET_NETHDR(ipp->skb, ipp->skb->data + media_header_len);

      /* Let unmodified packets pass on as if they were never intercepted.
         Note that this expects that skb->dst has not been cleared or modified
         during Engine processing. */
      if (pp->flags & SSH_PACKET_UNMODIFIED)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Passing unmodified packet to network"));

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          /* Remove the media header that was prepended to the packet
             in the inbound netfilter hook. Update skb->protocol and
             pp->protocol. */
          if (media_header_len > 0)
            {
              SSH_ASSERT(ipp->skb->len >= media_header_len);
              SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);
              ipp->skb->protocol = ssh_ethertype_to_skb_proto(pp->protocol,
                                                              media_header_len,
                                                              ipp->skb->data);
              skb_pull(ipp->skb, media_header_len);
              if (ntohs(ipp->skb->protocol) == ETH_P_IP)
                pp->protocol = SSH_PROTOCOL_IP4;
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
              else if (ntohs(ipp->skb->protocol) == ETH_P_IPV6)
                pp->protocol = SSH_PROTOCOL_IP6;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */
              else
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Invalid skb protocol %d, dropping packet",
                             ntohs(ipp->skb->protocol)));
                  goto error;
                }
            }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

          if (skb_dst(ipp->skb) == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Invalid skb->dst, dropping packet"));
              goto error;
            }

          /* Send packet to network. Note that this may cause recursive
             calls to the outbound netfilter hooks because the packet
             may trigger IPv6 neighbour discovery. */
          switch (pp->protocol)
            {
            case SSH_PROTOCOL_IP4:
              SSH_LINUX_STATISTICS(interceptor,
                                   { interceptor->stats.num_passthrough++; });
              ssh_interceptor_send_to_network_ipv4(ipp->skb);
              break;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
            case SSH_PROTOCOL_IP6:
              SSH_LINUX_STATISTICS(interceptor,
                                   { interceptor->stats.num_passthrough++; });
              ssh_interceptor_send_to_network_ipv6(ipp->skb);
              break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

            default:
              SSH_DEBUG(SSH_D_ERROR,
                        ("pp->protocol 0x%x ipp->skb->protocol 0x%x",
                         pp->protocol, ipp->skb->protocol));
              SSH_NOTREACHED;
              goto error;
            }

          /* All done for unmodified packet. */
          goto sent;
        }

      /* Clear local_df */
      SSH_SKB_IS_LOCAL_DF_ALLOWED(ipp->skb) = 0;

      /* Clear rxhash, it used also for tx hashing */
      SSH_SKB_SET_HASH(ipp->skb, 0);
      SSH_SKB_SET_L4_HASH(ipp->skb, 0);

      /* Mac header pointer is required by iptables */
      SSH_ASSERT(media_header_len <= ipp->skb->len);
      SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);

#ifdef DEBUG_LIGHT
      if (
          ipp->skb->ip_summed == CHECKSUM_PARTIAL
          )
        SSH_DEBUG(SSH_D_LOWOK, ("Hardware performs checksumming."));
      else if (ipp->skb->ip_summed == CHECKSUM_NONE)
        SSH_DEBUG(SSH_D_LOWOK, ("Checksum calculated in software."));
      else
        SSH_DEBUG(SSH_D_LOWOK, ("No checksumming required."));
#endif /* DEBUG_LIGHT */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      /* The usermode engine/interceptor interface does not perform
         the necessary interface-lookups to make the "receive IP" ->
         "send media layer" stuff work, so if YOU are running a
         quicksec_usermode engine, and the usermode engine has not
         connected yet, then this will cause crap to be sent into
         the network. If you wish to use the usermode engine in a
         production environment, then you should use
         SSH_IPSEC_IP_ONLY_INTERCEPTOR. */

      /* Media level */

      /* Set ipp->skb->protocol */
      SSH_ASSERT(skb_headlen(ipp->skb) >= media_header_len);
      ipp->skb->protocol = ssh_ethertype_to_skb_proto(pp->protocol,
                                                      media_header_len,
                                                      ipp->skb->data);

      SSH_LINUX_STATISTICS(interceptor,
      {
        interceptor->stats.num_packets_sent++;
        interceptor->stats.num_bytes_sent += (SshUInt64) ipp->skb->len;
      });

      /* Pass packet to network device driver. */
      SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to dev_queue_xmit()",
                              ipp->skb));
      dev_queue_xmit(ipp->skb);

      /* All done. */
      goto sent;

#else /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      /* IP level */

      /* Set ipp->skb->protocol */
      ipp->skb->protocol = ssh_proto_to_skb_proto(pp->protocol);

#ifdef SSH_LINUX_NF_FORWARD_AFTER_ENGINE

      /* Prepare to pass forwarded packets through
         SSH_NF_IP_FORWARD netfilter hook. */
      if (pp->flags & SSH_PACKET_FORWARDED)
        {
          /* Map 'pp->ifnum_in' to a net_device. */
          in_dev = ssh_interceptor_ifnum_to_netdev(interceptor, pp->ifnum_in);

          SSH_DEBUG(SSH_D_PCKDMP,
                    ("FWD 0x%04x/%d iface (%s[%d]->%s[%d]) length %d "
                     "%s dst 0x%08x",
                     ntohs(ipp->skb->protocol), pp->protocol,
                     (in_dev ? in_dev->name : "<none>"),
                     (in_dev ? in_dev->ifindex : -1),
                     (ipp->skb->dev ? ipp->skb->dev->name : "<none>"),
                     (ipp->skb->dev ? ipp->skb->dev->ifindex : -1),
                     ipp->skb->len,
                     SSH_LINUX_SKB_PKT_TYPE_RENDER(ipp->skb->pkt_type),
                     skb_dst(ipp->skb)));

          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Forwarding packet 0x%08x, len %d proto 0x%x [%s]",
                     ipp->skb, ipp->skb->len, ntohs(ipp->skb->protocol),
                     (pp->protocol == SSH_PROTOCOL_IP4 ? "ipv4" :
                      (pp->protocol == SSH_PROTOCOL_IP6 ? "ipv6" :
                       (pp->protocol == SSH_PROTOCOL_ARP ? "arp" :
                        "unknown")))));

          /* Change pkt_type to PACKET_HOST, which is expected
             in the SSH_NF_IP_FORWARD hook. It is set to PACKET_OUTGOING
             in ssh_interceptor_send_to_network_*() */
          ipp->skb->pkt_type = PACKET_HOST;
        }
#endif /* SSH_LINUX_NF_FORWARD_AFTER_ENGINE */

      SSH_ASSERT(media_header_len == 0);

      switch (pp->protocol)
        {
        case SSH_PROTOCOL_IP4:
          /* Set ipp->skb->dst */
          if (!ssh_interceptor_reroute_skb_ipv4(interceptor,
                                                ipp->skb,
                                                pp->route_selector,
                                                pp->ifnum_in,
                                                pp->routing_instance_id))
            {
              SSH_DEBUG(SSH_D_UNCOMMON,
                        ("Unable to reroute skb 0x%p", ipp->skb));
              goto error;
            }
          SSH_ASSERT(skb_dst(ipp->skb) != NULL);
#ifdef SSH_LINUX_NF_FORWARD_AFTER_ENGINE
          /* Pass forwarded packets to SSH_NF_IP_FORWARD netfilter hook */
          if (pp->flags & SSH_PACKET_FORWARDED)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP_FORWARD",
                                      ipp->skb));
              NF_HOOK(PF_INET, SSH_NF_IP_FORWARD, ipp->skb,
                      in_dev, ipp->skb->dev,
                      ssh_interceptor_send_to_network_ipv4);
            }
          /* Send local packets directly to network. */
          else
#endif /* SSH_LINUX_NF_FORWARD_AFTER_ENGINE */
            ssh_interceptor_send_to_network_ipv4(ipp->skb);
          break;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
        case SSH_PROTOCOL_IP6:
          /* Set ipp->skb->dst */
          if (!ssh_interceptor_reroute_skb_ipv6(interceptor,
                                                ipp->skb,
                                                pp->route_selector,
                                                pp->ifnum_in,
                                                pp->routing_instance_id))
            {
              SSH_DEBUG(SSH_D_UNCOMMON,
                        ("Unable to reroute skb 0x%p", ipp->skb));
              goto error;
            }
          SSH_ASSERT(skb_dst(ipp->skb) != NULL);
#ifdef SSH_LINUX_NF_FORWARD_AFTER_ENGINE
          /* Pass forwarded packets to SSH_NF_IP6_FORWARD netfilter hook */
          if (pp->flags & SSH_PACKET_FORWARDED)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP6_FORWARD",
                                      ipp->skb));
              NF_HOOK(PF_INET6, SSH_NF_IP6_FORWARD, ipp->skb,
                      in_dev, ipp->skb->dev,
                      ssh_interceptor_send_to_network_ipv6);
            }
          /* Send local packets directly to network. */
          else
#endif /* SSH_LINUX_NF_FORWARD_AFTER_ENGINE */
            ssh_interceptor_send_to_network_ipv6(ipp->skb);
          break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

        default:
          SSH_DEBUG(SSH_D_ERROR,
                    ("pp->protocol 0x%x ipp->skb->protocol 0x%x",
                     pp->protocol, ipp->skb->protocol));
          SSH_NOTREACHED;
          goto error;
        }

      /* All done. */
      goto sent;

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }

  /* Send to stack */
  else if (pp->flags & SSH_PACKET_FROMADAPTER)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SshUInt32 pkt_len4;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
      SshUInt32 pkt_len6;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

      /* Network header pointer is required by tcpdump. */
      SSH_SKB_SET_NETHDR(ipp->skb, ipp->skb->data + media_header_len);

      /* Let unmodified packets pass on as if they were never intercepted.
         Note that this expects that SSH_PACKET_UNMODIFIED packets are either
         IPv4 or IPv6. Currently there is no handling for ARP, as the Engine
         never sets SSH_PACKET_UNMODIFIED for ARP packets. */
      if (pp->flags & SSH_PACKET_UNMODIFIED)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Passing unmodified packet to stack"));

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          /* Remove the media header that was prepended to the packet
             in the inbound netfilter hook. Update skb->protocol and
             pp->protocol. */
          if (media_header_len > 0)
            {
              SSH_ASSERT(ipp->skb->len >= media_header_len);
              SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);
              ipp->skb->protocol = ssh_ethertype_to_skb_proto(pp->protocol,
                                                              media_header_len,
                                                              ipp->skb->data);
              skb_pull(ipp->skb, media_header_len);
              if (ntohs(ipp->skb->protocol) == ETH_P_IP)
                pp->protocol = SSH_PROTOCOL_IP4;
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
              else if (ntohs(ipp->skb->protocol) == ETH_P_IPV6)
                pp->protocol = SSH_PROTOCOL_IP6;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */
              else
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Invalid skb protocol %d, dropping packet",
                             ntohs(ipp->skb->protocol)));
                  goto error;
                }
            }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

          switch (pp->protocol)
            {
            case SSH_PROTOCOL_IP4:
              SSH_LINUX_STATISTICS(interceptor,
                                   { interceptor->stats.num_passthrough++; });
#ifdef SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP_PRE_ROUTING",
                                      ipp->skb));
              NF_HOOK_THRESH(PF_INET, SSH_NF_IP_PRE_ROUTING,
                             ipp->skb, ipp->skb->dev, NULL,
                             interceptor->nf->linux_fn.ip_rcv_finish,
                             ssh_nf_in4.priority + 1);
#else /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
              /* Call SSH_NF_IP_PREROUTING okfn() directly */
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip_rcv_finish",
                                      ipp->skb));
              (*interceptor->nf->linux_fn.ip_rcv_finish)(ipp->skb);
#endif /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
              break;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
            case SSH_PROTOCOL_IP6:
              SSH_LINUX_STATISTICS(interceptor,
                                   { interceptor->stats.num_passthrough++; });
#ifdef SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP6_PRE_ROUTING",
                                      ipp->skb));
              NF_HOOK_THRESH(PF_INET6, SSH_NF_IP6_PRE_ROUTING, ipp->skb,
                             ipp->skb->dev, NULL,
                             interceptor->nf->linux_fn.ip6_rcv_finish,
                             ssh_nf_out6.priority + 1);
#else /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
              /* Call SSH_NF_IP6_PREROUTING okfn() directly */
              SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip6_rcv_finish",
                                      ipp->skb));
              (*interceptor->nf->linux_fn.ip6_rcv_finish)(ipp->skb);
#endif /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
              break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

            default:
              SSH_DEBUG(SSH_D_ERROR,
                        ("pp->protocol 0x%x ipp->skb->protocol 0x%x",
                         pp->protocol, ipp->skb->protocol));
              SSH_NOTREACHED;
              goto error;
            }

          /* All done for unmodified packet. */
          goto sent;
        }

      /* If we do not wish to keep the broadcast state of
         the packet, then reset the pkt_type to PACKET_HOST. */
      if (!((ipp->skb->pkt_type == PACKET_MULTICAST
             || ipp->skb->pkt_type == PACKET_BROADCAST)
            && (pp->flags & SSH_PACKET_MEDIABCAST) != 0))
        ipp->skb->pkt_type = PACKET_HOST;

      /* Clear old routing decision */
      if (skb_dst(ipp->skb))
        {
          skb_dst_drop(ipp->skb);
        }

      /* If the packet has an associated SKB and that SKB is associated
         with a socket, orphan the skb from it's owner. These situations
         may arise when sending packets towards the protocol when
         the packet has been turned around by the engine. */
      skb_orphan(ipp->skb);

      /* Reset rxhash */
      SSH_SKB_SET_L4_HASH(ipp->skb, 0);
      SSH_SKB_SET_HASH(ipp->skb, 0);

      SSH_SKB_GET_HASH(ipp->skb);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR





      /* Media level */

      /* If the packet does not include a media level header (for
         example in case of pppoe), calling eth_type_trans() will
         corrupt the beginning of packet. Instead skb->protocol must
         be set from pp->protocol. */
      if (media_header_len == 0)
        {
          SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);
          ipp->skb->protocol = ssh_proto_to_skb_proto(pp->protocol);
        }
      else
        {
          /* Workaround for 802.2Q VLAN interfaces.
             Calling eth_type_trans() would corrupt these packets,
             as dev->hard_header_len includes the VLAN tag, but the
             packet does not. */
          if (ipp->skb->dev->priv_flags & IFF_802_1Q_VLAN)
            {
              struct ethhdr *ethernet;

              SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);
              ethernet = ssh_get_eth_hdr(ipp->skb);
              ipp->skb->protocol = ethernet->h_proto;
              skb_pull(ipp->skb, media_header_len);
            }

          /* For all other packets, call eth_type_trans() to
             set the protocol and the skb pointers. */
          else
            ipp->skb->protocol = eth_type_trans(ipp->skb, ipp->skb->dev);
        }
#else /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      /* IP level */

      /* Assert that the media_header_len is always zero. */
      SSH_ASSERT(media_header_len == 0);
      SSH_SKB_SET_MACHDR(ipp->skb, ipp->skb->data);
      ipp->skb->protocol = ssh_proto_to_skb_proto(pp->protocol);

#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef DEBUG_LIGHT
      if (ipp->skb->ip_summed == CHECKSUM_NONE)
        SSH_DEBUG(SSH_D_LOWOK, ("Checksum is verified in software"));
      else if (ipp->skb->ip_summed == CHECKSUM_UNNECESSARY)
        SSH_DEBUG(SSH_D_LOWOK, ("Hardware claims to have verified checksum"));
      else if (ipp->skb->ip_summed == CHECKSUM_PARTIAL)
        SSH_DEBUG(SSH_D_LOWOK, ("Hardware claims to have verified checksum"
                                " partially"));
      else if (
               ipp->skb->ip_summed == CHECKSUM_COMPLETE
               )
        SSH_DEBUG(SSH_D_LOWOK, ("Hardware has verified checksum, csum 0x%x",
                                SSH_SKB_CSUM(ipp->skb)));
      /* ip_summed is CHECKSUM_PARTIAL, this should never happen. */
      else
        SSH_DEBUG(SSH_D_ERROR, ("Invalid HW checksum flag %d",
                                ipp->skb->ip_summed));
#endif /* DEBUG_LIGHT */

      /* Set nh pointer */
      SSH_SKB_SET_NETHDR(ipp->skb, ipp->skb->data);
      switch(ntohs(ipp->skb->protocol))
        {
        case ETH_P_IP:
          neth = SSH_SKB_GET_NETHDR(ipp->skb);
          if (neth == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Could not access IP header"));
              goto error;
            }
          SSH_SKB_SET_TRHDR(ipp->skb, neth + SSH_IPH4_HLEN(neth) * 4);

#ifdef CONFIG_NETFILTER_DEBUG
#endif /* CONFIG_NETFILTER_DEBUG */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          /* Remove padding from packet. */
          pkt_len4 = SSH_IPH4_LEN(neth);
          SSH_ASSERT(pkt_len4 >= SSH_IPH4_HDRLEN && pkt_len4 <= 0xffff);
          if (pkt_len4 != ipp->skb->len)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Trimming skb down from %d to %d",
                                           ipp->skb->len, pkt_len4));
              skb_trim(ipp->skb, pkt_len4);
            }
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

          SSH_LINUX_STATISTICS(interceptor,
          {
            interceptor->stats.num_packets_sent++;
            interceptor->stats.num_bytes_sent += (SshUInt64) ipp->skb->len;
          });

#ifdef SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP_PRE_ROUTING",
                                  ipp->skb));
          NF_HOOK_THRESH(PF_INET, SSH_NF_IP_PRE_ROUTING,
                         ipp->skb, ipp->skb->dev, NULL,
                         interceptor->nf->linux_fn.ip_rcv_finish,
                         ssh_nf_in4.priority + 1);
#else /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          /* Call SSH_NF_IP_PREROUTING okfn() directly */
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip_rcv_finish",
                                  ipp->skb));
          (*interceptor->nf->linux_fn.ip_rcv_finish)(ipp->skb);
#endif /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          break;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
        case ETH_P_IPV6:
          neth = SSH_SKB_GET_NETHDR(ipp->skb);
          if (neth == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Could not access IPv6 header"));
              goto error;
            }

          ipproto = SSH_IPH6_NH(neth);
          pkt_len6 = SSH_IPH6_LEN(neth) + SSH_IPH6_HDRLEN;

          /* Parse hop-by-hop options and update IPv6 control buffer. */
          SSH_LINUX_IP6CB(ipp->skb)->iif = ipp->skb->dev->ifindex;
          SSH_LINUX_IP6CB(ipp->skb)->hop = 0;
          SSH_LINUX_IP6CB(ipp->skb)->ra = 0;
          SSH_LINUX_IP6CB(ipp->skb)->nhoff = SSH_IPH6_OFS_NH;

          offset = SSH_IPH6_HDRLEN;
          if (ipproto == SSH_IPPROTO_HOPOPT)
            {
              unsigned char *opt_ptr = neth + offset + 2;
              int opt_len;

              ipproto = SSH_IP6_EXT_COMMON_NH(neth + offset);
              offset += SSH_IP6_EXT_COMMON_LENB(neth + offset);

              while (opt_ptr < neth + offset)
                {
                  opt_len = opt_ptr[1] + 2;
                  switch (opt_ptr[0])
                    {
                      /* PAD0 */
                    case 0:
                      opt_len = 1;
                      break;

                      /* PADN */
                    case 1:
                      break;

                      /* Jumbogram */
                    case 194:
                      /* Take packet len from option (skb->len is zero). */
                      pkt_len6 = SSH_GET_32BIT(&opt_ptr[2])
                        + sizeof(struct ipv6hdr);
                      break;

                      /* Router alert */
                    case 5:
                      SSH_LINUX_IP6CB(ipp->skb)->ra = opt_ptr - neth;
                      break;

                      /* Unknown / unsupported */
                    default:
                      /* Just skip unknown options. */
                      break;
                    }
                  opt_ptr += opt_len;
                }
              SSH_LINUX_IP6CB(ipp->skb)->hop = sizeof(struct ipv6hdr);

              SSH_LINUX_IP6CB(ipp->skb)->nhoff = sizeof(struct ipv6hdr);
            }
          SSH_SKB_SET_TRHDR(ipp->skb, neth + offset);

          /* Remove padding from packet. */
          SSH_ASSERT(pkt_len6 >= sizeof(struct ipv6hdr));
          if (pkt_len6 != ipp->skb->len)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Trimming skb down from %d to %d",
                                           ipp->skb->len, pkt_len6));
              skb_trim(ipp->skb, pkt_len6);
            }

          SSH_LINUX_STATISTICS(interceptor,
          {
            interceptor->stats.num_packets_sent++;
            interceptor->stats.num_bytes_sent += (SshUInt64) ipp->skb->len;
          });

#ifdef SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_IP6_PRE_ROUTING",
                                  ipp->skb));
          NF_HOOK_THRESH(PF_INET6, SSH_NF_IP6_PRE_ROUTING, ipp->skb,
                         ipp->skb->dev, NULL,
                         interceptor->nf->linux_fn.ip6_rcv_finish,
                         ssh_nf_out6.priority + 1);
#else /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          /* Call SSH_NF_IP6_PREROUTING okfn() directly */
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to ip6_rcv_finish",
                                  ipp->skb));
          (*interceptor->nf->linux_fn.ip6_rcv_finish)(ipp->skb);
#endif /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
        case ETH_P_ARP:
          SSH_LINUX_STATISTICS(interceptor,
          {
            interceptor->stats.num_packets_sent++;
            interceptor->stats.num_bytes_sent += (SshUInt64) ipp->skb->len;
          });
#ifdef SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to NF_ARP_IN", ipp->skb));
          NF_HOOK_THRESH(SSH_NFPROTO_ARP, NF_ARP_IN,
                         ipp->skb, ipp->skb->dev, NULL,
                         interceptor->nf->linux_fn.arp_process,
                         ssh_nf_in_arp.priority + 1);
#else /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          /* Call NF_ARP_IN okfn() directly */
          SSH_DEBUG(SSH_D_LOWOK, ("Passing skb 0x%p to arp_process",
                                  ipp->skb));
          (*interceptor->nf->linux_fn.arp_process)(ipp->skb);
#endif /* SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE */
          break;
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

        default:
          SSH_DEBUG(SSH_D_ERROR,
                    ("skb->protocol 0x%x", htons(ipp->skb->protocol)));
          SSH_NOTREACHED;
          goto error;
        }

      /* All done. */
      goto sent;
    } /* SSH_PACKET_FROMADAPTER */

  else
    {
      /* Not SSH_PACKET_FROMPROTOCOL or SSH_PACKET_FROMADAPTER. */
      SSH_DEBUG(SSH_D_ERROR, ("Invalid packet direction flags"));
      SSH_NOTREACHED;
      goto error;
    }

 sent:
  SSH_DEBUG(SSH_D_LOWOK, ("Completed sending skb 0x%p", ipp->skb));
  ipp->skb = NULL;

 out:
  /* In debug build 'pp' may have been set to NULL. */
  /* coverity[check_after_deref] */
  if (pp)
    ssh_interceptor_packet_free(pp);

  /* Release net_device */
  if (dev)
    ssh_interceptor_release_netdev(dev);

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#ifdef SSH_LINUX_NF_FORWARD_AFTER_ENGINE
  /* Release inbound net_device that was used for
     FORWARD NF_HOOK traversal. */
  if (in_dev)
    ssh_interceptor_release_netdev(in_dev);
#endif /* SSH_LINUX_NF_FORWARD_AFTER_ENGINE */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  return;

 error:
  SSH_LINUX_STATISTICS(interceptor, { interceptor->stats.num_errors++; });
  goto out;
}

void
ssh_interceptor_send(SshInterceptor interceptor,
                     SshInterceptorPacket pp,
                     size_t media_header_len)
{
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  SshCpuContext cpu_ctx;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  SSH_ASSERT(in_irq() == 0);
  SSH_ASSERT(in_softirq());

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Check if we need to put the packet to send queue for unwinding stack.

     Packets sent to network never loop back synchronously to inbound hook,
     but may cause a recursive call to outbound hook (IPv6 ndisc).

     Note that the cpu MAY be executing an engine call either from inbound
     or outbound netfilter hook, or a timeout or ipm channel callback (in
     which case in_engine is 1), or the cpu MAY be continuing en engine
     call after hardware accelerator operation has completed (in which
     case in_engine is 0 and the packet may be sent to stack directly). */
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  if (cpu_ctx->in_engine == 1)
    {
      SSH_ASSERT(cpu_ctx->in_engine == 1);
      interceptor_send_queue_put(cpu_ctx, pp, media_header_len);
    }
  else
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
    ssh_interceptor_send_internal(interceptor, pp, media_header_len);
}

/******************************************************* General init/uninit */

/* Interceptor hook init. Utility function to initialize
   individual hooks. */
static Boolean
ssh_interceptor_hook_init(struct SshLinuxHooksRec *hook)
{
  int rval;

  SSH_ASSERT(hook->is_registered == FALSE);

  if (hook->pf == PF_INET && hook->hooknum == SSH_NF_IP_PRE_ROUTING)
    hook->priority = in_priority;

  if (hook->pf == PF_INET && hook->hooknum == SSH_NF_IP_POST_ROUTING)
    hook->priority = out_priority;

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  if (hook->pf == PF_INET6 && hook->hooknum == SSH_NF_IP6_PRE_ROUTING)
    hook->priority = in6_priority;

  if (hook->pf == PF_INET6 && hook->hooknum == SSH_NF_IP6_POST_ROUTING)
    hook->priority = out6_priority;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

  hook->ops->hook = hook->hookfn;
  hook->ops->pf = hook->pf;
  hook->ops->hooknum = hook->hooknum;
  hook->ops->priority = hook->priority;

  rval = nf_register_hook(hook->ops);
  if (rval < 0)
    {
      if (hook->is_mandatory)
        {
          printk(KERN_ERR
                 "INSIDE Secure QuickSec netfilter %s"
                 " hook failed to install.\n",
                 hook->name);
          return FALSE;
        }
      return TRUE;
    }

  hook->is_registered=TRUE;
  return TRUE;
}

/* Utility function for uninstalling a single netfilter hook. */
static void
ssh_interceptor_hook_uninit(struct SshLinuxHooksRec *hook)
{
  if (hook->is_registered == FALSE)
    return;

  nf_unregister_hook(hook->ops);

  hook->is_registered = FALSE;
}

/* IP/Network glue initialization. This must be called only
   after the engine has "opened" the interceptor, and packet_callback()
   has been set to a valid value. */
Boolean
ssh_interceptor_ip_glue_init(SshInterceptor interceptor)
{
  int i;

  SSH_ASSERT(!in_softirq());

  /* Verify that the hooks haven't been initialized yet. */
  if (interceptor->nf->hooks_installed)
    {
      ssh_warning("init called when hooks are initialized already.\n");
      return TRUE;
    }

  /* Register all hooks */
  for (i = 0; ssh_nf_hooks[i].name != NULL; i++)
    {
      if (ssh_interceptor_hook_init(&ssh_nf_hooks[i]) == FALSE)
        goto fail;
    }

  interceptor->nf->hooks_installed = TRUE;
  return TRUE;

 fail:
  for (i = 0; ssh_nf_hooks[i].name != NULL; i++)
    ssh_interceptor_hook_uninit(&ssh_nf_hooks[i]);
  return FALSE;
}

/* Uninitialization of netfilter glue. */
Boolean
ssh_interceptor_ip_glue_uninit(SshInterceptor interceptor)
{
  int i;

  SSH_ASSERT(!in_softirq());

  /* Note that we do not perform concurrency control here!
     We expect that we are essentially running single-threaded
     in init/shutdown! */

  if (interceptor->nf->hooks_installed == FALSE)
    return TRUE;

  /* Unregister netfilter hooks */
  for (i = 0; ssh_nf_hooks[i].name != NULL; i++)
    ssh_interceptor_hook_uninit(&ssh_nf_hooks[i]);

  interceptor->nf->hooks_installed = FALSE;

  return TRUE;
}

#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */
