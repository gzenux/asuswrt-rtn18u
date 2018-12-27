/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common internal declarations for linux interceptor.
*/

#ifndef LINUX_INTERNAL_H
#define LINUX_INTERNAL_H

#ifndef SSH_IS_MAIN_MODULE
#define __NO_VERSION__
#endif /* !SSH_IS_MAIN_MODULE */

#include "sshincludes.h"

/* Parameters used to tune the interceptor. */
#include "linux_versions.h"
#include "linux_params.h"

#ifdef SSHDIST_QUICKSEC
#ifdef SSH_BUILD_IPSEC
#include "ipsec_params.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_QUICKSEC */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/pkt_sched.h>

#include <linux/interrupt.h>
#include <linux/inetdevice.h>

#include <net/ip.h>
#include <net/inet_common.h>
#include <net/flow.h>

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
#include <net/ipv6.h>
#include <net/addrconf.h>
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#include <linux/if_arp.h>
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_arp.h>

#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/cpumask.h>

#include <linux/if_addr.h>

#include "engine.h"
#include "kernel_includes.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "interceptor.h"
#include "sshinet.h"
#include "sshdebug.h"
#include "sshadt.h"

#include "linux_packet_internal.h"
#include "linux_mutex_internal.h"

#include <linux/threads.h>

#ifdef SSHDIST_QUICKSEC
#ifdef SSH_BUILD_IPSEC
#include "linux_nf_internal.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_QUICKSEC */


/****************************** Sanity checks ********************************/

#ifndef MODULE
#error "Quicksec can only be compiled as a MODULE"
#endif /* MODULE */

#ifndef CONFIG_NETFILTER
#error "Kernel is not compiled with CONFIG_NETFILTER"
#endif /* CONFIG_NETFILTER */

/* Check VRF kernel flags */
#ifdef HAVE_MVL_VRF
#ifndef CONFIG_VRF
#error "Kernel is not compiled with CONFIG_VRF"
#endif /* CONFIG_VRF */
#endif /* HAVE_MVL_VRF */

#ifdef HAVE_WRL_VRF
#ifndef CONFIG_VIRTUAL_ROUTING
#error "Kernel is not compiled with CONFIG_VIRTUAL_ROUTING"
#endif /* CONFIG_VIRTUAL_ROUTING */
#endif /* HAVE_WRL_VRF */

/* Check that SSH_LINUX_FWMARK_EXTENSION_SELECTOR is in range. */
#ifdef SSH_LINUX_FWMARK_EXTENSION_SELECTOR
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
#if (SSH_LINUX_FWMARK_EXTENSION_SELECTOR >= \
     SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS)
#error "Invalid value specified for SSH_LINUX_FWMARK_EXTENSION_SELECTOR"
#endif
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
#endif /* SSH_LINUX_FWMARK_EXTENSION_SELECTOR */


/****************************** Internal defines *****************************/

#define SSH_LINUX_INTERCEPTOR_NR_CPUS NR_CPUS

/********************** Kernel version specific wrapper macros ***************/

#define SSH_LINUX_DEV_GET_FLAGS(dev) dev_get_flags(dev)

typedef struct sk_buff SshHookSkb;
#define SSH_HOOK_SKB_PTR(_skb) _skb

#define SSH_SKB_MARK(__skb) ((__skb)->mark)

#define SSH_LINUX_DST_MTU(__dst) (dst_mtu((__dst)))

/* For 2.6.24 -> kernels */
#define SSH_FIRST_NET_DEVICE(net)     first_net_device(net)
#define SSH_NEXT_NET_DEVICE(_dev)  next_net_device(_dev)


#define SSH_DEV_GET_BY_INDEX(_i) dev_get_by_index(&init_net, (_i))

/* On new kernel versions the skb->end, skb->tail, skb->network_header,
   skb->mac_header, and skb->transport_header are either pointers to
   skb->data (on 32bit platforms) or offsets from skb->data
   (on 64bit platforms). */

#define SSH_SKB_GET_END(__skb) (skb_end_pointer((__skb)))

#define SSH_SKB_GET_TAIL(__skb) (skb_tail_pointer((__skb)))
#define SSH_SKB_SET_TAIL(__skb, __ptr) \
   (skb_set_tail_pointer((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_TAIL(__skb) (skb_reset_tail_pointer((__skb)))

#define SSH_SKB_GET_NETHDR(__skb) (skb_network_header((__skb)))
#define SSH_SKB_SET_NETHDR(__skb, __ptr) \
   (skb_set_network_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_NETHDR(__skb) (skb_reset_network_header((__skb)))

#define SSH_SKB_GET_MACHDR(__skb) (skb_mac_header((__skb)))
#define SSH_SKB_SET_MACHDR(__skb, __ptr) \
   (skb_set_mac_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_MACHDR(__skb) (skb_reset_mac_header((__skb)))

#define SSH_SKB_GET_TRHDR(__skb) (skb_transport_header((__skb)))
#define SSH_SKB_SET_TRHDR(__skb, __ptr) \
   (skb_set_transport_header((__skb), (__ptr) - (__skb)->data))
#define SSH_SKB_RESET_TRHDR(__skb) (skb_reset_transport_header((__skb)))


/* On linux-2.6.20 and later skb->csum is split into
   a union of csum and csum_offset. */
#define SSH_SKB_CSUM_OFFSET(__skb) ((__skb)->csum_offset)
#define SSH_SKB_CSUM(__skb) ((__skb)->csum)


#define SSH_NF_IP_PRE_ROUTING NF_INET_PRE_ROUTING
#define SSH_NF_IP_LOCAL_IN NF_INET_LOCAL_IN
#define SSH_NF_IP_FORWARD NF_INET_FORWARD
#define SSH_NF_IP_LOCAL_OUT NF_INET_LOCAL_OUT
#define SSH_NF_IP_POST_ROUTING NF_INET_POST_ROUTING
#define SSH_NF_IP_PRI_FIRST INT_MIN

#define SSH_NF_IP6_PRE_ROUTING NF_INET_PRE_ROUTING
#define SSH_NF_IP6_LOCAL_IN NF_INET_LOCAL_IN
#define SSH_NF_IP6_FORWARD NF_INET_FORWARD
#define SSH_NF_IP6_LOCAL_OUT NF_INET_LOCAL_OUT
#define SSH_NF_IP6_POST_ROUTING NF_INET_POST_ROUTING
#define SSH_NF_IP6_PRI_FIRST INT_MIN


#ifdef LINUX_HAS_NFPROTO_ARP
#define SSH_NFPROTO_ARP NFPROTO_ARP
#else /* LINUX_HAS_NFPROTO_ARP */
#define SSH_NFPROTO_ARP NF_ARP
#endif /* LINUX_HAS_NFPROTO_ARP */

#ifdef LINUX_NF_HOOK_FIRST_ARG_IS_OPS
typedef const struct nf_hook_ops * SshNfHooknum;
#define SSH_GET_HOOKNUM(_arg) ((_arg)->hooknum)
#else /* LINUX_NF_HOOK_FIRST_ARG_IS_OPS */
typedef unsigned int SshNfHooknum;
#define SSH_GET_HOOKNUM(_arg) ((_arg))
#endif /* LINUX_NF_HOOK_FIRST_ARG_IS_OPS */

#ifdef LINUX_HAS_SKB_RXHASH
#define SSH_SKB_SET_HASH(_skb, a) ((_skb)->rxhash = a)
#else /* LINUX_HAS_SKB_RXHASH */
#ifdef LINUX_HAS_SKB_HASH
#define SSH_SKB_SET_HASH(_skb, a) ((_skb)->hash = a)
#else /* LINUX_HAS_SKB_HASH */
#define SSH_SKB_SET_HASH(_skb, a)
#endif /* LINUX_HAS_SKB_HASH */
#endif /* LINUX_HAS_SKB_RXHASH */

#ifdef LINUX_HAS_SKB_L4_RXHASH
#define SSH_SKB_SET_L4_HASH(_skb, a) ((_skb)->rxhash = a)
#else /* LINUX_HAS_SKB_L4_RXHASH */
#ifdef LINUX_HAS_SKB_L4_HASH
#define SSH_SKB_SET_L4_HASH(_skb, a) ((_skb)->hash = a)
#else /* LINUX_HAS_SKB_L4_HASH */
#define SSH_SKB_SET_L4_HASH(_skb, a)
#endif /* LINUX_HAS_SKB_L4_HASH */
#endif /* LINUX_HAS_SKB_L4_RXHASH */

#ifdef LINUX_HAS_SKB_GET_RXHASH
#define SSH_SKB_GET_HASH(_skb) skb_get_rxhash((_skb))
#else /* LINUX_HAS_SKB_GET_RXHASH */
#ifdef LINUX_HAS_SKB_GET_HASH
#define SSH_SKB_GET_HASH(_skb) skb_get_hash((_skb))
#else /* LINUX_HAS_SKB_GET_HASH */
#define SSH_SKB_GET_HASH(_skb)
#endif /* LINUX_HAS_SKB_GET_HASH */
#endif /* LINUX_HAS_SKB_GET_RXHASH */

/*
  Since 2.6.31 there is now skb->dst pointer and
  functions skb_dst() and skb_dst_set() should be used.

  The code is modified to use the functions. For older
  version corresponding macros are defined.
 */
#ifndef LINUX_HAS_SKB_DST_FUNCTIONS

#define skb_dst(__skb) ((__skb)->dst)
#define skb_dst_set(__skb, __dst) ((void)((__skb)->dst = (__dst)))

#define skb_dst_drop(__skb)                        \
  do {                                             \
    struct sk_buff *___skb_p = (__skb);            \
    dst_release(skb_dst((___skb_p)));              \
    skb_dst_set((___skb_p), NULL);                 \
  } while (0)

#endif /* !LINUX_HAS_SKB_DST_FUNCTIONS */

#ifdef LINUX_HAS_SKB_FRAG_PAGE
#define SSH_SKB_FRAG_PAGE(_frag) skb_frag_page((_frag))
#else /* LINUX_HAS_SKB_FRAG_PAGE */
#define SSH_SKB_FRAG_PAGE(_frag) (_frag)->page
#endif /* LINUX_HAS_SKB_FRAG_PAGE */

#ifdef LINUX_HAS_DST_NEIGHBOUR_FUNCTIONS

#define SSH_DST_NEIGHBOUR_READ_LOCK() rcu_read_lock()
#define SSH_DST_NEIGHBOUR_READ_UNLOCK() rcu_read_unlock()
#define SSH_DST_SET_NEIGHBOUR(_dst, _neigh) dst_set_neighbour((_dst), (_neigh))
#ifdef LINUX_USE_DST_GET_NEIGHBOUR_NOREF
#define SSH_DST_GET_NEIGHBOUR(_dst) dst_get_neighbour_noref((_dst))
#else  /* LINUX_USE_DST_GET_NEIGHBOUR_NOREF */
#define SSH_DST_GET_NEIGHBOUR(_dst) dst_get_neighbour((_dst))
#endif /* LINUX_USE_DST_GET_NEIGHBOUR_NOREF */

#else /* LINUX_HAS_DST_NEIGHBOUR_FUNCTIONS */

#define SSH_DST_NEIGHBOUR_READ_LOCK() do { } while (0)
#define SSH_DST_NEIGHBOUR_READ_UNLOCK() do { } while (0)
#define SSH_DST_GET_NEIGHBOUR(_dst) (_dst)->neighbour
#define SSH_DST_SET_NEIGHBOUR(_dst, _neigh)     \
  do {                                          \
    (_dst)->neighbour = (_neigh);               \
  } while (0)
#endif /* LINUX_HAS_DST_NEIGHBOUR_FUNCTIONS */


#define SSH_FOR_EACH_POSSIBLE_CPU(__cpu) for_each_possible_cpu(__cpu)

/* These HAVE_* defines were removed in linux-2.6.34 but the corresponding
   functions are in net_device_ops. */
#ifdef LINUX_HAS_NETDEV_NDO_CHANGE_RX_FLAGS
#ifndef HAVE_CHANGE_RX_FLAGS
#define HAVE_CHANGE_RX_FLAGS 1
#endif /* HAVE_CHANGE_RX_FLAGS */
#endif /* LINUX_HAS_NETDEV_NDO_CHANGE_RX_FLAGS */

#ifdef LINUX_HAS_NETDEV_NDO_SET_RX_MODE
#ifndef HAVE_SET_RX_MODE
#define HAVE_SET_RX_MODE 1
#endif /* HAVE_SET_RX_MODE */
#endif /* LINUX_HAS_NETDEV_NDO_SET_RX_MODE */

#ifdef LINUX_HAS_NETDEV_NDO_SET_MULTICAST_LIST
#ifndef HAVE_MULTICAST
#define HAVE_MULTICAST 1
#endif /* HAVE_MULTICAST */
#endif /* LINUX_HAS_NETDEV_NDO_SET_MULTICAST_LIST */

/* This HAVE_NET_DEVICE_OPS was removed in 3.1.x */
#ifdef LINUX_HAS_NET_DEVICE_OPS
#ifndef HAVE_NET_DEVICE_OPS
#define HAVE_NET_DEVICE_OPS 1
#endif /* HAVE_NET_DEVICE_OPS */
#endif /* LINUX_HAS_NET_DEVICE_OPS */

#ifdef LINUX_RT_DST_IS_NOT_IN_UNION
#define SSH_RT_DST(_rt) ((_rt)->dst)
#else /* LINUX_RT_DST_IS_NOT_IN_UNION */
#define SSH_RT_DST(_rt) ((_rt)->u.dst)
#endif /* LINUX_RT_DST_IS_NOT_IN_UNION */

/* Starting from linux 2.6.35 the IPv6 address list needs to be iterated
   using the list_for_each_* macros. */
#ifdef LINUX_HAS_INET6_IFADDR_LIST_HEAD
#define SSH_INET6_IFADDR_LIST_FOR_EACH(item, next, list)                \
  list_for_each_entry_safe((item), (next), &(list), if_list)
#else /* LINUX_HAS_INET6_IFADDR_LIST_HEAD */
#define SSH_INET6_IFADDR_LIST_FOR_EACH(item, next, list)                \
  for ((item) = (list), (next) = NULL;                                  \
       (item) != NULL;                                                  \
       (item) = (item)->if_next)
#endif /* LINUX_HAS_INET6_IFADDR_LIST_HEAD */

#if defined(LINUX_DST_ALLOC_HAS_MANY_ARGS)
#define SSH_DST_ALLOC(_dst) dst_alloc((_dst)->ops, NULL, 0, 0, 0)
#elif defined(LINUX_DST_ALLOC_HAS_REFCOUNT)
#define SSH_DST_ALLOC(_dst) dst_alloc((_dst)->ops, 0)
#else
#define SSH_DST_ALLOC(_dst) dst_alloc((_dst)->ops)
#endif

/* From 3.6 kernels the metrics in dst_entry for IPv4 are no longer used */
#ifdef LINUX_IPV4_DST_USES_METRICS
#define SSH_LINUX_IPV4_DST_USES_METRICS 1
#else
#define SSH_LINUX_IPV4_DST_USES_METRICS 0
#endif

#ifdef LINUX_SSH_RTABLE_FIRST_MEMBER_RT_KEY_DST
#define SSH_RTABLE_FIRST_MEMBER(_rt) ((_rt)->rt_key_dst)
#elif defined(LINUX_SSH_RTABLE_FIRST_MEMBER_RT_GENID)
#define SSH_RTABLE_FIRST_MEMBER(_rt) ((_rt)->rt_genid)
#endif /* defined(LINUX_SSH_RTABLE_FIRST_ELEMENT_NEEDED) */

/* Linux 2.6.39 removed fl4_dst and fl6_dst defines. We like to use
   those so redefinig those for our purposes. */
#ifdef LINUX_FLOWI_NO_FL4_ACCESSORS
#define fl4_dst u.ip4.daddr
#define fl4_src u.ip4.saddr
#define fl4_tos u.ip4.__fl_common.flowic_tos
#define oif u.ip4.__fl_common.flowic_oif
#define proto u.ip4.__fl_common.flowic_proto
#define fl4_scope u.ip4.__fl_common.flowic_scope
#endif /* LINUX_FLOWI_NO_FL4_ACCESSORS */

#ifdef LINUX_FLOWI_NO_FL6_ACCESSORS
#define fl6_dst u.ip6.daddr
#define fl6_src u.ip6.saddr
#endif /* LINUX_FLOWI_NO_FL6_ACCESSORS */

/* procfs  functions */

#ifdef LINUX_HAS_PROC_SET_FUNCTIONS
#define PROC_REMOVE(pde, parent) proc_remove(pde)
#else
#define PROC_REMOVE(pde, parent) remove_proc_entry((pde)->name, (parent))
#endif /* LINUX_HAS_PROC_SET_FUNCTIONS */

#ifdef LINUX_LOCAL_DF_RENAMED
#define SSH_SKB_IS_LOCAL_DF_ALLOWED(_skb) ((_skb)->ignore_df)
#else /* LINUX_LOCAL_DF_RENAMED */
#define SSH_SKB_IS_LOCAL_DF_ALLOWED(_skb) ((_skb)->local_df)
#endif /* LINUX_LOCAL_DF_RENAMED */

/****************************** Statistics helper macros *********************/

#ifdef DEBUG_LIGHT

#define SSH_LINUX_STATISTICS(interceptor, block)         \
do                                                       \
  {                                                      \
    if ((interceptor))                                   \
      {                                                  \
        spin_lock_bh(&(interceptor)->statistics_lock);   \
        block;                                           \
        spin_unlock_bh(&(interceptor)->statistics_lock); \
      }                                                  \
  }                                                      \
while (0)

#else /* DEBUG_LIGHT */

#define SSH_LINUX_STATISTICS(interceptor, block)

#endif /* DEBUG_LIGHT */

/****************************** Interface handling ***************************/

/* Sanity check that the interface index 'ifnum' fits into
   the SshInterceptorIfnum data type. 'ifnum' may be equal to
   SSH_INTERCEPTOR_INVALID_IFNUM. */
#define SSH_LINUX_ASSERT_IFNUM(ifnum) \
SSH_ASSERT(((SshUInt32) (ifnum)) < ((SshUInt32) SSH_INTERCEPTOR_MAX_IFNUM) \
|| ((SshUInt32) (ifnum)) == ((SshUInt32) SSH_INTERCEPTOR_INVALID_IFNUM))

/* Sanity check that the interface index 'ifnum' is a valid
   SshInterceptorIfnum. */
#define SSH_LINUX_ASSERT_VALID_IFNUM(ifnum) \
SSH_ASSERT(((SshUInt32) (ifnum)) < ((SshUInt32) SSH_INTERCEPTOR_MAX_IFNUM) \
&& ((SshUInt32) (ifnum)) != ((SshUInt32) SSH_INTERCEPTOR_INVALID_IFNUM))


/****************************** Proc entries *********************************/

#define SSH_PROC_ENGINE "engine"
#define SSH_PROC_STATISTICS "statistics"
#define SSH_PROC_DEBUG "debug"
#define SSH_PROC_VERSION "version"

/* Ipm receive buffer size. This must be big enough to fit a maximum sized
   IP packet + internal packet data + ipm message header. There is only
   one receive buffer. */
#define SSH_LINUX_IPM_RECV_BUFFER_SIZE 66000

/* Ipm channel message structure. These structures are used for queueing
   messages from kernel to userspace. The maximum number of allocated messages
   is limited by SSH_LINUX_MAX_IPM_MESSAGES (in linux_params.h). */
typedef struct SshInterceptorIpmMsgRec
SshInterceptorIpmMsgStruct, *SshInterceptorIpmMsg;

struct SshInterceptorIpmMsgRec
{
  /* Send queue is doubly linked, freelist uses only `next'. */
  SshInterceptorIpmMsg next;
  SshInterceptorIpmMsg prev;

  SshUInt8 reliable : 1; /* message is reliable */
  SshUInt8 emergency_mallocated : 1;  /* message is allocated from heap */

  /* Offset for partially sent message */
  size_t offset;

  /* Message length and data. */
  size_t len;
  unsigned char *buf;
};

/* Ipm structure */
typedef struct SshInterceptorIpmRec
{
  /* RW lock for protecting the send message queue and the message freelist. */
  rwlock_t lock;

  /* Is ipm channel open */
  atomic_t open;

  /* Message freelist and number of allocated messages. */
  SshInterceptorIpmMsg msg_freelist;
  SshUInt32 msg_allocated;

  /* Output message queue */
  SshInterceptorIpmMsg send_queue;
  SshInterceptorIpmMsg send_queue_tail;

  /* Number of unreliable messages in the sed queue. */
  SshUInt32 send_queue_num_unreliable;

} SshInterceptorIpmStruct, *SshInterceptorIpm;


/* Structure for ipm channel /proc entry. */
typedef struct SshInterceptorIpmProcEntryRec
{
  /* /proc filesystem inode */
  struct proc_dir_entry *entry;

  /* RW lock for protecting the proc entry */
  rwlock_t lock;

  /* Is an userspace application using this entry */
  Boolean open;

  /* Is another read ongoing? When this is TRUE
     then `send_msg' is owned by the reader. */
  Boolean read_active;

  /* Is another write ongoing? When this is TRUE
     then `recv_buf' is owned by the writer. */
  Boolean write_active;

  /* Wait queue for blocking mode reads and writes. */
  wait_queue_head_t wait_queue;

  /* Output message under processing. */
  SshInterceptorIpmMsg send_msg;

  /* Input message length */
  size_t recv_len;

  /* Input message buffer */
  size_t recv_buf_size;
  unsigned char *recv_buf;

  /* Proc entry enabled? */
  Boolean enabled;
} SshInterceptorIpmProcEntryStruct, *SshInterceptorIpmProcEntry;


/* Structure for other /proc entries. */
typedef struct SshInterceptorProcEntryRec
{
  /* /proc filesystem entry */
  struct proc_dir_entry *entry;

  /* RW lock for protecting the proc entry */
  rwlock_t lock;

  /* Is an userspace application using this entry */
  Boolean open;

  /* Is another read or write ongoing? When this is TRUE
     then `buf' is owned by the reader/writer. */
  Boolean active;

  /* Number of bytes returned to the userpace application */
  size_t buf_len;

  /* Preallocated buffer for read and write operations. */
  char buf[1024];

  /* Proc entry enabled? */
  Boolean enabled;
} SshInterceptorProcEntryStruct, *SshInterceptorProcEntry;


/****************************** CPU related items ***************************/

#ifndef SSH_IPSEC_SEND_IS_SYNC
/* Send queue recursion elimination does two things:
   1. eliminates synchronous replies to outbound packets from the system
   protocol stack to protect against deadlocks in system protocol stack
   2. minimizes stack usage

   Send queue recursion elimination MUST be enabled on linux if the engine
   does not implement asynchronous sending (that is SSH_IPSEC_SEND_IS_SYNC
   is undefined). See the comments in linux_ip_glue.c for more detailed
   explanation of the recursion elimination logic. */
#define SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION 1

/* Engine queue recursion elimination reduce maximum stack height by
   delaying the processing of recursive outbound reply packets from the
   system protocol stack.

   Engine queue recursion elimination should not be needed unless there are
   problems with stack height. Engine queue recursion elimination requires
   that send queue recursion elimination is enabled. */
#ifdef MINIMAL_STACK
#define SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION 1
#warning "Userspace programs (like quicksecpm) must also be compiled with\
 MINIMAL_STACK defined."
#endif /* MINIMAL_STACK */
#endif /* !SSH_IPSEC_SEND_IS_SYNC */

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
typedef struct SshCpuContextRec
{
  /* Send queue */
  SshInterceptorPacket send_queue_head;
  SshInterceptorPacket send_queue_tail;
#ifdef DEBUG_LIGHT
  /* Queue length, used in asserts. */
  SshUInt32 send_queue_len;
#endif /* DEBUG_LIGHT */

#ifdef SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION
  /* Engine queue */
  SshInterceptorPacket engine_queue_head;
  SshInterceptorPacket engine_queue_tail;
#ifdef DEBUG_LIGHT
  /* Queue length, used in asserts. */
  SshUInt32 engine_queue_len;
#endif /* DEBUG_LIGHT */
#endif /* SSH_LINUX_ENGINE_QUEUE_RECURSION_ELIMINATION */

  /* Flags */
  SshUInt8 in_engine : 1;  /* Executing engine call */
  SshUInt8 in_send : 1;    /* Executing packet send */

} SshCpuContextStruct, *SshCpuContext;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

/****************************** Timeout items *******************************/

/* Maximum length of timeout freelist. When freelist length exceeds this
   value then the timeout is freed instead of returned to freelist. */
#define SSH_KERNEL_TIMEOUT_FREELIST_LENGTH 50

typedef struct SshKernelTimeoutRec SshKernelTimeoutStruct;
typedef struct SshKernelTimeoutRec  *SshKernelTimeout;

struct SshKernelTimeoutRec
{
  /* Timeout list pointers. */
  SshKernelTimeout next;
  SshKernelTimeout prev;

  /* Timeout expiry in jiffies. */
  unsigned long expires;

  /* Timeout callback. */
  SshKernelTimeoutCallback callback;
  void *context;

  /* Status flags */
  SshUInt8 remove_from_list : 1;
};

typedef struct SshTimeoutManagerRec
{
  /* Timeout list. */
  SshKernelTimeout timeout_list;
  SshKernelTimeout timeout_list_tail;

  /* Timeout freelist. */
  SshKernelTimeout timeout_freelist;
  SshUInt32 free_timeouts;
#ifdef DEBUG_LIGHT
  SshUInt32 allocated_timeouts;
#endif /* DEBUG_LIGHT */

  /* Timeout lock. */
  SshKernelMutex timeout_lock;

  /* Currently running timeout and cpu where it is run. */
  SshKernelTimeout running_timeout;
  unsigned int running_timeout_cpu;

  /* System timer. */
  struct timer_list timer;
  SshUInt8 system_timer_registered : 1;

  /* Status variables. */
  SshUInt8 timeouts_stopped : 1;
  SshUInt8 must_reschedule : 1;

  SshUInt32 pending_cancels;

} SshTimeoutManagerStruct, *SshTimeoutManager;


/****************************** Packet Freelist ******************************/

/* Maximum length of shared packet freelist. */
#define SSH_LINUX_INTERCEPTOR_PACKET_FREELIST_SIZE 0xffff

typedef struct SshInterceptorPacketFreelistRec
{
  /* Packet context freelist head pointer array. There is a freelist entry for
     each CPU and one freelist entry (with index SSH_LINUX_INTERCEPTOR_NR_CPUS)
     shared among all CPU's. When getting a packet, the current CPU freelist is
     searched, if that is empty the shared freelist is searched (which requires
     taking the packet_lock). When returning a packet, if the CPU is the same
     as when the packet was allocated, the packet is returned to the CPU
     freelist, if not it is returned to the shared freelist (which again
     requires taking a lock). */
  SshInterceptorInternalPacket head[SSH_LINUX_INTERCEPTOR_NR_CPUS + 1];

  /* The counters below are protected by packet_lock. */

  /* Length of shared freelist. If the shared list length exceeds
     SSH_LINUX_INTERCEPTOR_PACKET_FREELIST_SIZE then the packet is freed
     immediately, otherwise it is returned to the shared list. */
  int shared_list_length;
#ifdef DEBUG_LIGHT
  int allocated;
  int reused;
#endif /* DEBUG_LIGHT */
} SshInterceptorPacketFreelistStruct, *SshInterceptorPacketFreelist;

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
/****************************** Dst entry cache ******************************/
#define SSH_DST_ENTRY_TBL_SIZE 128
typedef struct SshDstEntryRec
{
  struct dst_entry *dst_entry;

  SshTime allocation_time;
  SshUInt32 dst_entry_id;

  struct SshDstEntryRec *next;
} *SshDstEntry, SshDstEntryStruct;
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */


/****************************** Interceptor Object ***************************/

struct SshInterceptorRec {

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
  SshNfInterceptorStruct nf[1];
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */


  /* Engine context */
  SshEngine engine;
  Boolean engine_open;

  /* Callback for packet. */
  SshInterceptorPacketCB packet_callback;

  /* Context for packet callback. */
  void *packet_callback_context;

#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  SshInterceptorPacketCB active_packet_callback[SSH_LINUX_INTERCEPTOR_NR_CPUS];
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

  /* Number of cpus and cpu id mapping table. */
  SshUInt16 num_cpus;
  SshUInt16 cpu_ids[SSH_LINUX_INTERCEPTOR_NR_CPUS];

  /* Name of related engine-instance */
  char *name;

  /* Ipm channel */
  SshInterceptorIpmStruct ipm;

  /* /proc filesystem entries */
  struct proc_dir_entry *proc_dir;

  SshInterceptorIpmProcEntryStruct ipm_proc_entry;

  SshInterceptorProcEntryStruct version_proc_entry;
#ifdef DEBUG_LIGHT
  SshInterceptorProcEntryStruct debug_proc_entry;
  SshInterceptorProcEntryStruct stats_proc_entry;
#endif /* DEBUG_LIGHT */

  /* Debug level */
  unsigned char debug_level_string[128];

  /* Main mutex for interceptor use */
  SshKernelMutex interceptor_lock;

  /* Mutex for memory map manipulation */
  SshKernelMutex memory_lock;

  /* Mutex for packet handling */
  SshKernelMutex packet_lock;

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Per-cpu context for recursion elimination. */
  SshCpuContext cpu_ctx;

  /* List for delayed packet processing and lock for protecting it. */
  SshKernelMutex async_send_queue_lock;
  SshInterceptorPacket async_send_queue;
  SshInterceptorPacket async_send_queue_tail;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  /* Timeouts */
  SshTimeoutManagerStruct timeouts;

  /* Packet freelist */
  SshInterceptorPacketFreelistStruct packet_freelist[1];

#ifdef DEBUG_LIGHT
  /* Statistics spin lock */
  spinlock_t statistics_lock;

  struct {
    /* Statistics */
    SshUInt64 num_packets_out;
    SshUInt64 num_packets_in;
    SshUInt64 num_bytes_out;
    SshUInt64 num_bytes_in;
    SshUInt64 num_passthrough;
    SshUInt64 num_fastpath_packets_in;
    SshUInt64 num_fastpath_packets_out;
    SshUInt64 num_fastpath_bytes_in;
    SshUInt64 num_fastpath_bytes_out;
    SshUInt64 num_errors;
    SshUInt64 num_packets_sent;
    SshUInt64 num_bytes_sent;
    SshUInt64 allocated_memory;
    SshUInt64 allocated_memory_max;
    SshUInt64 num_allocations;
    SshUInt64 num_allocations_large;
    SshUInt64 num_allocations_total;
    SshUInt64 num_allocated_packets;
    SshUInt64 num_allocated_packets_total;
    SshUInt64 num_copied_packets;
    SshUInt64 num_failed_allocs;
    SshUInt64 num_light_locks;
    SshUInt64 num_light_interceptor_locks;
    SshUInt64 num_heavy_locks;
    SshUInt64 num_timeout_run;
    SshUInt64 num_timeout_cancelled;
    SshUInt64 ipm_send_queue_len;
    SshUInt64 ipm_send_queue_bytes;
  } stats;
#endif /* DEBUG_LIGHT */



































#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  SshKernelMutex dst_entry_cache_lock;
  Boolean dst_entry_cache_timeout_registered;
  SshUInt32 dst_entry_id;
  SshUInt32 dst_entry_cached_items;
  SshDstEntry dst_entry_table[SSH_DST_ENTRY_TBL_SIZE];
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
};

typedef struct SshInterceptorRec SshInterceptorStruct;

/****************************** Function prototypes **************************/

/* Call packet_callback */
#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)

/* On SMP systems, the used packet_callback function pointer
   is written to the CPU's slot in the 'active_packet_callback'
   table before making the call, and cleared after return from
   the callback. During interceptor_uninit the packet_callback
   is set to a dummy callback, and table is checked to ensure
   that no kernel threads are using the real packet_callback. */
#define SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, pkt)              \
do                                                                           \
  {                                                                          \
    SshUInt32 cpu_id = smp_processor_id();                                   \
    (interceptor)->active_packet_callback[cpu_id] =                          \
      (interceptor)->packet_callback;                                        \
    ((interceptor)->active_packet_callback[cpu_id])                          \
      ((SshInterceptorPacket) (pkt), (interceptor)->packet_callback_context);\
    (interceptor)->active_packet_callback[cpu_id] = NULL_FNPTR;              \
  }                                                                          \
while (0);

#else /* SSH_LINUX_INTERCEPTOR_NR_CPUS <= 1 */

/* On UP systems, just call the callback. */
#define SSH_LINUX_INTERCEPTOR_PACKET_CALLBACK(interceptor, pkt)              \
do                                                                           \
  {                                                                          \
    ((interceptor)->packet_callback)                                         \
      ((SshInterceptorPacket) (pkt), (interceptor)->packet_callback_context);\
  }                                                                          \
while (0);

#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

/* Timeout initialization & etc... */
Boolean ssh_kernel_timeouts_init(SshInterceptor interceptor);
void ssh_kernel_timeouts_uninit(SshInterceptor interceptor);
Boolean ssh_kernel_timeouts_stop(SshInterceptor interceptor);

/* Proc entries */
Boolean ssh_interceptor_proc_init(SshInterceptor interceptor);
void ssh_interceptor_proc_uninit(SshInterceptor interceptor);
void ssh_interceptor_proc_enable(SshInterceptor interceptor);

/* Ipm channel */

/* init / uninit */
Boolean ssh_interceptor_ipm_init(SshInterceptor interceptor);
void ssh_interceptor_ipm_uninit(SshInterceptor interceptor);

/* open / close. These functions handle ipm message queue flushing. */
void interceptor_ipm_open(SshInterceptor interceptor);
void interceptor_ipm_close(SshInterceptor interceptor);

/* open / close notifiers. These functions notify engine. */
void ssh_interceptor_notify_ipm_open(SshInterceptor interceptor);
void ssh_interceptor_notify_ipm_close(SshInterceptor interceptor);

Boolean ssh_interceptor_send_to_ipm(unsigned char *data, size_t len,
                                    Boolean reliable, void *machine_context);
ssize_t ssh_interceptor_receive_from_ipm(unsigned char *data, size_t len);

void interceptor_ipm_message_free(SshInterceptor interceptor,
                                  SshInterceptorIpmMsg msg);

/* Debug */
void ssh_kernel_fatal_callback(const char *buf, void *context);
void ssh_kernel_warning_callback(const char *buf, void *context);
void ssh_kernel_debug_callback(const char *buf, void *context);

size_t ssh_interceptor_get_debug_level(SshInterceptor interceptor,
                                       char *debug_string,
                                       size_t debug_string_len);
void ssh_interceptor_set_debug_level(SshInterceptor interceptor,
                                     char *debug_string);
void ssh_interceptor_restore_debug_level(SshInterceptor interceptor);
Boolean ssh_interceptor_debug_init(SshInterceptor interceptor);
void ssh_interceptor_debug_uninit(SshInterceptor interceptor);

/* Mutexes */
Boolean ssh_interceptor_mutexes_init(SshInterceptor interceptor);
void ssh_interceptor_mutexes_uninit(SshInterceptor interceptor);

/* Kernel memory allocation */
Boolean ssh_interceptor_kernel_alloc_init(SshInterceptor interceptor);
void ssh_interceptor_kernel_alloc_uninit(SshInterceptor interceptor);

/* Packet access and manipulation. */

/* Header-only allocation. This function will assert that the interface
   numbers will fit into the data type SshInterceptorIfnum. */

/* sk_buff is from system protocol stack. */
#define SSH_LINUX_PACKET_ALLOC_FLAG_PKT_FROM_SYSTEM        0x0001
/* Do not copy sk_buff even if it is cloned. */
#define SSH_LINUX_PACKET_ALLOC_FLAG_FORCE_NOCOPY_SKBUFF    0x0002
/* Force copy of sk_buff header and payload data. */
#define SSH_LINUX_PACKET_ALLOC_FLAG_FORCE_COPY_SKBUFF      0x0004
/* Free original sk_buff after copy. */
#define SSH_LINUX_PACKET_ALLOC_FLAG_FREE_ORGINAL_ON_COPY   0x0008

SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor interceptor,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out,
                                    struct sk_buff *skb,
                                    SshUInt32 alloc_flags);

/* Align the interceptor packet at the data offset 'offset' to a word
   boundary. On failure, 'pp' is freed and returns FALSE. */
Boolean
ssh_interceptor_packet_align(SshInterceptorPacket packet, size_t offset);

/* Verify that `skbp' has enough headroom to be sent out through `skbp->dev'.
   On failure this frees `skbp' and returns NULL. */
struct sk_buff *
ssh_interceptor_packet_verify_headroom(struct sk_buff *skbp,
                                       size_t media_header_len);

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
void
ssh_interceptor_packet_return_dst_entry(SshInterceptor interceptor,
                                        SshUInt32 dst_entry_id,
                                        SshInterceptorPacket pp,
                                        Boolean remove_only);
SshUInt32
ssh_interceptor_packet_cache_dst_entry(SshInterceptor interceptor,
                                       SshInterceptorPacket pp);

Boolean
ssh_interceptor_dst_entry_cache_init(SshInterceptor interceptor);

void
ssh_interceptor_dst_entry_cache_flush(SshInterceptor interceptor);

void
ssh_interceptor_dst_entry_cache_uninit(SshInterceptor interceptor);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

#ifdef DEBUG_LIGHT
/* Hexdump packet data. On failure this frees ipp and returns FALSE. */
Boolean
ssh_interceptor_packet_hexdump(SshInterceptorInternalPacket ipp);
#endif /* DEBUG_LIGHT */

/* Packet freelist init / uninit. */
Boolean ssh_interceptor_packet_freelist_init(SshInterceptor interceptor);
void ssh_interceptor_packet_freelist_uninit(SshInterceptor interceptor);
int ssh_interceptor_packet_freelist_stats(SshInterceptor interceptor,
                                          char *buf, int maxsize);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
/* Packet queue processing. */
void
interceptor_packet_queue_process(SshInterceptor interceptor,
                                 SshCpuContext cpu_ctx,
                                 Boolean async_to_stack);
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

/* Module usage counter. */
int ssh_linux_module_inc_use_count(void);
void ssh_linux_module_dec_use_count(void);




















































#endif /* LINUX_INTERNAL_H */
