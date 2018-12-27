/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal declarations for linux netfilter interceptor.
*/

#ifndef LINUX_NF_INTERNAL_H
#define LINUX_NF_INTERNAL_H

#ifndef LINUX_INTERNAL_H
#error "Never include linux_nf_internal.h directly, include linux_internal.h!"
#endif /* LINUX_INTERNAL_H */

/*************************** Interceptor capabilities **********************/

#define SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS

/*********************************** Includes ******************************/

#include <net/ip.h>
#include <net/route.h>
#include <net/inet_common.h>

#ifdef SSH_LINUX_INTERCEPTOR_IPV6
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/flow.h>
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#include "linux_virtual_adapter_internal.h"
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/****************************** Internal defines *****************************/

#ifdef IP6CB
#define SSH_LINUX_IP6CB(skbp) IP6CB(skbp)
#else /* IP6CB */
#define SSH_LINUX_IP6CB(skbp) ((struct inet6_skb_parm *) ((skbp)->cb))
#endif /* IP6CB */







/* Flags for ssh_engine_start */
#define SSH_LINUX_ENGINE_FLAGS SSH_IPSEC_ENGINE_FLAGS

/****************************** Module information ***************************/

#define SSH_LINUX_INTERCEPTOR_MODULE_DESCRIPTION "INSIDE Secure QuickSec"

/****************************** procfs ***************************************/

/* Procfs entries */
#define SSH_PROC_ROOT "quicksec"

/****************************** Interface handling ***************************/

/* Interface structure for caching "ifindex->dev" mapping. */
typedef struct SshInterceptorInternalInterfaceRec
*SshInterceptorInternalInterface;

struct SshInterceptorInternalInterfaceRec
{
  /* Next entry in the hashtable chain */
  SshInterceptorInternalInterface next;
  /* Interface index */
  SshUInt32 ifindex;
  /* Linux net_device structure */
  struct net_device *dev;

  /* This field is used to mark existing interfaces,
     and to remove disappeared interfaces from the hashtable. */
  SshUInt8 generation;

  /* Pointer to private data. This is currently used only by Octeon. */
  void *context;
};

/* Number of hashtable slots in the interface hashtable. */
#define SSH_LINUX_IFACE_HASH_SIZE 256

/* Maximum number of entries in the interface hashtable.
   Currently equal to maximum interface number. */
#define SSH_LINUX_IFACE_TABLE_SIZE SSH_INTERCEPTOR_MAX_IFNUM

/****************************** Interceptor data structures ******************/

struct SshNfInterceptorRec
{
  /* Function pointers to netfilter infrastructure */
  struct
  {
    int (*ip_rcv_finish) (struct sk_buff *);
    int (*ip_finish_output) (struct sk_buff *);
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    int (*ip6_rcv_finish) (struct sk_buff *);
    int (*ip6_output_finish) (struct sk_buff *);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    int (*arp_process) (struct sk_buff *);
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  } linux_fn;

  Boolean hooks_installed;









  /* Interface information used in ssh_interceptor_send()
     (and elsewhere obviously, but the aforementioned
     is the reason it is here). 'if_hash', 'if_table_size',
     and 'if_generation' are protected by 'if_table_lock' rwlock. */
  SshInterceptorInternalInterface if_hash[SSH_LINUX_IFACE_HASH_SIZE];

  SshInterceptorInternalInterface if_table;
  SshUInt32 if_table_size;
  SshUInt8 if_generation;

  /* Protected by interceptor_lock */
  int num_interface_callbacks;

  /* Notifiers, notifies when interfaces change. */
  Boolean iface_notifiers_installed;

  struct notifier_block notifier_netdev;
  struct notifier_block notifier_inetaddr;
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
  struct notifier_block notifier_inet6addr;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

  /* Reader Writer lock for interface table manipulation */
  rwlock_t if_table_lock;

  /* Mutex for route operations */
  SshKernelMutex route_lock;

  /* Registered callbacks */
  /* Protected by 'interceptor_lock' */
  SshInterceptorInterfacesCB interfaces_callback;

  /* Unused and unprotected */
  SshInterceptorRouteChangeCB route_callback;

  /* Callback context */
  void *callback_context;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  SshVirtualAdapter virtual_adapters[SSH_LINUX_MAX_VIRTUAL_ADAPTERS];
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
  /* Octeon accelerated fastpath packet handler callback */
  SshInterceptorOcteonPacketCB octeon_packet_handler;
  void *octeon_packet_handler_context;
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
};

typedef struct SshNfInterceptorRec SshNfInterceptorStruct;
typedef struct SshNfInterceptorRec *SshNfInterceptor;


/************************ Function prototypes *******************************/

/***************** Packet interception init / uninit. ***********************/
Boolean ssh_interceptor_ip_glue_init(SshInterceptor interceptor);
Boolean ssh_interceptor_ip_glue_uninit(SshInterceptor interceptor);

/* hook magic init */
int ssh_interceptor_hook_magic_init(void);

/************************* Interface handling. ******************************/
struct net_device *
ssh_interceptor_ifnum_to_netdev(SshInterceptor interceptor, SshUInt32 ifnum);
struct net_device *
ssh_interceptor_ifnum_to_netdev_ctx(SshInterceptor interceptor,
                                    SshUInt32 ifnum, void **context_return);
Boolean ssh_interceptor_iface_set_context(SshInterceptor interceptor,
                                          SshUInt32 ifnum, void *context);
void ssh_interceptor_release_netdev(struct net_device *dev);
void ssh_interceptor_receive_ifaces(SshInterceptor interceptor);
void ssh_interceptor_clear_ifaces(SshInterceptor interceptor);
Boolean ssh_interceptor_iface_init(SshInterceptor interceptor);
void ssh_interceptor_iface_uninit(SshInterceptor interceptor);

/****************************** Routing *************************************/

/* skb rerouting */
Boolean ssh_interceptor_reroute_skb_ipv4(SshInterceptor interceptor,
                                         struct sk_buff *skb,
                                         SshUInt32 route_selector,
                                         SshUInt32 ifnum_in,
                                         SshVriId routing_instance_id);
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
Boolean ssh_interceptor_reroute_skb_ipv6(SshInterceptor interceptor,
                                         struct sk_buff *skb,
                                         SshUInt32 route_selector,
                                         SshUInt32 ifnum_in,
                                         SshVriId routing_instance_id);
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
/*********************** Octeon packet interception. ************************/

#ifdef PLATFORM_OCTEON_LINUX
void ssh_interceptor_octeon_init(SshInterceptor interceptor);
void ssh_interceptor_octeon_uninit(SshInterceptor interceptor);
void ssh_interceptor_octeon_send(SshInterceptor interceptor,
                                 SshInterceptorPacket pp,
                                 size_t media_header_len);
void ssh_interceptor_octeon_free_work(SshInterceptorInternalPacket packet);
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#ifdef SSHDIST_FUNCTIONALITY_TLS
/**************************** TLS acceleration ******************************/

#ifdef HAVE_SAFENET
/* These functions are implemented only for Safenet hardware accelerator.
   They set up a character device to share harware accelerator between
   TLS library (in user mode) and IPSEC engine. */
struct file_operations *ssh_tls_accel_fops_init();
void ssh_tls_accel_fops_uninit();
#endif /* HAVE_SAFENET */
#endif /* SSHDIST_FUNCTIONALITY_TLS */

#endif /* LINUX_NF_INTERNAL_H */
