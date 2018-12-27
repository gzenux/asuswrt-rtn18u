/**
   @copyright
   Copyright (c) 2008 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file defines some parameters that have changed between
   various linux kernel versions. If you are using other than
   "vanilla" kernels from http://www.kernel.org/ and have
   these changes included in earlier or later kernel versions
   you have to modify this file.

   When adding support for new kernel versions, add the define
   block to the bottom of the file. The new kernel version will
   inherit all features of the previous kernel version. Create
   new defines for new features and undefine defines for features
   that have disappeared from the new kernel version.
*/

#ifndef LINUX_VERSION_H
#define LINUX_VERSION_H

#include <linux/version.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif /* KERNEL_VERSION */

/* Supported kernel versions are only long-terms 2.6.32, 3.2, 3.4, 3.10,
 * 3.12, 3.13, 3.14 and 3.18 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) && \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)) ||  \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0) &&  \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)) ||  \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0) &&  \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)) || \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) && \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)) || \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) && \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)) || \
  (LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0) && \
   LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0))

#ifndef HAVE_WRL_VRF /* WindRiver is a special case (uses 2.6.27) */
#warning \
  "Your kernel version is not a long-term version supported by INSIDE Secure"
#endif /* !HAVE_WRL_VRF */



#endif /* SSHDIST_QUICKSEC_INTERNAL */

/* 2.6 series specific things */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define LINUX_HAS_NET_DEVICE_PRIV 1
#define LINUX_HAS_PROC_DIR_ENTRY_OWNER 1
#define LINUX_HAS_HH_CACHE 1
#define LINUX_DST_HAS_NEIGHBOUR 1
#define LINUX_IPV4_DST_USES_METRICS 1
#endif /* >= 2.6.0 */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
/* Nothing here. */
#endif /* >= 2.6.27 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#define LINUX_HAS_NFPROTO_ARP 1
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#undef LINUX_HAS_NET_DEVICE_PRIV
#define LINUX_HAS_TASK_CRED_STRUCT 1
#endif /* >= 2.6.29 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#undef LINUX_HAS_PROC_DIR_ENTRY_OWNER
#define LINUX_HAS_IRQRETURN_T_ENUM
#endif /* >= 2.6.30 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#define LINUX_HAS_SKB_DST_FUNCTIONS 1
#endif /* >= 2.6.31 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define LINUX_IN6_DEV_GET_NEEDS_IPV6_ADDRESS 1
#endif /* >= 2.6.32 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
/* New notifier type value NETDEV_UNREGISTER_BATCH was introduced. */
#endif /* >= 2.6.33 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
#define LINUX_HAS_NETDEV_NDO_CHANGE_RX_FLAGS 1
#define LINUX_HAS_NETDEV_NDO_SET_RX_MODE 1
#define LINUX_HAS_NETDEV_NDO_SET_MULTICAST_LIST 1
#endif /* >= 2.6.34 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define LINUX_HAS_INET6_IFADDR_LIST_HEAD 1
#define LINUX_FRAGMENTATION_AFTER_NF6_POST_ROUTING 1
#define LINUX_IP_ONLY_PASSTHROUGH_NDISC 1
#define LINUX_USE_SKB_DST_NOREF 1
#define LINUX_HAS_SKB_RXHASH 1
#endif /* >= 2.6.35 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define LINUX_RT_DST_IS_NOT_IN_UNION 1
#define LINUX_DEV_GET_STATS_HAS_STATS_ARGUMENT 1
#endif /* >= 2.6.36 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#define LINUX_HAS_SKB_GET_RXHASH 1
#endif /* >= 2.6.37 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
#define LINUX_HAS_DST_METRICS_ACCESSORS 1
#endif /* >= 2.6.38 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
#define LINUX_USE_NF_FOR_ROUTE_OUTPUT 1
#define LINUX_FLOWI_NO_FL4_ACCESSORS 1
#define LINUX_FLOWI_NO_FL6_ACCESSORS 1
#define LINUX_DST_ALLOC_HAS_REFCOUNT 1
#endif /* >= 2.6.39 */


/* 3.0 series specific things */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#define LINUX_DST_ALLOC_REQUIRES_ZEROING 1
#define LINUX_DST_ALLOC_HAS_MANY_ARGS 1
#define LINUX_SSH_RTABLE_FIRST_MEMBER_RT_KEY_DST 1
#endif /* >= 3.0.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,21)
#define LINUX_HAS_DST_NEIGHBOUR_FUNCTIONS 1
#endif /* >= 3.0.21 */


/* 3.1 series specific things */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#define LINUX_HAS_NET_DEVICE_OPS 1
#undef LINUX_HAS_HH_CACHE
#endif /* >= 3.1.0 */


/* 3.2 series specific things */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
#define LINUX_HAS_SKB_FRAG_PAGE 1
#define LINUX_HAS_SKB_L4_RXHASH 1
#endif /* >= 3.2.0 */


/* 3.3 series specific things */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
#define LINUX_USE_DST_GET_NEIGHBOUR_NOREF 1
#endif /* >= 3.3.0 */


/* 3.4 series specific things */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define LINUX_KMAP_ATOMIC_HAS_NO_ARG 1
#endif /* >= 3.4.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
#undef LINUX_DST_HAS_NEIGHBOUR
#undef LINUX_SSH_RTABLE_FIRST_MEMBER_RT_KEY_DST
#undef LINUX_IPV4_DST_USES_METRICS
#define LINUX_RT6_INFO_HAS_NEIGHBOUR 1
#define LINUX_SSH_RTABLE_FIRST_MEMBER_RT_GENID 1
#define LINUX_RT_USE_DST_AS_GW 1
#define LINUX_RT_SLIM 1
#define LINUX_RT6_INFO_PEER_LONG 1
#endif /* >= 3.6.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#undef LINUX_RT6_INFO_HAS_NEIGHBOUR
#endif /* >= 3.9.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define LINUX_HAS_PROC_SET_FUNCTIONS 1
#endif /* >= 3.10.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#define LINUX_NF_HOOK_FIRST_ARG_IS_OPS 1
#endif /* >= 3.13.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#undef LINUX_HAS_SKB_GET_RXHASH
#define LINUX_HAS_SKB_GET_HASH 1
#endif /* >= 3.14.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
#undef LINUX_HAS_SKB_RXHASH
#undef LINUX_HAS_SKB_L4_RXHASH
#define LINUX_HAS_SKB_HASH 1
#define LINUX_HAS_SKB_L4_HASH 1
#define LINUX_USE_WAIT_EVENT 1
#endif /* >= 3.15.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
#define LINUX_LOCAL_DF_RENAMED 1
#endif /* >= 3.16.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
#define LINUX_ALLOC_NETDEV_NEEDS_TYPE 1
#endif /* >= 3.17.0 */

#endif /* LINUX_VERSION_H */
