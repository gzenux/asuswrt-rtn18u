/**
   The following copyright and permission notice must be included in all
   copies, modified as well as unmodified, of this file.

   This file is free software: you may copy, redistribute and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation, either version 2 of the License, or (at your
   option) any later version.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   This file incorporates work covered by the following copyright and
   permission notice:

   @copyright
   Copyright (c) 2010-2015, INSIDE Secure Oy. All rights reserved.

 */

/*
 * linux_versions.h
 *
 * Linux interceptor kernel version specific defines. When adding support
 * for new kernel versions, add the kernel version specific block to the
 * bottom of the file and undefine any removed feature defines inherited
 * from earlier kernel version blocks.
 *
 */

#ifndef LINUX_VERSION_H
#define LINUX_VERSION_H

#include <linux/version.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif /* KERNEL_VERSION */

/* 3.0.43 is the highest 3.0 series version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,43) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
#error "Kernel versions after 3.0.43 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,0,43) */

/* 3.1.10 is the highest 3.1 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,1,10) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#warning "Kernel versions after 3.1.10 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,1,10) && ... */

/* 3.2.30 is the highest 3.2 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,2,30) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#warning "Kernel versions after 3.2.30 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,2,30) && ... */

/* 3.3.8 is the highest 3.3 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,8) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#warning "Kernel versions after 3.3.8 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,3,8) && ... */

/* 3.4.11 is the highest 3.4 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,11) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#warning "Kernel versions after 3.4.11 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,4,11) && ... */

/* 3.10.69 is the highest 3.10 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,69) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
#warning "Kernel versions after 3.10.69 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,10,69) && ... */

/* 3.12.40 is the highest 3.12 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,12,40) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
#warning "Kernel versions after 3.12.40 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,12,40) && ... */

/* 3.14.39 is the highest 3.18 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,14,39) && \
  LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#warning "Kernel versions after 3.14.39 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,14,39) && ... */

/* 3.18.11 is the highest 3.18 version currently supported */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,18,11)
#warning "Kernel versions after 3.18.11 are not supported"
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(3,10,69) && ... */

/* 2.4 is not supported */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#error "Kernel versions pre 2.6.0 are not supported"
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

/* 2.6 series specific things */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define LINUX_HAS_SKB_SECURITY 1
#define LINUX_HAS_SKB_STAMP 1
#define LINUX_HAS_SKB_NFCACHE 1
#define LINUX_HAS_SKB_NFDEBUG 1
#define LINUX_SKB_LINEARIZE_NEEDS_FLAGS 1
#define LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA 1
#define LINUX_HAS_PROC_DIR_ENTRY_OWNER 1
#define LINUX_HAS_HH_CACHE 1
#define LINUX_DST_HAS_NEIGHBOUR 1
#define LINUX_IPV4_DST_USES_METRICS 1
#endif /* >= 2.6.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
#define LINUX_HAS_SKB_MAC_LEN 1
#endif /* >= 2.6.4 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
#define LINUX_HAS_ETH_HDR 1
#endif /* >= 2.6.9 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#define LINUX_HAS_DST_MTU 1
#define LINUX_HAS_DEV_GET_FLAGS 1
#endif /* >= 2.6.12 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
#undef LINUX_HAS_SKB_SECURITY
#undef LINUX_HAS_SKB_STAMP
#undef LINUX_HAS_SKB_NFCACHE
#undef LINUX_HAS_SKB_NFDEBUG
#endif /* >= 2.6.13 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
#define LINUX_HAS_NETIF_F_UFO 1
#endif /* >= 2.6.15 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#define LINUX_HAS_IP6CB_NHOFF 1
#define LINUX_FRAGMENTATION_AFTER_NF_POST_ROUTING 1
#endif /* >= 2.6.16 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#undef LINUX_SKB_LINEARIZE_NEEDS_FLAGS
#define LINUX_HAS_NETIF_F_GSO        1
#define LINUX_HAS_NETIF_F_TSO6       1
#define LINUX_HAS_NETIF_F_TSO_ECN    1
#define LINUX_HAS_NETIF_F_GSO_ROBUST 1
#endif /* >= 2.6.18 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#define LINUX_HAS_NEW_CHECKSUM_FLAGS 1
#define LINUX_NEED_IF_ADDR_H 1
#endif /* >= 2.6.19 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#define LINUX_HAS_SKB_MARK 1
#define LINUX_HAS_SKB_CSUM_OFFSET 1
#endif /* >= 2.6.20 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define LINUX_HAS_NETDEVICE_ACCESSORS 1
#define LINUX_HAS_SKB_DATA_ACCESSORS 1
#define LINUX_HAS_SKB_CSUM_START 1
#endif /* >= 2.6.22 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define LINUX_NET_DEVICE_HAS_ARGUMENT 1
#define LINUX_NF_HOOK_SKB_IS_POINTER  1
#endif /* >= 2.6.24 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define LINUX_NF_INET_HOOKNUMS 1
#define LINUX_IP_ROUTE_OUTPUT_KEY_HAS_NET_ARGUMENT 1
#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#define LINUX_IP6_ROUTE_OUTPUT_KEY_HAS_NET_ARGUMENT 1
#define LINUX_HAS_PROC_CREATE_DATA 1
#endif /* >= 2.6.26 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#undef LINUX_INODE_OPERATION_PERMISSION_HAS_NAMEIDATA
#endif /* >= 2.6.27 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#define LINUX_HAS_NFPROTO_ARP 1
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#define LINUX_HAS_TASK_CRED_STRUCT 1
#endif /* >= 2.6.29 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#undef LINUX_HAS_PROC_DIR_ENTRY_OWNER
#endif /* >= 2.6.30 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#define LINUX_HAS_SKB_DST_FUNCTIONS 1
#endif /* >= 2.6.31 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#endif /* >= 2.6.32 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#endif /* >= 2.6.33 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
#endif /* >= 2.6.34 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define LINUX_HAS_INET6_IFADDR_LIST_HEAD 1
#define LINUX_DST_POP_IS_SKB_DST_POP 1
#define LINUX_IP_ONLY_PASSTHROUGH_NDISC 1
#define LINUX_FRAGMENTATION_AFTER_NF6_POST_ROUTING 1
#define LINUX_USE_SKB_DST_NOREF 1
#define LINUX_HAS_SKB_RXHASH 1
#endif /* >= 2.6.35 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define LINUX_RT_DST_IS_NOT_IN_UNION 1
#endif /* >= 2.6.36 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#define LINUX_HAS_SKB_GET_RXHASH 1
#endif /* >= 2.6.37 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
#define LINUX_HAS_DST_METRICS_ACCESSORS 1
#define LINUX_SSH_RTABLE_FIRST_ELEMENT_NEEDED 1
#endif /* >= 2.6.38 */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
#define LINUX_USE_NF_FOR_ROUTE_OUTPUT 1
#define LINUX_FLOWI_NO_FL4_ACCESSORS 1
#define LINUX_FLOWI_NO_FL6_ACCESSORS 1
#define LINUX_DST_ALLOC_HAS_REFCOUNT 1
#endif /* >= 2.6.38 */


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
#undef LINUX_INODE_OPERATION_PERMISSION_HAS_UINT
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
