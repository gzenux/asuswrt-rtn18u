/**
   @copyright
   Copyright (c) 2008 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tunables for the Linux interceptor code.
*/

#ifndef LINUX_PARAMS_H
#define LINUX_PARAMS_H

#ifdef SSHDIST_QUICKSEC
#ifdef SSH_BUILD_IPSEC
/* Include linux netfilter interceptor parameters. */
#include "linux_nf_params.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_QUICKSEC */


/* Netfilter interoperability flag. This flags specifies the extension
   selector slot which is used for storing the Linux 'skb->nfmark' firewall
   mark.  Note that in kernel versions before 2.6.20 the linux kernel
   CONFIG_IP_ROUTE_FWMARK must be enabled if you wish to use `skb->nfmark'
   in route lookups.  This define is not used if
   SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS is 0. */
/* #define SSH_LINUX_FWMARK_EXTENSION_SELECTOR 0 */

/* Maximum amount of memory in bytes we can safely kmalloc() in the
   Linux kernel. */
#define SSH_LINUX_MAX_MALLOC_SIZE 65535

/* The upper treshold of queued messages from the engine to the policymanager.
   If this treshold is passed, then "unreliable" messages (messages not
   necessary for the correct operation of the engine/policymanager), are
   discarded. Both existing queued messages or new messages can be
   discarded. */
#define SSH_LINUX_MAX_IPM_MESSAGES 2000

/* Disable IPV6 support in the interceptor here, if explicitly desired.
   Undefining SSH_LINUX_INTERCEPTOR_IPV6 results into excluding IPv6
   specific code in the interceptor. The define does not affect the
   size of any common data structures.
   Currently it is disabled by default if IPv6 is not available in the
   kernel. */
#if defined (WITH_IPV6)
#define SSH_LINUX_INTERCEPTOR_IPV6 1
#ifndef CONFIG_IPV6
#ifndef CONFIG_IPV6_MODULE
#undef SSH_LINUX_INTERCEPTOR_IPV6
#endif /* !CONFIG_IPV6_MODULE */
#endif /* !CONFIG_IPV6 */
#endif /* WITH_IPV6 */

/* Enable this if you suspect there is a deadlock in the engine. Note
   that these debugs may not help you find it. This requires DEBUG_LIGHT. */
/* #define SSH_LINUX_DEBUG_MUTEX 1 */

#endif /* LINUX_PARAMS_H */
