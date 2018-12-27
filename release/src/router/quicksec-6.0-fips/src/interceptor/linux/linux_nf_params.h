/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tunables for the Linux netfilter interceptor code.
*/

#ifndef LINUX_NF_PARAMS_H
#define LINUX_NF_PARAMS_H

#include "ipsec_params.h"
#include "interceptor.h"

/* Netfilter interoperability flag. If this flag is set, then packets
   intercepted at the PRE_ROUTING hook are passed to other netfilter modules
   before the packet is given to the engine for processing. */
/* #define SSH_LINUX_NF_PRE_ROUTING_BEFORE_ENGINE 1 */

/* Netfilter interoperability flag. If this flag is set, then packets
   sent to host stack are passed to other netfilter modules in the PRE_ROUTING
   hook after the packet has been processed in the engine. */
/* #define SSH_LINUX_NF_PRE_ROUTING_AFTER_ENGINE 1 */

/* Netfilter interoperability flag. If this flag is set, then packets
   intercepted at the POST_ROUTING hook are passed to other netfilter
   modules before the packet is given to the engine for processing. */
/* #define SSH_LINUX_NF_POST_ROUTING_BEFORE_ENGINE 1 */

/* Netfilter interoperability flag. If this flag is set, then packets
   sent to network are passed to other netfilter modules in the POST_ROUTING
   hook after the packet has been processed in the engine. This flag is usable
   only if SSH_IPSEC_IP_ONLY_INTERCEPTOR is defined. */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* #define SSH_LINUX_NF_POST_ROUTING_AFTER_ENGINE 1 */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Netfilter interoperability flag. If this flags is set, then forwarded
   packets are passed to netfilter modules in the FORWARD hook after
   the packet has been processed in the engine.  This flag is usable
   only if SSH_IPSEC_IP_ONLY_INTERCEPTOR defined, and if the engine performs
   packet forwarding (that is, SSH_ENGINE_FLAGS does not include
   SSH_ENGINE_NO_FORWARDING). */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* #define SSH_LINUX_NF_FORWARD_AFTER_ENGINE 1 */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */















#endif /* LINUX_NF_PARAMS_H */
