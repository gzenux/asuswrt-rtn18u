/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec parameters for small devices, like PDAs, mobile and
   smartphones or such, that have limited number of top level policy
   rules and IPsec tunnels instantiated.

   @description
   These values take precedence over the default values defined at
   ipsec_params.h

   Values defined here may be overwritten at ipsec_params_site.h. For
   the values not defined here the default values from ipsec_params.h
   are used.

   This file is only included in compilation if SSH_IPSEC_SMALL has
   been defined.
*/

#ifndef IPSEC_PARAMS_H
# error "this file needs to be included from ipsec_params.h, not directly"
#endif /* IPSEC_PARAMS_H */

#define SSH_IPSEC_MAX_IKE_PORTS             2

#define SSH_INTERCEPTOR_MAX_PACKETS        16
#define SSH_ENGINE_REPLAY_WINDOW_WORDS      2
#define SSH_PM_MAX_TUNNELS                  5
#define SSH_PM_MAX_IKE_SA_NEGOTIATIONS      2
#define SSH_PM_MAX_QM_NEGOTIATIONS          2
#define SSH_PM_AUDIT_REQUESTS_PER_SECOND    0 /** Disables timer. */
#define SSH_ENGINE_MAX_SESSIONS           100
#define SSH_ENGINE_MAX_APPGW_OPEN_PORTS     0 /** No algs on small devices. */
#define SSH_ENGINE_FLOW_RATE_HASH_SIZE     31
#define SSH_ENGINE_MAX_FRAGS_PER_PACKET     6
#define SSH_ENGINE_FLOW_NAT_HASH_SIZE      64

/* eof */
