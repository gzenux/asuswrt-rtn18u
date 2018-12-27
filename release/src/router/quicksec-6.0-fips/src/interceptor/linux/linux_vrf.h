/**
   @copyright
   Copyright (c) 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linux VRF accessor function definitions.
*/

#ifndef LINUX_VRF_H
#define LINUX_VRF_H

#include "interceptor.h"

#ifdef HAVE_MVL_VRF
#include <net/vrf.h>
#elif defined(HAVE_WRL_VRF)
#include <linux/kernel.h>
#endif /* HAVE_MVL_VRF */

/* Convert SshVriId to platform specific VRI ID */
int ssh_interceptor_convert_vri_id_to_platform_vri(SshVriId id);

/* Set SKB VRI ID */
int ssh_skb_set_vrf_by_id(struct sk_buff *skb, SshVriId id);

/* Get SKB VRI ID */
SshVriId ssh_skb_get_vrf_id(struct sk_buff *skb);

/* Get device VRI ID */
SshVriId ssh_interceptor_get_dev_vrf_id(const struct net_device *dev);

/* Get Net (namespace) with VRI ID */
struct net *ssh_interceptor_get_vrf_net_by_id(SshVriId id);

/* Convert VRI ID to name */
void ssh_interceptor_vrf_id_to_name(SshVriId routing_instance_id,
                                     char *routing_instance_name);

/* Validate existence of VRI ID */
Boolean ssh_interceptor_is_valid_vrf_by_id(SshVriId id);

/* Platform dependent definitions. */
#ifdef HAVE_MVL_VRF
#define SSH_INTERCEPTOR_VRF_ID_START  VRF_ID_START
#define SSH_INTERCEPTOR_VRF_ID_MAX    VRF_ID_MAX
#elif defined(HAVE_WRL_VRF)
#define SSH_INTERCEPTOR_VRF_ID_START  DEFAULT_VR_ID
#define SSH_INTERCEPTOR_VRF_ID_MAX    CONFIG_MAX_VR_ID
#else /* HAVE_MVL_VRF, HAVE_WRL_VRF */
#define SSH_INTERCEPTOR_VRF_ID_START  0
#define SSH_INTERCEPTOR_VRF_ID_MAX    1
#endif /* HAVE_MVL_VRF */

/* Loop all VRF's */
#define SSH_INTERCEPTOR_VRF_FOR_EACH_VRFID(__vrf_id)                \
  for ((__vrf_id) = SSH_INTERCEPTOR_VRF_ID_START;                   \
       (__vrf_id) < SSH_INTERCEPTOR_VRF_ID_MAX;                     \
       (__vrf_id)++)

#endif /* LINUX_VRF_H */
