/**
   @copyright
   Copyright (c) 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Linux Generic VRF implemententation.
*/

#include "linux_internal.h"
#include "linux_vrf.h"
#include "interceptor.h"

#define SSH_DEBUG_MODULE "SshInterceptorVrfGeneric"

/* Convert SshVriId to platform specific VRI ID. */
int ssh_interceptor_convert_vri_id_to_platform_vri(SshVriId id)
{
  return (int)id;
}

/* Set SKB VRI ID */
int ssh_skb_set_vrf_by_id(struct sk_buff *skb, SshVriId id)
{
  /* Always success */
  return 0;
}

/* Get SKB VRI ID */
SshVriId ssh_skb_get_vrf_id(struct sk_buff *skb)
{
  /* No VRF support -> always global. */
  return SSH_INTERCEPTOR_VRI_ID_GLOBAL;
}

/* Get Device VRI ID */
SshVriId ssh_interceptor_get_dev_vrf_id(const struct net_device *dev)
{
  /* No VRF support -> always global. */
  return SSH_INTERCEPTOR_VRI_ID_GLOBAL;
}

/* Get Net (namespace) by VRI ID*/
struct net *ssh_interceptor_get_vrf_net_by_id(SshVriId id)
{
  /* Always initial net as no VRF support. */
  return &init_net;
}

/* Convert routing instance id to name. */
void ssh_interceptor_vrf_id_to_name(SshVriId routing_instance_id,
                                    char* routing_instance_name)
{
  char *name;
  SSH_ASSERT(routing_instance_name != NULL);

  if (routing_instance_id != SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    name="";
  else
    name = SSH_INTERCEPTOR_VRI_NAME_GLOBAL;

  strncpy(routing_instance_name, name, SSH_INTERCEPTOR_VRI_NAMESIZE - 1);
}

/* Validate existence of routing instance id  */
Boolean ssh_interceptor_is_valid_vrf_by_id(SshVriId id)
{
  if (id != SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    return FALSE;

  return TRUE;
}


