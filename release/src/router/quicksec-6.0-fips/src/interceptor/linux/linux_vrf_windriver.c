/**
   @copyright
   Copyright (c) 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windriver Linux specific VRF abstraction.
*/

#ifdef HAVE_WRL_VRF
#include "linux_internal.h"
#include "linux_vrf.h"
#include "interceptor.h"

/* Windriver headers */
#include <linux/kernel.h>
#include <net/ip_fib.h>

#define SSH_DEBUG_MODULE "SshInterceptorVrfWindriver"

/* Convert SshVriId to platform specific VRI ID. */
int ssh_interceptor_convert_vri_id_to_platform_vri(SshVriId id)
{
  switch(id)
    {
    case SSH_INTERCEPTOR_VRI_ID_ANY:
    case SSH_INTERCEPTOR_VRI_ID_GLOBAL:
      return DEFAULT_VR_ID;
    default:
      return (int)id;
    }
}

/* Set SKB VRI ID */
int ssh_skb_set_vrf_by_id(struct sk_buff *skb, SshVriId id)
{
  SshVriId pid = id;

  SSH_ASSERT(id != SSH_INTERCEPTOR_VRI_ID_ANY);

  if (id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    pid = DEFAULT_VR_ID;

  SSH_ASSERT(pid <= CONFIG_MAX_VR_ID);

  return skb_vrf_set(skb, (int) pid);
}

/* Get VRI ID from SKB. */
SshVriId ssh_skb_get_vrf_id(struct sk_buff *skb)
{
  SshVriId id = skb_vrf(skb);

  switch(id)
    {
    case -EINVAL:
      if (skb->dev != NULL)
        id = ssh_interceptor_get_dev_vrf_id(skb->dev);
      break;

    case DEFAULT_VR_ID:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

      /* We intentionally convert DONT_CARE_VR_ID to global. */
    case DONT_CARE_VR_ID:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

    default:
      break;
    }

  return id;
}

/* Get device VRI ID */
SshVriId ssh_interceptor_get_dev_vrf_id(const struct net_device *dev)
{
  SshVriId id = dev_vrf(dev);

  switch(id)
    {
    case -EINVAL:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

    case DEFAULT_VR_ID:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

      /* We intentionally convert DONT_CARE_VR_ID to global. */
    case DONT_CARE_VR_ID:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

    default:
      break;
    }

  return id;
}

/* Get net (namespace) by VRI ID */
struct net *ssh_interceptor_get_vrf_net_by_id(SshVriId id)
{
  /* WRL does not use network namespaces so just return the default one. */
  return &init_net;
}

/* Convert VRI ID to name */
void ssh_interceptor_vrf_id_to_name(SshVriId routing_instance_id,
                                    char *routing_instance_name)
{
  SSH_ASSERT(routing_instance_id != SSH_INTERCEPTOR_VRI_ID_ANY);
  SSH_ASSERT(routing_instance_name != NULL);


  if (routing_instance_id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    ssh_strncpy(routing_instance_name, SSH_INTERCEPTOR_VRI_NAME_GLOBAL,
            SSH_INTERCEPTOR_VRI_NAMESIZE - 1);
  else
    ssh_snprintf(routing_instance_name, SSH_INTERCEPTOR_VRI_NAMESIZE - 1,
                 "%d", routing_instance_id);
}

/* Validate existence of VRI ID */
Boolean ssh_interceptor_is_valid_vrf_by_id(SshVriId id)
{
  struct net_device *dev;

  if (id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    return TRUE;

  /* If we find a device with this id, then it's valid. */
  for_each_netdev(&init_net, dev)
    {
      if (dev->vr_id == (int) id)
        return TRUE;
    }

  return FALSE;
}

#endif /* HAVE_WRL_VRF */
