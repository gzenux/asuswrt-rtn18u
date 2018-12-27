/**
   @copyright
   Copyright (c) 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Montavista Linux specific VRF abstraction.
*/

#ifdef HAVE_MVL_VRF
#include "linux_internal.h"
#include "linux_vrf.h"
#include "interceptor.h"

/* Montavista header */
#include <net/vrf.h>

#define SSH_DEBUG_MODULE "SshInterceptorVrfMontavista"

/* Convert SshVriId to platform specific VRI ID. */
int ssh_interceptor_convert_vri_id_to_platform_vri(SshVriId id)
{
  switch(id)
    {
    case SSH_INTERCEPTOR_VRI_ID_ANY:
    case SSH_INTERCEPTOR_VRI_ID_GLOBAL:
      return VRF_ID_GLOBAL;
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
    pid = VRF_ID_GLOBAL;

  SSH_ASSERT(pid <= VRF_ID_MAX);

  return skb_vrf_set(skb, (uint16_t) pid);
}

/* Get VRI ID from SKB. */
SshVriId ssh_skb_get_vrf_id(struct sk_buff *skb)
{
  SshVriId id = skb_vrf(skb);

  switch(id)
    {
    case VRF_UNSPEC:
      if (skb->dev != NULL)
        id = ssh_interceptor_get_dev_vrf_id(skb->dev);
      break;

    case VRF_GLOBAL:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

      /* We intentionally convert VRF_ANY to global. */
    case VRF_ANY:
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
    case VRF_UNSPEC:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

    case VRF_GLOBAL:
      id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      break;

      /* We intentionally convert VRF_ANY to global. */
    case VRF_ANY:
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
  struct vrf *vrf;

  SSH_ASSERT(id != SSH_INTERCEPTOR_VRI_ID_ANY);

  if (id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    return vrf_net(vrf_global);

  vrf = vrf_lookup_by_id((uint16_t) id);
  if (vrf != NULL)
    return vrf_net((struct vrf *)vrf);

  /* If VRF is null and not global, we fail. */
  return NULL;
}

/* Convert VRI ID to name */
void ssh_interceptor_vrf_id_to_name(SshVriId routing_instance_id,
                                    char *routing_instance_name)
{
  const char *name;
  SSH_ASSERT(routing_instance_id != SSH_INTERCEPTOR_VRI_ID_ANY);
  SSH_ASSERT(routing_instance_name != NULL);

  if (routing_instance_id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    name = SSH_INTERCEPTOR_VRI_NAME_GLOBAL;
  else
    name = vrf_id_to_name((uint16_t) routing_instance_id);

  ssh_strncpy(routing_instance_name, name, SSH_INTERCEPTOR_VRI_NAMESIZE - 1);
}

/* Validate existence of VRI ID */
Boolean ssh_interceptor_is_valid_vrf_by_id(SshVriId id)
{
  int pid = id;

  if (id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    pid = VRF_ID_GLOBAL;

  if (vrf_lookup_by_id((uint16_t) pid) == NULL)
    return FALSE;
  else
    return TRUE;
}

#endif /* HAVE_MVL_VRF */
