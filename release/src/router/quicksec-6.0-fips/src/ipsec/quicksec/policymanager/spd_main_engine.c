/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Top-level functions for policy manager objects Engine dependent.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmEngine"

Boolean
ssh_pm_set_kernel_debug_level(SshPm pm, const char *level_string)
{
  ssh_pme_set_debug_level(pm->engine, level_string);
  return TRUE;
}

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
Boolean
ssh_pm_configure_internal_nat(SshPm pm,
                              const unsigned char *first_ip,
                              const unsigned char *last_ip,
                              SshPmStatusCB callback, void *context)
{
  SshIpAddrStruct first_ip_addr;
  SshIpAddrStruct last_ip_addr;

  SSH_IP_UNDEFINE(&first_ip_addr);
  SSH_IP_UNDEFINE(&last_ip_addr);

  if (first_ip != NULL || last_ip != NULL)
    {
      if (first_ip != NULL && !ssh_ipaddr_parse(&first_ip_addr, first_ip))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid IP address `%s'", first_ip));
          goto error;
        }
      if (last_ip != NULL && !ssh_ipaddr_parse(&last_ip_addr, last_ip))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid IP address `%s'", last_ip));
          goto error;
        }
      if (SSH_IP_CMP(&first_ip_addr, &last_ip_addr) > 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Invalid IP address range `%s-%s'",
                                  first_ip, last_ip));
          goto error;
        }

      /* Check that they are IPv4 addresses. */
      if (!SSH_IP_IS4(&first_ip_addr) || !SSH_IP_IS4(&last_ip_addr))
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Only IPv4 addresses support in internal NAT"));
          goto error;
        }
    }

  ssh_pme_configure_internal_nat(pm->engine, &first_ip_addr, &last_ip_addr,
                                 callback, context);

  /* All done. */
  return TRUE;

  /* Error handling. */

 error:

  if (callback)
    (*callback)(pm, FALSE, context);

  /* Indicate immediate error */
  return FALSE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

/*************************** Engine Configuration ***************************/

void
ssh_pm_set_engine_params(SshPm pm, SshEngineParams params)

{
  ssh_pme_set_engine_params(pm->engine, params);
}

void
ssh_pm_redo_flows(SshPm pm)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Calling ssh_pme_redo_flows()"));
  ssh_pme_redo_flows(pm->engine);
}


/**************** Standalone gateway configuration functions ****************/

void
ssh_pm_configure_clear_routes(SshPm pm)
{
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  ssh_pme_configure_route_clear(pm->engine);
#endif /* SSH_IPSEC_INTERNAL_ROUTING */
}


void
ssh_pm_configure_route(SshPm pm,
                       const unsigned char *ipmask,
                       const unsigned char *nexthopip,
                       SshUInt32 ifnum,
                       SshPmStatusCB callback, void *context)
{
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  SshIpAddrStruct dst;
  SshIpAddrStruct gw;

  if (!ssh_ipaddr_parse_with_mask(&dst, ipmask, NULL)
      && !ssh_ipaddr_parse(&dst, ipmask))
    goto error;

  if (!ssh_ipaddr_parse(&gw, nexthopip))
    goto error;

  ssh_pme_configure_route_add(pm->engine, &dst, &gw, ifnum, callback, context);

  /* All done. */
  return;


  /* Error handling. */

 error:
  /* FALLTHROUGH */
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

  if (callback)
    (*callback)(pm, FALSE, context);
}


void ssh_pm_media_address_mapping_add(SshPm pm,
                                       const SshIpAddr ip,
                                       SshUInt32 ifnum,
                                       const unsigned char *media_addr,
                                       size_t media_addr_len,
                                       SshUInt32 flags,
                                       SshPmStatusCB callback, void *context)
{
  SshUInt32 pme_arp_flags = 0;

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("ARP add for IP=%@", ssh_ipaddr_render, ip),
                    media_addr, media_addr_len);

  pme_arp_flags = SSH_PME_ARP_PERMANENT;

  if (ifnum == SSH_INVALID_IFNUM)
    pme_arp_flags |= SSH_PME_ARP_GLOBAL;

  ssh_pme_arp_add(pm->engine, ip, ifnum, media_addr, media_addr_len,
                  pme_arp_flags, callback, context);
}


void ssh_pm_media_address_mapping_remove(SshPm pm,
                                          const SshIpAddr ip,
                                          SshUInt32 ifnum)
{
  SSH_DEBUG(SSH_D_MY, ("ARP remove for IP=%@", ssh_ipaddr_render, ip));

  ssh_pme_arp_remove(pm->engine, ip, ifnum);
}

