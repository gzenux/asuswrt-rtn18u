/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains code related to manipulating network interfaces.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "sshtimeouts.h"
#include "sshmp-xuint.h"

#define SSH_DEBUG_MODULE "SshEngineInterfaces"

/**************************** Internal utility functions *********************/

void ssh_engine_interfaces_clear(SshEngine engine)
{
#ifdef SSHDIST_IPSEC_NAT
  SshUInt32 idx;
  SshEngineIfInfo if_info;

  ssh_kernel_mutex_lock(engine->interface_lock);

  for (idx = 0; idx < engine->ifs.nifs; idx++)
    {
      if_info = engine->ifs.ifs[idx].ctx_user;
      if (if_info != NULL)
        {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          ssh_engine_arp_if_info_free(engine, if_info);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
          ssh_free(if_info);
        }
      engine->ifs.ifs[idx].ctx_user = NULL;
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);
#endif /* SSHDIST_IPSEC_NAT */
}


/* Returns the offset of `addr' from `base', that is, the difference
   of the two addresses considered numerically.  This works for both
   IPv4 and IPv6.  The result is undefined if the difference does not fit
   in 32 bits (for IPv6). */

SshUInt32 ssh_engine_ipaddr_subtract(const SshIpAddr addr,
                                     const SshIpAddr base)
{
  size_t len, len2;
  unsigned char buf[16], buf2[16];

  SSH_IP_ENCODE(addr, buf, len);
  SSH_IP_ENCODE(base, buf2, len2);
  return SSH_GET_32BIT(buf + len - 4) - SSH_GET_32BIT(buf2 + len2 - 4);
}

/* Sets `*result' to the IP address at `offset' from `base', that is,
   adds `offset' to the numerical value of `base'.  This works for IPv4 and
   IPv6. */

void ssh_engine_ipaddr_add(SshIpAddr result,
                           const SshIpAddr base,
                           SshUInt32 offset)
{
  size_t len;
  unsigned char buf[16] = { 0 };
  SshUInt32 old, value;

  SSH_IP_ENCODE(base, buf, len);
  old = SSH_GET_32BIT(buf + len - 4);
  value = old + offset;
  SSH_PUT_32BIT(buf + len - 4, value);
  if (value < old && len == 16)
    { /* Value wrapped */
      value = SSH_GET_32BIT(buf + 8);
      value++;
      /* Note: we don't check if this wraps, even though theoretically
         we should.  However, IPv6 nets are typically allocated in
         chunks of 64 bits or less, and thus 32-bit ranges exceeding a
         64 bit boundary do not make sense. */
      SSH_PUT_32BIT(buf + 8, value);
    }
  SSH_IP_DECODE(result, buf, len);
}

/* Returns the offset of `addr' from `base', that is, the difference
   of the two addresses considered numerically.  This works for both
   IPv4 and IPv6. */

void ssh_engine_ipaddr_subtract_128(const SshIpAddr addr,
                                    const SshIpAddr base,
                                    SshXUInt128 difference)
{
  SshXUInt128 addr128;
  SshXUInt128 base128;
  SshXUInt128 diff128;

  /* This works even for IPv4/IPv6 combination, however,
     results are likely to be meaningless in that case. */
  SSH_XUINT128_FROM_IP(addr128, addr);
  SSH_XUINT128_FROM_IP(base128, base);

  SSH_XUINT128_SUB(diff128, addr128, base128);

  memcpy(difference, diff128, sizeof(SshXUInt128));
}

/* Sets `*result' to the IP address at `offset' from `base', that is,
   adds `offset' to the numerical value of `base'.  This works for IPv4 and
   IPv6. */

void ssh_engine_ipaddr_add_128(SshIpAddr result,
                               const SshIpAddr base,
                               SshXUInt128 number_to_add128)
{
  SshXUInt128 addr128;
  SshXUInt128 base128;
  SSH_XUINT128_FROM_IP(base128, base);
  SSH_XUINT128_ADD(addr128, base128, number_to_add128);

  /* Result inherits type of base. */
  SSH_XUINT128_TO_IP(addr128, result, SSH_IP_ADDR_LEN(base));
}

/********************** Interface change event processing ********************/

/* Send the new interface list to the policy manager by calling
   ssh_pmp_interface_change immediately.  This function gets called
   from a timeout in the policy manager context in the unified address
   space case, or immediately in the non-unified address space
   case. */

void ssh_engine_interface_change_pmp(void *context)
{
  SshEngine engine = (SshEngine)context;

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  if (ssh_engine_upcall_timeout(engine) == FALSE)
    return;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /* Call the policy manager interface change function. */
  ssh_pmp_interface_change(engine->pm, &engine->ifs);
}

/* This function is called whenever the interface list changes.  This
   function can be called concurrently with other functions, and it
   may also be possible that another interface callback is received
   before this completes. */

void ssh_engine_interfaces_callback(SshUInt32 nifs,
                                    SshInterceptorInterface *ifs,
                                    void *context)
{
  SshEngine engine = (SshEngine)context;
  SshInterceptorInterface *old_if, *new_if;
  SshUInt32 i;
  SshIpInterfacesStruct copy;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 iface_info_change_flags;
  SshUInt32 n, t;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_DEBUG(SSH_D_MIDSTART, ("received %d interfaces", (int) nifs));

  /* Package us into a table */
  if (ssh_ip_init_interfaces_from_table(&copy, ifs, nifs) == FALSE)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to allocate interface table!"));
      return;
    }

  /* Engine may use either interface_lock or flow_control_table_lock
     to access the interface table */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Update interfaces */
  for (i = 0; i < copy.nifs; i++)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      iface_info_change_flags = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      SSH_DEBUG(4, ("Added interface %s ifnum %d routing instance %d: %s",
                    copy.ifs[i].name, (int) copy.ifs[i].ifnum,
                    copy.ifs[i].routing_instance_id,
                    copy.ifs[i].routing_instance_name));

      old_if = ssh_ip_get_interface_by_ifnum(&engine->ifs, copy.ifs[i].ifnum);
#ifdef DEBUG_LIGHT
      if (old_if == NULL)
        {
          SshUInt32 print_idx;

          for (print_idx = 0; print_idx < copy.ifs[i].num_addrs; print_idx++)
            {
              SSH_DEBUG(4, ("interface %s: ifnum %d addr %@ mask %@",
                            copy.ifs[i].name,
                            (int) copy.ifs[i].ifnum,
                            ssh_ipaddr_render,
                            &copy.ifs[i].addrs[print_idx].addr.ip.ip,
                            ssh_ipaddr_render,
                            &copy.ifs[i].addrs[print_idx].addr.ip.mask));
            }
        }
#endif /* DEBUG_LIGHT */

      if (old_if != NULL)
        {
          copy.ifs[i].ctx_user = old_if->ctx_user;
        }
      else
        {
          SshEngineIfInfo if_info = NULL;

          if_info = ssh_calloc(1, sizeof(SshEngineIfInfoStruct));
          if (if_info == NULL)
            goto error_out;

          copy.ifs[i].ctx_user = (void *) if_info;

#ifdef SSHDIST_IPSEC_NAT
          if_info->nat_type = SSH_PM_NAT_TYPE_NONE;
#endif /* SSHDIST_IPSEC_NAT */
        }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (old_if)
        {
          /* Check if interface properties have changed. */
          if (memcmp(old_if->media_addr, copy.ifs[i].media_addr,
                     old_if->media_addr_len))
            iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;

          if (old_if->routing_instance_id != copy.ifs[i].routing_instance_id)
            iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;

          if (strncmp(old_if->routing_instance_name,
                      copy.ifs[i].routing_instance_name,
                      strlen(copy.ifs[i].routing_instance_name)) != 0)
            iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;

          if (old_if->num_addrs > copy.ifs[i].num_addrs)
            iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;

          /* Check if interface has moved from link down to link up. */
          if ((old_if->flags & SSH_INTERFACE_FLAG_LINK_DOWN)
              && (copy.ifs[i].flags & SSH_INTERFACE_FLAG_LINK_DOWN) == 0)
            iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;

          /* Check that all IP addresses are same, if any changes,
             update the interface. */
          for (n = 0;
               n < old_if->num_addrs && iface_info_change_flags == 0;
               n++)
            {
              Boolean found = FALSE;

              for (t = 0; t < copy.ifs[i].num_addrs && found != TRUE; t++)
                {
                  if ((SSH_IP_EQUAL(&copy.ifs[i].addrs[t].addr.ip.ip,
                                    &old_if->addrs[n].addr.ip.ip)) &&
                      (SSH_IP_EQUAL(&copy.ifs[i].addrs[t].addr.ip.mask,
                                    &old_if->addrs[n].addr.ip.mask)))
                    found = TRUE;
                }

              if (found == FALSE)
                iface_info_change_flags = SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH;
            }
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Old interface %p, flags: %x.", old_if,
                              iface_info_change_flags));

      /* Update ARP cache for new interfaces and changed interfaces. */
      ssh_engine_arp_update_interface(engine, copy.ifs[i].ifnum, old_if,
                                      &copy.ifs[i], iface_info_change_flags);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }

  for (i = 0; i < engine->ifs.nifs; i++)
    {
      new_if = ssh_ip_get_interface_by_ifnum(&copy, engine->ifs.ifs[i].ifnum);

      if (new_if == NULL)
        {
          SshEngineIfInfo if_info;

          SSH_DEBUG(4, ("Removed interface %s", engine->ifs.ifs[i].name));
          if_info = engine->ifs.ifs[i].ctx_user;

          if (if_info != NULL)
            {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
              ssh_engine_arp_if_info_free(engine, if_info);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
              ssh_free(if_info);
            }

          engine->ifs.ifs[i].ctx_user = NULL;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          ssh_engine_arp_update_interface(engine,
                                          engine->ifs.ifs[i].ifnum,
                                          &engine->ifs.ifs[i],
                                          NULL,
                                          SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
        }
    }

  ssh_ip_uninit_interfaces(&engine->ifs);
  engine->ifs = copy;

  ssh_kernel_mutex_unlock(engine->interface_lock);

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Record the timeout before actually wrapping to the policymanager
     thread */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_engine_record_upcall(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Schedule a timeout that will call ssh_pmp_interface_change.  Note
     that we intentionally use ssh_xregister_timeout, not
     ssh_kernel_timeout_register, so that the timeout will obey the
     concurrency control semantics that the single-threaded policy
     manager expects. */
  ssh_xregister_timeout(0L, 0L, ssh_engine_interface_change_pmp,
                       (void *)engine);
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  /* Call the pmp function immediately; the call will be queued by the
     interface between the engine and the policy manager. */
  ssh_engine_interface_change_pmp((void *)engine);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  return;

 error_out:
  SSH_DEBUG(SSH_D_ERROR, ("Memory allocation for interface info failed. "
                          "No update done for engine interfaces."));

  for (i = 0; i < copy.nifs; i++)
    {
      old_if = ssh_ip_get_interface_by_ifnum(&engine->ifs, copy.ifs[i].ifnum);
      if (old_if == NULL && copy.ifs[i].ctx_user)
        {
          SshEngineIfInfo if_info = copy.ifs[i].ctx_user;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          ssh_engine_arp_if_info_free(engine, if_info);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
          ssh_free(if_info);
          copy.ifs[i].ctx_user = NULL;
        }
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);
  ssh_ip_uninit_interfaces(&copy);
}


/*********************** IP address selection ********************************/

/* Retrieves an IP address for the given interface in the given
   protocol.  Engine->flow_table_lock must be held when this is
   called.  This returns TRUE if an address for that protocol was
   found; otherwise this returns FALSE. */
Boolean ssh_engine_get_ipaddr(SshEngine engine, SshEngineIfnum ifnum,
                              SshInterceptorProtocol protocol,
                              SshIpAddr match_ip,
                              SshIpAddr ip_addr_return)
{
  SshInterceptorInterface *ifp;
  SshUInt32 i;
  Boolean have_link_local;
  SshIpAddrStruct link_local;









  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Sanity check ifnum. */
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp == NULL)
    return FALSE;

  /* Loop over all addresses for ifnum, and return the first one in
     the correct protocol.  IPv6 link-local addresses are saved but
     not returned at this stage (this causes non-local addresses to be
     preferred). */
  have_link_local = FALSE;
  SSH_IP_UNDEFINE(&link_local);
  memset(ip_addr_return, 0, sizeof(*ip_addr_return));
  for (i = 0; i < ifp->num_addrs; i++)
    if (ifp->addrs[i].protocol == protocol)
      {
        if (match_ip && !ssh_ipaddr_with_mask_equal(match_ip,
                                                  &ifp->addrs[i].addr.ip.ip,
                                                  &ifp->addrs[i].addr.ip.mask))
          continue;

        if (SSH_IP6_IS_LINK_LOCAL(&ifp->addrs[i].addr.ip.ip))
          {
            link_local = ifp->addrs[i].addr.ip.ip;
            have_link_local = TRUE;
            continue;
          }

        *ip_addr_return = ifp->addrs[i].addr.ip.ip;
        return TRUE;
      }

  /* If we didn't find a real address, return the link-local address. */
  if (have_link_local)
    {
      *ip_addr_return = link_local;
      return TRUE;
    }

  /* No address was found. */
  memset(ip_addr_return, 0, sizeof(*ip_addr_return));
  return FALSE;
}
