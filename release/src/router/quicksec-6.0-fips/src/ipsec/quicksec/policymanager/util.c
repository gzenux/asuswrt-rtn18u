/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   General utility functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmUtil"

int
ssh_pm_rule_render(unsigned char *buf, int buf_size,
                   int precision, void *datum)
{
  SshPmRule rule = (SshPmRule) datum;
  int wrote;
  char flags[128];

  /* Format flags. */
  flags[0] = '\0';
  if (rule->flags & SSH_PM_RULE_PASS)
    strcat(flags, ", pass");
  if (rule->flags & SSH_PM_RULE_REJECT)
    strcat(flags, ", reject");
  if (rule->flags & SSH_PM_RULE_LOG)
    strcat(flags, ", log-flows");
  if (rule->flags & SSH_PM_RULE_RATE_LIMIT)
    strcat(flags, ", rate-limit");
  if (rule->flags & SSH_PM_RULE_NO_FLOW)
    strcat(flags, ", no-flow");

  wrote = ssh_snprintf(buf, buf_size,
                       "Rule ID %u: prec=%u, flags=[%s], ft=%u, tt=%u, "
                       "implement=0x%x, ttflags=0x%x",
                       (unsigned int) rule->rule_id,
                       (unsigned int) rule->precedence,
                       flags[0] ? flags + 2 : flags,
                       (unsigned int)
                       (rule->side_from.tunnel
                        ? rule->side_from.tunnel->tunnel_id : 0),
                       (unsigned int)
                       (rule->side_to.tunnel
                        ? rule->side_to.tunnel->tunnel_id : 0),
                       (unsigned int)
                       rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT],
                       (unsigned int)
                       (rule->side_to.tunnel
                        ? rule->side_to.tunnel->flags : 0));


  if (wrote >= buf_size - 1)
    return buf_size + 1;

#ifdef SSHDIST_IPSEC_NAT

  /* Dump src nat */
  if (SSH_IP_DEFINED(&(rule->nat_src_low)))
    {
      wrote +=
        ssh_snprintf(&buf[wrote], buf_size - wrote,
                     " src-nat: ip=%@-%@ port=%u flags=0x%x",
                     ssh_ipaddr_render, &(rule->nat_src_low),
                     ssh_ipaddr_render, &(rule->nat_src_high),
                     (unsigned int)rule->nat_src_port,
                     (unsigned int)rule->nat_flags);

      if (wrote >= buf_size - 1)
        return buf_size + 1;
    }
  /* Dump dst nat */
  if (SSH_IP_DEFINED(&(rule->nat_dst_low)))
    {
      wrote +=
        ssh_snprintf(&buf[wrote], buf_size - wrote,
                     " dst-nat: ip=%@-%@ port=%u flags=0x%x",
                     ssh_ipaddr_render, &(rule->nat_dst_low),
                     ssh_ipaddr_render, &(rule->nat_dst_high),
                     (unsigned int)rule->nat_dst_port,
                     (unsigned int)rule->nat_flags);

      if (wrote >= buf_size - 1)
        return buf_size + 1;
    }

#endif /* SSHDIST_IPSEC_NAT */

  if (precision >= 0)
    if (wrote > precision)
      wrote = precision;

  return wrote;
}


void
ssh_pm_destructor_timeout(void *context)
{
  SshPm pm = (SshPm) context;
  SshPmDestroyCB callback = pm->destroy_callback;
  void *callback_context = pm->destroy_callback_context;

  SSH_PM_ASSERT_PM(pm);

  SSH_DEBUG(SSH_D_HIGHOK, ("Freeing policy manager %p", pm));
  ssh_pm_free(pm);

#ifdef SSHDIST_IPSEC_DNSPOLICY
  /* Shut down domain name services */
  ssh_name_server_shutdown();
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  if (callback)
    (*callback)(callback_context);
}

/* Fills in the SshInterceptorRouteKey `key' from the given information. */
void ssh_pm_create_route_key(SshPm pm,
                             SshInterceptorRouteKey key,
                             SshIpAddr src,
                             SshIpAddr dst,
                             SshUInt8 ipproto,
                             SshUInt16 src_port,
                             SshUInt16 dst_port,
                             SshUInt32 ifnum,
                             SshVriId routing_instance_id)
{
  /* Assert that destination is valid. */
  SSH_ASSERT(dst != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(dst));

  /* Initialize key and set destination address selector */
  SSH_INTERCEPTOR_ROUTE_KEY_INIT(key);

  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(key, dst);
  if (ssh_pm_find_interface_by_address(pm, dst, routing_instance_id,
                                       NULL) != NULL)
    key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_DST;

  SSH_INTERCEPTOR_ROUTE_KEY_SET_RIID(key, routing_instance_id);

  /* Set the source address if applicable. */
  if (src && SSH_IP_DEFINED(src)
      && ssh_pm_find_interface_by_address(pm, src, routing_instance_id,
                                          NULL) != NULL)
    {
      key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_SRC;
      SSH_INTERCEPTOR_ROUTE_KEY_SET_SRC(key, src);
    }

  /* Interface number is also put, note that the src ip
     and ifnum might be in diffrent interfaces. */
  if (ifnum != SSH_INVALID_IFNUM)
    SSH_INTERCEPTOR_ROUTE_KEY_SET_OUT_IFNUM(key, ifnum);

  /* Set transport layer selectors if possible.
     Only couple of protocols supported. */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_SCTP:
      SSH_INTERCEPTOR_ROUTE_KEY_SET_IPPROTO(key, ipproto);

      if (src_port)
        SSH_INTERCEPTOR_ROUTE_KEY_SET_SRC_PORT(key, src_port);

      if (dst_port)
        SSH_INTERCEPTOR_ROUTE_KEY_SET_DST_PORT(key, dst_port);
      break;

    default:
      /* Do nothing, can't set anything reasonable infomation. */
      break;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("route key: selector 0x%04x "
             "dst %@ src %@ ifnum %d ipproto %d "
             "tcp dst_port %d src_port %d routing instance id %d",
             key->selector,
             ssh_ipaddr_render, &key->dst,
             ssh_ipaddr_render,
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC) ?
              &key->src : NULL),
             (int)
             ((key->selector & (SSH_INTERCEPTOR_ROUTE_KEY_IN_IFNUM |
                                SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM)) ?
              key->ifnum : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IPPROTO) ?
              key->ipproto : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_TCP_DST_PORT) ?
              key->th.tcp.dst_port : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_TCP_SRC_PORT) ?
              key->th.tcp.src_port : -1), routing_instance_id));
}

SshInterceptorInterface *
ssh_pm_find_interface(SshPm pm, const char *ifname, SshUInt32 *ifnum_return)
{
  SshUInt32 ifnum;
  Boolean retval;

  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      SshInterceptorInterface *ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);

      if (ifp != NULL && strcmp(ifp->name, ifname) == 0)
      {
        /* Found it. */
        if (ifnum_return)
          *ifnum_return = ifnum;

        return ifp;
      }
    }

  return NULL;
}


SshInterceptorInterface *
ssh_pm_find_interface_by_ifnum(SshPm pm, SshUInt32 ifnum)
{
  return ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
}

const char *
ssh_pm_find_interface_vri_name(int routing_instance_id,
                               void * context)
{
  SshPm pm = (SshPm) context;

  return ssh_ip_get_interface_vri_name(&pm->ifs, routing_instance_id);
}

int
ssh_pm_find_interface_vri_id(const char * routing_instance_name,
                             void * context)
{
  SshPm pm = (SshPm) context;

  return ssh_ip_get_interface_vri_id(&pm->ifs, routing_instance_name);
}

int
ssh_pm_find_interface_vri_id_by_ifnum(SshUInt32 ifnum, void * context)
{
  SshPm pm = (SshPm) context;
  SshInterceptorInterface *iface = NULL;

  iface = ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
  if (iface != NULL)
    return iface->routing_instance_id;
  else
    return SSH_INTERCEPTOR_VRI_ID_ANY;
}

SshInterceptorInterface *
ssh_pm_find_interface_by_address(SshPm pm, SshIpAddr addr,
                                     int routing_instance_id,
                                     SshUInt32 *ifnum_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_ip_get_interface_by_ip(&pm->ifs, addr, routing_instance_id);
  if (ifp != NULL && ifnum_return != NULL)
    *ifnum_return = ifp->ifnum;

  return ifp;
}

SshInterceptorInterface *
ssh_pm_find_interface_by_address_prefix(SshPm pm, SshIpAddr addr,
                                        SshVriId routing_instance_id,
                                        SshUInt32 *ifnum_return)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_ip_get_interface_by_ip(&pm->ifs, addr, routing_instance_id);
  if (ifp != NULL)
    {
      if (ifnum_return)
        *ifnum_return = ifp->ifnum;
      return ifp;
    }

  ifp = ssh_ip_get_interface_by_subnet(&pm->ifs, addr, routing_instance_id);
  if (ifp != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Could not find interface by exact address, using "
                 "interface based on masked address"));
      if (ifnum_return)
        *ifnum_return = ifp->ifnum;
      return ifp;
    }

  return NULL;
}

/* Return IP address (either of family IPv6 or IPv4 for interface
   'ifnum', or NULL if interface is unknown. Prefer addresses we
   are bound to (in order of appgw, ike) */
SshIpAddr
ssh_pm_find_interface_address(SshPm pm, SshUInt32 ifnum, Boolean ipv6,
                              const SshIpAddr dst)
{
  SshInterceptorInterface *ifp;
  SshUInt32 i;
  SshIpAddr first = NULL;
  SshUInt32 j;

  ifp = ssh_ip_get_interface_by_ifnum(&pm->ifs, ifnum);
  if (ifp == NULL)
    return NULL;

  /* If our IKE is bound to certain addresses, prefer those. */
  for (j = 0; j < pm->params.ike_addrs_count; j++)
    {
      for (i = 0; i < ifp->num_addrs; i++)
        {
          SshInterfaceAddress addr = &ifp->addrs[i];

          if (SSH_IP_EQUAL(&pm->params.ike_addrs[j], &addr->addr.ip.ip))
            return &addr->addr.ip.ip;
        }
    }

  /* Select the local address.  If the destination address is given,
     check if the interface has direct connection to the same network
     with the destination.  If the direct connection is not found, or
     the destination address was not given, return the first IP
     address of the given IP version. */
  for (i = 0; i < ifp->num_addrs; i++)
    {
      SshInterfaceAddress addr = &ifp->addrs[i];

      if ((addr->protocol == SSH_PROTOCOL_IP4 && ipv6)
          || (addr->protocol == SSH_PROTOCOL_IP6 && !ipv6))
        /* Wrong IP address version. */
        continue;

      /* The IP version matches. */

      if (first == NULL)
        {
          /* Record the first address of the given type. */
          first = &addr->addr.ip.ip;
        }
      else if (ipv6
               && SSH_IP6_IS_LINK_LOCAL(first)
               && !SSH_IP6_IS_LINK_LOCAL(&addr->addr.ip.ip))
        {
          /* Prefer non-local (or non-link local) addresses. */
          first = &addr->addr.ip.ip;
        }

      if (dst)
        {
          /* Check if address belongs to the same network with the
             destination. */

          SSH_ASSERT(SSH_IP_DEFINED(dst));

          if (SSH_IP_IS4(dst))
            {
              SshUInt32 ip_int = SSH_IP4_TO_INT(&addr->addr.ip.ip);
              SshUInt32 dst_int = SSH_IP4_TO_INT(dst);
              SshUInt32 mask_int = SSH_IP4_TO_INT(&addr->addr.ip.mask);

              if ((ip_int & mask_int) == (dst_int & mask_int))
                /* They both belong to the same network. */
                return &addr->addr.ip.ip;
            }
          else
            {
              unsigned char ipbuf[16];
              unsigned char dstbuf[16];
              unsigned char maskbuf[16];
              SshUInt32 indx;

              SSH_IP6_ENCODE(&addr->addr.ip.ip, ipbuf);
              SSH_IP6_ENCODE(dst, dstbuf);
              SSH_IP6_ENCODE(&addr->addr.ip.mask, maskbuf);

              /* Check all words. */
              for (indx = 0; indx < 4; indx++)
                {
                  SshUInt32 ip_int = SSH_GET_32BIT(ipbuf + indx * 4);
                  SshUInt32 dst_int = SSH_GET_32BIT(dstbuf + indx * 4);
                  SshUInt32 mask_int = SSH_GET_32BIT(maskbuf + indx * 4);

                  if ((ip_int & mask_int) != (dst_int & mask_int))
                    /* The address does not match. */
                    break;
                }

              if (indx < 4)
                /* It did not match.  Continue searching. */
                continue;

              /* The both belong to the same network. */
              return &addr->addr.ip.ip;
            }
        }
    }

  /* Return the first address of the given type or NULL if no
     addresses could be found. */
  return first;
}


Boolean
ssh_pm_fetch_ip6_payload(const unsigned char *packet,
                         size_t packet_len, size_t *offsetp,
                         SshInetIPProtocolID *ipprotop,
                         size_t *prev_nh_ofs_return,
                         SshIpAddr final_dst_return)
{
  size_t offset = 0;
  SshInetIPProtocolID next;
  size_t prev_nh_ofs;

  /* Fetch the IPv6 header. */

  if (SSH_IPH6_HDRLEN > packet_len)
    return FALSE;

  next = SSH_IPH6_NH(packet);

  prev_nh_ofs = SSH_IPH6_OFS_NH;
  offset += SSH_IPH6_HDRLEN;

  /* Skip all possible extension headers. */
  while (1)
    {
      if (SSH_IP6_EXT_IS_COMMON(next))
        {
          /* Extension header in the common extension header
             format. */
          if (offset + SSH_IP6_EXT_COMMON_HDRLEN > packet_len)
            /* Truncated packet. */
            return FALSE;

          /* Save the offset of the previous `Next Header' field. */
          prev_nh_ofs = offset + SSH_IP6_EXT_COMMON_OFS_NH;

          /* Handle routing header if caller wants to get the final
             destination address. */
          if (final_dst_return && next == SSH_IPPROTO_IPV6ROUTE)
            {
              size_t hdrlen = SSH_IP6_EXT_COMMON_LENB(packet + offset);
              SshUInt8 type, segments;

              /* Process routing header. */
              if (offset + hdrlen > packet_len)
                /* Truncated packet. */
                return FALSE;

              type = SSH_IP6_EXT_ROUTING_TYPE(packet + offset);
              segments = SSH_IP6_EXT_ROUTING_SEGMENTS(packet + offset);
              if (segments != 0)
                {
                  /* The final destination is still in the routing
                     header. */
                  if (type != 0)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Routing header with unknown type %u", type));
                      return FALSE;
                    }

                  /* Sanity check for header length. */
                  if (hdrlen != segments * 16 + 8)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Invalid header length in IPv6 "
                                 "routing header"));
                      return FALSE;
                    }

                  /* The final destination is the last address in the
                     list. */
                  SSH_IP6_DECODE(final_dst_return,
                                 packet + offset + hdrlen - 16);
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Found final destination %@ "
                             "from IPv6 routing header",
                             ssh_ipaddr_render, final_dst_return));
                }
            }

          /* Proceed to the next header. */
          next = SSH_IP6_EXT_COMMON_NH(packet + offset);
          offset += SSH_IP6_EXT_COMMON_LENB(packet + offset);
        }
      else
        {
          /* The payload itself or SSH_IPPROTO_IPV6FRAG for fragmented
             payloads. */
          break;
        }
    }

  *ipprotop = next;
  *offsetp = offset;

  if (prev_nh_ofs_return)
    *prev_nh_ofs_return = prev_nh_ofs;

  return TRUE;
}



char *
ssh_pm_util_data_to_hex(char *buf, size_t buflen,
                        const unsigned char *data, size_t datalen)
{
  int i;
  size_t nprint;

  nprint = datalen;
  if (buflen / 3 < nprint)
    nprint = buflen / 3;

  if (nprint)
    {
      for (i = 0; i < nprint; i++)
        ssh_snprintf(buf + i * 3, buflen - i * 3, "%02x ", data[i]);
      buf[nprint * 3 - 1] = '\000';
    }
  else
    {
      SSH_ASSERT(buflen >= 1);
      buf[0] = '\000';
    }

  return buf;
}

void
ssh_pm_set_extension_selectors(SshPmRule rule, SshEnginePolicyRule erule)
{
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 i;
  Boolean extsel_set = FALSE;

  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      if (rule->extsel_low[i] != 0 || rule->extsel_high[i] != 0xffffffff)
        {
          /* This extension selector is set. */
          erule->extension_selector_low[i] = rule->extsel_low[i];
          erule->extension_selector_high[i] = rule->extsel_high[i];

          /* At least one extension selector set. */
          extsel_set = TRUE;
        }
      else
        {
          /* This extension selector is not set.  Make is range
             nonexistent (the low value is bigger than the high
             value). */
          erule->extension_selector_low[i] = 42;
          erule->extension_selector_high[i] = 0;
        }
    }

  /* Set the extension selector flag if any of the extension selectors
     was set. */
  if (extsel_set)
    erule->selectors |= SSH_SELECTOR_EXTENSIONS;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
}


/********************** General thread help functions ***********************/

void
ssh_pm_timeout_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Check if authorization of p1 allows access to the rule. */
Boolean ssh_pm_check_rule_authorization(SshPmP1 p1, SshPmRule rule)
{
  SshUInt32 i, j;

  if (rule->num_access_groups == 0)
    return TRUE;

  SSH_DEBUG(SSH_D_LOWSTART, ("Matching authorization group IDS"));

  for (i = 0; i < rule->num_access_groups; i++)
    {
      for (j = 0; j < p1->num_authorization_group_ids; j++)
        {
          if (p1->authorization_group_ids[j] == rule->access_groups[i])
            {
              return TRUE;
            }
        }
      for (j = 0; j < p1->num_xauth_authorization_group_ids; j++)
        {
          if (p1->xauth_authorization_group_ids[j] == rule->access_groups[i])
            {
              return TRUE;
            }
        }
    }
  SSH_DEBUG(SSH_D_FAIL, ("Authorization failed; access groups did not match"));
  return FALSE;
}
