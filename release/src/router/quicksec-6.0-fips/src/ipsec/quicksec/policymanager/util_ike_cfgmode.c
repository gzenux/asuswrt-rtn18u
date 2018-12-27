/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Configuration payload related IKE utility functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmUtilIkeCfgmode"

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Store remote access attributes into the configuration payload. This is
   called by the IKE responder when it gets the remote access attributes.
   This function converts them into a IKE configuration payload which is
   then sent in the reply to the IKE initiator. */
Boolean
ssh_pm_encode_remote_access_attrs(SshIkev2PayloadConf conf_payload,
                                  SshPmRemoteAccessAttrs attributes)
{
  unsigned char buf[17];
  size_t len, len2;
  SshIpAddrStruct mask, mask2;
  SshIkev2Error ike_error;
  Boolean netmask_encoded = FALSE;
  SshUInt32 i;

  /* IPv{4,6} address and netmask. */
  for (i = 0; i < attributes->num_addresses; i++)
    {
      if (SSH_IP_IS4(&attributes->addresses[i]))
        {
          SSH_IP_ENCODE(&attributes->addresses[i], buf, len);

          ike_error =
            ssh_ikev2_conf_add(conf_payload,
                               SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS,
                               len, buf);

          if (ike_error != SSH_IKEV2_ERROR_OK)
            goto error;

          if (netmask_encoded == FALSE)
            {
              ssh_ipaddr_set_bits(&mask2, &attributes->addresses[i], 0, 1);
              ssh_ipaddr_set_bits(&mask, &mask2,
                                SSH_IP_MASK_LEN(&attributes->addresses[i]), 0);

              SSH_IP_ENCODE(&mask, buf, len);

              ike_error =
                ssh_ikev2_conf_add(conf_payload,
                                SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK,
                                len, buf);

              if (ike_error != SSH_IKEV2_ERROR_OK)
                goto error;
              netmask_encoded = TRUE;
            }
        }
      else
        {
          SSH_IP_ENCODE(&attributes->addresses[i], buf, len);

          buf[len] = SSH_IP_MASK_LEN(&attributes->addresses[i]);

          ike_error =
            ssh_ikev2_conf_add(conf_payload,
                               SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS,
                               len + 1, buf);

          if (ike_error != SSH_IKEV2_ERROR_OK)
            goto error;
        }
    }

  /* Address expiration. */
  if (attributes->address_expiry_set)
    {
      unsigned char expiry_buf[4];
      SSH_PUT_32BIT(expiry_buf, attributes->address_expiry);

      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY,
                           sizeof(expiry_buf), expiry_buf);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        goto error;
    }

  /* DNS server address. */
  for (i = 0; i < attributes->num_dns; i++)
    {
      SSH_IP_ENCODE(&attributes->dns[i], buf, len);

      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IP_IS4(&attributes->dns[i]) ?
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS :
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS,
                           len, buf);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        goto error;
    }

  /* NetBios name server (WINS) address. */
  for (i = 0; i < attributes->num_wins; i++)
    {
      SSH_IP_ENCODE(&attributes->wins[i], buf, len);

      if (SSH_IP_IS4(&attributes->wins[i]))
        {
          ike_error =
            ssh_ikev2_conf_add(conf_payload,
                               SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS,
                               len, buf);
          if (ike_error != SSH_IKEV2_ERROR_OK)
            goto error;
        }
      else
        SSH_DEBUG(SSH_D_FAIL, ("Ignoring invalid wins '%@'",
                               ssh_ipaddr_render, &attributes->wins[i]));
    }

  /* DHCP server address. */
  for (i = 0; i < attributes->num_dhcp; i++)
    {
      SSH_IP_ENCODE(&attributes->dhcp[i], buf, len);

      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IP_IS4(&attributes->dhcp[i]) ?
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP :
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP,
                           len, buf);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        goto error;
    }

  /* Additional sub-networks. */
  for (i = 0; i < attributes->num_subnets; i++)
    {
      SSH_IP_ENCODE(&attributes->subnets[i], buf, len);

      if (SSH_IP_IS4(&attributes->subnets[i]))
        {
          ssh_ipaddr_set_bits(&mask2, &attributes->subnets[i], 0, 1);
          ssh_ipaddr_set_bits(&mask, &mask2,
                              SSH_IP_MASK_LEN(&attributes->subnets[i]), 0);

          SSH_IP4_ENCODE(&mask, buf + len);
          len2 = 4;
          ike_error =
            ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET,
                           len + len2, buf);
          if (ike_error != SSH_IKEV2_ERROR_OK)
            goto error;
        }
      else
        {
          buf[len] = SSH_IP_MASK_LEN(&attributes->subnets[i]);
          len2 = 1;

          ike_error =
            ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET,
                           len + len2, buf);
          if (ike_error != SSH_IKEV2_ERROR_OK)
            goto error;
        }
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Encoded remote access attribute to the "
                             "configuration payload %@",
                             ssh_ikev2_payload_conf_render,
                             conf_payload));
  return TRUE;

 error:
  return FALSE;
}

/* Parse configuration payload in to the remote access attributes. */
Boolean
ssh_pm_decode_conf_payload_request(SshIkev2PayloadConf conf_payload,
                                   SshPmRemoteAccessAttrs attributes)
{
  SshIkev2ConfAttribute attr;
  SshUInt32 i, j, k, mask_len;

  SSH_DEBUG(SSH_D_MIDSTART, ("Decode the configuration payload %@ to remote "
                             "access attributes",
                             ssh_ikev2_payload_conf_render, conf_payload));

  memset(attributes, 0, sizeof(*attributes));

  SSH_IP_UNDEFINE(&attributes->own_address);

  if (conf_payload == NULL)
    return TRUE;

  mask_len = 32;
  for (i = 0; i < conf_payload->number_of_conf_attributes_used; i++)
    {
      attr = &conf_payload->conf_attributes[i];

      switch (attr->attribute_type)
        {
        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS:

          if (attr->length != 0 && attr->length != 4)
            return FALSE;

          if (attributes->num_addresses >=
              SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Received more addresses than the "
                                     "built-in maximum (%d)",
                                   SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES));
              break;
            }

          /* Use client-specified address in request if specified,
             otherwise use a null address to get any IPv4 address. */
          if (attr->length != 0)
            {
              SSH_IP4_DECODE(&attributes->addresses[attributes->num_addresses],
                             attr->value);
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Decoded an IPv4 address `%@'",
                         ssh_ipaddr_render,
                         &attributes->addresses[attributes->num_addresses]));
            }
          else
            {
              attributes->addresses[attributes->num_addresses].type =
                SSH_IP_TYPE_IPV4;
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Decoded a zero-length IPv4 address request"));
            }

          attributes->num_addresses++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS:

          if (attr->length != 0 && attr->length != 17)
            return FALSE;

          if (attributes->num_addresses >=
              SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Received more addresses than the "
                                     "built-in maximum (%d)",
                                   SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES));
              break;
            }

          /* Use client-specified address in request if specified,
             otherwise use a null address to get any IPv6 address. */
          if (attr->length != 0)
            {
              /* Decode IPv6 address. */
              SSH_IP6_DECODE(&attributes->addresses[attributes->num_addresses],
                             attr->value);

              /* Decode IPv6 prefix-length. */
              k = SSH_GET_8BIT(attr->value + 16);
              SSH_IP_MASK_LEN(&attributes->
                              addresses[attributes->num_addresses]) = k;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Decoded an IPv6 address `%@'",
                         ssh_ipaddr_render,
                         &attributes->addresses[attributes->num_addresses]));
            }
          else
            {
              attributes->addresses[attributes->num_addresses].type =
                SSH_IP_TYPE_IPV6;
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Decoded a zero-length IPv6 address request"));
            }

          attributes->num_addresses++;

          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK:

          /* empty request. */
          if (attr->length == 0)
            continue;

          if (attr->length != 4)
            return FALSE;

          k = SSH_GET_32BIT(attr->value);
          for (j = 1; j <= 32; j++)
            if ((k & (1 << (32 - j))) == 0)
              break;

          mask_len = j - 1;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an IPv4 netmask of %d bits", (int) mask_len));
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS:
        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS:

          if (attributes->num_dns >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Received more DNS addresses than the "
                                     "built-in maximum (%d)",
                                     SSH_PM_REMOTE_ACCESS_NUM_SERVERS));
              break;
            }
          SSH_IP_DECODE(&attributes->dns[attributes->num_dns],
                        attr->value, attr->length);

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an DNS address `%@'",
                     ssh_ipaddr_render,
                     &attributes->dns[attributes->num_dns]));

          attributes->num_dns++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_NBNS:
          /* RFC5996 removed support for INTERNAL_IP6_NBNS. Ignore
             this configuration payload attribute. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Ignoring unsupported configuration payload attribute "
                     "INTERNAL_IP6_NBNS"));
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NBNS:

          if (attributes->num_wins >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Received more NBNS addresses than the "
                                     "built-in maximum (%d)",
                                     SSH_PM_REMOTE_ACCESS_NUM_SERVERS));
              break;
            }

          SSH_IP_DECODE(&attributes->wins[attributes->num_wins],
                        attr->value, attr->length);

          if (attr->length != 0 &&
              !SSH_IP_IS4(&attributes->wins[attributes->num_wins]))
            return FALSE;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an NBNS address `%@'",
                     ssh_ipaddr_render,
                     &attributes->wins[attributes->num_wins]));

          attributes->num_wins++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DHCP:
        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DHCP:

          if (attributes->num_dhcp >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Received more DHCP addresses than the "
                                     "built-in maximum (%d)",
                                     SSH_PM_REMOTE_ACCESS_NUM_SERVERS));
              break;
            }
          SSH_IP_DECODE(&attributes->dhcp[attributes->num_dhcp],
                        attr->value, attr->length);

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an DHCP address `%@'",
                     ssh_ipaddr_render,
                     &attributes->dhcp[attributes->num_dhcp]));

          attributes->num_dhcp++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_ADDRESS_EXPIRY:

          /* empty request */
          if (attr->length == 0)
            continue;

          if (attr->length != 4)
            return FALSE;

          attributes->address_expiry = SSH_GET_32BIT(attr->value);
          attributes->address_expiry_set = TRUE;

          SSH_DEBUG(SSH_D_MIDSTART, ("Received an address expiry of %d "
                                     "seconds",
                                     (int) attributes->address_expiry));
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET:

          if (attr->length == 0)
            continue;

          if (attr->length != 8)
            return FALSE;

          if (attributes->num_subnets >= SSH_PM_REMOTE_ACCESS_NUM_SUBNETS)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Maximum number of subnets received %d",
                         SSH_PM_REMOTE_ACCESS_NUM_SUBNETS));
              goto error;
            }

          SSH_IP4_DECODE(&attributes->subnets[attributes->num_subnets],
                         attr->value);

          k = SSH_GET_32BIT(attr->value + 4);
          for (j = 1; j <= 32; j++)
            if ((k & (1 << (32 - j))) == 0)
              break;

          SSH_IP_MASK_LEN(&attributes->subnets[attributes->num_subnets])
            = j - 1;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an IPv4 subnet `%@'",
                     ssh_ipaddr_render,
                     &attributes->subnets[attributes->num_subnets]));

          attributes->num_subnets++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET:

          if (attr->length == 0)
            continue;

          if (attr->length != 17)
            return FALSE;

          if (attributes->num_subnets >= SSH_PM_REMOTE_ACCESS_NUM_SUBNETS)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Maximum number of subnets received %d",
                         SSH_PM_REMOTE_ACCESS_NUM_SUBNETS));
              goto error;
            }

          SSH_IP6_DECODE(&attributes->subnets[attributes->num_subnets],
                         attr->value);

          k = SSH_GET_8BIT(attr->value + 16);
          SSH_IP_MASK_LEN(&attributes->subnets[attributes->num_subnets]) = k;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Decoded an IPv6 subnet `%@'",
                     ssh_ipaddr_render,
                     &attributes->subnets[attributes->num_subnets]));

          attributes->num_subnets++;
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_SUPPORTED_ATTRIBUTES:
          SSH_DEBUG(SSH_D_LOWOK, ("Received supported attributes"));
          break;

        case SSH_IKEV2_CFG_ATTRIBUTE_APPLICATION_VERSION:
          SSH_DEBUG(SSH_D_LOWOK, ("Recevied application version attribute"));
          break;

        default:
          SSH_DEBUG(SSH_D_LOWOK, ("Ignoring received attribute of type %d",
                                  attr->attribute_type));
          break;
        }
    }

  /* Set the mask length of the IPv4 addresses */
  for (i = 0; i < attributes->num_addresses; i++)
    {
      if (SSH_IP_IS4(&attributes->addresses[i]))
        SSH_IP_MASK_LEN(&attributes->addresses[i]) = mask_len;
    }

  return TRUE;

 error:
  return FALSE;
}


/* Allocate and fill in attributes for a Configuration mode payload. */
SshIkev2PayloadConf
ssh_pm_construct_conf_request_payload(SshPm pm, SshPmP1 p1)
{
  SshIkev2PayloadConf conf_payload = NULL;
  SshPmRemoteAccessAttrs remote_access_attrs = NULL;
  unsigned char address[17], netmask[4];
  size_t i, address_len, netmask_len;
  Boolean netmask_encoded = FALSE;
  SshIpAddrStruct mask, mask2;
  SshIkev2Error ike_error;
  Boolean request_ipv4 = TRUE, ipv4_requested;
  SshPmTunnel tunnel;
#ifdef  SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmRemoteAccessAttrsStruct attrs_struct;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#if defined(WITH_IPV6)
  SshADTHandle handle;
  SshPmRule rule;
  Boolean request_ipv6, ipv6_requested;
#endif /* WITH_IPV6 */

  ipv4_requested = FALSE;
#if defined (WITH_IPV6)
  ipv6_requested = FALSE;
#endif /* WITH_IPV6 */

  conf_payload = ssh_ikev2_conf_allocate(pm->sad_handle,
                                         SSH_IKEV2_CFG_REQUEST);
  if (conf_payload == NULL)
    return NULL;

  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    goto error;

#if defined(WITH_IPV6)
  /* Loop through rules referring to the tunnel and check what addresses
     to request. */
  request_ipv4 = FALSE;
  request_ipv6 = FALSE;
  for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_id, handle))
    {
      rule = (SshPmRule) ssh_adt_get(pm->rule_by_id, handle);

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        continue;

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
      if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
        {
          request_ipv4 = TRUE;
          request_ipv6 = TRUE;
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

      if (SSH_PM_TUNNEL_IS_IKE(rule->side_to.tunnel)
          && rule->side_to.ts != NULL
          && rule->side_to.ts->number_of_items_used > 0
          && rule->side_to.tunnel == tunnel)
        {
          if (SSH_IP_IS4(rule->side_to.ts->items[0].start_address))
            request_ipv4 = TRUE;
          if (SSH_IP_IS6(rule->side_to.ts->items[0].start_address))
            request_ipv6 = TRUE;
        }

      if (SSH_PM_TUNNEL_IS_IKE(rule->side_from.tunnel)
          && rule->side_from.ts != NULL
          && rule->side_from.ts->number_of_items_used > 0
          && rule->side_from.tunnel == tunnel)
        {
          if (SSH_IP_IS4(rule->side_from.ts->items[0].start_address))
            request_ipv4 = TRUE;
          if (SSH_IP_IS6(rule->side_from.ts->items[0].start_address))
            request_ipv6 = TRUE;
        }

      if (request_ipv4 && request_ipv6)
        break;
    }
#endif /* WITH_IPV6 */

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (p1)
    remote_access_attrs = p1->remote_access_attrs;

  /* Should the client request a specific address. */
  if (remote_access_attrs == NULL)
    {
      SshUInt32 index;

      memset(&attrs_struct, 0, sizeof(attrs_struct));

      /* Prefer addresses defined by policy. Do not consider what address
         families the referring rules defined, but assume the user knows
         what he is doing. */
      if (tunnel->u.ike.num_irac_addresses)
        {
          for (index = 0;
               index < tunnel->u.ike.num_irac_addresses;
               index++)
            if (SSH_IP_DEFINED(&tunnel->u.ike.irac_address[index]))
              attrs_struct.addresses[index] =
                tunnel->u.ike.irac_address[index];

          SSH_ASSERT(index <= SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES);

          attrs_struct.num_addresses = tunnel->u.ike.num_irac_addresses;
          remote_access_attrs = &attrs_struct;
        }

      /* No addresses configured, use interface addresses. */
      else
        {
          SshInterceptorInterface *ifp = NULL;

          if (tunnel->vip)
            ifp = ssh_pm_find_interface_by_ifnum(pm,
                                            tunnel->vip->adapter_ifnum);
          if (ifp != NULL)
            {
              for (index = 0;
                   index < ifp->num_addrs
                     && attrs_struct.num_addresses <
                     SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES;
                   index++)
                {
                  /* Skip IPv4 addresses, if no referring rules uses IPv4. */
                  if (SSH_IP_IS4(&ifp->addrs[index].addr.ip.ip)
                      && request_ipv4 == FALSE)
                    continue;

#if defined (WITH_IPV6)
                  /* Skip IPv6 addresses, if no referring rules uses IPv6. */
                  if (SSH_IP_IS6(&ifp->addrs[index].addr.ip.ip)
                      && request_ipv6 == FALSE)
                    continue;
#endif /* WITH_IPV6 */

                  if (SSH_IP_DEFINED(&ifp->addrs[index].addr.ip.ip)
#ifndef SSH_IPSEC_LINK_LOCAL_SERVERS
                      && !SSH_IP6_IS_LINK_LOCAL(&ifp->addrs[index].addr.ip.ip)
#endif /* SSH_IPSEC_LINK_LOCAL_SERVERS */
                      )
                    {
                      attrs_struct.addresses[attrs_struct.num_addresses++] =
                        ifp->addrs[index].addr.ip.ip;
                    }
                }
              if (attrs_struct.num_addresses)
                remote_access_attrs = &attrs_struct;
            }
        }
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  if (remote_access_attrs)
    {
      for (i = 0; i < remote_access_attrs->num_addresses; i++)
        {
          SSH_IP_ENCODE(&remote_access_attrs->addresses[i],
                        address, address_len);

#if defined (WITH_IPV6)
          if (SSH_IP_IS6(&remote_access_attrs->addresses[i]))
            {
              address[16] =
                SSH_IP_MASK_LEN(&remote_access_attrs->addresses[i]);

              ike_error =
                ssh_ikev2_conf_add(conf_payload,
                                 SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS,
                                 address_len + 1, address);
              if (ike_error != SSH_IKEV2_ERROR_OK)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Cannot add IPV6 address attribute to the"
                             " conf payload"));
                  goto error;
                }
              /* Do not need to request any more IPv6 addresses. */
              request_ipv6 = FALSE;
              ipv6_requested = TRUE;
            }
          else
#endif /* WITH_IPV6 */
            {
              ike_error =
                ssh_ikev2_conf_add(conf_payload,
                                SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS,
                                address_len, address);
              if (ike_error != SSH_IKEV2_ERROR_OK)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Cannot add IPV4 address attribute to the"
                             " conf payload"));
                  goto error;
                }
              ipv4_requested = TRUE;

              if (netmask_encoded == FALSE)
                {
                  ssh_ipaddr_set_bits(&mask2,
                                      &remote_access_attrs->addresses[i],
                                      0, 1);
                  ssh_ipaddr_set_bits(&mask, &mask2,
                           SSH_IP_MASK_LEN(&remote_access_attrs->addresses[i]),
                           0);

                  SSH_IP4_ENCODE(&mask, netmask);
                  netmask_len = 4;

                  ike_error =
                    ssh_ikev2_conf_add(conf_payload,
                                SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK,
                                netmask_len, netmask);
                  if (ike_error != SSH_IKEV2_ERROR_OK)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Cannot add IPV4 netmask attribute to "
                                 "the conf payload"));
                      goto error;
                    }
                  netmask_encoded = TRUE;
                }
              /* Do not need to request any more IPv4 addresses. */
              request_ipv4 = FALSE;
            }
        }
    }

  /* If we need an IPv4 address and no IPv4 cfg request was already added,
     then request any IPv4 address. */
  if (request_ipv4)
    {
      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_NETMASK,
                           0, NULL);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot add IPV4 address attribute to the "
                                 "conf payload"));
          goto error;
        }

      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS,
                           0, NULL);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot add IPV4 address attribute to the "
                                 "conf payload"));
          goto error;
        }
      ipv4_requested = TRUE;
    }

#if defined (WITH_IPV6)
  /* If we need an IPv6 address and no IPv6 cfg request was already added,
     then request any IPv6 address */
  if (request_ipv6)
    {
      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS,
                           0, NULL);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot add IPV6 address attribute to the "
                                 "conf payload"));
          goto error;
        }
      ipv6_requested = TRUE;
    }
#endif /* WITH_IPV6 */

  if (ipv4_requested)
    {
      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_DNS,
                           0, NULL);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot add IPV4 DNS address attribute to the "
                     "conf payload"));
          goto error;
        }
    }

#if defined (WITH_IPV6)
  if (ipv6_requested)
    {
      ike_error =
        ssh_ikev2_conf_add(conf_payload,
                           SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_DNS,
                           0, NULL);
      if (ike_error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot add IPV6 DNS address attribute to the "
                     "conf payload"));
          goto error;
        }
      }
#endif /* WITH_IPV6 */


  return conf_payload;

 error:

  ssh_ikev2_conf_free(pm->sad_handle, conf_payload);
  return NULL;
}

SshIkev2Error
ssh_pm_narrow_remote_access_attrs(SshPm pm, Boolean client,
                                  SshPmRemoteAccessAttrs attrs,
                                  SshIkev2PayloadTS ts_local,
                                  SshIkev2PayloadTS ts_remote,
                                  SshIkev2PayloadTS *ts_return_local,
                                  SshIkev2PayloadTS *ts_return_remote)
{
  SshIkev2PayloadTS tmp;
  SshIkev2Error status;
  Boolean ok, ipv4;
  int i;

  *ts_return_local = *ts_return_remote = NULL;

  SSH_ASSERT(SSH_IP_DEFINED(&attrs->addresses[0]));

  SSH_DEBUG(SSH_D_LOWOK, ("Input traffic selectors = %@ <-> %@",
                          ssh_ikev2_ts_render, ts_local,
                          ssh_ikev2_ts_render, ts_remote));

  ipv4 = (ts_local->items[0].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE) ?
    TRUE : FALSE;

  /* Check the traffic selectors are of the same address family. */
  for (i = 0; i < ts_local->number_of_items_used; i++)
    {
      if (ts_local->items[i].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE && !ipv4)
        return SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
      if (ts_local->items[i].ts_type == SSH_IKEV2_TS_IPV6_ADDR_RANGE && ipv4)
        return SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
    }
  for (i = 0; i < ts_remote->number_of_items_used; i++)
    {
      if (ts_remote->items[i].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE && !ipv4)
        return SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
      if (ts_remote->items[i].ts_type == SSH_IKEV2_TS_IPV6_ADDR_RANGE && ipv4)
        return SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
    }

  tmp = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (tmp == NULL)
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  /* First narrow the input traffic selector using the assigned client's
     addresses */
  for (i = 0; i < SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES; i++)
    {
      if (!SSH_IP_DEFINED(&attrs->addresses[i]))
        break;

      /* Ignore assigned addresses of different IP families */
      if ((SSH_IP_IS4(&attrs->addresses[i]) && !ipv4) ||
          (SSH_IP_IS6(&attrs->addresses[i]) && ipv4))
        continue;

      SSH_IP_MASK_LEN(&attrs->addresses[i]) =
        8 * SSH_IP_ADDR_LEN(&attrs->addresses[i]);

      status = ssh_ikev2_ts_item_add(tmp, 0,
                                     &attrs->addresses[i],
                                     &attrs->addresses[i],
                                     0, 0xffff);
      if (status != SSH_IKEV2_ERROR_OK)
        {
          status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }
    }

  if (client)
    {
      ok = ssh_ikev2_ts_narrow(pm->sad_handle, FALSE, ts_return_local,
                               tmp, ts_local);
      if (ok)
        ssh_pm_ts_max_enforce(pm->sad_handle, ts_return_local);
    }
  else
    {
      ok = ssh_ikev2_ts_narrow(pm->sad_handle, FALSE, ts_return_remote,
                               tmp, ts_remote);
      if (ok)
        ssh_pm_ts_max_enforce(pm->sad_handle, ts_return_remote);
    }

  ssh_ikev2_ts_free(pm->sad_handle, tmp);
  tmp = NULL;

  if (!ok)
    {
      status = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
      goto error;
    }

  /* Then narrow the input traffic selector using the server's protected
     subnets */
  if (attrs->num_subnets)
    {
      tmp = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (tmp == NULL)
        {
          status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      for (i = 0; i < attrs->num_subnets; i++)
        {
          SshIpAddrStruct start, end;
          size_t mask_len;

          /* Ignore assigned subnets of different IP families */
          if ((SSH_IP_IS4(&attrs->subnets[i]) && !ipv4) ||
              (SSH_IP_IS6(&attrs->subnets[i]) && ipv4))
            continue;

          mask_len = SSH_IP_MASK_LEN(&attrs->subnets[i]);
          ssh_ipaddr_set_bits(&start, &attrs->subnets[i],
                              mask_len, 0);
          ssh_ipaddr_set_bits(&end, &attrs->subnets[i],
                              mask_len, 1);

          SSH_IP_MASK_LEN(&start) = 8 * SSH_IP_ADDR_LEN(&start);
          SSH_IP_MASK_LEN(&end) = 8 * SSH_IP_ADDR_LEN(&end);

          /* Get low and high addresses of the subnets */
          status = ssh_ikev2_ts_item_add(tmp, 0, &start, &end, 0, 0xffff);

          if (status != SSH_IKEV2_ERROR_OK)
            goto error;
        }

      /* Narrow using subnets as policy_ts and the narrowed traffic selector
         as proposed_ts. Otherwise the ssh_ikev2_narrow_ts() does not work
         correctly, because it assumes that proposed_ts->item[0] has a special
         meaning (the trigger packet or the highest priority item). */
      if (client)
        {
          ok = ssh_ikev2_ts_narrow(pm->sad_handle,
                                   FALSE,
                                   ts_return_remote,
                                   ts_remote, tmp);

          if (ok)
            ssh_pm_ts_max_enforce(pm->sad_handle,
                                  ts_return_remote);
        }
      else
        {
          ok = ssh_ikev2_ts_narrow(pm->sad_handle,
                                   FALSE,
                                   ts_return_local,
                                   ts_local, tmp);
          if (ok)
            ssh_pm_ts_max_enforce(pm->sad_handle,
                                  ts_return_local);
        }

      ssh_ikev2_ts_free(pm->sad_handle, tmp);
      tmp = NULL;

      if (!ok)
        {
          status = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
          goto error;
        }
    }
  else
    {
      if (client)
        {
          if ((*ts_return_remote =
               ssh_ikev2_ts_dup(pm->sad_handle, ts_remote)) == NULL)
            {
              status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
              goto error;
            }
        }
      else
        {
          if ((*ts_return_local =
               ssh_ikev2_ts_dup(pm->sad_handle, ts_local)) == NULL)
            {
              status = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
              goto error;
            }
        }

    }

  SSH_DEBUG(SSH_D_LOWOK, ("Narrowed traffic selectors = %@ <-> %@",
                           ssh_ikev2_ts_render, *ts_return_local,
                           ssh_ikev2_ts_render, *ts_return_remote));

  return SSH_IKEV2_ERROR_OK;

 error:
  SSH_ASSERT(status != SSH_IKEV2_ERROR_OK);
  if (*ts_return_local)
    ssh_ikev2_ts_free(pm->sad_handle, *ts_return_local);
  if (*ts_return_remote)
    ssh_ikev2_ts_free(pm->sad_handle, *ts_return_remote);
  if (tmp)
    ssh_ikev2_ts_free(pm->sad_handle, tmp);

  *ts_return_local = *ts_return_remote = NULL;
  return status;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
