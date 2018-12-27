/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Conversion routines of traffic selectors between IKEv1 and IKEv2.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-payloads.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "isakmp_doi.h"
#include "isakmp_util.h"

#include "ikev2-fb.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackTsConv"

/*--------------------------------------------------------------------*/
/* Traffic selector conversions                                       */
/*--------------------------------------------------------------------*/

/* Ikev2 Traffic Selector to IKEv1 ID payload (traffic selector forms) */

static Boolean ikev2_fb_ts_is_range(SshIpAddr ip_low,
                                    SshIpAddr ip_high,
                                    Boolean is_ipv4,
                                    unsigned int *mask_len)
{
  size_t len;
  size_t i, j;
  unsigned int masklen = 0;
  Boolean range = FALSE;
  Boolean mask = TRUE;
  unsigned char low[16];
  unsigned char high[16];

  if (is_ipv4)
    {
      SSH_IP4_ENCODE(ip_low, low);
      SSH_IP4_ENCODE(ip_high, high);
      len = 4;
    }
  else
    {
      SSH_IP6_ENCODE(ip_low, low);
      SSH_IP6_ENCODE(ip_high, high);
      len = 16;
    }

  for (i = len; i > 0; i--)
    for (j = 0; j < 8; j++)
      {
        if (mask)
          {
            if ((low[i - 1] & (1 << j)) == 0
                && (high[i - 1] & (1 << j)) != 0)
              masklen++;
            else
              mask = FALSE;
          }
        if (!mask)
          {
            if ((low[i - 1] & (1 << j))
                != (high[i - 1] & (1 << j)))
              {
                /* Failed. */
                range = TRUE;
                goto out;
              }
          }
      }
out:
  if (!range)
    *mask_len = len * 8 - masklen;
  else
    *mask_len = 0;
  return range;
}

SshIkePayloadID
ikev2_fb_tsv2_to_tsv1(SshIkev2PayloadTS ts)
{
  SshIkePayloadID id;
  unsigned char sbuf[SSH_IP_ADDR_STRING_SIZE], ebuf[SSH_IP_ADDR_STRING_SIZE];
  SshIkeIpsecIdentificationType type;
  SshUInt16 port, port_range_end;
  Boolean is_range;
  unsigned int mask_len;
  unsigned int i, len;
  SshIpAddrStruct ip = { 0 };

  if ((id = ssh_calloc(1, sizeof(*id))) == NULL)
    return NULL;

  if (ts->number_of_items_used == 1)
    {
      ssh_ipaddr_print(ts->items[0].start_address, sbuf, sizeof(sbuf));
      ssh_ipaddr_print(ts->items[0].end_address, ebuf, sizeof(ebuf));

      /* No port ranges in IKEv1 */
      if ((ts->items[0].start_port != ts->items[0].end_port) &&
          (ts->items[0].start_port != 0 && ts->items[0].end_port != 0xffff))
        goto failed;

      if (ts->items[0].start_port != 0)
        port = port_range_end = ts->items[0].start_port;
      else
        port = port_range_end = 0;

      if (SSH_IP_EQUAL(ts->items[0].start_address, ts->items[0].end_address))
        {
          if (ts->items[0].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
            type = IPSEC_ID_IPV4_ADDR;
          else
            type = IPSEC_ID_IPV6_ADDR;
        }
      else
        {
          if (ts->items[0].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
            {
              is_range = ikev2_fb_ts_is_range(ts->items[0].start_address,
                                              ts->items[0].end_address,
                                              TRUE,
                                              &mask_len);
              if (is_range)
                type = IPSEC_ID_IPV4_ADDR_RANGE;
              else
                type = IPSEC_ID_IPV4_ADDR_SUBNET;
              len = 4;
              ip.type = SSH_IP_TYPE_IPV4;
            }
          else
            {
              is_range = ikev2_fb_ts_is_range(ts->items[0].start_address,
                                              ts->items[0].end_address,
                                              FALSE,
                                              &mask_len);
              if (is_range)
                type = IPSEC_ID_IPV6_ADDR_RANGE;
              else
                type = IPSEC_ID_IPV6_ADDR_SUBNET;
              len = 16;
              ip.type = SSH_IP_TYPE_IPV6;
            }
          if (!is_range)
            {
              for (i = 0; i < len; i++)
                SSH_IP_BYTEN(&ip, i) = 0xff;

              ssh_ipaddr_set_bits(&ip, &ip, mask_len, 0);
              ssh_ipaddr_print(&ip, ebuf, sizeof(ebuf));
            }
        }

      if (ssh_ike_id_encode(id, type,
                            ts->items[0].proto,
                            port, port_range_end,
                            sbuf, ebuf))
        return id;
    }
  else
    {
#ifdef SSHDIST_IKE_ID_LIST
      int i;

      id->id_type = IPSEC_ID_LIST;
      id->identification.id_list_number_of_items = ts->number_of_items_used;
      if ((id->identification.id_list_items =
           ssh_calloc(ts->number_of_items_used, sizeof(*id))) == NULL)
        goto failed;

      for (i = 0; i < ts->number_of_items_used; i++)
        {
          SshIkePayloadID p;

          /* No port ranges in IKEv1 */
          if ((ts->items[i].start_port != ts->items[i].end_port) &&
              (ts->items[i].start_port != 0 &&
               ts->items[i].end_port != 0xffff))
            goto failed;

          ssh_ipaddr_print(ts->items[i].start_address, sbuf, sizeof(sbuf));
          ssh_ipaddr_print(ts->items[i].end_address, ebuf, sizeof(ebuf));

          if (SSH_IP_EQUAL(ts->items[i].start_address,
                           ts->items[i].end_address))
            {
              if (ts->items[i].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
                type = IPSEC_ID_IPV4_ADDR;
              else
                type = IPSEC_ID_IPV6_ADDR;
            }
          else
            {
              if (ts->items[i].ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
                {
                  is_range = ikev2_fb_ts_is_range(ts->items[i].start_address,
                                                  ts->items[i].end_address,
                                                  TRUE,
                                                  &mask_len);
                  if (is_range)
                    type = IPSEC_ID_IPV4_ADDR_RANGE;
                  else
                    type = IPSEC_ID_IPV4_ADDR_SUBNET;
                  len = 4;
                  ip.type = SSH_IP_TYPE_IPV4;
                }
              else
                {
                  is_range = ikev2_fb_ts_is_range(ts->items[i].start_address,
                                                  ts->items[i].end_address,
                                                  FALSE,
                                                  &mask_len);
                  if (is_range)
                    type = IPSEC_ID_IPV6_ADDR_RANGE;
                  else
                    type = IPSEC_ID_IPV6_ADDR_SUBNET;
                  len = 16;
                  ip.type = SSH_IP_TYPE_IPV6;
                }
                if (!is_range)
                  {
                    for (i = 0; i < len; i++)
                      SSH_IP_BYTEN(&ip, i) = 0xff;

                    ssh_ipaddr_set_bits(&ip, &ip, mask_len, 0);
                    ssh_ipaddr_print(&ip, ebuf, sizeof(ebuf));
                  }
            }
          p = &id->identification.id_list_items[i];
          if (!ssh_ike_id_encode(p, type,
                                 ts->items[i].proto,
                                 ts->items[i].start_port,
                                 ts->items[i].end_port,
                                 sbuf, ebuf))
            goto failed;
        }
#else /* SSHDIST_IKE_ID_LIST */
      goto failed;
#endif /* SSHDIST_IKE_ID_LIST */
    }

  return id;

 failed:
  ssh_ike_id_free(id);
  return NULL;
}

SshIkePayloadID
ikev2_fb_tsv2_to_fqdnv1(SshIkev2PayloadTS ts)
{
  SshIkePayloadID id;
  SshUInt16 port, port_range_end;

  if ((id = ssh_calloc(1, sizeof(*id))) == NULL)
    return NULL;

  if (ts->number_of_items_used == 1)
    {
      /* No port ranges in IKEv1 */
      if ((ts->items[0].start_port != ts->items[0].end_port) &&
          (ts->items[0].start_port != 0 && ts->items[0].end_port != 0xffff))
        goto failed;

      if (ts->items[0].start_port != 0)
        port = port_range_end = ts->items[0].start_port;
      else
        port = port_range_end = 0;

      if (ssh_ike_id_encode(id, IPSEC_ID_FQDN,
                            ts->items[0].proto,
                            port, port_range_end,
                            "dummy", NULL))
        return id;
    }
  else
    {
      goto failed;
    }

  return id;

 failed:
  ssh_ike_id_free(id);
  return NULL;
}

static Boolean
ikev2_fb_tsv1_to_tsv2_item(SshIkev2PayloadTS ts, SshIkePayloadID id)
{
  SshIpAddrStruct saddr[1], eaddr[1];
  unsigned char sbuf[16] = {0}, ebuf[16] = {0};
  SshUInt16 sport, eport;
  int i;

  memset(&saddr, 0, sizeof(saddr));
  memset(&eaddr, 0, sizeof(eaddr));

  switch (id->id_type)
    {
    case IPSEC_ID_FQDN:
    case IPSEC_ID_USER_FQDN:
    case IPSEC_ID_DER_ASN1_DN:
    case IPSEC_ID_DER_ASN1_GN:
    case IPSEC_ID_KEY_ID:
      return FALSE;
    default:
      break;
    }

  if (id->port_number)
    {
      sport = id->port_number;
      eport = id->port_number;
    }
  else
    {
      sport = 0x0;

      /* Protocols that use ports */
      if (id->protocol_id == 0 ||
          id->protocol_id == SSH_IPPROTO_ICMP ||
          id->protocol_id == SSH_IPPROTO_IPV6ICMP ||
          id->protocol_id == SSH_IPPROTO_TCP ||
          id->protocol_id == SSH_IPPROTO_SCTP ||
          id->protocol_id == SSH_IPPROTO_UDP ||
          id->protocol_id == SSH_IPPROTO_UDPLITE)
        eport = 0xffff;
      else
        eport = 0x0;
    }

  switch (id->id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      SSH_IP4_DECODE(saddr, id->identification.ipv4_addr);
      SSH_IP4_DECODE(eaddr, id->identification.ipv4_addr);
      break;
    case IPSEC_ID_IPV6_ADDR:
      SSH_IP6_DECODE(saddr, id->identification.ipv6_addr);
      SSH_IP6_DECODE(eaddr, id->identification.ipv6_addr);
      break;
    case IPSEC_ID_IPV4_ADDR_RANGE:
      SSH_IP4_DECODE(saddr, id->identification.ipv4_addr_range1);
      SSH_IP4_DECODE(eaddr, id->identification.ipv4_addr_range2);
      break;
    case IPSEC_ID_IPV6_ADDR_RANGE:
      SSH_IP6_DECODE(saddr,
                     id->identification.ipv6_addr_range1);
      SSH_IP6_DECODE(eaddr,
                     id->identification.ipv6_addr_range2);
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      for (i = 0; i < 4; i++)
        {
          sbuf[i] =
            (id->identification.ipv4_addr_subnet[i]
             & id->identification.ipv4_addr_netmask[i]);
          ebuf[i] =
            ((id->identification.ipv4_addr_subnet[i]
              & id->identification.ipv4_addr_netmask[i])
             | (unsigned char) ~(id->identification.ipv4_addr_netmask[i]));
        }
      SSH_IP4_DECODE(saddr, sbuf);
      SSH_IP4_DECODE(eaddr, ebuf);
      break;
    case IPSEC_ID_IPV6_ADDR_SUBNET:
      for (i = 0; i < 16; i++)
        {
          sbuf[i] =
            (id->identification.ipv6_addr_subnet[i]
             & id->identification.ipv6_addr_netmask[i]);
          ebuf[i] =
            ((id->identification.ipv6_addr_subnet[i]
              & id->identification.ipv6_addr_netmask[i])
             | (unsigned char) ~(id->identification.ipv6_addr_netmask[i]));
        }
      SSH_IP6_DECODE(saddr, sbuf);
      SSH_IP6_DECODE(eaddr, ebuf);
      break;

#ifdef SSHDIST_IKE_ID_LIST
    case IPSEC_ID_LIST:
      for (i = 0; i < id->identification.id_list_number_of_items; i++)
        {
          SshIkePayloadID p = &id->identification.id_list_items[i];
          if (!ikev2_fb_tsv1_to_tsv2_item(ts, p))
            return FALSE;
        }
      return TRUE;
#endif /* SSHDIST_IKE_ID_LIST */

    default:
      SSH_NOTREACHED;
    }

  if (ssh_ikev2_ts_item_add(ts,
                            id->protocol_id,
                            saddr, eaddr,
                            sport, eport) != SSH_IKEV2_ERROR_OK)
    return FALSE;

  return TRUE;
}

/* Ikev1 ID payload (when used as traffic selector) to Ikev2 traffic
   selector */
SshIkev2PayloadTS
ikev2_fb_tsv1_to_tsv2(SshSADHandle sad_handle, SshIkePayloadID id)
{
  SshIkev2PayloadTS ts;

  if ((ts = ssh_ikev2_ts_allocate(sad_handle)) == NULL)
    return NULL;

  if (ikev2_fb_tsv1_to_tsv2_item(ts, id))
    {
      return ts;
    }
  else
    {
      ssh_ikev2_ts_free(sad_handle, ts);
      return NULL;
    }
}
#endif /* SSHDIST_IKEV1 */
