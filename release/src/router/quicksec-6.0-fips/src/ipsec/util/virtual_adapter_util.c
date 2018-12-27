/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic utility functions for virtual adapter implementations.
*/

#include "sshincludes.h"
#include "virtual_adapter.h"
#include "sshencode.h"
#include "sshinetencode.h"
#include "sshbuffer.h"
#include "sshinet.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshVirtualAdapterUtil"


/**************************** Utility functions *****************************/

void
ssh_virtual_adapter_interface_ether_address(SshInterceptorIfnum adapter_ifnum,
                                            unsigned char *buffer)
{
  memset(buffer, 0, SSH_ETHERH_ADDRLEN);
  buffer[1] = 1;
  SSH_PUT_32BIT(buffer + 2, (SshUInt32) adapter_ifnum + 1);
}


void
ssh_virtual_adapter_ip_ether_address(SshIpAddr ip, unsigned char *buffer)
{
  memset(buffer, 0, SSH_ETHERH_ADDRLEN);

  if (SSH_IP_IS4(ip))
    {
      buffer[1] = 2;
      SSH_IP4_ENCODE(ip, buffer + 2);
    }
#if defined (WITH_IPV6)
  else
    {
      SshUInt32 value;

      value = SSH_IP6_WORD0_TO_INT(ip);
      value ^= SSH_IP6_WORD1_TO_INT(ip);
      value ^= SSH_IP6_WORD2_TO_INT(ip);
      value ^= SSH_IP6_WORD3_TO_INT(ip);

      buffer[1] = 2;
      SSH_PUT_32BIT(buffer + 2, value);
    }
#endif /* WITH_IPV6 */
}

Boolean
ssh_virtual_adapter_param_encode(SshVirtualAdapterParams params,
                                 unsigned char **data, size_t *len)
{
  unsigned char *dns, *wins;
  size_t dns_len, wins_len, win_domain_len, offset, encode_len;
  SshUInt32 i;
  unsigned char *data_ptr;
  size_t data_len;

  SSH_ASSERT(params != NULL);
  SSH_ASSERT(data != NULL);
  SSH_ASSERT(len != NULL);

  dns = NULL;
  wins = NULL;

  /* DNS. */
  dns = ssh_calloc(params->dns_ip_count, SSH_MAX_IPADDR_ENCODED_LENGTH);
  if (dns == NULL)
    goto error;
  offset = 0;
  dns_len = params->dns_ip_count * SSH_MAX_IPADDR_ENCODED_LENGTH;
  for (i = 0; i < params->dns_ip_count; i++)
    {
      encode_len = ssh_encode_ipaddr_array(dns + offset,
                                           dns_len - offset,
                                           &params->dns_ip[i]);
      if (encode_len == 0)
        goto error;
      offset += encode_len;
    }

  /* WINS. */
  wins = ssh_calloc(params->wins_ip_count, SSH_MAX_IPADDR_ENCODED_LENGTH);
  if (wins == NULL)
    goto error;
  offset = 0;
  wins_len = params->wins_ip_count * SSH_MAX_IPADDR_ENCODED_LENGTH;
  for (i = 0; i < params->wins_ip_count; i++)
    {
      encode_len = ssh_encode_ipaddr_array(wins + offset,
                                           wins_len - offset,
                                           &params->wins_ip[i]);
      if (encode_len == 0)
        goto error;
      offset += encode_len;
    }

  /* Windows domain name. */
  if (params->win_domain)
    win_domain_len = strlen(params->win_domain);
  else
    win_domain_len = 0;

  data_len = ssh_encode_array_alloc(&data_ptr,
                         SSH_ENCODE_UINT32(params->mtu),
                         SSH_ENCODE_UINT32(params->dns_ip_count),
                         SSH_ENCODE_UINT32_STR(dns, dns_len),
                         SSH_ENCODE_UINT32(params->wins_ip_count),
                         SSH_ENCODE_UINT32_STR(wins, wins_len),
                         SSH_ENCODE_UINT32_STR(
                         params->win_domain, win_domain_len),
                         SSH_ENCODE_UINT32(
                         (SshUInt32) params->netbios_node_type),
                         SSH_ENCODE_UINT32(
                         (SshUInt32) params->routing_instance_id),
                         SSH_FORMAT_END);
  if (data_len == 0)
    goto error;

  ssh_free(dns);
  ssh_free(wins);
  *data = data_ptr;
  *len = data_len;
  return TRUE;

 error:
  ssh_free(dns);
  ssh_free(wins);
  *data = NULL;
  *len = 0;
  return FALSE;
}

Boolean
ssh_virtual_adapter_param_decode(SshVirtualAdapterParams params,
                                 const unsigned char *data, size_t len)
{
  unsigned char *dns;
  size_t dns_len;
  unsigned char *wins;
  size_t wins_len;
  unsigned char *win_domain;
  size_t win_domain_len;
  SshUInt32 netbios_node_type;
  SshUInt32 routing_instance_id;
  SshUInt32 i;
  size_t decode_len;

  SSH_ASSERT(params != NULL);
  SSH_ASSERT(data != NULL);
  SSH_ASSERT(len > 0);

  memset(params, 0, sizeof(*params));

  if (ssh_decode_array(data, len,
                       SSH_DECODE_UINT32(&params->mtu),
                       SSH_DECODE_UINT32(&params->dns_ip_count),
                       SSH_DECODE_UINT32_STR_NOCOPY(&dns, &dns_len),
                       SSH_DECODE_UINT32(&params->wins_ip_count),
                       SSH_DECODE_UINT32_STR_NOCOPY(&wins, &wins_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &win_domain, &win_domain_len),
                       SSH_DECODE_UINT32(&netbios_node_type),
                       SSH_DECODE_UINT32(&routing_instance_id),
                       SSH_FORMAT_END) != len)
    return FALSE;

  /* DNS. */
  if (params->dns_ip_count)
    {
      params->dns_ip = ssh_calloc(params->dns_ip_count,
                                  sizeof(*params->dns_ip));
      if (params->dns_ip == NULL)
        goto error;

      for (i = 0; i < params->dns_ip_count; i++)
        {
          decode_len = ssh_decode_ipaddr_array(dns, dns_len,
                                               &params->dns_ip[i]);
          if (decode_len == 0)
            goto error;
          dns += decode_len;
          dns_len -= decode_len;
        }
    }

      /* WINS. */
  if (params->wins_ip_count)
    {
      params->wins_ip = ssh_calloc(params->wins_ip_count,
                                   sizeof(*params->wins_ip));
      if (params->wins_ip == NULL)
        goto error;

      for (i = 0; i < params->wins_ip_count; i++)
        {
          decode_len = ssh_decode_ipaddr_array(wins, wins_len,
                                               &params->wins_ip[i]);
          if (decode_len == 0)
            goto error;
          wins += decode_len;
          wins_len -= decode_len;
        }
    }

  if (win_domain_len)
    {
      params->win_domain = ssh_memdup(win_domain, win_domain_len);
      if (params->win_domain == NULL)
        goto error;
    }

  params->netbios_node_type = (SshUInt8) netbios_node_type;
  params->routing_instance_id = (SshVriId) routing_instance_id;

  return TRUE;

 error:
  ssh_free(params->dns_ip);
  ssh_free(params->wins_ip);
  ssh_free(params->win_domain);
  memset(params, 0, sizeof(*params));
  return FALSE;
}

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
