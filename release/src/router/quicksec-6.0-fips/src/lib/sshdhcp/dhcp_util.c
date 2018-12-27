/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshinet.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"

#define SSH_DEBUG_MODULE "SshDHCPUtil"


static const unsigned char default_options_discover[] = {
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
  SSH_DHCP_OPTION_HOST_NAME,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
  SSH_DHCP_OPTION_END
};


static const unsigned char default_options_request[] = {
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
  SSH_DHCP_OPTION_HOST_NAME,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
  SSH_DHCP_OPTION_END
};

static const unsigned char default_options_decline[] = {
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
  SSH_DHCP_OPTION_HOST_NAME,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_MESSAGE,
  SSH_DHCP_OPTION_END
};

static const unsigned char default_options_release[] = {
 SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_HOST_NAME,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_END
};

/* default option set for all BOOTRESPONSE type messages */
static const unsigned char default_options_response[] = {
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_SUBNET_MASK,
  SSH_DHCP_OPTION_ROUTERS,
  SSH_DHCP_OPTION_DOMAIN_NAME,
  SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS,
  SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS,
  SSH_DHCP_OPTION_DHCP_RENEWAL_TIME,
  SSH_DHCP_OPTION_DHCP_REBINDING_TIME,
  SSH_DHCP_OPTION_HOST_NAME,
  SSH_DHCP_OPTION_ROOT_PATH,
  SSH_DHCP_OPTION_NIS_DOMAIN,
  SSH_DHCP_OPTION_DHCP_MESSAGE,
  SSH_DHCP_OPTION_END
};

static void
ssh_dhcp_get_option_set(SshDHCP dhcp,
                        unsigned char type,
                        unsigned char **option_set)
{
 unsigned char *options = NULL;

 switch ((int)type)
    {
    case SSH_DHCPDISCOVER:
      if (dhcp->params.options != NULL
          && dhcp->params.options->discover != NULL)
        options = (unsigned char *)dhcp->params.options->discover;
      else options = (unsigned char *)default_options_discover;
      break;

    case SSH_DHCPREQUEST:
      if (dhcp->params.options != NULL
          && dhcp->params.options->request != NULL)
        options = (unsigned char *)dhcp->params.options->request;
      else options = (unsigned char *)default_options_request;
      break;
    case SSH_DHCPDECLINE:
      if (dhcp->params.options != NULL
          && dhcp->params.options->decline != NULL)
        options = (unsigned char *)dhcp->params.options->decline;
      else options = (unsigned char *)default_options_decline;
      break;
    case SSH_DHCPRELEASE:
      if (dhcp->params.options != NULL
          && dhcp->params.options->release != NULL)
        options = (unsigned char *)dhcp->params.options->release;
      else options = (unsigned char *)default_options_release;
      break;
    case SSH_DHCPINFORM:
      if (dhcp->params.options != NULL
          && dhcp->params.options->inform != NULL)
        options = (unsigned char *)dhcp->params.options->inform;
      else options = NULL; /* not supported */
      break;
    case SSH_DHCPOFFER:
      if (dhcp->params.options != NULL
          && dhcp->params.options->offer != NULL)
        options = (unsigned char *)dhcp->params.options->offer;
      else options = (unsigned char *)default_options_response;
      break;
    case SSH_DHCPACK:
      if (dhcp->params.options != NULL
          && dhcp->params.options->ack != NULL)
        options = (unsigned char *)dhcp->params.options->ack;
      else options = (unsigned char *)default_options_response;
      break;
    case SSH_DHCPNAK:
      if (dhcp->params.options != NULL
          && dhcp->params.options->nak != NULL)
        options = (unsigned char *)dhcp->params.options->nak;
      else options = (unsigned char *)default_options_response;
      break;
    default:
      break;
    }

 *option_set = options;
}

Boolean
ssh_dhcp_compare_option_set(SshDHCP dhcp, SshDHCPMessage message,
                            unsigned char type)
{
#ifdef SSH_DHCP_VALIDATE_OPTION_SET
  unsigned char *cp, *end, *opt;
  unsigned char *options = NULL;
  Boolean found = FALSE;
  int i = 0;

  if (options == NULL)
    ssh_dhcp_get_option_set(dhcp, type, &options);

  if (options == NULL)
    return FALSE;

  if (message->options_len < 4)
    return FALSE;

  cp = message->options + 4;    /* + 4 ignores cookie */
  end = cp + (message->options_len - 4);

  /* Check that there are no extra options. */
  while ((cp < end) && (*cp != SSH_DHCP_OPTION_END))
    {
      found = FALSE;
      opt = cp++;

      if (*cp == SSH_DHCP_OPTION_PAD)
        continue;

      /* Skip option and its length */
      cp += *cp + 1;

      for (i = 0;
           (int)options[i] != SSH_DHCP_OPTION_END;
           i++)
        {
          if (*opt == (unsigned char)options[i])
            {
              found = TRUE;
              break;
            }
        }

      if (found == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Option %d not valid for message type %d",
                                 *opt, type));
          return FALSE;
        }
    }

  /* Then check that all of the required options are present. */
  for (i = 0;
       (int)options[i] != SSH_DHCP_OPTION_END;
       i++)
    {
      if (!ssh_dhcp_option_check(message, (int)options[i]))
        return FALSE;
    }
#endif /* SSH_DHCP_VALIDATE_OPTION_SET */

  return TRUE;
}

/* Returns most common options (or at least attempts to return all of them)
   from the DHCP message. */
SshDHCPOptionsDefault
ssh_dhcp_get_dhcp_options(SshDHCP dhcp, SshDHCPMessage message)
{
  SshDHCPOptionsDefault def;
  unsigned char data[256];
  size_t len;
  int i = 0;
  unsigned char m[1] = {'\0'};
  unsigned char *options = NULL;


  /* Get message type */
  if (!ssh_dhcp_option_get(message,
                           SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
                           m, sizeof(m), &len))
    return NULL;

  ssh_dhcp_get_option_set(dhcp, m[0], &options);
  if (options == NULL)
    return NULL;

  if ((def = ssh_calloc(1, sizeof(*def))) == NULL)
    return NULL;

  for (i = 0;
       (int)options[i] != SSH_DHCP_OPTION_END;
       i++)
    {
      memset(data, 0, sizeof(data));
      if (!ssh_dhcp_option_get(message, (int)options[i],
                               data, sizeof(data), &len))
#ifdef SSH_DHCP_VALIDATE_OPTION_SET
        /* Requested behaviour, discard messages with invalid option set. */
        goto error;
#else /* SSH_DHCP_VALIDATE_OPTION_SET */
        continue;
#endif /* SSH_DHCP_VALIDATE_OPTION_SET */

      switch ((int)(options[i]))
        {
        case SSH_DHCP_OPTION_DHCP_RENEWAL_TIME:
          def->t1 = SSH_GET_32BIT(data);
          break;

        case SSH_DHCP_OPTION_DHCP_REBINDING_TIME:
          def->t2 = SSH_GET_32BIT(data);
          break;

        case SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER:
          def->server_ip = SSH_GET_32BIT(data);
          def->server_ip_len = len;
          break;

        case SSH_DHCP_OPTION_SUBNET_MASK:
          def->netmask = SSH_GET_32BIT(data);
          break;

        case SSH_DHCP_OPTION_ROUTERS:
          {
            int i = 0;
            char *cp;

            cp = (char *)data;
            def->gateway_ip = ssh_calloc(len / 4, sizeof(*def->gateway_ip));
            if (def->gateway_ip == NULL)
              goto error;

            for (i = 0; i < len / 4; i++)
              {
                def->gateway_ip[i] = SSH_GET_32BIT(cp);
                cp += 4;
              }
            def->gateway_ip_count = len / 4;
          }
          break;

        case SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS:
          {
            int i = 0;
            char *cp;

            cp = (char *)data;
            def->dns_ip = ssh_calloc(len / 4, sizeof(*def->dns_ip));
            if (def->dns_ip == NULL)
              goto error;

            for (i = 0; i < len / 4; i++)
              {
                def->dns_ip[i] = SSH_GET_32BIT(cp);
                cp += 4;
              }
            def->dns_ip_count = len / 4;
          }
          break;

        case SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS:
          {
            int i = 0;
            char *cp;

            cp = (char *)data;
            def->wins_ip = ssh_calloc(len / 4, sizeof(*def->wins_ip));
            if (def->wins_ip == NULL)
              goto error;

            for (i = 0; i < len / 4; i++)
              {
                def->wins_ip[i] = SSH_GET_32BIT(cp);
                cp += 4;
              }
            def->wins_ip_count = len / 4;
          }
          break;

        case SSH_DHCP_OPTION_HOST_NAME:
          memcpy(def->hostname, data, len <= sizeof(def->hostname) ? len :
                 sizeof(def->hostname));
          break;

        case SSH_DHCP_OPTION_DOMAIN_NAME:
          memcpy(def->dns_name, data, len <= sizeof(def->dns_name) ? len :
                 sizeof(def->dns_name));
          break;

        case SSH_DHCP_OPTION_ROOT_PATH:
          memcpy(def->file, data,
                 len <= sizeof(def->file) ? len : sizeof(def->file));
          break;

        case SSH_DHCP_OPTION_NIS_DOMAIN:
          memcpy(def->nis_name, data, len <= sizeof(def->nis_name) ? len :
                 sizeof(def->nis_name));
          break;

        default:
          break;
        }
    }
  /* Save the entire options buffer */
  if (dhcp->info)
    {
      if (!dhcp->info->params)
        dhcp->info->params = ssh_buffer_allocate();
      if (dhcp->info->params)
        ssh_buffer_append(dhcp->info->params, message->options,
                          message->options_len);
    }

  return def;

error:
  if (def)
    {
      if (def->gateway_ip)
        ssh_free(def->gateway_ip);
      if (def->dns_ip)
        ssh_free(def->dns_ip);
      if (def->wins_ip)
        ssh_free(def->wins_ip);
      ssh_free(def);
    }

  return NULL;
}


static
void ssh_dhcp_option_requested_params(SshDHCP dhcp, SshDHCPMessage message,
                                      SshDHCPInformation info)
{
  static unsigned char param_list[] = {
#ifdef SSH_DHCP_VALIDATE_OPTION_SET
    6       /* DNS server */
#else /* SSH_DHCP_VALIDATE_OPTION_SET */
    1,      /* Subnet mask */
    3,      /* Default gateway */
    6,      /* DNS server */
    12,     /* Host name */
    15,     /* Domain name */
    17,     /* Boot path */
    40,     /* NIS domain name */
    44,     /* WINS or NBNS server */
#endif /* SSH_DHCP_VALIDATE_OPTION_SET */
  };

  /* Put parameters request list, if any required */
  if (info && info->params && dhcp->status != SSH_DHCP_STATUS_RENEW &&
      dhcp->status != SSH_DHCP_STATUS_REBIND)
    {
      int i, k;
      unsigned char *cp = ssh_buffer_ptr(info->params);
      size_t len = ssh_buffer_len(info->params);
      SshBuffer params;

      params = ssh_buffer_allocate();

      /* Default params will be first */
      ssh_buffer_append(params, param_list, sizeof(param_list));

      /* Add user defined params (ignore if it is one of default params) */
      for (i = 0; i < len; i++)
        {
          for (k = 0; k < sizeof(param_list); k++)
            {
              if (cp[i] == param_list[k])
                break;
            }
          if (k >= sizeof(param_list))
            ssh_buffer_append(params, &cp[i], 1);
        }
      ssh_dhcp_option_put(message, SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
                          ssh_buffer_len(params), ssh_buffer_ptr(params));
      ssh_buffer_free(params);
    }
  else
    {
      ssh_dhcp_option_put(message, SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
                          sizeof(param_list), param_list);
    }

}


/* Puts customized set of options in DHCP client request. The option set is
   read from SshDhcpParams field options. */
void ssh_dhcp_set_dhcp_options(SshDHCP dhcp, SshDHCPMessage message,
                               SshDHCPInformation info, unsigned char type)
{
  size_t len = 0;
  unsigned char *data = NULL;
  unsigned char tmp[4] = {'\0'};
  unsigned char list[256] = {'\0'};
  int i = 0;
  SshIpAddrStruct ips;
  unsigned char *options = NULL;

  ssh_dhcp_get_option_set(dhcp, type, &options);
  if (options == NULL)
    return;

  ssh_dhcp_option_put_cookie(message);
  ssh_dhcp_option_set_message_type(message, type);

  for (i = 0;
       (int)options[i] != SSH_DHCP_OPTION_END;
       i++)
    {
      data = NULL;
      len = 0;
      if (!ssh_dhcp_option_check(message, (int)options[i]))
        {
          switch ((int)(options[i]))
            {
            case SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS:
              if (info && info->my_ip)
                {
                  ssh_ipaddr_parse(&ips, info->my_ip);
                  SSH_PUT_32BIT(tmp, SSH_IP4_TO_INT(&ips));
                  data = tmp;
                  len = 4;
                }
              break;
            case  SSH_DHCP_OPTION_DHCP_LEASE_TIME:
              SSH_PUT_32BIT(tmp, dhcp->params.requested_lease_time);
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Requesting IP Address Lease Time %u",
                         dhcp->params.requested_lease_time));
              data = tmp;
              len = 4;
              break;
            case SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER:
              if (info && info->server_ip)
                {
                  ssh_ipaddr_parse(&ips, info->server_ip);
                  SSH_PUT_32BIT(tmp, SSH_IP4_TO_INT(&ips));
                  data = tmp;
                  len = 4;
                }
              break;
            case SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER:
              data = dhcp->params.vendor_id;
              len = dhcp->params.vendor_id_len;
              break;
            case SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER:
              if (dhcp->params.no_compatibility == TRUE)
                {
                  data = dhcp->params.client_identifier;
                  len = dhcp->params.client_identifier_len;
                }
              break;
            case SSH_DHCP_OPTION_DHCP_MESSAGE:
              if (info && info->failure_reason != NULL)
                {
                  data = ssh_buffer_ptr(info->failure_reason);
                  len = ssh_buffer_len(info->failure_reason);
                }
              break;
            case SSH_DHCP_OPTION_SUBNET_MASK:
              if (info && info->netmask)
                {
                  ssh_ipaddr_parse(&ips, info->netmask);
                  SSH_PUT_32BIT(tmp, SSH_IP4_TO_INT(&ips));
                  data = tmp;
                  len = 4;
                }
              break;
            case SSH_DHCP_OPTION_ROUTERS:
              if (info && info->gateway_ip_count)
                {
                  char *cp = (char *)list;
                  int j = 0;
                  len = 0;
                  for (j = 0; j < info->gateway_ip_count; j++)
                    {
                      ssh_ipaddr_parse(&ips, info->gateway_ip[j]);
                      SSH_PUT_32BIT(cp, SSH_IP4_TO_INT(&ips));
                      cp += 4;
                      len += 4;
                    }
                  data = list;
                }
              break;
            case SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS:
              if (info && info->dns_ip_count)
                {
                  char *cp = (char *)list;
                  int j = 0;
                  len = 0;
                  for (j = 0; j < info->dns_ip_count; j++)
                    {
                      ssh_ipaddr_parse(&ips, info->dns_ip[j]);
                      SSH_PUT_32BIT(cp, SSH_IP4_TO_INT(&ips));
                      cp += 4;
                      len += 4;
                    }
                  data = list;
                }
              break;
            case SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS:
              if (info && info->wins_ip_count)
                {
                  char *cp = (char *)list;
                  int j = 0;
                  len = 0;
                  for (j = 0; j < info->wins_ip_count; j++)
                    {
                      ssh_ipaddr_parse(&ips, info->wins_ip[j]);
                      SSH_PUT_32BIT(cp, SSH_IP4_TO_INT(&ips));
                      cp += 4;
                      len += 4;
                    }
                  data = list;
                }
              break;
            case SSH_DHCP_OPTION_HOST_NAME:
              if (info && info->hostname)
                {
                  data = info->hostname;
                  len = ssh_ustrlen(info->hostname);
                }
              break;
            case SSH_DHCP_OPTION_DOMAIN_NAME:
              if (info && info->domain)
                {
                  data = info->domain;
                  len = ssh_ustrlen(info->domain);
                }
              break;
            case SSH_DHCP_OPTION_ROOT_PATH:
              if (info && info->file)
                {
                  data = info->file;
                  len = ssh_ustrlen(info->file);
                }
              break;
            case SSH_DHCP_OPTION_NIS_DOMAIN:
              if (info && info->nis)
                {
                  data = info->nis;
                  len = ssh_ustrlen(info->nis);
                }
              break;
            case SSH_DHCP_OPTION_DHCP_RENEWAL_TIME:
              if (info && info->renew_timeout)
                {
                  SSH_PUT_32BIT(tmp, info->renew_timeout);
                  data = tmp;
                  len = 4;
                }
              break;
            case SSH_DHCP_OPTION_DHCP_REBINDING_TIME:
              if (info && info->rebind_timeout)
                {
                  SSH_PUT_32BIT(tmp, info->rebind_timeout);
                  data = tmp;
                  len = 4;
                }
              break;
            case SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST:
              ssh_dhcp_option_requested_params(dhcp, message, info);
              break;
            default:
              break;

            }

          if (data && len > 0)
            ssh_dhcp_option_put(message,
                                (int)(options[i]),
                                len, data);
        }
    }
}

/* Fill in the message top part */
void ssh_dhcp_make_message(SshDHCP dhcp, SshDHCPMessage message,
                           SshDHCPInformation info)
{
  unsigned char xid[4];
  SshIpAddrStruct ga;
  SshUInt32 gateway = 0;

  SSH_PUT_32BIT(xid, 0);

  memset(message, 0, sizeof(*message));

  /* Get identifier */
  if (dhcp->xid == 0)
    {
      ssh_random_stir();
      xid[0] = ssh_random_get_byte();
      xid[1] = ssh_random_get_byte();
      xid[2] = ssh_random_get_byte();
      xid[3] = ssh_random_get_byte();
    }

  /* Get gateway address. Relay DHCP message through this server. */
  if (dhcp->params.gateway)
    {
      if (ssh_ipaddr_parse(&ga, dhcp->params.gateway))
        gateway = SSH_IP4_TO_INT(&ga);
    }

  /* Fill the DHCP message */
  message->op = SSH_DHCP_BOOTREQUEST;
  if (dhcp->params.flags & SSH_DHCP_CLIENT_FLAG_IPSEC)
    message->htype = DH_IFACE_IPSEC;
  else
    message->htype = dhcp->params.hw_addr_type;

  message->hlen = dhcp->params.hw_addr_len;
  message->hops = 0;
  if (dhcp->xid != 0)
    message->xid = dhcp->xid;
  else
    message->xid = SSH_GET_32BIT(xid);

  message->secs = dhcp->secs = 0;
  message->flags = 0;

  message->ciaddr = 0;
  message->yiaddr = 0;
  message->siaddr = 0;
  message->giaddr = gateway;
  memcpy(message->chaddr,
         dhcp->params.hw_addr,
         dhcp->params.hw_addr_len);
}

/* Duplicates the data found in `info' and returns new allocated info
   structure. This function can be used by application to copy the
   information structure if it needs to do so. */

SshDHCPInformation ssh_dhcp_dup_info(const SshDHCPInformation info)
{
  SshDHCPInformation i = NULL;
  int u;

  if (info == NULL)
    return NULL;

  i = ssh_calloc(1, sizeof(*i));
  if (i == NULL)
    return NULL;

  if (info->my_ip != NULL)
    {
      i->my_ip = ssh_strdup(info->my_ip);
      if (i->my_ip == NULL)
        goto alloc_error;
    }
  if (info->server_ip != NULL)
    {
      i->server_ip = ssh_strdup(info->server_ip);
      if (i->server_ip == NULL)
        goto alloc_error;
    }
  if (info->server_duid != NULL)
    {
      i->server_duid = ssh_memdup(info->server_duid, info->server_duid_len);
      if (i->server_duid == NULL)
        goto alloc_error;
    }
  i->server_duid_len = info->server_duid_len;
  if (info->netmask != NULL)
    {
      i->netmask = ssh_strdup(info->netmask);
      if (i->netmask == NULL)
        goto alloc_error;
    }
  if (info->hostname != NULL)
    {
    i->hostname = ssh_strdup(info->hostname);
      if (i->hostname == NULL)
        goto alloc_error;
    }
  if (info->domain != NULL)
    {
      i->domain = ssh_strdup(info->domain);
      if (i->domain == NULL)
        goto alloc_error;
    }
  if (info->file != NULL)
    {
      i->file = ssh_strdup(info->file);
      if (i->file == NULL)
        goto alloc_error;
    }
  if (info->nis != NULL)
    {
      i->nis = ssh_strdup(info->nis);
      if (i->nis == NULL)
        goto alloc_error;
    }
  i->renew_timeout = info->renew_timeout;
  i->rebind_timeout = info->rebind_timeout;
  i->lease_time = info->lease_time;
  if (info->params != NULL)
    {
      i->params = ssh_buffer_allocate();
      if (i->params != NULL)
        {
          ssh_buffer_append(i->params, ssh_buffer_ptr(info->params),
                            ssh_buffer_len(info->params));
        }
      else
        goto alloc_error;
    }

  if (info->gateway_ip_count > 0)
    {
      i->gateway_ip = ssh_calloc(info->gateway_ip_count,
                                 sizeof(*i->gateway_ip));
      if (i->gateway_ip == NULL)
        goto alloc_error;

      i->gateway_ip_count = info->gateway_ip_count;

      for (u = 0; u < info->gateway_ip_count; u++)
        {
          i->gateway_ip[u] = ssh_strdup(info->gateway_ip[u]);
          if (i->gateway_ip[u] == NULL)
            goto alloc_error;
        }
    }

  if (info->dns_ip_count > 0)
    {
      i->dns_ip = ssh_calloc(info->dns_ip_count, sizeof(*i->dns_ip));
      if (i->dns_ip == NULL)
        goto alloc_error;

      i->dns_ip_count = info->dns_ip_count;

      for (u = 0; u < info->dns_ip_count; u++)
        {
          i->dns_ip[u] = ssh_strdup(info->dns_ip[u]);
          if (i->dns_ip[u] == NULL)
            goto alloc_error;
        }
    }

  if (info->wins_ip_count > 0)
    {
      i->wins_ip = ssh_calloc(info->wins_ip_count, sizeof(*i->wins_ip));
      if (i->wins_ip == NULL)
        goto alloc_error;

      i->wins_ip_count = info->wins_ip_count;

      for (u = 0; u < info->wins_ip_count; u++)
        {
          i->wins_ip[u] = ssh_strdup(info->wins_ip[u]);
          if (i->wins_ip[u] == NULL)
            goto alloc_error;
        }
    }

  return i;

alloc_error:
  ssh_dhcp_free_info(i);
  return NULL;
}

/* This function can be used to free the duplicated info structure. */

void ssh_dhcp_free_info(SshDHCPInformation info)
{
  int i;

  ssh_free(info->my_ip);
  ssh_free(info->server_ip);
  ssh_free(info->server_duid);
  ssh_free(info->netmask);
  ssh_free(info->hostname);
  ssh_free(info->domain);
  ssh_free(info->file);
  ssh_free(info->nis);

  for (i = 0; i < info->gateway_ip_count; i++)
    ssh_free(info->gateway_ip[i]);
  ssh_free(info->gateway_ip);
  for (i = 0; i < info->dns_ip_count; i++)
    ssh_free(info->dns_ip[i]);
  ssh_free(info->dns_ip);
  for (i = 0; i < info->wins_ip_count; i++)
    ssh_free(info->wins_ip[i]);
  ssh_free(info->wins_ip);

  if (info->params)
    ssh_buffer_free(info->params);
  if (info->failure_reason)
    ssh_buffer_free(info->failure_reason);
  ssh_free(info);
}

void
ssh_dhcp_statistics_buffer_append(SshDHCPStats statistics,
                                  unsigned char *buf, unsigned int buf_len)
{
  SSH_ASSERT(buf != NULL);

  ssh_snprintf(buf, buf_len,
               "\n\t"
               "total-packets-transmitted=\"%u\"\n\t"
               "total-packets-received=\"%u\"\n\t"
               "packets-dropped=\"%u\"\n\t"
               "dhcpdiscover-sent=\"%u\"\n\t"
               "dhcpoffer-received=\"%u\"\n\t"
               "dhcprequest-sent=\"%u\"\n\t"
               "dhcpack-received=\"%u\"\n\t"
               "dhcpnak-received=\"%u\"\n\t"
               "dhcpdecline-sent=\"%u\"\n\t"
               "dhcprelease-sent=\"%u\"\n\t"
               "dhcpv6-relay-forward-sent=\"%u\"\n\t"
               "dhcpv6-relay-reply-received=\"%u\"\n\t"
               "dhcpv6-solicit-sent=\"%u\"\n\t"
               "dhcpv6-reply-received=\"%u\"\n\t"
               "dhcpv6-decline-sent=\"%u\"\n\t"
               "dhcpv6-renew-sent=\"%u\"\n\t"
               "dhcpv6-release-sent=\"%u\"",
               statistics->packets_transmitted,
               statistics->packets_received,
               statistics->packets_dropped,
               statistics->discover,
               statistics->offer,
               statistics->request,
               statistics->ack,
               statistics->nak,
               statistics->decline,
               statistics->release,
               statistics->dhcpv6_relay_forward,
               statistics->dhcpv6_relay_reply,
               statistics->dhcpv6_solicit,
               statistics->dhcpv6_reply,
               statistics->dhcpv6_decline,
               statistics->dhcpv6_renew,
               statistics->dhcpv6_release);


}

void ssh_dhcp_free_options_default(SshDHCPOptionsDefault def)
{
  if (def->gateway_ip_count)
    ssh_free(def->gateway_ip);
  if (def->dns_ip_count)
    ssh_free(def->dns_ip);
  if (def->wins_ip_count)
    ssh_free(def->wins_ip);
  ssh_free(def);
}

