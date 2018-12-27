/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshdebug.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"

#define SSH_DEBUG_MODULE "SshDHCPv6Util"

/* Allowed message options by message type */
static const unsigned char default_options_solicit[] = {
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_ELAPSED_TIME,
  SSH_DHCPV6_OPTION_AUTH,
  SSH_DHCPV6_OPTION_RAPID_COMMIT,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char default_options_decline[] = {
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_ELAPSED_TIME,
  SSH_DHCPV6_OPTION_AUTH,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char default_options_release[] = {
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_ELAPSED_TIME,
  SSH_DHCPV6_OPTION_AUTH,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char default_options_renew[] = {
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_ELAPSED_TIME,
  SSH_DHCPV6_OPTION_AUTH,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char default_options_reply[] = {
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_PREFERENCE,
  SSH_DHCPV6_OPTION_AUTH,
  SSH_DHCPV6_OPTION_UNICAST,
  SSH_DHCPV6_OPTION_STATUS_CODE,
  SSH_DHCPV6_OPTION_DNS_SERVERS,
  SSH_DHCPV6_OPTION_END
};

/* Fill in the basic message fields */
void ssh_dhcpv6_make_message(SshDHCP dhcp, SshDHCPv6Message message,
                             SshDHCPInformation info, unsigned char type)
{
  unsigned char xid[4] = {'\0'};

  memset(message, 0, sizeof(*message));

  /* Get identifier */
  if (dhcp->xid == 0)
    {
      ssh_random_stir();
      xid[0] = 0;
      xid[1] = ssh_random_get_byte();
      xid[2] = ssh_random_get_byte();
      xid[3] = ssh_random_get_byte();
      message->xid = SSH_GET_32BIT(xid);
    }
  else
    {
      message->xid = dhcp->xid;
    }

  /* Get gateway address. Relay DHCP message through this server. */
  if (dhcp->params.gateway)
    {
      ssh_ipaddr_parse(&message->peer_address, dhcp->params.gateway);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Peer address: %s", dhcp->params.gateway));
    }

  if (dhcp->params.local_ip)
    {
      ssh_ipaddr_parse(&message->link_address, dhcp->params.local_ip);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Link address: %s", dhcp->params.local_ip));
    }

  /* Fill the DHCP message */
  message->msg_type = type;

  message->hop_count = 1;
}

/* Get the option set for different types of messages */
static void
ssh_dhcpv6_get_option_set(SshDHCP dhcp,
                          unsigned char type,
                          const unsigned char **option_set)
{
  const unsigned char *options = NULL;
  SshDHCPOptions opts = dhcp->params.options;

  switch ((int)type)
    {
    case SSH_DHCPV6_SOLICIT:
      if (opts != NULL && opts->solicit != NULL)
          options = opts->solicit;
      else
          options = default_options_solicit;
      break;
    case SSH_DHCPV6_DECLINE:
      if (opts != NULL && opts->decline != NULL)
          options = opts->decline;
      else
          options = default_options_decline;
      break;
    case SSH_DHCPV6_RELEASE:
      if (opts != NULL && opts->release != NULL)
        options = opts->release;
      else
         options = default_options_release;
      break;
    case SSH_DHCPV6_RENEW:
      if (opts != NULL && opts->renew != NULL)
        options = opts->renew;
      else
        options = default_options_renew;
      break;
    case SSH_DHCPV6_REPLY:
      if (opts != NULL && opts->reply != NULL)
        options = opts->reply;
      else
        options = default_options_reply;
      break;
    default:
      break;
    }

 *option_set = options;
}

/* Puts customized set of options in DHCP client request. The option set is
   read from SshDhcpParams field options. */
void ssh_dhcpv6_set_dhcp_options(SshDHCP dhcp, SshDHCPv6Message message,
                                 SshDHCPInformation info, unsigned char type)
{
  int i = 0;
  int j = 0;
  size_t len = 0;
  unsigned char data[256] = {'\0'};
  SshIpAddrStruct ips;
  const unsigned char *options = NULL;
  const unsigned char *reply_options = NULL;
  Boolean add;

  ssh_dhcpv6_get_option_set(dhcp, type, &options);
  if (options == NULL)
    return;

  message->msg_type = type;

  for (i = 0; (int)options[i] != SSH_DHCPV6_OPTION_END; ++i)
    {
      len = 0;
      add = TRUE;

      switch ((int)(options[i]))
        {
        case SSH_DHCPV6_OPTION_RAPID_COMMIT:
          /* Rapid Commit has no internal data */
          break;

        case SSH_DHCPV6_OPTION_CLIENTID:
          if (dhcp->params.client_identifier)
            {
              if (dhcp->params.client_identifier_len >
                  SSH_DHCPV6_CLIENT_ID_MAX_LEN)
                len = SSH_DHCPV6_CLIENT_ID_MAX_LEN;
              else
                len = dhcp->params.client_identifier_len;

              SSH_PUT_16BIT(&data[0], (SshUInt16)SSH_DUID_EN);
              SSH_PUT_32BIT(&data[2], dhcp->params.enterprise_number);
              memcpy(&data[6], dhcp->params.client_identifier, len);

              len += 6;
            }
          else
            add = FALSE;
          break;

        case SSH_DHCPV6_OPTION_IA_NA:
          if (!dhcp->params.requested_lease_time)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Requested lease time 0"));
              add = FALSE;
              break;
            }
          /* IAID Not expecting more than one interface */
          SSH_PUT_32BIT(data, 1);
          /* T1 == 0.5 * requested lease time */
          SSH_PUT_32BIT(&data[4],
                  (SshUInt32)(dhcp->params.requested_lease_time / 2));
          /* T2 == 0.8 * requested lease time */
          SSH_PUT_32BIT(&data[8],
                  (SshUInt32)(dhcp->params.requested_lease_time * 4 / 5));

          len = 12;

          /* If SOLICIT, return. Else embed IAADDR option */
          if (type == SSH_DHCPV6_SOLICIT)
            {
              break;
            }

          /* add SSH_DHCPV6_OPTION_IAADDR */
          memset(data + len, 0, 24 + 4);
          SSH_PUT_16BIT(data + len, SSH_DHCPV6_OPTION_IAADDR);
          SSH_PUT_16BIT(data + len + 2, 24);
          len += 4;

          if (dhcp->info != NULL)
            {
              if (dhcp->info->my_ip != NULL)
                {
                  ssh_ipaddr_parse(&ips, dhcp->info->my_ip);
                  SSH_IP6_ENCODE(&ips, data + len);
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Own IP missing"));
                  add = FALSE;
                }

              if (dhcp->info->lease_time != 0)
                {
                  SSH_PUT_32BIT(&data[16 + len], dhcp->info->lease_time);
                  SSH_PUT_32BIT(&data[20 + len], dhcp->info->lease_time);
                }
              else
                {
                  /* fill with requested lease time */
                  SSH_PUT_32BIT(&data[16 + len],
                                dhcp->params.requested_lease_time);
                  SSH_PUT_32BIT(&data[20 + len],
                                dhcp->params.requested_lease_time);
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL, ("Info struct missing"));
              add = FALSE;
            }

          len += 24;
          break;

        case SSH_DHCPV6_OPTION_SERVERID:
          if (dhcp->info != NULL)
            {
              if (dhcp->info->server_duid != NULL)
                {
                  if (dhcp->info->server_duid_len)
                    {
                      len = dhcp->info->server_duid_len;
                      memcpy(data, dhcp->info->server_duid, len);
                    }
                  else
                    {
                      SSH_DEBUG(SSH_D_FAIL, ("Server DUID length zero"));
                      add = FALSE;
                    }
                }
              else
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Server DUID missing"));
                  add = FALSE;
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL, ("Info struct missing"));
              add = FALSE;
            }
          break;

        case SSH_DHCPV6_OPTION_ELAPSED_TIME:
          SSH_PUT_16BIT(data, 0);
          len = 2;
          break;

        case SSH_DHCPV6_OPTION_ORO:
          /* Get all the options allowed for a reply message */
          ssh_dhcpv6_get_option_set(dhcp, SSH_DHCPV6_REPLY, &reply_options);
          if (reply_options == NULL)
            {
              add = FALSE;
              break;
            }

          /* And add them to the requested options list */
          len = 0;
          for (j = 0; (int)reply_options[j] != SSH_DHCPV6_OPTION_END; ++j)
            {
              data[j * 2] = 0;
              data[j * 2 + 1] = reply_options[j];
              len += 2;
            }
          break;


        default:
          add = FALSE;
          break;
        }

      if (add)
        {
          ssh_dhcpv6_option_put(message, (int)(options[i]), len, data);
        }
    }
}

/* Parse the DHCPv6 options */
SshDHCPv6Extract
ssh_dhcpv6_get_options(SshDHCPv6Message message)
{
  unsigned char *options, *end;
  unsigned char buf[1024];
  SshUInt16 opt, opt_len, status_code;
  SshIpAddrStruct addr;
  size_t len;
  int i;
  SshDHCPv6Extract data;

  if (message->options_len == 0)
    return NULL;

  options = message->options;
  len = message->options_len;
  end = options + len;

  data = ssh_calloc(1, sizeof(SshDHCPv6ExtractStruct));

  if (data == NULL)
    return NULL;

  /* Set defaults */
  data->status_code = SSH_DHCPV6_STATUS_CODE_UNAVAILABLE;
  data->parsing_successful = TRUE;

  while (options + 4 <= end)
    {
      opt = SSH_GET_16BIT(options);
      opt_len = SSH_GET_16BIT(options + 2);
      options += 4;

      /* Do not read past the end of the options
         even if we get a corrupt length */
      if (options + opt_len > end)
        break;

      switch (opt)
        {
        case SSH_DHCPV6_OPTION_IA_TA:
        case SSH_DHCPV6_OPTION_ORO:
        case SSH_DHCPV6_OPTION_PREFERENCE:
        case SSH_DHCPV6_OPTION_ELAPSED_TIME:
        case SSH_DHCPV6_OPTION_RELAY_MSG:
        case SSH_DHCPV6_OPTION_AUTH:
        case SSH_DHCPV6_OPTION_UNICAST:
        case SSH_DHCPV6_OPTION_USER_CLASS:
        case SSH_DHCPV6_OPTION_VENDOR_CLASS:
        case SSH_DHCPV6_OPTION_VENDOR_OPTS:
        case SSH_DHCPV6_OPTION_INTERFACE_ID:
        case SSH_DHCPV6_OPTION_RECONF_MSG:
        case SSH_DHCPV6_OPTION_RECONF_ACCEPT:
        case SSH_DHCPV6_OPTION_SIP_SERVER_D:
        case SSH_DHCPV6_OPTION_SIP_SERVER_A:
        case SSH_DHCPV6_OPTION_DOMAIN_LIST:
          SSH_DEBUG(SSH_D_MY, ("Unhandled option: %d", opt));
          break;

        case SSH_DHCPV6_OPTION_CLIENTID:

          if (data->clientid != NULL || data->clientid_len != 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Second clientid in same packet."));
              break;
            }

          data->clientid_len = opt_len;

          if (opt_len != 0)
            {
              data->clientid = ssh_memdup(options, opt_len);
              if (data->clientid == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Memory allocation for clientid "
                                         "failed"));
                  data->parsing_successful = FALSE;
                }
            }
          break;

        case SSH_DHCPV6_OPTION_SERVERID:

          if (data->server_duid != NULL || data->server_duid_len != 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Second serverid in same packet."));
              break;
            }

          data->server_duid_len = opt_len;

          if (opt_len != 0)
            {
              data->server_duid = ssh_memdup(options, opt_len);
              if (data->server_duid == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Memory allocation for serverid "
                                         "failed"));
                  data->parsing_successful = FALSE;
                }
            }
          break;

        case SSH_DHCPV6_OPTION_IA_NA:

          /* skip IAID (4), get T1 (4) and T2 (4) */
          data->renew_timeout = SSH_GET_32BIT(options + 4);
          data->rebind_timeout = SSH_GET_32BIT(options + 8);

          /* Get the IA_NA options if they exist */
          if (opt_len > 12)
            {
              opt_len = 12;
            }
          break;

        case SSH_DHCPV6_OPTION_IAADDR:
          /* IPv6 address (16), preferred-lifetime (4),
             valid-lifetime (4), options (...) */

          SSH_IP_DECODE(&addr, options, SSH_IP_ADDR_SIZE);
          memset(&buf, 0, SSH_IP_ADDR_STRING_SIZE + 1);

          ssh_ipaddr_print(&addr, buf, SSH_IP_ADDR_STRING_SIZE);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Address: %s", buf));

          if (data->my_ip != NULL)
            {
              /* If the previous IADDR was not an address removal */
              if (data->lease_time != 0)
                {
                  /* We have an IP already. Skip the option. */
                  SSH_DEBUG(SSH_D_FAIL, ("Have an IP already."));
                  break;
                }
              else
                {
                  ssh_free(data->my_ip);
                  data->my_ip = NULL;
                }
            }

          data->my_ip = ssh_strdup(buf);

          if (data->my_ip == NULL)
            {
              /* Unable to get the IP. Skip the rest of the option. */
              SSH_DEBUG(SSH_D_FAIL, ("IP duplication failed."));
              data->parsing_successful = FALSE;
              break;
            }

          data->lease_time = SSH_GET_32BIT(options + 16);

          /* Get the IAADDR options if they exist */
          if (opt_len > 24)
            {
              opt_len = 24;
            }
          break;

        case SSH_DHCPV6_OPTION_STATUS_CODE:
          status_code = SSH_GET_16BIT(options);
          if (data->status_code == SSH_DHCPV6_STATUS_CODE_UNAVAILABLE ||
              data->status_code == SSH_DHCPV6_STATUS_CODE_SUCCESS)
            {
              data->status_code = status_code;

              if (data->status_message != NULL)
                {
                  ssh_free(data->status_message);
                  data->status_message = NULL;
                }

              /* Status message len == opt_len - 2 */
              data->status_message = ssh_calloc(1, opt_len - 1);

              if (data->status_message == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Memory alloc for status message "
                                         "failed."));
                  data->parsing_successful = FALSE;
                  break;
                }

              memcpy(data->status_message, options + 2, opt_len - 2);
            }
          SSH_DEBUG(SSH_D_NICETOKNOW, ("DHCPv6 Option Status: %d  '%s'",
                                       data->status_code,
                                       data->status_message));
          break;

        case SSH_DHCPV6_OPTION_RAPID_COMMIT:
          data->rapid_commit = TRUE;
          break;

        case SSH_DHCPV6_OPTION_DNS_SERVERS:
          /* DNS servers should be available in 16 byte fields for IPv6 */
          if (opt_len % 16 == 0)
            {
              data->dns_ip_count = opt_len / 16;
              data->dns_ip = ssh_calloc(data->dns_ip_count,
                                        sizeof(*data->dns_ip));
              if (data->dns_ip == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Memory alloc for DNS IP failed."));
                  data->parsing_successful = FALSE;
                  break;
                }

              for (i = 0; i < data->dns_ip_count; ++i)
                {
                  SSH_IP_DECODE(&addr, options + i * 16, SSH_IP_ADDR_SIZE);
                  memset(&buf, 0, SSH_IP_ADDR_STRING_SIZE + 1);
                  ssh_ipaddr_print(&addr, buf, SSH_IP_ADDR_STRING_SIZE);
                  data->dns_ip[i] = ssh_strdup(buf);

                  if (data->dns_ip[i] == NULL)
                    {
                      SSH_DEBUG(SSH_D_FAIL, ("Strdup for DNS IP failed."));
                      data->parsing_successful = FALSE;
                      break;
                    }
                }
            }
          else
            data->parsing_successful = FALSE;
          break;


        default:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Unexpected option: %d", opt));
          break;
        }

      options += opt_len;

      if (data->parsing_successful == FALSE)
        {
          break;
        }
    }

  return data;
}

/* Check if all the received options are allowed for the message type */
Boolean
ssh_dhcpv6_compare_option_set(SshDHCP dhcp, SshDHCPv6Message message,
                              unsigned char type)
{
#ifdef SSH_DHCP_VALIDATE_OPTION_SET
  unsigned char *cp, *end;
  unsigned char *options = NULL;
  SshUInt16 opt, len;
  Boolean found = FALSE;
  int i = 0;

  ssh_dhcpv6_get_option_set(dhcp, type, &options);

  if (options == NULL)
    {
      return FALSE;
    }

  cp = message->options;
  end = cp + (message->options_len);

  /* Check that there are no extra options. */
  while (cp + 4 <= end)
    {
      found = FALSE;
      opt = SSH_GET_16BIT(cp);
      len = SSH_GET_16BIT(cp + 2);
      cp += 4;

      for (i = 0; (int)options[i] != SSH_DHCPV6_OPTION_END; ++i)
        {
          if (opt == (SshUInt16)options[i])
            {
              found = TRUE;
              break;
            }
        }

      if (found == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Option %d not valid for message type %d",
                                 opt, type));
          return FALSE;
        }

      /* Skip option and its length */
      if (opt == SSH_DHCPV6_OPTION_IAADDR)
        {
          /* Skip only mandatory IAADDR fields
             to go throught possible options */
          cp += 24;
        }
      else if (opt == SSH_DHCPV6_OPTION_IA_NA)
        {
          cp += 12;
        }
      else
        {
          cp += len;
        }
    }

#endif /* SSH_DHCP_VALIDATE_OPTION_SET */

  return TRUE;
}

/* Move parsed data from the intermediate data structure to dhcp->info. */
Boolean
ssh_dhcpv6_populate_info(SshDHCP dhcp, SshDHCPv6Extract data)
{
  /* Save offered data */
  if (dhcp->info == NULL)
    {
      dhcp->info = ssh_calloc(1, sizeof(*dhcp->info));
      if (dhcp->info == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation for info struct failed"));
          dhcp->status = SSH_DHCP_STATUS_ERROR;
          return FALSE;
        }
    }

  if (dhcp->params.remote_ip != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Remote IP: %s", dhcp->params.remote_ip));
      if (dhcp->info->server_ip)
        {
          ssh_free(dhcp->info->server_ip);
          dhcp->info->server_ip = NULL;
        }

      dhcp->info->server_ip = dhcp->params.remote_ip;
      dhcp->params.remote_ip = NULL;
    }

  if (dhcp->info->server_duid != NULL)
    {
      ssh_free(dhcp->info->server_duid);
      dhcp->info->server_duid = NULL;
    }

  if (data->server_duid != NULL)
    {
      dhcp->info->server_duid = data->server_duid;
      data->server_duid = NULL;
    }

  dhcp->info->server_duid_len = data->server_duid_len;
  dhcp->info->renew_timeout = data->renew_timeout;
  dhcp->info->rebind_timeout = data->rebind_timeout;
  dhcp->info->lease_time = data->lease_time;


  if (dhcp->info->my_ip != NULL)
    {
      ssh_free(dhcp->info->my_ip);
      dhcp->info->my_ip = NULL;
    }

  if (data->my_ip != NULL)
    {
      dhcp->info->my_ip = data->my_ip;
      data->my_ip = NULL;
    }

  if (data->dns_ip_count > 0)
    {
      if (dhcp->info->dns_ip != NULL)
        {
          int i;
          for (i = 0; i < dhcp->info->dns_ip_count; i++)
            ssh_free(dhcp->info->dns_ip[i]);
          ssh_free(dhcp->info->dns_ip);
        }

      dhcp->info->dns_ip_count = data->dns_ip_count;
      dhcp->info->dns_ip = data->dns_ip;
      data->dns_ip_count = 0;
      data->dns_ip = NULL;
    }

  return TRUE;
}

/* Free the parsed data if available. */
void
ssh_dhcpv6_free_extract_data(SshDHCPv6Extract data)
{
  int i;

  if (data != NULL)
    {

      if (data->clientid != NULL)
        {
          ssh_free(data->clientid);
        }

      if (data->server_duid != NULL)
        {
          ssh_free(data->server_duid);
        }

      if (data->my_ip != NULL)
        {
          ssh_free(data->my_ip);
        }

      if (data->status_message != NULL)
        {
          ssh_free(data->status_message);
        }

      if (data->dns_ip_count > 0)
        {
          for (i = 0; i > data->dns_ip_count; ++i)
            {
              ssh_free(data->dns_ip[i]);
            }
        }

      if (data->dns_ip != NULL)
        {
          ssh_free(data->dns_ip);
        }

      ssh_free(data);
    }
}

