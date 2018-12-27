/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshfsm.h"
#include "sshtcp.h"
#include "sshtime.h"
#include "sshcrypt.h"
#include "sshinet.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"
#include "dhcp_states.h"

#define SSH_DEBUG_MODULE "SshDHCPv6States"

static void dhcp_retransmit(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;
  SshFSMStepCB state;
  switch (dhcp->status)
    {
    case SSH_DHCP_STATUS_SOLICIT:
      state = ssh_dhcpv6_st_solicit;
      break;
    case SSH_DHCP_STATUS_DECLINE:
      state = ssh_dhcpv6_st_decline;
      break;
    case SSH_DHCP_STATUS_RELEASE:
      state = ssh_dhcpv6_st_release;
      break;
    case SSH_DHCP_STATUS_RENEW:
      state = ssh_dhcpv6_st_renew;
      break;
    default:
      SSH_DEBUG(SSH_D_MY, ("Retransmit no longer valid. New status: %d",
                           dhcp->status));
      ssh_cancel_timeout(&dhcp->timeout);
      return;
    }

  dhcp->retransmit_count++;
  dhcp->params.retransmit_interval *= SSH_DHCP_TIMEOUT_MULTIPLIER;
  if (dhcp->params.retransmit_interval > dhcp->params.max_timeout)
    dhcp->params.retransmit_interval = dhcp->params.max_timeout;

  ssh_fsm_set_next(dhcp->thread, state);
  ssh_fsm_continue(dhcp->thread);
}

/* UDP Listener callback. Called when packet is received from the UDP
   connection. */
void ssh_dhcpv6_udp_callback(SshUdpListener listener, void *context)
{
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)context;
  size_t max_packet_len;
  SshDHCPv6MessageStruct message;
  SshUInt32 hashvalue;
  SshDHCP dhcp;
  unsigned char saddr[SSH_IP_ADDR_STRING_SIZE];

  SSH_ASSERT(main_context != NULL);
  SSH_ASSERT(listener != NULL);

  memset(&message, 0, sizeof(SshDHCPv6MessageStruct));
  main_context->p = ssh_udp_get_datagram_buffer(&max_packet_len);

  while (ssh_udp_read(listener, saddr, 40, NULL, 0, main_context->p,
                      max_packet_len, &main_context->p_len) == SSH_UDP_OK)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Received packet"),
                        main_context->p, main_context->p_len);

      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_received);

      if (ssh_dhcpv6_relay_message_decode(&message, main_context->p,
                                          main_context->p_len))
        {
          /* Find xid and corresponding thread */
          hashvalue = message.xid % DHCP_THREAD_HASH_TABLE_SIZE;
          dhcp = main_context->thread_hash_table[hashvalue];

          SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_relay_reply);

          /* no previous unhandled message */
          if (dhcp != NULL &&
              dhcp->xid == message.xid)
            {
              memcpy(&dhcp->dhcpv6_message, &message,
               sizeof(dhcp->dhcpv6_message));

              if (dhcp->params.remote_ip)
                {
                  ssh_free(dhcp->params.remote_ip);
                  dhcp->params.remote_ip = NULL;
                }

              dhcp->params.remote_ip = ssh_strdup(saddr);

              if (!dhcp->params.remote_ip)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                           ("Memory allocation failed. Packet dropped."));

                  SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
                  return;
                }

              ssh_fsm_set_next(dhcp->thread, ssh_dhcpv6_st_receive);

              SSH_ASSERT (ssh_fsm_get_callback_flag(dhcp->thread) == FALSE);

              ssh_fsm_continue(dhcp->thread);
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL, ("XID does not match or unable to get "
                                     "DHCP handle."));
              SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Message decode failed. Packet dropped."));
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
        }
    }
}

void send_udp_packet(SshDHCPMainCtx main_context, const SshDHCP dhcp,
                     const char* packet, size_t packet_len)
{
  int i = 0;
  unsigned char remote_port[6];
  Boolean send_to_all = TRUE;

  if (dhcp->status == SSH_DHCP_STATUS_DECLINE)
    {
      send_to_all = FALSE;
    }

  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
    {
      if (dhcp->params.dhcp_servers[i].remote_ip != NULL &&
          (send_to_all || !memcmp(dhcp->params.dhcp_servers[i].remote_ip,
                                  dhcp->info->server_ip,
                                  ssh_ustrlen(dhcp->info->server_ip))))
        {
          ssh_snprintf(remote_port, sizeof(remote_port), "%d",
                       dhcp->params.dhcp_servers[i].remote_port);
          ssh_udp_send(main_context->sender,
                       dhcp->params.dhcp_servers[i].remote_ip,
                       remote_port, packet, packet_len);
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_transmitted);
          SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_relay_forward);
          switch (dhcp->status)
            {
            case SSH_DHCP_STATUS_SOLICIT:
              SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_solicit);
              break;
            case SSH_DHCP_STATUS_DECLINE:
              SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_decline);
              break;
            case SSH_DHCP_STATUS_RELEASE:
              SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_release);
              break;
            case SSH_DHCP_STATUS_RENEW:
              SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_renew);
              break;
            default:
              SSH_DEBUG(SSH_D_MY, ("Unexpected status: %d", dhcp->status));
              SSH_ASSERT(FALSE);
              break;
            }
        }
    }
}

SshFSMStepStatus send_packet(SshFSMThread thread, SshDHCP dhcp,
                             SshDHCPMainCtx main_context,
                             unsigned int message_type)
{
  SshDHCPv6MessageStruct message;
  unsigned char packet[1024];
  size_t packet_len = 0;

  if (dhcp->retransmit_count > dhcp->params.retransmit_count)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Retransmission limit reached, giving up"));
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "DHCP operation timeout.");
      dhcp->status = SSH_DHCP_STATUS_TIMEOUT;

      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  ssh_dhcpv6_make_message(dhcp, &message, dhcp->info, message_type);
  ssh_dhcpv6_set_dhcp_options(dhcp, &message, dhcp->info, message_type);

  if (message_type == SSH_DHCPV6_SOLICIT)
    {
      /* Save session ID for future packet identifying */
      dhcp->xid = message.xid;
    }

  /* Encode packet */
  packet_len = ssh_dhcpv6_relay_message_encode(&message, packet,
                                               sizeof(packet));
  if (packet_len == 0)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Set retransmission timeout */
  ssh_cancel_timeout(&dhcp->timeout);
  ssh_register_timeout(&dhcp->timeout,
                       dhcp->params.retransmit_interval +
                       (ssh_random_get_byte() % SSH_DHCP_TIMEOUT_RANDOMIZER),
                       dhcp->params.retransmit_interval_usec,
                       dhcp_retransmit, dhcp);

  /* Send the packet to all configured servers */
  send_udp_packet(main_context, dhcp, packet, packet_len);

  return SSH_FSM_SUSPENDED;
}

/* Client to Server: request IP address from server. This is the first
   state (if previous DHCP configuration does not exist) and will be
   broadcasted to the network to receive offers from server(s). */
SSH_FSM_STEP(ssh_dhcpv6_st_solicit)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  dhcp->status = SSH_DHCP_STATUS_SOLICIT;
  SSH_DEBUG(SSH_D_MIDSTART, ("Sending SOLICIT"));
  return send_packet(thread, dhcp, (SshDHCPMainCtx)fsm_context,
                     SSH_DHCPV6_SOLICIT);
}

SSH_FSM_STEP(ssh_dhcpv6_st_renew)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  dhcp->status = SSH_DHCP_STATUS_RENEW;
  SSH_DEBUG(SSH_D_MIDSTART, ("Sending RENEW"));
  return send_packet(thread, dhcp, (SshDHCPMainCtx)fsm_context,
                     SSH_DHCPV6_RENEW);
}

SSH_FSM_STEP(ssh_dhcpv6_st_decline)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  dhcp->status = SSH_DHCP_STATUS_DECLINE;
  SSH_DEBUG(SSH_D_MIDSTART, ("Sending DECLINE"));
  return send_packet(thread, dhcp, (SshDHCPMainCtx)fsm_context,
                     SSH_DHCPV6_DECLINE);
}

SSH_FSM_STEP(ssh_dhcpv6_st_release)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  dhcp->status = SSH_DHCP_STATUS_RELEASE;
  SSH_DEBUG(SSH_D_MIDSTART, ("Sending RELEASE"));
  return send_packet(thread, dhcp, (SshDHCPMainCtx)fsm_context,
                     SSH_DHCPV6_RELEASE);
}

SSH_FSM_STEP(ssh_dhcpv6_st_reply)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPv6Message message = &dhcp->dhcpv6_message;
  SshDHCPv6Extract data = NULL;
  unsigned char buf[1024];
  SshFSMStepStatus retval = SSH_FSM_SUSPENDED;
  size_t len;

  SSH_ASSERT(dhcp != NULL);
  SSH_ASSERT(message != NULL);

  SSH_DEBUG(SSH_D_MIDSTART, ("Received REPLY"));

  /* If no longer need to handle packets */
  if (dhcp->status == SSH_DHCP_STATUS_ABORTED ||
      dhcp->status == SSH_DHCP_STATUS_BOUND)
    {
      goto next_out;
    }

  /* Check options */
  if (!ssh_dhcpv6_compare_option_set(dhcp, &dhcp->dhcpv6_message,
                                     SSH_DHCPV6_REPLY))
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Option set comparison failed."));
      /* Update statistics */
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  /* Get options to the intemediate structure */
  data = ssh_dhcpv6_get_options(message);

  if (data == NULL || data->parsing_successful == FALSE)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Packet parsing failed"));
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  /* Check that mandatory options server id and client id are included */
  if (data->server_duid == NULL || data->clientid == NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("No server duid or client id."));
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  /* Check that client id length is valid */
  if (dhcp->params.client_identifier_len > SSH_DHCPV6_CLIENT_ID_MAX_LEN)
    len = SSH_DHCPV6_CLIENT_ID_MAX_LEN;
  else
    len = dhcp->params.client_identifier_len;

  /* Check that ClientID length matches */
  if ((len + 6) != data->clientid_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("CLIENTID length didn't match."));
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  SSH_PUT_16BIT(&buf[0], (SshUInt16)SSH_DUID_EN);
  SSH_PUT_32BIT(&buf[2], dhcp->params.enterprise_number);
  memcpy(buf + 6, dhcp->params.client_identifier, len);

  /* Check that client id content matches */
  if (memcmp(buf, data->clientid, data->clientid_len) != 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("CLIENTID didn't match."));
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  /* Only rapid commit supported for solicit */
  if (dhcp->status == SSH_DHCP_STATUS_SOLICIT)
    {
      /* REPLY to SOLICIT. Check for RAPID COMMIT. */
      if (data->rapid_commit == FALSE)
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("No RAPID COMMIT in reply to SOLICIT. "
                                     "Dropping packet."));
          /* Update statistics */
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
          goto clear_out;
        }
    }
  /* Check status codes for replies to decline and release messages */
  else if (dhcp->status == SSH_DHCP_STATUS_DECLINE ||
      dhcp->status == SSH_DHCP_STATUS_RELEASE)
    {
      /* Received reply is good enough */
      if (data->status_code != SSH_DHCPV6_STATUS_CODE_UNAVAILABLE)
        {
          dhcp->status = SSH_DHCP_STATUS_OK;
          goto next_out;
        }

      goto clear_out;
    }
  /* Check the status code for a renew message */
  else if (dhcp->status == SSH_DHCP_STATUS_RENEW)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Status code: %d", data->status_code));
      /* Continue if status code success. No status code implies success. */
      if (data->status_code != SSH_DHCPV6_STATUS_CODE_SUCCESS &&
          data->status_code != SSH_DHCPV6_STATUS_CODE_UNAVAILABLE)
        {
          goto clear_out;
        }
    }

  if (data->lease_time == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Lease time not valid"));
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  if (data->my_ip == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No address offered"));
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      goto next_out;
    }

  if (ssh_inet_is_valid_ip_address(data->my_ip) == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Received IP not valid."));
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      goto clear_out;
    }

  /* Move the data to dhcp->info */
  if (ssh_dhcpv6_populate_info(dhcp, data) == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Received IP not valid."));
      goto clear_out;
    }

  /* We are now in BOUND status */
  dhcp->status = SSH_DHCP_STATUS_BOUND;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("We are in BOUND state"));

next_out:
  /* We're done */
  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
  retval = SSH_FSM_CONTINUE;

clear_out:
  /* Clear out the message */
  memset(&dhcp->dhcpv6_message, 0, sizeof(SshDHCPv6MessageStruct));
  /* Free temporary data */
  ssh_dhcpv6_free_extract_data(data);

  return retval;
}

SSH_FSM_STEP(ssh_dhcpv6_st_receive)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPv6Message message;
  unsigned char msg_type;

  SSH_ASSERT(dhcp != NULL);

  SSH_DEBUG(SSH_D_MIDSTART, ("Received packet, starting processing."));

  message = &dhcp->dhcpv6_message;

  if (message->xid != dhcp->xid)
    goto out;

  msg_type = message->msg_type;

  switch ((int)msg_type)
    {
    case SSH_DHCPV6_SOLICIT:
    case SSH_DHCPV6_REQUEST:
    case SSH_DHCPV6_CONFIRM:
    case SSH_DHCPV6_RENEW:
    case SSH_DHCPV6_REBIND:
    case SSH_DHCPV6_RELEASE:
    case SSH_DHCPV6_INFORMATION_REQUEST:
    case SSH_DHCPV6_RELAY_FORW:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received a non-reply message %d",
                 (int)msg_type));
      goto out;
      break;

    case SSH_DHCPV6_DECLINE:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Received DECLINE message."));
      goto out;
      break;

    case SSH_DHCPV6_RELAY_REPL :
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received RELAY_REPL message %d\nRelay header should have "
                 "been removed.", (int)msg_type));
      goto out;
      break;

    case SSH_DHCPV6_RECONFIGURE:
    case SSH_DHCPV6_ADVERTISE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received unsupported message %d", (int)msg_type));
      goto out;
      break;

    case SSH_DHCPV6_REPLY:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received REPLY message %d", (int)msg_type));
      SSH_DHCP_UPDATE_STATS(main_context->stats.dhcpv6_reply);
      SSH_FSM_SET_NEXT(ssh_dhcpv6_st_reply);
      break;

    default:
      SSH_DEBUG(SSH_D_NETGARB,
                ("Bad message type received %d", (int)msg_type));
      goto out;
    }
  return SSH_FSM_CONTINUE;

 out:
  memset(&dhcp->dhcpv6_message, 0, sizeof(dhcp->dhcpv6_message));
  SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
  SSH_DEBUG(SSH_D_MIDSTART, ("Error."));
  return SSH_FSM_SUSPENDED;
}

