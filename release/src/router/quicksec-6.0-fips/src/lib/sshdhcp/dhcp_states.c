/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
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

#define SSH_DEBUG_MODULE "SshDHCPStates"

/* Timeout during offer selecting. We've failed to get the preferred
   offer so we'll use the one we've received so far. This recalls the
   offer state. */
static void dhcp_offer_timeout(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;

  SSH_ASSERT(dhcp != NULL);

  dhcp->got_offer = TRUE;
  ssh_fsm_set_next(dhcp->thread, ssh_dhcp_st_offer);
  ssh_fsm_continue(dhcp->thread);
}

static void dhcp_retransmit(SshDHCP dhcp, SshFSMStepCB state)
{
  dhcp->retransmit_count++;
  dhcp->params.retransmit_interval *= SSH_DHCP_TIMEOUT_MULTIPLIER;
  if (dhcp->params.retransmit_interval > dhcp->params.max_timeout)
    dhcp->params.retransmit_interval = dhcp->params.max_timeout;

  ssh_fsm_set_next(dhcp->thread, state);
  ssh_fsm_continue(dhcp->thread);
}

/* Retransmit timeout. Restarts DHCP all over again. */
static void dhcp_retransmit_discovery(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;

  SSH_ASSERT(dhcp != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Retransmitting DISCOVERY"));
  dhcp_retransmit(dhcp, ssh_dhcp_st_discover);
}

/* Retransmit timeout for DHCP REQUEST. */
static void dhcp_retransmit_request(void *context)
{
  SshDHCP dhcp = (SshDHCP)context;

  SSH_ASSERT(dhcp != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Retransmitting REQUEST"));
  dhcp_retransmit(dhcp, ssh_dhcp_st_request);
}

/* UDP Listener callback. Called when packet is received from the UDP
   connection. */
void ssh_dhcp_udp_callback(SshUdpListener listener, void *context)
{
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)context;
  size_t max_packet_len;
  SshDHCPMessageStruct message;
  SshUInt32 hashvalue;
  SshDHCP dhcp;

  SSH_ASSERT(main_context != NULL);
  SSH_ASSERT(listener != NULL);

  main_context->p = ssh_udp_get_datagram_buffer(&max_packet_len);

  while (ssh_udp_read(listener, NULL, 0, NULL, 0, main_context->p,
                      max_packet_len, &main_context->p_len) == SSH_UDP_OK)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Received packet"),
                        main_context->p, main_context->p_len);

      if (ssh_dhcp_message_decode(&message, main_context->p,
                                  main_context->p_len))
        {
          if (message.op != SSH_DHCP_BOOTREPLY)
            continue;

          /* Update statistics */
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_received);

          /* Find xid and corresponding thread */
          hashvalue = message.xid % DHCP_THREAD_HASH_TABLE_SIZE;

          dhcp = main_context->thread_hash_table[hashvalue];
          /* Loop over the thread_hash_table to find the correct DHCP. */
          while (dhcp != NULL && (dhcp->xid != message.xid))
            dhcp = dhcp->xid_hash_next;

          /* no previous unhandled message */
          if (dhcp != NULL &&
              dhcp->message.op == 0 &&
              dhcp->xid == message.xid)
            {
              memcpy(&dhcp->message, &message, sizeof(dhcp->message));

              ssh_fsm_set_next(dhcp->thread, ssh_dhcp_st_receive);

              if (ssh_fsm_get_callback_flag(dhcp->thread))
                SSH_FSM_CONTINUE_AFTER_CALLBACK(dhcp->thread);
              else
                ssh_fsm_continue(dhcp->thread);
            }
          else
            SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
        }
    }
}

/* Client to Server: request IP address from server. This is the first
   state (if previous DHCP configuration does not exist) and will be
   broadcasted to the network to receive offers from server(s). */

SSH_FSM_STEP(ssh_dhcp_st_discover)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessageStruct message;
  unsigned char p[1024];
  size_t p_len;
  int i = 0;
  unsigned char remote_port[6];

  SSH_DEBUG(SSH_D_MIDSTART, ("Sending DHCPDISCOVER"));

  if (dhcp->retransmit_count > dhcp->params.retransmit_count)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Retransmission limit reached, giving up"));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "DHCP operation timeout.");
      dhcp->status = SSH_DHCP_STATUS_TIMEOUT;

      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  if (dhcp->info && dhcp->info->my_ip)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Previous configuration data exist, continuing to "
                 "DHCPREQUEST state"));
      dhcp->got_offer = FALSE;

      SSH_FSM_SET_NEXT(ssh_dhcp_st_request);
      return SSH_FSM_CONTINUE;
    }

  ssh_dhcp_make_message(dhcp, &message, dhcp->info);
  ssh_dhcp_set_dhcp_options(dhcp, &message, dhcp->info,
                            SSH_DHCPDISCOVER);
  ssh_dhcp_option_put(&message, SSH_DHCP_OPTION_END, 1, NULL);

  /* Save session ID for future packet identifying */
  dhcp->xid = message.xid;

  /* Encode packet */
  p_len = ssh_dhcp_message_encode(&message, p, sizeof(p));
  if (p_len == 0)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  dhcp->discover_secs = message.secs;

  /* Set retransmission timeout */
  ssh_cancel_timeout(&dhcp->timeout);
  ssh_register_timeout(&dhcp->timeout,
                       dhcp->params.retransmit_interval +
                       (ssh_random_get_byte() % SSH_DHCP_TIMEOUT_RANDOMIZER),
                       dhcp->params.retransmit_interval_usec,
                       dhcp_retransmit_discovery, dhcp);

  /* Send the packet to all configured servers */
  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
    {
      if (dhcp->params.dhcp_servers[i].remote_ip != NULL)
        {
          ssh_snprintf(remote_port, sizeof(remote_port), "%d",
                       dhcp->params.dhcp_servers[i].remote_port);
          ssh_udp_send(main_context->sender,
                       dhcp->params.dhcp_servers[i].remote_ip,
                       remote_port, p, p_len);
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_transmitted);
          SSH_DHCP_UPDATE_STATS(main_context->stats.discover);
        }
    }

  return SSH_FSM_SUSPENDED;
}

/* Server to Client: Server offered IP address to client. Note that there
   can be several DHCP offers from several DHCP servers. This code takes
   the first offer without considering other offers at all. All other offers
   from this point on will be ignored by default. */

SSH_FSM_STEP(ssh_dhcp_st_offer)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessage message = &dhcp->message;
  SshIpAddrStruct offered_ip, server_id;
  unsigned char data[8];
  unsigned char yiaddr[64], server[64];

  SSH_DEBUG(SSH_D_MIDSTART, ("Received DHCPOFFER"));

  if (dhcp->status == SSH_DHCP_STATUS_ABORTED)
    {
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Ignore offer if we've already got an offer */
  if (dhcp->got_offer && !dhcp->wait_offer)
    {
      /* Clear out this message. */
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      return SSH_FSM_SUSPENDED;
    }

  /* Ignore offer if option set is not valid. */
  if (ssh_dhcp_compare_option_set(dhcp, &dhcp->message, SSH_DHCPOFFER)
      == FALSE)
    {
      /* Clear out this message. */
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      /* Update statistics */
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      return SSH_FSM_SUSPENDED;
    }

  /* Get server identifier */
  ssh_dhcp_option_get(message, SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                      data, sizeof(data), NULL);
  SSH_INT_TO_IP4(&server_id, SSH_GET_32BIT(data));
  ssh_ipaddr_print(&server_id, server, sizeof(server));
  if (!ssh_inet_is_valid_ip_address(server))
    strncat(ssh_sstr(server), "[unknown]", strlen("[unknown]"));

  /* If user has a preferred DHCP server we will wait for that offer. If
     it never arrives we'll take the first one we got. */
  if (!dhcp->got_offer && dhcp->info && dhcp->info->server_ip)
    {
      if (ssh_ustrcmp(server, dhcp->info->server_ip) != 0)
        {
          if (!dhcp->wait_offer)
            {
              /* This offer is not from preferred server.
                 However, we'll save it as there's no quarantee that
                 the preferred server will ever send us an offer. In
                 that case, this offer will be used. */
              memcpy(&dhcp->offer, &dhcp->message,
                     sizeof(SshDHCPMessageStruct));
              dhcp->wait_offer = TRUE;

              /* If there's no offer from preferred server in this
                 time period we'll use this offer. We have received
                 message, sp we no longer need timeout to resend. */
              ssh_cancel_timeout(&dhcp->timeout);
              ssh_register_timeout(&dhcp->timeout,
                                   (ssh_random_get_byte() %
                                    SSH_DHCP_TIMEOUT_RANDOMIZER),
                                   dhcp->params.offer_timeout_usec,
                                   dhcp_offer_timeout, dhcp);
            }
          memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
          return SSH_FSM_SUSPENDED;
        }
      dhcp->wait_offer = FALSE;
    }

  if (dhcp->got_offer && dhcp->wait_offer)
    message = &dhcp->offer;
  else
    memcpy(&dhcp->offer, &dhcp->message, sizeof(SshDHCPMessageStruct));

  /* Cancel timeout waiting for delayed offers. */
  ssh_cancel_timeout(&dhcp->timeout);

  if (message->yiaddr == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Offer does not contain IP address, ignoring this offer"));
      dhcp->got_offer = FALSE;
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      return SSH_FSM_SUSPENDED;
    }

  /* Get offered IP */
  SSH_INT_TO_IP4(&offered_ip, message->yiaddr);
  ssh_ipaddr_print(&offered_ip, yiaddr, sizeof(yiaddr));
  if (!ssh_inet_is_valid_ip_address(yiaddr))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Offered IP address is not valid, ignoring this offer"));
      dhcp->got_offer = FALSE;
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      return SSH_FSM_SUSPENDED;
    }

  if (!dhcp->info)
    {
      dhcp->info = ssh_calloc(1, sizeof(*dhcp->info));
      if (dhcp->info == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No space"));
          dhcp->status = SSH_DHCP_STATUS_ERROR;
          SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
        }
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Offered address %s by server %s accepted", yiaddr, server));
  dhcp->got_offer = TRUE;

  /* Lets tell server that we'll take this offer, and restart retransmit
     count */
  dhcp->retransmit_count = 0;

  /* Clear out the message */
  memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));

  SSH_FSM_SET_NEXT(ssh_dhcp_st_request);
  return SSH_FSM_CONTINUE;
}

/* Client to Server: Client verifies/requests IP address.

   Sends request to the server. This can be first state as well if the
   information is already provided by application. On the other hand,
   this is called also when we've received offer from server. In this
   case, this is used to tell the server that we've accepted the
   offer. */

SSH_FSM_STEP(ssh_dhcp_st_request)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessageStruct request;
  SshDHCPMessage message;
  SshIpAddrStruct ip;
  SshDHCPInformation info;
  unsigned char p[1024];
  size_t p_len;
  int i = 0;
  unsigned char remote_port[6];
  unsigned char *remote_host = NULL;


  SSH_DEBUG(SSH_D_MIDSTART, ("Sending DHCPREQUEST"));

  if (dhcp->retransmit_count > dhcp->params.retransmit_count)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Retransmission limit reached, giving up"));
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "DHCP operation timeout.");
      dhcp->status = SSH_DHCP_STATUS_TIMEOUT;

      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Cancel retransmit for possibly running DISCOVER, We'll have own
     retransmit for this REQUEST. */
  ssh_cancel_timeout(&dhcp->timeout);

  message = NULL;

  /* Have we got an offer already? */
  if (dhcp->got_offer && !dhcp->wait_offer &&
      dhcp->status != SSH_DHCP_STATUS_RENEW &&
      dhcp->status != SSH_DHCP_STATUS_REBIND)
    {
      SshDHCPMessage m = &dhcp->offer;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending offer confirmation to server"));

      /* If a custom set of options has been defined */
      if (dhcp->params.options)
        {
          unsigned char data[8];

          ssh_dhcp_make_message(dhcp, &request, dhcp->info);

          ssh_dhcp_set_dhcp_options(dhcp, &request, dhcp->info,
                                    SSH_DHCPREQUEST);

          /* Take server ID and the offered IP from the offer message */
          if (ssh_dhcp_option_get(m, SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                              data, sizeof(data), NULL) == TRUE)
            {
              ssh_dhcp_option_put(&request,
                                  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                                  4, data);
            }

          if (m->yiaddr)
            {
              unsigned char offered_ip[4];
              SSH_PUT_32BIT(offered_ip, m->yiaddr);
              ssh_dhcp_option_put(&request,
                                  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
                                  4, offered_ip);
            }

          ssh_dhcp_option_put(&request, SSH_DHCP_OPTION_END, 1, NULL);
          message = &request;
        }
      /* No custom set of options, use what the server has set. */
      else
        {
          /* We actually make little modification to the offered packet
             and resend that. This way we'll quarantee that we have all
             the mandatory fields set (as server has set them already) */
          m->op = SSH_DHCP_BOOTREQUEST;

          /* Set mandatory `server identifier' option */
          if (!ssh_dhcp_option_check(m, SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER)
              && dhcp->info->server_ip)
            {
              unsigned char server_id[4];

              if (ssh_ipaddr_parse(&ip, dhcp->info->server_ip))
                {
                  SSH_PUT_32BIT(server_id, SSH_IP4_TO_INT(&ip));
                  ssh_dhcp_option_put(m,
                                      SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                                      4, server_id);
                }
            }

          /* Set mandatory `requested address' option */
          if (!ssh_dhcp_option_check(m,
                                     SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS))
            {
              unsigned char offered_ip[4];
              SSH_PUT_32BIT(offered_ip, m->yiaddr);
              ssh_dhcp_option_put(m,
                                  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
                                  4, offered_ip);
            }

          /* If client identifier was provided earlier we must provide it
             now as well. */
          if (dhcp->retransmit_count != 1 || dhcp->params.no_compatibility)
            {
              if (dhcp->params.client_identifier &&
                  !ssh_dhcp_option_check(m,
                                      SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER))
                {
                  ssh_dhcp_option_put(m,
                                      SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
                                      dhcp->params.client_identifier_len,
                                      dhcp->params.client_identifier);
                }
            }
          /* Set message type to DHCPREQUEST */
          ssh_dhcp_option_set_message_type(m, SSH_DHCPREQUEST);
          message = m;
        }

      /* RFC says that at this point ciaddr MUST be zero but
         older servers (implementing older RFC) requires ciaddr! This
         is a conflict in the RFC1541 and RFC2131. */
      if (dhcp->retransmit_count == 1 && !dhcp->params.no_compatibility)
        message->ciaddr = m->yiaddr;
      else
        message->ciaddr = 0;

      message->yiaddr = 0;
      message->secs = dhcp->discover_secs;
    }

  /* If we don't have an offer and have pre-set DHCP configuration,
     just send the request to the server. */
  info = NULL;

  if (!dhcp->got_offer || dhcp->status == SSH_DHCP_STATUS_RENEW ||
      dhcp->status == SSH_DHCP_STATUS_REBIND)
    {
      info = dhcp->info;

      if (info)
        {
          /* IP address must be defined */
          if (!info->my_ip)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Cannot send DHCPREQUEST because I don't know my "
                            "IP address, reverting to first state."));
              SSH_FSM_SET_NEXT(ssh_dhcp_st_discover);
              return SSH_FSM_CONTINUE;
            }

          ssh_dhcp_make_message(dhcp, &request, dhcp->info);

          ssh_dhcp_set_dhcp_options(dhcp, &request, info, SSH_DHCPREQUEST);

          ssh_dhcp_option_put(&request, SSH_DHCP_OPTION_END, 1, NULL);
          message = &request;
          /* This is a lease renewal, remove the server identifier to
             anticipate failover. */
          ssh_dhcp_option_remove(&request,
                                 SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER);

          /* Save session ID for future packet identifying */
          if (!dhcp->xid)
            dhcp->xid = request.xid;
        }
      else
        {
          /* Somehow the configuration does not exist. Revert to first state
             and send discover message. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("DHCP configuration does not exist, reverting to "
                        "first state"));
          SSH_FSM_SET_NEXT(ssh_dhcp_st_discover);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Encode packet */
  if (message == NULL ||
      (p_len = ssh_dhcp_message_encode(message, p, sizeof(p))) == 0)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Send the packet */
  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
    {
      if (dhcp->params.dhcp_servers[i].remote_ip != NULL)
        {
          /* Re-new MUST NOT be broadcasted */
          if (info && dhcp->status == SSH_DHCP_STATUS_RENEW &&
              !memcmp(dhcp->params.dhcp_servers[i].remote_ip,
                      SSH_DHCP_BROADCAST,
                      ssh_ustrlen(dhcp->params.dhcp_servers[i].remote_ip)))
            remote_host = info->server_ip;
          else
            remote_host = dhcp->params.dhcp_servers[i].remote_ip;
          ssh_snprintf(remote_port, sizeof(remote_port), "%d",
                       dhcp->params.dhcp_servers[i].remote_port);
          ssh_udp_send(main_context->sender, remote_host, remote_port,
                       p, p_len);
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_transmitted);
          SSH_DHCP_UPDATE_STATS(main_context->stats.request);
        }
    }


  /* Set retransmission timeout */
  ssh_cancel_timeout(&dhcp->timeout);
  ssh_register_timeout(&dhcp->timeout,
                       dhcp->params.retransmit_interval +
                       (ssh_random_get_byte() % SSH_DHCP_TIMEOUT_RANDOMIZER),
                       dhcp->params.retransmit_interval_usec,
                       dhcp_retransmit_request, dhcp);

  return SSH_FSM_SUSPENDED;
}

/* Server to Client: The IP address has been commited. This will again
   run through all the settings server sent, just in case, and will save
   them. This also registers the re-new and re-bind timeouts. */

SSH_FSM_STEP(ssh_dhcp_st_ack)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessage message = &dhcp->message;
  SshDHCPOptionsDefault def = NULL;
  SshIpAddrStruct offered_ip, server_id;
  SshUInt32 lease_time;
  unsigned char data[8];
  unsigned char yiaddr[64], server[64];
  Boolean inform = dhcp->status == SSH_DHCP_STATUS_INFORM;

  SSH_ASSERT(dhcp != NULL);
  SSH_ASSERT(message != NULL);

  SSH_DEBUG(SSH_D_MIDSTART, ("Received DHCPACK"));

  if (dhcp->status == SSH_DHCP_STATUS_ABORTED)
    {
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* We are already bound. */
  if (dhcp->got_ack && dhcp->status == SSH_DHCP_STATUS_BOUND)
    {
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Ignore offer if option set is not valid. */
  if (ssh_dhcp_compare_option_set(dhcp, &dhcp->message, SSH_DHCPACK)
      == FALSE)
    {
      /* Clear out this message. */
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      /* Update statistics */
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      return SSH_FSM_SUSPENDED;
    }

  if (message->yiaddr == 0 && !inform)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ACK does not contain IP address, bad packet"));
      SSH_FSM_SET_NEXT(ssh_dhcp_st_decline);
      return SSH_FSM_CONTINUE;
    }

  /* Save offered data */
  if (!dhcp->info)
    {
      dhcp->info = ssh_calloc(1, sizeof(*dhcp->info));
      if (dhcp->info == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No space"));
          dhcp->status = SSH_DHCP_STATUS_ERROR;
          SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Get lease time. We need this in case the DHCPACK does not explicitly
     specify renew and rebind times. */
  lease_time = 0;
  if (ssh_dhcp_option_get(message, SSH_DHCP_OPTION_DHCP_LEASE_TIME,
                          data, sizeof(data), NULL))
    lease_time = SSH_GET_32BIT(data);

  if (lease_time == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Lease time is not valid, bad packet"));
      SSH_FSM_SET_NEXT(ssh_dhcp_st_decline);
      return SSH_FSM_CONTINUE;
    }
  dhcp->info->lease_time = lease_time;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Received IP Address Lease Time %u",
                               lease_time));

  /* Get offered IP */
  if (!inform)
    {
      SSH_INT_TO_IP4(&offered_ip, message->yiaddr);
      ssh_ipaddr_print(&offered_ip, yiaddr, sizeof(yiaddr));
      if (!ssh_inet_is_valid_ip_address(yiaddr))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IP address is not valid, bad packet"));
          SSH_FSM_SET_NEXT(ssh_dhcp_st_decline);
          return SSH_FSM_CONTINUE;
        }
      if (dhcp->info->my_ip != NULL)
        ssh_free(dhcp->info->my_ip);
      dhcp->info->my_ip = ssh_strdup(yiaddr);
      if (dhcp->info->my_ip == NULL)
        goto alloc_error;
    }

  /* Get server identifier */
  ssh_dhcp_option_get(message,
                      SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                      data, sizeof(data), NULL);
  SSH_INT_TO_IP4(&server_id, SSH_GET_32BIT(data));
  ssh_ipaddr_print(&server_id, server, sizeof(server));
  if (!dhcp->info->server_ip)
    dhcp->info->server_ip = ssh_strdup(server);
  if (dhcp->info->server_ip == NULL)
    goto alloc_error;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Commited address %s by server %s", yiaddr, server));

  /* Get all common options and save them */
  def = ssh_dhcp_get_dhcp_options(dhcp, message);
  if (def)
    {
      SshIpAddrStruct ip;
      unsigned char ips[64];
      int i;

      /* Save timeouts for the assigned IP address. These mandate when
         we'll have to reissue the IP address. */
      if (def->t1)
        dhcp->info->renew_timeout = def->t1;
      else /* use default value (0.5 * lease) */
        dhcp->info->renew_timeout = (lease_time / 2);

      if (def->t2)
        dhcp->info->rebind_timeout = def->t2;
      else /* use default value (0.875 * lease) */
        dhcp->info->rebind_timeout = (lease_time / 8) * 7;

      if (dhcp->info->renew_timeout != 0xffffffff)
        {
          if (dhcp->info->rebind_timeout <= dhcp->info->renew_timeout)
            dhcp->info->rebind_timeout = dhcp->info->renew_timeout +
              (dhcp->info->renew_timeout / 4);
          dhcp->info->rebind_timeout -= dhcp->info->renew_timeout;
        }
      else
        {
          dhcp->info->rebind_timeout = def->t1;
        }

      /* Save netmask */
      if (def->netmask != 0)
        {
          if (dhcp->info->netmask != NULL)
            ssh_free(dhcp->info->netmask);
          SSH_INT_TO_IP4(&ip, def->netmask);
          ssh_ipaddr_print(&ip, ips, sizeof(ips));
          dhcp->info->netmask = ssh_strdup(ips);
          if (dhcp->info->netmask == NULL)
            goto alloc_error;
        }

      /* Save gateway(s) */
      if (def->gateway_ip_count > 0)
        {
          if (dhcp->info->gateway_ip != NULL)
            {
              for (i = 0; i < dhcp->info->gateway_ip_count; i++)
                ssh_free(dhcp->info->gateway_ip[i]);
              ssh_free(dhcp->info->gateway_ip);
            }
          dhcp->info->gateway_ip =
            ssh_calloc(def->gateway_ip_count,
                       sizeof(*dhcp->info->gateway_ip));
          if (dhcp->info->gateway_ip == NULL)
            goto alloc_error;

          for (i = 0; i < def->gateway_ip_count; i++)
            {
              SSH_INT_TO_IP4(&ip, def->gateway_ip[i]);
              ssh_ipaddr_print(&ip, ips, sizeof(ips));
              dhcp->info->gateway_ip[i] = ssh_strdup(ips);
              if (dhcp->info->gateway_ip[i] == NULL)
                goto alloc_error;
              dhcp->info->gateway_ip_count = i + 1;
            }
        }

      /* Save name server(s) */
      if (def->dns_ip_count > 0)
        {
          if (dhcp->info->dns_ip != NULL)
            {
              for (i = 0; i < dhcp->info->dns_ip_count; i++)
                ssh_free(dhcp->info->dns_ip[i]);
              ssh_free(dhcp->info->dns_ip);
            }
          dhcp->info->dns_ip = ssh_calloc(def->dns_ip_count,
                                          sizeof(*dhcp->info->dns_ip));
          if (dhcp->info->dns_ip == NULL)
            goto alloc_error;

          for (i = 0; i < def->dns_ip_count; i++)
            {
              SSH_INT_TO_IP4(&ip, def->dns_ip[i]);
              ssh_ipaddr_print(&ip, ips, sizeof(ips));
              dhcp->info->dns_ip[i] = ssh_strdup(ips);
              if (dhcp->info->dns_ip[i] == NULL)
                goto alloc_error;
              dhcp->info->dns_ip_count = i + 1;
            }
        }

      /* Save WINS server(s) */
      if (def->wins_ip_count > 0)
        {
          if (dhcp->info->wins_ip != NULL)
            {
              for (i = 0; i < dhcp->info->wins_ip_count; i++)
                ssh_free(dhcp->info->wins_ip[i]);
              ssh_free(dhcp->info->wins_ip);
            }
          dhcp->info->wins_ip = ssh_calloc(def->wins_ip_count,
                                           sizeof(*dhcp->info->wins_ip));
          if (dhcp->info->wins_ip == NULL)
            goto alloc_error;

          for (i = 0; i < def->wins_ip_count; i++)
            {
              SSH_INT_TO_IP4(&ip, def->wins_ip[i]);
              ssh_ipaddr_print(&ip, ips, sizeof(ips));
              dhcp->info->wins_ip[i] = ssh_strdup(ips);
              if (dhcp->info->wins_ip[i] == NULL)
                goto alloc_error;
              dhcp->info->wins_ip_count = i + 1;
            }
        }

      /* Save host name */
      if (def->hostname[0] != '\0')
        {
          if (dhcp->info->hostname != NULL)
            ssh_free(dhcp->info->hostname);
          dhcp->info->hostname = ssh_strdup(def->hostname);
          if (dhcp->info->hostname == NULL)
            goto alloc_error;
        }

      /* Save default DNS name */
      if (def->dns_name[0] != '\0')
        {
          if (dhcp->info->domain != NULL)
            ssh_free(dhcp->info->domain);
          dhcp->info->domain = ssh_strdup(def->dns_name);
          if (dhcp->info->domain == NULL)
            goto alloc_error;
        }

      /* Save root path */
      if (def->file[0] != '\0')
        {
          if (dhcp->info->file != NULL)
            ssh_free(dhcp->info->file);
          dhcp->info->file = ssh_strdup(def->file);
          if (dhcp->info->file == NULL)
            goto alloc_error;
        }

      /* Save NIS domain name */
      if (def->nis_name[0] != '\0')
        {
          if (dhcp->info->nis != NULL)
            ssh_free(dhcp->info->nis);
          dhcp->info->nis = ssh_strdup(def->nis_name);
          if (dhcp->info->nis == NULL)
            goto alloc_error;
        }

      if (def->gateway_ip_count)
        ssh_free(def->gateway_ip);
      if (def->dns_ip_count)
        ssh_free(def->dns_ip);
      if (def->wins_ip_count)
        ssh_free(def->wins_ip);
      ssh_free(def);
    }

  if (!inform)
    {
      /* Future ack's will be ignored from now on. */
      dhcp->got_ack = TRUE;

      SSH_DEBUG(5, ("Registering RENEW timeout"));

      /* Cancel any retransmits */
      ssh_cancel_timeout(&dhcp->timeout);

      /* We are now in BOUND status */
      dhcp->status = SSH_DHCP_STATUS_BOUND;
      dhcp->retransmit_count = 0;

      SSH_DEBUG(5, ("We are in BOUND state"));
    }

 /* Clear out the message */
  memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));

  /* We're done */
  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
  return SSH_FSM_CONTINUE;

 alloc_error:
  SSH_DEBUG(SSH_D_FAIL, ("No space"));
  if (def != NULL)
    {
      if (def->gateway_ip)
        ssh_free(def->gateway_ip);
      if (def->dns_ip)
        ssh_free(def->dns_ip);
      if (def->wins_ip)
        ssh_free(def->wins_ip);
      ssh_free(def);
    }
  dhcp->status = SSH_DHCP_STATUS_ERROR;
  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
  return SSH_FSM_CONTINUE;
}

/* Server to Client: The client won't get the IP address. For some reason
   server did not like our request and refuses to give us the IP. In this
   case we will trigger retransmission and try again. If we fail all over
   again and will reach the maximum retransmission limit we'll stop the
   DHCP session for good. */

SSH_FSM_STEP(ssh_dhcp_st_nak)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessage message = &dhcp->message;
  unsigned char data[1024];
  unsigned char server[64];

  SSH_ASSERT(dhcp != NULL);
  SSH_ASSERT(message != NULL);

  SSH_DEBUG(5, ("Received DHCPNAK"));

  /* If we have ACK, we'll ignore NAK's. */
  if (dhcp->got_ack)
    {
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Ignore offer if option set is not valid. */
  if (ssh_dhcp_compare_option_set(dhcp, &dhcp->message, SSH_DHCPNAK)
      == FALSE)
    {
      /* Clear out this message. */
      memset(&dhcp->message, 0, sizeof(SshDHCPMessageStruct));
      /* Update statistics */
      SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
      return SSH_FSM_SUSPENDED;
    }

  server[0] = '\000';

  /* Get server identifier */
  if (ssh_dhcp_option_get(message,
                          SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
                          data, sizeof(data), NULL))
    {
      SshIpAddrStruct server_id;

      SSH_INT_TO_IP4(&server_id, SSH_GET_32BIT(data));
      ssh_ipaddr_print(&server_id, server, sizeof(server));

      SSH_DEBUG(SSH_D_FAIL, ("DHCPNAK form server %s", server));
    }

  /* If we have offer from a specific server then check whether the
     NAK is from that.  If not then just ignore it. */
  if (dhcp->got_offer && dhcp->info->server_ip &&
      (ssh_ustrcmp(dhcp->info->server_ip, server) != 0))
    {
      return SSH_FSM_SUSPENDED;
    }

  dhcp->status = SSH_DHCP_STATUS_OK;

  /* Check whether we received error message */
  memset(data, 0, sizeof(data));
  if (ssh_dhcp_option_get(message, SSH_DHCP_OPTION_DHCP_MESSAGE,
                          data, sizeof(data), NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Server says: %s", data));
    }

  dhcp->xid = 0;
  dhcp->got_offer = FALSE;
  dhcp->got_ack = FALSE;

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                "Received DHCP NAK, address aquisition failed.");
  dhcp->status = SSH_DHCP_STATUS_ERROR;
  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);

  return SSH_FSM_CONTINUE;

}

/* Client to Server: The IP address is in use already. This is also sent
   if we fail in DHCPACK packet parsing. We'll refuse to use that IP and
   restart DHCP from the begin. */

SSH_FSM_STEP(ssh_dhcp_st_decline)
{
  SshDHCP dhcp = (SshDHCP)thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessageStruct message;
  unsigned char remote_port[6];
  unsigned char p[1024];
  size_t p_len;

  int i = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Sending DHCPDECLINE"));

  if (dhcp->info == NULL)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  ssh_dhcp_make_message(dhcp, &message, dhcp->info);

  ssh_dhcp_set_dhcp_options(dhcp, &message, dhcp->info,
                                SSH_DHCPDECLINE);

  ssh_dhcp_option_put(&message, SSH_DHCP_OPTION_END, 0, NULL);

  /* Encode packet */
  p_len = ssh_dhcp_message_encode(&message, p, sizeof(p));
  if (p_len == 0)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }

  /* Send decline unicast only to the server that ACKed */
  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
  {
    if (dhcp->params.dhcp_servers[i].remote_ip != NULL &&
        !memcmp(dhcp->params.dhcp_servers[i].remote_ip,
                dhcp->info->server_ip,
                ssh_ustrlen(dhcp->info->server_ip)))
      {
        ssh_snprintf(remote_port, sizeof(remote_port), "%d",
                     dhcp->params.dhcp_servers[i].remote_port);
        ssh_udp_send(main_context->sender,
                     dhcp->params.dhcp_servers[i].remote_ip,
                     remote_port,
                     p, p_len);
        SSH_DHCP_UPDATE_STATS(main_context->stats.packets_transmitted);
        SSH_DHCP_UPDATE_STATS(main_context->stats.decline);
        break;
      }
  }

  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
  return SSH_FSM_CONTINUE;
}

/* Client to Server: Client don't need the IP anymore. We are doing a
   graceful ending of the DHCP session and will notify the server that we
   won't need the IP anymore. */

SSH_FSM_STEP(ssh_dhcp_st_release)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessageStruct message;
  unsigned char p[1024];
  size_t p_len;
  int i = 0;
  unsigned char remote_port[6];
  SshIpAddrStruct ip;

  SSH_DEBUG(SSH_D_MIDSTART, ("Sending DHCPRELEASE"));

  ssh_dhcp_make_message(dhcp, &message, dhcp->info);
  if (dhcp->info && dhcp->info->my_ip)
    {
      if (ssh_ipaddr_parse(&ip, dhcp->info->my_ip))
        message.ciaddr = SSH_IP4_TO_INT(&ip);
    }
  else
    message.ciaddr = 0;


  ssh_dhcp_set_dhcp_options(dhcp, &message, dhcp->info,  SSH_DHCPRELEASE);
  ssh_dhcp_option_put(&message, SSH_DHCP_OPTION_END, 1, NULL);

  /* Encode packet */
  if ((p_len = ssh_dhcp_message_encode(&message, p, sizeof(p))) == 0)
    {
      dhcp->status = SSH_DHCP_STATUS_ERROR;
      SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
      return SSH_FSM_CONTINUE;
    }


  /* Send release to all DHCP servers, to accommodate for a failover */
  for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
    {
      if (dhcp->params.dhcp_servers[i].remote_ip != NULL)
        {
          ssh_snprintf(remote_port, sizeof(remote_port), "%d",
                       dhcp->params.dhcp_servers[i].remote_port);
          ssh_udp_send(main_context->sender,
                       dhcp->params.dhcp_servers[i].remote_ip,
                       remote_port, p, p_len);
          SSH_DHCP_UPDATE_STATS(main_context->stats.packets_transmitted);
          SSH_DHCP_UPDATE_STATS(main_context->stats.release);
        }
    }

  dhcp->status = SSH_DHCP_STATUS_OK;
  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish_pending);
  return SSH_FSM_CONTINUE;
}

/* Received an packet from network. Parse it and call correct
   state. */
SSH_FSM_STEP(ssh_dhcp_st_receive)
{
  SshDHCP dhcp = thread_context;
  SshDHCPMainCtx main_context = (SshDHCPMainCtx)fsm_context;
  SshDHCPMessage message;
  unsigned char m[1];
  size_t tmp_len;

  SSH_ASSERT(dhcp != NULL);

  SSH_DEBUG(SSH_D_MIDSTART, ("Received packet, starting processing."));

  message = &dhcp->message;

  if (message->op != SSH_DHCP_BOOTREPLY || message->xid != dhcp->xid)
    goto out;

  /* Check cookie */
  if (!ssh_dhcp_option_check_cookie(message))
    goto out;

  /* Get message type */
  if (!ssh_dhcp_option_get(message,
                           SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
                           m, sizeof(m), &tmp_len))
    goto out;

  switch (m[0])
    {
    case SSH_DHCPDISCOVER:
    case SSH_DHCPREQUEST:
    case SSH_DHCPDECLINE:
    case SSH_DHCPRELEASE:
    case SSH_DHCPINFORM:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received a non-reply message %d",
                 (int)m[0]));
      goto out;

    case SSH_DHCPOFFER:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received DHCPOFFER message %d", (int)m[0]));
      SSH_DHCP_UPDATE_STATS(main_context->stats.offer);
      SSH_FSM_SET_NEXT(ssh_dhcp_st_offer);
      break;

    case SSH_DHCPACK:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received DHCPACK message %d", (int)m[0]));
      SSH_DHCP_UPDATE_STATS(main_context->stats.ack);
      SSH_FSM_SET_NEXT(ssh_dhcp_st_ack);
      break;

    case SSH_DHCPNAK:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received DHCPNAK message %d", (int)m[0]));
      SSH_DHCP_UPDATE_STATS(main_context->stats.nak);
      SSH_FSM_SET_NEXT(ssh_dhcp_st_nak);
      break;

    default:
      SSH_DEBUG(SSH_D_NETGARB,
                ("Bad message type received %d", (int)m[0]));
      goto out;
    }
  return SSH_FSM_CONTINUE;

 out:
  SSH_DHCP_UPDATE_STATS(main_context->stats.packets_dropped);
  memset(&dhcp->message, 0, sizeof(dhcp->message));

  SSH_DEBUG(SSH_D_MIDSTART, ("Error."));
  return SSH_FSM_SUSPENDED;
}

/* User callback invoked, e.g for checking after ACK that the received address
   is not already in use. */

SSH_FSM_STEP(ssh_dhcp_st_finish_pending)
{
  SshDHCP dhcp = thread_context;

  /* Call user callback */
  SSH_DEBUG(SSH_D_MIDSTART, ("Invoking user callback."));

  SSH_FSM_SET_NEXT(ssh_dhcp_st_finish);

  ssh_dhcp_cancel_timeouts(dhcp);

  if (dhcp->callback)
    (*dhcp->callback)(dhcp, dhcp->info, dhcp->status, dhcp->context);
  return SSH_FSM_CONTINUE;
}

/* The final state that is always called when ending DHCP session. This is
   called regardless was the session successfully completed. */
SSH_FSM_STEP(ssh_dhcp_st_finish)
    {
  SshDHCP dhcp = thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("Finishing DHCP thread."));

  ssh_dhcp_cancel_timeouts(dhcp);

  return SSH_FSM_FINISH;
}

/* Cancels all timeouts. */
void ssh_dhcp_cancel_timeouts(SshDHCP dhcp)
{
  ssh_cancel_timeout(&dhcp->timeout);
  ssh_cancel_timeout(&dhcp->total_timeout);
}
