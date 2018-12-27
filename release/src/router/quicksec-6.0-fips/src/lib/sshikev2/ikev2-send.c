/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 send.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2NetSend"

static void ikev2_packet_send_timer(void *context)
{
  SshIkev2Packet packet = context;

  ssh_fsm_continue(packet->thread);
}

void ikev2_udp_retransmit_response_packet(SshIkev2Packet packet,
                                          SshIkev2Server server,
                                          SshIpAddr remote_ip,
                                          SshUInt16 remote_port)
{
  SshUdpListener listener;

  packet->server->statistics->total_packets_out++;
  packet->server->statistics->total_octets_out += packet->encoded_packet_len;

  listener =
    packet->use_natt ? server->nat_t_listener : server->normal_listener;

  if (listener != NULL)
    {
      if (ssh_udp_send_ip(listener, remote_ip, remote_port,
                          packet->encoded_packet, packet->encoded_packet_len)
          != SSH_UDP_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Can not send UDP datagram to %@:%d",
                                  ssh_ipaddr_render, remote_ip, remote_port));
        }
    }

  /* Mark packet as sent */
  packet->sent = 1;
}

void ikev2_udp_send_packet(SshIkev2Packet packet)
{
  SshUdpListener listener;

  packet->server->statistics->total_packets_out++;
  packet->server->statistics->total_octets_out += packet->encoded_packet_len;

#ifdef SSHDIST_IKE_MOBIKE
  if (packet->ed && !(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
    {
      /* Check if the remote IP address is different from the last used one */
      if (SSH_IP_DEFINED(&packet->ed->last_packet_remote_ip) &&
          SSH_IP_CMP(&packet->ed->last_packet_remote_ip, packet->remote_ip))
        packet->ed->multiple_addresses_used = 1;

      /* Check if the local IP address is different from the last used one */
      if (SSH_IP_DEFINED(&packet->ed->last_packet_local_ip) &&
          SSH_IP_CMP(&packet->ed->last_packet_local_ip,
                     packet->server->ip_address))
        packet->ed->multiple_addresses_used = 1;

      packet->ed->last_packet_remote_ip = packet->remote_ip[0];
      packet->ed->last_packet_local_ip = packet->server->ip_address[0];

    }
#endif /* SSHDIST_IKE_MOBIKE */

  if (packet->use_natt)
    listener = packet->server->nat_t_listener;
  else
    listener = packet->server->normal_listener;

  if (listener != NULL)
    {
      if (ssh_udp_send_ip(listener,
                          packet->remote_ip, packet->remote_port,
                          packet->encoded_packet, packet->encoded_packet_len)
          != SSH_UDP_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Can not send UDP datagram to %@:%d",
                                  ssh_ipaddr_render, packet->remote_ip,
                                  packet->remote_port));
        }
    }

  /* Mark packet as sent */
  packet->sent = 1;
}

#ifdef SSHDIST_IKE_MOBIKE
static void ikev2_reply_cb_get_address_pair(SshIkev2Error error_code,
                                            SshIkev2Server local_server,
                                            SshIpAddr remote_ip,
                                            void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code == SSH_IKEV2_ERROR_DISCARD_PACKET)
    {
      SSH_IKEV2_DEBUG(SSH_D_NICETOKNOW,
                      ("Error: Get address pair failed: %d (Discard packet)",
                       (int) error_code));
      packet->error = error_code;
      return;
    }
  else if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: Get address pair failed: %d",
                                   error_code));
      ikev2_error(packet, error_code);
      return;
    }
  SSH_ASSERT(SSH_IP_DEFINED(remote_ip));
  SSH_ASSERT(local_server != NULL);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Address pair returned from policy local=%@, remote=%@",
             ssh_ipaddr_render, local_server->ip_address,
             ssh_ipaddr_render, remote_ip));

  packet->remote_ip[0] = *remote_ip;
  packet->remote_port = packet->use_natt ?
    local_server->nat_t_remote_port : local_server->normal_remote_port;
  packet->server = local_server;

}
#endif /* SSHDIST_IKE_MOBIKE */


/*
 * State machine for sending packets
 */

SSH_FSM_STEP(ikev2_packet_st_send_request_address)
{
  SshIkev2Packet packet = thread_context;
#ifdef SSHDIST_IKE_MOBIKE
  SshIkev2Params params = &packet->server->context->params;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2ExchangeData ed = packet->ed;
#endif /* SSHDIST_IKE_MOBIKE */

  packet = thread_context;
  SSH_IKEV2_DEBUG(SSH_D_MIDSTART, ("Sending packet/request address pair"));
  SSH_FSM_SET_NEXT(ikev2_packet_st_send);

#ifdef SSHDIST_IKE_MOBIKE
  /* The initiator of an exchange using an MOBIKE enabled SA requests
     an address pair from policy when sending a packet in the following
     cases.

     1. An informational exchange with the PROBE_MESSAGE flag set.
     2. params->mobike_worry_counter packets have been sent on a given
     exchange without receiving a response.
     3. The IKE SA has the request_address_from_policy flag set. */

  if (!(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) && ike_sa != NULL &&
      ((!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
        (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE)) ||
       (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)))
    {
      if ((packet->retransmit_counter > params->mobike_worry_counter)
          || ike_sa->request_address_from_policy
          || (ed != NULL && ed->state == SSH_IKEV2_STATE_INFORMATIONAL &&
              ed->info_ed->flags & SSH_IKEV2_INFO_CREATE_FLAGS_PROBE_MESSAGE))
        {
          /* Should we request a new address pair? */
          if (++ike_sa->address_index_count == params->mobike_worry_counter)
            {
              ike_sa->address_index++;
              ike_sa->address_index_count = 0;
            }

          /* If the worry metric has been exceeded, then start requesting all
             addresses for sending packets on this SA from the policy call.
             When the application has decided on new addresses for the IKE
             SA, it will clear this flag. */
          if (packet->retransmit_counter > params->mobike_worry_counter)
            ike_sa->request_address_from_policy = 1;

          SSH_IKEV2_DEBUG(SSH_D_MIDSTART,
                          ("Requesting address pair from policy"));

          SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet,
                                                   ike_sa,
                                                   get_address_pair)
                             (ike_sa->server->sad_handle,
                              ed, ike_sa->address_index,
                              ikev2_reply_cb_get_address_pair, packet));
          SSH_NOTREACHED;
        }
    }
#endif /* SSHDIST_IKE_MOBIKE */

  return SSH_FSM_CONTINUE;
}


/* Send data to peer: this is called from the IKE to send (and
   retransmit packet on fire and forget mentality). */

SSH_FSM_STEP(ikev2_packet_st_send)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Params params = &packet->server->context->params;
  SshUInt32 timeout_sec, timeout_usec;

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART, ("Sending packet/Do"));
  if (packet->response_received)
    {
      SSH_FSM_SET_NEXT(ikev2_packet_st_send_done);
      return SSH_FSM_CONTINUE;
    }

  if (packet->retransmit_counter > params->retry_limit)
    {
      SSH_ASSERT(packet->ike_sa != NULL);

      /** Error: Timeout */
      /* Check if we have received any unprotected error notifies for this
         IKE SA and fail negotiation with that error code instead of TIMEOUT.*/
      /* This might call
         SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_done)
         SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
         SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_spi_delete)
         SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
      if (packet->ike_sa->received_unprotected_error != SSH_IKEV2_ERROR_OK)
        ikev2_xmit_error(packet, packet->ike_sa->received_unprotected_error);
      else
        ikev2_xmit_error(packet, SSH_IKEV2_ERROR_TIMEOUT);
      SSH_FSM_SET_NEXT(ikev2_packet_st_send_done);
      return SSH_FSM_CONTINUE;
    }

  if (packet->error != SSH_IKEV2_ERROR_DISCARD_PACKET)
    {
      /* Set the sending addresses from the IKE SA if the remote address
         is not defined. The remote address is not defined when retransmitting
         request packets. */
      if (!SSH_IP_DEFINED(packet->remote_ip))
        {
          SSH_ASSERT(packet->ike_sa != NULL);
          packet->server = packet->ike_sa->server;
          *packet->remote_ip = *packet->ike_sa->remote_ip;
          packet->remote_port = packet->ike_sa->remote_port;

          if (packet->ike_sa->flags &
              (SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T |
               SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
            packet->use_natt = 1;
          else
            packet->use_natt = 0;
        }
      SSH_ASSERT(packet->server != NULL);

      if (packet->retransmit_counter == 0)
        SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                          ("Sending packet %ld %@:%d to %@:%d",
                           (long) packet->message_id,
                           ssh_ipaddr_render,
                           packet->server->ip_address,
                           packet->use_natt ?
                           packet->server->nat_t_local_port :
                           packet->server->normal_local_port,
                           ssh_ipaddr_render, packet->remote_ip,
                           packet->remote_port),
                          packet->encoded_packet, packet->encoded_packet_len);
      else
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON,
                        SSH_LOG_INFORMATIONAL,
                        "IKEv2 packet S(%@:%d -> %@:%d): mID=%u "
                        "(retransmit count=%d)",
                        ssh_ipaddr_render, packet->server->ip_address,
                        (packet->use_natt ?
                         packet->server->nat_t_local_port :
                         packet->server->normal_local_port),
                        ssh_ipaddr_render, packet->remote_ip,
                        packet->remote_port,
                        packet->message_id,
                        packet->retransmit_counter);

          SSH_DEBUG(SSH_D_PCKDMP,
                    ("Retransmitting packet %ld to %@:%d (%d'th retry)",
                     (long) packet->message_id,
                     ssh_ipaddr_render, packet->remote_ip,
                     packet->remote_port,
                     packet->retransmit_counter));

          ikev2_debug_packet_out_retransmit(packet->ike_sa, packet);

          packet->server->statistics->total_retransmits++;
        }

      ikev2_udp_send_packet(packet);
    }

  /* we do not retransmit responses or packets we do not have a SA */
  if (packet->ike_sa == NULL)
    {
      SSH_FSM_SET_NEXT(ikev2_packet_st_send_done);
      return SSH_FSM_CONTINUE;
    }

  if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
    {
      SSH_FSM_SET_NEXT(ikev2_packet_st_send_done);
      return SSH_FSM_CONTINUE;
    }

  /* Clear discard packet error for the next retransmit */
  if (packet->error == SSH_IKEV2_ERROR_DISCARD_PACKET)
    packet->error = SSH_IKEV2_ERROR_OK;

  /* Undefine the remote address, it will get updated from the IKE SA
     if this packet is to be retransmitted. This is required since if the
     IKE SA remote address/port gets updated (due to NAT mapping change)
     the retransmitted packet should be sent using the updated remote
     address/port. */
  SSH_IP_UNDEFINE(packet->remote_ip);

  timeout_sec = 0;
  timeout_usec = packet->timeout_msec * 1000;
  while (timeout_usec >= 1000000)
    {
      timeout_sec += 1;
      timeout_usec -= 1000000;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Registering timeout at %lu (%lu.%lu)",
             (unsigned long) packet->timeout_msec,
             (unsigned long) timeout_sec, (unsigned long) timeout_usec));

  ssh_register_timeout(packet->timeout,
                       timeout_sec, timeout_usec,
                       ikev2_packet_send_timer, packet);

  packet->retransmit_counter += 1;

#if 1
  /* Exponential; 1 2 4 8 16 max max max */
  packet->timeout_msec *= 2;
#else
  {
    SshUInt32 tmp;
    /* Natural;     1 2 3 5 8  13   21 max */
    tmp = packet->timeout_msec_prev;
    packet->timeout_msec_prev = packet->timeout_msec;
    packet->timeout_msec += tmp;
  }
#endif
  if (packet->timeout_msec > params->retry_timer_max_msec)
    packet->timeout_msec = params->retry_timer_max_msec;

  SSH_FSM_SET_NEXT(ikev2_packet_st_send_request_address);
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ikev2_packet_st_send_done)
{
  SshIkev2Packet packet = thread_context;

  if (packet->in_window)
    return SSH_FSM_SUSPENDED;
  else
    return SSH_FSM_FINISH;
}

void
ikev2_udp_send(SshIkev2Sa sa,
               SshIkev2Packet packet)
{
  if (sa == NULL)
    {
      if (packet->ike_sa)
        SSH_IKEV2_IKE_SA_FREE(packet->ike_sa);
      packet->ike_sa = NULL;
    }

  if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
    {
      /* Sent responses do not have references to IKE SA's, nor do
         they store ED. */
      if (packet->ike_sa)
        {
          ikev2_free_exchange_data(packet->ike_sa, packet->ed);
          packet->ed = NULL;
          SSH_IKEV2_IKE_SA_FREE(packet->ike_sa);
          packet->ike_sa = NULL;
        }
      packet->ed = NULL;
    }

  packet->timeout_msec = packet->server->context->params.retry_timer_msec;
  packet->timeout_msec_prev = packet->timeout_msec;
  packet->retransmit_counter = 0;

  ssh_fsm_set_next(packet->thread, ikev2_packet_st_send_request_address);
}
/* eof */
