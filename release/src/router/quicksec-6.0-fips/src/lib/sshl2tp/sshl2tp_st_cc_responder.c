/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Control connection establishment, responder.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStCcResponder"

/******************************** FSM states ********************************/

#define SSH_L2TP_DATA           \
  SshL2tp l2tp = fsm_context;   \
  SshL2tpTunnel tunnel = thread_context


static void
tunnel_request_complete(Boolean accept,
                        const unsigned char *shared_secret,
                        size_t shared_secret_len,
                        const unsigned char *local_port,
                        SshL2tpTunnelResultCode result, SshL2tpErrorCode error,
                        const unsigned char *error_message,
                        size_t error_message_len,
                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshL2tpTunnel tunnel = ssh_fsm_get_tdata(thread);
  SshL2tp l2tp = tunnel->l2tp;

  /* The callback completes our asynchronous operation and invalidates
     the operation handle. */
  tunnel->operation_handle = NULL;

  if (accept)
    {
      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_accept_new);

      /* Did the user specify a new local port? */
      if (local_port)
        {
          SshL2tpServer server;

          /* Create a new L2TP server if needed. */
          server = ssh_l2tp_server_start(l2tp, tunnel->info.local_addr,
                                         local_port,
                                         tunnel->server->interface_index,
                                         tunnel->server->routing_instance_id);
          if (server == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not start L2TP server %s:%s",
                         tunnel->info.local_addr, local_port));

              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                  SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                                  NULL, 0);

              SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_reject_new);
            }
          else
            {

              if (server != tunnel->server)
                {
                  /* Float tunnel's local port. */
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Floating local port from %d to %d",
                             (int) tunnel->server->port,
                             (int) server->port));

                  /* Remove our reference from the original server. */
                  ssh_l2tp_server_stop(tunnel->server);

                  /* Assign the new server to the tunnel.  The
                     ssh_l2tp_server_start() has already added one
                     reference to the server for us. */
                  tunnel->server = server;



                  ssh_snprintf(ssh_sstr(tunnel->info.local_port), 12, "%d",
                               (int) server->port);
                }
            }
        }
    }
  else
    {
      /* Tunnel establishment rejected. */
      if (result)
        SSH_L2TP_SET_STATUS(l2tp, result, error, error_message,
                            error_message_len);
      else
        SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED, 0,
                            NULL, 0);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_reject_new);
    }

  /* Store shared secret. */
  if (shared_secret)
    {
      tunnel->shared_secret = ssh_memdup(shared_secret, shared_secret_len);

      if (tunnel->shared_secret == NULL)
        {
          /* Set error code if it is not already set. */
          if (l2tp->result_code == 0)
            SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                                NULL, 0);

          SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_reject_new);
        }
      else
        {
          tunnel->shared_secret_len = shared_secret_len;
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_idle)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (tunnel->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(tunnel->message_queue_cond);

  message = ssh_l2tp_message(&tunnel->message_queue);
  if (message->type != SSH_L2TP_CTRL_MSG_SCCRQ)
    ssh_fatal("Internal error: CC responder thread started for "
              "non-SCCRQ message");

  /* Update tunnel's attributes. */
  ssh_l2tp_tunnel_attributes_steal(&tunnel->info.attributes,
                                   &message->tunnel_attributes);

  /* Let's ask user whether he allows one more control connection
     negotiation. */
  if (l2tp->tunnel_request_cb)
    SSH_FSM_ASYNC_CALL(
      {
        SshOperationHandle h;

        h = (*l2tp->tunnel_request_cb)(&tunnel->info,
                                       tunnel_request_complete,
                                       thread,
                                       l2tp->callback_context);
        if (h)
          tunnel->operation_handle = h;
      });

  /* No callback set.  Let's accept it. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_accept_new);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_reject_new)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("New control connection establishment rejected"));

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

  /* This was not an acceptable SCCRQ.  The error code is already at
     `l2tp'.*/
  SSH_ASSERT(l2tp->result_code);
  SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);

  ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_accept_new)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New control connection accepted"));

  /* Was the packet decoding suspended? */
  message = ssh_l2tp_message(&tunnel->message_queue);
  if (message->suspended_packet)
    {
      unsigned char *packet;
      size_t packet_len;
      unsigned char remote_addr[SSH_IP_ADDR_STRING_SIZE];
      unsigned char remote_port[16];
      size_t data_offset;
      size_t data_len;
      Boolean decode_result;

      /* Yes it was.  Let's resume decoding. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Resuming packet decoding"));

      packet = message->suspended_packet;
      packet_len = message->suspended_packet_len;

      message->suspended_packet = NULL;
      message->suspended_packet_len = 0;

      (void) ssh_ipaddr_print(&message->remote_addr, remote_addr,
                              sizeof(remote_addr));



      ssh_snprintf(ssh_sstr(remote_port), sizeof(remote_port), "%d",
                   (int) message->remote_port);

      /* We reuse our current message so let's free its fields
         first. */
      ssh_l2tp_message_fields_free(message);

      /* Clear error code and message before decoding. */
      SSH_L2TP_CLEAR_STATUS(l2tp);
      decode_result = ssh_l2tp_decode_packet(l2tp, message, tunnel,
                                             packet, packet_len,
                                             remote_addr, remote_port,
                                             &data_offset, &data_len);

      /* We do not need the packet anymore. */
      ssh_free(packet);

      /* Check the success of the decode operation. */
      if (decode_result == FALSE || l2tp->result_code)
        {
          /* Decoding failed. */
          if (l2tp->result_code == 0)
            {
              /* There is no result code so the decode_packet()
                 returned FALSE.  This means that the incoming packet
                 was really malformed. */
              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED, 0,
                                  NULL, 0);
              SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);
            }

          /* Let's disable AVP hiding for this tunnel since we have
             problems decoding our peer's messages.  The reason might
             be wrong shared secret and it does not help us to use
             that one. */
          tunnel->dont_hide = 1;

          /* Tear down this tunnel. */
          ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);

          /* Recycle message. */
          ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

          /* And clean-up. */
          SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

          return SSH_FSM_CONTINUE;
        }

      /* Update tunnel's attributes since they might have changed or
         we have more of them now. */
      ssh_l2tp_tunnel_attributes_steal(&tunnel->info.attributes,
                                       &message->tunnel_attributes);

      /* Was the `Assigned Tunnel ID' AVP hidden in the initial
         message? */
      if (tunnel->info.remote_id == 0)
        {
          /* Yes it was.  Well, now we know it. */
          tunnel->info.remote_id = message->assigned_tunnel_id;
          ssh_adt_insert(l2tp->tunnels_addr_port_id, tunnel);
        }
    }

  /* Steal the challenge from the message. */

  tunnel->received_challenge = message->challenge;
  tunnel->received_challenge_len = message->challenge_len;

  message->challenge = NULL;
  message->challenge_len = 0;

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

  /* We accepted it.  Let's send our SCCRP reply packet. */
  ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_SCCRP);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_responder_wait_ctl_conn);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_wait_ctl_conn)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (tunnel->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(tunnel->message_queue_cond);

  message = ssh_l2tp_message(&tunnel->message_queue);

  if (message->type == SSH_L2TP_CTRL_MSG_SCCCN)
    {
      /* Check challenge response. */
      if (tunnel->sent_challenge)
        {
          if (message->challenge_response == NULL
              || !ssh_l2tp_tunnel_authenticate(
                                        l2tp, message->type,
                                        tunnel->sent_challenge,
                                        tunnel->sent_challenge_len,
                                        tunnel->shared_secret,
                                        tunnel->shared_secret_len,
                                        message->challenge_response,
                                        message->challenge_response_len))
            {
              /* Authentication failed. */
              if (message->challenge_response)
                SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication failed"));
              else
                SSH_DEBUG(SSH_D_NICETOKNOW, ("No response for challenge"));

              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED, 0,
                                  NULL, 0);
              SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);

              ssh_l2tp_send(l2tp, NULL, tunnel, NULL,
                            SSH_L2TP_CTRL_MSG_STOPCCN);

              /* Message handled. */
              ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

              /* Clean up. */
              SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);
              return SSH_FSM_CONTINUE;
            }

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication ok"));
        }

      /* Message handled.  Move to the established state. */
      ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

      ssh_l2tp_zlb(l2tp, tunnel);

      /* The tunnel is up. */
      tunnel->established = 1;

      /* Let's notify user. */
      if (l2tp->tunnel_status_cb)
        (*l2tp->tunnel_status_cb)(&tunnel->info,
                                  SSH_L2TP_TUNNEL_OPENED,
                                  l2tp->callback_context);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_established);
      return SSH_FSM_CONTINUE;
    }

  if (message->type != SSH_L2TP_CTRL_MSG_STOPCCN)
    {
      /* Send StopCCN. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_FSM_ERROR, 0, NULL, 0);
      SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);
      ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);
    }

  /* ACK everything. */
  ssh_l2tp_zlb(l2tp, tunnel);

  /* Copy possible status and error codes. */
  if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN
      || message->type == SSH_L2TP_CTRL_MSG_CDN)
    SSH_L2TP_COPY_STATUS(&tunnel->info, message);

  /* Message handled. */
  ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

  /* Clean up */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}
