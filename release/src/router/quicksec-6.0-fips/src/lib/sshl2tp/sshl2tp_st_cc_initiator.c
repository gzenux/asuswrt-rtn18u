/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Control connection establishment, initiator.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStCcInitiator"

/******************************** FSM states ********************************/

#define SSH_L2TP_DATA           \
  SshL2tp l2tp = fsm_context;   \
  SshL2tpTunnel tunnel = thread_context


SSH_FSM_STEP(ssh_l2tp_fsm_cc_initiator_idle)
{
  SSH_L2TP_DATA;

  /* Send SCCRQ. */
  ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_SCCRQ);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_cc_initiator_wait_ctl_reply);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_cc_initiator_wait_ctl_reply)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (tunnel->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(tunnel->message_queue_cond);

  message = ssh_l2tp_message(&tunnel->message_queue);

  /* Assign the remote peer's tunnel ID and possible changed UDP port.
     We do this before we checking message type or authentication.
     This way we get correct values to our possible error message. */

  tunnel->info.remote_id = message->assigned_tunnel_id;

  if (tunnel->remote_port != message->remote_port)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Remote peer %@ floated its port from %d to %d",
                 ssh_ipaddr_render, &message->remote_addr,
                 (int) tunnel->remote_port, (int) message->remote_port));

      /* Set the updated remote port. */
      tunnel->remote_port = message->remote_port;



      ssh_snprintf(ssh_sstr(tunnel->info.remote_port), 12, "%d",
                   (int) tunnel->remote_port);
    }

  if (message->type == SSH_L2TP_CTRL_MSG_SCCRP)
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

              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED,
                                  0, NULL, 0);
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

      /* Update our tunnel. */
      if (message->receive_window_size)
        {
          tunnel->info.send_window_size = message->receive_window_size;
          tunnel->info.sstresh = message->receive_window_size;
        }
      /* Tunnel attributes. */
      ssh_l2tp_tunnel_attributes_steal(&tunnel->info.attributes,
                                       &message->tunnel_attributes);

      /* Now we know the remote ID so we can put this tunnel to the
         second bag. */
      ssh_adt_insert(l2tp->tunnels_addr_port_id, tunnel);

      /* Steal the challenge from the message. */

      tunnel->received_challenge = message->challenge;
      tunnel->received_challenge_len = message->challenge_len;

      message->challenge = NULL;
      message->challenge_len = 0;

      /* Message handled. */
      ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

      /* The tunnel is up. */
      tunnel->established = 1;

      /* Notify waiting sessions. */
      ssh_fsm_condition_broadcast(l2tp->fsm, tunnel->condition);

      /* Send SCCCN. */
      ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_SCCCN);

      /* Let's notify user. */
      if (l2tp->tunnel_status_cb)
        (*l2tp->tunnel_status_cb)(&tunnel->info,
                                  SSH_L2TP_TUNNEL_OPENED,
                                  l2tp->callback_context);

      /* Move to the established state. */
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

  /* Copy status and error codes. */
  if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN
      || message->type == SSH_L2TP_CTRL_MSG_CDN)
    SSH_L2TP_COPY_STATUS(&tunnel->info, message);

  /* Message handled. */
  ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

  /* Clean up */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}
