/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Reliable transport level.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpTransport"


/***************************** Sending messages *****************************/

/* Send some unsent packets from the send window of the tunnel
   `tunnel'.  This reschedules the retransmit timeout if needed. */
static void ssh_l2tp_send_packets(SshL2tp l2tp, SshL2tpTunnel tunnel);

/* Retransmit all unacknowledged packets. */
static void
ssh_l2tp_retransmit_timer(void *context)
{
  SshL2tpTunnel tunnel = (SshL2tpTunnel) context;
  SshL2tpPacket packet;
  SshUInt32 packets_in_window = 0;

  /* Update tunnel outage statistics. */
  tunnel->outage_secs += tunnel->info.retransmit_timer;
  if (tunnel->outage_secs >= tunnel->l2tp->params.max_tunnel_outage)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destroying tunnel ID %lu due to no connectivity to its peer "
                 "within %d seconds",
                 (unsigned long) tunnel->info.local_id,
                 (int) tunnel->outage_secs));
      if (tunnel->destroyed || tunnel->on_destroy_list)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID %d already destroyed",
                                       tunnel->info.local_id));
          return;
        }

      tunnel->on_destroy_list = 1;
      ssh_adt_insert_to(tunnel->l2tp->tunnel_destroy_list, SSH_ADT_END,
                        tunnel);

      ssh_fsm_continue(tunnel->l2tp->transport_thread);
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Retransmit timer: "
             "sstresh=%d, cwnd=%d, ack_count=%d, timeout=%d",
             (int) tunnel->info.sstresh, (int) tunnel->info.cwnd,
             (int) tunnel->ack_count, (int) tunnel->info.retransmit_timer));

  /* Handle slow start and congestion avoidance. */
  tunnel->info.sstresh = (tunnel->info.cwnd + 1) / 2;
  tunnel->info.cwnd = 1;
  tunnel->ack_count = 0;

  /* Clear sent flags.  */
  for (packet = tunnel->send_window_head; packet; packet = packet->next)
    {
      packet->sent = FALSE;
      packets_in_window++;
    }

  /* Increase timeout. */
  tunnel->info.retransmit_timer *= 2;
  if (tunnel->info.retransmit_timer
      > tunnel->l2tp->params.max_retransmit_timer)
    tunnel->info.retransmit_timer = tunnel->l2tp->params.max_retransmit_timer;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("               => "
             "sstresh=%d, cwnd=%d, ack_count=%d, timeout=%d, #packets=%u",
             (int) tunnel->info.sstresh, (int) tunnel->info.cwnd,
             (int) tunnel->ack_count, (int) tunnel->info.retransmit_timer,
             (int) packets_in_window));

  /* And do retransmit. */
  ssh_l2tp_send_packets(tunnel->l2tp, tunnel);
}

/* Send a Hello message to detect any media interruption. */
static void
ssh_l2tp_hello_timer(void *context)
{
  SshL2tpTunnel tunnel = (SshL2tpTunnel) context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Hello timer: Tunnel ID %d",
                               tunnel->info.local_id));

  ssh_l2tp_send(tunnel->l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_HELLO);
}


static void
ssh_l2tp_send_packets(SshL2tp l2tp, SshL2tpTunnel tunnel)
{
  SshUInt32 i;
  SshL2tpPacket packet;
  Boolean sent = FALSE;

  /* Flush some messages if we can. */
  for (i = 0, packet = tunnel->send_window_head;
       i < tunnel->info.cwnd && packet;
       i++, packet = packet->next)
    {
      if (packet->sent)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Skipping sent packet ns=%d", packet->sequence_number));
          continue;
        }

      /* Send this message. */

      /* Set the ACK value to outgoing packets. */
      SSH_PUT_16BIT(packet->data + 10, tunnel->seq_nr);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Sending packet: ns=%d, nr=%d",
                 packet->sequence_number, tunnel->seq_nr));

      sent = TRUE;
      packet->sent = 1;

      ssh_udp_send(tunnel->server->listener,
                   tunnel->info.remote_addr, tunnel->info.remote_port,
                   packet->data, packet->data_len);
    }

  if (sent)
    {
      ssh_cancel_timeouts(ssh_l2tp_retransmit_timer, tunnel);
      ssh_xregister_timeout(tunnel->info.retransmit_timer, 0,
                           ssh_l2tp_retransmit_timer, tunnel);
    }
}


void
ssh_l2tp_send(SshL2tp l2tp, SshL2tpServer server,
              SshL2tpTunnel tunnel, SshL2tpSession session,
              SshL2tpControlMsgType message_type)
{
  Boolean result;
  size_t datagram_len;

  /* Encode packet. */
  result = ssh_l2tp_encode_packet(l2tp, tunnel, session,
                                  l2tp->datagram, sizeof(l2tp->datagram),
                                  &datagram_len, message_type);

  if (result == FALSE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Packet encoding failed"));
      return;
    }

  if (tunnel)
    {
      SshL2tpPacket packet;

      packet = ssh_calloc(1, sizeof(*packet));
      if (packet == NULL)
        {
        out_of_memory:
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate outbound packet"));
          return;
        }

      packet->data_len = datagram_len;
      packet->data = ssh_memdup(l2tp->datagram, datagram_len);
      if (packet->data == NULL)
        {
          ssh_free(packet);
          goto out_of_memory;
        }

      packet->sequence_number = tunnel->seq_ns++;
      SSH_PUT_16BIT(packet->data + 8, packet->sequence_number);

      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("Final %s (%d) packet (before setting Nr):",
                         ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                               message_type),
                         message_type),
                        packet->data, packet->data_len);

      /* Queue it. */
      if (tunnel->send_window_tail)
        {
          tunnel->send_window_tail->next = packet;
          tunnel->send_window_tail = packet;
        }
      else
        {
          tunnel->send_window_head = packet;
          tunnel->send_window_tail = packet;
        }

      /* And flush queue if needed. */
      ssh_l2tp_send_packets(l2tp, tunnel);
    }
  else
    {
      SSH_ASSERT(server != NULL);

      /* No tunnel.  This must be an error message.  Let's just send
         this message to the datagram's source L2TP server. */

      SSH_ASSERT(l2tp->datagram_addr && l2tp->datagram_port);
      SSH_ASSERT(l2tp->message != NULL);

      /* Set sequence numbers from the incoming message. */
      SSH_PUT_16BIT(l2tp->datagram + 8, l2tp->message->nr);
      SSH_PUT_16BIT(l2tp->datagram + 10, l2tp->message->ns + 1);

      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                        ("Final %s (%d) packet:",
                         ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                               message_type),
                         message_type),
                        l2tp->datagram, datagram_len);

      ssh_udp_send(server->listener,
                   l2tp->datagram_addr, l2tp->datagram_port,
                   l2tp->datagram, datagram_len);
    }
}


void
ssh_l2tp_send_data(SshL2tp l2tp, SshL2tpSession session,
                   const unsigned char *data, size_t data_len)
{
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("Final data packet:"),
                    data, data_len);
  ssh_udp_send(session->tunnel->server->listener,
               session->tunnel->info.remote_addr,
               session->tunnel->info.remote_port,
               data, data_len);
}


void
ssh_l2tp_zlb(SshL2tp l2tp, SshL2tpTunnel tunnel)
{
  size_t datagram_len;

  SSH_ASSERT(tunnel != NULL);

  if (tunnel->send_window_head != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Send window is not empty: ZLB not sent"));
      return;
    }

  (void) ssh_l2tp_encode_packet(l2tp, tunnel, NULL,
                                l2tp->datagram, sizeof(l2tp->datagram),
                                &datagram_len, SSH_L2TP_CTRL_MSG_ZLB);

  SSH_PUT_16BIT(l2tp->datagram + 8, tunnel->seq_ns);
  SSH_PUT_16BIT(l2tp->datagram + 10, tunnel->seq_nr);

  /* Send packet. */
  ssh_udp_send(tunnel->server->listener,
               tunnel->info.remote_addr, tunnel->info.remote_port,
               l2tp->datagram, datagram_len);
}


static void
ssh_l2tp_ack(SshL2tp l2tp, SshL2tpTunnel tunnel, SshUInt16 ack)
{
  SshL2tpPacket packet;
  SshL2tpPacket packet_next;
  SshL2tpPacket *packetp;
  SshUInt32 num_packets = 0;

  /* Remove all ACKed packets from the send window. */
  for (packetp = &tunnel->send_window_head, packet = tunnel->send_window_head;
       packet;
       packet = packet_next)
    {
      packet_next = packet->next;

      if (SSH_L2TP_SEQ_LT(packet->sequence_number, ack))
        {
          /* This is ACKed. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Removing ACKed message %d (ACK %d)",
                     packet->sequence_number, ack));

          *packetp = packet_next;

          ssh_free(packet->data);
          ssh_free(packet);

          /* Update slow start and congestion avoidance. */
          if (tunnel->info.cwnd >= tunnel->info.sstresh)
            {
              /* Congestion avoidance. */
              tunnel->ack_count++;
              if (tunnel->ack_count >= tunnel->info.cwnd)
                {
                  tunnel->info.cwnd++;
                  tunnel->ack_count = 0;
                }
            }
          else
            {
              /* Slow start. */
              tunnel->info.cwnd++;
            }

          /* And limit cwnd to the send window size. */
          if (tunnel->info.cwnd > tunnel->info.send_window_size)
            tunnel->info.cwnd = tunnel->info.send_window_size;
        }
      else
        {
          /* This was not ACKed.  Clear sent flag so this gets
             retransmitted. */
          packet->sent = FALSE;
          num_packets++;
          packetp = &packet->next;
        }
    }
  if (tunnel->send_window_head == NULL)
    tunnel->send_window_tail = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ACK: sstresh=%d, cwnd=%d, ack_count=%d, timeout=%d, #packets=%u",
             (int) tunnel->info.sstresh, (int) tunnel->info.cwnd,
             (int) tunnel->ack_count, (int) tunnel->info.retransmit_timer,
             (int) num_packets));

  /* Cancel retransmit timeout. */
  ssh_cancel_timeouts(ssh_l2tp_retransmit_timer, tunnel);
  tunnel->info.retransmit_timer = 1;

  /* Cancel HELLO timeout. */
  ssh_cancel_timeouts(ssh_l2tp_hello_timer, tunnel);

  /* Is the send window empty? */
  if (tunnel->send_window_head == NULL
      && l2tp->params.hello_timer != SSH_L2TP_HELLO_TIMER_INFINITE
      && !tunnel->destroyed)
    /* Order a timeout to send HELLO. */
    ssh_xregister_timeout(l2tp->params.hello_timer, 0,
                         ssh_l2tp_hello_timer, tunnel);

  /* And send more messages if needed. */
  ssh_l2tp_send_packets(l2tp, tunnel);
}


/**************************** Receiving messages ****************************/

/* Dispatch control message `message' to a tunnel or session thread.
   The function returns TRUE if the message was passed forward or
   FALSE otherwise.  If the function returns FALSE, the caller must
   free the message `message'. */
static Boolean
ssh_l2tp_dispatch_control_message(SshL2tp l2tp, SshFSMThread thread,
                                  SshL2tpControlMessage message)
{
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel = NULL;
  SshL2tpSessionStruct session_struct;
  SshL2tpSession session = NULL;
  SshADTHandle h;

  /* First, check if this is a message to an old tunnel.  If so, it
     gives us the control channel. */

  if (message->tunnel_id)
    {
      /* Message to an existing tunnel.  Let's look ip up. */
      tunnel_struct.info.local_id = message->tunnel_id;
      h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
      if (h == SSH_ADT_INVALID)
        {
          /* We do not know this tunnel. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Received %s for unknown Tunnel ID %d",
                     message->avp_count ? "control message" : "ZLB",
                     message->tunnel_id));

          /* Send StopCCN.  The send routine can handle ZLBs, StopCCN
             input messages, and unknown message types. */
          SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                              SSH_L2TP_ERROR_NO_CONTROL_CONNECTION, NULL, 0);
          goto error_stopccn;
        }

      /* Found it. */
      tunnel = ssh_adt_get(l2tp->tunnels_id, h);
    }
  else if (message->assigned_tunnel_id)
    {
      /* We know the remote address, port, and its assigned ID.  Let's
         see if we have seen this before. */

      tunnel_struct.remote_addr = message->remote_addr;
      tunnel_struct.remote_port = message->remote_port;
      tunnel_struct.info.remote_id = message->assigned_tunnel_id;

      h = ssh_adt_get_handle_to_equal(l2tp->tunnels_addr_port_id,
                                      &tunnel_struct);
      if (h == SSH_ADT_INVALID)
        {
          /* Our last resort.  Let's see if we have initiated a
             simultaenous tunnel establishment with the remote peer.*/
          /* TODO: detect simultaneous tunnel establishment.  Now we
             just fallthrough and check if this is a valid tunnel
             establishment start. */
        }
      else
        {
          /* Found it. */
          tunnel = ssh_adt_get(l2tp->tunnels_addr_port_id, h);
        }
    }

  if (tunnel)
    {
      /* Found an existing tunnel. */

      /* Ack everything seen so far. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("The remote end %sACKs %d",
                 message->avp_count ? "" : "ZLB ",
                 message->nr));
      ssh_l2tp_ack(l2tp, tunnel, message->nr);

      /* Let's check the sequence numbers. */
      if (message->ns != tunnel->seq_nr)
        {
          /* It was not the expected one. */
          if (SSH_L2TP_SEQ_LT(message->ns, tunnel->seq_nr))
            /* This is a retransmission. */
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Retransmission of message %d, nr=%d",
                       message->ns, tunnel->seq_nr));
          else
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Got a future packet: %d vs expected %d",
                       message->ns, tunnel->seq_nr));

          /* Send ZLB ACK if no messages are in the output window. */
          ssh_l2tp_zlb(l2tp, tunnel);

          return FALSE;
        }

      /* This is a new message. */

      if (message->avp_count == 0)
        /* ZLB ACK from the other end.  All done here. */
        return FALSE;

      /* Update the next expected sequence number for non ZLB packets. */
      tunnel->seq_nr = message->ns + 1;

      if (tunnel->on_destroy_list || tunnel->destroyed)
        /* The tunnel is destroyed.  The tunnel entry is here just to
           let us finish our transport task.  We are done with this
           message. */
        return FALSE;

      /* Did we have any errors in the message parsing? */
      if (l2tp->error_code)
        {
          /* Yes, we did.  Let's tear down this tunnel and send a
             StopCCN.  The error code is already in `l2tp'. */
        tear_down_tunnel:
          tunnel->on_destroy_list = 1;
          tunnel->stopccn_sent = 1;

          ssh_adt_insert_to(l2tp->tunnel_close_list, SSH_ADT_END, tunnel);

          /* Do not send StopCCN in response to StopCCN. */
          if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN)
            ssh_l2tp_zlb(l2tp, tunnel);
          else
            ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);

          /* Let our caller to free this message. */
          return FALSE;
        }

      /* Where is the message directed to? */
      switch (message->type)
        {
        case SSH_L2TP_CTRL_MSG_SCCRQ:
        case SSH_L2TP_CTRL_MSG_SCCRP:
        case SSH_L2TP_CTRL_MSG_SCCCN:
        case SSH_L2TP_CTRL_MSG_STOPCCN:
          /* To the control channel. */
          ssh_l2tp_message_queue(&tunnel->message_queue, message);
          SSH_FSM_CONDITION_SIGNAL(tunnel->message_queue_cond);
          break;

        case SSH_L2TP_CTRL_MSG_HELLO:
          /* The Session ID in a HELLO message MUST be 0. */
          if (message->session_id != 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("HELLO message for Session ID %d",
                                        message->session_id));
              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                                  SSH_L2TP_ERROR_INVALID_VALUE, NULL, 0);




              ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                           sizeof(l2tp->error_message_buf),
                           "HELLO message for Session ID %d",
                           message->session_id);
              l2tp->error_message = l2tp->error_message_buf;
              l2tp->error_message_len =
                ssh_ustrlen(l2tp->error_message_buf);

              goto tear_down_tunnel;
            }

          /* We received a HELLO message.  Let's ZLB ACK it if we do
             not have any messages pending in our output queue. */
          ssh_l2tp_zlb(l2tp, tunnel);

          /* And we'r done.  We did not pass the message forward so we
             let the caller to recycle the message. */
          return FALSE;
          break;

        case SSH_L2TP_CTRL_MSG_OCRQ:
          /* To a new session where we are the LAC. */
          session = ssh_l2tp_session_create(l2tp, tunnel, message, TRUE,
                                            FALSE);
          if (session == NULL)
            /* The ssh_l2tp_session_create has already formatted an
               error message. */
            goto error_cdn;

          /* Queue message to the thread. */
          ssh_l2tp_message_queue(&session->message_queue, message);
          break;

        case SSH_L2TP_CTRL_MSG_ICRQ:
          /* To a new session where we are the LNS. */
          session = ssh_l2tp_session_create(l2tp, tunnel, message, FALSE,
                                            FALSE);
          if (session == NULL)
            goto error_cdn;

          /* Queue message to the thread. */
          ssh_l2tp_message_queue(&session->message_queue, message);
          break;

        case SSH_L2TP_CTRL_MSG_OCRP:
        case SSH_L2TP_CTRL_MSG_OCCN:
        case SSH_L2TP_CTRL_MSG_ICRP:
        case SSH_L2TP_CTRL_MSG_ICCN:
        case SSH_L2TP_CTRL_MSG_CDN:
        case SSH_L2TP_CTRL_MSG_WEN:
        case SSH_L2TP_CTRL_MSG_SLI:
          /* To an old session. */

          /* Do we know this session. */
          session_struct.tunnel = tunnel;
          session_struct.info.local_id = message->session_id;
          h = ssh_adt_get_handle_to_equal(l2tp->sessions, &session_struct);
          if (h == SSH_ADT_INVALID)
            {
              /* Unknown session. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Received control message for unknown Session ID %d",
                         message->session_id));

              /* Send CDN. */
              SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ERROR,
                                  SSH_L2TP_ERROR_INVALID_SESSION_ID, NULL, 0);
              goto error_cdn;
            }

          /* Found it. */
          session = ssh_adt_get(l2tp->sessions, h);

          if (session->destroyed)
            /* The session is destroyed.  We are done with this
               message. */
            return FALSE;

          /* Handle WAN Error Notify (WEN). */
          if (message->type == SSH_L2TP_CTRL_MSG_WEN)
            {
              if (session->info.call_errors == NULL)
                {
                  session->info.call_errors
                    = ssh_malloc(sizeof(*session->info.call_errors));
                  if (session->info.call_errors == NULL)
                    {
                      SSH_DEBUG(SSH_D_ERROR,
                                ("Could not allocate Call Errors structure: "
                                 "message ignored"));
                      return FALSE;
                    }
                }
              /* Copy statistics. */
              memcpy(session->info.call_errors, &message->call_errors,
                     sizeof(message->call_errors));

              /* Notify user. */
              if (session->initiator_status_cb)
                (*session->initiator_status_cb)(
                                        &session->info,
                                        SSH_L2TP_SESSION_WAN_ERROR_NOTIFY,
                                        session->initiator_status_cb_context);
              else if (l2tp->session_status_cb)
                (*l2tp->session_status_cb)(&session->info,
                                           SSH_L2TP_SESSION_WAN_ERROR_NOTIFY,
                                           l2tp->callback_context);

              /* All done.  And we did not consume the message. */
              return FALSE;
            }

          /* Handle Set Link Info (SLI). */
          if (message->type == SSH_L2TP_CTRL_MSG_SLI)
            {
              /* Copy link info. */
              memcpy(&session->info.accm, &message->accm,
                     sizeof(message->accm));

              /* Notify user. */
              if (session->initiator_status_cb)
                (*session->initiator_status_cb)(
                                        &session->info,
                                        SSH_L2TP_SESSION_SET_LINK_INFO,
                                        session->initiator_status_cb_context);
              else if (l2tp->session_status_cb)
                (*l2tp->session_status_cb)(&session->info,
                                           SSH_L2TP_SESSION_SET_LINK_INFO,
                                           l2tp->callback_context);

              /* All done.  And we did not consume the message. */
              return FALSE;
            }

          /* It is a normal control message for our session thread. */
          ssh_l2tp_message_queue(&session->message_queue, message);
          SSH_FSM_CONDITION_SIGNAL(session->message_queue_cond);
          break;

        default:
          /* Got an unknown (or reserved) message.  Let's tear down
             this tunnel and send StopCCN. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Got message %s",
                     ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                           message->type)));
          SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                              SSH_L2TP_ERROR_INVALID_VALUE, NULL, 0);

          /* Format error message. */



          ssh_snprintf(ssh_sstr(l2tp->error_message_buf),
                       sizeof(l2tp->error_message_buf),
                       "Unknown control message %d", message->type);
          l2tp->error_message = l2tp->error_message_buf;
          l2tp->error_message_len =
            ssh_ustrlen(l2tp->error_message_buf);

          goto tear_down_tunnel;
          break;
        }

      /* Message sent to an existing tunnel / session. */
      return TRUE;
    }

  /* We did not find a tunnel. */

  /* Did we have any errors in the message parsing? */
  if (l2tp->error_code)
    /* Yes we did.  Let's send a StopCCN and we have handled this
       bogus message.  The error message is already in `l2tp'. */
    goto error_stopccn;

  /* Is this a valid control connection establishment start? */
  switch (message->type)
    {
    case SSH_L2TP_CTRL_MSG_SCCRQ:
      /* Ok, just fine. */
      break;

    case SSH_L2TP_CTRL_MSG_SCCRP:
      /* Send StopCCN and clean up. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_FSM_ERROR, 0, NULL, 0);
      goto error_stopccn;
      break;

    case SSH_L2TP_CTRL_MSG_SCCCN:
    case SSH_L2TP_CTRL_MSG_STOPCCN:
      /* Clean up, meaning that we do nothing here. */
      return FALSE;
      break;

    default:
      /* The other peer is really messed up. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("Received control message %s for non-existent tunnel",
                 ssh_find_keyword_name(ssh_l2tp_control_msg_types,
                                       message->type)));
      /* Cleanup. */
      return FALSE;
      break;
    }

  /* Can we start any more control connection negotiations? */
  if (l2tp->destroyed)
    {
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_SHUT_DOWN, 0, NULL, 0);
      goto error_stopccn;
    }

  /* Check the maximum number of L2TP tunnels. */
  if (ssh_adt_num_objects(l2tp->tunnels_id) >= l2tp->params.max_tunnels)
    {
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                          SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES, NULL, 0);
      goto error_stopccn;
    }

  /* Allocate a new L2TP tunnel. */

  SSH_ASSERT(message->server != NULL);

  tunnel = ssh_l2tp_tunnel_create(message->server, FALSE);
  if (tunnel == NULL)
    goto error_stopccn_memory;

  /* Initialize it from the message. */

  message->server->refcount++;
  tunnel->server = message->server;

  /* Set remote end's tunnel ID. */
  tunnel->info.remote_id = message->assigned_tunnel_id;

  tunnel->remote_addr = message->remote_addr;
  tunnel->remote_port = message->remote_port;

  tunnel->info.remote_addr = ssh_strdup(l2tp->datagram_addr);
  if (tunnel->info.remote_addr == NULL)
    goto error_stopccn_memory;

  SSH_ASSERT(ssh_ustrlen(l2tp->datagram_port) < 12);
  ssh_ustrcpy(tunnel->info.remote_port, l2tp->datagram_port);

  tunnel->info.local_addr = ssh_l2tp_tunnel_local_addr(tunnel,
                                                       l2tp->datagram_addr);
  if (tunnel->info.local_addr == NULL)
    goto error_stopccn_memory;




  ssh_snprintf(ssh_sstr(tunnel->info.local_port), 12,
               "%d", (int) tunnel->server->port);

  /* Sequence numbers. */
  tunnel->seq_nr = message->ns + 1;

  if (message->receive_window_size)
    tunnel->info.send_window_size = message->receive_window_size;

  /* Put the message to the message queue. */
  ssh_l2tp_message_queue(&tunnel->message_queue, message);

  if (tunnel->info.remote_id)
    /* We know (and have set) the remote end identification for this
       tunnel so we can put this tunnel to this bag.  This can be
       unknown if the `Assigned Tunnel ID' AVP was hidden. */
    ssh_adt_insert(l2tp->tunnels_addr_port_id, tunnel);

  /* Message passed to a new thread. */
  return TRUE;


  /* Error handling. */

 error_stopccn_memory:

  SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                      SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                      ssh_sstr("Out of memory"), 13);

 error_stopccn:

  ssh_l2tp_tunnel_free(tunnel);

  if (message->avp_count == 0)
    {
      /* Do not ACK ZLB ACKs. */
    }
  else if (message->type == 0)
    {
      /* Ignore unknown message types. */
    }
  else if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN)
    {
      /* ZLB ACK StopCCN messages. */
      if (tunnel)
        ssh_l2tp_zlb(l2tp, tunnel);
    }
  else
    {
      /* Send StopCCN. */
      ssh_l2tp_send(l2tp, message->server, NULL, NULL,
                    SSH_L2TP_CTRL_MSG_STOPCCN);
    }

  /* We did not pass the message to any thread.  We let our caller to
     free the message. */
  return FALSE;

 error_cdn:

  ssh_l2tp_send(l2tp, NULL, tunnel, session, SSH_L2TP_CTRL_MSG_CDN);

  /* We did not dispatch the message. */
  return FALSE;
}

/* Dispatch data message `message' with payload data `data',
   `data_len' to the data stream of the corresponding L2TP session. */
static Boolean
ssh_l2tp_dispatch_data_message(SshL2tp l2tp, SshL2tpControlMessage message,
                               unsigned char *data, size_t data_len)
{
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel;
  SshL2tpSessionStruct session_struct;
  SshL2tpSession session;
  SshADTHandle h;

  /* We must know this session. */
  if (message->tunnel_id == 0 || message->session_id == 0)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Data message for an invalid Session ID %d of Tunnel ID %d",
                 message->session_id, message->tunnel_id));
      /* Send StopCCN. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                          SSH_L2TP_ERROR_INVALID_VALUE, NULL, 0);
      ssh_l2tp_send(l2tp, message->server, NULL, NULL,
                    SSH_L2TP_CTRL_MSG_STOPCCN);

      /* We did not consume the message. */
      return FALSE;
    }

  tunnel_struct.info.local_id = message->tunnel_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Data message for an unknown Tunnel ID %d",
                                message->tunnel_id));
      /* Send StopCCN. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                          SSH_L2TP_ERROR_NO_CONTROL_CONNECTION, NULL, 0);
      ssh_l2tp_send(l2tp, message->server, NULL, NULL,
                    SSH_L2TP_CTRL_MSG_STOPCCN);

      return FALSE;
    }
  tunnel = ssh_adt_get(l2tp->tunnels_id, h);

  session_struct.tunnel = tunnel;
  session_struct.info.local_id = message->session_id;
  h = ssh_adt_get_handle_to_equal(l2tp->sessions, &session_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Data message for an unknown Session ID %d of Tunnel ID %d",
                 message->session_id, message->tunnel_id));
      /* Send CDN. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ERROR,
                          SSH_L2TP_ERROR_INVALID_SESSION_ID, NULL, 0);
      ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_CDN);

      return FALSE;
    }

  session = ssh_adt_get(l2tp->sessions, h);

  /* Check sequence numbers. */
  /* TODO: sequence numbers */

  /* Notify new data for the user data stream. */
  if (session->info.data_cb)
    (*session->info.data_cb)(&session->info, data, data_len);

  /* All done.  And we did not consume the message. */
  return FALSE;
}


/**************************** Tunnel termination ****************************/

static void
ssh_l2tp_tunnel_terminate_timer(void *context)
{
  SshL2tpTunnel tunnel = (SshL2tpTunnel) context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Terminating tunnel ID %d",
                               tunnel->info.local_id));

  ssh_adt_detach_object(tunnel->l2tp->tunnel_retransmission_wait_list, tunnel);
  ssh_adt_insert_to(tunnel->l2tp->tunnel_reclaim_list, SSH_ADT_END, tunnel);
  tunnel->terminated = 1;

  /* Notify transport thread. */
  ssh_fsm_continue(tunnel->l2tp->transport_thread);
}


void
ssh_l2tp_tunnel_terminated(SshL2tpTunnel tunnel)
{
  SSH_ASSERT(tunnel->destroyed);
  SSH_ASSERT(!tunnel->terminated);

  /* Cancel HELLO timer. */
  ssh_cancel_timeouts(ssh_l2tp_hello_timer, tunnel);

  if (tunnel->fast_shutdown)
    {
      /* Just put it to reclaim list. */
      ssh_adt_insert_to(tunnel->l2tp->tunnel_reclaim_list, SSH_ADT_END,
                        tunnel);
      tunnel->terminated = 1;

      /* Notify transport thread. */
      ssh_fsm_continue(tunnel->l2tp->transport_thread);
    }
  else
    {
      SshUInt32 timeout;

      timeout = tunnel->info.retransmit_timer + 1;
      if (timeout < SSH_L2TP_RECOMMENDED_RETRANSMISSION_CYCLE)
        timeout = SSH_L2TP_RECOMMENDED_RETRANSMISSION_CYCLE;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing tunnel ID %d after %d seconds",
                                   tunnel->info.local_id, (int) timeout));

      /* We must wait full retransmission cycle.  Actually, only the
         receiver of the StopCCN should wait because its ZLB ACK could
         be lost and the initiator of the tunnel termination can
         retransmit the StopCCN.  The initiator of the tunnel
         termination must wait for the full retransmission cycle or
         until it receives ZLB ACK for the StopCCN.  Anyhow, we wait
         for the full retransmission cycle in either case. */
      ssh_adt_insert_to(tunnel->l2tp->tunnel_retransmission_wait_list,
                        SSH_ADT_END, tunnel);
      ssh_xregister_timeout(timeout, 0, ssh_l2tp_tunnel_terminate_timer,
                           tunnel);
    }
}


void
ssh_l2tp_flush_retransmission_wait_list(SshL2tp l2tp)
{
  while (ssh_adt_num_objects(l2tp->tunnel_retransmission_wait_list))
    {
      SshL2tpTunnel tunnel;
      SshADTHandle h;

      h = ssh_adt_get_handle_to_location(l2tp->tunnel_retransmission_wait_list,
                                         SSH_ADT_BEGINNING);
      SSH_ASSERT(h != SSH_ADT_INVALID);

      tunnel = ssh_adt_get(l2tp->tunnel_retransmission_wait_list, h);
      SSH_ASSERT(tunnel->destroyed);
      SSH_ASSERT(!tunnel->terminated);

      /* Cancel terminate timer and call it by hand. */
      ssh_cancel_timeouts(ssh_l2tp_tunnel_terminate_timer, tunnel);
      ssh_l2tp_tunnel_terminate_timer(tunnel);
    }
}


/************************* Transport thread states **************************/

static void
ssh_l2tp_destroy_timeout(void *context)
{
  SshL2tp l2tp = (SshL2tp) context;
  SshL2tpFinishedCB callback = l2tp->destroy_callback;
  void *callback_context = l2tp->destroy_callback_context;

  ssh_l2tp_free(l2tp);

  if (callback)
    (*callback)(callback_context);
}


SSH_FSM_STEP(ssh_l2tp_fsm_tr_wait)
{
  SshADTHandle h;
  SshL2tp l2tp = fsm_context;

  /* Process all possible events at leat once. */
  do
    {
      /* Check session close requests. */
      while (ssh_adt_num_objects(l2tp->session_close_list))
        {
          SshL2tpSession session;

          h = ssh_adt_get_handle_to_location(l2tp->session_close_list,
                                             SSH_ADT_BEGINNING);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          session = ssh_adt_detach(l2tp->session_close_list, h);
          SSH_ASSERT(session->on_destroy_list);
          session->on_destroy_list = 0;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Closing session ID %d",
                                       session->info.local_id));

          /* Send an exception. */
          ssh_fsm_throw(thread, session->thread,
                        SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN);
        }

      /* Check session destroy requests. */
      while (ssh_adt_num_objects(l2tp->session_destroy_list))
        {
          SshL2tpSession session;

          h = ssh_adt_get_handle_to_location(l2tp->session_destroy_list,
                                             SSH_ADT_BEGINNING);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          session = ssh_adt_detach(l2tp->session_destroy_list, h);
          SSH_ASSERT(session->on_destroy_list);
          session->on_destroy_list = 0;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying session ID %d",
                                       session->info.local_id));

          /* Send an exception. */
          ssh_fsm_throw(thread, session->thread,
                        SSH_L2TP_THREAD_EXCEPTION_DESTROY);
        }

      /* Check tunnel close requests. */
      while (ssh_adt_num_objects(l2tp->tunnel_close_list))
        {
          SshL2tpTunnel tunnel;
          SshL2tpThreadException exception;

          h = ssh_adt_get_handle_to_location(l2tp->tunnel_close_list,
                                             SSH_ADT_BEGINNING);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          tunnel = ssh_adt_detach(l2tp->tunnel_close_list, h);
          SSH_ASSERT(tunnel->on_destroy_list);
          tunnel->on_destroy_list = 0;

          if (tunnel->stopccn_sent)
            exception = SSH_L2TP_THREAD_EXCEPTION_CLEAN_UP;
          else
            exception = SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Closing tunnel ID %d",
                                       tunnel->info.local_id));

          /* Send an exception. */
          ssh_fsm_throw(thread, tunnel->thread, exception);
        }

      /* Check tunnel destroy requests. */
      while (ssh_adt_num_objects(l2tp->tunnel_destroy_list))
        {
          SshL2tpTunnel tunnel;

          h = ssh_adt_get_handle_to_location(l2tp->tunnel_destroy_list,
                                             SSH_ADT_BEGINNING);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          tunnel = ssh_adt_detach(l2tp->tunnel_destroy_list, h);
          SSH_ASSERT(tunnel->on_destroy_list);
          tunnel->on_destroy_list = 0;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying tunnel ID %d",
                                       tunnel->info.local_id));

          /* Send an exception. */
          ssh_fsm_throw(thread, tunnel->thread,
                        SSH_L2TP_THREAD_EXCEPTION_DESTROY);
        }

      /* Check tunnel reclaim requests. */
      while (ssh_adt_num_objects(l2tp->tunnel_reclaim_list))
        {
          SshL2tpTunnel tunnel;

          h = ssh_adt_get_handle_to_location(l2tp->tunnel_reclaim_list,
                                             SSH_ADT_BEGINNING);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          tunnel = ssh_adt_detach(l2tp->tunnel_reclaim_list, h);
          SSH_ASSERT(tunnel->terminated);

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing tunnel %d",
                                       tunnel->info.local_id));

          /* Cancel all timeouts from the tunnel. */
          ssh_cancel_timeouts(SSH_ALL_CALLBACKS, tunnel);

          /* Remove tunnel from ADT bags. */

          h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, tunnel);
          if (h != SSH_ADT_INVALID)
            ssh_adt_detach(l2tp->tunnels_id, h);

          h = ssh_adt_get_handle_to_equal(l2tp->tunnels_addr_port_id, tunnel);
          if (h != SSH_ADT_INVALID)
            ssh_adt_detach(l2tp->tunnels_addr_port_id, h);

          SSH_ASSERT(tunnel->thread == NULL);
          SSH_ASSERT(tunnel->operation_handle == NULL);

          SSH_ASSERT(tunnel->sessions == NULL);

          /* Flush send window. */
          while (tunnel->send_window_head)
            {
              SshL2tpPacket packet = tunnel->send_window_head;

              tunnel->send_window_head = packet->next;
              if (tunnel->send_window_head == NULL)
                tunnel->send_window_tail = NULL;

              ssh_free(packet->data);
              ssh_free(packet);
            }

          /* Flush message queue. */
          while (tunnel->message_queue.head)
            ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

          /* And finally, free the tunnel structure. */
          ssh_l2tp_tunnel_free(tunnel);
        }

      /* Are we terminated? */
      if (l2tp->destroyed
          && ssh_adt_num_objects(l2tp->tunnel_close_list) == 0
          && ssh_adt_num_objects(l2tp->tunnel_destroy_list) == 0
          && ssh_adt_num_objects(l2tp->tunnel_reclaim_list) == 0
          && ssh_adt_num_objects(l2tp->tunnels_id) == 0)
        {
          /* Yes we are. */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroyed L2TP server"));
          ssh_xregister_timeout(0, 0, ssh_l2tp_destroy_timeout, l2tp);

          /* Mark us NULL since we are dying when we return
             SSH_FSM_FINISH. */
          l2tp->transport_thread = NULL;

          return SSH_FSM_FINISH;
        }

      /* Process incoming messages. */
      while (ssh_adt_num_objects(l2tp->incoming_messages))
        {
          SshL2tpServer server;

          h = ssh_adt_enumerate_start(l2tp->incoming_messages);
          SSH_ASSERT(h != SSH_ADT_INVALID);

          server = ssh_adt_get(l2tp->incoming_messages, h);

          /* Read as many messages as possible. */
          while (1)
            {
              SshUdpError error;
              unsigned char remote_addr[128];
              unsigned char remote_port[64];
              size_t datagram_len;

              /* Do we have any messages left in our message pool? */
              if (l2tp->message_pool.head == NULL)
                SSH_FSM_CONDITION_WAIT(l2tp->message_pool_cond);

              /* Now we have at least one. */

              /* Read the datagram. */
              error = ssh_udp_read(server->listener,
                                   remote_addr, sizeof(remote_addr),
                                   remote_port, sizeof(remote_port),
                                   l2tp->datagram, sizeof(l2tp->datagram),
                                   &datagram_len);
              if (error == SSH_UDP_OK)
                {
                  size_t data_offset;
                  size_t data_len;

                  SSH_DEBUG(SSH_D_LOWOK, ("New packet from %s:%s: %d bytes",
                                          remote_addr, remote_port,
                                          datagram_len));

                  /* Take a message from the message pool and parse
                     the request to it. */
                  l2tp->message = ssh_l2tp_message_get(&l2tp->message_pool);

                  SSH_ASSERT(l2tp->message->avp_count == 0);

                  /* Clear error code and message. */
                  SSH_L2TP_CLEAR_STATUS(l2tp);

                  /* Store datagram's source address and port. */
                  l2tp->datagram_addr = remote_addr;
                  l2tp->datagram_port = remote_port;

                  /* Assign listener to message. */
                  l2tp->message->server = server;

                  if (ssh_l2tp_decode_packet(l2tp, l2tp->message, NULL,
                                             l2tp->datagram, datagram_len,
                                             remote_addr, remote_port,
                                             &data_offset, &data_len))
                    {
                      Boolean dispatch_result;

                      /* Dispatch decoded packet. */
                      if (l2tp->message->f_type)
                        {
                          /* Control message. */
                          dispatch_result
                            = ssh_l2tp_dispatch_control_message(
                                                l2tp,
                                                l2tp->transport_thread,
                                                l2tp->message);
                        }
                      else
                        {
                          /* Data message. */
                          dispatch_result
                            = ssh_l2tp_dispatch_data_message(
                                                l2tp,
                                                l2tp->message,
                                                l2tp->datagram + data_offset,
                                                data_len);
                        }

                      if (!dispatch_result)
                        {
                          /* The dispatch function did not handle the
                             message. */
                          ssh_l2tp_message_fields_free(l2tp->message);
                          ssh_l2tp_message_queue(&l2tp->message_pool,
                                                 l2tp->message);
                        }
                    }
                  else
                    {
                      /* Put the message back to the message pool. */
                      ssh_l2tp_message_fields_free(l2tp->message);
                      ssh_l2tp_message_queue(&l2tp->message_pool,
                                             l2tp->message);
                    }

                  /* And clear l2tp's pointers to stack variables. */
                  l2tp->datagram_addr = NULL;
                  l2tp->datagram_port = NULL;

                  l2tp->message = NULL;
                }
              else if (error == SSH_UDP_NO_DATA)
                {
                  break;
                }
              else
                {
                  SSH_DEBUG(SSH_D_ERROR, ("UDP read failed: %s",
                                          ssh_udp_error_string(error)));
                }
            }

          /* Read all messages from this listener. */
          ssh_adt_detach(l2tp->incoming_messages, h);

          /* Remove one reference from the server. */
          ssh_l2tp_server_stop(server);
        }

      /* Continue processing while there are some events left in
         queues. */
    }
  while (ssh_adt_num_objects(l2tp->session_close_list)
         || ssh_adt_num_objects(l2tp->session_destroy_list)
         || ssh_adt_num_objects(l2tp->tunnel_close_list)
         || ssh_adt_num_objects(l2tp->tunnel_destroy_list)
         || ssh_adt_num_objects(l2tp->tunnel_reclaim_list));

  /* Wait more data. */
  return SSH_FSM_SUSPENDED;
}


/******************************* L2TP servers *******************************/

static void
ssh_l2tp_udp_callback(SshUdpListener udp_listener, void *context)
{
  SshL2tpServer server = (SshL2tpServer) context;
  SshADTHandle h;

  /* Is this server already in the incoming list? */
  h = ssh_adt_get_handle_to_equal(server->l2tp->incoming_messages, server);
  if (h == SSH_ADT_INVALID)
    {
      /* No it isn't. */
      server->refcount++;
      ssh_adt_insert(server->l2tp->incoming_messages, server);

      if (server->l2tp->transport_thread)
        ssh_fsm_continue(server->l2tp->transport_thread);
    }
}

SshL2tpServer ssh_l2tp_server_start_ip(SshL2tp l2tp,
                                       SshIpAddr address,
                                       SshUInt16 port,
                                       int interface_index,
                                       int routing_instance_id)
{
  SshL2tpServerStruct server_struct;
  SshL2tpServer server;
  SshADTHandle h;

  memset(&server_struct.address, 0, sizeof(server_struct.address));

  if (address)
    server_struct.address = *address;

  server_struct.port = port;
  server_struct.routing_instance_id = routing_instance_id;

  /* Do we know this server? */
  h = ssh_adt_get_handle_to_equal(l2tp->servers, &server_struct);
  if (h != SSH_ADT_INVALID)
    {
      /* Add one reference to the server object. */
      server = ssh_adt_get(l2tp->servers, h);
      server->refcount++;

      return server;
    }

  /* Create a new server. */

  server = ssh_calloc(1, sizeof(*server));
  if (server == NULL)
    goto error;

  server->refcount = 1;
  server->address = server_struct.address;
  server->port = server_struct.port;
  server->interface_index = interface_index;
  server->routing_instance_id = routing_instance_id;

  server->listener = ssh_udp_make_listener_ip(address, port, NULL, 0,
                                              interface_index,
                                              routing_instance_id,
                                              &l2tp->params.udp_params,
                                              ssh_l2tp_udp_callback, server);
  if (server->listener == NULL)
    goto error;

  server->l2tp = l2tp;

  /* Register this server to our server bag. */
  ssh_adt_insert(l2tp->servers, server);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("L2TP server running on port %d, "
        "routing instance %d", port, server->routing_instance_id));

  return server;

  /* Error handling. */

 error:
  SSH_DEBUG(SSH_D_FAIL,
           ("Could not create L2TP server %@:%d routing instance %d",
             ssh_ipaddr_render, address, port, routing_instance_id));

  if (server)
    {
      if (server->listener)
        ssh_udp_destroy_listener(server->listener);
      ssh_free(server);
    }

  return NULL;
}


SshL2tpServer
ssh_l2tp_server_start(SshL2tp l2tp,
                      const unsigned char *address,
                      const unsigned char *port,
                      int interface_index,
                      int routing_instance_id)
{
  SshIpAddrStruct ip_address = { 0 };
  SshUInt16 port_number = 0;
  SshInt16 s_port;

  SSH_IP_UNDEFINE(&ip_address);
  if (address != NULL && !SSH_IS_IPADDR_ANY(address))
    {
      if (!ssh_ipaddr_parse(&ip_address, address))
        return NULL;
    }

  if (port != NULL)
    {
      s_port = ssh_inet_get_port_by_service(port, ssh_custr("udp"));
      if (s_port == -1)
        return NULL;
      port_number = s_port;
    }
  else
    {
      port_number = 1701;
    }

  return ssh_l2tp_server_start_ip(l2tp, &ip_address, port_number,
                                  interface_index, routing_instance_id);
}


void
ssh_l2tp_server_stop(SshL2tpServer server)
{
  if (--server->refcount > 0)
    /* This was not the last reference. */
    return;

  /* Delete the server from the bag of servers. */
  ssh_adt_delete_object(server->l2tp->servers, server);
}
