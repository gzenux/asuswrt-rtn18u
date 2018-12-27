/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General utility functions.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpUtil"


/***************************** Tunnel handling ******************************/

void
ssh_l2tp_tunnel_authentication_compute(SshL2tp l2tp,
                                       SshL2tpControlMsgType message_type,
                                       const unsigned char *challenge,
                                       size_t challenge_len,
                                       const unsigned char *secret,
                                       size_t secret_len,
                                       unsigned char *response_return)
{
  unsigned char id[1];

  SSH_PUT_8BIT(id, message_type);

  ssh_hash_reset(l2tp->hash);
  ssh_hash_update(l2tp->hash, id, sizeof(id));

  ssh_hash_update(l2tp->hash, secret, secret_len);
  ssh_hash_update(l2tp->hash, challenge, challenge_len);

  ssh_hash_final(l2tp->hash, response_return);
}


Boolean
ssh_l2tp_tunnel_authenticate(SshL2tp l2tp,
                             SshL2tpControlMsgType message_type,
                             const unsigned char *challenge,
                             size_t challenge_len,
                             const unsigned char *secret,
                             size_t secret_len,
                             const unsigned char *response,
                             size_t response_len)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];

  if (response_len != l2tp->hash_digest_length)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Challenge Response of invalid length: %d vs %d",
                 response_len, l2tp->hash_digest_length));
      return FALSE;
    }

  ssh_l2tp_tunnel_authentication_compute(l2tp, message_type,
                                         challenge, challenge_len,
                                         secret, secret_len,
                                         digest);

  if (memcmp(digest, response, l2tp->hash_digest_length) != 0)
    return FALSE;

  return TRUE;
}


void
ssh_l2tp_tunnel_attributes_steal(SshL2tpTunnelAttributes dst,
                                 SshL2tpTunnelAttributes src)
{
  if (src->framing_capabilities)
    dst->framing_capabilities = src->framing_capabilities;

  if (src->bearer_capabilities)
    dst->bearer_capabilities = src->bearer_capabilities;

  if (src->firmware_revision)
    dst->firmware_revision = src->firmware_revision;

  if (src->host_name)
    {
      ssh_free(dst->host_name);

      dst->host_name = src->host_name;
      dst->host_name_len = src->host_name_len;
    }

  if (src->vendor_name)
    {
      ssh_free(dst->vendor_name);

      dst->vendor_name = src->vendor_name;
      dst->vendor_name_len = src->vendor_name_len;
    }

  if (src->ssh_transform_index)
    dst->ssh_transform_index = src->ssh_transform_index;

  /* And clear source so its destructor will not free the value,
     stolen to our destination. */
  memset(src, 0, sizeof(*src));
}


void
ssh_l2tp_tunnel_id_alloc(SshL2tp l2tp, SshL2tpTunnel tunnel)
{
  unsigned char idbuf[2];
  SshADTHandle h;

  do
    {
      size_t i;

      for (i = 0; i < sizeof(idbuf); i++)
        idbuf[i] = (unsigned char) ssh_random_get_byte();

      tunnel->info.local_id = SSH_GET_16BIT(idbuf);
      if (tunnel->info.local_id != 0)
        h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, tunnel);
      else
        h = SSH_ADT_INVALID;
    }
  while (tunnel->info.local_id == 0 || h != SSH_ADT_INVALID);

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated Tunnel ID %d",
                          (int) tunnel->info.local_id));
}


SshL2tpTunnel
ssh_l2tp_tunnel_create(SshL2tpServer server, Boolean initiator)
{
  SshL2tp l2tp = server->l2tp;
  SshL2tpTunnel tunnel;
  SshFSMStepCB start_state;

  tunnel = ssh_calloc(1, sizeof(*tunnel));
  if (tunnel == NULL)
    goto error_out;

  tunnel->l2tp = l2tp;

  /* Allocate a buffer to hold the port numbers as string.  Just take
     a buffer big enough for any port.  Twelve bytes is enough for 32
     bit integer number. */

  tunnel->info.local_port = ssh_calloc(1, 12);
  if (tunnel->info.local_port == NULL)
    goto error_out;

  tunnel->info.remote_port = ssh_calloc(1, 12);
  if (tunnel->info.remote_port == NULL)
    goto error_out;

  /* Allocate a tunnel ID. */
  ssh_l2tp_tunnel_id_alloc(l2tp, tunnel);

  /* Create send window. */
  tunnel->info.send_window_size = SSH_L2TP_DEFAULT_RECEIVE_WINDOW_SIZE;
  tunnel->info.cwnd = 1;
  tunnel->info.sstresh = tunnel->info.send_window_size;
  tunnel->info.retransmit_timer = 1;

  if (initiator)
    tunnel->info.initiator = 1;

  /* Create message queue. */
  tunnel->message_queue_cond = ssh_fsm_condition_create(l2tp->fsm);
  if (tunnel->message_queue_cond == NULL)
    goto error_out;

  /* Create tunnel establishment condition. */
  tunnel->condition = ssh_fsm_condition_create(l2tp->fsm);
  if (tunnel->condition == NULL)
    goto error_out;

  /* Create a FSM thread to handle this tunnel. */

  if (initiator)
    start_state = ssh_l2tp_fsm_cc_initiator_idle;
  else
    start_state = ssh_l2tp_fsm_cc_responder_idle;

  tunnel->thread = ssh_fsm_thread_create(l2tp->fsm, start_state,
                                         ssh_l2tp_tunnel_message_handler,
                                         NULL_FNPTR, tunnel);
  if (tunnel->thread == NULL)
    goto error_out;

  /* And register this tunnel to the L2TP module. */
  ssh_adt_insert(l2tp->tunnels_id, tunnel);

  /* All done. */
  return tunnel;


  /* Error handling. */

 error_out:

  SSH_DEBUG(SSH_D_ERROR, ("Could not allocate new L2TP tunnel"));

  ssh_l2tp_tunnel_free(tunnel);

  return NULL;
}


void
ssh_l2tp_tunnel_free(SshL2tpTunnel tunnel)
{
  if (tunnel == NULL)
    return;

  if (tunnel->server)
    ssh_l2tp_server_stop(tunnel->server);

  ssh_free(tunnel->shared_secret);
  ssh_free(tunnel->sent_challenge);
  ssh_free(tunnel->received_challenge);

  if (tunnel->thread)
    ssh_fsm_kill_thread(tunnel->thread);

  ssh_free(tunnel->info.remote_addr);
  ssh_free(tunnel->info.remote_port);
  ssh_free(tunnel->info.local_addr);
  ssh_free(tunnel->info.local_port);

  ssh_free(tunnel->info.attributes.host_name);
  ssh_free(tunnel->info.attributes.vendor_name);

  ssh_free(tunnel->info.error_message);

  if (tunnel->message_queue_cond)
    ssh_fsm_condition_destroy(tunnel->message_queue_cond);

  if (tunnel->condition)
    ssh_fsm_condition_destroy(tunnel->condition);

  ssh_free(tunnel);
}


unsigned char *
ssh_l2tp_tunnel_local_addr(SshL2tpTunnel tunnel,
                           const unsigned char *remote_addr)
{
  unsigned char *addr;

  if (!SSH_IP_DEFINED(&tunnel->server->address))
    {
      SshIpAddrStruct ip = { 0 };

      /* It is an IPv4 or IPv6 any-address.  Let's use the remote
         end's address to resolve the address type. */
      (void) ssh_ipaddr_parse(&ip, remote_addr);
      if (SSH_IP_IS4(&ip))
        addr = ssh_strdup("0.0.0.0");
      else
        addr = ssh_strdup("::");
    }
  else
    {
      unsigned char buf[SSH_IP_ADDR_STRING_SIZE];

      /* We can use the server's address. */
      (void) ssh_ipaddr_print(&tunnel->server->address, buf, sizeof(buf));
      addr = ssh_strdup(buf);
    }

  return addr;
}


/***************************** Session handling *****************************/

static void
ssh_l2tp_session_id_alloc(SshL2tpTunnel tunnel, SshL2tpSession session)
{
  unsigned char idbuf[2];
  SshADTHandle h;

  SSH_ASSERT(session->tunnel == tunnel);

  do
    {
      size_t i;

      for (i = 0; i < sizeof(idbuf); i++)
        idbuf[i] = (unsigned char) ssh_random_get_byte();

      session->info.local_id = SSH_GET_16BIT(idbuf);
      if (session->info.local_id != 0)
        h = ssh_adt_get_handle_to_equal(tunnel->l2tp->sessions, session);
      else
        h = SSH_ADT_INVALID;
    }
  while (session->info.local_id == 0 || h != SSH_ADT_INVALID);

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated Session ID %d",
                          (int) session->info.local_id));
}


SshL2tpSession
ssh_l2tp_session_create(SshL2tp l2tp, SshL2tpTunnel tunnel,
                        SshL2tpControlMessage message,
                        Boolean lac, Boolean initiator)
{
  SshL2tpSession session;
  SshFSMStepCB start_state;

  session = ssh_calloc(1, sizeof(*session));
  if (session == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate new L2TP session"));
      goto error_out;
    }

  session->tunnel = tunnel;
  session->info.tunnel = &tunnel->info;

  /* Allocate a session ID. */
  ssh_l2tp_session_id_alloc(tunnel, session);

  /* Remote end's session ID. */
  if (message)
    session->info.remote_id = message->assigned_session_id;

  if (lac)
    session->info.lac = 1;
  if (initiator)
    session->info.initiator = 1;

  /* Create message queue. */
  session->message_queue_cond = ssh_fsm_condition_create(l2tp->fsm);
  if (session->message_queue_cond == NULL)
    goto error_out;

  /* Create a FSM thread to handle this session. */

  if (lac)
    {
      if (initiator)
        start_state = ssh_l2tp_fsm_lac_ic_idle;
      else
        start_state = ssh_l2tp_fsm_lac_oc_idle;
    }
  else
    {
      if (initiator)
        start_state = ssh_l2tp_fsm_lns_oc_idle;
      else
        start_state = ssh_l2tp_fsm_lns_ic_idle;
    }

  session->thread = ssh_fsm_thread_create(l2tp->fsm, start_state,
                                          ssh_l2tp_session_message_handler,
                                          NULL_FNPTR, session);
  if (session->thread == NULL)
    goto error_out;

  /* Register this session to tunnel's sessions. */

  ssh_adt_insert(l2tp->sessions, session);

  session->sessions_next = tunnel->sessions;
  if (tunnel->sessions)
    tunnel->sessions->sessions_prev = session;

  tunnel->sessions = session;

  /* All done. */
  return session;


  /* Error handling. */

 error_out:

  ssh_l2tp_session_free(session);

  SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_ERROR,
                      SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                      ssh_sstr("Out of memory"), 13);

  return NULL;
}


void
ssh_l2tp_session_free(SshL2tpSession session)
{
  if (session == NULL)
    return;

  if (session->thread)
    ssh_fsm_kill_thread(session->thread);

  ssh_free(session->info.attributes.called_number);
  ssh_free(session->info.attributes.calling_number);
  ssh_free(session->info.attributes.sub_address);
  ssh_free(session->info.attributes.private_group_id);
  ssh_free(session->info.attributes.initial_rcvd_lcp_confreq);
  ssh_free(session->info.attributes.last_sent_lcp_confreq);
  ssh_free(session->info.attributes.last_rcvd_lcp_confreq);
  ssh_free(session->info.attributes.proxy_authen_name);
  ssh_free(session->info.attributes.proxy_authen_challenge);
  ssh_free(session->info.attributes.proxy_authen_response);

  ssh_free(session->info.call_errors);
  ssh_free(session->info.error_message);
  ssh_free(session->info.q931_advisory_message);

  if (session->message_queue_cond)
    ssh_fsm_condition_destroy(session->message_queue_cond);

  ssh_free(session);
}


/*************************** L2TP server handling ***************************/

void
ssh_l2tp_free(SshL2tp l2tp)
{
  SshADTHandle h;

  if (l2tp == NULL)
    return;

  ssh_free(l2tp->params.hostname);

  if (l2tp->hash)
    ssh_hash_free(l2tp->hash);

  /* Free all messages from the message pool */
  while (l2tp->message_pool.head)
    {
      SshL2tpControlMessage msg = ssh_l2tp_message_get(&l2tp->message_pool);

      /* All messages in the message pool are clean.  We just free the
         actual message structures. */
      ssh_free(msg);
    }

  if (l2tp->message_pool_cond)
    ssh_fsm_condition_destroy(l2tp->message_pool_cond);

  if (l2tp->tunnels_id)
    ssh_adt_destroy(l2tp->tunnels_id);
  if (l2tp->tunnels_addr_port_id)
    ssh_adt_destroy(l2tp->tunnels_addr_port_id);

  if (l2tp->sessions)
    ssh_adt_destroy(l2tp->sessions);

  if (l2tp->session_close_list)
    ssh_adt_destroy(l2tp->session_close_list);
  if (l2tp->session_destroy_list)
    ssh_adt_destroy(l2tp->session_destroy_list);

  if (l2tp->tunnel_close_list)
    ssh_adt_destroy(l2tp->tunnel_close_list);
  if (l2tp->tunnel_destroy_list)
    ssh_adt_destroy(l2tp->tunnel_destroy_list);
  if (l2tp->tunnel_retransmission_wait_list)
    ssh_adt_destroy(l2tp->tunnel_retransmission_wait_list);
  if (l2tp->tunnel_reclaim_list)
    ssh_adt_destroy(l2tp->tunnel_reclaim_list);

  if (l2tp->incoming_messages)
    {
      /* Remove all servers from the list of incoming messages. */
      while ((h = ssh_adt_enumerate_start(l2tp->incoming_messages))
             != SSH_ADT_INVALID)
        {
          SshL2tpServer server = ssh_adt_get(l2tp->incoming_messages, h);

          /* Remove the server from the list. */
          ssh_adt_detach(l2tp->incoming_messages, h);

          /* Drop one reference from the server.  When the server was
             put on the list, one reference was added for them. */
          ssh_l2tp_server_stop(server);
        }

      /* Destroy the ADT container. */
      ssh_adt_destroy(l2tp->incoming_messages);
    }

  if (l2tp->servers)
    {
      /* We have to clear the servers manually since the API allows
         user to destroy the L2TP server without stopping servers. */
      while ((h = ssh_adt_enumerate_start(l2tp->servers)) != SSH_ADT_INVALID)
        {
#ifdef DEBUG_LIGHT
          SshL2tpServer server = ssh_adt_get(l2tp->servers, h);

          SSH_ASSERT(server->refcount < 2);
#endif /* DEBUG_LIGHT */

          ssh_adt_delete(l2tp->servers, h);
        }
      ssh_adt_destroy(l2tp->servers);
    }

  if (l2tp->transport_thread)
    ssh_fsm_kill_thread(l2tp->transport_thread);

  if (l2tp->fsm)
    ssh_fsm_destroy(l2tp->fsm);

  ssh_free(l2tp);
}


/************************* Control message handling *************************/

void
ssh_l2tp_message_queue(SshL2tpMessageQueue queue,
                       SshL2tpControlMessage message)
{
  message->next = NULL;

  if (queue->tail)
    {
      queue->tail->next = message;
      queue->tail = message;
    }
  else
    {
      queue->head = message;
      queue->tail = message;
    }
}


SshL2tpControlMessage
ssh_l2tp_message_get(SshL2tpMessageQueue queue)
{
  SshL2tpControlMessage message = queue->head;

  SSH_ASSERT(queue->head != NULL);

  queue->head = queue->head->next;
  if (queue->head == NULL)
    queue->tail = NULL;

  return message;
}


void
ssh_l2tp_message_handled(SshL2tp l2tp, SshFSMThread thread,
                         SshL2tpMessageQueue queue)
{
  SshL2tpControlMessage message;

  SSH_ASSERT(queue->head != NULL);

  message = queue->head;
  queue->head = queue->head->next;
  if (queue->head == NULL)
    queue->tail = NULL;

  ssh_l2tp_message_fields_free(message);

  ssh_l2tp_message_queue(&l2tp->message_pool, message);
  ssh_fsm_condition_signal(l2tp->fsm, l2tp->message_pool_cond);
}


SshL2tpControlMessage
ssh_l2tp_message(SshL2tpMessageQueue queue)
{
  SSH_ASSERT(queue->head != NULL);
  return queue->head;
}


void
ssh_l2tp_message_fields_free(SshL2tpControlMessage message)
{
  ssh_free(message->suspended_packet);

  ssh_free(message->challenge);
  ssh_free(message->challenge_response);

  ssh_free(message->tunnel_attributes.host_name);
  ssh_free(message->tunnel_attributes.vendor_name);

  ssh_free(message->session_attributes.called_number);
  ssh_free(message->session_attributes.calling_number);
  ssh_free(message->session_attributes.sub_address);
  ssh_free(message->session_attributes.private_group_id);
  ssh_free(message->session_attributes.initial_rcvd_lcp_confreq);
  ssh_free(message->session_attributes.last_sent_lcp_confreq);
  ssh_free(message->session_attributes.last_rcvd_lcp_confreq);
  ssh_free(message->session_attributes.proxy_authen_name);
  ssh_free(message->session_attributes.proxy_authen_challenge);
  ssh_free(message->session_attributes.proxy_authen_response);

  ssh_free(message->random_vector);

  memset(message, 0, sizeof(*message));
}
