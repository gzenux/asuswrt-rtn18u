/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Handling of L2TP modules and some general purpose help functions.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tp"

/*************************** Local Tunnel ID bag ****************************/

static SshUInt32
tunnel_id_hash(void *ptr, void *ctx)
{
  SshL2tpTunnel tunnel = (SshL2tpTunnel) ptr;

  return (SshUInt32) tunnel->info.local_id;
}


static int
tunnel_id_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshL2tpTunnel tunnel1 = (SshL2tpTunnel) ptr1;
  SshL2tpTunnel tunnel2 = (SshL2tpTunnel) ptr2;

  return  tunnel1->info.local_id - tunnel2->info.local_id;
}


/***************** Tunnel remote address, port, and ID bag ******************/

static SshUInt32
tunnel_addr_port_id_hash(void *ptr, void *ctx)
{
  SshL2tpTunnel tunnel = (SshL2tpTunnel) ptr;
  SshUInt32 hash;

  hash = SSH_IP_HASH(&tunnel->remote_addr);
  hash ^= tunnel->remote_port << 7;
  hash ^= tunnel->info.remote_id << 13;

  return hash;
}


static int
tunnel_addr_port_id_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshL2tpTunnel tunnel1 = (SshL2tpTunnel) ptr1;
  SshL2tpTunnel tunnel2 = (SshL2tpTunnel) ptr2;

  if (SSH_IP_EQUAL(&tunnel1->remote_addr, &tunnel2->remote_addr)
      && tunnel1->remote_port == tunnel2->remote_port
      && tunnel1->info.remote_id == tunnel2->info.remote_id)
    return 0;

  /* They just differ. */
  return -1;
}

/******************************* Sessions bag *******************************/

static SshUInt32
session_hash(void *ptr, void *ctx)
{
  SshL2tpSession session = (SshL2tpSession) ptr;

  SSH_ASSERT(session->tunnel != NULL);

  return ((SshUInt32) session->tunnel->info.local_id << 16
          | (SshUInt32) session->info.local_id);
}


static int
session_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshL2tpSession session1 = (SshL2tpSession) ptr1;
  SshL2tpSession session2 = (SshL2tpSession) ptr2;

  SSH_ASSERT(session1->tunnel != NULL);
  SSH_ASSERT(session2->tunnel != NULL);

  if (session1->tunnel->info.local_id != session2->tunnel->info.local_id)
    return session1->tunnel->info.local_id - session2->tunnel->info.local_id;

  return session1->info.local_id - session2->info.local_id;
}


/**************** L2TP UDP servers and incoming message bags ****************/

static SshUInt32
ssh_l2tp_server_hash(void *ptr, void *ctx)
{
  SshL2tpServer server = (SshL2tpServer) ptr;
  SshUInt32 hash;

  hash = SSH_IP_HASH(&server->address);
  hash ^= server->port;

  return hash;
}


static int
ssh_l2tp_server_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshL2tpServer server1 = (SshL2tpServer) ptr1;
  SshL2tpServer server2 = (SshL2tpServer) ptr2;

  if (server1->routing_instance_id == server2->routing_instance_id
      && SSH_IP_EQUAL(&server1->address, &server2->address)
      && server1->port == server2->port)
    return 0;

  /* They just differ. */
  return -1;
}


static void
ssh_l2tp_server_destroy(void *ptr, void *ctx)
{
  SshL2tpServer server = (SshL2tpServer) ptr;

  ssh_udp_destroy_listener(server->listener);
  ssh_free(server);
}


/******************* Creating and destroying L2TP module ********************/

SshL2tp
ssh_l2tp_create(SshL2tpParams params,
                SshL2tpTunnelRequestCB tunnel_request_cb,
                SshL2tpTunnelStatusCB tunnel_status_cb,
                SshL2tpSessionRequestCB session_request_cb,
                SshL2tpSessionStatusCB session_status_cb,
                SshL2tpLacOutgoingCallCB lac_outgoing_call_cb,
                void *callback_context)
{
  SshUInt32 i;
  SshL2tp l2tp;

  l2tp = ssh_calloc(1, sizeof(*l2tp));
  if (l2tp == NULL)
    goto error;

  if (params)
    memcpy(&l2tp->params, params, sizeof(*params));

  /* Set the default values. */

  if (l2tp->params.max_tunnels == 0)
    l2tp->params.max_tunnels = 0xffffffff;

  if (l2tp->params.receive_window_size == 0)
    l2tp->params.receive_window_size = 16;

  if (l2tp->params.max_send_window_size == 0)
    l2tp->params.max_send_window_size = 32;

  if (l2tp->params.max_retransmit_timer == 0)
    l2tp->params.max_retransmit_timer = 30;

  if (l2tp->params.hello_timer == 0)
    l2tp->params.hello_timer = 86400;

  if (l2tp->params.max_tunnel_outage == 0)
    l2tp->params.max_tunnel_outage = 120;

  if (l2tp->params.challenge_len == 0)
    l2tp->params.challenge_len = 32;
  if (l2tp->params.challenge_len > 1017)
    l2tp->params.challenge_len = 1017;

  if (l2tp->params.random_vector_len == 0)
    l2tp->params.random_vector_len = 32;
  if (l2tp->params.random_vector_len > 1017)
    l2tp->params.random_vector_len = 1017;

  if (l2tp->params.framing_capabilities == 0)
    l2tp->params.framing_capabilities = SSH_L2TP_FRAMING_SYNCHRONOUS;

  /* Use whatever user provided for bearer capabilities. */

  if (l2tp->params.hostname == NULL || l2tp->params.hostname_len == 0)
    {
      /* The host name must have at least one octet so we must create
         our default value. */
      l2tp->params.hostname = (unsigned char *) "L2TP Host";
      l2tp->params.hostname_len = strlen((char *) l2tp->params.hostname);
    }
  l2tp->params.hostname = ssh_memdup(l2tp->params.hostname,
                                     l2tp->params.hostname_len);
  if (l2tp->params.hostname == NULL)
    goto error;

  /* Create FSM. */
  l2tp->fsm = ssh_fsm_create(l2tp);
  if (l2tp->fsm == NULL)
    goto error;

  /* Allocate hash function. */
  if (ssh_hash_allocate("md5", &l2tp->hash) != SSH_CRYPTO_OK)
      goto error;
  l2tp->hash_digest_length = ssh_hash_digest_length(ssh_hash_name(l2tp->hash));

  /* Condition variable that is signalled when messages are released
     to message pool. */
  l2tp->message_pool_cond = ssh_fsm_condition_create(l2tp->fsm);
  if (l2tp->message_pool_cond == NULL)
    goto error;

  /* And allocate messages for the message pool. */
  for (i = 0; i < l2tp->params.receive_window_size; i++)
    {
      SshL2tpControlMessage message = ssh_calloc(1, sizeof(*message));

      if (message == NULL)
        goto error;

      ssh_l2tp_message_queue(&l2tp->message_pool, message);
    }

  /* Initialize L2TP server's ADT bags and lists. */
  l2tp->tunnels_id
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct,
                                               adt_header_id),

                             SSH_ADT_HASH,      tunnel_id_hash,
                             SSH_ADT_COMPARE,   tunnel_id_compare,
                             SSH_ADT_ARGS_END);
  l2tp->tunnels_addr_port_id
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct,
                                               adt_header_addr_port_id),

                             SSH_ADT_HASH,      tunnel_addr_port_id_hash,
                             SSH_ADT_COMPARE,   tunnel_addr_port_id_compare,
                             SSH_ADT_ARGS_END);

  l2tp->sessions
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpSessionStruct,
                                               adt_header),

                             SSH_ADT_HASH,      session_hash,
                             SSH_ADT_COMPARE,   session_compare,
                             SSH_ADT_ARGS_END);

  l2tp->session_close_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpSessionStruct, list),
                             SSH_ADT_ARGS_END);
  l2tp->session_destroy_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpSessionStruct, list),
                             SSH_ADT_ARGS_END);
  l2tp->tunnel_close_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct, list),
                             SSH_ADT_ARGS_END);
  l2tp->tunnel_destroy_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct, list),
                             SSH_ADT_ARGS_END);
  l2tp->tunnel_retransmission_wait_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct, list),
                             SSH_ADT_ARGS_END);
  l2tp->tunnel_reclaim_list
    = ssh_adt_create_generic(SSH_ADT_LIST,
                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpTunnelStruct, list),
                             SSH_ADT_ARGS_END);

  l2tp->servers
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpServerStruct,
                                               adt_header_lookup),

                             SSH_ADT_HASH,      ssh_l2tp_server_hash,
                             SSH_ADT_COMPARE,   ssh_l2tp_server_compare,

                             /* Destroy is only in the lookup bag. */
                             SSH_ADT_DESTROY,   ssh_l2tp_server_destroy,
                             SSH_ADT_ARGS_END);

  l2tp->incoming_messages
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshL2tpServerStruct,
                                               adt_header_incoming),

                             SSH_ADT_HASH,      ssh_l2tp_server_hash,
                             SSH_ADT_COMPARE,   ssh_l2tp_server_compare,
                             SSH_ADT_ARGS_END);

  if (l2tp->tunnels_id == NULL
      || l2tp->tunnels_addr_port_id == NULL
      || l2tp->sessions == NULL
      || l2tp->session_close_list == NULL
      || l2tp->session_destroy_list == NULL
      || l2tp->tunnel_close_list == NULL
      || l2tp->tunnel_destroy_list == NULL
      || l2tp->tunnel_retransmission_wait_list == NULL
      || l2tp->tunnel_reclaim_list == NULL
      || l2tp->servers == NULL
      || l2tp->incoming_messages == NULL)
    goto error;

  /* Set callbacks. */
  l2tp->tunnel_request_cb = tunnel_request_cb;
  l2tp->tunnel_status_cb = tunnel_status_cb;
  l2tp->session_request_cb = session_request_cb;
  l2tp->session_status_cb = session_status_cb;
  l2tp->lac_outgoing_call_cb = lac_outgoing_call_cb;
  l2tp->callback_context = callback_context;

  /* Start transport thread. */
  l2tp->transport_thread = ssh_fsm_thread_create(l2tp->fsm,
                                                 ssh_l2tp_fsm_tr_wait,
                                                 NULL_FNPTR, NULL_FNPTR, NULL);
  if (l2tp->transport_thread == NULL)
    goto error;

  /* All done. */

  return l2tp;


  /* Error handling. */

 error:

  ssh_l2tp_free(l2tp);

  return NULL;
}


static void
ssh_l2tp_do_shutdown(SshL2tp l2tp, SshL2tpFinishedCB callback, void *context,
                     Boolean shutdown)
{
  SshADTHandle h;

  SSH_ASSERT(l2tp->destroyed == 0);
  l2tp->destroyed = 1;

  l2tp->destroy_callback = callback;
  l2tp->destroy_callback_context = context;

  if (!shutdown)
    l2tp->fast_shutdown = 1;

  /* Close all tunnels. */
  for (h = ssh_adt_enumerate_start(l2tp->tunnels_id);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(l2tp->tunnels_id, h))
    {
      SshL2tpTunnel tunnel = ssh_adt_get(l2tp->tunnels_id, h);

      if (tunnel->destroyed || tunnel->on_destroy_list)
        continue;

      /* Put in to the close or destroy list. */
      tunnel->on_destroy_list = 1;
      if (shutdown)
        ssh_adt_insert_to(l2tp->tunnel_close_list, SSH_ADT_END, tunnel);
      else
        ssh_adt_insert_to(l2tp->tunnel_destroy_list, SSH_ADT_END, tunnel);
    }

  if (!shutdown)
    /* Destroy all tunnels on the retransmission wait list. */
    ssh_l2tp_flush_retransmission_wait_list(l2tp);

  ssh_fsm_continue(l2tp->transport_thread);
}


void
ssh_l2tp_shutdown(SshL2tp l2tp, SshL2tpFinishedCB callback, void *context)
{
  ssh_l2tp_do_shutdown(l2tp, callback, context, TRUE);
}


void
ssh_l2tp_destroy(SshL2tp l2tp, SshL2tpFinishedCB callback, void *context)
{
  ssh_l2tp_do_shutdown(l2tp, callback, context, FALSE);
}


/***************************** Tunnel handling ******************************/

static void
ssh_l2tp_do_tunnel_close(SshL2tp l2tp, SshL2tpTunnelID local_id, Boolean close,
                         SshL2tpTunnelResultCode result,
                         SshL2tpErrorCode error,
                         const unsigned char *error_message,
                         size_t error_message_len)
{
  SshADTHandle h;
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel;

  tunnel_struct.info.local_id = local_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Tunnel ID %d does not exist", local_id));
      return;
    }

  tunnel = ssh_adt_get(l2tp->tunnels_id, h);
  if (tunnel->on_destroy_list || tunnel->destroyed)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID %d is already destroyed",
                                   local_id));
      return;
    }

  /* Set the termination reason. */
  if (tunnel->info.result_code == 0)
    {
      tunnel->info.result_code = result;
      tunnel->info.error_code = error;

      ssh_free(tunnel->info.error_message);
      tunnel->info.error_message = NULL;
      tunnel->info.error_message_len = 0;

      if (error_message)
        {
          tunnel->info.error_message = ssh_memdup(error_message,
                                                  error_message_len);
          if (tunnel->info.error_message)
            tunnel->info.error_message_len = error_message_len;
          else
            tunnel->info.error_message_len = 0;
        }
    }

  tunnel->on_destroy_list = 1;
  if (close)
    ssh_adt_insert_to(l2tp->tunnel_close_list, SSH_ADT_END, tunnel);
  else
    ssh_adt_insert_to(l2tp->tunnel_destroy_list, SSH_ADT_END, tunnel);

  ssh_fsm_continue(l2tp->transport_thread);
}


void
ssh_l2tp_tunnel_close(SshL2tp l2tp, SshL2tpTunnelID local_id,
                      SshL2tpTunnelResultCode result,
                      SshL2tpErrorCode error,
                      const unsigned char *error_message,
                      size_t error_message_len)
{
  ssh_l2tp_do_tunnel_close(l2tp, local_id, TRUE, result, error,
                           error_message, error_message_len);
}


void
ssh_l2tp_tunnel_destroy(SshL2tp l2tp, SshL2tpTunnelID local_id)
{
  ssh_l2tp_do_tunnel_close(l2tp, local_id, FALSE, 0, 0, NULL, 0);
}


SshL2tpServer
ssh_l2tp_tunnel_get_server(SshL2tp l2tp, SshL2tpTunnelID tunnel_id)
{
  SshADTHandle h;
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel;

  tunnel_struct.info.local_id = tunnel_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Tunnel ID %d does not exist", tunnel_id));
      return NULL;
    }

  tunnel = ssh_adt_get(l2tp->tunnels_id, h);

  return tunnel->server;
}


/***************************** Session handling *****************************/

void
ssh_l2tp_session_send(SshL2tp l2tp, SshL2tpSessionInfo session_info,
                      const unsigned char *data, size_t data_len)
{
  unsigned char *packet;
  SshL2tpSession session
    = (SshL2tpSession) (((unsigned char *) session_info)
                        - SSH_ADT_OFFSET_OF(SshL2tpSessionStruct, info));

  SSH_ASSERT(&session->info == session_info);

  SSH_DEBUG(SSH_D_LOWSTART, ("send: size=%d", data_len));

  /* Format data message to L2TP module's datagram buffer. */

  SSH_ASSERT(l2tp->datagram_addr == NULL);
  SSH_ASSERT(data_len + 8 <= sizeof(l2tp->datagram));

  packet = l2tp->datagram;

  /* TODO: sequencing. */

  SSH_L2TPH_SET_VERSION_AND_BITS(
          packet,
          SSH_L2TP_DATA_MESSAGE_HEADER_VERSION,
          SSH_L2TPH_F_LENGTH);

  packet += 2;

  /* Length. */
  SSH_PUT_16BIT(packet, 8 + data_len);
  packet += 2;

  /* Tunnel ID. */
  SSH_PUT_16BIT(packet, session->tunnel->info.remote_id);
  packet += 2;

  /* Session ID. */
  SSH_PUT_16BIT(packet, session->info.remote_id);
  packet += 2;

  memcpy(packet, data, data_len);

  /* Send the datagram. */
  ssh_l2tp_send_data(l2tp, session, l2tp->datagram, data_len + 8);
}


static void
ssh_l2tp_do_session_close(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                          SshL2tpSessionID session_id, Boolean close,
                          SshL2tpSessionResultCode result,
                          SshL2tpErrorCode error,
                          const unsigned char *error_message,
                          size_t error_message_len,
                          SshUInt16 q931_cause_code,
                          SshUInt8 q931_cause_msg,
                          const unsigned char *q931_advisory_message,
                          size_t q931_advisory_message_len)

{
  SshADTHandle h;
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel;
  SshL2tpSessionStruct session_struct;
  SshL2tpSession session;

  /* Lookup tunnel. */
  tunnel_struct.info.local_id = tunnel_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Tunnel ID %d does not exist", tunnel_id));
      return;
    }
  tunnel = ssh_adt_get(l2tp->tunnels_id, h);

  if (tunnel->on_destroy_list || tunnel->destroyed)
    {
      /* Tunnel is already destroyed.  So are all its sessions. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID %d is alrady destroyed",
                                   tunnel_id));
      return;
    }

  /* Lookup session. */
  session_struct.tunnel = tunnel;
  session_struct.info.local_id = session_id;
  h = ssh_adt_get_handle_to_equal(l2tp->sessions, &session_struct);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Session ID %d of tunnel ID %d does not exist",
                              session_id, tunnel_id));
      return;
    }
  session = ssh_adt_get(l2tp->sessions, h);
  if (session->on_destroy_list || session->destroyed)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Session ID %d is already destroyed",
                                   session_id));
      return;
    }

  /* Set the termination reason. */
  if (session->info.result_code == 0)
    {
      session->info.result_code = result;
      session->info.error_code = error;

      ssh_free(session->info.error_message);
      session->info.error_message = NULL;
      session->info.error_message_len = 0;

      if (error_message)
        {
          session->info.error_message = ssh_memdup(error_message,
                                                   error_message_len);
          if (session->info.error_message)
            session->info.error_message_len = error_message_len;
          else
            session->info.error_message_len = 0;
        }
    }
  if (session->info.q931_cause_code == 0)
    {
      session->info.q931_cause_code = q931_cause_code;
      session->info.q931_cause_msg = q931_cause_msg;

      ssh_free(session->info.q931_advisory_message);
      session->info.q931_advisory_message = NULL;
      session->info.q931_advisory_message_len = 0;

      if (q931_advisory_message)
        {
          session->info.q931_advisory_message
            = ssh_memdup(q931_advisory_message, q931_advisory_message_len);
          if (session->info.q931_advisory_message)
            session->info.q931_advisory_message_len
              = q931_advisory_message_len;
          else
            session->info.q931_advisory_message_len = 0;
        }
    }

  session->on_destroy_list = 1;
  if (close)
    ssh_adt_insert_to(l2tp->session_close_list, SSH_ADT_END, session);
  else
    ssh_adt_insert_to(l2tp->session_destroy_list, SSH_ADT_END, session);

  ssh_fsm_continue(l2tp->transport_thread);
}


void
ssh_l2tp_session_close(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                       SshL2tpSessionID session_id,
                       SshL2tpSessionResultCode result,
                       SshL2tpErrorCode error,
                       const unsigned char *error_message,
                       size_t error_message_len,
                       SshUInt16 q931_cause_code,
                       SshUInt8 q931_cause_msg,
                       const unsigned char *q931_advisory_message,
                       size_t q931_advisory_message_len)

{
  ssh_l2tp_do_session_close(l2tp, tunnel_id, session_id, TRUE,
                            result, error, error_message, error_message_len,
                            q931_cause_code, q931_cause_msg,
                            q931_advisory_message, q931_advisory_message_len);
}


void
ssh_l2tp_session_destroy(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                         SshL2tpSessionID session_id)
{
  ssh_l2tp_do_session_close(l2tp, tunnel_id, session_id, FALSE,
                            0, 0, NULL, 0,
                            0, 0, NULL, 0);
}


/**************************** LAC functionality *****************************/

#define SSH_L2TP_SET_ATTR(base)                         \
do                                                      \
  {                                                     \
    session->info.attributes.base = attrs->base;        \
  }                                                     \
while (0)

#define SSH_L2TP_SET_ALLOC_ATTR(base)                           \
do                                                              \
  {                                                             \
    if (attrs->base)                                            \
      {                                                         \
        session->info.attributes.base ## _len                   \
          = attrs->base ## _len;                                \
        session->info.attributes.base                           \
          = ssh_memdup(attrs->base, attrs->base ## _len);       \
        if (session->info.attributes.base == NULL)              \
          goto error_out;                                       \
      }                                                         \
  }                                                             \
while (0)

static const SshL2tpSessionAttributesStruct ssh_l2tp_lac_ic_defaults =
{
  0,                            /* Call Serial Number */
  0,                            /* Minimum BPS */
  0,                            /* Maximum BPS */
  0,                            /* Bearer Type */
  SSH_L2TP_FRAMING_SYNCHRONOUS, /* Framing Type */
  NULL, 0,                      /* Called Number */
  NULL, 0,                      /* Calling Number */
  NULL, 0,                      /* Sub-Address */
  10000000,                     /* (Tx) Connect Speed */
  0,                            /* Rx Connect Speed */
  0,                            /* Physical Channel ID */
  NULL, 0,                      /* Private Group ID */
  FALSE,                        /* Sequencing Required */
  NULL, 0,                      /* Initial Received LCP CONFREQ */
  NULL, 0,                      /* Last Sent LCP CONFREQ */
  NULL, 0,                      /* Last Received LCP CONFREQ */
  SSH_L2TP_PROXY_AUTHEN_RESERVED0, /* Proxy Authen Type */
  NULL, 0,                      /* Proxy Authen Name */
  NULL, 0,                      /* Proxy Authen Challenge */
  0,                            /* Proxy Authen ID */
  NULL, 0,                      /* Proxy Authen Response */
};

/* SSH operation abort callback to abort a session establishment. */
static void
ssh_l2tp_session_operation_abort(void *context)
{
  SshL2tpSession session = (SshL2tpSession) context;
  SshL2tpTunnel tunnel = session->tunnel;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Aborting Session ID %d",
                               session->info.local_id));
  SSH_ASSERT(!session->established);
  session->initiator_status_cb = NULL_FNPTR;
  session->initiator_status_cb_context = NULL;
  session->initiator_handle = NULL;

  /* Destroy tunnel if aborting its only session, otherwise destroy session. */
  if (tunnel->sessions == session && !session->sessions_next)
    {
      if (tunnel->on_destroy_list || tunnel->destroyed)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID %d is already destroyed",
                                       tunnel->info.local_id));
          return;
        }

      tunnel->on_destroy_list = 1;
      ssh_adt_insert_to(tunnel->l2tp->tunnel_destroy_list, SSH_ADT_END,
                        tunnel);
    }
  else
    {
      if (session->on_destroy_list || session->destroyed)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Session ID %d is already destroyed",
                                       session->info.local_id));
          return;
        }

      session->on_destroy_list = 1;
      ssh_adt_insert_to(session->tunnel->l2tp->session_destroy_list,
                        SSH_ADT_END, session);
    }

  ssh_fsm_continue(session->tunnel->l2tp->transport_thread);
}


SshOperationHandle
ssh_l2tp_lac_session_open(SshL2tp l2tp,
                          SshL2tpServer server,
                          SshL2tpTunnelID tunnel_id,
                          const unsigned char *remote_addr,
                          const unsigned char *remote_port,
                          const unsigned char *shared_secret,
                          size_t shared_secret_len,
                          SshL2tpSessionAttributes attrs,
                          SshL2tpSessionStatusCB status_cb,
                          void *callback_context)
{
  SshL2tpTunnel tunnel = NULL;
  Boolean new_tunnel = TRUE;
  SshL2tpSession session = NULL;

  /* Do we have to create a new tunnel? */
  if (tunnel_id)
    {
      SshL2tpTunnelStruct tunnel_struct;
      SshADTHandle h;

      tunnel_struct.info.local_id = tunnel_id;
      h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
      if (h != SSH_ADT_INVALID)
        {
          /* We know this tunnel. */
          tunnel = ssh_adt_get(l2tp->tunnels_id, h);
          if (tunnel->destroyed)
            {
              /* Sorry, we can not use this. */
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Tunnel ID %d is already destroyed",
                         tunnel_id));
              tunnel = NULL;
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Using existing tunnel ID %d",
                                           tunnel_id));
              new_tunnel = FALSE;
            }
        }
    }

  if (tunnel == NULL)
    {
      /* Was the server specified? */
      if (server == NULL)
        /* No it wasn't. */
        goto error_out;

      /* Yes, let's create a new tunnel. */
      tunnel = ssh_l2tp_tunnel_create(server, TRUE);
      if (tunnel == NULL)
        goto error_out;

      /* Init tunnel's fields. */
      if (!ssh_ipaddr_parse(&tunnel->remote_addr, remote_addr))
        goto error_out;

      tunnel->remote_port = ssh_uatoi(remote_port);

      if (shared_secret)
        {
          tunnel->shared_secret = ssh_memdup(shared_secret,
                                             shared_secret_len);
          if (tunnel->shared_secret == NULL)
            goto error_out;

          tunnel->shared_secret_len = shared_secret_len;
        }

      tunnel->info.remote_addr = ssh_strdup(remote_addr);
      if (tunnel->info.remote_addr == NULL)
        goto error_out;

      SSH_ASSERT(ssh_ustrlen(remote_port) < 12);
      ssh_ustrcpy(tunnel->info.remote_port, remote_port);

      /* Bind the server for the tunnel. */
      server->refcount++;
      tunnel->server = server;

      tunnel->info.local_addr = ssh_l2tp_tunnel_local_addr(tunnel,
                                                           remote_addr);
      if (tunnel->info.local_addr == NULL)
        goto error_out;




      ssh_snprintf(ssh_sstr(tunnel->info.local_port), 12,
                   "%d", (int) server->port);
    }

  /* Create a session to wait for this tunnel to open. */
  session = ssh_l2tp_session_create(l2tp, tunnel, NULL, TRUE, TRUE);
  if (session == NULL)
    goto error_out;

  /* Set the user's arguments for the session. */
  if (attrs == NULL)
    attrs = (SshL2tpSessionAttributes) &ssh_l2tp_lac_ic_defaults;

  SSH_L2TP_SET_ATTR(bearer_type);
  SSH_L2TP_SET_ATTR(framing_type);

  SSH_L2TP_SET_ALLOC_ATTR(called_number);
  SSH_L2TP_SET_ALLOC_ATTR(calling_number);
  SSH_L2TP_SET_ALLOC_ATTR(sub_address);

  SSH_L2TP_SET_ATTR(tx_connect_speed);
  SSH_L2TP_SET_ATTR(rx_connect_speed);
  SSH_L2TP_SET_ATTR(physical_channel_id);

  SSH_L2TP_SET_ALLOC_ATTR(private_group_id);

  SSH_L2TP_SET_ATTR(sequencing_required);

  SSH_L2TP_SET_ALLOC_ATTR(initial_rcvd_lcp_confreq);
  SSH_L2TP_SET_ALLOC_ATTR(last_sent_lcp_confreq);
  SSH_L2TP_SET_ALLOC_ATTR(last_rcvd_lcp_confreq);

  SSH_L2TP_SET_ATTR(proxy_authen_type);

  SSH_L2TP_SET_ALLOC_ATTR(proxy_authen_name);
  SSH_L2TP_SET_ALLOC_ATTR(proxy_authen_challenge);

  SSH_L2TP_SET_ATTR(proxy_authen_id);

  SSH_L2TP_SET_ALLOC_ATTR(proxy_authen_response);

  /* And save the completion callback. */
  session->initiator_status_cb = status_cb;
  session->initiator_status_cb_context = callback_context;

  /* Create an operation handle. */
  session->initiator_handle
    = ssh_operation_register(ssh_l2tp_session_operation_abort, session);
  if (session->initiator_handle == NULL)
    goto error_out;

  /* All done. */
  return session->initiator_handle;


  /* Error handling. */

 error_out:

  ssh_l2tp_session_free(session);

  if (new_tunnel)
    ssh_l2tp_tunnel_free(tunnel);

  (*status_cb)(NULL, SSH_L2TP_SESSION_OPEN_FAILED, callback_context);

  return NULL;
}


void
ssh_l2tp_lac_wan_error_notify(SshL2tp l2tp,
                              SshL2tpTunnelID tunnel_id,
                              SshL2tpSessionID session_id,
                              SshL2tpCallErrors call_errors)
{
  SshADTHandle h;
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel = NULL;
  SshL2tpSessionStruct session_struct;
  SshL2tpSession session = NULL;

  /* Lookup tunnel. */
  tunnel_struct.info.local_id = tunnel_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* No tunnel found. */
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel ID %u found", tunnel_id));
      return;
    }
  tunnel = ssh_adt_get(l2tp->tunnels_id, h);

  /* Lookup session. */
  session_struct.tunnel = tunnel;
  session_struct.info.local_id = session_id;
  h = ssh_adt_get_handle_to_equal(l2tp->sessions, &session_struct);
  if (h != SSH_ADT_INVALID)
    session = ssh_adt_get(l2tp->sessions, h);

  /* Send notify message. */

  SSH_ASSERT(l2tp->call_errors == NULL);
  l2tp->call_errors = call_errors;

  ssh_l2tp_send(l2tp, NULL, tunnel, session, SSH_L2TP_CTRL_MSG_WEN);

  l2tp->call_errors = NULL;
}


/**************************** LNS functionality *****************************/

static const SshL2tpSessionAttributesStruct ssh_l2tp_lns_oc_defaults =
{
  0,                            /* Call Serial Number */
  0,                            /* Minimum BPS */
  100000000,                    /* Maximum BPS */
  0,                            /* Bearer Type */
  SSH_L2TP_FRAMING_SYNCHRONOUS, /* Framing Type */
  (unsigned char *) "L2TP Outgoing Call", 18, /* Called Number */
  NULL, 0,                      /* Calling Number */
  NULL, 0,                      /* Sub-Address */
  10000000,                     /* (Tx) Connect Speed */
  0,                            /* Rx Connect Speed */
  0,                            /* Physical Channel ID */
  NULL, 0,                      /* Private Group ID */
  FALSE,                        /* Sequencing Required */
  NULL, 0,                      /* Initial Received LCP CONFREQ */
  NULL, 0,                      /* Last Sent LCP CONFREQ */
  NULL, 0,                      /* Last Received LCP CONFREQ */
  SSH_L2TP_PROXY_AUTHEN_RESERVED0, /* Proxy Authen Type */
  NULL, 0,                      /* Proxy Authen Name */
  NULL, 0,                      /* Proxy Authen Challenge */
  0,                            /* Proxy Authen ID */
  NULL, 0,                      /* Proxy Authen Response */
};


SshOperationHandle
ssh_l2tp_lns_session_open(SshL2tp l2tp,
                          SshL2tpServer server,
                          SshL2tpTunnelID tunnel_id,
                          const unsigned char *remote_addr,
                          const unsigned char *remote_port,
                          const unsigned char *shared_secret,
                          size_t shared_secret_len,
                          SshL2tpSessionAttributes attrs,
                          SshL2tpSessionStatusCB status_cb,
                          void *callback_context)
{
  SshL2tpTunnel tunnel = NULL;
  Boolean new_tunnel = TRUE;
  SshL2tpSession session = NULL;

  /* Do we have to create a new tunnel? */
  if (tunnel_id)
    {
      SshL2tpTunnelStruct tunnel_struct;
      SshADTHandle h;

      tunnel_struct.info.local_id = tunnel_id;
      h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
      if (h != SSH_ADT_INVALID)
        {
          /* We know this tunnel. */
          tunnel = ssh_adt_get(l2tp->tunnels_id, h);
          if (tunnel->destroyed)
            {
              /* Sorry, we can not use this. */
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Tunnel ID %d is already destroyed",
                         tunnel_id));
              tunnel = NULL;
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Using existing tunnel ID %d",
                                           tunnel_id));
              new_tunnel = FALSE;
            }
        }
    }

  if (tunnel == NULL)
    {
      /* Was the server specified? */
      if (server == NULL)
        /* No it wasn't. */
        goto error_out;

      /* Yes, let's create a new tunnel. */
      tunnel = ssh_l2tp_tunnel_create(server, TRUE);
      if (tunnel == NULL)
        goto error_out;

      /* Init tunnel's fields. */
      if (!ssh_ipaddr_parse(&tunnel->remote_addr, remote_addr))
        goto error_out;

      tunnel->remote_port = ssh_uatoi(remote_port);

      tunnel->info.remote_addr = ssh_strdup(remote_addr);
      if (tunnel->info.remote_addr == NULL)
        goto error_out;

      SSH_ASSERT(ssh_ustrlen(remote_port) < 12);
      ssh_ustrcpy(tunnel->info.remote_port, remote_port);

      /* Bind the server for the tunnel. */
      server->refcount++;
      tunnel->server = server;

      tunnel->info.local_addr = ssh_l2tp_tunnel_local_addr(tunnel,
                                                           remote_addr);
      if (tunnel->info.local_addr == NULL)
        goto error_out;




      ssh_snprintf(ssh_sstr(tunnel->info.local_port), 12,
                   "%d", (int) server->port);
    }

  /* Create a session to wait for this tunnel to open. */
  session = ssh_l2tp_session_create(l2tp, tunnel, NULL, FALSE, TRUE);
  if (session == NULL)
    goto error_out;

  /* Set the use's arguments for the session. */
  if (attrs == NULL)
    attrs = (SshL2tpSessionAttributes) &ssh_l2tp_lns_oc_defaults;

  SSH_L2TP_SET_ATTR(minimum_bps);
  SSH_L2TP_SET_ATTR(maximum_bps);
  SSH_L2TP_SET_ATTR(bearer_type);
  SSH_L2TP_SET_ATTR(framing_type);

  SSH_L2TP_SET_ALLOC_ATTR(called_number);
  SSH_L2TP_SET_ALLOC_ATTR(sub_address);

  SSH_L2TP_SET_ATTR(tx_connect_speed);
  SSH_L2TP_SET_ATTR(rx_connect_speed);
  SSH_L2TP_SET_ATTR(physical_channel_id);

  SSH_L2TP_SET_ATTR(sequencing_required);

  /* And save the completion callback. */
  session->initiator_status_cb = status_cb;
  session->initiator_status_cb_context = callback_context;

  /* Create an operation handle. */
  session->initiator_handle
    = ssh_operation_register(ssh_l2tp_session_operation_abort, session);
  if (session->initiator_handle == NULL)
    goto error_out;

  /* All done. */
  return session->initiator_handle;


  /* Error handling. */

 error_out:

  ssh_l2tp_session_free(session);

  if (new_tunnel)
    ssh_l2tp_tunnel_free(tunnel);

  (*status_cb)(NULL, SSH_L2TP_SESSION_OPEN_FAILED, callback_context);

  return NULL;
}


void
ssh_l2tp_lns_set_link_info(SshL2tp l2tp,
                           SshL2tpTunnelID tunnel_id,
                           SshL2tpSessionID session_id,
                           SshL2tpAccm accm)
{
  SshADTHandle h;
  SshL2tpTunnelStruct tunnel_struct;
  SshL2tpTunnel tunnel = NULL;
  SshL2tpSessionStruct session_struct;
  SshL2tpSession session = NULL;

  /* Lookup tunnel. */
  tunnel_struct.info.local_id = tunnel_id;
  h = ssh_adt_get_handle_to_equal(l2tp->tunnels_id, &tunnel_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* No tunnel found. */
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel ID %u found", tunnel_id));
      return;
    }
  tunnel = ssh_adt_get(l2tp->tunnels_id, h);

  /* Lookup session. */
  session_struct.tunnel = tunnel;
  session_struct.info.local_id = session_id;
  h = ssh_adt_get_handle_to_equal(l2tp->sessions, &session_struct);
  if (h != SSH_ADT_INVALID)
    session = ssh_adt_get(l2tp->sessions, h);

  /* Send notify message. */

  SSH_ASSERT(l2tp->accm == NULL);
  l2tp->accm = accm;

  ssh_l2tp_send(l2tp, NULL, tunnel, session, SSH_L2TP_CTRL_MSG_SLI);

  l2tp->accm = NULL;
}

/* Set the l2tp error status. */
void ssh_l2tp_set_status(SshL2tp l2tp,
                         int result,
                         SshL2tpErrorCode error,
                         const unsigned char *message,
                         size_t message_len)
{
  l2tp->result_code = result;
  l2tp->error_code = error;

  if (message)
    {
      size_t msg_len = message_len;

      if (msg_len > sizeof(l2tp->error_message_buf))
        msg_len = sizeof(l2tp->error_message_buf);

      memcpy(l2tp->error_message_buf, message, msg_len);

      l2tp->error_message = l2tp->error_message_buf;
      l2tp->error_message_len = msg_len;
    }
  else
    {
      l2tp->error_message = NULL;
      l2tp->error_message_len = 0;
    }
}

