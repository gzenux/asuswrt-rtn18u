/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtcp.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"
#include "sshstream.h"
#include "sshtlsextra.h"
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
#include "sshtlsaccel.h"
#include "tls_accel.h"
#include "sshencode.h"
#include "ssheloop.h"
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

#define SSH_DEBUG_MODULE "SshTls"

static const SshStreamMethodsStruct ssh_tls_methods =
{
  ssh_tls_stream_read,
  ssh_tls_stream_write,
  ssh_tls_stream_output_eof,
  ssh_tls_stream_set_callback,
  ssh_tls_stream_destroy,
};


/** Protocol destruction **/
static void
ssh_tls_free_protocols(SshTlsProtocolState s)
{
  /* The higher level protocols. */
  {
    SshTlsHigherProtocol temp;
    while (s->protocols != NULL)
      {
        temp = s->protocols; s->protocols = s->protocols->next;
        ssh_buffer_free(temp->data);
        ssh_free(temp);
      }
  }
}


void ssh_tls_actual_destroy(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(4, ("Destroying TLS protocol context %p. "
                "Sent: %lu pckts, %lu B  Rcvd: %ld pckts, %lu B   "
                "App: %lu B got, %lu B given   %lu KEXs\n",
                s,
                (unsigned long) s->stats.packets_sent,
                (unsigned long) s->stats.bytes_sent,
                (unsigned long) s->stats.packets_received,
                (unsigned long) s->stats.bytes_received,
                (unsigned long) s->stats.app_bytes_got,
                (unsigned long) s->stats.app_bytes_given,
                (unsigned long) s->stats.num_key_exchanges));

  SSH_ASSERT(s->flags & SSH_TLS_FLAG_DELETED);
  SSH_ASSERT(s->flags & SSH_TLS_FLAG_DESTROY_SCHEDULED);
  SSH_ASSERT(!(s->flags & (SSH_TLS_FLAG_REQUESTED_TIMEOUT)));
  SSH_ASSERT(s->incoming_raw_data != NULL);
  SSH_ASSERT(s->outgoing_raw_data != NULL);

  SSH_DEBUG(5, ("Buffer contents: incoming %d bytes, outgoing %d bytes.",
                ssh_buffer_len(s->incoming_raw_data),
                ssh_buffer_len(s->outgoing_raw_data)));

  if (s->extra.deleted_notify != NULL_FNPTR)
    (*(s->extra.deleted_notify))(s->extra.deleted_notify_context);

  if (s->stream != NULL)
    ssh_stream_destroy(s->stream);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS

  /* TLS accelerator driver will cancel any incomplete crypto operations */
  if (s->conn.incoming.accel_ctx)
    tls_accel_free_key(s->conn.incoming.accel_ctx);
  if (s->conn.outgoing.accel_ctx)
    tls_accel_free_key(s->conn.outgoing.accel_ctx);

  ssh_buffer_init(s->incoming_raw_data);
  ssh_buffer_init(s->outgoing_raw_data);

  ssh_free(s->incoming_raw_data_buff);
  ssh_free(s->outgoing_raw_data_buff);
#else
  ssh_buffer_free(s->incoming_raw_data);
  ssh_buffer_free(s->outgoing_raw_data);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  ssh_tls_free_protocols(s);

  /* Connection states. */

  if (s->conn.incoming.cipher != NULL)
    ssh_cipher_free(s->conn.incoming.cipher);

  if (s->conn.incoming.mac != NULL)
    ssh_mac_free(s->conn.incoming.mac);

  if (s->conn.outgoing.cipher != NULL)
    ssh_cipher_free(s->conn.outgoing.cipher);

  if (s->conn.outgoing.mac != NULL)
    ssh_mac_free(s->conn.outgoing.mac);

  /* Key exhance state. */

  ssh_tls_clear_kex_state(s);

  memset(s->kex.server_random, 0, sizeof(s->kex.server_random));
  memset(s->kex.client_random, 0, sizeof(s->kex.client_random));
  memset(s->kex.master_secret, 0, sizeof(s->kex.master_secret));

  /* The temporary key object */

  if (s->kex.locked_temporary_key != NULL)
    ssh_tls_release_temporary_key(s->kex.locked_temporary_key);

  /* The group name. */

  ssh_free((void *)s->conf.group_name);

  /* The record itself! */

  ssh_tls_call_app_hook(s, SSH_TLS_VANISHED);

  ssh_free(s);

  SSH_DEBUG(7, ("Protocol context destroyed."));
}

void ssh_tls_kill_failed_state(SshTlsProtocolState s,
                               SshTlsFailureReason reason)
{
  SSH_DEBUG(4, ("Shutting down the TLS protocol %p immediately.", s));

  s->status = SSH_TLS_FAILED;
  s->failure_reason = reason;

  /* If there is an application packet being fed, drop it now. */

  if (s->packet_feed_len > 0)
    {
      SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >=
                 s->packet_feed_len + s->trailer_len);
      ssh_buffer_consume(s->incoming_raw_data, s->packet_feed_len +
                         s->trailer_len);
      s->trailer_len = -1;
      s->packet_feed_len = 0;
    }

  /* Clear the incoming raw data buffer. */
  ssh_buffer_clear(s->incoming_raw_data);

  if (!(s->flags & SSH_TLS_FLAG_DELETED))
    /* Tell the upper layer that it can read us so that it will get
       EOF and hopely destroy us. At this point, application writes
       and reads are no longer possible. However, we still want to
       drain the outgoing buffer because there can be an alert packet
       still waiting for transport.

       We give this notification even if the protocol is in the
       `frozen' state. */
    {
      ssh_tls_ready_for_reading(s);
      ssh_tls_ready_for_writing(s);
    }
  else
    ssh_tls_destroy_if_possible(s);
}

void ssh_tls_immediate_kill(SshTlsProtocolState s, SshTlsFailureReason reason)
{
  SSH_DEBUG(4, ("Shutting down the TLS protocol %p immediately.", s));

  /* Invalidate the session cache entry if it exists. */
  if (s->kex.id_len > 0 && s->conf.session_cache != NULL)
    {
      SSH_DEBUG(5, ("Invalidating the session cache entry."));
      ssh_tls_invalidate_cached_session(s->conf.session_cache,
                                        s->kex.session_id,
                                        s->kex.id_len);
    }

  ssh_tls_kill_failed_state(s, reason);

  /* Inform the application of failure */
  if ((s->flags & SSH_TLS_FLAG_DELETED) == 0)
    {
      if (!s->tls_error_app_hook_sent)
        {
          ssh_tls_call_app_hook(s, SSH_TLS_ERROR);
          s->tls_error_app_hook_sent = TRUE;
        }
    }

#if 0
  s->status = SSH_TLS_FAILED;
  s->failure_reason = reason;

  /* If there is an application packet being fed, drop it now. */

  if (s->packet_feed_len > 0)
    {
      SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >=
                 s->packet_feed_len + s->trailer_len);
      ssh_buffer_consume(s->incoming_raw_data, s->packet_feed_len +
                         s->trailer_len);
      s->trailer_len = -1;
      s->packet_feed_len = 0;
    }s

  /* Clear the incoming raw data buffer. */
  ssh_buffer_clear(s->incoming_raw_data);

  if (!(s->flags & SSH_TLS_FLAG_DELETED))
    /* Tell the upper layer that it can read us so that it will get
       EOF and hopely destroy us. At this point, application writes
       and reads are no longer possible. However, we still want to
       drain the outgoing buffer because there can be an alert packet
       still waiting for transport.

       We give this notification even if the protocol is in the
       `frozen' state. */
    {
      ssh_tls_ready_for_reading(s);
      ssh_tls_ready_for_writing(s);
    }
  else
    ssh_tls_destroy_if_possible(s);
#endif

}

void ssh_tls_alert_and_kill(SshTlsProtocolState s, int alert_message)
{
  ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL, alert_message);

  /* Alert messages can be cast to SshTlsFailureReasons directly. */
  ssh_tls_immediate_kill(s, (SshTlsFailureReason) alert_message);
}


void ssh_tls_destroy_if_possible(SshTlsProtocolState s)
{
  SSH_ASSERT((s->flags & SSH_TLS_FLAG_DELETED));

  if (!(s->flags & SSH_TLS_FLAG_FROZEN)
      && (ssh_buffer_len(s->outgoing_raw_data) == 0)
      && !(s->flags & SSH_TLS_FLAG_DESTROY_SCHEDULED))
    {
      SSH_DEBUG(6, ("Now scheduling the actual destroy function to "
                    "be called for %p.", s));
      s->flags |= SSH_TLS_FLAG_DESTROY_SCHEDULED;
      ssh_tls_cancel_unfragment_timeout(s);
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, s);
      ssh_xregister_timeout(0, 0, ssh_tls_actual_destroy, s);
    }
}

void ssh_tls_hanging_delete_callback(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_ASSERT(s->flags & SSH_TLS_FLAG_DELETED);

  ssh_buffer_clear(s->outgoing_raw_data);
  ssh_tls_destroy_if_possible(s);
}

/** Protocol initialization **/

static Boolean
register_higher_protocol(SshTlsProtocolState s,
                         SshTlsContentType type,
                         SshTlsProtocolProcessFunc func)
{
  SshTlsHigherProtocol p;

  if ((p = ssh_calloc(1, sizeof(*p))) != NULL)
    {
      p->type = type; p->func = func;
      if ((p->data = ssh_buffer_allocate()) == NULL)
        {
          ssh_free(p);
          return FALSE;
        }
      p->next = s->protocols;
      s->protocols = p;

      SSH_DEBUG(5, ("Registered a handler for the content type `%s'.",
                    ssh_tls_content_type_str(type)));
      return TRUE;
    }
  return FALSE;
}

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
/* Read callback for hardware accelerator device */
static void ssh_tls_accel_rd_cb(unsigned int events, void *context)
{
  int fd = tls_accel_get_rd_fd();
  SshTlsAccelCryptoResultRec rb;

  SSH_DEBUG(SSH_D_MY1, ("cb"));

  if (!(events & SSH_IO_READ))
    return;

  while (read(fd, &rb, sizeof(rb)) > 0)
    {
      SshTlsProtocolState s = rb.usr_ctx;
      /* Check if incoming or outgoing direction */
      if (s->conn.incoming.accel_ctx == rb.ctx)
        {
          SSH_DEBUG(SSH_D_MY1, ("Incoming %p %p", s, rb.ctx));
          /* Check that data has not moved in buffer */
          SSH_ASSERT(s->incoming_raw_data->offset == 0);
          SSH_ASSERT(s->conn.incoming.ops_pending > 0);
          s->conn.incoming.flags |= SSH_TLS_DECRYPT_DONE;
          s->conn.incoming.ops_pending--;
          if (rb.status != 0)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("HW decrypt failed 0x%x, len %d",
                         rb.status, rb.size));
              ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
              return;
            }
          if (s->conn.incoming.ops_pending == 0)
            ssh_tls_parse_incoming(s);
        }
      else if (s->conn.outgoing.accel_ctx == rb.ctx)
        {
          SSH_DEBUG(SSH_D_MY1, ("Outgoing %p %p", s, rb.ctx));
          SSH_ASSERT(s->conn.outgoing.ops_pending > 0);
          s->conn.outgoing.ops_pending--;
          /* Completed encryption of TLS record. It can be sent out. */
          s->pend_len -= rb.size;
          SSH_ASSERT(s->pend_len >= 0);
          if (rb.status != 0)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("HW encrypt failed 0x%x, len %d",
                         rb.status, rb.size));
              ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
              return;
            }
          /* Call all ops completed callback if it's set */
          if (s->outgoing_all_complete_cb && s->conn.outgoing.ops_pending == 0)
            {
              void (*cb)(struct ssh_tls_protocol_state *) =
                s->outgoing_all_complete_cb;
              s->outgoing_all_complete_cb = NULL;
              cb(s);
            }
          ssh_tls_try_write_out(s);
        }
      else
        SSH_ASSERT(FALSE);
    }
}
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

SshStream ssh_tls_generic_wrap(SshStream stream,
                               SshTlsConfiguration configuration)
{
  SshStream newp = NULL;
  SshTlsProtocolState s;

  SSH_DEBUG(7, ("Creating a new TLS protocol instance (%s).",
                configuration->is_server ? "server" : "client"));

  if (configuration->max_buffered_data < SSH_TLS_MAX_RECORD_LENGTH + 1000)
    {
      SSH_DEBUG(SSH_D_ERROR, ("TLS protocol: buffer maximum size must be "
                              "at least %d bytes.",
                              (SSH_TLS_MAX_RECORD_LENGTH + 1000)));
      return NULL;
    }

  /* Allocate state. */
  if ((s = ssh_calloc(1, sizeof(*s))) == NULL)
    return NULL;

  /* Copy the configuration record. Do this first because
     e.g. ssh_tls_initialize_kex depends on the configuration
     information. */
  memcpy(&s->conf, configuration, sizeof(s->conf));

  /* Duplicate the group_name (if given) in the local copy. */
  if (s->conf.group_name != NULL)
    {
      if ((s->conf.group_name = ssh_strdup(s->conf.group_name)) == NULL)
        goto fail;
    }

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (!(configuration->flags & (SSH_TLS_SSL3 | SSH_TLS_TLS | SSH_TLS_TLS1_1)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("The TLS configuration must support either "
                              "SSL3 or TLS."));
      goto fail;
    }
#else
  if (!(configuration->flags & (SSH_TLS_TLS | SSH_TLS_TLS1_1 )))
    {
      SSH_DEBUG(SSH_D_ERROR, ("The TLS configuration must support TLS as "
                              "SSL3 support is not compiled in."));
      goto fail;
    }
#endif

  /* Initialize the main record. */
  s->magic = SSH_TLS_MAGIC_NUMBER;

  /* This is the initial version number that will show up in the
     record layer header of the first ClientHello packet. For servers
     the initial version number is set to zero to denote that the
     version is still unknown. */

  if (configuration->is_server)
    {
      s->protocol_version.major = s->protocol_version.minor = 0;
    }
  else
    {
      s->protocol_version.major = 3;
      s->protocol_version.minor = SSH_TLS_VER_TLS1_1;

#ifdef SSH_TLS_SSL_3_0_COMPAT
      /* Start with SSL3.0 if requested. */
      if (configuration->flags & SSH_TLS_SSL3)
        s->protocol_version.minor = 0;
#endif

      if (configuration->flags & SSH_TLS_TLS)
        s->protocol_version.minor = SSH_TLS_VER_TLS1_0;
      if (configuration->flags & SSH_TLS_TLS1_1)
        s->protocol_version.minor = SSH_TLS_VER_TLS1_1;
      SSH_DEBUG(6, ("TLS version configured is %d.%d",
                      s->protocol_version.major, s->protocol_version.minor));
    }
  s->incoming_raw_data = ssh_buffer_allocate();
  s->outgoing_raw_data = ssh_buffer_allocate();

  if (!s->incoming_raw_data || !s->outgoing_raw_data)
    goto fail;

  s->built_len = 0;
  s->built_content_type = SSH_TLS_CTYPE_APPDATA; /* arbitrary */
  s->stream = stream;
  s->flags = SSH_TLS_INITIAL_FLAGS;

  s->packet_feed_len = s->trailer_len = 0;
  s->stream_callback = NULL_FNPTR;
  s->stream_callback_context = NULL;
  s->status = SSH_TLS_STARTING_UP;
  s->failure_reason = SSH_TLS_NO_FAILURE;
  s->protocols = NULL;

  /* Statistics */
  s->stats.packets_sent = s->stats.packets_received = s->stats.bytes_sent =
    s->stats.bytes_received = s->stats.num_key_exchanges =
    s->stats.num_context_changes = 0L;
  s->stats.app_bytes_given = s->stats.app_bytes_got = 0L;

  /* Get the remote IP and port address of the underlying stream if this
     is a TCP stream. */
  if (!ssh_tcp_get_remote_address(stream, s->stats.remote_address,
                                  sizeof(s->stats.remote_address)))
    strcpy(ssh_sstr(s->stats.remote_address), "?.?.?.?");

  if (!ssh_tcp_get_remote_port(stream, s->stats.remote_port,
                               sizeof(s->stats.remote_port)))
    strcpy(ssh_sstr(s->stats.remote_port), "??");

  SSH_DEBUG(4, ("New connection from %s:%s",
                s->stats.remote_address, s->stats.remote_port));

  /* Initialize the key exchange state. */
  if (!ssh_tls_initialize_kex(s))
    goto fail;

  /* Initialize the connection states. */
  s->conn.incoming.cipher = NULL;
  s->conn.incoming.is_stream_cipher = FALSE;
  s->conn.incoming.mac = NULL;
  s->conn.incoming.mac_length = 0;
  SSH_TLS_ZERO_SEQ(s->conn.incoming.seq);

  s->conn.outgoing.cipher = NULL;
  s->conn.outgoing.is_stream_cipher = FALSE;
  s->conn.outgoing.mac = NULL;
  s->conn.outgoing.mac_length = 0;
  SSH_TLS_ZERO_SEQ(s->conn.outgoing.seq);

  s->conn.incoming.flags = 0;
  s->conn.incoming.current_len = 0;
  s->conn.outgoing.flags = 0;
  s->conn.outgoing.current_len = 0;

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS

  s->pend_len = 0;

  /* With hardware acceleration, use fixed size raw data buffers to prevent
     them to be reallocated while hw-assisted crypto operations are in
     progress. */
  {
    int size = s->conf.max_buffered_data + SSH_TLS_EXTRA_RAW_DATA_ROOM;
    s->incoming_raw_data_buff = ssh_calloc(1, size);
    s->outgoing_raw_data_buff = ssh_calloc(1, size);

    if (!s->incoming_raw_data_buff || !s->outgoing_raw_data_buff)
      goto fail;

    ssh_buffer_wrap(s->incoming_raw_data, s->incoming_raw_data_buff, size);
    ssh_buffer_wrap(s->outgoing_raw_data, s->outgoing_raw_data_buff, size);
    s->incoming_raw_data_buff = NULL;
    s->outgoing_raw_data_buff = NULL;
  }

  /* Context for data hardware acceleration */
  s->conn.incoming.accel_ctx = NULL;
  s->conn.incoming.ops_pending = 0;
  s->conn.outgoing.accel_ctx = NULL;
  s->conn.outgoing.ops_pending = 0;
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  /* Initialize the `extra' record. */
  s->extra.deleted_notify = NULL_FNPTR;
  s->extra.deleted_notify_context = NULL;

  s->extra.flags = 0L;

  /* Register the protocol handlers. */
  if (!register_higher_protocol(s,
                                SSH_TLS_CTYPE_HANDSHAKE,
                                ssh_tls_kex_process) ||
      !register_higher_protocol(s,
                                SSH_TLS_CTYPE_ALERT,
                                ssh_tls_alert_process) ||
      !register_higher_protocol(s,
                                SSH_TLS_CTYPE_CHANGE_CIPHER,
                                ssh_tls_cc_process))
    {
      SSH_DEBUG(3, ("Can not register higher protocols."));
      goto fail;
    }

  /* Create a new stream and steal the underlying stream's callbacks. */
  SSH_DEBUG(7, ("Changing the underlying stream's callbacks for %p.", s));
  newp = ssh_stream_create(&ssh_tls_methods, s);

  if (newp == NULL)
    goto fail;

  ssh_stream_set_callback(stream, ssh_tls_stream_callback, s);

  s->app_stream = newp;

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  tls_accel_open(ssh_tls_accel_rd_cb);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  SSH_DEBUG(7, ("New TLS protocol instance %p is ready.", s));

  /* If we are a client, a connection cache exists and a group name
     has been given, try to find a session ID for a session that could
     be resumed. */

  if (!(s->conf.is_server) && (s->conf.session_cache != NULL)
      && (s->conf.group_name != NULL))
  {
    SshTlsCachedSession c =
      ssh_tls_find_cached_by_group(s->conf.session_cache,
                                   s->conf.group_name);
    if (c != NULL)
      {
        SSH_DEBUG(6, ("Found a cached context for the group `%s', so "
                      "try to use it.", s->conf.group_name));
        s->kex.id_len = c->id_len;
        memcpy(s->kex.session_id, c->session_id, c->id_len);
        memcpy(s->kex.master_secret, c->master_secret, 48);
        s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;
        s->kex.cipher_suite = c->cipher_suite;

        s->kex.peer_certs = ssh_tls_duplicate_ber_cert_chain(c->peer_certs);

        /* As we are trying to reuse the session, use the protocol
           version used in it. */
        s->protocol_version.major = c->protocol_version.major;
        s->protocol_version.minor = c->protocol_version.minor;
        s->kex.client_version.major = c->protocol_version.major;
        s->kex.client_version.minor = c->protocol_version.minor;
      }
  }

  /* Inform the application of a new connection request. */
  ssh_tls_call_app_hook(s, SSH_TLS_NEW_CONNECTION_REQUEST);

  /* Then call the key exchange dispatch. */
  ssh_tls_kex_dispatch(s, 0, NULL, 0);

  return newp;

 fail:
  if (s != NULL)
    {
      if (s->incoming_raw_data)
        ssh_buffer_free(s->incoming_raw_data);

      if (s->outgoing_raw_data)
        ssh_buffer_free(s->outgoing_raw_data);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      if (s->incoming_raw_data_buff)
        ssh_free(s->incoming_raw_data_buff);

      if (s->outgoing_raw_data_buff)
        ssh_free(s->outgoing_raw_data_buff);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

      if (s->conf.group_name)
        ssh_free((void *)s->conf.group_name);

      ssh_free(s);
    }

  return NULL;
}

SshStream ssh_tls_server_wrap(SshStream stream,
                              SshTlsConfiguration configuration)
{
  SSH_ASSERT(configuration->is_server == TRUE);
  return ssh_tls_generic_wrap(stream, configuration);
}

SshStream ssh_tls_client_wrap(SshStream stream,
                              SshTlsConfiguration configuration)
{
  SSH_ASSERT(configuration->is_server == FALSE);
  return ssh_tls_generic_wrap(stream, configuration);
}

/** Other external interfaces **/

SshTlsCipherSuite ssh_tls_get_ciphersuite(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  return s->kex.cipher_suite;
}

SshTlsStatus ssh_tls_get_status(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  return s->status;
}

SshTlsFailureReason ssh_tls_get_failure_reason(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  return s->failure_reason;
}

SshTlsCertQueryResult ssh_tls_get_cert_chain(SshStream stream,
                                             SshTlsBerCert *chain_return)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  if (s->kex.query_status == SSH_TLS_CERT_OK)
    {
      *chain_return = s->kex.peer_certs;
    }
  return s->kex.query_status;
}

int ssh_tls_get_cache_id(SshStream stream,
                         unsigned char **session_id_return)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  *session_id_return = s->kex.session_id;
  return s->kex.id_len;
}


void ssh_tls_grab_certs(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  SSH_ASSERT(s->kex.query_status == SSH_TLS_CERT_OK);
  s->kex.flags |= SSH_TLS_KEX_GRABBED_CERTS;
}

#ifdef SSHDIST_VALIDATOR

Boolean ssh_tls_chain_verified_by_cm(SshStream stream)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  return ((s->kex.flags & SSH_TLS_KEX_CERT_VERIFIED_CM) != 0);
}

Boolean ssh_tls_get_cm_status(SshStream stream,
                              SshCMSearchInfo *info)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  if (s->kex.flags & SSH_TLS_KEX_CM_INFO_VALID)
    {
      *info = &(s->kex.cm_info);
      return TRUE;
    }
  return FALSE;
}

#endif /* SSHDIST_VALIDATOR */

void ssh_tls_decide_new_connection_request(SshStream stream, Boolean accept)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);

  if (accept)
    s->kex.flags &= ~SSH_TLS_KEX_REJECT_NEW_CONNECTION_REQUEST;
  else
    s->kex.flags |= SSH_TLS_KEX_REJECT_NEW_CONNECTION_REQUEST;
}

void ssh_tls_decide_certs(SshStream stream, Boolean accept)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);

  if (accept)
    s->kex.flags |= SSH_TLS_KEX_CERT_VERIFIED;
  else
    s->kex.flags &= ~SSH_TLS_KEX_CERT_VERIFIED;
}

void ssh_tls_set_private_key(SshStream stream, SshPrivateKey key,
                             unsigned char *id_data, size_t id_data_size)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  s->conf.private_key = key;
  s->conf.id_data = id_data;
  s->conf.id_data_size = id_data_size;
}

void ssh_tls_get_statistics(SshStream stream,
                            SshTlsStatistics ptr)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  memcpy(ptr, &(s->stats), sizeof(*ptr));
}

void ssh_tls_configuration_defaults(SshTlsConfiguration conf)
{
#ifdef SSHDIST_VALIDATOR
  conf->cert_manager = NULL;
  conf->trusted_set_peer_validation = NULL;
  conf->trusted_set_own_root = NULL;
#else /* SSHDIST_VALIDATOR */
  conf->own_certs = NULL;
#endif /* SSHDIST_VALIDATOR */

  conf->private_key = NULL;
  conf->id_data = NULL;
  conf->id_data_size = 0;
  conf->session_cache = NULL;
  conf->group_name = NULL;
  conf->temporary_key = NULL;
  conf->app_callback = NULL_FNPTR;
  conf->app_callback_context = NULL;
  conf->flags = SSH_TLS_SSL3 | SSH_TLS_TLS | SSH_TLS_TLS1_1;
  conf->is_server = FALSE;
  conf->unfragment_delay = 100L; /* 100 usec */
  conf->preferred_suites = NULL;
  conf->suggested_ca_distinguished_names = NULL;
  conf->crl_check_policy = SSH_TLS_CRL_CHECK_NEVER;
  conf->max_buffered_data = 131072; /* 2^17 */
  conf->fast_rekey_interval = 3600L; /* one hour */
  conf->fast_rekey_bytes = 1073741824L; /* one gigabyte */
  conf->full_rekey_interval = 0L; /* never */
  conf->full_rekey_bytes = 0L; /* never */
  conf->key_exchange_timeout = 600; /* 10 minutes */

}

SshTlsConfiguration ssh_tls_allocate_configuration(void)
{
  SshTlsConfiguration ptr;

  if ((ptr = ssh_calloc(1, sizeof(*ptr))) != NULL)
    ssh_tls_configuration_defaults(ptr);
  return ptr;
}








void ssh_tls_destroy_configuration(SshTlsConfiguration conf)
{
  int i;
  if (!conf)
    return;

  if (conf->temporary_key)
    ssh_tls_destroy_temporary_key(conf->temporary_key);

  if (conf->suggested_ca_distinguished_names)
    {
      for (i = 0; conf->suggested_ca_distinguished_names[i]; i++)
        ssh_free(conf->suggested_ca_distinguished_names[i]);
      ssh_free(conf->suggested_ca_distinguished_names);
    }

  if (conf->id_data)
    {
      ssh_free(conf->id_data);
      conf->id_data = NULL;
    }

#ifdef SSHDIST_VALIDATOR
  if (conf->cert_manager)
    ssh_cm_free(conf->cert_manager);

  if (conf->trusted_set_peer_validation)
    ssh_mprz_free(conf->trusted_set_peer_validation);
  if (conf->trusted_set_own_root)
    ssh_mprz_free(conf->trusted_set_own_root);
#else /* SSHDIST_VALIDATOR */
  if (conf->own_certs)
    ssh_tls_free_cert_chain(conf->own_certs);
#endif /* SSHDIST_VALIDATOR */

  ssh_free(conf);
  return;
}

/** Misc. **/

const char *ssh_tls_content_type_str(SshTlsContentType type)
{
  switch (type)
    {
    case SSH_TLS_CTYPE_APPDATA:
      return "application data";

    case SSH_TLS_CTYPE_ALERT:
      return "alert";

    case SSH_TLS_CTYPE_CHANGE_CIPHER:
      return "change cipher";

    case SSH_TLS_CTYPE_HANDSHAKE:
      return "handshake";

    default:
      return "unknown";
    }
}

Boolean ssh_tls_supported_version(SshTlsProtocolState s,
                                  unsigned char major, unsigned char minor)
{
  /* The major version must be 3. */
  if (major != 3) return FALSE;

  /* The minor version must be 0 or 1 or 2. */
  if (minor != 0 && minor != 1  && minor != 2) return FALSE;

  /* The minor version cannot be 1 if TLS or TLS1.1 is not supported. */
  if (!(s->conf.flags & SSH_TLS_TLS)
                  && !(s->conf.flags & SSH_TLS_TLS1_1) && minor == 1)
    return FALSE;

  /* The minor version cannot be 0 if SSL3 is not supported. */
  if (!(s->conf.flags & SSH_TLS_SSL3) && minor == 0) return FALSE;

  return TRUE;
}

void ssh_tls_degrade_version(SshTlsProtocolState s,
                             unsigned char *major, unsigned char *minor)
{
 redo:
  /* If the major version number has changed try to fall back to
     TLS 3.1. */
  if (*major > 3)
    {
      *major = 3; *minor = 1;
      goto redo;
    }

  /* Cannot degrade if the major version is smaller than three. */
  if (*major < 3)
    {
      return;
    }

  /* If the major version is three and the minor version is
     greater than 2, set the minor version to 2. */
  if (*minor > 2)
    {
      *minor = 2;
      goto redo;
    }

  /* If the minor version is 1 and TLS is not supported, fall to
     SSL3. */
  if (*minor == 1 && !(s->conf.flags & SSH_TLS_TLS))
    {
      *minor = 0;
      goto redo;
    }

  /* If the minor version is 2 and TLS1.1 is not supported, fall to
     TLS1.0. */
  if (*minor == 2 && !(s->conf.flags & SSH_TLS_TLS1_1))
    {
      *minor = 1;
      goto redo;
    }

  return;
}

SSH_TLS_PROTOCOL_VER ssh_tls_version(SshTlsProtocolState s)
{
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 2)
    return SSH_TLS_VER_TLS1_1;
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 1)
    return SSH_TLS_VER_TLS1_0;
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    return SSH_TLS_VER_SSL3;

  return SSH_TLS_VER_UNKNOWN;
}

SshTlsProtocolState ssh_tls_cast_stream(SshStream stream)
{
  SshTlsProtocolState s;
  SSH_PRECOND(stream != NULL);
  s = ssh_stream_get_context(stream);
  SSH_VERIFY(s != NULL && s->magic == SSH_TLS_MAGIC_NUMBER);
  return s;
}

void ssh_tls_call_app_hook(SshTlsProtocolState s,
                           SshTlsAppNotification notification)
{
  if (s->conf.app_callback != NULL_FNPTR)
    {
      (*(s->conf.app_callback))(s->app_stream,
                                notification,
                                s->conf.app_callback_context);
    }
}


#ifdef SSHDIST_EAP_TLS
Boolean ssh_tls_get_eap_master_key(SshStream stream,
                                   unsigned char **key,
                                   size_t *keylen)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  unsigned char random_buf[64];
  unsigned char *buf;

  if (!(s->kex.flags & SSH_TLS_KEX_HAVE_MASTER_SECRET))
    {
      SSH_DEBUG(SSH_D_FAIL, ("TLS master key not yet generated"));
      return FALSE;
    }
  if ((buf = ssh_malloc(64)) == NULL)
    return FALSE;

  memcpy(random_buf, s->kex.client_random, 32);
  memcpy(random_buf + 32, s->kex.server_random, 32);

  ssh_tls_prf(s->kex.master_secret, 48,
              (unsigned char *)"client EAP encryption",
              strlen("client EAP encryption"),
              random_buf, 64,
              buf, 64);

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("EAP TLS master key computed"), buf, 64);

  *keylen = 64;
  *key = buf;
  return TRUE;
}

Boolean ssh_tls_get_eap_session_id(SshStream stream,
                                   unsigned char **id,
                                   size_t *idlen)
{
  SshTlsProtocolState s = ssh_tls_cast_stream(stream);
  unsigned char *buf;

  if (!(s->kex.flags & SSH_TLS_KEX_HAVE_MASTER_SECRET))
    {
      SSH_DEBUG(SSH_D_FAIL, ("TLS master key not yet generated"));
      return FALSE;
    }
  if ((buf = ssh_malloc(65)) == NULL)
    return FALSE;

  buf[0] = 0x0d;
  memcpy(buf + 1, s->kex.client_random, 32);
  memcpy(buf + 33, s->kex.server_random, 32);

  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("EAP session id computed"), buf, 65);

  *idlen = 65;
  *id = buf;
  return TRUE;
}
#endif /* SSHDIST_EAP_TLS */

