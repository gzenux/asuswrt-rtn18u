/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements interfacing with the application that is using
   the TLS library. The functions ssh_tls_stream_read,
   ssh_tls_stream_write, ssh_tls_stream_destroy,
   ssh_tls_stream_output_eof and ssh_tls_stream_set_callback
   correspond to the five SshStream methods (see sshstream.h) of the
   stream that is returned to the application after TLS wrapping.

   ssh_tls_ready_for_reading and ssh_tls_ready_for_writing are
   functions that are called by the TLS library. They give the
   application a notification that new data can be read or written,
   but only if the application is expecting the notificiation
   according to the SshStream interface.

   These functions consult the state of the protocol, mainly in the
   fields SshTlsProtocolState.status and SshTlsProtocolState.flags, to
   decide what to do.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"

#define SSH_DEBUG_MODULE "SshTlsAppstream"

static void trigger_rekey_if_needed(SshTlsProtocolState s)
{
  s->kex.flags &= ~(SSH_TLS_KEX_VIRGIN_AFTER_FAST_REKEY |
                    SSH_TLS_KEX_VIRGIN_AFTER_FULL_REKEY);

  /* Trigger rekey if the data limits have been reached. */
  if (s->kex.full_rekey_data_limit > 0 &&
      s->stats.app_bytes_given + s->stats.app_bytes_got >=
      s->kex.full_rekey_data_limit)
    {
      ssh_tls_cancel_rekeying_timeouts(s);
      ssh_xregister_timeout(0L, 0L, ssh_tls_full_rekey_timeout, s);
      return;
    }

  if (s->kex.fast_rekey_data_limit > 0 &&
      s->stats.app_bytes_given + s->stats.app_bytes_got >=
      s->kex.fast_rekey_data_limit)
    {
      ssh_tls_cancel_rekeying_timeouts(s);
      ssh_xregister_timeout(0L, 0L, ssh_tls_fast_rekey_timeout, s);
      return;
    }
}

int ssh_tls_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_ASSERT(size > 0);
  SSH_ASSERT(s->packet_feed_len >= 0);

  SSH_DEBUG(7, ("The upper layer wants to read max. %d bytes of data.", size));

 reread_after_further_parsing:
  if (SSH_TLS_IS_FAILED_STATUS(s->status))
    {
      SSH_DEBUG(7, ("Protocol is in error condition so give EOF."));
      return 0;
    }

  if (s->packet_feed_len == 0)
    {
      SSH_DEBUG(7, ("Nothing to give (%d bytes in buffer).",
                    ssh_buffer_len(s->incoming_raw_data)));

      if (s->flags & SSH_TLS_FLAG_GOT_CLOSE_NOTIFY)
        {
          SSH_DEBUG(7, ("The protocol stream has closed, thus send EOF."));

          /* This is it. Now it is upto the application to kill us if
             it wants. Of course, data can be still sent. */
          return 0;
        }
      SSH_DEBUG(7, ("App. data packet totally consumed, trailer %d bytes.",
                    s->trailer_len));
      if (s->trailer_len >= 0)
        {
          SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >= s->trailer_len);
          ssh_buffer_consume(s->incoming_raw_data, s->trailer_len);
          s->trailer_len = -1;

          /* Now we need to call ssh_tls_parse_incoming because it is possible
             that there are more full packets in the incoming_raw_data buffer
             waiting for parsing. */
          ssh_tls_parse_incoming(s);
          goto reread_after_further_parsing;
        }

      s->flags |= SSH_TLS_FLAG_GIVE_READ_NOTIFY;
      SSH_DEBUG(7, ("Set flags to %x.", (unsigned int) s->flags));
      return -1;
    }

  if (size > s->packet_feed_len) size = s->packet_feed_len;
  memcpy(buf, ssh_buffer_ptr(s->incoming_raw_data), size);
  SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >= size + s->trailer_len);
  ssh_buffer_consume(s->incoming_raw_data, size);
  s->packet_feed_len -= size;

  SSH_DEBUG(7, ("%d bytes written to the buffer, %d to feed.",
                size, s->packet_feed_len));

  s->stats.app_bytes_given += size;

  trigger_rekey_if_needed(s);

  SSH_ASSERT(s->packet_feed_len >= 0);

  if (s->packet_feed_len == 0)
    {
      SSH_DEBUG(7, ("App. data packet totally consumed, trailer %d bytes.",
                    s->trailer_len));
      SSH_ASSERT(s->trailer_len >= 0);
      SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data) >= s->trailer_len);
      ssh_buffer_consume(s->incoming_raw_data, s->trailer_len);
      s->trailer_len = -1;

      /* Now we need to call ssh_tls_parse_incoming because it is possible
         that there are more full packets in the incoming_raw_data buffer
         waiting for parsing. */
      ssh_tls_parse_incoming(s);
    }

  /* Now that the incoming raw data buffer has been perhaps shrunk,
     try to read more data in. */
  if ((s->flags & SSH_TLS_FLAG_READING_CEASED)
      &&
      ssh_buffer_len(s->incoming_raw_data) < s->conf.max_buffered_data)
    {
      SSH_DEBUG(7, ("Try to read in more data as reading had been "
                    "temporarily stopped and now there is more room."));
      ssh_tls_try_read_in(s);
    }

  return size;
}

int ssh_tls_stream_write(void *context, const unsigned char *buf, size_t size)
{
  int iv_len = 0; /*CBCATT, TLS1.1: need space for storing random IV*/

  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(7, ("The upper layer wants to write max. %d bytes of data.",
                size));

  /* If this assert fails it is an application error. */
  SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_OUTPUT_EOF));

  if (SSH_TLS_IS_FAILED_STATUS(s->status))
    {
      SSH_DEBUG(7, ("Do not accept more application data as the "
                    "protocol is being shut down."));
      return 0;
    }

  if (s->flags & SSH_TLS_FLAG_STREAM_WRITE_CLOSED)
    {
      SSH_DEBUG(7, ("The underlying stream does not accept data any more, "
                    "thus return zero."));
      return 0;
    }

  if (!(s->flags & SSH_TLS_FLAG_INITIAL_KEX_DONE))
    {
      SSH_DEBUG(7, ("Do not accept application data yet as the initial "
                    "key exchange has not been finished."));

      /* We need to notify the application when the KEX has been finished. */
      s->flags |= SSH_TLS_FLAG_GIVE_WRITE_NOTIFY;
      return -1;
    }

  if (s->kex.state != SSH_TLS_KEX_CLEAR)
    {
      SSH_DEBUG(7, ("Do not send application data now as a key exchange "
                    "is in progress."));

      /* We need to notify the application when the KEX has been finished. */
      s->flags |= SSH_TLS_FLAG_GIVE_WRITE_NOTIFY;
      return -1;
    }

  if ((s->conn.outgoing.cipher) && !s->conn.outgoing.is_stream_cipher
                  && SSH_TLS_VER_TLS1_1 == ssh_tls_version(s))
    {
      iv_len = s->conn.outgoing.block_length;
      SSH_DEBUG(6, ("Adjusting for CBCATT random IV size %d", iv_len));
    }

  /* Check that we do not create a too long packet. */
  if (s->built_len == 0)
    {
      if (size > SSH_TLS_MAX_RECORD_LENGTH - iv_len)
        size = SSH_TLS_MAX_RECORD_LENGTH - iv_len;
    }
  else
    {
      if (size + s->built_len >
          SSH_TLS_MAX_RECORD_LENGTH + SSH_TLS_HEADER_SIZE - iv_len)
        size = (SSH_TLS_MAX_RECORD_LENGTH + SSH_TLS_HEADER_SIZE) -
          s->built_len - iv_len;
    }

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  {
    int bytes = ssh_tls_appstream_can_write_bytes(s);

    if (bytes < size)
      size = bytes;
#else
  {
    long l = ssh_buffer_len(s->outgoing_raw_data);

    if (size + l > s->conf.max_buffered_data)
      {
        if (l > s->conf.max_buffered_data)
          size = 0;
        else
          size = s->conf.max_buffered_data - l;
      }
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

    if (size == 0)
      {
        SSH_DEBUG(7, ("Cannot fit more data into the outgoing data buffer"));
        s->flags |= SSH_TLS_FLAG_GIVE_WRITE_NOTIFY;
        return -1;
      }
  }

  if (s->conf.flags & SSH_TLS_FIX_IV_LEAK)
    {
      ssh_tls_start_building(s, SSH_TLS_CTYPE_APPDATA);
      ssh_tls_flush(s);
    }
  ssh_tls_start_building(s, SSH_TLS_CTYPE_APPDATA);

  if (ssh_buffer_append(s->outgoing_raw_data, buf, size) == SSH_BUFFER_OK)
    {
      s->built_len += size;
      s->stats.app_bytes_got += size;
    }
  else
    {
      SSH_DEBUG(7, ("The send buffer can not fit any more data "
                    "thus return zero."));
      return 0;
    }

  trigger_rekey_if_needed(s);

  /* Check for a long packet that could be sent immediately.  This
     covers also those maximum-length packets that have been
     `truncated' above. */
  if (s->built_len > SSH_TLS_MAX_RECORD_LENGTH / 2)
    {
      SSH_DEBUG(6, ("Long packet, flush immediately."));
      ssh_tls_flush(s);
    }

  return size;
}

void ssh_tls_stream_output_eof(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(7, ("Got output eof from the upper layer."));

  s->flags |= SSH_TLS_FLAG_OUTPUT_EOF;
}

void ssh_tls_stream_destroy(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_DELETED));

  /* Drop the notification flags so that the application will not get
     a notification whatever happens. The flags can be raised again
     only if the application tries to access the deleted stream ---
     which is an error, of course. */
  s->flags &= ~(SSH_TLS_FLAG_GIVE_WRITE_NOTIFY |
                SSH_TLS_FLAG_GIVE_READ_NOTIFY);

  /* Cancel the kex timeout and the time-critical parts of the key
     exchange process. */
  ssh_tls_cancel_kex_timeout(s);
  ssh_tls_cancel_kex(s);

  /* Cancel the rekeying timeouts immediately. */
  ssh_tls_cancel_rekeying_timeouts(s);

  SSH_DEBUG(5, ("Got destroy request from the application level."));

  ssh_xregister_timeout(10L, 0L, ssh_tls_hanging_delete_callback,
                       (void *)s);

  /* If the protocol has been running correctly this far and the close
     notify has not yet been sent and the application has denoted that
     it will write no more, send the close notify now and change to
     the `terminated' status. */
  if (s->status == SSH_TLS_READY && (s->flags & SSH_TLS_FLAG_OUTPUT_EOF))
    {
      SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_SENT_CLOSE_NOTIFY));
      SSH_DEBUG(5, ("Sending close notify now."));
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_WARNING,
                                 SSH_TLS_ALERT_CLOSE_NOTIFY);
      s->flags |= SSH_TLS_FLAG_SENT_CLOSE_NOTIFY;
      s->status = SSH_TLS_TERMINATED;
    }
  else
    {
      if (s->status == SSH_TLS_READY || s->status == SSH_TLS_STARTING_UP)
        {
          SSH_DEBUG(5, ("The user has destroyed the TLS stream prematurely."));

          if (s->status == SSH_TLS_STARTING_UP)
            {
              ssh_tls_send_alert_message(s, SSH_TLS_ALERT_WARNING,
                                         SSH_TLS_ALERT_USER_CANCELED);
            }

          ssh_tls_send_alert_message(s, SSH_TLS_ALERT_WARNING,
                                     SSH_TLS_ALERT_CLOSE_NOTIFY);

          s->flags |= SSH_TLS_FLAG_DELETED;

          /* This will invalidate the session cache entry although
             we sent the close_notify message. */
          ssh_tls_immediate_kill(s, SSH_TLS_FAIL_USER_CANCELED);
          return;
        }
    }

  s->flags |= SSH_TLS_FLAG_DELETED;
  ssh_tls_flush(s);

  /* Stop reading at this point. */
  ssh_buffer_clear(s->incoming_raw_data);
  s->packet_feed_len = 0;
  s->trailer_len = -1;

  ssh_tls_destroy_if_possible(s);
}

void ssh_tls_stream_set_callback(void *context,
                                 SshStreamCallback callback,
                                 void *callback_context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(7, ("Upper level has registered its stream callback."));

  s->stream_callback = callback;
  s->stream_callback_context = callback_context;

  if (s->stream_callback != NULL_FNPTR)
    {
      (*s->stream_callback)(SSH_STREAM_INPUT_AVAILABLE,
                            s->stream_callback_context);
      (*s->stream_callback)(SSH_STREAM_CAN_OUTPUT,
                            s->stream_callback_context);
    }
}

void ssh_tls_ready_for_reading(SshTlsProtocolState s)
{
  if (s->flags & SSH_TLS_FLAG_GIVE_READ_NOTIFY)
    {
      SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_DELETED));
      SSH_DEBUG(7, ("TLS stream is ready for reading, "
                    "giving the read notification."));
      s->flags &= ~SSH_TLS_FLAG_GIVE_READ_NOTIFY;

      if (s->stream_callback != NULL_FNPTR)
        (*s->stream_callback)(SSH_STREAM_INPUT_AVAILABLE,
                              s->stream_callback_context);
    }
  else
    {
      SSH_DEBUG(7, ("TLS stream is ready for reading, "
                    "but the user doesn't expect a notification (flags %x).",
                    (unsigned int) s->flags));
    }
}

void ssh_tls_ready_for_writing(SshTlsProtocolState s)
{
  if (s->flags & SSH_TLS_FLAG_GIVE_WRITE_NOTIFY)
    {
      SSH_ASSERT(!(s->flags & SSH_TLS_FLAG_DELETED));
      SSH_DEBUG(7, ("TLS stream is ready for writing, "
                    "giving the write notification."));
      s->flags &= ~SSH_TLS_FLAG_GIVE_WRITE_NOTIFY;

      if (s->stream_callback != NULL_FNPTR)
        (*s->stream_callback)(SSH_STREAM_CAN_OUTPUT,
                              s->stream_callback_context);
    }
  else
    {
      SSH_DEBUG(7, ("TLS stream is ready for writing, "
                    "but the user doesn't expect a notification."));
    }
}

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
/* Get number of bytes application can write to a stream */
int ssh_tls_appstream_can_write_bytes(SshTlsProtocolState s)
{
  const int SSH_TLS_MAX_APP_DATA_PENDING = 2;

  /* With HW-acceleration, preallocated buffers are used. Therefore check
     for space available for application data. */
  long space = ssh_buffer_space(s->outgoing_raw_data) -
    SSH_TLS_EXTRA_RAW_DATA_ROOM;

  if (space <= 0)
    return 0;

  /* When using hardware acceleration, the driver has a limit of max. 6
     outstanding crypto operations. 2 app, 3 kex and alert. If there is
     already a request pending, let application wait. */
  if (s->conn.outgoing.ops_pending >= SSH_TLS_MAX_APP_DATA_PENDING)
      return 0;

  return space;
}
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
