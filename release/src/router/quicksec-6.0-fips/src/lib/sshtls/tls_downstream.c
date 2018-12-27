/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements interfacing with the underlying transport
   stream. ssh_tls_read_in reads data from the stream and calls
   ssh_tls_parse_incoming if some data is
   received. ssh_tls_try_read_in tries to read data, unless the
   EXPECT_READ_NOTIFY flag is set, in which case we know that the read
   will fail anyway and do not read at all.  Similarly, there exist
   ssh_tls_write_out and ssh_tls_try_write_out.  Finally,
   ssh_tls_stream_callback is the stream callback for the underlying
   stream.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshmalloc.h"

#define SSH_DEBUG_MODULE "SshTlsDownstream"

void ssh_tls_read_in(SshTlsProtocolState s)
{
  int l;
  int r;
  int allocated;
  int total_read;
  unsigned char *newp;

redo:
  if (s->flags & SSH_TLS_FLAG_STREAM_EOF) return;
  if (s->flags & SSH_TLS_FLAG_DELETED)    return;

  l = ssh_buffer_len(s->incoming_raw_data);

  if (l >= s->conf.max_buffered_data)
    {
      /* There must be a packet in the input buffer because the input
         buffer is larger than the maximum packet size. The packet is
         not parsed yet because an output packet is being fed or there
         is a KEX transition in progress. */
      SSH_DEBUG(7, ("Input buffer already full."));
      s->flags |= SSH_TLS_FLAG_READING_CEASED;
      return;
    }

  total_read = 0;
  allocated = s->conf.max_buffered_data - l;
  if (ssh_buffer_append_space(s->incoming_raw_data, &newp, allocated)
      != SSH_BUFFER_OK)
    {
      SSH_DEBUG(7, ("Can not allocate space for input."));
      s->flags |= SSH_TLS_FLAG_READING_CEASED;
      return;
    }

  s->flags &= ~SSH_TLS_FLAG_READING_CEASED;

  while (total_read < allocated)
    {
      r = ssh_stream_read(s->stream, newp, allocated - total_read);
      if (r < 0)
        {
          SSH_DEBUG(7, ("The underlying stream blocks for %p.", s));

          /* Next time we will get a notification. */
          s->flags |= SSH_TLS_FLAG_EXPECT_READ_NOTIFY;
          SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data)
                     >= allocated - total_read);
          ssh_buffer_consume_end(s->incoming_raw_data, allocated - total_read);
          goto finished;
        }

      if (r == 0)
        {
          SSH_DEBUG(7, ("EOF received from the underlying stream for %p.", s));
          s->flags |= SSH_TLS_FLAG_STREAM_EOF;
          SSH_ASSERT(ssh_buffer_len(s->incoming_raw_data)
                     >= allocated - total_read);
          ssh_buffer_consume_end(s->incoming_raw_data, allocated - total_read);

          /* We need to call this even if total_read == 0 because
             ssh_tls_parse_incoming checks if we have got EOF but not
             a close notify; this is a fatal error can causes e.g.
             the session cache entry to be invalidated. */
          goto finished;
        }

      SSH_DEBUG(7, ("Read %d bytes in for %p.", r, s));
      total_read += r;
      s->stats.bytes_received += r;
      newp += r;                 /* Advance the pointer. */
    }
  SSH_DEBUG(7, ("Input buffer for %p is now full.", s));
  ssh_tls_parse_incoming(s);
  goto redo;

 finished:
  ssh_tls_parse_incoming(s);
  return;
}

void ssh_tls_try_read_in(SshTlsProtocolState s)
{
  if (!(s->flags & SSH_TLS_FLAG_EXPECT_READ_NOTIFY))
    ssh_tls_read_in(s);
}

void ssh_tls_write_out(SshTlsProtocolState s)
{
  int l;
  int r;
#ifndef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  Boolean was_full = FALSE;     /* Set if the outgoing raw data buffer
                                   was full so that it is possible
                                   that application write has failed. */
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  if (s->flags & SSH_TLS_FLAG_STREAM_WRITE_CLOSED)
    return;

  l = ssh_buffer_len(s->outgoing_raw_data);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  /* Subtract those bytes that correspond to a partially built packet or
     packets pending crypto completion, they cannot be sent yet. */
  l -= s->built_len + s->pend_len +
    SSH_TLS_HEADER_SIZE * s->conn.outgoing.ops_pending;
#else
  if (l >= s->conf.max_buffered_data)
    was_full = TRUE;

  /* Subtract those bytes that correspond to a partially built packet */
  l -= s->built_len;
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  SSH_ASSERT(l >= 0);

  if (l == 0)
    return;

  while (l > 0)
    {
      SSH_DEBUG(7, ("Writing data to the underlying stream for %p (%d bytes).",
                    s, l));

      r = ssh_stream_write(s->stream, ssh_buffer_ptr(s->outgoing_raw_data), l);

      SSH_DEBUG(7, ("Stream write returned %d.", r));

      if (r == 0)
        {
          SSH_DEBUG(7, ("The underlying stream has closed the writing "
                        "direction."));
          SSH_DEBUG(7, ("%d bytes of data discarded from the buffer.", l));

          s->flags |= SSH_TLS_FLAG_STREAM_WRITE_CLOSED;
          ssh_buffer_clear(s->outgoing_raw_data);
          s->built_len = 0;

          /* It can be that we cannot write the close notify message
             but that is not a real problem. The standard explicitly
             mentions that it needs not to be possible to actually
             send the close notify. The other party will not receive a
             close notify, which will make the session non-resumeable
             for it. I don't claim TLS to be the best protocol I've
             seen. */

          /* Now that the output buffer is empty, delete the protocol
             if that is possible. */

          if (s->flags & SSH_TLS_FLAG_DELETED)
            {
              ssh_tls_destroy_if_possible(s);
            }

          return;
        }

      if (r < 0)
        {
          /* Next time we will get a notification. */
          s->flags |= SSH_TLS_FLAG_EXPECT_WRITE_NOTIFY;

          /* Give notification to the application if necessary. */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
          if (ssh_tls_appstream_can_write_bytes(s) > 0)
            ssh_tls_ready_for_writing(s);
#else
          if (was_full &&
              ssh_buffer_len(s->outgoing_raw_data) < s->conf.max_buffered_data)
            ssh_tls_ready_for_writing(s);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
          return;
        }

      SSH_ASSERT(ssh_buffer_len(s->outgoing_raw_data) >= r);
      ssh_buffer_consume(s->outgoing_raw_data, r);
      s->stats.bytes_sent += r;
      l -= r;
    }
  SSH_DEBUG(7, ("Output buffer does not contain data that could be sent."));

  /* Now that the output buffer is empty... see above. */

  if (s->flags & SSH_TLS_FLAG_DELETED)
    {
      /* There should not be any partially built packet after the protocol
         has been scheduled for deletion. */
      SSH_ASSERT(s->built_len == 0);
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      if (s->conn.outgoing.ops_pending == 0)
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
      ssh_tls_destroy_if_possible(s);
    }
  else
    {
      SSH_ASSERT(ssh_buffer_len(s->outgoing_raw_data)
                 < s->conf.max_buffered_data);

      /* Give notification to the application if necessary. */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
      {
        /* We use fixed size buffer when hw-acceleration is configured. Call
           ssh_buffer_append_space() with huge length. It will fail but move
           data at the beginning of SshBuffer and make room at buffer end.
           This can only be done when there are no outstanding crypto
           operations pending completion. Otherwise the data in buffer would
           move and ruin crypto. */
        unsigned char *ptr;
        if (s->conn.outgoing.ops_pending == 0)
          ssh_buffer_append_space(s->outgoing_raw_data, &ptr, 0x1000000);
      }

    if (ssh_tls_appstream_can_write_bytes(s) > 0)
      ssh_tls_ready_for_writing(s);
#else
      if (was_full)
        ssh_tls_ready_for_writing(s);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
    }
}

void ssh_tls_try_write_out(SshTlsProtocolState s)
{
  if (!(s->flags & SSH_TLS_FLAG_EXPECT_WRITE_NOTIFY))
    ssh_tls_write_out(s);
}

void ssh_tls_stream_callback(SshStreamNotification notification,
                             void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      s->flags &= ~(SSH_TLS_FLAG_EXPECT_READ_NOTIFY);
      SSH_DEBUG(7, ("Got SSH_STREAM_INPUT_AVAILABLE from the underlying "
                    "stream for %p.", s));
      ssh_tls_read_in(s);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      s->flags &= ~(SSH_TLS_FLAG_EXPECT_WRITE_NOTIFY);
      SSH_DEBUG(7, ("Got SSH_STREAM_CAN_OUTPUT from the underlying "
                    "stream for %p.", s));
      ssh_tls_write_out(s);
      break;

    case SSH_STREAM_DISCONNECTED:
      SSH_DEBUG(5, ("The underlying stream for %p disconnected!", s));

      /* No more notifications are to be expected. */
      s->flags &= ~(SSH_TLS_FLAG_EXPECT_WRITE_NOTIFY |
                    SSH_TLS_FLAG_EXPECT_READ_NOTIFY);

      /* Both EOF and the write direction have been closed. */
      s->flags |= SSH_TLS_FLAG_STREAM_WRITE_CLOSED |
          SSH_TLS_FLAG_STREAM_EOF;

      /* Clear the outgoing data buffer. */
      ssh_buffer_clear(s->outgoing_raw_data);
      s->built_len = 0;

      /* Parse incoming data now, actually mainly for checking
         error conditions. */
      ssh_tls_parse_incoming(s);
      break;
    }
}
