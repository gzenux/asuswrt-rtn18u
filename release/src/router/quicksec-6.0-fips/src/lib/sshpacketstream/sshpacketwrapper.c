/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This module implements a wrapper around SshStream for sending/receiving
   packets.  This has a simple interface based on a few function calls and
   callbacks, making it easy to do packet-based communications over a
   SshStream.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshstream.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshpacketstream.h"
#include "sshpacketint.h"

#define SSH_DEBUG_MODULE "SshPacketWrapper"

#define ALLOW_AFTER_BUFFER_FULL          (17 * 65536 + 5)
#define BUFFER_MAX_SIZE                 (200 * 65536)


struct SshPacketWrapperRec
{
  /* The underlying stream going down.  This stream will be automatically
     closed when we are destroyed. */
  SshStream stream;

  /* SshBuffer for incoming data (downwards). */
  SshBufferStruct incoming;
  Boolean incoming_eof;

  /* SshBuffer for outgoing data (downwards). */
  SshBufferStruct outgoing;
  Boolean outgoing_eof;

  /* SshBuffer for constructing outgoing packets. */
  SshBufferStruct outgoing_packet;

  /* Flag indicating that ssh_packet_wrapper_can_send has returned FALSE, and
     thus we should call the can_send callback when sending is again
     possible. */
  Boolean send_blocked;

  /* Flag indicating whether we can receive.  This flag can be set by
     the application using ssh_packet_wrapper_can_receive. */
  Boolean can_receive;

  /* Flag indicating whether we can receive.  This flag is internal to
     the library and should not be manipulated by the application. */
  Boolean can_receive_internal;

  /* Flag indicating that we have been destroyed, but the destroy has been
     postponed until buffers have drained. */
  Boolean destroy_pending;

  /* If TRUE, we are in a callback in a situation where we cannot destroy
     immediately.  If this is true in a destroy, destroy_requested is set
     to TRUE, and destroy will be called when possible. */
  Boolean cannot_destroy;

  /* Set to TRUE to request immediate destroy after returning from a
     callback. */
  Boolean destroy_requested;

  /* Flag indicating that we have shortcircuited the stream.  If this is
     FALSE but shortcircuit_up_stream is non-NULL, we have a shortcircuit
     pending as soon as downward buffers have drained. */
  Boolean shortcircuited;

  /* The stream to which we have shortcircuited.  NULL if not shortcircuited
     and no shortcircuit pending. */
  SshStream shortcircuit_up_stream;

  /* Application callbacks. */
  SshPacketReceiveProc received_packet;
  SshPacketEofProc received_eof;
  SshPacketCanSendProc can_send;
  size_t max_packet_size;
  void *context;

  /* Rewrap callback.  This is normally NULL, unless a rewrap operation
     is pending. */
  SshPacketRewrapProc rewrap_cb;
  void *rewrap_context;

  /* Timeout structs for register/cancel timeouts */
  SshTimeoutStruct can_output_timeout;
  SshTimeoutStruct input_available_timeout;
};

/* Some prototypes. */
void ssh_packet_wrapper_callback(SshStreamNotification op, void *context);


/* Fake an INPUT AVAILABLE callback from the packet stream. */

void ssh_packet_wrapper_fake_input_available(void *context)
{
  SshPacketWrapper down = (SshPacketWrapper)context;

  ssh_packet_wrapper_callback(SSH_STREAM_INPUT_AVAILABLE, down);
}

/* Fake an CAN OUTPUT callback from the packet stream. */

void ssh_packet_wrapper_fake_can_output(void *context)
{
  SshPacketWrapper down = (SshPacketWrapper)context;

  ssh_packet_wrapper_callback(SSH_STREAM_CAN_OUTPUT, down);
}

/* Destroys the protocol context immediately.  Closes the downward stream
   and frees memory. */

void ssh_packet_wrapper_destroy_now(SshPacketWrapper down)
{
  ssh_cancel_timeouts(ssh_packet_wrapper_fake_input_available, down);
  ssh_cancel_timeouts(ssh_packet_wrapper_fake_can_output, down);

  /* Close the downward stream. */
  ssh_stream_destroy(down->stream);

  /* Uninitialize buffers. */
  ssh_buffer_uninit(&down->incoming);
  ssh_buffer_uninit(&down->outgoing);
  ssh_buffer_uninit(&down->outgoing_packet);

  ssh_free(down);
}

/* This function outputs as much data from internal buffers to the downward
   stream.  This returns TRUE if something was successfully written. */

Boolean ssh_packet_wrapper_output(SshPacketWrapper down)
{
  int len;
  Boolean return_value = FALSE;

  /* Loop while we have data to output.  When all data has been sent,
     we check whether we need to send EOF. */
  while (ssh_buffer_len(&down->outgoing) > 0)
    {
      /* Write as much data as possible. */
      len = ssh_stream_write(down->stream, ssh_buffer_ptr(&down->outgoing),
                             ssh_buffer_len(&down->outgoing));
      if (len < 0)
        return return_value;  /* Cannot write more now. */
      if (len == 0)
        {
          /* EOF on output; will not be able to write any more. */
          down->outgoing_eof = TRUE;
          ssh_buffer_clear(&down->outgoing);
          return TRUE;
        }

      /* Consume written data. */
      ssh_buffer_consume(&down->outgoing, len);

      SSH_DEBUG(7, ("Wrote %d bytes of data.", len));

      /* We've done something, so return TRUE. */
      return_value = TRUE;
    }

  /* If there a scheduled rewrap operation, call it now. */
  if (down->rewrap_cb)
    {
      SshStream new_stream;

      new_stream = (*down->rewrap_cb)(down->stream, down->rewrap_context);
      down->rewrap_cb = NULL;
      if (new_stream)
        {
          down->stream = new_stream;
          /* Set callback for the downward stream.  Note that this
             will also cause can_send to be called from the output
             callback. */
          ssh_stream_set_callback(down->stream, ssh_packet_wrapper_callback,
                                  (void *)down);
          return_value = TRUE; /* This will cause read to be done. */
        }
      else
        {
          down->outgoing_eof = TRUE;
          down->incoming_eof = TRUE;
        }
    }

  /* All output has drained.  There is no more buffered data. */
  if (down->send_blocked)
    {
      down->send_blocked = FALSE;
      down->cannot_destroy = TRUE;
      if (down->can_send)
        (*down->can_send)(down->context);
      down->cannot_destroy = FALSE;
      if (down->destroy_requested)
        {
          ssh_packet_wrapper_destroy(down);
          return FALSE;
        }
    }

  /* If we should send EOF after output has drained, do it now. */
  if (down->outgoing_eof)
    ssh_stream_output_eof(down->stream);

  /* If we get here and the stream is shortcircuited, that means we had
     output data to drain before shortcircuiting. */
  if (down->shortcircuit_up_stream && !down->shortcircuited)
    {
      down->shortcircuited = TRUE;
      ssh_packet_impl_shortcircuit_now(down->shortcircuit_up_stream,
                                       down->stream);
    }

  /* If there's a destroy pending (that is, waiting for buffers to drain),
     do the destroy now. */
  if (down->destroy_pending)
    {
      /* Destroy the context now.  This also closes the stream. */
      ssh_packet_wrapper_destroy_now(down);

      /* Return FALSE to ensure that the loop in ssh_packet_wrapper_callback
         exits without looking at the context again. */
      return FALSE;
    }

  return return_value;
}

/* Reads as much data as possible from the downward stream, assuming we can
   receive packets.  Passes any received packets to the appropriate callbacks.
   Returns TRUE if packets were successfully received. */

Boolean ssh_packet_wrapper_input(SshPacketWrapper down)
{
  size_t data_to_read, data_read;
  int ret;
  unsigned char *ptr;
  SshPacketType type;
  Boolean return_value = FALSE;

  for (;;)
    {
      /* If we cannot receive, return immediately. */
      if (!down->can_receive ||
          !down->can_receive_internal ||
          down->incoming_eof ||
          down->destroy_pending ||
          down->shortcircuit_up_stream != NULL ||
          down->rewrap_cb != NULL)
        return return_value;

      /* Get length of data read so far. */
      data_read = ssh_buffer_len(&down->incoming);

      /* Add enough space to buffer for reading either header or
         entire packet.  This also sets `ptr' to point to the place
         where data should be read, and `data_to_read' to the number
         of bytes that should be there after reading (should read
         data_to_read - data_read bytes). */
      if (data_read < 4)
        {
          /* Packet header not yet in buffer.  Read only header if we can
             make space for it. If not, return. */
          data_to_read = 4;
          if (ssh_buffer_append_space(&down->incoming, &ptr, 4 - data_read)
              != SSH_BUFFER_OK)
            {
              return return_value;
            }
        }
      else
        {
          /* Packet header already in buffer. */
          ptr = ssh_buffer_ptr(&down->incoming);
          data_to_read = 4 + SSH_GET_32BIT(ptr);
          if (data_to_read < 5 || data_to_read > down->max_packet_size)
            {
              ssh_warning("ssh_packet_wrapper_input: "
                          "invalid packet received: len %ld "
                          "closing the offending input channel",
                          (long)data_to_read);

              down->incoming_eof = TRUE;
              /* Pass the EOF to the application callback. */
              down->cannot_destroy = TRUE;
              if (down->received_eof)
                (*down->received_eof)(down->context);
              down->cannot_destroy = FALSE;
              if (down->destroy_requested)
                ssh_packet_wrapper_destroy(down);
              return FALSE;
            }
          SSH_ASSERT(data_to_read >= data_read);
          if (ssh_buffer_append_space(&down->incoming,
                                      &ptr,
                                      data_to_read - data_read)
              != SSH_BUFFER_OK)
            {
              /* Assume upper protocol recovers/terminates if
                 malformed packet is received. */
              return FALSE;
            }
        }

      /* Keep reading until entire packet read, or no more data available. */
      while (data_read < data_to_read)
        {
          /* Try to read the remaining bytes. */
          ptr = (unsigned char *)ssh_buffer_ptr(&down->incoming) + data_read;
          ret = ssh_stream_read(down->stream, ptr, data_to_read - data_read);
          if (ret < 0)
            {
              /* No more data available at this time.  Remove
                 allocated but unread space from end of buffer. */
              ssh_buffer_consume_end(&down->incoming,
                                     data_to_read - data_read);
              return return_value;
            }

          if (ret == 0)
            {
              /* EOF received. */
              ssh_buffer_consume_end(&down->incoming,
                                     data_to_read - data_read);
              down->incoming_eof = TRUE;

              /* Pass the EOF to the application callback. */
              down->cannot_destroy = TRUE;
              if (down->received_eof)
                (*down->received_eof)(down->context);
              down->cannot_destroy = FALSE;
              if (down->destroy_requested)
                {
                  ssh_packet_wrapper_destroy(down);
                  return FALSE;
                }
              return TRUE;
            }

          if (data_read < 4 && data_read + ret >= 4)
            {
              /* Header has now been fully received.  Prepare to receive rest
                 of packet. */
              data_read += ret;
              ptr = ssh_buffer_ptr(&down->incoming);
              data_to_read = 4 + SSH_GET_32BIT(ptr);
              if (data_to_read < 5 || data_to_read > down->max_packet_size)
                {
                  ssh_warning("ssh_packet_wrapper_input: "
                              "invalid packet received: len %ld "
                              "closing the offending input channel.",
                              (long)data_to_read);
                  down->incoming_eof = TRUE;
                  /* Pass the EOF to the application callback. */
                  down->cannot_destroy = TRUE;
                  if (down->received_eof)
                    (*down->received_eof)(down->context);
                  down->cannot_destroy = FALSE;
                  if (down->destroy_requested)
                    ssh_packet_wrapper_destroy(down);
                  return FALSE;
                }

              if (data_to_read > data_read)
                {
                  if (ssh_buffer_append_space(&down->incoming,
                                              &ptr,
                                              data_to_read - data_read)
                      != SSH_BUFFER_OK)
                    {
                      return FALSE;
                    }
                }
            }
          else
            data_read += ret;
        }

      /* An entire packet has been received. */
      SSH_ASSERT(ssh_buffer_len(&down->incoming) == data_to_read);

      /* Process this packet just once. */
      down->can_receive_internal = FALSE;
      /* Get packet type. */
      ptr = ssh_buffer_ptr(&down->incoming);
      type = (SshPacketType)ptr[4];
      /* Call the application callback if set. */
      down->cannot_destroy = TRUE;
      if (down->received_packet)
        (*down->received_packet)(type, ptr + 5, data_to_read - 5,
                                 down->context);
      down->cannot_destroy = FALSE;
      if (down->destroy_requested)
        {
          ssh_packet_wrapper_destroy(down);
          return FALSE;
        }
      ssh_buffer_clear(&down->incoming);
      down->can_receive_internal = TRUE;
      return_value = TRUE;
    }
  /*NOTREACHED*/
}

/* Callback function for the lower-level stream.  This receives notifications
   when we can read/write data from the lower-level stream. */

void ssh_packet_wrapper_callback(SshStreamNotification op, void *context)
{
  SshPacketWrapper down = (SshPacketWrapper)context;
  Boolean ret = TRUE;

  /* Process the notification.  We loop between input and output
     operations until one returns FALSE (they return TRUE if the other
     operation should be performed). */
  while (ret == TRUE)
    {
      ret = FALSE;

      switch (op)
        {
        case SSH_STREAM_CAN_OUTPUT:
          ret = ssh_packet_wrapper_output(down);
          op = SSH_STREAM_INPUT_AVAILABLE;
          break;

        case SSH_STREAM_INPUT_AVAILABLE:
          ret = ssh_packet_wrapper_input(down);
          op = SSH_STREAM_CAN_OUTPUT;
          break;

        case SSH_STREAM_DISCONNECTED:
          ssh_debug("ssh_packet_wrapper_callback: disconnected");
          break;

        default:
          ssh_fatal("ssh_packet_wrapper_callback: unknown op %d", (int)op);
        }
      /* Note: `down' might have been destroyed by now.  In that case
         `ret' is FALSE. */
    }
}

/* Creates a packet stream wrapper around the given stream.
   This returns a wrapper handle.  The handle should be destroyed with
   ssh_packet_wrapper_destroy when no longer needed.  This takes over the
   stream, and the stream will be automatically closed when the wrapper
   is destroyed.  It is not legal to access the stream directly.
      `stream'               stream to lower-level protocol (or network)
      `received_packet'      called when a packet is received
      `received_eof'         called when EOF is received
      `can_send'             called when we can send after not being able to
      `context'              passed as argument to callbacks

   Any of the functions can be NULL if not needed.  It is guaranteed that
   the callbacks will not be called until from the bottom of the event
   loop.  This gives the caller a chance to store the returned pointer
   somewhere before one of the callbacks gets called.  Destroying the
   SshPacketWrapper object is legal in any callback.

   The stream will be ready to receive packets immediately.  If
   receiving packets immediately is not desirable,
   ssh_packet_wrapper_can_receive should be called immediately after
   creation to prevent receiving packets.  Note: Even though the
   ssh_packet_wrapper_can_send returns TRUE, the can_send callback may
   be called, so care should be taken not to send the same data
   multiple times. */

SshPacketWrapper ssh_packet_wrap(SshStream down_stream,
                                 SshPacketReceiveProc received_packet,
                                 SshPacketEofProc received_eof,
                                 SshPacketCanSendProc can_send,
                                 void *context)
{
  SshPacketWrapper down;
  unsigned char *datap;
  size_t data_len;

  if ((down = ssh_calloc(1, sizeof(*down))) == NULL)
    return NULL;
  down->stream = down_stream;
  ssh_buffer_init(&down->incoming);
  ssh_buffer_init(&down->outgoing);
  ssh_buffer_init(&down->outgoing_packet);
  down->incoming_eof = FALSE;
  down->outgoing_eof = FALSE;
  down->send_blocked = TRUE;
  down->can_receive = FALSE;
  down->can_receive_internal = TRUE;
  down->destroy_pending = FALSE;
  down->cannot_destroy = FALSE;
  down->destroy_requested = FALSE;
  down->shortcircuited = FALSE;

  /* Preallocate some buffer space */
  data_len = 1024;
  if ((ssh_buffer_append_space(&down->incoming, &datap, data_len)
       != SSH_BUFFER_OK) ||
      (ssh_buffer_append_space(&down->outgoing, &datap, data_len)
       != SSH_BUFFER_OK) ||
      (ssh_buffer_append_space(&down->outgoing_packet, &datap, data_len)
       != SSH_BUFFER_OK))
    {
      ssh_buffer_uninit(&down->incoming);
      ssh_buffer_uninit(&down->outgoing);
      ssh_buffer_uninit(&down->outgoing_packet);
      ssh_free(down);
      return NULL;
    }
  ssh_buffer_clear(&down->incoming);
  ssh_buffer_clear(&down->outgoing);
  ssh_buffer_clear(&down->outgoing_packet);

  /* Save the callback functions. */
  down->received_packet = received_packet;
  down->received_eof = received_eof;
  down->can_send = can_send;
  down->context = context;
  down->max_packet_size = BUFFER_MAX_SIZE;

  /* Set callback for the downward stream.  Note that this will also cause
     can_send to be called from the output callback. */
  ssh_stream_set_callback(down->stream, ssh_packet_wrapper_callback,
                          (void *)down);

  /* Enable receives. */
  ssh_packet_wrapper_can_receive(down, TRUE);

  return down;
}

/* Sets maximum packet size that can be received on the wrapper.
   This can be used to limit the amount of memory that an attacker can
   consume. */

void ssh_packet_wrapper_set_maxpacket(SshPacketWrapper down,
                                      size_t max_packet_size)
{
  down->max_packet_size = max_packet_size;
}

/* Destroys the wrapper object, and closes the underlying stream.  None
   of the callbacks will be called after this has been called.  Any
   buffered data will be sent out before the stream is actually
   closed.  The wrapper pointer and the stream object will be invalid after
   this has been called. */

void ssh_packet_wrapper_destroy(SshPacketWrapper down)
{
  /* Clear the callbacks so that user functions are not called. */
  down->received_packet = NULL_FNPTR;
  down->received_eof = NULL_FNPTR;
  down->can_send = NULL_FNPTR;

  /* If we cannot destroy at this time, set the proper flag and return
     immediately without destroying.  This happens in some callbacks.
     The code after the callback will check for the flag and call destroy
     again if set. */
  if (down->cannot_destroy)
    {
      down->destroy_requested = TRUE;
      return;
    }

  down->destroy_pending = TRUE;

  if (ssh_buffer_len(&down->outgoing) == 0)
    ssh_packet_wrapper_destroy_now(down);
}

/* Informs the packet stream wrapper whether `received_packet' can be
   called.  This is used for flow control. */

void ssh_packet_wrapper_can_receive(SshPacketWrapper down, Boolean status)
{
  down->can_receive = status;
  if (status == TRUE)
    {
      /* Schedule a fake can receive callback. */
      ssh_cancel_timeout(&down->input_available_timeout);
      ssh_register_timeout(&down->input_available_timeout,
                           0, 0, ssh_packet_wrapper_fake_input_available,
                           down);
    }
}

/* Sends EOF to the packet stream (after sending out any buffered data).
   It is illegal to send any packets after calling this. */

void ssh_packet_wrapper_send_eof(SshPacketWrapper down)
{
  /* If EOF already sent, return immediately. */
  if (down->outgoing_eof)
    return;

  /* Otherwise, send EOF now. */
  down->outgoing_eof = TRUE;
  if (ssh_buffer_len(&down->outgoing) == 0)
    ssh_stream_output_eof(down->stream);
}

/* Returns TRUE if it is OK to send more data.  It is not an error to
   send small amounts of data (e.g. a disconnect) when this returns
   FALSE, but sending lots of data when this returns FALSE will
   eventually cause packets to be lost.  To give a specific value, it
   is OK to send 10000 bytes after this starts returning FALSE (this
   provision exists to avoid checks in every disconnect and debug
   message). */

Boolean ssh_packet_wrapper_can_send(SshPacketWrapper down)
{
  Boolean status;

  status = ssh_buffer_len(&down->outgoing) <
    BUFFER_MAX_SIZE - ALLOW_AFTER_BUFFER_FULL;

  /* If no more can be sent, mark that sending is blocked.  This will
     trigger a callback when data can again be sent. */
  if (!status)
    down->send_blocked = TRUE;

  return status;
}

/* Sends a packet to the underlying stream.  The payload will be encoded as
   specified for ssh_encode_buffer_va. */

Boolean ssh_packet_wrapper_send_encode_va(SshPacketWrapper down,
                                          SshPacketType type,
                                          va_list va)
{
  /* Check if eof has been encountered on output. */
  if (down->outgoing_eof)
    return FALSE;

  /* Format the packet in a separate buffer. */
  ssh_buffer_clear(&down->outgoing_packet);

  if (ssh_packet_encode_va(&down->outgoing_packet, type, va) == 0)
    return FALSE;

  /* Check that we don't overflow maximum buffer size.  Drop the packet
     if we would. */
  if (ssh_buffer_len(&down->outgoing) +
      ssh_buffer_len(&down->outgoing_packet) >= BUFFER_MAX_SIZE)
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("ssh_packet_wrapper_send_encode_va: flow control problems; "
                 "outgoing packet dropped."));
      down->send_blocked = TRUE;
      return FALSE;
    }

  /* Append the packet to the outgoing buffer. */
  if (ssh_buffer_append(&down->outgoing,
                        ssh_buffer_ptr(&down->outgoing_packet),
                        ssh_buffer_len(&down->outgoing_packet))
      != SSH_BUFFER_OK)
    return FALSE;

  /* Cause our callback to be called, so that the data is actually sent.
     (We don't send it directly here so that callbacks are only called
     from the bottom of the event loop). */
  ssh_cancel_timeout(&down->can_output_timeout);
  ssh_register_timeout(&down->can_output_timeout,
                       0, 0, ssh_packet_wrapper_fake_can_output, down);

  return TRUE;
}

/* Sends a packet to the underlying stream.  The payload will be encoded as
   specified for ssh_encode_buffer. */

Boolean ssh_packet_wrapper_send_encode(SshPacketWrapper down,
                                       SshPacketType type,
                                       ...)
{
  va_list va;
  Boolean status;

  va_start(va, type);
  status = ssh_packet_wrapper_send_encode_va(down, type, va);
  va_end(va);

  return status;
}

/* Sends a packet to the underlying stream.  The packet may actually
   get buffered and sent later.  Packets will always get sent in
   sequence.  The application should use ssh_packet_wrapper_can_send and
   the `can_send' callback to implement flow control. */

Boolean ssh_packet_wrapper_send(SshPacketWrapper down, SshPacketType type,
                                const unsigned char *data, size_t len)
{
  return ssh_packet_wrapper_send_encode(down, type,
                                        SSH_ENCODE_DATA(data, len),
                                        SSH_FORMAT_END);
}

/* Set callbacks (and context) to new values. */
void ssh_packet_wrapper_set_callbacks(SshPacketWrapper wrapper,
                                      SshPacketReceiveProc received_packet,
                                      SshPacketEofProc received_eof,
                                      SshPacketCanSendProc can_send,
                                      void *context)
{
  SSH_PRECOND(wrapper != NULL);
  wrapper->received_packet = received_packet;
  wrapper->received_eof = received_eof;
  wrapper->can_send = can_send;
  wrapper->context = context;
}

/* Causes any I/O requests from `packet_stream' (which must be implemented
   using the ssh_impl_* functions in this module) to be shortcircuited to
   the stream inside `wrapper', and vice versa.  The `received_packet',
   `received_eof', and `can_send' callbacks will no longer be called for
   either object.  This will automatically allow sends/receives in each
   direction as appropriate.  This can only be called from a SshPacketWrapper
   `received_packet' callback.

   The `destroy' callback is not shortcircuited, and should destroy the
   wrapper and any other data that might have been allocated.

   The primary purpose is to allow a protocol module (e.g., an authentication
   module) to shortcircuit any traffic through it. */

void ssh_packet_shortcircuit(SshStream packet_stream,
                             SshPacketWrapper wrapper)
{
  /* Mark that the stream is shortcircuited. */
  wrapper->shortcircuited = FALSE;
  wrapper->shortcircuit_up_stream = packet_stream;

#if 0 /* the packet is still in wrapper->incoming when we call the callback */
  /* Sanity check: there must not be data in incoming buffer. */
  if (ssh_buffer_len(&wrapper->incoming) != 0)
    ssh_fatal("ssh_packet_shortcircuit: incoming data in buffer; not set "
              "in packet callback");
#endif /* 0 */

  /* If there is no data to drain, shortcircuit output now. */
  if (ssh_buffer_len(&wrapper->outgoing) == 0)
    {
      wrapper->shortcircuited = TRUE;
      ssh_packet_impl_shortcircuit_now(wrapper->shortcircuit_up_stream,
                                       wrapper->stream);
    }
}

/* This function requests that as soon as the internal send buffer is empty,
   the underlying stream should be wrapped into another stream before
   continuing to receive.  This function schedules a call to the `wrap_cb'
   callback as soon as buffers are empty.  This prevents reading from the
   underlying stream until the `wrap_cb' has been called.  The `wrap_cb'
   should return a valid stream or NULL; if it returns NULL, it is interpreted
   as an error, and `received_eof' will be called for the wrapper.
   The typical use of this function would be to initiate TLS on a
   packet-wrapped connection in the middle of the connection. */
void ssh_packet_wrapper_rewrap(SshPacketWrapper wrapper,
                               SshPacketRewrapProc wrap_cb,
                               void *context)
{
  wrapper->rewrap_cb = wrap_cb;
  wrapper->rewrap_context = context;

  /* Try to output buffered data.  This will also perform the wrapping
     if the buffers are empty (if they are not empty, the wrapping will
     get performed when they are empty). */
  ssh_packet_wrapper_output(wrapper);
}
