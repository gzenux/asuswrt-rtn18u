/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This module implements a SshStream that sends/receives packets.  This has
   a simple interface based on a few function calls and callbacks, making it
   easy to do packet-based communications over a SshStream.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshstream.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshpacketstream.h"
#include "sshpacketint.h"

#define SSH_DEBUG_MODULE "SshPacketImplementation"

#define ALLOW_AFTER_BUFFER_FULL         (10000 + 5)
#define BUFFER_MAX_SIZE                 50000

typedef struct SshPacketImplRec {
  /* SshBuffer for a partial incoming packet. */
  SshBufferStruct incoming;

  /* Flag indicating whether the callback may be called (determines whether
     we can receive more data). */
  Boolean can_receive;

  /* Flag indicating whether EOF has been received from up. */
  Boolean incoming_eof;

  /* This flag is TRUE if a write by the upper protocol has failed, and
     we need to call its callback when more data can again be written. */
  Boolean up_write_blocked;

  /* This flag is TRUE if a read by the upper protocol has failed, and
     we need to call its callback when more data is available. */
  Boolean up_read_blocked;

  /* This flag is TRUE if ssh_packet_impl_can_send has returned FALSE. */
  Boolean send_blocked;

  /* SshBuffer for outgoing data. */
  SshBufferStruct outgoing;

  /* SshBuffer for formatting outgoing packet. */
  SshBufferStruct outgoing_packet;

  /* Outgoing EOF. */
  Boolean outgoing_eof;

  /* Shortcircuit stream.  This is NULL if shortcircuiting not in effect. */
  SshStream shortcircuit_stream;

  /* Callbacks to the actual protocol implementation code. */

  SshPacketReceiveProc received_packet;
  SshPacketEofProc received_eof;
  SshPacketCanSendProc can_send;
  SshPacketImplDestroyProc destroy;
  void *context;

  /* Callbacks for the upwards stream. */
  SshStreamCallback up_callback;
  void *up_context;

} *SshPacketImpl;

/* Signals the module above us that it can write more data to the stream. */

void ssh_packet_impl_signal_output_proc(void *context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  if (up->up_callback)
    (*up->up_callback)(SSH_STREAM_CAN_OUTPUT, up->up_context);
}

/* Signals the module above us that it can read more data from the stream. */

void ssh_packet_impl_signal_input_proc(void *context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  if (up->up_callback)
    (*up->up_callback)(SSH_STREAM_INPUT_AVAILABLE, up->up_context);
}

/* Signals the implementation that more data can again be sent up. */

void ssh_packet_impl_signal_send_proc(void *context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  if (up->can_send)
    (*up->can_send)(up->context);
}

/* If output is blocked, restarts output (in the view of the upper module;
   in other words, tell the upper module that it can write to the stream
   now). */

void ssh_packet_impl_restart_output(SshPacketImpl up)
{
  if (up->up_write_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_xregister_timeout(0L, 0L, ssh_packet_impl_signal_output_proc,
                           (void *)up);
      up->up_write_blocked = FALSE;
    }
}

/* If input is blocked, restarts input (in the view of the upper module;
   in other words, tell the upper module that it can read from the stream
   now). */

void ssh_packet_impl_restart_input(SshPacketImpl up)
{
  if (up->up_read_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_xregister_timeout(0L, 0L, ssh_packet_impl_signal_input_proc,
                           (void *)up);
      up->up_read_blocked = FALSE;
    }
}

/* If sends are blocked, restarts sends (in the view of the implementation;
   in other words, tell the implementation that there is space in the buffer
   for more packets to be sent. */

void ssh_packet_impl_restart_send(SshPacketImpl up)
{
  if (up->send_blocked)
    {
      /* Schedule an event from which we'll call the callback.  The event
         is cancelled if the stream is destroyed. */
      ssh_xregister_timeout(0L, 0L, ssh_packet_impl_signal_send_proc,
                           (void *)up);
      up->send_blocked = FALSE;
    }
}

/* This function is used by the upper layer to read data from the stream. */

int ssh_packet_impl_read(void *context, unsigned char *buf, size_t size)
{
  SshPacketImpl up = (SshPacketImpl)context;
  size_t len;

  /* Compute the number of bytes we can transmit. */
  len = ssh_buffer_len(&up->outgoing);
  if (len > size)
    len = size;

  /* Return immediately if no data available. */
  if (len == 0)
    {
      /* If shortcircuiting, pass it to the shortcircuit stream. */
      if (up->shortcircuit_stream)
        return ssh_stream_read(up->shortcircuit_stream, buf, size);

      /* Return EOF or "no more data available yet". */
      if (up->outgoing_eof)
        return 0;
      else
        {
          up->up_read_blocked = TRUE;
          return -1;
        }
    }

  /* Move data to the caller's buffer. */
  memcpy(buf, ssh_buffer_ptr(&up->outgoing), len);
  ssh_buffer_consume(&up->outgoing, len);

  /* Wake up the sender if appropriate. */
  if (ssh_buffer_len(&up->outgoing) == 0)
    ssh_packet_impl_restart_send(up);

  return len;
}

/* This function is called when the upper layer writes to the stream.
   Note that there are essentially two very different cases: an entire
   packet is received at once, and a partial packet is received.  */

int ssh_packet_impl_write(void *context, const unsigned char *buf,
                          size_t size)
{
  SshPacketImpl up = (SshPacketImpl)context;
  size_t offset, payload_len, len;
  unsigned char *ucp;

  /* If shortcircuiting, direct the write down. */
  if (up->shortcircuit_stream)
    {
      SSH_ASSERT(ssh_buffer_len(&up->incoming) == 0);
      return ssh_stream_write(up->shortcircuit_stream, buf, size);
    }

  offset = 0;

normal:
  while (up->can_receive && !up->incoming_eof && offset < size &&
         !up->shortcircuit_stream)
    {
      /* If already processing a partial packet, continue it now. */
      if (ssh_buffer_len(&up->incoming) > 0)
        goto partial;

      /* If only partial packet available, do special proccessing. */
      if (size - offset < 4)
        goto partial;  /* Need partial packet processing. */
      payload_len = SSH_GET_32BIT(buf + offset);
      if (payload_len < 1)
        goto partial;

      if (size - offset < 4 + payload_len)
        goto partial;  /* Need partial packet processing. */

      /* The entire packet is available; pass it to the callback. */
      if (up->received_packet)
        (*up->received_packet)((SshPacketType)buf[offset + 4],
                               buf + offset + 5, payload_len - 1, up->context);
      offset += 4 + payload_len;
    }
  /* We cannot take more data now.  If we processed some data, return
     the number of bytes processed. */
  if (offset > 0)
    return offset;

  /* We couldn't take any data.  Remember that we have returned error to
     the writer and must call the callback later. */
  up->up_write_blocked = TRUE;
  return -1;

partial:
  /* Process partial packet.  First we read its header. */
  len = ssh_buffer_len(&up->incoming);
  if (len < 4)
    {
      len = 4 - len;
      if (size - offset < len)
        len = size - offset;
      if (ssh_buffer_append(&up->incoming, buf + offset, len)
          != SSH_BUFFER_OK)
        {
          (*up->received_eof)(up->context);
          return 0;
        }

      offset += len;
    }
  if (ssh_buffer_len(&up->incoming) < 4)
    return offset;

  /* Get the length of the packet. */
  ucp = ssh_buffer_ptr(&up->incoming);
  payload_len = SSH_GET_32BIT(ucp);
  if (payload_len < 1)
    {
      /* Received an invalid packet with length = 0, even though we should
         always have at least the packet type. */
      (*up->received_eof)(up->context);
      return 0;
    }

  /* Add remaining data in the packet to the buffer. */
  len = 4 + payload_len - ssh_buffer_len(&up->incoming);
  if (len > size - offset)
    len = size - offset;
  if (ssh_buffer_append(&up->incoming, buf + offset, len)
      != SSH_BUFFER_OK)
    {
      (*up->received_eof)(up->context);
      return 0;
    }
  offset += len;

  /* If some data still not available, return. */
  if (ssh_buffer_len(&up->incoming) < 4 + payload_len)
    return offset;

  /* The entire packet is now in buffer. */
  ucp = ssh_buffer_ptr(&up->incoming);
  if (up->received_packet)
    (*up->received_packet)((SshPacketType)ucp[4], ucp + 5,
                           payload_len - 1,
                           up->context);

  /* Clear the incoming partial packet buffer and resume normal processing. */
  ssh_buffer_clear(&up->incoming);
  goto normal;
}

/* This function is called when the upper level sends EOF. */

void ssh_packet_impl_output_eof(void *context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  /* If shortcircuited, process the operation immediately. */
  if (up->shortcircuit_stream)
    {
      ssh_stream_output_eof(up->shortcircuit_stream);
      return;
    }

  /* Mark that we have received EOF. */
  up->incoming_eof = TRUE;

  /* Clear any partial packet that might be buffered. */
  ssh_buffer_clear(&up->incoming);

  /* Call the protocol callback. */
  if (up->received_eof)
    (*up->received_eof)(up->context);
}

/* Sets the callback used to signal the upper level when something happens
   with the stream. */

void ssh_packet_impl_set_callback(void *context, SshStreamCallback callback,
                                  void *callback_context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  up->up_callback = callback;
  up->up_context = callback_context;

  up->up_read_blocked = TRUE;
  up->up_write_blocked = TRUE;
  ssh_packet_impl_restart_output(up);
  ssh_packet_impl_restart_input(up);

  /* If shortcircuiting, set the callbacks for the shortcircuited stream. */
  if (up->shortcircuit_stream)
    ssh_stream_set_callback(up->shortcircuit_stream, callback,
                            callback_context);
}

/* Destroys the stream.  This is called when the application destroys the
   stream.  We don't have any outgoing data that we might buffer (except
   perhaps to the application that just destroyed us, which we cannot
   deliver anyway).  Thus, we can just destroy everything immediately. */

void ssh_packet_impl_destroy(void *context)
{
  SshPacketImpl up = (SshPacketImpl)context;

  /* Call the destroy callback. */
  if (up->destroy)
    (*up->destroy)(up->context);

  /* Cancel pending callbacks. */
  ssh_cancel_timeouts(ssh_packet_impl_signal_output_proc, (void *)up);
  ssh_cancel_timeouts(ssh_packet_impl_signal_input_proc, (void *)up);
  ssh_cancel_timeouts(ssh_packet_impl_signal_send_proc, (void *)up);

  /* Uninitialize the buffers. */
  ssh_buffer_uninit(&up->outgoing);
  ssh_buffer_uninit(&up->outgoing_packet);
  ssh_buffer_uninit(&up->incoming);

  /* Fill the context with garbage so that accesses after freeing are more
     reliably trapped.  This eases debugging. */
  memset(up, 'F', sizeof(*up));
  ssh_xfree(up);
}

/* Methods table for the stream. */

const SshStreamMethodsStruct ssh_packet_impl_methods =
{
  ssh_packet_impl_read,
  ssh_packet_impl_write,
  ssh_packet_impl_output_eof,
  ssh_packet_impl_set_callback,
  ssh_packet_impl_destroy
};

/* Creates and initializes a packet stream implemented by the supplied
   functions.  This returns a packet stream object ready for communication.
      `received_packet'       called when a packet is received
      `received_eof'          called when EOF is received
      `can_send'              called when can send after not being able to
      `destroy'               called when we are destroyed
      `context'               passed as argument to callbacks

   It is guaranteed that after creation the callbacks won't be called until
   from the bottom of the event loop (thus, the caller will have a chance to
   store the stream pointer somewhere).  Any of the functions can be NULL if
   not needed.  It is illegal to desroy the stream from the callbacks (this is
   usually not a problem, since only the application will normally call
   ssh_stream_destroy for this).  The `can_send' callback will be called once
   after creation even without ssh_packet_impl_can_send having being called.

   The stream will be ready to receive packets immediately.  If receiving
   packets immediately is not desirable, ssh_packet_impl_can_receive
   should be called immediately after creation to prevent receiving
   packets. */

SshStream ssh_packet_impl_create(SshPacketReceiveProc received_packet,
                                 SshPacketEofProc received_eof,
                                 SshPacketCanSendProc can_send,
                                 SshPacketImplDestroyProc destroy,
                                 void *context)
{
  SshPacketImpl up;
  SshStream stream;

  /* Allocate and initialize the context. */
  if ((up = ssh_calloc(1, sizeof(*up))) == NULL)
    return NULL;

  ssh_buffer_init(&up->incoming);
  ssh_buffer_init(&up->outgoing);
  ssh_buffer_init(&up->outgoing_packet);
  up->can_receive = FALSE;
  up->incoming_eof = FALSE;
  up->outgoing_eof = FALSE;
  up->up_write_blocked = FALSE;
  up->up_read_blocked = FALSE;
  up->send_blocked = TRUE; /* Cause a callback immediately. */

  /* Save the callback functions. */
  up->received_packet = received_packet;
  up->received_eof = received_eof;
  up->can_send = can_send;
  up->destroy = destroy;
  up->context = context;

  up->up_callback = NULL_FNPTR;
  up->up_context = NULL;

  /* Cause the send callback to be called if non-NULL.  Note that it isn't
     called until from the bottom of the event loop. */
  ssh_packet_impl_restart_send(up);

  /* Wrap it into a stream. */
  stream = ssh_stream_create(&ssh_packet_impl_methods, (void *)up);

  if (stream == NULL)
    ssh_fatal("Insufficient memory to create packet stream object!");

  /* Enable receives. */
  ssh_packet_impl_can_receive(stream, TRUE);

  return stream;
}

/* Informs the packet stream implementation code whether we are willing receive
   packets (i.e., callbacks to the received_packet callback).
   If `enable' is TRUE, we are willing to receive packets.  If it is FALSE,
   `received_packet' will not be called.  This will eventually cause writes
   to the stream fail ("block") until receives are again enabled. */

void ssh_packet_impl_can_receive(SshStream up_stream, Boolean enable)
{
  SshPacketImpl up;

  /* Verify that it is a SshPacketImpl stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_packet_impl_methods)
    ssh_fatal("ssh_packet_impl_can_receive: not a SshPacketImpl stream");
  /* Get the internal context. */
  up = (SshPacketImpl)ssh_stream_get_context(up_stream);

  /* Save new status. */
  up->can_receive = enable;

  /* If allowing receive and writes are blocked, restart them now. */
  if (enable == TRUE && up->up_write_blocked)
    ssh_packet_impl_restart_output(up);
}

/* Causes an EOF to be signalled to anyone reading from the stream (after
   sending any data that has already been buffered).  It is illegal to
   send packets after sending EOF.  Sending an EOF does not affect
   receives. */

void ssh_packet_impl_send_eof(SshStream up_stream)
{
  SshPacketImpl up;

  /* Verify that it is a SshPacketImpl stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_packet_impl_methods)
    ssh_fatal("ssh_packet_impl_can_receive: not a SshPacketImpl stream");
  /* Get the internal context. */
  up = (SshPacketImpl)ssh_stream_get_context(up_stream);

  /* If EOF not already sent, signal the upper level that data is available
     for reading. */
  if (!up->outgoing_eof)
    {
      up->outgoing_eof = TRUE;
      ssh_packet_impl_restart_input(up);
    }
}

/* Returns TRUE if the packet stream can take more packets.  If this
   returns FALSE, and the `can_send' callback is non-NULL, the
   `can_send' callback will be called when packets can again be sent.

   It is not strictly an error to send packets after this has returned
   FALSE.  However, if too much data is sent, packets may eventually
   be ignored.  To give a specific value, sending at most 10000 bytes
   after this returns FALSE will always succeed (this provision exists
   to avoid checks in every disconnect or debug messages). */

Boolean ssh_packet_impl_can_send(SshStream up_stream)
{
  SshPacketImpl up;
  Boolean status;

  /* Verify that it is a SshPacketImpl stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_packet_impl_methods)
    ssh_fatal("ssh_packet_impl_can_receive: not a SshPacketImpl stream");
  /* Get the internal context. */
  up = (SshPacketImpl)ssh_stream_get_context(up_stream);

  /* Determine whether more data can be stored in the buffer. */
  status = ssh_buffer_len(&up->outgoing) <
    BUFFER_MAX_SIZE - ALLOW_AFTER_BUFFER_FULL;

  /* If no more can be stored, mark that sending is blocked.  This will
     trigger a callback when data can again be sent. */
  if (!status)
    up->send_blocked = TRUE;

  return status;
}

/* Sends a packet to the stream, encoding the payload of the packet
   as specified for ssh_encode_buffer_va. */

void ssh_packet_impl_send_encode_va(SshStream up_stream,
                                    SshPacketType type,
                                    va_list va)
{
  SshPacketImpl up;

  /* Verify that it is a SshPacketImpl stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_packet_impl_methods)
    ssh_fatal("ssh_packet_impl_can_receive: not a SshPacketImpl stream");
  /* Get the internal context. */
  up = (SshPacketImpl)ssh_stream_get_context(up_stream);

  /* Format the packet in a separate buffer. */
  ssh_buffer_clear(&up->outgoing_packet);
  ssh_packet_encode_va(&up->outgoing_packet, type, va);

  /* Check that we don't overflow maximum buffer size.  Drop the
     packet if we would. */
  if (ssh_buffer_len(&up->outgoing) + ssh_buffer_len(&up->outgoing_packet) >=
      BUFFER_MAX_SIZE)
    {
      ssh_debug("ssh_packet_impl_send_encode_va: "
                "flow control problems; outgoing packet dropped.");
      return;
    }

  /* Append the packet to the outgoing buffer. */
  if (ssh_buffer_append(&up->outgoing,
                        ssh_buffer_ptr(&up->outgoing_packet),
                        ssh_buffer_len(&up->outgoing_packet)) != SSH_BUFFER_OK)
    {
      return;
    }

  /* Restart reads by upper level. */
  ssh_packet_impl_restart_input(up);

  /* Sanity check that we didn't exceed max buffer size. */
  if (ssh_buffer_len(&up->outgoing) > BUFFER_MAX_SIZE)
    ssh_debug("ssh_packet_impl_send: buffer max size exceeded: size %ld",
              (long)ssh_buffer_len(&up->outgoing));
}

/* Sends a packet to the stream, encoding the payload of the packet
   as specified for ssh_encode_buffer. */

void ssh_packet_impl_send_encode(SshStream up_stream,
                                 SshPacketType type,
                                 ...)
{
  va_list va;

  va_start(va, type);
  ssh_packet_impl_send_encode_va(up_stream, type, va);
  va_end(va);
}

/* Sends a packet to the stream.  The packet is actually buffered, and
   the higher level is signalled that data is available.  The higher
   level will read the data when convenient.  The application should
   use ssh_packet_impl_can_send and the `can_send' callback to
   implement flow control.  This should only be called when
   ssh_packet_impl_can_send returns TRUE (see notes in that
   function). */

void ssh_packet_impl_send(SshStream up_stream, SshPacketType type,
                          const unsigned char *data, size_t len)
{
  ssh_packet_impl_send_encode(up_stream, type,
                              SSH_ENCODE_DATA(data, len),
                              SSH_FORMAT_END);
}

/* INTERNAL FUNCTION - not to be called from applications.  This
   immediately shortcircuits the up stream downward to the other
   stream.  Directs reads/writes/callbacks directly to it.  The stream
   argument may be NULL to cancel shortcircuiting.  There must be no partial
   incoming packet in the up_stream stream buffers. */

void ssh_packet_impl_shortcircuit_now(SshStream up_stream,
                                      SshStream down_stream)
{
  SshPacketImpl up;

  /* Verify that it is a SshPacketImpl stream. */
  if (ssh_stream_get_methods(up_stream) != &ssh_packet_impl_methods)
    ssh_fatal("ssh_packet_impl_can_receive: not a SshPacketImpl stream");
  /* Get the internal context. */
  up = (SshPacketImpl)ssh_stream_get_context(up_stream);

  /* Save shortcircuit stream. */
  up->shortcircuit_stream = down_stream;

  /* We currently require there to be no partial incoming packet. */
  SSH_ASSERT(ssh_buffer_len(&up->incoming) == 0);

  /* If it is non-NULL, make it use application callbacks directly. */
  if (down_stream)
    ssh_stream_set_callback(down_stream, up->up_callback, up->up_context);
}
