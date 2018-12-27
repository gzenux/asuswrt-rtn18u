/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An object for filtering a data stream bidirectionally.  The object
   allows callbacks to modify and filter data bidirectionally, and allow
   them to disconnect the connection.
*/

#include "sshincludes.h"
#include "sshfilterstream.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshFilterStream"

struct SshStreamFilterRec
{
  /* The underlying stream whose data we are filtering.  The "to" direction is
     data being written to this stream, and the "from" direction is data
     being read from this stream. */
  SshStream stream;

  /* Function to filter data to ``stream''. */
  SshFilterProc to_filter;

  /* Function to filter data from ``stream''. */
  SshFilterProc from_filter;

  /* Function to be called when the filter stream is closed. */
  void (*destroy)(void *context);

  /* Context to pass to the callback functions. */
  void *context;

  /* SshBuffer for data coming from ``stream''. */
  SshBufferStruct from_buffer;

  /* SshBuffer for data going to ``stream''. */
  SshBufferStruct to_buffer;

  /* Maximum number of bytes to store in buffer (including already accepted
     data). */
  size_t max_buffer_size;

  /* Number of bytes that have already been accepted but not yet written in
     the "from" direction. */
  size_t from_accepted_bytes;

  /* Number of bytes that have already been accepted but not yet written in
     the "to" direction. */
  size_t to_accepted_bytes;

  /* Set to TRUE if EOF is received from the stream. */
  Boolean from_eof_received;

  /* Set to TRUE if the upper level calls output_eof. */
  Boolean to_eof_received;

  /* Set to TRUE if the stream has been disconnected. */
  Boolean disconnected;

  /* Set to TRUE if shortcircuiting has been requested. */
  Boolean shortcircuit_requested;

  /* Set to TRUE if the stream has been shortcircuited and buffers flushed
     in the "from" direction. */
  Boolean from_shortcircuited;

  /* Set to TRUE if the stream has been shortcircuited and buffers flushed
     in the "to" direction. */
  Boolean to_shortcircuited;

  /* Callback to call when data can be read/written from the filter stream. */
  SshStreamCallback callback;

  /* Context to pass to ``callback''. */
  void *callback_context;

  /* Read from up has returned -1. */
  Boolean read_blocked;

  /* Write from up has returned -1. */
  Boolean write_blocked;

  /* Set to TRUE if the stream has been scheduled for deletion. */
  Boolean deleted;
};

typedef enum {
  SSH_STREAM_FILTER_INBOUND,
  SSH_STREAM_FILTER_OUTBOUND
} SshStreamFilterDataDir;

typedef struct SshStreamFilterRec *SshStreamFilter;

/* Predeclarations. */
static void actual_destroy(SshStreamFilter sf);
void ssh_stream_filter_get_inbound(void *internal_context,
                                   SshBuffer *data_ret,
                                   size_t *offset_ret,
                                   Boolean *eof_received_ret);

void ssh_stream_filter_get_outbound(void *internal_context,
                                    SshBuffer *data_ret,
                                    size_t *offset_ret,
                                    Boolean *eof_received_ret);
void ssh_stream_filter_complete_inbound(void *internal_context,
                                        SshInt32 operation);
void ssh_stream_filter_complete_outbound(void *internal_context,
                                         SshInt32 operation);
void ssh_stream_filter_accept(SshStreamFilter sf,
                              SshStreamFilterDataDir dir,
                              int op);

/* Called when the underlying stream wants to notify us. */
void ssh_stream_filter_callback(SshStreamNotification op, void *context);


/* Called from a generated event, this calls the callback registered for
   this stream with INPUT_AVAILABLE notification. */

void
ssh_stream_filter_read_upcall(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  if (sf->callback)
    (*sf->callback)(SSH_STREAM_INPUT_AVAILABLE, sf->callback_context);
}

/* Called from a generated event, this calls the callback registered for
   this stream with CAN_OUTPUT notification. */

void
ssh_stream_filter_write_upcall(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  if (sf->callback)
    (*sf->callback)(SSH_STREAM_CAN_OUTPUT, sf->callback_context);
}

/* Schedules a call to our stream callback with INPUT_AVAILABLE, but only
   if reads are blocked (i.e., our read function has returned -1). */

void
ssh_stream_filter_wake_up_reads(SshStreamFilter sf)
{
  if (!sf->read_blocked && !sf->deleted)
    return;

  SSH_DEBUG(5, ("Scheduling ssh_stream_filter_read_upcall timeout"));
  ssh_xregister_timeout(0L, 0L, ssh_stream_filter_read_upcall, (void *)sf);
  sf->read_blocked = FALSE;
}

/* Schedules a call to our stream callback with CAN_OUTPUT, but only
   if writes are blocked (i.e., our write function has returned -1). */

void
ssh_stream_filter_wake_up_writes(SshStreamFilter sf)
{
  if (!sf->write_blocked && !sf->deleted)
    return;

  ssh_xregister_timeout(0L, 0L, ssh_stream_filter_write_upcall, (void *)sf);
  sf->write_blocked = FALSE;
}

/* Disconnect the stream immediately.  This means that EOF will be set
   in both directions, the filter functions will not be called again,
   and no more data will be transmitted. */

void
ssh_stream_filter_disconnect_now(SshStreamFilter sf)
{
  sf->disconnected = TRUE;
  ssh_stream_output_eof(sf->stream);
  ssh_stream_filter_wake_up_reads(sf);
  ssh_stream_filter_wake_up_writes(sf);
}

/* Tries to write data to the underlying stream. */

void
ssh_stream_filter_try_write(SshStreamFilter sf)
{
  int len;

  /* If disconnected or already shortcircuiting, just return. */
  if (sf->disconnected || sf->to_shortcircuited)
    return;

  /* Try to write the accepted data to the stream. */
  while (sf->to_accepted_bytes > 0)
    {
      len = ssh_stream_write(sf->stream, ssh_buffer_ptr(&sf->to_buffer),
                             sf->to_accepted_bytes);
      if (len == -1)
        return;
      if (len == 0)
        {



          return;
        }
      sf->to_accepted_bytes -= len;
      ssh_buffer_consume(&sf->to_buffer, len);
    }

  if (sf->to_accepted_bytes == 0 && sf->deleted)
    {
      actual_destroy(sf);
      return;
    }

  /* Start shortcircuiting now if appropriate. */
  if (sf->shortcircuit_requested && ssh_buffer_len(&sf->to_buffer) == 0)
    {
      sf->to_shortcircuited = TRUE;
      if (sf->from_shortcircuited)
        ssh_stream_set_callback(sf->stream, sf->callback,
                                sf->callback_context);
      return;
    }

  /* Check if we should schedule a callback to the application write
     function.  Note that a call is scheduled only if writes are blocked. */
  if (ssh_buffer_len(&sf->to_buffer) < sf->max_buffer_size
      && !(sf->deleted))
    ssh_stream_filter_wake_up_writes(sf);
}

/* Shortcircuit the stream; arrange not to call the filter functions
   again.  This may shortcircuit immediately, or may arrange for
   shortcircuit to happen when all data has been transmitted. */

void
ssh_stream_filter_shortcircuit_now(SshStreamFilter sf)
{
  /* Mark that shortcircuit has been requested. */
  sf->shortcircuit_requested = TRUE;

  /* Shortcircuit "from" direction if buffers are empty. */
  if (ssh_buffer_len(&sf->from_buffer) == 0)
    sf->from_shortcircuited = TRUE;
  else
    sf->from_accepted_bytes = ssh_buffer_len(&sf->from_buffer);

  /* Shortcircuit "to" direction if buffers are empty. */
  if (ssh_buffer_len(&sf->to_buffer) == 0)
    sf->to_shortcircuited = TRUE;
  else
    sf->to_accepted_bytes = ssh_buffer_len(&sf->to_buffer);

  /* If both directions shortcircuited, bypass callbacks. */
  if (sf->from_shortcircuited && sf->to_shortcircuited)
    ssh_stream_set_callback(sf->stream, sf->callback, sf->callback_context);

  /* Try to finalize the shortcircuit (this is needed so that reading/writing
     wakes up to eventually empty the buffers). */
  if (!sf->from_shortcircuited)
    ssh_stream_filter_wake_up_reads(sf);
  if (!sf->to_shortcircuited)
    ssh_stream_filter_try_write(sf);
}

/* Calls the filter in the "to" direction. */

void
ssh_stream_filter_call_to_filter(SshStreamFilter sf)
{
  /* Call filter or accept everything */
  SSH_ASSERT(sf->to_accepted_bytes <= ssh_buffer_len(&sf->to_buffer));
  if (sf->to_filter)
    (*sf->to_filter)(sf->context, ssh_stream_filter_get_inbound,
                     ssh_stream_filter_complete_inbound,
                     sf);
  else
    {
      int len = ssh_buffer_len(&sf->to_buffer) -
        sf->to_accepted_bytes;

      if (len > 0)
        ssh_stream_filter_accept(sf, SSH_STREAM_FILTER_INBOUND, len);
      else
        ssh_stream_filter_accept(sf, SSH_STREAM_FILTER_INBOUND,
                                 SSH_FILTER_HOLD);
    }
}

/* Calls the filter in the "from" direction */

void
ssh_stream_filter_call_from_filter(SshStreamFilter sf)
{
  /* Call the filter or accept everything straight away. */
  SSH_ASSERT(sf->from_accepted_bytes <= ssh_buffer_len(&sf->from_buffer));
  if (sf->from_filter)
    (*sf->from_filter)(sf->context, ssh_stream_filter_get_outbound,
                       ssh_stream_filter_complete_outbound,
                       sf);
  else
    {
      int len = ssh_buffer_len(&sf->from_buffer) -
        sf->from_accepted_bytes;

      if (len > 0)
        ssh_stream_filter_accept(sf, SSH_STREAM_FILTER_OUTBOUND, len);
      else
        ssh_stream_filter_accept(sf, SSH_STREAM_FILTER_OUTBOUND,
                                 SSH_FILTER_HOLD);
    }
}

void
ssh_stream_filter_call_to_filter_timeout(void *context)
{
  ssh_stream_filter_call_to_filter((SshStreamFilter)context);
}

void
ssh_stream_filter_call_from_filter_timeout(void *context)
{
  ssh_stream_filter_call_from_filter((SshStreamFilter)context);
}

/* Tries to read data from the underlying stream. */

void
ssh_stream_filter_try_read(SshStreamFilter sf)
{
  char buf[1024];
  int len;
  Boolean max_buffer_size_reached = FALSE;

  /* If disconnected or already shortcircuiting, just return. */
  if (sf->disconnected || sf->shortcircuit_requested)
    return;

  /* If already too much data buffered, don't read any more. */
  SSH_ASSERT(ssh_buffer_len(&sf->from_buffer) <= sf->max_buffer_size);
  if (ssh_buffer_len(&sf->from_buffer) >= sf->max_buffer_size)
    {
      SSH_DEBUG(4, ("Buffer has reached max_buf_size (%zd bytes)",
                    sf->max_buffer_size));
      return;
    }

  for (;;)
    {
      /* Determine how much we can read without overflowing buffers. */
      len = sf->max_buffer_size - ssh_buffer_len(&sf->from_buffer);
      if (len > sizeof(buf))
        len = sizeof(buf);
      if (len <= 0)
        {
          max_buffer_size_reached = TRUE;
          break;
        }

      /* Try to read data from the stream. */
      len = ssh_stream_read(sf->stream, (unsigned char *) buf, len);
      if (len < 0)
        break;

      if (len == 0)
        {
          sf->from_eof_received = TRUE;
          break;
        }
      ssh_buffer_append(&sf->from_buffer, (unsigned char *) buf, len);
    }

  ssh_stream_filter_call_from_filter(sf);

  if (max_buffer_size_reached)
    {
      SSH_DEBUG(4, ("Waking up read from down, because ssh_stream_read "
                    "didn't return -1"));
      ssh_stream_set_callback(sf->stream,
                              ssh_stream_filter_callback, (void *)sf);
    }
}

/* This is called when the underlying stream wants to notify us. */

void
ssh_stream_filter_callback(SshStreamNotification op, void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  switch (op)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      if (sf->deleted) return; /* Do not read after the stream has been
                                  scheduled for deletion. */
      ssh_stream_filter_try_read(sf);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_stream_filter_try_write(sf);
      break;

    case SSH_STREAM_DISCONNECTED:
      ssh_debug("ssh_stream_filter_callback: DISCONNECTED\n");
      break;

    default:
      SSH_NOTREACHED;
    }
}

/* This function accepts (a part of) the data. It is called through the
   completion functions. */

void
ssh_stream_filter_accept(SshStreamFilter sf,
                         SshStreamFilterDataDir dir,
                         int op)
{
  SSH_DEBUG(10, ("Entered with op %d in direction %s", op,
                 dir == SSH_STREAM_FILTER_INBOUND ? "inbound" : "outbound"));

  if (dir == SSH_STREAM_FILTER_INBOUND)
    {
      /* First handle the case that we accepted a non-zero number of bytes. */
      if (op > 0)
        {
          /* We accepted some bytes. */
          sf->to_accepted_bytes += op;

          if (op >= 0)
            {
              /* This is accept-op, so schedule the filter proc to be
                 called again. */
              ssh_xregister_timeout(0, 0,
                                   ssh_stream_filter_call_to_filter_timeout,
                                   sf);
            }

          /* Try writing to the stream. */
          ssh_stream_filter_try_write(sf);
          return;
        }

      /* Process special return values. */
      switch (op)
        {
        case SSH_FILTER_HOLD:
          /* Gather more data and continue then.
             Note: this is not equivalent to accepting zero bytes. */
          if (sf->to_accepted_bytes == 0 &&
              ssh_buffer_len(&sf->to_buffer) >= sf->max_buffer_size)
            ssh_fatal("ssh_stream_filter_call_to_filter: SSH_FILTER_HOLD "
                      "returned, but buffer already full.");
          break;

        case SSH_FILTER_DISCONNECT:
          ssh_stream_filter_disconnect_now(sf);
          break;

        case SSH_FILTER_SHORTCIRCUIT:
          ssh_stream_filter_shortcircuit_now(sf);
          break;

        default:
          ssh_fatal("ssh_stream_filter_call_to_filter: filter returned bad "
                    "op %d", op);
        }
    }
  else
    {
      /* First handle the case that we accepted a non-zero number of bytes. */
      if (op > 0)
        {
          if (op > (ssh_buffer_len(&sf->from_buffer) -
                    sf->from_accepted_bytes))
            {
              ssh_fatal("ssh_stream_filter_accept: trying to accept more "
                        "bytes (%d) than there are unaccepted bytes in buffer",
                        op);
            }
          /* We accepted some bytes. */
          sf->from_accepted_bytes += op;
        }

      if (op >= 0)
        {
          /* Wake up reads if they are blocked. */
          ssh_stream_filter_wake_up_reads(sf);

          /* This is accept-op, so schedule the filter proc to be
             called again. */
          ssh_xregister_timeout(0, 0,
                               ssh_stream_filter_call_from_filter_timeout, sf);
          return;
        }

      /* Process special return values. */
      switch (op)
        {
        case SSH_FILTER_HOLD:
          /* Gather more data and continue then.  Note: this is not
             equivalent to accepting zero bytes. */
          if (sf->from_accepted_bytes == 0 &&
              ssh_buffer_len(&sf->from_buffer) >= sf->max_buffer_size)
            ssh_fatal("ssh_stream_filter_accept: SSH_FILTER_HOLD "
                      "returned, but buffer already full.");

          /* Must wake up reads if we got EOF. */
          if (sf->from_eof_received)
            {
              ssh_stream_filter_wake_up_reads(sf);
            }
          break;

        case SSH_FILTER_DISCONNECT:
          ssh_stream_filter_disconnect_now(sf);
          break;

        case SSH_FILTER_SHORTCIRCUIT:
          ssh_stream_filter_shortcircuit_now(sf);
          break;

        default:
          ssh_fatal("ssh_stream_filter_accept: filter returned bad op %d",
                    op);
        }
    }
}

/* Returns the buffer and offset */

void
ssh_stream_filter_get_inbound(void *internal_context,
                              SshBuffer *data_ret,
                              size_t *offset_ret,
                              Boolean *eof_received_ret)
{
  SshStreamFilter sf = (SshStreamFilter)internal_context;
  *data_ret = &(sf->to_buffer);
  *offset_ret = sf->to_accepted_bytes;
  *eof_received_ret = sf->to_eof_received;
}

void
ssh_stream_filter_get_outbound(void *internal_context,
                               SshBuffer *data_ret,
                               size_t *offset_ret,
                               Boolean *eof_received_ret)
{
  SshStreamFilter sf = (SshStreamFilter)internal_context;
  *data_ret = &(sf->from_buffer);
  *offset_ret = sf->from_accepted_bytes;
  *eof_received_ret = sf->from_eof_received;
}

/* Completes the filtering of a piece of data */

void
ssh_stream_filter_complete_outbound(void *internal_context,
                                    SshInt32 operation)
{
  ssh_stream_filter_accept((SshStreamFilter)internal_context,
                           SSH_STREAM_FILTER_OUTBOUND, operation);
}

void
ssh_stream_filter_complete_inbound(void *internal_context,
                                   SshInt32 operation)
{
  ssh_stream_filter_accept((SshStreamFilter)internal_context,
                           SSH_STREAM_FILTER_INBOUND, operation);
}


static void
actual_destroy(SshStreamFilter sf)
{
  /* Call the user destroy function if supplied. */
  if (sf->destroy)
    (*sf->destroy)(sf->context);

  /* Destroy the underlying stream. */
  ssh_stream_destroy(sf->stream);
  sf->stream = NULL;

  /* Uninitialize the buffers. */
  ssh_buffer_uninit(&sf->to_buffer);
  ssh_buffer_uninit(&sf->from_buffer);

  /* Cancel pending timeouts (the context is about to be destroyed) */
  ssh_cancel_timeouts(ssh_stream_filter_call_to_filter_timeout, (void *)sf);
  ssh_cancel_timeouts(ssh_stream_filter_call_from_filter_timeout, (void *)sf);
  ssh_cancel_timeouts(ssh_stream_filter_read_upcall, (void *)sf);
  ssh_cancel_timeouts(ssh_stream_filter_write_upcall, (void *)sf);

  /* Free the context. */
  memset(sf, 'F', sizeof(*sf));
  ssh_free(sf);
}

/* Called when the filter stream is destroyed. */
void
ssh_stream_filter_destroy(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* Sanity check: we should have an underlying stream. */
  SSH_ASSERT(sf->stream != NULL);
  SSH_ASSERT(sf->deleted == FALSE);
  sf->deleted = TRUE;

  /* Mark that we have received EOF. */
  sf->to_eof_received = TRUE;
  sf->from_eof_received = TRUE;

  /* Call "to" filter.  This ensures that the filter function gets called
     with EOF, so that it presumably processes all remaining data. */
  ssh_stream_filter_call_to_filter(sf);

  /* Cancel any callbacks to the stream callback. */
  ssh_cancel_timeouts(ssh_stream_filter_read_upcall, (void *)sf);
  ssh_cancel_timeouts(ssh_stream_filter_write_upcall, (void *)sf);

  sf->callback = NULL_FNPTR;

  /* If we have no more bytes to write, destroy immediately.  Otherwise,
     destroy when the buffer has been drained. */
  if (sf->to_accepted_bytes == 0)
    actual_destroy(sf);
}

/* Called when the application reads from the filter stream. */

int
ssh_stream_filter_read(void *context, unsigned char *buf, size_t size)
{
  SshStreamFilter sf = (SshStreamFilter)context;
  size_t len;

  SSH_ASSERT(!(sf->deleted));

  /* If disconnected, return EOF. */
  if (sf->disconnected)
    return 0;

  /* If already shortcircuited, just pass the call through. */
  if (sf->from_shortcircuited)
    return ssh_stream_read(sf->stream, buf, size);

  /* See if we have data we could return. */
  len = sf->from_accepted_bytes;
  if (len > 0)
    {
      if (len > size)
        len = size;
      memcpy(buf, ssh_buffer_ptr(&sf->from_buffer), len);
      ssh_buffer_consume(&sf->from_buffer, len);
      sf->from_accepted_bytes -= len;
      ssh_stream_filter_try_read(sf);
      return len;
    }

  /* See if we should return EOF. */
  if (sf->from_eof_received)
    return 0;

  /* Check if we should start shortcircuiting. */
  if (sf->shortcircuit_requested)
    {
      sf->from_shortcircuited = TRUE;
      if (sf->to_shortcircuited)
        ssh_stream_set_callback(sf->stream, sf->callback,
                                sf->callback_context);
      return -1;
    }

  /* Cannot return more data right now. */
  sf->read_blocked = TRUE;
  return -1;
}

/* Processes a write from up. */

int
ssh_stream_filter_write(void *context, const unsigned char *buf,
                        size_t size)
{
  SshStreamFilter sf = (SshStreamFilter)context;
  size_t len;

  SSH_ASSERT(!(sf->deleted));

  /* If disconnected, return EOF. */
  if (sf->disconnected || sf->to_eof_received)
    return 0;

  /* If already shortcircuited, just pass the call through. */
  if (sf->to_shortcircuited)
    return ssh_stream_write(sf->stream, buf, size);

  /* If shortcircuit requested, but we are not yet shortcircuited,
     return -1 while we wait for buffers to drain. */
  if (sf->shortcircuit_requested)
    {
      sf->write_blocked = TRUE;
      return -1;
    }

  /* Compute the number of bytes that we can accept. */
  SSH_ASSERT(ssh_buffer_len(&sf->to_buffer) <= sf->max_buffer_size);
  len = sf->max_buffer_size - ssh_buffer_len(&sf->to_buffer);
  if (len > size)
    len = size;

  /* If we cannot take more bytes at this time, block writes. */
  if (len == 0)
    {
      sf->write_blocked = TRUE;
      return -1;
    }

  /* Copy the bytes to the buffer. */
  ssh_buffer_append(&sf->to_buffer, buf, len);

  /* Writes are not blocked. */
  sf->write_blocked = FALSE;

  /* Call "to" filter. */
  ssh_stream_filter_call_to_filter(sf);

  return len;
}

/* Processes EOF from up. */

void
ssh_stream_filter_output_eof(void *context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* If shortcircuited, pass directly down. */
  if (sf->to_shortcircuited)
    {
      ssh_stream_output_eof(sf->stream);
      return;
    }

  /* If disconnected or EOF already processed, ignore. */
  if (sf->disconnected || sf->to_eof_received)
    return;

  /* Mark that we have received EOF. */
  sf->to_eof_received = TRUE;

  /* If no buffered data, send EOF to stream. */
  if (ssh_buffer_len(&sf->to_buffer) == 0)
    ssh_stream_output_eof(sf->stream);

  /* Call "to" filter. */
  ssh_stream_filter_call_to_filter(sf);
}

/* Sets the stream callback. */

void
ssh_stream_filter_set_callback(void *context, SshStreamCallback callback,
                               void *callback_context)
{
  SshStreamFilter sf = (SshStreamFilter)context;

  /* If shortcircuited, pass the upper level callback directly to the
     original stream. */
  if (sf->from_shortcircuited && sf->to_shortcircuited)
    ssh_stream_set_callback(sf->stream, callback, callback_context);

  /* Save the callback. */
  sf->callback = callback;
  sf->callback_context = callback_context;
  sf->read_blocked = TRUE;
  sf->write_blocked = TRUE;

  /* Schedule initial calls to callback */
  ssh_stream_filter_wake_up_reads(sf);
  ssh_stream_filter_wake_up_writes(sf);
}

/* Stream methods table for filter streams. */

static const SshStreamMethodsStruct ssh_stream_filter_methods =
{
  ssh_stream_filter_read,
  ssh_stream_filter_write,
  ssh_stream_filter_output_eof,
  ssh_stream_filter_set_callback,
  ssh_stream_filter_destroy
};

/* Creates a stream that can be used to filter data to/from another
   stream.  ``stream'' is an already existing stream whose data is to
   be filter.  It is wrapped into the filter stream, and will be
   closed automatically when the filter stream is closed.
   ``to_stream_filter'', if non-NULL, is a filter to call whenever
   data is written to the returned stream (and is on its way to
   ``stream'').  ``from_stream_filter'' (if non-NULL) is called
   whenever data is received from ``stream''.  ``destroy'' (if
   non-NULL) is called when the returned stream is closed; it can be
   used to free ``context''.  The filter functions must ensure that the
   buffer does not grow unboundedly.
     `stream'             stream whose data is to be filtered
     `max_buffer_size'    maximum number of bytes to buffer
     `to_stream_filter'   filter for data going to ``stream'', or NULL
     `from_stream_filter' filter for data coming from ``stream'', or NULL
     `destroy'            called when the returned stream is closed, or NULL
     `context'            context argument to pass to the functions.
   The filter functions are not allowed to directly destroy the stream. */

SshStream
ssh_stream_filter_create(SshStream stream,
                         size_t max_buffer_size,
                         SshFilterProc to_stream_filter,
                         SshFilterProc from_stream_filter,
                         void (*destroy)(void *context),
                         void *context)
{
  SshStreamFilter sf;
  SshStream str;

  /* Initialize the internal state. */
  sf = ssh_calloc(1, sizeof(*sf));
  if (sf == NULL)
    return NULL;

  sf->stream = stream;
  sf->max_buffer_size = max_buffer_size;
  sf->to_filter = to_stream_filter;
  sf->from_filter = from_stream_filter;
  sf->destroy = destroy;
  sf->context = context;
  ssh_buffer_init(&sf->from_buffer);
  ssh_buffer_init(&sf->to_buffer);
  sf->read_blocked = TRUE;
  sf->write_blocked = TRUE;
  sf->callback = NULL_FNPTR;
  sf->callback_context = NULL;

  /* Set the original stream's callback to our callback. */
  ssh_stream_set_callback(stream, ssh_stream_filter_callback, (void *)sf);

  SSH_DEBUG(4, ("Wrapping stream with %zd byte buffer.", max_buffer_size));
  /* Wrap the context into a stream. */
  str = ssh_stream_create(&ssh_stream_filter_methods, (void *) sf);

  if (str == NULL)
    {
      ssh_buffer_uninit(&sf->from_buffer);
      ssh_buffer_uninit(&sf->to_buffer);
      ssh_free(sf);
      return NULL;
    }

  return str;
}
