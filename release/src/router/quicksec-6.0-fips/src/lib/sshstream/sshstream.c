/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A generic bidirectional data stream with a callback-based interface.
*/

#include "sshincludes.h"
#include "sshstream.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshStream"

/* All stream types have a structure that starts with the method table
   pointer.  This structure should be considered private to the implementation
   and should not be accessed directly by applications. */

struct SshStreamRec {
  const SshStreamMethodsStruct *methods;
  SshUInt64 read_bytes;
  SshUInt64 written_bytes;
  void *context;
  SshStreamCallback user_callback;
  void *user_context;

  void *private_methods;

  unsigned int closed:1;
  unsigned int disconnected:1;
  unsigned int in_callback:1;
  unsigned int can_output_received:1;
  unsigned int input_available_received:1;
  unsigned int disconnect_received:1;
};

/* Callbacks from the stream implementation are passed to this function for
   sanity checks.  This will then call the application callback.  Note
   that the user callback is allowed to close the stream. */

void ssh_stream_internal_callback(SshStreamNotification notification,
                                  void *context)
{
  SshStream stream = (SshStream)context;

  /* Disallow recursive callbacks by serializing them here.
     The actual function call is made from within the first
     ssh_stream_internal_callback invocation after the 'user_callback'
     is finished. */
  if (stream->in_callback)
    {
      switch (notification)
        {
        case SSH_STREAM_INPUT_AVAILABLE:
          stream->input_available_received = 1;
          break;
        case SSH_STREAM_CAN_OUTPUT:
          stream->can_output_received = 1;
          break;
        case SSH_STREAM_DISCONNECTED:
          stream->disconnect_received = 1;
          break;
        }
      return;
    }
  stream->in_callback = 1;

  if (stream->closed)
    ssh_fatal("ssh_stream_internal_callback: stream implementation generated "
              "a callback after close.");
  if (stream->disconnected)
    ssh_fatal("ssh_stream_internal_callback: stream implementation generated "
              "a callback after disconnected notification");
  if (notification == SSH_STREAM_DISCONNECTED)
    stream->disconnected = 1;

  /* Call the user callback if set.  Note that it is legal for the user
     callback to be NULL, in which case it is just not called. */
  if (stream->user_callback)
    (*stream->user_callback)(notification, stream->user_context);

 restart:

  if (!stream->closed)
    {
      /* Check if other callbacks were received during callback. */
      if (stream->input_available_received)
        {
          stream->input_available_received = 0;
          if (stream->user_callback)
            (*stream->user_callback)(SSH_STREAM_INPUT_AVAILABLE,
                                     stream->user_context);
          goto restart;
        }
      if (stream->can_output_received)
        {
          stream->can_output_received = 0;
          if (stream->user_callback)
            (*stream->user_callback)(SSH_STREAM_CAN_OUTPUT,
                                     stream->user_context);
          goto restart;
        }
      if (stream->disconnect_received)
        {
          stream->disconnect_received = 0;
          stream->disconnected = 1;
          if (stream->user_callback)
            (*stream->user_callback)(SSH_STREAM_DISCONNECTED,
                                 stream->user_context);
          /* Disconnected should be the last callback called so we don't
             have to restart in this case. */
        }
    }
  stream->in_callback = 0;
}

/* Creates a stream.  This is usually not called directly by applications;
   instead, applications call stream type specific creation functions that
   will eventually call this. */

SshStream ssh_stream_create(const SshStreamMethodsStruct *methods,
                            void *context)
{
  SshStream stream;

  stream = ssh_calloc(1, sizeof(*stream));

  if (stream == NULL)
    return NULL;

  stream->methods = methods;
  stream->context = context;

  (*stream->methods->set_callback)(stream->context,
                                   ssh_stream_internal_callback,
                                   (void *)stream);
  return stream;
}

/* Reads at most `size' bytes to the buffer `buffer'.  Returns 0 if
  EOF is encountered, negative value if the read would block, and
  the number of bytes read if something was read. */

int ssh_stream_read(SshStream stream, unsigned char *buffer,
                    size_t size)
{
  int len;

  SSH_ASSERT(!stream->closed);
  len = (*stream->methods->read)(stream->context, buffer, size);
  SSH_ASSERT(!stream->disconnected || len == 0);
  if (len > 0)
    stream->read_bytes += len;
  return len;
}

/* Writes at most `size' bytes from the buffer `buffer'.  Returns 0 if the
   other end has indicated that it will no longer read (this condition is not
   guaranteed to be detected), a negative value if the write would block,
   and the number of bytes written if something was actually written. */

int ssh_stream_write(SshStream stream, const unsigned char *buffer,
                     size_t size)
{
  int len;

  SSH_ASSERT(!stream->closed);
  len = (*stream->methods->write)(stream->context, buffer, size);
  SSH_ASSERT(!stream->disconnected || len == 0);
  if (len > 0)
    stream->written_bytes += len;
  return len;
}

/* Signals that the application will not write anything more to the stream. */

void ssh_stream_output_eof(SshStream stream)
{
  SSH_ASSERT(!stream->closed);
  (*stream->methods->output_eof)(stream->context);
}

/* Calls the stream implementation's `set_callback' method. */
void ssh_stream_set_callback_timeout(void *context)
{
  SshStream stream = (SshStream) context;

  SSH_ASSERT(!stream->closed);
  (*stream->methods->set_callback)(stream->context,
                                   ssh_stream_internal_callback, stream);
}

/* Sets the callback that the stream uses to notify the application of
   events of interest.  This function may be called at any time, and
   may be called multiple times.  The callback may be NULL, in which
   case it just won't be called.  Setting the callback to non-NULL
   will result in a call to the callback, latest when something can be
   done.  Applications can rely on doing all I/O in the callback, if
   they wish. */

void ssh_stream_set_callback(SshStream stream,
                             SshStreamCallback callback,
                             void *context)
{
  SSH_ASSERT(!stream->closed);
  stream->user_callback = callback;
  stream->user_context = context;

  /* Call the `set_callback' method from the bottom of the event loop. */
  ssh_cancel_timeouts(ssh_stream_set_callback_timeout, stream);
  ssh_xregister_timeout(0, 0, ssh_stream_set_callback_timeout, stream);
}

/* Retrieves stream statistics. */

void ssh_stream_get_stats(SshStream stream, SshStreamStats stats)
{
  SSH_ASSERT(!stream->closed);
  stats->read_bytes = stream->read_bytes;
  stats->written_bytes = stream->written_bytes;
}

/* Frees the given stream immediately. */

void ssh_stream_real_destroy(void *context)
{
  SshStream stream = (SshStream)context;

  /* Fill the context with garbage as an extra sanity check. */
  memset(stream, 'F', sizeof(*stream));

  ssh_free(stream);
}

/* Schedules the stream to be closed and destroyed at the bottom of the
   event loop. */

void ssh_stream_destroy(SshStream stream)
{
  SSH_ASSERT(!stream->closed);
  stream->closed = 1;
  (*stream->methods->destroy)(stream->context);

  /* Cancel possible pending `set_callback' timeout. */
  ssh_cancel_timeouts(ssh_stream_set_callback_timeout, stream);

  /* Perform a delayed free of the stream context.  We would basically be
     allowed to free it immediately; however, as a sanity check, we keep
     the context around until all events have been processed, and
     call fatal if the stream is still accessed. */
  ssh_xregister_timeout(0L, 0L, ssh_stream_real_destroy, (void *)stream);
}

/* Returns the methods table for the stream.  This function is primarily
   used by various stream implementations to determine whether a particular
   stream is of the appropriate type. */

SshStreamMethods ssh_stream_get_methods(SshStream stream)
{
  SSH_ASSERT(!stream->closed);
  return (SshStreamMethods)(stream->methods);
}

/* Returns the method context of the stream.  This function is intended
   for use by stream implementations only. */

void *ssh_stream_get_context(SshStream stream)
{
  SSH_ASSERT(!stream->closed);
  return stream->context;
}

/* Returns the private methods of the stream */
void ssh_stream_set_private_methods(SshStream stream, void *private_methods)
{
  SSH_ASSERT(!stream->closed);
  stream->private_methods = private_methods;
}

/* Returns the private methods of the stream */
void *ssh_stream_get_private_methods(SshStream stream)
{
  SSH_ASSERT(!stream->closed);
  return stream->private_methods;
}
