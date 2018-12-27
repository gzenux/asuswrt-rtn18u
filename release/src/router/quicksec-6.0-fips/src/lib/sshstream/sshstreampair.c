/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshstream.h"
#include "sshstreampair.h"
#include "sshtimeouts.h"

#define BUFFER_SIZE 16384

#define SSH_DEBUG_MODULE "SshStreamPair"

/* Data structure for "half" of the stream. */

typedef struct SshStreamHalfRec
{
  /* SshBuffer for data that can be read from this half.  This is managed as
     a ring buffer. */
  unsigned char buf[BUFFER_SIZE];

  /* Offset of the first byte in the buffer. */
  size_t offset;

  /* Number of bytes in the buffer. */
  size_t inbuf;

  /* True if the other side has sent EOF.  EOF isn't actually signalled until
     the buffer is empty. */
  Boolean eof_received;

  /* True if our write has failed due to buffer full, and we should be
     signalled when more data can be written. */
  Boolean write_has_failed;

  /* True if a read has failed because there was no data in the buffer
     (in other words, the other side should signal us when data is
     again available). */
  Boolean read_has_failed;

  /* True if this half of the stream has been destroyed. */
  Boolean destroyed;

  /* Callback to be called when we are signalled. */
  SshStreamCallback callback;
  void *context;

  /* Pointer to the other side of the pair. */
  struct SshStreamHalfRec *other;

  /* Pointer to the shared pair structure. */
  struct SshStreamPairRec *pair;
} *SshStreamHalf;

/* A data structure for the entire pair. */

typedef struct SshStreamPairRec
{
  /* Data structures for the individual pipe halfs. */
  struct SshStreamHalfRec s1, s2;

  /* Number of references.  This is decremented whenever one side is
     destroyed. */
  int references;
} *SshStreamPair;

/* Auxiliary function that signals that output buffer space is available on
   the side given as argument. */

void ssh_stream_pair_can_output(void *context)
{
  SshStreamHalf me = (SshStreamHalf)context;

  /* Signal that we can take more data. */
  if (me->callback)
    (*me->callback)(SSH_STREAM_CAN_OUTPUT, me->context);
}

/* Reads data from the internal buffer.  Returns 0 on eof, -1 if no data
   available, otherwise the number of bytes actually read. */

int ssh_stream_pair_read(void *context, unsigned char *buf, size_t size)
{
  SshStreamHalf me = (SshStreamHalf)context;
  size_t len, bytes;

  /* Keep reading data until buffer full or no more data available. */
  bytes = 0;
  while (me->inbuf > 0 && bytes < size)
    {
      /* Compute the number of contiguous bytes available. */
      len = me->inbuf;  /* At most as many as in buffer. */
      if (len > size - bytes)  /* At most as many as still space. */
        len = size - bytes;
      if (len > sizeof(me->buf) - me->offset)  /* At most until end of buf */
        len = sizeof(me->buf) - me->offset;

      /* Copy some data to the read buffer. */
      memcpy(buf + bytes, me->buf + me->offset, len);

      /* Update the ring buffer status. */
      me->offset += len;
      if (me->offset == sizeof(me->buf))
        me->offset = 0;
      me->inbuf -= len;
      SSH_ASSERT(me->offset <= sizeof(me->buf));
      bytes += len;
    }

  /* Return EOF if appropriate. */
  if (bytes == 0 && me->eof_received)
    return 0;  /* An EOF has been received. */

  /* Mark that read was successful. */
  me->read_has_failed = FALSE;

  /* Generate an event to signal the other side that it can write more data. */
  if (me->other->write_has_failed &&
      me->inbuf < sizeof(me->buf) / 2 &&
      !me->other->destroyed)
    {
      me->other->write_has_failed = FALSE;
      ssh_xregister_timeout(0L, 0L, ssh_stream_pair_can_output, me->other);
    }

  /* If couldn't read any data, return failure. */
  if (bytes == 0)
    {
      me->read_has_failed = TRUE;
      return -1;
    }
  return bytes;
}

/* Signals the side given as argument that more data is available for
   reading. */

void ssh_stream_pair_input_available(void *context)
{
  SshStreamHalf me = (SshStreamHalf)context;

  /* Signal that more data is available, if the callback is set. */
  if (me->callback)
    (*me->callback)(SSH_STREAM_INPUT_AVAILABLE, me->context);
}

/* Writes data from the buffer to the pipe.  Returns 0 if writing is no
   longer possible, -1 if the write would block, and the number of bytes
   actually written otherwise. */

int ssh_stream_pair_write(void *context, const unsigned char *buf, size_t size)
{
  SshStreamHalf me = (SshStreamHalf)context;
  size_t len, bytes, offset;

  /* If we have already sent an eof, fail. */
  if (me->other->eof_received)
    return 0;

  /* If buffer is full, return error. */
  if (me->other->inbuf == sizeof(me->other->buf) || size == 0)
    {
      /* Mark that the write has failed so that our callback will get called
         when space is again available. */
      me->write_has_failed = TRUE;
      return -1;
    }

  /* Keep copying data until either buffer full or no more data available. */
  bytes = 0;
  while (me->other->inbuf < sizeof(me->other->buf) && bytes < size)
    {
      offset = me->other->offset + me->other->inbuf;
      if (offset >= sizeof(me->other->buf))
        offset -= sizeof(me->other->buf);
      SSH_ASSERT(offset < sizeof(me->other->buf));

      len = size - bytes;  /* At most as many bytes as left. */
      if (len > sizeof(me->other->buf) - offset)
        len = sizeof(me->other->buf) - offset; /* Ring end limit */
      if (len > sizeof(me->other->buf) - me->other->inbuf)
        len = sizeof(me->other->buf) - me->other->inbuf;

      /* Copy some bytes into the buffer. */
      memcpy(me->other->buf + offset, buf + bytes, len);

      /* Update the ring buffer to indicate the new situation. */
      me->other->inbuf += len;
      SSH_ASSERT(me->other->inbuf <= sizeof(me->other->buf));
      bytes += len;
    }
  SSH_ASSERT(bytes != 0);

  /* Mark that write was successful. */
  me->write_has_failed = FALSE;

  /* Signal the other side that more data is available. */
  if (me->other->read_has_failed && !me->other->destroyed)
    {
      me->other->read_has_failed = FALSE;
      ssh_xregister_timeout(0L, 0L, ssh_stream_pair_input_available,
                           (void *)me->other);
    }
  return bytes;
}

/* Sends an eof to the other side.  The other side will first process any
   buffered data. */

void ssh_stream_pair_output_eof(void *context)
{
  SshStreamHalf me = (SshStreamHalf)context;

  /* Set the EOF flag. */
  me->other->eof_received = TRUE;

  /* If the other side is waiting for input, wake it up now. */
  if (me->other->read_has_failed && !me->other->destroyed)
    {
      me->other->read_has_failed = FALSE;
      ssh_xregister_timeout(0L, 0L, ssh_stream_pair_input_available,
                           (void *)me->other);
    }
}

/* Sets the callback. */

void ssh_stream_pair_set_callback(void *context, SshStreamCallback callback,
                           void *callback_context)
{
  SshStreamHalf me = (SshStreamHalf)context;

  me->callback = callback;
  me->context = callback_context;
  me->read_has_failed = TRUE;
  me->write_has_failed = TRUE;
  ssh_xregister_timeout(0L, 0L, ssh_stream_pair_input_available, (void *)me);
  ssh_xregister_timeout(0L, 0L, ssh_stream_pair_can_output, (void *)me);
}

/* Destroys the current side of the pipe immediately.  Closes the
   other side.  The whole pipe is destroyed when both sides have been
   freed. */

void ssh_stream_pair_destroy(void *context)
{
  SshStreamHalf me = (SshStreamHalf)context;
  SshStreamPair pair;

  me->callback = NULL_FNPTR;
  me->eof_received = TRUE;
  me->destroyed = TRUE;
  if (!me->other->eof_received)
    ssh_stream_pair_output_eof(context);
  ssh_cancel_timeouts(ssh_stream_pair_input_available, (void *)me);
  ssh_cancel_timeouts(ssh_stream_pair_can_output, (void *)me);

  pair = me->pair;
  pair->references--;
  SSH_ASSERT(pair->references >= 0);
  if (pair->references == 0)
    {
      memset(pair, 'F', sizeof(*pair));
      ssh_free(pair);
    }
}

/* Methods table for stream pairs. */

static const SshStreamMethodsStruct ssh_stream_pair_methods =
{
  ssh_stream_pair_read,
  ssh_stream_pair_write,
  ssh_stream_pair_output_eof,
  ssh_stream_pair_set_callback,
  ssh_stream_pair_destroy
};

/* Creates a pair of streams so that everything written on one stream
   will appear as output from the other stream. */

void ssh_stream_pair_create(SshStream *stream1, SshStream *stream2)
{
  SshStreamPair pair;

  pair = ssh_calloc(1, sizeof(*pair));
  if (pair == NULL)
    {
      *stream1 = *stream2 = NULL;
      return;
    }

  memset(pair, 0, sizeof(*pair));
  pair->s1.other = &pair->s2;
  pair->s2.other = &pair->s1;
  pair->s1.pair = pair;
  pair->s2.pair = pair;
  pair->references = 2;
  *stream1 = ssh_stream_create(&ssh_stream_pair_methods, (void *)&pair->s1);
  *stream2 = ssh_stream_create(&ssh_stream_pair_methods, (void *)&pair->s2);

  if (*stream1 == NULL || *stream2 == NULL)
    {
      if (*stream1)
        ssh_stream_destroy(*stream1);
      if (*stream2)
        ssh_stream_destroy(*stream2);
      *stream1 = *stream2 = NULL;
    }
}
