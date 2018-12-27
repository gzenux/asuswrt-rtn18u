/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Streams interface interfacing to file descriptors on Unix.
*/

#include "sshincludes.h"
#include "sshfdstream.h"
#include "ssheloop.h"
#include "sshtimeouts.h"

#include <sys/socket.h>  /* for shutdown() */

#define SSH_DEBUG_MODULE "SshFdStream"

typedef struct
{
  SshIOHandle readfd;
  SshIOHandle writefd;
  Boolean close_on_destroy;

  Boolean write_has_failed;
  Boolean read_has_failed;
  Boolean destroyed;
  Boolean keep_nonblocking;

  SshStreamCallback callback;
  void *context;

  void (*close_callback)(void *);
  void *close_param;

  /* This is here to avoid strange bugs with memory-allocation failures
     during destroy (not easy to get info about that to the
     application). */
  SshTimeoutStruct destroy_timeout;
} *SshFdStream;

/* The method structure is defined later in this file. */
static const SshStreamMethodsStruct ssh_stream_fd_methods;

/* Methods table for this stream type. */

int ssh_stream_fd_read(void *context, unsigned char *buf, size_t size);
int ssh_stream_fd_write(void *context, const unsigned char *buf, size_t size);
void ssh_stream_fd_output_eof(void *context);
void ssh_stream_fd_set_callback(void *context, SshStreamCallback callback,
                                void *callback_context);
void ssh_stream_fd_destroy(void *context);

static const SshStreamMethodsStruct ssh_stream_fd_methods =
{
  ssh_stream_fd_read,
  ssh_stream_fd_write,
  ssh_stream_fd_output_eof,
  ssh_stream_fd_set_callback,
  ssh_stream_fd_destroy
};

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE,
   the descriptor will be automatically closed when the stream is
   destroyed. */

SshStream ssh_stream_fd_wrap(SshIOHandle fd, Boolean close_on_destroy)
{
  return ssh_stream_fd_wrap2(fd, fd, close_on_destroy);
}

SshStream
ssh_stream_fd_wrap_with_close_callback(SshIOHandle fd,
                                       void (*close_callback)(void *),
                                       void *close_param,
                                       Boolean close_on_destroy)
{
  SshStream stream;

  stream = ssh_stream_fd_wrap2(fd, fd, close_on_destroy);
  if (stream != NULL)
    {
      SshFdStream sdata = ssh_stream_get_context(stream);

      sdata->close_callback = close_callback;
      sdata->close_param = close_param;
    }

  return stream;
}

/* Creates a stream around the standard input/standard output of the
   current process. */

SshStream ssh_stream_fd_stdio(void)
{
  SshStream str;
  str = ssh_stream_fd_wrap2(0, 1, FALSE);
  if (str == NULL)
    ssh_fatal("Insufficient resources to create stdio stream");
  return str;
}

/* Stderr */
SshStream ssh_stream_fd_stderr(void)
{
  SshStream str;
  str = ssh_stream_fd_wrap2(2, 2, FALSE);
  if (str == NULL)
    ssh_fatal("Insufficient resources to create stderr stream");
  return str;
}

/* Recompute and set event loop request masks for the file descriptors. */

void ssh_stream_fd_request(SshFdStream sdata)
{
  unsigned int read_request, write_request;

  assert(!sdata->destroyed);

  if (sdata->read_has_failed)
    read_request = SSH_IO_READ;
  else
    read_request = 0;

  if (sdata->write_has_failed)
    write_request = SSH_IO_WRITE;
  else
    write_request = 0;

  if (sdata->readfd == sdata->writefd)
    {
      if (sdata->readfd >= 0)
        ssh_io_set_fd_request(sdata->readfd, read_request | write_request);
    }
  else
    {
      if (sdata->readfd >= 0)
          ssh_io_set_fd_request(sdata->readfd, read_request);
      if (sdata->writefd >= 0)
          ssh_io_set_fd_request(sdata->writefd, write_request);
    }
}

/* This function is called by the event loop whenever an event of interest
   occurs on one of the file descriptors. */

void ssh_stream_fd_callback(unsigned int events, void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* This might get called by a pending callback, and might have been
     destroyed in the meanwhile.  Thus, we check for destroyed status.
     Note that no such events should come after the generated event that
     actually frees the context. */
  if (sdata->destroyed)
    return;

  /* Convert the event loop callback to a stream callback. */
  if (events & SSH_IO_READ)
    {
      sdata->read_has_failed = FALSE;
      if (sdata->callback)
        (*sdata->callback)(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
    }
  if ((events & SSH_IO_WRITE) && !sdata->destroyed)
    {
      sdata->write_has_failed = FALSE;
      if (sdata->callback)
        (*sdata->callback)(SSH_STREAM_CAN_OUTPUT, sdata->context);
    }

  /* Check if the stream got destroyed in the callbacks. */
  if (sdata->destroyed)
    return;

  /* Recompute the request masks.  Note that the context might have been
     destroyed by one of the earlier callbacks. */
  ssh_stream_fd_request(sdata);
}

/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is TRUE, both descriptors will be
   automatically closed when the stream is destroyed. */

SshStream ssh_stream_fd_wrap2(SshIOHandle readfd, SshIOHandle writefd,
                              Boolean close_on_destroy)
{
  SshFdStream sdata;
  SshStream str;

  sdata = ssh_malloc(sizeof(*sdata));

  if (sdata == NULL)
    return NULL;

  memset(sdata, 0, sizeof(*sdata));
  sdata->readfd = readfd;
  sdata->writefd = writefd;
  sdata->close_on_destroy = close_on_destroy;
  sdata->read_has_failed = FALSE;
  sdata->write_has_failed = FALSE;
  sdata->destroyed = FALSE;
  sdata->keep_nonblocking = FALSE;
  sdata->callback = NULL_FNPTR;
  if (readfd >= 0)
    {
      if (ssh_io_register_fd(readfd, ssh_stream_fd_callback, (void *)sdata)
           == FALSE )
        {
          ssh_free(sdata);
          return NULL;
        }
    }
  if (readfd != writefd && writefd >= 0)
    {
      if (ssh_io_register_fd(writefd, ssh_stream_fd_callback, (void *)sdata)
           == FALSE )
        {
          if (readfd >= 0)
            ssh_io_unregister_fd(readfd,TRUE);
          ssh_free(sdata);
          return NULL;
        }
    }
  str = ssh_stream_create(&ssh_stream_fd_methods, (void *)sdata);
  if (str == NULL)
    {
      ssh_free(sdata);
      if (readfd >= 0)
        ssh_io_unregister_fd(readfd, TRUE);
      if (readfd != writefd && writefd >= 0)
        ssh_io_unregister_fd(writefd, TRUE);
      return NULL;
    }
  return str;

}

/* Reads at most `size' bytes to the buffer `buffer'.  Returns 0 if
  EOF is encountered, negative value if the read would block, and
  the number of bytes read if something was read. */

int ssh_stream_fd_read(void *context, unsigned char *buf, size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  int len;

  assert(!sdata->destroyed);
  if (sdata->readfd >= 0)
    {
#ifndef VXWORKS
      SSH_HEAVY_DEBUG(99, ("fd %d is %sin non-blocking mode.", sdata->readfd,
                           (fcntl(sdata->readfd, F_GETFL, 0)
                            & (O_NONBLOCK|O_NDELAY)) != 0 ?
                           "" : "not "));
#endif /* VXWORKS */
      len = read(sdata->readfd, buf, size);
      if (len >= 0)
        return len;

      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        {
          /* No more data available at this time. */
          sdata->read_has_failed = TRUE;
          ssh_stream_fd_request(sdata);
          return -1;
        }

      /* A real error occurred while reading. */
      sdata->read_has_failed = TRUE;
      ssh_stream_fd_request(sdata);
    }
  return 0;
}

/* Writes at most `size' bytes from the buffer `buffer'.  Returns 0 if the
   other end has indicated that it will no longer read (this condition is not
   guaranteed to be detected), a negative value if the write would block,
   and the number of bytes written if something was actually written. */

int ssh_stream_fd_write(void *context, const unsigned char *buf, size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  int len;

  assert(!sdata->destroyed);
  if (sdata->writefd >= 0)
    {
      len = (int)(write(sdata->writefd, (void *)buf, size));
      if (len > 0)
        return len;

      /* In NetBSD current (2003/06/10) write() may return 0, and
         the filedescriptor is still valid. */
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
          /* Mystical special case. */
          (len == 0 && errno == 0))
        {
          /* Cannot write more at this time. */
          sdata->write_has_failed = TRUE;
          ssh_stream_fd_request(sdata);
          return -1;
        }
      else if (len == 0)
        {
          SSH_DEBUG(4, ("write() returned 0. (and errno does not indicate "
                        "that the fd just couldn't be written at this time)"));
          return 0;
        }
      /* A real error occurred while writing. */
      sdata->write_has_failed = TRUE;
      ssh_stream_fd_request(sdata);
    }
  return 0;
}

/* Signals that the application will not write anything more to the stream. */

void ssh_stream_fd_output_eof(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  assert(!sdata->destroyed);

  /* We don't want to get more callbacks for write. */
  sdata->write_has_failed = FALSE;

  if (sdata->writefd >= 0)
    {
      if (sdata->writefd == sdata->readfd)
        {
          /* Note: if writefd is not a socket, this will do nothing. */
          shutdown(sdata->writefd, 1);
        }
      else
        {
          /* Close the outgoing file descriptor. */
          ssh_io_unregister_fd(sdata->writefd, sdata->keep_nonblocking);
          close(sdata->writefd);
          sdata->writefd = -1;
        }
    }
}

/* Sets the callback that the stream uses to notify the application of
   events of interest.  This function may be called at any time, and
   may be called multiple times.  The callback may be NULL, in which
   case it just won't be called.  Setting the callback to non-NULL
   will result in a call to the callback, latest when something can be
   done.  Applications can rely on doing all I/O in the callback, if
   they wish. */

void ssh_stream_fd_set_callback(void *context, SshStreamCallback callback,
                                void *callback_context)
{
  SshFdStream sdata = (SshFdStream)context;

  assert(!sdata->destroyed);
  sdata->callback = callback;
  sdata->context = callback_context;
  sdata->read_has_failed = TRUE;
  sdata->write_has_failed = TRUE;
  ssh_stream_fd_request(sdata);
  if (callback != NULL_FNPTR)
    {
      (*callback)(SSH_STREAM_INPUT_AVAILABLE, callback_context);
      /* check that stream was not destroyed in above callback */
      if (!sdata->destroyed)
        (*callback)(SSH_STREAM_CAN_OUTPUT, callback_context);
    }
}

/* The actual destruction of the context, done from the bottom of the
   event loop. */
void ssh_stream_fd_destroy_real(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* Destroy the context.  We first fill it with garbage to ease
     debugging. */
  memset(sdata, 'F', sizeof(*sdata));
  ssh_free(sdata);
}

/* Closes, destroys, and frees the given stream.  Destruction is delayed,
   and the actual freeing is done from the bottom of the event loop.  This
   is needed because we might generated pending events for the object. */

void ssh_stream_fd_destroy(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* Mark it as destroyed. */
  assert(!sdata->destroyed);
  sdata->destroyed = TRUE;
  sdata->callback = NULL_FNPTR;

  /* Unregister the descriptors from the event loop. */
  if (sdata->readfd >= 0)
    ssh_io_unregister_fd(sdata->readfd, sdata->keep_nonblocking);
  if (sdata->readfd != sdata->writefd && sdata->writefd >= 0)
    ssh_io_unregister_fd(sdata->writefd, sdata->keep_nonblocking);

  /* Call the close callback if appropriate. */
  if (sdata->close_callback != NULL)
    {
      sdata->close_callback(sdata->close_param);
    }

  /* Close the file descriptors if appropriate. */
  if (sdata->close_on_destroy)
    {
      if (sdata->readfd >= 0)
        close(sdata->readfd);
      if (sdata->readfd != sdata->writefd && sdata->writefd >= 0)
        close(sdata->writefd);
      sdata->writefd = -1;
      sdata->readfd = -1;
    }

  ssh_register_timeout(&sdata->destroy_timeout, 0L, 0L,
                       ssh_stream_fd_destroy_real, sdata);
}

/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */

SshIOHandle ssh_stream_fd_get_readfd(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return -1;
  return ((SshFdStream)ssh_stream_get_context(stream))->readfd;
}

/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */

SshIOHandle ssh_stream_fd_get_writefd(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return -1;
  return ((SshFdStream)ssh_stream_get_context(stream))->writefd;
}

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */

void ssh_stream_fd_mark_forked(SshStream stream)
{
  if (ssh_stream_get_methods(stream) != &ssh_stream_fd_methods)
    return;
  ((SshFdStream)ssh_stream_get_context(stream))->keep_nonblocking = TRUE;
}

/* Creates a file descriptor stream around the file `filename'.  If
   the argument `readable' is TRUE, the application will read data
   from the file.  If the argument `writable' is TRUE, the application
   will write data to the file.  The function returns a stream or NULL
   if the operation fails. */

SshStream ssh_stream_fd_file(const char *filename, Boolean readable,
                             Boolean writable)
{
  SshIOHandle fd;
  int mode;
  SshStream stream;

  SSH_ASSERT(readable || writable);
  if (readable && writable)
    mode = O_RDWR;
  else if (readable)
    mode = O_RDONLY;
  else
    mode = O_WRONLY;

  fd = open(filename, mode, 0);
  if (fd < 0)
    return NULL;

  /* Create the stream. */
  stream = ssh_stream_fd_wrap(fd, TRUE);
  if (stream == NULL)
    close(fd);

  /* Return the stream or NULL if the wrap operation failed. */
  return stream;
}


