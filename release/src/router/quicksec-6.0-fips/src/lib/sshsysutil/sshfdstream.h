/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Streams interface interfacing to file descriptors on Unix
   and Win32 platforms.
*/

#ifndef SSHFDSTREAM_H
#define SSHFDSTREAM_H

#include "sshstream.h"

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE, the
   descriptor will be automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap(SshIOHandle fd, Boolean close_on_destroy);

/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is TRUE, both descriptors will be
   automatically closed when the stream is destroyed. */
SshStream ssh_stream_fd_wrap2(SshIOHandle readfd, SshIOHandle writefd,
                              Boolean close_on_destroy);

/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE, the
   descriptor will be automatically closed when the stream is destroyed.
   Calls close callback with close param when closed.
*/
SshStream
ssh_stream_fd_wrap_with_close_callback(SshIOHandle fd,
                                       void (*close_callback)(void *),
                                       void *close_param,
                                       Boolean close_on_destroy);


/* Creates a stream around the standard input/standard output of the
   current process. */
SshStream ssh_stream_fd_stdio(void);

/* Creates a stream for stderr output of the current process.
   This stream is for output only, and has never anything to read.*/
SshStream ssh_stream_fd_stderr(void);

/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_readfd(SshStream stream);

/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_writefd(SshStream stream);

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */
void ssh_stream_fd_mark_forked(SshStream stream);

/* Creates a file descriptor stream around the file `filenane'.  If
   the argument `readable' is TRUE, the application will read data
   from the file.  If the argument `writable' is TRUE, the application
   will write data to the file.  The function returns a stream or NULL
   if the operation fails. */
SshStream ssh_stream_fd_file(const char *filename, Boolean readable,
                             Boolean writable);

#ifdef WIN32
/* Callback function for performing actual I/O-operations using some
   other means than the standard read- or write- calls of the
   underlying O/S.  Currently this is used only for implementing Win95
   device streams (which uses DeviceIoControl for transferring the
   data). Callback implementation is responsible to fill the
   'bytes_transferred' field with true number of successfully read or
   written bytes. */

typedef unsigned int (*SshLowLevelIo)(HANDLE handle,
                                      unsigned char *addr,
                                      size_t len,
                                      size_t *bytes_transferred,
                                      void *context);

/* Callback function for performing actual cancel I/O -operation using some
   other means than the standard cancel I/O call of the underlying O/S.
   Currently this is used only for implementing Win95 device streams
   (which uses DeviceIoControl for cancelling the pending read/write
   requests). */

typedef void (*SshCancelIo)(HANDLE handle,
                            void *context);

/* Creates a stream around two file handles, one for reading and one
   for writing. `readfd' must be open for reading, and `writefd' for
   writing.  This version uses 'read_func' and 'write_func' for doing
   real I/O ops with the operating system. */

SshStream ssh_stream_fd_wrap_with_callbacks(HANDLE read_handle,
                                            HANDLE write_handle,
                                            Boolean close_on_destroy,
                                            SshLowLevelIo read_func,
                                            SshLowLevelIo write_func,
                                            SshCancelIo cancel_io_func);

#endif /* WIN32 */

#endif /* SSHFDSTREAM_H */
