/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of asynchronous file handle I/O operations.
   Utilizes ring buffers to guarantee nonblocking behavior
   of both read- and write operations. I/O completion is
   notified by events which are being waited in event loop.
*/

/* #includes */

#include "sshincludes.h"
#include "sshstream.h"
#include "sshfdstream.h"
#include "ssheloop.h"
#include "sshtimeouts.h"

/* #defines */

#define SSH_DEBUG_MODULE "SshFdStream"

#define SSH_FD_STREAM_BUF_COUNT   2
#define SSH_FD_STREAM_BUF_LENGTH  8192


/* Local types */

struct SshIoBufferRec;
typedef struct SshIoBufferRec *SshIoBuffer;

typedef BOOL (WINAPI *CANCEL_IO)(HANDLE);

typedef struct
{
  /* Handles used for read- and write ops */
  HANDLE hread;
  HANDLE hwrite;

  /* If TRUE, call CloseHandle() within stream_destroy() */
  Boolean close_on_destroy;

  /* If TRUE, no more I/O operations are allowed or performed */
  Boolean destroyed;

  /* If TRUE, call stream callback when I/O can continue */
  Boolean write_has_failed;
  Boolean read_has_failed;

  /* Callback and associated context registered by upper level */
  SshStreamCallback callback;
  void *context;

  /* Used for storing offset parameters for disk I/O operations */
  unsigned __int64 bytes_read;
  unsigned __int64 bytes_written;

  /* Number and length of allocated I/O buffers */
  unsigned read_buf_count;
  size_t read_buf_len;
  unsigned write_buf_count;
  size_t write_buf_len;

  /* Current positions in buffer rings */
  SshIoBuffer curr_read_buf;
  SshIoBuffer curr_write_buf;

  /* Current position within active read buffer */
  size_t read_buf_offset;

  /* Routines used for initiating the os and handle type dependent I/O op */
  SshLowLevelIo read;
  SshLowLevelIo write;
  SshCancelIo cancel_io;

  SshTimeoutStruct destroy_timeout;
  SshTimeoutStruct start_output_timeout;
} *SshFdStream;

typedef struct SshIoBufferRec
{
  struct SshIoBufferRec *next;

  SshFdStream sdata;

  Boolean write_buffer; /* TRUE for write buffer, FALSE for read buffer */

  OVERLAPPED overlapped;
  unsigned status;

  size_t len;
  unsigned char *addr;
  unsigned long bytes_read;

};

void ssh_io_buffer_destroy(SshIoBuffer buf)
{
  VirtualFree(buf->addr, 0, MEM_RELEASE);
  ssh_free(buf);
}

/* Local prototypes */

static int
ssh_stream_fd_read(void *context, unsigned char* buf, size_t size);
static int
ssh_stream_fd_write(void *context, const unsigned char* buf, size_t size);
static void
ssh_stream_fd_output_eof(void *context);
static void
ssh_stream_fd_set_callback(void *context,
                           SshStreamCallback callback, void *callback_context);
static void
ssh_stream_fd_destroy(void *context);

static void
ssh_stream_fd_do_read(SshIoBuffer read_buf);

static void
ssh_stream_fd_read_completed(SshIoBuffer read_buf);

static void
ssh_stream_fd_do_write(SshIoBuffer write_buf);

static void
ssh_stream_fd_write_completed(SshIoBuffer write_buf);

static unsigned
ssh_stream_fd_default_read(HANDLE h,
                           unsigned char *addr, size_t len,
                           size_t *bytes_read, SshIoBuffer read_buf);
static unsigned
ssh_stream_fd_default_write(HANDLE h,
                            unsigned char *addr, size_t len,
                            size_t *bytes_written, SshIoBuffer write_buf);

static void
ssh_stream_fd_default_cancel_io(HANDLE h, void *context);

static void
ssh_stream_fd_start_output(void* context);

static void
ssh_stream_fd_indicate_disconnection(void *context);

static SshIoBuffer
ssh_stream_fd_initialize_buffer_ring(unsigned count,
                                     size_t len,
                                     Boolean write_buffer,
                                     SshEventCallback callback,
                                     void *context);


/* Local variables */

/* Methods table for this stream type. */
static const SshStreamMethodsStruct ssh_stream_fd_methods =
{
  ssh_stream_fd_read,
  ssh_stream_fd_write,
  ssh_stream_fd_output_eof,
  ssh_stream_fd_set_callback,
  ssh_stream_fd_destroy
};


/* Exported functions */

/* Creates a file descriptor stream around the file `filenane'.  If
   the argument `readable' is TRUE, the application will read data
   from the file.  If the argument `writable' is TRUE, the application
   will write data to the file.  The function returns a stream or NULL
   if the operation fails. */

SshStream ssh_stream_fd_file(const char *filename,
                             Boolean readable,
                             Boolean writable)
{
#ifdef UNICODE
  WCHAR name[MAX_PATH];
#else
  const char *name = filename;
#endif /* UNICODE */
  HANDLE fd;
  unsigned int access;
  SshStream stream;
  DWORD attributes = FILE_ATTRIBUTE_NORMAL;

  SSH_ASSERT(filename != NULL);
  SSH_ASSERT(readable || writable);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Creating FD stream: filename='%s', readable=%u, writable=%u",
             filename, readable, writable));

  attributes |= FILE_FLAG_OVERLAPPED;

  access = 0;
  if (readable)
    access |= GENERIC_READ;
  if (writable)
    access |= GENERIC_WRITE;

#ifdef UNICODE
  ssh_ascii_to_unicode(name, sizeof(name), filename);
#endif /* UNICODE */

  fd = CreateFile(name, access, 0, NULL, OPEN_EXISTING,
                  attributes, NULL);
  if (fd == INVALID_HANDLE_VALUE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to open '%s'! (%08X)", filename, GetLastError()));
      return NULL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("'%s' successfully opened; handle=0x%p", filename, fd));

  /* Create the stream. */
  stream = ssh_stream_fd_wrap_with_callbacks(fd, fd, TRUE, NULL, NULL, NULL);
  if (stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FD stream creation failed!"));
      CloseHandle(fd);
    }

  /* Return the stream or NULL if the wrap operation failed. */
  return stream;
}


/* Creates a stream around a file descriptor.  The descriptor must be
   open for both reading and writing.  If close_on_destroy is TRUE, the
   descriptor will be automatically closed when the stream is destroyed. */

SshStream ssh_stream_fd_wrap(SshIOHandle h, Boolean close_on_destroy)
{
  return ssh_stream_fd_wrap2(h, h, close_on_destroy);
}


/* Creates a stream around two file descriptors, one for reading and
   one for writing.  `readfd' must be open for reading, and `writefd' for
   writing.  If close_on_destroy is TRUE, both descriptors will be
   automatically closed when the stream is destroyed. */

SshStream ssh_stream_fd_wrap2(SshIOHandle hread,
                              SshIOHandle hwrite,
                              Boolean close_on_destroy)
{
  return ssh_stream_fd_wrap_with_callbacks((HANDLE)hread,
                                           (HANDLE)hwrite,
                                           close_on_destroy,
                                           NULL, NULL, NULL);
}


SshStream ssh_stream_fd_wrap_with_callbacks(HANDLE hread,
                                            HANDLE hwrite,
                                            Boolean close_on_destroy,
                                            SshLowLevelIo read_func,
                                            SshLowLevelIo write_func,
                                            SshCancelIo cancel_func)
{
  SshFdStream sdata;
  SshStream str;

  sdata = ssh_calloc(1, sizeof(*sdata));
  if (sdata == NULL)
    return NULL;

  sdata->hread = hread;
  sdata->hwrite = hwrite;
  sdata->close_on_destroy = close_on_destroy;
  sdata->read_has_failed = FALSE;
  sdata->write_has_failed = FALSE;
  sdata->destroyed = FALSE;
  sdata->callback = NULL;

  sdata->bytes_read = 0;
  sdata->bytes_written = 0;
  sdata->read_buf_count = SSH_FD_STREAM_BUF_COUNT;
  sdata->read_buf_len = SSH_FD_STREAM_BUF_LENGTH;
  sdata->write_buf_count = SSH_FD_STREAM_BUF_COUNT;
  sdata->write_buf_len = SSH_FD_STREAM_BUF_LENGTH;
  sdata->curr_read_buf = NULL;
  sdata->curr_write_buf = NULL;

  sdata->read_buf_offset = 0;

  if (read_func != NULL_FNPTR)
    sdata->read = read_func;
  else
    sdata->read = ssh_stream_fd_default_read;

  if (write_func != NULL_FNPTR)
    sdata->write = write_func;
  else
    sdata->write = ssh_stream_fd_default_write;

  if (cancel_func != NULL_FNPTR)
    sdata->cancel_io = cancel_func;
  else
    sdata->cancel_io = ssh_stream_fd_default_cancel_io;

  str = ssh_stream_create(&ssh_stream_fd_methods, (void *)sdata);
  if (str == NULL)
    {
      ssh_free(sdata);
      return NULL;
    }

  return str;
}


/* Following stream routines are exported via function pointers, but
   not directly as symbols.  */

static int
ssh_stream_fd_read(void *context, unsigned char* buf, size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  size_t len, offset = 0;

  SSH_ASSERT(sdata->hread != NULL);
  SSH_ASSERT(sdata->hread != INVALID_HANDLE_VALUE);

  if (sdata->curr_read_buf == NULL)
    {
      /* Delayed initialization of the ring buffer */
      sdata->curr_read_buf =
        ssh_stream_fd_initialize_buffer_ring(sdata->read_buf_count,
                                             sdata->read_buf_len,
                                             FALSE,
                                             ssh_stream_fd_read_completed,
                                             sdata);
    }

  if (sdata->curr_read_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize buffer ring"));
      /* Memory allocation failed in ..._initialize_buffer_ring() */
      sdata->read_has_failed = TRUE;
      return 0;
    }

  if (sdata->curr_read_buf->status != ERROR_SUCCESS &&
      sdata->curr_read_buf->status != ERROR_IO_PENDING)
    {
      /* 0 indicates EOF or disconnected status */
      return 0;
    }

  sdata->read_has_failed = FALSE;

  do
    {
      if (sdata->curr_read_buf->status != ERROR_SUCCESS)
        break;

      /* If we got this far, our buffer has ERROR_SUCCESS status */

      if (sdata->curr_read_buf->len > 0)
        {
          /* Copy as much as possible to requestors buffer */
          if (size - offset < sdata->curr_read_buf->len)
            len = size - offset;
          else
            len = sdata->curr_read_buf->len;

          memcpy(buf + offset,
                 sdata->curr_read_buf->addr + sdata->read_buf_offset,
                 len);

          offset += len;
          sdata->curr_read_buf->len -= len;
          sdata->read_buf_offset += len;
        }

      if (sdata->curr_read_buf->len == 0)
        {
          /* Buffer is consumed, start new read op and switch to the
             next buffer */
          ssh_stream_fd_do_read(sdata->curr_read_buf);
          sdata->curr_read_buf = sdata->curr_read_buf->next;
          sdata->read_buf_offset = 0;
        }
    }
  while (offset < size);

  if (offset == 0)
    {
      sdata->read_has_failed = TRUE;
      /* -1 indicates 'would block' condition, which is not an error */
      return -1;
    }
  else
    {
      return ((int)offset);
    }
}


static int
ssh_stream_fd_write(void *context, const unsigned char *buf, size_t size)
{
  SshFdStream sdata = (SshFdStream)context;
  size_t len, offset = 0;

  SSH_ASSERT(sdata->hwrite != NULL);
  SSH_ASSERT(sdata->hwrite != INVALID_HANDLE_VALUE);

  if (sdata->hwrite == INVALID_HANDLE_VALUE)
    {
      sdata->write_has_failed = TRUE;
      return 0;
    }

  if (sdata->curr_write_buf == NULL)
    {
      /* Delayed initialization of the ring buffer */
      sdata->curr_write_buf =
        ssh_stream_fd_initialize_buffer_ring(sdata->write_buf_count,
                                             sdata->write_buf_len,
                                             TRUE,
                                             ssh_stream_fd_write_completed,
                                             sdata);
    }

  if (sdata->curr_write_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize buffer ring"));
      /* Memory allocation failed in ..._initialize_buffer_ring() */
      sdata->write_has_failed = TRUE;
      return 0;
    }

  if (sdata->curr_write_buf->status != ERROR_SUCCESS &&
      sdata->curr_write_buf->status != ERROR_IO_PENDING)
    /* 0 indicates EOF or disconnected status */
    return 0;

  sdata->write_has_failed = FALSE;

  do
    {
      if (sdata->curr_write_buf->status == ERROR_SUCCESS)
        {
          if (size - offset < sdata->write_buf_len)
            len = size - offset;
          else
            len = sdata->write_buf_len;

          memcpy(sdata->curr_write_buf->addr, buf + offset, len);

          offset += len;
          sdata->curr_write_buf->len = len;

          /* Asynchronously output the current buffer and switch to the next */
          ssh_stream_fd_do_write(sdata->curr_write_buf);
          sdata->curr_write_buf = sdata->curr_write_buf->next;
        }
      else
        {
          /* */
          break;
        }
    }
  while (offset < size);

  if (offset == 0)
    {
      sdata->write_has_failed = TRUE;
      /* -1 indicates 'would block' condition, which is not an error */
      return -1;
    }
  else
    {
      return ((int)offset);
    }
}


/* Signals that the application will not write anything more to the stream. */

static void
ssh_stream_fd_output_eof(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* We don't want to get more callbacks for write. */
  sdata->write_has_failed = FALSE;

  if (sdata->hwrite != NULL && sdata->hwrite != INVALID_HANDLE_VALUE)
    {
      CloseHandle(sdata->hwrite);

      if (sdata->hread == sdata->hwrite)
        sdata->hread = INVALID_HANDLE_VALUE;

      sdata->hwrite = INVALID_HANDLE_VALUE;
    }
}


static void
ssh_stream_fd_set_callback(void *context,
                           SshStreamCallback callback,
                           void *callback_context)
{
  SshFdStream sdata = (SshFdStream)context;

  ssh_cancel_timeouts(ssh_stream_fd_start_output, sdata);

  sdata->callback = callback;
  sdata->context = callback_context;
  sdata->read_has_failed = TRUE;
  sdata->write_has_failed = TRUE;

  ssh_register_timeout(&sdata->start_output_timeout, 0, 0,
                       ssh_stream_fd_start_output, sdata);
}

static void
ssh_stream_fd_start_output(void* context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* Be careful here! Stream may have been destroyed already! */
  if (sdata->callback != NULL_FNPTR && !sdata->destroyed)
    {
      (*sdata->callback)(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
      if (!sdata->destroyed)
        (*sdata->callback)(SSH_STREAM_CAN_OUTPUT, sdata->context);
    }
}

/* The actual destruction of the context, done from the bottom of the
   event loop. */
static void
ssh_stream_fd_destroy_real(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  /* Destroy the context.  We first fill it with garbage to ease
     debugging. */
  memset(sdata, 'F', sizeof(*sdata));
  ssh_free(sdata);
}


static void
ssh_stream_fd_destroy(void *context)
{
  SshFdStream sdata = (SshFdStream)context;
  SshIoBuffer first_buf, buf;

  SSH_ASSERT(context != NULL);

  /* Mark it as destroyed. */
  sdata->destroyed = TRUE;
  sdata->callback = NULL_FNPTR;

  /* Cancel pending I/O requests */
  if (sdata->hread != NULL
      && sdata->hread != INVALID_HANDLE_VALUE)
    {
      sdata->cancel_io(sdata->hread, sdata->curr_read_buf);
    }

  if (sdata->hwrite != NULL
      && sdata->hwrite != INVALID_HANDLE_VALUE
      && sdata->hwrite != sdata->hread
      )
    {
      sdata->cancel_io(sdata->hwrite, sdata->curr_write_buf);
    }

  /* Cancel pending timeouts */
  ssh_cancel_timeouts(ssh_stream_fd_start_output, sdata);
  ssh_cancel_timeouts(ssh_stream_fd_destroy_real, sdata);

  /* Unregister read buffer events from the event loop. */
  first_buf = sdata->curr_read_buf;
  buf = first_buf;
  if (buf)
    {
      do
        {
          ssh_event_loop_unregister_handle(buf->overlapped.hEvent);
          CloseHandle(buf->overlapped.hEvent);
          buf = buf->next;
        }
      while (buf != first_buf);
    }
  /* Unregister write buffer events from the event loop. */
  first_buf = sdata->curr_write_buf;
  buf = first_buf;
  if (buf)
    {
      do
        {
          ssh_event_loop_unregister_handle(buf->overlapped.hEvent);
          CloseHandle(buf->overlapped.hEvent);
          buf = buf->next;
        }
      while (buf != first_buf);
    }

  /* Close the file descriptors if appropriate. */
  if (sdata->close_on_destroy)
    {
      if (sdata->hread != NULL &&
          sdata->hread != INVALID_HANDLE_VALUE)
        {
          CloseHandle(sdata->hread);
        }

      if (sdata->hwrite != NULL &&
          sdata->hwrite != INVALID_HANDLE_VALUE &&
          sdata->hwrite != sdata->hread)
        {
          CloseHandle(sdata->hwrite);
        }

      sdata->hread = INVALID_HANDLE_VALUE;
      sdata->hwrite = INVALID_HANDLE_VALUE;
    }

  /* Free read buffers */
  first_buf = sdata->curr_read_buf;
  buf = first_buf;
  if (buf)
    {
      do
        {
          SshIoBuffer cur = buf;
          buf = buf->next;
          ssh_io_buffer_destroy(cur);
        }
      while (buf != first_buf);
    }

  /* Free write buffers */
  first_buf = sdata->curr_write_buf;
  buf = first_buf;
  if (buf)
    {
      do
        {
          SshIoBuffer cur = buf;
          buf = buf->next;
          ssh_io_buffer_destroy(cur);
         }
      while (buf != first_buf);
    }

  ssh_register_timeout(&sdata->destroy_timeout, 0L, 0L,
                       ssh_stream_fd_destroy_real, sdata);
}

/* Local functions */

static void
ssh_stream_fd_do_read(SshIoBuffer read_buf)
{
  SshFdStream sdata = read_buf->sdata;
  size_t bytes_read;
#ifdef DEBUG
  int i;

  /* Initialize buffer with ascending bytes to ease debugging */
  for (i = 0; i < sdata->read_buf_len; i++)
    read_buf->addr[i] = i + 1;
#endif

  read_buf->overlapped.Offset =
    (unsigned long)(sdata->bytes_read & 0xFFFFFFFF);
  read_buf->overlapped.OffsetHigh =
    (unsigned long)(sdata->bytes_read >> 32);
  sdata->bytes_read += sdata->read_buf_len;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("issuing read operation, read_buf=0x%p", read_buf));

  read_buf->status = sdata->read(sdata->hread,
                                 read_buf->addr,
                                 sdata->read_buf_len,
                                 &bytes_read,
                                 read_buf);

  if (read_buf->status == ERROR_SUCCESS)
    {
      /* Operation completed synchronously */
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("read operation completed synchronously, "
                         "read_buf=0x%p, bytes_read=%d, data:",
                         read_buf, bytes_read),
                        read_buf->addr, bytes_read);
      SSH_ASSERT(bytes_read <= sdata->read_buf_len);
      read_buf->len = bytes_read;
    }
  else if (read_buf->status == ERROR_IO_PENDING)
    {
      /* Overlapped I/O is pending, completion will be handled via
         event loop */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("read pending, buf=0x%p", read_buf));
    }
  else
    {
      ssh_cancel_timeouts(ssh_stream_fd_start_output, sdata);

      /* Some real I/O error occurred, let's notify the app */
      SSH_DEBUG(SSH_D_FAIL,
                ("read error, buf=0x%p, status=0x%08X",
                 read_buf, read_buf->status));
      /* signal app from the bottom of the event loop */
      ssh_register_timeout(&sdata->start_output_timeout, 0, 0,
                           ssh_stream_fd_start_output, sdata);
    }
}

static void
ssh_stream_fd_read_completed(SshIoBuffer read_buf)
{
  SshFdStream sdata = read_buf->sdata;
  unsigned bytes_read;

  if (read_buf->status != ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Read operation already completed (read_buf=0x%p)",
                 read_buf));
      return;
    }

  /* This call to GetOverlappedResult() must be non-blocking! (last
     arg == FALSE) */
  if (GetOverlappedResult(sdata->hread,
                          &read_buf->overlapped, &bytes_read, FALSE))
    {
      read_buf->status = ERROR_SUCCESS;
      read_buf->len = bytes_read;
      /* Read completed successfully */
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                        ("read operation complete, read_buf=0x%p, "
                         "bytes_read=%d, data:",
                         read_buf, bytes_read),
                        read_buf->addr, bytes_read);

      SSH_ASSERT(bytes_read <= sdata->read_buf_len);

      if (sdata->read_has_failed &&
          sdata->curr_read_buf->len >= 0 && sdata->callback)
        {
          sdata->read_has_failed = FALSE;
          sdata->callback(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
        }
    }
  else
    {
      /* Read is still pending, or there was error during operation */
      read_buf->status = GetLastError();
      if (read_buf->status == ERROR_IO_INCOMPLETE)
        {
          read_buf->status = ERROR_IO_PENDING;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("read op failed, read_buf=0x%p, status=0x%08X",
                     read_buf, read_buf->status));

          /* something went wrong, let's notify the app */
          if (sdata->callback)
            sdata->callback(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
        }
    }
}


static void
ssh_stream_fd_do_write(SshIoBuffer write_buf)
{
  SshFdStream sdata = write_buf->sdata;
  size_t bytes_written;

  write_buf->overlapped.Offset =
    (unsigned long)(sdata->bytes_written & 0xFFFFFFFF);
  write_buf->overlapped.OffsetHigh =
    (unsigned long)(sdata->bytes_written >> 32);
  sdata->bytes_written += write_buf->len;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("issuing write operation, write_buf=0x%p", write_buf));

  write_buf->status = sdata->write(sdata->hwrite,
                                   write_buf->addr,
                                   write_buf->len,
                                   &bytes_written,
                                   write_buf);

  if (write_buf->status == ERROR_SUCCESS)
    {
      /* Operation completed synchronously */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("write completed synchronously, write_buf=0x%p", write_buf));
      SSH_ASSERT(bytes_written == write_buf->len);
      write_buf->len = 0;
    }
  else if (write_buf->status == ERROR_IO_PENDING)
    {
      /* Overlapped I/O is pending, completion will be handled via
         event loop */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("write pending, write_buf=0x%p", write_buf));
    }
  else
    {
      /* Some real I/O error occurred, this will be seen as soon as
         this becomes the current buffer */
      SSH_DEBUG(SSH_D_FAIL,
                ("write error, write_buf=0x%p, status=0x%08X",
                 write_buf, write_buf->status));
    }
}


static void
ssh_stream_fd_write_completed(SshIoBuffer write_buf)
{
  SshFdStream sdata = write_buf->sdata;
  unsigned bytes_written;

  if (write_buf->status != ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Write operation already completed (write_buf=0x%p)",
                 write_buf));
      return;
    }

  /* This call to GetOverlappedResult() must be non-blocking! (last
     arg == FALSE) */
  if (GetOverlappedResult(sdata->hwrite,
                          &write_buf->overlapped, &bytes_written, FALSE))
    {
      write_buf->status = ERROR_SUCCESS;
      /* Write completed successfully */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Write operation complete, write_buf=0x%p, bytes_written=%u",
                 write_buf, bytes_written));

      write_buf->len = 0;

      if (sdata->write_has_failed && sdata->callback)
        {
          sdata->write_has_failed = FALSE;
          sdata->callback(SSH_STREAM_CAN_OUTPUT, sdata->context);
        }
    }
  else
    {
      /* Write is still pending, or there was error during operation */
      write_buf->status = GetLastError();
      if (write_buf->status == ERROR_IO_INCOMPLETE)
        {
          write_buf->status = ERROR_IO_PENDING;
        }
      else
        if (write_buf->status == ERROR_BROKEN_PIPE)
        {
          /* Pipe has been broken. Signal application (return 0 from stream
            write function). */
          SSH_DEBUG(SSH_D_FAIL, ("Broken pipe!"));

          if (sdata->callback)
            sdata->callback(SSH_STREAM_CAN_OUTPUT, sdata->context);
        }
    }
}


/* Default low-level read routine */
static unsigned
ssh_stream_fd_default_read(HANDLE h,
                           unsigned char *addr, size_t len,
                           size_t *bytes_read,
                           SshIoBuffer read_buf)
{
  DWORD size = (DWORD)len;

  if (ReadFile(h, addr, size, &size, &read_buf->overlapped))
    {
      *bytes_read = size;
      return ERROR_SUCCESS;
    }
  else
    {
      *bytes_read = size;
      return GetLastError();
    }
}


/* Default low-level write routine */
static unsigned
ssh_stream_fd_default_write(HANDLE h,
                            unsigned char *addr, size_t len,
                            size_t *bytes_written,
                            SshIoBuffer write_buf)
{
  DWORD size = (DWORD)len;

  if (WriteFile(h, addr, size, &size, &write_buf->overlapped))
    {
      *bytes_written = size;
      return ERROR_SUCCESS;
    }
  else
    {
      *bytes_written = size;
      return GetLastError();
    }
}


/* Default low-level cancel I/O routine */
static void
ssh_stream_fd_default_cancel_io(HANDLE h,
                                void *context)
{
  CANCEL_IO cancel_io = (CANCEL_IO) GetProcAddress(
                                            GetModuleHandle("KERNEL32.DLL"),
                                            "CancelIo");

  if (cancel_io != NULL)
    {
      cancel_io(h);
    }
}


static void
ssh_stream_fd_indicate_disconnection(void *context)
{
  SshFdStream sdata = (SshFdStream)context;

  if (sdata->callback)
    {
      sdata->callback(SSH_STREAM_DISCONNECTED, sdata->context);
    }
}


static SshIoBuffer
ssh_stream_fd_initialize_buffer_ring(unsigned count,
                                     size_t len,
                                     Boolean write_buffer,
                                     SshEventCallback callback,
                                     void *context)
{
  SshIoBuffer buf, first_buf = NULL, prev_buf = NULL;
  unsigned i;

  for (i = 0; i < count; i++)
    {
      Boolean manual_reset = FALSE;
      buf = ssh_calloc(1, sizeof(*buf));
      if (buf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to allocate I/O buffer descriptor"));
          return first_buf;
        }

      buf->addr = VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
      if (buf->addr == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate I/O buffer"));
          ssh_free(buf);
          return first_buf;
        }

      buf->overlapped.hEvent = CreateEvent(NULL, manual_reset, FALSE, NULL);
      if (buf->overlapped.hEvent == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to create I/O completion event"));
          ssh_io_buffer_destroy(buf);
          return first_buf;
        }

      buf->write_buffer = write_buffer;
      buf->sdata = context;
      buf->len = 0;
      SSH_ASSERT(buf->addr != NULL);
      buf->status = ERROR_SUCCESS;

      if (first_buf == NULL)
        first_buf = buf;
      if (prev_buf)
        prev_buf->next = buf;
      prev_buf = buf;
      buf->next = first_buf;

      ssh_event_loop_register_handle(buf->overlapped.hEvent,
                                     manual_reset, callback, buf);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Allocated & registered buffer 0x%p (addr=0x%p, event=0x%p)",
                 buf, buf->addr, buf->overlapped.hEvent));
    }

  return first_buf;
}

/* Creates a stream around the standard input/standard output of the
   current process. SEE sshwinstdiostream.c. */
/* SshStream ssh_stream_fd_stdio(void) */


/* Returns the file descriptor being used for reads, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_readfd(SshStream stream)
{



  ssh_fatal("ssh_stream_fd_get_readfd: Not implemented on this platform");
  return 0;
}
/* Returns the file descriptor being used for writes, or -1 if the stream is
   not an fd stream. */
SshIOHandle ssh_stream_fd_get_writefd(SshStream stream)
{



  ssh_fatal("ssh_stream_fd_get_writefd: Not implemented on this platform");
  return 0;
}

/* Marks the stream as a forked copy.  The consequence is that when the stream
   is destroyed, the underlying file descriptors are not restored to blocking
   mode.  This should be called for each stream before destroying them
   after a fork (but only on one of parent or child). */
void ssh_stream_fd_mark_forked(SshStream stream)
{



  ssh_fatal("ssh_stream_fd_mark_forked: Not implemented on this platform");
}

/* EOF */
