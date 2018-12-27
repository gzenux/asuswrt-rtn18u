/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of asynchronous stdin/stdout/stderr I/O operations.

   On Windows, file handles can not be put into non-blocking mode after
   creation. Since a process can't control how it's standard file
   handles are created by the parent, the only option to have
   non-blocking stdin in the client is to create a thread for reading
   stdin in blocking mode.

   If you can control the creation of standard file handles for a
   process (that is, you launch a client process and set its
   stdin/stdout/stderr), create standard file handles in non-blocking
   (OVERLAPPED) mode and instead of using ssh_stream_fd_stdio(), call

   ssh_stream_fd_wrap_with_callbacks(GetStdHandle(STD_INPUT_HANDLE),
                                     GetStdHandle(STD_OUTPUT_HANDLE),
                                  TRUE, NULL, NULL, NULL);

   The latter solution is more efficient and does not require the
   creation of a reader thread.

   Note: The console window is normally in a line input mode which
   means that a line of input is returned only after enter is
   pressed. To get input one char at a time, you must call
   SetConsoleMode() and disable line input.
*/









#include "sshincludes.h"
#include "sshstream.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshbuffer.h"
#include "sshthread.h"




/* Local types */

typedef struct
{
  /* Handles used for read- and write ops */
  HANDLE hstdin;
  HANDLE hstdout;

  /* If TRUE, call CloseHandle() within stream_destroy() */
  Boolean close_on_destroy;

  /* If TRUE, stdin has been closed and there is nothing to read. */
  Boolean stdin_closed;

  /* If TRUE, call stream callback when I/O can continue */
  Boolean write_has_failed;
  Boolean read_has_failed;

  /* The buffer and the synchronization object to serialize access
     to the buffer. */
  SshBuffer buffer;
  CRITICAL_SECTION guard;

  /* Callback and associated context registered by upper level */
  SshStreamCallback callback;
  void *context;

  /* Used for storing offset parameters for disk I/O operations */
  unsigned __int64 bytes_read;
  unsigned __int64 bytes_written;

  DWORD   old_input_mode;
  Boolean is_input_console;
  /* HANDLE  event_enable_read; */

  SshThread stdin_thread;

  /* Handle of event representing the reading thread. */
  HANDLE thread_event;
} *SshStdioStream;


#define SSH_DEBUG_MODULE "SshStdioStream"
#define GET_CONTEXT(a)   SshStdioStream sdata = (SshStdioStream)a;




/* Local prototypes */

static int
ssh_stream_stdio_read(void *context, unsigned char* buf, size_t size);
static int
ssh_stream_stdio_write(void *context, const unsigned char* buf, size_t size);
static void
ssh_stream_stdio_output_eof(void *context);
static void
ssh_stream_stdio_set_callback(void *context,
                           SshStreamCallback callback, void *callback_context);
static void
ssh_stream_stdio_destroy(void *context);


SshStream ssh_stream_stdio_init(SshStdioStream *s);
void ssh_stream_stdio_signal_app(void* context);
void ssh_stream_stdio_signal_disconnection(void* context);

void *thread_read_stdin(void *context);

/* Duplicates a given handle. */
HANDLE ssh_dup_handle(HANDLE src);


/* Local variables */

/* Methods table for this stream type. */
static const SshStreamMethodsStruct ssh_stream_stdio_methods =
{
  ssh_stream_stdio_read,
  ssh_stream_stdio_write,
  ssh_stream_stdio_output_eof,
  ssh_stream_stdio_set_callback,
  ssh_stream_stdio_destroy
};


static SshStream existing_stdio  = NULL;
static SshStream existing_stderr = NULL;


/* Exported functions */

/* Creates a stream around the standard input/standard output of the
   current process. */
SshStream ssh_stream_fd_stdio(void)
{
  SshStdioStream sdata;
  SshStream stdio_stream;

  if (existing_stdio)
  {
    ssh_fatal("ssh_stream_fd_stdio() called again in the same process!");
  }

  stdio_stream = ssh_stream_stdio_init(&sdata);
  sdata->hstdin  = ssh_dup_handle(GetStdHandle(STD_INPUT_HANDLE));
  sdata->hstdout = ssh_dup_handle(GetStdHandle(STD_OUTPUT_HANDLE));

  /* Create a thread that will read stdin in blocking mode. */
  sdata->stdin_thread = ssh_thread_create(thread_read_stdin, sdata);
  if (sdata->stdin_thread == NULL)
    ssh_fatal("Cannot create thread");

  /* Inform event loop of the existence of this stream. This dummy event will
   * keep us alive while the stream exists. */
  sdata->thread_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  ssh_event_loop_register_handle(sdata->thread_event, FALSE, NULL, NULL);

  existing_stdio = stdio_stream;
  return stdio_stream;
}


/* Creates a stream for standard stderr output of the current process.
   This stream is for output only, and has never anything to read.*/
SshStream ssh_stream_fd_stderr(void)
{
  SshStdioStream sdata;
  SshStream stderr_stream;

  if (existing_stderr)
  {
    ssh_fatal("ssh_stream_fd_stderr() called again in the same process!");
  }

  stderr_stream = ssh_stream_stdio_init(&sdata);
  /* Set output handle to stdout.
     stdin is NULL since it's not read. */
  sdata->hstdout = ssh_dup_handle(GetStdHandle(STD_ERROR_HANDLE));

  /* We don't have to create a read thread for stderr - it's only
     written to. */
  existing_stderr = stderr_stream;
  return stderr_stream;
}

SshStream ssh_stream_stdio_init(SshStdioStream *s)
{
  SshStdioStream sdata;
  SshStream str;

  sdata = ssh_xmalloc(sizeof(*sdata));
  memset(sdata, 0, sizeof(*sdata));

  sdata->close_on_destroy = TRUE;
  sdata->stdin_closed     = FALSE;
  sdata->read_has_failed  = FALSE;
  sdata->write_has_failed = FALSE;
  sdata->callback  = NULL;

  sdata->bytes_read    = 0;
  sdata->bytes_written = 0;

  sdata->buffer = ssh_buffer_allocate();
  /* Create the synchronization object. */
  InitializeCriticalSection(&sdata->guard);

  sdata->is_input_console   =
    GetConsoleMode(sdata->hstdin, &sdata->old_input_mode);
  /*sdata->event_enable_read = CreateEvent(NULL, FALSE, FALSE, NULL);*/

  *s = sdata;
  str = ssh_stream_create(&ssh_stream_stdio_methods, (void *)sdata);
  if (str == NULL)
    ssh_fatal("Insufficient memory available.");
  return str;
}


/* Local functions */

static int
ssh_stream_stdio_read(void *context, unsigned char* buf, size_t size)
{
  size_t bytes;
  GET_CONTEXT(context);

  SSH_ASSERT(sdata->hstdin != NULL);
  SSH_ASSERT(sdata->hstdin != INVALID_HANDLE_VALUE);

  /* Compute number of bytes to return.  If zero, indicate we don't have
     data yet. */
  EnterCriticalSection(&sdata->guard);

  bytes = ssh_buffer_len(sdata->buffer);

  /* If stdin has been closed and no data to read, return zero to indicate
   * eof. */
  if (sdata->stdin_closed && bytes == 0)
  {
    SSH_DEBUG(4, ("ssh_stream_stdio_read() returns 0"));
    goto exit;
  }

  if (bytes == 0)
  {
    sdata->read_has_failed = TRUE;
    bytes = -1;
  }
  else
  {
    sdata->read_has_failed = FALSE;

    /* Copy data out of the buffer. */
    if (bytes > size)
      bytes = size;
    memcpy(buf, ssh_buffer_ptr(sdata->buffer), bytes);
    ssh_buffer_consume(sdata->buffer, bytes);
    sdata->bytes_read += bytes;
  }
  exit:
  LeaveCriticalSection(&sdata->guard);
  return ((int)bytes);
}

static int
ssh_stream_stdio_write(void *context, const unsigned char* buf, size_t size)
{
  DWORD written;
  GET_CONTEXT(context);

  SSH_ASSERT(sdata->hstdout != NULL);
  SSH_ASSERT(sdata->hstdout != INVALID_HANDLE_VALUE);





  WriteFile(sdata->hstdout, buf, (DWORD)size, &written, NULL);
  sdata->bytes_written += written;
  return written;
}

static void
ssh_stream_stdio_output_eof(void *context)
{
  GET_CONTEXT(context);
  SSH_DEBUG(3, ("eof outputted to stdio stream."));

  /* We don't want to get more callbacks for write. */
  sdata->write_has_failed = FALSE;

  /* Close the outgoing file descriptor. */
  CloseHandle(sdata->hstdout);
  sdata->hstdout = INVALID_HANDLE_VALUE;
}

static void
ssh_stream_stdio_set_callback(void *context,
                           SshStreamCallback callback, void *callback_context)
{
  GET_CONTEXT(context);

  sdata->callback = callback;
  sdata->context  = callback_context;
  sdata->read_has_failed  = TRUE;
  sdata->write_has_failed = TRUE;

  /* do not call callback if we are write-only stdio */
  if (callback && sdata->stdin_thread)
    ssh_xregister_timeout(0, 0, ssh_stream_stdio_signal_app, sdata);
}


static void
ssh_stream_stdio_destroy(void *context)
{
  GET_CONTEXT(context);
  SSH_DEBUG(4, ("stdio stream %x is being destroyed.", context));

  /* Close the file descriptors if appropriate. */
  if (sdata->close_on_destroy)
  {
    DWORD exit_code;

    CloseHandle(sdata->hstdout);

    /* make the stdin thread exit itself by closing the handle its reading */
    if (sdata->hstdin)
      CloseHandle(sdata->hstdin);

    /* Argh! By closing the handle above, the reader thread exits nicely on
     * NT, but not on Win9x! As a workaround, I sleep some and then see if the
     * thread exited. If not, we are running on Win9x and I don't wait for the
     * thread to exit but let it run until the end of program. This is a
     * little bit ugly but works. */
    Sleep(200);
    if (GetExitCodeThread(sdata->stdin_thread, &exit_code) &&
        exit_code != STILL_ACTIVE)
    {
      /* wait for the thread to return */
      if (sdata->stdin_thread)
      {
        SSH_DEBUG(4, ("waiting for reader thread"));
        ssh_thread_join(sdata->stdin_thread);
      }
    }
  }

  sdata->callback = NULL;
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sdata);

  /* remove our thread event so the event loop may exit */
  if (sdata->thread_event)
  {
    ssh_event_loop_unregister_handle(sdata->thread_event);
    CloseHandle(sdata->thread_event);
  }

  DeleteCriticalSection(&sdata->guard);
  ssh_buffer_free(sdata->buffer);

  /* Destroy the context.  We first fill it with garbage to ease debugging. */
  memset(sdata, 'F', sizeof(*sdata));
  ssh_xfree(sdata);

  existing_stdio = NULL;

  SSH_DEBUG(4, ("stdio stream %x was destroyed.", context));
}

void
ssh_stream_stdio_signal_app(void* context)
{
  GET_CONTEXT(context);

  if (sdata->callback != NULL)
    sdata->callback(SSH_STREAM_INPUT_AVAILABLE, sdata->context);

  /* We don't need to signal SSH_STREAM_CAN_OUTPUT since writes
     to us never blocks.
  if (sdata->callback != NULL)
    sdata->callback(SSH_STREAM_CAN_OUTPUT, sdata->context); */
}

void
ssh_stream_stdio_signal_disconnection(void* context)
{
  GET_CONTEXT(context);

  sdata->stdin_closed = TRUE;

  SSH_DEBUG(3, ("disconnection signaled to stdio stream."));

  /* Notify application that the input has been disconnected. */

  /* All applications don't act on the SSH_STREAM_DISCONNECTED
     signal although they should. Therefore we send signal
     SSH_STREAM_INPUT_AVAILABLE and return zero in the read callback.
     This is another way to signal of disconnection.

     (Secure shell client is an example of an app that wants
     SSH_STREAM_INPUT_AVAILABLE and zero in the read cb.) */
  if (sdata->callback != NULL)
    sdata->callback(SSH_STREAM_INPUT_AVAILABLE, sdata->context);
  /*
    if (sdata->callback != NULL)
    sdata->callback(SSH_STREAM_DISCONNECTED, sdata->context);
  */
}



#define MAX_READ_SIZE 4096

void *thread_read_stdin(void *context)
{
  unsigned char buf[MAX_READ_SIZE];
  int read;
  int bytes_to_read;
  DWORD err;

  GET_CONTEXT(context);

  ssh_threaded_timeouts_init();

  /* If input is not a console, we can read data in bigger chunks.
     From a console we read only one user key at a time. */
  if (sdata->is_input_console)
    bytes_to_read = 1;
  else
    bytes_to_read = MAX_READ_SIZE;

  /* Read until failure. This call will block, that's why we do
     it here in another thread. */
  /* ReadFile() will fail if the parent application closes stdin, or if we
     destroy this stream. */
  SSH_DEBUG(4, ("stdin reader thread starts to read stdin."));

  while (ReadFile(sdata->hstdin, buf, bytes_to_read, &read, NULL))
  {
    /* For Win9x. This reader thread may live after stream has been
       destroyed. Let's check if we are destroyed. */
    if (existing_stdio == NULL)
      break;

    if (read > 0)
    {
      EnterCriticalSection(&sdata->guard);

      /* We shouldn't access buffer from another thread but since
         buffer manipulation is very simple, it shouldn't be a disaster. */
      ssh_buffer_append(sdata->buffer, buf, read);
      LeaveCriticalSection(&sdata->guard);

      /* Let main thread know that there is data in the stream. */
      ssh_xregister_threaded_timeout(0, 0, ssh_stream_stdio_signal_app,
                                     context);
    }
  }
  err = GetLastError();

  if (existing_stdio)
  {
    /* stdin was closed, let's inform the application about disconnection. */
    ssh_xregister_threaded_timeout(0, 0, ssh_stream_stdio_signal_disconnection,
                                   context);
  }

  ssh_threaded_timeouts_uninit();

  SSH_DEBUG(4,
            ("stdin reader thread is exiting, ReadFile() returned %d.", err));
  return NULL;
}

HANDLE ssh_dup_handle(HANDLE src)
{
  HANDLE new_handle;
  HANDLE process_current;
  BOOL   ret;

  SSH_ASSERT(src != NULL);
  process_current = GetCurrentProcess();

  ret = DuplicateHandle(process_current, src, process_current,
                        &new_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
  if (!ret)
  {
    SSH_TRACE(1, ("handle could not be duplicated, err %d", GetLastError()));
    return NULL;
  }
  return new_handle;
}














SshStream ssh_stream_fd_stdio_without_input(void)
{
  SshStdioStream sdata;
  SshStream stdio_stream;

  if (existing_stdio)
  {
    ssh_fatal("ssh_stream_fd_stdio() called again in the same process!");
  }

  stdio_stream = ssh_stream_stdio_init(&sdata);
  sdata->hstdin  = ssh_dup_handle(GetStdHandle(STD_INPUT_HANDLE));
  sdata->hstdout = ssh_dup_handle(GetStdHandle(STD_OUTPUT_HANDLE));

  existing_stdio = stdio_stream;
  return stdio_stream;
}
