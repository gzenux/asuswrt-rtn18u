/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Displaying debugging, warning, and fatal error messages.
   Sending messages to the system log.
*/

#include "sshincludes.h"

#ifdef VXWORKS
#include "intLib.h"
#endif /* VXWORKS */

/* We have real globals in the kernel. */
#ifdef SSH_GLOBALS_EMULATION
#undef SSH_GLOBALS_EMULATION
#endif /* not SSH_GLOBALS_EMULATION */

#include "sshdebug.h"
#include "sshglobals.h"
#ifdef HAVE_SYS_SELECT_H
#if !defined(KERNEL) || !defined(__linux__)
#include <sys/select.h>
#else /* KERNEL && __linux__*/
#include <linux/kernel.h>
#endif /* !defined(KERNEL) || !defined(__linux__) */
#endif /* HAVE_SYS_SELECT_H */


/* Be very careful in calling debugging output from the debugging
   module itself. Careless introduction of debugging constructs could
   lead to a recursive loop. Do not add them if you do not know what
   you are doing.

   Here is a comprehensive list of debugging constructs appearing in
   the module itself:

   1. SSH_ASSERT in ssh_debug_wait_fd_writable
   2. SSH_ASSERT * 2 in ssh_debug_print
*/

#define SSH_DEBUG_MODULE "SshFatal"

/* Size of buffers used in formatting the messages in ssh_debug functions. */
#ifdef KERNEL
#define SSH_DEBUG_BUFFER_SIZE 256
#else /* KERNEL */
#define SSH_DEBUG_BUFFER_SIZE 1024
#endif /* KERNEL */

SSH_GLOBAL_DECLARE(int, ssh_error_initialized);
#define ssh_error_initialized SSH_GLOBAL_USE(ssh_error_initialized)
SSH_GLOBAL_DEFINE(int, ssh_error_initialized);

/* Callbacks to which the debugging/error/log messages are delivered. */
SSH_GLOBAL_DECLARE(SshErrorCallback, ssh_debug_fatal_callback);
#define ssh_debug_fatal_callback SSH_GLOBAL_USE(ssh_debug_fatal_callback)
SSH_GLOBAL_DEFINE(SshErrorCallback, ssh_debug_fatal_callback);

SSH_GLOBAL_DECLARE(SshErrorCallback, ssh_debug_warning_callback);
#define ssh_debug_warning_callback SSH_GLOBAL_USE(ssh_debug_warning_callback)
SSH_GLOBAL_DEFINE(SshErrorCallback, ssh_debug_warning_callback);

SSH_GLOBAL_DECLARE(SshErrorCallback, ssh_debug_debug_callback);
#define ssh_debug_debug_callback SSH_GLOBAL_USE(ssh_debug_debug_callback)
SSH_GLOBAL_DEFINE(SshErrorCallback, ssh_debug_debug_callback);

SSH_GLOBAL_DECLARE(void *, ssh_debug_error_context);
#define ssh_debug_error_context SSH_GLOBAL_USE(ssh_debug_error_context)
SSH_GLOBAL_DEFINE(void *, ssh_debug_error_context);

SSH_GLOBAL_DECLARE(SshLogCallback, ssh_debug_log_callback);
#define ssh_debug_log_callback SSH_GLOBAL_USE(ssh_debug_log_callback)
SSH_GLOBAL_DEFINE(SshLogCallback, ssh_debug_log_callback);

SSH_GLOBAL_DECLARE(void *, ssh_debug_log_context);
#define ssh_debug_log_context SSH_GLOBAL_USE(ssh_debug_log_context)
SSH_GLOBAL_DEFINE(void *, ssh_debug_log_context);


/* Initializes debug system if not done already. */
void
ssh_error_maybe_initialize(void)
{
  if
#ifdef SSH_GLOBALS_EMULATION
         /* On emulated environments the check is sufficient proof of
            initialization, the value can (does not have to) be
            ignored. */
         (!ssh_global_check("ssh_error_initialized"))
#else
         (!ssh_error_initialized)
#endif
    {
      SSH_GLOBAL_INIT(ssh_error_initialized, 1);

      SSH_GLOBAL_INIT(ssh_debug_fatal_callback, NULL_FNPTR);
      SSH_GLOBAL_INIT(ssh_debug_warning_callback, NULL_FNPTR);
      SSH_GLOBAL_INIT(ssh_debug_debug_callback, NULL_FNPTR);
      SSH_GLOBAL_INIT(ssh_debug_error_context, NULL);

      SSH_GLOBAL_INIT(ssh_debug_log_callback, NULL_FNPTR);
      SSH_GLOBAL_INIT(ssh_debug_log_context, NULL);
    }
}

#ifndef KERNEL
/*
 *  Waits until given output file descriptor allows
 *  to be written on again.
 *
 */

#if 0
static int
ssh_debug_wait_fd_readable(unsigned int filedes, unsigned long wait,
                           size_t *reason)
{
  struct timeval tv;
  fd_set fdset;
  int ret;

  /* Initialize the file descriptor set. */
  FD_ZERO(&fdset);
  FD_SET(filedes, &fdset);

  /* set timeout values */
  memset((void *)&tv, 0, sizeof(tv));

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  errno = 0;

  if (wait > 0)
    {
      tv.tv_sec = wait / 1000000;
      tv.tv_usec = wait % 1000000;
      ret = select(filedes + 1, &fdset, NULL, NULL, &tv);
    }
  else
    {
      ret = select(filedes + 1, &fdset, NULL, NULL, NULL);
    }

  if (ret > 0)
    {
      SSH_ASSERT(FD_ISSET(filedes, &fdset));
    }
  else
    {
      if (ret < 0 && reason)
        *reason = errno;
    }
  return ret;
}
#endif /* 0 */

static int
ssh_debug_wait_fd_writable(unsigned int filedes, unsigned long wait,
                           size_t *reason)
{
  struct timeval tv;
  fd_set fdset;
  int ret;

  /* Initialize the file descriptor set. */
  FD_ZERO(&fdset);
  FD_SET(filedes, &fdset);

  /* set timeout values */
  memset((void *)&tv, 0, sizeof(tv));

  /* select returns 0 if timeout, 1 if input available, -1 if error. */
  errno = 0;

  if (wait > 0)
    {
      tv.tv_sec = (long)(wait / 1000000);
      tv.tv_usec = (long)(wait % 1000000);
      ret = select(filedes + 1, NULL, &fdset, NULL, &tv);
    }
  else
    {
      ret = select(filedes + 1, NULL, &fdset, NULL, NULL);
    }

  if (ret > 0)
    {
      SSH_ASSERT(FD_ISSET(filedes, &fdset));
    }
  else
    {
      if (ret < 0 && reason)
        *reason = errno;
    }
  return ret;
}

static int
ssh_debug_stream_unbuffer(FILE *stream)
{
  fflush(stream);
  setvbuf(stream, NULL, _IONBF, 0);

  return 0;
}

int
ssh_debug_set_stream_unbuffered(FILE *stream)
{
  ssh_debug_stream_unbuffer(stdout);
  ssh_debug_stream_unbuffer(stderr);
  ssh_debug_stream_unbuffer(stream);

  return 0;
}

/*
 *  Tries to write the whole string in 'buf'
 *  to the stream. Appends a newline if requested by boolean cr.
 *
 */
void
ssh_debug_print(FILE *stream, const char *buf)
{
  size_t len;
  size_t c;
  size_t reason;
  int fd;
  int r;
  int result;
  len = strlen(buf);
  c = 0;
  fd = fileno(stream);

  for (;;)
    {
      errno = 0;
      r = (int)(write(fd, (char *)buf + c, len - c));
      if (r > 0)
        {
          c += r;

          if (c == len)
            {
              /* We have managed to write everything */
              return;
            }
        }
      else
        {
          /* In NetBSD current (2003/06/10) write() may return 0, and
             the filedescriptor is still valid. */
          if (len == 0 && errno == 0)
            break;

          SSH_ASSERT(errno != 0);
          if (errno != EAGAIN &&
#ifdef EWOULDBLOCK
              errno != EWOULDBLOCK &&
#endif /* EWOULDBLOCK */
              errno != EINTR)
            break;
        }

      do
        {
          reason = 0;
          result = ssh_debug_wait_fd_writable(fd, 0, &reason);
        } while (result == -1 && reason == EINTR);
      SSH_ASSERT(result == 1);
    }
}
#endif /* !KERNEL */

/* Outputs a warning message. */

void ssh_warning(const char *fmt, ...)
{
  va_list va;
  unsigned char buf[SSH_DEBUG_BUFFER_SIZE];
  static int initd = 0;

  /* Format the message. */
  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  ssh_error_maybe_initialize();
  if (!initd)
    {
      initd = 1;
#ifndef KERNEL
      ssh_debug_set_stream_unbuffered(stderr);
#endif /* not KERNEL */
    }

  /* Send the message to the callback registered for warning messages,
     or use default handling. */
  if (ssh_debug_warning_callback)
    {
      (*ssh_debug_warning_callback)((char *) buf, ssh_debug_error_context);
    }
  else
    {
# ifndef KERNEL
      ssh_debug_print(stderr, (char *) buf);
      ssh_debug_print(stderr, "\n");
# endif /* KERNEL */
    }
}

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
extern STATUS tt(int);
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

/* Outputs a fatal error message.  This function never returns. */

void ssh_fatal(const char *fmt, ...)
{
  va_list va;
  unsigned char buf[SSH_DEBUG_BUFFER_SIZE];
  static int initd = 0;

  /* Format the message. */
  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  ssh_error_maybe_initialize();
  if (!initd)
    {
      initd = 1;
#ifndef KERNEL
      ssh_debug_set_stream_unbuffered(stderr);
#endif /* not KERNEL */
    }

  /* Send it to the callback, or do default handling if no callback has
     been specified. */
  if (ssh_debug_fatal_callback)
    {
      (*ssh_debug_fatal_callback)((char *) buf, ssh_debug_error_context);
    }
  else
    {
# ifndef KERNEL
      ssh_debug_print(stderr, (char *) buf);
      ssh_debug_print(stderr, "\n");
      fflush(stderr);
# endif /* KERNEL */
    }

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
  /* spawn a helper task which would print stack trace of this one */
  sp((FUNCPTR)tt, taskIdSelf(), 0,0,0,0, 0,0,0,0);
  /* suspend ourselves, allow for debugging */
  taskSuspend(0);
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

  /* Cause a fatal error on the current program; this is the fatal
     error handler, and should never return. */
#ifndef KERNEL
  if (getenv("SSH_FATAL_EXIT_0"))
    {
      exit(0);
    }
  else if (getenv("SSH_FATAL_EXIT_42"))
    {
      exit(42);
    }
  else
    {
      abort();
      exit(1);
    }
#else /* KERNEL */
#ifdef __linux__
#ifndef FASTPATH_IS_TILEGX
  panic(buf);
#endif /* FASTPATH_IS_TILEGX */
#endif /* __linux__ */
#endif /* KERNEL */
}

/* Defines callbacks that will receive the debug, warning, and fatal error
   messages.  Any of the callbacks can be NULL to specify default
   handling. */

void ssh_debug_register_callbacks(SshErrorCallback fatal_callback,
                                  SshErrorCallback warning_callback,
                                  SshErrorCallback debug_callback,
                                  void *context)
{
  ssh_error_maybe_initialize();

  ssh_debug_fatal_callback = fatal_callback;
  ssh_debug_warning_callback = warning_callback;
  ssh_debug_debug_callback = debug_callback;
  ssh_debug_error_context = context;
}

/* Sends a message to the system log.  The message is actually sent to the
   log callback if one is defined; otherwise, an implementation-specific
   mechanism is used. */

void ssh_log_event(SshLogFacility facility, SshLogSeverity severity,
                   const char *fmt, ...)
{
  va_list va;
  unsigned char buf[SSH_DEBUG_BUFFER_SIZE];

  /* There is no default handling for log messages; if the log callback
     has not been set, they are ignored. */
  if (ssh_debug_log_callback == NULL_FNPTR)
    return;

  /* Format the message. */
  va_start(va, fmt);
  ssh_vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  /* If a callback has been set, use it to send the message. */
  if (ssh_debug_log_callback)
    (*ssh_debug_log_callback)(facility, severity,
                              (char *) buf, ssh_debug_log_context);
}

/* Sets the callback for processing log messages.  All log messages will
   be passed to this function instead of the default function.  NULL specifies
   to use the default function. */

void ssh_log_register_callback(SshLogCallback log_callback,
                               void *context)
{
  ssh_error_maybe_initialize();
  ssh_debug_log_callback = log_callback;
  ssh_debug_log_context = context;
}

/* Returns the current log callback and its context. */

void ssh_log_get_callback(SshLogCallback *log_cb_return, void **context_return)
{
  *log_cb_return = ssh_debug_log_callback;
  *context_return = ssh_debug_log_context;
}

/* Checks an assertion and calls ssh_fatal if the assertion has
   failed. */

SSH_FASTTEXT
void ssh_generic_assert(const char *expression,
                        const char *file,
                        unsigned int line, const char *module,
                        const char *function, int type)
{
  const char *ts;

  switch (type)
    {
    case 0:
      ts = "Precondition failed";
      break;
    case 1:
      ts = "Postcondition failed";
      break;
    case 2:
      ts = "Assertion failed";
      break;
    case 3:
      ts = "Invariant failed";
      break;
    case 5:
      ts = "Verified expression failed";
      break;

    case 4:
      ts = "Unreachable code failed";
      expression = "Invalid code reached.";
      break;

    default:
      ts = "unknown generic_assert";
      break;
    }

  if (file == NULL)
    file = "(file unavailable)";
  if (module == NULL)
    module = "(module unavailable)";
  if (function == NULL)
    function = "(function name unavailable)";

  /* Call ssh_fatal() to exit. */
  ssh_fatal("%s:%d %s %s %s: %s",
            file, line, module, function, ts, expression);
}
