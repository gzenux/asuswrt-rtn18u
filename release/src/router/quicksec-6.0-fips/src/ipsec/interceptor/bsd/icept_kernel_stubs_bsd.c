/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel-mode implementations of various functions for BSD-like operating
   systems.
*/

#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "icept_internal.h"
#include <sys/malloc.h>
#include <sys/kernel.h>
#ifdef __FreeBSD__
#define HAVE_SYS_CALLOUT_H 1 /*  */
#ifdef HAVE_SYS_CALLOUT_H
#include <sys/callout.h>
#endif /* HAVE_SYS_CALLOUT_H */
#endif /* FreeBSD */
#if SSH_NetBSD >= 150
#include <sys/callout.h>
#endif /* SSH_NetBSD >= 150 */

#define SSH_DEBUG_MODULE "IceptKernelStubsBSD"

/**********************************************************************
 * ssh_kernel_alloc functions
 **********************************************************************/

void *
ssh_kernel_alloc(size_t size, SshUInt32 flag)
{
  if (size == 0)
    size = 1;

#ifdef SSH_Darwin
  return _MALLOC(size, M_TEMP, M_NOWAIT);
#else /* !SSH_Darwin */
  return malloc(size, M_TEMP, M_NOWAIT);
#endif /* SSH_Darwin */
}


void
ssh_kernel_free(void *ptr)
{
#ifdef SSH_Darwin
  _FREE(ptr, M_TEMP);
#else /* !SSH_Darwin */
  free(ptr, M_TEMP);
#endif /* SSH_Darwin */
}

void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timeval tv;

  microtime(&tv);

  if (seconds)
    *seconds = (SshTime)tv.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)tv.tv_usec;
}

/**********************************************************************
 * Timeout functions
 **********************************************************************/

/* Data structure used to record timeouts.  This is needed to implement
   SSH_KERNEL_ALL_CALLBACKS and SSH_ALL_CONTEXTS in ssh_cancel_timeouts. */
typedef struct SshKernelTimeoutRec
{
  SshKernelTimeoutCallback cb;
  void *context;
  struct SshKernelTimeoutRec *next;
#ifdef __FreeBSD__
#ifdef HAVE_SYS_CALLOUT_H
#ifndef SSH_Darwin
  struct callout_handle callout_handle;
#endif /* !SSH_Darwin */
#endif /* HAVE_SYS_CALLOUT_H */
#endif /* __FreeBSD__ */
#if SSH_NetBSD >= 150
  struct callout callout;
#endif /* SSH_NetBSD >= 150 */
} *SshKernelTimeout;

SshKernelTimeout ssh_timeouts = NULL;

/* This function is called on timeouts instead of calling the real timeout
   callback directly.  This will remove the timeout from the kernel
   list of timeouts and call the real callback. */
void ssh_kernel_timeout_cb(void *arg)
{
  SshKernelTimeout t, *tp;
  int s;

  s = ssh_interceptor_spl();
  t = (SshKernelTimeout)arg;
  for (tp = &ssh_timeouts; *tp; tp = &(*tp)->next)
    if (*tp == t)
      {
        *tp = t->next;
        (*t->cb)(t->context);
        ssh_free(t);
        splx(s);
        return;
    }
  splx(s);
}

/* Registers a timeout function that is to be called once when the specified
   time has elapsed.  The time may be zero, in which case the callback will
   be called as soon as possible from the bottom of the event loop.  There
   is no guarantee about the order in which callbacks with zero timeouts are
   delivered.

   The timeout will be delivered approximately after the specified time.  The
   exact time may differ somewhat from the specified time.  The timeout will
   be delivered from the bottom of the event loop (i.e., it will be delayed if
   another callback from the event loop is being executed).

   The arguments are as follows:
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function. */

void ssh_kernel_timeout_register(SshUInt32 seconds, SshUInt32 microseconds,
                                 SshKernelTimeoutCallback callback,
                                 void *context)
{
  SshKernelTimeout t;

  /* Zero timeouts are not allowed in kernel-mode. */
  SSH_ASSERT(seconds || microseconds);

  t = ssh_malloc(sizeof(*t));
  if (t == NULL)
    /*  */
    ssh_fatal("Could not allocate timeout context");

  t->cb = callback;
  t->context = context;
  t->next = ssh_timeouts;
  ssh_timeouts = t;

#if defined(__FreeBSD__) && defined(HAVE_SYS_CALLOUT_H) && !defined(SSH_Darwin)
  t->callout_handle = timeout(ssh_kernel_timeout_cb, (void *)t,
                              hz * seconds + hz * microseconds / 1000000);
#else /* FreeBSD && HAVE_SYS_CALLOUT_H */
#if SSH_NetBSD >= 150
  callout_init(&t->callout);
  callout_reset(&t->callout, hz * seconds + hz * microseconds / 1000000,
                ssh_kernel_timeout_cb, t);
#else /* not SSH_NetBSD >= 150 */
  timeout(ssh_kernel_timeout_cb, (void *)t,
          hz * seconds + hz * microseconds / 1000000);
#endif /* not SSH_NetBSD >= 150 */
#endif /* FreeBSD && HAVE_SYS_CALLOUT_H */
}

/* Cancels any timeouts with a matching callback function and context.
   `callback' may be SSH_KERNEL_ALL_CALLBACKS, which matches any function, and
   `context' may be SSH_ALL_CONTEXTS, which matches any context.
   It is guaranteed that the timeout will not be delivered once it has
   been cancelled, even if it had elapsed (but not yet delivered) before
   cancelling it. */

void ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                               void *context)
{
  SshKernelTimeout *tp, t;
  for (tp = &ssh_timeouts; *tp; )
    {
      t = *tp;
      if ((t->cb == callback || callback == SSH_KERNEL_ALL_CALLBACKS) &&
          (t->context == context || context == SSH_KERNEL_ALL_CONTEXTS))
        {
          *tp = t->next;
#if defined(__FreeBSD__) && defined(HAVE_SYS_CALLOUT_H) && !defined(SSH_Darwin)
          untimeout(ssh_kernel_timeout_cb, (void *)t, t->callout_handle);
#else /* __FreeBSD__ && HAVE_SYS_CALLOUT_H */
#if SSH_NetBSD >= 150
          callout_stop(&t->callout);
#else /* not SSH_NetBSD >= 150 */
          untimeout(ssh_kernel_timeout_cb, (void *)t);
#endif /* not SSH_NetBSD >= 150 */
#endif /* __FreeBSD__ && HAVE_SYS_CALLOUT_H */
          ssh_free(t);
        }
      else
        tp = &t->next;
    }
}

/**********************************************************************
 * Miscellaneous stubs to get things to compile
 **********************************************************************/

#if SSH_NetBSD < 140
void *memcpy(void *dst, const void *src, size_t len)
{
  bcopy(src, dst, len);
  return dst;
}
#endif /* SSH_NetBSD < 140 */

#if !defined(SSH_NetBSD) || SSH_NetBSD < 140
char *strrchr(const char *str, int ch)
{
  char *last;

  for (last = NULL; *str; str++)
    if ((unsigned char)*str == (unsigned char)ch)
      last = (char *)str;

  return last;
}

#ifndef SSH_Darwin
void *memmove(void *dst, const void *src, size_t len)
{
  bcopy(src, dst, len);
  return dst;
}
#endif /* SSH_Darwin */

#if !defined(SSH_FreeBSD_42) && !defined(SSH_FreeBSD_43) \
        && !defined(SSH_FreeBSD_44) && !defined(SSH_FreeBSD_45) \
        && !defined(SSH_FreeBSD_46) \
        && !defined(SSH_Darwin)
void *memset(void *dst, int ch, size_t len)
{
  unsigned char *ucp, *ucp_end;

  if (ch == 0)
    bzero(dst, len);
  else
    {
      ucp = dst;
      ucp_end = ucp + len;
      for (; ucp < ucp_end; ucp++)
        *ucp = ch;
    }
  return dst;
}

int memcmp(const void *ptr1, const void *ptr2, size_t len)
{
  const unsigned char *s1 = ptr1, *s2 = ptr2;
  unsigned int i;

  for (i = 0; i < len; i++)
    if (s1[i] != s2[i])
      return (int)s1[i] - (int)s2[i];
  return 0;
}
#endif /* !SSH_FreeBSD_{42,43,44} && !SSH_Darwin */

void *memchr(const void *ptr, int ch, size_t len)
{
  const unsigned char *ucp;
  unsigned int i;

  ucp = ptr;
  for (i = 0; i < len; i++)
    if (ucp[i] == (unsigned char)ch)
      return (void *)&ucp[i];
  return NULL;
}
#endif /* !SSH_NetBSD || SSH_NetBSD < 140 */

#ifndef SSH_Darwin
int atoi(const char *cp)
{
  int value;

  for (value = 0; *cp >= '0' && *cp <= '9'; cp++)
    value = 10 * value + *cp - '0';
  return value;
}
#endif /* SSH_Darwin */

#ifdef __FreeBSD__
#ifndef SSH_Darwin
char *strchr(const char *str, int ch)
{
  for (; *str; str++)
    if ((unsigned char)*str == (unsigned char)ch)
      return (char *)str;
  return NULL;
}
#endif /* !SSH_Darwin */

#define tolower(ch) \
  (((unsigned char)(ch) >= 'A' && (unsigned char)(ch) <= 'Z') ? \
   ((ch) + 32) : (ch))

int strncasecmp(const char *s1, const char *s2, size_t len)
{
  if (len == 0)
    return 0;

  while (len-- > 1 && *s1 && (*s1 == *s2 || tolower(*s1) == tolower(*s2)))
    {
      s1++;
      s2++;
    }
  return (int) tolower(*(unsigned char *)s1)
       - (int) tolower(*(unsigned char *)s2);
}
#endif /* __FreeBSD__ */

#if 0
char *strncpy(char *dst, const char *src, size_t n)
{
  size_t i;
  char *orig_dst = dst;

  for (i = 0; i < n; i++)
    {
      if ((dst[i] = src[i]) == 0)
        {
          for (i++; i < n; i++)
            dst[i] = '\0';
          break;
        }
    }

  return orig_dst;
}
#endif

#if defined(__NetBSD__)
void exit(int status)
{
  panic("exit");
  /*NOTREACHED*/
}
#endif /* __NetBSD__ */
