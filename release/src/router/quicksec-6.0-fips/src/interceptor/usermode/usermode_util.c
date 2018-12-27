/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements user-mode interceptor low-level utilities
   (mutexes). This interceptor is used by programs needing the interceptor
   services on the user level.
*/

#include "sshincludes.h"
#include "sshmutex.h"
#include "sshcondition.h"
#include "sshthreadedmbox.h"
#include "usermodeinterceptor.h"
#include "usermodeinterceptor_internal.h"
#include "sshfdstream.h"

/* The eloop<->threaded side message box, initialized by the "other" side */
extern SshThreadedMbox thread_mbox;

/* Notice about memory allocation:

   Though we *know* this module is executed in user context, we still
   program this module as it was in kernel mode (since semantically
   that is where it is), thus using ssh_k*alloc routines and checking
   their return values --- even if we know they're really ssh_x*alloc
   versions and would never return a NULL value.

   Except the packet manipulation routines use ssh_x* versions,
   because they have their own allocation failure points.
 */


#define SSH_DEBUG_MODULE "SshUserModeInterceptor"

/* This is an ugly kludge to allow initialization of the engine without
   being in thread_mbox "thread context. */




#ifdef SSH_ASSERT_THREAD
#undef SSH_ASSERT_THREAD
#define SSH_ASSERT_THREAD()
#endif /* SSH_ASSERT_THREAD */


/* Allocates a simple mutex.  This should be as fast as possible, but work
   between different processors in a multiprocessor machine.  This need
   not work between different independent processes. */

SshKernelMutex ssh_kernel_mutex_alloc(void)
{
  SshKernelMutex mutex;
  SSH_ASSERT_THREAD();

  mutex = ssh_calloc(1, sizeof(struct SshKernelMutexRec));
  if (!mutex)
    return NULL;

  if (!ssh_kernel_mutex_init(mutex))
    {
      ssh_free(mutex);
      mutex = NULL;
    }
  return mutex;
}

Boolean ssh_kernel_mutex_init(SshKernelMutex mutex)
{
  mutex->taken = FALSE;
  mutex->mutex = ssh_mutex_create(NULL, 0);
  if (mutex->mutex == NULL)
    return FALSE;
  return TRUE;
}

void ssh_kernel_mutex_uninit(SshKernelMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(!mutex->taken);
  if (mutex->mutex != NULL)
  ssh_mutex_destroy(mutex->mutex);
  mutex->mutex = NULL;
}

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */
void ssh_kernel_mutex_free(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex != NULL);
  SSH_ASSERT(mutex->mutex != NULL);
  ssh_kernel_mutex_uninit(mutex);
  ssh_free(mutex);
}

/* Locks the mutex.  Only one thread of execution can have a mutex locked
   at a time.  This will block until execution can continue.  One should
   not keep mutexes locked for extended periods of time. */

void ssh_kernel_mutex_lock(SshKernelMutex mutex)
{
  SSH_ASSERT_THREAD();
  ssh_mutex_lock(mutex->mutex);
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

/* Unlocks the mutex.  If other threads are waiting to lock the mutex,
   one of them will get the lock and continue execution. */

void ssh_kernel_mutex_unlock(SshKernelMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
  ssh_mutex_unlock(mutex->mutex);
}

#ifdef DEBUG_LIGHT

/* Check that the mutex is locked.  It is a fatal error if it is not. */
void ssh_kernel_mutex_assert_is_locked(SshKernelMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(mutex->taken);
}
#endif /* DEBUG_LIGHT */

/* Returns the ID of the kernel thread that is currently executing the
   code.  The returned ID must be a non-zero pointer identifying the
   thread. */

void *ssh_kernel_thread_id(void)
{



  return (void *) 1;
}

unsigned int ssh_kernel_num_cpus(void)
{
  return 1;
}

unsigned int ssh_kernel_get_cpu(void)
{
  return 0;
}

SshInterceptor
ssh_interceptor_alloc(void *machine_context)
{
  SshInterceptor interceptor;

  /* Initialize the interceptor data structure. */
  interceptor = ssh_calloc(1, sizeof(*interceptor));
  if (!interceptor)
    return NULL;

  interceptor->mutex = ssh_mutex_create("interceptor", 0);

  if (!interceptor->mutex)
    {
      ssh_free(interceptor);
      return NULL;
    }

  interceptor->machine_context = machine_context;
  return interceptor;
}

void
ssh_interceptor_free(SshInterceptor interceptor)
{
  ssh_mutex_destroy(interceptor->mutex);
  ssh_free(interceptor);
}

void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  SshTimeValueStruct tv;

  ssh_get_time_of_day(&tv);

  if (seconds)
    *seconds = tv.seconds;
  if (useconds)
    *useconds = tv.microseconds;

  return;
}


SshKernelCriticalSection
ssh_kernel_critical_section_alloc(void)
{
  SshKernelCriticalSection cs;
  SSH_ASSERT_THREAD();

  cs = ssh_calloc(1, sizeof(struct SshKernelCriticalSectionRec));
  if (!cs)
    return NULL;

  if (!ssh_kernel_critical_section_init(cs))
    {
      ssh_free(cs);
      cs = NULL;
    }
  return cs;
}

Boolean ssh_kernel_critical_section_init(SshKernelCriticalSection cs)
{
  cs->taken = FALSE;
  cs->mutex = ssh_mutex_create(NULL, 0);
  if (cs->mutex == NULL)
    return FALSE;
  return TRUE;
}

void ssh_kernel_critical_section_uninit(SshKernelCriticalSection cs)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(!cs->taken);
  if (cs->mutex != NULL)
  ssh_mutex_destroy(cs->mutex);
  cs->mutex = NULL;
}

void ssh_kernel_critical_section_free(SshKernelCriticalSection cs)
{
  SSH_ASSERT(cs != NULL);
  SSH_ASSERT(cs->mutex != NULL);
  ssh_kernel_critical_section_uninit(cs);
  ssh_free(cs);
}

void ssh_kernel_critical_section_start(SshKernelCriticalSection cs)
{
  SSH_ASSERT_THREAD();
  ssh_mutex_lock(cs->mutex);
  SSH_ASSERT(!cs->taken);
  cs->taken = TRUE;
}

void ssh_kernel_critical_section_end(SshKernelCriticalSection cs)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(cs->taken);
  cs->taken = FALSE;
  ssh_mutex_unlock(cs->mutex);
}

Boolean ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex)
{
  mutex->taken = FALSE;
  mutex->mutex = ssh_mutex_create(NULL, 0);
  if (mutex->mutex == NULL)
    return FALSE;
  return TRUE;
}

SshKernelRWMutex ssh_kernel_rw_mutex_alloc(void)
{
  SshKernelRWMutex mutex;
  SSH_ASSERT_THREAD();

  mutex = ssh_calloc(1, sizeof(struct SshKernelRWMutexRec));
  if (!mutex)
    return NULL;

  if (!ssh_kernel_rw_mutex_init(mutex))
    {
      ssh_free(mutex);
      mutex = NULL;
    }
  return mutex;
}

void ssh_kernel_rw_mutex_uninit(SshKernelRWMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(!mutex->taken);
  if (mutex->mutex != NULL)
  ssh_mutex_destroy(mutex->mutex);
  mutex->mutex = NULL;
}

void ssh_kernel_rw_mutex_free(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex != NULL);
  SSH_ASSERT(mutex->mutex != NULL);
  ssh_kernel_rw_mutex_uninit(mutex);
  ssh_free(mutex);
}

void ssh_kernel_rw_mutex_lock_read(SshKernelRWMutex mutex)
{
  SSH_ASSERT_THREAD();
  ssh_mutex_lock(mutex->mutex);
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

void ssh_kernel_rw_mutex_unlock_read(SshKernelRWMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
  ssh_mutex_unlock(mutex->mutex);
}

void ssh_kernel_rw_mutex_lock_write(SshKernelRWMutex mutex)
{
  SSH_ASSERT_THREAD();
  ssh_mutex_lock(mutex->mutex);
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

void ssh_kernel_rw_mutex_unlock_write(SshKernelRWMutex mutex)
{
  SSH_ASSERT_THREAD();
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
  ssh_mutex_unlock(mutex->mutex);
}


#if 0
/* For now these are off, we do not prefer ssh* versions any more. */
#ifdef sun

#undef atoi
#undef strcasecmp
#undef strncasecmp
#undef strrchr

/* Can't include <string.h>, since that'll cause macro problems */
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);

/* Some functions needed for Solaris usermode interceptor. */

int ssh_atoi(const char *input)
{
  return atoi(input);
}

int ssh_strcasecmp(const char *s1, const char *s2)
{
  return strcasecmp(s1, s2);
}

int ssh_strncasecmp(const char *s1, const char *s2, int n)
{
  return strncasecmp(s1, s2, n);
}

char *ssh_strrchr(const char *s, int c)
{
  return strrchr(s, c);
}

#undef memmove
#undef memcpy
#undef memset
#undef memcmp
#undef memchr

extern void *memmove(void *, const void *, size_t);
extern void *memcpy(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern int memcmp(const void *, const void *, size_t);
extern void *memchr(const void *, int, size_t);

void *ssh_memmove(void *t, const void *s, size_t n)
{
  return memmove(t, s, n);
}

void *ssh_memcpy(void *t, const void *s, size_t n)
{
  return memcpy(t, s, n);
}

void *ssh_memset(void *t, int c, size_t n)
{
  return memset(t, c, n);
}

int ssh_memcmp(const void *s1, const void *s2, size_t n)
{
  return memcmp(s1, s2, n);
}

void *ssh_memchr(const void *s, int c, size_t n)
{
  return memchr(s, c, n);
}

void ssh_exit(int value)
{
  exit(value);
}

#endif /* __sun__ */
#endif /* 0 */

#if defined(__linux__) && !defined(__i386__)
void *ssh_memchr(const void *s, int c, size_t n)
{
  return memchr(s, c, n);
}
#endif /* __linux__ && !__i386__ */


#ifdef INTERCEPTOR_SUPPORTS_MAPPED_MEMORY

/* If the underlying platform supports mapped memory, we'll have to
   provide stub functions. Since the policy manager will never succeed
   with mmap on the usermode engine socket, we should never actually
   see any mmaped pages, thus the asserts */

void ssh_interceptor_mmap_ref(SshInterceptor icept, SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
}

void ssh_interceptor_mmap_unref(SshInterceptor icept, SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
}

/* This just warns instead of doing fatal, and returns failure. */
SshKernelMemoryMap ssh_interceptor_mmap_by_user_address(SshInterceptor icept,
                                                  SshUInt64 user_address)
{
  ssh_warning("Should not happen.");
  return NULL;
}

void * ssh_interceptor_mmap_kernel_address(SshInterceptor icept,
                                           SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
  return NULL;
}

size_t ssh_interceptor_mmap_size(SshInterceptor icept,
                                 SshKernelMemoryMap map)
{
  ssh_fatal("Should not happen.");
  return 0;
}

#endif /* INTERCEPTOR_SUPPORTS_MAPPED_MEMORY */
