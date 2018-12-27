/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Trivial pseudo-mutex implementation for debugging.
*/

#include "sshincludes.h"
#include "kernel_mutex.h"

#define SSH_DEBUG_MODULE "SshKernelMutex"

/* Initializes a mutex allocated from the stack. Returns TRUE on success
   and FALSE on failure. */

Boolean ssh_kernel_mutex_init(SshKernelMutex mutex)
{
  mutex->taken = 0;
  return TRUE;
}

/* Allocates a simple mutex.  This should be as fast as possible, but work
   between different processors in a multiprocessor machine.  This need
   not work between different independent processes. */

SshKernelMutex ssh_kernel_mutex_alloc(void)
{
  SshKernelMutex m = ssh_calloc(1, sizeof(struct SshKernelMutexRec));
  if (m == NULL)
    return NULL;

  if (!ssh_kernel_mutex_init(m))
    {
      ssh_free(m);
      m = NULL;
    }
  return m;
}

/* Uninitializes the given mutex.  The mutex must not be locked when it is
   uninitialized. */

void ssh_kernel_mutex_uninit(SshKernelMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
}

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */

void ssh_kernel_mutex_free(SshKernelMutex mutex)
{
  if (mutex)
    {
      ssh_kernel_mutex_uninit(mutex);
      ssh_free(mutex);
    }
}

/* Locks the mutex.  Only one thread of execution can have a mutex locked
   at a time.  This will block until execution can continue.  One should
   not keep mutexes locked for extended periods of time. */

void ssh_kernel_mutex_lock(SshKernelMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

/* Unlocks the mutex.  If other threads are waiting to lock the mutex,
   one of them will get the lock and continue execution. */

void ssh_kernel_mutex_unlock(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
}

#ifdef DEBUG_LIGHT
/* Check that the mutex is locked.  It is a fatal error if it is not. */

void ssh_kernel_mutex_assert_is_locked(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex->taken);
}
#endif /* DEBUG_LIGHT */

Boolean ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex)
{
  mutex->taken = 0;
  return TRUE;
}

SshKernelRWMutex ssh_kernel_rw_mutex_alloc(void)
{
  SshKernelRWMutex m;

  m = ssh_calloc(1, sizeof(struct SshKernelRWMutexRec));
  if (m == NULL)
    return NULL;

  if (!ssh_kernel_rw_mutex_init(m))
    {
      ssh_free(m);
      m = NULL;
    }
  return m;
}

void ssh_kernel_rw_mutex_uninit(SshKernelRWMutex mutex)
{
  return;
}

void ssh_kernel_rw_mutex_free(SshKernelRWMutex mutex)
{
  if (mutex)
    {
      ssh_kernel_rw_mutex_uninit(mutex);
      ssh_free(mutex);
    }
}

void ssh_kernel_rw_mutex_lock_read(SshKernelRWMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

void ssh_kernel_rw_mutex_unlock_read(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
}

void ssh_kernel_rw_mutex_lock_write(SshKernelRWMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

void ssh_kernel_rw_mutex_unlock_write(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
}

/* Returns the ID of the kernel thread that is currently executing the
   code.  The returned ID must be a non-zero pointer identifying the
   thread. */

void *ssh_kernel_thread_id(void)
{
  return (void *)ssh_kernel_thread_id;
}

unsigned int ssh_kernel_num_cpus(void)
{
  return 1;
}

unsigned int ssh_kernel_get_cpu(void)
{
  return 0;
}


SshKernelCriticalSection ssh_kernel_critical_section_alloc(void)
{
  SshKernelCriticalSection cs;

  cs = ssh_calloc(1, sizeof(struct SshKernelCriticalSectionRec));
  if (cs == NULL)
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
  return TRUE;
}

void ssh_kernel_critical_section_uninit(SshKernelCriticalSection cs)
{
  return;
}

void ssh_kernel_critical_section_free(SshKernelCriticalSection cs)
{
  if (cs)
    {
      ssh_kernel_critical_section_uninit(cs);
      ssh_free(cs);
    }
}

void ssh_kernel_critical_section_start(SshKernelCriticalSection cs)
{
  return;
}

void ssh_kernel_critical_section_end(SshKernelCriticalSection cs)
{
  return;
}
