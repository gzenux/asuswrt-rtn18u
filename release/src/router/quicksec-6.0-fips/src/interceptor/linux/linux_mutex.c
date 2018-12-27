/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of Mutex API, ssh_kernel_mutex_* functions for
   the Linux 2.4.x and 2.6.x kernels.
*/

#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorMutex"

#include "linux_mutex_internal.h"

extern SshInterceptor ssh_interceptor_context;


Boolean ssh_kernel_mutex_init(SshKernelMutex mutex)
{
  spin_lock_init(&mutex->lock);

#ifdef DEBUG_LIGHT
  mutex->taken = FALSE;
  mutex->jiffies = 0;
#endif
  return TRUE;
}

/* Allocates a simple mutex.  This should be as fast as possible, but work
   between different processors in a multiprocessor machine.  This need
   not work between different independent processes. */

SshKernelMutex
ssh_kernel_mutex_alloc(void)
{
  SshKernelMutex m;

  m = ssh_calloc(1, sizeof(struct SshKernelMutexRec));
  if (m == NULL)
    return NULL;

  if (!ssh_kernel_mutex_init(m))
    {
      ssh_free(m);
      m = NULL;
    }
  return m;
}

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */

void ssh_kernel_mutex_uninit(SshKernelMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
}

void ssh_kernel_mutex_free(SshKernelMutex mutex)
{
  if (mutex)
    {
      ssh_kernel_mutex_uninit(mutex);
      ssh_free(mutex);
    }
}

#ifdef KERNEL_MUTEX_USE_FUNCTIONS
/* Locks the mutex.  Only one thread of execution can have a mutex locked
   at a time.  This will block until execution can continue.  One should
   not keep mutexes locked for extended periods of time. */

void
ssh_kernel_mutex_lock_i(SshKernelMutex mutex)
{
  SSH_LINUX_STATISTICS(ssh_interceptor_context,
  { ssh_interceptor_context->stats.num_light_locks++; });

  spin_lock(&mutex->lock);

  SSH_ASSERT(!mutex->taken);

#ifdef DEBUG_LIGHT
  mutex->taken = TRUE;
  mutex->jiffies = jiffies;
#endif /* DEBUG_LIGHT */
}

/* Unlocks the mutex.  If other threads are waiting to lock the mutex,
   one of them will get the lock and continue execution. */

void
ssh_kernel_mutex_unlock_i(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex->taken);
#ifdef DEBUG_LIGHT
  mutex->taken = FALSE;
#endif /* DEBUG_LIGHT */

  spin_unlock(&mutex->lock);
}
#endif /* KERNEL_MUTEX_USE_FUNCTIONS */

#ifdef SSH_LINUX_DEBUG_MUTEX

static int cpu_lock_count[SSH_LINUX_INTERCEPTOR_NR_CPUS] = { 0 };

void
ssh_linux_debug_lock(SshKernelMutex mutex, const char *name, int line)
{
#ifdef DEBUG_LIGHT
  if ((spin_is_locked(&mutex->lock))
      && cpu_lock_count[smp_processor_id()])
    printk(KERN_ERR " potential deadlock(): %s:%d and %s:%d\n",
           mutex->taken_at_func, mutex->taken_at_linenr,
           name, line);
#endif /* DEBUG_LIGHT */

  spin_lock(&mutex->lock);

  cpu_lock_count[smp_processor_id()]++;

#ifdef DEBUG_LIGHT
  strncpy(mutex->taken_at_func, name, sizeof(mutex->taken_at_func));
  mutex->taken_at_func[sizeof(mutex->taken_at_func) - 1] = '\0';
  mutex->taken_at_linenr = line;
#endif /* DEBUG_LIGHT */
}

void
ssh_linux_debug_unlock(SshKernelMutex mutex, const char *name, int line)
{
  cpu_lock_count[smp_processor_id()]--;
  spin_unlock(&mutex->lock);
}
#endif /* SSH_LINUX_DEBUG_MUTEX */

#ifdef DEBUG_LIGHT
/* Check that the mutex is locked.  It is a fatal error if it is not. */

void
ssh_kernel_mutex_assert_is_locked(SshKernelMutex mutex)
{
#ifdef SSH_LINUX_DEBUG_MUTEX
  SSH_ASSERT(spin_is_locked(&mutex->lock));
#else /* SSH_LINUX_DEBUG_MUTEX */
  SSH_ASSERT(mutex->taken);
#endif /* SSH_LINUX_DEBUG_MUTEX */
}
#endif


/** Reader-writer mutexes */

Boolean ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex)
{
  rwlock_init(&mutex->lock);
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

#ifdef KERNEL_MUTEX_USE_FUNCTIONS

void ssh_kernel_rw_mutex_lock_read_i(SshKernelRWMutex mutex)
{
  read_lock(&mutex->lock);
}

void ssh_kernel_rw_mutex_unlock_read_i(SshKernelRWMutex mutex)
{
  read_unlock(&mutex->lock);
}

void ssh_kernel_rw_mutex_lock_write_i(SshKernelRWMutex mutex)
{
  write_lock(&mutex->lock);
}

void ssh_kernel_rw_mutex_unlock_write_i(SshKernelRWMutex mutex)
{
  write_unlock(&mutex->lock);
}

#endif /* KERNEL_MUTEX_USE_FUNCTIONS */

/* Returns the ID of the kernel thread that is currently executing the
   code.  The returned ID must be a non-zero pointer identifying the
   thread. */

void *ssh_kernel_thread_id(void)
{
  return (void *)(current);
}


unsigned int ssh_kernel_num_cpus(void)
{
  return (unsigned int) ssh_interceptor_context->num_cpus;
}

unsigned int ssh_kernel_get_cpu(void)
{
  SSH_ASSERT(ssh_interceptor_context->cpu_ids[smp_processor_id()] != 0xffff);
  SSH_ASSERT(ssh_interceptor_context->cpu_ids[smp_processor_id()]
             < ssh_interceptor_context->num_cpus);
  return (unsigned int) ssh_interceptor_context->cpu_ids[smp_processor_id()];
}

/** Critical sections */

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

#ifdef KERNEL_MUTEX_USE_FUNCTIONS

void ssh_kernel_critical_section_start_i(SshKernelCriticalSection cs)
{
  icept_preempt_disable();
}

void ssh_kernel_critical_section_end_i(SshKernelCriticalSection cs)
{
  icept_preempt_enable();
}

#endif /* KERNEL_MUTEX_USE_FUNCTIONS */


/************************ Module init / uninit ******************************/

Boolean ssh_interceptor_mutexes_init(SshInterceptor interceptor)
{
  int cpu;
  SshUInt16 cpu_id = 0;

  /* Initialize cpu id mapping table. This is a memory usage optimization.
     The cpu id mapping table is an array of SSH_INTERCEPTOR_LINUX_NR_CPUS
     (possibly a large number) cpu ids and it is initialized here for all
     possible cpus (possibly a smaller number than
     SSH_INTERCEPTOR_LINUX_NR_CPUS) with internal monotonically increasing
     cpu id. The ssh_kernel_get_cpu() uses the mapping table to convert values
     returned by smp_processor_id() to the internal cpu id value, which are
     guaranteed to have smaller value than returned by ssh_kernel_num_cpus().
     This way the engine does not need to reserve memory for cpus that will
     never be active in the system.

     The reason behind this all is that:
      - smp_processor_id() returns values between 0 and
        SSH_INTERCEPTOR_LINUX_NR_CPUS and there might be gaps between the
        values.
      - Typically SSH_INTERCEPTOR_LINUX_NR_CPUS is much larger than the actual
        number of cpus in the system (this is especially true in standard
        desktop linuxes).
      - num_possible_cpus() returns the actual maximum number of cpus in the
        system.
      - We do not want to allocate possibly large data structures for cpus
        that will never be active in the system.
  */
  memset(&interceptor->cpu_ids, 0xff, sizeof(interceptor->cpu_ids));
  SSH_FOR_EACH_POSSIBLE_CPU(cpu)
    {
      interceptor->cpu_ids[cpu] = cpu_id++;
    }

  SSH_ASSERT(cpu_id > 0);
  interceptor->num_cpus = cpu_id;

  return TRUE;
}

void ssh_interceptor_mutexes_uninit(SshInterceptor interceptor)
{
  /* Placeholder for possible future module uninitialization tasks. */
}
