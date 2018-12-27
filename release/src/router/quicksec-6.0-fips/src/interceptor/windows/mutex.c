/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SshKernelMutex implementation for all Windows NT series operating systems.
*/

/* #includes */

#include "sshincludes.h"
#include "kernel_mutex.h"
#include "interceptor_i.h"







/* #defines */

#define SSH_DEBUG_MODULE "SshMutex"

/* Local types */

#define SSH_MUTEX_STATE_LOCKED  ((SshKernelMutexState)TRUE)
#define SSH_MUTEX_STATE_FREE    ((SshKernelMutexState)FALSE)


/* Local prototypes */


/* Local variables */










/* Exported functions */

#ifdef KERNEL_MUTEX_USE_FUNCTIONS

SshKernelMutex ssh_kernel_mutex_alloc(void)
{
  SshKernelMutex mutex = ssh_calloc(1, sizeof(*mutex));

  if (mutex != NULL)
    ssh_kernel_mutex_init(mutex);

  return mutex;
}


Boolean ssh_kernel_mutex_init(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex != NULL);

#ifdef DEBUG_LIGHT
  mutex->state = SSH_MUTEX_STATE_FREE;
#endif /* DEBUG_LIGHT */

  NdisAllocateSpinLock(&mutex->lock);

  return TRUE;
}


void ssh_kernel_mutex_uninit(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex != NULL);
  SSH_ASSERT(mutex->state == SSH_MUTEX_STATE_FREE);

  NdisFreeSpinLock(&mutex->lock);
}


void ssh_kernel_mutex_free(SshKernelMutex mutex)
{
  if (mutex == NULL)
    return;

  ssh_kernel_mutex_uninit(mutex);
  ssh_free(mutex);
}



void ssh_kernel_mutex_lock(SshKernelMutex mutex)
{
#ifdef DEBUG_LIGHT
  KIRQL old_irql = SSH_GET_IRQL();
#endif /* DEBUG_LIGHT */

  NdisAcquireSpinLock(&mutex->lock);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(mutex->state == SSH_MUTEX_STATE_FREE);
  mutex->state = SSH_MUTEX_STATE_LOCKED;
  mutex->old_irql = old_irql;
  mutex->owner_cpu = ssh_kernel_get_cpu();
  mutex->owner_thread = ssh_kernel_thread_id();
#endif /* DEBUG_LIGHT */





}



void ssh_kernel_mutex_unlock(SshKernelMutex mutex)
{












#ifdef DEBUG_LIGHT
  SSH_ASSERT(mutex->state == SSH_MUTEX_STATE_LOCKED);
  mutex->state = SSH_MUTEX_STATE_FREE;
#endif /* DEBUG_LIGHT */

  NdisReleaseSpinLock(&mutex->lock);

























}

#ifdef DEBUG_LIGHT

void ssh_kernel_mutex_assert_is_locked(SshKernelMutex mutex)
{
  SSH_ASSERT(mutex->state == SSH_MUTEX_STATE_LOCKED);
}

#endif /* DEBUG_LIGHT */

/* Returns the ID of the kernel thread that is currently executing the
   code.  The returned ID must be a non-zero pointer identifying the
   thread. */

void *ssh_kernel_thread_id(void)
{
  return PsGetCurrentThread();
}


/* Allocates and initializes a reader-writer mutex. */
SshKernelRWMutex ssh_kernel_rw_mutex_alloc(void)
{
  SshKernelRWMutex mutex = ssh_malloc(sizeof(*mutex));

  if (mutex != NULL)
    ssh_kernel_rw_mutex_init(mutex);

  return mutex;
}

/* Initializes a mutex allocated from the stack. */
Boolean ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex != NULL);

  ssh_kernel_mutex_init(&mutex->writer_lock);
  ssh_kernel_critical_section_init(&mutex->cs);
  mutex->read_enabled = TRUE;
  mutex->reader_count = 0;

  return TRUE;
}

/* Uninitializes the given mutex.  */
void ssh_kernel_rw_mutex_uninit(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex != NULL);
  SSH_ASSERT(mutex->reader_count == 0);

  ssh_kernel_critical_section_uninit(&mutex->cs);
  ssh_kernel_mutex_uninit(&mutex->writer_lock);
}

/* Frees the given mutex. */
void ssh_kernel_rw_mutex_free(SshKernelRWMutex mutex)
{
  ssh_kernel_rw_mutex_uninit(mutex);
  ssh_free(mutex);
}


/* Takes a read lock on the mutex. */
void ssh_kernel_rw_mutex_lock_read(SshKernelRWMutex mutex)
{
  SSH_ASSERT(mutex != NULL);

  ssh_kernel_critical_section_start(&mutex->cs);
 
  for (;;)
    {
      if (InterlockedCompareExchange(&mutex->read_enabled,
                                     TRUE, TRUE) == TRUE)
        {
          InterlockedIncrement(&mutex->reader_count);

          /* There was a short period of time when a new write operation 
             could have been started. That's why we need to re-check that 
             reading is still enabled. */
          if (InterlockedCompareExchange(&mutex->read_enabled, 
                                         TRUE, TRUE) == TRUE)
            {
#ifdef DEBUG_LIGHT
              InterlockedIncrement(&mutex->owning_readers);
#endif /* DEBUG_LIGHT */
              return;  /* Done; we have the reader lock */
            }

          /* Failed to get the reader lock because new write operation was 
             started before we incremented the reader_count. We need to wait 
             until reading is re-enabled. */
          InterlockedDecrement(&mutex->reader_count);
        }
    }
}

/* Releases the read lock on the mutex. */
void ssh_kernel_rw_mutex_unlock_read(SshKernelRWMutex mutex)
{
  LONG new_lock_count;

  SSH_ASSERT(mutex != NULL);

#ifdef DEBUG_LIGHT
  InterlockedDecrement(&mutex->owning_readers);
#endif /* DEBUG_LIGTH */
  new_lock_count = InterlockedDecrement(&mutex->reader_count);

  ssh_kernel_critical_section_end(&mutex->cs);
 
  SSH_ASSERT(new_lock_count >= 0);
}

/* Takes a write lock on the mutex. */
void ssh_kernel_rw_mutex_lock_write(SshKernelRWMutex mutex)
{
  ULONG old_value;

  SSH_ASSERT(mutex != NULL);

  ssh_kernel_mutex_lock(&mutex->writer_lock);

  old_value = InterlockedExchange(&mutex->read_enabled, FALSE);
  SSH_ASSERT(old_value == TRUE);

  /* We have to wait until all pending read operations have completed */
  while (InterlockedCompareExchange(&mutex->reader_count, 0, 0) != 0)
    {};

  /* Now we have acquired the write lock on the mutex. */
#ifdef DEBUG_LIGHT
  mutex->cpu = ssh_kernel_get_cpu();
  mutex->thread = ssh_kernel_thread_id();
#endif /* DEBUG_LIGHT */
}

/* Releases the write lock on the mutex. */ 
void ssh_kernel_rw_mutex_unlock_write(SshKernelRWMutex mutex)
{
  ULONG old_value;

  SSH_ASSERT(mutex != NULL);
  SSH_ASSERT(InterlockedCompareExchange(&mutex->owning_readers, 0, 0) == 0);

  old_value = InterlockedExchange(&mutex->read_enabled, TRUE);
  SSH_ASSERT(old_value == FALSE);
 
#ifdef DEBUG_LIGHT
  mutex->thread = NULL;
#endif /* DEBUG_LIGHT */
  ssh_kernel_mutex_unlock(&mutex->writer_lock);
}


/* Functions for handling concurreny control over per-CPU data.  */

/* Allocates and initializes a critical section.  */
SshKernelCriticalSection ssh_kernel_critical_section_alloc(void)
{
  SshKernelCriticalSection cs;

  cs = ssh_calloc(1, sizeof(*cs));
  if (cs != NULL)
    {
      if (!ssh_kernel_critical_section_init(cs))
        {
          ssh_free(cs);
          cs = NULL;
        }
    }

  return cs;
}

/* Frees the given critical section. */
void ssh_kernel_critical_section_free(SshKernelCriticalSection cs)
{
  if (cs == NULL)
    return;

  ssh_kernel_critical_section_uninit(cs);
  ssh_free(cs);
}

/* Enter the critical section. */
void ssh_kernel_critical_section_start(SshKernelCriticalSection cs)
{
  unsigned int i;
  KIRQL old_irql;

  SSH_ASSERT(cs != NULL);

  SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);

  i = (unsigned int)ssh_kernel_get_cpu();
  SSH_ASSERT(i < cs->num_cpus);

  cs->cpu[i].old_irql = old_irql;

#ifdef DEBUG_LIGHT
  SSH_ASSERT(cs->cpu[i].entered == FALSE);
  cs->cpu[i].entered = TRUE;
  cs->cpu[i].thread = ssh_kernel_thread_id();
#endif /* DEBUG_LIGHT */
}

/* Signals the end of the critical section. */
void ssh_kernel_critical_section_end(SshKernelCriticalSection cs)
{
  unsigned int i;

  SSH_ASSERT(cs != NULL);

  i = (unsigned int)ssh_kernel_get_cpu();
  SSH_ASSERT(i < cs->num_cpus);

  SSH_ASSERT(cs->cpu[i].entered == TRUE);
  SSH_ASSERT(cs->cpu[i].thread == ssh_kernel_thread_id());

#ifdef DEBUG_LIGHT
  cs->cpu[i].entered = FALSE;
#endif /* DEBUG_LIGHT */

  SSH_LOWER_IRQL(cs->cpu[i].old_irql);
}

#endif /* KERNEL_MUTEX_USE_FUNCTIONS */

/* Initializes a critical section allocated from the stack. */
Boolean ssh_kernel_critical_section_init(SshKernelCriticalSection cs)
{
  memset(cs, 0x00, sizeof(*cs));
  cs->num_cpus = ssh_kernel_num_cpus();

  cs->cpu = ssh_calloc(cs->num_cpus, sizeof(*(cs->cpu)));
  if (cs->cpu == NULL)
    return FALSE;

  return TRUE;
}

/* Uninitializes the given critical section. */
void ssh_kernel_critical_section_uninit(SshKernelCriticalSection cs)
{
#ifdef DEBUG_LIGHT
  unsigned int i;

  SSH_ASSERT(cs != NULL);

  for (i = 0; i < cs->num_cpus; i++)
    SSH_ASSERT(cs->cpu[i].entered == FALSE);
#endif /* DEBUG_LIGHT */

  ssh_free(cs->cpu);
}

/* Returns the number of processors in the system. */
unsigned int ssh_kernel_num_cpus(void)
{
  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->processor_count > 0);

  return (the_interceptor->processor_count);
}

/* Returns an id of the currently executing processor. */
unsigned int ssh_kernel_get_cpu(void)
{
  /* Check that scheduler is currently disabled. */
  SSH_ASSERT(SSH_GET_IRQL() >= SSH_DISPATCH_LEVEL);

#ifdef NDIS620
  if ((the_interceptor->processor_count > 64)
      && (the_interceptor->get_current_cpu_fn != NULL_FNPTR))
    {
      return ((unsigned int)(the_interceptor->get_current_cpu_fn)(NULL));
    }
  else
#endif /* NDIS_620 */
    {
      return ((unsigned int)KeGetCurrentProcessorNumber());
    }
}

/* EOF */
