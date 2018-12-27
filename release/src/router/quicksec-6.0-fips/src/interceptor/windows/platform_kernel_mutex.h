/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Additional platform-dependent thinngs. This file is included from
   engine-interface/kernel_mutex.h
*/

#ifndef PLATFORM_KERNEL_MUTEX_H
#define PLATFORM_KERNEL_MUTEX_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#pragma warning(push, 3)
#include <ndis.h>
#pragma warning(pop)

typedef LONG SshKernelMutexState;

typedef struct SshKernelMutexRec
{
  NDIS_SPIN_LOCK lock;

#ifdef DEBUG_LIGHT
  SshKernelMutexState state;  
  KIRQL    old_irql;
  ULONG    owner_cpu;     
  PETHREAD owner_thread;
#endif /* DEBUG_LIGHT */





} SshKernelMutexStruct;


typedef struct SshKernelCSCpuStateRec
{
  KIRQL old_irql;

#ifdef DEBUG_LIGHT
  Boolean entered;
  PETHREAD thread;
#endif /* DEBUG_LIGHT */
} SshKernelCSCpuStateStruct, *SshKernelCSCpuState;


typedef struct SshKernelCriticalSectionRec
{
  /* Number of processors on this hardware platform */
  unsigned int num_cpus;

  /* Per-CPU state for the critical section */
  SshKernelCSCpuState cpu;
} SshKernelCriticalSectionStruct;


typedef struct SshKernelRWMutexRec
{
  /* Writer lock (uses spin lock) */
  SshKernelMutexStruct writer_lock;
#ifdef DEBUG_LIGHT
  unsigned int cpu;
  PETHREAD thread;
#endif /* DEBUG_LIGHT */

  /* Reader lock (uses InterlockedXxx functions) */
  LONG read_enabled;
  LONG reader_count;
#ifdef DEBUG_LIGHT
  LONG owning_readers;
#endif /* DEBUG_LIGHT */
  SshKernelCriticalSectionStruct cs;
} SshKernelRWMutexStruct;


#ifndef KERNEL_MUTEX_USE_FUNCTIONS

__forceinline SshKernelMutex
ssh_kernel_mutex_alloc(void)
{
  SshKernelMutex mutex;
  
  mutex = ssh_calloc(1, sizeof(*mutex));
  if (mutex)
    {
      ssh_kernel_mutex_init(mutex);
    }

  return mutex;
}

__forceinline Boolean 
ssh_kernel_mutex_init(SshKernelMutex mutex)
{
  NdisAllocateSpinLock(&mutex->lock);
  return TRUE;
}

#define ssh_kernel_mutex_lock(mutex) \
  NdisAcquireSpinLock(&((mutex)->lock))

#define ssh_kernel_mutex_unlock(mutex) \
  NdisReleaseSpinLock(&((mutex)->lock))

#define ssh_kernel_mutex_uninit(mutex) \
  NdisFreeSpinLock(&((mutex)->lock))

__forceinline void
ssh_kernel_mutex_free(SshKernelMutex mutex)
{
  ssh_kernel_mutex_uninit(mutex);
  ssh_free(mutex);
}

#define ssh_kernel_thread_id() \
  ((void *)PsGetCurrentThread())

#define ssh_kernel_critical_section_start(cs)                 \
do                                                            \
{                                                             \
  KIRQL irql;                                                 \
  KeRaiseIrql(DISPATCH_LEVEL, &irql);                         \
  (cs)->cpu[ssh_kernel_get_cpu()].old_irql = irql;            \
}                                                             \
while (0);

#define ssh_kernel_critical_section_end(cs) \
  KeLowerIrql((cs)->cpu[ssh_kernel_get_cpu()].old_irql);

__forceinline SshKernelRWMutex 
ssh_kernel_rw_mutex_alloc(void)
{
  SshKernelRWMutex mutex = ssh_malloc(sizeof(*mutex));

  if (mutex != NULL)
    ssh_kernel_rw_mutex_init(mutex);

  return mutex;
}

__forceinline Boolean 
ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex)
{
  ssh_kernel_mutex_init(&mutex->writer_lock);
  ssh_kernel_critical_section_init(&mutex->cs);
  mutex->read_enabled = TRUE;
  mutex->reader_count = 0;

  return TRUE;
}

#define ssh_kernel_rw_mutex_uninit(mutex)             \
do                                                    \
{                                                     \
  ssh_kernel_critical_section_uninit(&(mutex)->cs);   \
  ssh_kernel_mutex_uninit(&(mutex)->writer_lock);     \
}                                                     \
while (0);

#define ssh_kernel_rw_mutex_free(mutex)               \
do                                                    \
{                                                     \
  ssh_kernel_rw_mutex_uninit((mutex));                \
  ssh_free((mutex));                                  \
}                                                     \
while (0);


#define ssh_kernel_rw_mutex_lock_read(mutex)                     \
do                                                               \
{                                                                \
  ssh_kernel_critical_section_start(&(mutex)->cs);               \
  for (;;)                                                       \
    {                                                            \
      if (InterlockedCompareExchange(&(mutex)->read_enabled,     \
                                     TRUE, TRUE) == TRUE)        \
        {                                                        \
          InterlockedIncrement(&(mutex)->reader_count);          \
          if (InterlockedCompareExchange(&(mutex)->read_enabled, \
                                         TRUE, TRUE) == TRUE)    \
            {                                                    \
              break;                                             \
            }                                                    \
          InterlockedDecrement(&(mutex)->reader_count);          \
        }                                                        \
    }                                                            \
}                                                                \
while (0); 

#define ssh_kernel_rw_mutex_unlock_read(mutex)                   \
do                                                               \
{                                                                \
  InterlockedDecrement(&(mutex)->reader_count);                  \
  ssh_kernel_critical_section_end(&(mutex)->cs);                 \
}                                                                \
while (0);

#define ssh_kernel_rw_mutex_lock_write(mutex)                           \
do                                                                      \
{                                                                       \
  ssh_kernel_mutex_lock(&(mutex)->writer_lock);                         \
  InterlockedExchange(&(mutex)->read_enabled, FALSE);                   \
  while (InterlockedCompareExchange(&(mutex)->reader_count, 0, 0) != 0) \
    {};                                                                 \
}                                                                       \
while (0);

#define ssh_kernel_rw_mutex_unlock_write(mutex)                  \
do                                                               \
{                                                                \
  InterlockedExchange(&(mutex)->read_enabled, TRUE);             \
  ssh_kernel_mutex_unlock(&(mutex)->writer_lock);                \
}                                                                \
while (0);

#endif /* KERNEL_MUTEX_USE_FUNCTIONS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PLATFORM_KERNEL_MUTEX_H */
