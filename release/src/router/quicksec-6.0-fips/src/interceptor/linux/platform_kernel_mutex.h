/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Additional platform-dependent things. This file is included from
   engine-interface/kernel_mutex.h
*/

#ifndef PLATFORM_KERNEL_MUTEX_H
#define PLATFORM_KERNEL_MUTEX_H 1

/* Sanity check to make sure that optimizations get done correcly
   on a UP machine. The following block can be safely removed. */
#ifndef CONFIG_SMP
#ifdef __ASM_SPINLOCK_H
#error "asm/spinlock.h" should not be included explicitly.
#endif /* __ASM_SPINLOCK_H */
#endif /* !CONFIG_SMP */

#include "linux_params.h"
#include "linux_mutex_internal.h"

/* Directly map linux mutexes to macros. This causes significantly
   less overhead in the non-preemptive UP case, where these macros
   are empty. */
#ifndef KERNEL_MUTEX_USE_FUNCTIONS

/* This code should not be used unless DEBUG_LIGHT is disabled. */

#define ssh_kernel_mutex_lock(a) spin_lock(&((a)->lock))
#define ssh_kernel_mutex_unlock(b) spin_unlock(&((b)->lock))

#define ssh_kernel_rw_mutex_lock_read(a) read_lock(&((a)->lock))
#define ssh_kernel_rw_mutex_unlock_read(a) read_unlock(&((a)->lock))
#define ssh_kernel_rw_mutex_lock_write(a) write_lock(&((a)->lock))
#define ssh_kernel_rw_mutex_unlock_write(a) write_unlock(&((a)->lock))

#define ssh_kernel_critical_section_start(a) icept_preempt_disable()
#define ssh_kernel_critical_section_end(a) icept_preempt_enable()

#else /* KERNEL_MUTEX_USE_FUNCTIONS */

#ifdef SSH_LINUX_DEBUG_MUTEX

void ssh_linux_debug_lock(SshKernelMutex mutex, const char *name, int line);
void ssh_linux_debug_unlock(SshKernelMutex mutex, const char *name, int line);

#define ssh_kernel_mutex_lock(a) \
  ssh_linux_debug_lock((a), __FUNCTION__, __LINE__)
#define ssh_kernel_mutex_unlock(a) \
  ssh_linux_debug_unlock((a), __FUNCTION__, __LINE__)

#else /* SSH_LINUX_DEBUG_MUTEX */

void ssh_kernel_mutex_lock_i(SshKernelMutex mutex);
void ssh_kernel_mutex_unlock_i(SshKernelMutex mutex);

#define ssh_kernel_mutex_lock(a) \
  ssh_kernel_mutex_lock_i((a))
#define ssh_kernel_mutex_unlock(a) \
  ssh_kernel_mutex_unlock_i((a))

#endif /* SSH_LINUX_DEBUG_MUTEX */

void ssh_kernel_rw_mutex_lock_read_i(SshKernelRWMutex mutex);
void ssh_kernel_rw_mutex_unlock_read_i(SshKernelRWMutex mutex);
void ssh_kernel_rw_mutex_lock_write_i(SshKernelRWMutex mutex);
void ssh_kernel_rw_mutex_unlock_write_i(SshKernelRWMutex mutex);

#define ssh_kernel_rw_mutex_lock_read(a) \
  ssh_kernel_rw_mutex_lock_read_i((a))
#define ssh_kernel_rw_mutex_unlock_read(a) \
  ssh_kernel_rw_mutex_unlock_read_i((a))
#define ssh_kernel_rw_mutex_lock_write(a) \
  ssh_kernel_rw_mutex_lock_write_i((a))
#define ssh_kernel_rw_mutex_unlock_write(a) \
  ssh_kernel_rw_mutex_unlock_write_i((a))

void ssh_kernel_critical_section_start_i(SshKernelCriticalSection cs);
void ssh_kernel_critical_section_end_i(SshKernelCriticalSection cs);

#define ssh_kernel_critical_section_start(a) \
  ssh_kernel_critical_section_start_i((a))
#define ssh_kernel_critical_section_end(a) \
  ssh_kernel_critical_section_end_i((a))

#endif /* KERNEL_MUTEX_USE_FUNCTIONS */

#endif /* PLATFORM_KERNEL_MUTEX_H */
