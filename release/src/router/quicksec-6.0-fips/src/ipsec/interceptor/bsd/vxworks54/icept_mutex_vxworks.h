/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VxWorks-specific mutexes and locks.
*/

#ifndef ICEPT_MUTEX_VXWORKS_H
#define ICEPT_MUTEX_VXWORKS_H

#include "ipsec_params.h"
#include <engine.h>
#include "interceptor.h"

typedef struct SshKernelMutexRec
{
  int dummy;
} SshKernelMutexStruct;

typedef struct SshKernelRWMutexRec
{
  int dummy;
} SshKernelRWMutexStruct;

typedef struct SshKernelCriticalSectionRec
{
  int dummy;
} SshKernelCriticalSectionStruct;

#define ssh_kernel_mutex_init(mutex) TRUE
#define ssh_kernel_mutex_alloc() ((void *)4096)
#define ssh_kernel_mutex_uninit(mutex)
#define ssh_kernel_mutex_free(mutex)
#define ssh_kernel_mutex_lock(mutex)
#define ssh_kernel_mutex_unlock(mutex)
#ifdef DEBUG_LIGHT
#define ssh_kernel_mutex_assert_is_locked(mutex)
#endif /* DEBUG_LIGHT */

#define ssh_kernel_rw_mutex_init(mutex) TRUE
#define ssh_kernel_rw_mutex_alloc() ((void *)4096)
#define ssh_kernel_rw_mutex_uninit(mutex)
#define ssh_kernel_rw_mutex_free(mutex)
#define ssh_kernel_rw_mutex_lock_read(mutex)
#define ssh_kernel_rw_mutex_unlock_read(mutex)
#define ssh_kernel_rw_mutex_lock_write(mutex)
#define ssh_kernel_rw_mutex_unlock_write(mutex)

#define ssh_kernel_critical_section_init(cs) TRUE
#define ssh_kernel_critical_section_alloc() ((void *)4096)
#define ssh_kernel_critical_section_uninit(cs)
#define ssh_kernel_critical_section_free(cs)
#define ssh_kernel_critical_section_start(cs)
#define ssh_kernel_critical_section_end(cs)

#endif /* ICEPT_MUTEX_VXWORKS_H */
