/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   linux_mutex_internal.h
*/

#ifndef LINUX_MUTEX_INTERNAL_H
#define LINUX_MUTEX_INTERNAL_H

#include <linux/spinlock.h>
#include <asm/current.h>

typedef struct SshKernelMutexRec
{
  spinlock_t lock;
  unsigned long flags;

#ifdef SSH_LINUX_DEBUG_MUTEX
  unsigned char taken_at_func[128];
  int taken_at_linenr;
#endif /* SSH_LINUX_DEBUG_MUTEX */

#ifdef DEBUG_LIGHT
  Boolean taken;
  unsigned long jiffies;
#endif
} SshKernelMutexStruct;


typedef struct SshKernelRWMutexRec
{
  rwlock_t lock;
} SshKernelRWMutexStruct;


typedef struct SshKernelCriticalSectionRec
{
  int dummy;
} SshKernelCriticalSectionStruct;

#ifdef CONFIG_PREEMPT

#include <linux/preempt.h>

#define icept_preempt_enable()  preempt_enable()
#define icept_preempt_disable() preempt_disable()

#else /* CONFIG_PREEMPT */

#define icept_preempt_enable()  do {;} while(0)
#define icept_preempt_disable() do {;} while(0)

#endif /* CONFIG_PREEMPT */

#endif /* LINUX_MUTEX_INTERNAL_H */
