/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Additional platform-dependent things. This file is included from
   engine-interface/kernel_mutex.h
*/

#ifndef PLATFORM_KERNEL_MUTEX_H
#define PLATFORM_KERNEL_MUTEX_H

#ifndef VXWORKS

typedef struct SshKernelMutexRec
{
  int taken;
} SshKernelMutexStruct;

typedef struct SshKernelRWMutexRec
{
  int taken;
} SshKernelRWMutexStruct;

typedef struct SshKernelCriticalSectionRec
{
  int taken;
} SshKernelCriticalSectionStruct;

#else /* VXWORKS */

#include "icept_mutex_vxworks.h"

#endif /* VXWORKS */

#endif /* PLATFORM_KERNEL_MUTEX_H */
