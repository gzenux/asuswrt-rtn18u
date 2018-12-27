/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel-mode implementations of various functions for BSD-like
   operating systems.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "kernel_mutex.h"
#include "icept_internal.h"
#include "kernel_alloc.h"
#include <stdlib.h>
#include <time.h>
#include <netLib.h>
#include "cacheLib.h"
#include "icept_vxworks.h"
#include "sshsimplehashtable.h"
#include "sshdlqueue.h"


#define SSH_DEBUG_MODULE "IceptKernelStubsVxWorks"

/* From VxWorks BSP */
extern int sysClkRateGet();

/*
  Undefine SSH macros which are supposed to protect against
  unwanted use of system malloc / free.
*/
#ifdef malloc
#undef malloc
#endif
#ifdef free
#undef free
#endif

/**********************************************************************
 * ssh_kernel_alloc functions
 **********************************************************************/

#define SSH_MALLOC_OVERHEAD  (sizeof(SshUInt32))
#define SSH_VX_KERNEL_ALLOC_DMA 0x00000001

void *
ssh_kernel_alloc(size_t size, SshUInt32 flag)
{
  unsigned char *v;

  if (flag & SSH_KERNEL_ALLOC_DMA)
    {
      v = cacheDmaMalloc(size + SSH_MALLOC_OVERHEAD);
      ((SshUInt32 *) v)[0] = SSH_VX_KERNEL_ALLOC_DMA;
    }
  else
    {
      v = malloc(size + SSH_MALLOC_OVERHEAD);
      ((SshUInt32 *) v)[0] = 0;
    }

  return (v + SSH_MALLOC_OVERHEAD);
}


void
ssh_kernel_free(void *ptr)
{
  SshUInt32 v = ((SshUInt32 *)ptr)[-1];

  SSH_ASSERT(v == SSH_VX_KERNEL_ALLOC_DMA || v == 0);

  if (v == SSH_VX_KERNEL_ALLOC_DMA)
    cacheDmaFree((unsigned char *) ptr - SSH_MALLOC_OVERHEAD);
  else
    free((unsigned char *) ptr - SSH_MALLOC_OVERHEAD);
}

extern int ssh_net_id; /* To check if this is already tNetTask. */
/* Mechanism for moving execution to tNetTask. */

/* Move execution to netJob. returns 0 if successful. */
int ssh_netjob_synchronous_invoke(FUNCPTR function, void *context)
{
  STATUS stat;
  SEMAPHORE *s;

  s = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
  if (!s) return 2;

  semTake(s, WAIT_FOREVER);
  stat = netJobAdd(function, (int)context, (int)s, 0, 0, 0);

  if (stat == OK)
    {
      semTake(s, WAIT_FOREVER);
      semDelete(s);
      return 0;
    }

  semGive(s);
  semDelete(s);
  return 1;
}

#if VXWORKS_NETVER < 55122
void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);

  if (seconds)
    *seconds = (SshTime)ts.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)ts.tv_nsec / 1000;
}
#else /* VXWORKS_NETVER < 55122 */
void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timeval tv;

  microtime(&tv);

  if (seconds)
    *seconds = (SshTime)tv.tv_sec;
  if (useconds)
    *useconds = (SshUInt32)tv.tv_usec;
}
#endif /* VXWORKS_NETVER < 55122 */

void *ssh_kernel_thread_id(void)
{
  return (void *)taskIdSelf();
}

unsigned int ssh_kernel_num_cpus(void)
{
  return 1;
}

unsigned int ssh_kernel_get_cpu(void)
{
  return 0;
}

/**********************************************************************
 * Miscellaneous stubs to get things to compile
 **********************************************************************/













































































