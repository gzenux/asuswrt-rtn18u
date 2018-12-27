/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of kernel_timeouts.h and supporting functions.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "sshsimplehashtable.h"
#include "sshdlqueue.h"
#include "icept_vxworks.h"
#include <time.h>
#include <netLib.h>

#define SSH_DEBUG_MODULE "IceptKernelTimeoutsVxWorks"

/* Timeout lists */
#define SSH_KTIMEOUT_SLOTS 32
#define SSH_KTIMEOUT_MASK (SSH_KTIMEOUT_SLOTS - 1)

typedef struct SshVxKernelTimeoutRec {
  /* This link must be the first member in the structure. */
  SshDlNodeStruct link;
  SshKernelTimeoutCallback callback;
  void *context;
  timer_t timer;
  int remove;
#ifdef DEBUG_LIGHT
  SshUInt32 tag;
  SshUInt32 magic;
#endif /* DEBUG_LIGHT */
} *SshVxKernelTimeout;

union {
  SshSimpleHashStruct hash;
  void *size[SSH_SIMPLE_HASH_SIZE_POINTERS(SSH_KTIMEOUT_SLOTS)];
} ssh_timeouts;

SshDlQueueStruct ssh_timeouts_free_queue;
SshUInt32 ssh_timeouts_cnt;

extern int ssh_net_id;

static SshUInt32 ssh_vx_kernel_timeout_hash(SshVxKernelTimeout t)
{
  SshUInt32 hash;

  hash = ((int) t->callback ) ^ ((int) t->context);
  return hash ^ (hash >> 16);
}

static void ssh_vx_kernel_timeout_cb(timer_t tid, int kto);

static SshVxKernelTimeout ssh_vx_alloc_kernel_timeout(void)
{
  SshVxKernelTimeout t = NULL;

  if (!(t = ssh_calloc(1, sizeof *t)))
    goto fail;

  if (timer_create(CLOCK_REALTIME, NULL, &t->timer) != OK)
    goto fail;

  if (timer_connect(t->timer, &ssh_vx_kernel_timeout_cb, (int)t) != OK)
    goto fail;

#ifdef DEBUG_LIGHT
  t->tag = ssh_timeouts_cnt++;
  t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */
  return t;

 fail:
  if (t)
    {
      if (t->timer)
        timer_delete(t->timer);
      ssh_free(t);
    }
  return NULL;
}

static void ssh_vx_delete_kernel_timeout(SshVxKernelTimeout t)
{
#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xf4eeda7a);
  t->magic = 0xdead7173;
#endif /* DEBUG_LIGHT */
  timer_delete(t->timer);
  ssh_free(t);
}

void ssh_vx_kernel_timeout_init(void)
{
  SSH_SIMPLE_HASH_INIT(
    &(ssh_timeouts.hash), SSH_KTIMEOUT_SLOTS, sizeof(ssh_timeouts));
  SSH_DLQUEUE_INIT(&ssh_timeouts_free_queue, 100);
}

/* Free ssh_timeouts_free_queue contents. */
void ssh_vx_kernel_timeout_uninit(void)
{
  SshDlNode node;

  while ((node = SSH_DLQUEUE_DETACH(&ssh_timeouts_free_queue)) != NULL)
    ssh_vx_delete_kernel_timeout((SshVxKernelTimeout)node);
}

/* This function is called on timeouts instead of calling the real timeout
   callback directly.  This will remove the timeout from the kernel
   list of timeouts and call the real callback. */
static void ssh_vx_kernel_timeout_wrap(int tid, int kto, int do_callback,
                                       int hash, int stub)
{
  SshVxKernelTimeout t = (SshVxKernelTimeout)kto;
  SshUInt32 h = hash;
  SshDlNode n;

  /* Do nothing if timer was cancelled between invocation of
     ssh_vx_kernel_timeout_cb and this function. */
  if (!SSH_SIMPLE_HASH_NODE_EXISTS(&(ssh_timeouts.hash), &(t->link), h))
    return;

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xbeef1234);
#endif /* DEBUG_LIGHT */

  /* Mark timer for removal after running callback. Callback may
     cancel removal by calling ssh_kernel_timeout_move(). */
  t->remove = 1;

  if (do_callback)
    t->callback(t->context);

  if (t->remove)
    {

#ifdef DEBUG_LIGHT
      t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */

      t->remove = 0;

      SSH_SIMPLE_HASH_NODE_DETACH(&(ssh_timeouts.hash), &(t->link), h);

      if ((n = SSH_DLQUEUE_INSERT(&(ssh_timeouts_free_queue), &(t->link))))
        ssh_vx_delete_kernel_timeout((SshVxKernelTimeout)n);
    }
}

static void ssh_vx_kernel_timeout_cb(timer_t tid, int kto)
{
  SshUInt32 hash;
  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  /* Calculate hash here, the timeout structure might have been freed
     prior netjob is actually executed. */
  hash = ssh_vx_kernel_timeout_hash((SshVxKernelTimeout)kto);

  if (netJobAdd((FUNCPTR)ssh_vx_kernel_timeout_wrap,
                (int)tid, (int)kto, TRUE, (int)hash, 0) != OK)
    {
      ssh_warning("cannot netJobAdd timeout function, deleting");
      ssh_vx_kernel_timeout_wrap((int)tid, (int)kto, FALSE, (int)hash, 0);
    }
}

/* Register a timeout. Explanation in kernel_timeouts.h. */

SSH_COND_SWITCH_HELPER_P4(ssh_kernel_timeout_register,
                          SshUInt32, seconds,
                          SshUInt32, microseconds,
                          SshKernelTimeoutCallback, callback,
                          void *, context);

void ssh_kernel_timeout_register(SshUInt32 seconds, SshUInt32 microseconds,
                                 SshKernelTimeoutCallback callback,
                                 void *context)
{
  SshDlNode n;
  SshVxKernelTimeout t;
  struct itimerspec value;
  int i = 0;

  SSH_COND_SWITCH_TO_NETTASK_P4(ssh_kernel_timeout_register,
                                SshUInt32, seconds,
                                SshUInt32, microseconds,
                                SshKernelTimeoutCallback, callback,
                                void *, context);

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  n = SSH_DLQUEUE_DETACH(&(ssh_timeouts_free_queue));
  if (n)
    {
      t = (SshVxKernelTimeout)n;
    }
  else
    {
      /* Loop until a new kernel timeout is available. */
      for(t = ssh_vx_alloc_kernel_timeout();
          t == NULL;
          t = ssh_vx_alloc_kernel_timeout())
        {
          taskDelay(1);
          if ((i++ & 0x100))
            ssh_warning("cannot allocate timer, retrying");
        }
    }

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xf4eeda7a);
  t->magic = 0xbeef1234;
#endif /* DEBUG_LIGHT */
  t->callback = callback;
  t->context = context;

  SSH_SIMPLE_HASH_NODE_INSERT(&(ssh_timeouts.hash), &(t->link),
                              ssh_vx_kernel_timeout_hash(t));

  if (microseconds >= 1000000)
    {
      seconds += microseconds/1000000;
      microseconds = microseconds%1000000;
    }

  /* Ensure nonzero time value to timer_settime(). */
  if (seconds == 0 && microseconds == 0)
    microseconds = 1;

  value.it_interval.tv_sec = 0;
  value.it_interval.tv_nsec = 0;
  value.it_value.tv_sec = seconds;
  value.it_value.tv_nsec = microseconds * 1000;

  if (timer_settime(t->timer, 0, &value, NULL) != OK)
      ssh_fatal("timer_settime() failed");
}

static void ssh_vx_kernel_timeout_cancel(SshVxKernelTimeout t)
{
  SshDlNode n;

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  SSH_SIMPLE_HASH_NODE_DETACH(&(ssh_timeouts.hash), &(t->link),
                              ssh_vx_kernel_timeout_hash(t));

  timer_cancel(t->timer);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xbeef1234);
  t->magic = 0xf4eeda7a;
#endif /* DEBUG_LIGHT */

  n = SSH_DLQUEUE_INSERT(&(ssh_timeouts_free_queue), &(t->link));
  if (n)
    ssh_vx_delete_kernel_timeout((SshVxKernelTimeout)n);
}

/* Cancel a timeout. Explanation in kernel_timeouts.h. */

SSH_COND_SWITCH_HELPER_P2(ssh_kernel_timeout_cancel,
                          SshKernelTimeoutCallback, callback,
                          void *, context);

void ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                               void *context)
{
  SshVxKernelTimeout t;
  struct SshVxKernelTimeoutRec dummy;
  SshSimpleHashEnumerator e;
  SshDlNode n;

  SSH_COND_SWITCH_TO_NETTASK_P2(ssh_kernel_timeout_cancel,
                                SshKernelTimeoutCallback, callback,
                                void *, context);

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  if (callback == SSH_KERNEL_ALL_CALLBACKS ||
      context == SSH_KERNEL_ALL_CONTEXTS)
    {
      /* Scan all hash buckets. */
      n = SSH_SIMPLE_HASH_ENUMERATOR_START(&(ssh_timeouts.hash), e);
      while (n)
        {
          t = (SshVxKernelTimeout) n;

          if ((callback == SSH_KERNEL_ALL_CALLBACKS ||
               t->callback == callback) &&
              (context == SSH_KERNEL_ALL_CONTEXTS ||
               t->context == context))
            {
              ssh_vx_kernel_timeout_cancel(t);
            }

          n = SSH_SIMPLE_HASH_ENUMERATOR_NEXT(&(ssh_timeouts.hash), e);
        }
    }
  else
    {
      /* Scan matching hash bucket only. */
      dummy.callback = callback;
      dummy.context = context;

      n = SSH_SIMPLE_HASH_ENUMERATOR_START_HASHVALUE(
        &(ssh_timeouts.hash), e, ssh_vx_kernel_timeout_hash(&dummy));
      while (n)
        {
          t = (SshVxKernelTimeout) n;

          if (t->callback == callback && t->context == context)
            ssh_vx_kernel_timeout_cancel(t);

          n = SSH_SIMPLE_HASH_ENUMERATOR_NEXT(&(ssh_timeouts.hash), e);
        }
    }
}

/* Move a timeout. Explanation in kernel_timeouts.h. */

SSH_COND_SWITCH_HELPER_P4_R(ssh_kernel_timeout_move, Boolean,
                          SshUInt32, seconds,
                          SshUInt32, microseconds,
                          SshKernelTimeoutCallback, callback,
                          void *, context);

Boolean ssh_kernel_timeout_move(SshUInt32 seconds, SshUInt32 microseconds,
                                SshKernelTimeoutCallback callback,
                                void *context)
{
  SshVxKernelTimeout t = NULL;
  struct SshVxKernelTimeoutRec dummy;
  SshSimpleHashEnumerator e;
  SshDlNode n;
  struct itimerspec value;

  SSH_ASSERT(callback != SSH_KERNEL_ALL_CALLBACKS);
  SSH_ASSERT(context != SSH_KERNEL_ALL_CONTEXTS);

  SSH_COND_SWITCH_TO_NETTASK_P4_R(ssh_kernel_timeout_move,
                                  SshUInt32, seconds,
                                  SshUInt32, microseconds,
                                  SshKernelTimeoutCallback, callback,
                                  void *, context);

  SSH_ASSERT(taskIdSelf() == ssh_net_id);

  dummy.callback = callback;
  dummy.context = context;

  n = SSH_SIMPLE_HASH_ENUMERATOR_START_HASHVALUE(
    &(ssh_timeouts.hash), e, ssh_vx_kernel_timeout_hash(&dummy));
  while (n)
    {
      t = (SshVxKernelTimeout) n;

      if (t->callback == callback && t->context == context)
        break;

      n = SSH_SIMPLE_HASH_ENUMERATOR_NEXT(&(ssh_timeouts.hash), e);
    }
  if (!n)
    return FALSE;

#ifdef DEBUG_LIGHT
  SSH_ASSERT(t->magic == 0xbeef1234);
#endif /* DEBUG_LIGHT */

  if (microseconds >= 1000000)
    {
      seconds += microseconds/1000000;
      microseconds = microseconds%1000000;
    }

  /* Ensure nonzero time value to timer_settime(). */
  if (seconds == 0 && microseconds == 0)
    microseconds = 1;

  value.it_interval.tv_sec = 0;
  value.it_interval.tv_nsec = 0;
  value.it_value.tv_sec = seconds;
  value.it_value.tv_nsec = microseconds * 1000;

  if (timer_settime(t->timer, 0, &value, NULL) != OK)
      ssh_fatal("timer_settime() failed");

  /* Prevent running timeout from being removed if it is moving
     itself. */
  if (t->remove)
    t->remove = 0;

  return TRUE;
}
