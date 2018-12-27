/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains implementation of functions for timed callback
   functions. The description for these functions can be found at
   kernel_timeouts.h.

   The timed callbacks are managed by using a TimeoutManager object
   that maintains a list of all registered timed callbacks.

   The OS kernel timer object (NDIS_TIMER) is used to implement
   timed callback features. One periodic timer is created to run in a
   pre-defined interval. This timer calculates the elapsed time and then
   schedules WorkItems that runs the timed callbacks functions in a
   system worker thread context.
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "interceptor_i.h"
#include "engine_alloc.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* Debug info */
#define SSH_DEBUG_MODULE "SshInterceptorTimeout"

/* Number of pre-allocated timeout structures */
#define SSH_PRE_ALLOCATED_TIMEOUTS      20

/* Type definitions */

/*------------------------------------------------------------------------
  SSH Timeout

  Type definition for timeout attributes.
  ------------------------------------------------------------------------*/
typedef struct SshTimeoutRec
{
  /* For book-keeping timeouts in a double-linked list. Do not move this, 
     because some code assumes (for performance reasons) that this is the
     first item in SshTimeoutStruct. */
  LIST_ENTRY link;

  /* Expiry time in ticks */
  SshInt64 expires;

  /* Pointer into our timeout manager object */
  SshTimeoutManager timeout_mgr;

  /* Timed callback function that is executed when timer is expired */
  SshKernelTimeoutCallback callback;

  /* Parameter for timed callback function */
  void *context;

  /* This flag is set if this is a pre-allocated timeout. */
  SshUInt8 pre_allocated : 1;

  /* This flag is set if the timeout must be removed from timeout list after
     it's execution has finished. */
  SshUInt8 remove_from_list : 1;

} SshTimeoutStruct, *SshTimeout;


/*------------------------------------------------------------------------
  SSH Timer

  Type definition for system timer object.
  ------------------------------------------------------------------------*/
typedef struct SshTimerRec
{
  /* Kernel timer and associated DPC object */
  KTIMER timer;
  KDPC timer_dpc;
  /* Length of single (timer interrupt) tick in microseconds */
  ULONG tick_length;
} SshTimerStruct, *SshTimer;


/*------------------------------------------------------------------------
  SSH Timeout Manager
  
  Type definition for object that manages all timeout operations 
  (register, cancel).
  ------------------------------------------------------------------------*/
typedef struct SshTimeoutManagerRec
{
  /* System timer */
  SshTimerStruct timer;

  /* Timeout currently in timer callback */
  SshTimeout active_timeout;

  /* The processor running the active timeout */
  SshInt16 active_timeout_cpu;

  /* Number of cancel operations pending */
  SshUInt32 pending_cancels : 31;
  /* This flag is set if system timer must be resceduled when the last 
     pending cancel operation completes */
  SshUInt32 must_reschedule : 1;

  /* Double-linked list for timeouts and it's lock */
  LIST_ENTRY timeout_list;
  NDIS_SPIN_LOCK timeout_list_lock;

  /* Free-list of pre-allocated timeout structures and lock for ensuring the
     data integrity */
  LIST_ENTRY free_timeouts;
  NDIS_SPIN_LOCK free_list_lock;

  /* Pre-allocated timeouts */
  SshTimeoutStruct pre_allocated_timeouts[SSH_PRE_ALLOCATED_TIMEOUTS];

} SshTimeoutManagerStruct;


/* We can use higher resolution timer on Windows 2K/XP/2K3 */
typedef PKDEFERRED_ROUTINE SshSystemTimerCallback;

__inline void
ssh_get_tick_count_us(SshTimeoutManager timeout_mgr,
                      SshInt64 *tick_count)
{
  LARGE_INTEGER ticks;

  KeQueryTickCount(&ticks);

  *tick_count = ticks.QuadPart * timeout_mgr->timer.tick_length;
}

__inline void
ssh_timer_init(SshTimer timer,
               SshSystemTimerCallback cb,
               void *context)
{
  timer->tick_length = KeQueryTimeIncrement();
  timer->tick_length /= 10;

  KeInitializeTimer(&timer->timer);               
  KeInitializeDpc(&timer->timer_dpc,              
                  cb, context);                     
} 

#define ssh_timer_uninit(timer)  /* Nothing to do */

__inline void
ssh_timer_start(SshTimer timer,
                SshInt64 microseconds)
{
  LARGE_INTEGER expires;

  expires.QuadPart = microseconds;
  expires.QuadPart *= -10;

  KeSetTimer(&timer->timer, expires, &timer->timer_dpc);
}

__inline void
ssh_timer_stop(SshTimer timer)   
{
  KeCancelTimer(&timer->timer);
}

/* For increased WHQL compatibility (prevent one warning), we should not
   use the outdated macro-version of KeQueryTickCount() */
#if defined(KeQueryTickCount) && !defined(_WIN64)
#undef KeQueryTickCount

NTKERNELAPI VOID KeQueryTickCount(PLARGE_INTEGER tick_count);

#endif /* KeQueryTickCount */


/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

KDEFERRED_ROUTINE ssh_kernel_timeout_execute;

/*-------------------------------------------------------------------------
  IN-LINE FUNCTIONS
  -------------------------------------------------------------------------*/

__inline SshTimeout
ssh_kernel_timeout_alloc(SshTimeoutManager timeout_mgr)
{
  SshTimeout timeout = NULL;
  PLIST_ENTRY entry;
  
  entry = NdisInterlockedRemoveHeadList(&timeout_mgr->free_timeouts,
                                        &timeout_mgr->free_list_lock);
  if (entry != NULL)
    timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);

  if (timeout == NULL)
    {
      timeout = ssh_calloc(1, sizeof(*timeout));
      if (timeout == NULL)
        ssh_fatal("Out of memory!");

      timeout->pre_allocated = 0;
    }

  return (timeout);
}


__inline void
ssh_kernel_timeout_free(SshTimeoutManager timeout_mgr,
                        SshTimeout timeout)
{
  if (timeout->pre_allocated)
    NdisInterlockedInsertTailList(&timeout_mgr->free_timeouts,
                                  &timeout->link,
                                  &timeout_mgr->free_list_lock);
  else
    ssh_free(timeout);
}


__inline void
ssh_kernel_timeout_reschedule_timer(SshTimeoutManager timeout_mgr,
                                    SSH_IRQL irql)
{
  if (IsListEmpty(&timeout_mgr->timeout_list))
    {
      ssh_timer_stop(&timeout_mgr->timer);
    }
  else
    {
      SshInt64 now;
      SshInt64 expires;
      SshTimeout timeout = CONTAINING_RECORD(timeout_mgr->timeout_list.Flink,
                                             SshTimeoutStruct, link);

      ssh_get_tick_count_us(timeout_mgr, &now);

      expires = timeout->expires - now;

      if (expires < 0)
        expires = 0;

      if ((irql < SSH_DISPATCH_LEVEL) && (expires < 1000))
        {
          /* If the calling thread was running at IRQL less than 
             DISPATCH_LEVEL before it acquired the spin lock (meaning that
             it can be pre-empted), we should refuse to schedule "too short"
             (repetitive) timeout, otherwise we could cause an infinite loop.

             This is what could happen:

             1) After the calling thread releases the spin lock currently
                held, thus causing the IRQL to drop below DISPATCH_LEVEL...

             2) If the very short timeout was not already executed (by
                another CPU on SMP platform...

             3) With a very high probability, DPC routine of the system 
                timer is executed on the context of the thread which 
                originally scheduled the timeout (because this thread is
                the one executing when the dispatcher interrupt is 
                handled)...

             4) If the timeout callback simply checks whether the original
                caller thread has completed some task... and when not, it 
                re-schedules another very short timeout which will fire 
                almost immediately...

             5) The result is that the original thread will never get chance 
                to continue execution... */

          expires = 1000;  /* one millisecond */
        }

      ssh_timer_start(&timeout_mgr->timer, expires);
    }
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_kernel_timeout_register()

  Registers a timed callback function. Timeouts are kept in a
  double-linked list so that they can be cancelled before their
  timer is expired.
  
  Arguments:
  secs - expiration time in seconds
  usecs - expiration time in microseconds
  callback - callback function to execute when timeout expires
  context - context passed to callback function
  
  Returns:
  
  Notes:
   If the registered timeout is currently under cancellation it
   is immediately cancelled by not registering it.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeout_register(SshUInt32 secs,
                            SshUInt32 usecs,
                            SshKernelTimeoutCallback callback,
                            void *context)
{
  SshTimeoutManager timeout_mgr;
  SshTimeout timeout;
  PLIST_ENTRY pred, succ;
  SSH_IRQL irql = SSH_GET_IRQL();

  
  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->timeout_mgr != NULL);

  timeout_mgr = the_interceptor->timeout_mgr;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_register()"));

  timeout = ssh_kernel_timeout_alloc(timeout_mgr);

  /* Compute relative expiration time, units are microsecond intervals */
  ssh_get_tick_count_us(timeout_mgr, &timeout->expires);
  timeout->expires += 1000000 * secs + usecs;
  timeout->callback = callback;
  timeout->context = context;
  timeout->remove_from_list = 0;

  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  for (succ = timeout_mgr->timeout_list.Flink;
       succ != &timeout_mgr->timeout_list; succ = succ->Flink)
    {
      SshTimeout to = CONTAINING_RECORD(succ, SshTimeoutStruct, link);

      if (to->expires > timeout->expires)
        break;
    }
  
  /* Insert new timeout to the sorted, doubly-linked queue */
  pred = succ->Blink;
  timeout->link.Blink = pred;
  timeout->link.Flink = succ;
  pred->Flink = &timeout->link;
  succ->Blink = &timeout->link;

  /* If new timeout was inserted into the beginning of the queue AND 
     timer callback is not currently running, reschedule the timer. 
     If timer callback is running, the timer is rescheduled after the 
     callback returns (in that case this timeout could also get 
     immediately canceled). */
  if ((pred == &timeout_mgr->timeout_list) && 
      (timeout_mgr->active_timeout == NULL))
    {
      /* The system timer is rescheduled either now or when all pending 
         cancel operations have been completed. */
      if (timeout_mgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);
      else
        timeout_mgr->must_reschedule = 1;
    }
  
  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
}


/*--------------------------------------------------------------------------
  ssh_kernel_timeout_cancel()

  Cancels a previously registered timeout or all timed callbacks
  if their's timed callback execution has not yet started.

  Arguments:
  callback - timed callback function to cancel or all callbacks
  context - callback function context or all contexts
  
  Returns:
  
  Notes:
  Global cancellation of timeouts is still required before the application
  using timeouts is terminated.
  -------------------------------------------------------------------------*/
VOID
ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                          void *context)
{
  SshTimeoutManager timeout_mgr;
  LIST_ENTRY canceled_timeouts;
  PLIST_ENTRY first;
  SshTimeout timeout;
  SSH_IRQL irql = SSH_GET_IRQL();

  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->timeout_mgr != NULL);

  timeout_mgr = the_interceptor->timeout_mgr;

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_cancel()"));

  NdisInitializeListHead(&canceled_timeouts);

  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  timeout_mgr->pending_cancels++;

 retry:

    /* If we have active timeout, check that are we canceling 
     it. If we aren't, we can continue disabling other timeouts.
     Actually there still remains one rare condition, we could 
     prepare ourselves. If we are canceling all timeouts, we should
     make a delayed waiting for active timeout gets away and then 
     we can remove the timeouts. */
  if (timeout_mgr->active_timeout && 
      (timeout_mgr->active_timeout->context == context ||
       context == SSH_KERNEL_ALL_CONTEXTS) &&
      timeout_mgr->active_timeout->callback == callback &&
      timeout_mgr->active_timeout_cpu == ssh_kernel_get_cpu())
    {
      /* If we are canceling the timeout we are already executing, 
         we cannot cancel it, since it executing and is anyway disabled
         after the callback execution ends. Just release spinlock and
	 return to the caller. */

      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      ssh_fatal("Canceling timeout callback (%p %p) on the same CPU where the" 
                " callback is executing at the moment.", context, callback);
      return;
    }
  else if (timeout_mgr->active_timeout && 
           (timeout_mgr->active_timeout->context == context ||
            context == SSH_KERNEL_ALL_CONTEXTS) &&
           timeout_mgr->active_timeout->callback == callback &&
           timeout_mgr->active_timeout_cpu != ssh_kernel_get_cpu())
    {
      /* We are cancelling the same callback which is on execution on 
         other CPU. Wait for it to finish and cancel it only after 
         that. */
      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      
      if (irql < SSH_DISPATCH_LEVEL)
        {
          NdisMSleep(50);
        }
      else
        {
          SSH_ASSERT(ssh_kernel_num_cpus() > 1);
          NdisStallExecution(20);
        }
      
      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
      goto retry;
    }
  else if (timeout_mgr->active_timeout &&
           context == SSH_KERNEL_ALL_CONTEXTS &&
           callback == SSH_KERNEL_ALL_CALLBACKS) 
           
    {
      /* Case when we are disabling all callbacks on all contexts (i.e.
         disabling the interceptor) or we are disabling all certain callbacks
         in all contexts. We must wait until active timeout finishes. */
      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      
      if (irql < SSH_DISPATCH_LEVEL)
        {
          NdisMSleep(50);
        }
      else
        {
          SSH_ASSERT(ssh_kernel_num_cpus() > 1);
          NdisStallExecution(20);
        }
      
      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
      goto retry;
    }
  else
    {
      PLIST_ENTRY current;

      /* No timer callbacks running, perform the cancel processing */
      first = timeout_mgr->timeout_list.Flink;
      
      current = first;
      while (current != &timeout_mgr->timeout_list)
        {
          PLIST_ENTRY next = current->Flink;

          timeout = CONTAINING_RECORD(current, SshTimeoutStruct, link);

          if ((timeout->callback == callback) ||
              (callback == SSH_KERNEL_ALL_CALLBACKS))
            {
              if ((timeout->context == context) ||
                  (context == SSH_KERNEL_ALL_CONTEXTS))
                {
                  /* Move this timeout into the list of canceled timeouts.
                     The timeout will be freed after we release the spin
                     lock. */
                  RemoveEntryList(current);
                  InitializeListHead(current);
                  InsertTailList(&canceled_timeouts, current);
                }
            }

          current = next;
        }

      timeout_mgr->pending_cancels--;

      if (timeout_mgr->pending_cancels == 0 &&
          !timeout_mgr->active_timeout)
        {
          /* If first timeout was canceled, reschedule the timer */
          if ((timeout_mgr->timeout_list.Flink != first) ||
              (timeout_mgr->must_reschedule == 1))
            {
              ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);

              timeout_mgr->must_reschedule = 0;
            }
        }
    }

  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  while (!IsListEmpty(&canceled_timeouts))
    {
      first = RemoveHeadList(&canceled_timeouts);

      timeout = CONTAINING_RECORD(first, SshTimeoutStruct, link);

      ssh_kernel_timeout_free(timeout_mgr, timeout);
    }
}

Boolean ssh_kernel_timeout_move(SshUInt32 secs,
				SshUInt32 usecs,
				SshKernelTimeoutCallback callback,
				void *context)
{
  SshTimeoutManager timeout_mgr;
  SshTimeout timeout;
  SshTimeout insert_before_to;
  SshTimeout moved_to;
  PLIST_ENTRY pred, succ;
  SSH_IRQL irql = SSH_GET_IRQL();
  SshInt64 expires;
  Boolean reschedule = FALSE;

  SSH_ASSERT(the_interceptor != NULL);
  SSH_ASSERT(the_interceptor->timeout_mgr != NULL);

  timeout_mgr = the_interceptor->timeout_mgr;

  /* Timeout move must always be called with specific callback and
     context parameters. */
  SSH_ASSERT(callback != NULL);
  SSH_ASSERT(callback != SSH_KERNEL_ALL_CALLBACKS);
  SSH_ASSERT(context != SSH_KERNEL_ALL_CONTEXTS);

  if (callback == NULL
      || callback == SSH_KERNEL_ALL_CALLBACKS
      || context == SSH_KERNEL_ALL_CONTEXTS)
    ssh_fatal("ssh_kernel_timeout_move must be called with specific "
	      "callback and context parameters");

  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  /* Calculate new expiry time in jiffies. */
  ssh_get_tick_count_us(timeout_mgr, &expires);
  expires += 1000000 * secs + usecs;

  SSH_DEBUG(SSH_D_LOWOK,
	    ("Moving timeout callback %p context %p to %lu.%06lu expires %lu",
	     callback, context,
	     (unsigned long) secs,
	     (unsigned long) usecs,
	     (unsigned long) expires));

  /* Lookup timeout from list and scan for the correct position where
     the timeout should be re-inserted.*/
  moved_to = NULL;
  insert_before_to = NULL;
  for (succ = timeout_mgr->timeout_list.Flink;
       succ != &timeout_mgr->timeout_list;
       succ = succ->Flink)
    {
      SshTimeout to = CONTAINING_RECORD(succ, SshTimeoutStruct, link);

      /* Check if timeout matches the parameters */
      if (moved_to == NULL
	  && to->callback == callback
	  && to->context == context)
	moved_to = to;
      
      /* No match, check if this is the position were the timeout
	 should be moved to. */
      else if (insert_before_to == NULL && to->expires > expires)
	insert_before_to = to;
      
      /* Found both the first matching timeout and the point where
	 it is moved. */
      if (moved_to != NULL && insert_before_to != NULL)
	break;
    }
  
  /* No matching timeout was found, all done. */
  if (moved_to == NULL)
    {
      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);
      SSH_DEBUG(SSH_D_LOWOK, ("No timeout found for callback %p context %p",
			      callback, context));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching timeout %p expires %lu",
			  moved_to, (unsigned long) moved_to->expires));
  
  /* Check if rescheduling is required. */
  if (&moved_to->link == timeout_mgr->timeout_list.Flink)
    reschedule = TRUE; 
  else
    reschedule = FALSE;
  
  RemoveEntryList(&moved_to->link);
    
  /* Set new expiry time and insert the matching timeout to new position on
     the timeout list. */
  moved_to->expires = expires;

  /* If the moved timeout is currently running, then clear remove_from_list
     to signal that the timeout has been moved to a new position in the
     timeout list and the timeout should not be removed from timeout list
     when execution has finished. */
  if (moved_to->remove_from_list == 1)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Moving timeout %p that is currently executing",
			      moved_to));
      moved_to->remove_from_list = 0;
    }

  /* Insert the timeout to head or middle of the non-empty timeout list. */
  if (insert_before_to != NULL)
    {
      SSH_ASSERT(moved_to->expires < insert_before_to->expires);

      pred = insert_before_to->link.Blink;
      moved_to->link.Blink = pred;
      moved_to->link.Flink = &insert_before_to->link;
      pred->Flink = &moved_to->link;
      insert_before_to->link.Blink = &moved_to->link;

      if (pred == &timeout_mgr->timeout_list)
	reschedule = TRUE;
    }

  /* Insert the timeout into empty timeout list. */
  else if (IsListEmpty(&timeout_mgr->timeout_list))
    {
      InitializeListHead(&moved_to->link);
      InsertHeadList(&timeout_mgr->timeout_list, &moved_to->link);
      reschedule = TRUE;
    }

  /* Insert to tail of non-empty timeout list. */
  else
    {
      InitializeListHead(&moved_to->link);
      InsertTailList(&timeout_mgr->timeout_list, &moved_to->link);
    }

  /* Check if need to reschedule system timer. */
  if (reschedule == TRUE && timeout_mgr->active_timeout == NULL)
    {
      if (timeout_mgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);
      else
        timeout_mgr->must_reschedule = 1;
    }
  
  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  return TRUE;
}


Boolean
ssh_kernel_timeouts_init(SshInterceptor interceptor)
{
  SshTimeoutManager timeout_mgr;
  unsigned int i;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  /* Create timeout_manager if it does not exist. */
  timeout_mgr = ssh_calloc(1, sizeof(*timeout_mgr));
  if (timeout_mgr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create timeout manager!"));
      return FALSE;
    }

  NdisInitializeListHead(&timeout_mgr->timeout_list);
  NdisAllocateSpinLock(&timeout_mgr->timeout_list_lock);

  NdisInitializeListHead(&timeout_mgr->free_timeouts);
  NdisAllocateSpinLock(&timeout_mgr->free_list_lock);

  for (i = 0; i < SSH_PRE_ALLOCATED_TIMEOUTS; i++)
    {
      SshTimeout timeout = &timeout_mgr->pre_allocated_timeouts[i];

      timeout->pre_allocated = 1;
      InitializeListHead(&timeout->link);
      InsertTailList(&timeout_mgr->free_timeouts, &timeout->link);
    }

  interceptor->timeout_mgr = timeout_mgr;

  ssh_timer_init(&timeout_mgr->timer, 
                 ssh_kernel_timeout_execute, 
                 timeout_mgr);

  return TRUE;
}


VOID
ssh_kernel_timeouts_uninit(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  ssh_timer_stop(&(interceptor->timeout_mgr->timer));
  ssh_timer_uninit(&(interceptor->timeout_mgr->timer));

  /* Destroy the TimeoutManager */
  ssh_free(interceptor->timeout_mgr);
  interceptor->timeout_mgr = NULL;
}


VOID
ssh_kernel_timeouts_suspend(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  ssh_timer_stop(&(interceptor->timeout_mgr->timer));
}


VOID
ssh_kernel_timeouts_resume(SshInterceptor interceptor,
                           SshUInt32 suspend_time_sec,
                           SshUInt32 suspend_time_usec)
{
  SshTimeoutManager timeout_mgr;
  PLIST_ENTRY entry;
  __int64 interval;
  SSH_IRQL irql = SSH_GET_IRQL();

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->timeout_mgr != NULL);

  timeout_mgr = interceptor->timeout_mgr;

  /* Compute relative expiration time, units are microsecond intervals */
  interval = 1000000 * suspend_time_sec + suspend_time_usec;

  /* Adjust the tick counts for scheduled timeouts */
  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

  for (entry = timeout_mgr->timeout_list.Flink;
       entry != &(timeout_mgr->timeout_list);
       entry = entry->Flink)
    {
      SshTimeout timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);

      if (interval > timeout->expires)
        timeout->expires = 0;
      else
        timeout->expires -= interval;
    }

  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  ssh_kernel_timeout_reschedule_timer(timeout_mgr, irql);
}


/*-------------------------------------------------------------------------
  LOCAL FUNCTIONS
  -------------------------------------------------------------------------*/

static void
ssh_timeout_flush_queue(SshInterceptor interceptor, SshCpuContext cpu_ctx)
{
  if (cpu_ctx->in_timeout_queue_flush)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring recursive timeout queue "
				   "flush request"));
      return;
    }

  cpu_ctx->in_timeout_queue_flush = 1;  
  while (cpu_ctx->packets_in_timeout_send_queue 
	 || cpu_ctx->packets_in_timeout_recv_queue)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Flushing packets in timeout queue."));

      if (cpu_ctx->packets_in_timeout_send_queue)
	{
	  cpu_ctx->packets_in_timeout_send_queue = 0;
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->timeout_send_queue, 
					     TRUE);
	}
      
      if (cpu_ctx->packets_in_timeout_recv_queue)
	{
	  cpu_ctx->packets_in_timeout_recv_queue = 0;
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->timeout_recv_queue,
					     FALSE);
	}
    }
  cpu_ctx->in_timeout_queue_flush = 0;
}

/* This function is called as a DPC routine when timer expires */
static void
ssh_kernel_timeout_execute(
                           KDPC *dpc,
                           SshTimeoutManager timeout_mgr,
                           void *sys_agr2,
                           void *sys_arg3)
{
  SshInterceptor interceptor = the_interceptor;
  SshTimeout timeout = NULL;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(the_interceptor != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, ("ssh_kernel_timeout_execute()"));

#pragma warning(disable : 6011)
  /* */
  NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);
  if (!IsListEmpty(&timeout_mgr->timeout_list))
    {
      PLIST_ENTRY entry;

      entry = timeout_mgr->timeout_list.Flink;

      timeout = CONTAINING_RECORD(entry, SshTimeoutStruct, link);
      timeout_mgr->active_timeout = timeout;
      timeout_mgr->active_timeout_cpu = (SshUInt16)ssh_kernel_get_cpu();

      /* Mark that timeout is to be removed from timeout list after
	 timeout execution has finished. */
      timeout->remove_from_list = 1;
    }
  NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

  if (timeout != NULL)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Executing timer callback"));

      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
      cpu_ctx->in_timeout_cb = 1;

      timeout->callback(timeout->context);

      cpu_ctx->in_timeout_cb = 0;
      ssh_timeout_flush_queue(interceptor, cpu_ctx);

      SSH_DEBUG(SSH_D_LOWSTART, ("Timer callback done"));

      NdisAcquireSpinLock(&timeout_mgr->timeout_list_lock);

      timeout_mgr->active_timeout = NULL;

      /* Remove the timeout from timeout list unless it was moved while
	 under execution. */
      if (timeout->remove_from_list == 1)
	RemoveEntryList(&timeout->link);
      else
	timeout = NULL;

      /* Do not restart the system timer now if one or more cancel operations
         are currently pending. (In this case the timer is rescheduled when
         the last cancel operation completes.) This "trick" keeps timeout
         cancellation simple... */
      if (timeout_mgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(timeout_mgr,
                                            SSH_DISPATCH_LEVEL);
      else
        timeout_mgr->must_reschedule = 1;

      NdisReleaseSpinLock(&timeout_mgr->timeout_list_lock);

      if (timeout != NULL) 
	ssh_kernel_timeout_free(timeout_mgr, timeout);
    }
  else
    {
      /* All timeouts were canceled after the timer expired, but before this
         function acquired the timeout_list_lock. Unlikely, but possible. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Timeout queue is empty!"));
    }
#pragma warning(default : 6011)
} 

