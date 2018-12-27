/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the kernel timeout API, ssh_kernel_timeout_*
   functions. These functions are common to all Linux 2.x versions.
*/

#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorTimeout"

extern SshInterceptor ssh_interceptor_context;

static void
ssh_kernel_timeout_cb(unsigned long data);


/********************* Timeout freelist *************************************/

static inline SshKernelTimeout
ssh_kernel_timeout_freelist_get(SshTimeoutManager tmgr)
{
  SshKernelTimeout item;

  SSH_ASSERT(tmgr != NULL);

  if (unlikely(tmgr->free_timeouts == 0))
    {
      SSH_ASSERT(tmgr->timeout_freelist == NULL);
      item = ssh_calloc(1, sizeof(SshKernelTimeoutStruct));

#ifdef DEBUG_LIGHT
      if (item != NULL)
        tmgr->allocated_timeouts++;
#endif /* DEBUG_LIGHT */

      SSH_DEBUG(SSH_D_LOWOK, ("No free timeouts, allocated new %p", item));
      return item;
    }
  else
    {
      SSH_ASSERT(tmgr->timeout_freelist != NULL);

      item = tmgr->timeout_freelist;
      tmgr->timeout_freelist = item->next;
      tmgr->free_timeouts--;

#ifdef DEBUG_LIGHT
      tmgr->allocated_timeouts++;
      SSH_ASSERT(tmgr->free_timeouts < SSH_KERNEL_TIMEOUT_FREELIST_LENGTH);
#endif /* DEBUG_LIGHT */

      SSH_DEBUG(SSH_D_LOWOK,
                ("Allocated timeout %p from freelist, free timeouts %u",
                 item, tmgr->free_timeouts));
      return item;
    }
}

static inline void
ssh_kernel_timeout_freelist_put(SshTimeoutManager tmgr,
                                SshKernelTimeout timeout)
{
  SSH_ASSERT(tmgr != NULL);
  SSH_ASSERT(timeout != NULL);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(tmgr->allocated_timeouts > 0);
  tmgr->allocated_timeouts--;
#endif /* DEBUG_LIGHT */

  if (unlikely((tmgr->free_timeouts + 1) > SSH_KERNEL_TIMEOUT_FREELIST_LENGTH))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Freed timeout %p, freelist full", timeout));
      ssh_free(timeout);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Put timeout %p into freelist, free timeouts %u.",
                          timeout, tmgr->free_timeouts + 1));

#ifdef DEBUG_LIGHT
  memset(timeout, 'F', sizeof(SshKernelTimeoutStruct));
#endif /* DEBUG_LIGHT */

  timeout->next = tmgr->timeout_freelist;
  tmgr->timeout_freelist = timeout;
  tmgr->free_timeouts++;

  SSH_ASSERT(tmgr->free_timeouts > 0 &&
             tmgr->free_timeouts <= SSH_KERNEL_TIMEOUT_FREELIST_LENGTH);
}

void
ssh_kernel_timeout_freelist_uninit(SshKernelTimeout list)
{
  SshKernelTimeout next;

  SSH_DEBUG(SSH_D_LOWOK, ("Uninitialising timeout freelist."));

  while (list)
    {
      next = list->next;
      ssh_free(list);
      list = next;
    }
}

SshKernelTimeout
ssh_kernel_timeout_freelist_init(SshUInt32 count)
{
  SshKernelTimeout tmp_list = NULL;
  SshKernelTimeout item;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_LOWOK, ("Initializing timeout freelist of size %u.", count));

  for (i = 0; i < count; i++)
    {
      item = ssh_calloc(1, sizeof(SshKernelTimeoutStruct));
      if (item == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Freelist allocation failed!"));
          ssh_kernel_timeout_freelist_uninit(tmp_list);
          return NULL;
        }

      item->next = tmp_list;
      tmp_list = item;
    }

  return tmp_list;
}


/********************** Timeouts init/uninit *********************************/

void
ssh_kernel_timeouts_uninit(SshInterceptor interceptor)
{
  SshTimeoutManager tmgr = &interceptor->timeouts;

  SSH_DEBUG(SSH_D_LOWOK, ("Uninitializing interceptor timeouts %p.",
                          tmgr));

  if (tmgr->timeout_freelist)
    {
      SSH_ASSERT(tmgr->free_timeouts == SSH_KERNEL_TIMEOUT_FREELIST_LENGTH);
      SSH_ASSERT(tmgr->allocated_timeouts == 0);

      ssh_kernel_timeout_freelist_uninit(tmgr->timeout_freelist);
      tmgr->free_timeouts = 0;
    }

  if (tmgr->timeout_lock)
    ssh_kernel_mutex_free(tmgr->timeout_lock);
}

Boolean
ssh_kernel_timeouts_stop(SshInterceptor interceptor)
{
  SshTimeoutManager tmgr = &interceptor->timeouts;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(tmgr != NULL);

  ssh_kernel_mutex_lock(tmgr->timeout_lock);
  tmgr->timeouts_stopped = 1;
  ssh_kernel_mutex_unlock(tmgr->timeout_lock);

  return TRUE;
}

Boolean
ssh_kernel_timeouts_init(SshInterceptor interceptor)
{
  SshTimeoutManager tmgr = &interceptor->timeouts;
  SSH_DEBUG(SSH_D_LOWOK, ("Initializing timeouts."));

  /* Initialize kernel timeout context structure. */
  memset(tmgr, 0x0, sizeof(SshTimeoutManagerStruct));

  tmgr->timeout_lock = ssh_kernel_mutex_alloc();
  if (tmgr->timeout_lock == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Timeout lock allocation failed."));
      return FALSE;
    }

  /* Initialize the freelist for timeouts. */
  tmgr->timeout_freelist =
    ssh_kernel_timeout_freelist_init(SSH_KERNEL_TIMEOUT_FREELIST_LENGTH);
  if (tmgr->timeout_freelist == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Timeout freelist allocation failed."));

      ssh_kernel_mutex_free(tmgr->timeout_lock);
      return FALSE;
    }
  tmgr->free_timeouts = SSH_KERNEL_TIMEOUT_FREELIST_LENGTH;
  tmgr->running_timeout_cpu = 0xBAD0;

  SSH_DEBUG(SSH_D_MIDOK, ("Successfully initialized timeouts %p.",
                          interceptor->timeouts));

  return TRUE;
}


/******************* Timeout register, cancel and execution ******************/

































void
ssh_kernel_timeout_reschedule_timer(SshTimeoutManager tmgr)
{
  SshKernelTimeout to = tmgr->timeout_list;

  /* If timeout_list is NULL, we do not need to do anything. */
  if (likely((to != NULL) && (tmgr->timeouts_stopped == 0)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Scheduling timer: expires %lu current jiffies %lu",
                 to->expires, jiffies));

      /* System timer is registered, modify expire time. */
      if (likely(tmgr->system_timer_registered == 1))
        {
          if (time_before_eq(to->expires, jiffies))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Timeout expiry %lu is in the past: jiffies %lu",
                         to->expires, jiffies));
              mod_timer(&tmgr->timer, jiffies + 1);
            }
          else
            mod_timer(&tmgr->timer, to->expires);
        }

      /* Register a new system timer. */
      else
        {
          init_timer(&tmgr->timer);

          if (time_before_eq(to->expires, jiffies))
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Timeout expiry %lu is in the past: jiffies %lu",
                         to->expires, jiffies));
              tmgr->timer.expires = jiffies + 1;
            }
          else
            tmgr->timer.expires = to->expires;

          tmgr->timer.data = (unsigned long) tmgr;
          tmgr->timer.function = ssh_kernel_timeout_cb;

          tmgr->system_timer_registered = 1;
          add_timer(&tmgr->timer);
        }
    }
  else if (tmgr->system_timer_registered == 1)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Cancelling old system timer"));
      tmgr->system_timer_registered = 0;
      del_timer(&tmgr->timer);
    }
}

/* System timer callback function. */
static void
ssh_kernel_timeout_cb(unsigned long data)
{
  SshInterceptor interceptor = ssh_interceptor_context;
  SshTimeoutManager tmgr = &interceptor->timeouts;
  SshKernelTimeout to;
#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  SshCpuContext cpu_ctx;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */
#ifdef DEBUG_LIGHT
  unsigned long timeout_start_jiffies;
  int timeouts_executed;
#endif /* DEBUG_LIGHT */





  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(tmgr != NULL);
  SSH_ASSERT(in_softirq());

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  SSH_DEBUG(SSH_D_LOWOK, ("Timeout callback: jiffies %lu",
                          (unsigned long) jiffies));

  ssh_kernel_mutex_lock(tmgr->timeout_lock);

#ifdef DEBUG_LIGHT
  /* Store jiffies to local variable for calculating duration of timeout
     execution . */
  timeout_start_jiffies = jiffies;
  timeouts_executed = 0;
#endif /* DEBUG_LIGHT */

  /* Take first timer from timeout list and check if it is time to execute
     the timeout. */
 execute_next:
  ssh_kernel_mutex_assert_is_locked(tmgr->timeout_lock);
  if (likely(tmgr->timeout_list != NULL
             && time_after_eq(jiffies, tmgr->timeout_list->expires)
             && tmgr->timeouts_stopped == 0))
    {
      /* Do not remove timeout from list, so that timeout move can move
         currently executing timeouts. Instead mark that the timeout must
         be removed from timeout list after execution has finished. */
      to = tmgr->timeout_list;
      to->remove_from_list = 1;

      /* Store running timeout and executing CPU. */
      SSH_ASSERT(tmgr->running_timeout == NULL);
      SSH_ASSERT(tmgr->running_timeout_cpu == 0xBAD0);
      tmgr->running_timeout = to;
      tmgr->running_timeout_cpu = smp_processor_id();

      SSH_DEBUG(SSH_D_MIDOK,
                ("Executing timeout %p expires %lu current jiffies %lu",
                 to, to->expires, jiffies));

      /* Unlock before executing the timeout. `tmgr->running_timeout'
         protects the timeout from disappearing while it is executed. */
      ssh_kernel_mutex_unlock(tmgr->timeout_lock);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that cpu is executing an engine call. */
      SSH_ASSERT(cpu_ctx->in_engine == 0);
      cpu_ctx->in_engine = 1;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

      /* Execute timeout callback. */
      to->callback(to->context);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
      /* Mark that engine call has completed. */
      SSH_ASSERT(cpu_ctx->in_engine == 1);
      cpu_ctx->in_engine = 0;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

      ssh_kernel_mutex_lock(tmgr->timeout_lock);

      /* Clear running timeout pointer. */
      tmgr->running_timeout = NULL;
      tmgr->running_timeout_cpu = 0xBAD0;

      SSH_DEBUG(SSH_D_MIDOK,
                ("Timeout %p execution finished current jiffies %lu",
                 to, (unsigned long) jiffies));

      SSH_LINUX_STATISTICS(interceptor,
                           { interceptor->stats.num_timeout_run++; });

#ifdef DEBUG_LIGHT
      timeouts_executed++;
#endif /* DEBUG_LIGHT */

      /* Remove the timeout from timeout list unless it was moved while
         under execution. */
      if (to->remove_from_list == 1)
        {
          if (to->prev != NULL)
            {
              to->prev->next = to->next;
            }
          else
            {
              SSH_ASSERT(tmgr->timeout_list == to);
              tmgr->timeout_list = to->next;
            }

          if (to->next != NULL)
            {
              to->next->prev = to->prev;
            }
          else
            {
              SSH_ASSERT(tmgr->timeout_list_tail == to);
              tmgr->timeout_list_tail = to->prev;
            }

          /* Return the timeout back to freelist. */
          ssh_kernel_timeout_freelist_put(tmgr, to);
        }

      /* Continue to check if more timeouts need to be executed. */
      goto execute_next;
    }
  ssh_kernel_mutex_assert_is_locked(tmgr->timeout_lock);

  /* All firing timeouts have been executed. Check if need to reschedule
     system timer. */
  if (tmgr->pending_cancels == 0)
    ssh_kernel_timeout_reschedule_timer(tmgr);
  else
    tmgr->must_reschedule = 1;










  ssh_kernel_mutex_unlock(tmgr->timeout_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("Timeouts executed %d total duration %lu jiffies",
                          timeouts_executed,
                          (unsigned long) (jiffies - timeout_start_jiffies)));

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Process queued packets. */
  SSH_DEBUG(SSH_D_LOWOK, ("Processing packet queue"));
  interceptor_packet_queue_process(interceptor, cpu_ctx, FALSE);
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */




}

void
ssh_kernel_timeout_register(SshUInt32 seconds,
                            SshUInt32 useconds,
                            SshKernelTimeoutCallback callback,
                            void *context)
{
  SshInterceptor interceptor = ssh_interceptor_context;
  SshTimeoutManager tmgr = &interceptor->timeouts;
  SshKernelTimeout to, list;
  Boolean reschedule = FALSE;
  unsigned long expires;
#ifdef DEBUG_LIGHT
  SshUInt32 list_length = 0;
#endif /* DEBUG_LIGHT */
  struct timeval tv;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(tmgr != NULL);

  /* Sanity check requested timeout interval */
  if ((seconds + useconds) == 0)
    ssh_warning("Registering zero-length timeout!");

  /* Grab the lock before computing expiry time. Otherwise we would
     compute the absolute expiry time first and then might end up waiting
     for the timeout_lock, which could potentially cause trouble. */
  local_bh_disable();
  ssh_kernel_mutex_lock(tmgr->timeout_lock);

  /* Calculate expiry relative to current time in jiffies. This will take
     care of jiffies overflow by limiting the maximum timeout interval. */
  tv.tv_sec = seconds;
  tv.tv_usec = useconds;
  expires = jiffies + timeval_to_jiffies(&tv);

  /* If the expiry time is now, adjust it a bit to the future. */
  if (time_before_eq(expires, jiffies))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Timeout expiry %lu is in the current moment, "
                 "setting expiry to %lu",
                 (unsigned long) expires, (unsigned long) jiffies + 1));
      expires = jiffies + 1;
    }

  /* Check if timeout delay was truncated to maximum timer delay. */
  jiffies_to_timeval(expires - jiffies, &tv);
  if (tv.tv_sec < seconds
      || (tv.tv_sec == seconds && tv.tv_usec < useconds))
    ssh_warning("Requested timeout delay %lu.%06lus is too large, "
                "timeout delay was truncated to %lu.%06lus",
                (unsigned long) seconds,
                (unsigned long) useconds,
                (unsigned long) tv.tv_sec,
                (unsigned long) tv.tv_usec);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registering timeout to %lu.%06lus (%lu.%06lus) expires %lu "
             "callback %p context %p current jiffies %lu",
             (unsigned long) tv.tv_sec, (unsigned long) tv.tv_usec,
             (unsigned long) seconds, (unsigned long) useconds,
             (unsigned long) expires,
             callback, context,
             (unsigned long) jiffies));

  /* Allocate and initialize a timeout. */
  to = ssh_kernel_timeout_freelist_get(&interceptor->timeouts);
  if (to == NULL)
    ssh_fatal("Could not allocate timeout!");

  to->callback = callback;
  to->context = context;
  to->expires = expires;
  to->remove_from_list = 0;

  /* Insert to the timeout list. */
  if (unlikely(tmgr->timeout_list == NULL))
    {
      /* Inserting to empty timeout list, need to reschedule system timer.  */
      reschedule = TRUE;

      SSH_ASSERT(tmgr->timeout_list_tail == NULL);
      tmgr->timeout_list = to;
      tmgr->timeout_list_tail = to;

      to->next = NULL;
      to->prev = NULL;

      SSH_DEBUG(SSH_D_LOWOK, ("Inserted timeout %p to empty timeout list",
                              to));
    }
  else
    {
      /* We are inserting somewhere in the middle of existing list. Look
         for the place starting from timeout list tail. */
      for (list = tmgr->timeout_list_tail; list != NULL; list = list->prev)
        {
          /* Insert timeout after this timeout list node. */
          if (time_before_eq(list->expires, expires))
            {
              /* Found the place. */
              if (list->next != NULL)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Inserted timeout %p into middle of timeout list",
                             to));
                  list->next->prev = to;
                  to->next = list->next;
                }
              else
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Inserted timeout %p into tail of timeout list",
                             to));
                  /* This case handles the timeout_list tail. */
                  tmgr->timeout_list_tail = to;
                  to->next = NULL;
                }

              to->prev = list;
              list->next = to;
              break;
            }

          /* Start of list, add to head of timeout list. Need to reschedule
             system timer. */
          else if (list->prev == NULL)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Inserted timeout %p into head of timeout list",
                         to));
              SSH_ASSERT(time_after(list->expires, expires));
              list->prev = to;
              to->next = list;
              to->prev = NULL;
              tmgr->timeout_list = to;
              reschedule = TRUE;
              break;
            }

#ifdef DEBUG_LIGHT
          else
            list_length++;
#endif /* DEBUG_LIGHT */
        }

      SSH_ASSERT(list != NULL);
    }

#ifdef DEBUG_LIGHT
  /* Warn if there were too many timers with larger or equal expiry
     in the timeout list. */
  if (list_length > SSH_KERNEL_TIMEOUT_FREELIST_LENGTH)
    SSH_DEBUG(SSH_D_FAIL, ("Registered timeout at %dth node in timeout list!",
                           list_length));
#endif /* DEBUG_LIGHT */

  /* Check if need to reschedule system timer. */
  if (reschedule == TRUE && tmgr->running_timeout == NULL)
    {
      if (tmgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(tmgr);
      else
        tmgr->must_reschedule = 1;
    }










  ssh_kernel_mutex_unlock(tmgr->timeout_lock);
  local_bh_enable();
}

void
ssh_kernel_timeout_cancel(SshKernelTimeoutCallback callback,
                          void *context)
{
  SshInterceptor interceptor = ssh_interceptor_context;
  SshTimeoutManager tmgr = &interceptor->timeouts;
  unsigned int cpu;
#ifdef DEBUG_LIGHT
  SshUInt32 list_length = 0;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(tmgr != NULL);
  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Cancelling timeout with callback %p and with context %p.",
             callback, context));

  local_bh_disable();
  ssh_kernel_mutex_lock(tmgr->timeout_lock);

  tmgr->pending_cancels++;

 retry:
  cpu = smp_processor_id();

  if (tmgr->running_timeout &&
      (tmgr->running_timeout->context == context ||
       context == SSH_KERNEL_ALL_CONTEXTS) &&
      (tmgr->running_timeout->callback == callback ||
       callback == SSH_KERNEL_ALL_CALLBACKS) &&
      tmgr->running_timeout_cpu == cpu)
    {
      ssh_fatal("Attempt to cancel timeout (callback %p context %p) on the "
                "same CPU %d where the callback is executing.",
                context, callback, cpu);
    }
  else if (tmgr->running_timeout &&
           (tmgr->running_timeout->context == context ||
            context == SSH_KERNEL_ALL_CONTEXTS) &&
           (tmgr->running_timeout->callback == callback ||
            callback == SSH_KERNEL_ALL_CALLBACKS) &&
           tmgr->running_timeout_cpu != cpu)
    {
      /* We are cancelling the same callback which is on execution on
         other CPU. Wait for it to finish and cancel it only after
         that. */
      ssh_kernel_mutex_unlock(tmgr->timeout_lock);



      local_bh_enable();

      /* Unfortunate busy loop, we cannot use any sleeping functions, since
         we may be in soft-irq. Note that this loop causes a deadlock if the
         caller of ssh_kernel_timeout_cancel() has a lock taken that the
         running timeout is attempting to acquire. Therefore calling
         ssh_kernel_timeout_cancel() must always be done without having any
         common lock taken. */
      local_bh_disable();
      ssh_kernel_mutex_lock(tmgr->timeout_lock);
      goto retry;
    }
  else
    {
      SshKernelTimeout first, to, prev = NULL;

      to = first = tmgr->timeout_list;

      while (to)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Comparing timeout %p callback %p<->%p and "
                     "context %p<->%p.",
                     to, to->callback, callback, to->context, context));

          if ((to->callback == callback) ||
              (callback == SSH_KERNEL_ALL_CALLBACKS))
            {
              if ((to->context == context) ||
                  (context == SSH_KERNEL_ALL_CONTEXTS))
                {
                  SSH_ASSERT(tmgr->running_timeout != to);

                  SSH_LINUX_STATISTICS(interceptor,
                        { interceptor->stats.num_timeout_cancelled++; });

                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Cancelled timeout %p with callback %p and "
                             "context %p",
                             to, to->callback, to->context));

                  /* Remove from the list. */
                  if (to == tmgr->timeout_list)
                    {
                      /* Remove from the head of the list. */
                      tmgr->timeout_list = to->next;
                      if (tmgr->timeout_list != NULL)
                        {
                          tmgr->timeout_list->prev = NULL;
                        }
                      else
                        {
                          SSH_ASSERT(tmgr->timeout_list_tail == to);
                          tmgr->timeout_list_tail = NULL;
                        }

                      ssh_kernel_timeout_freelist_put(tmgr, to);

                      to = tmgr->timeout_list;
                      continue;
                    }
                  else
                    {
                      /* Remove from the middle of the list. */
                      SSH_ASSERT(prev != NULL);
                      if (to->next != NULL)
                        {
                          to->next->prev = prev;
                        }
                      else
                        {
                          SSH_ASSERT(tmgr->timeout_list_tail == to);
                          tmgr->timeout_list_tail = prev;
                        }
                      prev->next = to->next;

                      ssh_kernel_timeout_freelist_put(tmgr, to);

                      to = prev->next;
                      continue;
                    }

                  SSH_NOTREACHED;
                }
            }

          prev = to;
          to = to->next;
#ifdef DEBUG_LIGHT
          list_length++;
#endif /* DEBUG_LIGHT */
        }

#ifdef DEBUG_LIGHT
      /* Warn if there were too many timers with smaller or equal expiry
         in the timeout list. */
      if (list_length > SSH_KERNEL_TIMEOUT_FREELIST_LENGTH)
        SSH_DEBUG(SSH_D_FAIL,
                  ("Traversed %d nodes in timeout list when canceling "
                   "timeout!",
                   list_length));
#endif /* DEBUG_LIGHT */

      /* Ready to go. Just nuke all the timeouts which need to go. */
      tmgr->pending_cancels--;
      if (tmgr->pending_cancels == 0 &&
          tmgr->running_timeout == NULL &&
          ((tmgr->must_reschedule == 1) ||
           first != tmgr->timeout_list))
        {
          ssh_kernel_timeout_reschedule_timer(tmgr);
          tmgr->must_reschedule = 0;
        }
    }










  ssh_kernel_mutex_unlock(tmgr->timeout_lock);
  local_bh_enable();
}

Boolean ssh_kernel_timeout_move(SshUInt32 seconds, SshUInt32 useconds,
                                SshKernelTimeoutCallback callback,
                                void *context)
{
  SshInterceptor interceptor = ssh_interceptor_context;
  SshTimeoutManager tmgr = &interceptor->timeouts;
  SshKernelTimeout to, moved_to, insert_before_to;
  Boolean reschedule;
  unsigned long expires;
  struct timeval tv;

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

  /* Grab the lock before computing expiry time. Otherwise we would
     compute the absolute expiry time first and then might end up waiting
     for the timeout_lock, which could potentially cause trouble. */
  local_bh_disable();
  ssh_kernel_mutex_lock(tmgr->timeout_lock);

  /* Calculate new expiry time in jiffies. This will take care of jiffies
     overflow by limiting the maximum timeout interval. */
  tv.tv_sec = seconds;
  tv.tv_usec = useconds;
  expires = jiffies + timeval_to_jiffies(&tv);

  /* If the expiry time is now, adjust it a bit to the future. */
  if (expires == jiffies)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Timeout expiry %lu is in the past: jiffies %lu",
                 expires, jiffies));
      expires = jiffies + 1;
    }

  /* Check if timeout delay was truncated to maximum timer delay. */
  jiffies_to_timeval(expires - jiffies, &tv);
  if (tv.tv_sec < seconds
      || (tv.tv_sec == seconds && tv.tv_usec < useconds))
    ssh_warning("Requested timeout delay %lu.%06lus is too large, "
                "timeout delay was truncated to %lu.%06lus",
                (unsigned long) seconds,
                (unsigned long) useconds,
                (unsigned long) tv.tv_sec,
                (unsigned long) tv.tv_usec);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Moving timeout callback %p context %p to %lu.%06lu "
             "(%lu.%06lus) expires %lu current jiffies %lu",
             callback, context,
             (unsigned long) tv.tv_sec, (unsigned long) tv.tv_usec,
             (unsigned long) seconds, (unsigned long) useconds,
             (unsigned long) expires,
             (unsigned long) jiffies));

  /* Lookup timeout from list and scan for the correct position where
     the timeout should be re-inserted.*/
  moved_to = NULL;
  insert_before_to = NULL;
  for (to = tmgr->timeout_list; to != NULL; to = to->next)
    {
      /* Check if timeout matches the parameters */
      if (moved_to == NULL
          && to->callback == callback
          && to->context == context)
        moved_to = to;

      /* No match, check if this is the position were the timeout
         should be moved to. */
      else if (insert_before_to == NULL && time_after(to->expires, expires))
        insert_before_to = to;

      /* Found both the first matching timeout and the point where
         it is moved. */
      if (moved_to != NULL && insert_before_to != NULL)
        break;
    }

  /* No matching timeout was found, all done. */
  if (moved_to == NULL)
    {
      ssh_kernel_mutex_unlock(tmgr->timeout_lock);
      local_bh_enable();
      SSH_DEBUG(SSH_D_LOWOK, ("No timeout found for callback %p context %p",
                              callback, context));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching timeout %p expires %lu",
                          moved_to, (unsigned long) moved_to->expires));

  /* Remove matching timeout from list. */
  reschedule = FALSE;
  if (moved_to->prev != NULL)
    {
      moved_to->prev->next = moved_to->next;
    }
  else
    {
      SSH_ASSERT(tmgr->timeout_list == moved_to);
      tmgr->timeout_list = moved_to->next;

      /* Timeout was removed from timeout list head,
         need to reschedule system timer. */
      reschedule = TRUE;
    }

  if (moved_to->next != NULL)
    {
      moved_to->next->prev = moved_to->prev;
    }
  else
    {
      SSH_ASSERT(tmgr->timeout_list_tail == moved_to);
      tmgr->timeout_list_tail = moved_to->prev;
    }

  /* Assert that timeout list head and tail pointers are sane after
     timeout removal. */
  SSH_ASSERT((tmgr->timeout_list == NULL
              && tmgr->timeout_list_tail == NULL)
             || (tmgr->timeout_list != NULL
                 && tmgr->timeout_list_tail != NULL));
  SSH_ASSERT(tmgr->timeout_list == NULL
             || tmgr->timeout_list->prev == NULL);
  SSH_ASSERT(tmgr->timeout_list_tail == NULL
             || tmgr->timeout_list_tail->next == NULL);

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
      SSH_ASSERT(tmgr->running_timeout == moved_to);
      moved_to->remove_from_list = 0;
    }

  /* Insert the timeout to head or middle of the non-empty timeout list. */
  if (insert_before_to != NULL)
    {
      SSH_ASSERT(time_before(moved_to->expires, insert_before_to->expires));
      moved_to->next = insert_before_to;
      if (insert_before_to->prev != NULL)
        {
          insert_before_to->prev->next = moved_to;
          SSH_DEBUG(SSH_D_LOWOK, ("Moved timeout %p to middle of timeout list",
                                  moved_to));
        }
      else
        {
          SSH_ASSERT(tmgr->timeout_list == insert_before_to);
          tmgr->timeout_list = moved_to;

          /* Inserted into the timeout list head, need to
             reschedule system timer. */
          reschedule = TRUE;
          SSH_DEBUG(SSH_D_LOWOK, ("Moved timeout %p to head of timeout list",
                                  moved_to));
        }
      moved_to->prev = insert_before_to->prev;
      insert_before_to->prev = moved_to;
    }

  /* Insert the timeout into empty timeout list. */
  else if (tmgr->timeout_list == NULL)
    {
      SSH_ASSERT(tmgr->timeout_list_tail == NULL);
      moved_to->next = NULL;
      moved_to->prev = NULL;
      tmgr->timeout_list = moved_to;
      tmgr->timeout_list_tail = moved_to;

      /* Inserted into the head of empty timeout list,
         need to reschedule system timer. */
      reschedule = TRUE;
      SSH_DEBUG(SSH_D_LOWOK, ("Moved timeout %p to empty timeout list",
                              moved_to));
    }

  /* Insert to tail of non-empty timeout list. */
  else
    {
      SSH_ASSERT(tmgr->timeout_list_tail != NULL);
      SSH_ASSERT(time_before_eq(tmgr->timeout_list_tail->expires,
                                moved_to->expires));
      moved_to->next = NULL;
      moved_to->prev = tmgr->timeout_list_tail;
      tmgr->timeout_list_tail->next = moved_to;
      tmgr->timeout_list_tail = moved_to;
      SSH_DEBUG(SSH_D_LOWOK, ("Moved timeout %p to tail of timeout list",
                              moved_to));
    }

  /* Check if need to reschedule system timer. */
  if (reschedule == TRUE && tmgr->running_timeout == NULL)
    {
      if (tmgr->pending_cancels == 0)
        ssh_kernel_timeout_reschedule_timer(tmgr);
      else
        tmgr->must_reschedule = 1;
    }










  ssh_kernel_mutex_unlock(tmgr->timeout_lock);
  local_bh_enable();

  return TRUE;
}
