/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation for SshTask object that
   is utilized to execute specified task procedures in multi-tasking
   environments.

             Execution states of SshTask object:
             -----------------------------------

                                   +-------------+
                                   |   HALTED    |<---+
                                   +-------------+    |
                                       A    |         |
                                       |    |         |
                                       |    V         |
                                   +-------------+    |
                                   |INITIALIZING |    |
                                   +-------------+    |
                                         |            |
                                         |            |
                                         V            |
               +-------------+     +-------------+    |
               |   PAUSING   |---->|   PAUSED    |----+
               +-------------+     +-------------+
                        A              A    |
                        |              |    |
                        |              |    V
               +=============+     +------------+
               |   RUNNING   |<----| RESTARTING |
               +=============+     +------------+
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "engine_alloc.h"
#include "task.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE "SshInterceptorTask"

/*-------------------------------------------------------------------------
  EXTERNALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  GLOBALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

/* This function is executed in a task context */  
KSTART_ROUTINE ssh_task_run;

/* Adjusts the task priority */
static void 
ssh_task_set_priority(SshTask task);

#ifdef DEBUG_LIGHT
const unsigned char *
ssh_task_state_str_get(SshTaskState state)
{
  switch (state)
    {
    case SSH_TASK_STATE_HALTED:
      return (const unsigned char *)"HALTED";

    case SSH_TASK_STATE_INITIALIZING:
      return (const unsigned char *)"INITIALIZING";

    case SSH_TASK_STATE_RESTARTING:
      return (const unsigned char *)"RESTARTING";

    case SSH_TASK_STATE_RUNNING:
      return (const unsigned char *)"RUNNING";

    case SSH_TASK_STATE_PAUSING:
      return (const unsigned char *)"PAUSING";

    case SSH_TASK_STATE_PAUSED:
      return (const unsigned char *)"PAUSED";

    default:
      SSH_NOTREACHED;
      return (const unsigned char *)"<Invalid state>";
    }
}

/* Render function to render task identifier and state for %@ format 
   string for ssh_e*printf */
int 
ssh_task_id_st_render(unsigned char *buf, 
                      int buf_size, 
                      int precision,
                      void *datum)
{
  SshTask task = (SshTask)datum;
  const unsigned char *state_str;
  int len;

  state_str = ssh_task_state_str_get(task->state);

  ssh_snprintf(buf, buf_size + 1, "0x%p (id=%u, suspend_count=%u) [%s]", 
               task, task->id, task->suspend_count, state_str);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}
#endif /* DEBUG_LIGHT */



/*-------------------------------------------------------------------------
  INLINE FUNCTIONS
  -------------------------------------------------------------------------*/

__forceinline void
ssh_task_state_transition(SshTask task,
                          SshTaskState from_state,
                          SshTaskState to_state)
{
  SshTaskState old_state;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Task %@ entering state: %s...",
             ssh_task_id_st_render, task,
             ssh_task_state_str_get(to_state)));

  SSH_ASSERT(sizeof(task->state) == sizeof(to_state));
  old_state = InterlockedExchange((LONG *)&task->state, 
                                  (LONG)to_state);
  SSH_ASSERT(old_state == from_state);

  if (task->tcb.state_change_cb != NULL_FNPTR)
    {
      (*(task->tcb.state_change_cb))(task,
                                     to_state,
                                     task->tcb.state_change_context);
    }
}


/*-------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  -------------------------------------------------------------------------*/

Boolean
ssh_task_init(SshTask task,
              unsigned int task_id,
              SshTaskMethod task_cb,
              void *context,
              SshTCB tcb)
{
  OBJECT_ATTRIBUTES attributes;
  NTSTATUS nt_status = STATUS_SUCCESS;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Initializing task 0x%p (%u)", task, task_id));

  /* Init task attributes */
  memset(task, 0, sizeof(*task));
  task->state = SSH_TASK_STATE_HALTED;
  task->id = task_id;
  task->task_cb = task_cb;
  task->context = context;
  task->tcb = *tcb;

  ssh_task_state_transition(task,
                            SSH_TASK_STATE_HALTED, 
                            SSH_TASK_STATE_INITIALIZING);

  ssh_kernel_mutex_init(&task->lock);

  /* Create and register signal event */
  task->signal_evt = ssh_event_create(~0UL, NULL, NULL);
  if (!task->signal_evt)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Task %@: Failed to create signal event!",
                ssh_task_id_st_render, task));
      goto failed;
    }

  if (!ssh_task_register_event(task, task->signal_evt))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Task %@: Failed to register signal event!",
                ssh_task_id_st_render, task));
      goto failed;
    }

  /* Create worker thread (notice that specified task_cb won't be
     called before ssh_task_start() has been called) */
  InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

  /* Try to create system thread */
  nt_status = PsCreateSystemThread(&task->handle, 
                                THREAD_ALL_ACCESS,
                                &attributes, NULL, NULL,
                                ssh_task_run, 
                                task);
  if (!NT_SUCCESS(nt_status))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Task %@: Failed to create thread (error=0x%08X)", 
                ssh_task_id_st_render, task, nt_status));
      task->handle = NULL;
    }

  if (task->handle == NULL)
    goto failed;

  /* Wait until task enters PAUSED state. */
  while (InterlockedCompareExchange((LONG *)&task->state,
                            SSH_TASK_STATE_PAUSED,
                            SSH_TASK_STATE_PAUSED) != SSH_TASK_STATE_PAUSED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Task %@: Waiting for worker thread to enter "
                 "PAUSED state...",
                 ssh_task_id_st_render, task));
      NdisMSleep(10000);
    }

  SSH_DEBUG(SSH_D_HIGHOK, 
            ("Task %@ successfully initialized.", 
            ssh_task_id_st_render, task));

  return TRUE;

 failed:
  SSH_DEBUG(SSH_D_FAIL, 
            ("Task %@: Failed to initialize!", 
            ssh_task_id_st_render, task));

  ssh_task_state_transition(task,
                            SSH_TASK_STATE_INITIALIZING, 
                            SSH_TASK_STATE_HALTED);

  ssh_task_uninit(task);

  return FALSE;
}

void 
ssh_task_uninit(SshTask task)
{
  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT((task->state == SSH_TASK_STATE_PAUSED)
             || (task->state == SSH_TASK_STATE_HALTED));

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Task %@: uninitializing...",
            ssh_task_id_st_render, task));

  /* We will most probably cause a memory/resource leak if we destroy 
     a suspended task. */
  SSH_ASSERT(task->suspend_count == 0);

  /* Terminate thread */
  if (task->handle != NULL)
    {
      PKTHREAD thread = NULL;
      NTSTATUS status = STATUS_SUCCESS;

      /* Get the thread object using the handle */
      status = ObReferenceObjectByHandle(task->handle,
                                         THREAD_ALL_ACCESS, 
                                         NULL, 
                                         KernelMode,
                                         &thread, 
                                         NULL);

      if (NT_SUCCESS(status) && thread)
        {
          /* Release thread handle */
          ZwClose(task->handle);
          task->handle = NULL;

          ssh_task_notify(task, SSH_TASK_SIGNAL_EXIT);

          /* Wait until thread is terminated */
          status = KeWaitForSingleObject(thread, 
                                         Executive, 
                                         KernelMode, 
                                         FALSE,
                                         NULL);

          /* Dereference thread object */
          ObDereferenceObject(thread);
        }
    }

  SSH_ASSERT(task->state == SSH_TASK_STATE_HALTED);

  ssh_kernel_mutex_uninit(&task->lock);

  if (task->signal_evt)
    ssh_event_destroy(task->signal_evt);

  ssh_free(task->event);
}

void 
ssh_task_start(SshTask task)
{
  SSH_ASSERT(task != NULL);
  SSH_ASSERT(task->state == SSH_TASK_STATE_PAUSED);

  ssh_task_notify(task, SSH_TASK_SIGNAL_START);
}

void
ssh_task_stop(SshTask task)
{
  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(task != NULL);

  ssh_task_notify(task, SSH_TASK_SIGNAL_STOP);

  while (InterlockedCompareExchange(
                   (LONG *)&task->state,
                   SSH_TASK_STATE_PAUSED,
                   SSH_TASK_STATE_PAUSED) != SSH_TASK_STATE_PAUSED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Task %@: Waiting for task to enter PAUSED state...", 
                 ssh_task_id_st_render, task));

      NdisMSleep(10000);
    }
}

Boolean
ssh_task_suspend(SshTask task,
                 SshUInt32 timeout_sec)
{
  ULONG suspend_count;

  SSH_ASSERT(task != NULL);

  suspend_count = InterlockedIncrement(&task->suspend_count);

  if (suspend_count == 1)
    {
      SshUInt64 tick_count;
      SSH_IRQL irql = SSH_GET_IRQL();

      SSH_DEBUG(SSH_D_MIDSTART, 
                ("Task %@: Suspending task...", 
                ssh_task_id_st_render, task));

      if (timeout_sec == 0)
        timeout_sec = SSH_TASK_WAIT_INFINITE;

      if (irql >= SSH_DISPATCH_LEVEL)
        {
          /* Maximum number of 20us ticks to wait */
          tick_count = (SshUInt64)60 * 50000;
        }
      else
        {
          /* Maximum number of 10ms ticks to wait */
          tick_count = (SshUInt64)60 * 100;
        }

      /* Wait until task suspends */
      while (InterlockedCompareExchange(&task->executing_cb, 0, 0) != 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Task %@: Waiting for task to stop...", 
                    ssh_task_id_st_render, task));

          if (irql >= SSH_DISPATCH_LEVEL)
            {
              SSH_ASSERT(ssh_kernel_num_cpus() > 1);

              if (ssh_kernel_num_cpus() == 1)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Task %@: Can't wait on raised IRQL on "
                             "uniprocessor platform!",
                             ssh_task_id_st_render, task));

                  return FALSE;
                }
              else
                {
                  NdisStallExecution(20);
                }
            }
          else
            {
              NdisMSleep(10000);
            }
  
          tick_count--;

          if (tick_count == 0)
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Task %@: Did not stop execution before %u second "
                         "timeout occurred!", 
                        ssh_task_id_st_render, task, timeout_sec));

              return FALSE;
            }
        };
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART, 
                ("Task %@: Incremented suspend_count", 
                ssh_task_id_st_render, task));
    }

  return TRUE;
}


void
ssh_task_resume(SshTask task)
{
  ULONG suspend_count;

  SSH_ASSERT(task != NULL);
  SSH_ASSERT(InterlockedCompareExchange(&task->suspend_count, 0, 0) != 0);

  suspend_count = InterlockedDecrement(&task->suspend_count);

  if (suspend_count == 0)
    {
      SSH_DEBUG(SSH_D_MIDSTART, 
                ("Task %@: Resuming task", 
                ssh_task_id_st_render, task));

      ssh_task_notify(task, SSH_TASK_SIGNAL_NOTIFY);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART, 
                ("Task %@: Decremented suspend_count", 
                ssh_task_id_st_render, task));
    }
}


/*-------------------------------------------------------------------------
  Notifies task routine of specific 'signal' events.
  -------------------------------------------------------------------------*/
void __fastcall  
ssh_task_notify(SshTask task, 
                SshTaskSignal signal)
{
  SSH_ASSERT(task != NULL);

  /* Set the associated bit in the mask */
  ssh_kernel_mutex_lock(&task->lock);
  task->signal |= signal;
  ssh_kernel_mutex_unlock(&task->lock);

  /* Fire signalling event */
  ssh_event_signal(task->signal_evt);
}

/*-------------------------------------------------------------------------
  Registers a new event that should be monitored.
  -------------------------------------------------------------------------*/
Boolean
ssh_task_register_event(SshTask task,
                        SshEvent event)
{
  SshEvent *new_events;

  SSH_DEBUG(SSH_D_FAIL, 
            ("Task %@: Registering event 0x%p...",
            ssh_task_id_st_render, task, event));

  /* Check if max count for events has been exceeded */
  if (task->evt_cnt >= 64)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Task %@: Maximum number of events exceeded!",
                ssh_task_id_st_render, task));

      return FALSE;
    }

  ssh_kernel_mutex_lock(&task->lock);

  /* Insert new task into task array */
  new_events = ssh_realloc(task->event, 
                           (task->evt_cnt * sizeof(SshEvent)),
                           ((task->evt_cnt + 1) * sizeof(SshEvent)));
  if (new_events == NULL)
    {
      ssh_kernel_mutex_unlock(&task->lock);

      SSH_DEBUG(SSH_D_FAIL, 
                ("Task %@: Failed to allocate storage for events!",
                ssh_task_id_st_render, task));

      return FALSE;
    }

  task->event = new_events;
  task->event[task->evt_cnt] = event;
  task->evt_cnt++;

  ssh_kernel_mutex_unlock(&task->lock);

  /* Notify task of changes */
  ssh_task_notify(task, SSH_TASK_SIGNAL_RESET);

  return TRUE;
}

/*-------------------------------------------------------------------------
  Removes previously registered event.
  -------------------------------------------------------------------------*/
Boolean
ssh_task_deregister_event(SshTask task,
                          SshEvent event)
{
  unsigned long i = 0, j = 0;

  SSH_DEBUG(SSH_D_FAIL, 
            ("Task %@: Deregistering event 0x%p...",
            ssh_task_id_st_render, task, event));

  ssh_kernel_mutex_lock(&task->lock);

  /* Search specific event from the list */  
  for (i = 0; i < task->evt_cnt; i++)
    {
      if (task->event[i] == event)
        break;
    }

  /* Check if found */
  if (i != task->evt_cnt)
    {
      /* Remove event from the list */
      for (j = i; j < task->evt_cnt - 1; j++)
        task->event[j] = task->event[j+1];

      /* Decrement event count */
      task->evt_cnt--;
    }

  ssh_kernel_mutex_unlock(&task->lock);

  /* Notify task of changes */
  ssh_task_notify(task, SSH_TASK_SIGNAL_RESET);

  return TRUE;
}

/*-------------------------------------------------------------------------
  LOCAL FUNCTIONS
  -------------------------------------------------------------------------*/

/*------------------------------------------------------------------------
  ssh_task_set_priority()
  
  Sets the priority of given task.

  Arguments:
  task - SshTask object,
  priority - Task priority
  
  Returns:
  Notes:
  ------------------------------------------------------------------------*/
static void
ssh_task_set_priority(SshTask task)
{
  PKTHREAD thread = NULL;
  NTSTATUS status = STATUS_SUCCESS;

  SSH_ASSERT(task != NULL);

  if (task->handle == NULL)
    return;

  /* Get the thread object using the handle */
  status = ObReferenceObjectByHandle(task->handle,
                                     THREAD_ALL_ACCESS, 
                                     NULL, 
                                     KernelMode,
                                     &thread, 
                                     NULL);
  if (NT_SUCCESS(status))
    {
      /* Set priority */
      switch (task->tcb.priority)
        {
        default:
        case SSH_TASK_PRIORITY_NOCHANGE:
          break;

        case SSH_TASK_PRIORITY_NORMAL:
          KeSetPriorityThread(thread, LOW_REALTIME_PRIORITY);
          break;

        case SSH_TASK_PRIORITY_LOW:
          KeSetPriorityThread(thread, LOW_PRIORITY);
          break;

        case SSH_TASK_PRIORITY_HIGH:
          KeSetPriorityThread(thread, HIGH_PRIORITY);
          break;
        }

      /* Release thread reference */
      ObDereferenceObject(thread);
    }
}

/*-------------------------------------------------------------------------
  Executes periodic task.
  -------------------------------------------------------------------------*/
static void
ssh_task_exec_periodic(SshTask task)
{
  SshUInt32 signal;
  LARGE_INTEGER to;

  to.QuadPart = (task->tcb.period_ms * (-10000));

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Task %@: Starting periodic execution...",
            ssh_task_id_st_render, task));

  /* Loop until abort */
  do 
    {
      /* Don't execute task routine if this task is currently suspended */
      if (InterlockedCompareExchange(&task->suspend_count, 0, 0) == 0)
        {
          /* Execute task routine */
          if (task->task_cb)
            {
              InterlockedIncrement(&task->executing_cb);
              task->task_cb(task->context);
              InterlockedDecrement(&task->executing_cb);
            }
        }

      /* Sleep specified time */
      KeDelayExecutionThread(KernelMode, FALSE, &to);
      ssh_kernel_mutex_lock(&task->lock);
      signal = task->signal;
      task->signal &= ~SSH_TASK_SIGNAL_STOP;
      ssh_kernel_mutex_unlock(&task->lock);
    }
  while (!(signal & SSH_TASK_SIGNAL_STOP));
}

/*-------------------------------------------------------------------------
  Executes event listener task.
  -------------------------------------------------------------------------*/
static void
ssh_task_exec_event_monitor(SshTask task)
{
  long evt_cnt = 0;
  SshEvent *event = NULL;
  SshWCBStruct wcb;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Task %@: Starting event monitoring...",
            ssh_task_id_st_render, task));

  /* Loop until abort */
  while (1)
    {
      SshUInt32 signal;

      /* Init event monitoring list */
      ssh_kernel_mutex_lock(&task->lock);
      evt_cnt = task->evt_cnt;
      event = ssh_calloc(evt_cnt, sizeof(SshEvent));
      if (event == NULL)
        {
          ssh_kernel_mutex_unlock(&task->lock);
          break;
        }
      RtlCopyMemory(event, task->event, (evt_cnt * sizeof(SshEvent)));
      ssh_kernel_mutex_unlock(&task->lock);

      /* Init wait control block */
      RtlZeroMemory(&wcb, sizeof(wcb));
      if (task->tcb.period_ms == SSH_TASK_EVENT_WAIT_INFINITE)
        wcb.wait_time_ms = SSH_EVT_WAIT_INFINITE;
      else
        wcb.wait_time_ms = task->tcb.period_ms;
      wcb.mode = SSH_EVT_WAIT_MODE_ANY;

      /* Loop until abort or reset */
      while (1)
        {
          /* Wait event(s) to occur */
          ssh_event_wait((SshUInt8)evt_cnt, event, &wcb);

          /* Restart wait if task is currently suspended */
          if (InterlockedCompareExchange(&task->suspend_count, 0, 0) != 0)
            continue;

          /* Run task callback if requested */
          ssh_kernel_mutex_lock(&task->lock);
          signal = task->signal;
          task->signal &= ~SSH_TASK_SIGNAL_NOTIFY;
          ssh_kernel_mutex_unlock(&task->lock);
          if ((signal & SSH_TASK_SIGNAL_NOTIFY) && task->task_cb)
            {
              InterlockedIncrement(&task->executing_cb);
              task->task_cb(task->context);
              InterlockedDecrement(&task->executing_cb);
            }

          /* Check whether we should terminate event monitoring */
          ssh_kernel_mutex_lock(&task->lock);
          signal = task->signal;
          task->signal &= ~SSH_TASK_SIGNAL_RESET;
          ssh_kernel_mutex_unlock(&task->lock);
          if ((signal & SSH_TASK_SIGNAL_STOP) 
              || (signal & SSH_TASK_SIGNAL_RESET))
            break;
        }

      /* Release resources allocated for event monitoring */
      ssh_free(event);
      ssh_free(wcb.reserved[0]);
      ssh_free(wcb.reserved[1]);
      ssh_free(wcb.reserved[2]);
      ssh_free(wcb.reserved[3]);

      if (signal & SSH_TASK_SIGNAL_STOP)
        break;
    }
}

/*-------------------------------------------------------------------------
  This function is run within task context.
  -------------------------------------------------------------------------*/
static VOID 
ssh_task_run(void *context)
{
  SshTask task = (SshTask)context;

  ssh_task_state_transition(task,
                            SSH_TASK_STATE_INITIALIZING, 
                            SSH_TASK_STATE_PAUSED);

  /* Adjust task priority */
  ssh_task_set_priority(task);

  /* Wait for start or stop signal */
  while (TRUE)
    {
      SshUInt32 signal;

      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Task %@: waiting for START or EXIT signal", 
                ssh_task_id_st_render, task));

      do 
        {
          ssh_event_wait(1, &task->signal_evt, NULL);
          signal = task->signal;
        }
      while ((signal & (SSH_TASK_SIGNAL_START | SSH_TASK_SIGNAL_EXIT)) == 0);

      ssh_kernel_mutex_lock(&task->lock);
      signal = task->signal;
      task->signal &= ~SSH_TASK_SIGNAL_START;
      ssh_kernel_mutex_unlock(&task->lock);

      if (signal & SSH_TASK_SIGNAL_START)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Task %@: received START signal", 
                    ssh_task_id_st_render, task));

          ssh_task_state_transition(task,
                                    SSH_TASK_STATE_PAUSED, 
                                    SSH_TASK_STATE_RESTARTING);

          ssh_task_state_transition(task,
                                    SSH_TASK_STATE_RESTARTING, 
                                    SSH_TASK_STATE_RUNNING);

          /* Run task according to the type */
          switch (task->tcb.exec_type)
            {
            default:
              SSH_NOTREACHED;
              break;

            case SSH_TASK_TYPE_ONCE:
              /* Execute task callback once */
              InterlockedIncrement(&task->executing_cb);
              task->task_cb(task->context);
              InterlockedDecrement(&task->executing_cb);
              break;

            case SSH_TASK_TYPE_PERIODIC:
              /* Execute task callback periodically */
              ssh_task_exec_periodic(task);
              break;

            case SSH_TASK_TYPE_EVENT_MONITOR:
              /* Event monitoring task */
              ssh_task_exec_event_monitor(task);
              break;
            }

          ssh_task_state_transition(task,
                                    SSH_TASK_STATE_RUNNING, 
                                    SSH_TASK_STATE_PAUSING);

          ssh_task_state_transition(task,
                                    SSH_TASK_STATE_PAUSING, 
                                    SSH_TASK_STATE_PAUSED);

          ssh_kernel_mutex_lock(&task->lock);
          signal = task->signal;
          task->signal &= ~SSH_TASK_SIGNAL_STOP;
          ssh_kernel_mutex_unlock(&task->lock);
        }

      if (signal & SSH_TASK_SIGNAL_EXIT)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Task %@: received EXIT signal", 
                    ssh_task_id_st_render, task));
          break;
        }
    };

  ssh_task_state_transition(task,
                            SSH_TASK_STATE_PAUSED, 
                            SSH_TASK_STATE_HALTED);

  /* Terminate system thread */
  PsTerminateSystemThread(STATUS_SUCCESS);
}
