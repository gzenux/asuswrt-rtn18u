/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the function definitions for SshTask object that is
   utilized to execute specific routines in multi-tasking OS environments.
*/

#ifndef SSH_TASK_H
#define SSH_TASK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "interceptor_i.h"
#include "kernel_mutex.h"
#include "event.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* "Infinite" wait time for event monitor task */
#define SSH_TASK_EVENT_WAIT_INFINITE  -1
#define SSH_TASK_WAIT_INFINITE        -1

/* Task priorities */
typedef enum SshTaskPriorityEnum
{
  SSH_TASK_PRIORITY_NOCHANGE = 0,
  SSH_TASK_PRIORITY_NORMAL,
  SSH_TASK_PRIORITY_LOW,
  SSH_TASK_PRIORITY_HIGH,
  SSH_TASK_PRIORITY_MAX
} SshTaskPriority;

/* Task types */
typedef enum TaskTypeEnum
{
  /* Runs only once */
  SSH_TASK_TYPE_ONCE = 0,

  /* Runs periodically */
  SSH_TASK_TYPE_PERIODIC,

  /* Sleeps until some event occurs and then executes associated callback */ 
  SSH_TASK_TYPE_EVENT_MONITOR
} SshTaskType;

/* Task signal flags */
typedef enum SshTaskSignalEnum
{
  /* Start event */
  SSH_TASK_SIGNAL_START  = 0x00000001,
  /* General purpose notify indication for task routine */
  SSH_TASK_SIGNAL_NOTIFY = 0x00000002,
  /* Reset indication */
  SSH_TASK_SIGNAL_RESET  = 0x00000004,
  /* Stop event */
  SSH_TASK_SIGNAL_STOP   = 0x00000008,
  /* Exit event */
  SSH_TASK_SIGNAL_EXIT   = 0x00000010
} SshTaskSignal;

typedef struct SshTaskRec SshTaskStruct, *SshTask;

/* Task state change events */
typedef enum
{
  SSH_TASK_STATE_HALTED,
  SSH_TASK_STATE_INITIALIZING,
  SSH_TASK_STATE_RUNNING,
  SSH_TASK_STATE_PAUSING,
  SSH_TASK_STATE_RESTARTING,
  SSH_TASK_STATE_PAUSED
} SshTaskState;

/* Optional execution state change callback. This callback function can
   be used e.g. for application level indications or for performing addtional
   tasks needed for state change. */
typedef void (*SshTaskStateChangeCallback)(SshTask task, 
                                           SshTaskState new_state,
                                           void *context);

/* Task Control Block (TCB) descriptor */
typedef struct SshTCBRec 
{
  /* Task priority */
  SshTaskPriority priority;

  /* Task execution type (ONCE, PERIODIC, EVENT_MONITOR) */
  SshTaskType exec_type;

  /* Periodic task execution interval */
  long period_ms;

  /* Optional 'state change' callback. This function will be called 
     whenever task's execution state changes. */
  SshTaskStateChangeCallback state_change_cb;
  void *state_change_context;
} SshTCBStruct, *SshTCB;


/* Function pointer with single input argument */
typedef void (*SshTaskMethod)(void *);

typedef struct SshEventRec SshEventStruct, *SshEvent;

/* SSH Task descriptor */
typedef struct SshTaskRec 
{
  /* For keeping tasks in a list */
  SshTaskState state;

  /* Handle for accessing task object */
  HANDLE handle;       

  /* Task identifier (1...) */
  unsigned long id;

  /* Task suspend count (task can run only when suspend count is zero) */
  LONG suspend_count;

  /* Task callback */
  SshTaskMethod task_cb;
  ULONG executing_cb;  /* Non-zero when 'task_cb' is executing */

  /* Single input argument for task callback */
  void* context;

  /* Signal flag and the related event that is fired when 
     signal mask is changed */
  SshUInt32 signal;
  SshEvent signal_evt;

  /* Event list and it's lock for event monitoring task */
  unsigned long evt_cnt;
  SshKernelMutexStruct lock;
  SshEvent *event;

  /* Task Control Block */
  SshTCBStruct tcb;
};

/*-------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  Initializes a task object. 
  -------------------------------------------------------------------------*/
Boolean
ssh_task_init(SshTask task,
              unsigned int task_id,
              SshTaskMethod task_cb,
              void *context,
              SshTCB tcb);

/*-------------------------------------------------------------------------
  Uninitializes a task object. 
  -------------------------------------------------------------------------*/
void 
ssh_task_uninit(SshTask task);

/*-------------------------------------------------------------------------
  Starts a task. 
  -------------------------------------------------------------------------*/
void
ssh_task_start(SshTask task);

/*-------------------------------------------------------------------------
  Stops a task. 
  -------------------------------------------------------------------------*/
void
ssh_task_stop(SshTask task);

/*-------------------------------------------------------------------------
  ssh_task_suspend()

  Increments the suspend count of a task. If the task is currently running, 
  waits until the task execution callback return and task enters to wait 
  state.

  Arguments:
  task        - SshTask object
  timeout_sec - Maximum number of seconds to wait

  Returns:
  TRUE  - Task succesfully suspended when this function returned.
  FALSE - Task could not be suspended during the specified maximum 
          waiting time or task can't be suspended because 
          ssh_task_suspend() was called at IRQL >= DISPATCH_LEVEL on single 
          core platform (i.e. it's impossible to wait until the execution of
          the task completes).
  ------------------------------------------------------------------------*/
Boolean
ssh_task_suspend(SshTask task,
                 SshUInt32 timeout_sec);

/*-------------------------------------------------------------------------
  ssh_task_resume()

  Decrements the suspend count of a task. The task is resumed if the new 
  value of suspend count is equal to zero.

  Arguments:
  task - SshTask object

  Returns:
  Notes:
  ------------------------------------------------------------------------*/
void
ssh_task_resume(SshTask task);

/*-------------------------------------------------------------------------
  Notifies task routine of specific 'signal' events.
  -------------------------------------------------------------------------*/
void __fastcall 
ssh_task_notify(SshTask task, 
                SshTaskSignal signal);

/*-------------------------------------------------------------------------
  Registers a new event that should be monitored.
  -------------------------------------------------------------------------*/
Boolean
ssh_task_register_event(SshTask task,
                        SshEvent event);

/*-------------------------------------------------------------------------
  Removes previously registered event.
  -------------------------------------------------------------------------*/
Boolean
ssh_task_deregister_event(SshTask task,
                          SshEvent event);

#ifdef __cplusplus
}
#endif

#endif
