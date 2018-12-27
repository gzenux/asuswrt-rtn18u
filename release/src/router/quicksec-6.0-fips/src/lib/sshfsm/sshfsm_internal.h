/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal data structures for FSM.  Do not include / use this header
   or its data structures directly.  You must use the functions and
   macros defined in the `sshfsm.h' header file to manipulate these
   objects.
*/

#ifndef SSHFSM_INTERNAL_H
#define SSHFSM_INTERNAL_H

#include "sshtimeouts.h"

#ifndef SSHFSM_H
#error "Do not include sshfsm_internal.h, include the sshfsm.h instead"
#endif /* not SSHFSM_H */

/*************************** Internal structures ****************************/

/* The structures are declared here to allow allocation from stack or
   from pre-allocated structures.  You must not modify or refer any of
   the fields directly.  You must use the function and macro API above
   to access and modify FSM objects. */

/* Type definition of a finite state machine object. */
struct SshFSMRec
{
  /* The ring of active threads, ie.e those that can be run. */
  SshFSMThread active;

  /* The ring of threads that are suspended and are waiting for
     external callback, i.e. an externally given
     ssh_fsm_continue(). */
  SshFSMThread waiting_external;

  /* Threads waiting for message handler call. */
  SshFSMThread waiting_message_handler;

  /* Flags. */
  SshUInt32 flags;

  /* FSM flags. */
#define SSH_FSM_IN_SCHEDULER            1  /* Control inside scheduler. */
#define SSH_FSM_SCHEDULER_SCHEDULED     2  /* Scheduler scheduled for running*/
#define SSH_FSM_SCHEDULER_SUSPENDED     4  /* Scheduler suspended */

  /* User-supplied context data. */
  void *context_data;

  /* FSM scheduler and destroy timeout */
  SshTimeoutStruct fsm_timeout;
#ifdef DEBUG_LIGHT
  /* For sanity check in ssh_fsm_destroy(). */
  SshUInt32 num_threads;

  /* Description of states. */
  SshFSMStateDebug states;
  int num_states;
#endif /* DEBUG_LIGHT */
};


/* Thread statuses. */
typedef enum
{
  SSH_FSM_T_ACTIVE,             /* On the active list. */
  SSH_FSM_T_SUSPENDED,          /* On the waiting_external list. */
  SSH_FSM_T_WAITING_CONDITION,  /* On the waiting list of a condition var. */
  SSH_FSM_T_WAITING_THREAD      /* On the waiting list of a thread. */
} SshFSMThreadStatus;

#ifdef DEBUG_LIGHT
#define SSH_FSM_DEBUG 1
#define SSH_FSM_DEBUG_RING_BUFFER_SIZE  32
/* State item structure. This stores information of one step in the fsm
   thread. */
typedef struct SshFSMThreadStateItemRec {
  SshFSMStepCB state_func;
  SshUInt16 status;
} *SshFSMThreadStateItem, SshFSMThreadStateItemStruct;
#endif /* DEBUG_LIGHT */

/* Type definition of a thread object. */
struct SshFSMThreadRec
{
  /* Ring pointers.  The thread belongs always to exactly one ring. */
  struct SshFSMThreadRec *next;
  struct SshFSMThreadRec *prev;

  /* The FSM the thread belongs to. */
  SshFSM fsm;

  /* The current (next) state. */
  SshFSMStepCB current_state;

  /* A pointer to an object the thread is waiting for. */
  union
  {
    /* Waiting for a condition variable. */
    SshFSMCondition condition;

    /* Waiting for a thread to terminate */
    SshFSMThread thread;
  } waited;

  /* The ring of threads waiting for this thread to terminate. */
  SshFSMThread waiting;

  /* Flags */
  SshUInt16 flags;

  /* Thread flags. */
#define SSH_FSM_RUNNING                 1 /* Control inside a step function */
#define SSH_FSM_IN_MESSAGE_QUEUE        2 /* Waiting for message handler call*/
#define SSH_FSM_CALLBACK_FLAG           4
#define SSH_FSM_DYNAMIC_THREAD          8 /* Thread malloc()ated. */
#define SSH_FSM_DONE                   16
#define SSH_FSM_EXISTS                 32

  /* Status of the thread (SshFSMThreadStatus). */
  SshUInt16 status;

  /* Message handler callback. */
  SshFSMMessageHandler message_handler;

  /* Destructor for user-supplied context data. */
  SshFSMDestructor destructor;

  /* The latest message thrown.  This is valid if flags have
     SSH_FSM_IN_MESSAGE_QUEUE. */
  SshUInt32 message;

  /* User-supplied context data. */
  void *context_data;

#ifdef DEBUG_LIGHT
  char *name;
#ifdef SSH_FSM_DEBUG
  int next_in_ring;
  SshFSMThreadStateItemStruct last_states[SSH_FSM_DEBUG_RING_BUFFER_SIZE];
#endif /* SSH_FSM_DEBUG */
#endif /* DEBUG_LIGHT */
};


/* Type definition of a condition variable. */
struct SshFSMConditionRec
{
  /* The ring of threads waiting for this condition variable. */
  SshFSMThread waiting;
};

#endif /* not SSHFSM_INTERNAL_H */
