/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Finite State Machine abstraction layer.
*/

#ifndef SSHFSM_H
#define SSHFSM_H

/* ************************ Types and definitions ***************************/

/** Type definition of a finite state machine object. */
typedef struct SshFSMRec *SshFSM;

/** Type definition of a finite state machine object. */
typedef struct SshFSMRec SshFSMStruct;

/** Type definition of a thread object. */
typedef struct SshFSMThreadRec *SshFSMThread;

/** Type definition of a thread object. */
typedef struct SshFSMThreadRec SshFSMThreadStruct;

/** Type definition of a condition variable. */
typedef struct SshFSMConditionRec *SshFSMCondition;

/** Type definition of a condition variable. */
typedef struct SshFSMConditionRec SshFSMConditionStruct;

/** These are the allowed return values from a step function.
    All of the values are non-negative. */
typedef enum
{
  /** Continue from the next state immediately without going through
      the event loop.  However, if the state did send some messages
      with ssh_fsm_throw, the message handler functions are run before
      the execution continues from the next state. */
  SSH_FSM_CONTINUE,

  /** Like SSH_FSM_CONTINUE but the thread goes to the end of the list
      of active threads i.e. all other active threads get run first
      before this thread continues. */
  SSH_FSM_YIELD,

  /** End of thread.  No more callbacks will be called for the
      thread. */
  SSH_FSM_FINISH,

  /** Waiting for an async call.  The thread continues when it is wake
      up with the ssh_fsm_continue function. */
  SSH_FSM_SUSPENDED,

  /* These do not need to be returned explicitly. */

  /** Waiting for a condition variable.  This is automatically returned
      by SSH_FSM_CONDITION_WAIT(...) and does not need to be
      explicitly returned by user code. */
  SSH_FSM_WAIT_CONDITION,

  /** Waiting for a thread to terminate.  This is automatically
      returned by SSH_FSM_WAIT_THREAD(...) and does not need to be
      explicitly returned by user code. */
  SSH_FSM_WAIT_THREAD
} SshFSMStepStatus;

/** The type of step functions. */
typedef SshFSMStepStatus (*SshFSMStepCB)(SshFSM fsm,
                                         SshFSMThread thread,
                                         void *thread_context,
                                         void *fsm_context);

/** Function header for a step function. */
#define SSH_FSM_STEP(name)                      \
SshFSMStepStatus name(SshFSM fsm,               \
                      SshFSMThread thread,      \
                      void *thread_context,     \
                      void *fsm_context)

/** Message handler type.  The thread is allowed to call
    ssh_fsm_set_next() and ssh_fsm_continue() functions from the
    message handler. */
typedef void (*SshFSMMessageHandler)(SshFSMThread thread,
                                     SshUInt32 message);

/** Destructor function type.  A callback function of this type is
    called to free thread's context data `context'. */
typedef void (*SshFSMDestructor)(SshFSM fsm, void *context);

/** Description of an FSM state.  This is used in debugging the FSM.
    It is not used unless you specify it for an FSM for debugging
    purposes. */
struct SshFSMStateDebugRec
{
  /** A short label for the state. */
  const char *state_id;

  /** Description of the state. */
  const char *descr;

  /** A function implementing this FSM state. */
  SshFSMStepCB func;
};

typedef struct SshFSMStateDebugRec SshFSMStateDebugStruct;
typedef struct SshFSMStateDebugRec *SshFSMStateDebug;

/** An initializer for an item in the SshFSMStateDebugStruct array. */
#define SSH_FSM_STATE(x,y,z) { x, y, z },

/** Calculate the size of a state debug array. */
#define SSH_FSM_NUM_STATES(array) (sizeof(array)/sizeof(array[0]))

#include "sshfsm_internal.h"


/* ********************* Creating and destroying FSMs ***********************/

/** Create a new finite state machine.  The function returns NULL if
    the FSM creation fails. This function performs memory allocation and
    initialization of the FSM object. */
SshFSM ssh_fsm_create(void *context);

/** Initialize a new finite state machine object into memory are
    allocated by caller.  This call does not perform dynamic memory
    allocations  */
void ssh_fsm_init(SshFSM fsm, void *context);

/** Destroy the FSM when next reaching the event loop.  This checks
    that there are no active threads when deleting the FSM. This frees the
    FSM object, thus it expects it to be dynamically allocated. */
void ssh_fsm_destroy(SshFSM fsm);

/** Uninit the FSM.  The FSM must not have any threads running. This
    does not free the FSM object. */
void ssh_fsm_uninit(SshFSM fsm);

/** Register state names and descriptions for debugging purposes.  If
    the state array is registered and the debugging is enabled, the FSM
    will print debugging information when it executes the state
    machine.  This have effect only if DEBUG_LIGHT is defined. */
void ssh_fsm_register_debug_names(SshFSM fsm, const SshFSMStateDebug states,
                                  int num_states);


/* ************************** Thread operations *****************************/

/** Create a new thread.  The `fsm' is the state machine the thread
    will run on.  The argument `first_state' is the state where the
    thread starts from.  The argument `message_handler' is the message
    handling function.  The function returns a thread handle or NULL if
    the thread creation failed. */
SshFSMThread ssh_fsm_thread_create(SshFSM fsm,
                                   SshFSMStepCB first_state,
                                   SshFSMMessageHandler message_handler,
                                   SshFSMDestructor destructor,
                                   void *context);

/** Initialize a new thread for the FSM 'fsm'.  The function is like
    ssh_fsm_thread_create() but the thread context is already
    allocated by the caller. */
void ssh_fsm_thread_init(SshFSM fsm,
                         SshFSMThread thread,
                         SshFSMStepCB first_state,
                         SshFSMMessageHandler message_handler,
                         SshFSMDestructor destructor,
                         void *context);

/** Set the next state. */
void ssh_fsm_set_next(SshFSMThread thread, SshFSMStepCB next_state);

/** Get current/next state. */
SshFSMStepCB ssh_fsm_get_thread_current_state(SshFSMThread);

/** Set the next state. */
#define SSH_FSM_SET_NEXT(n) ssh_fsm_set_next(thread, n)

/** Wake up a thread from an external callback or from condition
    variable wait. */
void ssh_fsm_continue(SshFSMThread thread);

/** Kill a thread that was suspended. Calling this function is legal
    only if it can be guaranteed that the thread won't get any
    ssh_fsm_continue calls after this; that is, that the thread was not
    waiting for an external callback that couldn't be cancelled.

    If the thread `thread' was waiting for a condition variable, then
    the thread is automatically removed from the variable's waiting
    list. */
void ssh_fsm_kill_thread(SshFSMThread thread);

/** Like ssh_fsm_kill_thread() but does not free thread i.e. assumes
    external allocation and initialisation by ssh_fsm_thread_init().
*/
void ssh_fsm_uninit_thread(SshFSMThread thread);

/** Wait until the thread 'waited' has been terminated.  When the
    thread 'waited' terminates, all waiting threads will become active.
    Do not call this function directly, prefer the macro below. */
void ssh_fsm_wait_thread(SshFSMThread thread, SshFSMThread waited);

/** Wait for a thread to die. */
#define SSH_FSM_WAIT_THREAD(waited)             \
do                                              \
  {                                             \
    ssh_fsm_wait_thread(thread, (waited));      \
    return SSH_FSM_WAIT_THREAD;                 \
  }                                             \
while (0)

/** Set the debugging name for thread 'thread'. */
void ssh_fsm_set_thread_name(SshFSMThread thread, const char *name);

/** Get the debugging name of the thread `thread'.  This works only if
    DEBUG_LIGHT is defined.  If the DEBUG_LIGHT is not defined, this
    returns the string "???" for all threads. */
const char *ssh_fsm_get_thread_name(SshFSMThread thread);

/** Print last n states of the thread. This can be used to
    debug problems in the fsm state machine, as the normal
    debugger backtrace does not tell what the state machine
    has been doing. Support for this is compiled in only if
    SSH_FSM_DEBUG is defined (defined by default if
    DEBUG_LIGHT is defined). */
void ssh_fsm_print_trace(SshFSMThread thread);

/** Is the thread running. As long as the thread is running we cannot
    kill it using ssh_fsm_kill_thread, so this can be used to check
    whether we can use that or not. This implies that thread is also
    active.*/
#define SSH_FSM_IS_THREAD_RUNNING(thread) ((thread)->flags & SSH_FSM_RUNNING)

/** Is the thread done. The thread is considered as done at the later
    of times the state function returns NULL or the thread destructor
    is about to be called (e.g it is not active at the
    destructor). This call is useful for piggy-packed threads
    only. Dynamically allocated threads will never see thread as DONE
    state. */
#define SSH_FSM_IS_THREAD_DONE(thread) ((thread)->flags & SSH_FSM_DONE)

/** Does the thread exist?. This flag is set between calls to
    init/create and destructor. */
#define SSH_FSM_THREAD_EXISTS(thread) ((thread)->flags & SSH_FSM_EXISTS)

/* ************************ Accessing context data **************************/

/** Get the opaque FSM context data from the thread `thread'. */
void *ssh_fsm_get_gdata(SshFSMThread thread);

/** Get the opaque FSM context data from the FSM `fsm'. */
void *ssh_fsm_get_gdata_fsm(SshFSM fsm);

/** Get the opaque thread context data from the thread `thread'. */
void *ssh_fsm_get_tdata(SshFSMThread thread);

/** Get the underlying FSM for the thread `thread'. */
SshFSM ssh_fsm_get_fsm(SshFSMThread thread);


/* ************************* Condition variables ****************************/

/** Create a new condition variable for the FSM `fsm'.  The function
    returns NULL if the condition variable could not be created. */
SshFSMCondition ssh_fsm_condition_create(SshFSM fsm);

/** Initialize a new condition variable for the FSM `fsm'.  The
    condition variable must have been allocated by caller. */
void ssh_fsm_condition_init(SshFSM fsm, SshFSMCondition condition);

/** Destroy a condition variable. When a condition variable is destroyed,
    not threads may be waiting for it. Use SSH_FSM_CONDITION_BROADCAST if
    there are some threads left and you want to release them prior
    to destroying. */
void ssh_fsm_condition_destroy(SshFSMCondition condition);

/** Uninit the condition variable `condition'.  No threads must be
    waiting for it. */
void ssh_fsm_condition_uninit(SshFSMCondition condition);

/** Signal the condition variable `cv'.  This function can be called
    both from step functions and outside the FSM. */
void ssh_fsm_condition_signal(SshFSM fsm, SshFSMCondition cv);

/** Signal a condition. */
#define SSH_FSM_CONDITION_SIGNAL(cv)    \
  ssh_fsm_condition_signal(ssh_fsm_get_fsm(thread), cv)

/** Broadcast the condition variable `cv'.  This function can be called
    both from step functions and outside the FSM. */
void ssh_fsm_condition_broadcast(SshFSM fsm, SshFSMCondition cv);

/** Broadcast a condition. */
#define SSH_FSM_CONDITION_BROADCAST(cv) \
  ssh_fsm_condition_broadcast(ssh_fsm_get_fsm(thread), cv)

/** Wait for a condition.  Do not call this function directly but use
    the macro below. */
void ssh_fsm_condition_wait(SshFSMThread thread, SshFSMCondition cv);

/** Wait for a condition. */
#define SSH_FSM_CONDITION_WAIT(cv)      \
do                                      \
  {                                     \
    ssh_fsm_condition_wait(thread, cv); \
    return SSH_FSM_WAIT_CONDITION;      \
  }                                     \
while (0)


/* ************************** Asynchronous calls ****************************/

/** The async function call streamlining functions. Do not call these
    directly! Use macros instead. */
void ssh_fsm_set_callback_flag(SshFSMThread thread);
/** The async function call streamlining functions. Do not call these
    directly! Use macros instead. */
void ssh_fsm_drop_callback_flag(SshFSMThread thread);
/** The async function call streamlining functions. Do not call these
    directly! Use macros instead. */
Boolean ssh_fsm_get_callback_flag(SshFSMThread thread);

/** Call a function (in general, run a block) that will return a
    callback, either immediately or later. Can be used only inside step
    functions. Terminates the step function after the block. */
#define SSH_FSM_ASYNC_CALL(x)                           \
do                                                      \
  {                                                     \
    SSH_ASSERT(!(ssh_fsm_get_callback_flag(thread)));   \
    ssh_fsm_set_callback_flag(thread);                  \
    do                                                  \
      {                                                 \
        x;                                              \
      }                                                 \
    while (0);                                          \
    if (ssh_fsm_get_callback_flag(thread))              \
      return SSH_FSM_SUSPENDED;                         \
    return SSH_FSM_CONTINUE;                            \
  }                                                     \
while (0)

/** This macro can be used inside a callback to revive the thread. Use
    in conjunction with calls made with SSH_FSM_ASYNC_CALL. This macro
    does *NOT* return implicitly because the callback might want a
    value to be returned. */
#define SSH_FSM_CONTINUE_AFTER_CALLBACK(thread)         \
do                                                      \
  {                                                     \
    SSH_ASSERT(ssh_fsm_get_callback_flag(thread));      \
    ssh_fsm_drop_callback_flag(thread);                 \
    ssh_fsm_continue(thread);                           \
  }                                                     \
while (0)

/** This macro can be used in exception cases to continue the thread
    safely regardless whether the thread was suspended or was waiting
    for completion of as SSH_FSM_ASYNC_CALL. Use this macro only in
    true exception handling cases if the thread status is unknown. */
#define SSH_FSM_CONTINUE_AFTER_EXCEPTION(thread)        \
do                                                      \
  {                                                     \
    if (ssh_fsm_get_callback_flag(thread))              \
      ssh_fsm_drop_callback_flag(thread);               \
    ssh_fsm_continue(thread);                           \
  }                                                     \
while (0)


/* ******************************* Messages *********************************/

/** Throw a message to another thread that must belong to the same FSM.
    If 'recipient' does not have a message handler then the call does
    nothing.  It is guaranteed that you can send one message to each
    thread from an FSM state.  The messages will be delivered to the
    recipient threads after the step function calling ssh_fsm_throw
    returns. */
void ssh_fsm_throw(SshFSMThread thread,
                   SshFSMThread recipient,
                   SshUInt32 message);

/** Throw a message to another thread. */
#define SSH_FSM_THROW(r, e)    \
  ssh_fsm_throw(thread, r, e)

/* ******************************* Suspend / Resumed ***********************/

/** Suspends FSM. After this no threads will be run on the FSM at all, but
    asyncronous calls can return and try to continue threads, and they are
    marked as so that they will start running immediately when the FSM is
    resumed again. Note, that if this function is called from FSM thread
    itself, then the suspend only happens AFTER the current FSM thread step
    returns. It is fatal error to call this if FSM is already suspended. */
void ssh_fsm_suspend(SshFSM fsm);

/** Resumes FSM. This will mark FSM as running, and will insert zero timeout to
    continue FSM after we reach back to bottom of event loop. It is fatal error
    to call this if FSM is not suspended. */
void ssh_fsm_resume(SshFSM fsm);

#endif /* not SSHFSM_H */
