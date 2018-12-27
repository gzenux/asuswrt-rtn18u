/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshdebug.h"
#include "sshtimeouts.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshFSM"

/***************************** Ring functions ******************************/

#ifdef DEBUG_LIGHT
  /* Check if 'object' is on the ring with root 'root_ptr' */
Boolean is_on_ring(SshFSMThread *root_ptr, SshFSMThread object)
{
  SshFSMThread tmp = *root_ptr;

  while (tmp)
    {
      if (tmp == object)
        return TRUE;

      tmp = tmp->next;

      if (tmp == *root_ptr)
        break;
    }
  return FALSE;
}
#endif /* DEBUG_LIGHT */


static void
fsm_ring_add(SshFSMThread *root_ptr,
             SshFSMThread object,
             Boolean first)
{
#ifdef DEBUG_LIGHT
  SSH_ASSERT(is_on_ring(root_ptr, object) == FALSE);
#endif /* DEBUG_LIGHT */

  if ((*root_ptr) == NULL)
    {
      *root_ptr = object;
      object->next = object->prev = object;
    }
  else
    {
      object->prev = (*root_ptr)->prev;
      (*root_ptr)->prev = object;
      object->prev->next = object;
      object->next = *root_ptr;

      if (first)
        *root_ptr = object;
    }
}

static void
fsm_ring_remove(SshFSMThread *root_ptr,
                SshFSMThread object)
{
#ifdef DEBUG_LIGHT
  SSH_ASSERT(is_on_ring(root_ptr, object) == TRUE);
#endif /* DEBUG_LIGHT */

  if (object->next == object)
    {
      *root_ptr = NULL;
    }
  else
    {
      object->next->prev = object->prev;
      object->prev->next = object->next;
      if (*root_ptr == object)
        *root_ptr = object->next;
    }
}


/************************ Create and destroying FSMs ************************/

SshFSM ssh_fsm_create(void *context)
{
  SshFSM fsm;

  fsm = ssh_malloc(sizeof(*fsm));
  if (fsm == NULL)
    return NULL;

  ssh_fsm_init(fsm, context);

  return fsm;
}

void ssh_fsm_init(SshFSM fsm, void *context)
{
  memset(fsm, 0, sizeof(*fsm));
  fsm->context_data = context;
}

static void destroy_callback(void *ctx)
{
  SshFSM fsm = (SshFSM)ctx;

#ifdef DEBUG_LIGHT
  if (fsm->num_threads > 0)
    ssh_fatal("Tried to destroy a FSM that has %d thread(s) left",
              (int) fsm->num_threads);
#endif /* DEBUG_LIGHT */

  ssh_free(fsm);

  SSH_DEBUG(8, ("FSM context destroyed"));
}

void ssh_fsm_destroy(SshFSM fsm)
{
  if (fsm->flags & SSH_FSM_SCHEDULER_SCHEDULED)
    ssh_cancel_timeout(&fsm->fsm_timeout);

  ssh_register_timeout(&fsm->fsm_timeout,
                       0L, 0L, destroy_callback, (void *)fsm);
}

void ssh_fsm_uninit(SshFSM fsm)
{
#ifdef DEBUG_LIGHT
  if (fsm->num_threads > 0)
    ssh_fatal("Tried to destroy a FSM that has %d thread(s) left",
              (int) fsm->num_threads);
#endif /* DEBUG_LIGHT */

  /* Cancel all callbacks from the FSM. */
  ssh_cancel_timeout(&fsm->fsm_timeout);

  SSH_DEBUG(8, ("FSM context uninitialized"));
}

void ssh_fsm_register_debug_names(SshFSM fsm, const SshFSMStateDebug states,
                                  int num_states)
{
#ifdef DEBUG_LIGHT
  fsm->states = states;
  fsm->num_states = num_states;
#endif /* DEBUG_LIGHT */
}


/**************************** Thread operations *****************************/

/* Move threads. */
static void
fsm_move_thread(SshFSMThread *from_ring,
                SshFSMThread *to_ring,
                SshFSMThread thread,
                Boolean first)
{
  fsm_ring_remove(from_ring, thread);
  fsm_ring_add(to_ring, thread, first);
}

/* Delete a thread. */
static void
fsm_uninit_thread(SshFSMThread thread)
{
#ifdef DEBUG_LIGHT
  thread->fsm->num_threads--;
#endif /* DEBUG_LIGHT */

  /* Wake up all waiters.  We are dying now. */
  while (thread->waiting)
    {
      SSH_ASSERT(thread->waiting->status == SSH_FSM_T_WAITING_THREAD);
      thread->waiting->status = SSH_FSM_T_ACTIVE;
      fsm_move_thread(&(thread->waiting),
                      (&thread->fsm->active),
                      thread->waiting,
                      FALSE);
    }

  SSH_ASSERT((thread->flags & SSH_FSM_DONE) == 0);
  thread->flags |= SSH_FSM_DONE;
  thread->flags &= ~SSH_FSM_EXISTS;

  if (thread->destructor)
    (*thread->destructor)(thread->fsm, thread->context_data);
}

/* Delete a thread. */
static void
fsm_delete_thread(SshFSMThread thread)
{
  Boolean dynamic = FALSE;

  /* Store the info about dynamic threads into a local variable since
     the `thread' argument can be invalidated at the thread's
     destructor. */
  if (thread->flags & SSH_FSM_DYNAMIC_THREAD)
    dynamic = TRUE;

  fsm_uninit_thread(thread);

  if (dynamic)
    ssh_free(thread);
}

#ifdef DEBUG_LIGHT
static const char *
ssh_fsm_state_name(SshFSM fsm, SshFSMStepCB step, char *buf, size_t buflen)
{
  int i;

  if (fsm->num_states)
    {
      for (i = 0; i < fsm->num_states; i++)
        if (fsm->states[i].func == step)
          {
            if (fsm->states[i].state_id)
              return fsm->states[i].state_id;

            break;
          }
    }

  ssh_snprintf(ssh_ustr(buf), buflen, "%p", step);
  return buf;
}

static const char *
ssh_fsm_state_descr(SshFSM fsm, SshFSMStepCB step, char *buf, size_t buflen)
{
  int i;

  if (fsm->num_states)
    {
      for (i = 0; i < fsm->num_states; i++)
        if (fsm->states[i].func == step)
          {
            if (fsm->states[i].descr)
              return fsm->states[i].descr;

            break;
          }
    }

  ssh_snprintf(ssh_ustr(buf), buflen, "%p", step);
  return buf;
}
#endif /* DEBUG_LIGHT */

/* Internal dispatcher, scheduler, whatever. */
static void fsm_scheduler(SshFSM fsm)
{
  /* No recursive invocations! */
  if (fsm->flags & SSH_FSM_IN_SCHEDULER)
    return;

  /* FSM is suspended! */
  if (fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED)
    return;

  SSH_DEBUG(8, ("Entering the scheduler"));
  SSH_DEBUG_INDENT;

  fsm->flags |= SSH_FSM_IN_SCHEDULER;

  while (1)
    {
      SshFSMThread thread;
      SshFSMStepStatus status;
#ifdef DEBUG_LIGHT
      char buf[128];
#endif /* DEBUG_LIGHT */

      if (fsm->active == NULL)
        {
          SSH_DEBUG_UNINDENT;
          SSH_DEBUG(6, ("No active threads so return from scheduler"));
          fsm->flags &= ~SSH_FSM_IN_SCHEDULER;
          break;
        }

      thread = fsm->active;
      fsm_ring_remove(&(fsm->active), thread);
      SSH_ASSERT(thread->status == SSH_FSM_T_ACTIVE);

      SSH_ASSERT(!(thread->flags & SSH_FSM_RUNNING));
      thread->flags |= SSH_FSM_RUNNING;

      SSH_DEBUG(8, ("Thread continuing from state `%s' (%s)",
                    ssh_fsm_state_name(fsm, thread->current_state,
                                       buf, sizeof(buf)),
                    ssh_fsm_state_descr(fsm, thread->current_state,
                                        buf, sizeof(buf))));

      /* Continue as long as it is possible. */
      do
        {
#ifdef SSH_FSM_DEBUG
          thread->last_states[thread->next_in_ring].state_func =
            thread->current_state;
          thread->last_states[thread->next_in_ring].status = 99;
#endif /* SSH_FSM_DEBUG */
          status = (*thread->current_state)(fsm, thread,
                                            thread->context_data,
                                            fsm->context_data);

#ifdef SSH_FSM_DEBUG
          thread->last_states[thread->next_in_ring].status = status;
          thread->next_in_ring++;
          if (thread->next_in_ring >= SSH_FSM_DEBUG_RING_BUFFER_SIZE)
            thread->next_in_ring = 0;
#endif /* SSH_FSM_DEBUG */

          /* If the FSM gets suspended, get out. */
          if (fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED)
            break;

          /* Pass messages. */
          while (fsm->waiting_message_handler)
            {
              SshFSMThread msg_thr = fsm->waiting_message_handler;

              fsm_ring_remove(&(fsm->waiting_message_handler), msg_thr);

              SSH_ASSERT(msg_thr->message_handler != NULL_FNPTR);
              SSH_ASSERT(msg_thr->flags & SSH_FSM_IN_MESSAGE_QUEUE);

              SSH_DEBUG(8, ("Delivering the message %u to thread `%s'",
                            (int) msg_thr->message,
                            (msg_thr->name
                             ? msg_thr->name : "unknown")));

              (*msg_thr->message_handler)(msg_thr, msg_thr->message);

              /* And put thread back to correct list. */
              msg_thr->flags &= ~SSH_FSM_IN_MESSAGE_QUEUE;
              switch (msg_thr->status)
                {
                case SSH_FSM_T_ACTIVE:
                  fsm_ring_add(&(fsm->active), msg_thr, FALSE);
                  break;

                case SSH_FSM_T_SUSPENDED:
                  fsm_ring_add(&(fsm->waiting_external), msg_thr, FALSE);
                  break;

                case SSH_FSM_T_WAITING_CONDITION:
                  SSH_ASSERT(msg_thr->waited.condition != NULL);
                  fsm_ring_add(&(msg_thr->waited.condition->waiting),
                               msg_thr, FALSE);
                  break;

                case SSH_FSM_T_WAITING_THREAD:
                  SSH_ASSERT(msg_thr->waited.thread != NULL);
                  fsm_ring_add(&(msg_thr->waited.thread->waiting),
                               msg_thr, FALSE);
                  break;
                }

              /* If the FSM gets suspended, get out. */
              if (fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED)
                break;

            }
        }
      while (status == SSH_FSM_CONTINUE);

      thread->flags &= ~SSH_FSM_RUNNING;

      if (fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED)
        {
          fsm->flags &= ~SSH_FSM_IN_SCHEDULER;
        }

      switch (status)
        {
        case SSH_FSM_FINISH:
          SSH_DEBUG(8, ("Thread finished in state `%s'",
                        ssh_fsm_state_name(fsm, thread->current_state,
                                           buf, sizeof(buf))));
          fsm_delete_thread(thread);
          break;

        case SSH_FSM_SUSPENDED:
          SSH_DEBUG(8, ("Thread suspended in state `%s'",
                        ssh_fsm_state_name(fsm, thread->current_state,
                                           buf, sizeof(buf))));
          thread->status = SSH_FSM_T_SUSPENDED;
          fsm_ring_add(&(fsm->waiting_external), thread, FALSE);
          break;

        case SSH_FSM_WAIT_CONDITION:
          SSH_DEBUG(8, ("Thread waiting for a condition variable in "
                        "state `%s'",
                        ssh_fsm_state_name(fsm, thread->current_state,
                                           buf, sizeof(buf))));
          /* Already added to the condition variable's ring. */
          break;

        case SSH_FSM_WAIT_THREAD:
          SSH_DEBUG(8, ("Thread waiting for a thread to terminate in "
                        "state `%s'",
                        ssh_fsm_state_name(fsm, thread->current_state,
                                           buf, sizeof(buf))));
          /* Already added to the thread's ring. */
          break;

        case SSH_FSM_CONTINUE:
          /* This means we got out from the loop because FSM got suspended, do
             nothing here. */
          SSH_ASSERT((fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED) != 0);
          break;

        case SSH_FSM_YIELD:
          fsm_ring_add(&(fsm->active), thread, FALSE);
          break;
        }
    }
}

static void fsm_scheduler_callback(void *ctx)
{
  if (!(((SshFSM)ctx)->flags & SSH_FSM_SCHEDULER_SUSPENDED))
    {
      ((SshFSM)ctx)->flags &= ~SSH_FSM_SCHEDULER_SCHEDULED;
      fsm_scheduler((SshFSM)ctx);
    }
}

static void fsm_schedule_scheduler(SshFSM fsm)
{
  if (!(fsm->flags & (SSH_FSM_IN_SCHEDULER |
                      SSH_FSM_SCHEDULER_SCHEDULED)))
    {
      if (!(fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED))
        {
          fsm->flags |= SSH_FSM_SCHEDULER_SCHEDULED;
          ssh_register_timeout(&fsm->fsm_timeout,
                               0L, 0L, fsm_scheduler_callback, (void *)fsm);
        }
    }
}

SshFSMThread ssh_fsm_thread_create(SshFSM fsm,
                                   SshFSMStepCB first_state,
                                   SshFSMMessageHandler ehandler,
                                   SshFSMDestructor destructor,
                                   void *context)
{
  SshFSMThread thread;

  thread = ssh_malloc(sizeof(*thread));
  if (thread == NULL)
    return NULL;

  ssh_fsm_thread_init(fsm, thread, first_state, ehandler, destructor, context);
  thread->flags |= SSH_FSM_DYNAMIC_THREAD;

  return thread;
}

void ssh_fsm_thread_init(SshFSM fsm, SshFSMThread thread,
                         SshFSMStepCB first_state,
                         SshFSMMessageHandler message_handler,
                         SshFSMDestructor destructor,
                         void *context)
{
#ifdef DEBUG_LIGHT
  char buf[128];
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(8, ("Starting a new thread starting from `%s'",
                ssh_fsm_state_name(fsm, first_state,
                                   buf, sizeof(buf))));

  memset(thread, 0, sizeof(*thread));

  thread->fsm = fsm;
  thread->current_state = first_state;
  thread->message_handler = message_handler;
  thread->destructor = destructor;
  thread->context_data = context;

#ifdef DEBUG_LIGHT
  fsm->num_threads++;
#endif /* DEBUG_LIGHT */

  fsm_ring_add(&(fsm->active), thread, FALSE);
  thread->status = SSH_FSM_T_ACTIVE;
  thread->flags |= SSH_FSM_EXISTS;

  fsm_schedule_scheduler(fsm);
}

void ssh_fsm_set_next(SshFSMThread thread, SshFSMStepCB next_state)
{
  thread->current_state = next_state;
}

SshFSMStepCB ssh_fsm_get_thread_current_state(SshFSMThread thread)
{
  return thread->current_state;
}


void ssh_fsm_continue(SshFSMThread thread)
{
  SSH_DEBUG(8, ("Continue called for thread `%s'.",
                thread->name ? thread->name : "unknown"));







  /* Check if the call comes from a message handler. */
  if (thread->flags & SSH_FSM_IN_MESSAGE_QUEUE)
    {
      SSH_DEBUG(8, ("Continue called from a message handler"));
      /* We simply make the thread active. */
      thread->status = SSH_FSM_T_ACTIVE;
      return;
    }

  if (thread->status == SSH_FSM_T_SUSPENDED)
    {
      /* Motive for having these to continue immediately is that we
         typically have already performed computation for the goal on
         the async operation and want to complete asap */
      SSH_DEBUG(8, ("Reactivating a suspended thread"));
      thread->status = SSH_FSM_T_ACTIVE;
      fsm_move_thread(&(thread->fsm->waiting_external),
                      &(thread->fsm->active),
                      thread,
                      TRUE);
      fsm_schedule_scheduler(thread->fsm);
      return;
    }

  if (thread->status == SSH_FSM_T_WAITING_CONDITION)
    {
      SSH_DEBUG(8, ("Reactivating a thread waiting for a condition variable "
                    "(detaching from the condition)"));
      thread->status = SSH_FSM_T_ACTIVE;
      fsm_move_thread(&(thread->waited.condition->waiting),
                      &(thread->fsm->active),
                      thread,
                      FALSE);
      fsm_schedule_scheduler(thread->fsm);
      return;
    }

  if (thread->status == SSH_FSM_T_WAITING_THREAD)
    {
      SSH_DEBUG(8, ("Reactivating a thread waiting for a thread to terminate "
                    "(detaching from the thread)"));
      thread->status = SSH_FSM_T_ACTIVE;
      fsm_move_thread(&(thread->waited.thread->waiting),
                      &(thread->fsm->active),
                      thread,
                      FALSE);
      fsm_schedule_scheduler(thread->fsm);
      return;
    }

  if (thread->status == SSH_FSM_T_ACTIVE)
    {
      SSH_DEBUG(8, ("Reactivating an already active thread (do nothing)"));
      return;
    }

  SSH_NOTREACHED;
}

static void fsm_remove_thread(SshFSMThread thread)
{
  SSH_ASSERT(!(thread->flags & SSH_FSM_RUNNING));

  /* Remove the thread from the appropriate ring. */
  switch (thread->status)
    {
    case SSH_FSM_T_ACTIVE:
      fsm_ring_remove(&(thread->fsm->active), thread);
      break;

    case SSH_FSM_T_SUSPENDED:
      fsm_ring_remove(&(thread->fsm->waiting_external), thread);
      break;

    case SSH_FSM_T_WAITING_CONDITION:
      fsm_ring_remove(&(thread->waited.condition->waiting), thread);
      break;

    case SSH_FSM_T_WAITING_THREAD:
      fsm_ring_remove(&(thread->waited.thread->waiting), thread);
      break;
    }
}

void ssh_fsm_kill_thread(SshFSMThread thread)
{
  fsm_remove_thread(thread);
  fsm_delete_thread(thread);
}

void ssh_fsm_uninit_thread(SshFSMThread thread)
{
  SSH_ASSERT((thread->flags & SSH_FSM_DYNAMIC_THREAD) == 0);

  fsm_remove_thread(thread);
  fsm_uninit_thread(thread);
}

void ssh_fsm_wait_thread(SshFSMThread thread, SshFSMThread waited)
{
  /* A thread can start to wait a thread only when it is running. */
  SSH_ASSERT(thread->flags & SSH_FSM_RUNNING);
  SSH_ASSERT(thread->status == SSH_FSM_T_ACTIVE);
  fsm_ring_add(&(waited->waiting), thread, FALSE);
  thread->status = SSH_FSM_T_WAITING_THREAD;
  thread->waited.thread = waited;
}


void ssh_fsm_set_thread_name(SshFSMThread thread, const char *name)
{
#ifdef DEBUG_LIGHT
  thread->name = (char *) name;
#endif /* DEBUG_LIGHT */
}


const char *ssh_fsm_get_thread_name(SshFSMThread thread)
{
#ifdef DEBUG_LIGHT
  return thread->name;
#else /* not DEBUG_LIGHT */
  return "???";
#endif /* not DEBUG_LIGHT */
}


/************************** Accessing context data **************************/

void *ssh_fsm_get_gdata(SshFSMThread thread)
{
  return thread->fsm->context_data;
}

void *ssh_fsm_get_gdata_fsm(SshFSM fsm)
{
  return fsm->context_data;
}

void *ssh_fsm_get_tdata(SshFSMThread thread)
{
  return thread->context_data;
}

SshFSM ssh_fsm_get_fsm(SshFSMThread thread)
{
  return thread->fsm;
}


/*************************** Condition variables ****************************/

SshFSMCondition ssh_fsm_condition_create(SshFSM fsm)
{
  SshFSMCondition condition;

  condition = ssh_malloc(sizeof(*condition));
  if (condition == NULL)
    return NULL;

  ssh_fsm_condition_init(fsm, condition);

  return condition;
}

void ssh_fsm_condition_init(SshFSM fsm, SshFSMCondition condition)
{
  memset(condition, 0, sizeof(*condition));
}

void ssh_fsm_condition_destroy(SshFSMCondition condition)
{
  SSH_ASSERT(condition->waiting == NULL);
  ssh_free(condition);
}

void ssh_fsm_condition_uninit(SshFSMCondition condition)
{
  SSH_ASSERT(condition->waiting == NULL);
}

void ssh_fsm_condition_signal(SshFSM fsm, SshFSMCondition condition)
{
  SSH_DEBUG(8, ("Signalling a condition variable"));

  if (condition->waiting == NULL)
    {
      SSH_DEBUG(8, ("Waiting list empty"));
      return;
    }

  SSH_ASSERT(condition->waiting->status == SSH_FSM_T_WAITING_CONDITION);

  SSH_DEBUG(8, ("Ok, activating one of the waiting threads"));

  condition->waiting->status = SSH_FSM_T_ACTIVE;

  fsm_move_thread(&(condition->waiting),
                  &(fsm->active),
                  condition->waiting,
                  FALSE);
  fsm_schedule_scheduler(fsm);
}

void ssh_fsm_condition_broadcast(SshFSM fsm, SshFSMCondition condition)
{
  while (condition->waiting != NULL)
    ssh_fsm_condition_signal(fsm, condition);
}

void ssh_fsm_condition_wait(SshFSMThread thread,
                            SshFSMCondition condition)
{
  /* A thread can start to wait a condition only when it is running. */
  SSH_ASSERT(thread->flags & SSH_FSM_RUNNING);
  SSH_ASSERT(thread->status == SSH_FSM_T_ACTIVE);
  fsm_ring_add(&(condition->waiting), thread, FALSE);
  thread->status = SSH_FSM_T_WAITING_CONDITION;
  thread->waited.condition = condition;
}


/**************************** Asynchronous calls ****************************/

void ssh_fsm_set_callback_flag(SshFSMThread thread)
{
  thread->flags |= SSH_FSM_CALLBACK_FLAG;
}

void ssh_fsm_drop_callback_flag(SshFSMThread thread)
{
  thread->flags &= ~SSH_FSM_CALLBACK_FLAG;
}

Boolean ssh_fsm_get_callback_flag(SshFSMThread thread)
{
  return ((thread->flags & SSH_FSM_CALLBACK_FLAG) != 0);
}


/********************************* Messages *********************************/

void ssh_fsm_throw(SshFSMThread thread,
                   SshFSMThread recipient,
                   SshUInt32 message)
{
  /* Message throwing is not allowed outside the execution of the
     state machine. */
  SSH_ASSERT(thread->fsm->flags & SSH_FSM_IN_SCHEDULER);
  SSH_ASSERT(thread != recipient);

  if (recipient->message_handler == NULL_FNPTR)
    /* Nothing to do. */
    return;

  /* Check the state of the recipient and remove it from its ring. */
  switch (recipient->status)
    {
    case SSH_FSM_T_ACTIVE:
      fsm_ring_remove(&(recipient->fsm->active), recipient);
      break;

    case SSH_FSM_T_SUSPENDED:
      fsm_ring_remove(&(recipient->fsm->waiting_external), recipient);
      break;

    case SSH_FSM_T_WAITING_CONDITION:
      fsm_ring_remove(&(recipient->waited.condition->waiting), recipient);
      break;

    case SSH_FSM_T_WAITING_THREAD:
      fsm_ring_remove(&(recipient->waited.thread->waiting), recipient);
      break;
    }

  /* Add the thread to the list of threads, waiting for message
     handler call. */
  recipient->flags |= SSH_FSM_IN_MESSAGE_QUEUE;
  recipient->message = message;
  fsm_ring_add(&(thread->fsm->waiting_message_handler), recipient, FALSE);
}

#ifdef SSH_FSM_DEBUG
void ssh_fsm_print_trace(SshFSMThread thread)
{
  char buf1[32], buf2[32];
  const char *status;
  int i, j;

  ssh_debug("Trace of last %d steps of thread %s",
            SSH_FSM_DEBUG_RING_BUFFER_SIZE,
            thread->name ? thread->name : "unknown");
  i = thread->next_in_ring + 1;
  if (i >= SSH_FSM_DEBUG_RING_BUFFER_SIZE)
    i = 0;
  j = 0;
  while (1)
    {
      if (thread->last_states[i].state_func != NULL)
        {
          if (i == thread->next_in_ring &&
              thread->last_states[i].status != 99)
            break;
          switch (thread->last_states[i].status)
            {
            case 99: status = "Running"; break;
            case SSH_FSM_CONTINUE: status = "Continue"; break;
            case SSH_FSM_YIELD: status = "Yield"; break;
            case SSH_FSM_FINISH: status = "Finish"; break;
            case SSH_FSM_SUSPENDED: status = "Suspended"; break;
            case SSH_FSM_WAIT_CONDITION: status = "Wait condition"; break;
            case SSH_FSM_WAIT_THREAD: status = "Wait thread"; break;
            default: status = "Unknown"; break;
            }
          ssh_debug("[%d] State %s (%s) returned %s (%d)",
                    j++,
                    ssh_fsm_state_name(thread->fsm,
                                       thread->last_states[i].state_func,
                                       buf1, sizeof(buf1)),
                    ssh_fsm_state_descr(thread->fsm,
                                        thread->last_states[i].state_func,
                                        buf2, sizeof(buf2)),
                    status,
                    thread->last_states[i].status);
        }
      if (i == thread->next_in_ring)
        break;
      i++;
      if (i >= SSH_FSM_DEBUG_RING_BUFFER_SIZE)
        i = 0;
    }
  ssh_debug("End of trace of thread %s",
            thread->name ? thread->name : "unknown");
}
#else /* SSH_FSM_DEBUG */
void ssh_fsm_print_trace(SshFSMThread thread)
{
  ssh_debug("Ssh_fsm_print_trace support not compiled in");
}
#endif /* SSH_FSM_DEBUG */


/* Suspends FSM. After this no threads will be run on the FSM at all, but
   asyncronous calls can return and try to continue threads, and they are
   marked as so that they will start running immediately when the FSM is
   resumed again. Note, that if this function is called from FSM thread
   itself, then the suspend only happens AFTER the current FSM thread step
   returns.  */
void ssh_fsm_suspend(SshFSM fsm)
{
  SSH_ASSERT((fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED) == 0);

  fsm->flags |= SSH_FSM_SCHEDULER_SUSPENDED;
  if (fsm->flags & SSH_FSM_SCHEDULER_SCHEDULED)
    {
      fsm->flags &= ~SSH_FSM_SCHEDULER_SCHEDULED;
      ssh_cancel_timeout(&fsm->fsm_timeout);
    }
}

/* Resumes FSM. This will mark FSM as running, and will insert zero timeout to
   continue FSM after we reach back to bottom of event loop. */
void ssh_fsm_resume(SshFSM fsm)
{
  SSH_ASSERT((fsm->flags & SSH_FSM_SCHEDULER_SUSPENDED) != 0);

  fsm->flags &= ~SSH_FSM_SCHEDULER_SUSPENDED;
  fsm_schedule_scheduler(fsm);
}
