/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General help states for session threads.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStSession"

/******************************** FSM states ********************************/

#define SSH_L2TP_DATA           \
  SshL2tp l2tp = fsm_context;   \
  SshL2tpSession session = thread_context


SSH_FSM_STEP(ssh_l2tp_fsm_session_established)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (session->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(session->message_queue_cond);

  message = ssh_l2tp_message(&session->message_queue);

  if (message->type != SSH_L2TP_CTRL_MSG_CDN)
    {
      /* Send CDN */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE, 0,
                          NULL, 0);
      SSH_L2TP_COPY_STATUS(&session->info, l2tp);
      ssh_l2tp_send(l2tp, NULL, session->tunnel, session,
                    SSH_L2TP_CTRL_MSG_CDN);
    }

  /* ACK everything. */
  ssh_l2tp_zlb(l2tp, session->tunnel);

  /* Store the possible status and error codes. */
  if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN
      || message->type == SSH_L2TP_CTRL_MSG_CDN)
    {
      SSH_L2TP_COPY_STATUS(&session->info, message);
      SSH_L2TP_COPY_Q931_STATUS(&session->info, message);
    }

  /* Message handled. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* Clean up. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_session_closed)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Closing session %d", session->info.local_id));

  /* Copy or set the termination code. */
  if (session->info.result_code)
    {
      SSH_L2TP_SET_STATUS(l2tp,
                          session->info.result_code,
                          session->info.error_code,
                          session->info.error_message,
                          session->info.error_message_len);
    }
  else
    {
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE, 0,
                          NULL, 0);
      SSH_L2TP_COPY_STATUS(&session->info, l2tp);
    }

  /* Send CDN. */
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_CDN);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_session_destroyed)
{
#ifdef DEBUG_LIGHT
  SshL2tpSession session = ssh_fsm_get_tdata(thread);
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying session %d",
                               session->info.local_id));
  SSH_ASSERT(session->destroyed);
  SSH_ASSERT(session->operation_handle == NULL);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_session_clean_up)
{
  SshADTHandle h;
  SSH_L2TP_DATA;

  /* Remove us from our tunnel. */
  h = ssh_adt_get_handle_to_equal(l2tp->sessions, session);
  if (h == SSH_ADT_INVALID)
    {
      ssh_fatal("Session is not in L2TP's session list");
    }
  else
    {
      ssh_adt_detach(l2tp->sessions, h);
      SSH_ASSERT(session->tunnel->sessions != NULL);

      if (session->sessions_next)
        session->sessions_next->sessions_prev = session->sessions_prev;

      if (session->sessions_prev)
        session->sessions_prev->sessions_next = session->sessions_next;
      else
        session->tunnel->sessions = session->sessions_next;
    }

  /* We can not have a pending operation. */
  SSH_ASSERT(session->operation_handle == NULL);

  /* Flush message queue. */
  while (session->message_queue.head)
    ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* Call the notification callback.  We have two options.  If we are
     the responder, we must use the L2TP module's notification
     function.  Otherwise we are the initiator and we have a special
     initiator callback to call. */
  if (session->info.initiator)
    {
      /* We are the initiator. */
      if (session->established)
        {
          /* The session was established. */
          SSH_ASSERT(session->initiator_handle == NULL);
          SSH_ASSERT(session->initiator_status_cb != NULL_FNPTR);
          (session->initiator_status_cb)(&session->info,
                                         SSH_L2TP_SESSION_TERMINATED,
                                         session->initiator_status_cb_context);
        }
      else
        {
          /* The session was never established, so the open failed and
             this callback completes the user's asynchronous
             operation. */
          if (session->initiator_status_cb)
            {
              /* The operation was not aborted. */
              SSH_ASSERT(session->initiator_handle != NULL);

              ssh_operation_unregister(session->initiator_handle);
              session->initiator_handle = NULL;

              (session->initiator_status_cb)(
                                        &session->info,
                                        SSH_L2TP_SESSION_OPEN_FAILED,
                                        session->initiator_status_cb_context);
            }
          else
            {
              /* The operation was aborted. */
              SSH_ASSERT(session->initiator_handle == NULL);
            }
        }
    }
  else
    {
      /* We are the responder.  We must now call the notification with
         an appropriate status.  If the session reached the
         established state, this session was terminated.  Otherwise
         the open failed. */
      SSH_ASSERT(!session->info.initiator);
      if (l2tp->session_status_cb)
        {
          if (session->established)
            (*l2tp->session_status_cb)(&session->info,
                                       SSH_L2TP_SESSION_TERMINATED,
                                       l2tp->callback_context);
          else
            (*l2tp->session_status_cb)(&session->info,
                                       SSH_L2TP_SESSION_OPEN_FAILED,
                                       l2tp->callback_context);
        }
    }

  /* Signal our tunnel that we have been destroyed. */
  SSH_FSM_CONDITION_SIGNAL(session->tunnel->condition);

  /* Mark the thread as NULL since it will be destroyed when we return
     SSH_FSM_FINISH from this function. */
  session->thread = NULL;

  /* Free the session object. */
  ssh_l2tp_session_free(session);

  /* And terminate. */
  return SSH_FSM_FINISH;
}


/************************** Public help functions ***************************/

void
ssh_l2tp_session_message_handler(SshFSMThread thread, SshUInt32 exception_arg)
{
  SshL2tpSession session = ssh_fsm_get_tdata(thread);
  SshL2tpThreadException exception = (SshL2tpThreadException) exception_arg;
  SshFSMStepCB next_state;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Received exception `%s' (%d)",
             ssh_find_keyword_name(ssh_l2tp_thread_exceptions,
                                   exception), exception));

  /* Resolve our next state. Assigned first to shut up some compilers. */
  next_state = NULL_FNPTR;
  switch (exception)
    {
    case SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN:
      next_state = ssh_l2tp_fsm_session_closed;
      break;

    case SSH_L2TP_THREAD_EXCEPTION_DESTROY:
      next_state = ssh_l2tp_fsm_session_destroyed;
      break;

    case SSH_L2TP_THREAD_EXCEPTION_CLEAN_UP:
      next_state = ssh_l2tp_fsm_session_clean_up;
      break;
    }

  ssh_fsm_set_next(thread, next_state);

  /* Cancel all pending operations. */
  if (session->operation_handle)
    {
      ssh_operation_abort(session->operation_handle);
      session->operation_handle = NULL;
    }

  /* Mark us destroyed and continue from the next state. */
  session->destroyed = 1;
  ssh_fsm_continue(thread);
}
