/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General help states for control connection (tunnel) threads.
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStTunnel"

/*************************** FSM state functions ****************************/

#define SSH_L2TP_DATA           \
  SshL2tp l2tp = fsm_context;   \
  SshL2tpTunnel tunnel = thread_context


SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_established)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (tunnel->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(tunnel->message_queue_cond);

  message = ssh_l2tp_message(&tunnel->message_queue);

  if (message->type != SSH_L2TP_CTRL_MSG_STOPCCN)
    {
      /* Send StopCCN */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_FSM_ERROR, 0, NULL, 0);
      SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);
      ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);
    }

  /* ACK everything. */
  ssh_l2tp_zlb(l2tp, tunnel);

  /* Copy possible status and error codes. */
  if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN
      || message->type == SSH_L2TP_CTRL_MSG_CDN)
    SSH_L2TP_COPY_STATUS(&tunnel->info, message);

  /* Message handled. */
  ssh_l2tp_message_handled(l2tp, thread, &tunnel->message_queue);

  /* Clean up. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_closed)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel was closed by user"));
  SSH_ASSERT(tunnel->destroyed);
  SSH_ASSERT(tunnel->operation_handle == NULL);

  if (tunnel->info.result_code)
    {
      SSH_L2TP_SET_STATUS(l2tp,
                          tunnel->info.result_code,
                          tunnel->info.error_code,
                          tunnel->info.error_message,
                          tunnel->info.error_message_len);
    }
  else
    {
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_TUNNEL_RESULT_SHUT_DOWN, 0, NULL, 0);
      SSH_L2TP_COPY_STATUS(&tunnel->info, l2tp);
    }

  ssh_l2tp_send(l2tp, NULL, tunnel, NULL, SSH_L2TP_CTRL_MSG_STOPCCN);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_destroyed)
{
  SshL2tpTunnel tunnel = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel was destroyed user"));
  SSH_ASSERT(tunnel->destroyed);
  SSH_ASSERT(tunnel->operation_handle == NULL);

  /* This tunnel can be destroyed as fast as possible.  There is no
     need to wait for the transport level's retransmission cycle. */
  tunnel->fast_shutdown = 1;

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_clean_up)
{
  SshL2tpTunnel tunnel = thread_context;
  SshL2tpSession session;

  /* We can not have any pending operations. */
  SSH_ASSERT(tunnel->operation_handle == NULL);

  /* Mark us destroyed.  The flag is unset if we come here from the
     FSM, not from the message handler. */
  tunnel->destroyed = 1;

  /* First, signal all sessions that they must terminate now. */
  for (session = tunnel->sessions; session; session = session->sessions_next)
    {
      if (session->destroyed)
        /* The session is already destroyed but it has not terminated
           yet. */
        continue;

      /* Signal session's thread. */
      ssh_fsm_throw(thread, session->thread,
                    SSH_L2TP_THREAD_EXCEPTION_DESTROY);
    }

  /* And wait that the sessions terminate themselves. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_tunnel_terminate);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_terminate)
{
  SSH_L2TP_DATA;

  if (tunnel->sessions)
    SSH_FSM_CONDITION_WAIT(tunnel->condition);

  /* Now our sessions have terminated. */

  /* Call tunnel notification callback. */
  if (l2tp->tunnel_status_cb)
    {
      if (tunnel->established)
        /* The tunnel was successfully established and we have called
           the SSH_L2TP_TUNNEL_OPENED for it. */
        (*l2tp->tunnel_status_cb)(&tunnel->info,
                                  SSH_L2TP_TUNNEL_TERMINATED,
                                  l2tp->callback_context);
      else
        /* The tunnel was destroyed (for some reason) before it was
           established. */
        (*l2tp->tunnel_status_cb)(&tunnel->info,
                                  SSH_L2TP_TUNNEL_OPEN_FAILED,
                                  l2tp->callback_context);
    }

  /* If the L2TP server is doing fast shutdown, do it also for this
     tunnel. */
  if (l2tp->fast_shutdown)
    tunnel->fast_shutdown = 1;

  /* Notify our transport level that this tunnel is ready for
     destruction. */
  ssh_l2tp_tunnel_terminated(tunnel);

  /* Finally, terminate this thread.  The actual tunnel structure is
     not freed here but it is left for the transport level.  But we
     mark the thread as NULL since it will die when we return from
     this step function. */
  tunnel->thread = NULL;

  return SSH_FSM_FINISH;
}


/************************** Public help functions ***************************/

void
ssh_l2tp_tunnel_message_handler(SshFSMThread thread, SshUInt32 exception_arg)
{
  SshL2tpTunnel tunnel = ssh_fsm_get_tdata(thread);
  SshL2tpThreadException exception = (SshL2tpThreadException) exception_arg;
  SshFSMStepCB next_state;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Received exception `%s' (%d)",
             ssh_find_keyword_name(ssh_l2tp_thread_exceptions,
                                   exception), exception));

  /* Resolve our next state. */
  next_state = NULL_FNPTR;
  switch (exception)
    {
    case SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN:
      next_state = ssh_l2tp_fsm_tunnel_closed;
      break;

    case SSH_L2TP_THREAD_EXCEPTION_DESTROY:
      next_state = ssh_l2tp_fsm_tunnel_destroyed;
      break;

    case SSH_L2TP_THREAD_EXCEPTION_CLEAN_UP:
      next_state = ssh_l2tp_fsm_tunnel_clean_up;
      break;
    }

  ssh_fsm_set_next(thread, next_state);

  /* Cancel all pending operations. */
  if (tunnel->operation_handle)
    {
      ssh_operation_abort(tunnel->operation_handle);
      tunnel->operation_handle = NULL;
    }

  /* Mark us destroyed and continue from the next state. */
  tunnel->destroyed = 1;
  ssh_fsm_continue(thread);
}
