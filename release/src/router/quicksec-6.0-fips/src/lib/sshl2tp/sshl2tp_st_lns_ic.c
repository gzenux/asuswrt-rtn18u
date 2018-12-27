/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LNS Incoming Call (responder).
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStLnsIc"

/******************************** FSM states ********************************/

#define SSH_L2TP_DATA           \
  SshL2tp l2tp = fsm_context;   \
  SshL2tpSession session = thread_context


static void
session_request_complete(Boolean accept,
                         SshL2tpSessionResultCode result,
                         SshL2tpErrorCode error,
                         const unsigned char *error_message,
                         size_t error_message_len,
                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshL2tpSession session = ssh_fsm_get_tdata(thread);
  SshL2tp l2tp = session->tunnel->l2tp;

  if (accept)
    {
      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lns_ic_accept_new);
    }
  else
    {
      if (result)
        SSH_L2TP_SET_STATUS(l2tp, result, error, error_message,
                            error_message_len);
      else
        SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE, 0,
                            NULL, 0);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lns_ic_reject_new);
    }

  session->operation_handle = NULL;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_idle)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (session->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(session->message_queue_cond);

  message = ssh_l2tp_message(&session->message_queue);
  if (message->type != SSH_L2TP_CTRL_MSG_ICRQ)
    ssh_fatal("Internal error: LNS IC responder thread started for "
              "non-ICRQ message");

  /* Let's ask user whether he allows one more incoming call. */
  if (l2tp->session_request_cb)
    SSH_FSM_ASYNC_CALL(
    {
      SshOperationHandle h;

      h = (*l2tp->session_request_cb)(&session->info,
                                      session_request_complete,
                                      thread,
                                      l2tp->callback_context);
      if (h)
        session->operation_handle = h;
    });


  /* No callback set.  Let's accept it. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lns_ic_accept_new);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_reject_new)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New incoming call rejected"));

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* This was not an acceptable ICRQ. */
  SSH_L2TP_COPY_STATUS(&session->info, l2tp);
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_CDN);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_accept_new)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New incoming call accepted"));

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* We accepted it.  Let's send our ICRP reply packet. */
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_ICRP);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lns_ic_wait_connect);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_lns_ic_wait_connect)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (session->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(session->message_queue_cond);

  message = ssh_l2tp_message(&session->message_queue);

  if (message->type == SSH_L2TP_CTRL_MSG_ICCN)
    {
      /* Assume everything is ok. */

      /* Message handled. */
      ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

      ssh_l2tp_zlb(l2tp, session->tunnel);

      /* The session is established.  Let's notify our user. */
      session->established = 1;
      if (l2tp->session_status_cb)
        (*l2tp->session_status_cb)(&session->info,
                                   SSH_L2TP_SESSION_OPENED,
                                   l2tp->callback_context);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_established);
      return SSH_FSM_CONTINUE;
    }

  if (message->type != SSH_L2TP_CTRL_MSG_CDN)
    {
      /* Send CDN. */
      SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE, 0,
                          NULL, 0);
      SSH_L2TP_COPY_STATUS(&session->info, l2tp);
      ssh_l2tp_send(l2tp, NULL, session->tunnel, session,
                    SSH_L2TP_CTRL_MSG_CDN);
    }

  /* ACK everything. */
  ssh_l2tp_zlb(l2tp, session->tunnel);

  /* Copy possible result code. */
  if (message->type == SSH_L2TP_CTRL_MSG_STOPCCN
      || message->type == SSH_L2TP_CTRL_MSG_CDN)
    {
      SSH_L2TP_COPY_STATUS(&session->info, message);
      SSH_L2TP_COPY_Q931_STATUS(&session->info, message);
    }

  /* Message handled. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* And clean up this session. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}
