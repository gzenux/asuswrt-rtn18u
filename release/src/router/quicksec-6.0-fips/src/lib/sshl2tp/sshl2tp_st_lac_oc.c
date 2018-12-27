/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LAC outgoing call (responder).
*/

#include "sshincludes.h"
#include "sshl2tp_internal.h"

#define SSH_DEBUG_MODULE "SshL2tpStLacOc"

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
      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lac_oc_accept_new);
    }
  else
    {
      if (result)
        SSH_L2TP_SET_STATUS(l2tp, result, error, error_message,
                            error_message_len);
      else
        SSH_L2TP_SET_STATUS(l2tp, SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE, 0,
                            NULL, 0);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lac_oc_reject_new);
    }

  session->operation_handle = NULL;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_idle)
{
  SshL2tpControlMessage message;
  SSH_L2TP_DATA;

  /* Wait for message. */
  if (session->message_queue.head == NULL)
    SSH_FSM_CONDITION_WAIT(session->message_queue_cond);

  message = ssh_l2tp_message(&session->message_queue);
  if (message->type != SSH_L2TP_CTRL_MSG_OCRQ)
    ssh_fatal("Internal error: AC OC responder thread started for "
              "non-OCRQ message");

  /* Let's ask user whether he allows one more outgoing call. */
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
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lac_oc_accept_new);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_reject_new)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New outgoing call rejected"));

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* This was not an acceptable OCRQ.  We copy the result also to our
     session object so it is available at the notification
     callback. */
  SSH_L2TP_COPY_STATUS(&session->info, l2tp);
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_CDN);

  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);

  return SSH_FSM_CONTINUE;
}


static void
outgoing_call_complete(Boolean success,
                       SshL2tpLacOutgoingCallStatus status,
                       void *completion_cb_context)
{
  SshFSMThread thread = (SshFSMThread) completion_cb_context;
  SshL2tpSession session = ssh_fsm_get_tdata(thread);

  if (success)
    {
      /* Operation was successful.  Let's copy the parameters from
         status. */
      if (status)
        {
          session->info.attributes.tx_connect_speed = status->tx_connect_speed;
          session->info.attributes.framing_type = status->framing_type;
          session->info.attributes.rx_connect_speed = status->rx_connect_speed;
          session->info.attributes.sequencing_required
            = status->sequencing_required;
        }
    }
  else
    {
      /* Operation failed.  Fetch the error code or use our
         default. */
      if (status && status->result_code)
        {
          SSH_L2TP_COPY_STATUS(&session->info, status);
          SSH_L2TP_COPY_Q931_STATUS(&session->info, status);
        }
      else
        {
          session->info.result_code = SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE;
        }
    }

  session->operation_handle = NULL;

  /* The error case is checked at `wait-cs-answer'. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lac_oc_wait_cs_answer);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_accept_new)
{
  SSH_L2TP_DATA;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New incoming call accepted"));

  /* We do not need the message anymore. */
  ssh_l2tp_message_handled(l2tp, thread, &session->message_queue);

  /* Send OCRP. */
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_OCRP);

  /* Let's ask user to make the call. */
  if (l2tp->lac_outgoing_call_cb)
    SSH_FSM_ASYNC_CALL(
    {
      SshOperationHandle h;

      h = (*l2tp->lac_outgoing_call_cb)(&session->info,
                                        outgoing_call_complete,
                                        thread,
                                        l2tp->callback_context);
      if (h)
        session->operation_handle = h;
    });

  /* No callback set.  Let's just accept it with the default
     parameters. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_lac_oc_wait_cs_answer);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_l2tp_fsm_lac_oc_wait_cs_answer)
{
  SSH_L2TP_DATA;

  if (session->info.result_code)
    {
      /* Bearer failure.  Let's copy the error message to the L2TP
         server and report it. */
      SSH_L2TP_SET_STATUS(l2tp,
                          session->info.result_code,
                          session->info.error_code,
                          session->info.error_message,
                          session->info.error_message_len);

      ssh_l2tp_send(l2tp, NULL, session->tunnel, session,
                    SSH_L2TP_CTRL_MSG_CDN);

      SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_clean_up);
      return SSH_FSM_CONTINUE;
    }

  /* Set the default values for unset fields. */
  if (session->info.attributes.tx_connect_speed == 0)
    session->info.attributes.tx_connect_speed
      = SSH_L2TP_DEFAULT_TX_CONNECT_SPEED;
  if (session->info.attributes.framing_type == 0)
    session->info.attributes.framing_type = SSH_L2TP_FRAMING_SYNCHRONOUS;

  /* Send OCCN. */
  ssh_l2tp_send(l2tp, NULL, session->tunnel, session, SSH_L2TP_CTRL_MSG_OCCN);

  /* The session is established.  let's notify our user. */
  session->established = 1;
  if (l2tp->session_status_cb)
    (*l2tp->session_status_cb)(&session->info, SSH_L2TP_SESSION_OPENED,
                               l2tp->callback_context);

  /* Move to the established state. */
  SSH_FSM_SET_NEXT(ssh_l2tp_fsm_session_established);
  return SSH_FSM_CONTINUE;
}
