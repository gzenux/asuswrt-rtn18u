/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Handling L2TP servers.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmL2tp"

#ifdef SSHDIST_L2TP

/************************** Static help functions ***************************/

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* Destructor for LNS tunnel threads. */
static void
ssh_pm_lns_tunnel_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmLnsTunnel t = (SshPmLnsTunnel) context;

  /* Recycle the negotiation context. */
  if (t->n)
    {
      ssh_pm_lns_tunnel_negotiation_free(pm, t->n);
      t->n = NULL;
    }

  SSH_ASSERT(pm->num_l2tp_lns_threads > 0);
  pm->num_l2tp_lns_threads--;

  ssh_pm_lns_tunnel_free(pm, t);
}

/* Abort callback for the tunnel request. */
static void
ssh_pm_lns_tunnel_request_abort(void *context)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) context;

  SSH_ASSERT(t->n != NULL);
  t->n->aborted = 1;
}

/* Destructor for LNS session threads. */
static void
ssh_pm_lns_session_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmLnsSession s = (SshPmLnsSession) context;

  /* Free the session object. */
  ssh_pm_lns_session_free(pm, s);
}

/* A callback function that the L2TP module calls when it wants to
   output a data frame to the PPP module of the session. */
static void
ssh_pm_l2tp_lns_data_cb(SshL2tpSessionInfo session, const unsigned char *data,
                        size_t data_len)
{
  SshPmLnsSession s = (SshPmLnsSession) session->upper_level_data;
  unsigned char *buf;

  if (s->ppp == NULL)
    {
      /* No PPP yet.  This should not happen. */
      SSH_DEBUG(SSH_D_UNCOMMON, ("No PPP yet"));
      return;
    }

  buf = ssh_memdup(data, data_len);
  if (buf == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not duplicate PPP frame"));
      return;
    }

  ssh_ppp_frame_input(s->ppp, buf, 0, data_len);
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */


/****************************** LNS callbacks *******************************/

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

/* A callback function that is called for new incoming tunnel
   requests. */
static SshOperationHandle
ssh_pm_l2tp_tunnel_request_cb(SshL2tpTunnelInfo info,
                              SshL2tpTunnelRequestCompletionCB completion_cb,
                              void *completion_cb_context,
                              void *callback_context)
{
  SshPm pm = (SshPm) callback_context;
  SshPmLnsTunnel t;

  t = ssh_pm_lns_tunnel_alloc(pm);
  if (t == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate LNS tunnel object"));
    error_resources:
      (*completion_cb)(FALSE, NULL, 0, NULL,
                       SSH_L2TP_TUNNEL_RESULT_ERROR,
                       SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                       NULL, 0,
                       completion_cb_context);
      return NULL;
    }
  /* One reference from our thread.  The second reference will be
     added when the tunnel object is stored into the
     `upper_level_data' of the SshL2tpTunnelInfo structure. */
  t->refcount = 1;

  t->n = ssh_pm_lns_tunnel_negotiation_alloc(pm);
  if (t->n == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate LNS tunnel negotiation object"));
      ssh_pm_lns_tunnel_free(pm, t);
      goto error_resources;
    }

  t->sa_rule_index = SSH_IPSEC_INVALID_INDEX;
  t->n->info = info;
  t->n->req_completion_cb = completion_cb;
  t->n->req_completion_cb_context = completion_cb_context;

  /* Start a thread handling the request. */
  pm->num_l2tp_lns_threads++;
  ssh_fsm_thread_init(&pm->fsm, &t->thread,
                      ssh_pm_st_lns_tunnel_request, NULL_FNPTR,
                      ssh_pm_lns_tunnel_thread_destructor, t);

  ssh_fsm_set_thread_name(&t->thread, "LNS tunnel request");

  /* And create an SshOperationHandle. */
  ssh_operation_register_no_alloc(&t->n->operation_handle,
                                  ssh_pm_lns_tunnel_request_abort, t);

  return &t->n->operation_handle;
}

/* Tunnel status callback for L2TP tunnels.  This function is called
   for both initiator and responder tunnels so care must be taken when
   referencing `info->upper_level_data'. */
static void
ssh_pm_l2tp_tunnel_status_cb(SshL2tpTunnelInfo info,
                             SshL2tpTunnelStatus status,
                             void *callback_context)
{
  SshPm pm = (SshPm) callback_context;
  SshPmLnsTunnel t;

  switch (status)
    {
    case SSH_L2TP_TUNNEL_OPEN_FAILED:
      if (info->initiator)
        {
          /* Nothing here. */
        }
      else
        {
          /* We may or may not have the tunnel object set in the L2TP
             tunnel's `upper_level_data'.  If the tunnel request was
             rejected, the field is unset, but if the request was
             accepted but it failed for some reason (insufficient
             resources, negotiation timed out, etc.) the field is set
             and we must free it now. */
          t = (SshPmLnsTunnel) info->upper_level_data;
          if (t)
            ssh_pm_lns_tunnel_free(pm, t);
        }
      break;

    case SSH_L2TP_TUNNEL_OPENED:
#ifdef DEBUG_LIGHT
      if (info->initiator)
        SSH_ASSERT(info->upper_level_data == NULL);
      else
        SSH_ASSERT(info->upper_level_data != NULL);
#endif /* DEBUG_LIGHT */
      break;

    case SSH_L2TP_TUNNEL_TERMINATED:
      if (info->initiator)
        {
          /* Nothing here. */
        }
      else
        {
          t = (SshPmLnsTunnel) info->upper_level_data;
          SSH_ASSERT(t != NULL);

          pm->num_l2tp_lns_threads++;
          ssh_fsm_thread_init(&pm->fsm, &t->thread,
                              ssh_pm_st_lns_tunnel_terminate, NULL_FNPTR,
                              ssh_pm_lns_tunnel_thread_destructor, t);

          ssh_fsm_set_thread_name(&t->thread, "LNS tunnel terminate");
        }
      break;
    }
}

/* A callback function that is called for new incoming session
   requests. */
static SshOperationHandle
ssh_pm_l2tp_session_request_cb(SshL2tpSessionInfo info,
                               SshL2tpSessionRequestCompletionCB completion_cb,
                               void *completion_cb_context,
                               void *callback_context)
{
  SshPm pm = (SshPm) callback_context;
  SshPmLnsSession s;

  s = ssh_pm_lns_session_alloc(pm);
  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate LNS session object"));
      (*completion_cb)(FALSE,
                       SSH_L2TP_SESSION_RESULT_ERROR,
                       SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                       NULL, 0,
                       completion_cb_context);
      return NULL;
    }

  /* Initially the session object has only one reference from the L2TP
     library.  When the session is successfully opened, we start a
     thread that controls it and add the second reference. */
  s->refcount = 1;
  s->info = info;
  s->outbound_rule_index = SSH_IPSEC_INVALID_INDEX;
  info->upper_level_data = s;

  /* Accept the session. */
  (*completion_cb)(TRUE, 0, 0, NULL, 0, completion_cb_context);
  return NULL;
}

/* Session status callback for LNS' responder sessions. */
static void
ssh_pm_l2tp_session_status_cb(SshL2tpSessionInfo info,
                              SshL2tpSessionStatus status,
                              void *callback_context)
{
  SshPm pm = (SshPm) callback_context;
  SshPmLnsSession s;

  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      SSH_DEBUG(SSH_D_FAIL, ("Session opening failed"));

      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            info->tunnel, info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Result:  %s",
                    ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                          info->result_code));
      if (info->result_code == SSH_L2TP_SESSION_RESULT_ERROR)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  Error:   %s",
                      ssh_find_keyword_name(ssh_l2tp_error_codes,
                                            info->error_code));
      if (info->error_message)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                      "  Message: %.*s",
                      (int) info->error_message_len, info->error_message);

      SSH_ASSERT(info->upper_level_data != NULL);
      s = (SshPmLnsSession) info->upper_level_data;

      /* Free the session object. */
      ssh_pm_lns_session_free(pm, s);
      break;

    case SSH_L2TP_SESSION_OPENED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Session opened"));

      SSH_ASSERT(info->upper_level_data != NULL);
      s = (SshPmLnsSession) info->upper_level_data;

      /* Set the L2TP data callback to pass L2TP data frames to PPP
         session. */
      s->info->data_cb = ssh_pm_l2tp_lns_data_cb;

      /* The thread adds a second reference to the session object. */
      s->refcount++;

      /* Create a thread for the session and initialize its
         synchronization variables. */
      ssh_fsm_condition_init(&pm->fsm, &s->cond);
      ssh_fsm_thread_init(&pm->fsm, &s->thread,
                          ssh_pm_st_lns_session_opened, NULL_FNPTR,
                          ssh_pm_lns_session_thread_destructor, s);
      ssh_fsm_set_thread_name(&s->thread, "LNS session open");
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Session terminated"));

      SSH_ASSERT(info->upper_level_data != NULL);
      s = (SshPmLnsSession) info->upper_level_data;

      /* Abort RAS attribute allocation */
      if (s->sub_operation)
        {
          ssh_operation_abort(s->sub_operation);
          s->sub_operation = NULL;
          ssh_fsm_set_next(&s->thread, ssh_pm_st_lns_session_terminate);
          SSH_FSM_CONTINUE_AFTER_CALLBACK(&s->thread);
        }

      /* Shutdown our PPP instance. */
      if (s->ppp)
        {
          ssh_ppp_destroy(s->ppp);
          s->ppp = NULL;
        }

      /* Notify thread about the termination. */
      s->terminated = 1;
      ssh_fsm_condition_signal(&pm->fsm, &s->cond);

      /* Unlink session from the L2TP info. */
      info->upper_level_data = NULL;
      info->data_cb = NULL_FNPTR;
      s->info = NULL;

      /* Free our reference to the LNS session object. */
      ssh_pm_lns_session_free(pm, s);

      /* Close the L2TP tunnel from the first session close. If you
         wish to let the initiator decide when to close the actual
         tunnel, comment this statement out. */
      ssh_l2tp_tunnel_close(pm->l2tp,
                            info->tunnel->local_id,
                            SSH_L2TP_TUNNEL_RESULT_TERMINATED,
                            SSH_L2TP_ERROR_NO_GENERAL_ERROR,
                            NULL, 0);
      break;

    case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("WAN error notify"));
      break;

    case SSH_L2TP_SESSION_SET_LINK_INFO:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Set link info: send=0x%lx, receive=0x%lx",
                 info->accm.send_accm,
                 info->accm.receive_accm));
      break;
    }
}
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
/* A callback function that is called for new incoming tunnel
   requests. */
static SshOperationHandle
ssh_pm_l2tp_tunnel_request_cb(SshL2tpTunnelInfo info,
                              SshL2tpTunnelRequestCompletionCB completion_cb,
                              void *completion_cb_context,
                              void *callback_context)
{
  char *error_message = "Operation not supported";

  (*completion_cb)(FALSE, NULL, 0, NULL,
                   SSH_L2TP_TUNNEL_RESULT_ERROR,
                   SSH_L2TP_ERROR_GENERIC,
                   (unsigned char *) error_message, strlen(error_message),
                   completion_cb_context);
  return NULL;
}

/* Tunnel status callback for L2TP tunnels.  This function is called
   for both initiator and responder tunnels so care must be taken when
   referencing `info->upper_level_data'. */
static void
ssh_pm_l2tp_tunnel_status_cb(SshL2tpTunnelInfo info,
                             SshL2tpTunnelStatus status,
                             void *callback_context)
{
  /* Nothing here. */
}

/* A callback function that is called for new incoming session
   requests. */
static SshOperationHandle
ssh_pm_l2tp_session_request_cb(SshL2tpSessionInfo info,
                               SshL2tpSessionRequestCompletionCB completion_cb,
                               void *completion_cb_context,
                               void *callback_context)
{
  (*completion_cb)(FALSE, SSH_L2TP_SESSION_RESULT_PERMANENTLY_UNAVAILABLE,
                   SSH_L2TP_ERROR_NO_GENERAL_ERROR,
                   NULL, 0, completion_cb_context);
  return NULL;
}

/* Session status callback for LNS' responder sessions. */
static void
ssh_pm_l2tp_session_status_cb(SshL2tpSessionInfo info,
                              SshL2tpSessionStatus status,
                              void *callback_context)
{
  /* Nothing here. */
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/************************** Handling L2TP servers ***************************/

Boolean
ssh_pm_l2tp_init(SshPm pm)
{
  SshL2tpParamsStruct params;

  /* Initialize L2TP parameters. */

  memset(&params, 0, sizeof(params));

  params.hostname = (unsigned char *) pm->params.hostname;
  if (pm->params.hostname)
    params.hostname_len = ssh_ustrlen(pm->params.hostname);

  params.max_tunnel_outage = 30;
  params.hello_timer = SSH_L2TP_HELLO_TIMER_INFINITE;

  /* Create L2TP context. */
  pm->l2tp = ssh_l2tp_create(&params,
                             ssh_pm_l2tp_tunnel_request_cb,
                             ssh_pm_l2tp_tunnel_status_cb,
                             ssh_pm_l2tp_session_request_cb,
                             ssh_pm_l2tp_session_status_cb,
                             NULL_FNPTR,
                             pm);
  if (pm->l2tp == NULL)
    return FALSE;

  return TRUE;
}


void
ssh_pm_l2tp_uninit(SshPm pm, SshL2tpFinishedCB callback, void *context)
{
  if (pm->l2tp == NULL)
    {
      if (callback)
        (*callback)(context);
    }
  else
    {
      ssh_l2tp_destroy(pm->l2tp, callback, context);
    }
}
#endif /* SSHDIST_L2TP */
