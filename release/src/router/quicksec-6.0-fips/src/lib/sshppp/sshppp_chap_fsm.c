/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppChap"

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"

#define SSH_CHAP_ENTRY()                                \
  SSH_FSM_DATA(SshPppState, SshPppChap);                \
  ssh_ppp_thread_enter_state(gdata, tdata->ppp_thread); \
  ssh_ppp_chap_handle_events(gdata, tdata);

#define SSH_CHAP_EXIT()                                         \
  return ssh_ppp_thread_leave_state(gdata,tdata->ppp_thread);

static void
ssh_ppp_chap_init_counter(SshPppState gdata, SshPppChap tdata)
{
  tdata->counter_current = 0;
}

static void
ssh_ppp_chap_inc_counter(SshPppState gdata, SshPppChap tdata)
{
  tdata->counter_current++;
}

static void
ssh_ppp_chap_cancel_timeout(SshPppState gdata, SshPppChap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);
  ssh_ppp_timer_cancel_timeout(timer);
  tdata->is_reauth_tmout_set = 0;
}

static void
ssh_ppp_chap_reset_timeout_resend(SshPppState gdata, SshPppChap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
  ssh_ppp_timer_set_timeout(timer,2,0);
  tdata->counter_max = 10;
}

static void
ssh_ppp_chap_reset_timeout_reauth(SshPppState gdata, SshPppChap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
  ssh_ppp_timer_set_timeout(timer, 86400, 0);

  tdata->counter_max = 5;
  tdata->is_reauth_tmout_set = 1;
}

void
ssh_ppp_chap_handle_events(SshPppState gdata, SshPppChap tdata)
{
  SshPppPktBuffer pkt;
  SshPppEvent ev;

  /* Handle timeouts */

  ev = ssh_ppp_thread_get_event(gdata, tdata->ppp_thread);

  if (ev == SSH_PPP_EVENT_TIMEOUT)
    {
      ssh_ppp_chap_inc_counter(gdata,tdata);

      ev = (tdata->counter_current > tdata->counter_max ?
            SSH_PPP_EVENT_TOMINUS : SSH_PPP_EVENT_TOPLUS);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
      return;
    }

  /* If an event has occurred or is cached do nothing */

  if (ev != SSH_PPP_EVENT_NONE)
    return;

  /* If we have input, parse it into an event */

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  if (pkt == NULL)
    return;

  if (ssh_ppp_protocol_frame_isvalid(pkt) == SSH_PPP_OK)
    {
      ssh_ppp_protocol_frame_strip_pad(pkt);
      ev = ssh_ppp_chap_input(gdata,tdata);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
    }
  return;
}

#ifdef SSHDIST_RADIUS
void
ssh_ppp_chap_radius_cb(SshPppState gdata,
                       void *auth_state,
                       SshRadiusClientRequestStatus status,
                       SshRadiusClientRequest request,
                       SshRadiusOperationCode reply_code)
{
  SshPppChap chap;
  Boolean auth_ok;
  SshPppEventsOutput op;
  unsigned char *param,*ptr;
  size_t param_len;
  SshPppEvent ret;

  chap = (SshPppChap)auth_state;

  /* OperationHandle is void when callback hits */
  chap->radius_client.radius_handle = NULL;

  SSH_ASSERT(request == chap->radius_client.radius_req);

  param = NULL;
  param_len = 0;

  auth_ok = ssh_ppp_radius_parse_chap_reply(gdata, chap->algorithm,
                                            status, request, reply_code,
                                            &param,&param_len);

  ptr = NULL;
  if (param != NULL && param_len > 1)
    {
      ptr = param + 1; /* Skip identifier byte in reply */
      param_len--;
    }

  if (auth_ok)
    {
      ssh_ppp_chap_build_success(gdata,chap,ptr,param_len);
      ret = SSH_PPP_EVENT_AUTH_OK;
    }
  else
    {
      ret = SSH_PPP_EVENT_AUTH_PEER_FAIL;
      if (ssh_ppp_chap_build_failure(gdata,chap,ptr,param_len) == TRUE)
        {
          ret = ssh_ppp_chap_mschap_failure_to_event(gdata, chap, ptr,
                                                     param_len);

          if (ret != SSH_PPP_EVENT_AUTH_THIS_FAIL_CHANGEPW)
            {
              ssh_ppp_chap_build_failure(gdata,chap,NULL,0);
              ret = SSH_PPP_EVENT_AUTH_PEER_FAIL;
            }
        }
    }

  ssh_free(param);

  op = ssh_ppp_thread_get_cb_outputq(chap->ppp_thread);

  ssh_radius_client_request_destroy(request);
  chap->radius_client.radius_req = NULL;

  ssh_ppp_events_signal(op, ret);
}

static void
ssh_ppp_chap_make_radius_query(SshPppState gdata, SshPppChap tdata)
{
  if (tdata->is_radius_used == 1
      && tdata->radius_client.radius_req == NULL)
    {
      SshUInt8 id = ssh_ppp_identifier_get(&tdata->id,
                                           SSH_PPP_CHAP_CODE_CHALLENGE);

      if (ssh_ppp_radius_make_chap_query(gdata,
                                         &tdata->radius_client,
                                         tdata->algorithm,
                                         tdata->peer_name,
                                         tdata->peer_name_length,
                                         id,
                                         tdata->challenge,
                                         tdata->challenge_length,
                                         tdata->response_buf,
                                         tdata->response_length)
          == FALSE)
        {
          ssh_ppp_fatal(gdata);
          return;
        }
    }
  return;
}

#endif /* SSHDIST_RADIUS */

SSH_FSM_STEP(ssh_chap_server_failed)
{
  SshPppEventsOutput out;

  SSH_CHAP_ENTRY();

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  ssh_ppp_forget_secret(tdata->secret_buf, tdata->secret_length);
  tdata->secret_buf = NULL;
  tdata->secret_length = 0;

  if (tdata->auth_status != SSH_PPP_EVENT_AUTH_PEER_FAIL)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_PEER_FAIL;
      ssh_ppp_server_auth_fail(gdata);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_PEER_FAIL);
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_server_initial)
{
  SSH_CHAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_inc_id(gdata,tdata);
      ssh_ppp_chap_init_challenge(gdata,tdata);
      ssh_ppp_chap_init_counter(gdata,tdata);
      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);
      ssh_ppp_chap_output_challenge(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_challenge);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_server_challenge)
{
  SSH_CHAP_ENTRY();

  tdata->is_reauth_tmout_set = 0;

  (void)ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_inc_counter(gdata,tdata);

      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);
      ssh_ppp_chap_output_challenge(gdata,tdata);
      break;

    case SSH_PPP_EVENT_TOMINUS:
      SSH_DEBUG(SSH_D_MIDOK,
                ("CHAP authentication failed due to timeout"));
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_failed);
      break;

    case SSH_PPP_EVENT_RESPONSE:

#ifdef SSHDIST_RADIUS
      if (tdata->is_radius_used == 1)
        {
          ssh_ppp_chap_make_radius_query(gdata,tdata);
          ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_verify);
          break;
        }
#endif /* SSHDIST_RADIUS */
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_verify);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_server_verify)
{
  SshPppEvent ev;
  SshPppThread ppp_thread;

  SSH_CHAP_ENTRY();

  (void)ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  /* Map secrets in this state to AUTH_OK/AUTH_FAIL events before
     the event dispatcher */
  ev = ssh_ppp_thread_get_event(gdata, tdata->ppp_thread);
  if (ev == SSH_PPP_EVENT_SECRET)
    {
      ev = ssh_ppp_chap_input_server_secret(gdata,tdata);
      if (ev != SSH_PPP_EVENT_NONE)
        {
          ppp_thread = tdata->ppp_thread;
          ssh_ppp_thread_set_event(ppp_thread, ev);
        }
    }

  switch (ev)
    {
    case SSH_PPP_EVENT_RESPONSE:
#ifdef SSHDIST_RADIUS
      if (tdata->is_radius_used == 1)
        {
          ssh_ppp_chap_make_radius_query(gdata,tdata);
          ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_verify);
          break;
        }
#endif /* SSHDIST_RADIUS */
      break;

    case SSH_PPP_EVENT_AUTH_OK:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_output_success(gdata,tdata);
       ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_auth);
      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL_CHANGEPW:
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_failed);
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("CHAP change password not supported"));
      break;

    case SSH_PPP_EVENT_TOMINUS:
      SSH_DEBUG(SSH_D_MIDOK,
                ("CHAP authentication failed due to timeout"));
      /* fallthrough */
    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
      /* We don't bother sending a CHAP Failure packet. We just
         get on with tearing the LCP connection down. */

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_failed);
      break;
    }

  SSH_CHAP_EXIT();
}

/* Force a reauthentication */

SSH_FSM_STEP(ssh_chap_server_auth)
{
  SshPppEventsOutput out;

  SSH_CHAP_ENTRY();

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  if (tdata->auth_status != SSH_PPP_EVENT_AUTH_OK)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_OK;
      ssh_ppp_server_auth_ok(gdata);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_OK);
    }

  ssh_ppp_forget_secret(tdata->secret_buf, tdata->secret_length);
  tdata->secret_buf = NULL;
  tdata->secret_length = 0;

  if (tdata->is_reauth_tmout_set == 0)
    ssh_ppp_chap_reset_timeout_reauth(gdata,tdata);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_RESPONSE:

#ifdef SSHDIST_RADIUS
      if (tdata->is_radius_used == 1)
        {
          ssh_ppp_chap_make_radius_query(gdata,tdata);
          ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_verify);
          break;
        }
#endif /* SSHDIST_RADIUS */
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_verify);
      break;

    case SSH_PPP_EVENT_TOMINUS:
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_inc_id(gdata,tdata);
      ssh_ppp_chap_init_challenge(gdata,tdata);
      ssh_ppp_chap_init_counter(gdata,tdata);
      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);
      ssh_ppp_chap_output_challenge(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_server_challenge);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_client_initial)
{
  SSH_CHAP_ENTRY();

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: initial"));

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      ssh_ppp_chap_init_peer_challenge(gdata,tdata);
      ssh_ppp_chap_init_counter(gdata,tdata);
      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_client_wait);
      break;
    }
  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_client_wait)
{
  SSH_CHAP_ENTRY();

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: wait"));

  (void)ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_TOMINUS:
      if (tdata->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
        ssh_ppp_thread_set_next(tdata->ppp_thread,
                                ssh_chap_client_auth_peer_fail);
      else
        ssh_ppp_thread_set_next(tdata->ppp_thread,
                                ssh_chap_client_auth_this_fail);
      break;

    case SSH_PPP_EVENT_CHALLENGE:
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_chap_cancel_timeout(gdata, tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_client_generate);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_client_generate)
{
  SSH_CHAP_ENTRY();

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: generate"));

  (void)ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_SECRET:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_build_response(gdata,tdata);
      ssh_ppp_chap_init_counter(gdata,tdata);
      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);
      ssh_ppp_chap_output_response(gdata,tdata);

      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_client_result);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_client_result)
{
  SSH_CHAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_chap_inc_counter(gdata,tdata);
      ssh_ppp_chap_reset_timeout_resend(gdata,tdata);
      ssh_ppp_chap_output_response(gdata,tdata);
      break;

    case SSH_PPP_EVENT_AUTH_OK:
      ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_chap_client_auth_ok);
      break;

    case SSH_PPP_EVENT_TOMINUS:
      if (tdata->algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
        ssh_ppp_thread_set_next(tdata->ppp_thread,
                                ssh_chap_client_auth_peer_fail);
      else
        ssh_ppp_thread_set_next(tdata->ppp_thread,
                                ssh_chap_client_auth_this_fail);
      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
    case SSH_PPP_EVENT_AUTH_THIS_FAIL_CHANGEPW:
      ssh_ppp_thread_set_next(tdata->ppp_thread,
                              ssh_chap_client_auth_this_fail);
      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL_RECHALLENGE:
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_thread_set_next(tdata->ppp_thread,
                              ssh_chap_client_auth_this_fail_rechallenge);
      break;

    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
      ssh_ppp_thread_set_next(tdata->ppp_thread,
                              ssh_chap_client_auth_peer_fail);
      break;

    case SSH_PPP_EVENT_CHALLENGE:
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_chap_cancel_timeout(gdata, tdata);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_client_generate);
      break;
    }

  SSH_CHAP_EXIT();
}

SSH_FSM_STEP(ssh_chap_client_auth_this_fail_rechallenge)
{
  SSH_FSM_DATA(SshPppState,SshPppChap);

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: rechallenge"));

  (void)ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  ssh_ppp_forget_secret(tdata->secret_buf, tdata->secret_length);
  tdata->secret_buf = NULL;
  tdata->secret_length = 0;

  ssh_ppp_forget_secret(tdata->new_secret_buf, tdata->new_secret_length);
  tdata->new_secret_buf = NULL;
  tdata->new_secret_length = 0;
  tdata->response_length = 0;

  ssh_ppp_chap_cancel_timeout(gdata, tdata);

  tdata->auth_status = SSH_PPP_EVENT_AUTH_THIS_FAIL;
  ssh_ppp_client_auth_fail(gdata);
  tdata->auth_status = SSH_PPP_EVENT_NONE;

  ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
  ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_chap_client_generate);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_chap_client_auth_this_fail)
{
  SshPppEventsOutput out;
  SSH_FSM_DATA(SshPppState,SshPppChap);

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: this_fail"));

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  ssh_ppp_chap_cancel_timeout(gdata, tdata);

  if (tdata->auth_status != SSH_PPP_EVENT_AUTH_THIS_FAIL)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_THIS_FAIL;
      ssh_ppp_client_auth_fail(gdata);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_THIS_FAIL);
    }

  ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_chap_client_auth_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_chap_client_auth_peer_fail)
{
  SshPppEventsOutput out;
  SSH_FSM_DATA(SshPppState,SshPppChap);

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: peer fail"));

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  ssh_ppp_chap_cancel_timeout(gdata, tdata);

  if (tdata->auth_status != SSH_PPP_EVENT_AUTH_PEER_FAIL)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_PEER_FAIL;
      ssh_ppp_client_auth_fail(gdata);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_PEER_FAIL);
    }

  ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_chap_client_auth_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_chap_client_auth_ok)
{
  SshPppEventsOutput out;
  SSH_FSM_DATA(SshPppState,SshPppChap);

  SSH_DEBUG(SSH_D_NICETOKNOW,("CHAP client in state: auth ok"));

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  ssh_ppp_chap_cancel_timeout(gdata, tdata);

  if (tdata->auth_status != SSH_PPP_EVENT_AUTH_OK)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_OK;
      ssh_ppp_client_auth_ok(gdata);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_OK);
    }
  ssh_ppp_thread_set_next(tdata->ppp_thread,ssh_chap_client_auth_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_chap_client_auth_done)
{
  SSH_CHAP_ENTRY();

  /* Forget secret */

  ssh_ppp_forget_secret(tdata->secret_buf, tdata->secret_length);
  tdata->secret_buf = NULL;
  tdata->secret_length = 0;

  ssh_ppp_forget_secret(tdata->new_secret_buf, tdata->new_secret_length);
  tdata->new_secret_buf = NULL;
  tdata->new_secret_length = 0;

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_CHALLENGE:
      ssh_ppp_chap_init_peer_challenge(gdata,tdata);
      ssh_ppp_chap_get_secret(gdata,tdata,FALSE);
      ssh_ppp_thread_set_next(tdata->ppp_thread, ssh_chap_client_generate);
      break;
    }

  SSH_CHAP_EXIT();
}
