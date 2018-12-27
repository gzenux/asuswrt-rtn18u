/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppEap"

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "ssheap.h"

#ifdef SSHDIST_EAP

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"
#include "sshppp_eap.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"

#ifdef SSHDIST_RADIUS
static Boolean
ssh_ppp_eap_radius_req_cb(SshEap eap,
                          SshRadiusClientRequestStatus status,
                          SshRadiusClientRequest request,
                          SshRadiusOperationCode reply_code,
                          void *ctx);
#endif /* SSHDIST_RADIUS */

void
ssh_ppp_eap_destroy(void *ctx)
{
  SshPppMuxProtocolStruct *mux;
  SshPppEap eap = (SshPppEap)ctx;

  SSH_ASSERT(eap != NULL);

  SSH_DEBUG(SSH_D_MIDOK,("destroying EAP instance %p",ctx));

  ssh_fsm_kill_thread(ssh_ppp_thread_get_thread(eap->ppp_thread));

  ssh_eap_destroy(eap->eap);
  ssh_eap_config_destroy(eap->eap_config);
  ssh_eap_connection_destroy(eap->eap_con);

  mux = ssh_ppp_thread_get_mux(eap->ppp_thread);
  ssh_ppp_flush_del_protocol(mux);

  ssh_ppp_thread_destroy(eap->ppp_thread);

  if (eap->peer_name != NULL)
    ssh_free(eap->peer_name);

  ssh_eap_free_token(eap->token);
  eap->token = NULL;
  eap->eap_type = 0;

  ssh_free(ctx);
}

static SshIterationStatus
ssh_ppp_eap_isauthenticator(SshPppPktBuffer pkt)
{
  SshPppPktBufferStruct buf;
  unsigned long len;
  SshUInt8 *ptr;

  if (ssh_ppp_protocol_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);

  ssh_ppp_protocol_skip_hldc(pkt);

  len = ssh_ppp_pkt_buffer_get_contentlen(pkt);
  ptr = ssh_ppp_pkt_buffer_get_ptr(pkt,0,len);

  if (ssh_eap_packet_destination(ptr,len) == SSH_EAP_AUTHENTICATOR)
    {
      return SSH_PPP_OK;
    }
  return SSH_PPP_ERROR;
}

static SshIterationStatus
ssh_ppp_eap_isauthenticatee(SshPppPktBuffer pkt)
{
  SshPppPktBufferStruct buf;
  unsigned long len;
  SshUInt8 *ptr;

  if (ssh_ppp_protocol_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);

  ssh_ppp_protocol_skip_hldc(pkt);

  len = ssh_ppp_pkt_buffer_get_contentlen(pkt);
  ptr = ssh_ppp_pkt_buffer_get_ptr(pkt,0,len);

  if (ssh_eap_packet_destination(ptr,len) == SSH_EAP_PEER)
    {
      return SSH_PPP_OK;
    }

  return SSH_PPP_ERROR;
}

Boolean
ssh_ppp_eap_set_name(void *ctx,
                     SshUInt8 *buf,
                     unsigned long len)
{
  SshPppEap tdata = (SshPppEap)ctx;

  SSH_PRECOND(buf != NULL);

  if (tdata->auth_mode == SSH_PPP_AUTH_PEER)
    {
      if (tdata->peer_name != NULL)
        {
          ssh_free(tdata->peer_name);
          tdata->peer_name = NULL;
          tdata->peer_name_length = 0;
        }

      tdata->peer_name = ssh_malloc(len);

      if (tdata->peer_name == NULL)
        {
          tdata->peer_name_length = 0;
          return FALSE;
        }

      tdata->peer_name_length = len;

      memcpy(tdata->peer_name,buf,len);
    }
  return TRUE;
}

SshPppEvent
ssh_ppp_eap_get_status(void *ctx)
{
  SshPppEap tdata = (SshPppEap)ctx;

  return tdata->auth_status;
}

SshPppAuthMode
ssh_ppp_eap_get_mode(void *ctx)
{
  SshPppEap tdata = (SshPppEap)ctx;

  return tdata->auth_mode;
}

SshPppEvents
ssh_ppp_eap_get_events(void *ctx)
{
  SshPppEap tdata = (SshPppEap)ctx;

  return ssh_ppp_thread_get_events(tdata->ppp_thread);
}

static void
ssh_ppp_eap_auth_ok(SshPppState state, SshPppEap tdata)
{
  if (tdata->auth_status == SSH_PPP_EVENT_NONE
      || (tdata->auth_mode == SSH_PPP_AUTH_PEER
          && tdata->auth_status == SSH_PPP_EVENT_AUTH_THIS_FAIL))
    {

      tdata->auth_status = SSH_PPP_EVENT_AUTH_OK;

      if (tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
        {
          ssh_ppp_server_auth_ok(state);
        }

      if (tdata->auth_mode == SSH_PPP_AUTH_PEER)
        {
          ssh_ppp_client_auth_ok(state);
        }

      tdata->is_auth_ok = 1;
      ssh_ppp_thread_wakeup(tdata->ppp_thread);
    }
}

static void
ssh_ppp_eap_auth_this_fail(SshPppState state, SshPppEap tdata)
{
  if (tdata->auth_status == SSH_PPP_EVENT_NONE
      || tdata->auth_status == SSH_PPP_EVENT_AUTH_OK)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_THIS_FAIL;

      if (tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
        ssh_ppp_server_auth_fail(state);

      if (tdata->auth_mode == SSH_PPP_AUTH_PEER)
        ssh_ppp_client_auth_fail(state);

      tdata->is_auth_this_fail = 1;
      tdata->is_auth_ok = 0;
      ssh_ppp_thread_wakeup(tdata->ppp_thread);
    }
}

static void
ssh_ppp_eap_auth_peer_fail(SshPppState state, SshPppEap tdata)
{
  if (tdata->auth_status == SSH_PPP_EVENT_NONE
      || tdata->auth_status == SSH_PPP_EVENT_AUTH_OK)
    {
      tdata->auth_status = SSH_PPP_EVENT_AUTH_PEER_FAIL;

      if (tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
        ssh_ppp_server_auth_fail(state);

      if (tdata->auth_mode == SSH_PPP_AUTH_PEER)
        ssh_ppp_client_auth_fail(state);

      tdata->is_auth_peer_fail = 1;
      tdata->is_auth_ok = 0;
      ssh_ppp_thread_wakeup(tdata->ppp_thread);
    }
}


/* Cache secret so we can gracefully
   return to bottom of eventloop */

static const char ssh_ppp_eap_dummybuf[1] = { 0 };

void
ssh_ppp_eap_return_secret(SshPppState gdata,
                          void *ctx,
                          SshUInt8 *buf,
                          SshUInt32 len,
                          Boolean isvalid)
{
  SshPppEventsOutput op;
  SshPppEap tdata = (SshPppEap)ctx;

  ssh_eap_free_token(tdata->token);
  tdata->token = NULL;

  op = ssh_ppp_thread_get_cb_outputq(tdata->ppp_thread);
  ssh_ppp_events_unreserve(op);

  SSH_DEBUG(SSH_D_LOWOK,
            ("received external shared secret isvalid %d",
             isvalid));

  if (isvalid == FALSE)
    {
      return;
    }

  if (buf != NULL)
    {
      SshEapTokenStruct dummy;

      ssh_eap_init_token_secret(&dummy, buf, len);
      tdata->token = ssh_eap_dup_token(&dummy);
    }
  else if (tdata->auth_mode == SSH_PPP_AUTH_PEER)
    {
      SshEapTokenStruct dummy;
      ssh_eap_init_token_secret(&dummy,(SshUInt8*)ssh_ppp_eap_dummybuf,0);
      tdata->token = ssh_eap_dup_token(&dummy);
    }

  ssh_ppp_events_signal(op, SSH_PPP_EVENT_SECRET);
}

void
ssh_ppp_eap_return_token(SshPppState gdata,
                         void *ctx,
                         SshUInt8 eap_type,
                         SshEapToken tok,
                         Boolean isvalid)
{
  SshPppEap tdata = (SshPppEap)ctx;
  SshPppEventsOutput op;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("received token %p for type %d isvalid %d",
             tok,(int) eap_type, isvalid));

  ssh_eap_free_token(tdata->token);
  tdata->token = NULL;
  tdata->eap_type = SSH_EAP_TOKEN_NONE;

  op = ssh_ppp_thread_get_cb_outputq(tdata->ppp_thread);
  ssh_ppp_events_unreserve(op);

  if (isvalid == FALSE)
    {
      return;
    }


  if (tok != NULL)
    {
      SSH_ASSERT(tok->type != SSH_EAP_TOKEN_NONE);

      tdata->token = ssh_eap_dup_token(tok);
      tdata->eap_type = eap_type;
    }

  ssh_ppp_events_signal(op, SSH_PPP_EVENT_SECRET);
}

static void
ssh_ppp_eap_input_secret(SshPppState gdata, SshPppEap tdata)
{
  SshEapToken tok;

  tok = tdata->token;
  tdata->token = NULL;

  switch (tdata->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
      if (tok != NULL)
        {
          ssh_eap_token(tdata->eap, tdata->eap_type, tok);
        }
      else
        {
          ssh_eap_authenticate(tdata->eap, SSH_EAP_AUTH_FAILURE);
        }
      break;

    case SSH_PPP_AUTH_PEER:
      if (tok != NULL)
        {
          ssh_eap_token(tdata->eap, tdata->eap_type, tok);
        }
      break;
    default:
      SSH_NOTREACHED;
    }

  ssh_eap_free_token(tok);
}

void
ssh_ppp_eap_get_token(SshPppState gdata, void* ctx)
{
  SshPppEventsOutput out;
  SshPppEap tdata;

  tdata = (SshPppEap)ctx;

  out = ssh_ppp_thread_get_cb_outputq(tdata->ppp_thread);
  ssh_ppp_events_reserve(out);

  switch (tdata->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
      ssh_ppp_get_token(gdata, tdata, SSH_PPP_AUTH_EAP,
                        tdata->eap_type, tdata->token_type,
                        tdata->peer_name,
                        tdata->peer_name_length);
                        break;

    case SSH_PPP_AUTH_PEER:
      ssh_ppp_get_token(gdata, tdata, SSH_PPP_AUTH_EAP,
                        tdata->eap_type, tdata->token_type,
                        NULL, 0);
      break;

    default:
      SSH_NOTREACHED;
    }
}

void
ssh_ppp_eap_get_secret(SshPppState gdata, void* ctx)
{
  SshPppEventsOutput out;
  SshPppEap tdata;
  SshPppAuthType auth_type;

  tdata = (SshPppEap)ctx;

  out = ssh_ppp_thread_get_cb_outputq(tdata->ppp_thread);
  ssh_ppp_events_reserve(out);

  auth_type = (tdata->is_secret_id==1?
               SSH_PPP_AUTH_EAP_ID:SSH_PPP_AUTH_EAP);

  switch (tdata->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
      ssh_ppp_get_secret(gdata, tdata, auth_type,
                         tdata->peer_name, tdata->peer_name_length);
      break;
    case SSH_PPP_AUTH_PEER:
      ssh_ppp_get_secret(gdata, tdata, auth_type, NULL, 0);
      break;
    default:
      SSH_NOTREACHED;
    }
}

static void
ssh_ppp_eap_signal(SshEap eap,
                   SshUInt8 type,
                   SshEapSignal signal,
                   SshBuffer buf,
                   void *ctx)
{
  SshPppEap tdata;
  SshPppState gdata;
  SshEapTokenType token_type;

  tdata = (SshPppEap)ctx;
  gdata = tdata->gdata;

  SSH_DEBUG(SSH_D_MIDOK,
            ("received synch signal %d from eap library", signal));

  switch (signal)
    {
    case SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK:
    case SSH_EAP_SIGNAL_AUTH_OK_USERNAME:
      ssh_ppp_eap_auth_ok(gdata,tdata);
      break;

    case SSH_EAP_SIGNAL_AUTH_PEER_OK:
      ssh_ppp_eap_auth_ok(gdata,tdata);
      break;

    case SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR:
      ssh_ppp_eap_auth_peer_fail(gdata,tdata);
      break;
    case SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME:
    case SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION:
      if (tdata->require_mutual_auth == 1)
        ssh_ppp_eap_auth_peer_fail(gdata,tdata);
      else
        ssh_ppp_eap_auth_this_fail(gdata,tdata);
      break;

    case SSH_EAP_SIGNAL_AUTH_FAIL_REPLY:
      ssh_ppp_eap_auth_this_fail(gdata,tdata);
      break;

    case SSH_EAP_SIGNAL_IDENTITY:
      if (buf == NULL)
        break;

      if (tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
        {
          if (tdata->peer_name != NULL)
            ssh_free(tdata->peer_name);

          tdata->peer_name_length = ssh_buffer_len(buf);
          tdata->peer_name = ssh_malloc(ssh_buffer_len(buf));

          if (tdata->peer_name == NULL)
            {
              tdata->peer_name_length = 0;
              ssh_ppp_fatal(gdata);
              break;
            }

          memcpy(tdata->peer_name, ssh_buffer_ptr(buf), ssh_buffer_len(buf));
        }

      tdata->is_identity = 1;
      ssh_ppp_thread_wakeup(tdata->ppp_thread);
      break;
    case SSH_EAP_SIGNAL_NOTIFICATION:
      break;
    case SSH_EAP_SIGNAL_FATAL_ERROR:
    case SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT:
      ssh_ppp_fatal(gdata);
      break;
    case SSH_EAP_SIGNAL_NEED_TOKEN:
      if (buf != NULL)
        {
          token_type = ssh_eap_get_token_type_from_buf(buf);

          tdata->eap_type = type;
          tdata->token_type = token_type;

          switch (token_type)
            {
#if 0
              /* If this is #if 1'd, then EAP-MD5 will work using
                 the same callbacks as CHAP / PAP. */
            case SSH_EAP_TOKEN_SHARED_SECRET:
              tdata->is_secret_id = 0;
              ssh_ppp_eap_get_secret(gdata, tdata);
              break;
#endif /* 0 */

              /* Play username token directly from cache or
                 configuration, avoid unnecessary callback. */
            case SSH_EAP_TOKEN_USERNAME:
              {
                SshEapTokenStruct token;
                SshPppEventsOutput out;

                if (tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
                  {
                    ssh_eap_init_token_username(&token,
                                                tdata->peer_name,
                                                tdata->peer_name_length);
                  }
                else
                  {
                    ssh_eap_init_token_username(&token,
                                                gdata->sys_name,
                                                gdata->sys_name_length);
                  }

                out = ssh_ppp_thread_get_cb_outputq(tdata->ppp_thread);
                ssh_ppp_events_reserve(out);

                ssh_ppp_eap_return_token(gdata, tdata, tdata->eap_type,
                                         &token, TRUE);
              }
              break;
            default:
              ssh_ppp_eap_get_token(gdata, tdata);
              break;
            case SSH_EAP_TOKEN_NONE:
              SSH_NOTREACHED;
              break;
            }
        }
      break;

    case SSH_EAP_SIGNAL_AUTH_PEER_MAYBE_OK:
      ssh_ppp_eap_auth_ok(gdata,tdata);
      break;

    case SSH_EAP_SIGNAL_TOKEN_DISCARDED:
      SSH_DEBUG(SSH_D_FAIL,("EAP library discarded token!"));
      break;
    case SSH_EAP_SIGNAL_PACKET_DISCARDED:
      break;
    case SSH_EAP_SIGNAL_NONE:
    default:
      SSH_NOTREACHED;
    }
}

static void
ssh_ppp_eap_output_cb(SshEapConnection con,
                      void *ctx,
                      const SshBuffer buf)
{
  SshPppEap ppp_eap;
  SshPppPktBuffer pkt;
  SshPppMuxProtocolStruct *mux;
  SshPppState gdata;
  size_t len;

  ppp_eap = (SshPppEap)ctx;
  gdata = ppp_eap->gdata;

  mux = ssh_ppp_thread_get_mux(ppp_eap->ppp_thread);

  if (ssh_ppp_flush_output_pkt_isavail(mux) == FALSE)
    return;

  pkt = ssh_ppp_flush_get_output_pkt(mux);

  if (pkt == NULL)   /* Could not get packet, even if we should! */
    {
      ssh_ppp_fatal(gdata);
      return;
    }

  ssh_ppp_pkt_buffer_offset(pkt,16);

  len = ssh_buffer_len(buf);

  /* Cannot send packet, discarding */

  if (ssh_ppp_pkt_buffer_get_trailer(pkt) < len)
    {
      SSH_DEBUG(SSH_D_FAIL,("EAP packet exceeds mru, discarding"));
      return;
    }

  ssh_ppp_pkt_buffer_append_buf(pkt,ssh_buffer_ptr(buf),len);

  ssh_ppp_flush_send_pkt(ppp_eap->gdata,mux);
}

void*
ssh_ppp_eap_create(SshPppState gdata,
                   SshPppAuthMode eap_mode,
                   SshPppEvents eventq,
                   SshPppFlush output_mux)
{
  SshFSMThread thread;
  SshPppEap eap;
  SshPppMuxProtocolStruct *mux;
  SshPppMuxAcceptanceCB pkt_cb;
  SshFSMStepCB state_cb;

  SSH_DEBUG(SSH_D_MIDOK,("creating EAP %s instance",
                         (eap_mode==SSH_PPP_AUTH_AUTHENTICATOR?
                          "authenticator":"peer")));

  eap = ssh_malloc(sizeof(*eap));

  if (eap == NULL)
    return NULL;

  thread = NULL;
  eap->ppp_thread = NULL;
  eap->eap_con = NULL;
  eap->eap_config = NULL;
  eap->eap = NULL;
  mux = NULL;

  pkt_cb = (eap_mode==SSH_PPP_AUTH_AUTHENTICATOR?
            ssh_ppp_eap_isauthenticator:ssh_ppp_eap_isauthenticatee);

  state_cb = (eap_mode==SSH_PPP_AUTH_AUTHENTICATOR?
              ssh_eap_server_initial:ssh_eap_client_initial);


  thread = ssh_fsm_thread_create(gdata->fsm,
                                 state_cb,
                                 NULL_FNPTR,
                                 NULL_FNPTR,
                                 eap);

  if (thread == NULL)
    goto fail;

  eap->gdata = gdata;

  eap->auth_mode = eap_mode;
  eap->ppp_thread = ssh_ppp_thread_create(gdata, thread, eventq, "EAP");
  eap->auth_status = SSH_PPP_EVENT_NONE;

  mux = ssh_ppp_flush_add_protocol(output_mux,
                                   SSH_PPP_PID_EAP,
                                   eap->ppp_thread,
                                   1024,
                                   pkt_cb);

  if (mux == NULL)
    goto fail;

  ssh_ppp_thread_attach_mux(eap->ppp_thread, mux);

  eap->eap_config = ssh_eap_config_create();
  eap->eap_con = ssh_eap_connection_create_cb(ssh_ppp_eap_output_cb,eap);

  if (eap->eap_config == NULL || eap->eap_con == NULL)
    goto fail;

  eap->eap_config->num_retransmit = 5;
  eap->eap_config->retransmit_delay_sec = 2;
  eap->eap_config->re_auth_delay_sec = 0;
  eap->eap_config->auth_timeout_sec = 10;

  eap->eap_config->signal_cb = ssh_ppp_eap_signal;

  eap->eap_config->refcount = 0;

  switch (eap->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
#ifdef SSHDIST_RADIUS
      eap->eap_config->radius_buffer_identity = TRUE;
      eap->eap_config->radius_req_cb = ssh_ppp_eap_radius_req_cb;
#endif /* SSHDIST_RADIUS */
      eap->eap = ssh_eap_create_server(eap, eap->eap_config, eap->eap_con);

      if (eap->eap == NULL)
        goto fail;

      ssh_eap_accept_auth_none(eap->eap);

      if (gdata->eap_server_md5)
        if (ssh_eap_accept_auth(eap->eap, SSH_EAP_TYPE_MD5_CHALLENGE , 1)
            != SSH_EAP_OPSTATUS_SUCCESS)
          goto fail;

      break;
    case SSH_PPP_AUTH_PEER:
      eap->eap = ssh_eap_create_client(eap, eap->eap_config, eap->eap_con);

      if (eap->eap == NULL)
        goto fail;

      ssh_eap_accept_auth_none(eap->eap);

      if (gdata->eap_client_md5)
        if (ssh_eap_accept_auth(eap->eap, SSH_EAP_TYPE_MD5_CHALLENGE , 1)
            != SSH_EAP_OPSTATUS_SUCCESS)
          goto fail;

      break;
    default:
      SSH_NOTREACHED;
      break;
    }

  eap->is_timeout = 0;
  eap->is_identity = 0;
  eap->is_auth_ok = 0;
  eap->is_auth_peer_fail = 0;
  eap->is_auth_this_fail = 0;
  eap->is_secret_id = 0;
  eap->require_mutual_auth = 0;
#ifdef SSHDIST_RADIUS
  eap->is_radius_used = (gdata->radius_config == NULL?0:1);
#endif /* SSHDIST_RADIUS */

  eap->peer_name_length = 0;
  eap->peer_name = NULL;
  eap->token = NULL;
  eap->eap_type = 0;
  eap->token_type = SSH_EAP_TOKEN_NONE;





  return eap;

 fail:
  if (eap->eap != NULL)
    ssh_eap_destroy(eap->eap);

  if (eap->eap_con != NULL)
    ssh_eap_connection_destroy(eap->eap_con);

  if (eap->eap_config != NULL)
    ssh_eap_config_destroy(eap->eap_config);

  if (mux != NULL)
    ssh_ppp_flush_del_protocol(mux);

  if (eap->ppp_thread != NULL)
    ssh_ppp_thread_destroy(eap->ppp_thread);

  if (thread != NULL)
    ssh_fsm_kill_thread(thread);

  ssh_free(eap);

  return NULL;
}

void
ssh_ppp_eap_boot(void *ctx)
{
  SshPppEap eap = (SshPppEap)ctx;
  ssh_ppp_thread_boot(eap->ppp_thread);
}

static void
ssh_ppp_eap_handle_events(SshPppState gdata,
                          SshPppEap tdata)
{
  SshPppEvent ev;
  unsigned long len;
  SshUInt8 *ptr;
  SshPppPktBuffer pkt;
  SshBufferStruct tmp;

  ev = ssh_ppp_thread_get_event(gdata, tdata->ppp_thread);

  if (ev != SSH_PPP_EVENT_NONE)
    {
      return;
    }

  /* Check timeouts */

  if (tdata->is_timeout == 1)
    {
      ssh_ppp_thread_set_event(tdata->ppp_thread, SSH_PPP_EVENT_TIMEOUT);
      tdata->is_timeout = 0;
      return;
    }

  /* Check if identity has been received, and if so. Signal
     the FSM */

  if (tdata->is_identity == 1)
    {
      ssh_ppp_thread_set_event(tdata->ppp_thread, SSH_PPP_EVENT_IDENTITY_RECV);

      tdata->is_identity = 0;
      return;
    }

  /* Check if authentication has succeeded, or failed */

  if (tdata->is_auth_peer_fail == 1)
    {
      ssh_ppp_thread_set_event(tdata->ppp_thread,
                               SSH_PPP_EVENT_AUTH_PEER_FAIL);
      tdata->is_auth_peer_fail = 0;
      return;
    }

  if (tdata->is_auth_this_fail == 1)
    {
      ssh_ppp_thread_set_event(tdata->ppp_thread,
                               SSH_PPP_EVENT_AUTH_THIS_FAIL);
      tdata->is_auth_this_fail = 0;
      return;
    }


  if (tdata->is_auth_ok == 1)
    {
      ssh_ppp_thread_set_event(tdata->ppp_thread, SSH_PPP_EVENT_AUTH_OK);
      tdata->is_auth_ok = 0;
      return;
    }

  /* Pass input packets */

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  if (pkt == NULL)
    return;

  if (ssh_ppp_protocol_frame_isvalid(pkt) == SSH_PPP_OK)
    {
      len = ssh_ppp_pkt_buffer_get_contentlen(pkt);
      ptr = ssh_ppp_pkt_buffer_get_ptr(pkt,0,len);

      tmp.dynamic = FALSE;
      tmp.buf = ptr;
      tmp.alloc = len;
      tmp.end = len;

      if (ssh_ppp_hldc_ispfc(pkt))
        tmp.offset = 1;
      else
        tmp.offset = 2;

      ssh_eap_connection_input_packet(tdata->eap_con, &tmp);
    }
  return;
}

#ifdef SSHDIST_RADIUS
void
ssh_ppp_eap_radius_cb(SshPppState gdata,
                      void *auth_state,
                      SshRadiusClientRequestStatus status,
                      SshRadiusClientRequest request,
                      SshRadiusOperationCode reply_code)
{
  /* The ssheap library has it's own RADIUS support. */
  SSH_NOTREACHED;
}

static Boolean
ssh_ppp_eap_radius_req_cb(SshEap eap,
                          SshRadiusClientRequestStatus status,
                          SshRadiusClientRequest request,
                          SshRadiusOperationCode reply_code,
                          void *ctx)
{
  SshPppEap tdata;
  SshPppState gdata;

  tdata = (SshPppEap)ctx;
  gdata = tdata->gdata;

  /* Skip into sshppp_radius library */

  return ssh_ppp_radius_parse_nopayload_reply(gdata, SSH_PPP_AUTH_EAP,
                                              status, request, reply_code);
}

#endif /* SSHDIST_RADIUS */

SSH_FSM_STEP(ssh_eap_server_initial)
{
  SSH_EAP_ENTRY();

  switch(ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_eap_send_identification_request(tdata->eap,
                                   (unsigned char *)"Please identify yourself",
                                   strlen("Please identify yourself"));

      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_server_identity);
      break;
    }
  SSH_EAP_EXIT();
}

SSH_FSM_STEP(ssh_eap_server_identity)
{
  SSH_EAP_ENTRY();

  /* Wait till an identity has been received, pass it through
     the user, and then continue. */

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_IDENTITY_RECV:
      tdata->is_secret_id = 1;
      ssh_ppp_eap_get_secret(gdata, tdata);
      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_PEER_FAIL);
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_server_failure);
      break;

    case SSH_PPP_EVENT_SECRET:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      /* Check whether we are using RADIUS */

#ifdef SSHDIST_RADIUS
      if (gdata->radius_config != NULL
          && tdata->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR
          && gdata->radius_config->eap_radius_config != NULL)
        {
          tdata->is_radius_used = 1;
          ssh_eap_radius_attach(tdata->eap,
                                gdata->radius_config->eap_radius_config);
        }
      else
        {
          tdata->is_radius_used = 0;
          ssh_eap_radius_attach(tdata->eap, NULL);
        }
#endif /* SSHDIST_RADIUS */

      ssh_eap_authenticate(tdata->eap, SSH_EAP_AUTH_CONTINUE);
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_server_request);
      break;
    }

  SSH_EAP_EXIT();
}

SSH_FSM_STEP(ssh_eap_server_request)
{
  SSH_EAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_SECRET:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_eap_input_secret(gdata,tdata);
      break;

    case SSH_PPP_EVENT_AUTH_OK:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_OK);

      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_server_success);
      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_PEER_FAIL);

      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_server_failure);
      break;
    }

  SSH_EAP_EXIT();
}

SSH_FSM_STEP(ssh_eap_server_success)
{
  SSH_EAP_ENTRY();

  /* Eap up events */

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    default:
      break;
    }

  SSH_EAP_EXIT();

}

SSH_FSM_STEP(ssh_eap_server_failure)
{
  SSH_EAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    default:
      break;
    }

  SSH_EAP_EXIT();
}

SSH_FSM_STEP(ssh_eap_client_initial)
{
  SSH_EAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_eap_client_waiting);
      break;
    }

  SSH_EAP_EXIT();
}

SSH_FSM_STEP(ssh_eap_client_waiting)
{
  SshEapTokenStruct token;
  SSH_EAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_IDENTITY_RECV:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      if (tdata->peer_name != NULL)
        {
          ssh_eap_init_token_username(&token,
                                      tdata->peer_name,
                                      tdata->peer_name_length);

          ssh_eap_token(tdata->eap,
                        tdata->eap_type,
                        &token);
        }
      break;

    case SSH_PPP_EVENT_SECRET:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_eap_input_secret(gdata,tdata);
      break;

    case SSH_PPP_EVENT_AUTH_OK:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_OK);

      break;

    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_THIS_FAIL);

      break;


    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
      ssh_ppp_events_signal(ssh_ppp_thread_get_outputq(tdata->ppp_thread),
                            SSH_PPP_EVENT_AUTH_PEER_FAIL);

      break;
    }

  SSH_EAP_EXIT();
}

#endif /* SSHDIST_EAP */
