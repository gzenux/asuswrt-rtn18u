/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppPap"

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
#include "sshppp_pap.h"

void
ssh_ppp_pap_get_secret(SshPppState gdata, void *ctx)
{
  SshPppEventsOutput out;
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  out = ssh_ppp_thread_get_cb_outputq(pap->ppp_thread);

  ssh_ppp_events_reserve(out);

  switch (pap->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:

      ssh_ppp_get_secret(gdata, pap, SSH_PPP_AUTH_PAP,
                         pap->peer_name_buf, pap->peer_name_length);
      break;
    case SSH_PPP_AUTH_PEER:
      ssh_ppp_get_secret(gdata, pap, SSH_PPP_AUTH_PAP, NULL, 0);
      break;
    }
}

void
ssh_ppp_pap_return_secret(SshPppState gdata,
                          void *ctx,
                          SshUInt8* buf,
                          SshUInt32 length,
                          Boolean isvalid)
{
  SshPppPap pap;
  SshPppEventsOutput op;
  SshPppEvent ev;

  pap = (SshPppPap)ctx;

  op = ssh_ppp_thread_get_cb_outputq(pap->ppp_thread);
  ssh_ppp_events_unreserve(op);

  if (isvalid == FALSE)
    return;

#ifdef SSHDIST_RADIUS
  /* "Re-play" secret, now that we have RADIUS configuration */
  if (gdata->radius_config != NULL
      && pap->auth_mode == SSH_PPP_AUTH_AUTHENTICATOR)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Using RADIUS for PAP authentication"));
      pap->is_radius_used = TRUE;
      ssh_ppp_events_signal(op, SSH_PPP_EVENT_RESPONSE);
      return;
    }
  pap->is_radius_used = FALSE;
#endif /* SSHDIST_RADIUS */

  switch (pap->auth_mode)
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
      ev = SSH_PPP_EVENT_AUTH_PEER_FAIL;

      if (pap->secret_buf != NULL)
        {
          if (pap->secret_length == length
              &&  memcmp(buf, pap->secret_buf, length) == 0)
            {
              ev = SSH_PPP_EVENT_AUTH_OK;
            }

          ssh_ppp_forget_secret(pap->secret_buf, pap->secret_length);
          pap->secret_buf = NULL;
        }
      ssh_ppp_events_signal(op, ev);
      break;
    case SSH_PPP_AUTH_PEER:

      ssh_ppp_events_signal(op, SSH_PPP_EVENT_SECRET);

      ssh_ppp_forget_secret(pap->secret_buf, pap->secret_length);
      pap->secret_buf = NULL;

      if (buf != NULL)
        {
          pap->secret_buf = ssh_malloc(length);

          if (pap->secret_buf == NULL)
            {
              pap->secret_length = 0;
              ssh_ppp_fatal(gdata);
              return;
            }

          memcpy(pap->secret_buf, buf, length);
        }

      pap->secret_length = length;
      break;
    }
}

SshIterationStatus
ssh_ppp_pap_isauthenticator(SshPppPktBuffer pkt)
{
  SshUInt8 code;

  if (ssh_ppp_protocol_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  code = ssh_ppp_protocol_frame_get_code(pkt);

  if (code == SSH_PPP_PAP_CODE_AUTH_REQ)
    {
      return SSH_PPP_OK;
    }

  return SSH_PPP_ERROR;
}

SshIterationStatus
ssh_ppp_pap_isauthenticatee(SshPppPktBuffer pkt)
{
  SshUInt8 code;

  if (ssh_ppp_protocol_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      return SSH_PPP_ERROR;
    }

  code = ssh_ppp_protocol_frame_get_code(pkt);

  if (code == SSH_PPP_PAP_CODE_AUTH_ACK
      || code == SSH_PPP_PAP_CODE_AUTH_NAK)
    {
      return SSH_PPP_OK;
    }

  return SSH_PPP_ERROR;
}

void
ssh_ppp_pap_boot(void* ctx)
{
  SshPppPap tdata;

  tdata = (SshPppPap)ctx;

  ssh_ppp_thread_boot(tdata->ppp_thread);
}

void
ssh_ppp_pap_destroy(void* ctx)
{
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  SSH_DEBUG(SSH_D_MIDOK,("destroying PAP instance %p",ctx));

  ssh_fsm_kill_thread(ssh_ppp_thread_get_thread(pap->ppp_thread));

  ssh_ppp_timer_destroy(ssh_ppp_thread_get_timer(pap->ppp_thread));
  ssh_ppp_flush_del_protocol(ssh_ppp_thread_get_mux(pap->ppp_thread));
  ssh_ppp_thread_destroy(pap->ppp_thread);

  ssh_ppp_forget_secret(pap->secret_buf, pap->secret_length);
  pap->secret_buf = NULL;

#ifdef SSHDIST_RADIUS
  ssh_ppp_radius_uninit(&pap->radius_client);
#endif /* SSHDIST_RADIUS */

  if (pap->peer_name_buf != NULL)
    {
      ssh_free(pap->peer_name_buf);
      pap->peer_name_buf = NULL;
    }

  ssh_free(pap);
}

void*
ssh_ppp_pap_create(SshPppState gdata,
                   SshPppAuthMode mode,
                   SshPppEvents eventq,
                   SshPppFlush output_mux)
{
  SshFSMThread pap_thread;
  SshPppTimer timer;
  SshPppMuxProtocol mux;
  SshPppPap pap;

  pap = ssh_malloc(sizeof(*pap));

  if (pap == NULL)
    return NULL;

  pap_thread = NULL;
  pap->ppp_thread = NULL;
  timer = NULL;
  mux = NULL;

  if (mode == SSH_PPP_AUTH_AUTHENTICATOR)
    {
      SSH_DEBUG(SSH_D_MIDOK,("creating PAP server instance"));
      pap_thread = ssh_fsm_thread_create(gdata->fsm,
                                         ssh_ppp_pap_server_initial,
                                         NULL_FNPTR, NULL_FNPTR, pap);
  }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK,("creating PAP client instance"));
      pap_thread = ssh_fsm_thread_create(gdata->fsm,
                                         ssh_ppp_pap_client_initial,
                                         NULL_FNPTR, NULL_FNPTR, pap);
    }

  if (pap_thread == NULL)
    goto fail;

  pap->peer_name_length = 0;
  pap->peer_name_buf = NULL;
  pap->secret_length = 0;
  pap->secret_buf = NULL;

  ssh_ppp_identifier_init(gdata, &pap->id);
  pap->auth_mode = mode;
  pap->auth_status = SSH_PPP_EVENT_NONE;

  pap->counter = 0;

  pap->ppp_thread = ssh_ppp_thread_create(gdata,pap_thread, eventq, "PAP");

  timer = ssh_ppp_timer_create(pap->ppp_thread);

  mux = ssh_ppp_flush_add_protocol(output_mux,
                                   SSH_PPP_PID_PAP,
                                   pap->ppp_thread,
                                   1024,
                                   (mode == SSH_PPP_AUTH_AUTHENTICATOR ?
                                    ssh_ppp_pap_isauthenticator :
                                    ssh_ppp_pap_isauthenticatee));

  ssh_ppp_thread_attach_timer(pap->ppp_thread, timer);
  ssh_ppp_thread_attach_mux(pap->ppp_thread, mux);

  ssh_ppp_flush_set_output_mru(mux,1024);

#ifdef SSHDIST_RADIUS
  ssh_ppp_radius_init(&pap->radius_client);
  pap->is_radius_used = FALSE;
#endif /* SSHDIST_RADIUS */

  return pap;

 fail:
  if (pap->ppp_thread != NULL)
    ssh_ppp_thread_destroy(pap->ppp_thread);

  return NULL;
}

SshPppEvent
ssh_ppp_pap_get_status(void *ctx)
{
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  return pap->auth_status;
}

SshPppAuthMode
ssh_ppp_pap_get_mode(void *ctx)
{
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  return pap->auth_mode;
}

SshPppEvents
ssh_ppp_pap_get_events(void *ctx)
{
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  return ssh_ppp_thread_get_events(pap->ppp_thread);
}

Boolean
ssh_ppp_pap_set_name(void *ctx,
                     SshUInt8 *buf,
                     unsigned long len)
{
  SshPppPap pap;

  pap = (SshPppPap)ctx;

  if (pap->auth_mode == SSH_PPP_AUTH_PEER)
    {
      if (pap->peer_name_buf != NULL)
        ssh_free(pap->peer_name_buf);

      pap->peer_name_buf = ssh_malloc(len);

      if (pap->peer_name_buf == NULL)
        {
          pap->peer_name_length = 0;
          return FALSE;
        }

      pap->peer_name_length = len;

      memcpy(pap->peer_name_buf, buf, len);
    }
  return TRUE;
}

static void
ssh_ppp_pap_inc_counter(SshPppState gdata, SshPppPap tdata)
{
  tdata->counter++;
}

static void
ssh_ppp_pap_reset_counter(SshPppState gdata, SshPppPap tdata)
{
  tdata->counter = 0;
}

static void
ssh_ppp_pap_reset_timeout_resend(SshPppState gdata, SshPppPap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
  ssh_ppp_timer_set_timeout(timer,2,0);
}

static void
ssh_ppp_pap_cancel_timeout_resend(SshPppState gdata, SshPppPap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
}

static void
ssh_ppp_pap_reset_timeout_auth(SshPppState gdata, SshPppPap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
  ssh_ppp_timer_set_timeout(timer,15,0);
}

static void
ssh_ppp_pap_cancel_timeout_auth(SshPppState gdata, SshPppPap tdata)
{
  SshPppTimer timer = ssh_ppp_thread_get_timer(tdata->ppp_thread);

  ssh_ppp_timer_cancel_timeout(timer);
}


SshPppPktBuffer
ssh_ppp_pap_get_output_buf(SshPppState gdata, SshPppPap pap)
{
  SshPppPktBuffer pkt;
  SshPppMuxProtocolStruct* mux;

  mux = ssh_ppp_thread_get_mux(pap->ppp_thread);

  if (ssh_ppp_flush_output_pkt_isavail(mux) == FALSE)
    return NULL;

  pkt = ssh_ppp_flush_get_output_pkt(mux);

  if (pkt == NULL)
    {
      ssh_ppp_fatal(gdata);
      return NULL;
    }

  SSH_ASSERT(ssh_ppp_pkt_buffer_isempty(pkt));

  ssh_ppp_pkt_buffer_offset(pkt,16);

  return pkt;
}

void
ssh_ppp_pap_output_frame(SshPppState gdata,
                         SshPppPap pap,
                         SshPppPktBuffer pkt,
                         SshUInt8 code,
                         SshUInt8 id)
{
  SshPppMuxProtocol mux;

  ssh_ppp_protocol_frame(pkt,
                         code,
                         ssh_ppp_identifier_get(&pap->id, code));

  mux = ssh_ppp_thread_get_mux(pap->ppp_thread);

  ssh_ppp_flush_send_pkt(gdata, mux);
}

static void
ssh_ppp_pap_output_auth_req(SshPppState gdata, SshPppPap tdata)
{
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_pap_get_output_buf(gdata, tdata);

  ssh_ppp_pkt_buffer_append_uint8(pkt,
                                       (SshUInt8)tdata->peer_name_length);

  if (tdata->peer_name_buf != NULL)
    {
      ssh_ppp_pkt_buffer_append_buf(pkt,
                                    tdata->peer_name_buf,
                                    tdata->peer_name_length);
  }

  ssh_ppp_pkt_buffer_append_uint8(pkt,(SshUInt8)tdata->secret_length);


  if (tdata->secret_buf != NULL)
    {
      ssh_ppp_pkt_buffer_append_buf(pkt,
                                    tdata->secret_buf,
                                    tdata->secret_length);
    }

  ssh_ppp_forget_secret(tdata->secret_buf,tdata->secret_length);
  tdata->secret_buf = NULL;

  ssh_ppp_pap_output_frame(gdata,
                           tdata,
                           pkt,
                           SSH_PPP_PAP_CODE_AUTH_REQ,
                           ssh_ppp_identifier_get(&tdata->id,
                                                  SSH_PPP_PAP_CODE_AUTH_REQ));
}

static void
ssh_ppp_pap_output_auth_ack(SshPppState gdata, SshPppPap tdata)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_pap_get_output_buf(gdata, tdata);

  ssh_ppp_pkt_buffer_append_uint8(pkt,0);

  id = ssh_ppp_identifier_get(&tdata->id,
                              SSH_PPP_PAP_CODE_AUTH_NAK);

  SSH_DEBUG(SSH_D_MIDOK,("sending pap auth ack id = %d",id));

  ssh_ppp_pap_output_frame(gdata,
                           tdata,
                           pkt,
                           SSH_PPP_PAP_CODE_AUTH_ACK,
                           id);

}

static void
ssh_ppp_pap_output_auth_nak(SshPppState gdata, SshPppPap tdata)
{
  SshPppPktBuffer pkt;
  SshUInt8 id;

  pkt = ssh_ppp_pap_get_output_buf(gdata, tdata);

  ssh_ppp_pkt_buffer_append_uint8(pkt,0);

  id = ssh_ppp_identifier_get(&tdata->id,
                              SSH_PPP_PAP_CODE_AUTH_NAK);

  SSH_DEBUG(SSH_D_MIDOK,("sending pap auth nak id = %d",id));

  ssh_ppp_pap_output_frame(gdata,
                           tdata,
                           pkt,
                           SSH_PPP_PAP_CODE_AUTH_NAK,
                           id);
}

static SshPppEvent
ssh_ppp_pap_input_req(SshPppState gdata, SshPppPap tdata)
{
  SshPppPktBufferStruct buf;
  SshPppPktBuffer pkt;
  SshUInt8 id;
  SshUInt8 peer_id_len;
  SshUInt8 passwd_len;

  /* New authentication round beginning, destroy any leftovers */

  if (tdata->peer_name_buf != NULL)
    {
      ssh_free(tdata->peer_name_buf);
      tdata->peer_name_buf = NULL;
      tdata->peer_name_length = 0;
    }

  if (tdata->secret_buf != NULL)
    {
      ssh_free(tdata->secret_buf);
      tdata->secret_buf = NULL;
      tdata->secret_length = 0;
    }

  /* Check packet validity */

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);
  pkt = ssh_ppp_pkt_buffer_save(&buf,pkt);

  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_MIDOK,("received pap auth req id = %d",id));

  ssh_ppp_protocol_skip_hdr(pkt);

  ssh_ppp_identifier_mark(&tdata->id, SSH_PPP_PAP_CODE_AUTH_REQ, id);

  /* Store peer name */

  if (ssh_ppp_pkt_buffer_get_contentlen(pkt) < 1)
    {
      SSH_DEBUG(SSH_D_NETGARB,("PAP authentication request corrupted"));
      return SSH_PPP_EVENT_NONE;
    }

  peer_id_len = ssh_ppp_pkt_buffer_get_uint8(pkt,0);

  ssh_ppp_pkt_buffer_skip(pkt,1);

  if (peer_id_len > ssh_ppp_pkt_buffer_get_contentlen(pkt))
    {
      SSH_DEBUG(SSH_D_NETGARB,("PAP authentication request corrupted"));
      return SSH_PPP_EVENT_NONE;
    }

  tdata->peer_name_buf = ssh_malloc(peer_id_len);

  if (tdata->peer_name_buf == NULL)
    {
      tdata->peer_name_length = 0;
      ssh_ppp_fatal(gdata);
      return SSH_PPP_EVENT_NONE;
    }


  tdata->peer_name_length = peer_id_len;

  memcpy(tdata->peer_name_buf,
         ssh_ppp_pkt_buffer_get_ptr(pkt, 0, peer_id_len),
         tdata->peer_name_length);


  ssh_ppp_pkt_buffer_skip(pkt,peer_id_len);

  /* Store peer passwd */

  if (ssh_ppp_pkt_buffer_get_contentlen(pkt) < 1)
    {
      SSH_DEBUG(SSH_D_NETGARB,("PAP authentication request corrupted"));
      return SSH_PPP_EVENT_NONE;
    }

  passwd_len = ssh_ppp_pkt_buffer_get_uint8(pkt,0);

  ssh_ppp_pkt_buffer_skip(pkt,1);

  if (passwd_len > ssh_ppp_pkt_buffer_get_contentlen(pkt))
    {
      SSH_DEBUG(SSH_D_NETGARB,("PAP authentication request corrupted"));
      return SSH_PPP_EVENT_NONE;
    }

  tdata->secret_buf = ssh_malloc(passwd_len);

  if (tdata->secret_buf == NULL)
    {
      tdata->secret_length = 0;
      ssh_ppp_fatal(gdata);
      return SSH_PPP_EVENT_NONE;
    }

  tdata->secret_length = passwd_len;

  memcpy(tdata->secret_buf,
         ssh_ppp_pkt_buffer_get_ptr(pkt, 0, passwd_len),
         tdata->secret_length);

  /* Signal thread with event */

  SSH_DEBUG(SSH_D_MIDOK,("received PAP authentication request"));

  return SSH_PPP_EVENT_RESPONSE;
}

static SshPppEvent
ssh_ppp_pap_input_ack(SshPppState gdata, SshPppPap tdata)
{
  SshUInt8 id;
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_MIDOK,("received pap auth ack id = %d",id));

  if (ssh_ppp_identifier_ismatch(&tdata->id,
                                 SSH_PPP_PAP_CODE_AUTH_REQ,
                                 id) == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB,("authentication ACK identifier mismatch"));
      return SSH_PPP_EVENT_NONE;
    }

  SSH_DEBUG(SSH_D_MIDOK,("received PAP authentication ACK"));
  return SSH_PPP_EVENT_AUTH_OK;
}

static SshPppEvent
ssh_ppp_pap_input_nak(SshPppState gdata, SshPppPap tdata)
{
  SshUInt8 id;
  SshPppPktBuffer pkt;

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);
  id = ssh_ppp_protocol_frame_get_id(pkt);

  SSH_DEBUG(SSH_D_MIDOK,("received pap auth nak id = %d",id));

  if (ssh_ppp_identifier_ismatch(&tdata->id,
                                 SSH_PPP_PAP_CODE_AUTH_REQ,
                                 id) == FALSE)
    {

      SSH_DEBUG(SSH_D_NETGARB,("authentication NAK identifier mismatch"));
      return SSH_PPP_EVENT_NONE;
    }

  SSH_DEBUG(SSH_D_MIDOK,("received PAP authentication NAK"));
  return SSH_PPP_EVENT_AUTH_THIS_FAIL;
}

static SshPppEvent
ssh_ppp_pap_input(SshPppState gdata, SshPppPap tdata)
{
  SshPppPktBuffer pkt;
  SshUInt8 code;

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  if (ssh_ppp_protocol_frame_isvalid(pkt) != SSH_PPP_OK)
    {
      SSH_DEBUG(SSH_D_NETGARB,("PAP frame is not valid, discarding"));
      return SSH_PPP_EVENT_NONE;
    }

  code = ssh_ppp_protocol_frame_get_code(pkt);

  switch (code)
    {
    case SSH_PPP_PAP_CODE_AUTH_REQ:
      return ssh_ppp_pap_input_req(gdata,tdata);
    case SSH_PPP_PAP_CODE_AUTH_ACK:
      return ssh_ppp_pap_input_ack(gdata,tdata);
    case SSH_PPP_PAP_CODE_AUTH_NAK:
      return ssh_ppp_pap_input_nak(gdata,tdata);
    default:
      SSH_DEBUG(SSH_D_NETGARB,("unknown PAP code %d received!",code));
    }
  return SSH_PPP_EVENT_NONE;
}

static void
ssh_ppp_pap_handle_events(SshPppState gdata, SshPppPap tdata)
{
  SshPppEvent ev;
  SshPppPktBuffer pkt;

  /* Handle timeouts */

  ev = ssh_ppp_thread_get_event(gdata, tdata->ppp_thread);

  if (ev == SSH_PPP_EVENT_TIMEOUT)
    {
      ssh_ppp_pap_inc_counter(gdata,tdata);

      ev = ( tdata->counter > SSH_PPP_PAP_RESEND_MAX ?
             SSH_PPP_EVENT_TOMINUS : SSH_PPP_EVENT_TOPLUS);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
      return;
    }

  if (ev != SSH_PPP_EVENT_NONE)
    {
      return;
    }

  pkt = ssh_ppp_thread_get_input_pkt(tdata->ppp_thread);

  if (pkt == NULL)
    {
      return;
    }

  if (ssh_ppp_protocol_frame_isvalid(pkt) == SSH_PPP_OK)
    {
      ssh_ppp_protocol_frame_strip_pad(pkt);

      ev = ssh_ppp_pap_input(gdata,tdata);

      ssh_ppp_thread_set_event(tdata->ppp_thread, ev);
    }
  return;
}

#ifdef SSHDIST_RADIUS
void
ssh_ppp_pap_radius_cb(SshPppState gdata,
                      void *auth_state,
                      SshRadiusClientRequestStatus status,
                      SshRadiusClientRequest request,
                      SshRadiusOperationCode reply_code)
{
  SshPppPap pap;
  Boolean auth_ok;
  SshPppEventsOutput op;

  pap = (SshPppPap)auth_state;

  /* OperationHandle is void when callback hits */
  pap->radius_client.radius_handle = NULL;

  SSH_ASSERT(request == pap->radius_client.radius_req);

  auth_ok = ssh_ppp_radius_parse_nopayload_reply(gdata, SSH_PPP_AUTH_PAP,
                                                 status, request, reply_code);

  ssh_radius_client_request_destroy(request);
  pap->radius_client.radius_req = NULL;

  op = ssh_ppp_thread_get_cb_outputq(pap->ppp_thread);

  ssh_ppp_events_signal(op, (SshPppEvent)(auth_ok==TRUE
                             ?SSH_PPP_EVENT_AUTH_OK
                             :SSH_PPP_EVENT_AUTH_PEER_FAIL));


}
#endif /* SSHDIST_RADIUS */

SSH_FSM_STEP(ssh_ppp_pap_server_initial)
{
  SshPppEventsOutput out;

  SSH_PAP_ENTRY();

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      /* Set total authentication timeout */
      ssh_ppp_pap_reset_timeout_auth(gdata, tdata);
      break;

    case SSH_PPP_EVENT_RESPONSE:
#ifdef SSHDIST_RADIUS
      if (tdata->is_radius_used == TRUE)
        {



          if (tdata->radius_client.radius_req != NULL)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("There is already an ongoing PAP query"));
            }
          else
            {
              if (ssh_ppp_radius_make_pap_query(gdata,
                                             &tdata->radius_client,
                                             tdata->peer_name_buf,
                                             (SshUInt8)tdata->peer_name_length,
                                             tdata->secret_buf,
                                             (SshUInt8)tdata->secret_length)
                  == FALSE)
                {
                  ssh_ppp_fatal(gdata);
                }
            }
          break;
        }
#endif /* SSHDIST_RADIUS */
      ssh_ppp_pap_get_secret(gdata, tdata);
      break;

    case SSH_PPP_EVENT_AUTH_OK:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_pap_cancel_timeout_auth(gdata, tdata);

      if (tdata->auth_status != SSH_PPP_EVENT_AUTH_OK)
        {
          tdata->auth_status = SSH_PPP_EVENT_AUTH_OK;
          ssh_ppp_server_auth_ok(gdata);
          ssh_ppp_events_signal(out, SSH_PPP_EVENT_AUTH_OK);
          ssh_ppp_pap_output_auth_ack(gdata,tdata);
        }
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_ppp_pap_server_done);
      break;

      /* Note that in PAP, PAP failure messages cannot be sent
         in response to timeouts.. */

    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);
      if (tdata->auth_status != SSH_PPP_EVENT_AUTH_PEER_FAIL)
        {
          ssh_ppp_pap_output_auth_nak(gdata,tdata);
        }

      /* These timeouts are the total authentication timeout failing,
         not a resend timeouts */

    case SSH_PPP_EVENT_TOPLUS:
    case SSH_PPP_EVENT_TOMINUS:

      if (tdata->auth_status != SSH_PPP_EVENT_AUTH_PEER_FAIL)
        {
          tdata->auth_status = SSH_PPP_EVENT_AUTH_PEER_FAIL;
          ssh_ppp_pap_cancel_timeout_auth(gdata, tdata);
          ssh_ppp_server_auth_fail(gdata);
          ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_PEER_FAIL);
        }
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_ppp_pap_server_done);

      break;

    }

  SSH_PAP_EXIT();
}

SSH_FSM_STEP(ssh_ppp_pap_server_done)
{
  SSH_PAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    default:
      break;
    }

  SSH_PAP_EXIT();
}

SSH_FSM_STEP(ssh_ppp_pap_client_initial)
{
  SSH_PAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    case SSH_PPP_EVENT_OPEN:
      /* Request secret */
      ssh_ppp_pap_get_secret(gdata, tdata);
      break;

    case SSH_PPP_EVENT_SECRET:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_ppp_pap_client_running);

      ssh_ppp_pap_reset_counter(gdata, tdata);
      ssh_ppp_pap_reset_timeout_resend(gdata, tdata);
      ssh_ppp_pap_output_auth_req(gdata,tdata);

      break;
    }

  SSH_PAP_EXIT();
}

SSH_FSM_STEP(ssh_ppp_pap_client_running)
{
  SshPppEventsOutput out;

  SSH_PAP_ENTRY();

  out = ssh_ppp_thread_get_outputq(tdata->ppp_thread);

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {

    case SSH_PPP_EVENT_AUTH_OK:
      tdata->auth_status = SSH_PPP_EVENT_AUTH_OK;
      ssh_ppp_client_auth_ok(gdata);
      ssh_ppp_pap_cancel_timeout_resend(gdata, tdata);
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_ppp_pap_client_done);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_OK);
      break;

    case SSH_PPP_EVENT_TOMINUS:
    case SSH_PPP_EVENT_AUTH_PEER_FAIL:
    case SSH_PPP_EVENT_AUTH_THIS_FAIL:
      tdata->auth_status = SSH_PPP_EVENT_AUTH_THIS_FAIL;
      ssh_ppp_client_auth_fail(gdata);
      ssh_ppp_pap_cancel_timeout_resend(gdata, tdata);
      ssh_fsm_set_next(ssh_ppp_thread_get_thread(tdata->ppp_thread),
                       ssh_ppp_pap_client_done);
      ssh_ppp_events_signal(out,SSH_PPP_EVENT_AUTH_THIS_FAIL);
      break;

    case SSH_PPP_EVENT_TOPLUS:
      SSH_PPP_THREAD_IO_BLOCK(tdata->ppp_thread);

      ssh_ppp_pap_output_auth_req(gdata,tdata);
      break;
    }

  SSH_PAP_EXIT();
}

SSH_FSM_STEP(ssh_ppp_pap_client_done)
{
  SSH_PAP_ENTRY();

  switch (ssh_ppp_thread_get_event(gdata, tdata->ppp_thread))
    {
    default:
      break;
    }

  SSH_PAP_EXIT();
}
