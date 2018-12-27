/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cisco Simple Certificate Enrollment Protocol (SCEP) implementation.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshfsm.h"
#include "sshurl.h"
#include "sshtcp.h"
#include "sshhttp.h"
#include "sshstream.h"
#include "sshoperation.h"
#include "sshbase64.h"

#include "x509.h"
#include "enroll-internal.h"
#include "enroll-scep.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshPkiEnrollScep"

/* Describe the session this FSM belongs to. Also stores the input
   processor thread and the condition to signal when input is
   available. */
typedef struct SshPkiGlobalDataRec
{
  SshPkiSession    session;
  SshFSMCondition  input_avail;
  SshFSMThread     input_thread;
  SshTimeoutStruct timeout;
} *SshPkiGlobalData;

/* Describe per FSM thread data in the session. Store the packets
   received and send so far. */
typedef struct SshPkiThreadDataRec
{
  SshHttpClientContext http;

  /* Back pointer to the thread running this connection */
  SshFSMThread thread;

  /* State information. */
  Boolean finished;
  SshTime polling_time;

  /* The last received packet. */
  unsigned char *input;
  size_t input_len;

  SshOperationHandle transport_op;
  SshTimeoutStruct timeout;
} *SshPkiThreadData;

static void
  scep_http_stream_callback(SshStreamNotification not, void *context),
  scep_http_receive_data(SshHttpClientContext ctx, SshHttpResult result,
                         SshTcpError ip_error, SshStream stream,
                         void *context),
  scep_timeout_handler(void *context);

SSH_FSM_STEP(scep_connect);
SSH_FSM_STEP(scep_send_initial);
SSH_FSM_STEP(scep_recv_initial);
SSH_FSM_STEP(scep_done);
SSH_FSM_STEP(scep_process_input);
SSH_FSM_STEP(scep_aborted);

static Boolean scep_session_start(SshPkiSession session, SshFSMStepCB state);

/** HTTP TRANSPORT ***********************************************************/
typedef struct ScepHttpReadContextRec
{
  SshStream http_stream;
  SshBuffer input;
  void *upper_context;
} *ScepHttpReadContext;

/* This function reads complete payload from the HTTP stream described
   at the context argument (also the thread running this session is
   identified b the context's upper context), and calls the input
   processing thread when done. This gets called when the CA replies
   to the clients message or poll. */
static void
scep_http_stream_callback(SshStreamNotification not, void *context)
{
  int i;
  unsigned char input[256];
  ScepHttpReadContext c = (ScepHttpReadContext)context;
  SshFSMThread thread = (SshFSMThread) c->upper_context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  while (TRUE)
    {
      i = ssh_stream_read(c->http_stream, input, sizeof(input));
      if (i == 0)
        {
          if ((tdata->input_len = ssh_buffer_len(c->input)) == 0)
            goto error;

          if ((tdata->input =
               ssh_memdup(ssh_buffer_ptr(c->input), tdata->input_len))
              == NULL)
            tdata->input_len = 0;

          ssh_stream_destroy(c->http_stream);
          ssh_buffer_free(c->input);
          ssh_free(c);
          ssh_fsm_continue(gdata->input_thread);
          return;
        }
      else if (i < 0)
        {
          return;
        }
      else
        {
          if (ssh_buffer_append(c->input, input, i) != SSH_BUFFER_OK)
            {
            error:
              ssh_fsm_set_next(thread, scep_aborted);
              tdata->input_len = 0;
              ssh_stream_destroy(c->http_stream);
              ssh_buffer_free(c->input);
              ssh_free(c);
              ssh_fsm_continue(gdata->input_thread);
              return;
            }
        }
    }
}

/* This function gets called from the HTTP library when the HTTP
   client receives response to its request from the server. It starts
   reading the stream. */
static void
scep_http_receive_data(SshHttpClientContext ctx,
                       SshHttpResult result,
                       SshTcpError ip_error,
                       SshStream stream,
                       void *context)
{
  SshFSMThread thread = context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session = gdata->session;

  if (result == SSH_HTTP_RESULT_SUCCESS)
    {
      ScepHttpReadContext c;
      const unsigned char *cp;

      cp = ssh_http_get_header_field(ctx, (unsigned char *)"content-type");
      if (cp == NULL)
        {
          ssh_fsm_set_next(thread, scep_aborted);
          session->status = SSH_PKI_FAILED;
        }
      else
        {
          if (strcmp((char *)cp, "application/x-pki-message") &&
              strcmp((char *)cp, "x-pki-message"))
            {
              ssh_fsm_set_next(thread, scep_aborted);
              session->status = SSH_PKI_FAILED;
            }
        }

      if ((c = ssh_calloc(sizeof(*c), 1)) == NULL)
        goto error;

      c->http_stream = stream;
      c->upper_context = context;
      if ((c->input = ssh_buffer_allocate()) == NULL)
        {
          ssh_free(c);
          goto error;
        }

      tdata->transport_op = NULL;
      ssh_stream_set_callback(stream, scep_http_stream_callback, (void *)c);
      scep_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, (void *)c);
      return;
    }
  else
    {
    error:
      if (result == SSH_HTTP_RESULT_ABORTED && ip_error == SSH_TCP_OK)
        return;

      ssh_fsm_set_next(thread, scep_aborted);
      session->status = SSH_PKI_FAILED;
      if (tdata->transport_op && result == SSH_HTTP_RESULT_SUCCESS)
        {
          ssh_operation_abort(tdata->transport_op);
        }
      tdata->transport_op = NULL;
      ssh_fsm_continue(thread);
      return;
    }
}


/* HTTP/TCP transport independent send ***************************************/
static Boolean
scep_client_srv_send(SshPkiThreadData tdata,
                     const unsigned char *data, size_t len)
{
  SshFSMThread thread = (SshFSMThread)tdata->thread;
  SshFSM fsm = ssh_fsm_get_fsm(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session;
  SshBufferStruct buffer;
  const unsigned char *url;
  char *payload;
  size_t i, payload_len;

  /* Start input processor now. */
  if (!gdata->input_thread)
    {
      if ((gdata->input_thread =
           ssh_fsm_thread_create(fsm,
                                 scep_process_input, NULL_FNPTR, NULL_FNPTR,
                                 NULL))
          == NULL)
        return FALSE;
    }
  session = gdata->session;
  ssh_buffer_init(&buffer);

  if ((payload = (char *)ssh_buf_to_base64(data, len)) == NULL)
    {
      return FALSE;
    }

  if (ssh_buffer_append_cstrs(&buffer,
                              session->access,
                              "?operation=", "PKIOperation",
                              "&message=", NULL) != SSH_BUFFER_OK)
    {
      ssh_free(payload);
      ssh_buffer_uninit(&buffer);
      return FALSE;
    }

  payload_len = strlen(payload) + 1;
  for (i = 0; i < payload_len; i++)
    {
      SshBufferStatus rv;

      if (payload[i] == '+' || payload[i] == '/')
        rv = ssh_buffer_append_cstrs(&buffer,
                                     "%",
                                     (payload[i] == '+') ? "2B" : "2F",
                                     NULL);
      else
        rv = ssh_buffer_append(&buffer, (unsigned char *)&payload[i], 1);

      if (rv != SSH_BUFFER_OK)
        {
          ssh_free(payload);
          ssh_buffer_uninit(&buffer);
          return FALSE;
        }
    }
  ssh_free(payload);
  ssh_buffer_append(&buffer, (unsigned char *)"\0", 1);
  url = ssh_buffer_ptr(&buffer);
  tdata->transport_op =
    ssh_http_get(tdata->http, url,
                 scep_http_receive_data, (void *)tdata->thread,
                 SSH_HTTP_HDR_CONNECTION_CLOSE,
                 SSH_HTTP_HDR_END);

  ssh_buffer_uninit(&buffer);
  return TRUE;
}

/* This function will continue the threads that send
   SSH_PKI_MSG_POLLREQ's after timeouts from the CA have been
   reached. */
static void scep_timeout_handler(void *context)
{
  SshFSMThread thread = (SshFSMThread)context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Received timeout for thread %p", thread));
  ssh_fsm_continue(thread);
}

/* Start connect trial. */
SSH_FSM_STEP(scep_connect)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  unsigned char *scheme, *host, *port;
  SshHttpClientParams params;

  SSH_DEBUG(SSH_D_HIGHSTART, ("open to %s for thread %p",
                              gdata->session->access, thread));

  /* Now find out if to connect using http or tcp, and the version as well. */
  if (ssh_url_parse_and_decode(gdata->session->access,
                               &scheme, &host, &port, NULL, NULL, NULL))
    {
      if (ssh_usstrncasecmp(scheme, "http", 4) == 0)
        {
          ssh_free(scheme);
          memset(&params, 0, sizeof(params));
          params.socks = gdata->session->socks;
          params.http_proxy_url = gdata->session->proxy;
          params.use_http_1_0 = TRUE;
          tdata->http = ssh_http_client_init(&params);

          if (host) ssh_free(host);
          if (port) ssh_free(port);
          SSH_FSM_SET_NEXT(scep_send_initial);
          return SSH_FSM_CONTINUE;
        }
      if (1)
        return SSH_FSM_FINISH;
    }
  else
    return SSH_FSM_FINISH;
}

/* Transition from scep-start to scep-req-sent by composing the PKI
   message and sending it to the CA. */
SSH_FSM_STEP(scep_send_initial)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Sending pkiReq for thread %p", thread));
  session = gdata->session;
  if (scep_client_srv_send(tdata,
                           session->request, session->request_len))
    SSH_FSM_SET_NEXT(scep_recv_initial);
  else
    SSH_FSM_SET_NEXT(scep_aborted);
  return SSH_FSM_CONTINUE;
}

/* Transition from pki-req-send to either polling or final state
   depending on the reponse from CA. */
SSH_FSM_STEP(scep_recv_initial)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session;

  /* Wait here for input from the CA. */
  if (tdata->input_len == 0)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Thread %p Waiting for input", thread));
      SSH_FSM_CONDITION_WAIT(gdata->input_avail);
    }

  SSH_FSM_SET_NEXT(scep_done);

  session = gdata->session;

  session->response_len = tdata->input_len;
  if ((session->response = ssh_memdup(tdata->input, tdata->input_len))
      == NULL)
    session->response_len = 0;

  return SSH_FSM_CONTINUE;
}

static void call_fsm_destroy(void *fsm)
{
  SshPkiGlobalData gdata;

  gdata = ssh_fsm_get_gdata_fsm(fsm);
  if (gdata)
    {
      ssh_fsm_condition_destroy(gdata->input_avail);
      ssh_free(gdata);

    }
  ssh_fsm_destroy((SshFSM)fsm);
}

/* This step outputs the certificate/error reply to the upper level
   and finalizes the state machine. */
SSH_FSM_STEP(scep_done)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiSession session = gdata->session;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enrollment complete (thread %p)", thread));

  session->flags &= ~SSH_ENROLL_RESUMED;
  if (session->done)
    (*session->done)(session->status, session, session->done_context);

  if (!(session->flags & SSH_ENROLL_RESUMED))
    {
    done:
      ssh_pki_session_free(session);
      if (gdata->input_thread)
        {
          ssh_fsm_kill_thread(gdata->input_thread);
          gdata->input_thread = NULL;
        }

      ssh_cancel_timeouts(SSH_ALL_CALLBACKS, fsm);
      ssh_register_timeout(&gdata->timeout,
                           0L, 0L, call_fsm_destroy, (void *)fsm);
      return SSH_FSM_FINISH;
    }
  else
    {
      if ((ssh_time() + session->polling_interval) > session->expire_time)
        goto done;
      ssh_register_timeout(&tdata->timeout,
                           session->polling_interval, 0L, scep_timeout_handler,
                           (void *)thread);
      return SSH_FSM_SUSPENDED;
    }
}

SSH_FSM_STEP(scep_process_input)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Processing input (thread %p) signal", thread));
  SSH_FSM_CONDITION_SIGNAL(gdata->input_avail);
  SSH_FSM_SET_NEXT(scep_process_input);

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(scep_aborted)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Aborting session %p thread %p", gdata->session, thread));

  if (gdata->session->done)
    (*gdata->session->done)(SSH_PKI_ABORTED,
                            gdata->session, gdata->session->done_context);

  ssh_cancel_timeouts(scep_timeout_handler, (void *)thread);
  ssh_pki_session_free(gdata->session);
  if (gdata->input_thread)
    {
      ssh_fsm_kill_thread(gdata->input_thread);
      gdata->input_thread = NULL;
    }
  ssh_register_timeout(&gdata->timeout,
                       0, 0, call_fsm_destroy, (void *)fsm);

  return SSH_FSM_FINISH;
}

static void
scep_linearize_add_message(SshBuffer buffer,
                           const unsigned char *msg_data, size_t msg_len)
{
  size_t n_msgs = 0;

  if (msg_len)
    n_msgs = 1;
  ssh_encode_buffer(buffer, SSH_ENCODE_UINT32(n_msgs), SSH_FORMAT_END);
  if (n_msgs)
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_UINT32_STR(msg_data, msg_len),
                      SSH_FORMAT_END);
}

static void
scep_linearize_get_message(SshBuffer buffer,
                           unsigned char **msg_data, size_t *msg_len)
{
  SshUInt32 n_msgs;

  (void) ssh_decode_buffer(buffer, SSH_DECODE_UINT32(&n_msgs), SSH_FORMAT_END);
  if (n_msgs > 0)
    {
      ssh_decode_buffer(buffer,
                        SSH_DECODE_UINT32_STR(msg_data, msg_len),
                        SSH_FORMAT_END);
    }
  else
    {
      *msg_len = 0;
      *msg_data = NULL;
    }
}

/* Destructor for threads. Cancel all timeouts for this thread. */
static void scep_client_thread_destructor(SshFSM fsm, void *context)
{
  SshPkiThreadData tdata = (SshPkiThreadData)context;

  ssh_free(tdata->input);
  if (tdata->http)
    ssh_http_client_uninit(tdata->http);
  ssh_cancel_timeouts(scep_timeout_handler, (void *)tdata->thread);
  ssh_free(tdata);
}

static Boolean scep_session_start(SshPkiSession session, SshFSMStepCB state)
{
  SshFSM fsm;
  SshFSMThread thread;
  SshPkiThreadData tdata = NULL;
  SshPkiGlobalData gdata = NULL;

  if (!(session->flags & SSH_ENROLL_RESUMED)
      || session->method_context == NULL)
    {
      if ((gdata = ssh_calloc(1, sizeof(*gdata))) == NULL)
        goto failed;

      if ((fsm = ssh_fsm_create(gdata)) == NULL)
        goto failed;

      if ((tdata = ssh_calloc(1, sizeof(*tdata))) == NULL)
        {
          ssh_fsm_destroy(fsm);
          goto failed;
        }

      if ((session->method_context =
           thread = ssh_fsm_thread_create(fsm,
                                          state,
                                          NULL_FNPTR,
                                          scep_client_thread_destructor,
                                          tdata))
          == NULL)
        {
          ssh_fsm_destroy(fsm);
          goto failed;
        }


      tdata->thread = thread;
      tdata->finished = FALSE;

      gdata->input_avail = ssh_fsm_condition_create(fsm);
      gdata->session = session;
      gdata->input_thread = NULL;
    }
  else
    {
      thread = session->method_context;
      SSH_FSM_SET_NEXT(scep_connect);
    }

  return TRUE;
 failed:
  ssh_free(tdata);
  ssh_free(gdata);
  return FALSE;
}


/****************************************************************************
 * The module export these symbols.
 */
SshPkiStatus ssh_pki_scep_session_start(SshPkiSession session)
{
  if (!scep_session_start(session, scep_connect))
    return SSH_PKI_FAILED;
  else
    return SSH_PKI_OK;
}

/* Confirm a PKI exchange. This is pretty similar with start
   actually. The connection is kept open if possible and the state
   machine is started. */
SshPkiStatus ssh_pki_scep_session_confirm(SshPkiSession session)
{
  SshFSMThread thread = (SshFSMThread)session->method_context;

  ssh_fsm_set_next(thread, scep_connect);
  ssh_fsm_continue(thread);

  return SSH_PKI_OK;
}


static void call_fsm_continue(void *thread)
{
  ssh_fsm_continue((SshFSMThread)thread);
}

void ssh_pki_scep_session_finish(SshPkiSession session)
{
  SshFSMThread thread = (SshFSMThread)session->method_context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);

  ssh_fsm_set_next(thread, scep_aborted);
  if (tdata->transport_op)
    {
      ssh_operation_abort(tdata->transport_op);
      tdata->transport_op = NULL;
    }
  ssh_register_timeout(&tdata->timeout,
                       0L, 0L, call_fsm_continue, (void *)thread);
}


Boolean ssh_pki_scep_session_linearize(SshPkiSession session)
{
  ssh_encode_buffer(&session->statebuffer,
                    SSH_ENCODE_UINT32(1),
                    SSH_ENCODE_UINT32_STR(session->access,
                                          ssh_ustrlen(session->access)),
                    SSH_ENCODE_UINT32_STR(session->proxy,
                                          ssh_ustrlen(session->proxy)),
                    SSH_ENCODE_UINT32_STR(session->socks,
                                          ssh_ustrlen(session->socks)),
                    SSH_FORMAT_END);

  scep_linearize_add_message(&session->statebuffer,
                             session->request, session->request_len);
  return TRUE;
}

Boolean ssh_pki_scep_session_delinarize(SshPkiSession session)
{
  SshUInt32 version;

  (void) ssh_decode_buffer(&session->statebuffer,
                           SSH_DECODE_UINT32(&version),
                           SSH_DECODE_UINT32_STR(&session->access, NULL),
                           SSH_DECODE_UINT32_STR(&session->proxy, NULL),
                           SSH_DECODE_UINT32_STR(&session->socks, NULL),
                           SSH_FORMAT_END);
  scep_linearize_get_message(&session->statebuffer,
                             &session->request, &session->request_len);
  return TRUE;
}

/* eof */
#endif /* SSHDIST_CERT */
