/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RFC2510 based enrollment protocol augmented with docs
   draft-ietf-pkix-cmp-tcp-00.txt
   draft-ietf-pkix-cmp-http-00.txt
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshfsm.h"
#include "sshurl.h"
#include "sshtcp.h"
#include "sshhttp.h"
#include "sshstream.h"
#include "sshpacketstream.h"
#include "sshoperation.h"

#include "x509.h"
#include "enroll-internal.h"
#include "enroll-pkix.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshPkiEnrollPkix"

/* Describe the session this FSM belongs to. Also stores the input
   processor thread and the condition to signal when input is
   available. */
typedef struct SshPkiGlobalDataRec
{
  SshPkiSession    session;
  SshFSMCondition  input_avail;
  SshFSMThread     input_thread;
  SshTimeoutStruct timeout;
  Boolean          user_aborted;
} *SshPkiGlobalData;

/* Describe per FSM thread data in the session. Store the packets
   received and send so far. */
typedef struct SshPkiThreadDataRec
{
  /* Connection information. Either one is NULL. */
  SshPacketWrapper     wrapper;
  SshHttpClientContext http;

  /* Back pointer to the thread running this connection */
  SshFSMThread thread;

  /* State information. */
  Boolean finished;
  SshUInt32 polling_id;
  SshTime polling_time;

  /* The last received packet. */
  SshPkiTcpProtoMessage input_type;
  SshUInt8 input_version;
  SshUInt8 input_flags;
  unsigned char *input;
  size_t input_len;
  SshOperationHandle transport_op;

  SshTimeoutStruct timeout;
  Boolean timeout_set;
} *SshPkiThreadData;

static void
  pkix_http_stream_callback(SshStreamNotification not, void *context),
  pkix_http_receive_data(SshHttpClientContext ctx, SshHttpResult result,
                         SshTcpError ip_error, SshStream stream,
                         void *context),
  pkix_tcp_kill_input(SshFSMThread thread),
  pkix_tcp_connect_callback(SshTcpError error, SshStream stream,
                            void *context),
  pkix_tcp_receive_data(SshPacketType type,
                        const unsigned char *data, size_t len, void *context),
  pkix_tcp_receive_eof(void *context),
  pkix_timeout_handler(void *context);

SSH_FSM_STEP(pkix_connect);
SSH_FSM_STEP(pkix_send_initial);
SSH_FSM_STEP(pkix_recv_initial);
SSH_FSM_STEP(pkix_done);
SSH_FSM_STEP(pkix_send_subsequent);
SSH_FSM_STEP(pkix_process_input);
SSH_FSM_STEP(pkix_aborted);

/** HTTP TRANSPORT ***********************************************************/
typedef struct PkixHttpReadContextRec
{
  SshStream http_stream;
  SshBuffer input;
  void *upper_context;
} *PkixHttpReadContext;

/* This function reads complete payload from the HTTP stream described
   at the context argument (also the thread running this session is
   identified b the context's upper context), and calls the input
   processing thread when done. This gets called when the CA replies
   to the clients message or poll. */
static void
pkix_http_stream_callback(SshStreamNotification not, void *context)
{
  int i;
  size_t len;
  SshUInt8 type_or_version;
  unsigned char input[256], *data;
  PkixHttpReadContext c = (PkixHttpReadContext)context;
  SshFSMThread thread = (SshFSMThread) c->upper_context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  while (TRUE)
    {
      i = ssh_stream_read(c->http_stream, input, sizeof(input));
      if (i == 0)
        {
          if ((len = ssh_buffer_len(c->input)) > 5)
            {
              data = ssh_buffer_ptr(c->input);
              len = SSH_GET_32BIT(data);
              type_or_version = data[4];

              if (type_or_version < 10)
                {
                  tdata->input_version = SSH_PKI_VERSION_0;
                  tdata->input_flags = 0;
                  tdata->input_type = type_or_version;
                  tdata->input_len = len - 1;
                  tdata->input = ssh_memdup(data + 5, tdata->input_len);
                }
              else
                {
                  if (type_or_version == 10)
                    {
                      data += 4; /* skip to end of length */
                      tdata->input_version = SSH_PKI_VERSION_1;
                      tdata->input_len = len - 3;
                      tdata->input_flags = data[1];
                      tdata->input_type  = data[2];
                      data += 3;
                      tdata->input = ssh_memdup(data, tdata->input_len);
                    }
                  else
                    {
                      tdata->input_version = type_or_version;
                      tdata->input_type = SSH_PKI_MSG_ERRORREP;
                    }
                }

              if (tdata->input == NULL)
                tdata->input_type = SSH_PKI_MSG_ERRORREP;

              ssh_buffer_free(c->input);
              ssh_stream_destroy(c->http_stream);
              ssh_fsm_continue(gdata->input_thread);
              ssh_free(c);
              return;
            }
          else
            {
            error:
              tdata->input_type = SSH_PKI_MSG_ERRORREP;
              ssh_fsm_set_next(thread, pkix_aborted);
              ssh_fsm_continue(gdata->input_thread);
              ssh_stream_destroy(c->http_stream);
              ssh_buffer_free(c->input);
              ssh_free(c);
              return;
            }
        }
      else if (i < 0)
        {
          return;
        }
      else
        {
          if (ssh_buffer_append(c->input, input, i) != SSH_BUFFER_OK)
            {
              goto error;
            }
        }

    }
}

static void
pkix_http_receive_data_operate(SshHttpClientContext ctx,
                               SshHttpResult result,
                               SshTcpError ip_error,
                               SshStream stream,
                               void *context)
{
  PkixHttpReadContext c = (PkixHttpReadContext)ssh_malloc(sizeof(*c));
  SshFSMThread thread = (SshFSMThread)context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  tdata->transport_op = NULL;
  if (c && result == SSH_HTTP_RESULT_SUCCESS)
    {
      c->http_stream = stream;
      c->upper_context = context;
      if ((c->input = ssh_buffer_allocate()) != NULL)
        {
          ssh_stream_set_callback(stream,
                                  pkix_http_stream_callback, (void *)c);
          pkix_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, (void *)c);
          return;
        }
    }
  ssh_free(c);
  tdata->input_type = SSH_PKI_MSG_ERRORREP;
  tdata->input_len = 1;
  ssh_fsm_continue(gdata->input_thread);
}


/* This function gets called from the HTTP library when the HTTP
   client receives response to its request from the server. It starts
   reading the stream. */
static void
pkix_http_receive_data(SshHttpClientContext ctx,
                       SshHttpResult result,
                       SshTcpError ip_error,
                       SshStream stream,
                       void *context)
{
  if (result == SSH_HTTP_RESULT_ABORTED)
    {
      /* This callback is called with http aborted status
         when enrollment has been aborted. Session has already
         been clean-up and so we must return. */
      return;
    }
  else
    {
      /* Operate the response normally. */
      pkix_http_receive_data_operate(ctx, result, ip_error, stream, context);
      return;
    }
}

/** TCP TRANSPORT ************************************************************/

static void
pkix_tcp_receive_data(SshPacketType type,
                      const unsigned char *data, size_t len,
                      void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("thread %p %zd bytes from CA", thread, len));

  if (type < 10)
    {
      tdata->input_version = SSH_PKI_VERSION_0;
      tdata->input_flags = 0;
      tdata->input_type = type;
      tdata->input_len = len;
      tdata->input = ssh_memdup(data, len);
    }
  else
    {
      switch (type)
        {
        case 10:
          tdata->input_version = SSH_PKI_VERSION_1;
          tdata->input_flags = data[0];
          tdata->input_type = data[1];
          tdata->input_len = len - 2;
          tdata->input = ssh_memdup(data + 2, tdata->input_len);
          break;
        default:
          return;
        }
    }

  if (tdata->input == NULL)
    tdata->input_type = SSH_PKI_MSG_ERRORREP;

  SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                    ("DATA %d bytes", tdata->input_len),
                    tdata->input, tdata->input_len);
  ssh_fsm_continue(gdata->input_thread);
}

static void
pkix_tcp_receive_eof(void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);

  ssh_packet_wrapper_destroy(tdata->wrapper);
  tdata->wrapper = NULL;
  SSH_DEBUG(SSH_D_HIGHOK, ("Received EOF from CA for thread %p", thread));
}

/* This function is called by the transport library when the CA has
   been connected, or the connection has failed. The `error' indicates
   the reason. This starts a thread to process the client initiated
   enrollment. */
static void
pkix_tcp_connect_callback(SshTcpError error, SshStream stream, void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("thread %p connected error %d", thread, error));
  if (error == SSH_TCP_OK)
    {
      tdata->wrapper =
        ssh_packet_wrap(stream,
                        pkix_tcp_receive_data, pkix_tcp_receive_eof,
                        NULL_FNPTR,
                        context);

      if (tdata->polling_id == 0)
        SSH_FSM_SET_NEXT(pkix_send_initial);
      else
        SSH_FSM_SET_NEXT(pkix_send_subsequent);
    }
  else
    {
      SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
      SshPkiSession session = gdata->session;

      session->status = SSH_PKI_FAILED;
      SSH_FSM_SET_NEXT(pkix_done);
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
pkix_tcp_kill_input(SshFSMThread thread)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Deleting wrapper and timeouts for thread %p conn=%p",
             thread, tdata->http));

  ssh_cancel_timeouts(pkix_timeout_handler, (void *)thread);
  tdata->timeout_set = FALSE;
  if (tdata->wrapper)
    {
      ssh_packet_wrapper_destroy(tdata->wrapper);
      tdata->wrapper = NULL;
    }
  if (tdata->http)
    {
      ssh_http_client_uninit(tdata->http);
      tdata->http = NULL;
    }
  if (gdata->input_thread)
    {
      ssh_fsm_kill_thread(gdata->input_thread);
      gdata->input_thread = NULL;
    }
}

/* HTTP/TCP transport independent send ***************************************/
static Boolean
pkix_client_srv_send(SshPkiThreadData tdata,
                     SshPkiTcpProtoVersion v, SshUInt32 flags,
                     SshPkiTcpProtoMessage type,
                     const unsigned char *data, size_t len)
{
  SshFSMThread thread = (SshFSMThread)tdata->thread;
  SshFSM fsm = ssh_fsm_get_fsm(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  size_t out_len;
  unsigned char *out;

  /* Start input processor now. */
  if (!gdata->input_thread)
    gdata->input_thread = ssh_fsm_thread_create(fsm,
                                                pkix_process_input,
                                                NULL_FNPTR, NULL_FNPTR,
                                                NULL);

  /* If it is a TCP or HTTP... */
  if (!tdata->http)
    {
      if (tdata->wrapper)
        {
          switch (v)
            {
            case SSH_PKI_VERSION_1:
              out_len = len + 2;
              out = ssh_malloc(out_len);
              if (out)
                {
                  out[0] = (unsigned char) flags;
                  out[1] = (unsigned char) type;
                  memmove(out + 2, data, len);
                  ssh_packet_wrapper_send(tdata->wrapper, v, out, out_len);
                  ssh_free(out);
                }
              break;
            case SSH_PKI_VERSION_0:
              ssh_packet_wrapper_send(tdata->wrapper, type, data, len);
            default:
              return FALSE;
            }
        }
      else
        {
          /* Trying to send to closed; reopen. */
          ssh_fsm_set_next(thread, pkix_connect);
          return TRUE;
        }
    }
  else
    {
      switch (v)
        {
        case SSH_PKI_VERSION_1:
          out_len = len + 7;
          out = ssh_malloc(out_len);
          if (out)
            {
              SSH_PUT_32BIT(out, out_len - 4);
              out[4] = v;
              out[5] = (unsigned char)flags;
              out[6] = (unsigned char)type;
              memmove(out + 7, data, len);
            }
          break;
        case SSH_PKI_VERSION_0:
          out_len = len + 5;
          out = ssh_malloc(out_len);
          if (out)
            {
              SSH_PUT_32BIT(out, out_len - 4);
              out[4] = (unsigned char)type;
              memmove(out + 5, data, len);
            }
          break;
        default:
          return FALSE;
        }
      if (out)
        {
          tdata->transport_op =
            ssh_http_post(tdata->http,
                          gdata->session->access, out, out_len,
                          pkix_http_receive_data, (void *)tdata->thread,
                          SSH_HTTP_HDR_END);
          ssh_free(out);
        }
    }
  return TRUE;
}

static Boolean
pkix_client_srv_close(SshPkiThreadData tdata)
{
  if (tdata->wrapper)
    {
      ssh_packet_wrapper_destroy(tdata->wrapper);
      tdata->wrapper = NULL;
    }
  return TRUE;
}
/* This function will continue the threads that send
   SSH_PKI_MSG_POLLREQ's after timeouts from the CA have been
   reached. */
static void pkix_timeout_handler(void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("Received timeout for thread %p", thread));
  tdata->timeout_set = FALSE;
  ssh_fsm_continue(thread);
}


/* Start connect trial. */
SSH_FSM_STEP(pkix_connect)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  unsigned char *scheme, *host, *port;
  SshHttpClientParams params;

  SSH_DEBUG(SSH_D_HIGHOK, ("open to %s for thread %p",
                              gdata->session->access, thread));

  if (gdata->session->stream)
    {
      SSH_FSM_ASYNC_CALL(
        pkix_tcp_connect_callback(SSH_TCP_OK, gdata->session->stream,
                                  (void *) thread);
      );
      return SSH_FSM_CONTINUE;
    }

  if (tdata->wrapper || tdata->http)
    {
      SSH_FSM_SET_NEXT(pkix_send_initial);
      return SSH_FSM_CONTINUE;
    }

  /* Now find out if to connect using http or tcp, and the version as well. */
  if (ssh_url_parse_and_decode(gdata->session->access,
                               &scheme, &host, &port, NULL, NULL, NULL))
    {
      if (ssh_usstrncasecmp(scheme, "tcp", 3) == 0)
        {
          SshTcpConnectParamsStruct tcp_connect_params;
          memset(&tcp_connect_params, 0, sizeof(tcp_connect_params));
          tcp_connect_params.socks_server_url = gdata->session->socks;

          ssh_free(scheme);
          if (port == NULL) port = ssh_strdup("829");
          SSH_FSM_ASYNC_CALL(
            ssh_tcp_connect(host, port, -1, 0, &tcp_connect_params,
                            pkix_tcp_connect_callback,
                            (void *)thread);
            if (host) ssh_free(host);
            if (port) ssh_free(port);
          );
          /* ASYNC-CALL returns here */
        }
      if (ssh_usstrncasecmp(scheme, "http", 4) == 0)
        {
          ssh_free(scheme);
          memset(&params, 0, sizeof(params));
          params.socks = gdata->session->socks;
          params.http_proxy_url = gdata->session->proxy;
          if (!tdata->http)
            tdata->http = ssh_http_client_init(&params);

          if (host) ssh_free(host);
          if (port) ssh_free(port);
          if (tdata->polling_id == 0)
            SSH_FSM_SET_NEXT(pkix_send_initial);
          else
            SSH_FSM_SET_NEXT(pkix_send_subsequent);
          return SSH_FSM_CONTINUE;
        }
      if (1)
        return SSH_FSM_FINISH;
    }
  else
    return SSH_FSM_FINISH;
}

/* Transition from pkix-start to pkix-req-sent by composing the PKI
   message and sending it to the CA. */
SSH_FSM_STEP(pkix_send_initial)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session;

  SSH_DEBUG(SSH_D_HIGHOK, ("Sending pkiReq for thread %p", thread));
  session = gdata->session;

  if (tdata->input_flags & 0x1)
    pkix_client_srv_close(tdata);

  SSH_FSM_SET_NEXT(pkix_recv_initial);

  pkix_client_srv_send(tdata,
                       session->version, 1L, SSH_PKI_MSG_PKIREQ,
                       session->request, session->request_len);

  if (session->flags & SSH_ENROLL_CONFIRMED)
    {
      session->status = SSH_PKI_OK;
      session->flags &= ~SSH_ENROLL_CONFIRMED;
      SSH_FSM_SET_NEXT(pkix_done);
    }

  return SSH_FSM_CONTINUE;
}

/* Transition from pki-req-send to either polling or final state
   depending on the reponse from CA. */
SSH_FSM_STEP(pkix_recv_initial)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  signed int pollwhen;
  SshPkiSession session;

  session = gdata->session;
  /* Wait here for input from the CA. */
  if (tdata->input_type != SSH_PKI_MSG_ERRORREP)
    {
      if (tdata->input_len == 0)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Thread %p Waiting for input", thread));
          SSH_FSM_CONDITION_WAIT(gdata->input_avail);
        }
    }
  SSH_DEBUG(SSH_D_HIGHOK,
            ("Received %s for thread %p",
             (tdata->input_type == SSH_PKI_MSG_PKIREP)  ? "pkiRep":
             (tdata->input_type == SSH_PKI_MSG_POLLREP) ? "pollRep":
             (tdata->input_type == SSH_PKI_MSG_ERRORREP)? "errorRep": "?",
             thread));

  switch (tdata->input_type)
    {
    case SSH_PKI_MSG_PKIREP:
      SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                        ("PkiRep %d bytes", tdata->input_len),
                        tdata->input, tdata->input_len);
      SSH_FSM_SET_NEXT(pkix_done);
      if (session->response)
        ssh_free(session->response);

      /* Steal tdata->input */
      session->response = tdata->input;
      session->response_len = tdata->input_len;
      session->status = SSH_PKI_OK;
      tdata->input_len = 0;
      return SSH_FSM_CONTINUE;

    case SSH_PKI_MSG_ERRORREP:
      SSH_DEBUG(SSH_D_UNCOMMON,("ErrorRep"));

      if (session->version == SSH_PKI_VERSION_1 &&
          tdata->input_version < SSH_PKI_VERSION_1)
        {
          session->version = SSH_PKI_VERSION_0;
          SSH_FSM_SET_NEXT(pkix_send_initial);
        }
      else
        {
          session->status = SSH_PKI_FAILED;
          SSH_FSM_SET_NEXT(pkix_done);
        }

      ssh_free(tdata->input);
      tdata->input_len = 0;
      return SSH_FSM_CONTINUE;

    case SSH_PKI_MSG_POLLREP:
      SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                        ("PollRep %d bytes", tdata->input_len),
                        tdata->input, tdata->input_len);

      tdata->polling_id   = SSH_GET_32BIT(tdata->input + 0);
      tdata->polling_time = (SshTime)SSH_GET_32BIT(tdata->input + 4);
      pollwhen = (int) (tdata->polling_time - ssh_time());
      if (pollwhen < 5 || pollwhen > 100000L)
        pollwhen = 10;

      gdata->session->polling_id = tdata->polling_id;
      gdata->session->polling_interval = pollwhen;
      gdata->session->polling_time = tdata->polling_time;

      SSH_FSM_SET_NEXT(pkix_send_subsequent);
      if (tdata->timeout_set)
        ssh_cancel_timeout(&tdata->timeout);
      tdata->timeout_set = TRUE;
      ssh_register_timeout(&tdata->timeout,
                           pollwhen, 0L,
                           pkix_timeout_handler, (void *)thread);

      if (gdata->session->done)
        (*gdata->session->done)(SSH_PKI_DELAYED,
                                gdata->session, gdata->session->done_context);
      ssh_free(tdata->input);
      tdata->input_len = 0;
      return SSH_FSM_SUSPENDED;
    default:
      return SSH_FSM_FINISH;
    }

  /* SSH_NOTREACHED; */
}

static void call_fsm_destroy(void *context)
{
  SshFSM fsm = context;
  SshPkiGlobalData gdata;

  gdata = ssh_fsm_get_gdata_fsm(fsm);
  if (gdata)
    {
      ssh_fsm_condition_destroy(gdata->input_avail);
      ssh_free(gdata);
    }
  ssh_fsm_destroy(fsm);
}

/* This step outputs the certificate/error reply to the upper level
   and finalizes the state machine. */
SSH_FSM_STEP(pkix_done)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiSession session = gdata->session;

  SSH_DEBUG(SSH_D_HIGHOK, ("Enrollment complete (thread %p)", thread));

  session->flags = 0;

  if (session->done)
    (*session->done)(session->status, session, session->done_context);

  if (!(session->flags & (SSH_ENROLL_CONFIRMED|SSH_ENROLL_RESTARTED)))
    {
      pkix_tcp_kill_input(thread);
      ssh_pki_session_free(session);

      ssh_register_timeout(&gdata->timeout,
                           0, 0, call_fsm_destroy, (void *)fsm);
      return SSH_FSM_FINISH;
    }
  else
    {
      /* pkix_tcp_kill_input(thread); */
      return SSH_FSM_CONTINUE;
    }
}

/* Transition from pkix-polling state (due reaching poll-time) to
   pkix-poll-sent state by sending SSH_PKI_MSG_POLLREQ. */
SSH_FSM_STEP(pkix_send_subsequent)
{
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  unsigned char pollbuf[4];
  SshPkiSession session = gdata->session;

  if (tdata->polling_time > ssh_time())
    return SSH_FSM_SUSPENDED;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Sending pollReq (thread %p id %d)", thread,
             (int) tdata->polling_id));

  SSH_PUT_32BIT(pollbuf, tdata->polling_id);
  if ((session->request = ssh_memdup(pollbuf, 4)) != NULL)
    session->request_len = 4;
  else
    {
      SSH_FSM_SET_NEXT(pkix_aborted);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(pkix_recv_initial);

  pkix_client_srv_send(tdata,
                       session->version, 1L, SSH_PKI_MSG_POLLREQ,
                       session->request, session->request_len);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pkix_process_input)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("Processing input (thread %p) signal", thread));
  SSH_FSM_CONDITION_SIGNAL(gdata->input_avail);
  SSH_FSM_SET_NEXT(pkix_process_input);

  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(pkix_aborted)
{
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);
  SshPkiThreadData tdata = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Aborting session %p thread %p", gdata->session, thread));

  if (!gdata->user_aborted && gdata->session->done)
    (*gdata->session->done)(SSH_PKI_ABORTED,
                            gdata->session, gdata->session->done_context);

  tdata->timeout_set = FALSE;
  ssh_cancel_timeouts(pkix_timeout_handler, (void *)thread);
  ssh_pki_session_free(gdata->session);
  pkix_tcp_kill_input(thread);
  ssh_register_timeout(&gdata->timeout,
                       0, 0, call_fsm_destroy, (void *)fsm);

  return SSH_FSM_FINISH;
}

static void
pkix_linearize_add_message(SshBuffer buffer,
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
pkix_linearize_get_message(SshBuffer buffer,
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

static void pkix_client_thread_destructor(SshFSM fsm, void *context)
{
  SshPkiThreadData tdata = (SshPkiThreadData)context;
  tdata->timeout_set = FALSE;
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, (void *)tdata->thread);
  ssh_free(tdata);
}

static Boolean
pkix_session_start(SshPkiSession session, SshFSMStepCB state)
{
  SshFSM fsm;
  Boolean ginit = FALSE;
  SshFSMThread thread;
  SshPkiThreadData tdata;
  SshPkiGlobalData gdata;

  if (session->method_context == NULL)
    {
      if ((gdata = ssh_calloc(1, sizeof(*gdata))) == NULL)
        return FALSE;
      if ((tdata = ssh_calloc(1, sizeof(*tdata))) == NULL)
        {
          ssh_free(gdata);
          return FALSE;
        }
      if ((fsm = ssh_fsm_create(gdata)) == NULL)
        {
          ssh_free(gdata);
          ssh_free(tdata);
          return FALSE;
        }

      session->method_context =
        thread = ssh_fsm_thread_create(fsm,
                                       state,
                                       NULL_FNPTR,
                                       pkix_client_thread_destructor,
                                       tdata);
      ginit = TRUE;
    }
  else
    {
      thread = session->method_context;
      fsm = ssh_fsm_get_fsm(thread);
      SSH_FSM_SET_NEXT(state);
    }

  /* Must start out with the highest version number we support. The
     server may not support it, but we'll detect that later. */
  session->version = SSH_PKI_VERSION_1;
  tdata = ssh_fsm_get_tdata(thread);

  if (ginit)
    {
      tdata->wrapper = NULL;
      tdata->http = NULL;
      tdata->thread = thread;
      tdata->finished = FALSE;
      tdata->polling_id = session->polling_id;
      tdata->polling_time = session->polling_time;
    }

  tdata->input_type = 0;
  tdata->input_version = 0;
  tdata->input_flags = 0;
  tdata->input = NULL;
  tdata->input_len = 0;

  if (ginit)
    {
      gdata = ssh_fsm_get_gdata_fsm(fsm);
      gdata->input_avail = ssh_fsm_condition_create(fsm);
      gdata->session = session;
      gdata->input_thread = NULL;
      gdata->user_aborted = FALSE;
    }
  return TRUE;
}


/****************************************************************************
 * The module export these symbols.
 */
SshPkiStatus ssh_pki_pkix_session_start(SshPkiSession session)
{
  SshFSMStepCB state =
    session->flags & SSH_ENROLL_RESTARTED ? pkix_send_initial : pkix_connect;

  if (!pkix_session_start(session, state))
    return SSH_PKI_FAILED;
  else
    return SSH_PKI_OK;
}

static void call_fsm_continue(void *thread)
{
  ssh_fsm_continue((SshFSMThread)thread);
}

/* Confirm a PKI exchange. This is pretty similar with start
   actually. The connection is kept open if possible and the state
   machine is started. */
SshPkiStatus ssh_pki_pkix_session_confirm(SshPkiSession session)
{
  SshFSMThread thread = (SshFSMThread)session->method_context;

  ssh_fsm_set_next(thread, pkix_connect);
  return SSH_PKI_OK;
}

void ssh_pki_pkix_session_finish(SshPkiSession session)
{
  SshFSMThread thread = (SshFSMThread)session->method_context;
  SshPkiThreadData tdata = (SshPkiThreadData)ssh_fsm_get_tdata(thread);
  SshPkiGlobalData gdata = ssh_fsm_get_gdata(thread);

  ssh_fsm_set_next(thread, pkix_aborted);
  if (tdata->transport_op)
    {
      ssh_operation_abort(tdata->transport_op);
      tdata->transport_op = NULL;
    }

  if (tdata->timeout_set)
    ssh_cancel_timeout(&tdata->timeout);
  tdata->timeout_set = TRUE;
  gdata->user_aborted = TRUE;

  ssh_register_timeout(&tdata->timeout,
                       0L, 0L, call_fsm_continue, (void *)thread);
}

Boolean ssh_pki_pkix_session_linearize(SshPkiSession session)
{
  SshFSMThread thread = (SshFSMThread)session->method_context;
  SshPkiThreadData tdata = (SshPkiThreadData)ssh_fsm_get_tdata(thread);

  ssh_encode_buffer(&session->statebuffer,
                    SSH_ENCODE_UINT32(1),
                    SSH_ENCODE_UINT32_STR(session->access,
                                          ssh_ustrlen(session->access)),
                    SSH_ENCODE_UINT32_STR(session->proxy,
                                          ssh_ustrlen(session->proxy)),
                    SSH_ENCODE_UINT32_STR(session->socks,
                                          ssh_ustrlen(session->socks)),
                    SSH_ENCODE_UINT32(tdata->polling_id),
                    SSH_ENCODE_UINT64(tdata->polling_time),
                    SSH_FORMAT_END);

  pkix_linearize_add_message(&session->statebuffer,
                             session->request, session->request_len);
  return TRUE;
}

Boolean ssh_pki_pkix_session_delinarize(SshPkiSession session)
{
  SshUInt32 version;

  (void) ssh_decode_buffer(&session->statebuffer,
                    SSH_DECODE_UINT32(&version),
                    SSH_DECODE_UINT32_STR(&session->access, NULL),
                    SSH_DECODE_UINT32_STR(&session->proxy, NULL),
                    SSH_DECODE_UINT32_STR(&session->socks, NULL),
                    SSH_DECODE_UINT32(&session->polling_id),
                    SSH_DECODE_UINT64(&session->polling_time),
                    SSH_FORMAT_END);
  pkix_linearize_get_message(&session->statebuffer,
                             &session->request, &session->request_len);
  return TRUE;
}

/* eof */
#endif /* SSHDIST_CERT */
