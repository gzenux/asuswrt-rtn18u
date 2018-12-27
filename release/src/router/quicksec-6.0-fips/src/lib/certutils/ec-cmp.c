/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CMP enrollment client.
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshoperation.h"
#include "sshinet.h"
#include "sshstream.h"
#include "sshfdstream.h"
#include "sshpacketstream.h"
#include "sshhttp.h"
#include "sshurl.h"
#include "sshtcp.h"
#include "sshsnprintf.h"
#include "sshdsprintf.h"

#include "sshfsm.h"

#include "sshcrypt.h"
#include "sshprvkey.h"
#include "sshexternalkey.h"
#include "sshfileio.h"

#include "x509.h"
#include "x509cmp.h"
#include "sshcrmf.h"
#include "au-ek.h"
#include "ec-cmp.h"

int brokenflags = 0;

static SshFSMConditionStruct session_ready_cond;

typedef struct
EcCmpEnrollClientRec *EcCmpEnrollClient, EcCmpEnrollClientStruct;

typedef struct
EcCmpTransSessionRec *EcCmpTransSession, EcCmpTransSessionStruct;

#define SSH_DEBUG_MODULE "SshEcCmp"

typedef struct SshCmpEnrollCaRec
{
  SshX509Certificate certtemp; /* If not null, then from param->cert */
  SshEcCmpCA param;
  EcCmpEnrollClient client;
} *SshCmpEnrollCa, SshCmpEnrollCaStruct;

typedef struct SshCmpEnrollEntityRec
{
  SshUInt8 poptype;
  SshEcCmpKeyPair keypair;
  unsigned char *cert; size_t cert_len;
  SshX509Certificate certtemp;
  Boolean do_backup;
  Boolean backup_done;
  SshPublicKey protocol_encryption_key;
  EcCmpEnrollClient client;
  SshUInt32 num_request_ids;
  SshMPInteger request_ids;
} *SshCmpEnrollEntity, SshCmpEnrollEntityStruct;

typedef struct SshCmpEnrollAuthenticatorRec
{
  SshX509Certificate certtemp; /* If not null, then from param->cert */
  SshEcCmpAuth param;
} *SshCmpEnrollAuthenticator, SshCmpEnrollAuthenticatorStruct;


/* accept_or_reject is an array of size `ncerts', where each value
   indicates if the user accepts or rejects the cert at respective
   position at `certs' array of SshCmpClientCertCB. */

struct EcCmpEnrollClientRec
{
  Boolean finished;

  SshCmpEnrollCaStruct ca;
  SshCmpEnrollAuthenticatorStruct current;
  SshCmpEnrollEntityStruct subject;

  SshCmpBodyType opcode;
  SshFSMThread thread;

  /* Extra certs to send with the initial message (mainly ir, kur). */
  size_t num_extra_certs;
  SshEcCertStruct *extra_certs;

  /* Messages the client has received from the CA and sent to the CA. */
  SshCmpMessage request;
  unsigned char *request_der; size_t request_der_len;
  SshCmpMessage response;

  /* These are used while decrypting the response, and constructing
     confirmation message for the CA . */
  SshCmpCertStatusSet plaincerts;
  SshCmpCertStatusSet reps;
  SshCmpCertSet extra;
  SshUInt32 nreps, nextra, thisrep;
  SshCmpMessage confirm;

  /* Select/save certificates and private keys CB */
  SshEcCmpCB user_callback;
  SshEcCmpErrorCB error_callback;
  SshEcCmpRevokeCB user_revoked_callback;

  SshEcCmpDoneCB done_callback;
  void *user_callback_context;

  SshCmpVersion version;
  Boolean transport_level_poll;
  EcCmpTransSession session;

  /* Try to be compatible with older servers. */
  Boolean rfc2511_compatibility;

  /* Try to use sha256 instead of sha1. */
  Boolean prefer_sha256;

  SshFSM fsm;
};

/****************************************************************************
 * TRANSPORT level state machine
 */

typedef enum {
  EC_CMP_OK, EC_CMP_DELAYED, EC_CMP_FAILED, EC_CMP_ABORTED
} EcCmpStatus;


typedef enum
{
  EC_CMP_TRANS_VERSION_0     =  0,
  EC_CMP_TRANS_VERSION_1     = 10
} EcCmpTcpProtoVersion;


typedef Boolean (*EcCmpTransDone)(EcCmpStatus status,
                                  EcCmpTransSession session,
                                  const unsigned char *data, size_t len,
                                  void *context);

/* Describe the transport session. Also stores the input processor
   thread and the condition to signal when input is available. */
struct EcCmpTransSessionRec
{
  SshFSMThread     thread;
  SshFSMThread     input_thread;

  SshTimeoutStruct timeout;
  Boolean          user_aborted;
  EcCmpStatus      status;

  unsigned char    *access;
  unsigned char    *proxy;
  unsigned char    *socks;
  SshStream         stream;
  EcCmpTransDone    done;
  void             *done_context;

  EcCmpTcpProtoVersion     version;
  SshUInt32         flags;

  SshCmpBodyType    message_type, response_type;
  unsigned char    *message, *response;
  size_t            message_len, response_len;
  SshUInt32         polling_id;

  Boolean transport_level_poll;
  Boolean rfc2511_compatibility;
  Boolean prefer_sha256;
  SshOperationHandle  operation;

  /* Monotonically increasing integer, indicating message order. */
  int message_id;
};

typedef enum
{
  EC_CMP_MSG_PKIREQ    = 0,
  EC_CMP_MSG_POLLREP   = 1,
  EC_CMP_MSG_POLLREQ   = 2,
  EC_CMP_MSG_FINREP    = 3,
  EC_CMP_MSG_PKIREP    = 5,
  EC_CMP_MSG_ERRORREP  = 6
} EcCmpTransTcpProtoMessage;


/* Describe per FSM thread data in the session. Store the packets
   received and send so far. */
typedef struct EcCmpTransThreadDataRec
{
  /* Connection */
  SshPacketWrapper     wrapper;
#ifdef SSHDIST_HTTP_CLIENT
  SshHttpClientContext http;
#endif /* SSHDIST_HTTP_CLIENT */

  /* State information. */
  Boolean finished;

  /* The last received packet. */
  unsigned char *input;
  size_t input_len;

  EcCmpTransTcpProtoMessage input_type;
  SshUInt8 input_version;
  SshUInt8 input_flags;

  /* Extracted from transport level poll */
  SshUInt32 polling_id;
  SshTime polling_time;

  SshOperationHandle transport_op;
  SshTimeoutStruct timeout;
  EcCmpTransSession session;
} *EcCmpTransThreadData;

static void
#ifdef SSHDIST_HTTP_CLIENT
  ec_cmp_trans_http_callback(SshStreamNotification notification,
                             void *context),
  ec_cmp_trans_http_receive_data(SshHttpClientContext client,
                                 SshHttpResult result,
                                 SshTcpError error,
                                 SshStream stream,
                                 void *context),
#endif /* SSHDIST_HTTP_CLIENT */
  ec_cmp_trans_tcp_kill_input(SshFSMThread thread),
  ec_cmp_trans_tcp_connect_callback(SshTcpError error, SshStream stream,
                                    void *context),
  ec_cmp_trans_tcp_receive_data(SshPacketType type,
                                const unsigned char *data, size_t len,
                                void *context),
  ec_cmp_trans_tcp_receive_eof(void *context);


SSH_FSM_STEP(ec_cmp_trans_connect);
SSH_FSM_STEP(ec_cmp_trans_send);
SSH_FSM_STEP(ec_cmp_trans_recv);
SSH_FSM_STEP(ec_cmp_trans_done);
SSH_FSM_STEP(ec_cmp_trans_process_input);
SSH_FSM_STEP(ec_cmp_trans_aborted);

#ifdef SSHDIST_HTTP_CLIENT
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
ec_cmp_trans_http_callback(SshStreamNotification notify, void *context)
{
  int i;
  size_t len;
  SshUInt8 type_or_version;
  unsigned char input[256], *data;

  PkixHttpReadContext c = (PkixHttpReadContext)context;
  EcCmpTransSession session = c->upper_context;
  SshFSMThread thread = session->thread;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);

  if (notify != SSH_STREAM_INPUT_AVAILABLE)
    return;

  while (TRUE)
    {
      i = ssh_stream_read(c->http_stream, input, sizeof(input));
      if (i == 0)
        {
          /* EOF found */
          if (!session->rfc2511_compatibility)
            {
              tdata->input = ssh_buffer_steal(c->input, &tdata->input_len);
              SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                                ("Got response, %u bytes:",
                                 (unsigned int) tdata->input_len),
                                tdata->input, tdata->input_len);
              /* Fake this to pass possible asserts later. */
              tdata->input_version = EC_CMP_TRANS_VERSION_1;
              tdata->input_type = EC_CMP_MSG_PKIREP;
              ssh_buffer_free(c->input);
              ssh_stream_destroy(c->http_stream);
              ssh_fsm_continue(session->input_thread);
              ssh_free(c);
              return;
            }
          else
            {
              if ((len = ssh_buffer_len(c->input)) > 5)
                {
                  data = ssh_buffer_ptr(c->input);
                  len = SSH_GET_32BIT(data);
                  type_or_version = data[4];

                  if (tdata->input)
                    {
                      ssh_free(tdata->input);
                      tdata->input = NULL;
                      tdata->input_len = 0;
                    }

                  if (type_or_version < 10)
                    {
                      tdata->input_version = EC_CMP_TRANS_VERSION_0;
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
                          tdata->input_version = EC_CMP_TRANS_VERSION_1;
                          tdata->input_len = len - 3;
                          tdata->input_flags = data[1];
                          tdata->input_type  = data[2];
                          data += 3;
                          tdata->input = ssh_memdup(data, tdata->input_len);
                        }
                      else
                        {
                          tdata->input_version = type_or_version;
                          tdata->input_type = EC_CMP_MSG_ERRORREP;
                        }
                    }

                  if (tdata->input == NULL)
                    tdata->input_type = EC_CMP_MSG_ERRORREP;

                  ssh_buffer_free(c->input);
                  ssh_stream_destroy(c->http_stream);
                  ssh_fsm_continue(session->input_thread);
                  ssh_free(c);
                  return;
                }
              else
                {
                  goto error;
                }
              /* end of RFC2511 compatibility. */
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
 error:
  tdata->input_type = EC_CMP_MSG_ERRORREP;
  ssh_fsm_set_next(thread, ec_cmp_trans_aborted);
  ssh_fsm_continue(session->input_thread);
  ssh_stream_destroy(c->http_stream);
  ssh_buffer_free(c->input);
  ssh_free(c);
  return;
}

/* This function gets called from the HTTP library when the HTTP
   client receives response to its request from the server. It starts
   reading the stream. */
static void
ec_cmp_trans_http_receive_data(SshHttpClientContext ctx,
                               SshHttpResult result,
                               SshTcpError ip_error,
                               SshStream stream,
                               void *context)
{
  PkixHttpReadContext c  = NULL;
  EcCmpTransSession session = context;
  SshFSMThread thread = session->thread;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);

  if (result == SSH_HTTP_RESULT_ABORTED)
    {
      /* This callback is called with http aborted status
         when enrollment has been aborted. Session has already
         been clean-up and so we must return. */
      return;
    }

  tdata->transport_op = NULL;
  if (result == SSH_HTTP_RESULT_SUCCESS &&
      (c = (PkixHttpReadContext)ssh_malloc(sizeof(*c))) != NULL)
    {
      c->http_stream = stream;
      c->upper_context = session;

      if ((c->input = ssh_buffer_allocate()) != NULL)
        {
          ssh_stream_set_callback(stream,
                                  ec_cmp_trans_http_callback,
                                  (void *)c);
          ec_cmp_trans_http_callback(SSH_STREAM_INPUT_AVAILABLE, (void *)c);
          return;
        }
    }
  ssh_free(c);
  tdata->input_type = EC_CMP_MSG_ERRORREP;
  tdata->input_len = 1;
  ssh_fsm_continue(session->input_thread);
}

#endif /* SSHDIST_HTTP_CLIENT */

static void
ec_cmp_session_free(EcCmpTransSession session)
{
  if (session)
    {
      if (session->input_thread)
        {
          ssh_fsm_kill_thread(session->input_thread);
          session->input_thread = NULL;
        }
      ssh_free(session->access);
      ssh_free(session->proxy);
      ssh_free(session->socks);

      ssh_free(session->message);
      ssh_free(session->response);

      ssh_operation_unregister(session->operation);
      ssh_free(session);
    }
}

static void
ec_cmp_free_client(EcCmpEnrollClient c)
{
  SshEcCmpAuth auth = c->current.param;
  SshEcCmpCA ca = c->ca.param;
  int ii;

  if (ca->identity_type == SSH_EC_CA_ID_CERT)
    ssh_xfree(ca->id_cert);
  else
    ssh_xfree(ca->identity.name);

  /* Free extra_certs. */
  for (ii = 0; ii < c->num_extra_certs; ii++)
    {
      /* Previously copied, so the cast is ok. */
      ssh_free((void *)c->extra_certs[ii].ber);
    }
  ssh_free(c->extra_certs);

  ssh_xfree(ca->address);
  ssh_xfree(ca->socks);
  ssh_xfree(ca->proxy);
  ssh_xfree(ca);
  ssh_x509_cert_free(c->ca.certtemp);

  if (auth->identity_type ==  SSH_EC_EE_ID_CERT)
    {
      ssh_private_key_free(auth->id_prvkey);
      ssh_xfree(auth->id_cert);
      ssh_x509_cert_free(c->current.certtemp);
    }
  else if (auth->identity_type ==  SSH_EC_EE_ID_RA)
    {
      ssh_private_key_free(auth->id_prvkey);
      ssh_xfree(auth->id_cert);
      ssh_x509_cert_free(c->current.certtemp);
    }
  else
    {
      ssh_xfree(auth->id_kid);
      ssh_xfree(auth->id_key);
    }
  ssh_xfree(auth);

  if (c->subject.keypair)
    {
      if (c->subject.keypair->prvkey)
        ssh_private_key_free(c->subject.keypair->prvkey);
      if (c->subject.keypair->pubkey)
        ssh_public_key_free(c->subject.keypair->pubkey);
      ssh_xfree(c->subject.keypair);
    }
  ssh_xfree(c->subject.cert);
  ssh_x509_cert_free(c->subject.certtemp);

  if (c->subject.num_request_ids > 0)
    {
      for (ii = 0; ii < c->subject.num_request_ids; ii++)
        ssh_mprz_clear(&c->subject.request_ids[ii]);
      ssh_free(c->subject.request_ids);
    }

  ssh_cmp_free(c->request);
  ssh_cmp_free(c->response);
  ssh_cmp_free(c->confirm);
  ssh_xfree(c->plaincerts);
  ssh_xfree(c->request_der);
  ssh_xfree(c->reps);
  ssh_xfree(c->extra);

  ec_cmp_session_free(c->session);
  if (c->fsm) ssh_fsm_destroy(c->fsm);
  ssh_xfree(c);
}


static void
ec_cmp_fsm_destroy(SshFSM fsm, void *context)
{
  EcCmpEnrollClient client = context;

  ec_cmp_free_client(client);
}

/** TCP TRANSPORT ************************************************************/

static void
ec_cmp_trans_tcp_receive_data(SshPacketType type,
                              const unsigned char *data, size_t len,
                              void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_HIGHOK, ("thread %p %d bytes from CA", thread, len));

  if (type < 10)
    {
      tdata->input_version = EC_CMP_TRANS_VERSION_0;
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
          tdata->input_version = EC_CMP_TRANS_VERSION_1;
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
    tdata->input_type = EC_CMP_MSG_ERRORREP;

  ssh_fsm_continue(tdata->session->input_thread);
}

static void
ec_cmp_trans_tcp_receive_eof(void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  ssh_packet_wrapper_destroy(tdata->wrapper);

  tdata->wrapper = NULL;
}

/* This function is called by the transport library when the CA has
   been connected, or the connection has failed. The `error' indicates
   the reason. This starts a thread to process the client initiated
   enrollment. */
static void
ec_cmp_trans_tcp_connect_callback(SshTcpError error,
                                  SshStream stream,
                                  void *context)
{
  SshFSMThread thread = (SshFSMThread)context;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);

  if (error == SSH_TCP_OK)
    {
      tdata->wrapper =
        ssh_packet_wrap(stream,
                        ec_cmp_trans_tcp_receive_data,
                        ec_cmp_trans_tcp_receive_eof,
                        NULL_FNPTR,
                        context);

      tdata->input_flags = 0;
      SSH_FSM_SET_NEXT(ec_cmp_trans_send);
    }
  else
    {
      EcCmpTransSession session = tdata->session;

      session->status = EC_CMP_FAILED;
      SSH_FSM_SET_NEXT(ec_cmp_trans_done);
    }

  SSH_FSM_CONDITION_SIGNAL(&session_ready_cond);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ec_cmp_trans_tcp_kill_input(SshFSMThread thread)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Deleting wrapper and timeouts for thread %p", thread));

  if (tdata->wrapper)
    {
      ssh_packet_wrapper_destroy(tdata->wrapper);
      tdata->wrapper = NULL;
    }
#ifdef SSHDIST_HTTP_CLIENT
  if (tdata->http)
    {
      ssh_http_client_uninit(tdata->http);
      tdata->http = NULL;
    }
#endif /* SSHDIST_HTTP_CLIENT */
  if (session->input_thread)
    {
      ssh_fsm_kill_thread(session->input_thread);
      session->input_thread = NULL;
    }
}

static void dump_message(int message_id, Boolean outgoing,
                         const unsigned char *data, size_t len)
{
  unsigned char *fn;
  FILE *fp;
  char *dump_dir;

  if (data == NULL || len == 0)
    return;

  dump_dir = getenv("CMP_MESSAGE_DUMP_DIR");
  if (!dump_dir)
    return;

  ssh_xdsprintf(&fn, "%s/cmp-%04d-%s.der", dump_dir, message_id,
                outgoing ? "outgoing" : "incoming");

  fp = fopen(ssh_csstr(fn), "w");
  if (fp)
    {
      fwrite(data, len, 1, fp);
      fclose(fp);
    }
  ssh_xfree(fn);
}

/* Transport independent send *********************************************/
static Boolean
ec_cmp_trans_client_srv_send(EcCmpTransSession session,
                             EcCmpTcpProtoVersion v, SshUInt32 flags,
                             EcCmpTransTcpProtoMessage type,
                             const unsigned char *data, size_t len)
{
  SshFSMThread thread = session->thread;
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  SshFSM fsm = ssh_fsm_get_fsm(thread);
  size_t out_len;
  unsigned char *out;

  /* Start input processor now. */
  if (session->input_thread == NULL)
    session->input_thread = ssh_fsm_thread_create(fsm,
                                                  ec_cmp_trans_process_input,
                                                  NULL_FNPTR,
                                                  NULL_FNPTR,
                                                  ssh_fsm_get_tdata(thread));

  ssh_fsm_set_thread_name(session->input_thread, "ec-cmp input thread");

  session->message_id++;
  dump_message(session->message_id, TRUE, data, len);

#ifdef SSHDIST_HTTP_CLIENT
  if (tdata->http)
    {
      if (!session->rfc2511_compatibility)
        {
          out = ssh_memdup(data, len);
          out_len = len;
        }
      else
        {
          switch (v)
            {
            case EC_CMP_TRANS_VERSION_1:
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
            case EC_CMP_TRANS_VERSION_0:
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
          /* RFC2511 compat */
        }
      if (out)
        {
          SSH_DEBUG_HEXDUMP(7, ("Sending message %u, version: %d, "
                                "flags:%lx, RFC2511 compat: %s:", type, v,
                                (unsigned long)flags,
                                session->rfc2511_compatibility ? "yes" : "no"),
                            out, out_len);

          if (session->rfc2511_compatibility)
            tdata->transport_op =
              ssh_http_post(tdata->http,
                            session->access, out, out_len,
                            ec_cmp_trans_http_receive_data,
                            (void *)session,
                            SSH_HTTP_HDR_END);
          else
            tdata->transport_op =
              ssh_http_post(tdata->http,
                            session->access, out, out_len,
                            ec_cmp_trans_http_receive_data,
                            (void *)session,
                            /* Required by RFC 6712. */
                            SSH_HTTP_HDR_FIELD,
                            "Content-Type", "application/pkixcmp",
                            SSH_HTTP_HDR_END);
          ssh_free(out);
        }

      return TRUE;
    }
#endif /* SSHDIST_HTTP_CLIENT */

  if (tdata->wrapper)
    {
      switch (v)
        {
        case EC_CMP_TRANS_VERSION_1:
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
        case EC_CMP_TRANS_VERSION_0:
          ssh_packet_wrapper_send(tdata->wrapper, type, data, len);
        default:
          return FALSE;
        }
    }
  else
    {
      /* Trying to send to closed; reopen. */
      ssh_fsm_set_next(thread, ec_cmp_trans_connect);
      return TRUE;
    }
  return TRUE;
}

static Boolean
ec_cmp_trans_client_srv_close(EcCmpTransThreadData tdata)
{
  if (tdata->wrapper)
    {
      ssh_packet_wrapper_destroy(tdata->wrapper);
      tdata->wrapper = NULL;
    }
  return TRUE;
}


/* Start connect trial. */
SSH_FSM_STEP(ec_cmp_trans_connect)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;
  unsigned char *scheme, *host, *port;
#ifdef SSHDIST_HTTP_CLIENT
  SshHttpClientParams params;
#endif /* SSHDIST_HTTP_CLIENT */

  if (session->stream)
    {
      SSH_FSM_ASYNC_CALL(
        ec_cmp_trans_tcp_connect_callback(SSH_TCP_OK, session->stream,
                                          (void *) thread);
      );
      SSH_NOTREACHED;
    }

  if (tdata->wrapper
#ifdef SSHDIST_HTTP_CLIENT
      || tdata->http
#endif /* SSHDIST_HTTP_CLIENT */
      )
    {
      SSH_FSM_SET_NEXT(ec_cmp_trans_send);
      return SSH_FSM_CONTINUE;
    }

  /* Now find out if to connect using http or tcp, and the version as well. */
  if (ssh_url_parse_and_decode(session->access,
                               &scheme, &host, &port, NULL, NULL, NULL))
    {
      if (ssh_usstrncasecmp(scheme, "tcp", 3) == 0)
        {
          SshTcpConnectParamsStruct tcp_connect_params;
          memset(&tcp_connect_params, 0, sizeof(tcp_connect_params));
          tcp_connect_params.socks_server_url = session->socks;
          ssh_free(scheme);

          if (port == NULL)
            port = ssh_strdup("829");

          SSH_FSM_ASYNC_CALL({
              ssh_tcp_connect(host, port, -1, 0, &tcp_connect_params,
                              ec_cmp_trans_tcp_connect_callback,
                              (void *)thread);
            if (host) ssh_free(host);
            if (port) ssh_free(port);
            });
          SSH_NOTREACHED;
        }
#ifdef SSHDIST_HTTP_CLIENT
      if (ssh_usstrncasecmp(scheme, "http", 4) == 0)
        {
          ssh_free(scheme);
          memset(&params, 0, sizeof(params));
          params.socks = session->socks;
          params.http_proxy_url = session->proxy;
          if (!tdata->http)
            tdata->http = ssh_http_client_init(&params);

          if (host) ssh_free(host);
          if (port) ssh_free(port);
          SSH_FSM_SET_NEXT(ec_cmp_trans_send);
          return SSH_FSM_CONTINUE;
        }
#endif /* SSHDIST_HTTP_CLIENT */
      if (1)
        return SSH_FSM_FINISH;
    }
  else
    {
      session->status = EC_CMP_FAILED;
      SSH_FSM_SET_NEXT(ec_cmp_trans_done);
      return SSH_FSM_CONTINUE;
    }
}


/* Send CMP message */
SSH_FSM_STEP(ec_cmp_trans_send)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  /* We called this again, now close the stream and again with lower
     protocol version. */
  if (tdata->input_flags & 0x1)
    ec_cmp_trans_client_srv_close(tdata);

  SSH_FSM_SET_NEXT(ec_cmp_trans_recv);

  ec_cmp_trans_client_srv_send(session,
                               session->version, 1L,
                               (session->message_type = SSH_CMP_POLL_REQUEST &&

                                session->transport_level_poll) ?
                               EC_CMP_MSG_POLLREQ:
                               EC_CMP_MSG_PKIREQ,
                               session->message, session->message_len);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ec_cmp_trans_poll)
{
  unsigned char pollbuf[4];
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  SSH_PUT_32BIT(pollbuf, session->polling_id);
  if (session->message) ssh_free(session->message);
  if ((session->message = ssh_memdup(pollbuf, 4)) != NULL)
    session->message_len = 4;
  else
    {
      SSH_FSM_SET_NEXT(ec_cmp_trans_aborted);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ec_cmp_trans_recv);

  ec_cmp_trans_client_srv_send(session,
                               session->version, 1L, EC_CMP_MSG_POLLREQ,
                               session->message, session->message_len);
  return SSH_FSM_CONTINUE;
}


static void
ec_cmp_trans_fakerep_encoded(SshX509Status status,
                             const unsigned char *der, size_t der_len,
                             void *context)
{
  EcCmpTransSession session = context;
  SshFSMThread thread = session->thread;;

  session->response = ssh_memdup(der, der_len);
  session->response_len = der_len;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ec_cmp_trans_recv)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  /* Wait here for input from the CA. */
  if (tdata->input_type != EC_CMP_MSG_ERRORREP)
    {
      if (tdata->input_len == 0)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Thread %p Waiting for input", thread));
          return SSH_FSM_SUSPENDED;
        }
    }

  session->message_id++;
  dump_message(session->message_id, FALSE, tdata->input, tdata->input_len);

  switch (tdata->input_type)
    {
    case EC_CMP_MSG_PKIREP:
      SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                        ("PkiRep %d bytes", tdata->input_len),
                        tdata->input, tdata->input_len);

      SSH_FSM_SET_NEXT(ec_cmp_trans_done);
      if (session->response)
        ssh_free(session->response);

      session->response = ssh_memdup(tdata->input, tdata->input_len);
      session->response_len = tdata->input_len;
      session->status = EC_CMP_OK;

      if (tdata->input != NULL)
        {
          ssh_free(tdata->input);
          tdata->input = NULL;
        }
      tdata->input_len = 0;

      return SSH_FSM_CONTINUE;

    case EC_CMP_MSG_ERRORREP:
      SSH_DEBUG(SSH_D_UNCOMMON,("ErrorRep"));

      if (session->version == EC_CMP_TRANS_VERSION_1 &&
          tdata->input_version < EC_CMP_TRANS_VERSION_1)
        {
          session->version = EC_CMP_TRANS_VERSION_0;
          SSH_FSM_SET_NEXT(ec_cmp_trans_send);
        }
      else
        {
          session->status = EC_CMP_FAILED;
          SSH_FSM_SET_NEXT(ec_cmp_trans_done);
        }
      ssh_free(tdata->input);
      tdata->input = NULL;
      tdata->input_len = 0;
      return SSH_FSM_CONTINUE;

    case EC_CMP_MSG_POLLREP:
      /* When receiving a transport level POLL, If this is the
         response to a non-poll message, we will generate a fake IR,
         version 1 stating the transaction is was not granted, due to
         waiting state. The request_id at the response will be the
         polling identifier. Unfortunately there is no space for poll
         when time.

         If we received pollrep as response to transport level POLL
         request, we create version 1 pollrep instead, Now we have
         space for polling time as well.

         All this to make transport level and application level polls
         to appear the same on the upper level application. */

      SSH_DEBUG_HEXDUMP(SSH_D_UNCOMMON,
                        ("PollRep %d bytes", tdata->input_len),
                        tdata->input, tdata->input_len);

      {
        SshCmpMessage fakerep;
        SshMPIntegerStruct pid;

        tdata->polling_id   = SSH_GET_32BIT(tdata->input + 0);
        ssh_mprz_init_set_ui(&pid, tdata->polling_id);
        tdata->polling_time = (SshTime)SSH_GET_32BIT(tdata->input + 4);


        SSH_FSM_SET_NEXT(ec_cmp_trans_done);
        session->status = EC_CMP_OK;

        ssh_cancel_timeout(&tdata->timeout);
        ssh_free(tdata->input);
        tdata->input = NULL;
        tdata->input_len = 0;

        fakerep = ssh_cmp_allocate(SSH_CMP_VERSION_1);
        ssh_cmp_header_set_transaction_id(fakerep,
                                          (unsigned char *)"0", 1,
                                          (unsigned char *)"0", 1,
                                          (unsigned char *)"0", 1);
        ssh_cmp_header_set_names(fakerep, NULL, NULL);

        if (session->message_type == SSH_CMP_POLL_REQUEST)
          {
            ssh_cmp_body_set_type(fakerep, SSH_CMP_POLL_RESPONSE);
            ssh_cmp_add_poll_response(fakerep,
                                      &pid,
                                      (SshUInt32)tdata->polling_time, NULL);
          }
        else
          {
            SshCmpStatusInfoStruct info;

            info.status = SSH_CMP_STATUS_WAITING;
            info.failure = SSH_CMP_FINFO_BAD_TIME;
            info.freetext = NULL;
            ssh_cmp_body_set_type(fakerep, SSH_CMP_INIT_RESPONSE);
            ssh_cmp_add_cert_response(fakerep, &pid, &info, FALSE,
                                      NULL, 0, NULL, 0);
          }
        SSH_FSM_ASYNC_CALL({
          ssh_cmp_encode(fakerep, NULL, ec_cmp_trans_fakerep_encoded, session);
          ssh_cmp_free(fakerep);});

      }

    default:
      return SSH_FSM_FINISH;
    }

  /*NOTREACHED*/
}

/* This step outputs the certificate/error reply to the upper level
   and finalizes the state machine. */

SSH_FSM_STEP(ec_cmp_trans_done)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  Boolean finished = FALSE;
  session->flags = 0;

  if (session->done)
    finished = (*session->done)(session->status, session,
                                session->response, session->response_len,
                                session->done_context);

  if (finished)
    {
      ec_cmp_trans_tcp_kill_input(thread);
      return SSH_FSM_FINISH;
    }
  else
    return SSH_FSM_SUSPENDED;
}


SSH_FSM_STEP(ec_cmp_trans_process_input)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;

  SSH_FSM_SET_NEXT(ec_cmp_trans_process_input);

  /* Wait if we are not using http and tcp connection is
     not ready. */
  if (tdata->wrapper == NULL
#ifdef SSHDIST_HTTP_CLIENT
      && tdata->http == NULL
#endif /* SSHDIST_HTTP_CLIENT */
      )
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Connection not ready, thread suspended"));
      SSH_FSM_CONDITION_WAIT(&session_ready_cond);
    }


  ssh_fsm_continue(session->thread);
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ec_cmp_trans_aborted)
{
  EcCmpTransThreadData tdata = ssh_fsm_get_tdata(thread);
  EcCmpTransSession session = tdata->session;


  if (!session->user_aborted && session->done)
    (*session->done)(EC_CMP_ABORTED, session, NULL, 0, session->done_context);

  session->input_thread = NULL;

  ec_cmp_trans_tcp_kill_input(thread);

  return SSH_FSM_FINISH;
}

static void ec_cmp_trans_abort(void *context)
{
  EcCmpTransSession session = context;

  ssh_operation_unregister(session->operation); session->operation = NULL;
  session->done = NULL_FNPTR;
  session->done_context = NULL;
  ssh_fsm_set_next(session->thread, ec_cmp_trans_aborted);
  ssh_fsm_continue(session->thread);
}

static void ec_cmp_trans_tdata_destroy(SshFSM fsm, void *context)
{
  EcCmpTransThreadData tdata = context;

  if (tdata->input) ssh_free(tdata->input);
  ssh_free(tdata);
}

static EcCmpTransSession
ec_cmp_trans_alloc(SshFSM fsm,
                   const char *access, const char *proxy, const char *socks,
                   SshCmpVersion initial_version)
{
  EcCmpTransThreadData tdata;
  EcCmpTransSession session;

  if ((session = ssh_calloc(1, sizeof(*session))) == NULL)
    return NULL;

  if ((tdata = ssh_calloc(1, sizeof(*tdata))) == NULL)
    {
      ssh_free(session);
      return NULL;
    }

  session->thread =
    ssh_fsm_thread_create(fsm,
                          ec_cmp_trans_send,
                          NULL_FNPTR,
                          ec_cmp_trans_tdata_destroy,
                          tdata);

  ssh_fsm_set_thread_name(session->thread, "ec-cmp transport");

  /* Must start out with the highest version number we support. The
     server may not support it, but we'll detect that later. */
  session->version = EC_CMP_TRANS_VERSION_1;
  if (initial_version == SSH_CMP_VERSION_1)
    session->version = EC_CMP_TRANS_VERSION_0;
  tdata->session = session;
  tdata->wrapper = NULL;
#ifdef SSHDIST_HTTP_CLIENT
  tdata->http = NULL;
#endif /* SSHDIST_HTTP_CLIENT */
  tdata->finished = FALSE;
  tdata->input_type = 0;
  tdata->input_version = 0;
  tdata->input_flags = 0;
  tdata->input = NULL;
  tdata->input_len = 0;

  session->access = access ? ssh_strdup(access) : NULL;
  session->socks = socks ? ssh_strdup(socks) : NULL;
  session->proxy = proxy ? ssh_strdup(proxy) : NULL;
  session->operation = ssh_operation_register(ec_cmp_trans_abort, session);
  session->input_thread = NULL;
  session->user_aborted = FALSE;
  session->done = NULL_FNPTR;
  session->done_context = NULL;

  return session;
}


/* Send CMP transport level POLL to CA at 'access'. If 'session' is
   given use that instead of 'access'. Call 'callback' with
   'callback_context' when the CA responds or connection terminates
   due to error. */
static EcCmpTransSession
ec_cmp_session_poll(EcCmpTransSession session, SshCmpVersion version,
                    SshFSM fsm,
                    const char *access, const char *proxy, const char *socks,
                    SshUInt32 pid,
                    EcCmpTransDone callback, void *callback_context)
{
  if (session == NULL)
    if ((session = ec_cmp_trans_alloc(fsm, access, proxy, socks,
                                      version)) == NULL)
      return NULL;
  if (session->message) ssh_free(session->message);

  session->message_type = SSH_CMP_POLL_REQUEST;
  session->message = NULL;
  session->message_len = 0;
  session->polling_id = pid;
  session->done = callback;
  session->transport_level_poll = TRUE;
  session->done_context = callback_context;

  ssh_fsm_set_next(session->thread, ec_cmp_trans_poll);
  return session;
}

/* Send CMP PDU 'message' to CA at 'access'. If 'session' is not a
   NULL pointer, use existing session, else create new session based
   on access information provided. Call 'callback' with
   'callback_context' when the CA responds or connection terminates
   due to error. */
static EcCmpTransSession
ec_cmp_session_enroll(EcCmpTransSession session,
                      Boolean rfc2511_compatibility,
                      Boolean prefer_sha256,
                      SshCmpVersion version,
                      SshFSM fsm,
                      const char *access, const char *proxy, const char *socks,
                      SshCmpBodyType message_type,
                      const unsigned char *message, size_t message_len,
                      EcCmpTransDone callback, void *callback_context)
{
  if (session == NULL)
    if ((session = ec_cmp_trans_alloc(fsm, access, proxy, socks,
                                      version)) == NULL)
      return NULL;
  if (session->message) ssh_free(session->message);

  session->rfc2511_compatibility = rfc2511_compatibility;
  session->prefer_sha256 = prefer_sha256;

  session->polling_id = 0;
  session->message_type = message_type;
  session->message = ssh_memdup(message, message_len);
  session->message_len = message_len;
  session->done = callback;
  session->done_context = callback_context;
  session->transport_level_poll = FALSE;
  ssh_fsm_set_next(session->thread, ec_cmp_trans_send);
  ssh_fsm_continue(session->thread);
  return session;
}


SSH_FSM_STEP(cmp_compose_template);     /* template content */
SSH_FSM_STEP(cmp_compose_envelope);     /* wrapit */
SSH_FSM_STEP(cmp_send_request);         /* and send */
SSH_FSM_STEP(cmp_process_response);     /* receive response */
SSH_FSM_STEP(cmp_cert_decrypt);         /* decrypt response */
SSH_FSM_STEP(cmp_cert_display_certs);   /* show certs to user */
SSH_FSM_STEP(cmp_cert_display_revoked); /* show revoked to user */
SSH_FSM_STEP(cmp_cert_compose_confirm); /* send confirm after user response */
SSH_FSM_STEP(cmp_cert_compose_pollreq); /* send pollreq after response */

SSH_FSM_STEP(cmp_done);                 /* done, call finish */
SSH_FSM_STEP(cmp_error);                /* done, call error and finish */

SSH_FSM_STEP(cmp_cert_display_poll_ids); /* show polling ids to user */

static void
cmp_crt_encode_done(SshX509Status status,
                    const unsigned char *ber, size_t ber_len,
                    void *context)
{
  EcCmpEnrollClient c = context;

  if (status == SSH_X509_OK)
    {
      ssh_fsm_set_next(c->thread, cmp_compose_envelope);

      c->subject.cert = ssh_xmemdup(ber, ber_len);
      c->subject.cert_len = ber_len;

      /* 2: break CRMF */
      if (brokenflags & 2)
        c->subject.cert[ssh_random_get_byte() % 10] += 17;

      /* 256: break CRMF PoP */
      if (brokenflags & 256)
        c->subject.cert[ber_len-7] += 1;
    }
  else
    ssh_fsm_set_next(c->thread, cmp_done);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static void
cmp_key_backup_encrypt_done(SshX509EncryptedValue ciphered,
                            SshX509EncryptedValue plaintext,
                            void *context)
{
  EcCmpEnrollClient c = context;
  SshCmpEnrollEntity s = &c->subject;

  if (ciphered)
    {
      s->backup_done = TRUE;
      s->certtemp->controls.node->s.pki_options.encrypted_value = ciphered;
      ssh_fsm_set_next(c->thread, cmp_compose_template);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Key encrypt operation failed"));
      ssh_fsm_set_next(c->thread, cmp_error);
    }
  ssh_public_key_free((SshPublicKey)plaintext->value_hint);
  plaintext->value_hint = NULL;
  ssh_crmf_encrypted_value_free(plaintext);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static Boolean
cmp_select_signature_scheme(SshPrivateKey prvkey, Boolean prefer_sha256)
{
  SshCryptoStatus cr_status;
  const char *kt, *sign;
  cr_status = ssh_private_key_get_info(prvkey,
                                       SSH_PKF_KEY_TYPE, &kt,
                                       SSH_PKF_END);
  if (cr_status != SSH_CRYPTO_OK)
    {
      SSH_TRACE(2, ("Failed to get private key info, signature schema "
                    "unchanged."));
      return FALSE;
    }













  if (!strncmp(kt, "if-modn", sizeof("if-modn")))
    {
      if (prefer_sha256)
        sign = "rsa-pkcs1-sha256";
      else
        sign = "rsa-pkcs1-sha1";
    }
  else
    {
      if (prefer_sha256)
        sign = "dsa-nist-sha256";
      else
        sign = "dsa-nist-sha1";
    }
  SSH_TRACE(4, ("Using signature alg: %s", sign));
  cr_status = ssh_private_key_select_scheme(prvkey,
                                            SSH_PKF_SIGN, sign,
                                            SSH_PKF_END);

  return cr_status == SSH_CRYPTO_OK;
}

/* This state is entered twice in case of key backup. */
SSH_FSM_STEP(cmp_compose_template)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollEntity s = &c->subject;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshX509PopStruct *pop;
  SshPrivateKey prvkey = NULL;
  SshX509ControlsNode cn;

  if (c->opcode == SSH_CMP_KEY_REC_REQUEST && !s->backup_done)
    {
      SshX509PublicKey pk;

      cn = ssh_xcalloc(1, sizeof(*cn));
      cn->next = NULL;
      cn->type = SSH_X509_CTRL_PUBLIC_KEY;
      pk = &cn->s.public_key;
      pk->pk_type = SSH_X509_PKALG_RSA;
      pk->subject_key_usage_mask = 0L;
      pk->ca_key_usage_mask = 0L;
      pk->public_key = s->protocol_encryption_key;
      pk->public_group = NULL;
      c->subject.certtemp->controls.node = cn;
      c->subject.certtemp->controls.unknown = 0;
    }

  if (c->opcode == SSH_CMP_KEY_UP_REQUEST && !s->backup_done)
    {
      SshMPInteger old_serial;
      struct SshX509NameRec *issuer_ptr, *old_issuer_name;

      cn = ssh_xcalloc(1, sizeof(*cn));
      cn->next = c->subject.certtemp->controls.node;
      cn->type = SSH_X509_CTRL_OLD_CERT_ID;
      old_serial = &cn->s.old_cert_id.serial_no;
      ssh_mprz_init(old_serial);
      ssh_mprz_set(old_serial, &s->certtemp->serial_number);

      old_issuer_name = cn->s.old_cert_id.issuer =
        ssh_xmalloc(sizeof *old_issuer_name);
      issuer_ptr = ssh_x509_name_copy(s->certtemp->issuer_name);
      *old_issuer_name = *issuer_ptr;

      c->subject.certtemp->controls.node = cn;
      c->subject.certtemp->controls.unknown = 0;
    }

  /* Template came from command line options and key generation, it
     has been filled with this information.  Now, if we are to do key
     backup, insert the control.*/
  if (s->do_backup
      && !s->backup_done
      && (c->opcode == SSH_CMP_INIT_REQUEST ||
          c->opcode == SSH_CMP_CERT_REQUEST ||
          c->opcode == SSH_CMP_KEY_UP_REQUEST))
    {
      /* We can be quiet here, this actually has already been
         checked.
         8: broken backup, no private key. */
      if (c->subject.do_backup && c->ca.certtemp)
        {
          SshX509ArchiveOptions ao;
          SshPublicKey pubkey;
          SshX509EncryptedValue ev = NULL;

          if (ssh_x509_cert_get_public_key(c->ca.certtemp, &pubkey))
            {
              cn = ssh_xcalloc(1, sizeof(*cn));
              cn->next = c->subject.certtemp->controls.node;
              cn->type = SSH_X509_CTRL_PKI_OPTIONS;
              ao = &cn->s.pki_options;
              ao->archive_prv_key = FALSE;
              ao->keygen_parameters = NULL;
              ao->keygen_parameters_len = 0;
              /* Encrypted value will be filled in
                 cmp_key_backup_encrypt_done */

              if (!(brokenflags & 8))
                ev =
                  ssh_crmf_create_encrypted_private_key("3des-cbc",
                                                        s->keypair->prvkey);
              c->subject.certtemp->controls.node = cn;
              c->subject.certtemp->controls.unknown = 0;



              ev->value_hint = (unsigned char *)pubkey;
              SSH_FSM_ASYNC_CALL({
                ssh_crmf_encrypt_encrypted_value(ev,
                                                 pubkey,
                                                 cmp_key_backup_encrypt_done,
                                                 c);

              });
              /* NOTREACHED */
            }
        }
    }

  if (c->opcode != SSH_CMP_REVOC_REQUEST &&
      c->opcode != SSH_CMP_KEY_REC_REQUEST &&
      c->current.param->identity_type != SSH_EC_EE_ID_RA)
    {
      pop = &s->certtemp->pop;
      /* Prepare for signature POP */
      if (s->poptype == SSH_X509_POP_SUBSEQ_UNDEF && s->keypair)
        {
          prvkey = s->keypair->prvkey;
          algorithm = ssh_x509_private_key_algorithm(prvkey);
          pop->pkey.pk_type = algorithm->algorithm;


          cmp_select_signature_scheme(prvkey, c->prefer_sha256);
        }

      if (s->poptype == SSH_X509_POP_SUBSEQ_ENCRYPT_CERT)
        {
          prvkey = s->keypair->prvkey;
          pop->subsequent_message = s->poptype;
        }
    }

  s->certtemp->type =  SSH_X509_PKIX_CRMF;
  SSH_FSM_ASYNC_CALL({
    ssh_x509_cert_encode_async(s->certtemp,
                               prvkey,
                               cmp_crt_encode_done, c);
  });
}

static void
cmp_cmp_encode_done(SshX509Status status,
                    const unsigned char *ber, size_t ber_len,
                    void *context)
{
  EcCmpEnrollClient c = context;

  if (c->request_der) ssh_xfree(c->request_der);

  if (status == SSH_X509_OK)
    {
      c->request_der = ssh_xmemdup(ber, ber_len);
      c->request_der_len = ber_len;

      /* 4: break CMP */
      if (brokenflags & 4)
        c->request_der[ssh_random_get_byte() % ber_len] += 1;
    }
  else
    {
      SSH_TRACE(1, ("Encoding certificate failed."));
      ssh_fsm_set_next(c->thread, cmp_done);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static void fill_in_digest_algorithms(EcCmpEnrollClient c, SshPSWBMac param)
{
  char *mac_name = getenv("CMP_PSWBMAC_HMAC");
  if (!mac_name)
    mac_name = "hmac-sha1";

  if (c->prefer_sha256)
    {
      param->hash_name = ssh_xstrdup("sha256");
      /* Insta does not seem to like hmac-sha256.  This generates

         Status: Rejected (2)
         Status message: ASN.1 decoding error

         against Insta demo CA.
      */

      param->mac_name = ssh_xstrdup(mac_name);
    }
  else
    {
      param->hash_name = ssh_xstrdup("sha1");
      param->mac_name = ssh_xstrdup(mac_name);
    }

}

SSH_FSM_STEP(cmp_compose_envelope)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollCa  ca = &c->ca;
  SshCmpEnrollAuthenticator a = &c->current;
  SshCmpEnrollEntity s = &c->subject;

  SshCmpMessage message;
  SshX509Name sender = NULL, recipient = NULL;
  unsigned char *kid, tid[16], snonce[16];
  size_t kid_len, i;
  SshPrivateKey prvkey;
  Boolean crit;

  /* If doing PSK or Certs based envelope authentication */
  if ((c->opcode == SSH_CMP_POLL_REQUEST ||
       c->opcode == SSH_CMP_INIT_REQUEST ||
       c->opcode == SSH_CMP_REVOC_REQUEST)
      && a->param->identity_type == SSH_EC_EE_ID_PSK)
    {
      ssh_x509_name_push_directory_name_der(&sender, NULL, 0);
      /* 16: recipient missing. */
      if (!(brokenflags & 16))
        {
          if (ca->param->identity_type == SSH_EC_CA_ID_NAME)
            ssh_x509_name_push_directory_name(&recipient,
                                              ca->param->identity.name);
          else
            recipient = ssh_x509_name_copy(ca->certtemp->subject_name);
        }
      kid = a->param->id_kid;
      kid_len = a->param->id_kid_len;
    }
  else
    {
      if (c->current.certtemp &&
          c->current.certtemp->subject_name)
        sender = ssh_x509_name_copy(c->current.certtemp->subject_name);
      else if (c->subject.certtemp &&
               c->subject.certtemp->subject_name)
        sender = ssh_x509_name_copy(c->subject.certtemp->subject_name);
      else
        sender = ssh_x509_name_copy(a->certtemp->subject_name);
      if (ca->param->identity_type == SSH_EC_CA_ID_NAME)
        ssh_x509_name_push_directory_name(&recipient,
                                          ca->param->identity.name);
      else
        recipient = ssh_x509_name_copy(ca->certtemp->subject_name);

      if (!a->certtemp ||
          !ssh_x509_cert_get_subject_key_id(a->certtemp,
                                            &kid, &kid_len, &crit))
        {
          kid = NULL;
          kid_len = 0;
        }
    }

  /* 32: wrong kid */
  if (brokenflags & 32 && kid != NULL)
    kid[3] |= 7;

  for (i = 0; i < sizeof(tid); i++)    tid[i]    = ssh_random_get_byte();
  for (i = 0; i < sizeof(snonce); i++) snonce[i] = ssh_random_get_byte();

  message = ssh_cmp_allocate(c->version);
  ssh_x509_name_reset(sender);
  ssh_x509_name_reset(recipient);
  ssh_cmp_header_set_names(message, sender, recipient);
  ssh_cmp_header_set_key_id(message, kid, kid_len, NULL, 0);

  /* Will have zero txid on polls, meaning we have lost the original
     value and the server should assign us new. */





  ssh_cmp_header_set_transaction_id(message,
                                    tid,
                                    (c->opcode == SSH_CMP_POLL_REQUEST) ?
                                    0 : sizeof(tid),
                                    snonce, sizeof(snonce),
                                    NULL, 0);

  if (a->param->id_kid_len &&
      (c->opcode == SSH_CMP_POLL_REQUEST ||
       c->opcode == SSH_CMP_INIT_REQUEST ||
       c->opcode == SSH_CMP_REVOC_REQUEST))
    {
      SshPSWBMac param;
      int i;

      param = ssh_xmalloc(sizeof(*param));
      param->salt = ssh_xmalloc(param->salt_length = 16);
      for (i = 0; i < 16; i++) param->salt[i] = ssh_random_get_byte();

      fill_in_digest_algorithms(c, param);
      param->iteration_count = (a->param->id_count) ? a->param->id_count:1024;

      /* 64: wrong key */
      if (brokenflags & 64)
        a->param->id_key_len -= 2;

      ssh_cmp_header_set_pswbmac(message, param,
                                 a->param->id_key, a->param->id_key_len);
    }

  ssh_cmp_body_set_type(message, c->opcode);

  switch (c->opcode)
    {
    case SSH_CMP_INIT_REQUEST:
    case SSH_CMP_CERT_REQUEST:
    case SSH_CMP_KEY_UP_REQUEST:
    case SSH_CMP_KEY_REC_REQUEST:
      /* 128: CMP payload missing. */
      if (!(brokenflags & 128))
        ssh_cmp_set_cert_request(message, s->cert, s->cert_len);
      break;
    case SSH_CMP_REVOC_REQUEST:
      ssh_cmp_add_revocation_request(message, s->cert, s->cert_len, NULL);
      break;
    case SSH_CMP_POLL_REQUEST:
      for (i = 0; i < s->num_request_ids; i++)
        ssh_cmp_add_poll_request(message, &s->request_ids[i]);
      break;

    default:
      SSH_NOTREACHED;
    }

  prvkey = NULL;
  if (a->param->identity_type == SSH_EC_EE_ID_CERT)
    {
      SSH_TRACE(2, ("Using signature protection."));
      prvkey = a->param->id_prvkey;
    }
  /* Add the given extraCerts. */
  {
    int ii;
    for (ii = 0; ii < c->num_extra_certs; ii++)
      {
        Boolean ret;
        ret = ssh_cmp_add_extra_cert(message,
                                     c->extra_certs[ii].ber,
                                     c->extra_certs[ii].ber_len);
        if (!ret)
          {
            SSH_TRACE(1, ("Failed to encode extra cert, trying to continue."));
          }
      }
  }

  c->request = message;

  SSH_TRACE(8, ("Signing key: %p", prvkey));

  cmp_select_signature_scheme(prvkey, c->prefer_sha256);

    {
      SSH_FSM_SET_NEXT(cmp_send_request);
      SSH_FSM_ASYNC_CALL({
        ssh_cmp_encode(message,
                       prvkey,
                       cmp_cmp_encode_done, c);
      });
    }
}

static Boolean
cmp_cmp_receive_done(EcCmpStatus status,
                     EcCmpTransSession session,
                     const unsigned char *message, size_t message_len,
                     void *context)
{
  EcCmpEnrollClient c = context;
  SshCmpMessage pkirep;

  switch (status)
    {
    case EC_CMP_OK:
    case EC_CMP_DELAYED:
      if (ssh_cmp_decode(message, message_len, &pkirep) != SSH_X509_OK)
        {
          c->finished = TRUE;
          ssh_warning("Can't decode response from the CA");
          ssh_fsm_set_next(c->thread, cmp_done);
          goto failed;
        }

      if (c->response)
        ssh_cmp_free(c->response);
      c->response = pkirep;
      break;

    case EC_CMP_FAILED:
      SSH_DEBUG(SSH_D_FAIL, ("Receiving CMP message failed"));
      c->finished = TRUE;
      ssh_fsm_set_next(c->thread, cmp_error);
      goto failed;

    default:
      break;
    }

 failed:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
  return c->finished;
}

SSH_FSM_STEP(cmp_send_request)
{
  EcCmpTransSession session;
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollCa  ca = &c->ca;
  SshCmpEnrollEntity s = &c->subject;
  SshUInt32 id;

  SSH_FSM_SET_NEXT(cmp_process_response);

  SSH_FSM_ASYNC_CALL({
    if (c->opcode == SSH_CMP_POLL_REQUEST &&
        ((c->version == SSH_CMP_VERSION_1) ||
         (c->transport_level_poll && !c->confirm)))
      {
        id = ssh_mprz_get_ui32(&s->request_ids[0]);
        session = ec_cmp_session_poll(c->session,
                                      c->version,
                                      ssh_fsm_get_fsm(thread),
                                      ca->param->address,
                                      ca->param->proxy,
                                      ca->param->socks,
                                      id,
                                      cmp_cmp_receive_done, c);
      }
    else
      {
        session = ec_cmp_session_enroll(c->session,
                                        c->rfc2511_compatibility,
                                        c->prefer_sha256,
                                        c->version,
                                        ssh_fsm_get_fsm(thread),
                                        ca->param->address,
                                        ca->param->proxy,
                                        ca->param->socks,
                                        c->opcode,
                                        c->request_der, c->request_der_len,
                                        cmp_cmp_receive_done, c);
      }
    c->session = session;
    if (strcmp(ca->param->address, "-") == 0)
      {
        SshStream stream = ssh_stream_fd_wrap2(0, 1, FALSE);
        session->stream = stream;
      }
  });
}

static void
cmp_crmf_decrypt_done(SshX509EncryptedValue value,
                      SshX509EncryptedValue decrypted,
                      void *context)
{
  EcCmpEnrollClient c = context;

  if (decrypted)
    {
      c->plaincerts[c->thisrep].cert =
        ssh_xmemdup(decrypted->encrypted_value,
                    decrypted->encrypted_value_len);
      c->plaincerts[c->thisrep].cert_len = decrypted->encrypted_value_len;
      c->thisrep += 1;
    }
  else
    {
      ssh_fsm_set_next(c->thread, cmp_cert_display_certs);
      c->thisrep += 1;
    }
  ssh_crmf_encrypted_value_free(value);
  ssh_crmf_encrypted_value_free(decrypted);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(cmp_cert_decrypt)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollEntity s = &c->subject;
  SshOperationHandle op;
  SshX509EncryptedValue ev;
  SshCmpCertStatusSet rep;

  if (c->thisrep == c->nreps)
    {
      SSH_FSM_SET_NEXT(cmp_cert_display_certs);
      return SSH_FSM_CONTINUE;
    }

  if (!c->plaincerts)
    {
      c->plaincerts = ssh_xcalloc(c->nreps, sizeof(*c->plaincerts));
    }

  rep = &c->reps[c->thisrep];
  c->plaincerts[c->thisrep] = *rep;

  if (rep->encrypted && !rep->prvkey &&
      s->keypair && s->keypair->prvkey != NULL)
    {
      if (ssh_crmf_decode_encrypted_value(rep->cert, rep->cert_len, &ev)
          == SSH_X509_OK)
        {
          SSH_FSM_ASYNC_CALL({
            op = ssh_crmf_decrypt_encrypted_value(ev,
                                                  s->keypair->prvkey,
                                                  cmp_crmf_decrypt_done, c);
            /* Cast to keep compiler happy. */
            op = op;});
        }
      else
        {
          SSH_FSM_SET_NEXT(cmp_cert_display_certs);
          return SSH_FSM_CONTINUE;
        }
    }
  else
    {
      c->thisrep += 1;
      SSH_FSM_SET_NEXT(cmp_cert_decrypt);
      return SSH_FSM_CONTINUE;
    }
}


static void
cmp_cert_poll_id_seen(SshCmpStatus *freeme, void *context)
{
  EcCmpEnrollClient c = context;
  ssh_xfree(freeme);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(cmp_cert_display_poll_ids)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SSH_FSM_SET_NEXT(cmp_done);
  SSH_FSM_ASYNC_CALL({
    (*c->user_callback)(SSH_CMP_STATUS_GRANTED, /* Lie */
                        c->plaincerts, c->nreps,
                        c->extra, c->nextra,
                        cmp_cert_poll_id_seen, c,
                        c->user_callback_context);
  });
}

static void
cmp_cert_user_done(SshCmpStatus *accept_or_reject,
                   void *context)
{
  EcCmpEnrollClient c = context;
  int i;

  for (i = 0; i < c->nreps; i++)
    {
      c->plaincerts[i].info->status = accept_or_reject[i];
    }
  ssh_xfree(accept_or_reject);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(cmp_key_recovery_done)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  ec_cmp_trans_abort(c->session);
  SSH_FSM_SET_NEXT(cmp_done);
  SSH_FSM_WAIT_THREAD(c->session->thread);
}

SSH_FSM_STEP(cmp_cert_display_certs)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  if (c->thisrep == c->nreps)
    {
      if (c->reps &&
          c->reps->info->status != SSH_CMP_STATUS_GRANTED &&
          c->reps->info->status != SSH_CMP_STATUS_GRANTED_WITH_MODS)
        {
          ec_cmp_trans_abort(c->session);
          SSH_FSM_SET_NEXT(cmp_cert_display_poll_ids);
          SSH_FSM_WAIT_THREAD(c->session->thread);
          SSH_NOTREACHED;
        }
      else
        {
          if (c->opcode == SSH_CMP_KEY_REC_REQUEST)
            SSH_FSM_SET_NEXT(cmp_key_recovery_done);
          else
            SSH_FSM_SET_NEXT(cmp_cert_compose_confirm);

        }
      SSH_FSM_ASYNC_CALL({
          (*c->user_callback)(SSH_CMP_STATUS_GRANTED,
                              c->plaincerts, c->nreps,
                              c->extra, c->nextra,
                              cmp_cert_user_done, c,
                              c->user_callback_context);
      });
    }
  else
    {
      SSH_FSM_SET_NEXT(cmp_done);
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(cmp_cert_display_revoked)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpRevokedSet revoked;
  SshUInt32 nrevoked;

  ssh_cmp_get_revocation_response(c->response, &nrevoked, &revoked);

  (*c->user_revoked_callback)(revoked, nrevoked, c->user_callback_context);
  ssh_xfree(revoked);

  ec_cmp_trans_abort(c->session);

  SSH_FSM_SET_NEXT(cmp_done);
  return SSH_FSM_CONTINUE;
}

static SshCmpMessage cmp_message_with_template(SshCmpMessage message)
{
  SshCmpMessage copy;
  SshCmpVersion version = ssh_cmp_version(message);
  const unsigned char *buf0, *buf1, *buf2;
  size_t len0, len1, len2;
  SshX509Name sender, recipient;

  if ((copy = ssh_cmp_allocate(version)) != NULL)
    {
      ssh_cmp_header_get_names(message, &sender, &recipient);
      ssh_x509_name_reset(sender);
      ssh_x509_name_reset(recipient);
      ssh_cmp_header_set_names(copy,
                               ssh_x509_name_copy(recipient),
                               ssh_x509_name_copy(sender));
      ssh_cmp_header_get_transaction_id(message,
                                        &buf0, &len0,
                                        &buf1, &len1,
                                        &buf2, &len2);
      ssh_cmp_header_set_transaction_id(copy,
                                        buf0, len0,
                                        buf2, len2,
                                        buf1, len1);
    }
  return copy;
}

SSH_FSM_STEP(cmp_cert_compose_pollreq)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollAuthenticator a = &c->current;
  SshCmpMessage preq;
  size_t kid_len;
  int i;
  unsigned char *kid;
  SshPrivateKey prvkey = NULL;
  Boolean need_poll = FALSE;

  need_poll = FALSE;
  for (i = 0; i < c->nreps; i++)
    {
      if (c->plaincerts[i].info->status == SSH_CMP_STATUS_WAITING)
        need_poll = TRUE;
    }
  if (!need_poll)
    {
      /* We are done, CertConf is done and no pending requests. */
      SSH_FSM_SET_NEXT(cmp_done);
      return SSH_FSM_CONTINUE;
    }

  preq = cmp_message_with_template(c->response);

  if (a->param->identity_type == SSH_EC_EE_ID_RA)
    {
      prvkey = NULL;
    }
  else if (a->param->identity_type == SSH_EC_EE_ID_CERT)
    {
      prvkey = a->param->id_prvkey;
      ssh_x509_cert_get_subject_unique_identifier(a->certtemp, &kid, &kid_len);
      ssh_cmp_header_set_key_id(preq, kid, kid_len, NULL, 0);
      ssh_xfree(kid);
    }
  else
    {
      prvkey = NULL;
      kid = ssh_xmemdup(a->param->id_kid, a->param->id_kid_len);
      kid_len = a->param->id_kid_len;
      ssh_cmp_header_set_key_id(preq, kid, kid_len, NULL, 0);
      ssh_xfree(kid);
    }

  if (a->param->id_kid_len)
    {
      SshPSWBMac param;
      int i;

      param = ssh_xmalloc(sizeof(*param));
      param->salt = ssh_xmalloc(param->salt_length = 16);
      for (i = 0; i < 16; i++) param->salt[i] = ssh_random_get_byte();
      param->iteration_count = 1024;
      fill_in_digest_algorithms(c, param);

      ssh_cmp_header_set_pswbmac(preq, param,
                                 a->param->id_key, a->param->id_key_len);
    }

  ssh_cmp_body_set_type(preq, SSH_CMP_POLL_REQUEST);
  for (i = 0; i < c->nreps; i++)
    {
      if (c->plaincerts[i].info->status == SSH_CMP_STATUS_WAITING)
        {
          ssh_cmp_add_poll_request(preq, c->plaincerts[i].request_id);
        }
    }

  SSH_FSM_SET_NEXT(cmp_send_request);
  SSH_FSM_ASYNC_CALL({
    ssh_cmp_encode(preq, prvkey, cmp_cmp_encode_done, c);
  });
}

SSH_FSM_STEP(cmp_cert_compose_confirm)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpEnrollAuthenticator a = &c->current;
  SshCmpMessage conf;
  size_t digest_len, kid_len;
  int i;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH], *kid;
  SshHash hash;
  SshCmpStatusInfoStruct accepted;
  SshPrivateKey prvkey = NULL;
  SshCmpVersion version = ssh_cmp_version(c->response);

  conf = cmp_message_with_template(c->response);

  if (a->param->identity_type == SSH_EC_EE_ID_RA)
    {
      prvkey = NULL;
    }
  else if (a->param->identity_type == SSH_EC_EE_ID_CERT)
    {
      prvkey = a->param->id_prvkey;
      ssh_x509_cert_get_subject_unique_identifier(a->certtemp, &kid, &kid_len);
      ssh_cmp_header_set_key_id(conf, kid, kid_len, NULL, 0);
      ssh_xfree(kid);
    }
  else
    {
      prvkey = NULL;
      kid = ssh_xmemdup(a->param->id_kid, a->param->id_kid_len);
      kid_len = a->param->id_kid_len;
      ssh_cmp_header_set_key_id(conf, kid, kid_len, NULL, 0);
      ssh_xfree(kid);
    }

  if (a->param->id_kid_len)
    {
      SshPSWBMac param;
      int i;

      param = ssh_xmalloc(sizeof(*param));
      param->salt = ssh_xmalloc(param->salt_length = 16);
      for (i = 0; i < 16; i++) param->salt[i] = ssh_random_get_byte();
      param->iteration_count = 1024;
      fill_in_digest_algorithms(c, param);

      ssh_cmp_header_set_pswbmac(conf, param,
                                 a->param->id_key, a->param->id_key_len);
    }

  if (version == SSH_CMP_VERSION_1)
    ssh_cmp_body_set_type(conf, SSH_CMP_CONFIRM);
  else
    {
      ssh_cmp_body_set_type(conf, SSH_CMP_CERT_CONFIRM);

      if (ssh_hash_allocate("sha1", &hash) == SSH_CRYPTO_OK)
        {
          digest_len = ssh_hash_digest_length(ssh_hash_name(hash));
          for (i = 0; i < c->nreps; i++)
            {
              ssh_hash_reset(hash);
              ssh_hash_update(hash,
                              c->plaincerts[i].cert,
                              c->plaincerts[i].cert_len);
              ssh_hash_final(hash, digest);

              accepted.status = c->plaincerts[i].info->status;
              accepted.failure = SSH_CMP_FINFO_BAD_TEMPLATE;
              accepted.freetext = NULL;

              ssh_cmp_add_cert_confirm(conf,
                                       c->plaincerts[i].request_id,
                                       digest, digest_len,
                                       &accepted);
            }
          ssh_hash_free(hash);
        }
    }

  if (c->subject.poptype == SSH_X509_POP_SUBSEQ_ENCRYPT_CERT)
    for (i = 0; i < c->nreps; i++)
      ssh_xfree((void *)c->plaincerts[i].cert);

  c->confirm = conf;

    {
      SSH_FSM_SET_NEXT(cmp_send_request);
      c->finished = TRUE;
      SSH_FSM_ASYNC_CALL({
        ssh_cmp_encode(conf, prvkey, cmp_cmp_encode_done, c);
      });
    }
}

SSH_FSM_STEP(cmp_process_response)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCmpStatusInfo status;
  SshStr details, instructions;

  if (c->response == NULL)
    {
      SSH_FSM_SET_NEXT(cmp_done);
      return SSH_FSM_CONTINUE;
    }

  if (ssh_cmp_header_protection_type(c->response)
      == SSH_CMP_PROT_SHARED_SECRET)
    {
      SshEcCmpAuth a = c->current.param;
      if (!ssh_cmp_header_verify_pswbmac(c->response,
                                         a->id_key,
                                         a->id_key_len))
        {
          ssh_warning("Can't validate MACed message from the CA");
          ec_cmp_trans_abort(c->session);
          SSH_FSM_SET_NEXT(cmp_error);
          SSH_FSM_WAIT_THREAD(c->session->thread);
        }
    }

  switch (ssh_cmp_body_get_type(c->response))
    {
    case SSH_CMP_INIT_RESPONSE:
    case SSH_CMP_CERT_RESPONSE:
    case SSH_CMP_KEY_UP_RESPONSE:
      ssh_cmp_get_cert_response(c->response, &c->nreps, &c->reps);
      ssh_cmp_get_extra_certs(c->response, &c->nextra, &c->extra);
      SSH_FSM_SET_NEXT(cmp_cert_decrypt);
      return SSH_FSM_CONTINUE;

    case SSH_CMP_KEY_REC_RESPONSE:
      ssh_cmp_get_recovery_response(c->response, &c->nreps, &c->reps,
                                    &status);
      if (status->status != SSH_CMP_STATUS_GRANTED)
        {
          (*c->error_callback)(status->status,
                               0, 0,
                               status->freetext,
                               NULL,
                               NULL,
                               c->user_callback_context);
          ec_cmp_trans_abort(c->session);
          SSH_FSM_SET_NEXT(cmp_error);
          SSH_FSM_WAIT_THREAD(c->session->thread);
        }
      ssh_cmp_get_extra_certs(c->response, &c->nextra, &c->extra);
      SSH_FSM_SET_NEXT(cmp_cert_decrypt);
      return SSH_FSM_CONTINUE;

    case SSH_CMP_REVOC_RESPONSE:
      SSH_FSM_SET_NEXT(cmp_cert_display_revoked);
      ssh_cmp_get_extra_certs(c->response, &c->nextra, &c->extra);
      return SSH_FSM_YIELD;

    case SSH_CMP_ERROR_MESSAGE:
      ssh_cmp_get_error_msg(c->response, &status, NULL,
                            &details, &instructions);
      (*c->error_callback)(status->status,
                           0, 0,
                           status->freetext,
                           details,
                           instructions,
                           c->user_callback_context);
      SSH_FSM_SET_NEXT(cmp_done);
      if (!c->finished)
        {
          ec_cmp_trans_abort(c->session);
          SSH_FSM_WAIT_THREAD(c->session->thread);
        }
      else
        return SSH_FSM_CONTINUE;
    case SSH_CMP_POLL_RESPONSE:
      {
        SshStr *reasons;
        SshMPInteger *ids;
        SshUInt32 i, *whens, id, npolls;

        ssh_cmp_get_poll_responses(c->response,
                                   &npolls, &ids, &whens, &reasons);
        for (i = 0; i < npolls; i++)
          {
            id = ssh_mprz_get_ui32(ids[i]);
            (*c->error_callback)(SSH_CMP_STATUS_WAITING,
                                 id, whens[i],
                                 NULL,
                                 reasons[i],
                                 NULL,
                                 c->user_callback_context);
          }
        }
      SSH_FSM_SET_NEXT(cmp_done);
      ec_cmp_trans_abort(c->session);
      SSH_FSM_WAIT_THREAD(c->session->thread);
      SSH_NOTREACHED;

    case SSH_CMP_CONFIRM:
      if (!(c->finished))
        {
          ec_cmp_trans_abort(c->session);
          SSH_FSM_SET_NEXT(cmp_done);
          SSH_FSM_WAIT_THREAD(c->session->thread);
        }
      /* else fallthru */
    default:
      SSH_FSM_SET_NEXT(cmp_done);
      break;
    }
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(cmp_done)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);

  (*c->done_callback)(c->user_callback_context);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(cmp_error)
{
  EcCmpEnrollClient c = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Arrived in CMP error state"));

  (*c->error_callback)(SSH_CMP_STATUS_REJECTION,
                       0, 0,
                       NULL, NULL, NULL,
                       c->user_callback_context);

  (*c->done_callback)(c->user_callback_context);

  return SSH_FSM_FINISH;
}

/* Input structures are stolen (and eventually freed) by the
   library. */
SshOperationHandle
ssh_ec_cmp_enroll(SshCmpBodyType which,
                  SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshEcCmpKeyPair keypair, Boolean backup, Boolean encrypt,
                  SshX509Certificate certtemp,
                  size_t num_extra_certs,
                  SshEcCertStruct *extra_certs,
                  SshEcCmpCB callback,
                  SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context)
{
  SshCmpVersion version = ca->protocol_version;
  SshFSM fsm;
  SshFSMThread thread;
  EcCmpEnrollClient c;
  SshX509Certificate cacert = NULL;

  if (backup &&
      ((ca->identity_type != SSH_EC_CA_ID_CERT)
       || (ca->identity.cert.len == 0)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("CA required for backup operation"));
      goto fail;
    }

  if (ca->identity_type == SSH_EC_CA_ID_CERT)
    {
      cacert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->id_cert, ca->id_cert_len, cacert)
          != SSH_X509_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to decode CA certificate"));
          goto fail;
        }
    }

  if (backup)
    {
      SshPublicKey cakey = NULL;
      const char *name = NULL;
      if ((ca->identity_type != SSH_EC_CA_ID_CERT)
          || (    ca->identity_type == SSH_EC_CA_ID_CERT
               && ca->identity.cert.len == 0))
        goto fail;
      if ((FALSE == ssh_x509_cert_get_public_key(cacert, &cakey)) ||
          (SSH_CRYPTO_OK != ssh_public_key_get_info(cakey,
                                                    SSH_PKF_ENCRYPT,
                                                    &name,
                                                    SSH_PKF_END)) ||
          (!name || !*name))
        {
          ssh_public_key_free(cakey);
          goto fail;
        }
      ssh_public_key_free(cakey);
  }

  fsm = ssh_fsm_create(NULL);

  c = ssh_xcalloc(1, sizeof(*c));

  thread = ssh_fsm_thread_create(fsm,
                                 cmp_compose_template,
                                 NULL_FNPTR, ec_cmp_fsm_destroy,
                                 c);

  ssh_fsm_set_thread_name(thread, "ec-cmp enroll thread");

  c->fsm = fsm;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Version: %d", version));
  c->version = version;
  c->transport_level_poll = ca->transport_level_poll;
  c->rfc2511_compatibility = ca->rfc2511_compatibility;
  c->prefer_sha256 = ca->prefer_sha256;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("RFC 2511 compatibility: %d, prefer sha256: %d",
             c->rfc2511_compatibility, c->prefer_sha256));

  c->opcode = which;
  c->thread = thread;
  c->ca.param = ca;
  c->ca.certtemp = cacert;
  if (num_extra_certs)
    {
      int ii;
      c->extra_certs = ssh_xcalloc(num_extra_certs, sizeof(*c->extra_certs));
      for (ii = 0; ii < num_extra_certs; ii++)
        {
          c->extra_certs[ii].ber = ssh_xmemdup(extra_certs[ii].ber,
                                               extra_certs[ii].ber_len);
          c->extra_certs[ii].ber_len = extra_certs[ii].ber_len;
        }
      c->num_extra_certs = num_extra_certs;
    }
  c->current.param = authenticator;
  if (authenticator->identity_type == SSH_EC_EE_ID_CERT ||
      authenticator->identity_type == SSH_EC_EE_ID_RA)
    {
      c->current.certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      ssh_x509_cert_decode(authenticator->id_cert,
                           authenticator->id_cert_len, c->current.certtemp);
    }

  if (encrypt)
    c->subject.poptype = SSH_X509_POP_SUBSEQ_ENCRYPT_CERT;
  else
    c->subject.poptype = SSH_X509_POP_SUBSEQ_UNDEF;

  c->subject.keypair = keypair;
  c->subject.do_backup = backup;
  c->subject.backup_done = FALSE;
  c->subject.certtemp = certtemp;
  c->user_callback = callback;
  c->done_callback = done;
  c->error_callback = error;
  c->user_callback_context = callback_context;

  c->session = NULL;

  return NULL;

 fail:
  ssh_x509_cert_free (cacert);
  (*error)(SSH_CMP_STATUS_REJECTION,
           0, 0,
           NULL, NULL, NULL,
           callback_context);
  (*done)(callback_context);
  return NULL;
}

/* Input structures are stolen (and eventually freed) by the
   library. */
SshOperationHandle
ssh_ec_cmp_revoke(SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshX509Certificate certtemp,
                  SshEcCmpRevokeCB callback, SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  EcCmpEnrollClient tmp = callback_context;
  EcCmpEnrollClient c;
  SshX509Certificate cacert = NULL;

  if (ca->identity_type == SSH_EC_CA_ID_CERT)
    {
      cacert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->id_cert, ca->id_cert_len, cacert)
          != SSH_X509_OK)
        {
          (*callback)(NULL, 0, callback_context);
          (*done)(callback_context);
          return NULL;
        }
    }

  fsm = ssh_fsm_create(NULL);

  c = ssh_xcalloc(1, sizeof(*c));
  thread = ssh_fsm_thread_create(fsm,
                                 cmp_compose_template,
                                 NULL_FNPTR, ec_cmp_fsm_destroy,
                                 c);

  ssh_fsm_set_thread_name(thread, "ec-cmp revoke thread");

  c->fsm = fsm;
  c->opcode = SSH_CMP_REVOC_REQUEST;
  c->version = ca->protocol_version;
  c->version = ca->transport_level_poll;
  c->thread = thread;
  c->ca.param = ca;
  c->ca.certtemp = cacert;
  c->current.param = authenticator;
  if (authenticator->identity_type == SSH_EC_EE_ID_CERT)
    {
      c->current.certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      ssh_x509_cert_decode(authenticator->id_cert,
                           authenticator->id_cert_len, c->current.certtemp);
    }
  c->subject.keypair = NULL;
  c->subject.do_backup = FALSE;
  c->subject.backup_done = FALSE;
  c->subject.poptype = SSH_X509_POP_SUBSEQ_UNDEF;
  certtemp->type = SSH_X509_PKIX_CRMF;
  if (authenticator->identity_type == SSH_EC_EE_ID_RA)
    certtemp->pop.ra_verified = TRUE;
  c->rfc2511_compatibility = tmp->rfc2511_compatibility;
  c->subject.certtemp = certtemp;
  c->user_revoked_callback = callback;
  c->error_callback = error;
  c->done_callback = done;
  c->user_callback_context = callback_context;

  c->session = NULL;

  return NULL;
}

SshOperationHandle
ssh_ec_cmp_recover(SshEcCmpCA ca,
                   SshEcCmpAuth authenticator,
                   SshX509Certificate certtemp,
                   SshPublicKey protocol_encryption_key,
                   SshEcCmpCB callback, SshEcCmpDoneCB done,
                   SshEcCmpErrorCB error,
                   void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  EcCmpEnrollClient c;
  SshX509Certificate cacert = NULL;

  if (ca->identity_type == SSH_EC_CA_ID_CERT)
    {
      cacert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->id_cert, ca->id_cert_len, cacert)
          != SSH_X509_OK)
        {
          (*callback)(SSH_CMP_STATUS_REJECTION,
                      NULL, 0, NULL, 0,
                      NULL_FNPTR, NULL, callback_context);
          (*done)(callback_context);
        }
    }

  fsm = ssh_fsm_create(NULL);

  c = ssh_xcalloc(1, sizeof(*c));
  thread = ssh_fsm_thread_create(fsm,
                                 cmp_compose_template,
                                 NULL_FNPTR, ec_cmp_fsm_destroy,
                                 c);

  ssh_fsm_set_thread_name(thread, "ec-cmp recover thread");

  c->fsm = fsm;
  c->opcode = SSH_CMP_KEY_REC_REQUEST;
  c->thread = thread;
  c->ca.param = ca;
  c->ca.certtemp = cacert;
  c->current.param = authenticator;
  if (authenticator->identity_type == SSH_EC_EE_ID_CERT)
    {
      c->current.certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      ssh_x509_cert_decode(authenticator->id_cert,
                           authenticator->id_cert_len, c->current.certtemp);

    }
  c->subject.keypair = NULL;
  c->subject.do_backup = FALSE;
  c->subject.backup_done = FALSE;
  c->subject.poptype = SSH_X509_POP_SUBSEQ_UNDEF;
  certtemp->type = SSH_X509_PKIX_CRMF;
  if (authenticator->identity_type == SSH_EC_EE_ID_RA)
    certtemp->pop.ra_verified = TRUE;
  c->subject.certtemp = certtemp;
  c->subject.protocol_encryption_key = protocol_encryption_key;

  c->user_callback = callback;
  c->done_callback = done;
  c->error_callback = error;
  c->user_callback_context = callback_context;

  c->version = ca->protocol_version;
  c->transport_level_poll = ca->transport_level_poll;
  c->session = NULL;

  return NULL;
}

/* This eats ids array */
SshOperationHandle
ssh_ec_cmp_poll(SshEcCmpCA ca,
                SshEcCmpAuth authenticator,
                SshUInt32 nids, SshMPInteger ids,
                SshEcCmpCB callback,
                SshEcCmpDoneCB done,
                SshEcCmpErrorCB error,
                void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  EcCmpEnrollClient c;

  fsm = ssh_fsm_create(NULL);

  c = ssh_xcalloc(1, sizeof(*c));
  thread = ssh_fsm_thread_create(fsm,
                                 cmp_compose_envelope,
                                 NULL_FNPTR, ec_cmp_fsm_destroy,
                                 c);

  ssh_fsm_set_thread_name(thread, "ec-cmp poll thread");

  c->fsm = fsm;
  c->opcode = SSH_CMP_POLL_REQUEST;
  c->version = ca->protocol_version;
  c->transport_level_poll = ca->transport_level_poll;
  c->thread = thread;
  c->ca.param = ca;
  c->current.param = authenticator;
  if (authenticator->identity_type == SSH_EC_EE_ID_CERT)
    {
      c->current.certtemp = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      ssh_x509_cert_decode(authenticator->id_cert,
                           authenticator->id_cert_len, c->current.certtemp);
    }

  if (ca->identity_type == SSH_EC_CA_ID_CERT)
    {
      SshX509Certificate cacert;

      cacert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->id_cert, ca->id_cert_len, cacert)
          != SSH_X509_OK)
        {
          (*callback)(SSH_CMP_STATUS_REJECTION,
                      NULL, 0, NULL, 0,
                      NULL_FNPTR, NULL, callback_context);
          (*done)(callback_context);
          return NULL;
        }
      c->ca.certtemp = cacert;
    }
  c->subject.keypair = NULL;
  c->subject.do_backup = FALSE;
  c->subject.poptype = SSH_X509_POP_SUBSEQ_UNDEF;
  c->subject.num_request_ids = nids;
  c->subject.request_ids = ids;

  c->user_callback = callback;
  c->error_callback = error;
  c->done_callback = done;
  c->user_callback_context = callback_context;

  c->version = ca->protocol_version;
  c->session = NULL;

  return NULL;

}
#endif /* SSHDIST_CERT */
