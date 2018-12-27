/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CEP enrollment client.
*/

#include "sshincludes.h"

#ifdef SSHDIST_CERT

#include "sshinet.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshfileio.h"
#include "sshexternalkey.h"
#include "sshgetopt.h"
#include "x509.h"
#include "x509scep.h"
#include "sshenroll.h"
#include "sshfsm.h"
#include "sshprvkey.h"
#ifdef SSHDIST_VALIDATOR_HTTP
#include "sshhttp.h"
#else /* SSHDIST_VALIDATOR_HTTP */
#include "sshtcp.h"
#endif /* SSHDIST_VALIDATOR_HTTP */
#include "sshurl.h"
#include "sshpkcs7.h"

#include "au-ek.h"
#include "ec-cep.h"

int brokenflags = 0;

typedef struct
SshCepEnrollClientRec *SshCepEnrollClient, SshCepEnrollClientStruct;

#define SSH_DEBUG_MODULE "SshEcCep"

typedef struct SshCepEnrollCaRec
{
  SshX509Certificate rasign;
  SshX509Certificate raencr;
#define catemp rasign

  SshEcCepCA param;
  SshCepEnrollClient client;
} *SshCepEnrollCa, SshCepEnrollCaStruct;

typedef struct SshCepEnrollEntityRec
{
  SshEcCepKeyPair keypair;
  unsigned char *cert; size_t cert_len;
  SshX509Certificate certtemp;
  SshCepEnrollClient client;
} *SshCepEnrollEntity, SshCepEnrollEntityStruct;

typedef struct SshCepEnrollAuthenticatorRec
{
  SshEcCepAuth param;
} *SshCepEnrollAuthenticator, SshCepEnrollAuthenticatorStruct;

struct SshCepEnrollClientRec
{
  SshCepEnrollCaStruct ca;
  SshCepEnrollAuthenticatorStruct current;
  SshCepEnrollEntityStruct subject;

  SshFSMThread thread;

  unsigned char *request, *response;
  size_t request_len, response_len;

  /* Select/save certificates and private keys CB */
  SshEcCepCB user_callback;
  void *user_callback_context;

  int number_of_polls;
  SshPkiSession session;
};

#ifdef SSHDIST_VALIDATOR_HTTP
static char *cep_iperror_to_string(SshTcpError err)
{
  switch (err)
    {
    case SSH_TCP_OK: return "no error";
    case SSH_TCP_NEW_CONNECTION: return "new connection";
    case SSH_TCP_NO_ADDRESS: return "unknown host";
    case SSH_TCP_NO_NAME: return "reverse DNS failed";
    case SSH_TCP_UNREACHABLE: return "destination unreachable";
    case SSH_TCP_REFUSED: return "connection refused";
    case SSH_TCP_TIMEOUT: return "connection timeout";
    case SSH_TCP_FAILURE: return "unspecified failure";
    }
  return("unknown error");
}
#endif /* SSHDIST_VALIDATOR_HTTP */


SSH_FSM_STEP( cep_compose_template );
SSH_FSM_STEP( cep_compose_envelope );
SSH_FSM_STEP( cep_send_request );
SSH_FSM_STEP( cep_process_response );
SSH_FSM_STEP( cep_done );
SSH_FSM_STEP( cep_error );

static void
cep_crt_encode_done(SshX509Status status,
                    const unsigned char *ber, size_t ber_len,
                    void *context)
{
  SshCepEnrollClient c = context;

  if (status == SSH_X509_OK)
    {
      c->subject.cert = ssh_xmemdup(ber, ber_len);
      c->subject.cert_len = ber_len;
    }
  else
    ssh_fsm_set_next(c->thread, cep_done);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}


SSH_FSM_STEP(cep_compose_template)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCepEnrollEntity s = &c->subject;
  SshCepEnrollAuthenticator a = &c->current;
  const char *kt;

  /* Template came from command line options and key generation, it
     has been filled with this information.  Now only insert the
     challenge password. */

  if (a->param && a->param->id_key_len > 0)
    {
      SshX509Attribute challattr = ssh_xcalloc(1, sizeof(*challattr));

      challattr->type = SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD;
      challattr->len = a->param->id_key_len;
      challattr->data = ssh_xstrdup(a->param->id_key);
      ssh_x509_cert_set_attribute(c->subject.certtemp, challattr);
    }

  /* Then select signature scheme. */
  if (ssh_private_key_get_info(s->keypair->prvkey,
                               SSH_PKF_KEY_TYPE, &kt,
                               SSH_PKF_END) == SSH_CRYPTO_OK)
    {
      const char *sign;

      if (!strncasecmp(kt, "if-modn", sizeof("if-modn")))
        sign = "rsa-pkcs1-md5";
      else
        sign = "dsa-nist-sha1";

      ssh_private_key_select_scheme(s->keypair->prvkey,
                                    SSH_PKF_SIGN, sign, SSH_PKF_END);
    }

  SSH_FSM_SET_NEXT(cep_compose_envelope);

  /* And sign. */
  s->certtemp->type =  SSH_X509_PKCS_10;

  SSH_FSM_ASYNC_CALL({
    ssh_x509_cert_encode_async(s->certtemp,
                               s->keypair->prvkey,
                               cep_crt_encode_done, c);
  });
}

static void
cep_cep_encode_done(SshScepStatus status,
                    SshScepFailure failure,
                    const SshScepTransactionAndNonce txnonce,
                    const unsigned char *ber, size_t ber_len,
                    void *context)
{
  SshCepEnrollClient c = context;

  if (status == SSH_SCEP_OK)
    {



      if (c->request)
        ssh_free(c->request);
      c->request = ssh_xmemdup(ber, ber_len);
      c->request_len = ber_len;
    }
  else
    {
      ssh_fsm_set_next(c->thread, cep_done);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(cep_compose_envelope)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCepEnrollEntity s = &c->subject;
  SshCepEnrollCa ca = &c->ca;

  SSH_FSM_SET_NEXT(cep_send_request);
  if (c->number_of_polls == 0)
    {
      SSH_FSM_ASYNC_CALL({
        ssh_scep_create_request(s->keypair->prvkey,
                                s->certtemp,
                                ca->raencr ? ca->raencr : ca->catemp,
                                cep_cep_encode_done, c);
      });
    }
  else
    {
      SSH_FSM_ASYNC_CALL({
        ssh_scep_create_poll(s->keypair->prvkey,
                             s->certtemp,
                             ca->raencr ? ca->raencr : ca->catemp,
                             cep_cep_encode_done, c);
      });
    }
}


static void
cep_cep_receive_done(SshPkiStatus status,
                     SshPkiSession session, void *context)
{
  const unsigned char *data;
  size_t len;
  SshCepEnrollClient c = context;
  char *linear;

  SSH_DEBUG(4, ("status %d", status));

  if ((linear = ssh_pki_session_linearize(session)) != NULL)
    {
      c->session = ssh_pki_session_delinearize(linear);
      ssh_free(linear);
    }
  else
    c->session = NULL;

  switch (status)
    {
    case SSH_PKI_OK:
      if (!ssh_pki_enrollment_get_response(session, &data, &len))
        {
          ssh_fsm_set_next(c->thread, cep_done);
          goto failed;
        }
      else
        {
          ssh_fsm_set_next(c->thread, cep_process_response);

          if (c->response)
            ssh_xfree(c->response);
          c->response = ssh_xmemdup(data, len);
          c->response_len = len;
        }
      break;

    case SSH_PKI_FAILED:
      ssh_fsm_set_next(c->thread, cep_done);
      goto failed;

    case SSH_PKI_DELAYED:
      SSH_NOTREACHED;
      break;

    default:
      break;
    }

 failed:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

SSH_FSM_STEP(cep_send_request)
{
  SshPkiSession session;
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);
  SshCepEnrollCa  ca = &c->ca;

  if (c->session == NULL)
    session = ssh_pki_session_create(SSH_PKI_SCEP,
                                     ca->param->address,
                                     ca->param->proxy, ca->param->socks,
                                     60, 24*3600);
  else
    session = c->session;

  SSH_FSM_SET_NEXT(cep_process_response);
  SSH_FSM_ASYNC_CALL({
    ssh_pki_enroll(session,
                   c->request, c->request_len,
                   cep_cep_receive_done, c);
  });
}


static void
cep_response_parsed(SshScepStatus status,
                    SshScepFailure failure,
                    const SshScepTransactionAndNonce txnonce,
                    const unsigned char *der, size_t der_len,
                    void *context)
{
  const char *status_string, *failure_string;
  SshCepEnrollClient c = context;
  SshEcCepCertStruct certs[1];

  SSH_DEBUG(2, ("status %d, failure %d", status, failure));

  status_string = failure_string = NULL;
  switch (status)
    {
    case SSH_SCEP_OK:
      certs[0].data_is_state = FALSE;
      certs[0].data = (unsigned char *)der;
      certs[0].len = der_len;
      (*c->user_callback)(SSH_X509_OK,
                          &certs[0], 1,
                          c->user_callback_context);
      break;

    case SSH_SCEP_PENDING:
      SSH_DEBUG(5, ("pending, polls %d", c->number_of_polls));

      /* Now send one getCertInitial. If we get one back, well save
         the state and exit, so the user can later issue POLL's */
#if 1
      if (c->number_of_polls == 0)
        {
          char *state;

          c->number_of_polls += 1;
          state = ssh_pki_session_linearize(c->session);
          ssh_pki_session_free(c->session);
          c->session = ssh_pki_session_delinearize(state);
          ssh_fsm_set_next(c->thread, cep_compose_envelope);
          ssh_free(state);

          /* Add small delay so CA/RA has time to process the request. */
#ifdef WIN32
          Sleep(5);
#else
          sleep(5);
#endif /* WIN32 */
          break;
        }
      else
#endif
        {
          certs[0].data_is_state = TRUE;
          certs[0].data =
            (unsigned char *)ssh_pki_session_linearize(c->session);
          certs[0].len = strlen((char *)certs[0].data);
          (*c->user_callback)(SSH_X509_OK,
                              &certs[0], 1,
                              c->user_callback_context);
          ssh_free(certs[0].data);
        }
      break;

    case SSH_SCEP_FAILURE:
      status_string = "SCEP Failure";
      /* fall */
    case SSH_SCEP_ERROR:
      if (!status_string)
        status_string = "SCEP Error";

      switch (failure)
        {
        case SSH_SCEP_FINFO_BAD_ALG:
          failure_string = "Unrecognized or unsupported algorithm";
          break;
        case SSH_SCEP_FINFO_BAD_CHECK:
          failure_string = "Integrity check failed";
          break;
        case SSH_SCEP_FINFO_BAD_REQ:
          failure_string = "Transaction not permitted or supported";
          break;
        case SSH_SCEP_FINFO_BAD_TIME:
          failure_string = "Message time too far from the system time";
          break;
        case SSH_SCEP_FINFO_BAD_ID:
          failure_string = "No certificate could be identified matching the "
            "provided criteria";
          break;
        default:
          failure_string = "Unknown failure code";
          break;
        }
        ssh_warning("SCEP enrollment failed with status: %s\n"
                    "Failure reason: %s",
                    status_string, failure_string);

        (*c->user_callback)(SSH_X509_FAILURE,
                            NULL, 0,
                            c->user_callback_context);

        break;
      break;

    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(c->thread);
}

static void
cep_response_find_keys(const SshScepTransactionAndNonce txnonce,
                       SshScepClientCertAndKeyRep result,
                       void *result_context,
                       void *context)
{
  SshCepEnrollClient c = context;





  (*result)(c->ca.raencr ? c->ca.rasign : c->ca.catemp,
            c->subject.keypair->prvkey,
            result_context);
}

SSH_FSM_STEP(cep_process_response)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);

  SSH_FSM_SET_NEXT(cep_done);
  SSH_FSM_ASYNC_CALL({
    if (ssh_scep_parse_response(c->response, c->response_len,
                                cep_response_find_keys,
                                cep_response_parsed,
                                c) != SSH_SCEP_OK)
      cep_response_parsed(SSH_SCEP_FAILURE,
                          SSH_SCEP_FINFO_BAD_REQ,
                          NULL,
                          NULL, 0,
                          c);
  });
}

static void ec_cep_free_client(SshCepEnrollClient c)
{
  SshEcCepAuth auth = c->current.param;
  SshEcCepCA ca = c->ca.param;

  if (c->ca.raencr) ssh_x509_cert_free(c->ca.raencr);
  if (c->ca.rasign) ssh_x509_cert_free(c->ca.rasign);

  ssh_xfree(ca->ca_cert);
  ssh_xfree(ca->ra_encr);
  ssh_xfree(ca->address);
  ssh_xfree(ca->socks);
  ssh_xfree(ca->proxy);
  ssh_xfree(ca);

  if (auth)
    {
      ssh_xfree(auth->id_key);
      ssh_xfree(auth);
    }

  if (c->subject.keypair)
    {
      ssh_private_key_free(c->subject.keypair->prvkey);
      ssh_public_key_free(c->subject.keypair->pubkey);
      ssh_xfree(c->subject.keypair);
    }
  ssh_xfree(c->subject.cert);
  ssh_x509_cert_free(c->subject.certtemp);

  ssh_xfree(c->request);
  ssh_xfree(c->response);
  if (c->session)
    ssh_pki_session_free(c->session);
  ssh_xfree(c);
}

SSH_FSM_STEP(cep_done)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);

  ec_cep_free_client(c);
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(cep_error)
{
  SshCepEnrollClient c = ssh_fsm_get_tdata(thread);

  (*c->user_callback)(SSH_X509_OK, NULL, 0, c->user_callback_context);
  ec_cep_free_client(c);
  ssh_fsm_destroy(ssh_fsm_get_fsm(thread));
  return SSH_FSM_FINISH;
}

Boolean
ec_cep_decode_ca_ra_certs(SshEcCepCA ca,
                          SshX509Certificate *cacert,
                          SshX509Certificate *raencr,
                          SshX509Certificate *rasign)
{
  if (ca->identity_type == SSH_EC_CA_TYPE_CA)
    {
      *cacert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->ca_cert, ca->ca_cert_len, *cacert)
          != SSH_X509_OK)
        {
          ssh_x509_cert_free(*cacert);
          *cacert = NULL;
        }
    }
  else
    {
      *raencr = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      *rasign = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
      if (ssh_x509_cert_decode(ca->ra_sign, ca->ra_sign_len,
                               *rasign) != SSH_X509_OK ||
          ssh_x509_cert_decode(ca->ra_encr, ca->ra_encr_len,
                               *raencr) != SSH_X509_OK)
        {
          ssh_x509_cert_free(*raencr);
          ssh_x509_cert_free(*rasign);
          *raencr = *rasign = NULL;
        }
    }
  if (!(*cacert || *rasign || *raencr))
    {
      return FALSE;
    }

  return TRUE;
}

/* Input structures are stolen (and eventually freed) by the
   library. */
SshOperationHandle
ssh_ec_cep_enroll(SshEcCepCA ca,
                  SshEcCepAuth authenticator,
                  SshEcCepKeyPair keypair,
                  SshX509Certificate certtemp,
                  SshEcCepCB callback, void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  SshCepEnrollClient c;
  SshX509Certificate cacert = NULL, rasign = NULL, raencr = NULL;

  fsm = ssh_fsm_create(NULL);
  c = ssh_xcalloc(1, sizeof(*c));

  thread = ssh_fsm_thread_create(fsm,
                                 cep_compose_template,
                                 NULL_FNPTR, NULL_FNPTR,
                                 c);
  c->thread = thread;

  if (!ec_cep_decode_ca_ra_certs(ca, &cacert, &raencr, &rasign))
    return NULL;
  if (ca->identity_type == SSH_EC_CA_TYPE_CA)
    c->ca.catemp = cacert;
  else
    {
      c->ca.raencr = raencr;
      c->ca.rasign = rasign;
    }


  c->ca.param = ca;
  c->current.param = authenticator;
  c->subject.keypair = keypair;
  c->subject.certtemp = certtemp;
  c->user_callback = callback;
  c->user_callback_context = callback_context;

  c->number_of_polls = 0;
  c->session = NULL;

  return NULL;
}


SshOperationHandle
ssh_ec_cep_poll(SshEcCepCA ca,
                SshEcCepKeyPair keypair,
                char *state,
                SshEcCepCB callback, void *callback_context)
{
  SshFSM fsm;
  SshFSMThread thread;
  SshCepEnrollClient c;
  SshX509Certificate cacert = NULL, rasign = NULL, raencr = NULL;

  fsm = ssh_fsm_create(NULL);
  c = ssh_xcalloc(1, sizeof(*c));

  thread = ssh_fsm_thread_create(fsm,
                                 cep_send_request,
                                 NULL_FNPTR, NULL_FNPTR,
                                 c);
  c->thread = thread;

  if (!ec_cep_decode_ca_ra_certs(ca, &cacert, &raencr, &rasign))
    return NULL;
  if (ca->identity_type == SSH_EC_CA_TYPE_CA)
    c->ca.catemp = cacert;
  else
    {
      c->ca.raencr = raencr;
      c->ca.rasign = rasign;
    }

  c->ca.param = ca;
  c->subject.keypair = keypair;
  c->user_callback = callback;
  c->user_callback_context = callback_context;

  c->number_of_polls = 1;
  c->session = ssh_pki_session_delinearize(state);
  return NULL;
}

typedef struct {
  SshBufferStruct input;
  SshStream stream;
#ifdef SSHDIST_VALIDATOR_HTTP
  SshHttpClientContext httpclient;
#endif /* SSHDIST_VALIDATOR_HTTP */
  int type;
  SshEcCepCB callback;
  void *callback_context;
} *ScepAuthenticate;

void dumpcerts(SshPkcs7 envelope, ScepAuthenticate c)
{
  unsigned char **bers;
  size_t *ber_lens, nobjects, i;
  SshEcCepCert certs;

  if ((nobjects = ssh_pkcs7_get_certificates(envelope, &bers, &ber_lens)) > 0)
    {
      certs = ssh_xcalloc(nobjects, sizeof(*certs));
      for (i = 0; i < nobjects; i++)
        {
          certs[i].data = bers[i];
          certs[i].len = ber_lens[i];
        }
      (*c->callback)(SSH_X509_OK, certs, nobjects, c->callback_context);
      ssh_xfree(certs);
    } else {
      (*c->callback)(SSH_X509_FAILURE, NULL, 0, c->callback_context);
    }
  ssh_xfree(bers);
  ssh_xfree(ber_lens);
}

#ifdef SSHDIST_VALIDATOR_HTTP
static void
cep_http_stream_callback(SshStreamNotification not, void *context)
{
  int i;
  unsigned char input[256];
  ScepAuthenticate c = context;
  SshPkcs7 pkcs7;

  while (TRUE)
    {
      i = ssh_stream_read(c->stream, input, sizeof(input));
      if (i == 0)
        {
          if (c->type == 1)
            {
              SshEcCepCert certs;

              certs = ssh_xcalloc(1, sizeof(*certs));
              certs[i].data = ssh_buffer_ptr(&c->input);
              certs[i].len = ssh_buffer_len(&c->input);

              (*c->callback)(SSH_X509_OK, certs, 1, c->callback_context);
              ssh_xfree(certs);
            }
          else
            {
              printf("Received CA and RA certificate chain.\n");
              ssh_pkcs7_decode(ssh_buffer_ptr(&c->input),
                               ssh_buffer_len(&c->input),
                               &pkcs7);
              dumpcerts(pkcs7, c);
              ssh_pkcs7_free(pkcs7);
            }

          ssh_buffer_uninit(&c->input);
          ssh_stream_destroy(c->stream);
          ssh_http_client_uninit(c->httpclient);
          ssh_xfree(c);
          return;
        }
      else if (i < 0)
        return;
      else
        ssh_xbuffer_append(&c->input, input, i);
    }
}

static void cep_readstream_destructor(void *ctx)
{
  ScepAuthenticate c = ctx;

  ssh_buffer_uninit(&c->input);
  if (c->stream) ssh_stream_destroy(c->stream);
  ssh_http_client_uninit(c->httpclient);
  ssh_xfree(c);
}

static void
cep_ca_authenticated(SshHttpClientContext ctx,
                     SshHttpResult result,
                     SshTcpError ip_error,
                     SshStream stream,
                     void *callback_context)
{
  const char *type;
  ScepAuthenticate c = callback_context;

  if (result == SSH_HTTP_RESULT_SUCCESS)
    {
      c->stream = stream;

      type = (const char *) ssh_http_get_header_field(ctx,
                                              (unsigned char *)"Content-Type");
      if (!type)
        {
          ssh_warning("Did not receive proper response from the server; "
                      "check the CA Address URL.");
          (*c->callback)(SSH_X509_FAILURE,
                         NULL, 0, c->callback_context);
          ssh_xregister_timeout(0, 0, cep_readstream_destructor, c);
          return;
        }
      if (!(
            /* draft-nourse-scep */
            (strcmp(type, "application/x-x509-ca-ra-cert-chain") == 0) ||
            (strcmp(type, "application/x-x509-ca-ra-cert") == 0)       ||
            (strcmp(type, "application/x-x509-ca-cert") == 0)          ||
            /* interoperability */
            (strcmp(type, "application/x-x509-ca-ra-certs") == 0)      ||
            (strcmp(type, "application/x-x509-ra-ca-certs") == 0)      ||
            (strcmp(type, "application/x-x509-ra-ca-cert") == 0)))
        {
          ssh_warning("Server replied with unknown response type: %s",
                      type?type:"no type");
          (*c->callback)(SSH_X509_FAILURE,
                         NULL, 0, c->callback_context);
          ssh_xregister_timeout(0, 0, cep_readstream_destructor, c);
          return;
        }

      if (strcmp(type, "application/x-x509-ca-cert") == 0)
        c->type = 1;
      else /* ra-ca-cert(s) or ca-ra-cert(s) */
        c->type = 2;

      ssh_stream_set_callback(stream, cep_http_stream_callback, c);
      cep_http_stream_callback(SSH_STREAM_INPUT_AVAILABLE, c);
    } /* SSH_HTTP_RESULT_SUCCESS */
  else
    {
      if (result == SSH_HTTP_RESULT_CONNECT_FAILED)
        ssh_warning("IP connection to server failed: %s",
                    cep_iperror_to_string(ip_error));
      else
        ssh_warning("HTTP connection to server failed: %s",
                    ssh_http_error_code_to_string(result));

      (*c->callback)(SSH_X509_FAILURE, NULL, 0, c->callback_context);
      ssh_xregister_timeout(0, 0, cep_readstream_destructor, c);
      return;
    }
}

SshOperationHandle
ssh_ec_cep_authenticate(SshEcCepCA ca,
                        SshEcCepCB callback, void *context)
{
  SshBufferStruct buffer;
  SshHttpClientContext http;
  SshHttpClientParams params;
  unsigned char *caname_url;
  SshOperationHandle op;
  char *opname;
  ScepAuthenticate c;

  c = ssh_xmalloc(sizeof(*c));
  c->stream = NULL;
  c->type = 0;
  c->callback = callback;
  c->callback_context = context;
  ssh_buffer_init(&c->input);

  if (ca->identity_type == SSH_EC_CA_TYPE_CA)
    opname = "GetCACert";
  else
    opname = "GetCACertChain";

  ssh_buffer_init(&buffer);
  caname_url = ssh_url_data_encode((unsigned char *)ca->name,
                                   strlen(ca->name),
                                   NULL);
  ssh_xbuffer_append_cstrs(&buffer,
                           ca->address,
                           "?operation=", opname, "&message=", caname_url,
                          NULL);
  ssh_xfree(caname_url);

  ssh_xbuffer_append(&buffer, (unsigned char *)"\0", 1);
  memset(&params, 0, sizeof(params));

  params.socks = ca->socks;
  params.http_proxy_url = ca->proxy;

  http = ssh_http_client_init(&params);
  c->httpclient = http;
  op = ssh_http_get(http,
                    ssh_buffer_ptr(&buffer),
                    cep_ca_authenticated, c,
                    SSH_HTTP_HDR_USE_HTTP_1_0,
                    SSH_HTTP_HDR_CONNECTION_CLOSE,
                    SSH_HTTP_HDR_END);

  ssh_xfree(ca->socks);
  ssh_xfree(ca->proxy);
  ssh_xfree(ca->address);
  ssh_xfree(ca->name);
  ssh_xfree(ca);
  ssh_buffer_uninit(&buffer);
  return op;
}
#endif /* SSHDIST_VALIDATOR_HTTP */
#endif /* SSHDIST_CERT */
