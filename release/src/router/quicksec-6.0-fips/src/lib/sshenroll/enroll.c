/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic PKI client enrollment layer that hides the details of
   actual protocols. Input is the CMP message and output is a
   session where one can extract CMP messages.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "enroll-internal.h"
#include "sshbase64.h"

#ifdef SSHDIST_CERT

#include "enroll-scep.h"
#include "enroll-pkix.h"

#define SSH_DEBUG_MODULE "SshPkiEnroll"

/* Match values at SshPkiType */
static const struct SshPkiSessionMethodRec
ssh_pki_enroll_all_methods[] =
{
  {
    "scep", SSH_PKI_SCEP,
    ssh_pki_scep_session_start,
    NULL_FNPTR,
    ssh_pki_scep_session_finish,
    ssh_pki_scep_session_linearize,
    ssh_pki_scep_session_delinarize,
  },
  {
    "pkix", SSH_PKI_CMP,
    ssh_pki_pkix_session_start,
    ssh_pki_pkix_session_confirm,
    ssh_pki_pkix_session_finish,
    ssh_pki_pkix_session_linearize,
    ssh_pki_pkix_session_delinarize,
  },
  { NULL, }
};


void ssh_pki_session_abort(void *context)
{
  SshPkiSession session = (SshPkiSession)context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Enrollment is aborted (sess=%p thread=%p)",
                           session, session->method_context));

  session->operation = NULL;
  if (session->methods->finish)
    (*session->methods->finish)(session);
}

void ssh_pki_session_free(SshPkiSession session)
{
  ssh_operation_unregister(session->operation);
  ssh_free(session->response);
  ssh_free(session->request);
  ssh_free(session->access);
  ssh_free(session->proxy);
  ssh_free(session->socks);
  ssh_free(session->extra);
  ssh_free(session);
}

SshPkiSession
ssh_pki_session_create(SshPkiType type,
                       const unsigned char *ca_access_uri,
                       const unsigned char *http_proxy_uri,
                       const unsigned char *socks_server_uri,
                       SshUInt32 retry_timer_secs,
                       SshUInt32 expire_timer_secs)
{
  SshPkiSession session;
  int i;
  const SshPkiSessionMethodStruct *m;

  if ((session = ssh_calloc(1, sizeof(*session))) == NULL)
    return NULL;

  session->type = type;

  for (i = 0; ssh_pki_enroll_all_methods[i].name; i++)
    {
      m = &ssh_pki_enroll_all_methods[i];
      if (m->method == type)
        {
          session->methods = m;
          break;
        }
    }
#define SSH_STRDUP(_str) ((_str) ? ssh_ustrdup((_str)) : ssh_strdup(""))

  session->done         = NULL_FNPTR;
  session->done_context = NULL;
  session->flags        = 0;
  session->request      = NULL;
  session->request_len  = 0;
  session->response     = NULL;
  session->response_len = 0;
  session->access       = SSH_STRDUP(ca_access_uri);
  session->proxy        = SSH_STRDUP(http_proxy_uri);
  session->socks        = SSH_STRDUP(socks_server_uri);
  session->polling_id   = 0;
  session->polling_time = 0;
  session->operation    = NULL;
  session->extra        = NULL;
  session->extra_len    = 0;

  session->polling_interval = retry_timer_secs;
  if (expire_timer_secs)
    session->expire_time = (SshUInt32)ssh_time() + expire_timer_secs;
  else
    session->expire_time = 0;

  return session;
}

/* Used to open session with existing stream, for example to use
   stdin/stdout communication. Useful only for replacing TCP based
   protocols at the moment. */
void ssh_pki_session_set_stream(SshPkiSession session, SshStream stream)
{
  session->stream = stream;
}

/* This function returns the type of the PKI session. */
SshPkiType ssh_pki_enrollment_get_type(SshPkiSession session)
{
  return session->type;
}

/* This function retieves the last payload received into the
   session. */
Boolean ssh_pki_enrollment_get_response(SshPkiSession session,
                                        const unsigned char **message,
                                        size_t *message_len)
{
  if (session->response)
    {
      *message = session->response;
      *message_len = session->response_len;
      return TRUE;
    }
  else
    return FALSE;
}

SshOperationHandle
ssh_pki_enroll(SshPkiSession session,
               const unsigned char *message, size_t message_len,
               SshPkiSessionDone callback, void *context)
{
  SshOperationHandle op;

  if (message)
    {
      if (session->request)
        {
          ssh_free(session->request);
          session->flags |= SSH_ENROLL_RESTARTED;
        }
      if ((session->request = ssh_memdup(message, message_len)) == NULL)
        {
          (*callback)(SSH_PKI_FAILED, session, context);
          return NULL;
        }
      session->request_len = message_len;
    }
  else
    session->flags |= SSH_ENROLL_RESUMED;

  session->done = callback;
  session->done_context = context;

  if ((*session->methods->start)(session) != SSH_PKI_OK)
    {
      ssh_free(session);
      return NULL;
    }
  op = ssh_operation_register(ssh_pki_session_abort, session);
  SSH_DEBUG(SSH_D_HIGHOK, ("Enrollment is started"));
  if (session->operation)
    ssh_operation_unregister(session->operation);
  session->operation = op;
  return op;
}

char *ssh_pki_session_linearize(SshPkiSession session)
{
  char *linear;

  ssh_buffer_init(&session->statebuffer);
  switch (session->type)
    {
    case SSH_PKI_SCEP:
      ssh_xbuffer_append_cstrs(&session->statebuffer, "scep: ", NULL);
      break;
    case SSH_PKI_CMP:
      ssh_xbuffer_append_cstrs(&session->statebuffer, "cmp: ", NULL);
      break;
    default:
      ssh_buffer_uninit(&session->statebuffer);
      return NULL;
    }

  ssh_encode_buffer(&session->statebuffer,
                    SSH_ENCODE_UINT32_STR(session->extra,
                                          session->extra_len),
                    SSH_FORMAT_END);

  if ((*session->methods->linear)(session))
    linear = (char *) ssh_buf_to_base64(ssh_buffer_ptr(&session->statebuffer),
                                        ssh_buffer_len(&session->statebuffer));
  else
    linear = NULL;
  ssh_buffer_uninit(&session->statebuffer);

  return linear;
}

SshPkiSession ssh_pki_session_delinearize(const char *linear)
{
  SshPkiSession session;
  unsigned char *data;
  size_t data_len, offset = 0;

  if ((session = ssh_calloc(1, sizeof(*session))) == NULL)
    return NULL;

  data = ssh_base64_to_buf((unsigned char *) linear, &data_len);

  ssh_buffer_init(&session->statebuffer);
  ssh_buffer_append(&session->statebuffer, data, data_len);

  if (strncmp((char *) data, "scep: ", 6) == 0)
    {
      session->type = SSH_PKI_SCEP;
      offset = 6;
    }
  else if (strncmp((char *) data, "cmp: ", 5) == 0)
    {
      session->type = SSH_PKI_CMP;
      offset = 5;
    }
  else
    {
      ssh_buffer_uninit(&session->statebuffer);
      ssh_free(session);
      ssh_free(data);
      return NULL;
    }

  ssh_free(data);
  session->methods = &ssh_pki_enroll_all_methods[session->type];

  ssh_buffer_consume(&session->statebuffer, offset);

  ssh_decode_buffer(&session->statebuffer,
                    SSH_DECODE_UINT32_STR(&session->extra,
                                          &session->extra_len),
                    SSH_FORMAT_END);

  if ((*session->methods->delinear)(session) == FALSE)
    {
      ssh_buffer_uninit(&session->statebuffer);
      ssh_free(session);
      session = NULL;
    }
  ssh_buffer_uninit(&session->statebuffer);
  return session;
}

SshOperationHandle
ssh_pki_confirm(SshPkiSession session,
                const unsigned char *message, size_t message_len,
                SshPkiSessionDone callback, void *context)
{
  SshOperationHandle op = NULL;

  if (session->methods->confirm)
    {
      session->flags |= SSH_ENROLL_CONFIRMED;
      if (session->request)
        ssh_free(session->request);

      if ((session->request = ssh_memdup(message, message_len)) == NULL)
        {
          (*callback)(SSH_PKI_FAILED, session, context);
          return NULL;
        }
      session->request_len = message_len;
      session->response = NULL;
      session->response_len = 0;

      (*session->methods->confirm)(session);
      op = ssh_operation_register(ssh_pki_session_abort, session);
    }
  SSH_DEBUG(SSH_D_HIGHOK, ("Enrollment is confirmed"));
  if (session->operation)
    ssh_operation_unregister(session->operation);
  session->operation = op;
  return op;
}


void
ssh_pki_session_set_extra(SshPkiSession session,
                          const unsigned char *data, size_t len)
{
  session->extra_len = 0;
  if ((session->extra = ssh_memdup(data, len)) != NULL)
    session->extra_len = len;
}

void
ssh_pki_session_get_extra(SshPkiSession session,
                          unsigned char **data, size_t *len)
{
  *len = 0;
  if ((*data = ssh_memdup(session->extra, session->extra_len)) != NULL)
    *len = session->extra_len;
}

/* eof */
#endif /* SSHDIST_CERT */
