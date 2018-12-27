/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"
#include "ssheap_connection.h"

#define SSH_DEBUG_MODULE "SshEapProtocol"

static void
ssh_eap_timeout(SshEap eap);

static void
ssh_eap_signal_all(SshEap eap, SshEapProtocolSignalEnum sig);

static void
ssh_eap_resend_timeout_cb(void *ctx)
{
  unsigned long max_retransmit;
  SshEap eap = (void*)ctx;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->retransmit_timer_active == 1);
  SSH_ASSERT(eap->prev_pkt != NULL);

  SSH_DEBUG(SSH_D_LOWOK,("resend timeout"));

  eap->retransmit_timer_active = 0;
  eap->num_retransmit++;

  max_retransmit = ssh_eap_config_get_ulong(eap->params,
                                            SSH_EAP_PARAM_MAX_RETRANSMIT);

  if (eap->is_authenticator == 1)
    {
      if ((unsigned long)eap->num_retransmit > max_retransmit
          && eap->num_retransmit >= 0)
        {
          ssh_eap_timeout(eap);
          return;
        }

      ssh_eap_set_resend_timeout(eap);
    }

  ssh_eap_send_packet(eap, eap->prev_pkt);
}

static void
ssh_eap_set_send_timeout(SshEap eap,
                         unsigned long delay_sec,
                         unsigned long delay_usec)
{
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->retransmit_timer_active == 0);
  SSH_ASSERT(eap->destroy_pending == 0);

  if (delay_sec > 0 || delay_usec > 0)
    {
      eap->retransmit_timer_active = 1;
      ssh_xregister_timeout(delay_sec,
                           delay_usec,
                           ssh_eap_resend_timeout_cb,
                           eap);
    }
}

void
ssh_eap_set_resend_timeout(SshEap eap)
{
  unsigned long delay_sec;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->retransmit_timer_active == 0);
  SSH_ASSERT(eap->is_authenticator == 1);
  SSH_ASSERT(eap->destroy_pending == 0);

  delay_sec = ssh_eap_config_get_ulong(eap->params,
                                       SSH_EAP_PARAM_RETRANSMIT_DELAY_SEC);

#ifdef SSHDIST_RADIUS
  if (eap->radius_config != NULL && eap->radius_session_timeout != 0)
    delay_sec = eap->radius_session_timeout;
#endif /* SSHDIST_RADIUS */

  ssh_eap_set_send_timeout(eap, delay_sec, 0);
}

void
ssh_eap_cancel_resend_timeout(SshEap eap)
{
#ifdef SSHDIST_RADIUS
  eap->radius_session_timeout = 0;
#endif /* SSHDIST_RADIUS */
  eap->num_retransmit = 0;
  eap->retransmit_timer_active = 0;
  ssh_cancel_timeouts(ssh_eap_resend_timeout_cb, eap);
}

void
ssh_eap_auth_timeout_cb(void *ctx)
{
  SshEap eap = (SshEap)ctx;

  SSH_DEBUG(SSH_D_LOWOK,("authentication process timed out"));

  eap->auth_timeout_active = 1;
  ssh_eap_timeout(eap);
}

void
ssh_eap_begin_auth_timeout(SshEap eap)
{
  unsigned long delay_sec;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(eap->destroy_pending == 0);

  delay_sec = ssh_eap_config_get_ulong(eap->params,
                                       SSH_EAP_PARAM_AUTH_TIMEOUT_SEC);

  if (delay_sec > 0)
    {
      if (eap->auth_timeout_active == 0)
        {
          ssh_xregister_timeout(delay_sec,
                               0,
                               ssh_eap_auth_timeout_cb,
                               eap);
          eap->auth_timeout_active = 1;
        }
    }
}

void
ssh_eap_cancel_auth_timeout(SshEap eap)
{
  SSH_ASSERT(eap != NULL);

  eap->auth_timeout_active = 0;
  ssh_cancel_timeouts(ssh_eap_auth_timeout_cb, eap);
}

static void
ssh_eap_timeout(SshEap eap)
{
  SSH_PRECOND(eap != NULL);

  /* Reset the EAP instance, so that no further signals
     are delivered untill action by the owner of the
     instance. */
  ssh_eap_reset(eap);

  /* Signal the caller that authentication has failed due to a timeout */

  SSH_DEBUG(SSH_D_MIDOK,("EAP authentication timed out"));

  ssh_eap_send_signal(eap, eap->previous_eap_type,
                      SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT, NULL);
}

void
ssh_eap_send_signal(SshEap eap,
                    SshUInt8 type,
                    SshEapSignal signal,
                    SshBuffer buf)
{
  SSH_PRECOND(eap != NULL);

  if (eap->destroy_pending == 1
      || eap->params == NULL
      || eap->params->signal_cb == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("incapable of delivering signal, discarding it"));
      if (buf && (buf->dynamic == TRUE))
        ssh_buffer_free(buf);
      return;
    }

  SSH_EAP_CB(eap, eap->params->signal_cb(eap,
                                         type,
                                         signal,
                                         buf,
                                         eap->ctx));
}


void
ssh_eap_remember_packet(SshEap eap, SshBuffer buf)
{
  if (eap->prev_pkt != NULL)
    ssh_buffer_free(eap->prev_pkt);

  eap->prev_pkt = buf;
}

void
ssh_eap_send_packet(SshEap eap, SshBuffer buf)
{
  SSH_PRECOND(eap != NULL);

  /* Remember the last packet we sent out */

  eap->previous_eap_code = ssh_eap_packet_get_code(buf);

  if (ssh_eap_packet_get_length(buf) > 4)
    eap->previous_eap_type = ssh_eap_packet_get_type(buf);

  /* Assume that the eap->con has been destroyed, if we
     have been destroyed (which may well be the case). */

  if (eap->destroy_pending == 0)
    {
      SSH_EAP_CB(eap,
                 ssh_eap_connection_output_packet(eap->con,buf));
    }
}

void
ssh_eap_build_and_send_request(SshEap eap, SshUInt8 type,
                               const SshUInt8 *ptr, unsigned long len)
{
  SshBuffer pkt;

  pkt = ssh_eap_create_request(eap, (SshUInt16)len, type);

  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send request.");
      return;
    }

  if (len != 0 && ptr != NULL)
    {
      if (ssh_buffer_append(pkt, ptr, len) != SSH_BUFFER_OK)
        {
          ssh_buffer_free(pkt);
          ssh_eap_fatal(eap, NULL,
                        "Out of memory. Can not send request.");
          return;
        }
    }

  /* Send packet */

  ssh_eap_protocol_send_request(NULL, eap, pkt);
}


void
ssh_eap_build_and_send_request_buf(SshEap eap,
                                   SshUInt8 type,
                                   const SshBuffer buf)
{
  SshUInt8 *ptr;
  SshUInt16 len;

  if (buf == NULL)
    {
      len = 0;
      ptr = NULL;
    }
  else
    {
      len = (SshUInt16)ssh_buffer_len(buf);
      ptr = (len == 0 ? NULL : ssh_buffer_ptr(buf));
    }

  ssh_eap_build_and_send_request(eap, type, ptr, len);
}

void
ssh_eap_build_and_send_reply(SshEap eap, SshUInt8 type,
                             const SshUInt8 *ptr, SshUInt16 len)
{
  SshBuffer pkt;

  /* Only send replies to requests */

  SSH_ASSERT(eap->id_isinit == 1);

  pkt = ssh_buffer_allocate();

  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send reply.");
      return;
    }

  if (!ssh_eap_packet_build_hdr_with_type(pkt,
                                          SSH_EAP_CODE_REPLY,
                                          eap->id,
                                          len,
                                          type))
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send reply.");
      return;
    }

  if (len != 0 && ptr != NULL)
    {
      if (ssh_buffer_append(pkt, ptr, len) != SSH_BUFFER_OK)
        {
          ssh_buffer_free(pkt);
          ssh_eap_fatal(eap, NULL, "Out of memory. Can not send reply.");
          return;
        }
    }

  /* Ok. let's transmit this packet */

  ssh_eap_remember_packet(eap, pkt);
  ssh_eap_send_packet(eap, pkt);
}


void
ssh_eap_build_and_send_reply_buf(SshEap eap,
                                 SshUInt8 type,
                                 const SshBuffer buf)
{
  SshUInt8 *ptr;
  SshUInt16 len;

  if (buf == NULL)
    {
      len = 0;
      ptr = NULL;
    }
  else
    {
      len = (SshUInt16)ssh_buffer_len(buf);
      ptr = (len == 0 ? NULL : ssh_buffer_ptr(buf));
    }

  ssh_eap_build_and_send_reply(eap,type, ptr, len);
}


static void
ssh_eap_signal_all(SshEap eap,
                   SshEapProtocolSignalEnum sig)
{
  int i;
  SshEapProtocolSignalCB handler;

  for (i = 0; i < eap->nprotocols; i++)
    {
      handler = eap->protocols[i]->impl->handler;
      SSH_EAP_CB(eap,
                 handler(sig, eap, eap->protocols[i], NULL));
    }
}

SshEapOpStatus
ssh_eap_reset(SshEap eap)
{
  SshEapProtocol pro;
  unsigned long i;

  ssh_eap_cancel_auth_timeout(eap);
  ssh_eap_cancel_resend_timeout(eap);

  ssh_eap_signal_all(eap, SSH_EAP_PROTOCOL_RESET);

  eap->id_isinit = 0;
  eap->id_isrecv = 0;

#ifdef SSHDIST_RADIUS
  /* It may seem odd to call radius_reset() and radius_init() in
     sequence, but the intent is to reset state variables (such
     as radius_framed_protocol, which are not reset in a
     radius_reset(), as they are required after a RADIUS round
     ends. */
  ssh_eap_radius_reset(eap);
  ssh_eap_radius_init(eap);
#endif /* SSHDIST_RADIUS */

  if (eap->prev_pkt != NULL)
    {
      ssh_buffer_free(eap->prev_pkt);
      eap->prev_pkt = NULL;
    }

  if (eap->delayed_token != NULL)
    {
      ssh_eap_free_token(eap->delayed_token);
      eap->delayed_token = NULL;
    }

  for (i = 0; i < eap->nprotocols; i++)
    {
      pro = eap->protocols[i];

      if (pro != NULL)
        {
          pro->is_nak = FALSE;
        }
    }

  SSH_DEBUG(SSH_D_MIDOK,("eap instance reset"));

  return SSH_EAP_OPSTATUS_SUCCESS;
}

/* Handle reception of packets */

/* Send message */

void*
ssh_eap_protocol_get_state(SshEapProtocol protocol)
{
  SSH_PRECOND(protocol != NULL);

  return protocol->state;
}


void*
ssh_eap_protocol_get_params(SshEapProtocol protocol)
{
  SSH_PRECOND(protocol != NULL);

  return protocol->params;
}

/* Signaling */

void
ssh_eap_protocol_request_token(SshEap eap,
                               SshUInt8 eap_type,
                               SshEapTokenType type)
{
  SshBufferStruct buf;
  SshEapTokenStruct token;

  SSH_PRECOND(eap != NULL);

  SSH_DEBUG(SSH_D_MIDOK,("requesting token of type %d from user", type));

  eap->waiting_for_callback = 1;

  buf.dynamic = FALSE;
  buf.buf = (unsigned char*)&token;
  buf.alloc = sizeof(token);
  buf.offset = 0;
  buf.end = buf.alloc;

  token.type = type;

  ssh_eap_send_signal(eap,
                      eap_type,
                      SSH_EAP_SIGNAL_NEED_TOKEN,
                      &buf);
}

void
ssh_eap_protocol_request_token_with_args(SshEap eap,
                                         SshUInt8 eap_type,
                                         SshEapTokenType type,
                                         unsigned char *input,
                                         SshUInt16 input_len)
{
  SshBufferStruct   buf;
  SshEapTokenStruct token;

  SSH_PRECOND(eap != NULL);

  SSH_DEBUG(SSH_D_MIDOK,("requesting token of type %d from user %u",
                         type, input_len));

  eap->waiting_for_callback = 1;

  buf.dynamic = FALSE;
  buf.buf = (unsigned char*)&token;
  buf.alloc = sizeof(token);
  buf.offset = 0;
  buf.end = buf.alloc;

  token.token.buffer.dptr = input;
  token.token.buffer.len  = input_len;

  token.type = type;

  ssh_eap_send_signal(eap,
                      eap_type,
                      SSH_EAP_SIGNAL_NEED_TOKEN,
                      &buf);
}

static Boolean
ssh_eap_send_success(SshEap eap)
{
  SshBuffer pkt;
  Boolean ret;

  pkt = ssh_buffer_allocate();
  ret = FALSE;

  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send EAP success packet.");
      return FALSE;
    }

  eap->previous_eap_code = SSH_EAP_CODE_SUCCESS;
  eap->previous_eap_type = 0;

  if (eap->id_isrecv == 1)
    {
      SSH_DEBUG(SSH_D_MIDOK,("sending EAP success packet"));

      if (ssh_eap_packet_build_hdr(pkt, SSH_EAP_CODE_SUCCESS,
                                    eap->id, 0) == TRUE)
        {
          ssh_eap_remember_packet(eap, pkt);
          ssh_eap_send_packet(eap, pkt);
          ret = TRUE;
        }
      else
        {
          ssh_buffer_free(pkt);
          ssh_eap_fatal(eap, NULL,
                        "Out of memory. Can not send EAP success packet.");
        }
    }
  else
    {
      ssh_buffer_free(pkt);
      SSH_DEBUG(SSH_D_NETGARB,("Cannot send EAP success packet, "
                               "no valid identifier available!"));
    }
  return ret;
}

static Boolean
ssh_eap_send_failure(SshEap eap)
{
  SshBuffer pkt;
  Boolean ret;

  ret = FALSE;
  pkt = ssh_buffer_allocate();

  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send EAP failure packet.");
      return FALSE;
    }

  eap->previous_eap_code = SSH_EAP_CODE_FAILURE;
  eap->previous_eap_type = 0;

  if (eap->id_isrecv == 1)
    {
      SSH_DEBUG(SSH_D_MIDOK,("sending EAP failure packet!"));

      if (ssh_eap_packet_build_hdr(pkt, SSH_EAP_CODE_FAILURE,
                                   eap->id, 0) == TRUE)
        {
          ssh_eap_remember_packet(eap, pkt);
          ssh_eap_send_packet(eap, pkt);
          ret = TRUE;
        }
      else
        {
          ssh_buffer_free(pkt);
          ssh_eap_fatal(eap, NULL,
                        "Out of memory. "
                        "Canot not send EAP failure packet");
        }
    }
  else
    {
      ssh_buffer_free(pkt);
      ssh_eap_fatal(eap, NULL, "Cannot send EAP failure packet, "
                               "no valid identifier available!");
    }
  return ret;
}

void
ssh_eap_protocol_master_session_key(SshEap eap,
                                    const unsigned char *session_key,
                                    size_t session_key_len)
{
  SSH_PRECOND(eap->msk == NULL);

  eap->msk = ssh_memdup(session_key, session_key_len);
  eap->msk_len = session_key_len;
}


void
ssh_eap_protocol_auth_ok(SshEapProtocol protocol,
                         SshEap eap,
                         SshEapSignal sig,
                         SshBuffer buf)
{
  SshUInt8 id;

  SSH_PRECOND(eap != NULL);

  eap->method_done = 1;
  eap->method_ok = 1;

#ifdef SSHDIST_RADIUS
  ssh_eap_radius_reset(eap);
#endif /* SSHDIST_RADIUS */

  ssh_eap_cancel_auth_timeout(eap);

  if (protocol != NULL)
    {
      id = protocol->impl->id;
    }
  else
    {
      id = eap->previous_eap_type;
    }

  if (ssh_eap_isauthenticator(eap))
    {
      /* Send the packet first, and then the signal */
      if (ssh_eap_send_success(eap) == TRUE)
        {
          eap->id_isrecv = 0;
          if (sig != SSH_EAP_SIGNAL_AUTH_OK_USERNAME)
            {
              sig = SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK;
              buf = NULL;
            }

          ssh_eap_send_signal(eap, id, sig, buf);
        }
      eap->id_isrecv = 0;
    }
  else
    {
      ssh_eap_send_signal(eap,
                          id,
                          SSH_EAP_SIGNAL_AUTH_PEER_MAYBE_OK,
                          NULL);
    }
}

void
ssh_eap_protocol_auth_fail(SshEapProtocol protocol,
                           SshEap eap,
                           SshEapSignal sig,
                           SshBuffer buf)
{
  SshUInt8 id;

  SSH_PRECOND(eap != NULL);

  eap->method_done = 1;
  eap->method_ok = 0;

#ifdef SSHDIST_RADIUS
  ssh_eap_radius_reset(eap);
#endif /* SSHDIST_RADIUS */

  ssh_eap_cancel_auth_timeout(eap);

  /* Send the packet first, and then the signal */
  if (eap->is_authenticator == 1 &&
      ssh_eap_send_failure(eap) == FALSE)
    {
      eap->id_isrecv = 0;
      return;
    }
  eap->id_isrecv = 0;

  if (protocol != NULL)
    {
      id = protocol->impl->id;
    }
  else
    {
      id = eap->previous_eap_type;
    }

  switch (sig)
    {
    case SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME:
      break;
    case SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION:
      buf = NULL;
      break;
    default:
      if (ssh_eap_isauthenticator(eap) == TRUE)
        {
          buf = NULL;
          sig = SSH_EAP_SIGNAL_AUTH_FAIL_REPLY;
        }
      else
        sig = SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR;
      break;
    }

  ssh_eap_send_signal(eap, id, sig, buf);
}

SshBuffer
ssh_eap_create_request(SshEap eap, SshUInt16 len, SshUInt8 type)
{
  SshBuffer pkt;

  pkt = ssh_buffer_allocate();

  if (pkt == NULL)
    return NULL;

  eap->id++; /* Increment identifier here,
                making "each packet" unique */

  if (!ssh_eap_packet_build_hdr_with_type(pkt,
                                          SSH_EAP_CODE_REQUEST,
                                          eap->id,
                                          len,
                                          type))
    {
      ssh_buffer_free(pkt);
      return NULL;
    }


  return pkt;
}

SshBuffer
ssh_eap_create_reply(SshEap eap, SshUInt16 len, SshUInt8 type)
{
  SshBuffer pkt;

  SSH_PRECOND(eap != NULL);

  pkt = ssh_buffer_allocate();

  if (pkt == NULL)
    return NULL;

  SSH_ASSERT(eap->id_isinit == 1);

  if (!ssh_eap_packet_build_hdr_with_type(pkt,
                                          SSH_EAP_CODE_REPLY,
                                          eap->id,
                                          len,
                                          type))
    {
      ssh_buffer_free(pkt);
      return NULL;
    }
  return pkt;
}

void
ssh_eap_protocol_send_request(SshEapProtocol protocol,
                              SshEap eap,
                              SshBuffer buf)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(ssh_eap_isauthenticator(eap));

  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Grab fields from packet */

  eap->id = ssh_eap_packet_get_identifier(buf);
  eap->id_isinit = 1;
  eap->id_isrecv = 0;

  /* Initialize retransmit timers */

  ssh_eap_set_resend_timeout(eap);

  /* Send packet */

  ssh_eap_remember_packet(eap,buf);

  ssh_eap_send_packet(eap,buf);
}

void
ssh_eap_protocol_send_request_random_delay(SshEapProtocol protocol,
                                           SshEap eap,
                                           SshBuffer buf,
                                           unsigned long max_delay)
{
  SshUInt8 rnd_byte[4];
  unsigned long val;
  unsigned long sec, usec;

  eap->id = ssh_eap_packet_get_identifier(buf);
  eap->id_isinit = 1;
  eap->num_retransmit = -1;

  rnd_byte[0] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[1] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[2] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[3] = (SshUInt8)ssh_random_get_byte();

  val = SSH_GET_32BIT(rnd_byte);

  /* The Ssh API allows a granularity of 1 microsecond for timeouts, but
     it is not realistic to assume that the timeout mechanism will always
     work at that granularity.

     If we assume that the timeout mechanism works at a granularity
     of approximately one millisecond, then the amount of entropy
     that can be added to leaked timing information is approximately
     10 bits per second.

     Additionally any leaked timing information may be padded
     by the amount (time_when_set_timeout % granularity). */

  val = val & 0xfffff;

  sec = (max_delay * val) >> 20;
  usec = (max_delay * val) & 0xFFFFF;

  SSH_DEBUG(SSH_D_MY,("delay send by %lu sec %lu usec",
                      (unsigned long) sec, (unsigned long) usec));

  ssh_eap_set_send_timeout(eap, sec, usec);
  ssh_eap_remember_packet(eap, buf);
}

void
ssh_eap_protocol_send_response(SshEapProtocol protocol,
                               SshEap eap,
                               SshBuffer buf)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(ssh_eap_isauthenticator(eap) == 0);

  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Send packet */

  ssh_eap_remember_packet(eap, buf);
  ssh_eap_send_packet(eap, buf);
}

void
ssh_eap_protocol_send_response_random_delay(SshEapProtocol protocol,
                                            SshEap eap,
                                            SshBuffer buf,
                                            unsigned long max_delay)
{
  unsigned long val;
  unsigned long sec, usec;
  SshUInt8 rnd_byte[4];

  rnd_byte[0] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[1] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[2] = (SshUInt8)ssh_random_get_byte();
  rnd_byte[3] = (SshUInt8)ssh_random_get_byte();

  val = SSH_GET_32BIT(rnd_byte);

  /* The Ssh API allows a granularity of 1 microsecond for timeouts, but
     it is not realistic to assume that the timeout mechanism will always
     work at that granularity.

     If we assume that the timeout mechanism works at a granularity
     of approximately one millisecond, then the amount of entropy
     that can be added to leaked timing information is approximately
     10 bits per second.

     Additionally any leaked timing information may be padded
     by the amount (time_when_set_timeout % granularity). */

  eap->num_retransmit = -1;

  val = val & 0xfffff;

  sec = (max_delay * val) >> 20;
  usec = (max_delay * val) & 0xFFFFF;

  SSH_DEBUG(SSH_D_MY, ("delay send by %lu sec %lu usec",
                       (unsigned long) sec, (unsigned long) usec));

  ssh_eap_remember_packet(eap, buf);
  ssh_eap_set_send_timeout(eap, sec, usec);
}

/* Configuration */

unsigned long
ssh_eap_protocol_get_mru(SshEapProtocol protocol, SshEap eap)
{
  SSH_PRECOND(eap != NULL);

  return (eap->con != NULL ? eap->con->mru : 1400);
}


Boolean
ssh_eap_isauthenticator(SshEap eap)
{
  SSH_PRECOND(eap != NULL);

  return (eap->is_authenticator == 1 ? TRUE : FALSE);
}
