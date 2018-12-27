/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshenum.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"

#define SSH_DEBUG_MODULE "SshEapCommon"

/* Prototypes for static functions */

static void ssh_eap_input_identity_request(SshEap eap, SshBuffer buf);
static void ssh_eap_input_notification_request(SshEap eap, SshBuffer buf);
static void ssh_eap_input_request(SshEap eap, SshBuffer buf);
static void ssh_eap_input_notification_reply(SshEap eap, SshBuffer buf);
static void ssh_eap_input_identity_reply(SshEap eap, SshBuffer buf);
static void ssh_eap_input_reply(SshEap eap, SshBuffer buf);
static void ssh_eap_input_ext_request(SshEap eap, SshBuffer buf);
static void ssh_eap_send_nak_reply(SshEap eap, SshEapProtocol protocol,
                                   Boolean iscommit);
/* Peer */

static void
ssh_eap_input_identity_request(SshEap eap, SshBuffer buf)
{
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Signal an identity message */

  ssh_eap_packet_skip_hdr(buf);

  if (ssh_buffer_len(buf) == 0)
    {
      buf = NULL;
    }

  /* Send a callback signal back */

  ssh_eap_protocol_request_token(eap, SSH_EAP_TYPE_IDENTITY,
                                 SSH_EAP_TOKEN_USERNAME);
}

static void
ssh_eap_input_notification_request(SshEap eap, SshBuffer buf)
{
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  ssh_eap_packet_skip_hdr(buf);

  if (ssh_buffer_len(buf) == 0)
    {
      buf = NULL;
    }

  /* Send a "notification response" back */





  ssh_eap_build_and_send_reply(eap,
                               SSH_EAP_TYPE_NOTIFICATION,
                               NULL,
                               0);

  /* Send a callback signal back */

  ssh_eap_send_signal(eap,
                      SSH_EAP_TYPE_NOTIFICATION,
                      SSH_EAP_SIGNAL_NOTIFICATION,
                      buf);
}

void
ssh_eap_discard_token(SshEap eap,
                      SshEapProtocol protocol,
                      SshBuffer buf,
                      char *cause_str)
{
  SshEapTokenType tok_type;
  SshUInt8 eap_type;
  SSH_PRECOND(eap != NULL);

  tok_type = ssh_eap_get_token_type_from_buf(buf);

  /* Tokens are received by EAP protocols generally */
  eap_type = (protocol != NULL ? protocol->impl->id : 0);

  SSH_DEBUG(SSH_D_NETGARB,("discarding token of type %d%s%s",
                           tok_type,
                           (cause_str != NULL ? ": " : ""),
                           (cause_str != NULL ? cause_str : "")));

  ssh_eap_send_signal(eap, eap_type,  SSH_EAP_SIGNAL_TOKEN_DISCARDED, buf);
}


void
ssh_eap_fatal(SshEap eap,
              SshEapProtocol protocol,
              char *cause_str)
{
  SshUInt8 eap_type;
  SSH_PRECOND(eap != NULL);

  if (protocol != NULL)
    eap_type = protocol->impl->id;
  else
    eap_type = 0;

  SSH_DEBUG(SSH_D_FAIL,
            ("fatal error from type %d%s%s",
             eap_type,
             (cause_str != NULL ? ": " : ""),
             (cause_str != NULL ? cause_str : "")));

  ssh_eap_send_signal(eap, eap_type, SSH_EAP_SIGNAL_FATAL_ERROR, NULL);
}



void
ssh_eap_discard_packet(SshEap eap,
                       SshEapProtocol protocol,
                       SshBuffer buf,
                       char *cause_str)
{
  SshUInt8 eap_type;
  SshUInt8 eap_code;
  SSH_PRECOND(eap != NULL);

  if (ssh_eap_packet_isvalid(buf))
    {
      eap_code = ssh_eap_packet_get_code(buf);
    }
  else
    {
      eap_code = 0;
    }

  if (protocol != NULL)
    {
      eap_type = protocol->impl->id;
    }
  else if (ssh_eap_packet_isvalid(buf))
    {
      eap_type = ssh_eap_packet_get_type(buf);
    }
  else
    {
      eap_type = 0;
    }

  SSH_DEBUG(SSH_D_NETGARB,
            ("discarding EAP packet with code %d type %d%s%s",
             eap_code, eap_type,
             (cause_str != NULL ? ": " : ""),
             (cause_str != NULL ? cause_str : "")));

  ssh_eap_send_signal(eap, eap_type,  SSH_EAP_SIGNAL_PACKET_DISCARDED, buf);
}

static void
ssh_eap_input_request(SshEap eap, SshBuffer buf)
{
  SshUInt8 id;
  SshUInt16 len;
  SshUInt8 type;
  unsigned long max_retransmit;

  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Only peer's handle requests */

  if (eap->is_authenticator == 1)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "authenticator received request");
      return;
    }

  /* RFC 3748 Section 4.1

     If identifier matches previous requests, then it MUST be a
     resent packet, and the implementation MUST resend the
     previously sent reply. */

  id = ssh_eap_packet_get_identifier(buf);
  len = ssh_eap_packet_get_length(buf);
  type = ssh_eap_packet_get_type(buf);

  /* This id != 0 || len == eap->len is a compatibility issue
     with Checkpoint gateways. Checkpoint gateway uses same identifier
     twice (id is zero) which is against RFC, but for compatibility
     reasons we allow this. */
  if (eap->id_isinit == 1 && eap->id == id &&
      (id != 0 || len == eap->len))
    {
      max_retransmit = ssh_eap_config_get_ulong(eap->params,
                                                SSH_EAP_PARAM_MAX_RETRANSMIT);
      if (eap->prev_pkt != NULL)
        {
          eap->num_retransmit++;

          if (eap->num_retransmit > max_retransmit)
            {
              SSH_DEBUG(SSH_D_MIDOK,("retransmit count exceeded"));
              ssh_eap_send_signal(eap,
                                  type,
                                  SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR,
                                  NULL);
            }
          else
            {
              SSH_DEBUG(SSH_D_MIDOK,("re-sending reply to "
                                     "duplicate request"));

              ssh_eap_send_packet(eap, eap->prev_pkt);
            }
        }
      else
        {
          eap->id_isinit = 0;
          ssh_eap_discard_packet(eap, NULL, buf, "internal error");
        }
      return;
    }

  if (eap->waiting_for_callback == 1)
    {
      ssh_eap_discard_packet(eap, NULL, buf, "waiting for callback");
      return;
    }

  /* Free previous reply message */

  if (eap->prev_pkt != NULL)
    {
      ssh_buffer_free(eap->prev_pkt);
      eap->prev_pkt = NULL;
    }

  /* Store id of current request */

  eap->id_isinit = 1;
  eap->id = id;
  eap->len = len;
  eap->num_retransmit = 0;

  /* Route packet further based on EAP type */

  ssh_eap_begin_auth_timeout(eap);

  switch (type)
    {
    case SSH_EAP_TYPE_IDENTITY:
      ssh_eap_input_identity_request(eap,buf);
      break;

    case SSH_EAP_TYPE_NOTIFICATION:
      ssh_eap_input_notification_request(eap,buf);
      break;

    default:
      ssh_eap_input_ext_request(eap,buf);
      break;
    }
}

/* Authenticator */

static void
ssh_eap_input_nak_reply(SshEap eap, SshBuffer buf)
{
  SshEapProtocol protocol;

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  if (eap->previous_eap_type == SSH_EAP_TYPE_IDENTITY
      || eap->previous_eap_type == SSH_EAP_TYPE_NOTIFICATION)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "received NAK to mandatory EAP type");
      return;
    }

  /* Record NAK response */

  protocol = ssh_eap_get_protocol(eap, eap->previous_eap_type);

  if (protocol == NULL)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "received NAK to unconfigured protocol");
      return;
    }

  protocol->is_nak = 1;

  SSH_DEBUG(SSH_D_NICETOKNOW,("received nak for eap type %d",
                              eap->previous_eap_type));

  /* Inform the protocol to reset itself */

  SSH_EAP_CB(eap, protocol->impl->handler(SSH_EAP_PROTOCOL_RESET,
                                          eap,
                                          protocol,
                                          NULL));

  /* Re-begin authentication */

  ssh_eap_authenticate(eap, SSH_EAP_AUTH_CONTINUE);
}

static void
ssh_eap_input_notification_reply(SshEap eap, SshBuffer buf)
{
  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  if (ssh_eap_packet_get_type(buf) != eap->previous_eap_type)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "unexpected notification response");
      return;
    }





  /* Received a notification reply */

  ssh_eap_send_signal(eap,
                      SSH_EAP_TYPE_NOTIFICATION,
                      SSH_EAP_SIGNAL_NOTIFICATION,
                      NULL);
}

static void
ssh_eap_input_ext_request(SshEap eap, SshBuffer buf)
{
  SshEapProtocol protocol;
  SshUInt8 type;

  /* Sanity check that the protocol actually exists */

  type = ssh_eap_packet_get_type(buf);
  protocol = ssh_eap_get_protocol(eap, type);

  if (protocol == NULL || protocol->is_nak == 1)
    {
      if (protocol == NULL)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("request type for an unknown protocol %d",
                                    type));
        }
      else
        {
          SSH_DEBUG(SSH_D_NETGARB,("request for already NAK'd protocol %d",
                                   type));
        }

      ssh_eap_send_nak_reply(eap, protocol, TRUE);
      return;
    }

  if (protocol->state == NULL)
    {
      protocol->state = protocol->impl->create(protocol, eap,
                                               protocol->impl->id);
      if (protocol->state == NULL)
        {
          ssh_eap_fatal(eap, protocol,
                        "Out of memory. "
                        "Cannot allocate state for protocol run.");
          return;
        }
    }

  /* Forward message to protocol */

  SSH_EAP_CB(eap,
             protocol->impl->handler(SSH_EAP_PROTOCOL_RECV_MSG,
                                     eap, protocol, buf));
}

static void
ssh_eap_input_ext_reply(SshEap eap, SshBuffer buf)
{
  SshEapProtocol protocol;

  /* Currently we assume that all EAP protocols operate with only
     one type. This is for simplicity / robustness reasons, but
     this assumption could be weakened. */

  if (eap->previous_eap_type != ssh_eap_packet_get_type(buf))
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "response type does not match request type");
      return;
    }

  /* Sanity check that the protocol actually exists */

  protocol = ssh_eap_get_protocol(eap, eap->previous_eap_type);

  if (protocol == NULL)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "response type is an unknown EAP type");
      return;
    }

  /* Forward message to protocol */

  SSH_DEBUG(SSH_D_LOWOK,("forwarding response to eap type %d",
                         protocol->impl->id));

  SSH_EAP_CB(eap,
             protocol->impl->handler(SSH_EAP_PROTOCOL_RECV_MSG,
                                     eap, protocol, buf));

}

static void
ssh_eap_input_identity_reply(SshEap eap, SshBuffer buf)
{
#ifdef SSHDIST_RADIUS
  SshBufferStruct bak;
#endif /* SSHDIST_RADIUS */

  SSH_ASSERT(eap != NULL);
  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  if (ssh_eap_packet_get_type(buf) != eap->previous_eap_type)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "unexpected identity response");
      return;
    }

  SSH_DEBUG(SSH_D_HIGHOK,("processing identity response packet"));

#ifdef SSHDIST_RADIUS
  memcpy(&bak, buf, sizeof(bak));
  bak.dynamic = FALSE;
#endif /* SSHDIST_RADIUS */

  ssh_eap_packet_skip_hdr(buf);

  ssh_eap_send_signal(eap, SSH_EAP_TYPE_IDENTITY, SSH_EAP_SIGNAL_IDENTITY,
                      buf);

#ifdef SSHDIST_RADIUS
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Calling radius input identity reply"));

  /* RADIUS configuration may have been set here */
  if (eap->radius_config != NULL
      || eap->params->radius_buffer_identity == TRUE)
    ssh_eap_radius_input_identity_reply(eap, &bak, TRUE);
#endif /* SSHDIST_RADIUS */

}

static void
ssh_eap_input_reply(SshEap eap, SshBuffer buf)
{
  SshUInt8 id;
  SshUInt8 type;

  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Peer's do not handle replies */

  if (eap->is_authenticator == 0)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "peer received reply packet");
      return;
    }

  /* If identifier does not match, drop packet */

  id = ssh_eap_packet_get_identifier(buf);

  if (eap->id_isinit == 0
      || eap->id != id
      || eap->previous_eap_code != SSH_EAP_CODE_REQUEST)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "reply id does not match request id");
      return;
    }

  if (eap->waiting_for_callback == 1)
    {
      ssh_eap_discard_packet(eap, NULL, buf, "waiting for callback");
      return;
    }

  /* Reset retransmission count and remove buffer */

  ssh_eap_cancel_resend_timeout(eap);

  if (eap->prev_pkt != NULL)
    {
      ssh_buffer_free(eap->prev_pkt);
      eap->prev_pkt = NULL;
    }

  eap->id_isinit = 0;
  eap->id_isrecv = 1;

#ifdef SSHDIST_RADIUS
  if (eap->radius_config != NULL)
    {
      ssh_eap_radius_input_reply(eap, buf);
      return;
    }
#endif /* SSHDIST_RADIUS */

  /* Route packet further */

  type = ssh_eap_packet_get_type(buf);

  switch (type)
    {
    case SSH_EAP_TYPE_IDENTITY:
      ssh_eap_input_identity_reply(eap, buf);
      break;
    case SSH_EAP_TYPE_NOTIFICATION:
      ssh_eap_input_notification_reply(eap, buf);
      break;
    case SSH_EAP_TYPE_NAK:
      ssh_eap_input_nak_reply(eap, buf);
      break;
    default:
      ssh_eap_input_ext_reply(eap, buf);
      break;
    }
}

/* Peer */

void
ssh_eap_input_succfail(SshEap eap, SshBuffer buf)
{
  SshUInt8 id;
  SshUInt8 code;

  SSH_ASSERT(ssh_eap_packet_isvalid(buf));

  /* Authenticator's drop these messages */

  if (eap->is_authenticator == 1)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "authenticator received success/failure "
                             "message");
      return;
    }

  /* RFC 3748, the peer must discard SUCCESS/FAILURES messages if the method
     is not permitted to finish at this point. */
  if (eap->method_done == 0 &&
      eap->previous_eap_type != SSH_EAP_TYPE_NAK)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "Recevied a success/failure message before the "
                             "EAP method has completed");
      return;
    }

  /* A success or failure message must be a reply to a reply this peer has
     previously sent. */
  id = ssh_eap_packet_get_identifier(buf);

  if (eap->id_isinit == 0 || eap->id != id)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "success/failure message contains incorrect "
                             "message id");
      return;
    }

  code = ssh_eap_packet_get_code(buf);

  eap->id_isinit = 0;

  /* Forget packet, DO NOT store this packet */

  if (eap->prev_pkt != NULL)
    {
      ssh_buffer_free(eap->prev_pkt);
      eap->prev_pkt = NULL;
    }

  /* Signal message based on type */

  ssh_eap_cancel_auth_timeout(eap);

  switch (code)
    {
    case SSH_EAP_CODE_SUCCESS:
      SSH_DEBUG(SSH_D_NETGARB,("received success message"));

      ssh_eap_send_signal(eap,
                          SSH_EAP_TYPE_NONE,
                          SSH_EAP_SIGNAL_AUTH_PEER_OK,
                          NULL);

      break;

    case SSH_EAP_CODE_FAILURE:
      SSH_DEBUG(SSH_D_NETGARB,("received failure message"));

      ssh_eap_send_signal(eap,
                          SSH_EAP_TYPE_NONE,
                          SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                          NULL);
      break;
    }
}

void
ssh_eap_input_packet(SshEap eap, SshBuffer orig_buf)
{
  SshUInt8 code;
  SshBufferStruct buf_place;
  SshBuffer buf;

  SSH_PRECOND(eap != NULL);

  /* Use our own SshBuffer, so we are free to modify
     offset and end. */

  buf = &buf_place;

  buf->buf = orig_buf->buf;
  buf->offset = orig_buf->offset;
  buf->end = orig_buf->end;
  buf->alloc = orig_buf->alloc;
  buf->size_index = orig_buf->size_index;
  buf->dynamic = FALSE;
  buf->borrowed = orig_buf->borrowed;

  /* If we cannot handle a packet, drop it */

  if (eap == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,("eap instance not initialized"));
      return;
    }

  /* Clean up packet */

  if (ssh_eap_packet_isvalid(buf) == FALSE)
    {
      ssh_eap_discard_packet(eap,  NULL, buf, "packet corrupted");
      return;
    }

  ssh_eap_packet_strip_pad(buf);

  /* Route it on the basis of EAP code field */

  code = ssh_eap_packet_get_code(buf);

  switch (code)
    {
    case SSH_EAP_CODE_REQUEST:
      ssh_eap_input_request(eap, buf);
      break;

    case SSH_EAP_CODE_REPLY:
      ssh_eap_input_reply(eap, buf);
      break;

    case SSH_EAP_CODE_SUCCESS:
    case SSH_EAP_CODE_FAILURE:
      ssh_eap_input_succfail(eap, buf);
      break;

    default:
      ssh_eap_discard_packet(eap,  NULL, buf, "unknown EAP code");
      break;
    }

  ssh_eap_delayed_token(eap);
}

void
ssh_eap_send_identification_request(SshEap eap,
                                    const unsigned char *buffer,
                                    unsigned long len)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(eap->is_authenticator == 1);

  /* The authentication round begings with this request */

  ssh_eap_begin_auth_timeout(eap);

  /* Send the identification request */
  ssh_eap_build_and_send_request(eap, SSH_EAP_TYPE_IDENTITY, buffer, len);

  ssh_eap_delayed_token(eap);
}

void
ssh_eap_send_notification_request(SshEap eap,
                                  const unsigned char *buffer,
                                  unsigned long len)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(eap->is_authenticator == 1);

  /* The authentication round begings with this request */

  ssh_eap_begin_auth_timeout(eap);

  /* Send the notification request */
  ssh_eap_build_and_send_request(eap, SSH_EAP_TYPE_NOTIFICATION, buffer, len);

  ssh_eap_delayed_token(eap);
}

static void
ssh_eap_send_nak_reply(SshEap eap,
                       SshEapProtocol protocol,
                       Boolean iscommit)
{
  SshEapProtocol pro;
  unsigned long idx;
  SshUInt8 id;

  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(eap->is_authenticator == 0);

  /* If this NAK reply has some overloaded semantics, and hence
     one that does not imply that we don't actually understand
     the protocol (an example would be the EAP-SRP "do-not-support
     lightweight rechallenges"). */

  if (protocol != NULL && iscommit == TRUE)
    {
      protocol->is_nak = 1;
    }

  /* Find an authentication protocol to place in the NAK reply */

  pro = NULL;
  for (idx = 0; idx < eap->nprotocols; idx++)
    {
      pro = eap->protocols[idx];
      if (pro != NULL)
        {
          if (pro->is_nak == 0)
            {
              break;
            }
        }
    }

  if (idx == eap->nprotocols && pro != NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,("already NAK'd all configured protocols, "
                             "no new protocols to suggest"));
      id = 0;
    }
  else if (pro == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("no configured protocols"));
      id = 0;
    }
  else
    {
      id = pro->impl->id;
      SSH_DEBUG(SSH_D_MIDOK,("sending NAK reply and requesting "
                             "protocol %d", id));
    }

  ssh_eap_build_and_send_reply(eap, SSH_EAP_TYPE_NAK, &id, 1);
  return;
}

Boolean
ssh_eap_send_id_reply(SshEap eap,
                      const char *buffer,
                      unsigned long len)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(eap->is_authenticator == 0);

  /* If we are not looking for an identity reply, then do nothing */

  if (eap->id_isinit == 0)
    {
      ssh_eap_discard_token(eap, NULL, NULL,
                            "EAP instance cannot send a reply, no request id");
      return FALSE;
    }

  /* Build a packet, and send it */

  SSH_DEBUG(SSH_D_MIDOK,("sending EAP identity reply"));

  ssh_eap_build_and_send_reply(eap,
                               SSH_EAP_TYPE_IDENTITY,
                               (const unsigned char*)buffer,
                               (SshUInt16)len);
  return TRUE;
}

static void
ssh_eap_begin(SshEap eap, SshEapProtocol protocol)
{
  if (protocol->state == NULL)
    {
      protocol->state = protocol->impl->create(protocol,
                                               eap,
                                               protocol->impl->id);

      if (protocol->state == NULL)
        {
          ssh_eap_fatal(eap, protocol,
                        "Out of memory. "
                        "Cannot allocate state for protocol run.");
          return;
        }
    }

  SSH_EAP_CB(eap,
             protocol->impl->handler(SSH_EAP_PROTOCOL_BEGIN,
                                     eap,
                                     protocol, NULL));
}

static void
ssh_eap_continue_noradius(SshEap eap)
{
  SshEapProtocol pr;
  int i;

  for (i = 0; i < eap->nprotocols; i++)
    {
      pr = eap->protocols[i];
      if ((pr->is_nak == 0) &&
          ((pr->impl->flags & SSH_EAP_PASS_THROUGH_ONLY) == 0))
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("continuing authentication using protocol %d",
                     pr->impl->id));
          ssh_eap_begin_auth_timeout(eap);
          ssh_eap_begin(eap, pr);
          return;
        }
    }

  if (i == eap->nprotocols)
    {

      SSH_DEBUG(SSH_D_FAIL,
                ("authentication failed due to lack of common protocol"));

      ssh_eap_protocol_auth_fail(NULL, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION,
                                 NULL);
    }
  return;
}

void
ssh_eap_authenticate(SshEap eap, SshEapAuthStep step)
{
  /* Only an authenticating instance can use use this
     "continue" the protocol run, basically in
     response to a request for a secret.  */

  SSH_ASSERT(eap->is_authenticator == 1);

  eap->waiting_for_callback = 0;

  /* If authentication timeout is inactive, restart it */

  if (eap->auth_timeout_active == 0)
    ssh_eap_begin_auth_timeout(eap);

  switch (step)
    {
    case SSH_EAP_AUTH_CONTINUE:
#ifdef SSHDIST_RADIUS
      if (eap->radius_config != NULL)
        {
          ssh_eap_radius_continue(eap, TRUE);
          break;
        }

      if (eap->params->radius_buffer_identity)
        {
          ssh_eap_radius_reset(eap);
        }
#endif /* SSHDIST_RADIUS */
      ssh_eap_continue_noradius(eap);
      break;

    case SSH_EAP_AUTH_SUCCESS:

      SSH_DEBUG(SSH_D_MIDOK,("accepting authentication upon caller request"));
      ssh_eap_protocol_auth_ok(NULL, eap,
                               SSH_EAP_SIGNAL_AUTH_OK_USERNAME,
                               NULL);

      break;

    case SSH_EAP_AUTH_FAILURE:
      SSH_DEBUG(SSH_D_MIDOK,("failing authentication upon caller request"));
      ssh_eap_protocol_auth_fail(NULL, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME,
                                 NULL);
      break;
    }

  ssh_eap_delayed_token(eap);
}

static const SshKeywordStruct signal_code_keywords[] =
{
  {"None",                              SSH_EAP_SIGNAL_NONE},
  {"Authenticator OK",                  SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK},
  {"Authentication peer OK",            SSH_EAP_SIGNAL_AUTH_PEER_OK},
  {"Authentication failed: reply",      SSH_EAP_SIGNAL_AUTH_FAIL_REPLY},
  {"Authentication failed:negotiation", SSH_EAP_SIGNAL_AUTH_FAIL_NEGOTIATION},
  {"Identity",                          SSH_EAP_SIGNAL_IDENTITY},
  {"Notification",                      SSH_EAP_SIGNAL_NOTIFICATION},
  {"Need token",                        SSH_EAP_SIGNAL_NEED_TOKEN},
  {"Authentication peer maybe OK",      SSH_EAP_SIGNAL_AUTH_PEER_MAYBE_OK },
  {"Authentication failed: authenticator",
   SSH_EAP_SIGNAL_AUTH_FAIL_AUTHENTICATOR},
  {"Packet discarded",                  SSH_EAP_SIGNAL_PACKET_DISCARDED},
  {"Token discarded",                   SSH_EAP_SIGNAL_TOKEN_DISCARDED},
  {"Authentication failed: username",   SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME},
  {"Authentication OK: username",       SSH_EAP_SIGNAL_AUTH_OK_USERNAME},
  {"Fatal error",                       SSH_EAP_SIGNAL_FATAL_ERROR},
  {"Authentication failed: timeout",    SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT},
  {NULL, 0},
};


const char*
ssh_eap_signal_code_to_string(SshEapSignal code)
{
  const char *str;

  str = ssh_find_keyword_name(signal_code_keywords, code);

  if (str == NULL)
    str = "unknown";

  return str;
}
