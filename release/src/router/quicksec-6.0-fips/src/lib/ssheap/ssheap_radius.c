/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"

#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshgetput.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"

#define SSH_DEBUG_MODULE "SshEapRadius"

#ifdef SSHDIST_RADIUS

void
ssh_eap_radius_reset(SshEap eap)
{
  if (eap->radius_handle != NULL)
    {
      ssh_operation_abort(eap->radius_handle);
      eap->radius_handle = NULL;
    }

  if (eap->radius_req != NULL)
    {
      ssh_radius_client_request_destroy(eap->radius_req);
      eap->radius_req = NULL;
    }

  if (eap->radius_pkt != NULL)
    {
      ssh_free(eap->radius_pkt);
      eap->radius_pkt = NULL;
    }

  if (eap->radius_state_buf != NULL)
    {
      ssh_free(eap->radius_state_buf);
      eap->radius_state_buf = NULL;
      eap->radius_state_len = 0;
    }

  if (eap->radius_user_id_buf != NULL)
    {
      ssh_free(eap->radius_user_id_buf);
      eap->radius_user_id_buf = NULL;
      eap->radius_user_id_len = 0;
    }

  eap->radius_config = NULL;
  eap->radius_session_timeout = 0;

  if (eap->mppe_recv_key != NULL)
    {
      ssh_free(eap->mppe_recv_key);
      eap->mppe_recv_key    = NULL;
      eap->mppe_recv_keylen = 0;
    }

  if (eap->mppe_send_key != NULL)
    {
      ssh_free(eap->mppe_send_key);
      eap->mppe_send_keylen = 0;
      eap->mppe_send_key    = NULL;
    }
}

void
ssh_eap_radius_init(SshEap eap)
{
  eap->radius_user_id_buf = NULL;
  eap->radius_user_id_len = 0;

  eap->radius_pkt = NULL;
  eap->radius_pkt_len = 0;

  eap->radius_handle = NULL;
  eap->radius_req = NULL;

  eap->radius_state_buf = NULL;
  eap->radius_state_len = 0;

  eap->radius_config = NULL;
  eap->radius_session_timeout = 0;
}

static Boolean
ssh_eap_radius_parse_prelim_reply(SshEap eap,
                                  SshRadiusClientRequestStatus status,
                                  SshRadiusClientRequest request,
                                  SshRadiusOperationCode reply_code)
{

  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(request != NULL);

  if (eap->radius_user_id_buf == NULL)
    {
      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS user id unknown. Internal error.");
      return FALSE;
    }

  if (eap->radius_req != request)
    {
      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS request unknown. Internal error.");
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS request completed: status %d "
                              "reply_code %d",
                              status,reply_code));

  switch (status)
    {
    case SSH_RADIUS_CLIENT_REQ_SUCCESS:
      break;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST:
      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS client request malformed");
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES:

      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS client failed due to insufficient "
                             "resources");
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_TIMEOUT:

      ssh_eap_send_signal(eap, eap->previous_eap_type,
                          SSH_EAP_SIGNAL_AUTH_FAIL_TIMEOUT, NULL);


      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS client failed due to timeout");
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY:
      ssh_eap_discard_packet(eap, NULL, NULL,
                             "RADIUS client failed due to malformed reply");
      goto fail;

    default:
      ssh_eap_discard_packet(eap, NULL, NULL,
                             "Internal error: RADIUS client unknown "
                             "status code");
      goto fail;
    }

  SSH_ASSERT(status == SSH_RADIUS_CLIENT_REQ_SUCCESS);

  return TRUE;

 fail:
  return FALSE;
}

static Boolean
ssh_eap_radius_parse_avp_status(SshRadiusAvpStatus ret)
{
  switch (ret)
    {
    case SSH_RADIUS_AVP_STATUS_SUCCESS:
      return TRUE;
    case SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG:
      return FALSE;
    case SSH_RADIUS_AVP_STATUS_TOO_MANY:
      return FALSE;
    case SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY:
      return FALSE;
    case SSH_RADIUS_AVP_STATUS_NOT_FOUND:
      return TRUE;
    case SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS:
      return FALSE;
    }
  return FALSE;
}

static void
ssh_eap_radius_dump_avps(SshRadiusClientRequestStatus status,
                         SshRadiusClientRequest request,
                         SshRadiusOperationCode reply_code)
{
  SshRadiusAvpStatus ret;
  unsigned char *ucp;
  size_t value_len;
  SshRadiusAvpType type;
  const SshRadiusAvpInfoStruct *avp_info;
  const char *code_name;
  SshRadiusClientReplyEnumeratorStruct e;

  code_name = ssh_find_keyword_name(ssh_radius_operation_codes,reply_code);

  SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS code: %d: %s",
                              reply_code,
                              (code_name!=NULL?code_name:"<unknown>")));

  ssh_radius_client_reply_enumerate_init(&e, request,
                                         SSH_RADIUS_VENDOR_ID_NONE, 0);


  do {
    ret = ssh_radius_client_reply_enumerate_next(&e, NULL, &type,
                                                 &ucp, &value_len);

    if (ssh_eap_radius_parse_avp_status(ret) == FALSE)
      return;

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS)
      {
        avp_info = ssh_radius_avp_info(type);
        SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS AVP type %d: name: %s: length %d",
                                    type,
                                    (avp_info != NULL
                                     ? avp_info->name
                                     : "<unknown>"),
                                    value_len));
      }

  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);
}

Boolean
ssh_eap_radius_read_avps(SshEap eap,
                         SshRadiusClientRequestStatus status,
                         SshRadiusClientRequest request,
                         SshRadiusOperationCode reply_code)
{
  SshRadiusAvpStatus ret;
  unsigned char *ucp;
  size_t value_len;
  SshRadiusVendorId vendor_id;
  SshRadiusAvpType type;
  SshRadiusClientReplyEnumeratorStruct e;

  ssh_radius_client_reply_enumerate_init(&e, request,
                                         SSH_RADIUS_VENDOR_ID_NONE, 0);

  do {
    ret = ssh_radius_client_reply_enumerate_next(&e, &vendor_id,
                                                 &type, &ucp, &value_len);

    SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("AVP length %d", value_len),
                      ucp, value_len);

    if (ssh_eap_radius_parse_avp_status(ret) == FALSE)
      return FALSE;

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS)
      {
        int vendor_type = type;
        switch (vendor_type)
          {
          case SSH_RADIUS_AVP_FRAMED_PROTOCOL:
            if (value_len != 4)
              {
                SSH_DEBUG(SSH_D_NETGARB,("Framed-Protocol AVP corrupted"));
                break;
              }
            break;

          case SSH_RADIUS_AVP_SERVICE_TYPE:
            if (value_len != 4)
              {
                SSH_DEBUG(SSH_D_NETGARB,("Framed-Protocol AVP corrupted"));
                break;
              }
            break;

          case SSH_RADIUS_AVP_VENDOR_SPECIFIC:
          default:
            break;
          }
        }
  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);


  ssh_radius_client_reply_enumerate_init(&e, request,
                                         SSH_RADIUS_VENDOR_ID_MS, 0);

  do {
    ret = ssh_radius_client_reply_enumerate_next(&e, NULL,
                                                 &type, &ucp, &value_len);

    SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("AVP length %d", value_len),
                      ucp, value_len);

    if (ssh_eap_radius_parse_avp_status(ret) == FALSE)
      return FALSE;

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS)
      {
        int vendor_type = type;
        switch (vendor_type)
          {
          case SSH_RADIUS_VENDOR_MS_MPPE_SEND_KEY:

            SSH_DEBUG_HEXDUMP(5, ("Send key %d", reply_code), ucp, value_len);

            /* MPPE keys are only sent in an Access-Accept message. */
            if (reply_code == SSH_RADIUS_ACCESS_ACCEPT)
              {
                eap->mppe_send_key = ssh_memdup(ucp, value_len);
                eap->mppe_send_keylen = value_len;
              }
            break;

          case SSH_RADIUS_VENDOR_MS_MPPE_RECV_KEY:

            SSH_DEBUG_HEXDUMP(5, ("Recv key %d", reply_code), ucp, value_len);

            /* MPPE keys are only sent in an Access-Accept message. */
            if (reply_code == SSH_RADIUS_ACCESS_ACCEPT)
              {
                eap->mppe_recv_key = ssh_memdup(ucp, value_len);
                eap->mppe_recv_keylen = value_len;
              }

            break;
          default:
            break;
          }
      }
  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);

  SSH_ASSERT(eap->msk == NULL);
  SSH_ASSERT(eap->msk_len == 0);

  if (eap->mppe_send_key != NULL && eap->mppe_recv_key != NULL)
    {
      SshEapProtocol protocol;

      protocol =
        ssh_eap_get_protocol(eap, eap->previous_eap_type);

      /* Method specific key formatting. */
      if (protocol && protocol->impl && protocol->impl->key)
        {
          if (protocol->impl->key(protocol, eap, protocol->impl->id)
              != SSH_EAP_OPSTATUS_SUCCESS)
            {
              return FALSE;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Received success message, but EAP "
                                       "protocol or key not available."));
        }
    }

  return TRUE;
}

static Boolean
ssh_eap_radius_forward_eap(SshEap eap,
                           SshRadiusClientRequestStatus status,
                           SshRadiusClientRequest request,
                           SshRadiusOperationCode reply_code)
{
  SshRadiusAvpStatus ret;
  SshRadiusAvpType type;
  unsigned char *ucp;
  size_t value_len;
  SshBuffer pkt;
  SshUInt8 *eap_pkt_buf;
  size_t eap_pkt_len;
  SshRadiusClientReplyEnumeratorStruct e;

  SSH_PRECOND(reply_code == SSH_RADIUS_ACCESS_CHALLENGE);

  /* Extract relevant fields from RADIUS reply */

  ssh_radius_client_reply_enumerate_init(&e,request,
                                         SSH_RADIUS_VENDOR_ID_NONE,0);

  if (eap->radius_state_buf != NULL)
    {
      ssh_free(eap->radius_state_buf);
      eap->radius_state_buf = NULL;
      eap->radius_state_len = 0;
    }

  eap_pkt_buf = NULL;

  pkt = ssh_buffer_allocate();

  if (pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Cannot create RADIUS request");
      return FALSE;
    }

  do {
    ret = ssh_radius_client_reply_enumerate_next(&e,NULL, &type,
                                                 &ucp,&value_len);

    if (ssh_eap_radius_parse_avp_status(ret) == FALSE)
      {
        ssh_eap_discard_packet(eap, NULL, NULL,
                               "Fatal error parsing RADIUS message");
        ssh_buffer_free(pkt);
        return FALSE;
      }

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS)
      {
        switch (type)
          {
          case SSH_RADIUS_AVP_SESSION_TIMEOUT:
            if (value_len != 4)
              {
                SSH_DEBUG(SSH_D_NETGARB,("Session-Timeout AVP corrupted"));
                break;
              }

            if (eap->radius_config->ignore_radius_session_timeout == FALSE)
              {
                eap->radius_session_timeout = SSH_GET_32BIT(ucp);
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Session-Timeout for EAP-Request is "
                           "%d s", (int) eap->radius_session_timeout));
              }
            break;

          case SSH_RADIUS_AVP_EAP_MESSAGE:
            eap_pkt_buf = ucp;
            eap_pkt_len = value_len;

            if (ssh_buffer_append(pkt, eap_pkt_buf, eap_pkt_len)
                != SSH_BUFFER_OK)
              {
                ssh_buffer_free(pkt);
                ssh_eap_fatal(eap, NULL,
                              "Out of memory. Cannot create RADIUS request.");
                return FALSE;
              }
            break;

          case SSH_RADIUS_AVP_STATE:
            if (eap->radius_state_buf == NULL)
              {
                eap->radius_state_buf = ssh_malloc(value_len);

                if (eap->radius_state_buf == NULL)
                  {
                    ssh_eap_fatal(eap, NULL,
                                  "Out of memory. "
                                  "Cannot cache RADIUS state variable");
                    ssh_buffer_free(pkt);
                    return FALSE;
                  }

                eap->radius_state_len = (unsigned long)value_len;
                memcpy(eap->radius_state_buf, ucp, eap->radius_state_len);
              }
            break;

          default:
            break;
          }
      }
  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);

  if (eap_pkt_buf == NULL)
    {
      ssh_eap_discard_packet(eap,NULL,NULL,
                             "RADIUS reply missing required fields");
      ssh_buffer_free(pkt);
      return FALSE;
    }


  if (ssh_eap_packet_isvalid(pkt) == FALSE ||
      ssh_eap_packet_get_code(pkt) != SSH_EAP_CODE_REQUEST)
    {
      ssh_buffer_free(pkt);
      ssh_eap_discard_packet(eap, NULL, pkt,
                             "Received invalid EAP packet from RADIUS server");
      return FALSE;
    }

  /* The below function sets up resend timers and identifiers */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("forwarding packet (code %d type %d id %d) from RADIUS server",
             ssh_eap_packet_get_code(pkt),
             ssh_eap_packet_get_type(pkt),
             ssh_eap_packet_get_identifier(pkt)));

  ssh_eap_protocol_send_request(NULL, eap, pkt);

  return TRUE;
}

static void
ssh_eap_radius_cb(SshRadiusClientRequestStatus status,
                  SshRadiusClientRequest request,
                  SshRadiusOperationCode reply_code,
                  void *ctx,
                  Boolean is_start)
{
  SshEap eap;
  SshBufferStruct dummy;

  eap = (SshEap)ctx;
  eap->radius_handle = NULL;

  SSH_ASSERT(eap->radius_req == request);

  if (ssh_eap_radius_parse_prelim_reply(eap, status, request, reply_code)
      == FALSE)
    {
      goto fail;
    }

  dummy.dynamic = FALSE;
  dummy.offset = 0;
  dummy.alloc = eap->radius_user_id_len;
  dummy.end = dummy.alloc;
  dummy.buf = eap->radius_user_id_buf;

  ssh_eap_radius_dump_avps(status, request, reply_code);

  /* Ok, a successful reply was received for the first request.
     Store used radius server index to eap context and continue
     radius exchanges using this server index. */
  if (is_start == TRUE
      && ssh_radius_client_request_get_server(request,
                                              &eap->radius_server_index)
      == FALSE)
    goto fail;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Initial radius exchange completed on server index %d",
             eap->radius_server_index));

  switch (reply_code)
    {
    default:
    case SSH_RADIUS_ACCESS_REJECT:
      /* This function calls ssh_eap_radius_reset() */
      ssh_eap_protocol_auth_fail(NULL, eap,
                                 SSH_EAP_SIGNAL_AUTH_FAIL_USERNAME,
                                 &dummy);
      break;

    case SSH_RADIUS_ACCESS_ACCEPT:

      /* RADIUS attributes may be used in e.g. decisions to allow/deny
         access to certain services. If we cannot extract the attributes
         we support, discard message. */

      if (ssh_eap_radius_read_avps(eap, status, request, reply_code)
          == FALSE)
        {
          ssh_eap_discard_packet(eap, NULL, NULL,
                                 "Fatal error parsing RADIUS reply");
          break;
        }

      if (eap->radius_config != NULL
          && eap->params->radius_req_cb != NULL_FNPTR)
        {
          if ((*eap->params->radius_req_cb)(eap,
                                            status,
                                            request,
                                            reply_code,
                                            eap->ctx) == FALSE)
            {
              ssh_eap_protocol_auth_fail(NULL, eap,
                                         SSH_EAP_SIGNAL_AUTH_FAIL_REPLY,
                                         NULL);
              break;
            }
        }
      /* This function calls ssh_eap_radius_reset(), which destroys
         the cached request which is used by ssh_eap_radius_read_avps() */
      ssh_eap_protocol_auth_ok(NULL, eap,
                               SSH_EAP_SIGNAL_AUTH_AUTHENTICATOR_OK,
                               &dummy);
      break;

    case SSH_RADIUS_ACCESS_CHALLENGE:
      ssh_eap_radius_forward_eap(eap, status, request, reply_code);
      break;
    }

 fail:
  /* Use radius->req to refer to the request, as a call
     to ssh_eap_radius_reset() may have destroyed it. */
  if (eap->radius_req != NULL)
    {
      ssh_radius_client_request_destroy(eap->radius_req);
      eap->radius_req = NULL;
    }
}

static void
ssh_eap_radius_start_cb(SshRadiusClientRequestStatus status,
                      SshRadiusClientRequest request,
                      SshRadiusOperationCode reply_code,
                      void *ctx)
{
  ssh_eap_radius_cb(status, request, reply_code, ctx, TRUE);
}

static void
ssh_eap_radius_normal_cb(SshRadiusClientRequestStatus status,
                         SshRadiusClientRequest request,
                         SshRadiusOperationCode reply_code,
                         void *ctx)
{
  ssh_eap_radius_cb(status, request, reply_code, ctx, FALSE);
}

static void
ssh_eap_input_generic_reply_radius(SshEap eap, SshBuffer buf)
{
  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(ssh_eap_packet_isvalid(buf) == TRUE);

  /* Grab a copy of packet for later use */
  if (eap->radius_pkt != NULL)
    {
      ssh_free(eap->radius_pkt);
      eap->radius_pkt = NULL;
    }

  eap->radius_pkt = ssh_buffer_ptr(buf);
  eap->radius_pkt_len = (unsigned long)ssh_buffer_len(buf);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("forwarding packet (code %d type %d id %d) to RADIUS server",
             ssh_eap_packet_get_code(buf),
             ssh_eap_packet_get_type(buf),
             ssh_eap_packet_get_identifier(buf)));


  ssh_eap_radius_continue(eap, FALSE);

  eap->radius_pkt = NULL;
  eap->radius_pkt_len = 0;
}

void
ssh_eap_radius_input_identity_reply(SshEap eap,
                                    SshBuffer buf,
                                    Boolean signal_sent)

{
  SSH_PRECOND(eap != NULL);

  /* Discard nonsense */
  if (ssh_eap_packet_get_type(buf) != eap->previous_eap_type)
    {
      ssh_eap_discard_packet(eap, NULL, buf,
                             "unexpected identity response");
      return;
    }

  /* Grab a copy of packet for later use */
  if (eap->radius_pkt != NULL)
    {
      ssh_free(eap->radius_pkt);
      eap->radius_pkt = NULL;
    }

  /* Reset state. */
  if (eap->radius_state_buf != NULL)
    {
      ssh_free(eap->radius_state_buf);
      eap->radius_state_buf = NULL;
      eap->radius_state_len = 0;
    }

  eap->radius_pkt_len = (unsigned long)ssh_buffer_len(buf);

  eap->radius_pkt = ssh_malloc(eap->radius_pkt_len);

  if (eap->radius_pkt == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not cache EAP packet.");
      return;
    }

  memcpy(eap->radius_pkt, ssh_buffer_ptr(buf), eap->radius_pkt_len);

  /* Grab a copy of username */
  ssh_eap_packet_skip_hdr(buf);

  if (eap->radius_user_id_buf == NULL)
    {
      eap->radius_user_id_buf = ssh_malloc(ssh_buffer_len(buf) + 1);

      if (eap->radius_user_id_buf == NULL)
        {
          ssh_eap_fatal(eap, NULL,
                        "Out of memory. Can not cache peer identity.");

          ssh_free(eap->radius_pkt);
          eap->radius_pkt = NULL;
          return;
        }

      eap->radius_user_id_len = (unsigned long)ssh_buffer_len(buf);
      memcpy(eap->radius_user_id_buf, ssh_buffer_ptr(buf),
             eap->radius_user_id_len);
      eap->radius_user_id_buf[eap->radius_user_id_len] = '\0';
    }
  else
    {
      /* If a username has been previously set, the caller of the library is
         probably expecting that the authentication is done using that
         username to the RADIUS server. */
      if (eap->radius_user_id_len != ssh_buffer_len(buf)
          || memcmp(eap->radius_user_id_buf, ssh_buffer_ptr(buf),
                    eap->radius_user_id_len) != 0)
        {
          ssh_eap_discard_packet(eap, NULL, buf,
                                 "unexpected username in EAP identity reply");
          return;
        }
    }

  if (signal_sent == FALSE)
    {
      ssh_eap_send_signal(eap, SSH_EAP_TYPE_IDENTITY, SSH_EAP_SIGNAL_IDENTITY,
                          buf);
    }
}

void
ssh_eap_radius_attach(SshEap eap,
                      SshEapRadiusConfiguration radius_config)
{
  SSH_PRECOND(radius_config == NULL || radius_config->radius_client != NULL);

  eap->radius_config = radius_config;
}

void
ssh_eap_radius_input_reply(SshEap eap, SshBuffer buf)
{
  SshUInt8 type;

  type = ssh_eap_packet_get_type(buf);

  switch (type)
    {
    case SSH_EAP_TYPE_IDENTITY:
      ssh_eap_radius_input_identity_reply(eap,buf, FALSE);
      break;
    default:
      ssh_eap_input_generic_reply_radius(eap,buf);
      break;
    }
  return;
}

static Boolean
ssh_eap_radius_add_avps(SshEap eap,
                        SshRadiusClientRequest req)
{
  SshUInt8 value[4];
  int ok;
  SshRadiusAvpStatus ret;
  Boolean ret_b;

  /* This is for non-EAP aware RADIUS proxies */

  ok = 1;

  ret = ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_USER_NAME,
                                                eap->radius_user_id_buf,
                                                eap->radius_user_id_len);

  ok &= (ret == SSH_RADIUS_AVP_STATUS_SUCCESS ? 1 : 0);

  /* Provide the actual EAP server with the link MTU */

  SSH_PUT_32BIT(&value, eap->con->mru);

  ret = ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_FRAMED_MTU,
                                                value, 4);

  ok &= (ret == SSH_RADIUS_AVP_STATUS_SUCCESS ? 1 : 0);

  /* Pass in a possible RADIUS State variable */

  if (eap->radius_state_buf != NULL)
    {
      ret = ssh_radius_client_request_add_attribute(req,
                                                    SSH_RADIUS_AVP_STATE,
                                                    eap->radius_state_buf,
                                                    eap->radius_state_len);

      ok &= (ret == SSH_RADIUS_AVP_STATUS_SUCCESS ? 1 : 0);

      ssh_free(eap->radius_state_buf);
      eap->radius_state_buf = NULL;
      eap->radius_state_len = 0;
    }

  /* Additional AVP's requested by user */

  if (eap->radius_config->default_avps != NULL)
    {
      ret_b = ssh_radius_url_add_avps(req,
                                    eap->radius_config->default_avps);

      ok &= (ret_b == TRUE ? 1 : 0);
    }


  /* All EAP packets require the Message Authenticator [RFC2869] */

  ret = ssh_radius_client_request_add_attribute(req,
                                  SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR,
                                  NULL,
                                  0);

  if (ret != SSH_RADIUS_AVP_STATUS_SUCCESS
      && ret != SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS)
    ok = 0;

  return (ok ? TRUE : FALSE);
}

Boolean
ssh_eap_radius_send_start(SshEap eap, SshEapToken t)
{
  SshRadiusClient client;
  SshRadiusClientRequest req;
  SshRadiusClientServerInfo servers;
  SshBuffer buf = NULL;

  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(t != NULL);
  SSH_PRECOND(t->type == SSH_EAP_TOKEN_USERNAME);
  SSH_PRECOND(eap->radius_config != NULL);
  SSH_PRECOND(eap->radius_config->radius_client != NULL);
  SSH_PRECOND(eap->radius_config->radius_servers != NULL);

  client = eap->radius_config->radius_client;

  if (eap->radius_handle != NULL)
    {
      ssh_operation_abort(eap->radius_handle);
      eap->radius_handle = NULL;
    }

  if (eap->radius_req != NULL)
    {
      ssh_radius_client_request_destroy(eap->radius_req);
      eap->radius_req = NULL;
    }

  if (eap->radius_state_buf != NULL)
    {
      ssh_free(eap->radius_state_buf);
      eap->radius_state_buf = NULL;
      eap->radius_state_len = 0;
    }

  if (eap->radius_user_id_buf != NULL)
    {
      ssh_free(eap->radius_user_id_buf);
      eap->radius_user_id_buf = NULL;
    }

  if (eap->radius_pkt != NULL)
    {
      ssh_free(eap->radius_pkt);
      eap->radius_pkt = NULL;
    }

  req = NULL;
  eap->radius_user_id_buf = ssh_malloc(t->token.buffer.len + 1);

  if (eap->radius_user_id_buf == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send RADIUS request.");
      goto fail;
    }

  eap->radius_user_id_len = t->token.buffer.len;

  memcpy(eap->radius_user_id_buf, t->token.buffer.dptr,
         eap->radius_user_id_len);

  eap->radius_user_id_buf[eap->radius_user_id_len] = '\0';

  req = ssh_radius_client_request_create(client,
                                         SSH_RADIUS_ACCESS_REQUEST);

  eap->radius_req = req;

  buf = ssh_buffer_allocate();

  if (buf == NULL || req == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not create RADIUS request.");
      goto fail;
    }

  if (ssh_eap_packet_build_hdr_with_type(buf,
                                         SSH_EAP_CODE_REPLY,
                                         (SshUInt8)ssh_random_get_byte(),
                                         (SshUInt16)eap->radius_user_id_len,
                                         SSH_EAP_TYPE_IDENTITY)
      == FALSE)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send RADIUS request.");
      goto fail;
    }

  if (ssh_buffer_append(buf,  eap->radius_user_id_buf,
                        eap->radius_user_id_len) != SSH_BUFFER_OK)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Can not send RADIUS request.");
      goto fail;

    }

  if ((ssh_radius_client_request_add_attribute(req,
                                               SSH_RADIUS_AVP_EAP_MESSAGE,
                                               ssh_buffer_ptr(buf),
                                               ssh_buffer_len(buf)))
      != SSH_RADIUS_AVP_STATUS_SUCCESS
      || (ssh_eap_radius_add_avps(eap, req) == FALSE))
    {
      ssh_eap_fatal(eap, NULL,
                    "Error building RADIUS request.");
      goto fail;
    }

  ssh_buffer_free(buf);
  buf = NULL;

  SSH_DEBUG(SSH_D_MIDOK,("sending fabricated EAP Identity packet "
                         "to RADIUS server"));

  servers = eap->radius_config->radius_servers;

  eap->radius_handle = ssh_radius_client_request(req,
                                                 servers,
                                                 ssh_eap_radius_start_cb,
                                                 eap);

  if (eap->radius_handle == NULL)
    {
      req = NULL;
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Unable to allocate RADIUS request.");
      goto fail;
    }

  return TRUE;
 fail:
  if (buf != NULL)
    ssh_buffer_free(buf);

  if (eap->radius_req != NULL)
    ssh_radius_client_request_destroy(eap->radius_req);
  eap->radius_req = NULL;

  if (eap->radius_user_id_buf != NULL)
    ssh_free(eap->radius_user_id_buf);

  eap->radius_user_id_buf = NULL;
  eap->radius_user_id_len = 0;


  return FALSE;
}

Boolean
ssh_eap_radius_continue(SshEap eap,
                        Boolean free_pkt)
{
  SshUInt16 sent;
  SshRadiusClient client;
  SshRadiusClientRequest req;
  SshRadiusClientServerInfo servers;
  SshRadiusAvpStatus avp_stat;

  SSH_PRECOND(eap->radius_config != NULL);
  SSH_PRECOND(eap->radius_config->radius_client != NULL);
  SSH_PRECOND(eap->radius_config->radius_servers != NULL);

  client = eap->radius_config->radius_client;
  req = NULL;

  if (eap->radius_handle != NULL)
    {
      ssh_operation_abort(eap->radius_handle);
      eap->radius_handle = NULL;
    }

  if (eap->radius_req != NULL)
    {
      ssh_radius_client_request_destroy(eap->radius_req);
      eap->radius_req = NULL;
    }

  if (eap->radius_user_id_buf == NULL || eap->radius_pkt == NULL)
    {
      ssh_eap_protocol_request_token(eap,
                                     SSH_EAP_TYPE_IDENTITY,
                                     SSH_EAP_TOKEN_USERNAME);
      return TRUE;
    }

  req = ssh_radius_client_request_create(client,
                                         SSH_RADIUS_ACCESS_REQUEST);

  if (req == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Unable to create RADIUS request.");
      goto fail;
    }

  eap->radius_req = req;

  for (sent = 0; sent < eap->radius_pkt_len; sent += 253)
    {
      SshUInt16 send_len;

      if ((eap->radius_pkt_len - sent) > 253)
        send_len = 253;
      else
        send_len = (SshUInt16)(eap->radius_pkt_len - sent);

      avp_stat = ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_EAP_MESSAGE,
                                                eap->radius_pkt + sent,
                                                send_len);

      if (avp_stat != SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          ssh_eap_fatal(eap, NULL,
                        "Error adding attribute to RADIUS request.");
          goto fail;
        }
    }

  if (ssh_eap_radius_add_avps(eap, req) == FALSE)
    {
      ssh_eap_fatal(eap, NULL,
                    "Error adding attribute to RADIUS request.");
      goto fail;
    }

  /* Destroy packet */

  if (free_pkt == TRUE)
    {
      ssh_free(eap->radius_pkt);
      eap->radius_pkt = NULL;
      eap->radius_pkt_len = 0;
    }

  servers = eap->radius_config->radius_servers;
  if (ssh_radius_client_request_set_server(req, servers,
                                           eap->radius_server_index) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to bind radius request to server index %d",
                 eap->radius_server_index));
      goto fail;
    }

  eap->radius_handle = ssh_radius_client_request(req,
                                                 servers,
                                                 ssh_eap_radius_normal_cb,
                                                 eap);

  if (eap->radius_handle == NULL)
    {
      ssh_eap_fatal(eap, NULL,
                    "Out of memory. Error creating RADIUS request.");
      goto fail;
    }
  return TRUE;
 fail:
  if (eap->radius_req != NULL)
    ssh_radius_client_request_destroy(eap->radius_req);
  eap->radius_req = NULL;

  return FALSE;
}

void
ssh_eap_radius_input_peer_identity(SshEap eap,
                                   SshUInt8 *ptr, unsigned long len)
{
  SshEapTokenStruct token;

  SSH_PRECOND(eap != NULL);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Input peer identity"), ptr, len);

  if (!ssh_eap_isauthenticator(eap))
    return;

  ssh_eap_init_token_username(&token, ptr, len);

  if (eap->radius_config)
    ssh_eap_radius_send_start(eap, &token);
}

#endif /* SSHDIST_RADIUS */
