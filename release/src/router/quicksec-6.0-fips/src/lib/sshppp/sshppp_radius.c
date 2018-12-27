/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppRadius"

#include "sshincludes.h"
#include "sshradius.h"
#include "sshinet.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshfsm.h"
#include "sshgetput.h"

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

#include "sshppp_lcp_config.h"
#include "sshppp_ipcp_config.h"
#include "sshppp_protocol.h"
#include "sshppp_lcp.h"
#include "sshppp_ipcp.h"

#include "sshppp_chap.h"

#ifdef SSHDIST_RADIUS

/* Configure crap after authentication ok */
static void
ssh_ppp_radius_use_reply(SshPppState gdata,
                         SshRadiusClientRequestStatus status,
                         SshRadiusClientRequest request,
                         SshRadiusOperationCode reply_code);

static Boolean
ssh_ppp_radius_check_reply(SshPppState gdata,
                           SshRadiusClientRequestStatus status,
                           SshRadiusClientRequest request,
                           SshRadiusOperationCode reply_code);


/* Misc. convenience */

static Boolean
ssh_ppp_radius_status_isok(SshRadiusAvpStatus status)
{
  /* This function divides the AvpStatus return codes
     into classes which "allow" the sending of the
     request (in possibly unexpected form), and
     into those that do not.. */

  switch (status)
    {
    case SSH_RADIUS_AVP_STATUS_SUCCESS:
    case SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG:
    case SSH_RADIUS_AVP_STATUS_TOO_MANY:
    case SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS:
      return 1;
    case SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY:
    case SSH_RADIUS_AVP_STATUS_NOT_FOUND:
    default:
      break;
    }
  return 0;
}

static int
ssh_ppp_radius_reply_isok(SshPppState gdata,
                          SshRadiusClientRequestStatus status,
                          SshRadiusClientRequest request,
                          SshRadiusOperationCode reply_code)
{
  SSH_PRECOND(gdata != NULL);
  SSH_PRECOND(request != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS request completed: status %s (%d) "
                              "reply_code: %s (%d)",
                              ssh_find_keyword_name(
                                   ssh_radius_client_request_status_codes,
                                   status),
                              status,
                              ssh_find_keyword_name(ssh_radius_operation_codes,
                                                    reply_code),
                              reply_code));

  switch (status)
    {
    case SSH_RADIUS_CLIENT_REQ_SUCCESS:
      break;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST:
      SSH_DEBUG(SSH_D_NETGARB, ("RADIUS client request malformed"));
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES:
      SSH_DEBUG(SSH_D_NETGARB,("RADIUS client failed due to insufficient "
                               "resources"));
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_TIMEOUT:
      SSH_DEBUG(SSH_D_NETGARB,("RADIUS client failed due to timeout"));
      goto fail;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY:
      SSH_DEBUG(SSH_D_NETGARB,("RADIUS client failed due to malformed reply"));
      goto fail;

    default:
      SSH_DEBUG(SSH_D_NETGARB,("Internal error: RADIUS client unknown "
                               "status code"));
      goto fail;
    }

  SSH_ASSERT(status == SSH_RADIUS_CLIENT_REQ_SUCCESS);

  return 1;

 fail:
  return 0;
}

/* RADIUS->SshPppState Configuration functions */

static void
ssh_ppp_radius_configure_mtu(SshPppState gdata, SshUInt32 framed_mtu)
{
  SshPppConfigOption opt;

  if (gdata->link.lcp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Error accessing LCP instance!"));
      return;
    }

  opt = ssh_ppp_lcp_config_get_option(&gdata->link.lcp->config_output,
                                      SSH_LCP_CONFIG_TYPE_MRU);

  if (opt == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Error accessing MRU option"));
      return;
    }

  if (ssh_ppp_config_option_get_status(opt) != SSH_PPP_CONFIG_STATUS_ACK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Using MRU %ld from RADIUS server for outgoing traffic",
                 (unsigned long) framed_mtu));

      /* The LCP MRU is the one which is provided to the user of
         the SshPppState instance, even if other protocols can use
         other (higher) MRU values. */
      ssh_ppp_protocol_set_output_mru(gdata->link.lcp->protocol, framed_mtu);
      return;
    }
}

static void
ssh_ppp_radius_configure_framed_ipv4(SshPppState gdata, SshUInt32 framed_ip)
{
  SshPppConfigOption opt;

  if (gdata->ipcp == NULL)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Cannot configure Framed-IP address. IPCP not enabled"));
      return;
    }

  /* Server must supply an IP address */

  if (framed_ip == 0xFFFFFFFE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS instructs to use NAS configuration "
                                  "for choosing IPv4 address"));

      ssh_ppp_ipcp_use_radius(&gdata->ipcp->config_output, FALSE);
      return;
    }

  ssh_ppp_ipcp_use_radius(&gdata->ipcp->config_output, TRUE);

  opt = ssh_ppp_ipcp_config_get_option(&gdata->ipcp->config_output,
                                       SSH_IPCP_CONFIG_TYPE_IP_ADDRESS);

  if (opt == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failure accessing RADIUS IP Address option!"));
      return;
    }

  if (framed_ip == 0xFFFFFFFF) /* Client may request IP address */
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS instructs to let client choose "
                                  "IPv4 address"));

      ssh_ppp_config_option_reset(opt);
      ssh_ppp_config_option_ipv4_unset_constraint(opt);
      ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
    }
  else
    {

      SSH_DEBUG(SSH_D_NICETOKNOW,("RADIUS instructs to force client to "
                                  "IPv4 address %d.%d.%d.%d",
                                  (int) (framed_ip>>24),
                                  (int) ((framed_ip>>16) & 0xFF),
                                  (int) ((framed_ip>>8) & 0xFF),
                                  (int) (framed_ip & 0xFF)));

      ssh_ppp_config_option_reset(opt);
      ssh_ppp_config_option_ipv4_set_ip(opt, framed_ip);
      ssh_ppp_config_option_push(opt);
      ssh_ppp_config_option_ipv4_set_constraint(opt, framed_ip, 0xFFFFFFFF);
      ssh_ppp_config_preference_set(opt, SSH_PPP_CONFIG_PREF_MANDATORY);
    }
}

/* Add AVP's common to all requests */

static Boolean
ssh_ppp_radius_add_avps(SshPppState gdata,
                        SshRadiusClientRequest req)
{
  SshRadiusAvpStatus avp_stat;
  Boolean ok;
  SshUInt8 number_buf[4];

  SSH_PRECOND(gdata->radius_config != NULL);

  ok = TRUE;

  /* Add Framed-MTU value to request */

  if (gdata->link.lcp != NULL)
    {
      unsigned long mru;

      mru = ssh_ppp_protocol_get_output_mru(gdata->link.lcp->protocol);

      SSH_PUT_32BIT(number_buf, mru);

      avp_stat =
        ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_FRAMED_MTU,
                                                number_buf, 4);

      ok &= ssh_ppp_radius_status_isok(avp_stat);
    }

  /* Add Message-Authenticator */

  if (gdata->radius_config->authenticate_access_requests == TRUE)
    {
      avp_stat = ssh_radius_client_request_add_attribute(
                                      req,
                                      SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR,
                                      NULL, 0);

      ok &= ssh_ppp_radius_status_isok(avp_stat);
    }

  return TRUE;
}

Boolean
ssh_ppp_radius_user_parse(SshPppState gdata,
                          SshPppAuthType auth_type,
                          SshRadiusClientRequestStatus status,
                          SshRadiusClientRequest request,
                          SshRadiusOperationCode reply_code)
{
  Boolean res;

  res = TRUE;

  if (gdata->radius_config != NULL &&
      gdata->radius_config->radius_req_cb != NULL_FNPTR)
    {
      res = gdata->radius_config->radius_req_cb(gdata,
                                                auth_type,
                                                status,
                                                request,
                                                reply_code,
                                                gdata->ctx);
    }

  return res;
}

static void
ssh_ppp_radius_cb(SshRadiusClientRequestStatus status,
                  SshRadiusClientRequest request,
                  SshRadiusOperationCode reply_code,
                  void *context)
{
  SshPppState gdata;
  SshPppAuthProtocol auth_server;

  gdata = (SshPppState)context;

  auth_server = &gdata->link.auth_server;

  /* Do nothing. In fact, this request should never happen. */

  if (auth_server == NULL)
    {
      SSH_NOTREACHED;
      return;
    }

  ssh_ppp_auth_radius_cb(gdata, auth_server, status,
                         request, reply_code);
}

static SshRadiusAvpStatus
ssh_ppp_radius_add_chunked_attribute(SshRadiusClientRequest req,
                                     SshRadiusVendorId vendor_id,
                                     unsigned int type,
                                     SshUInt8 code,
                                     SshUInt8 id,
                                     SshUInt8 *chunk,
                                     size_t len)
{
  unsigned char tmpbuf[256];
  unsigned int idx;
  unsigned int clen;
  SshRadiusAvpStatus res;

  idx = 01;

  while (len > 0)
    {

      tmpbuf[0] = code;
      tmpbuf[1] = id;
      tmpbuf[2] = idx;
      tmpbuf[3] = idx;

      clen = (unsigned int)(len > 200 ? 200 : len);
      memcpy(tmpbuf+4,chunk, clen);

      res = ssh_radius_client_request_add_vs_attribute(
                                         req,
                                         vendor_id,
                                         type,
                                         tmpbuf,
                                         4 + clen);

      if (res != SSH_RADIUS_AVP_STATUS_SUCCESS)
        return res;

      idx++;
      chunk += clen;
      len -= clen;
    }
  return SSH_RADIUS_AVP_STATUS_SUCCESS;
}


Boolean
ssh_ppp_radius_make_changepw_query(SshPppState gdata,
                                   SshPppRadiusClient radius_client,
                                   SshUInt8 algorithm,
                                   SshUInt8 id,
                                   SshUInt8* peer_name,
                                   size_t peer_name_length,
                                   SshUInt8* challenge,
                                   size_t challenge_length,
                                   SshUInt8 *response,
                                   size_t response_length)
{
  unsigned char tmpbuf[256];
  unsigned int res;
  SshRadiusClientRequest req;
  SshRadiusAvpStatus avp_stat;
  SshOperationHandle handle;

  SSH_DEBUG(SSH_D_MIDOK,("sending RADIUS MS-CHAP changepw request"));

  req = ssh_radius_client_request_create(gdata->radius_config->client,
                                         SSH_RADIUS_ACCESS_REQUEST);

  if (req == NULL)
    goto fail;

  res = 1;

  avp_stat =
    ssh_radius_client_request_add_attribute(req,
                                            SSH_RADIUS_AVP_USER_NAME,
                                            peer_name, peer_name_length);
  res &= ssh_ppp_radius_status_isok(avp_stat);

  /* The RADIUS server requires the Challenge to authenticate
     the changepw request */
  avp_stat =
    ssh_radius_client_request_add_vs_attribute(
                                       req,
                                       SSH_RADIUS_VENDOR_ID_MS,
                                       SSH_RADIUS_VENDOR_MS_CHAP_CHALLENGE,
                                       challenge, challenge_length);
  res &= ssh_ppp_radius_status_isok(avp_stat);

  if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      if (response_length < ( 516 + 16 + 16 + 8 + 24 + 2))
        goto fail;

      avp_stat = ssh_ppp_radius_add_chunked_attribute(
                                         req,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP_NT_ENC_PW,
                                         6,
                                         id,
                                         response,
                                         516);

      res &= ssh_ppp_radius_status_isok(avp_stat);

      tmpbuf[0] = 7;
      tmpbuf[1] = id;
      memcpy(tmpbuf+2,response+516,64);
      tmpbuf[66] = 0;
      tmpbuf[67] = 0;
      avp_stat = ssh_radius_client_request_add_vs_attribute(
                                         req,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP2_CPW,
                                         tmpbuf,
                                         68);

      res &= ssh_ppp_radius_status_isok(avp_stat);
    }
  else if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
    {
      if (response_length < (516 + 16 + 516 + 16 + 24 + 24 + 2))
        goto fail;

      tmpbuf[0] = 6;
      tmpbuf[1] = id;
      memcpy(tmpbuf+2, response+516, 16);
      memcpy(tmpbuf+18,response+1048,66);

      avp_stat = ssh_radius_client_request_add_vs_attribute(
                                          req,
                                          SSH_RADIUS_VENDOR_ID_MS,
                                          SSH_RADIUS_VENDOR_MS_CHAP_PW_2,
                                          tmpbuf,
                                          84);

      avp_stat = ssh_ppp_radius_add_chunked_attribute(
                                         req,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP_NT_ENC_PW,
                                         6,
                                         id,
                                         response,
                                         516);

      res &= ssh_ppp_radius_status_isok(avp_stat);

      avp_stat = ssh_ppp_radius_add_chunked_attribute(
                                         req,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP_LM_ENC_PW,
                                         6,
                                         id,
                                         response+516+16,
                                         516);

      res &= ssh_ppp_radius_status_isok(avp_stat);
    }

  if (res == 0)
    goto fail;

  if (gdata->radius_config->default_avps != NULL)
    {
      if (ssh_radius_url_add_avps(req, gdata->radius_config->default_avps)
          == FALSE)
        goto fail;
    }

  radius_client->radius_req = req;

  handle = ssh_radius_client_request(req,
                                     gdata->radius_config->servers,
                                     ssh_ppp_radius_cb,
                                     gdata);

  if (handle == NULL)
    {
      req = NULL;
      goto fail;
    }

  radius_client->radius_handle = handle;

  return TRUE;
 fail:
  if (req != NULL)
    ssh_radius_client_request_destroy(req);

  radius_client->radius_req = NULL;
  radius_client->radius_handle = NULL;

  return FALSE;
}

Boolean
ssh_ppp_radius_make_chap_query(SshPppState gdata,
                               SshPppRadiusClient radius_client,
                               SshUInt8 algorithm,
                               SshUInt8 *user,
                               size_t user_length,
                               SshUInt8 challenge_id,
                               SshUInt8 *challenge,
                               size_t challenge_length,
                               SshUInt8 *response,
                               size_t response_length)
{
  SshRadiusClientRequest req;
  SshOperationHandle handle;
  SshRadiusAvpStatus avp_stat;
  Boolean res;
  SshUInt8 *tmpbuf;
  size_t reslen;

  SSH_PRECOND(user_length < 256);
  SSH_PRECOND(challenge_length < 256);
  SSH_PRECOND(response_length < 256);

  /* Previous requests must have been terminated before calling this */
  SSH_PRECOND(radius_client->radius_req == NULL);
  SSH_PRECOND(radius_client->radius_handle == NULL);

  /* User has changed config on us, let it slide. */
  if (gdata->radius_config == NULL)
    return FALSE;

  SSH_PRECOND(challenge_length > 0);

  req = ssh_radius_client_request_create(gdata->radius_config->client,
                                         SSH_RADIUS_ACCESS_REQUEST);

  /* Out of memory, please destroy this link! */

  if (req == NULL)
    goto fail;

  /* Add basic attributes */

  if (ssh_ppp_radius_add_avps(gdata, req) == FALSE)
    goto fail;

  res = 1;

  avp_stat =
    ssh_radius_client_request_add_attribute(req,
                                            SSH_RADIUS_AVP_USER_NAME,
                                            user, user_length);
  res &= ssh_ppp_radius_status_isok(avp_stat);

  switch (algorithm)
    {
    case SSH_PPP_CHAP_ALGORITHM_MD5:
      avp_stat =
        ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_CHAP_CHALLENGE,
                                                challenge, challenge_length);
      res &= ssh_ppp_radius_status_isok(avp_stat);

      tmpbuf = ssh_malloc(response_length + 1);
      if (tmpbuf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory. Cannot construct RADIUS request."));
          goto fail;
        }

      tmpbuf[0] = challenge_id;
      memcpy(tmpbuf+1, response, response_length);

      avp_stat =
        ssh_radius_client_request_add_attribute(req,
                                                SSH_RADIUS_AVP_CHAP_PASSWORD,
                                                tmpbuf, response_length+1);

      ssh_free(tmpbuf);

      res &= ssh_ppp_radius_status_isok(avp_stat);
      break;
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
    case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
      avp_stat =
        ssh_radius_client_request_add_vs_attribute(
                                         req,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP_CHALLENGE,
                                         challenge, challenge_length);
      res &= ssh_ppp_radius_status_isok(avp_stat);

      if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
        {
          reslen = SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH
            + SSH_PPP_MSCHAPV2_RESERVED_LENGTH
            + SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH;
        }
      else
        {
          reslen = SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH
            + SSH_PPP_MSCHAPV1_NTRESPONSE_LENGTH;
        }

      if (response_length < reslen)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("challenge/response lengths incorrect, can not construct "
                     "MS-CHAPv2-Response attribute"));
          goto fail;
        }


      tmpbuf = ssh_malloc(reslen + 2);
      if (tmpbuf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Out of memory. Cannot construct RADIUS request."));
          goto fail;
        }

      tmpbuf[0] = challenge_id;

      if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
        tmpbuf[1] = 0;
      else
        tmpbuf[1] = response[reslen];

      SSH_ASSERT(reslen < SSH_PPP_MSCHAPV2_RESPONSE_LENGTH);

      /* The fields are copied directly from the MS-CHAP* Response into
         the RADIUS AVP. */
      memcpy(tmpbuf+2,response,reslen);

      avp_stat =
        ssh_radius_client_request_add_vs_attribute(
                                req,
                                SSH_RADIUS_VENDOR_ID_MS,
                                (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2
                                 ?SSH_RADIUS_VENDOR_MS_CHAP2_RESPONSE
                                 :SSH_RADIUS_VENDOR_MS_CHAP_RESPONSE),
                                tmpbuf,reslen+2);
      ssh_free(tmpbuf);
      res &= ssh_ppp_radius_status_isok(avp_stat);
      break;
    default:
      res = 0;
      break;
    }

  if (res == 0)
    goto fail;

  if (gdata->radius_config->default_avps != NULL)
    {
      if (ssh_radius_url_add_avps(req, gdata->radius_config->default_avps)
          == FALSE)
        goto fail;
    }

  radius_client->radius_req = req;

  handle = ssh_radius_client_request(req,
                                     gdata->radius_config->servers,
                                     ssh_ppp_radius_cb,
                                     gdata);

  if (handle == NULL)
    {
      req = NULL;
      goto fail;
    }

  radius_client->radius_handle = handle;

  return TRUE;
 fail:
  if (req != NULL)
    ssh_radius_client_request_destroy(req);

  radius_client->radius_req = NULL;
  radius_client->radius_handle = NULL;

  return FALSE;

}

Boolean
ssh_ppp_radius_make_pap_query(SshPppState gdata,
                              SshPppRadiusClient radius_client,
                              SshUInt8 *user,
                              SshUInt8 user_length,
                              SshUInt8 *pw,
                              SshUInt8 pw_length)
{
  SshRadiusClientRequest req;
  SshOperationHandle handle;
  SshRadiusAvpStatus avp_stat;
  Boolean res;

  /* Previous requests must have been terminated before calling this */
  SSH_PRECOND(radius_client->radius_req == NULL);
  SSH_PRECOND(radius_client->radius_handle == NULL);

  /* User has changed config on us, let it slide. */
  if (gdata->radius_config == NULL)
    return FALSE;

  SSH_PRECOND(gdata->radius_config->client != NULL);

  req = ssh_radius_client_request_create(gdata->radius_config->client,
                                         SSH_RADIUS_ACCESS_REQUEST);

  /* Out of memory, please destroy this link! */

  if (req == NULL)
    goto fail;

  /* Add basic attributes */

  if (ssh_ppp_radius_add_avps(gdata, req) == FALSE)
    goto fail;

  res = 1;

  avp_stat =
    ssh_radius_client_request_add_attribute(req,
                                            SSH_RADIUS_AVP_USER_NAME,
                                            user, user_length);

  res &= ssh_ppp_radius_status_isok(avp_stat);

  avp_stat =
    ssh_radius_client_request_add_attribute(req,
                                            SSH_RADIUS_AVP_USER_PASSWORD,
                                            pw, pw_length);
  res &= ssh_ppp_radius_status_isok(avp_stat);

  if (res == 0)
    goto fail;


  if (gdata->radius_config->default_avps != NULL)
    {
      if (ssh_radius_url_add_avps(req, gdata->radius_config->default_avps)
          == FALSE)
        goto fail;
    }

  radius_client->radius_req = req;

  handle = ssh_radius_client_request(req,
                                     gdata->radius_config->servers,
                                     ssh_ppp_radius_cb,
                                     gdata);

  if (handle == NULL)
    {
      req = NULL;
      goto fail;
    }

  radius_client->radius_handle = handle;

  return TRUE;
 fail:
  SSH_DEBUG(SSH_D_FAIL,("Failed to construct RADIUS request"));

  if (req != NULL)
    ssh_radius_client_request_destroy(req);

  radius_client->radius_req = NULL;
  radius_client->radius_handle = NULL;


  return FALSE;
}

Boolean
ssh_ppp_radius_parse_nopayload_reply(SshPppState gdata,
                              SshPppAuthType auth_type,
                              SshRadiusClientRequestStatus status,
                              SshRadiusClientRequest request,
                              SshRadiusOperationCode reply_code)
{
  if (ssh_ppp_radius_check_reply(gdata,status,request,reply_code) == FALSE)
    return FALSE;

  if (ssh_ppp_radius_user_parse(gdata, auth_type,
                                status, request, reply_code) == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("User callback rejected RADIUS access accept"));
      return FALSE;
    }

  ssh_ppp_radius_use_reply(gdata,status,request,reply_code);

  return TRUE;
}

static Boolean
ssh_ppp_radius_handle_mschap_reject(SshPppState gdata,
                                    SshUInt8 algorithm,
                                    SshRadiusClientRequestStatus status,
                                    SshRadiusClientRequest request,
                                    SshRadiusOperationCode reply_code,
                                    unsigned char **param_buf_return,
                                    size_t *param_len_return)
{
  SshRadiusClientReplyEnumeratorStruct e;
  SshRadiusAvpStatus ret;
  SshRadiusVendorId vendor_id;
  SshRadiusAvpType type;
  unsigned char *ucp;
  size_t value_len;

  *param_buf_return = NULL;
  *param_len_return = 0;

  if (gdata->radius_config == NULL)
    goto fail;

  if (status == SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES)
    ssh_ppp_fatal(gdata);

  if (ssh_ppp_radius_reply_isok(gdata, status, request, reply_code) == 0)
    goto fail;

  ssh_radius_client_reply_enumerate_init(&e,request,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP_ERROR);

  ret = ssh_radius_client_reply_enumerate_next(&e,
                                               &vendor_id,
                                               &type,
                                               &ucp,
                                               &value_len);

  if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS
      && vendor_id == SSH_RADIUS_VENDOR_ID_MS
      && (SshRadiusVendorMsType)type == SSH_RADIUS_VENDOR_MS_CHAP_ERROR
      && value_len >= 1)
    {
      *param_buf_return = ssh_malloc(value_len);
      if (*param_buf_return == NULL)
        goto fail;

      memcpy(*param_buf_return,ucp,value_len);
      *param_len_return = value_len;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("Could not find MS-CHAP-Error attribute in "
               "RADIUS Access-Reject response"));
    }

  /* Always return FALSE to denote that auth failed */
 fail:
  return FALSE;
}

Boolean
ssh_ppp_radius_parse_chap_reply(SshPppState gdata,
                                SshUInt8 algorithm,
                                SshRadiusClientRequestStatus status,
                                SshRadiusClientRequest request,
                                SshRadiusOperationCode reply_code,
                                unsigned char **param_buf_return,
                                size_t *param_len_return)
{
  SshRadiusClientReplyEnumeratorStruct e;
  SshRadiusAvpStatus ret;
  unsigned char *ucp, *mschap2_authenticator;
  size_t value_len, mschap2_authenticator_len;
  SshRadiusVendorId vendor_id;
  SshRadiusAvpType type;

  SSH_ASSERT(param_buf_return != NULL);
  SSH_ASSERT(param_len_return != NULL);

  *param_buf_return = NULL;
  *param_len_return = 0;
  mschap2_authenticator = NULL;
  mschap2_authenticator_len = 0;

  if ((algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2
       || algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV1)
      && reply_code == SSH_RADIUS_ACCESS_REJECT)
    return ssh_ppp_radius_handle_mschap_reject(gdata,algorithm,
                                               status,request,reply_code,
                                               param_buf_return,
                                               param_len_return);

  if (ssh_ppp_radius_check_reply(gdata,status,request,reply_code) == FALSE)
    goto fail;

  if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      ssh_radius_client_reply_enumerate_init(
                                         &e,
                                         request,
                                         SSH_RADIUS_VENDOR_ID_MS,
                                         SSH_RADIUS_VENDOR_MS_CHAP2_SUCCESS);

      ret = ssh_radius_client_reply_enumerate_next(&e,
                                                   &vendor_id,
                                                   &type,
                                                   &ucp,
                                                   &value_len);

      if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS
          && vendor_id == SSH_RADIUS_VENDOR_ID_MS
          && (SshRadiusVendorMsType)type == SSH_RADIUS_VENDOR_MS_CHAP2_SUCCESS)
        {
          if (value_len != 43)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("unexpected vendor-length for MS-CHAP2 "
                         "Success subtype"));

              goto fail;
            }

          mschap2_authenticator = ucp;
          mschap2_authenticator_len = value_len;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("MS-CHAPv2 authenticator missing from RADIUS response"));
          goto fail;
        }
    }

  if (ssh_ppp_radius_user_parse(gdata, SSH_PPP_AUTH_CHAP,
                                status, request, reply_code) == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("User callback rejected RADIUS access accept"));
      goto fail;
    }

  if (algorithm == SSH_PPP_CHAP_ALGORITHM_MSCHAPV2)
    {
      *param_buf_return = ssh_malloc(mschap2_authenticator_len);

      if (*param_buf_return == NULL)
        goto fail;

      memcpy(*param_buf_return,
             mschap2_authenticator,
             mschap2_authenticator_len);

      *param_len_return = mschap2_authenticator_len;
    }

  ssh_ppp_radius_use_reply(gdata,status,request,reply_code);

  return TRUE;
 fail:
  return FALSE;
}

static Boolean
ssh_ppp_radius_check_reply(SshPppState gdata,
                           SshRadiusClientRequestStatus status,
                           SshRadiusClientRequest request,
                           SshRadiusOperationCode reply_code)
{
  SshRadiusAvpType type;
  SshRadiusVendorId vendor_id;
  size_t value_len;
  unsigned char *ucp;
  SshRadiusAvpStatus ret;
  SshRadiusFramedProtocolType framed_protocol;
  SshRadiusServiceType service_type;
  SshPppRadiusConfiguration radius_config;
  SshRadiusClientReplyEnumeratorStruct e;

  framed_protocol = SSH_RADIUS_FRAMED_PROTOCOL_NONE;
  service_type = SSH_RADIUS_SERVICE_TYPE_NONE;
  radius_config = gdata->radius_config;

  if (radius_config == NULL)
    goto fail;

  if (status == SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES)
    ssh_ppp_fatal(gdata);

  if (ssh_ppp_radius_reply_isok(gdata, status, request, reply_code) == 0)
    goto fail;

  /* Check if access accepts */

  switch (reply_code)
    {
    default:
    case SSH_RADIUS_ACCESS_REJECT:
    case SSH_RADIUS_ACCESS_CHALLENGE:
      goto fail;
    case SSH_RADIUS_ACCESS_ACCEPT:
      break;
    }

  /* Traverse list of AVP's and check that request seems ok. */

  ssh_radius_client_reply_enumerate_init(&e,request,
                                         SSH_RADIUS_VENDOR_ID_NONE, 0);


  do {
    ret=ssh_radius_client_reply_enumerate_next(&e,
                                               &vendor_id,
                                               &type,
                                               &ucp,
                                               &value_len);

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS &&
        vendor_id == SSH_RADIUS_VENDOR_ID_NONE)
      {
        switch (type)
          {
          case SSH_RADIUS_AVP_SERVICE_TYPE:
            if (value_len != 4)
              goto fail;

            service_type = SSH_GET_32BIT(ucp);
            break;

          case SSH_RADIUS_AVP_FRAMED_PROTOCOL:
            if (value_len != 4)
              goto fail;

            framed_protocol = SSH_GET_32BIT(ucp);
            break;

          case SSH_RADIUS_AVP_FRAMED_MTU:
          case SSH_RADIUS_AVP_FRAMED_IP_ADDRESS:
          case SSH_RADIUS_AVP_SESSION_TIMEOUT:
            if (value_len != 4)
              goto fail;
            break;

          default:
            break;
          }
      }
  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);

  /* Check that framed protocol is as required */

  if (gdata->radius_config->require_service_ppp == TRUE)
    {
      if (framed_protocol != SSH_RADIUS_FRAMED_PROTOCOL_PPP
          || service_type != SSH_RADIUS_SERVICE_TYPE_FRAMED)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Authentication failed because required service type "
                     "and framed protocol not present"));
          goto fail;
        }
    }

  return TRUE;
 fail:
  return FALSE;
}


static void
ssh_ppp_radius_use_reply(SshPppState gdata,
                         SshRadiusClientRequestStatus status,
                         SshRadiusClientRequest request,
                         SshRadiusOperationCode reply_code)
{
  SshRadiusAvpType type;
  SshRadiusVendorId vendor_id;
  size_t value_len;
  unsigned char *ucp;
  SshRadiusAvpStatus ret;
  SshUInt32 framed_ip, framed_mtu;
  Boolean ip_configured;
  SshPppRadiusConfiguration radius_config;
  SshRadiusClientReplyEnumeratorStruct e;

  ip_configured = FALSE;
  framed_ip = 0;
  framed_mtu = 0;
  radius_config = gdata->radius_config;

  SSH_ASSERT(radius_config != NULL);


  /* Traverse list of AVP's */

  ssh_radius_client_reply_enumerate_init(&e,request,
                                         SSH_RADIUS_VENDOR_ID_NONE,
                                         0);

  do {
    ret=ssh_radius_client_reply_enumerate_next(&e,
                                               &vendor_id,
                                               &type,
                                               &ucp,
                                               &value_len);

    if (ret == SSH_RADIUS_AVP_STATUS_SUCCESS
        && vendor_id == SSH_RADIUS_VENDOR_ID_NONE)
      {
        switch (type)
          {
          case SSH_RADIUS_AVP_SESSION_TIMEOUT:
            SSH_ASSERT(value_len == 4);
            /* If one wants to read the SESSION TIMEOUT value,
               it can be read like:
               session_timeout = SSH_GET_32BIT(ucp); */
            break;

          case SSH_RADIUS_AVP_FRAMED_IP_ADDRESS:
            SSH_ASSERT(value_len == 4);
            ip_configured = TRUE;
            framed_ip = SSH_GET_32BIT(ucp);

            break;

            /* If LCP does not negotiate MTU. Use this value. [RFC2865] */
          case SSH_RADIUS_AVP_FRAMED_MTU:
            SSH_ASSERT(value_len == 4);
            framed_mtu = SSH_GET_32BIT(ucp);
            break;

          default:
            break;
          }
      }
  } while (ret == SSH_RADIUS_AVP_STATUS_SUCCESS);

  /* Handle Framed-IP */
  if (gdata->radius_config->use_framed_ip_address == TRUE)
    {
      if (ip_configured == FALSE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("RADIUS did not provide Framed-IP-Address attribute, "
                     "using NAS configuration"));
          framed_ip = 0xFFFFFFFE;
        }
    }

  /* User chosen vars */

  if (gdata->radius_config->use_framed_ip_address == TRUE)
    ssh_ppp_radius_configure_framed_ipv4(gdata, framed_ip);

  if (gdata->radius_config->honor_radius_mtu == TRUE)
    {
      if (framed_mtu > 0)
        ssh_ppp_radius_configure_mtu(gdata, framed_mtu);
    }
}

/* Initialize RADIUS specific stuff */

void
ssh_ppp_radius_init(SshPppRadiusClient gdata)
{
  gdata->radius_handle = NULL;
  gdata->radius_req = NULL;
}

void
ssh_ppp_radius_uninit(SshPppRadiusClient gdata)
{
  if (gdata->radius_handle != NULL)
    {
      ssh_operation_abort(gdata->radius_handle);
      gdata->radius_handle = NULL;
    }

  if (gdata->radius_req != NULL)
    {
      ssh_radius_client_request_destroy(gdata->radius_req);
      gdata->radius_req = NULL;
    }
}

/* Configure RADIUS specific parts of RADIUS support */

void
ssh_ppp_radius_reset_radius(SshPppRadiusClient gdata)
{
  ssh_ppp_radius_uninit(gdata);
}

#endif /* SSHDIST_RADIUS */
