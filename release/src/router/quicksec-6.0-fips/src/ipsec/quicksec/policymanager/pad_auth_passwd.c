/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements:
     IKEv1 Extented Authentication using Local Database (server)
     IKEv1 Extented Authentication using Radius (server)
     IKEv2 Peer Authentication using Local Database (client, server)
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "pad_auth_passwd.h"
#include "sshfsm.h"

/*--------------------------------------------------------------------*/
/* Types and definitions                                              */
/*--------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshPmAuth"


/* A password list entry. */
struct SshPmAuthPasswdEntryRec
{
  struct SshPmAuthPasswdEntryRec *next;
  unsigned char *user_name;
  size_t user_name_len;
  unsigned char *password;
  size_t password_len;
};

typedef struct SshPmAuthPasswdEntryRec SshPmAuthPasswdEntryStruct;
typedef struct SshPmAuthPasswdEntryRec *SshPmAuthPasswdEntry;

/* A password list object. */
struct SshPmAuthPasswdRec
{
#ifdef SSHDIST_RADIUS
  SshRadiusClient client;
  SshRadiusClientServerInfo servers;
#endif /* SSHDIST_RADIUS */

  /* List of user-name password pairs. */
  SshPmAuthPasswdEntry entries;

  /* SSH FSM instance. */
  SshFSMStruct fsm[1];

  /* Hash function for RADIUS-CHAP authentication. */
  SshHash md5_hash;
  size_t md5_digest_len;
};

#ifdef SSHDIST_IKE_XAUTH
/* An extended authentication operation (local or radius). */
struct SshPmXauthOperationRec
{
  SshPm pm; /* Policy manager pointer */

  SshSADHandle sad_handle;
  SshPmAuthPasswd module;

  /* Initiated exchange */
  SshIkev2ExchangeData ed;

  /* Proxy IKE SA to receive extra authentication. */
  SshIkev2Sa sa;

  /* Flags. */
#ifdef SSHDIST_RADIUS
  unsigned int radius : 1;      /* Use Radius */
#endif /* SSHDIST_RADIUS */
  unsigned int use_chap : 1;    /* Use RADIUS-CHAP. */

  /* Callbacks. */
  SshIkev2FbXauthRequest request;
  SshIkev2FbXauthSet set;
  SshIkev2FbXauthDone done;

  SshIkev2FbXauthStatus status;
  void *callback_context;

  /* Ike library provided context */
  void *context;

  /* The last challenge.  This is valid if `use_chap' is set. */
  unsigned char challenge[16];

  /* A response from our XAUTH peer. */
  struct
  {
    unsigned char *user_name;
    size_t user_name_len;

    unsigned char *user_password;
    size_t user_password_len;
  } response;

#ifdef SSHDIST_RADIUS
  Boolean addresses_sent;

  SshPmXauthFlags flags;

  /* Information about our peer. */
  SshUInt32 port_number;

  /* A pending RADIUS client request. */
  SshRadiusClientRequest radius_request;
  SshOperationHandle radius_request_handle;

  /* A response from the RADIUS server. */
  struct
  {
    SshRadiusClientRequestStatus status;
    SshRadiusOperationCode code;

    unsigned char *reply_message;
    size_t reply_message_len;

    unsigned char *state;
    size_t state_len;

    SshUInt32 session_timeout;
    SshUInt32 idle_timeout;

    /* Configuration mode attributes. */

    /* IP address and netmask. */
    SshIpAddrStruct internal_address;

    /* Additional sub-networks. */
    SshUInt32 num_subnets;
    SshIpAddr subnets;
  } radius_response;
#endif /* SSHDIST_RADIUS */

  /* Configuration attributes to be sent at xauth-set (or at server
     initiated configuration mode set). */
  SshIkev2PayloadConf conf;

  /* The final status of the operation. */
  Boolean success;

  /* FSM thread handling this authentication. */
  SshFSMThreadStruct thread[1];

  /* Client side */
  SshIkev2FbXauthAttributes attributes;

  SshOperationHandleStruct operation[1];

  SshUInt32 try_number;
};
typedef struct SshPmXauthOperationRec  SshPmXauthOperationStruct;
typedef struct SshPmXauthOperationRec *SshPmXauthOperation;
#endif /* SSHDIST_IKE_XAUTH */

#define SSH_PM_DUP(rval, rlen, lval, llen)                 \
do                                                         \
  {                                                        \
    if ((rval))                                            \
      {                                                    \
        if ((lval)) ssh_free((lval));                      \
        if (((lval) = ssh_memdup((rval), (rlen))) == NULL) \
          goto error;                                      \
        (llen) = (rlen);                                   \
      }                                                    \
  }                                                        \
while (0)

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IKE_XAUTH
SSH_FSM_STEP(ssh_pm_st_xauth_start);
SSH_FSM_STEP(ssh_pm_st_xauth_passwd);
SSH_FSM_STEP(ssh_pm_st_xauth_send_radius_request);
SSH_FSM_STEP(ssh_pm_st_xauth_authorization);
SSH_FSM_STEP(ssh_pm_st_xauth_collect_attributes);
SSH_FSM_STEP(ssh_pm_st_xauth_do_set);
SSH_FSM_STEP(ssh_pm_st_xauth_error);
SSH_FSM_STEP(ssh_pm_st_xauth_finish);

static void
pm_xauth_request_cb(SshIkev2Error status,
                    SshIkev2FbXauthAttributes attributes,
                    void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmXauthOperation xauth = (SshPmXauthOperation) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Xauth peer responded our request %p status %d",
             xauth, status));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);

  /* Clear possible old reply fields. */
  ssh_free(xauth->response.user_name);
  ssh_free(xauth->response.user_password);
  memset(&xauth->response, 0, sizeof(xauth->response));

  if (status != SSH_IKEV2_ERROR_OK)
    goto error;

  /* Check if the XAUTH status was set to FAIL. */
  if (attributes->status_set && attributes->status == 0)
    goto status_fail;

  /* Save attributes. */

  SSH_PM_DUP(attributes->user_name,
             attributes->user_name_len,
             xauth->response.user_name,
             xauth->response.user_name_len);

#ifdef SSHDIST_RADIUS
  if (xauth->radius)
    {









      switch (xauth->flags)
        {
        case SSH_PM_XAUTH_GENERIC_USER_NAME_PASSWORD:
          SSH_PM_DUP(attributes->user_password,
                     attributes->user_password_len,
                     xauth->response.user_password,
                     xauth->response.user_password_len);
          break;

        case SSH_PM_XAUTH_GENERIC_SECURID:
          SSH_PM_DUP(attributes->passcode,
                     attributes->passcode_len,
                     xauth->response.user_password,
                     xauth->response.user_password_len);
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_send_radius_request);
    }
  else
#endif /* SSHDIST_RADIUS */
    {
      SSH_PM_DUP(attributes->user_password,
                 attributes->user_password_len,
                 xauth->response.user_password,
                 xauth->response.user_password_len);

      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_passwd);
    }
  return;

 error:
  /* The IKE operation failed.  This means that we (probably) won't
     get the SET/ACK exchange through and we can simply end this XAUTH
     operation.  So, let's finish. */

 status_fail:
  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_finish);
}

SSH_FSM_STEP(ssh_pm_st_xauth_start)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  SshIkev2FbXauthAttributesStruct attributes;
  size_t i;
  SshPmP1 p1 = (SshPmP1)xauth->sa;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Xauth starting for %p - sending a request", xauth));

  if (p1->unusable)
    {
      xauth->success = FALSE;
      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_finish);
      return SSH_FSM_CONTINUE;
    }

  memset(&attributes, 0, sizeof(attributes));

  /* Standard fields. */
  attributes.user_name = (unsigned char *) "";
  /* attributes.user_password = (unsigned char *) ""; */

  /* Fields for the RADIUS-CHAP authentication. */
  if (xauth->use_chap)
    {
      attributes.type = SSH_IKE_XAUTH_TYPE_RADIUS_CHAP;
      attributes.type_set = TRUE;

      /* Create a random challenge. */
      for (i = 0; i < sizeof(xauth->challenge); i++)
        xauth->challenge[i] = ssh_random_get_byte();

      attributes.challenge = xauth->challenge;
      attributes.challenge_len = sizeof(xauth->challenge);
    }

#ifdef SSHDIST_RADIUS
  if (xauth->radius)
    {
      switch (xauth->flags)
        {
        case SSH_PM_XAUTH_GENERIC_USER_NAME_PASSWORD:
          attributes.user_password = (unsigned char *) "";
          break;

        case SSH_PM_XAUTH_GENERIC_SECURID:
          attributes.passcode = (unsigned char *)"";
          break;

        default:
          SSH_NOTREACHED;
          break;
        }
    }
  else
#endif /* SSHDIST_RADIUS */
    {
      attributes.type = SSH_IKE_XAUTH_TYPE_GENERIC;
      attributes.user_password = (unsigned char *) "";
    }

  SSH_FSM_ASYNC_CALL({
    (*xauth->request)(xauth->sa,
                      &attributes,
                      pm_xauth_request_cb,
                      thread,
                      xauth->context);
  });
}


#define SSH_PM_AVP_TEXT(lvalue) \
  SSH_PM_DUP(value, value_len, lvalue, lvalue ## _len)

#define SSH_PM_AVP_INT(lvalue)                            \
 do                                                       \
  {                                                       \
    if (value_len == 4) lvalue = SSH_GET_32BIT(value);    \
    else lvalue = 0;                                      \
  }                                                       \
while (0)

#ifdef SSHDIST_RADIUS
static void
pm_xauth_radius_request_cb(SshRadiusClientRequestStatus status,
                           SshRadiusClientRequest request,
                           SshRadiusOperationCode reply_code,
                           void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmXauthOperation xauth = (SshPmXauthOperation) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Xauth radius request completed for %p status %d",
             xauth, status));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);

  xauth->radius_request_handle = NULL;

  /* Clear possible old reply fields. */
  ssh_free(xauth->radius_response.reply_message);
  ssh_free(xauth->radius_response.state);
  memset(&xauth->radius_response, 0, sizeof(xauth->radius_response));

  xauth->radius_response.status = status;
  xauth->success = FALSE;

  if (status == SSH_RADIUS_CLIENT_REQ_SUCCESS)
    {
      SshRadiusClientReplyEnumeratorStruct e;
      SshRadiusAvpType type;
      unsigned char *value;
      size_t value_len;
      SshUInt32 i, j;
      unsigned char buf[64];

      xauth->radius_response.code = reply_code;
      if (reply_code == SSH_RADIUS_ACCESS_ACCEPT)
        xauth->success = TRUE;

      /* Pick all interesting attributes. */
      ssh_radius_client_reply_enumerate_init(&e,request,
                                             SSH_RADIUS_VENDOR_ID_NONE,
                                             0);
      while (ssh_radius_client_reply_enumerate_next(&e, NULL, &type,
                                                    &value, &value_len)
             == SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          switch (type)
            {
              /* Possible return values from the RFC 2865 are: */
              /* Accept   Reject   Challenge   Attribute                */
              /* 0-1      0        0           User-Name                */
              /* 0-1      0        0           Service-Type             */
              /* 0-1      0        0           Framed-Protocol          */
              /* 0-1      0        0           Framed-IP-Address        */
            case SSH_RADIUS_AVP_FRAMED_IP_ADDRESS:
              /* Special cases 0xffffffff and 0xffffffe are handled
                 after all AVPs have been parsed. */
              if (value_len == 4)
                SSH_IP4_DECODE(&xauth->radius_response.internal_address,
                               value);
              break;
              /* 0-1      0        0           Framed-IP-Netmask        */
            case SSH_RADIUS_AVP_FRAMED_IP_NETMASK:
              if (value_len == 4)
                {
                  i = SSH_GET_32BIT(value);

                  for (j = 1; j <= 32; j++)
                    if ((i & (1 << (32 - j))) == 0)
                      break;

                  SSH_IP_MASK_LEN(&xauth->radius_response.internal_address)
                    = j - 1;
                }
              break;
              /* 0-1      0        0           Framed-Routing           */
              /* 0+       0        0           Filter-Id                */
              /* 0-1      0        0           Framed-MTU               */
              /* 0+       0        0           Framed-Compression       */
              /* 0+       0        0           Login-IP-Host            */
              /* 0-1      0        0           Login-Service            */
              /* 0-1      0        0           Login-TCP-Port           */
              /* 0+       0+       0+          Reply-Message            */
            case SSH_RADIUS_AVP_REPLY_MESSAGE:
              SSH_PM_AVP_TEXT(xauth->radius_response.reply_message);
              break;
              /* 0-1      0        0           Callback-Number          */
              /* 0-1      0        0           Callback-Id              */
              /* 0+       0        0           Framed-Route             */
            case SSH_RADIUS_AVP_FRAMED_ROUTE:
              /* Additional sub-networks for client.  The value SHOULD
                 (RFC 2865) be in format:

                   ADDR[/MASKLEN] GW[ METRIC]...

                 We are only interested in the first space-separated
                 part. */

              /* Lookup the first separator. */
              for (i = 0; i < value_len && value[i] != ' '; i++)
                ;
              if (i < value_len && i < sizeof(buf) - 1)
                {
                  SshIpAddrStruct ip;
                  SshIpAddr tmp;

                  /* Found it and it is short enough to contain a
                     valid IP address and optional mask length. */
                  memcpy(buf, value, i);
                  buf[i] = '\0';

                  if (ssh_ipaddr_parse_with_mask(&ip, buf, NULL))
                    {
                      /* Got it and we have the prefix length too. */
                    }
                  else if (ssh_ipaddr_parse(&ip, buf))
                    {
                      /* Got it without the prefix length.  Resolve
                         the prefix length from the address class. */
                      if (!SSH_IP_IS4(&ip))
                        {
                          SSH_DEBUG(SSH_D_FAIL,
                                    ("Got a non-IPv4 address from "
                                     "Framed-Route"));
                          continue;
                        }

                      i = SSH_IP4_TO_INT(&ip);

                      if (i <= 0x7fffffff)
                        j = 8;
                      else if (i <= 0xbfffffff)
                        j = 16;
                      else if (i <= 0xdfffffff)
                        j = 24;
                      else
                        {
                          SSH_DEBUG(SSH_D_FAIL,
                                    ("Invalid Class-D or Class-E IP address "
                                     "in Framed-Route"));
                          continue;
                        }
                      SSH_IP_MASK_LEN(&ip) = j;
                    }
                  else
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Invalid IP address `%s' in Framed-Route",
                                 buf));
                      continue;
                    }

                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Framed-Route: adding network %@",
                             ssh_ipaddr_render, &ip));

                  tmp = ssh_realloc(xauth->radius_response.subnets,
                                    (xauth->radius_response.num_subnets
                                     * sizeof(SshIpAddrStruct)),
                                    ((xauth->radius_response.num_subnets + 1)
                                     * sizeof(SshIpAddrStruct)));
                  if (tmp == NULL)
                    {
                      SSH_DEBUG(SSH_D_ERROR,
                                ("Could not allocate memory for additional "
                                 "sub-network"));
                    }
                  else
                    {
                      tmp[xauth->radius_response.num_subnets++] = ip;
                      xauth->radius_response.subnets = tmp;
                    }
                }
              break;
              /* 0-1      0        0           Framed-IPX-Network       */
              /* 0-1      0        0-1         State [Note 1]           */
            case SSH_RADIUS_AVP_STATE:
              SSH_PM_AVP_TEXT(xauth->radius_response.state);
              break;
              /* 0+       0        0           Class                    */
              /* 0+       0        0+          Vendor-Specific          */
              /* 0-1      0        0-1         Session-Timeout          */
            case SSH_RADIUS_AVP_SESSION_TIMEOUT:
              SSH_PM_AVP_INT(xauth->radius_response.session_timeout);
              break;
              /* 0-1      0        0-1         Idle-Timeout             */
            case SSH_RADIUS_AVP_IDLE_TIMEOUT:
              SSH_PM_AVP_INT(xauth->radius_response.idle_timeout);
              break;
              /* 0-1      0        0           Termination-Action       */
              /* 0+       0+       0+          Proxy-State              */
              /* 0-1      0        0           Login-LAT-Service        */
              /* 0-1      0        0           Login-LAT-Node           */
              /* 0-1      0        0           Login-LAT-Group          */
              /* 0-1      0        0           Framed-AppleTalk-Link    */
              /* 0+       0        0           Framed-AppleTalk-Network */
              /* 0-1      0        0           Framed-AppleTalk-Zone    */
              /* 0-1      0        0           Port-Limit               */
              /* 0-1      0        0           Login-LAT-Port           */
              /* Accept   Reject   Challenge   Attribute                */

            default:
#ifdef DEBUG_LIGHT
              {
                const SshRadiusAvpInfoStruct *info = ssh_radius_avp_info(type);

                if (info)
                  SSH_DEBUG(SSH_D_LOWOK, ("Skipping AVP %s(%d): length=%d",
                                          info->name, type, value_len));
                else
                  SSH_DEBUG(SSH_D_LOWOK, ("Skipping AVP %d", type));
              }
#endif /* DEBUG_LIGHT */
              break;
            }
        }

      /* Handle special 0xffffffff and 0xfffffffe addresses. */
      if (SSH_IP_DEFINED(&xauth->radius_response.internal_address))
        {
          SshUInt32 ip_int;

          SSH_ASSERT(SSH_IP_IS4(&xauth->radius_response.internal_address));
          ip_int = SSH_IP4_TO_INT(&xauth->radius_response.internal_address);

          if (ip_int == 0xffffffff || ip_int == 0xfffffffe)
            {
              /* Undefine the internal IP and let the policy manager
                 to pick a suitable address from its address pool. */
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Letting policy manager to pick an internal "
                         "IP address because of the RADIUS response %@",
                         ssh_ipaddr_render,
                         &xauth->radius_response.internal_address));
              SSH_IP_UNDEFINE(&xauth->radius_response.internal_address);
            }
        }
    }
  return;

 error:
  xauth->success = FALSE;
  return;
}


SSH_FSM_STEP(ssh_pm_st_xauth_send_radius_request)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  SshRadiusAvpStatus status;
  SshRadiusAvpType type;
  unsigned char buf[64];
  SshPmP1 p1 = (SshPmP1)xauth->ed->ike_sa;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth sending radius request for %p", xauth));

  SSH_ASSERT(xauth->radius);

  /* Create RADIUS request. */
  if ((xauth->radius_request
       = ssh_radius_client_request_create(p1->auth_domain->passwd_auth->client,
                                          SSH_RADIUS_ACCESS_REQUEST))
      == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create RADIUS client request"));
      goto error;
    }

  /* Add attributes. */

  if ((status =
       ssh_radius_client_request_add_attribute(xauth->radius_request,
                                               SSH_RADIUS_AVP_USER_NAME,
                                               xauth->response.user_name,
                                               xauth->response
                                               .user_name_len))
      != SSH_RADIUS_AVP_STATUS_SUCCESS)
    goto avp_error;

  if (xauth->use_chap)
    type = SSH_RADIUS_AVP_CHAP_PASSWORD;
  else
    type = SSH_RADIUS_AVP_USER_PASSWORD;

  if ((status =
       ssh_radius_client_request_add_attribute(xauth->radius_request,
                                               type,
                                               xauth->response.
                                               user_password,
                                               xauth->response
                                               .user_password_len))
      != SSH_RADIUS_AVP_STATUS_SUCCESS)
    goto avp_error;

  SSH_PUT_32BIT(buf, xauth->port_number);
  if ((status =
       ssh_radius_client_request_add_attribute(xauth->radius_request,
                                               SSH_RADIUS_AVP_NAS_PORT,
                                               buf, 4))
      != SSH_RADIUS_AVP_STATUS_SUCCESS)
    goto avp_error;

  SSH_PUT_32BIT(buf, SSH_RADIUS_NAS_PORT_TYPE_ETHERNET);
  if ((status =
       ssh_radius_client_request_add_attribute(xauth->radius_request,
                                               SSH_RADIUS_AVP_NAS_PORT_TYPE,
                                               buf, 4))
      != SSH_RADIUS_AVP_STATUS_SUCCESS)
    goto avp_error;

  if (xauth->use_chap)
    {
      if ((status =
           ssh_radius_client_request_add_attribute(xauth->radius_request,
                                                SSH_RADIUS_AVP_CHAP_CHALLENGE,
                                                   xauth->challenge, 16))
          != SSH_RADIUS_AVP_STATUS_SUCCESS)
        goto avp_error;
    }

  /* Send request to the RADIUS server. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending request to RADIUS servers"));

  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_authorization);
  SSH_FSM_ASYNC_CALL({
    xauth->radius_request_handle =
      ssh_radius_client_request(xauth->radius_request,
                                p1->auth_domain->passwd_auth->servers,
                                pm_xauth_radius_request_cb,
                                thread);
  });

  SSH_NOTREACHED;


  /* Error handling. */

 avp_error:

  SSH_DEBUG(SSH_D_ERROR,
            ("Could not add AVP to RADIUS request: %s",
             ssh_find_keyword_name(ssh_radius_avp_status_codes, status)));

 error:

  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_error);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_RADIUS */


static void
pm_xauth_authorization_cb(SshUInt32 *group_ids,
                          SshUInt32 num_group_ids,
                          void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmXauthOperation xauth = (SshPmXauthOperation) ssh_fsm_get_tdata(thread);
  SshPm pm = xauth->pm;
  SshPmP1 p1 = (SshPmP1)xauth->sa;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth authorization done for %p; %d groups",
                          xauth, (unsigned int) num_group_ids));

  if (num_group_ids > 0)
    {
      SshUInt32 *tmp;

      if ((tmp =
           ssh_memdup(group_ids, sizeof(group_ids[0]) * num_group_ids))
          != NULL)
        {
          ssh_free(p1->xauth_authorization_group_ids);
          p1->xauth_authorization_group_ids =  tmp;
          p1->num_xauth_authorization_group_ids = num_group_ids;
        }

      /* The IKE SA is updated. */
      ssh_pm_ike_sa_event_updated(pm, p1);
    }

  /* Complete the pending FSM operation. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_xauth_authorization)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  SshPm pm = xauth->pm;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth performing authorization for %p", xauth));

  if (xauth->success)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_collect_attributes);
#ifdef SSHDIST_RADIUS
      if (xauth->radius)
        {
          SSH_FSM_ASYNC_CALL({
            ssh_pm_authorization_xauth(pm,
                                       (SshPmP1)xauth->sa,
                                       SSH_PM_XAUTH_RADIUS,
                                       xauth->radius_request,
                                       pm_xauth_authorization_cb,
                                       thread);
          });
        }
      else
#endif /* SSHDIST_RADIUS */
        {
          SSH_FSM_ASYNC_CALL({
            ssh_pm_authorization_xauth(pm,
                                       (SshPmP1)xauth->sa,
                                       SSH_PM_XAUTH_PASSWORD,
                                       NULL,
                                       pm_xauth_authorization_cb,
                                       thread);
          });
        }
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_error);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_xauth_passwd)
{
  SshPmAuthPasswd auth = (SshPmAuthPasswd) fsm_context;
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  SshPmAuthPasswdEntry entry;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth looking for local password %p", xauth));

  xauth->success = FALSE;

  /* Check response. */
  for (entry = auth->entries; entry; entry = entry->next)
    if (xauth->response.user_name_len == entry->user_name_len
        && memcmp(xauth->response.user_name, entry->user_name,
                  xauth->response.user_name_len) == 0)
      {
        SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                          ("Matching password%s for username:",
                           xauth->use_chap ? " with chap" : ""),
                          entry->user_name, entry->user_name_len);

        if (xauth->use_chap)
          {
            if (xauth->response.user_password_len == auth->md5_digest_len + 1)
              {
                ssh_hash_reset(auth->md5_hash);
                ssh_hash_update(auth->md5_hash,
                                xauth->response.user_password, 1);
                ssh_hash_update(auth->md5_hash,
                                ssh_custr(entry->password),
                                entry->password_len);
                ssh_hash_update(auth->md5_hash,
                                xauth->challenge,
                                sizeof(xauth->challenge));
                if (ssh_hash_final(auth->md5_hash, digest) == SSH_CRYPTO_OK)
                  {
                    if (memcmp(xauth->response.user_password + 1,
                               digest,
                               auth->md5_digest_len) == 0)
                      xauth->success = TRUE;
                  }
              }
          }
        else
          {
            if (xauth->response.user_password_len == entry->password_len
                && memcmp(xauth->response.user_password, entry->password,
                          xauth->response.user_password_len) == 0)
              xauth->success = TRUE;
          }
        break;
      }

#ifdef DEBUG_LIGHT
  if (xauth->success)
    SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                      ("Xauth (%p) found local password for:", xauth),
                      entry->password, entry->password_len);
  else if (xauth->response.user_name_len == 0)
    SSH_DEBUG(SSH_D_MIDOK,
              ("Xauth (%p)did not find local password, no username given.",
               xauth));
  else
    SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                      ("Xauth (%p) did not find password for given username:",
                       xauth),
                      xauth->response.user_name,
                      xauth->response.user_name_len);
#endif /* DEBUG_LIGHT */

  if (!xauth->success)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_do_set);
      return SSH_FSM_CONTINUE;
    }

  /* Perform authorization based on the result. When authorization is
     done, sent SET(OK) to the peer (we do say YES even if this
     authorization does not allow access to any resources). The access
     control is performed later when selecting the child SA policy. */
  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_authorization);
  return SSH_FSM_CONTINUE;
}

static void
pm_xauth_set_cb(SshIkev2Error error,
                SshIkev2FbXauthAttributes attributes,
                void *context)
{
  SshFSMThread thread = context;
  SshPmXauthOperation xauth = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Xauth peer responded our set %p status %d",
             xauth, error));

  if (xauth->success == TRUE)
    xauth->success = (error == SSH_IKEV2_ERROR_OK);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_finish);

#ifdef SSHDIST_RADIUS
  if (!xauth->addresses_sent
      && xauth->radius_response.code == SSH_RADIUS_ACCESS_ACCEPT
      && SSH_IP_DEFINED(&xauth->radius_response.internal_address))
    {
      xauth->addresses_sent = TRUE;
      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_do_set);
    }
#endif /* SSHDIST_RADIUS */
}

static void pm_cfg_attributes_cb(SshIkev2Error status,
                                 SshIkev2PayloadConf conf_payload,
                                 void *context)
{
  SshFSMThread thread = context;
  SshPmXauthOperation xauth = ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Xauth collected cfgmode attributes for %p status %d",
             xauth, status));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  xauth->conf = conf_payload;
}

SSH_FSM_STEP(ssh_pm_st_xauth_collect_attributes)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_do_set);
  xauth->success = TRUE;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth collecting cfgmode attributes for %p",
                          xauth));

  if (xauth->conf)
    {
      return SSH_FSM_CONTINUE;
    }

  /* Collect remote access attributes using the configuration request
     processing mechanisms */
  SSH_FSM_ASYNC_CALL({
    ssh_pm_ike_conf_request(xauth->sad_handle,
                            xauth->ed,
                            pm_cfg_attributes_cb,
                            thread);
  });
  SSH_NOTREACHED;
}

static Boolean
pm_cfg_attributes_convert_from_conf(SshIkev2PayloadConf conf,
                                    SshIkev2FbXauthAttributes attributes)
{
  SshIkev2ConfAttribute ca;
  int nsubnets = 0, i;

  for (i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      ca = &conf->conf_attributes[i];
      if (ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET
          ||
          ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET)
        nsubnets++;
    }
  if (nsubnets
      && ((attributes->subnets =
           ssh_calloc(nsubnets, sizeof(attributes->subnets[0]))) == NULL))
    return FALSE;

  attributes->num_subnets = nsubnets;

  for (i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      ca = &conf->conf_attributes[i];
      if (ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_ADDRESS
          ||
          ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_ADDRESS)
        SSH_IP_DECODE(&attributes->address, ca->value, ca->length);

      if (ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP4_SUBNET
          ||
          ca->attribute_type == SSH_IKEV2_CFG_ATTRIBUTE_INTERNAL_IP6_SUBNET)
        SSH_IP_DECODE(&attributes->subnets[--nsubnets],
                      ca->value, ca->length);
    }
  return TRUE;
}

SSH_FSM_STEP(ssh_pm_st_xauth_do_set)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  unsigned char *message = NULL;
  size_t message_len = 0;
  SshIkev2FbXauthAttributesStruct attributes;
  SshIkev2FbXauthAttributesStruct *attributesp = NULL;
  SshPmP1 p1 = (SshPmP1)xauth->sa;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth continuing for %p - sending set %d",
                          xauth, xauth->success));

  if (p1->unusable)
    {
      xauth->success = FALSE;
      if (xauth->conf)
        {
          ssh_ikev2_conf_free(xauth->sad_handle, xauth->conf);
          xauth->conf = NULL;
        }
      SSH_FSM_SET_NEXT(ssh_pm_st_xauth_finish);
      return SSH_FSM_CONTINUE;
    }

  if (p1->ike_sa->xauth_enabled && xauth->success == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Xauth negotiation has failed"));

      SSH_FSM_ASYNC_CALL({
        (*xauth->set)(xauth->sa,
                      FALSE,
                      NULL, 0,
                      NULL,
                      pm_xauth_set_cb, thread,
                      xauth->context);
        if (xauth->conf)
          {
            if (attributesp)
              ssh_free(attributesp->subnets);
            ssh_ikev2_conf_free(xauth->sad_handle, xauth->conf);
            xauth->conf = NULL;
          }
      });
      SSH_NOTREACHED;
    }


  memset(&attributes, 0, sizeof(attributes));

  if (xauth->conf)
    {







      if (pm_cfg_attributes_convert_from_conf(xauth->conf, &attributes))
        {
          /* CFG mode without XAUTH, set the success value to TRUE */
          xauth->success = TRUE;
          attributesp = &attributes;
        }
    }
#ifdef SSHDIST_RADIUS
  else if (xauth->radius)
    {
      message = xauth->radius_response.reply_message;
      message_len = xauth->radius_response.reply_message_len;

      if (xauth->radius_response.code == SSH_RADIUS_ACCESS_ACCEPT)
        {
          /* Do we have dynamic config mode attributes? */
          if (SSH_IP_DEFINED(&xauth->radius_response.internal_address))
            {
              /* Internal IP adress. */
              attributes.address = xauth->radius_response.internal_address;

              /* Additional sub-networks. */
              attributes.subnets = xauth->radius_response.subnets;
              attributes.num_subnets = xauth->radius_response.num_subnets;

              /* CFG mode without XAUTH, set the success value to TRUE */
              xauth->success = TRUE;
              attributesp = &attributes;
            }

        }
    }
#endif /* SSHDIST_RADIUS */

  SSH_FSM_ASYNC_CALL({
    (*xauth->set)(xauth->sa,
                  xauth->success,
                  message, message_len,
                  attributesp,
                  pm_xauth_set_cb, thread,
                  xauth->context);


    if (xauth->conf)
      {
        if (attributesp)
          ssh_free(attributesp->subnets);
        ssh_ikev2_conf_free(xauth->sad_handle, xauth->conf);
        xauth->conf = NULL;
      }
  });
}


SSH_FSM_STEP(ssh_pm_st_xauth_error)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth %p in error", xauth));

#ifdef SSHDIST_RADIUS
  if (xauth->radius)
    {
      xauth->radius_response.code = SSH_RADIUS_ACCESS_REJECT;

      ssh_free(xauth->radius_response.reply_message);
      ssh_free(xauth->radius_response.state);
      ssh_free(xauth->radius_response.subnets);
      memset(&xauth->radius_response, 0, sizeof(xauth->radius_response));
    }
#endif /* SSHDIST_RADIUS */

  xauth->success = FALSE;
  SSH_FSM_SET_NEXT(ssh_pm_st_xauth_do_set);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_xauth_finish)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation) thread_context;
  SshPmP1 p1 = (SshPmP1)xauth->sa;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth %p terminating success=%d", xauth,
                          xauth->success));

  if (p1->ike_sa->xauth_started)
    p1->ike_sa->xauth_done = 1;
  p1->failed = xauth->success ? 0 : 1;

  /* Calling 'done' will eventually cause the informational exchange
     to complete, and the QM thread to continue. */
  (*xauth->done)(xauth->context);

  return SSH_FSM_FINISH;
}

void pm_xauth_thread_destructor(SshFSM fsm, void *context)
{
  SshPmXauthOperation xauth = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth thread destroyed %p", xauth));

  if (xauth->attributes)
    {
      ssh_free(xauth->attributes->user_name);
      ssh_free(xauth->attributes->user_password);
      ssh_free(xauth->attributes->passcode);
      ssh_free(xauth->attributes->message);
      ssh_free(xauth->attributes->challenge);
      ssh_free(xauth->attributes->domain);
      ssh_free(xauth->attributes->next_pin);
      ssh_free(xauth->attributes->answer);

      if (xauth->attributes->num_subnets)
        ssh_free(xauth->attributes->subnets);

      ssh_free(xauth->attributes);
    }

#ifdef SSHDIST_RADIUS
  if (xauth->radius_request)
    ssh_radius_client_request_destroy(xauth->radius_request);
#endif /* SSHDIST_RADIUS */

  ssh_free(xauth->response.user_name);
  ssh_free(xauth->response.user_password);

#ifdef SSHDIST_RADIUS
  ssh_free(xauth->radius_response.reply_message);
  ssh_free(xauth->radius_response.state);
#endif /* SSHDIST_RADIUS */

#ifdef DEBUG_LIGHT
  /* Mark as freed */
  memset(xauth, 'F', sizeof(*xauth));
#endif /* DEBUG_LIGHT */
  ssh_free(xauth);
}

static void pm_xauth_abort(void *context)
{
  SshPmXauthOperation xauth = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth aborted %p", xauth));

#ifdef SSHDIST_RADIUS
  if (xauth->radius_request_handle)
    ssh_operation_abort(xauth->radius_request_handle);
#endif /* SSHDIST_RADIUS */

  ssh_fsm_kill_thread(xauth->thread);
}

/* This function services the IKEv2 library with IKEv1 fallback
   related Extented authentication requests and server side CfgMode
   set/ack exchanges for address assignments (for SoftRemote
   compatibility). */
SshOperationHandle
ssh_pm_xauth(SshSADHandle sad_handle,
             SshIkev2ExchangeData ed,
             SshIkev2FbXauthRequest request,
             SshIkev2FbXauthSet set,
             SshIkev2FbXauthDone done,
             void *callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmAuthPasswd module = NULL;
  SshPmXauthOperation xauth;
  SshFSMStepCB start;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*done)(callback_context);
      return NULL;
    }

  if (!SSH_PM_P1_READY(p1))
    {
      (*done)(callback_context);
      return NULL;
    }

  module = p1->auth_domain->passwd_auth;

  if (module == NULL)
    {
      p1->auth_domain->passwd_auth = module = ssh_pm_auth_passwd_create();
    }

  /* Allocate context for our extended authentication operation. */
  xauth = ssh_calloc(1, sizeof(*xauth));
  if (xauth == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create operation context"));
      (*done)(callback_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Xauth exchange request from IKE; allocated %p",
                          xauth));

  xauth->ed = ed;
  xauth->sad_handle = sad_handle;
  xauth->sa = ed->ike_sa;
  xauth->request = request;
  xauth->set = set;
  xauth->done = done;
#ifdef SSHDIST_RADIUS
  xauth->radius = (p1->auth_domain->radius_auth != NULL);
  xauth->flags = pm->xauth.flags;
#endif /* SSHDIST_RADIUS */
  xauth->pm = pm;
  xauth->context = callback_context;

  if (pm->xauth.type == SSH_IKE_XAUTH_TYPE_RADIUS_CHAP)
    xauth->use_chap = 1;

  start = (p1->ike_sa->xauth_enabled) ?
    ssh_pm_st_xauth_start : ssh_pm_st_xauth_collect_attributes;

    /* Start thread to handle the authentication. */
  ssh_fsm_thread_init(module->fsm,
                      xauth->thread,
                      start,
                      NULL_FNPTR,
                      pm_xauth_thread_destructor,
                      xauth);
  ssh_fsm_set_thread_name(xauth->thread, "XAuth server");

  ssh_operation_register_no_alloc(xauth->operation, pm_xauth_abort, xauth);
  return xauth->operation;
}
#endif /* SSHDIST_IKE_XAUTH */

/*--------------------------------------------------------------------*/
/* Password authentication with password lists                        */
/*--------------------------------------------------------------------*/

static void
ssh_pm_passwd_auth(const unsigned char *user_name, size_t user_name_len,
                   SshPmPasswdAuthResultCB result_callback,
                   void *result_callback_context,
                   void *context)
{
  SshPmAuthPasswd auth = (SshPmAuthPasswd) context;
  SshPmAuthPasswdEntry entry;

  /* Check if we know the user. */
  for (entry = auth->entries; entry; entry = entry->next)
    if (entry->user_name_len == user_name_len
        && memcmp(entry->user_name, user_name, user_name_len) == 0)
      {
        /* Found a match. */
        SSH_DEBUG(SSH_D_MIDOK, ("Xauth - found local user %s", user_name));
        (*result_callback)((unsigned char *) entry->password,
                           entry->password_len,
                           result_callback_context);
        return;
      }

  /* No match found. */
  SSH_DEBUG(SSH_D_MIDOK, ("Xauth - no match for local user %s", user_name));
  (*result_callback)(NULL, 0, result_callback_context);
}

/*--------------------------------------------------------------------*/
/*Creating password objects                                           */
/*--------------------------------------------------------------------*/

SshPmAuthPasswd
ssh_pm_auth_passwd_create(void)
{
  SshPmAuthPasswd auth_passwd;

  auth_passwd = ssh_calloc(1, sizeof(*auth_passwd));
  if (auth_passwd == NULL)
    return NULL;

  ssh_fsm_init(auth_passwd->fsm, auth_passwd);
  if (ssh_hash_allocate("md5", &auth_passwd->md5_hash) != SSH_CRYPTO_OK)
    goto error;
  auth_passwd->md5_digest_len = ssh_hash_digest_length("md5");

  SSH_DEBUG(SSH_D_MIDOK,
            ("Created password authenticator %p", auth_passwd));

  return auth_passwd;

  /* Error handling. */
 error:
  ssh_pm_auth_passwd_destroy(auth_passwd);
  return NULL;
}


void
ssh_pm_auth_passwd_destroy(SshPmAuthPasswd auth_passwd)
{
  if (auth_passwd == NULL)
    return;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Destroying password authenticator %p", auth_passwd));

  while (auth_passwd->entries)
    {
      SshPmAuthPasswdEntry entry = auth_passwd->entries;

      auth_passwd->entries = entry->next;
      ssh_free(entry->user_name);
      ssh_free(entry->password);
      ssh_free(entry);
    }

  ssh_fsm_uninit(auth_passwd->fsm);

  if (auth_passwd->md5_hash)
    ssh_hash_free(auth_passwd->md5_hash);

  ssh_free(auth_passwd);
}


Boolean
ssh_pm_auth_passwd_add(SshPmAuthPasswd auth_passwd,
                       const unsigned char *user_name,
                       size_t user_name_len,
                       const unsigned char *password,
                       size_t password_len)
{
  SshPmAuthPasswdEntry entry;




  SSH_DEBUG(SSH_D_MIDOK, ("Adding user/password to password authenticator"));

  entry = ssh_calloc(1, sizeof(*entry));
  if (entry == NULL)
    return FALSE;

  entry->user_name = ssh_memdup(user_name, user_name_len);
  entry->user_name_len = user_name_len;
  entry->password = ssh_memdup(password, password_len);
  entry->password_len = password_len;

  if (entry->user_name == NULL || entry->password == NULL)
    {
      ssh_free(entry->user_name);
      ssh_free(entry->password);
      ssh_free(entry);

      return FALSE;
    }

  entry->next = auth_passwd->entries;
  auth_passwd->entries = entry;

  return TRUE;
}


Boolean
ssh_pm_auth_passwd_remove(SshPmAuthPasswd auth_passwd,
                          const unsigned char *user_name,
                          size_t user_name_len)
{
  SshPmAuthPasswdEntry *entryp;

  SSH_DEBUG(SSH_D_MIDOK, ("Removing user from password authenticator"));

  for (entryp = &auth_passwd->entries; *entryp; entryp = &(*entryp)->next)
    {
      SshPmAuthPasswdEntry entry = *entryp;

      if (entry->user_name_len == user_name_len &&
          memcmp(entry->user_name, user_name, user_name_len) == 0)
        {
          /* Found it. */

          *entryp = entry->next;

          ssh_free(entry->user_name);
          ssh_free(entry->password);
          ssh_free(entry);

          return TRUE;
        }
    }

  /* Unknown user-name. */
  return FALSE;
}


/*--------------------------------------------------------------------*/
/* Entry; Password list authentication                                */
/*--------------------------------------------------------------------*/

void
ssh_pm_set_auth_passwd(SshPm pm, SshPmAuthPasswd auth_passwd)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Enabling password authenticator %p", auth_passwd));

#ifdef SSHDIST_IKE_XAUTH
  /* Enable extended authentication. */
  ssh_pm_xauth_server(pm, TRUE);
#endif /* SSHDIST_IKE_XAUTH */

  /* Password authentication L2TP/EAP. */
  ssh_pm_passwd_auth_server(pm, ssh_pm_passwd_auth, auth_passwd);
}

/*--------------------------------------------------------------------*/
/* Entry; Radius authentication                                       */
/*--------------------------------------------------------------------*/

#ifdef SSHDIST_RADIUS
void ssh_pm_set_auth_passwd_radius(SshPm pm,
                                   SshPmAuthPasswd auth_passwd,
                                   SshRadiusClient client,
                                   SshRadiusClientServerInfo servers)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Enabling Radius authenticator"));

#ifdef SSHDIST_IKE_XAUTH
  /* Enable extended authentication. */
  ssh_pm_xauth_server(pm, TRUE);
#endif /* SSHDIST_IKE_XAUTH */

  auth_passwd->client = client;
  auth_passwd->servers = servers;
}
#endif /* SSHDIST_RADIUS */

#else /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_XAUTH
/** No-op IKEV2 policy callback function for extended authentication. */
SshOperationHandle
ssh_pm_xauth(SshSADHandle sad_handle,
             SshIkev2ExchangeData ed,
             SshIkev2FbXauthRequest request,
             SshIkev2FbXauthSet set,
             SshIkev2FbXauthDone done,
             void *callback_context)
{
  (*done)(callback_context);
  return NULL;
}
#endif /* SSHDIST_IKE_XAUTH */

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_IKE_XAUTH
static void pm_xauth_client_reply(Boolean success,
                                  const unsigned char *user_name,
                                  size_t user_name_len,
                                  const unsigned char *user_password,
                                  size_t user_password_len,
                                  const unsigned char *passcode,
                                  size_t passcode_len,
                                  const unsigned char *next_pin,
                                  size_t next_pin_len,
                                  const unsigned char *answer,
                                  size_t answer_len,
                                  void *context)
{
  SshPmXauthOperation xauth = (SshPmXauthOperation)context;
  SshIkev2FbXauthAttributes attributes = xauth->attributes;
  SshPmP1 p1 = (SshPmP1)xauth->sa;

  p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

  SSH_PM_DUP(user_name, user_name_len,
             attributes->user_name, attributes->user_name_len);
  SSH_PM_DUP(user_password, user_password_len,
             attributes->user_password, attributes->user_password_len);
  SSH_PM_DUP(passcode, passcode_len,
             attributes->passcode, attributes->passcode_len);
  SSH_PM_DUP(next_pin, next_pin_len,
             attributes->next_pin, attributes->next_pin_len);
  SSH_PM_DUP(answer, answer_len,
             attributes->answer, attributes->answer_len);

  /* Remove any message or challenge attributes from the original request,
     they should not be returned to the peer. */
  if (attributes->message)
    {
      ssh_free(attributes->message);
      attributes->message = NULL;
      attributes->message_len = 0;
    }
  if (attributes->challenge)
    {
      ssh_free(attributes->challenge);
      attributes->challenge = NULL;
      attributes->challenge_len = 0;
    }

  (*xauth->status)(success
                   ? SSH_IKEV2_ERROR_OK
                   : SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                   attributes,
                   xauth->callback_context);

  ssh_free(xauth);
  return;

 error:
  (*xauth->status)(SSH_IKEV2_ERROR_OUT_OF_MEMORY,
                   NULL,
                   xauth->callback_context);
  ssh_free(xauth);
}

SshOperationHandle
pm_xauth_client_request(SshIkev2Sa sa,
                        SshIkev2FbXauthAttributes attributes,
                        SshIkev2FbXauthStatus callback,
                        void *callback_context,
                        void *user_callback_context)
{
  SshPmXauthOperation xauth;
  SshPm pm = (SshPm)user_callback_context;
  SshPmP1 p1 = (SshPmP1)sa;
  SshUInt32 attrs = 0;

  xauth = ssh_calloc(1, sizeof(*xauth));
  if (xauth == NULL)
    {
      (*callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL, callback_context);
      return NULL;
    }

  xauth->attributes = attributes;
  xauth->status = callback;
  xauth->callback_context = callback_context;
  xauth->sa = sa;

  attrs = SSH_PM_LA_XAUTH;

  if (attributes->attributes_mask & SSH_IKEV2_XAUTH_ATTRIBUTE_USER_NAME)
    attrs |= SSH_PM_LA_ATTR_USER_NAME;
  if (attributes->attributes_mask & SSH_IKEV2_XAUTH_ATTRIBUTE_USER_PASSWORD)
    attrs |= SSH_PM_LA_ATTR_USER_PASSWORD;
  if (attributes->attributes_mask & SSH_IKEV2_XAUTH_ATTRIBUTE_PASSCODE)
    attrs |= SSH_PM_LA_ATTR_PASSCODE;
  if (attributes->attributes_mask & SSH_IKEV2_XAUTH_ATTRIBUTE_NEXT_PIN)
    attrs |= SSH_PM_LA_ATTR_NEXT_PIN;
  if (attributes->attributes_mask & SSH_IKEV2_XAUTH_ATTRIBUTE_ANSWER)
    attrs |= SSH_PM_LA_ATTR_ANSWER;

  p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] =
    (*pm->la_client_query_cb)(xauth->try_number++,
                              p1->ike_sa->remote_ip,
                              attributes->domain, attributes->domain_len,
                              attributes->message, attributes->message_len,
                              attrs,
                              0L,
                              pm_xauth_client_reply,
                              xauth,
                              pm->la_client_context);

  return NULL;
}

SshOperationHandle
pm_xauth_client_set(SshIkev2Sa sa,
                    Boolean status,
                    const unsigned char *message, size_t message_len,
                    SshIkev2FbXauthAttributes attributes,

                    SshIkev2FbXauthStatus callback,
                    void *callback_context,
                    void *user_callback_context)
{
  SshPm pm = (SshPm)user_callback_context;
  SshPmXauthOperation xauth = callback_context;
  SshPmP1 p1 = (SshPmP1)sa;

  if (pm->la_client_result_cb)
    (*pm->la_client_result_cb)(xauth->try_number,
                               status,
                               message, message_len,
                               pm->la_client_context);

  (void) (*callback)(SSH_IKEV2_ERROR_OK, attributes, callback_context);

  if (p1->ike_sa->xauth_started)
    p1->ike_sa->xauth_done = 1;
  p1->failed = status ? 0 : 1;

  if (p1->failed)
    {
      ssh_ikev2_debug_error_remote(p1->ike_sa, "Xauth authentication failed");
      SSH_DEBUG(SSH_D_FAIL, ("Xauth negotiation failed, deleting IKE SA"));

      if (!SSH_PM_P1_DELETED(p1))
        {
          SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
          SSH_PM_IKEV2_IKE_SA_DELETE(p1,
                                  SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW,
                                  pm_ike_sa_delete_notification_done_callback);
        }
    }

  /* Need to continue qm thread */
  return NULL;
}

#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
