/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmRadiusAccounting"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

#define SSH_PM_RADIUS_SESSION_ID_BYTES 8

#ifdef SSH_IPSEC_STATISTICS

#define PM_RADIUS_STAT_INC(radius_acct, counter) \
                        (++(radius_acct)->stat->counter)

#define PM_RADIUS_STAT_ADD(radius_acct, counter, add) \
                        ((radius_acct)->stat->counter += (add))

#else /* SSH_IPSEC_STATISTICS */

#define PM_RADIUS_STAT_INC(radius_acct, counter)
#define PM_RADIUS_STAT_ADD(radius_acct, counter, add)

#endif /* !SSH_IPSEC_STATISTICS */


/*
  RADIUS Accounting session structure to hold the accounting session
  identifier for a session.
*/
typedef struct SshPmRadiusAcctSessionRec *SshPmRadiusAcctSession;
struct SshPmRadiusAcctSessionRec {
  unsigned char session_id[SSH_PM_RADIUS_SESSION_ID_BYTES];
};


/*
   Allocate and initialise RADIUS Accounting instance within SshPm
   structure.
*/
static Boolean
pm_radius_acct_alloc(SshPm pm)
{
  SshPmRadiusAcct radius_acct;

#ifdef SSH_IPSEC_STATISTICS
  SSH_ASSERT(pm->radius_acct == NULL);

  if (pm->radius_acct_stats == NULL)
    {
      pm->radius_acct_stats = ssh_calloc(1, sizeof(*pm->radius_acct_stats));
    }

  if (pm->radius_acct_stats == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
              ("RADIUS Accounting: ssh_calloc() failed.."));

      return FALSE;
    }
#endif /* SSH_IPSEC_STATISTICS */

  /*
    pm->radius_acct_stats is not freed below in case of error, because
    it is only allocated once; when radius accouting is configured the
    first time and freed when pm is freed in ssh_pm_free().
   */

  radius_acct = ssh_calloc(1, sizeof(*radius_acct));
  if (radius_acct != NULL)
    {
      radius_acct->pm = pm;
      radius_acct->radius_acct_next_session = 1;
      radius_acct->radius_acct_refcount = 1;
      pm->radius_acct = radius_acct;

#ifdef SSH_IPSEC_STATISTICS
      radius_acct->stat = pm->radius_acct_stats;
#endif /* SSH_IPSEC_STATISTICS */

      return TRUE;
    }

  SSH_DEBUG(SSH_D_ERROR,
          ("RADIUS Accounting: ssh_calloc() failed.."));

  return FALSE;
}


/* Take a reference i.e. increase reference count on RADIUS Accounting
   instance.
 */
static void
pm_radius_acct_reference(SshPmRadiusAcct radius_acct)
{
  SSH_ASSERT(radius_acct->radius_acct_refcount > 0);

  ++radius_acct->radius_acct_refcount;

  SSH_DEBUG(SSH_D_LOWOK,
          ("RADIUS Accounting %p: reference count increased to %d",
           radius_acct,
           radius_acct->radius_acct_refcount));
}


/* Release a reference i.e. decrease reference count on RADIUS
   Accounting instance.

   If reference count goes to zero destroy RADIUS client and server
   info and release the accounting instance memory.
 */
static void
pm_radius_acct_release(SshPmRadiusAcct radius_acct)
{
  SSH_ASSERT(radius_acct->radius_acct_refcount > 0);

  --radius_acct->radius_acct_refcount;

  SSH_DEBUG(SSH_D_LOWOK,
          ("RADIUS Accounting %p: reference count decreased to %d",
           radius_acct,
           radius_acct->radius_acct_refcount));

  if (radius_acct->radius_acct_refcount == 0)
    {
      if (radius_acct->radius_acct_client != NULL)
        {
          ssh_radius_client_destroy(radius_acct->radius_acct_client);
        }

      if (radius_acct->radius_acct_servers != NULL)
        {
          ssh_radius_client_server_info_destroy(
                                             radius_acct->radius_acct_servers);
        }

      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: freeing radius_acct %p",
               radius_acct));

      ssh_free(radius_acct);
    }
}


/*
  Return TRUE if radius_acct points to configured RADIUS Accounting instance.
 */
static Boolean
pm_radius_acct_is_configured(SshPmRadiusAcct radius_acct)
{
  if (radius_acct == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: not configured in pm."));

      return FALSE;
    }

  if (radius_acct->radius_acct_client == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: RADIUS client not configured in pm."));

      return FALSE;
    }

  if (radius_acct->radius_acct_servers == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: RADIUS servers not configured in pm."));

      return FALSE;
    }

  return TRUE;
}


/*
  Return TRUE if pm structure has radius accounting configured and
  enabled.
 */
static Boolean
pm_radius_acct_is_active(SshPmRadiusAcct radius_acct)
{
  if (!pm_radius_acct_is_configured(radius_acct))
    {
      return FALSE;
    }

  if (radius_acct->radius_acct_enabled == FALSE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: disabled in pm."));

      return FALSE;
    }

  return TRUE;
}


/*
   Allocate and initialize RADIUS Accounting session structure.
   Return pointer to the allocated structure or NULL incase of error.
 */
static SshPmRadiusAcctSession
pm_radius_acct_session_create(SshPmRadiusAcct radius_acct)
{
  SshPmRadiusAcctSession acct_session;

  acct_session = ssh_malloc(sizeof(*acct_session));
  if (acct_session != NULL)
    {
      SSH_ASSERT(SSH_PM_RADIUS_SESSION_ID_BYTES == 8);

      SSH_PUT_32BIT(acct_session->session_id,
              (SshUInt32) radius_acct->radius_acct_start_time);

      SSH_PUT_32BIT(acct_session->session_id + 4,
              (SshUInt32) radius_acct->radius_acct_next_session);

      ++radius_acct->radius_acct_next_session;
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
              ("RADIUS Accounting: ssh_malloc() failed.."));
    }

  return acct_session;
}


/*
  Free accounting session structure.
 */
static void
pm_radius_acct_session_free(SshPmRadiusAcctSession acct_session)
{
  SSH_DEBUG(SSH_D_LOWOK, ("RADIUS Accounting: freeing session %p",
                          acct_session));

  ssh_free(acct_session);
}


/*
  Allocate and initialise a RADIUS Accounting request.
 */
static SshRadiusClientRequest
pm_radius_acct_allocate_request(SshPmRadiusAcct radius_acct,
                                SshRadiusAccountingStatusType status_type)
{
  SshRadiusClientRequest request;
  SshRadiusAvpStatus avp_status = SSH_RADIUS_AVP_STATUS_SUCCESS;
  unsigned char value[4];

  request = ssh_radius_client_request_create(radius_acct->radius_acct_client,
                                             SSH_RADIUS_ACCOUNTING_REQUEST);
  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory allocating RADIUS request Status-Type %s.",
                 ssh_find_keyword_name(ssh_radius_acct_status_types,
                         status_type)));
      return NULL;
    }

  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_PUT_32BIT(value, status_type);
      avp_status = ssh_radius_client_request_add_attribute(request,
                                               SSH_RADIUS_AVP_ACCT_STATUS_TYPE,
                                               value,
                                               4);
    }

  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      /* RFC2866 RADIUS Accounting specifies that each accounting
         request must contain Acct-Session-Id attribute. However,
         accounting statuses On and Off are not linked to any session.
         A common solution for RADIUS Accounting is to use a dummy
         string of zeroes for On and Off requests.
       */
      static const char dummy_session_id[] =
          "0000000000000000";

      if (status_type == SSH_RADIUS_ACCT_STATUS_ON ||
          status_type == SSH_RADIUS_ACCT_STATUS_OFF)
        {
          avp_status = ssh_radius_client_request_add_attribute(request,
                                                SSH_RADIUS_AVP_ACCT_SESSION_ID,
                                                dummy_session_id,
                                                sizeof(dummy_session_id)
                                                /* nul termination */ - 1);
        }
    }

  if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting: Packet encoding failed, avp status %d",
               avp_status));

      ssh_radius_client_request_destroy(request);
      request = NULL;
    }


  SSH_DEBUG(SSH_D_LOWOK,
          ("Allocated RADIUS Accounting request %p Acc-Status-Type %s.",
           request,
           ssh_find_keyword_name(ssh_radius_acct_status_types, status_type)));

  return request;
}


/*
  Add accounting session id attribute to given RADIUS request.
 */
static SshRadiusAvpStatus
pm_radius_add_session_id(SshRadiusClientRequest request,
        SshPmRadiusAcctSession acct_session)
{
                             /* binary to hex plus nul termination */
  unsigned char session_id_buf[SSH_PM_RADIUS_SESSION_ID_BYTES*2+1];
  int i;

  /* Acct-Session-Id attribute SHOULD be a string. => encode
     session_id as hexadecimal string.
   */
  for (i = 0; i < sizeof(acct_session->session_id); i++)
    {
      ssh_snprintf(session_id_buf + 2 * i,
              3,
              "%.2x",
              (int) acct_session->session_id[i]);
    }

  return ssh_radius_client_request_add_attribute(request,
                                                SSH_RADIUS_AVP_ACCT_SESSION_ID,
                                                session_id_buf,
                                                sizeof(session_id_buf) - 1);
}


/*
  Adds ike id to request and User-Name attribute.
 */
static SshRadiusAvpStatus
pm_radius_acct_request_add_ike_id(SshRadiusClientRequest request,
                                  SshIkev2PayloadID ike_id)
{
  unsigned char id_buf[SSH_IP_ADDR_STRING_SIZE];
  unsigned char *id_data;
  int id_data_size;

  if (ike_id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR)
    {
      ssh_ipaddr_ipv4_print(ike_id->id_data, id_buf, sizeof(id_buf));
      id_data = id_buf;
      id_data_size = strlen(id_data);
    }
  else
  if (ike_id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
    {
      ssh_ipaddr_ipv6_print(ike_id->id_data, id_buf, sizeof(id_buf), 0);
      id_data = id_buf;
      id_data_size = strlen(id_data);
    }
  else
    {
      /* The rest of the id types are copied as they are to the RADIUS
         attribute.

         With id type KEY_ID this might cause interoperability issues
         if binary ids are used. In that case the encoding of KEY_ID
         typed ids could be changed to hexadecimal string.
       */

      id_data = ike_id->id_data;
      id_data_size = ike_id->id_data_size;
    }


  return ssh_radius_client_request_add_attribute(request,
                                                 SSH_RADIUS_AVP_USER_NAME,
                                                 id_data,
                                                 id_data_size);
}


/*
  Callback function for RADIUS library.
 */
static void
pm_radius_acct_callback(SshRadiusClientRequestStatus status,
                        SshRadiusClientRequest request,
                        SshRadiusOperationCode reply_code,
                        void *context)
{
  SshPmRadiusAcct radius_acct = context;

  switch (status)
    {
    case SSH_RADIUS_CLIENT_REQ_SUCCESS:
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting Request %p finished: SUCCESS.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_response_count);
      break;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST:
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Request %p finished: REQUEST MALFORMED.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
      break;

    case SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES:
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Request %p finished: NO RESOURCES.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
      break;

    case SSH_RADIUS_CLIENT_REQ_TIMEOUT:
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Request %p finished: TIMEOUT.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_timeout_count);
      break;

    case SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY:
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Request %p finished: RESPONSE MALFORMED.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_response_invalid_count);
      break;

    case SSH_RADIUS_CLIENT_REQ_CANCELLED:
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Request %p finished: REQUEST CANCELLED.",
               request));

      PM_RADIUS_STAT_INC(radius_acct, acct_request_cancelled_count);
      break;

    default:
      SSH_NOTREACHED;
    }

  PM_RADIUS_STAT_ADD(radius_acct,
                     acct_request_retransmit_count,
                     ssh_radius_client_request_get_retranmit_count(request));

  ssh_radius_client_request_destroy(request);

  if (radius_acct->radius_acct_shutdown == TRUE)
    {
      SshPm pm = radius_acct->pm;

      SSH_DEBUG(SSH_D_LOWOK,
                ("RADIUS Accounting: "
                 "shutdown in progress, notify main thread"));

      ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
    }

  /* Free the reference taken in pm_radius_acct_send_request() */
  pm_radius_acct_release(radius_acct);
}


/* Send request using RADIUS client and server info from radius_acct.
   Take a reference for the sent request. The reference is freed from
   the callback function.
 */
static void
pm_radius_acct_send_request(SshPmRadiusAcct radius_acct,
                            SshRadiusClientRequest request)
{
  pm_radius_acct_reference(radius_acct);

  PM_RADIUS_STAT_INC(radius_acct, acct_request_count);

  ssh_radius_client_request(request,
          radius_acct->radius_acct_servers,
          pm_radius_acct_callback,
          radius_acct);
}


/*
  Send Accounting-On accounting request.
 */
static void
pm_radius_acct_send_accounting_on(SshPmRadiusAcct radius_acct)
{
  SshRadiusClientRequest request;

  SSH_ASSERT(radius_acct->radius_acct_enabled == TRUE);
  SSH_ASSERT(radius_acct->radius_acct_client != NULL);
  SSH_ASSERT(radius_acct->radius_acct_servers != NULL);

  request =
      pm_radius_acct_allocate_request(radius_acct,
              SSH_RADIUS_ACCT_STATUS_ON);
  if (request != NULL)
    {
      PM_RADIUS_STAT_INC(radius_acct, acct_request_on_count);

      SSH_DEBUG(SSH_D_LOWOK,
                ("RADIUS Accounting %p: Sending Accounting-On %p",
                 radius_acct,
                 request));

      pm_radius_acct_send_request(radius_acct, request);
    }
}


/*
  Send Accounting-Off accounting request.
 */
static void
pm_radius_acct_send_accounting_off(SshPmRadiusAcct radius_acct)
{
  SshRadiusClientRequest request;

  SSH_ASSERT(radius_acct->radius_acct_enabled == TRUE);
  SSH_ASSERT(radius_acct->radius_acct_client != NULL);
  SSH_ASSERT(radius_acct->radius_acct_servers != NULL);

  request =
      pm_radius_acct_allocate_request(radius_acct,
              SSH_RADIUS_ACCT_STATUS_OFF);
  if (request != NULL)
    {
      PM_RADIUS_STAT_INC(radius_acct, acct_request_off_count);

      SSH_DEBUG(SSH_D_LOWOK,
                ("RADIUS Accounting %p: Sending Accounting-Off %p",
                 radius_acct,
                 request));

      pm_radius_acct_send_request(radius_acct, request);
    }
}


/*
  Policy manager configuration API call. See ipsec_pm.h for details.
 */
void
ssh_pm_ras_set_radius_acct_client(SshPm pm,
                                  SshRadiusClient radius_client)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;
  SshRadiusClientServerInfo servers = NULL;

  if (radius_acct != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: "
               "releasing previous radius_acct %p from pm %p",
               radius_acct,
               pm));

      /* Store server pointer for new radius_acct structure. */
      servers = radius_acct->radius_acct_servers;
      radius_acct->radius_acct_servers = NULL;

      radius_acct->pm = NULL;
      pm_radius_acct_release(pm->radius_acct);
      pm->radius_acct = NULL;
    }

  if (radius_client != NULL)
    {
      if (pm_radius_acct_alloc(pm) != TRUE)
        return;

      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: allocated new radius_acct %p for pm %p",
               radius_acct,
               pm));

      radius_acct = pm->radius_acct;

      radius_acct->radius_acct_servers = servers;
      radius_acct->radius_acct_client = radius_client;
    }
  else if (servers != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting: radius_acct %p destroying serverlist %p",
               radius_acct,
               servers));

      /* No new accounting instance; destroy servers */
      ssh_radius_client_server_info_destroy(servers);
    }
}


/*
  Policy manager configuration API call. See ipsec_pm.h for details.
 */
Boolean
ssh_pm_ras_set_radius_acct_servers(SshPm pm,
                                   SshRadiusClientServerInfo radius_servers)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;

  if (radius_acct == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting: failure setting RADIUS servers, "
               "client not configured"));

      return FALSE;
    }

  if (radius_acct->radius_acct_servers != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting %p: Releasing old server list %p",
               radius_acct,
               radius_acct->radius_acct_servers));

      ssh_radius_client_server_info_destroy(radius_acct->radius_acct_servers);
    }

  radius_acct->radius_acct_servers = radius_servers;

  SSH_DEBUG(SSH_D_MIDOK,
          ("RADIUS Accounting %p: server list set to %p",
           radius_acct,
           radius_servers));

  return TRUE;
}


/*
  Policy manager configuration API call. See ipsec_pm.h for details.
 */
Boolean
ssh_pm_ras_set_radius_acct_enabled(SshPm pm,
                                   SshUInt32 flags)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;

  if (pm_radius_acct_is_configured(radius_acct) == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("RADIUS Accounting: can't enable, not configured"));

      return FALSE;
    }

  if (pm_radius_acct_is_active(radius_acct) == TRUE)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("RADIUS Accounting: can't enable, already enabled"));

      return TRUE;
    }


  SSH_DEBUG(SSH_D_MIDOK, ("RADIUS Accounting %p: enabling", radius_acct));

  radius_acct->radius_acct_enabled = TRUE;
  radius_acct->radius_acct_start_time = ssh_time();

  if ((flags & SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_ON) != 0)
    {
      pm_radius_acct_send_accounting_on(radius_acct);
    }

  return TRUE;
}


/*
  Policy manager configuration API call. See ipsec_pm.h for details.
 */
Boolean
ssh_pm_ras_set_radius_acct_disabled(SshPm pm,
                                    SshUInt32 flags)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;

  if (radius_acct == NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("RADIUS Accounting: can't disable, not configured"));

      return FALSE;
    }

  if (pm_radius_acct_is_active(radius_acct) == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("RADIUS Accounting: can't disable, already disabled"));

      return TRUE;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("RADIUS Accounting %p: disabling", radius_acct));

  if ((flags & SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_OFF) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting %p: "
               "cancelling all requests before sending Accounting-Off",
               radius_acct));

      /* All accounting requests in transmission are cancelled,
         because we are about to send Accounting-Off. Accounting-Off
         tells the RADIUS server that we have stopped the accounting
         function and all accounting sessions are stopped.
       */
      ssh_radius_client_cancel_all_requests(radius_acct->radius_acct_client);

      pm_radius_acct_send_accounting_off(radius_acct);
    }

  radius_acct->radius_acct_enabled = FALSE;

  return TRUE;
}


/*
   Policy manager internal function. Called after IPsec setup is ready
   for cfgmode.
 */
void
pm_ras_radius_acct_start(SshPm pm,
                         SshPmActiveCfgModeClient client)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;
  SshRadiusClientRequest request = NULL;
  SshRadiusAvpStatus avp_status = SSH_RADIUS_AVP_STATUS_SUCCESS;
  SshPmRadiusAcctSession acct_session = NULL;

  SSH_ASSERT(client != NULL);

  if (!pm_radius_acct_is_active(radius_acct))
    {
      return;
    }

  if (client->radius_acct_context != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting-Start Client %p: "
               "already started for cfgmode client.",
               client));
      return;
    }

  acct_session = pm_radius_acct_session_create(radius_acct);
  if (acct_session == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting-Start Client %p: "
               "Failed to create Session.",
               client));

      return;
    }

  request =
      pm_radius_acct_allocate_request(radius_acct,
                                      SSH_RADIUS_ACCT_STATUS_START);

  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting-Start Client %p: "
               "Failed to allocate request.",
               client));

      pm_radius_acct_session_free(acct_session);

      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
      return;
    }


  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      avp_status = pm_radius_add_session_id(request, acct_session);
    }

  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SshPmPeer peer;

      peer = ssh_pm_peer_by_handle(pm, client->peer_handle);
      SSH_ASSERT(peer != NULL);

      avp_status =
          pm_radius_acct_request_add_ike_id(request,
                                            peer->remote_id);

      if (avp_status == SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG)
        {
          SSH_DEBUG(SSH_D_FAIL,
                  ("RADIUS Accounting-Start Client %p: "
                   "IKE ID too long to fit in RADIUS attribute: %@",
                   client,
                   ssh_pm_ike_id_render, peer->remote_id));

          PM_RADIUS_STAT_INC(radius_acct, acct_request_too_long_ike_id_count);
        }
    }


    {
      int i;

      for (i = 0; avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS &&
               i < client->num_addresses; i++)
        {
          SshIpAddr ip = client->addresses[i];

          if (SSH_IP_IS4(ip))
            {
              avp_status = ssh_radius_client_request_add_attribute(request,
                                              SSH_RADIUS_AVP_FRAMED_IP_ADDRESS,
                                              SSH_IP_ADDR_DATA(ip),
                                              SSH_IP_ADDR_LEN(ip));
            }
#ifdef WITH_IPV6
          else if (SSH_IP_IS6(ip))
            {
              unsigned char attr_data[2 + SSH_IP_ADDR_SIZE];

              /* RFC 3162 */
              attr_data[0] = 0;
              attr_data[1] = SSH_IP_MASK_LEN(ip);

              SSH_IP6_ENCODE(ip, attr_data + 2);

              avp_status = ssh_radius_client_request_add_attribute(request,
                                             SSH_RADIUS_AVP_FRAMED_IPV6_PREFIX,
                                             attr_data,
                                             sizeof(attr_data));
            }
#endif /* WITH_IPV6 */
          else
            {
              SSH_NOTREACHED;
            }
        }

      /* We must have added at least one address. */
      SSH_ASSERT(i > 0);
    }


  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_MIDOK,
              ("RADIUS Accounting-Start Client %p: Session started.",
               client));

      client->radius_acct_context = acct_session;

      pm_radius_acct_send_request(radius_acct, request);

      PM_RADIUS_STAT_INC(radius_acct, acct_request_start_count);
    }


  if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting-Start Client %p: packet encoding failed, "
               "avp_status %d.",
               client,
               avp_status));

      if (request != NULL)
        {
          ssh_radius_client_request_destroy(request);
        }

      if (acct_session != NULL)
        {
          pm_radius_acct_session_free(acct_session);
        }


      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
    }
}


/*
   Policy manager internal function. Called after when cfgmode client
   is to be destroyed.
 */
void
pm_ras_radius_acct_stop(SshPm pm,
                        SshPmActiveCfgModeClient client)
{
  SshPmRadiusAcct radius_acct = pm->radius_acct;
  SshRadiusClientRequest request = NULL;
  SshRadiusAvpStatus avp_status = SSH_RADIUS_AVP_STATUS_SUCCESS;
  SshPmRadiusAcctSession acct_session = client->radius_acct_context;

  if (acct_session == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting-Stop Client %p:"
               " No session on cfgmode client.",
               client));
      return;
    }

  if (!pm_radius_acct_is_active(radius_acct))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
              ("RADIUS Accounting-Stop Client %p:"
               " Not sending request.",
               client));

      pm_radius_acct_session_free(acct_session);
      client->radius_acct_context = NULL;
      return;
    }

  request = pm_radius_acct_allocate_request(radius_acct,
                                            SSH_RADIUS_ACCT_STATUS_STOP);

  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting-Stop Client %p: Request allocation failed.",
               client));

      pm_radius_acct_session_free(acct_session);
      client->radius_acct_context = NULL;

      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
      return;
    }

  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      avp_status = pm_radius_add_session_id(request, acct_session);
    }

  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SshPmPeer peer;

      peer = ssh_pm_peer_by_handle(pm, client->peer_handle);
      SSH_ASSERT(peer != NULL);

      avp_status =
          pm_radius_acct_request_add_ike_id(request,
                                            peer->remote_id);

      if (avp_status == SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG)
        {
          SSH_DEBUG(SSH_D_FAIL,
                  ("RADIUS Accounting-Stop Client %p: "
                   "IKE ID too long to fit in RADIUS attribute: %@",
                   client,
                   ssh_pm_ike_id_render, peer->remote_id));

          PM_RADIUS_STAT_INC(radius_acct, acct_request_too_long_ike_id_count);
        }
    }


  if (avp_status == SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_MIDOK,
              ("RADIUS Accounting-Stop Client %p: Session stopped.",
               client));

      pm_radius_acct_send_request(radius_acct, request);

      PM_RADIUS_STAT_INC(radius_acct, acct_request_stop_count);
   }


  if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting-Stop Client %p: "
               "Packet encoding failed, avp_status %d",
               client, avp_status));

      if (request != NULL)
        {
          ssh_radius_client_request_destroy(request);
        }

      PM_RADIUS_STAT_INC(radius_acct, acct_request_failed_count);
    }

  pm_radius_acct_session_free(client->radius_acct_context);
  client->radius_acct_context = NULL;
}


/*
   Policy manager internal function. Called when shutdown starts.
 */
Boolean
pm_ras_radius_acct_shutdown(SshPm pm)
{
  Boolean shutdown_ready = TRUE;

  if (pm->radius_acct != NULL)
    {
      if (pm->radius_acct->radius_acct_refcount == 1)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                  ("RADIUS Accounting %p: "
                   "No pending requests releasing for shutdown."));

          pm_radius_acct_release(pm->radius_acct);
          pm->radius_acct = NULL;
        }
      else
        {
          if (pm->radius_acct->radius_acct_shutdown == FALSE)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                      ("RADIUS Accounting %p: Marked for shutdown.",
                       pm->radius_acct));

              pm->radius_acct->radius_acct_shutdown = TRUE;
            }

          shutdown_ready = FALSE;
        }
    }

  return shutdown_ready;
}


void
ssh_pm_radius_acct_get_stats(SshPm pm,
                             SshPmRadiusAcctStatsCB callback,
                             void *context)
{
  SshPmRadiusAcctStats stats = NULL;

  SSH_ASSERT(pm != NULL);
  SSH_ASSERT(callback != NULL);

#ifdef SSH_IPSEC_STATISTICS
  if (pm->radius_acct != NULL)
    {
      stats = pm->radius_acct_stats;
    }
#endif /* SSH_IPSEC_STATISTICS */

  SSH_DEBUG(SSH_D_MIDOK,
          ("RADIUS Accounting: "
           "Calling statistics callback %p with context %p stats %p",
           callback,
           context,
           stats));

  (*callback)(pm, stats, context);
}



/* Import/Export functions */


size_t
pm_radius_acct_encode_session(SshBuffer buffer,
                              SshPmP1 p1)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshPmActiveCfgModeClient client = NULL;

  if (p1 != NULL)
    client = p1->cfgmode_client;

  if (client != NULL && client->radius_acct_context != NULL)
    {
      SshPmRadiusAcctSession acct_session = client->radius_acct_context;

      SSH_DEBUG(SSH_D_LOWOK,
              ("RADIUS Accounting Client %p: "
               "Encoded session.",
                       client));

      return
          ssh_encode_buffer(buffer,
                            SSH_ENCODE_UINT32_STR((void *) acct_session,
                                                  sizeof(*acct_session)),
                            SSH_FORMAT_END);
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  return
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32_STR((void *) "", 0),
                        SSH_FORMAT_END);
}


const void *
pm_radius_acct_decode_session(SshBuffer buffer)
{
  size_t size;
  unsigned char *session_data;
  size_t session_data_len;

  size =
      ssh_decode_buffer(buffer,
                        SSH_DECODE_UINT32_STR_NOCOPY(&session_data,
                                                     &session_data_len),
                        SSH_FORMAT_END);

  if (size == 0 ||
      session_data_len != sizeof(struct SshPmRadiusAcctSessionRec))
    {
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("RADIUS Accounting: Decoded session."));

  return session_data;
}


void
pm_radius_acct_install_session(SshPmActiveCfgModeClient client,
                               const void *radius_acct_context)
{
  SshPmRadiusAcctSession acct_session;

  SSH_ASSERT(client != NULL);
  SSH_ASSERT(radius_acct_context != NULL);

  acct_session = ssh_malloc(sizeof(*acct_session));
  if (acct_session == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("RADIUS Accounting Client %p: "
               "Imported session installation failed: Out of memory.",
                       client));
      return;
    }

  memcpy(acct_session, radius_acct_context, sizeof(*acct_session));

  client->radius_acct_context = acct_session;

  SSH_DEBUG(SSH_D_MIDOK,
          ("RADIUS Accounting Client %p: "
           "Installed imported RADIUS Accounting session.",
                   client));
}

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
