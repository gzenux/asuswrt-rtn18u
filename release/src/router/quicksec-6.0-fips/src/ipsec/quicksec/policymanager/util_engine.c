/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   General utility functions - engine dependent.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "ipsec_internal.h"

#include "util_engine.h"

#define SSH_DEBUG_MODULE "SshPmUtilEngine"


/* from util_unknown_spis.c */

/* Lifetime of an SPI error entry after recovery actions have been
 *    performed. The entry will remain this long in the database catching
 *       any remaining errors. */
#define SSH_PM_UNKNOWN_SPI_HOLDTIME    4

#define PM_DEBUG_SPI_ADDR(msg, remote_ip, ipproto, spi)         \
  SSH_DEBUG(SSH_D_HIGHOK,                                       \
            (msg " (address %@, protocol %s, spi 0x%08x)",      \
             ssh_ipaddr_render, remote_ip,                      \
             ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",         \
             (unsigned)spi))


/* Report a new valid inbound SA. */
void
ssh_pm_new_inbound_spi(SshPm pm,
                       SshIpAddr local_ip, SshIpAddr remote_ip,
                       SshInetIPProtocolID ipproto, SshUInt32 spi,
                       SshPmTunnel tunnel)
{
  SshPmSpiUnknownStruct dummy, *item;
  SshADTHandle h;

  dummy.local_ip = *local_ip;
  dummy.remote_ip = *remote_ip;
  dummy.ipproto = ipproto;
  dummy.remote_port = 0;
  dummy.spi = spi;
  dummy.ike_sa_handle = SSH_IPSEC_INVALID_INDEX;

  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel given"));
      return;
    }
  dummy.routing_instance_id = tunnel->routing_instance_id;

  h = ssh_adt_get_handle_to_equal(pm->unknown_spis, &dummy);
  if (h == SSH_ADT_INVALID)
    return;

  PM_DEBUG_SPI_ADDR("Inbound SA is now up", remote_ip, ipproto, spi);
  item = ssh_adt_get(pm->unknown_spis, h);

  /* Reprocess the stored ESP/AH packet that should now have a known SPI. */
  if (item->packet)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Reprocessing stored packet"));
      ssh_pme_process_packet(pm->engine,
                             item->tunnel_id,
                             item->protocol,
                             item->ifnum,
                             item->routing_instance_id,
                             item->flags,
                             item->prev_transform_index,
                             item->packet,
                             item->packet_len);

      ssh_free(item->packet);
      pm->unknown_spi_bytes -= item->packet_len;
      item->packet = NULL;
    }

  /* Keep the entry for a while. */
  item->done = 1;
  item->lifetime = item->age + SSH_PM_UNKNOWN_SPI_HOLDTIME;
}


/* from util_alloc.c */
#define SSH_PM_FREELIST_INDEX_PUT(list, item) \
pm_freelist_index_put(&(list), (SshPmFreelistItem) (item), sizeof(*(item)), \
                      &(item)->index)

void ssh_pm_p1_free(SshPm pm, SshPmP1 p1)
{
#ifdef DEBUG_LIGHT
  SshIkev2Sa sa = p1->ike_sa;
#endif /* DEBUG_LIGHT */

  SSH_PM_ASSERT_PM(pm);
  SSH_PM_ASSERT_P1(p1);
  SSH_ASSERT(!SSH_FSM_THREAD_EXISTS(&p1->thread));

  SSH_ASSERT(sa->ref_cnt == 0);

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, p1);

  /* One active Phase-1 negotiation less. */
  SSH_ASSERT(pm->stats.num_p1_active > 0);
  pm->stats.num_p1_active--;

  /* And notify main thread if the policy manager is shutting down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  ssh_fsm_condition_uninit(&p1->xauth_wait_condition);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  /* Free this Phase-1 structure. */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  if (p1->auth_cert)
    {
      ssh_cm_cert_remove_reference(p1->auth_cert);
      p1->auth_cert = NULL;
    }

  if (p1->auth_ca_cert)
    {
      ssh_cm_cert_remove_reference(p1->auth_ca_cert);
      p1->auth_ca_cert = NULL;
    }
#else /* SSHDIST_CERT */
#ifdef WITH_MSCAPI



  if (p1->auth_cert)
    {
      ssh_pm_mscapi_free_cert(p1->auth_cert);
      p1->auth_cert = NULL;
    }
  if (p1->auth_ca_cert)
    {
      ssh_pm_mscapi_free_cert(p1->auth_ca_cert);
      p1->auth_ca_cert = NULL;
    }
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (p1->auth_domain)
    {
      ssh_pm_auth_domain_destroy(pm, p1->auth_domain);
      p1->auth_domain = NULL;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->first_round_auth_domain)
    {
      ssh_pm_auth_domain_destroy(pm, p1->first_round_auth_domain);
      p1->first_round_auth_domain = NULL;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (p1->authorization_group_ids)
    ssh_free(p1->authorization_group_ids);
  if (p1->xauth_authorization_group_ids)
    ssh_free(p1->xauth_authorization_group_ids);

  if (p1->local_secret)
    ssh_free(p1->local_secret);

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Free possible remote access attributes. */
  if (p1->remote_access_attrs)
    ssh_pm_free_remote_access_attrs(p1->remote_access_attrs);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  if (p1->cfgmode_client)
    SSH_PM_CFGMODE_CLIENT_FREE_REF(pm, p1->cfgmode_client);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  if (p1->local_id) ssh_pm_ikev2_payload_id_free(p1->local_id);
  if (p1->remote_id) ssh_pm_ikev2_payload_id_free(p1->remote_id);
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->second_local_id)
    ssh_pm_ikev2_payload_id_free(p1->second_local_id);

  if (p1->second_remote_id)
    ssh_pm_ikev2_payload_id_free(p1->second_remote_id);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
  if (p1->eap_remote_id)
    ssh_pm_ikev2_payload_id_free(p1->eap_remote_id);
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->second_eap_remote_id)
    ssh_pm_ikev2_payload_id_free(p1->second_eap_remote_id);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

  if (p1->n)
    ssh_pm_p1_negotiation_free(pm, p1->n);

  /* p1->index is used by the policy manager as follows.
     is_ikev1 : 1;    this is not used at the policy manager side.
     generation : 7;  incremented here
     index : 24;      held here */
  {
    int generation = ((p1->index >> 24) & 0x7f);
    if (++generation == 128)
      generation = 0;
    p1->index = ((p1->index & 0x00ffffff)| generation << 24);
  }

#ifdef SSH_IPSEC_SMALL
  ssh_cancel_timeout(p1->timeout);
#endif /* SSH_IPSEC_SMALL */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Release network connection. */
  if (p1->conn_handle)
    ssh_pm_connection_release(p1->conn_handle);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_IPSEC_TCPENCAP
  /* Release encapsulating TCP connections. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Removing TCP encapsulation for IKE SA %p",
                              p1->ike_sa));

      ssh_pme_tcp_encaps_update_ike_mapping(pm->engine, FALSE, NULL, NULL,
                                            p1->ike_sa->ike_spi_i,
                                            NULL, NULL, NULL);
    }
#endif /* SSH_IPSEC_TCPENCAP */

  if (p1->delete_notification_requests)
    ssh_pm_free_ipsec_delete_notification_requests(p1);
  SSH_ASSERT(p1->delete_notification_requests == NULL);

#ifdef SSHDIST_IPSEC_MOBIKE
  SSH_ASSERT(p1->mobike_suspended_operation == NULL);
#endif /* SSHDIST_IPSEC_MOBIKE */

  /* Remove from resume queue. */
  if (p1->in_resume_queue)
    {
      if (pm->resume_queue == p1)
        {
          pm->resume_queue = p1->resume_queue_next;
        }
      else
        {
          SshPmP1 prev_p1;
          for (prev_p1 = pm->resume_queue;
               prev_p1 != NULL;
               prev_p1 = prev_p1->resume_queue_next)
            {
              if (prev_p1->resume_queue_next == p1)
                {
                  prev_p1->resume_queue_next = p1->resume_queue_next;
                  break;
                }
            }
        }
      p1->resume_queue_next = NULL;
      p1->in_resume_queue = 0;
    }

  /* Put the structure back to PM's Phase-1 structure freelist. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Recycling Phase-1 SA context %p", p1));
  SSH_PM_FREELIST_INDEX_PUT(pm->p1_freelist, p1);
}


/* from util_audit.c */

/************ Requesting audit events from the engine *********************/
static void
engine_audit_callback(SshPm pm, Boolean more_events,
                      SshUInt32 flags, SshUInt32 num_events,
                      const SshEngineAuditEvent events, void *context)
{
  SshEngineAuditEventStruct event_s;
  SshEngineAuditEvent event;
  SshUInt32 i;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

#ifdef DEBUG_HEAVY
  SSH_DEBUG(SSH_D_MY, ("In the engine audit callback, got %d engine "
                       "audit events", num_events));
#endif /* DEBUG_HEAVY */

  /* Do not audit resource failure events more than once per second. */
  if ((flags & SSH_ENGINE_AUDIT_EVENT_FAILURE) &&
      (pm->audit.last_resource_failure_time + 1 <= ssh_time()))
    {
      memset(&event_s, 0, sizeof(event_s));
      event_s.event = SSH_AUDIT_RESOURCE_FAILURE;
      ssh_pm_audit_engine_event(pm, &event_s);
    }

  /* Do not audit rate limited events more than once per second. */
  if ((flags & SSH_ENGINE_AUDIT_RATE_LIMITED_EVENT) &&
      (pm->audit.last_flood_time + 1 <= ssh_time()))
    {
      pm->audit.last_flood_time = ssh_time();

      memset(&event_s, 0, sizeof(event_s));
      event_s.event = SSH_AUDIT_FLOOD;
      ssh_pm_audit_engine_event(pm, &event_s);
    }

  for (i = 0; i < num_events; i++)
    {
      event = (SshEngineAuditEvent)((unsigned char *)events +
                                    i * sizeof(SshEngineAuditEventStruct));

      /* Audit the event */
      ssh_pm_audit_engine_event(pm, event);
    }

  /* Schedule the next request for audit events. At present we do not
     vary the time interval for which we request audit events from
     the engine.*/
  ssh_cancel_timeout(&pm->audit.timer);

  if (pm->audit.request_interval != 0)
    ssh_register_timeout(&pm->audit.timer, 0, pm->audit.request_interval,
                         ssh_pm_audit_get_engine_events_timer, pm);

  return;
}


#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL 0
#define SSH_PM_AUDIT_NUM_REQUESTS (2 * SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS)
#else
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL \
        (1000000 / SSH_PM_AUDIT_REQUESTS_PER_SECOND)
#define SSH_PM_AUDIT_NUM_REQUESTS 10
#endif
/* The number of audit events that the policymanager requests the engine
   to send it each time it requests audit events from the engine. */


void ssh_pm_audit_get_engine_events(SshPm pm)
{
#ifdef DEBUG_HEAVY
  SSH_DEBUG(SSH_D_MY, ("Requesting audit event from the engine"));
#endif /* DEBUG_HEAVY */

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

  if (pm->audit.modules)
    ssh_pme_get_audit_events(pm->engine, SSH_PM_AUDIT_NUM_REQUESTS,
                             engine_audit_callback, pm);


  /* Reschedule the timeout after 1 second in case the engine fails
     to return audit events to the policymanager. */
  ssh_cancel_timeout(&pm->audit.retry_timer);
  if (pm->audit.request_interval != 0)
    ssh_register_timeout(&pm->audit.retry_timer, 1, 0,
                         ssh_pm_audit_get_engine_events_timer, pm);
}


