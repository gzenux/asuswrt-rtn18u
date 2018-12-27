/**
   @copyright
   Copyright (c) 2007 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Module for handling with unknown SPI's related events. Such events may
   related to inbound or outbound SPI's. Notification of unknown inbound SPI's
   are received from the engine. Notification of unknown outbound SPI's are
   recevied from authenticated notify from an IKE peer.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmUnknownSPI"


/* Max number of bytes to store received ESP/AH packets with unknown
   SPIs. When an unknown SPI value is stored in the system, the
   offending packet will stored for later reprocessing unless this
   limit would be exceeded. */
#ifdef SSH_IPSEC_SMALL
#define SSH_PM_MAX_UNKNOWN_SPI_BYTES 300
#else /* SSH_IPSEC_SMALL */
#define SSH_PM_MAX_UNKNOWN_SPI_BYTES 3000
#endif /* SSH_IPSEC_SMALL */

/* Number of seconds between calls to pm_unknown_spi_tick(). All times
   below are expressed using this unit. */
#define SSH_PM_UNKNOWN_SPI_PERIOD      1

/* Maximum time to keep an SPI error entry in the database. */
#define SSH_PM_UNKNOWN_SPI_LIFETIME   16

/* Time to wait after the first SPI error before counting additional errors */
#define SSH_PM_UNKNOWN_SPI_DELAY       2

/* Lifetime of an SPI error entry after recovery actions have been
   performed. The entry will remain this long in the database catching
   any remaining errors. */
#define SSH_PM_UNKNOWN_SPI_HOLDTIME    4

/* How many SPI errors per entry must be seen before taking actions. */
#define SSH_PM_UNKNOWN_SPI_NUM_ERRORS  2

static void pm_unknown_spi_tick(void *context);

/* Hash function for SPI values. */
#define SSH_PM_SPI_HASH(spi) \
  ((spi) + 3 * ((spi) >> 8) + 7 * ((spi) >> 16) + 11 * ((spi) >> 24))

static SshUInt32
pm_spi_unknown_hash(void *ptr, void *ctx)
{
  SshPmSpiUnknown item = (SshPmSpiUnknown) ptr;

  return SSH_PM_SPI_HASH(item->spi);
}

static int
pm_spi_unknown_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmSpiUnknown item1 = (SshPmSpiUnknown) ptr1;
  SshPmSpiUnknown item2 = (SshPmSpiUnknown) ptr2;

  if (item1->spi != item2->spi)
    return -1;

  if (item1->type != item2->type)
    return -1;

  if (item1->routing_instance_id != item2->routing_instance_id)
    return -1;

  if (item1->ipproto != item2->ipproto)
    return -1;

  if (!SSH_IP_EQUAL(&item1->local_ip, &item2->local_ip))
    return -1;

  if (!SSH_IP_EQUAL(&item1->remote_ip, &item2->remote_ip))
    return -1;

  if (item1->remote_port != item2->remote_port)
    return -1;

 if (item1->ike_sa_handle != item2->ike_sa_handle)
    return -1;

 return 0;
}

static void
pm_spi_unknown_destroy(void *ptr, void *ctx)
{
  return;
}


/* Init ADT container of inbound and unknown SPI's.
   Return TRUE if successful. */
Boolean
ssh_pm_unknown_spis_create(SshPm pm)
{
  pm->unknown_spis =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmSpiUnknownStruct,
                                             adt_header),

                           SSH_ADT_HASH,      pm_spi_unknown_hash,
                           SSH_ADT_COMPARE,   pm_spi_unknown_compare,
                           SSH_ADT_DESTROY,   pm_spi_unknown_destroy,
                           SSH_ADT_CONTEXT,   pm,
                           SSH_ADT_ARGS_END);

  if (pm->unknown_spis == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating SPI freelist"));
      return FALSE;
    }

  pm->unknown_spi_bytes = 0;
  return TRUE;
}

void
ssh_pm_unknown_spis_destroy(SshPm pm)
{
  SshADTHandle h;
  SshPmSpiUnknown spi_unknown;

  ssh_cancel_timeout(&pm->unknown_spi_timer);
  pm->unknown_spi_bytes = 0;

  if (pm->unknown_spis)
    {
      while ((h = ssh_adt_enumerate_start(pm->unknown_spis)) !=
             SSH_ADT_INVALID)
        {
          spi_unknown = ssh_adt_get(pm->unknown_spis, h);
          SSH_ASSERT(spi_unknown != NULL);
          ssh_adt_detach(pm->unknown_spis, h);
          if (spi_unknown->packet)
            {
              ssh_free(spi_unknown->packet);
              spi_unknown->packet = NULL;
              pm->unknown_spi_bytes -= spi_unknown->packet_len;
            }
          ssh_pm_spi_unknown_free(pm, spi_unknown);
        }
      SSH_ASSERT(ssh_adt_num_objects(pm->unknown_spis) == 0);
      ssh_adt_destroy(pm->unknown_spis);
    }
  pm->unknown_spis = NULL;
}




/************************* Unknown SPI management  ***************************/

#define PM_DEBUG_SPI_ADDR(msg, remote_ip, ipproto, spi)         \
  SSH_DEBUG(SSH_D_HIGHOK,                                       \
            (msg " (address %@, protocol %s, spi 0x%08x)",      \
             ssh_ipaddr_render, remote_ip,                      \
             ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",         \
             (unsigned)spi))

#define PM_DEBUG_SPI_PEER(msg, remote_ip, remote_port, ipproto, spi)    \
  SSH_DEBUG(SSH_D_HIGHOK,                                               \
            (msg " (peer %@:%u, protocol %s, spi 0x%08x)",              \
             ssh_ipaddr_render, remote_ip,                              \
             (unsigned)remote_port,                                     \
             ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",                 \
             (unsigned)spi))

#define PM_DEBUG_PEER(msg, remote_ip, remote_port)                      \
  SSH_DEBUG(SSH_D_HIGHOK,                                               \
            (msg " (peer %@:%u)",                                       \
             ssh_ipaddr_render, remote_ip,                              \
             (unsigned)remote_port))

/* Try to find a working IKE SA matching the given peer addresses */
static SshPmP1
pm_find_p1_with_peer(SshPm pm, SshPmSpiUnknown item,
                     SshUInt16 remote_port)
{
  SshPmP1 p1;
  SshUInt32 hash;

  SSH_DEBUG(SSH_D_LOWSTART,
           ("Find IKE SA with local %@ remote %@;%d routing instance id %d",
            ssh_ipaddr_render, &item->local_ip,
            ssh_ipaddr_render, &item->remote_ip, item->remote_port,
            item->routing_instance_id));

  /* Lookup active Phase-1 initiator and responder negotiations. */
  for (p1 = pm->active_p1_negotiations; p1; p1 = p1->n->next)
    {
      if (item->routing_instance_id == p1->ike_sa->server->routing_instance_id
          && !SSH_IP_CMP(&item->local_ip, p1->ike_sa->server->ip_address)
          && !SSH_IP_CMP(&item->remote_ip, p1->ike_sa->remote_ip)
          && remote_port == p1->ike_sa->remote_port)
        return p1;
    }

  /* Check IKE SA hash table. */
  hash = SSH_PM_IKE_PEER_HASH(&item->remote_ip);
  for (p1 = pm->ike_sa_hash[hash]; p1; p1 = p1->hash_next)
    {
      if (p1->failed || p1->unusable || p1->ike_sa->waiting_for_delete)
        continue;

      if (item->routing_instance_id == p1->ike_sa->server->routing_instance_id
          && !SSH_IP_CMP(&item->local_ip, p1->ike_sa->server->ip_address)
          && !SSH_IP_CMP(&item->remote_ip, p1->ike_sa->remote_ip)
          && remote_port == p1->ike_sa->remote_port)
        return p1;
    }

  return NULL;
}

#ifdef SSHDIST_IKEV1
/* Return true if traffic selector includes the given address or is empty. */
static Boolean
pm_ts_allows_addr(SshIkev2PayloadTS ts, SshIpAddr addr)
{
  SshUInt32 i;

  if (ts == NULL || ts->number_of_items_used == 0)
    return TRUE;

  for (i = 0; i < ts->number_of_items_used; i++)
    {
      SshIkev2PayloadTSItem item = &ts->items[i];
      if (!SSH_IP_DEFINED(item->start_address) ||
          (SSH_IP_IS_NULLADDR(item->start_address) &&
           SSH_IP_IS_NULLADDR(item->end_address)) ||
          (SSH_IP_CMP(addr, item->start_address) >= 0 &&
           SSH_IP_CMP(addr, item->end_address) <= 0))
        return TRUE;
    }

  return FALSE;
}

/* Scan policy rules and try to find one that allows initiating IKE
   SAs using the given IKE peer addresses. */
static SshPmRule
pm_find_rule_to_peer(SshPm pm, SshPmSpiUnknown item)
{
  SshADTHandle handle;
  SshPmRule rule;
  SshPmTunnel tunnel;
  SshUInt32 i;
  SshPmTunnelLocalIp tunnel_local_ip;

  SSH_DEBUG(SSH_D_LOWSTART,
           ("Find rule for local %@ remote %@:%d routing instance id %d",
            ssh_ipaddr_render, &item->local_ip,
            ssh_ipaddr_render, &item->remote_ip, item->remote_port,
            item->routing_instance_id));


  for (handle = ssh_adt_enumerate_start(pm->rule_by_precedence);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_precedence, handle))
    {
      rule = ssh_adt_get(pm->rule_by_precedence, handle);

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        continue;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      if (SSH_PM_RULE_IS_VIRTUAL_IP(rule))
        continue;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      tunnel = rule->side_to.tunnel;
      if (tunnel == NULL)
        continue;

      /* Skip manually keyed tunnels and tunnels that do not allow
         initiator negotiations. */
      if (!SSH_PM_TUNNEL_IS_IKE(tunnel) ||
          (tunnel->flags & SSH_PM_TI_DONT_INITIATE))
        continue;

      /* Skip tunnels that use IKEv2. In IKEv2 the built-in DPD
         handles crash recovery. For mixed IKEv2&IKEv1 tunnels this
         is problematic, as we do not know what IKE version the peer
         supports. Currently we think it supports IKEv2 and do nothing. */
      if (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2)
        continue;

      if (item->routing_instance_id != tunnel->routing_instance_id)
        continue;

      /* Match local address */
      if (tunnel->local_ip != NULL
          || tunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
          || tunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
          )
        {
          /* Match with configured local address */
          for (tunnel_local_ip = tunnel->local_ip;
               tunnel_local_ip != NULL;
               tunnel_local_ip = tunnel_local_ip->next)
            if (SSH_IP_EQUAL(&item->local_ip, &tunnel_local_ip->ip))
              break;
          if (tunnel_local_ip == NULL)
            continue;
        }
      else
        {
          /* No local addr configured, match with source traffic selectors. */
          if (!pm_ts_allows_addr(rule->side_from.ts, &item->local_ip))
            continue;
        }

      /* Match remote address */
      if (tunnel->num_peers)
        {
          /* Match with configured peer addresses */
          for (i = 0; i < tunnel->num_peers; i++)
            if (SSH_IP_EQUAL(&item->remote_ip, &tunnel->peers[i]))
              break;
          if (i >= tunnel->num_peers)
            continue;
        }
      else
        {
          /* No peer addrs configured, match with dest traffic selectors. */
          if (!pm_ts_allows_addr(rule->side_to.ts, &item->remote_ip))
            continue;
        }

      /* This rule will do */
      return rule;
    }

  return NULL;
}
#endif /* SSHDIST_IKEV1 */

/* Contact the origin of an unknown SPI if possible. If there is a
   suitable IKE SA, use that for sending an INVALID_SPI
   notification. Otherwise, try to initiate an IKE SA and send an
   empty informational exchange.  */
static void
pm_report_unknown_spi(SshPm pm, SshPmSpiUnknown item)
{
  SshPmP1 p1 = NULL;
#ifdef SSHDIST_IKEV1
  SshPmRule rule;
#endif /* SSHDIST_IKEV1 */
  int slot, i;
  unsigned char remote_str[SSH_IP_ADDR_STRING_SIZE];
  SshPmStatus pm_status = ssh_pm_get_status(pm);


  if ((pm_status == SSH_PM_STATUS_SUSPENDED) ||
      (pm_status == SSH_PM_STATUS_SUSPENDING))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Pm suspending / suspended, ignoring "
                              "report unknown spi."));
      return;
    }

  for (i = 0; i < pm->params.num_ike_ports; i++)
    {
      p1 = pm_find_p1_with_peer(pm, item,
                                pm->params.remote_ike_ports[i]);
      if (p1 != NULL && p1->done)
        break;

      p1 = pm_find_p1_with_peer(pm, item,
                                pm->params.remote_ike_natt_ports[i]);
      if (p1 != NULL && p1->done)
        break;

      p1 = NULL;
    }

  if (p1)
    {
      /* Existing IKE SA. Send an INVALID_SPI notify payload. */
      SshIkev2ExchangeData ed;
      unsigned char spi_buf[4];
      SshIkev2ProtocolIdentifiers protocol_id;

      PM_DEBUG_SPI_PEER("Sending INVALID_SPI notify",
                        &item->remote_ip, p1->ike_sa->remote_port,
                        item->ipproto, item->spi);
      ssh_ipaddr_print(&item->remote_ip, remote_str, sizeof remote_str);
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "Notifying IKE peer %s:%u about invalid %s SPI 0x%08x",
                    remote_str, (unsigned)p1->ike_sa->remote_port,
                    item->ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",
                    (unsigned)item->spi);

      SSH_ASSERT(p1->done);

      if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot send notify payload"));
          return;
        }

      ed = ssh_ikev2_info_create(p1->ike_sa, 0);
      if (ed == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("Cannot allocate exchange data"));
          return;
        }

      if (item->ipproto == SSH_IPPROTO_ESP)
        protocol_id = SSH_IKEV2_PROTOCOL_ID_ESP;
      else
        protocol_id = SSH_IKEV2_PROTOCOL_ID_AH;

      SSH_PUT_32BIT(spi_buf, item->spi);
      if (ssh_ikev2_info_add_n(ed, protocol_id,
                               spi_buf, sizeof spi_buf,
                               SSH_IKEV2_NOTIFY_INVALID_SPI,
                               spi_buf, sizeof spi_buf) != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot add notify payload"));
          ssh_ikev2_info_destroy(ed);
          return;
        }

      ed->application_context = NULL;
      PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
                        ssh_ikev2_info_send(ed,
                                            pm_ike_info_done_callback));
    }
#ifdef SSHDIST_IKEV1
  else if ((rule = pm_find_rule_to_peer(pm, item)))
    {
      /* Start a QM initiator with IKEv1 with `qm->unknown_spi' value
         set. This will cause just an informational exchange to be done
         instead of creating an IPSec SA. */
      SshPmQm qm;

      if ((qm = ssh_pm_qm_alloc(pm, FALSE)) == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate QM"));
          return;
        }

      /* Mark that this rule is being used for a Quick-Mode negotiation. */
      rule->ike_in_progress = 1;
      qm->rule = rule;
      SSH_PM_RULE_LOCK(qm->rule);

      qm->initiator = 1;
      qm->trigger = 0;
      qm->send_trigger_ts = 0;
      qm->forward = 1;
      qm->tunnel = rule->side_to.tunnel;
      SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
      qm->packet = NULL;
      qm->sel_src = item->local_ip;
      qm->sel_dst = item->remote_ip;
      qm->sel_ipproto = item->ipproto;
      qm->unknown_spi = item->spi;
      qm->sa_handler_done = 1; /* no SA handler */

      PM_DEBUG_SPI_ADDR("Initiating IKE SA and informational exchange",
                        &item->remote_ip, item->ipproto, item->spi);
      ssh_ipaddr_print(&item->remote_ip, remote_str, sizeof remote_str);
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                    "Contacting address %s due to unknown %s SPI %08x",
                    remote_str,
                    item->ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",
                    (unsigned)item->spi);

      /* Start a Quick-Mode initiator thread. */
      ssh_fsm_thread_init(&pm->fsm, &qm->thread,
                          ssh_pm_st_qm_i_start_negotiation,
                          NULL_FNPTR, pm_qm_thread_destructor, qm);
      ssh_fsm_set_thread_name(&qm->thread, "Unknown SPI recovery");
    }
#endif /* SSHDIST_IKEV1 */
  else
    {
      PM_DEBUG_SPI_ADDR("Not reporting SPI errors because of no IKE SA "
                        "or suitable rule",
                        &item->remote_ip, item->ipproto, item->spi);
    }
}

/* Find an IKE SA with the given peer addresses and destroy it. */
static void
pm_disconnect_ike_peer(SshPm pm, SshUInt32 ike_sa_handle)
{
  SshPmP1 p1;
  unsigned char remote_str[SSH_IP_ADDR_STRING_SIZE];

  p1 = ssh_pm_p1_from_ike_handle(pm, ike_sa_handle, FALSE);

  if (p1 == NULL || p1->unusable || SSH_PM_P1_DELETED(p1))
    return;

  PM_DEBUG_PEER("Destroying IKE SA due to SPI errors",
                p1->ike_sa->remote_ip, p1->ike_sa->remote_port);
  ssh_ipaddr_print(p1->ike_sa->remote_ip, remote_str, sizeof remote_str);
  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "Destroying IKE SA with peer %s:%u due to SPI errors",
                remote_str, (unsigned)p1->ike_sa->remote_port);

  SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
  SSH_PM_IKEV2_IKE_SA_DELETE(p1, 0,
                             pm_ike_sa_delete_notification_done_callback);
}

/* Record the event that an IPSec SA associated with the given IKE
   peers was deleted because of too many INVALID_SPI notifications. */
static void
pm_invalid_spi_sa_deleted(SshPm pm, SshPmSpiUnknown deleted_item)
{
  SshPmSpiUnknownStruct dummy, *item;
  SshADTHandle h;

  dummy.type = SSH_PM_UNKNOWN_SPI_PEER_ERROR_COUNT;
  dummy.local_ip = deleted_item->local_ip;
  dummy.remote_ip = deleted_item->remote_ip;
  dummy.remote_port = deleted_item->remote_port;
  dummy.ipproto = 0;
  dummy.spi = 0;
  dummy.ike_sa_handle = deleted_item->ike_sa_handle;
  dummy.routing_instance_id = deleted_item->routing_instance_id;

  h = ssh_adt_get_handle_to_equal(pm->unknown_spis, &dummy);
  if (h == SSH_ADT_INVALID)
    {
      /* New source/dest address combination */
      PM_DEBUG_PEER("Recording 1st SPI fault",
                    &deleted_item->remote_ip, deleted_item->remote_port);
      item = ssh_pm_spi_unknown_alloc(pm);
      if (item == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate unknown SPI entry"));
          return;
        }

      item->type = SSH_PM_UNKNOWN_SPI_PEER_ERROR_COUNT;
      item->local_ip = deleted_item->local_ip;
      item->remote_ip = deleted_item->remote_ip;
      item->remote_port = deleted_item->remote_port;
      item->ipproto = 0;
      item->spi = 0;
      item->ike_sa_handle = deleted_item->ike_sa_handle;
      item->routing_instance_id = deleted_item->routing_instance_id;

      /* This entry counts how many times per-SPI entries go off. Use
         a longer lifetime. */
      item->lifetime =
        SSH_PM_UNKNOWN_SPI_LIFETIME *
        SSH_PM_UNKNOWN_SPI_NUM_ERRORS;
      item->age = 0;
      item->count = 1;

      ssh_adt_insert(pm->unknown_spis, item);

      /* Start periodic timer if this was the first entry */
      if (ssh_adt_num_objects(pm->unknown_spis) == 1)
        {
          SSH_ASSERT(!pm->unknown_spi_timer.callback);
          ssh_register_timeout(&pm->unknown_spi_timer,
                               SSH_PM_UNKNOWN_SPI_PERIOD, 0,
                               pm_unknown_spi_tick, pm);
        }
    }
  else
    {
      /* Another packet to previously seen source/dest address combination */
      PM_DEBUG_PEER("Recording another SPI fault",
                    &deleted_item->remote_ip, deleted_item->remote_port);
      item = ssh_adt_get(pm->unknown_spis, h);

      if (item->age > SSH_PM_UNKNOWN_SPI_DELAY)
        item->count++;
    }
}

/* Do aging of unknown SPI entries and perform corrective actions if
   sufficient amount of SPI errors per entry have been received. */
static void
pm_unknown_spi_tick(void *context)
{
  SshPm pm = (SshPm) context;
  SshADTHandle h, hnext;
  SshPmSpiUnknown item;

  /* PM is going down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

  for (h = ssh_adt_enumerate_start(pm->unknown_spis);
       h != SSH_ADT_INVALID;
       h = hnext)
    {
      hnext = ssh_adt_enumerate_next(pm->unknown_spis, h);

      item = ssh_adt_get(pm->unknown_spis, h);
      item->age++;

      if (item->age >= item->lifetime)
        {
          /* Remove expired entry */
          if (item->type == SSH_PM_UNKNOWN_SPI_INBOUND)
            {
              PM_DEBUG_SPI_ADDR("Expiring unknown SPI entry",
                                &item->remote_ip, item->ipproto, item->spi);
            }
          else if (item->type == SSH_PM_UNKNOWN_SPI_OUTBOUND)
            {
              PM_DEBUG_SPI_PEER("Expiring invalid SPI notifies",
                                &item->remote_ip, item->remote_port,
                                item->ipproto, item->spi);
            }
          else /* item->type == SSH_PM_UNKNOWN_SPI_PEER_ERROR_COUNT */
            {
              PM_DEBUG_PEER("Expiring SPI faults",
                            &item->remote_ip, item->remote_port);
            }
          ssh_adt_detach(pm->unknown_spis, h);
          if (item->packet)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,("Discarding saved packet"));
              ssh_free(item->packet);
              item->packet = NULL;
              pm->unknown_spi_bytes -= item->packet_len;
            }
          ssh_pm_spi_unknown_free(pm, item);
        }
      else if (item->done)
        {
          /* Already processed entry */
          continue;
        }
      else if (item->count >= SSH_PM_UNKNOWN_SPI_NUM_ERRORS)
        {
          /* Enough SPI errors detected to take corrective actions. */
          if (item->type == SSH_PM_UNKNOWN_SPI_INBOUND)
            {
              /* Repeated ESP/AH packets with an unknown SPI. Try
                 notifying the peer in some way. */
              pm_report_unknown_spi(pm, item);
              if (item->packet)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,("Discarding saved packet"));
                  ssh_free(item->packet);
                  pm->unknown_spi_bytes -= item->packet_len;
                  item->packet = NULL;
                }
            }
          else if (item->type == SSH_PM_UNKNOWN_SPI_OUTBOUND)
            {
              /* Repeated INVALID_SPI notifies have been received.
                 Destroy IPSec SA. */
              unsigned char remote_str[SSH_IP_ADDR_STRING_SIZE];

              ssh_ipaddr_print(&item->remote_ip,remote_str, sizeof remote_str);
              PM_DEBUG_SPI_PEER("Destroying IPsec SA",
                                &item->remote_ip, item->remote_port,
                                item->ipproto, item->spi);
              ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                            "Destroying IPsec SA with %s SPI 0x%08x reported "
                            "invalid by peer %s:%u",
                            item->ipproto == SSH_IPPROTO_ESP ? "ESP" : "AH",
                            (unsigned)item->spi,
                            remote_str, (unsigned)item->remote_port);
              ssh_pm_delete_by_spi(pm, item->spi, item->routing_instance_id,
                                   item->ipproto,
                                   &item->remote_ip, item->remote_port,
                                   NULL_FNPTR, NULL);

              /* Create a SSH_PM_UNKNOWN_SPI_IKE_ERROR_COUNT item for
                 the deleted SSH_PM_UNKNOWN_SPI_OUTBOUND item. */
              pm_invalid_spi_sa_deleted(pm, item);

            }
          else /* item->type == SSH_PM_UNKNOWN_SPI_IKE_ERROR_COUNT */
            {
              /* Too many IPSec SAs deleted because of INVALID_SPI
                 notifies.  Destroy IKE SA. */
              pm_disconnect_ike_peer(pm, item->ike_sa_handle);
            }
          item->done = 1;
          /* Keep the entry for a while in order to catch possible
             remaining SPI errors. */
          item->lifetime = item->age + SSH_PM_UNKNOWN_SPI_HOLDTIME;
        }
    }

  /* Re-schedule timer if there is something left to age. */
  if (ssh_adt_num_objects(pm->unknown_spis))
    {
      SSH_ASSERT(!pm->unknown_spi_timer.callback);
      ssh_register_timeout(&pm->unknown_spi_timer,
                           SSH_PM_UNKNOWN_SPI_PERIOD, 0,
                           pm_unknown_spi_tick, pm);
    }
}


/* Handle an inbound ESP/AH packet with an unknown SPI. */
void
ssh_pm_unknown_spi_packet(SshPm pm,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshInetIPProtocolID ipproto, SshUInt32 spi,
                          SshInterceptorProtocol protocol,
                          SshUInt32 tunnel_id,
                          SshVriId routing_instance_id,
                          SshUInt32 ifnum, SshUInt32 flags,
                          SshUInt32 prev_transform_index,
                          unsigned char *packet, size_t packet_len)
{
  SshPmSpiUnknownStruct dummy, *item;
  SshADTHandle h;

  dummy.type = SSH_PM_UNKNOWN_SPI_INBOUND;
  dummy.local_ip = *local_ip;
  dummy.remote_ip = *remote_ip;
  dummy.remote_port = 0;
  dummy.ipproto = ipproto;
  dummy.spi = spi;
  dummy.ike_sa_handle = SSH_IPSEC_INVALID_INDEX;
  dummy.routing_instance_id = routing_instance_id;

  h = ssh_adt_get_handle_to_equal(pm->unknown_spis, &dummy);
  if (h == SSH_ADT_INVALID)
    {
      /* New address/protocol/SPI combination */
      PM_DEBUG_SPI_ADDR("Received packet with new unknown SPI",
                        remote_ip, ipproto, spi);
      item = ssh_pm_spi_unknown_alloc(pm);
      if (item == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate unknown SPI entry"));
          ssh_free(packet);
          return;
        }

      item->type = SSH_PM_UNKNOWN_SPI_INBOUND;
      item->local_ip = *local_ip;
      item->remote_ip = *remote_ip;
      item->remote_port = 0;
      item->ipproto = ipproto;
      item->spi = spi;
      item->ike_sa_handle = SSH_IPSEC_INVALID_INDEX;
      item->lifetime = SSH_PM_UNKNOWN_SPI_LIFETIME;
      item->age = 0;
      item->count = 1;
      item->routing_instance_id = routing_instance_id;

      /* Store packet for later reprocessing if possible */
      if (pm->unknown_spi_bytes + packet_len <= SSH_PM_MAX_UNKNOWN_SPI_BYTES)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,("Saving packet for later reprocessing"));
          item->tunnel_id = tunnel_id;
          item->protocol = protocol;
          item->ifnum = ifnum;
          item->prev_transform_index = prev_transform_index;
          item->packet = packet;
          item->packet_len = packet_len;
          pm->unknown_spi_bytes += packet_len;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("No space to save packet"));
          ssh_free(packet);
        }
      ssh_adt_insert(pm->unknown_spis, item);

      /* Start periodic timer if this was the first entry */
      if (ssh_adt_num_objects(pm->unknown_spis) == 1)
        {
          SSH_ASSERT(!pm->unknown_spi_timer.callback);
          ssh_register_timeout(&pm->unknown_spi_timer,
                               SSH_PM_UNKNOWN_SPI_PERIOD, 0,
                               pm_unknown_spi_tick, pm);
        }
    }
  else
    {
      /* Another packet to previously seen address/protocol/SPI */
      PM_DEBUG_SPI_ADDR("Received packet with previously seen unknown SPI",
                        remote_ip, ipproto, spi);
      item = ssh_adt_get(pm->unknown_spis, h);

      if (item->age > SSH_PM_UNKNOWN_SPI_DELAY)
        item->count++;

      /* Drop packet */
      ssh_free(packet);
    }
}




/* Handle authenticated INVALID_SPI notify. */
void
ssh_pm_invalid_spi_notify(SshPm pm, SshUInt32 ike_sa_handle,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshUInt16 remote_port, SshInetIPProtocolID ipproto,
                          SshUInt32 spi)
{
  SshPmSpiUnknownStruct dummy, *item;
  SshADTHandle h;
  SshPmP1 p1;

  p1 = ssh_pm_p1_from_ike_handle(pm, ike_sa_handle, FALSE);
  if (p1 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IKE SA handle 0x%08x",
                            (unsigned long) ike_sa_handle));
      return;
    }

  dummy.type = SSH_PM_UNKNOWN_SPI_OUTBOUND;
  dummy.local_ip = *local_ip;
  dummy.remote_ip = *remote_ip;
  dummy.remote_port = remote_port;
  dummy.ipproto = ipproto;
  dummy.spi = spi;
  dummy.ike_sa_handle = ike_sa_handle;
  dummy.routing_instance_id = p1->ike_sa->server->routing_instance_id;

  h = ssh_adt_get_handle_to_equal(pm->unknown_spis, &dummy);
  if (h == SSH_ADT_INVALID)
    {
      /* New address/protocol/SPI combination */
      PM_DEBUG_SPI_PEER("Received new invalid SPI notify",
                        remote_ip, remote_port, ipproto, spi);
      item = ssh_pm_spi_unknown_alloc(pm);
      if (item == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate unknown SPI entry"));
          return;
        }

      item->type = SSH_PM_UNKNOWN_SPI_OUTBOUND;
      item->local_ip = *local_ip;
      item->remote_ip = *remote_ip;
      item->remote_port = remote_port;
      item->ipproto = ipproto;
      item->spi = spi;
      item->ike_sa_handle = ike_sa_handle;

      item->lifetime = SSH_PM_UNKNOWN_SPI_LIFETIME;
      item->age = 0;
      item->count = 1;
      item->routing_instance_id = p1->ike_sa->server->routing_instance_id;

      ssh_adt_insert(pm->unknown_spis, item);

      /* Start periodic timer if this was the first entry */
      if (ssh_adt_num_objects(pm->unknown_spis) == 1)
        {
          SSH_ASSERT(!pm->unknown_spi_timer.callback);
          ssh_register_timeout(&pm->unknown_spi_timer,
                               SSH_PM_UNKNOWN_SPI_PERIOD, 0,
                               pm_unknown_spi_tick, pm);
        }
    }
  else
    {
      /* Another packet to previously seen address/protocol/SPI */
      PM_DEBUG_SPI_PEER("Received previosly seen invalid SPI notify",
                        remote_ip, remote_port, ipproto, spi);
      item = ssh_adt_get(pm->unknown_spis, h);

      if (item->age > SSH_PM_UNKNOWN_SPI_DELAY)
        item->count++;
    }
}
