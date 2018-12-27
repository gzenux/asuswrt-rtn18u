/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initialization of the IKE library. This file also manages the IKE SA
   database for IKEv2 SA's.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#define SSH_DEBUG_MODULE "SshPmSpdIkeInit"

/* Forward declaration */
void ssh_pm_ike_sa_timer(void *context);


static const SshSADInterfaceStruct ssh_pm_sad_interface;

static SshUInt32 pm_ike_sad_ike_sa_hash(const void *p, void *context)
{
  SshIkev2Sa sa = (SshIkev2Sa) p;
  SshUInt32 hash = 0;
  unsigned char *spi;
  int i;

  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    spi = sa->ike_spi_i;
  else
    spi = sa->ike_spi_r;

  for (i = 0; i < sizeof(sa->ike_spi_i); i++)
    {
      hash += spi[i];
      hash += hash << 10;
      hash ^= hash >> 6;
    }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

static int pm_ike_sad_ike_sa_compare(const void *p1, const void *p2,
                                     void *context)
{
  SshIkev2Sa sa1 = (SshIkev2Sa) p1;
  SshIkev2Sa sa2 = (SshIkev2Sa) p2;

  if ((sa1->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) !=
      (sa2->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    return 1;

  if (sa1->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    return memcmp(sa1->ike_spi_i, sa2->ike_spi_i, sizeof(sa1->ike_spi_i));
  else
    return memcmp(sa1->ike_spi_r, sa2->ike_spi_r, sizeof(sa1->ike_spi_r));
}

#ifndef SSH_IPSEC_SMALL

/* Initialize the decaying counter for new IKE connection rate.

   Parameter `alpha' is the percentage of the current counter value
   used in the calculation of the decaying average:

   average_n = ( alpha * current  + (100 - alpha) * average_n-1 ) / 100; */
static void pm_ike_connection_rate_init(SshPm pm, SshUInt32 alpha)
{
  pm->ike_connection_rate.average_value = 0;
  pm->ike_connection_rate.current_value = 0;
  pm->ike_connection_rate.alpha = alpha;
}

/* Update the average new connection rate.
   This function is called in one second intervals from pm_ike_sa_timer(). */
static void pm_ike_connection_rate_update(SshPm pm)
{
  pm->ike_connection_rate.average_value =
    ((pm->ike_connection_rate.alpha * pm->ike_connection_rate.current_value) +
     ((100 - pm->ike_connection_rate.alpha) *
      pm->ike_connection_rate.average_value)) / 100;
  pm->ike_connection_rate.current_value = 0;
}
#endif /* SSH_IPSEC_SMALL */

/*************************** IKE initialization ***************************/


Boolean
ssh_pm_ike_init(SshPm pm)
{
#ifdef SSHDIST_EXTERNALKEY
  SshUInt32 num_providers;
  size_t i;
  SshEkProvider provider_array;
#endif /* SSHDIST_EXTERNALKEY */
#ifdef SSHDIST_IKEV1
  SshIkev2FallbackParamsStruct fallback_params;
#endif /* SSHDIST_IKEV1 */

  SSH_ASSERT(pm->sad_handle != NULL);

#ifdef SSHDIST_IKEV1
  memset(&pm->ike_params.v1_params, 0, sizeof(pm->ike_params.v1_params));
  pm->ike_params.v1_fallback = TRUE;
  pm->ike_params.v1_params->max_isakmp_sa_count = SSH_PM_MAX_IKE_SAS_IKE;
  pm->ike_params.v1_params->spi_size = 0;
  pm->ike_params.v1_params->zero_spi = TRUE;
  pm->ike_params.v1_params->debug_config = &pm->debug_config;
#endif /* SSHDIST_IKEV1 */

  pm->ike_params.audit_context = pm->audit.ike_audit;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  if (!ssh_pm_cm_access_init(pm))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to initialize validator access"));
      return FALSE;
    }
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
  if (!ssh_pm_mscapi_init())
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to initialize MSCAPI"));
      return FALSE;
    }
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Authentication domains */
  if (!ssh_pm_auth_domains_init(pm))
    return FALSE;

#ifdef SSHDIST_EXTERNALKEY
  /* Set the IKE external key parameters */
  pm->ike_params.external_key = pm->externalkey;

  if (!ssh_ek_get_providers(pm->externalkey, &provider_array, &num_providers))
    return FALSE;

  for (i = 0; i < num_providers; i++)
    {
      /* Set the IKE accelerator if one is found. */
      if (provider_array[i].provider_flags &
          SSH_EK_PROVIDER_FLAG_KEY_ACCELERATOR)
        {
          pm->ike_params.accelerator_short_name =
            (provider_array[i]).short_name;
          break;
        }
    }
  ssh_free(provider_array);
#endif /* SSHDIST_EXTERNALKEY */

  pm->ike_params.debug_config = &pm->debug_config;

#ifdef SSHDIST_IPSEC_MOBIKE
  /* Set default mobike rrc policy. */
  ssh_pm_set_mobike_default_rrc_policy(pm,
                                    SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE);
#endif /* SSHDIST_IPSEC_MOBIKE */

  if (!ssh_pm_unknown_spis_create(pm))
    goto error;

  if (!ssh_ikev2_sa_freelist_create(pm->sad_handle) ||
      !ssh_ikev2_conf_freelist_create(pm->sad_handle))
    goto error;

  if ((pm->sad_handle->ike_sa_by_spi =
       ssh_adt_create_generic(SSH_ADT_BAG,
                              SSH_ADT_HEADER,
                              SSH_ADT_OFFSET_OF(SshIkev2SaStruct, sa_header),
                              SSH_ADT_HASH, pm_ike_sad_ike_sa_hash,
                              SSH_ADT_COMPARE, pm_ike_sad_ike_sa_compare,
                              SSH_ADT_ARGS_END)) == NULL)
    goto error;

  pm->sad_interface = (SshSADInterface) &ssh_pm_sad_interface;
  pm->ike_context = ssh_ikev2_create(&pm->ike_params);

  if (pm->ike_context == NULL)
    goto error;

#ifdef SSHDIST_IKEV1
  memset(&fallback_params, 0, sizeof(fallback_params));

  /* Maximum number of simultaneous responder aggressive mode negotiations. */
  fallback_params.max_num_aggr_mode_active = SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS;
  ssh_policy_ikev2_fallback_set_params(pm->ike_context, &fallback_params);
#endif /* SSHDIST_IKEV1 */

  pm->ike_sa_hash_element_next = 0;
  pm->ike_sa_hash_index_next = 0;

#ifndef SSH_IPSEC_SMALL
  pm_ike_connection_rate_init(pm, SSH_PM_IKE_CONNECTION_RATE_DECAY);

  ssh_register_timeout(&pm->ike_sa_timer, 1, 0, ssh_pm_ike_sa_timer, pm);
#endif /* SSH_IPSEC_SMALL */

  return TRUE;

  /* Error handling. */
 error:

  ssh_ikev2_sa_freelist_destroy(pm->sad_handle);
  ssh_ikev2_conf_freelist_destroy(pm->sad_handle);

  if (pm->sad_handle->ike_sa_by_spi)
    {
      ssh_adt_destroy(pm->sad_handle->ike_sa_by_spi);
      pm->sad_handle->ike_sa_by_spi = NULL;
    }

  if (pm->ike_context)
    {
      ssh_ikev2_destroy(pm->ike_context);
      pm->ike_context = NULL;
    }

  if (pm->auth_domains)
    {
      ssh_pm_auth_domains_uninit(pm);
    }

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  ssh_pm_cm_access_uninit(pm);
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
  ssh_pm_mscapi_uninit();
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_pm_unknown_spis_destroy(pm);

  return FALSE;
}

void
ssh_pm_ike_uninit(SshPm pm)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Uninitializing the IKE library"));

  if (pm->sad_handle)
    {
      ssh_ikev2_sa_freelist_destroy(pm->sad_handle);
      ssh_ikev2_conf_freelist_destroy(pm->sad_handle);

      ssh_adt_destroy(pm->sad_handle->ike_sa_by_spi);
    }

  if (pm->ike_context)
    {
      ssh_ikev2_destroy(pm->ike_context);
      pm->ike_context = NULL;
    }

  if (pm->auth_domains)
    {
      ssh_pm_auth_domains_uninit(pm);
      pm->auth_domains = NULL;
    }
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  ssh_pm_cm_access_uninit(pm);
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
  ssh_pm_mscapi_uninit();
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_pm_unknown_spis_destroy(pm);

  ssh_pm_peers_uninit(pm);

  /* Cancel the IKE rekey timer. */
  ssh_cancel_timeout(&pm->ike_sa_timer);
  ssh_cancel_timeout(&pm->ike_sa_half_timer);
  pm->ike_sa_half_timer_registered = 0;

  /* Cancel timer that aborts pending IPSec delete notifications
     during PM shutdown. */
  ssh_cancel_timeout(&pm->delete_timer);
}

/*-----------------------------------------------------------------------*/
/* IKE SA timer. This function is called periodically and it checks the  */
/* IKE SA database to see which IKE SA's should be rekeyed or deleted.   */
/*-----------------------------------------------------------------------*/


/* This timer callback purges half open SA's on the responder side. It
   is started at the new connection callback when the connection is
   accepted, by calling this callback function directly.

   This timeout will die away after there are no active
   negotiations. */

void ssh_pm_ike_sa_half_timer(void *context)
{
  SshPm pm = (SshPm) context;
  SshTime current_time, half_open_expiry_time, last_input;
  SshPmP1 p1, next;
  int num_active_negotiations = 0;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

  current_time = ssh_time();
  pm->ike_sa_half_timer_registered = 0;

  /* If we are closing the maximum number of negotiations,
     start taking half open negotiations down a bit more
     aggressively. */
  if (pm->num_active_p1_negotiations >=
      (SSH_PM_MAX_IKE_SA_NEGOTIATIONS -
       ((SSH_PM_MAX_IKE_SA_NEGOTIATIONS / 10) - 1)))
    half_open_expiry_time = (SSH_PM_IKE_HALF_OPEN_LIFETIME / 3);
  else
    half_open_expiry_time = SSH_PM_IKE_HALF_OPEN_LIFETIME;

  for (p1 = pm->active_p1_negotiations; p1; p1 = next)
    {
      num_active_negotiations++;

      next = p1->n->next;
      if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
#ifdef SSHDIST_IKEV1
          !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
#endif /* SSHDIST_IKEV1 */
          !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
          (p1->ike_sa->ref_cnt == 0))
        {
          last_input = ssh_ikev2_sa_last_input_packet_time(p1->ike_sa);

          /* Half open forced expiry. */
          if (last_input &&
              (last_input < (current_time - half_open_expiry_time) &&
               p1->n->ed && (p1->n->ed->state == SSH_IKEV2_STATE_IKE_INIT_SA ||
                            p1->n->ed->state == SSH_IKEV2_STATE_IKE_AUTH_1ST)))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Deleting half open IKE SA"));
              goto do_delete;
            }

          /* Maximum IKE SA negotiation lifetime. */
          if (last_input && last_input < ((current_time -
                              SSH_PM_IKE_SA_RESPONDER_MAX_NEGOTIATION_TIME)))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Deleting half open IKE SA, negotiation"
                                      " exceeded maximum time limit."));
              goto do_delete;
            }

          /* Special case. Last input time may be zero in the case that
             IKE SA has been created, but for some reason the actual packet
             did not make the IKE window. */
          if (last_input == 0 && (p1->expire_time < current_time))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Deleting half open IKE SA that has zero"
                                      " last packet time. Expiry time %d, "
                                      "current time %d", p1->expire_time,
                                      current_time));
              goto do_delete;
            }

          continue;

        do_delete:

          if (SSH_PM_P1_DELETED(p1))
            continue;

          SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
          SSH_PM_IKEV2_IKE_SA_DELETE(p1,
                                    SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION,
                                    pm_ike_sa_delete_done_callback);
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Have %d active Phase-I negotiations",
                          num_active_negotiations));

  /* Reschedule the timeout, cancelling the previous if it was set. */
  if (pm->num_active_p1_negotiations && pm->ike_sa_half_timer_registered == 0)
    {
      pm->ike_sa_half_timer_registered = 1;
      ssh_register_timeout(&pm->ike_sa_half_timer,
                           SSH_PM_IKE_TIMER_INTERVAL, 0,
                           ssh_pm_ike_sa_half_timer, pm);
    }
}

/* Maximum number of attempts to rekey IKE SA. The IKE SA rekey soft grace
   time is calculated based on the IKE SA rekey attempt count. The first
   rekey attempt triggers at full IKE SA rekey soft grace time seconds
   before IKE SA expiry and subsequent rekey attempts are triggered at
   roughly equal intervals until the IKE SA hard expires. */
#define SSH_PM_MAX_IKE_REKEY_ATTEMPTS 3

SshTime
ssh_pm_ike_sa_soft_grace_time(SshPmP1 p1)
{
  SshTime value;

  /* First calculate time of first soft event time relative to hard expiry.
     For 8 hour lifetime, this equals 288 sec. */
  value = (p1->lifetime / 100);
  if (value < SSH_PM_IKE_SA_SOFT_GRACE_TIME)
    value = SSH_PM_IKE_SA_SOFT_GRACE_TIME;
  if (value > SSH_PM_IKE_SA_SOFT_GRACE_TIME_MAX)
    value = SSH_PM_IKE_SA_SOFT_GRACE_TIME_MAX;

  /* Then calculate time of the rekey_attempt'th soft event. */
  if (p1->rekey_attempt > SSH_PM_MAX_IKE_REKEY_ATTEMPTS)
    return 0;

  value =
    (value * (SSH_PM_MAX_IKE_REKEY_ATTEMPTS - p1->rekey_attempt))
    / SSH_PM_MAX_IKE_REKEY_ATTEMPTS;

  return value;
}

/* This function checks single IKE SA for need to rekey or
   delete. This function can be used as a timeout callback, provided
   IKE SA rekeys would register one timeout for each IKE SA. The IKE
   SA is expected to be the context. */
void ssh_pm_ike_sa_timer_event(SshPm pm,
                               void *context, SshTime comparison_time)
{
  SshPmP1 p1 = context;
  SshUInt32 flags = 0;
  SshUInt32 num_child_sas = 0;

#ifdef SSHDIST_IKEV1
  flags = SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

  SSH_DEBUG(SSH_D_MIDOK, ("IKE SA %p; timer tick", p1));

  if (!SSH_PM_P1_DELETED(p1))
    {
      /* Handle P1's which have a nonexistent tunnel. This might happen in
         some reconfiguration cases. */
      if (p1->tunnel_id == SSH_IPSEC_INVALID_INDEX
          && !pm_ike_async_call_pending(p1->ike_sa))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Deleting IKE SA with invalid tunnel ID (IKE SA %p)",
                     p1));
          goto hard_expire;
        }

      /* Check childless IKE SAs. */
      num_child_sas = ssh_pm_peer_num_child_sas_by_p1(pm, p1);

      /* Set expiry time for childless IKE SAs. */
      if (num_child_sas == 0)
        {
          /* Delete IKE SA immediately if childless SA deletion
             is requested. */
          if (p1->delete_childless_sa == 1)
            goto hard_expire;

          /* Otherwise set childless SA expiry time. */
          else if (p1->childless_sa_expire_time == 0)
            p1->childless_sa_expire_time =
              comparison_time + SSH_PM_IKE_SA_DELETE_TIMEOUT;
        }
      /* Clear expiry time if IKE SA has child SAs. */
      else if (num_child_sas != 0)
        p1->childless_sa_expire_time = 0;

      /* Check childless IKE SA expiry time. */
      if (p1->childless_sa_expire_time != 0)
        {
          if (p1->childless_sa_expire_time <= comparison_time)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Deleting childless IKE SA %p",
                                      p1->ike_sa));
              goto hard_expire;
            }

#ifdef SSH_IPSEC_SMALL
          /* Register IKE SA timer to handle childless SA expiry. */
          SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1,
                                             p1->childless_sa_expire_time,
                                             comparison_time);
#endif /* SSH_IPSEC_SMALL */
        }
    }

#ifdef SSHDIST_IKEV1
  /* IKEv1 SA's are not currently managed by the policy manager. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    return;
#endif /* SSHDIST_IKEV1 */

  /* Handle already deleted IKE SAs. */
  if (SSH_PM_P1_DELETED(p1))
    {
      /* Abort delete operation if it is taking too long. Expire time
         has been set to time of deletion in ssh_pm_ike_sa_delete(). */
      if (p1->expire_time + SSH_PM_IKE_SA_DELETE_TIMEOUT <= comparison_time
          && p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] != NULL)
        {
          SshOperationHandle op;

          SSH_DEBUG(SSH_D_LOWOK, ("Aborting delete operation of IKE SA %p",
                                  p1->ike_sa));

          op = p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE];
          p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;
          ssh_operation_abort(op);
        }
      return;
    }

  SSH_ASSERT(!SSH_PM_P1_DELETED(p1));

  /* Check hard expiry for IKE SAs that have rekey pending. */
  if (p1->expire_time <= comparison_time && p1->rekey_pending)
    goto hard_expire;

  /* Check soft expiry. The soft grace time is calculated from IKE SA
     lifetime. */
  if (p1->expire_time - ssh_pm_ike_sa_soft_grace_time(p1) > comparison_time)
    {
#ifdef SSH_IPSEC_SMALL
      /* Register timeout to IKE SA rekey. */
      if (p1->childless_sa_expire_time != 0
          && (p1->childless_sa_expire_time >
              (p1->expire_time - ssh_pm_ike_sa_soft_grace_time(p1))))
        SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1,
                                           p1->expire_time
                                           - ssh_pm_ike_sa_soft_grace_time(p1),
                                           comparison_time);
#endif /* SSH_IPSEC_SMALL */
      return;
    }

  /* Time to start IKE SA rekey. */

  /* Do we have ongoing operations? */
  if (!p1->rekeyed && p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] == NULL)
    {
#ifdef SSH_PM_BLACKLIST_ENABLED
      /* Do blacklist check for this IKE SA. */
      if (p1->enable_blacklist_check &&
          !ssh_pm_blacklist_check(pm,
                                  p1->remote_id,
                                  SSH_PM_BLACKLIST_CHECK_IKEV2_I_IKE_SA_REKEY))
        {
          /* IKE ID is in the blacklist. Do not start IKE SA rekey. */
          goto check_hard_expiry;
        }
#endif /* SSH_PM_BLACKLIST_ENABLED */

      if (pm_ike_async_call_pending(p1->ike_sa))
        {
          /* There are ongoing initiator negotiations. Mark IKE SA rekey
             pending so that new initiator negotiations are not started.
             When the last negotiation has finished we come back here and
             start the rekey below (or expire the IKE SA in the worst case). */
          SSH_DEBUG(SSH_D_MIDOK, ("Ongoing initiator negotiations, "
                                  "IKE SA %p rekey left pending", p1->ike_sa));
          p1->rekey_pending = 1;
          return;
        }

      /* Ongoing operations have finished. Start IKE SA rekey. */
      if (!p1->unusable && num_child_sas > 0
          && p1->expire_time > comparison_time)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Rekeying IKE SA %p attempt %d",
                                  p1->ike_sa,
                                  p1->rekey_attempt + 1));

#ifdef SSH_IPSEC_SMALL
          /* Register timeout to IKE SA hard expiry. */
          SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1, p1->expire_time,
                                             comparison_time);
#endif /* SSH_IPSEC_SMALL */

          p1->rekey_pending = 0;
          p1->rekey_attempt++;
          p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] =
            ssh_ikev2_ike_sa_rekey(p1->ike_sa, 0,
                                   pm_ike_sa_rekey_done_callback);
          return;
        }
    }

#ifdef SSH_PM_BLACKLIST_ENABLED
 check_hard_expiry:
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /* Check hard expiry. */
  if (p1->expire_time > comparison_time)
    {
#ifdef SSH_IPSEC_SMALL
      /* Register timeout to IKE SA hard expiry. */
      SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1, p1->expire_time, comparison_time);
#endif /* SSH_IPSEC_SMALL */
      return;
    }

  SSH_ASSERT(p1->expire_time <= comparison_time ||
             p1->childless_sa_expire_time <= comparison_time);

 hard_expire:

  /* Already deleted IKE SAs were handled at the start of this function. */
  SSH_ASSERT(!SSH_PM_P1_DELETED(p1));

  /* Abort ongoing rekey, as we are going to delete the IKE SA. */
  if (p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
    {
      SshOperationHandle op;

      SSH_DEBUG(SSH_D_LOWOK,
                ("Aborting rekey of IKE SA %p since hard expiry reached",
                 p1->ike_sa));

      op = p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY];
      p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] = NULL;
      ssh_operation_abort(op);
    }

  /* Delete the IKE SA, unless the rekey was aborted in which case the IKEv2
     library already started deleting the IKE SA. */
  if (!SSH_PM_P1_DELETED(p1))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Deleting expired IKE SA %p", p1->ike_sa));

#ifdef SSH_IPSEC_SMALL
      /* Register timeout to near future for aborting the delete operation. */
      SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1,
                                         comparison_time
                                         + SSH_PM_IKE_SA_DELETE_TIMEOUT,
                                         comparison_time);
#endif /* SSH_IPSEC_SMALL */

      SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags,
                                 pm_ike_sa_delete_notification_done_callback);
    }

  SSH_APE_MARK(1, ("IKE SA expired"));
}


#ifndef SSH_IPSEC_SMALL

/* This timer callback runs over existing IKE SAs and decided if they
   need to be rekeyed or deleted. This always registers itself to be
   run after SSH_PM_IKE_TIMER_INTERVAL. */
void ssh_pm_ike_sa_timer(void *context)
{

  SshPm pm = (SshPm) context;
  SshUInt32 i, hash, index, processed, checked, last_hash_to_process;
  SshTime current_time;
  SshPmP1 p1, next;

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    return;

  /* Skip this timer event if policy manager is suspended or suspending. */
  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    goto register_again;

  current_time = ssh_time();

  /* Check to see which IKE SA's should be rekeyed or deleted. Use
     pm->ike_sa_hash_element_next and pm->ike_sa_hash_index_next to begin
     searching for IKE SA's at the point where they were last processed
     in the previous call to this timeout. */
  hash = pm->ike_sa_hash_element_next;
  index = pm->ike_sa_hash_index_next;
  SSH_ASSERT(hash < SSH_PM_IKE_SA_HASH_TABLE_SIZE);
  p1 = pm->ike_sa_hash[hash];

  if (hash == 0)
    last_hash_to_process = SSH_PM_IKE_SA_HASH_TABLE_SIZE - 1;
  else
    last_hash_to_process = hash - 1;

  for (i = 0; i < index && p1 != NULL; i++)
    p1 = p1->hash_next;

  for (processed = 0, checked = 0;
       checked < SSH_PM_IKE_MAX_TO_CHECK;
       checked++, p1 = next)
    {
      if (p1 && p1->hash_next)
        {
          next = p1->hash_next;
          index++;
        }
      else
        {
          if (hash == last_hash_to_process)
            checked = SSH_PM_IKE_MAX_TO_CHECK;

          index = 0;
          hash++;
          if (hash == SSH_PM_IKE_SA_HASH_TABLE_SIZE)
            hash = 0;
          next = pm->ike_sa_hash[hash];
        }

      if (p1 == NULL)
        continue;

      ssh_pm_ike_sa_timer_event(pm, (void *)p1, current_time);

      if (p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY]
          || p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE])
        processed++;

      if (processed == SSH_PM_IKE_MAX_TO_PROCESS)
        break;
    }

  SSH_ASSERT(hash < SSH_PM_IKE_SA_HASH_TABLE_SIZE);
  pm->ike_sa_hash_element_next = hash;
  pm->ike_sa_hash_index_next = index;

 register_again:
  /* Update the average connection rate counter. */
  pm_ike_connection_rate_update(pm);

  /* Reschedule the timeout. */
  ssh_register_timeout(&pm->ike_sa_timer,
                       SSH_PM_IKE_TIMER_INTERVAL, 0,
                       ssh_pm_ike_sa_timer, pm);
}
#else /* SSH_IPSEC_SMALL */
void ssh_pm_ike_sa_timer(void *context)
{
  SshPmP1 p1 = context;

  /* Delay timer event by 1 second for this IKE SA if policy manager
     is suspended. */
  if (ssh_pm_get_status(p1->pm) != SSH_PM_STATUS_ACTIVE)
    SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1, ssh_time() + 1, ssh_time());
  else
    ssh_pm_ike_sa_timer_event(p1->pm, p1, ssh_time());
}
#endif /* SSH_IPSEC_SMALL */

/*-----------------------------------------------------------------------*/
/* Functions for adding and removing completed IKE SA's to the IKE SA    */
/* database.                                                             */
/*-----------------------------------------------------------------------*/

void
ssh_pm_ike_sa_hash_insert(SshPm pm, SshPmP1 p1)
{
  SshUInt32 hash;

  /* Insert it into the remote IP hash table. */
  SSH_ASSERT(p1->hash_next == NULL);
  SSH_ASSERT(p1->hash_prev == NULL);

  /* Compute the hash value from IKE SA remote IP. Remote IP may be
     undefined but we still want to put the IKE SA to the remote IP
     hash table. */
  hash = SSH_PM_IKE_PEER_HASH(p1->ike_sa->remote_ip);

  p1->hash_next = pm->ike_sa_hash[hash];
  if (pm->ike_sa_hash[hash])
    pm->ike_sa_hash[hash]->hash_prev = p1;

  pm->ike_sa_hash[hash] = p1;

  /* Insert it into the remote ID hash table. */
  SSH_ASSERT(p1->hash_id_next == NULL);
  SSH_ASSERT(p1->hash_id_prev == NULL);

  /* Compute the hash value from IKE SA remote ID. p1->remote_id may
     be NULL in some error cases and we do not want to put such IKE SAs
     to ID hash table. */
  if (p1->remote_id != NULL)
    {
      hash = SSH_PM_IKE_ID_HASH(p1->remote_id);

      p1->hash_id_next = pm->ike_sa_id_hash[hash];
      if (pm->ike_sa_id_hash[hash])
        pm->ike_sa_id_hash[hash]->hash_id_prev = p1;

      pm->ike_sa_id_hash[hash] = p1;
    }
}

void
ssh_pm_ike_sa_hash_remove(SshPm pm, SshPmP1 p1)
{
  SshUInt32 hash;

  /* Remove the Phase-1 SA from the remote IP hash table. */
  if (p1->hash_next)
    p1->hash_next->hash_prev = p1->hash_prev;
  if (p1->hash_prev)
    p1->hash_prev->hash_next = p1->hash_next;
  else
    {
      /* Count the hash value. */
      hash = SSH_PM_IKE_PEER_HASH(p1->ike_sa->remote_ip);

      /* The IKE SA `p1' was in the hash table. */
      if (pm->ike_sa_hash[hash] == p1)
        pm->ike_sa_hash[hash] = p1->hash_next;
    }
  p1->hash_next = NULL;
  p1->hash_prev = NULL;

  /* Remove the Phase-1 SA from the remote ID hash table. */
  if (p1->hash_id_next)
    p1->hash_id_next->hash_id_prev = p1->hash_id_prev;
  if (p1->hash_id_prev)
    p1->hash_id_prev->hash_id_next = p1->hash_id_next;
  else if (p1->remote_id != NULL)
    {
      /* Count the hash value. */
      hash = SSH_PM_IKE_ID_HASH(p1->remote_id);

      /* The IKE SA `p1' was in the hash table. */
      if (pm->ike_sa_id_hash[hash] == p1)
        pm->ike_sa_id_hash[hash] = p1->hash_id_next;
    }
  p1->hash_id_next = NULL;
  p1->hash_id_prev = NULL;
}


/********************* Policy function pointers for IKE *********************/

static const SshSADInterfaceStruct ssh_pm_sad_interface =
  {
    /* SAD (security association database) Functions. */
    ssh_pm_ike_sa_allocate,               /* ike-sa-allocate */
    ssh_pm_ipsec_spi_allocate,            /* ipsec-spi-allocate */
    ssh_pm_ike_sa_delete,                 /* ike-sa-delete */
    ssh_pm_ipsec_spi_delete,              /* ipsec-spi-delete */
    ssh_pm_ipsec_spi_delete_received,     /* ipsec-spi-delete-received */
    ssh_pm_ike_sa_rekey,                  /* ike-sa-rekey */
    ssh_pm_ike_sa_get,                    /* ike-sa-get */
    ssh_pm_ike_sa_take_ref,               /* ike_sa_take_ref */
    ssh_pm_ike_sa_free_ref,               /* ike_sa_free_ref */
    ssh_pm_ike_exchange_data_alloc,       /* exchange_data_alloc */
    ssh_pm_ike_exchange_data_free,        /* exchange_data_free */
    ssh_pm_ike_enumerate,                 /* ike-enumerate */
    ssh_pm_ipsec_sa_install,              /* ipsec-install */
    ssh_pm_ipsec_sa_update,               /* ipsec-update */
    ssh_pm_ike_sa_done,                   /* ike-done */
    ssh_pm_ipsec_sa_done,                 /* ipsec-done */
    /* PAD (peer authorzation database) functions. */
    ssh_pm_ike_new_connection,            /* new-connection */
#ifdef SSHDIST_IKE_REDIRECT
    ssh_pm_ike_redirect,                  /* ike_redirect */
#endif /* SSHDIST_IKE_REDIRECT */
    ssh_pm_ike_id,                        /* id */
#ifdef SSHDIST_IKE_CERT_AUTH
    ssh_pm_ike_get_cas,                   /* get-cas */
    ssh_pm_ike_get_certificates,          /* get-certificates */
    ssh_pm_ike_new_certificate_request,   /* new-cert-request */
    ssh_pm_ike_public_key,                /* public-key */
#endif /* SSHDIST_IKE_CERT_AUTH */
    ssh_pm_ike_pre_shared_key,            /* pre-shared-key */
#ifdef SSHDIST_IKE_CERT_AUTH
    ssh_pm_ike_new_certificate,           /* new-certificate */
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
    ssh_pm_ike_eap_received,              /* eap-received */
    ssh_pm_ike_eap_request,               /* eap-request */
    ssh_pm_ike_eap_key,                   /* eap-shared-key */
#endif /* SSHDIST_IKE_EAP_AUTH */
    ssh_pm_ike_conf_received,             /* conf-received */
    ssh_pm_ike_conf_request,              /* conf-request */
    ssh_pm_ike_received_vendor_id,        /* vendor-id-received */
    ssh_pm_ike_request_vendor_id,         /* vendor-id-request */
#ifdef SSHDIST_IKE_MOBIKE
    ssh_pm_ike_get_address_pair,          /* get_address_pair */
    ssh_pm_ike_get_additional_address_list,/* get_local_address_list */
#endif /* SSHDIST_IKE_MOBIKE */

    /* SPD (security policy database) functions. */
    ssh_pm_ike_spd_fill_ike_sa,           /* fill-ike-sa */
    ssh_pm_ike_spd_fill_ipsec_sa,         /* fill-ipsec-sa */
    ssh_pm_ike_spd_select_ike_sa,         /* select-ike-sa */
    ssh_pm_ike_spd_select_ipsec_sa,       /* select-ipsec-sa */
    ssh_pm_ike_narrow_traffic_selectors,  /* narrow */
    ssh_pm_ike_spd_notify_request,        /* notify-request */
    ssh_pm_ike_spd_notify_received,       /* notify-received */
    ssh_pm_ike_spd_responder_exchange_done /* responder-exchange-done */
#ifdef SSHDIST_IKE_XAUTH
    , ssh_pm_xauth
#endif /* SSHDIST_IKE_XAUTH */
  };
