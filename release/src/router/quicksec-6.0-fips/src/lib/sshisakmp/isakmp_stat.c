/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp statistics module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshIkeStat"

/* Finds ISAKMP SA related to given negotiation and fills in the
   SshIkeStatistics structure for it. */
SshIkeErrorCode ssh_ike_isakmp_sa_statistics(SshIkeNegotiation negotiation,
                                             SshIkeStatistics statistics)
{
  SshIkeSA sa;
  int i;

  if (negotiation == NULL || negotiation->sa == NULL ||
      negotiation->negotiation_index != -1)
    {
      SSH_DEBUG(7, ("Invalid argument given to ssh_ike_isakmp_sa_statistics"));
      return SSH_IKE_ERROR_INVALID_ARGUMENTS;
    }

  if (negotiation->exchange_type != SSH_IKE_XCHG_TYPE_AGGR &&
      negotiation->exchange_type != SSH_IKE_XCHG_TYPE_IP &&
#ifdef SSHDIST_ISAKMP_CFG_MODE
      negotiation->exchange_type != SSH_IKE_XCHG_TYPE_CFG &&
#endif /* SSHDIST_ISAKMP_CFG_MODE */
      negotiation->exchange_type != SSH_IKE_XCHG_TYPE_INFO)
    {
      SSH_DEBUG(7, ("Invalid exchange type for negotiation in "
                    "ssh_ike_isakmp_sa_statistics"));
      return SSH_IKE_ERROR_INVALID_ARGUMENTS;
    }

  sa = negotiation->sa;
  statistics->pm_info = negotiation->ike_pm_info;
  statistics->phase_1_done = sa->phase_1_done;
  statistics->number_of_negotiations = 0;
  for (i = 0; i < sa->number_of_negotiations; i++)
    {
      if (sa->negotiations[i] != NULL)
        statistics->number_of_negotiations++;
    }

  statistics->private_groups_count = sa->private_groups_count;
  statistics->byte_count = sa->byte_count;
  statistics->created_time = sa->created_time;
  statistics->last_use_time = sa->last_use_time;
  statistics->statistics = sa->statistics;

  statistics->encryption_algorithm_name = sa->encryption_algorithm_name;
  statistics->encryption_key_length = sa->cipher_key_len;
  statistics->hash_algorithm_name = sa->hash_algorithm_name;
  statistics->prf_algorithm_name = sa->prf_algorithm_name;

  statistics->default_retry_limit = sa->retry_limit;
  statistics->default_retry_timer = sa->retry_timer;
  statistics->default_retry_timer_usec = sa->retry_timer_usec;
  statistics->default_retry_timer_max = sa->retry_timer_max;
  statistics->default_retry_timer_max_usec = sa->retry_timer_max_usec;
  statistics->default_expire_timer = sa->expire_timer;
  statistics->default_expire_timer_usec = sa->expire_timer_usec;

  if (negotiation->notification_state ==
      SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
    statistics->caller_notification_sent = TRUE;
  else
    statistics->caller_notification_sent = FALSE;

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE)
    statistics->waiting_for_done = TRUE;
  else
    statistics->waiting_for_done = FALSE;

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE)
    statistics->waiting_for_remove = TRUE;
  else
    statistics->waiting_for_remove = FALSE;

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    statistics->waiting_for_policy_manager = TRUE;
  else
    statistics->waiting_for_policy_manager = FALSE;
  return SSH_IKE_ERROR_OK;
}


/* ssh_ike_foreach_isakmp_sa will call given callback for each ISAKMP SA. */
void ssh_ike_foreach_isakmp_sa(SshIkeServerContext server_context,
                               SshIkeStatisticsCB callback,
                               void *context)
{
  struct SshIkeStatisticsRec stat;
  SshIkeErrorCode err;
  SshADTHandle h, hnext;
  SshIkeSA sa;

  for (h = ssh_adt_enumerate_start(server_context->isakmp_context->
                                  isakmp_sa_mapping);
      h != SSH_ADT_INVALID;
      h = hnext)
    {
      hnext = ssh_adt_enumerate_next(server_context->isakmp_context->
                                     isakmp_sa_mapping, h);

      sa = ssh_adt_map_lookup(server_context->isakmp_context->
                              isakmp_sa_mapping, h);

      if (sa->server_context != server_context)
        continue;
      err = ssh_ike_isakmp_sa_statistics(sa->isakmp_negotiation, &stat);
      if (err != SSH_IKE_ERROR_OK)
        {
          SSH_DEBUG(3, ("Internal error, mapping returned sa, but "
                        "ssh_ike_isakmp_sa_statistics failed for it"));
          continue;
        }
      if (!(*callback)(sa->isakmp_negotiation, &stat, context))
        return;
    }
  return;
}


/* ssh_ike_foreach_isakmp_sa will call given callback for each negotiation
   inside one ISAKMP SA. */
void ssh_ike_foreach_negotiation(SshIkeNegotiation negotiation,
                                 SshIkeNegotiationStatisticsCB callback,
                                 void *context)
{
  struct SshIkeNegotiationStatisticsRec stat;
  int i;
  SshIkeSA sa;
  SshIkeNegotiation neg;

  if (negotiation == NULL || negotiation->sa == NULL)
    return;
  sa = negotiation->sa;
  for (i = 0; i < sa->number_of_negotiations; i++)
    {
      if (sa->negotiations[i] != NULL)
        {
          neg = sa->negotiations[i];
          stat.quick_mode = FALSE;

          switch (neg->exchange_type)
            {
            case SSH_IKE_XCHG_TYPE_NONE:
            case SSH_IKE_XCHG_TYPE_BASE:
            case SSH_IKE_XCHG_TYPE_AO:
            case SSH_IKE_XCHG_TYPE_ANY:
              SSH_DEBUG(3, ("Invalid exchange type in "
                            "ssh_ike_foreach_negotiation"));
              continue;
            case SSH_IKE_XCHG_TYPE_IP:
            case SSH_IKE_XCHG_TYPE_AGGR:
              SSH_DEBUG(3, ("Invalid exchange type (phase 1) in "
                            "ssh_ike_foreach_negotiation"));
              continue;
            case SSH_IKE_XCHG_TYPE_INFO:
              stat.phaseii_pm_info = neg->info_pm_info;
              break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
            case SSH_IKE_XCHG_TYPE_CFG:
              stat.phaseii_pm_info = neg->cfg_pm_info;
              break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
            case SSH_IKE_XCHG_TYPE_QM:
              stat.quick_mode_pm_info = neg->qm_pm_info;
              stat.quick_mode = TRUE;
              break;
            case SSH_IKE_XCHG_TYPE_NGM:
              stat.phaseii_pm_info = neg->ngm_pm_info;
              break;
            }

          if (neg->notification_state ==
              SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
            stat.caller_notification_sent = TRUE;
          else
            stat.caller_notification_sent = FALSE;

          if (neg->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE)
            stat.waiting_for_done = TRUE;
          else
            stat.waiting_for_done = FALSE;

          if (neg->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE)
            stat.waiting_for_remove = TRUE;
          else
            stat.waiting_for_remove = FALSE;

          if (neg->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
            stat.waiting_for_policy_manager = TRUE;
          else
            stat.waiting_for_policy_manager = FALSE;

          if (!(*callback)(neg, &stat, context))
            return;
        }
    }
}

/* Fills statistics with current ike library global statistics. */
void ssh_ike_global_statistics(SshIkeServerContext server,
                               SshIkeGlobalStatistics statistics)
{
  *statistics = *server->statistics;
}
