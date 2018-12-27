/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Engine-side implementation of the engine-policy manager API.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_pm_api_marshal.h"
#include "sshinetencode.h"

#ifdef SSH_IPSEC_TCPENCAP
#include "engine_pm_api_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */

#define SSH_DEBUG_MODULE "SshEnginePmApiEngine"

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

Boolean
ssh_engine_upcall_timeout(SshEngine engine)
{
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  SSH_ASSERT(engine->num_pending_upcall_timeouts > 0);
  engine->num_pending_upcall_timeouts--;
  if (engine->stopped)
    {
      if (engine->num_pending_upcall_timeouts == 0)
        {
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          /* We were the last pending timeout.  We must free the engine
             structure. */
          ssh_engine_stop_now(engine);
        }
      else
        ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      return FALSE;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  return TRUE;
}

void
ssh_engine_record_upcall(SshEngine engine)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  engine->num_pending_upcall_timeouts++;
}

#else /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */


/* Formats the message, and tries to send it to the policy manager.  This
   returns FALSE if sending the message fails (e.g., the queue is full).
   Every argument list should start with SSH_FORMAT_UINT32, (SshUInt32) 0,
   SSH_FORMAT_CHAR, type.  The first integer will be set to the length
   of the resulting packet.  This function can be called concurrently. */



Boolean
ssh_engine_send(SshEngine engine, Boolean locked, Boolean reliable, ...)
{
  va_list ap;
  unsigned char *ucp;
  size_t len;

  /* The `engine->ipm_open' is protected by the
     `engine->flow_control_table_lock' but we can not take it here since this
     function can be called from debug statements both inside and
     outside `engine->flow_control_table_lock' protected blocks.  We are here
     only reading the `ipm_open' flag so the race condition is not
     very likely or harmful.  Also, later we are sending data to the
     engine's send routine and the policy manager connection can be
     already closed so the interceptor must handle (drop) the messages
     send after the policy manager has gone away. */
  if (!engine->ipm_open)
    return FALSE;

  /* WARNING: this function is called from ssh_debug callback, which
     means that no debug functions can be called here or we'll end up
     with infinite recursion. */

  /* Construct the final packet to send to ipm. */
  va_start(ap, reliable);
  len = ssh_encode_array_alloc_va(&ucp, ap);
  va_end(ap);

  /* Out of memory? */
  if (!ucp)
    return FALSE;

  SSH_ASSERT(len >= 5); /* must have at least len+type */

  /* Update the length of the packet. */
  SSH_PUT_32BIT(ucp, len - 4);

  /* Send and/or queue the packet to the ipm.  This will free the buffer. */
  return (*engine->send)(ucp, len, reliable, engine->machine_context);
}

/* Send an initialization error message to the policy manager. */
void
ssh_engine_send_init_error(SshEngine engine)
{
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_INIT_ERROR),
                  SSH_FORMAT_END);
}

/* Send a version message to the policy manager. */
void
ssh_engine_send_version(SshEngine engine)
{
  unsigned char supported_api_calls[64];
  SshUInt32 build_flags;
  SshPmTransform supported_transforms;

  ssh_pm_api_build_flags(&build_flags);
  SSH_VERIFY(ssh_pm_api_supported_api_calls(supported_api_calls,
                                            sizeof(supported_api_calls)));
  ssh_pm_api_supported_transforms(&supported_transforms);

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_VERSION),
                  SSH_ENCODE_UINT32((SshUInt32) SSH_PM_API_RPC_VERSION_MAJOR),
                  SSH_ENCODE_UINT32((SshUInt32) SSH_PM_API_RPC_VERSION_MINOR),
                  SSH_ENCODE_UINT32(build_flags),
                  SSH_ENCODE_UINT32_STR(supported_api_calls,
                                        sizeof(supported_api_calls)),
                  SSH_ENCODE_UINT64(supported_transforms),
                  SSH_ENCODE_UINT32(SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS),
                  SSH_FORMAT_END);
}

/* Send a debugging message to the policy manager. */
void
ssh_engine_send_debug(SshEngine engine, const char *message)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_DEBUG),
                  SSH_ENCODE_UINT32_STR(message, strlen(message)),
                  SSH_FORMAT_END);
}

/* Send a warning message to the policy manager. */
void
ssh_engine_send_warning(SshEngine engine, const char *message)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_WARNING),
                  SSH_ENCODE_UINT32_STR(message, strlen(message)),
                  SSH_FORMAT_END);
}


/********* Completion callbacks for asynchronous engine operations. *********/

void
ssh_engine_status_callback(SshPm pm, Boolean status, void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_STATUS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_BOOLEAN(status),
                  SSH_FORMAT_END);
}

void
ssh_engine_pme_add_rule_callback(SshPm pm, SshUInt32 ind,
                                 const SshEnginePolicyRule rule,
                                 void *context)
{
  SshEngine engine = (SshEngine)pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *rule_buf;
  size_t rule_len;

  rule_buf = NULL;
  rule_len = 0;
  if (rule)
    rule_len = ssh_pm_api_encode_policy_rule(&rule_buf, rule);

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int)SSH_EPA_ADD_RULE_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32(ind),
                  SSH_ENCODE_UINT32_STR(rule_buf, rule_len),
                  SSH_FORMAT_END);

  ssh_free(rule_buf);
}


void
ssh_engine_index_callback(SshPm pm, SshUInt32 ind, void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_INDEX_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32(ind),
                  SSH_FORMAT_END);
}


void
ssh_engine_sa_index_callback(SshPm pm, const SshEnginePolicyRule rule,
                             SshUInt32 transform_index, SshUInt32 outbound_spi,
                             void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *rule_data = NULL;
  size_t rule_data_len = 0;

  if (rule)
    {
      rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
      if (rule_data_len == 0)
        {
          /* An empty rule data will indicate error in the operation. */
          SSH_DEBUG(SSH_D_ERROR, ("Could not encode policy rule"));
          rule_data = NULL;
        }
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_SA_INDEX_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                  SSH_ENCODE_UINT32(transform_index),
                  SSH_ENCODE_UINT32(outbound_spi),
                  SSH_FORMAT_END);

  ssh_free(rule_data);
}

void
ssh_engine_get_audit_event_callback(SshPm pm, Boolean more_events,
                                    SshUInt32 flags, SshUInt32 num_events,
                                    const SshEngineAuditEvent events,
                                    void *context)
{
  SshEngine engine = (SshEngine)pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *event_buf;
  size_t event_len;

  event_buf = NULL;
  event_len = 0;

  if (num_events)
    event_len = ssh_pm_api_encode_engine_audit_events(&event_buf,
                                                      num_events, events);

  if (event_len == 0)
    {
      SSH_ASSERT(event_buf == NULL);
      num_events = 0;
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32)0),
                  SSH_ENCODE_CHAR((unsigned int)SSH_EPA_AUDIT_ENGINE_EVENT),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_BOOLEAN(more_events),
                  SSH_ENCODE_UINT32(flags),
                  SSH_ENCODE_UINT32(num_events),
                  SSH_ENCODE_UINT32_STR(event_buf, event_len),
                  SSH_FORMAT_END);

  if (event_buf)
    ssh_free(event_buf);
}

void
ssh_engine_delete_callback(SshPm pm, Boolean done, SshUInt32 rule_index,
                           SshUInt32 peer_handle, SshEngineTransform tr,
                           void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *encoded_tr = NULL;
  size_t encoded_tr_len = 0;

  if (tr != NULL)
    {
      encoded_tr_len = ssh_pm_api_encode_transform_data(&encoded_tr, tr);
      if (encoded_tr_len == 0)
        SSH_DEBUG(SSH_D_FAIL, ("Failed to encode transform data"));
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_DELETE_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_BOOLEAN(done),
                  SSH_ENCODE_UINT32(rule_index),
                  SSH_ENCODE_UINT32(peer_handle),
                  SSH_ENCODE_UINT32_STR(encoded_tr, encoded_tr_len),
                  SSH_FORMAT_END);

  ssh_free(encoded_tr);
}



void
ssh_engine_delete_transform_callback(SshPm pm, Boolean done,
                                     SshUInt32 peer_handle,
                                     SshEngineTransform tr,
                                     void *policy_context,
                                     void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *encoded_tr = NULL;
  size_t encoded_tr_len = 0;

  if (tr != NULL)
    {
      encoded_tr_len = ssh_pm_api_encode_transform_data(&encoded_tr, tr);
      if (encoded_tr_len == 0)
        SSH_DEBUG(SSH_D_FAIL, ("Failed to encode transform data"));
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_DELETE_TRANSFORM_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_BOOLEAN(done),
                  SSH_ENCODE_UINT32(peer_handle),
                  SSH_ENCODE_UINT32_STR(encoded_tr, encoded_tr_len),
                  SSH_ENCODE_UINT32_STR((const unsigned char *)
                  &policy_context, sizeof(policy_context)),
                  SSH_FORMAT_END);

  ssh_free(encoded_tr);
}

void
ssh_engine_rule_callback(SshPm pm, const SshEnginePolicyRule rule,
                         void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *rule_data = NULL;
  size_t rule_data_len = 0;

  /* Encode policy rule. */
  if (rule)
    {
      rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
      if (rule_data_len == 0)
        {
          /* An empty rule data will indicate error in the operation. */
          SSH_DEBUG(SSH_D_ERROR, ("Could not encode policy rule"));
          rule_data = NULL;
        }
    }

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_GET_RULE_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                  SSH_FORMAT_END);

  ssh_free(rule_data);
}


void
ssh_engine_transform_callback(SshPm pm, const SshEngineTransform trd,
                              void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *trd_data = NULL;
  size_t trd_data_len = 0;

  /* Encode transform data. */
  if (trd)
    {
      trd_data_len = ssh_pm_api_encode_transform_data(&trd_data, trd);
      if (trd_data_len == 0)
        {
          /* An empty transform data will indicate error in the
             operation. */
          SSH_DEBUG(SSH_D_ERROR, ("Could not encode transform data"));
          trd_data = NULL;
        }
    }

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_GET_TRANSFORM_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(trd_data, trd_data_len),
                  SSH_FORMAT_END);

  ssh_free(trd_data);
}

#ifdef SSH_IPSEC_STATISTICS
void
ssh_engine_global_stats_callback(SshPm pm,
                                 const SshEngineGlobalStats engine_stats,
                                 const SshFastpathGlobalStats fastpath_stats,
                                 void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  SshEngineGlobalStatsStruct e_stats;
  SshFastpathGlobalStatsStruct f_stats;
  unsigned char in_octets_comp[8];
  unsigned char in_octets_uncomp[8];
  unsigned char out_octets_comp[8];
  unsigned char out_octets_uncomp[8];
  unsigned char forwarded_octets_comp[8];
  unsigned char forwarded_octets_uncomp[8];
  unsigned char in_packets[8];
  unsigned char out_packets[8];
  unsigned char forwarded_packets[8];
  unsigned char counters[SSH_ENGINE_NUM_GLOBAL_STATS * sizeof(SshUInt32)];
  unsigned char *stats_data = NULL;
  size_t stats_data_len = 0;
  Boolean have_e_stats, have_f_stats;
  int i;

  if (engine_stats)
    {
      have_e_stats = TRUE;
      memcpy(&e_stats, engine_stats, sizeof(e_stats));
    }
  else
    {
      have_e_stats = FALSE;
      memset(&e_stats, 0, sizeof(e_stats));
    }

  if (fastpath_stats)
    {
      have_f_stats = TRUE;
      memcpy(&f_stats, fastpath_stats, sizeof(f_stats));
    }
  else
    {
      have_f_stats = FALSE;
      memset(&f_stats, 0, sizeof(f_stats));
    }
  /* Encode 64 bit values. */
  ssh_pm_api_encode_uint64(in_octets_comp, f_stats.in_octets_comp);
  ssh_pm_api_encode_uint64(in_octets_uncomp, f_stats.in_octets_uncomp);
  ssh_pm_api_encode_uint64(out_octets_comp, f_stats.out_octets_comp);
  ssh_pm_api_encode_uint64(out_octets_uncomp, f_stats.out_octets_uncomp);
  ssh_pm_api_encode_uint64(forwarded_octets_comp,
                           f_stats.forwarded_octets_comp);
  ssh_pm_api_encode_uint64(forwarded_octets_uncomp,
                           f_stats.forwarded_octets_uncomp);
  ssh_pm_api_encode_uint64(in_packets, f_stats.in_packets);
  ssh_pm_api_encode_uint64(out_packets, f_stats.out_packets);
  ssh_pm_api_encode_uint64(forwarded_packets, f_stats.forwarded_packets);

  /* Encode counters. */
  for (i = 0; i < SSH_ENGINE_NUM_GLOBAL_STATS; i++)
    SSH_PUT_32BIT(counters + i * sizeof(SshUInt32), f_stats.counters[i]);

  stats_data_len = ssh_encode_array_alloc(
                       &stats_data,
                       SSH_ENCODE_BOOLEAN(have_e_stats),
                       SSH_ENCODE_BOOLEAN(have_f_stats),
                       SSH_ENCODE_DATA(in_octets_comp, 8),
                       SSH_ENCODE_DATA(in_octets_uncomp, 8),
                       SSH_ENCODE_DATA(out_octets_comp, 8),
                       SSH_ENCODE_DATA(out_octets_uncomp, 8),
                       SSH_ENCODE_DATA(forwarded_octets_comp, 8),
                       SSH_ENCODE_DATA(forwarded_octets_uncomp, 8),
                       SSH_ENCODE_DATA(in_packets, 8),
                       SSH_ENCODE_DATA(out_packets, 8),
                       SSH_ENCODE_DATA(forwarded_packets, 8),

                       SSH_ENCODE_UINT32(e_stats.active_nexthops),
                       SSH_ENCODE_UINT32(e_stats.total_nexthops),
                       SSH_ENCODE_UINT32(e_stats.out_of_nexthops),

                       SSH_ENCODE_UINT32(e_stats.active_flows),
                       SSH_ENCODE_UINT32(e_stats.total_flows),
                       SSH_ENCODE_UINT32(e_stats.out_of_flows),

                       SSH_ENCODE_UINT32(e_stats.active_transforms),
                       SSH_ENCODE_UINT32(e_stats.total_transforms),
                       SSH_ENCODE_UINT32(e_stats.out_of_transforms),

                       SSH_ENCODE_UINT32(f_stats.active_transform_contexts),
                       SSH_ENCODE_UINT32(f_stats.total_transform_contexts),
                       SSH_ENCODE_UINT32(f_stats.out_of_transform_contexts),

                       SSH_ENCODE_UINT32(f_stats.active_packet_contexts),
                       SSH_ENCODE_UINT32(f_stats.out_of_packet_contexts),
                       SSH_ENCODE_UINT32(e_stats.out_of_arp_cache_entries),

                       SSH_ENCODE_UINT32(e_stats.total_rekeys),
                       SSH_ENCODE_UINT32(e_stats.active_rules),
                       SSH_ENCODE_UINT32(e_stats.total_rules),

                       SSH_ENCODE_DATA(counters, sizeof(counters)),

                       SSH_ENCODE_UINT32(e_stats.flow_table_size),
                       SSH_ENCODE_UINT32(e_stats.transform_table_size),
                       SSH_ENCODE_UINT32(e_stats.rule_table_size),
                       SSH_ENCODE_UINT32(e_stats.next_hop_table_size),
                       SSH_ENCODE_UINT32(f_stats.packet_context_table_size),
                       SSH_ENCODE_UINT32(f_stats.transform_context_table_size),

                       SSH_ENCODE_UINT32(e_stats.policy_rule_struct_size),
                       SSH_ENCODE_UINT32(e_stats.transform_data_struct_size),
                       SSH_ENCODE_UINT32(
                                       f_stats.transform_context_struct_size),
                       SSH_ENCODE_UINT32(e_stats.flow_struct_size),

                       SSH_ENCODE_UINT32(e_stats.age_callback_interval),
                       SSH_ENCODE_UINT32(e_stats.age_callback_flows),
                       SSH_FORMAT_END);

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_GLOBAL_STATS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(stats_data, stats_data_len),
                  SSH_FORMAT_END);

  ssh_free(stats_data);
}


void
ssh_engine_flow_info_callback(SshPm pm, const SshEngineFlowInfo info,
                              void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *info_data = NULL;
  size_t info_data_len = 0;

  if (info)
    {
      unsigned char src_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
      size_t src_len;
      unsigned char dst_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
      size_t dst_len;
#ifdef SSHDIST_IPSEC_NAT
      unsigned char nat_src_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
      size_t nat_src_len;
      unsigned char nat_dst_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
      size_t nat_dst_len;
#endif /* SSHDIST_IPSEC_NAT */

      src_len = ssh_encode_ipaddr_array(src_buf, sizeof(src_buf), &info->src);
      dst_len = ssh_encode_ipaddr_array(dst_buf, sizeof(dst_buf), &info->dst);
#ifdef SSHDIST_IPSEC_NAT
      nat_src_len = ssh_encode_ipaddr_array(nat_src_buf, sizeof(nat_src_buf),
                                            &info->nat_src);
      nat_dst_len = ssh_encode_ipaddr_array(nat_dst_buf, sizeof(nat_dst_buf),
                                            &info->nat_dst);
#endif /* SSHDIST_IPSEC_NAT */

      info_data_len = ssh_encode_array_alloc(
                        &info_data,

                        SSH_ENCODE_UINT32_STR(src_buf, src_len),
                        SSH_ENCODE_UINT32_STR(dst_buf, dst_len),
                        SSH_ENCODE_UINT32((SshUInt32) info->src_port),
                        SSH_ENCODE_UINT32((SshUInt32) info->dst_port),
                        SSH_ENCODE_UINT32((SshUInt32) info->ipproto),
#ifdef SSHDIST_IPSEC_NAT
                        SSH_ENCODE_UINT32_STR(nat_src_buf, nat_src_len),
                        SSH_ENCODE_UINT32_STR(nat_dst_buf, nat_dst_len),
                        SSH_ENCODE_UINT32((SshUInt32) info->nat_src_port),
                        SSH_ENCODE_UINT32((SshUInt32) info->nat_dst_port),
#endif /* SSHDIST_IPSEC_NAT */
                        SSH_ENCODE_UINT32(info->forward_transform_index),
                        SSH_ENCODE_UINT32(info->reverse_transform_index),
                        SSH_ENCODE_UINT32(info->rule_index),
                        SSH_ENCODE_UINT32(info->protocol_state),
                        SSH_ENCODE_UINT32(info->lru_level),
                        SSH_ENCODE_UINT32(info->idle_time),
                        SSH_ENCODE_UINT32((SshUInt32) info->is_dangling),
                        SSH_ENCODE_UINT32((SshUInt32) info->is_trigger),
                        SSH_ENCODE_UINT32((SshUInt32)
                                            info->routing_instance_id),
                        SSH_FORMAT_END);
    }

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_FLOW_INFO_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(info_data, info_data_len),
                  SSH_FORMAT_END);

  ssh_free(info_data);
}


void
ssh_engine_flow_stats_callback(SshPm pm, const SshEngineFlowStats stats,
                               void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *stats_data = NULL;
  size_t stats_data_len = 0;

  if (stats)
    {
      unsigned char forward_octets[8];
      unsigned char reverse_octets[8];
      unsigned char forward_packets[8];
      unsigned char reverse_packets[8];
      unsigned char drop_packets[8];

      ssh_pm_api_encode_uint64(forward_octets, stats->forward_octets);
      ssh_pm_api_encode_uint64(reverse_octets, stats->reverse_octets);
      ssh_pm_api_encode_uint64(forward_packets, stats->forward_packets);
      ssh_pm_api_encode_uint64(reverse_packets, stats->reverse_packets);
      ssh_pm_api_encode_uint64(drop_packets, stats->drop_packets);


      stats_data_len = ssh_encode_array_alloc(
                        &stats_data,

                        SSH_ENCODE_DATA(forward_octets, 8),
                        SSH_ENCODE_DATA(reverse_octets, 8),
                        SSH_ENCODE_DATA(forward_packets, 8),
                        SSH_ENCODE_DATA(reverse_packets, 8),
                        SSH_ENCODE_DATA(drop_packets, 8),

                        SSH_FORMAT_END);
    }

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_FLOW_STATS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(stats_data, stats_data_len),
                  SSH_FORMAT_END);

  ssh_free(stats_data);
}


void
ssh_engine_transform_stats_callback(SshPm pm,
                                    const SshEngineTransformStats stats,
                                    void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *stats_data = NULL;
  size_t stats_data_len = 0;

  if (stats)
    {
      unsigned char in_octets[8];
      unsigned char out_octets[8];
      unsigned char in_packets[8];
      unsigned char out_packets[8];
      unsigned char drop_packets[8];
      unsigned char num_mac_fails[8];

      ssh_pm_api_encode_uint64(in_octets, stats->data.in_octets);
      ssh_pm_api_encode_uint64(out_octets, stats->data.out_octets);
      ssh_pm_api_encode_uint64(in_packets, stats->data.in_packets);
      ssh_pm_api_encode_uint64(out_packets, stats->data.out_packets);
      ssh_pm_api_encode_uint64(drop_packets, stats->data.drop_packets);
      ssh_pm_api_encode_uint64(num_mac_fails, stats->data.num_mac_fails);

      stats_data_len = ssh_encode_array_alloc(
                        &stats_data,

                        SSH_ENCODE_DATA(in_octets, 8),
                        SSH_ENCODE_DATA(out_octets, 8),
                        SSH_ENCODE_DATA(in_packets, 8),
                        SSH_ENCODE_DATA(out_packets, 8),
                        SSH_ENCODE_DATA(drop_packets, 8),
                        SSH_ENCODE_DATA(num_mac_fails, 8),

                        SSH_ENCODE_UINT32(stats->control.num_rekeys),
                        SSH_ENCODE_UINT32(stats->control.num_flows_active),

                        SSH_FORMAT_END);
    }

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_TRANSFORM_STATS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(stats_data, stats_data_len),
                  SSH_FORMAT_END);

  ssh_free(stats_data);
}


void
ssh_engine_rule_stats_callback(SshPm pm, const SshEngineRuleStats stats,
                               void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char *stats_data = NULL;
  size_t stats_data_len = 0;

  if (stats)
    stats_data_len = ssh_encode_array_alloc(
                        &stats_data,
                        SSH_ENCODE_UINT32(stats->times_used),
                        SSH_ENCODE_UINT32(stats->num_flows_active),
                        SSH_ENCODE_UINT32(stats->num_flows_total),
                        SSH_FORMAT_END);

  /* Send the message. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_RULE_STATS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32_STR(stats_data, stats_data_len),
                  SSH_FORMAT_END);

  ssh_free(stats_data);
}
#endif /* SSH_IPSEC_STATISTICS */

void
ssh_engine_route_callback(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                          const SshIpAddr next_hop, size_t mtu, void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  unsigned char next_hop_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t next_hop_len;

  if (next_hop)
    {
      next_hop_len = ssh_encode_ipaddr_array(next_hop_buf,
                                             sizeof(next_hop_buf), next_hop);
      SSH_ASSERT(next_hop_len != 0);
    }
  else
    {
      next_hop_len = 0;
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_ROUTE_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32(flags),
                  SSH_ENCODE_UINT32((SshUInt32)ifnum),
                  SSH_ENCODE_UINT32_STR(next_hop_buf, next_hop_len),
                  SSH_ENCODE_UINT32((SshUInt32) mtu),
                  SSH_FORMAT_END);
}

void
ssh_engine_route_success_callback(SshPm pm,
                                  SshInterceptorRouteError error,
                                  void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_ROUTE_SUCCESS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32(error),
                  SSH_FORMAT_END);
}

void
ssh_pmp_flow_free_notification(SshPm pm,
                               SshUInt32 flow_index)
{
  SshEngine engine = (SshEngine)pm;

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32)0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_FLOW_FREE),
                  SSH_ENCODE_UINT32(0), /* operation index */
                  SSH_ENCODE_UINT32(flow_index),
                  SSH_FORMAT_END);
}


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
void
ssh_engine_pme_virtual_adapter_status_cb(SshPm pm,
                                         SshVirtualAdapterError error,
                                         SshUInt32 num_adapters,
                                         SshPmeVirtualAdapter adapters,
                                         void *context)
{
  SshEngine engine = (SshEngine) pm;
  SshUInt32 operation_index = SSH_PTR_TO_UINT32(context);
  SshUInt32 i;
  unsigned char *adapter_buffer;
  size_t adapter_size, adapter_buffer_len, len, offset;

  adapter_buffer = NULL;
  adapter_buffer_len = 0;
  if (num_adapters > 0)
    {
      adapter_size = SSH_INTERCEPTOR_IFNAME_SIZE * sizeof(unsigned char)
                     + 4 * sizeof(SshUInt32);
      adapter_buffer = ssh_calloc(num_adapters, adapter_size);
      if (adapter_buffer == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate adapter buffer"));
          return;
        }
      adapter_buffer_len = num_adapters * adapter_size;
      offset = 0;
      for (i = 0; i < num_adapters; i++)
        {
          len = ssh_encode_array(adapter_buffer + offset,
                                 adapter_buffer_len - offset,
                                 SSH_ENCODE_UINT32(adapters[i].adapter_ifnum),
                                 SSH_ENCODE_UINT32(adapters[i].adapter_state),
                                 SSH_ENCODE_UINT32_STR(
                                 adapters[i].adapter_name,
                                 strlen(adapters[i].adapter_name)),
                                 SSH_FORMAT_END);
          if (len == 0)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Could not encode virtual adapters"));
              goto error;
            }

          offset += len;
        }
      adapter_buffer_len = offset;
    }

  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int)
                                  SSH_EPA_VIRTUAL_ADAPTER_STATUS_CB),
                  SSH_ENCODE_UINT32(operation_index),
                  SSH_ENCODE_UINT32(error),
                  SSH_ENCODE_UINT32(num_adapters),
                  SSH_ENCODE_UINT32_STR(adapter_buffer, adapter_buffer_len),
                  SSH_FORMAT_END);

  ssh_free(adapter_buffer);
  return;

 error:
  ssh_free(adapter_buffer);
}
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


static Boolean
engine_verify_state_is_sane(SshEngine engine)
{
  SshEngineTransformControl c_trd;
  SshEnginePolicyRule rule;
  SshUInt32 num_rules_freelist = 0;
  SshUInt32 num_transforms_freelist = 0;
  SshUInt32 index;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Count the number of items on the transform table freelist */
  index = engine->transform_table_freelist;
  while (index != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_ASSERT(index < engine->transform_table_size);

      c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, index);
      SSH_ASSERT(c_trd != NULL);
      num_transforms_freelist++;
      index = c_trd->rules;
    }
  if (num_transforms_freelist != engine->transform_table_size)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Not all transforms are on the freelist, "
                              " %d on freelist, %d total",
                              (int) num_transforms_freelist,
                              (int) engine->transform_table_size));
      goto error;
    }

  /* Count the number of items on the rule table freelist */
  index = engine->rule_table_freelist;
  while (index != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_ASSERT(index < engine->rule_table_size);

      rule = SSH_ENGINE_GET_RULE(engine, index);
      SSH_ASSERT(rule != NULL);
      num_rules_freelist++;
      index = rule->transform_index;
    }

  /* default rules are not on freelist */
  if (num_rules_freelist != engine->rule_table_size -
      SSH_ENGINE_NUM_DEFAULT_RULES)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Not all rules are on the freelist, "
                              " %d on freelist, %ld total",
                              (int) num_rules_freelist,
                              (unsigned long)
                              (engine->rule_table_size -
                               SSH_ENGINE_NUM_DEFAULT_RULES)));
      goto error;
    }

  /* Verify the state of certain hash tables */
  for (index = 0; index < SSH_ENGINE_PEER_HASH_SIZE; index++)
    if (engine->peer_hash[index] != SSH_IPSEC_INVALID_INDEX)
      {
        SSH_DEBUG(SSH_D_ERROR, ("The engine peer hash is uninitiatized"));
        goto error;
      }
  for (index = 0; index < SSH_ENGINE_PEER_HANDLE_HASH_SIZE; index++)
    if (engine->peer_handle_hash[index] != SSH_IPSEC_INVALID_INDEX)
      {
        SSH_DEBUG(SSH_D_ERROR,
                  ("The engine peer handle hash is uninitialized"));
        goto error;
      }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return TRUE;

 error:
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return FALSE;
}

/* The machine-specific main program should call this when the policy
   manager has opened the connection to the engine.  This also
   sends the version packet to the policy manager.  This function can
   be called concurrently with packet/interface callbacks or timeouts. */

void
ssh_engine_notify_ipm_open(SshEngine engine)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Policy manager opened connection"));

  /* Update state information about the policy manager connection. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  SSH_ASSERT(!engine->ipm_open);
  engine->ipm_open = TRUE;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Fastpath open */
  fastpath_notify_open(engine->fastpath);

  /* Verify the engine state is sane. If not signal to the policy manager */
  if (!engine_verify_state_is_sane(engine))
    {
      ssh_engine_send_init_error(engine);
      return;
  }

  /* Send a version packet to the policy manager. */
  ssh_engine_send_version(engine);

  /* Send a cached interface list to the policy manager. */
  ssh_pmp_interface_change(engine->pm, &engine->ifs);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Attach virtual adapters to engine. */
  ssh_virtual_adapter_init(engine->interceptor);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
}

/* This function is called whenever the policy manager closes the
   connection to the engine.  This is also called when the
   engine is stopped.  This function can be called concurrently with
   packet/interface callbacks or timeouts. */

void
ssh_engine_notify_ipm_close(SshEngine engine)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Policy manager closed connection"));

  ssh_engine_notify_pm_close(engine);

  /* Set debug level to 0 */
  ssh_debug_set_level_string("*=0");
}























/*************** Processing messages from the policy manager ****************/

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ENGINE_INIT)
{
  SshUInt32 dummy;
  unsigned char *local_ike_ports, *local_ike_natt_ports;
  size_t local_ike_ports_len, local_ike_natt_ports_len;
  unsigned char *remote_ike_ports, *remote_ike_natt_ports;
  size_t remote_ike_ports_len, remote_ike_natt_ports_len;
  int i;
#ifdef SSHDIST_IPSEC_NAT
  SshUInt32 nat_port_range_low;
  SshUInt32 nat_port_range_high;
  SshUInt32 nat_privileged_port_range_low;
  SshUInt32 nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&dummy),
#ifdef SSHDIST_IPSEC_NAT
                       SSH_DECODE_UINT32(&nat_port_range_low),
                       SSH_DECODE_UINT32(&nat_port_range_high),
                       SSH_DECODE_UINT32(&nat_privileged_port_range_low),
                       SSH_DECODE_UINT32(&nat_privileged_port_range_high),
#endif /* SSHDIST_IPSEC_NAT */
                       SSH_DECODE_UINT32_STR_NOCOPY(&local_ike_ports,
                                                    &local_ike_ports_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&local_ike_natt_ports,
                                                    &local_ike_natt_ports_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&remote_ike_ports,
                                                    &remote_ike_ports_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&remote_ike_natt_ports,
                                                &remote_ike_natt_ports_len),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  SSH_ASSERT(local_ike_ports_len == local_ike_natt_ports_len &&
             remote_ike_ports_len == remote_ike_natt_ports_len &&
             local_ike_ports_len == remote_ike_ports_len);
  for (i = 0; i  < local_ike_ports_len / 2; i++)
    {
      engine->local_ike_ports[i] = SSH_GET_16BIT(local_ike_ports + 2 * i);
      engine->local_ike_natt_ports[i] =
        SSH_GET_16BIT(local_ike_natt_ports + 2 * i);
      engine->remote_ike_ports[i] = SSH_GET_16BIT(remote_ike_ports + 2 * i);
      engine->remote_ike_natt_ports[i] =
        SSH_GET_16BIT(remote_ike_natt_ports + 2 * i);
    }
  engine->num_ike_ports = (SshUInt16)i;

  if (dummy != 0)
    return FALSE;

#ifdef SSHDIST_IPSEC_NAT
  /* Copy NAT port range into the engine. */
  engine->nat_normal_low_port = (SshUInt16) nat_port_range_low;
  engine->nat_normal_high_port = (SshUInt16) nat_port_range_high;
  engine->nat_privileged_low_port = (SshUInt16) nat_privileged_port_range_low;
  engine->nat_privileged_high_port =
    (SshUInt16) nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */

  return TRUE;
}


SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ENGINE_SALT)
{
  SshUInt32 salt[4];

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&salt[0]),
                       SSH_DECODE_UINT32(&salt[1]),
                       SSH_DECODE_UINT32(&salt[2]),
                       SSH_DECODE_UINT32(&salt[3]),
                       SSH_FORMAT_END) != data_len)
    return FALSE;




  memcpy(engine->flow_id_salt, salt, sizeof(engine->flow_id_salt));
#ifdef SSH_ENGINE_PRNG
  ssh_engine_random_add_entropy(engine,
                                (unsigned char *)engine->flow_id_salt,
                                sizeof(engine->flow_id_salt));
  ssh_engine_random_stir(engine);
#endif /* SSH_ENGINE_PRNG */

  fastpath_set_salt(engine->fastpath,
                    (unsigned char *)engine->flow_id_salt,
                    sizeof(engine->flow_id_salt));
  return TRUE;
}


SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_POLICY_LOOKUP)
{
  SshUInt32 operation_index;
  Boolean enabled;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_BOOLEAN(&enabled),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  if (enabled)
    ssh_engine_pme_enable_policy_lookup(engine, ssh_engine_status_callback,
                                        context);
  else
    ssh_engine_pme_disable_policy_lookup(engine, ssh_engine_status_callback,
                                         context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_DEBUG)
{
  unsigned char *str;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&str, NULL),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Policy manager is kind enough to send null-terminated strings. */
  ssh_debug_set_level_string(ssh_sstr(str));

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_SET_PARAMS)
{
  SshEngineParamsStruct params;
  SshUInt32 is_defined;

  if(ssh_decode_array(data, data_len,
                      SSH_DECODE_UINT32(&is_defined),
                      SSH_DECODE_UINT32(&params.min_ttl_value),
                      SSH_DECODE_BOOLEAN(&params.do_not_decrement_ttl),
                      SSH_DECODE_BOOLEAN(&params.optimize_routing),
                      SSH_DECODE_BOOLEAN(&params.audit_corrupt),
                      SSH_DECODE_BOOLEAN(&params.drop_if_cannot_audit),
                      SSH_DECODE_BOOLEAN(&params.broadcast_icmp),
                      SSH_DECODE_UINT32(&params.audit_total_rate_limit),
                      SSH_DECODE_UINT32(&params.flow_rate_allow_threshold),
                      SSH_DECODE_UINT32(&params.flow_rate_limit_threshold),
                      SSH_DECODE_UINT32(&params.flow_rate_max_share),
                      SSH_DECODE_UINT32(&params.transform_dpd_timeout),
                      SSH_DECODE_UINT32((SshUInt32 *)&params.
                                        fragmentation_policy),
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
                      SSH_DECODE_UINT32(&params.natt_keepalive_interval),
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                      SSH_FORMAT_END) != data_len)
    return FALSE;

  if (is_defined)
    ssh_engine_pme_set_engine_params(engine, &params);
  else
    ssh_engine_pme_set_engine_params(engine, NULL);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_PROCESS_PACKET)
{
  SshUInt32 tunnel_id;
  SshUInt32 protocol;
  SshUInt32 ifnum;
  SshUInt32 flags;
  SshUInt32 prev_transform_index;
  SshUInt32 routing_instance_id;
  unsigned char *packet;
  size_t packet_len;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&tunnel_id),
                       SSH_DECODE_UINT32(&protocol),
                       SSH_DECODE_UINT32(&ifnum),
                       SSH_DECODE_UINT32(&routing_instance_id),
                       SSH_DECODE_UINT32(&flags),
                       SSH_DECODE_UINT32(&prev_transform_index),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &packet, &packet_len),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_engine_pme_process_packet(engine, tunnel_id, protocol,
                                ifnum, (SshVriId) routing_instance_id, flags,
                                prev_transform_index, packet, packet_len);

  return TRUE;
}

#ifdef SSHDIST_IPSEC_NAT

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_SET_INTERFACE_NAT)
{
  SshUInt32 ifnum, type, num_ips, flags;
  unsigned char *int_ip_buf,*ext_ip_buf;
  size_t int_ip_len, ext_ip_len;
  SshIpAddrStruct int_ip, ext_ip;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&ifnum),
                       SSH_DECODE_UINT32(&type),
                       SSH_DECODE_UINT32(&flags),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &int_ip_buf, &int_ip_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &ext_ip_buf, &ext_ip_len),
                       SSH_DECODE_UINT32(&num_ips),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  memset(&int_ip, 0, sizeof(int_ip));
  memset(&ext_ip, 0, sizeof(ext_ip));

  if (int_ip_buf)
    ssh_decode_ipaddr_array(int_ip_buf, int_ip_len,
                            &int_ip);

  if (ext_ip_buf)
    ssh_decode_ipaddr_array(ext_ip_buf, ext_ip_len,
                            &ext_ip);

  ssh_engine_pme_set_interface_nat(engine, ifnum, (SshPmNatType)type,
                                   (SshPmNatFlags)flags,
                                   &int_ip, &ext_ip, num_ips);

  return TRUE;
}

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_CONFIGURE_INTERNAL_NAT)
{
  SshUInt32 operation_index;
  unsigned char *first;
  size_t first_len;
  unsigned char *last;
  size_t last_len;
  SshIpAddrStruct first_ip, last_ip;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32_STR_NOCOPY(&first, &first_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&last, &last_len),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(first, first_len, &first_ip);
  ssh_decode_ipaddr_array(last, last_len, &last_ip);

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_configure_internal_nat(engine, &first_ip, &last_ip,
                                        ssh_engine_status_callback,
                                        context);


  return TRUE;
}

#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_CREATE_TRANSFORM)
{
  SshUInt32 operation_index;
  SshEngineTransformStruct trd;
  unsigned char *trd_data;
  size_t trd_data_len;
  SshUInt32 life_seconds;
  SshUInt32 life_kilobytes;
  void *context;

  if (ssh_decode_array(
                       data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32_STR_NOCOPY(&trd_data, &trd_data_len),
                       SSH_DECODE_UINT32(&life_seconds),
                       SSH_DECODE_UINT32(&life_kilobytes),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  if (!ssh_pm_api_decode_transform_data(trd_data, trd_data_len, &trd))
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  /* Create transform. */
  ssh_engine_pme_create_transform(engine, &trd, life_seconds, life_kilobytes,
                                  ssh_engine_index_callback,
                                  context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_DELETE_TRANSFORM)
{
  SshUInt32 transform_index;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_engine_pme_delete_transform(engine, transform_index);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_REKEY_INBOUND)
{
  SshUInt32 operation_index;
  SshUInt32 transform_index;
  SshUInt32 new_in_spis[3];
  unsigned char keymat_in[SSH_IPSEC_MAX_KEYMAT_LEN / 2];
  SshUInt32 life_seconds;
  SshUInt32 life_kilobytes;
  SshUInt32 flags;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_DECODE_UINT32(&new_in_spis[0]),
                       SSH_DECODE_UINT32(&new_in_spis[1]),
                       SSH_DECODE_UINT32(&new_in_spis[2]),

                       SSH_DECODE_DATA(
                       keymat_in, SSH_IPSEC_MAX_KEYMAT_LEN / 2),

                       SSH_DECODE_UINT32(&life_seconds),
                       SSH_DECODE_UINT32(&life_kilobytes),
                       SSH_DECODE_UINT32(&flags),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_rekey_transform_inbound(engine, transform_index,
                                         new_in_spis, keymat_in,
                                         life_seconds, life_kilobytes,
                                         flags,
                                         ssh_engine_transform_callback,
                                         context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_REKEY_OUTBOUND)
{
  SshUInt32 operation_index;
  SshUInt32 transform_index;
  SshUInt32 new_out_spis[3];
  unsigned char keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN / 2];
#ifdef SSH_IPSEC_TCPENCAP
  unsigned char *tcp_encaps_conn_spi;
  size_t tcp_encaps_conn_spi_len = 0;
#endif /* SSH_IPSEC_TCPENCAP */
  SshUInt32 flags;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_DECODE_UINT32(&new_out_spis[0]),
                       SSH_DECODE_UINT32(&new_out_spis[1]),
                       SSH_DECODE_UINT32(&new_out_spis[2]),

                       SSH_DECODE_DATA(
                       keymat_out, SSH_IPSEC_MAX_KEYMAT_LEN / 2),
#ifdef SSH_IPSEC_TCPENCAP
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &tcp_encaps_conn_spi, &tcp_encaps_conn_spi_len),
#endif /* SSH_IPSEC_TCPENCAP */
                       SSH_DECODE_UINT32(&flags),

                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_rekey_transform_outbound(engine, transform_index,
                                          new_out_spis, keymat_out,
#ifdef SSH_IPSEC_TCPENCAP
                                          (tcp_encaps_conn_spi_len ?
                                           tcp_encaps_conn_spi : NULL),
#endif /* SSH_IPSEC_TCPENCAP */
                                          flags,
                                          ssh_engine_status_callback,
                                          context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_REKEY_INVALIDATE_OLD_INBOUND)
{
  SshUInt32 operation_index;
  SshUInt32 transform_index;
  SshUInt32 inbound_spi;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_DECODE_UINT32(&inbound_spi),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_transform_invalidate_old_inbound(engine,
                                                 transform_index,
                                                 inbound_spi,
                                                 ssh_engine_transform_callback,
                                                 context);
  return TRUE;
}

#ifdef SSHDIST_L2TP

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_UPDATE_L2TP)
{
  SshUInt32 transform_index;
  SshUInt32 flags;
  SshUInt32 local_tunnel_id;
  SshUInt32 local_session_id;
  SshUInt32 remote_tunnel_id;
  SshUInt32 remote_session_id;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_DECODE_UINT32(&flags),
                       SSH_DECODE_UINT32(&local_tunnel_id),
                       SSH_DECODE_UINT32(&local_session_id),
                       SSH_DECODE_UINT32(&remote_tunnel_id),
                       SSH_DECODE_UINT32(&remote_session_id),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_engine_pme_update_transform_l2tp_info(engine, transform_index,
                                            (SshUInt8) flags,
                                            (SshUInt16) local_tunnel_id,
                                            (SshUInt16) local_session_id,
                                            (SshUInt16) remote_tunnel_id,
                                            (SshUInt16) remote_session_id);
  return TRUE;
}

#endif /* SSHDIST_L2TP */


SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ADD_RULE)
{
  SshUInt32 operation_index;
  SshEnginePolicyRuleStruct rule;
  Boolean rekey;
  unsigned char *rule_data;
  size_t rule_data_len;
  void *context;

  if (ssh_decode_array(
                data, data_len,
                SSH_DECODE_UINT32(&operation_index),
                SSH_DECODE_BOOLEAN(&rekey),
                SSH_DECODE_UINT32_STR_NOCOPY(&rule_data, &rule_data_len),
                SSH_FORMAT_END) != data_len)
    return FALSE;

  if (!ssh_pm_api_decode_policy_rule(rule_data, rule_data_len, &rule))
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  /* Add rule. */
  ssh_engine_pme_add_rule(engine, rekey, &rule,
                          ssh_engine_pme_add_rule_callback,
                          context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_DELETE_RULE)
{
  SshUInt32 operation_index;
  SshUInt32 rule_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&rule_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_delete_rule(engine, rule_index,
                             ssh_engine_delete_callback,
                             context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_FIND_TRANSFORM_RULE)
{
  SshUInt32 operation_index;
  SshUInt32 tunnel_id;
  SshUInt32 ifnum;
  unsigned char *src;
  size_t src_len;
  unsigned char *dst;
  size_t dst_len;
  SshUInt32 ipproto;
  SshUInt32 src_port;
  SshUInt32 dst_port;
  SshUInt32 impl_tunnel_id;
  SshUInt32 trd_index;
  SshUInt32 flags;
  SshIpAddrStruct src_ip, dst_ip;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&tunnel_id),
                       SSH_DECODE_UINT32(&ifnum),
                       SSH_DECODE_UINT32_STR_NOCOPY(&src, &src_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&dst, &dst_len),
                       SSH_DECODE_UINT32(&ipproto),
                       SSH_DECODE_UINT32(&src_port),
                       SSH_DECODE_UINT32(&dst_port),
                       SSH_DECODE_UINT32(&impl_tunnel_id),
                       SSH_DECODE_UINT32(&trd_index),
                       SSH_DECODE_UINT32(&flags),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(src, src_len, &src_ip);
  ssh_decode_ipaddr_array(dst, dst_len, &dst_ip);

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_find_transform_rule(engine, tunnel_id, ifnum,
                                     &src_ip, &dst_ip,
                                     (SshUInt8)ipproto,
                                     (SshUInt16)src_port, (SshUInt16)dst_port,
                                     impl_tunnel_id, trd_index, flags,
                                     ssh_engine_sa_index_callback,
                                     context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_FIND_MATCHING_TRANSFORM_RULE)
{
  SshUInt32 operation_index;
  SshEnginePolicyRuleStruct rule;
  unsigned char *rule_data, *peer_ip_buf, *local_ip_buf, *peer_id;
  size_t rule_data_len, peer_ip_len, local_ip_len, peer_id_len;
  SshPmTransform transform;
  SshUInt32 flags, cipher_key_size;
  SshIpAddrStruct peer_ip_struct, local_ip_struct;
  SshIpAddr peer_ip, local_ip;
  SshUInt32 local_port, remote_port;
  void *context;

  peer_id = NULL;

  if (ssh_decode_array(
                data, data_len,
                SSH_DECODE_UINT32(&operation_index),
                SSH_DECODE_UINT32_STR_NOCOPY(&rule_data, &rule_data_len),
                SSH_DECODE_UINT64(&transform),
                SSH_DECODE_UINT32(&cipher_key_size),
                SSH_DECODE_UINT32_STR_NOCOPY(&peer_ip_buf, &peer_ip_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&local_ip_buf, &local_ip_len),
                SSH_DECODE_UINT32(&local_port),
                SSH_DECODE_UINT32(&remote_port),
                SSH_DECODE_UINT32_STR_NOCOPY(&peer_id, &peer_id_len),
                SSH_DECODE_UINT32(&flags),
                SSH_FORMAT_END) != data_len)
    return FALSE;

  if (!ssh_pm_api_decode_policy_rule(rule_data, rule_data_len, &rule))
    return FALSE;

  if (peer_ip_len != 0)
    {
      ssh_decode_ipaddr_array(peer_ip_buf, peer_ip_len, &peer_ip_struct);
      peer_ip = &peer_ip_struct;
    }
  else
    peer_ip = NULL;

  if (local_ip_len != 0)
    {
      ssh_decode_ipaddr_array(local_ip_buf, local_ip_len, &local_ip_struct);
      local_ip = &local_ip_struct;
    }
  else
    local_ip = NULL;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  SSH_ASSERT(peer_id_len == 0 || peer_id_len == SSH_ENGINE_PEER_ID_SIZE);

  if (peer_id_len == 0)
    peer_id = NULL;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  context = SSH_UINT32_TO_PTR(operation_index);

  /* Do the search. */
  ssh_engine_pme_find_matching_transform_rule(
                                      engine, &rule,
                                      transform,
                                      cipher_key_size,
                                      peer_ip, local_ip,
                                      (SshUInt16) local_port,
                                      (SshUInt16) remote_port,
                                      peer_id, flags,
                                      ssh_engine_sa_index_callback,
                                      context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_HAVE_TRANSFORM_WITH_PEER)
{
  SshUInt32 operation_index;
  unsigned char *peer;
  size_t peer_len;
  SshUInt32 peer_ike_port;
  SshIpAddrStruct peer_ip;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32_STR_NOCOPY(&peer, &peer_len),
                       SSH_DECODE_UINT32(&peer_ike_port),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(peer, peer_len, &peer_ip);

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_have_transform_with_peer(engine, &peer_ip,
                                          (SshUInt16)peer_ike_port,
                                          ssh_engine_status_callback,
                                          context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_DELETE_BY_SPI)
{
  SshUInt32 operation_index, trd_index;
  Boolean async_op;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_BOOLEAN(&async_op),
                       SSH_DECODE_UINT32(&trd_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  if (async_op)
    ssh_engine_pme_delete_by_spi(engine, trd_index,
                                 ssh_engine_transform_callback,
                                 context);
  else
    ssh_engine_pme_delete_by_spi(engine, trd_index,
                                 NULL_FNPTR,
                                 NULL);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_UPDATE_BY_PEER_HANDLE)
{
  Boolean async_op, enable_natt;
  unsigned char *remote, *local;
  SshUInt32 peer_handle;
  size_t remote_len, local_len;
  SshIpAddrStruct remote_ip, local_ip;
  SshUInt32 remote_port;
  SshUInt32 routing_instance_id;
#ifdef SSH_IPSEC_TCPENCAP
  unsigned char *tcp_encaps_conn_spi;
  size_t tcp_encaps_conn_spi_len = 0;
#endif /* SSH_IPSEC_TCPENCAP */
  SshUInt32 operation_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_BOOLEAN(&async_op),
                       SSH_DECODE_UINT32(&peer_handle),
                       SSH_DECODE_BOOLEAN(&enable_natt),
                       SSH_DECODE_UINT32(&routing_instance_id),
                       SSH_DECODE_UINT32_STR_NOCOPY(&local, &local_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&remote, &remote_len),
                       SSH_DECODE_UINT32(&remote_port),
#ifdef SSH_IPSEC_TCPENCAP
                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &tcp_encaps_conn_spi, &tcp_encaps_conn_spi_len),
#endif /* SSH_IPSEC_TCPENCAP */
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  if (!local_len || !remote_len)
    return FALSE;

  ssh_decode_ipaddr_array(local, local_len, &local_ip);
  ssh_decode_ipaddr_array(remote, remote_len, &remote_ip);

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_update_by_peer_handle(engine,
                                       peer_handle,
                                       enable_natt,
                                       (SshVriId) routing_instance_id,
                                       &local_ip,
                                       &remote_ip,
                                       (SshUInt16) remote_port,
#ifdef SSH_IPSEC_TCPENCAP
                                       (tcp_encaps_conn_spi_len ?
                                        tcp_encaps_conn_spi : NULL),
#endif /* SSH_IPSEC_TCPENCAP */
                                       async_op ? ssh_engine_status_callback :
                                       NULL_FNPTR,
                                       context);
  return TRUE;
}


SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_DELETE_BY_PEER_HANDLE)
{
  Boolean async_op;
  SshUInt32 peer_handle;
  SshUInt32 operation_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_BOOLEAN(&async_op),
                       SSH_DECODE_UINT32(&peer_handle),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  if (async_op)
    ssh_engine_pme_delete_by_peer_handle(engine, peer_handle,
                                         ssh_engine_delete_transform_callback,
                                         context);
  else
    ssh_engine_pme_delete_by_peer_handle(engine, peer_handle,
                                         NULL_FNPTR, NULL);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_RULE)
{
  SshUInt32 operation_index;
  SshUInt32 rule_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&rule_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_rule(engine, rule_index, ssh_engine_rule_callback,
                          context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_TRANSFORM)
{
  SshUInt32 operation_index;
  SshUInt32 trd_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&trd_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_get_transform(engine, trd_index,
                               ssh_engine_transform_callback,
                               context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ADD_REFERENCE_TO_RULE)
{
  SshUInt32 operation_index;
  SshUInt32 rule_index;
  SshUInt32 transform_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&rule_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_add_reference_to_rule(engine, rule_index, transform_index,
                                       ssh_engine_status_callback,
                                       context);
  return TRUE;
}

#ifdef SSH_IPSEC_STATISTICS

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_GLOBAL_STATS)
{
  SshUInt32 operation_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_global_stats(engine, ssh_engine_global_stats_callback,
                                  context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_NEXT_FLOW_INDEX)
{
  SshUInt32 operation_index;
  SshUInt32 flow_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&flow_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_next_flow_index(engine, flow_index,
                                     ssh_engine_index_callback,
                                     context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_FLOW_INFO)
{
  SshUInt32 operation_index;
  SshUInt32 flow_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&flow_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_flow_info(engine, flow_index,
                               ssh_engine_flow_info_callback,
                               context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_FLOW_STATS)
{
  SshUInt32 operation_index;
  SshUInt32 flow_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&flow_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_flow_stats(engine, flow_index,
                                ssh_engine_flow_stats_callback,
                                context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_NEXT_TRANSFORM_INDEX)
{
  SshUInt32 operation_index;
  SshUInt32 transform_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_next_transform_index(engine, transform_index,
                                          ssh_engine_index_callback,
                                          context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_TRANSFORM_STATS)
{
  SshUInt32 operation_index;
  SshUInt32 transform_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&transform_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_transform_stats(engine, transform_index,
                                     ssh_engine_transform_stats_callback,
                                     context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_NEXT_RULE_INDEX)
{
  SshUInt32 operation_index;
  SshUInt32 rule_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&rule_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_get_next_rule_index(engine, rule_index,
                                     ssh_engine_index_callback,
                                     context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_RULE_STATS)
{
  SshUInt32 operation_index;
  SshUInt32 rule_index;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&rule_index),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_get_rule_stats(engine, rule_index,
                                ssh_engine_rule_stats_callback,
                                context);
  return TRUE;
}

#endif /* SSH_IPSEC_STATISTICS */

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ARP_ADD)
{
  SshUInt32 operation_index;
  unsigned char *ip;
  size_t ip_len;
  SshIpAddrStruct ipaddr;
  unsigned char *media_addr;
  size_t media_addr_len;
  SshUInt32 flags, ifnum;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32_STR_NOCOPY(&ip, &ip_len),

                       SSH_DECODE_UINT32(&ifnum),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &media_addr, &media_addr_len),

                       SSH_DECODE_UINT32(&flags),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(ip, ip_len, &ipaddr);

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_arp_add(engine, &ipaddr, ifnum,
                         media_addr, media_addr_len, flags,
                         ssh_engine_status_callback,
                         context);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ARP_REMOVE)
{
  unsigned char *ip;
  size_t ip_len;
  SshIpAddrStruct ipaddr;
  SshUInt32 ifnum;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&ip, &ip_len),
                       SSH_DECODE_UINT32(&ifnum),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(ip, ip_len, &ipaddr);

  ssh_engine_pme_arp_remove(engine, &ipaddr, ifnum);

  return TRUE;
}

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_VIRTUAL_ADAPTER_CONFIGURE)
{
  SshUInt32 operation_index;
  SshUInt32 adapter_ifnum;
  SshUInt32 adapter_state;
  unsigned char *ip = NULL;
  size_t ip_len = 0;
  SshUInt32 num_addresses = 0;
  SshIpAddr addresses = NULL;
  unsigned char *params = NULL;
  size_t params_len = 0;
  SshVirtualAdapterParamsStruct p;
  SshUInt32 i;
  size_t len;
  void *context;

  memset(&p, 0, sizeof(p));

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&adapter_ifnum),
                       SSH_DECODE_UINT32(&adapter_state),
                       SSH_DECODE_UINT32(&num_addresses),
                       SSH_DECODE_UINT32_STR_NOCOPY(&ip, &ip_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&params, &params_len),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Decode addresses. */
  if (ip_len)
    {
      SSH_ASSERT(num_addresses > 0);
      addresses = ssh_calloc(num_addresses, sizeof(*addresses));
      if (addresses == NULL)
        goto error;
      for (i = 0; i < num_addresses; i++)
        {
          len = ssh_decode_ipaddr_array(ip, ip_len, &addresses[i]);
          if (len == 0)
            goto error;
          ip += len;
          ip_len -= len;
        }

      /* A single undefined address "means clear all addresses". */
      if (num_addresses == 1 && !SSH_IP_DEFINED(&addresses[0]))
        num_addresses = 0;
    }

  /* Decode params */
  if (params_len)
    {
      if (!ssh_virtual_adapter_param_decode(&p, params, params_len))
        goto error;
    }

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_virtual_adapter_configure(engine,
                                      adapter_ifnum,
                                      (SshVirtualAdapterState) adapter_state,
                                      num_addresses, addresses,
                                      (params_len ? &p : NULL),
                                      ssh_engine_pme_virtual_adapter_status_cb,
                                      context);

  /* Cleanup. */
  ssh_free(p.dns_ip);
  ssh_free(p.wins_ip);
  ssh_free(p.win_domain);
  ssh_free(addresses);

  /* All done. */
  return TRUE;

  /* Error handling. */
 error:
  ssh_free(addresses);

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_virtual_adapter_status_cb((SshPm) engine,
                                       SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR,
                                       0, NULL,
                                       context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_VIRTUAL_ADAPTER_LIST)
{
  SshUInt32 operation_index;
  SshUInt32 adapter_ifnum;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&adapter_ifnum),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);
  ssh_engine_pme_virtual_adapter_list(engine,
                                      adapter_ifnum,
                                      ssh_engine_pme_virtual_adapter_status_cb,
                                      context);
  return TRUE;
}

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */




SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ROUTE)
{
  SshUInt32 operation_index;
  SshUInt32 flags;
  SshInterceptorRouteKeyStruct key;
  unsigned char *dst, *src;
  size_t dst_len, src_len;
  SshUInt32 key_selector;
  SshUInt32 key_ipproto;
  void *context;

  if (ssh_decode_array(data, data_len,
                SSH_DECODE_UINT32(&operation_index),
                SSH_DECODE_UINT32(&flags),
                SSH_DECODE_UINT32_STR_NOCOPY(&dst, &dst_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&src, &src_len),
                SSH_DECODE_UINT32(&key_ipproto),
                SSH_DECODE_UINT32(&key.ifnum),
                SSH_DECODE_UINT32(&key_selector),
                SSH_DECODE_UINT16(&key.th.tcp.dst_port),
                SSH_DECODE_UINT16(&key.th.tcp.src_port),
                SSH_DECODE_UINT32((SshUInt32*)(&key.routing_instance_id)),
                SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(dst, dst_len, &key.dst);
  ssh_decode_ipaddr_array(src, src_len, &key.src);

  key.ipproto = (SshInetIPProtocolID) key_ipproto;
  key.selector = (SshUInt32) key_selector;

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_route(engine, flags, &key, ssh_engine_route_callback,
                       context);
  return TRUE;
}

/* Common workhorse for route_add and route_remove */
static Boolean ssh_engine_modify_route(SshEngine engine,
                                       Boolean add,
                                       const unsigned char *data,
                                       size_t data_len)
{
  SshUInt32 operation_index;
  SshInterceptorRouteKeyStruct key;
  unsigned char *key_dst, *key_src, *key_nh, *key_th, *gateway_buf;
  size_t key_dst_len, key_src_len, key_nh_len, key_th_len, gateway_len;
  SshUInt32 key_ipproto, key_ifnum, key_selector;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char *key_ext;
  size_t key_ext_len;
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  SshIpAddrStruct gateway;
  SshUInt32 ifnum, precedence, flags;
  void *context;

  if (ssh_decode_array(
                data, data_len,
                SSH_DECODE_UINT32(&operation_index),

                SSH_DECODE_UINT32_STR_NOCOPY(&key_dst, &key_dst_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&key_src, &key_src_len),
                SSH_DECODE_UINT32(&key_ipproto),
                SSH_DECODE_UINT32(&key_ifnum),
                SSH_DECODE_UINT32_STR_NOCOPY(&key_nh, &key_nh_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&key_th, &key_th_len),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                SSH_DECODE_UINT32_STR_NOCOPY(&key_ext, &key_ext_len),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                SSH_DECODE_UINT32(&key_selector),

                SSH_DECODE_UINT32_STR_NOCOPY(&gateway_buf, &gateway_len),
                SSH_DECODE_UINT32(&ifnum),
                SSH_DECODE_UINT32(&precedence),
                SSH_DECODE_UINT32(&flags),
                SSH_FORMAT_END) != data_len)
    return FALSE;

  /* Fill SshInterceptorRouteKey */
  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);
  ssh_decode_ipaddr_array(key_dst, key_dst_len, &key.dst);
  if (key_selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
    ssh_decode_ipaddr_array(key_src, key_src_len, &key.src);
  else
    SSH_IP_UNDEFINE(&key.src);
  key.ipproto = (SshInetIPProtocolID) key_ipproto;
  key.ifnum = key_ifnum;
  memcpy(&key.nh.raw, key_nh, key_nh_len);
  memcpy(&key.th.raw, key_th, key_th_len);
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SSH_ASSERT(key_ext_len == (4 * SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS));
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    key.extension[i] = SSH_GET_32BIT(key_ext + 4 * i);
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  key.selector = (SshUInt16) key_selector;

  /* Decode gateway address */
  ssh_decode_ipaddr_array(gateway_buf, gateway_len, &gateway);

  context = SSH_UINT32_TO_PTR(operation_index);

  if (add)
    ssh_engine_pme_route_add(engine,
                             &key,
                             &gateway,
                             ifnum,
                             (SshRoutePrecedence) precedence,
                             flags,
                             ssh_engine_route_success_callback,
                             context);
  else
    ssh_engine_pme_route_remove(engine,
                                &key,
                                &gateway,
                                ifnum,
                                (SshRoutePrecedence) precedence,
                                flags,
                                ssh_engine_route_success_callback,
                                context);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ROUTE_ADD)
{
  return ssh_engine_modify_route(engine, TRUE, data, data_len);
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_ROUTE_REMOVE)
{
  return ssh_engine_modify_route(engine, FALSE, data, data_len);
}

#ifdef SSH_IPSEC_INTERNAL_ROUTING

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_CONFIGURE_ROUTE_CLEAR)
{
  if (data_len != 0)
    return FALSE;

  ssh_engine_pme_configure_route_clear(engine);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_CONFIGURE_ROUTE_ADD)
{
  SshUInt32 operation_index;
  unsigned char *dst;
  size_t dst_len;
  unsigned char *next_hop;
  size_t next_hop_len;
  SshUInt32 ifnum;
  SshIpAddrStruct dst_ip, next_hop_ip;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32_STR_NOCOPY(&dst, &dst_len),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &next_hop, &next_hop_len),

                       SSH_DECODE_UINT32(&ifnum),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  ssh_decode_ipaddr_array(dst, dst_len, &dst_ip);
  ssh_decode_ipaddr_array(next_hop, next_hop_len, &next_hop_ip);

  context = SSH_UINT32_TO_PTR(operation_index);

  ssh_engine_pme_configure_route_add(engine, &dst_ip, &next_hop_ip, ifnum,
                                     ssh_engine_status_callback,
                                     context);
  return TRUE;
}

#endif /* SSH_IPSEC_INTERNAL_ROUTING */

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_FLOW_SET_STATUS)
{
  SshUInt32 operation_index;
  Boolean async_op;
  SshUInt32 flow_index, status;
  void *context;

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_BOOLEAN(&async_op),
                       SSH_DECODE_UINT32(&flow_index),
                       SSH_DECODE_UINT32(&status),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  /* Switch flow status between "pass/drop packets". */
  if (async_op)
    ssh_engine_pme_flow_set_status(engine, flow_index,
                                   (SshPmeFlowStatus)status,
                                   ssh_engine_status_callback,
                                   context);
  else
    ssh_engine_pme_flow_set_status(engine, flow_index,
                                   (SshPmeFlowStatus)status,
                                   NULL_FNPTR, NULL);

  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_REDO_FLOWS)
{
  ssh_engine_pme_redo_flows(engine);
  return TRUE;
}

SSH_ENGINE_PM_HANDLER_DEFINE(SSH_PEA_GET_AUDIT_EVENTS)
{
  SshUInt32 operation_index;
  SshUInt32 num_events;
  void *context;

  /* Decode the data and give it to the handler. */
  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&operation_index),
                       SSH_DECODE_UINT32(&num_events),
                       SSH_FORMAT_END) != data_len)
    return FALSE;

  context = SSH_UINT32_TO_PTR(operation_index);

  /* Request the engine to send audit events to the PM. */
  ssh_engine_pme_get_audit_events(engine, num_events,
                                  ssh_engine_get_audit_event_callback,
                                  context);
  return TRUE;
}




















/* This function should be called by the machine-dependent main
   program whenever a packet for this engine is received from
   the policy manager.  The data should not contain the 32-bit length
   or the type (they have already been processed at this stage, to
   check for possible machine-specific packets).  The `data' argument
   remains valid until this function returns; it should not be freed
   by this function.  This function can be called concurrently. */

void
ssh_engine_packet_from_ipm(SshEngine engine, SshUInt32 type,
                           const unsigned char *data, size_t data_len)
{
  SshEnginePmApiCallType call_type = (SshEnginePmApiCallType) type;

  SSH_INTERCEPTOR_STACK_MARK();

  switch (call_type)
    {
    case SSH_PEA_ENGINE_INIT:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ENGINE_INIT);
      break;

    case SSH_PEA_ENGINE_SALT:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ENGINE_SALT);
      break;

    case SSH_PEA_POLICY_LOOKUP:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_POLICY_LOOKUP);
      break;

    case SSH_PEA_DEBUG:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_DEBUG);
      break;

    case SSH_PEA_SET_PARAMS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_SET_PARAMS);
      break;

    case SSH_PEA_PROCESS_PACKET:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_PROCESS_PACKET);
      break;

#ifdef SSHDIST_IPSEC_NAT
    case SSH_PEA_SET_INTERFACE_NAT:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_SET_INTERFACE_NAT);
      break;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    case SSH_PEA_CONFIGURE_INTERNAL_NAT:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_CONFIGURE_INTERNAL_NAT);
      break;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

    case SSH_PEA_CREATE_TRANSFORM:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_CREATE_TRANSFORM);
      break;

    case SSH_PEA_DELETE_TRANSFORM:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_DELETE_TRANSFORM);
      break;

    case SSH_PEA_REKEY_INBOUND:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_REKEY_INBOUND);
      break;

    case SSH_PEA_REKEY_OUTBOUND:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_REKEY_OUTBOUND);
      break;

    case SSH_PEA_REKEY_INVALIDATE_OLD_INBOUND:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_REKEY_INVALIDATE_OLD_INBOUND);
      break;

#ifdef SSHDIST_L2TP
    case SSH_PEA_UPDATE_L2TP:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_UPDATE_L2TP);
      break;
#endif /* SSHDIST_L2TP */

    case SSH_PEA_ADD_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ADD_RULE);
      break;

    case SSH_PEA_DELETE_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_DELETE_RULE);
      break;

    case SSH_PEA_FIND_TRANSFORM_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_FIND_TRANSFORM_RULE);
      break;

    case SSH_PEA_FIND_MATCHING_TRANSFORM_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_FIND_MATCHING_TRANSFORM_RULE);
      break;

    case SSH_PEA_HAVE_TRANSFORM_WITH_PEER:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_HAVE_TRANSFORM_WITH_PEER);
      break;

    case SSH_PEA_DELETE_BY_SPI:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_DELETE_BY_SPI);
      break;

    case SSH_PEA_GET_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_RULE);
      break;

    case SSH_PEA_GET_TRANSFORM:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_TRANSFORM);
      break;

    case SSH_PEA_ADD_REFERENCE_TO_RULE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ADD_REFERENCE_TO_RULE);
      break;

#ifdef SSH_IPSEC_STATISTICS
    case SSH_PEA_GET_GLOBAL_STATS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_GLOBAL_STATS);
      break;

    case SSH_PEA_GET_NEXT_FLOW_INDEX:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_NEXT_FLOW_INDEX);
      break;

    case SSH_PEA_GET_FLOW_INFO:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_FLOW_INFO);
      break;

    case SSH_PEA_GET_FLOW_STATS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_FLOW_STATS);
      break;

    case SSH_PEA_GET_NEXT_TRANSFORM_INDEX:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_NEXT_TRANSFORM_INDEX);
      break;

    case SSH_PEA_GET_TRANSFORM_STATS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_TRANSFORM_STATS);
      break;

    case SSH_PEA_GET_NEXT_RULE_INDEX:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_NEXT_RULE_INDEX);
      break;

    case SSH_PEA_GET_RULE_STATS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_RULE_STATS);
      break;
#endif /* SSH_IPSEC_STATISTICS */

    case SSH_PEA_ARP_ADD:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ARP_ADD);
      break;

    case SSH_PEA_ARP_REMOVE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ARP_REMOVE);
      break;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
    case SSH_PEA_VIRTUAL_ADAPTER_CONFIGURE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_VIRTUAL_ADAPTER_CONFIGURE);
      break;

    case SSH_PEA_VIRTUAL_ADAPTER_LIST:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_VIRTUAL_ADAPTER_LIST);
      break;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

    case SSH_PEA_ROUTE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ROUTE);
      break;

    case SSH_PEA_ROUTE_ADD:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ROUTE_ADD);
      break;

    case SSH_PEA_ROUTE_REMOVE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_ROUTE_REMOVE);
      break;

#ifdef SSH_IPSEC_INTERNAL_ROUTING

    case SSH_PEA_CONFIGURE_ROUTE_CLEAR:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_CONFIGURE_ROUTE_CLEAR);
      break;

    case SSH_PEA_CONFIGURE_ROUTE_ADD:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_CONFIGURE_ROUTE_ADD);
      break;

#endif /* SSH_IPSEC_INTERNAL_ROUTING */

    case SSH_PEA_FLOW_SET_STATUS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_FLOW_SET_STATUS);
      break;

    case SSH_PEA_REDO_FLOWS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_REDO_FLOWS);
      break;

    case SSH_PEA_GET_AUDIT_EVENTS:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_GET_AUDIT_EVENTS);
      break;

    case SSH_PEA_UPDATE_BY_PEER_HANDLE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_UPDATE_BY_PEER_HANDLE);
      break;

    case SSH_PEA_DELETE_BY_PEER_HANDLE:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_DELETE_BY_PEER_HANDLE);
      break;

#ifdef SSH_IPSEC_TCPENCAP
    case SSH_PEA_TCP_ENCAPS_ADD_CONFIG:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_TCP_ENCAPS_ADD_CONFIG);
      break;

    case SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG);
      break;

    case SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING);
      break;

    case SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING);
      break;

    case SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING:
      SSH_ENGINE_PM_HANDLER(SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING);
      break;
#endif /* SSH_IPSEC_TCPENCAP */







    default:
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Received unknown message %d from policy manager",
                         (int) type),
                        data, data_len);
      break;
    }

  /* All done. */
  return;

  /* Error handling. */

 format_error:

  SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                    ("Malformed message of type %d from policy manager:",
                     (int) type),
                    data, data_len);
  return;
}


/*** Proxies for policy manager functions that are called from the engine ***/

/* This function grabs the interface lock when traversing the interface
   table 'ifs' to avoid calls to ssh_ip_uninit_interfaces() that might
   free entries from 'ifs'. */
void
ssh_pmp_interface_change(SshPm pm, const struct SshIpInterfacesRec *ifs)
{
  SshEngine engine = (SshEngine) pm;
  unsigned int i, k;
  const SshInterceptorInterface *ifp;
  Boolean ret;
  unsigned char *buf;
  size_t bufsize, offset, added;
  SshUInt32 nifs;

  /* Initialize a buffer and format the per-interface data into the buffer. */

  bufsize = 8192;

  /* Grab interface lock to prevent calls to ssh_ip_uninit_interfaces() */
  ssh_kernel_mutex_lock(engine->interface_lock);

 restart:
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(bufsize < 1000000);
  buf = ssh_malloc(bufsize);
  if (buf == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate memory for interface notification"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }

  nifs = ifs->nifs;
  offset = 0;
  for (i = 0; i < ifs->nifs; i++)
    {
      ifp = &ifs->ifs[i];

      if (ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        added =
          ssh_encode_array(buf + offset, bufsize - offset,
                           SSH_ENCODE_UINT32(
                           (SshUInt32) SSH_INTERCEPTOR_MEDIA_NONEXISTENT),

                           SSH_ENCODE_UINT32((SshUInt32) 0),
                           SSH_ENCODE_UINT32((SshUInt32) 0),
#ifdef WITH_IPV6
                           SSH_ENCODE_UINT32((SshUInt32) 0),
#endif /* WITH_IPV6 */

                           SSH_ENCODE_UINT32(
                           (SshUInt32) SSH_INTERCEPTOR_MEDIA_NONEXISTENT),

                           SSH_ENCODE_UINT32((SshUInt32) 0),
                           SSH_ENCODE_UINT32((SshUInt32) 0),
#ifdef WITH_IPV6
                           SSH_ENCODE_UINT32((SshUInt32) 0),
#endif /* WITH_IPV6 */

                           SSH_ENCODE_UINT32_STR("", (size_t)0),
                           SSH_ENCODE_UINT32_STR("", (size_t)0),
                           SSH_ENCODE_UINT32(ifp->ifnum),
                           SSH_ENCODE_UINT32(ifp->flags),
                           SSH_ENCODE_UINT32((SshUInt32)0),
                           SSH_FORMAT_END);
      else
        added =
          ssh_encode_array(
                      buf + offset, bufsize - offset,
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_protocol.media),
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_protocol.flags),
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_protocol.mtu_ipv4),
#ifdef WITH_IPV6
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_protocol.mtu_ipv6),
#endif /* WITH_IPV6 */
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_adapter.media),
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_adapter.flags),
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_adapter.mtu_ipv4),
#ifdef WITH_IPV6
                      SSH_ENCODE_UINT32((SshUInt32) ifp->to_adapter.mtu_ipv6),
#endif /* WITH_IPV6 */

                      SSH_ENCODE_UINT32_STR(
                      ifp->media_addr, ifp->media_addr_len),

                      SSH_ENCODE_UINT32_STR(ifp->name, strlen(ifp->name)),
                      SSH_ENCODE_UINT32((SshUInt32)ifp->routing_instance_id),
                      SSH_ENCODE_UINT32_STR(ifp->routing_instance_name,
                                          strlen(ifp->routing_instance_name)),
                      SSH_ENCODE_UINT32(ifp->ifnum),
                      SSH_ENCODE_UINT32(ifp->flags),
                      SSH_ENCODE_UINT32(ifp->num_addrs),
                      SSH_FORMAT_END);


      if (added == 0)
        {
        enlarge:
          ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
          bufsize *= 2;
          ssh_free(buf);
          goto restart;
        }

      offset += added;

      if (ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          /* We make a plain assumption that the addresses are always
             IP addresses. So far, we do not support any other
             protocols than IP, so it's not a problem. */

          for (k = 0; k < ifp->num_addrs; k++)
            {
              unsigned char *addr;
              size_t addr_size;

              if (ifp->addrs[k].protocol == SSH_PROTOCOL_IP4 ||
                  ifp->addrs[k].protocol == SSH_PROTOCOL_IP6)
                {
                  unsigned char *ip, *mask, *bcast;
                  size_t ip_size, mask_size, bcast_size;

                  ip_size =
                    ssh_encode_ipaddr_array_alloc(&ip,
                                                  &ifp->addrs[k].addr.ip.ip);

                  mask_size =
                    ssh_encode_ipaddr_array_alloc(&mask,
                                                  &ifp->addrs[k].addr.ip.mask);

                  bcast_size =
                    ssh_encode_ipaddr_array_alloc(&bcast,
                                           &ifp->addrs[k].addr.ip.broadcast);

                  /* Out of memory */
                  if (!ip_size || !mask_size || !bcast_size)
                    {
                    failure:
                      SSH_DEBUG(SSH_D_ERROR, ("Out of memory when creating "
                                              "interface notification"));
                      ssh_kernel_mutex_assert_is_locked(engine->
                                                        interface_lock);
                      ssh_free(ip);
                      ssh_free(mask);
                      ssh_free(bcast);
                      ssh_free(buf);
                      ssh_kernel_mutex_unlock(engine->interface_lock);
                      return;
                    }

                  addr_size = ssh_encode_array_alloc(&addr,
                                                     SSH_ENCODE_UINT32_STR(
                                                     ip, ip_size),
                                                     SSH_ENCODE_UINT32_STR(
                                                     mask, mask_size),
                                                     SSH_ENCODE_UINT32_STR(
                                                     bcast, bcast_size),
                                                     SSH_FORMAT_END);

                  if (!addr_size)
                    goto failure;

                  ssh_free(ip);
                  ssh_free(mask);
                  ssh_free(bcast);
                }
              else
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("ifp->addrs[%d].protocol == %d is not supported",
                             k, ifp->addrs[k].protocol));

                  addr = ssh_strdup("");

                  if (!addr)
                    {
                      SSH_DEBUG(SSH_D_ERROR, ("Out of memory when creating "
                                              "interface nnotification"));
                      ssh_free(buf);
                      ssh_kernel_mutex_unlock(engine->interface_lock);
                      return;
                    }

                  addr_size = 0;
                }

              added = ssh_encode_array(buf + offset, bufsize - offset,
                                       SSH_ENCODE_UINT32(
                                        ifp->addrs[k].protocol),
                                       SSH_ENCODE_UINT32_STR(addr, addr_size),
                                       SSH_FORMAT_END);

              ssh_free(addr);

              if (added == 0)
                goto enlarge;

              offset += added;
            }
        }
    }

  /* There is a possibility that the last operation to add to the buf
     exceeded its size, but still had added != 0 .. */
  if (offset == bufsize)
      goto enlarge;

  /* Release lock */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Send the message, adding any data that is included only once. */
  ret = ssh_engine_send(engine, FALSE, FALSE,
                        SSH_ENCODE_UINT32((SshUInt32) 0), /* reserve for len */
                        SSH_ENCODE_CHAR((unsigned int) SSH_EPA_INTERFACE),
                        SSH_ENCODE_UINT32((SshUInt32) nifs),
                        SSH_ENCODE_UINT32_STR(buf, offset),
                        SSH_FORMAT_END);

  /* Free the buffer and return. */
  ssh_free(buf);
}


void
ssh_pmp_trigger(SshPm pm, const SshEnginePolicyRule rule,
                SshUInt32 flow_index,
                const SshIpAddr nat_src_ip,
                SshUInt16 nat_src_port,
                const SshIpAddr nat_dst_ip,
                SshUInt16 nat_dst_port,
                SshUInt32 tunnel_id,
                SshVriId routing_instance_id,
                SshUInt32 prev_transform_index,
                SshUInt32 ifnum, SshUInt32 flags,
                unsigned char *data, size_t len)
{
  SshEngine engine = (SshEngine) pm;
  unsigned char *rule_data;
  unsigned char nat_src_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char nat_dst_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t rule_data_len, nat_src_len, nat_dst_len;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(nat_src_ip != NULL && nat_dst_ip != NULL);

  nat_src_len = ssh_encode_ipaddr_array(nat_src_buf, sizeof(nat_src_buf),
                                        nat_src_ip);
  nat_dst_len = ssh_encode_ipaddr_array(nat_dst_buf, sizeof(nat_dst_buf),
                                        nat_dst_ip);

  /* Encode rule. */
  rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
  if (rule_data_len == 0)
    {
      /* We must also free the data of the triggered packet. */
      ssh_free(data);
      return;
    }

  /* Send the trigger message. */
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                  SSH_ENCODE_CHAR((unsigned int) SSH_EPA_TRIGGER),
                  SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                  SSH_ENCODE_UINT32(flow_index),
                  SSH_ENCODE_UINT32_STR(nat_src_buf, nat_src_len),
                  SSH_ENCODE_UINT32_STR(nat_dst_buf, nat_dst_len),
                  SSH_ENCODE_UINT32(nat_src_port),
                  SSH_ENCODE_UINT32(nat_dst_port),
                  SSH_ENCODE_UINT32(tunnel_id),
                  SSH_ENCODE_UINT32(routing_instance_id),
                  SSH_ENCODE_UINT32(prev_transform_index),
                  SSH_ENCODE_UINT32(ifnum),
                  SSH_ENCODE_UINT32(flags),
                  SSH_ENCODE_UINT32_STR(data, len),
                  SSH_FORMAT_END);

  /* Free rule data since it is already sent. */
  ssh_free(rule_data);

  /* We must also free the data of the triggered packet. */
  ssh_free(data);
}


Boolean
ssh_pmp_transform_event(SshPm pm, SshPmeFlowEvent event,
                        SshUInt32 transform_index,
                        const SshEngineTransform trd,
                        SshUInt32 rule_index,
                        const SshEnginePolicyRule rule,
                        SshTime run_time)
{
  SshEngine engine = (SshEngine) pm;
  unsigned char *trd_data;
  size_t trd_data_len;
  unsigned char *rule_data;
  size_t rule_data_len;
  Boolean result;
  unsigned char run_time_buf[sizeof(SshTime)];
  size_t run_time_buf_len = sizeof(SshTime);

  /* Encode transform data. */
  trd_data_len = ssh_pm_api_encode_transform_data(&trd_data, trd);
  if (trd_data_len == 0)
    return FALSE;

  /* Encode policy rule. */
  if (rule)
    {
      rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
      if (rule_data_len == 0)
        {
          ssh_free(trd_data);
          return FALSE;
        }
    }
  else
    {
      rule_data = NULL;
      rule_data_len = 0;
    }

  ssh_pm_api_encode_time(run_time_buf, run_time_buf_len, run_time);

  /* Send the message. */
  result = ssh_engine_send(
                engine, FALSE, FALSE,
                SSH_ENCODE_UINT32((SshUInt32) 0), /* reserved for length */
                SSH_ENCODE_CHAR((unsigned int) SSH_EPA_TRANSFORM_EVENT),
                SSH_ENCODE_UINT32((SshUInt32) event),
                SSH_ENCODE_UINT32(transform_index),
                SSH_ENCODE_UINT32_STR(trd_data, trd_data_len),
                SSH_ENCODE_UINT32(rule_index),
                SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                SSH_ENCODE_UINT32_STR(run_time_buf, run_time_buf_len),
                SSH_FORMAT_END);

  ssh_free(trd_data);
  ssh_free(rule_data);

  return result;
}

#endif /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
