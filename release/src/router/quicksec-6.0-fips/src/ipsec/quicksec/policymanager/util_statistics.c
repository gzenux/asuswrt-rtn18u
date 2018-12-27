/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for retrieving statistics for the engine and the policy
   manager.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "engine_pm_api.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmStats"

/* Context data for the global statistics retrieving. */
struct SshPmGlobalStatsCtxRec
{
  SshPmGlobalStatsCB callback;
  void *context;
};

typedef struct SshPmGlobalStatsCtxRec SshPmGlobalStatsCtxStruct;
typedef struct SshPmGlobalStatsCtxRec *SshPmGlobalStatsCtx;

/* Context data for the detailed statistics */
struct SshPmStatsCtxRec
{
  union
  {
    SshPmIndexCB index;
    SshPmTransformInfoCB tr_info;
    SshPmTransformStatsCB tr_stats;
    SshPmFlowInfoCB flow_info;
    SshPmFlowStatsCB flow_stats;
    SshPmRuleInfoCB rule_info;
    SshPmRuleStatsCB rule_stats;
  } cb;
  void *context;
};

typedef struct SshPmStatsCtxRec SshPmStatsCtxStruct;
typedef struct SshPmStatsCtxRec *SshPmStatsCtx;


/************************** Static help functions ***************************/

static void
ssh_pm_get_next_index_cb(SshPm pm, SshUInt32 ind, void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;

  (*ctx->cb.index)(pm, ind, ctx->context);
  ssh_free(ctx);
}


/**************************** Global statistics *****************************/

static void
ssh_pm_engine_global_stats_cb(SshPm pm,
                              const SshEngineGlobalStats e_stats,
                              const SshFastpathGlobalStats f_stats,
                              void *context)
{
  SshPmGlobalStatsCtx ctx = (SshPmGlobalStatsCtx) context;

  /* Call the user callback. */
  (*ctx->callback)(pm, &pm->stats, e_stats, f_stats, ctx->context);

  ssh_free(ctx);
}

void
ssh_pm_get_global_stats(SshPm pm, SshPmGlobalStatsCB callback, void *context)
{
  SshPmGlobalStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, NULL, NULL, context);
      return;
    }

  ctx->callback = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  /* Read the global statistics from the engine. */
  ssh_pme_get_global_stats(pm->engine, ssh_pm_engine_global_stats_cb, ctx);
#else /* not SSH_IPSEC_STATISTICS */
  /* Call the callback directly indicating non-existing engine
     statistics. */
  ssh_pm_engine_global_stats_cb(pm, NULL, NULL, ctx);
#endif /* not SSH_IPSEC_STATISTICS */
}


/*************************** Transform statistics ***************************/

void
ssh_pm_get_next_transform_index(SshPm pm, SshUInt32 transform_index,
                                SshPmIndexCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  ctx->cb.index = callback;
  ctx->context = context;
#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_next_transform_index(pm->engine, transform_index,
                                   ssh_pm_get_next_index_cb, ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_next_index_cb(pm, SSH_IPSEC_INVALID_INDEX, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_transform_cb(SshPm pm, const SshEngineTransform tr,
                        void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;
  SshEngineTransformData trd = &tr->data;
  SshPmTunnel tunnel;

  if (trd)
    {
      SshEngineTransformInfoStruct info;

      memset(&info, 0, sizeof(info));

      info.transform = trd->transform;
      info.gw_addr = trd->gw_addr;
      info.own_addr = trd->own_addr;
      info.tunnel_id = trd->inbound_tunnel_id;

      info.spi_esp_in = trd->spis[SSH_PME_SPI_ESP_IN];
      info.spi_esp_out = trd->spis[SSH_PME_SPI_ESP_OUT];
      info.spi_ah_in = trd->spis[SSH_PME_SPI_AH_IN];
      info.spi_ah_out = trd->spis[SSH_PME_SPI_AH_OUT];
      info.cpi_ipcomp_in = trd->spis[SSH_PME_SPI_IPCOMP_IN];
      info.cpi_ipcomp_out = trd->spis[SSH_PME_SPI_IPCOMP_OUT];

      info.cipher_key_size = trd->cipher_key_size;
      info.mac_key_size = trd->mac_key_size;
      tunnel = ssh_pm_tunnel_get_by_id(pm, info.tunnel_id);

      if (tunnel != NULL)
        {
          ssh_strncpy(info.routing_instance_name,
                      tunnel->routing_instance_name, 64);
          info.routing_instance_id = tunnel->routing_instance_id;
        }
      else
        {
          ssh_strncpy(info.routing_instance_name, "NULL", 64);
          info.routing_instance_id = 0;
        }

      (*ctx->cb.tr_info)(pm, &info, ctx->context);
    }
  else
    {
      (*ctx->cb.tr_info)(pm, NULL, ctx->context);
    }

  ssh_free(ctx);
}


void
ssh_pm_get_transform_info(SshPm pm, SshUInt32 transform_index,
                          SshPmTransformInfoCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.tr_info = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_transform(pm->engine, transform_index, ssh_pm_get_transform_cb,
                        ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_transform_cb(pm, NULL, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_transform_stats_cb(SshPm pm, const SshEngineTransformStats stats,
                              void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;

  (*ctx->cb.tr_stats)(pm, stats, ctx->context);
  ssh_free(ctx);
}


void
ssh_pm_get_transform_stats(SshPm pm, SshUInt32 transform_index,
                           SshPmTransformStatsCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.tr_stats = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_transform_stats(pm->engine, transform_index,
                              ssh_pm_get_transform_stats_cb, ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_transform_stats_cb(pm, NULL, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


/***************************** Flow statistics ******************************/

void ssh_pm_get_next_flow_index(SshPm pm, SshUInt32 flow_index,
                                SshPmIndexCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  ctx->cb.index = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_next_flow_index(pm->engine, flow_index,
                              ssh_pm_get_next_index_cb, ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_next_index_cb(pm, SSH_IPSEC_INVALID_INDEX, ctx);
#endif  /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_flow_info_cb(SshPm pm, SshEngineFlowInfo info, void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;
  const char* routing_instance_name;

  routing_instance_name = ssh_ip_get_interface_vri_name (&pm->ifs,
                                  info->routing_instance_id);
  ssh_strncpy(info->routing_instance_name, routing_instance_name, 64);

  (*ctx->cb.flow_info)(pm, info, ctx->context);
  ssh_free(ctx);
}


void
ssh_pm_get_flow_info(SshPm pm, SshUInt32 flow_index,
                     SshPmFlowInfoCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.flow_info = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_flow_info(pm->engine, flow_index, ssh_pm_get_flow_info_cb,
                        ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_flow_info_cb(pm, NULL, ctx);
#endif  /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_flow_stats_cb(SshPm pm, const SshEngineFlowStats stats,
                         void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;

  (*ctx->cb.flow_stats)(pm, stats, ctx->context);
  ssh_free(ctx);
}


void
ssh_pm_get_flow_stats(SshPm pm, SshUInt32 flow_index,
                      SshPmFlowStatsCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.flow_stats = callback;
  ctx->context = context;

#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_flow_stats(pm->engine, flow_index, ssh_pm_get_flow_stats_cb,
                         ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_flow_stats_cb(pm, NULL, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


/***************************** Rule statistics ******************************/

void
ssh_pm_get_next_rule_index(SshPm pm, SshUInt32 rule_index,
                           SshPmIndexCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  ctx->cb.index = callback;
  ctx->context = context;
#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_next_rule_index(pm->engine, rule_index,
                              ssh_pm_get_next_index_cb, ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_next_index_cb(pm, SSH_IPSEC_INVALID_INDEX, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_rule_cb(SshPm pm, const SshEnginePolicyRule rule, void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;

  if (rule)
    {
      SshEngineRuleInfoStruct info;
      const char* routing_instance_name;

      memset(&info, 0, sizeof(info));

      info.type = (SshPmEngineRuleType) rule->type;

      info.precedence = rule->precedence;
      info.tunnel_id = rule->tunnel_id;
      if (rule->protocol == SSH_PROTOCOL_IP4)
        {
          if (rule->selectors & SSH_SELECTOR_SRCIP)
            {
              SSH_IP4_DECODE(&info.src_ip_low, rule->src_ip_low);
              SSH_IP4_DECODE(&info.src_ip_high, rule->src_ip_high);
            }
          if (rule->selectors & SSH_SELECTOR_DSTIP)
            {
              SSH_IP4_DECODE(&info.dst_ip_low, rule->dst_ip_low);
              SSH_IP4_DECODE(&info.dst_ip_high, rule->dst_ip_high);
            }
        }
      else
        {
          SSH_ASSERT(rule->protocol == SSH_PROTOCOL_IP6);
          if (rule->selectors & SSH_SELECTOR_SRCIP)
            {
              SSH_IP6_DECODE(&info.src_ip_low, rule->src_ip_low);
              SSH_IP6_DECODE(&info.src_ip_high, rule->src_ip_high);
            }
          if (rule->selectors & SSH_SELECTOR_DSTIP)
            {
              SSH_IP6_DECODE(&info.dst_ip_low, rule->dst_ip_low);
              SSH_IP6_DECODE(&info.dst_ip_high, rule->dst_ip_high);
            }
        }
      info.src_port_low = rule->src_port_low;
      info.src_port_high = rule->src_port_high;
      info.dst_port_low = rule->dst_port_low;
      info.dst_port_high = rule->dst_port_high;
      info.ipproto = SSH_IPPROTO_ANY;
      info.routing_instance_id = rule->routing_instance_id;
      routing_instance_name = ssh_ip_get_interface_vri_name (&pm->ifs,
                                                   info.routing_instance_id);
      if (routing_instance_name != NULL)
        ssh_strncpy(info.routing_instance_name, routing_instance_name, 64);
      else
        ssh_strncpy(info.routing_instance_name, "Any", 64);

      if (rule->selectors & SSH_SELECTOR_IFNUM)
        {
          info.flags |= SSH_PM_ENGINE_RULE_SEL_IFNUM;
          info.ifnum = rule->selector_ifnum;
        }

      if (rule->selectors & SSH_SELECTOR_IPPROTO)
        info.ipproto = (SshUInt8) rule->ipproto;

      if (rule->selectors & SSH_SELECTOR_ICMPTYPE)
        {
          info.flags |= SSH_PM_ENGINE_RULE_SEL_ICMPTYPE;
          info.icmp_type = (rule->dst_port_low >> 8) & 0xff;
        }

      if (rule->selectors & SSH_SELECTOR_ICMPCODE)
        {
          info.flags |= SSH_PM_ENGINE_RULE_SEL_ICMPCODE;
          info.icmp_code = rule->dst_port_low & 0xff;
        }

      info.transform_index = rule->transform_index;
      info.depends_on = rule->depends_on;

      (*ctx->cb.rule_info)(pm, &info, ctx->context);
    }
  else
    {
      (*ctx->cb.rule_info)(pm, NULL, ctx->context);
    }

  ssh_free(ctx);
}


void
ssh_pm_get_rule_info(SshPm pm, SshUInt32 rule_index,
                     SshPmRuleInfoCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.rule_info = callback;
  ctx->context = context;
#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_rule(pm->engine, rule_index, ssh_pm_get_rule_cb, ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_rule_cb(pm, NULL, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}


static void
ssh_pm_get_rule_stats_cb(SshPm pm, const SshEngineRuleStats stats,
                         void *context)
{
  SshPmStatsCtx ctx = (SshPmStatsCtx) context;

  (*ctx->cb.rule_stats)(pm, stats, ctx->context);
  ssh_free(ctx);
}


void
ssh_pm_get_rule_stats(SshPm pm, SshUInt32 rule_index,
                      SshPmRuleStatsCB callback, void *context)
{
  SshPmStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(pm, NULL, context);
      return;
    }

  ctx->cb.rule_stats = callback;
  ctx->context = context;
#ifdef SSH_IPSEC_STATISTICS
  ssh_pme_get_rule_stats(pm->engine, rule_index, ssh_pm_get_rule_stats_cb,
                         ctx);
#else /* SSH_IPSEC_STATISTICS */
  ssh_pm_get_rule_stats_cb(pm, NULL, ctx);
#endif /* SSH_IPSEC_STATISTICS */
}
