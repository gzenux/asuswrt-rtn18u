/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager; Certificate validator initiated automatic port open.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshadt.h"
#include "sshadt_bag.h"

#define SSH_DEBUG_MODULE "SshPmCmAccess"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

/* Map requested host:port to rule-index. There may be multiple
   entries for the same tuple (as DNS may contain multiple names) */
typedef struct SshPmCmAccessElementRec
{
  SshADTBagHeaderStruct adt_header;

  /* host or port may be NULL for non first */
  unsigned char *host;
  SshUInt16 port;

  SshUInt32 rule_index;

  struct SshPmCmAccessElementRec *next;
} *SshPmCmAccessElement, SshPmCmAccessElementStruct;

typedef struct SshPmDynamicRuleLoaderRec
{
  SshOperationHandle subop;
  SshOperationHandleStruct op[1];
  SshFSMThreadStruct thread[1];
  SshPm pm;

  /* Requested resources */
  unsigned char *host;
  SshUInt16 port;

  SshUInt16 ok : 1;
  SshUInt16 open : 1;
  SshUInt16 changes : 1;
  SshUInt16 aborted : 1;

  /* Result of name resolution */
  SshUInt16 naddrs;
  SshIpAddr addrs;

  /* Iterator for DNS names and rules. */
  SshUInt32 current_index;
  SshUInt32 current_rule;

  /* Callbacks to call when rule is ready */
  SshCMAccessReadyCB ready_callback;
  void *ready_callback_context;

  SshPmCmAccessElement to_be_deleted;
} *SshPmDynamicRuleLoader;


SSH_FSM_STEP(pm_cm_access_start)
{
  SshPm pm = fsm_context;
  SshPmDynamicRuleLoader ac = thread_context;
  SshPmCmAccessElementStruct probe, *entry = NULL;
  SshADTHandle handle;

  ac->current_index = 0;

  probe.host = ac->host;
  probe.port = ac->port;

  /* Check if we already have this address open */
  if ((handle =
       ssh_adt_get_handle_to_equal(pm->cm_access_list, &probe))
      != SSH_ADT_INVALID)
    {
      entry = ssh_adt_get(pm->cm_access_list, handle);
    }

  if (ac->open)
    {
      if (handle)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Reusing rule for %s:%d (index=%d)",
                     ac->host, ac->port,
                     (int) entry->rule_index));

          ac->ok = 1;
          SSH_FSM_SET_NEXT(pm_cm_access_done);
        }
      else
        {
          SSH_FSM_SET_NEXT(pm_cm_access_resolve_name);
        }
    }
  else
    {
      if (handle)
        {
          ac->to_be_deleted = entry;
          ssh_adt_detach(pm->cm_access_list, handle);
          SSH_FSM_SET_NEXT(pm_cm_access_delete_rule);
        }
      else
        {
          SSH_FSM_SET_NEXT(pm_cm_access_done);
        }
    }
  return SSH_FSM_CONTINUE;
}

static void
pm_cm_access_resolve_name_done(SshTcpError status,
                               const unsigned char *result,
                               void *context)
{
  SshPmDynamicRuleLoader ac = context;
  int naddrs = 1, i = 0;
  SshIpAddr addrs;
  char *tmp, *p, *comma;

  ac->subop = NULL;

  if (status == SSH_TCP_OK)
    {
      tmp = ssh_strdup(result);
      if (tmp == NULL)
        {
          ssh_fsm_set_next(ac->thread, pm_cm_access_done);
          SSH_FSM_CONTINUE_AFTER_CALLBACK(ac->thread);
          return;
        }

      /* Count number of result addresses. */
      for (p = (char *)result, comma = (char *)strchr(p, ',');
           comma;
           p = ++comma, comma = strchr(p, ','))
        naddrs += 1;

      addrs = ssh_calloc(naddrs, sizeof(addrs[0]));
      if (addrs == NULL)
        {
          ssh_free(tmp);

          ssh_fsm_set_next(ac->thread, pm_cm_access_done);
          SSH_FSM_CONTINUE_AFTER_CALLBACK(ac->thread);
          return;
        }

      /* Handle addresses */
      for (i = 0, p = tmp, comma = strchr(p, ',');
           comma;
           p = ++comma, comma = strchr(p, ','))
        {
          *comma = '\000';
          ssh_ipaddr_parse(&(addrs[i++]), p);
        }
      ssh_ipaddr_parse(&(addrs[i++]), p);
      ssh_free(tmp);
      SSH_ASSERT(i == naddrs);

      ac->addrs = addrs;
      ac->naddrs = naddrs;
    }
  else
    ssh_fsm_set_next(ac->thread, pm_cm_access_done);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ac->thread);
}

SSH_FSM_STEP(pm_cm_access_resolve_name)
{
  SshPmDynamicRuleLoader ac = thread_context;

  SSH_DEBUG(SSH_D_MIDSTART, ("DPORT; Resolving name '%s'", ac->host));
  SSH_FSM_ASYNC_CALL({
    SSH_FSM_SET_NEXT(pm_cm_access_create_rule);
    ac->subop =
      ssh_tcp_get_host_addrs_by_name(ac->host,
                                     pm_cm_access_resolve_name_done,
                                     ac);
  });
}

SSH_FSM_STEP(pm_cm_access_create_rule_done)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmDynamicRuleLoader ac = thread_context;
  SshPmCmAccessElement probe, entry;
  SshADTHandle handle;

  SSH_FSM_SET_NEXT(pm_cm_access_create_rule);

  if (ac->current_rule == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to add dynamic access rule %u",
                 (unsigned int) ac->current_index));
      ac->ok = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Creating rule for %@:%d (index=%d)",
                                  ssh_ipaddr_render,
                                  &ac->addrs[ac->current_index],
                                  ac->port,
                                  (int) ac->current_rule));

      ac->changes = 1;
      ac->ok = 1;

      probe = ssh_malloc(sizeof(*probe));
      if (probe == NULL)
        return SSH_FSM_CONTINUE;

      probe->host = ssh_strdup(ac->host);
      if (probe->host == NULL)
        {
          ssh_free(probe);
          return SSH_FSM_CONTINUE;
        }

      probe->port = ac->port;
      probe->rule_index = ac->current_rule;
      probe->next = NULL;

      handle = ssh_adt_get_handle_to_equal(pm->cm_access_list, probe);
      if (handle != SSH_ADT_INVALID)
        {
          entry = ssh_adt_get(pm->cm_access_list, handle);
          ssh_free(probe->host); probe->host = NULL;
          probe->next = entry->next;
          entry->next = probe;
        }
      else
        {
          ssh_adt_insert(pm->cm_access_list, probe);
        }
    }
  ac->current_index++;
  return SSH_FSM_CONTINUE;
}

static void pm_cm_add_rule_cb(SshPm pm, SshUInt32 ind,
                              const SshEnginePolicyRule rule,
                              void *context)
{
  SshPmDynamicRuleLoader ac = context;

  ac->current_rule = ind;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ac->thread);
}

static void pm_cm_delete_rule_cb(SshPm pm,
                                 Boolean done,
                                 SshUInt32 rule_index,
                                 SshUInt32 peer_handle,
                                 SshEngineTransform tr,
                                 void *context)
{
  SshPmDynamicRuleLoader ac = context;

  ac->changes = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ac->thread);
}

SSH_FSM_STEP(pm_cm_access_create_rule)
{
  SshPm pm = fsm_context;
  SshPmDynamicRuleLoader ac = thread_context;
  SshEnginePolicyRuleStruct engine_rule;
  int i, dstip_len;

  if (ac->current_index >= ac->naddrs)
    {
      SSH_FSM_SET_NEXT(pm_cm_access_done);
      return SSH_FSM_CONTINUE;
    }

  i = ac->current_index;

  memset(&engine_rule, 0, sizeof(engine_rule));
  engine_rule.transform_index = SSH_IPSEC_INVALID_INDEX;
  engine_rule.depends_on = SSH_IPSEC_INVALID_INDEX;
  engine_rule.flags = 0;
  engine_rule.selectors =
    (SSH_SELECTOR_FROMLOCAL |
     SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTIP | SSH_SELECTOR_DSTPORT);
  engine_rule.precedence = SSH_PM_RULE_PRI_SYSTEM_DEFAULT;
  engine_rule.tunnel_id = 0;

  engine_rule.protocol = SSH_IP_IS4(&ac->addrs[i])
    ? SSH_PROTOCOL_IP4 : SSH_PROTOCOL_IP6;

  engine_rule.ipproto = SSH_IPPROTO_TCP;
  engine_rule.dst_port_low = ac->port;
  engine_rule.dst_port_high = ac->port;
  SSH_IP_ENCODE(&ac->addrs[i], engine_rule.dst_ip_low, dstip_len);
  SSH_IP_ENCODE(&ac->addrs[i], engine_rule.dst_ip_high, dstip_len);

  engine_rule.flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule.flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule.flow_max_lifetime = 0;

  engine_rule.flags |= SSH_PM_ENGINE_RULE_FORWARD;

  engine_rule.type = SSH_ENGINE_RULE_PASS;

  SSH_FSM_ASYNC_CALL({
    SSH_FSM_SET_NEXT(pm_cm_access_create_rule_done);
    ssh_pme_add_rule(pm->engine, FALSE, &engine_rule, pm_cm_add_rule_cb, ac);
  });
}

SSH_FSM_STEP(pm_cm_access_delete_rule)
{
  SshPm pm = fsm_context;
  SshPmDynamicRuleLoader ac = thread_context;
  SshPmCmAccessElement next;
  SshUInt32 index = SSH_IPSEC_INVALID_INDEX;

 next_rule:
  if (ac->to_be_deleted)
    {
      index = ac->to_be_deleted->rule_index;
      next = ac->to_be_deleted->next;

      ssh_free(ac->to_be_deleted->host);
      ssh_free(ac->to_be_deleted);

      ac->to_be_deleted = next;

      if (index == SSH_IPSEC_INVALID_INDEX)
        goto next_rule;
    }

  if (ac->to_be_deleted)
    SSH_FSM_SET_NEXT(pm_cm_access_delete_rule);
  else
    SSH_FSM_SET_NEXT(pm_cm_access_done);

  if (index != SSH_IPSEC_INVALID_INDEX)
    SSH_FSM_ASYNC_CALL({
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Deleting rule for %s:%d (index=%d)",
                 ac->host, ac->port, (int) index));
      ssh_pme_delete_rule(pm->engine, index, pm_cm_delete_rule_cb, ac);
    });
  else
    return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_cm_access_done)
{
  SshPmDynamicRuleLoader ac = thread_context;
  SshPm pm = fsm_context;

  if (ac->ready_callback)
    (*ac->ready_callback)(ac->ok ? TRUE: FALSE,
                          ac->ready_callback_context);

  SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);
  return SSH_FSM_FINISH;
}

static void pm_cm_access_abort(void *context)
{
  SshPmDynamicRuleLoader ac = context;

  /* Abort the current sub-operation, and force the thread to finish
     cleanly */
  ac->aborted = 1;
  ac->ready_callback = NULL_FNPTR;
  ssh_fsm_set_next(ac->thread, pm_cm_access_done);
  ssh_fsm_continue(ac->thread);

  ssh_operation_abort(ac->subop);
}

static void pm_cm_access_destroy(SshFSM fsm, void *context)
{
  SshPmDynamicRuleLoader ac = context;

  ac->pm->mt_num_sub_threads--;
  ssh_fsm_condition_broadcast(&ac->pm->fsm,
                              &ac->pm->main_thread_cond);
  if (!ac->aborted)
    ssh_operation_unregister(ac->op);
  ssh_free(ac->addrs);
  ssh_free(ac->host);
  ssh_free(ac);
}

/* This function runs a state machine that opens access from local
   stack to destination 'host:port' for use of Certificate
   validator. At this time, implementation opens a high precedence
   plaintext connection (unless the policy states not to open anything
   at all. */
static SshOperationHandle
pm_cm_access_callback(Boolean for_open,
                      const unsigned char *host, const unsigned char *port,
                      SshCMAccessReadyCB ready_callback,
                      void *ready_callback_context,
                      void *callback_context)
{
  SshPm pm = callback_context;
  SshPmDynamicRuleLoader ac;
  Boolean ret_status = FALSE;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Validator requests %s access to %s:%s",
             for_open ? "to allow" : "to close",
             host, port));

  if ((ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED) && for_open)
      goto fail;

  /* Uninitialized? */
  if (pm->cm_access_list == NULL)
    goto fail;

  if (pm->cm_auto_rules || 1)
    {
      ac = ssh_calloc(1, sizeof(*ac));
      if (ac == NULL)
        goto fail;

      ac->ready_callback = ready_callback;
      ac->ready_callback_context = ready_callback_context;
      ac->host = ssh_ustrdup(host);
      if (ac->host == NULL)
        {
          ssh_free(ac);
          ac = NULL;
          goto fail;
        }

      ac->port = (SshUInt16) strtol((char *)port, NULL, 0);
      ac->naddrs = 0;
      ac->addrs = NULL;
      ac->ok = 0;
      ac->changes = 0;
      ac->open = for_open ? 1 : 0;
      ac->pm = pm;
      ac->current_index = 0;
      ac->current_rule = SSH_IPSEC_INVALID_INDEX;

      pm->mt_num_sub_threads++;

      ac->aborted = 0;
      ssh_operation_register_no_alloc(ac->op, pm_cm_access_abort, ac);
      ssh_fsm_thread_init(&pm->fsm,
                          ac->thread,
                          pm_cm_access_start,
                          NULL_FNPTR,
                          pm_cm_access_destroy,
                          ac);
      ssh_fsm_set_thread_name(ac->thread, "CM access");
      return ac->op;
    }
  else
    {
      ret_status = TRUE;

    fail:
      if (ready_callback)
        (*ready_callback)(ret_status, ready_callback_context);
      return NULL;
    }

}


static SshUInt32 pm_cm_ac_hash(const void *p, void *context)
{
  SshPmCmAccessElement e = (SshPmCmAccessElement)p;
  SshUInt32 h = e->port;
  int i, len;

  for (len = strlen(e->host), i = 0; i < len; i++)
    {
      h += tolower(e->host[i]); h += h << 10; h ^= h >> 6;
    }
  h += h << 3; h ^= h >> 11; h += h << 15;
  return h;
}

static int pm_cm_ac_compare(const void *p1, const void *p2, void *context)
{
  const SshPmCmAccessElement e1 = (SshPmCmAccessElement)p1;
  const SshPmCmAccessElement e2 = (SshPmCmAccessElement)p2;

  if (e1->port != e2->port)
    return e2->port - e1->port;
  return strcmp(e1->host, e2->host);
}

static void pm_cm_ac_destroy(void *p, void *context)
{
  SshPmCmAccessElement next, ac = (SshPmCmAccessElement) p;

  while (ac)
    {
      next = ac->next;
      if (ac->host) ssh_free(ac->host);
      ssh_free(ac);
      ac = next;
    }
}

Boolean ssh_pm_cm_access_init(SshPm pm)
{
  SSH_ASSERT(pm->cm_access_list == NULL);

  pm->cm_access_list =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmCmAccessElementStruct,
                                             adt_header),
                           SSH_ADT_HASH, pm_cm_ac_hash,
                           SSH_ADT_COMPARE, pm_cm_ac_compare,
                           SSH_ADT_DESTROY, pm_cm_ac_destroy,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);

  if (pm->cm_access_list == NULL)
    return FALSE;
  else
    return TRUE;
}

Boolean ssh_pm_cm_set_access_callback(SshPm pm, SshCMConfig config)
{
  if (pm->cm_access_list)
    {
      ssh_cm_config_set_access_callback(config, pm_cm_access_callback, pm);
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Validator access list not initialized to policymanager!"));
      return FALSE;
    }
}

void ssh_pm_cm_access_uninit(SshPm pm)
{
  if (pm->cm_access_list)
    {
      ssh_adt_destroy(pm->cm_access_list);
      pm->cm_access_list = NULL;
    }
}

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
