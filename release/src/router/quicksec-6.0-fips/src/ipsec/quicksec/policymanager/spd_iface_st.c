/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM interface changes.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStIface"


/* The interval (in microseconds) after an interface change to wait until
   restarting servers and their failure TTLs are decremented. */
#define SSH_PM_IFACE_CHANGE_TIMER_INTERVAL      250000

/* The maximum number of times to try restarting the servers after an
   interface change. */
#define SSH_PM_IFACE_CHANGE_RETRY_LIMIT      20

/*********************** Processing interface changes ***********************/

static void
ssh_pm_interface_timeout_cb(void *ctx)
{
  SshFSMThread thread = (SshFSMThread) ctx;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ssh_pm_servers_interface_change_done_cb(SshPm pm, Boolean success,
                                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  pm->iface_change_ok = success ? 1 : 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_ASSERT(pm->iface_change);
  SSH_ASSERT(pm->batch_active);

  pm->iface_change = 0;
  pm->iface_change_ok = 0;

  /* On some platforms, we can actually end up here before the host
     operating system has managed to get all its state in synch, so
     we allow this operation to fail up to 'pm->interface_change_retry'
     times, with a timeout inbetween each attempt. */
  pm->interface_change_retry = SSH_PM_IFACE_CHANGE_RETRY_LIMIT;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_update_tunnels);
  SSH_FSM_ASYNC_CALL(ssh_register_timeout(&pm->interface_change_timeout,
                                          0,
                                          SSH_PM_IFACE_CHANGE_TIMER_INTERVAL,
                                          ssh_pm_interface_timeout_cb,
                                          thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_update_tunnels)
{
#ifdef SSHDIST_IPSEC_MOBIKE
  SshPm pm = (SshPm) fsm_context;
  SshADTHandle handle;
  SshPmTunnel tunnel;

  SSH_DEBUG(SSH_D_LOWSTART, ("Updating tunnel local IP addresses"));

  /* Iterate through tunnels and update local interface addresses. */
  for (handle = ssh_adt_enumerate_start(pm->tunnels);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
      tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
      if (tunnel != NULL)
        ssh_pm_tunnel_update_local_interface_addresses(tunnel);
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Reiterating all tunnels for VIP"));

  for (handle = ssh_adt_enumerate_start(pm->tunnels);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
      tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);

      if (tunnel != NULL && tunnel->vip != NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Tunnel 0x%p VIP marked for reconfiguration", tunnel));

          tunnel->vip->reconfigure_routes = 1;
          ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
        }
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  SSH_DEBUG(SSH_D_LOWSTART, ("Updating tunnel routing instance ids."));
  /* Iterate through tunnels and update routing instance id. */
  for (handle = ssh_adt_enumerate_start(pm->tunnels);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
      tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
      if (tunnel != NULL)
        tunnel->routing_instance_id = ssh_ip_get_interface_vri_id(
                                              &pm->ifs,
                                              tunnel->routing_instance_name);
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_servers)
{
  SshPm pm = (SshPm) fsm_context;

  /* Notify servers about updated interface listing. If starting some new
     server has failed, reschedule a timeout to try again. */
  if (pm->interface_change_retry && !pm->iface_change_ok)
    {
      pm->interface_change_retry--;

      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers_check_done);
      SSH_FSM_ASYNC_CALL(ssh_pm_servers_interface_change(pm,
                                       ssh_pm_servers_interface_change_done_cb,
                                       thread));
      SSH_NOTREACHED;

    }

#ifdef SSHDIST_IPSEC_MOBIKE
  /* Re-evaluate MOBIKE SAs if policy manager is active and there is no
     ongoing policy configuration. */
  if ((ssh_pm_get_status(pm) == SSH_PM_STATUS_ACTIVE) && !pm->config_active)
    ssh_pm_mobike_reevaluate(pm, NULL_FNPTR, NULL);
#endif /* SSHDIST_IPSEC_MOBIKE */

  /* Start processing rules. */
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rules);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_servers_check_done)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_servers);

  if (pm->iface_change_ok)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Servers Interface changes OK"));

      SSH_APE_MARK(1, ("Interface change event complete"));

      return SSH_FSM_CONTINUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Servers Interface changes failed, "
                               "rescheduling for another attempt"));

      SSH_FSM_ASYNC_CALL(ssh_register_timeout(&pm->interface_change_timeout,
                                            0,
                                            SSH_PM_IFACE_CHANGE_TIMER_INTERVAL,
                                            ssh_pm_interface_timeout_cb,
                                            thread));

      SSH_NOTREACHED;
    }
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  /* Reset the indices of the rule's traffic selectors */
  pm->from_ts_index = 0;
  pm->to_ts_index = 0;

  if (pm->mt_current.handle == SSH_ADT_INVALID)
    {
      /* All rules processed. */
#ifdef SSHDIST_IPSEC_NAT
      /* Check possible pending interface NATs. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_nat);
#else /* SSHDIST_IPSEC_NAT */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_pending_iface);
#endif /* SSHDIST_IPSEC_NAT */

      return SSH_FSM_CONTINUE;
    }

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  if (rule->flags & SSH_PM_RULE_I_DELETED
      || rule->side_from.ifname == NULL)
    {
      /* Nothing to do for this rule. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Skipping rule `%@'",
                                   ssh_pm_rule_render, rule));
      pm->mt_current.handle = ssh_adt_enumerate_next(pm->mt_current.container,
                                                     pm->mt_current.handle);
      return SSH_FSM_CONTINUE;
    }

  /* Check if the interfaces have changed. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Checking rule `%@'",
                               ssh_pm_rule_render, rule));
  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshInterceptorInterface *ifp;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  SSH_ASSERT(rule->side_from.ifname != NULL);
  ifp = ssh_pm_find_interface(pm, rule->side_from.ifname, NULL);

  if (ifp == NULL)
    {
      /* The interface has disappeared.  Delete all rules we have
         created. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing rule `%@'",
                                   ssh_pm_rule_render, rule));
      /** Interface disappeared. */
      pm->mt_index = pm_get_next_engine_rule(rule);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_delete);

      return SSH_FSM_CONTINUE;
    }

  /* We just check the first index for the implementation rule. This is
     OK since either all traffic selector items should be installed or none
     of them are. */
  if (ifp &&
      (rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT] == SSH_IPSEC_INVALID_INDEX))
    {
      /* The interface came up but we do not have rule for it. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating rule `%@'",
                                   ssh_pm_rule_render, rule));
      /** Interface up. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_add);
      return SSH_FSM_CONTINUE;
    }
  SSH_DEBUG(SSH_D_NICETOKNOW, ("The rule `%@' is up-to-date",
                               ssh_pm_rule_render, rule));

  /** Rule processed. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_delete)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* Do we have more rules to delete? */
      pm->mt_index = pm_get_next_engine_rule(rule);
      if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
        {
          /* No.  This rule is now handled. */
          SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_done);
          return SSH_FSM_CONTINUE;
        }
      /* More rules to delete.  Let's start below. */
    }

  /* Delete the rule `pm->mt_index'.  Note that we can end up here
     multiple times with the same rule index.  The engine can call the
     completion callback multiple times until all flows of the rule
     are deleted. */
  SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, pm->mt_index,
                                         ssh_pm_delete_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_add)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  /* Create the rule. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  if (ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                              rule->side_from.ts,
                              pm->from_ts_index,
                              rule->side_to.ts,
                              pm->to_ts_index,
                              FALSE) != PM_ENGINE_RULE_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create engine rule "
                              "although the interface has come up"));
      pm->mt_index = SSH_IPSEC_INVALID_INDEX;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_delete);
      return SSH_FSM_CONTINUE;
    }
  SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_add_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to add engine rule"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_delete);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      /* Store the rule index. */
      rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
      rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT +
                  SSH_PM_CURRENT_RULE_INDEX(pm)] = pm->mt_index;
    }

  /* Implementation rule created, now check the policy enforcement rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_enforcement);
  return SSH_FSM_CONTINUE;
}


/* Return the next engine rule index of the rule `rule'.  The function
   sets the rule index in the high-level rule `rule' to
   SSH_IPSEC_INVALID_INDEX.  The function returns the rule index or
   SSH_IPSEC_INVALID_INDEX if the rule does not have any more
   low-level engine rules. */
SshUInt32 pm_get_next_engine_rule(SshPmRule rule)
{
  SshUInt32 index;
  SshUInt32 i;

  for (i = 0; i < SSH_PM_RULE_MAX_ENGINE_RULES; i++)
    if (rule->rules[i] != SSH_IPSEC_INVALID_INDEX)
      {
        index = rule->rules[i];
        rule->rules[i] = SSH_IPSEC_INVALID_INDEX;

        return index;
      }

  return SSH_IPSEC_INVALID_INDEX;
}

Boolean pm_get_next_ts_items(SshPm pm, SshPmRule rule)
{
  SshIkev2PayloadTS from, to;

  from = rule->side_from.ts;
  to = rule->side_to.ts;

  SSH_ASSERT(from != NULL && to != NULL);
  SSH_ASSERT(pm->from_ts_index < SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS);
  SSH_ASSERT(pm->to_ts_index   < SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS);

  if (++pm->from_ts_index == from->number_of_items_used)
    {
      if (++pm->to_ts_index == to->number_of_items_used)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Iterated over all TS item pairs"));
          return FALSE;
        }
      pm->from_ts_index = 0;
    }
  return TRUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_enforcement)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshEnginePolicyRuleStruct engine_rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                              "enforcement for rule for %@ not created yet.",
                              ssh_pm_rule_render, rule));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_done);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /* Do we need policy enforcement rule? */
  if (rule->side_to.tunnel == NULL
      || (rule->flags & SSH_PM_RULE_PASS) == 0)
    {
      /* Check if there are any more traffic selector items to process */
      if (pm_get_next_ts_items(pm, rule))
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_add);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_done);
      return SSH_FSM_CONTINUE;
    }

  /* Create the enforcement rule. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  if (ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                              rule->side_to.ts,
                              pm->to_ts_index,
                              rule->side_from.ts,
                              pm->from_ts_index,
                              TRUE) != PM_ENGINE_RULE_OK)
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_ERROR, ("Could not create policy enforcement rule"));
      pm->mt_index = SSH_IPSEC_INVALID_INDEX;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_delete);
      return SSH_FSM_CONTINUE;
    }

  SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);
  /** Create enforcement rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_enforcement_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_enforcement_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to add policy enforcement rule"));
      pm->mt_index = SSH_IPSEC_INVALID_INDEX;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_delete);
    }
  else
    {
      /* Store the rule index. */
      rule->rules[SSH_PM_RULE_ENGINE_ENFORCE +
                  SSH_PM_CURRENT_RULE_INDEX(pm)] = pm->mt_index;

      /* Check if there are any more traffic selector items to process */
      if (pm_get_next_ts_items(pm, rule))
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_add);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rule_done);
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_iface_change_rule_done)
{
  SshPm pm = (SshPm) fsm_context;

  /* Continue processing the next rule. */

  pm->mt_current.handle = ssh_adt_enumerate_next(pm->mt_current.container,
                                                 pm->mt_current.handle);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_rules);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_NAT
SSH_FSM_STEP(ssh_pm_st_main_iface_change_nat)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmIfaceNat nat;
  SshUInt32 ifnum;
  Boolean retval;

  SSH_DEBUG(SSH_D_MIDSTART, ("Processing interface NATs"));

  /* This is a bit silly (O(n^2)), but under the assumption that
     NAT is only performed against one interface, this is sufficient. */

  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      SshInterceptorInterface *ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);

      if (ifp == NULL)
        continue;

      for (nat = pm->iface_nat_list; nat != NULL; nat = nat->next)
        {
          if (strcmp(nat->ifname, ifp->name) == 0)
            {
              /* We know the interface now. */
              SSH_DEBUG(SSH_D_MIDOK, ("Configuring interface NAT for `%s': "
                                      "ifnum=%d",
                                      nat->ifname, (int) ifp->ifnum));
              ssh_pme_set_interface_nat(pm->engine, ifp->ifnum,
                                        nat->type, nat->flags,
                                        NULL, NULL, 0);
              break;
            }
        }
      if (nat == NULL)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Configuring NO NAT for '%s': "
                                  "ifnum=%d",
                                  ifp->name, (int) ifp->ifnum));
          ssh_pme_set_interface_nat(pm->engine, ifp->ifnum,
                                    SSH_PM_NAT_TYPE_NONE,
                                    SSH_PM_NAT_FLAGS_EMPTY,
                                    NULL, NULL, 0);
        }
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_pending_iface);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_NAT */

SSH_FSM_STEP(ssh_pm_st_main_iface_change_pending_iface)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshPmRule rule;
  Boolean batch_active = FALSE;
  SshPmMakeEngineRuleStatus status;
  size_t from_index, to_index;
  Boolean interface_not_up = FALSE;
  SshADTHandle handle, next;

  /* Check the pending interface rules. For any rules that are now valid
     add them to the batch additions. When finished, signal a policy
     reconfiguration.*/

  for (handle = ssh_adt_enumerate_start(pm->iface_pending_additions);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      next = ssh_adt_enumerate_next(pm->iface_pending_additions, handle);
      rule = ssh_adt_get(pm->iface_pending_additions, handle);

#ifdef SSHDIST_IPSEC_DNSPOLICY
      if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                                  "pending interface can't be processed "
                                  "for rule %@.",
                                  ssh_pm_rule_render, rule));
          continue;
        }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

      engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

      SSH_ASSERT(rule->side_from.ts != NULL && rule->side_to.ts != NULL);

      /* Check that all traffic selectors items pairs of a rule are ready
         to be added to the engine. */
      for (from_index = 0;
           from_index < rule->side_from.ts->number_of_items_used;
           from_index++)
        {
          for (to_index = 0;
               to_index < rule->side_to.ts->number_of_items_used;
               to_index++)
            {
              status = ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                                               rule->side_from.ts, from_index,
                                               rule->side_to.ts, to_index,
                                               FALSE);
              switch (status)
                {
                case PM_ENGINE_RULE_OK:
                  SSH_ASSERT(engine_rule.protocol !=
                             SSH_PROTOCOL_NUM_PROTOCOLS);
                  break;

                case PM_ENGINE_RULE_NO_INTERFACE:
                case PM_ENGINE_RULE_FAILED:
                default:
                  /* This rule is not yet ready for addition to the engine. */
                  interface_not_up = TRUE;
                  goto next_rule;
                }
            }
        }

    next_rule:
      if (!interface_not_up)
        {
          /* Remove this from the list of pending interface rules */
          ssh_adt_detach(pm->iface_pending_additions, handle);

          /* If this happens when batch is not active, we need to
             react properly */
          if (pm->batch.additions != NULL)
            ssh_adt_insert(pm->batch.additions, rule);
          else
            if ((pm->batch.additions =
                 ssh_adt_create_generic(SSH_ADT_BAG,
                                SSH_ADT_HEADER,
                                SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                  rule_by_index_add_hdr),
                                SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                                SSH_ADT_CONTEXT, pm,
                                SSH_ADT_ARGS_END))
                != NULL)
              {
                ssh_adt_insert(pm->batch.additions, rule);
                batch_active = TRUE;
              }
        }
    }

  /* Clear batch_active that was set in
     ssh_pm_st_main_run to disable reconfigurations. */
  pm->batch_active = 0;

  /* Reconfiguration if necessary */
  if (batch_active)
    {
      pm->batch_active = 1;
      pm->batch.status_cb = NULL_FNPTR;
      pm->batch.status_cb_context = NULL;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change_done);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_iface_change_done)
{
  SshPm pm = (SshPm) fsm_context;

  /* Check auto-start rules after rule changes. */
  pm->auto_start = 1;

  /* Notify the top level policy manager interface callback
     that the interface information has changed. */
  if (pm->interface_callback != NULL_FNPTR)
    (*pm->interface_callback)(pm, pm->interface_callback_context);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
  return SSH_FSM_CONTINUE;
}
