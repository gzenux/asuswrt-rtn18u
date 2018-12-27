/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM start and event waiting.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStBatch"

/***************** Callbacks, etc... utility functions     ******************/
/* A callback function that is called to notify that the policy lookups
   have been enabled / disabled. */
static void
pm_batch_policy_lookup_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Engine policy lookup status changed to %s",
                               (status ? "enabled" : "disabled")));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to notify that the policy manager has
   been suspended. */
static void
pm_batch_policy_suspend_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  if (status == TRUE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager suspended."));
    }
  else
    {
      pm->batch_failed = 1;
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Policy manager could not be suspended, batch failed."));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/***************** Processing rule additions and deletions ******************/

SSH_FSM_STEP(ssh_pm_st_main_batch_start)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_suspend_ike);

  SSH_ASSERT(pm->batch_active);
  pm->batch.nested_tunnels = 0;

  /* Start update batch by disabling policy lookups from the engine.
     This makes our update operation semi-atomic.  Well, anyhow it
     assures that policy lookups are not done with inconsistent
     (partially updated) rule set. */
  SSH_FSM_ASYNC_CALL(ssh_pme_disable_policy_lookup(pm->engine,
                                                   pm_batch_policy_lookup_cb,
                                                   thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_suspend_ike)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch);

  SSH_ASSERT(pm->batch_active);

  /* Continue batch by disabling ike library for a while. */
  SSH_FSM_ASYNC_CALL(ssh_pm_policy_suspend(pm, pm_batch_policy_suspend_cb,
                                           thread));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshADTHandle handle, next;

  /* Did we fail suspend operation? */
  if (pm->batch_failed)
    {
      /* We need to take care of the batch additions and deletions here. */
      if (pm->batch.deletions)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing batch deletions."));

          for (handle = ssh_adt_enumerate_start(pm->batch.deletions);
               handle != SSH_ADT_INVALID;
               handle = next)
            {
              next = ssh_adt_enumerate_next(pm->batch.deletions, handle);
              ssh_adt_detach(pm->batch.deletions, handle);
            }

          SSH_ASSERT(ssh_adt_num_objects(pm->batch.deletions) == 0);
          ssh_adt_destroy(pm->batch.deletions);
          pm->batch.deletions = NULL;
        }

      if (pm->batch.additions)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing batch additions."));

          for (handle = ssh_adt_enumerate_start(pm->batch.additions);
               handle != SSH_ADT_INVALID;
               handle = next)
            {
              next = ssh_adt_enumerate_next(pm->batch.additions, handle);
              ssh_adt_detach(pm->batch.additions, handle);
            }

          SSH_ASSERT(ssh_adt_num_objects(pm->batch.additions) == 0);
          ssh_adt_destroy(pm->batch.additions);
          pm->batch.additions = NULL;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done);
      return SSH_FSM_CONTINUE;
    }

  pm->mt_current.container = NULL;
  pm->mt_current.handle = SSH_ADT_INVALID;

  /* Calculate union of inner tunnel IKE trigger traffic selectors */
  pm->batch.ike_triggers_to_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  pm->batch.ike_triggers_from_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  for (handle = ssh_adt_enumerate_start(pm->rule_ike_trigger);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_ike_trigger, handle))
    {
      rule = ssh_adt_get(pm->rule_ike_trigger, handle);
      SSH_ASSERT(rule != NULL);
      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_IKE_TRIGGER);
      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);

      if (rule->flags & SSH_PM_RULE_I_DELETED)
        continue;

      if (ssh_ikev2_ts_union(pm->sad_handle, pm->batch.ike_triggers_to_ts,
                             rule->side_to.ts) != SSH_IKEV2_ERROR_OK
          || ssh_ikev2_ts_union(pm->sad_handle, pm->batch.ike_triggers_from_ts,
                                rule->side_from.ts) != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not create IKE trigger traffic selector union"));
          goto error;
        }
    }

  /* Then, move to rule additions. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
  return SSH_FSM_CONTINUE;

 error:
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
  return SSH_FSM_CONTINUE;
}

/* Process entries on batch.additions container */
SSH_FSM_STEP(ssh_pm_st_main_batch_additions)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  if (pm->mt_current.container == NULL)
    {
      /* Add the first rule from the additions list. */
      pm->mt_current.container = pm->batch.additions;
      if (pm->batch.additions)
        pm->mt_current.handle = ssh_adt_enumerate_start(pm->batch.additions);
      else
        pm->mt_current.handle = SSH_ADT_INVALID;
    }
  else
    {
      /* advance and detach the old rule */
      pm->mt_current.handle =
        ssh_adt_enumerate_next(pm->mt_current.container,
                               pm->mt_current.handle);
    }

  /* All additions done, next sanity check added rules. */
  if (pm->mt_current.handle == SSH_ADT_INVALID)
    {
      pm->mt_current.container = pm->batch.deletions;
      if (pm->batch.deletions)
        pm->mt_current.handle = ssh_adt_enumerate_start(pm->batch.deletions);
      else
        pm->mt_current.handle = SSH_ADT_INVALID;

      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_sanity_check);
      return SSH_FSM_CONTINUE;
    }

  pm->from_ts_index = 0;
  pm->to_ts_index = 0;

  /* Insert it into rule by precedence and rule by id containers. */
  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  ssh_adt_insert(pm->rule_by_precedence, rule);
  ssh_adt_insert(pm->rule_by_id, rule);

  /* Insert auto start rules to rule by autostart container. */
  if (rule->side_from.auto_start || rule->side_to.auto_start)
    {
      ssh_adt_insert(pm->rule_by_autostart, rule);
      rule->in_auto_start_adt = 1;
    }

  /* Check if the configuration batch contains nested tunnel rules. */
  if ((rule->side_to.tunnel != NULL
       && rule->side_to.tunnel->outer_tunnel != NULL)
      || (rule->side_from.tunnel != NULL
          && rule->side_from.tunnel->outer_tunnel != NULL))
    pm->batch.nested_tunnels = 1;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshEnginePolicyRuleStruct engine_rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  SSH_ASSERT(rule != NULL);

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Not creating filter rules for cfgmode placeholder rule `%@'",
                 ssh_pm_rule_render, rule));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_rule);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating filter rules for rule `%@'", ssh_pm_rule_render, rule));

  /* Create the engine rule. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                              "can't create engine rules for rule %@.",
                              ssh_pm_rule_render, rule));
    }
  else
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    {
      if (ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                                  rule->side_from.ts,
                                  pm->from_ts_index,
                                  rule->side_to.ts,
                                  pm->to_ts_index,
                                  FALSE) == PM_ENGINE_RULE_OK)
        {
          /* Install inactive engine rule for no-trigger policy rules. */
          if (engine_rule.type == SSH_ENGINE_RULE_TRIGGER &&
              (rule->flags & SSH_PM_RULE_I_NO_TRIGGER))
            engine_rule.flags |= SSH_ENGINE_RULE_INACTIVE;

          SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);
          /** Add engine rule. */
          SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_result);
          SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE,
                                              &engine_rule,
                                              ssh_pm_add_rule_cb,
                                              thread));
          SSH_NOTREACHED;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Not enough information to create rule `%@'",
                     ssh_pm_rule_render, rule));
        }
    }

  /** Move ahead. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_batch_addition_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to add rule to the engine: "
                              "restoring old state."));
      pm->mt_current.container = pm->rule_by_id;
      pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  pm->batch.current_index = SSH_PM_RULE_ENGINE_IMPLEMENT +
    SSH_PM_CURRENT_RULE_INDEX(pm);
  SSH_ASSERT(rule->rules[pm->batch.current_index] == SSH_IPSEC_INVALID_INDEX);
  rule->rules[pm->batch.current_index] = pm->mt_index;
  pm->batch_changes = 1;

  /* Implementation rule created, now check the policy enforcement rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_enforcement);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_enforcement)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshEnginePolicyRuleStruct engine_rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (pm_rule_get_dns_status(pm, rule) == SSH_PM_DNS_STATUS_ERROR)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("DNS selectors for rule not yet resolved; "
                              "reverse drop rule for %@ not created yet.",
                              ssh_pm_rule_render, rule));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /* Do we need policy enforcement rule? */
  if (rule->side_to.tunnel == NULL || (rule->flags & SSH_PM_RULE_PASS) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      || SSH_PM_RULE_IS_VIRTUAL_IP(rule)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      )
    {
      /* Policy enforcement is not needed. */

      /* Check if there are any more traffic selector items to process */
      if (pm_get_next_ts_items(pm, rule))
        {
          SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_rule);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating enforcement (trigger's reverse"
                               " drop rule) rule for rule `%@'",
                               ssh_pm_rule_render, rule));

  /* Create the enforcement rule. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  if (ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                              rule->side_to.ts, pm->to_ts_index,
                              rule->side_from.ts, pm->from_ts_index,
                              TRUE) != PM_ENGINE_RULE_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create policy enforcement rule:"
                              "restoring old state."));
      pm->mt_current.container = pm->rule_by_id;
      pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }
  SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_enforcement_result);

  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_enforcement_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshUInt32 i;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to add policy enforcement rule: "
                              "restoring old state."));
      pm->mt_current.container = pm->rule_by_id;
      pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  pm->batch.current_index = SSH_PM_RULE_ENGINE_ENFORCE +
    SSH_PM_CURRENT_RULE_INDEX(pm);
  SSH_ASSERT(rule->rules[pm->batch.current_index] == SSH_IPSEC_INVALID_INDEX);
  rule->rules[pm->batch.current_index] = pm->mt_index;

  /* Check if there are any more traffic selector items to process */
  if (pm_get_next_ts_items(pm, rule))
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition);
      return SSH_FSM_CONTINUE;
    }
  /* An addition processed.
     Check if need to create trigger rules for inner tunnel IKE.*/
  if (rule->flags & SSH_PM_RULE_MATCH_LOCAL_IKE)
    {
      for (i = 0; i < SSH_PM_MAX_INNER_TUNNELS; i++)
        {
          pm->batch.inner_local_ike_ports[i] = 0;
          pm->batch.inner_local_ike_natt_ports[i] = 0;
          pm->batch.inner_remote_ike_ports[i] = 0;
          pm->batch.inner_remote_ike_natt_ports[i] = 0;
        }
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_rule);
    }
  else
    SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
  return SSH_FSM_CONTINUE;
}



SSH_FSM_STEP(ssh_pm_st_main_batch_addition_create_ike_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule, inner_rule = NULL, ike_rule = NULL;
  SshADTHandle h;
  SshUInt16 local_ike_port = 0, local_ike_natt_port = 0;
  SshUInt16 remote_ike_port = 0, remote_ike_natt_port = 0;
  SshUInt32 i;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  SSH_ASSERT(rule != NULL);

  /* Need to consider only to-tunnel rules. */
  if (rule->side_to.tunnel == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
      return SSH_FSM_CONTINUE;
    }

  /* Find an inner rule that refers to this outer-tunnel. */
  for (h = ssh_adt_enumerate_start(pm->batch.additions);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->batch.additions, h))
    {
      inner_rule = ssh_adt_get(pm->batch.additions, h);
      SSH_ASSERT(inner_rule != NULL);

      /* Check if inner IKE traffic needs to be tunneled via outer tunnel. */
      if (inner_rule->side_to.tunnel != NULL
          && inner_rule->side_to.tunnel->ike_tn
          && inner_rule->side_to.tunnel->outer_tunnel != NULL
          && inner_rule->side_to.tunnel->outer_tunnel == rule->side_to.tunnel
          && inner_rule->side_to.tunnel->outer_tunnel_ike_sa == 0)
        {
          /* Take IKE ports from the tunnel. */
          if (inner_rule->side_to.tunnel->local_port)
            local_ike_port = inner_rule->side_to.tunnel->local_port;
          else
            local_ike_port = pm->params.local_ike_ports[0];
          for (i = 0; i < pm->params.num_ike_ports; i++)
            {
              if (local_ike_port == pm->params.local_ike_ports[i])
                {
                  local_ike_natt_port = pm->params.local_ike_natt_ports[i];
                  remote_ike_port = pm->params.remote_ike_ports[i];
                  remote_ike_natt_port = pm->params.remote_ike_natt_ports[i];
                  break;
                }
            }

          /* Check is this IKE port pair is already processed. */
          for (i = 0; i < SSH_PM_MAX_INNER_TUNNELS; i++)
            {
              if (pm->batch.inner_local_ike_ports[i] == 0)
                break;
              else if (local_ike_port
                       == pm->batch.inner_local_ike_ports[i])
                break;
            }
          if (i == SSH_PM_MAX_INNER_TUNNELS)
            goto error;

          /* Yes, there is already an IKE trigger rule for this port pair. */
          if (pm->batch.inner_local_ike_ports[i] != 0)
            continue;

          /* Mark this IKE port pair processed and continue
             with rule creation.*/
          SSH_ASSERT(i < SSH_PM_MAX_INNER_TUNNELS);
          SSH_ASSERT(pm->batch.inner_local_ike_ports[i] == 0);
          pm->batch.inner_local_ike_ports[i] = local_ike_port;
          pm->batch.inner_local_ike_natt_ports[i] = local_ike_natt_port;
          SSH_ASSERT(pm->batch.inner_remote_ike_ports[i] == 0);
          pm->batch.inner_remote_ike_ports[i] = remote_ike_port;
          pm->batch.inner_remote_ike_natt_ports[i] = remote_ike_natt_port;
          break;
        }
    }
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No more inner tunnel IKE rules needed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_additions);
      return SSH_FSM_CONTINUE;
    }

  /* Create high-level rule for outbound IKE trigger and inbound IKE pass. */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating inner tunnel IKE rule for rule `%@'",
             ssh_pm_rule_render, rule));

  ike_rule = ssh_pm_rule_create_internal(pm, rule->precedence,
                                         SSH_PM_RULE_PASS, NULL,
                                         rule->side_to.tunnel, NULL);
  if (ike_rule == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IKE rule"));
      goto error;
    }

  /* This is a system rule. */
  ike_rule->flags |= (SSH_PM_RULE_I_SYSTEM | SSH_PM_RULE_I_IKE_TRIGGER);
  ike_rule->rule_id = pm->next_rule_id++;
  ike_rule->master_rule = rule;

  SSH_ASSERT(local_ike_port != 0);
  SSH_ASSERT(local_ike_natt_port != 0);
  SSH_ASSERT(remote_ike_port != 0);
  SSH_ASSERT(remote_ike_natt_port != 0);

  ike_rule->side_to.ts =
    ssh_pm_calculate_inner_ike_ts(pm, rule->side_to.ts,
                                  remote_ike_port, remote_ike_natt_port);
  ike_rule->side_from.ts =
    ssh_pm_calculate_inner_ike_ts(pm, rule->side_from.ts, 0, 0);

  if (ike_rule->side_to.ts == NULL
      || ike_rule->side_from.ts == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Inner tunnel IKE tunneling is not allowed by rule `%@'",
                 ssh_pm_rule_render, rule));
      goto error;
    }

  /* Skip IKE trigger if the outer rule is no-trigger. */
  if (rule->flags & SSH_PM_RULE_I_NO_TRIGGER)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No IKE trigger rule needed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_pass_rule);
      goto out;
    }

  /* Check that these IKE trigger traffic selectors do not overlap with
     another rule's IKE trigger traffic selectors. */
  if (ssh_ikev2_ts_narrow(pm->sad_handle, FALSE, NULL,
                          ike_rule->side_to.ts,
                          pm->batch.ike_triggers_to_ts)
      || ssh_ikev2_ts_narrow(pm->sad_handle, FALSE, NULL,
                             ike_rule->side_from.ts,
                             pm->batch.ike_triggers_from_ts))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Inner tunnel IKE trigger traffic selectors overlap with "
                 "another rule's IKE trigger traffic selectors."));
      goto error;
    }

  /* Store traffic selectors to the IKE trigger traffic selectors union. */
  if (ssh_ikev2_ts_union(pm->sad_handle, pm->batch.ike_triggers_from_ts,
                         ike_rule->side_from.ts) != SSH_IKEV2_ERROR_OK
      || ssh_ikev2_ts_union(pm->sad_handle, pm->batch.ike_triggers_to_ts,
                            ike_rule->side_to.ts) != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not store IKE trigger traffic selectors"));
      goto error;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adding inner tunnel IKE trigger rules for rule `%@'",
             ssh_pm_rule_render, rule));

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_trigger);

  /* IKE trigger traffic selectors are valid and do not overlap with another
     rule's IKE trigger traffic selectors. Add rules to engine. */

 out:
  /* Add rule to IKE trigger rule ADT and rule_by_id ADT. */
  ssh_adt_insert(pm->rule_ike_trigger, ike_rule);
  ssh_adt_insert(pm->rule_by_id, ike_rule);

  /* Add IKE trigger rule to outer tunnel rule's subrule list. */
  ike_rule->sub_rule = rule->sub_rule;
  rule->sub_rule = ike_rule;

  pm->batch.ike_rule = ike_rule;
  pm->to_ts_index = 0;
  pm->from_ts_index = 0;
  pm->batch.current_index = 0;

  return SSH_FSM_CONTINUE;

 error:
  if (ike_rule != NULL)
    ssh_pm_rule_free(pm, ike_rule);
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_add_ike_trigger)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule, ike_rule;
  SshEnginePolicyRuleStruct engine_rule;

  ike_rule = pm->batch.ike_rule;
  SSH_ASSERT(ike_rule != NULL);

  /* Use the outer tunnel rule as engine rule's policy context. */
  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  SSH_ASSERT(rule != NULL);

  /* Create engine rule from IKE trigger rule traffic selector item pair. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;
  if (ssh_pm_make_inner_ike_trigger_rule(pm, &engine_rule,
                                         ike_rule->side_from.ts,
                                         pm->from_ts_index,
                                         ike_rule->side_to.ts,
                                         pm->to_ts_index,
                                         SSH_PM_RULE_PRI_USER_HIGH,
                                         TRUE, rule) != PM_ENGINE_RULE_OK)
    goto error;
  SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  /* Add engine rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_trigger_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;

 error:
  SSH_DEBUG(SSH_D_ERROR,
            ("Could not create inner tunnel IKE trigger rule:"
             "restoring old state."));
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_add_ike_trigger_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule ike_rule;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to add inner tunnel IKE trigger rule: "
                              "restoring old state."));
      pm->mt_current.container = pm->rule_by_id;
      pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }

  ike_rule = pm->batch.ike_rule;
  SSH_ASSERT(ike_rule != NULL);
  SSH_ASSERT(ike_rule->rules[pm->batch.current_index]
             == SSH_IPSEC_INVALID_INDEX);
  ike_rule->rules[pm->batch.current_index] = pm->mt_index;
  pm->batch.current_index++;
  SSH_ASSERT(pm->batch.current_index <= SSH_PM_RULE_MAX_ENGINE_RULES);
  pm->batch_changes = 1;

  /* Advance to next traffic selector item pair. */
  if (++pm->from_ts_index  == ike_rule->side_from.ts->number_of_items_used)
    {
      if (++pm->to_ts_index == ike_rule->side_to.ts->number_of_items_used)
        {
          /* Done with the IKE trigger rule. Advance to IKE pass rules. */
          SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_pass_rule);
          return SSH_FSM_CONTINUE;
        }
      pm->from_ts_index = 0;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_trigger);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_create_ike_pass_rule)
{
  SshPm pm = (SshPm) fsm_context;
#ifdef DEBUG_LIGHT
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  SSH_ASSERT(rule != NULL);
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adding inner tunnel IKE pass rules for rule `%@'",
             ssh_pm_rule_render, rule));
#endif /* DEBUG_LIGHT */

  pm->to_ts_index = 0;
  pm->from_ts_index = 0;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_pass_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_add_ike_pass_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule, ike_rule;
  SshEnginePolicyRuleStruct engine_rule;

  ike_rule = pm->batch.ike_rule;
  SSH_ASSERT(ike_rule != NULL);

  /* Use the outer tunnel rule as engine rule's policy context. */
  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
  SSH_ASSERT(rule != NULL);

  /* Create inbound pass rule for inner tunnel IKE. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;
  if (!ssh_pm_make_inner_ike_inbound_pass_rule(pm, &engine_rule,
                                               ike_rule->side_from.ts,
                                               pm->from_ts_index,
                                               ike_rule->side_to.ts,
                                               pm->to_ts_index,
                                               rule->side_to.tunnel->tunnel_id,
                                               SSH_PM_RULE_PRI_USER_HIGH,
                                               TRUE, rule))
    goto error;
  SSH_ASSERT(engine_rule.protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  /* Add engine rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_pass_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;

 error:
  SSH_DEBUG(SSH_D_ERROR,
            ("Could not create inner tunnel IKE pass rule:"
             "restoring old state."));
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_addition_add_ike_pass_rule_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule ike_rule;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** Failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Failed to add inner tunnel IKE pass rule: "
                             "restoring old state."));
      pm->mt_current.container = pm->rule_by_id;
      pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }

  ike_rule = pm->batch.ike_rule;
  SSH_ASSERT(ike_rule != NULL);
  SSH_ASSERT(ike_rule->rules[pm->batch.current_index]
             == SSH_IPSEC_INVALID_INDEX);
  ike_rule->rules[pm->batch.current_index] = pm->mt_index;
  pm->batch.current_index++;
  SSH_ASSERT(pm->batch.current_index <= SSH_PM_RULE_MAX_ENGINE_RULES);
  pm->batch_changes = 1;

  /* Advance to next traffic selector item pair. */
  if (++pm->from_ts_index == ike_rule->side_from.ts->number_of_items_used)
    {
      if (++pm->to_ts_index == ike_rule->side_to.ts->number_of_items_used)
        {
          /* Done with the IKE pass rules. */
          SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_create_ike_rule);
          return SSH_FSM_CONTINUE;
        }
      pm->from_ts_index = 0;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_addition_add_ike_pass_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_sanity_check)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule irule, orule;
  SshADTHandle ih, oh;
  SshPmTunnel itunnel, p1_tunnel;
  SshIkev2PayloadTS to_ts = NULL, from_ts = NULL;
  SshInetIPProtocolID ipproto = 0;
  SshPmTunnelLocalIp local_ip;
  SshUInt32 i;
  SshUInt16 local_ike_port, local_ike_natt_port;
  SshUInt16 remote_ike_port, remote_ike_natt_port;
  Boolean no_trigger_to_tunnel_rule_seen, nested_tunnels;

  /* Skip this sanity check if the policy does not contain any
     nested tunnels. */
  if (pm->batch.nested_tunnels == 0 && pm->nested_tunnels == 0)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions);
      return SSH_FSM_CONTINUE;
    }

  /* Sanity check nested tunnels. This operation is heavy as we need
     to check all rules in rule_by_precedence. */
  nested_tunnels = FALSE;
  for (ih = ssh_adt_enumerate_start(pm->rule_by_precedence);
       ih != SSH_ADT_INVALID;
       ih = ssh_adt_enumerate_next(pm->rule_by_precedence, ih))
    {
      irule = ssh_adt_get(pm->rule_by_precedence, ih);
      SSH_ASSERT(irule != NULL);

      if (irule->flags & SSH_PM_RULE_I_DELETED)
        continue;

      if (irule->side_to.tunnel == NULL
          || irule->side_to.tunnel->outer_tunnel == NULL)
        continue;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Looking up outer rule for inner tunnel traffic "
                 "for rule `%@'",
                 ssh_pm_rule_render, irule));

      itunnel = irule->side_to.tunnel;

      /* Select the tunnel to use for p1. */
      SSH_PM_TUNNEL_GET_P1_TUNNEL(p1_tunnel, itunnel);
      SSH_ASSERT(p1_tunnel != NULL);

      if (itunnel->transform & SSH_PM_IPSEC_ESP)
        ipproto = SSH_IPPROTO_ESP;
      else if (itunnel->transform & SSH_PM_IPSEC_AH)
        ipproto = SSH_IPPROTO_AH;

      /* Use p1_tunnel for checking NAT-T,
         and itunnel for checking NO_NATS_ALLOWED and manual-key. */
      local_ike_port = 0;
      local_ike_natt_port = 0;
      remote_ike_port = 0;
      remote_ike_natt_port = 0;
      if (itunnel->ike_tn
          && (p1_tunnel->flags & SSH_PM_T_DISABLE_NATT) == 0
          && (itunnel->flags & SSH_PM_T_NO_NATS_ALLOWED) == 0)
        {
          for (i = 0; i < pm->params.num_ike_ports; i++)
            {
              if ((p1_tunnel->local_port != 0
                   && p1_tunnel->local_port == pm->params.local_ike_ports[i])
                  || p1_tunnel->local_port == 0)
                {
                  local_ike_port = pm->params.local_ike_ports[i];
                  local_ike_natt_port = pm->params.local_ike_natt_ports[i];
                  remote_ike_port = pm->params.remote_ike_ports[i];
                  remote_ike_natt_port = pm->params.remote_ike_natt_ports[i];
                  break;
                }
            }
        }

      /* Construct packet traffic selectors from inner tunnel. */
      to_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      from_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (to_ts == NULL || from_ts == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not construct inner tunnel traffic selectors"));
          goto error;
        }

      /* Fill in all possible source addresses. */
      if (itunnel->local_ip != NULL
          || itunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
          || itunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
          )
        {
          for (local_ip = itunnel->local_ip;
               local_ip != NULL;
               local_ip = local_ip->next)
            {
              if (!local_ip->unavailable)
                {
                  if (ssh_ikev2_ts_item_add(from_ts, ipproto,
                                            &local_ip->ip, &local_ip->ip,
                                            0, 0) != SSH_IKEV2_ERROR_OK
                      || (local_ike_port != 0 &&
                          ssh_ikev2_ts_item_add(from_ts, SSH_IPPROTO_UDP,
                                &local_ip->ip, &local_ip->ip,
                                local_ike_port, local_ike_port)
                          != SSH_IKEV2_ERROR_OK)
                      || (local_ike_natt_port != 0 &&
                          ssh_ikev2_ts_item_add(from_ts, SSH_IPPROTO_UDP,
                                &local_ip->ip, &local_ip->ip,
                                local_ike_natt_port, local_ike_natt_port)
                          != SSH_IKEV2_ERROR_OK))
                    {
                      SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner "
                                             "tunnel traffic selectors"));
                      goto error;
                    }
                }
            }
        }
      else
        {
          for (i = 0; i < irule->side_from.ts->number_of_items_used; i++)
            {
              if (ssh_ikev2_ts_item_add(from_ts, ipproto,
                                        irule->side_from.ts->items[i].
                                        start_address,
                                        irule->side_from.ts->items[i].
                                        end_address,
                                        0, 0) != SSH_IKEV2_ERROR_OK
                  || (local_ike_port != 0 &&
                      ssh_ikev2_ts_item_add(from_ts, SSH_IPPROTO_UDP,
                                            irule->side_from.ts->items[i].
                                            start_address,
                                            irule->side_from.ts->items[i].
                                            end_address,
                                            local_ike_port, local_ike_port)
                      != SSH_IKEV2_ERROR_OK)
                  || (local_ike_natt_port != 0 &&
                      ssh_ikev2_ts_item_add(from_ts, SSH_IPPROTO_UDP,
                                irule->side_from.ts->items[i].
                                start_address,
                                irule->side_from.ts->items[i].
                                end_address,
                                local_ike_natt_port, local_ike_natt_port)
                      != SSH_IKEV2_ERROR_OK))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner tunnel "
                                         "traffic selectors"));
                  goto error;
                }
            }
        }

      /* Fill in all possible destination addresses. */
      if (itunnel->num_peers > 0)
        {
          for (i = 0; i < itunnel->num_peers; i++)
            {
              if (ssh_ikev2_ts_item_add(to_ts, ipproto,
                                        &itunnel->peers[i],
                                        &itunnel->peers[i],
                                        0, 0) != SSH_IKEV2_ERROR_OK
                  || (remote_ike_port != 0 &&
                      ssh_ikev2_ts_item_add(to_ts, SSH_IPPROTO_UDP,
                                            &itunnel->peers[i],
                                            &itunnel->peers[i],
                                            remote_ike_port, remote_ike_port)
                      != SSH_IKEV2_ERROR_OK)
                  || (remote_ike_natt_port != 0 &&
                      ssh_ikev2_ts_item_add(to_ts, SSH_IPPROTO_UDP,
                                &itunnel->peers[i],
                                &itunnel->peers[i],
                                remote_ike_natt_port, remote_ike_natt_port)
                      != SSH_IKEV2_ERROR_OK))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner tunnel "
                                         "traffic selectors"));
                  goto error;
                }
            }
        }
      else
        {
          for (i = 0; i < irule->side_to.ts->number_of_items_used; i++)
            {
              if (ssh_ikev2_ts_item_add(to_ts, ipproto,
                                        irule->side_to.ts->items[i].
                                        start_address,
                                        irule->side_to.ts->items[i].
                                        end_address,
                                        0, 0) != SSH_IKEV2_ERROR_OK
                  || (remote_ike_port != 0 &&
                      ssh_ikev2_ts_item_add(to_ts, SSH_IPPROTO_UDP,
                                            irule->side_to.ts->items[i].
                                            start_address,
                                            irule->side_to.ts->items[i].
                                            end_address,
                                            remote_ike_port, remote_ike_port)
                      != SSH_IKEV2_ERROR_OK)
                  || (remote_ike_natt_port != 0 &&
                      ssh_ikev2_ts_item_add(to_ts, SSH_IPPROTO_UDP,
                                irule->side_to.ts->items[i].
                                start_address,
                                irule->side_to.ts->items[i].
                                end_address,
                                remote_ike_natt_port, remote_ike_natt_port)
                      != SSH_IKEV2_ERROR_OK))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not construct inner tunnel "
                                         "traffic selectors"));
                  goto error;
                }
            }
        }

      /* Find an outer tunnel rule that matches the inner tunnel traffic. */
      no_trigger_to_tunnel_rule_seen = FALSE;
      for (oh = ssh_adt_enumerate_start(pm->rule_by_precedence);
           oh != SSH_ADT_INVALID;
           oh = ssh_adt_enumerate_next(pm->rule_by_precedence, oh))
        {
          orule = ssh_adt_get(pm->rule_by_precedence, oh);
          SSH_ASSERT(orule != NULL);

          if (orule->flags & SSH_PM_RULE_I_DELETED)
            continue;

          if (orule->side_to.tunnel == itunnel->outer_tunnel || orule == irule)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Matching `%@' <-> `%@' and `%@' <-> `%@'",
                         ssh_ikev2_ts_render, orule->side_to.ts,
                         ssh_ikev2_ts_render, to_ts,
                         ssh_ikev2_ts_render, orule->side_from.ts,
                         ssh_ikev2_ts_render, from_ts));
              if (ssh_ikev2_ts_match(orule->side_to.ts, to_ts)
                  && ssh_ikev2_ts_match(orule->side_from.ts, from_ts))
                {
                  if (orule == irule)
                    {
                      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                    "Recursive nested tunnel configuration");
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Detected recursion in nested tunnel "
                                 "configuration"));
                      SSH_DEBUG(SSH_D_FAIL,
                                ("Inner rule %@",
                                 ssh_pm_rule_render, irule));
                      goto error;
                    }

                  /* For auto-start and interface-trigger to-tunnel rules,
                     continue lookup until a matching drop rule is found. */
                  else if (orule->flags & SSH_PM_RULE_I_NO_TRIGGER)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Found no-trigger outer rule `%@` for "
                                 "inner tunnel traffic, "
                                 "continuing searching for a drop rule.",
                                 ssh_pm_rule_render, orule));
                      no_trigger_to_tunnel_rule_seen = TRUE;
                      continue;
                    }
                  else
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Found outer rule `%@` for inner tunnel "
                                 "traffic",
                                 ssh_pm_rule_render, orule));
                      break;
                    }
                }
            }

          if (no_trigger_to_tunnel_rule_seen
              && (orule->flags & SSH_PM_RULE_PASS) == 0
              && ssh_ikev2_ts_match(orule->side_to.ts, to_ts)
              && ssh_ikev2_ts_match(orule->side_from.ts, from_ts))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Found drop rule `%@` for inner tunnel traffic",
                         ssh_pm_rule_render, orule));
              break;
            }
        }
      ssh_ikev2_ts_free(pm->sad_handle, to_ts);
      to_ts = NULL;
      ssh_ikev2_ts_free(pm->sad_handle, from_ts);
      from_ts = NULL;

      if (oh == SSH_ADT_INVALID)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "No policy rule found for encapsulation of nested "
                        "inner tunnel traffic.");
          SSH_DEBUG(SSH_D_FAIL,
                    ("No rule found for nested inner tunnel traffic."));
          goto error;
        }

      /* A sane nested tunnel has been seen. */
      nested_tunnels = TRUE;
    }

  /* Mark that policy contains at least one nested tunnel. */
  if (nested_tunnels == TRUE)
    pm->nested_tunnels = 1;
  else
    pm->nested_tunnels = 0;

  /* All additions are checked for sanity.  Move on to deletions. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions);
  return SSH_FSM_CONTINUE;

 error:
  if (to_ts)
    ssh_ikev2_ts_free(pm->sad_handle, to_ts);
  if (from_ts)
    ssh_ikev2_ts_free(pm->sad_handle, from_ts);
  pm->mt_current.container = pm->rule_by_id;
  pm->mt_current.handle = ssh_adt_enumerate_start(pm->rule_by_id);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_deletions)
{
  SshPm pm = (SshPm) fsm_context;
  SshADTHandle handle, next;
  SshPmRule rule;

  if (pm->mt_current.handle != SSH_ADT_INVALID)
    {
      rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_DELETED);

      pm->batch_deleted_rules = 1;

      /* Delete this rule's low-level rules. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions_delete);
      return SSH_FSM_CONTINUE;
    }

  /* All deletions done.  As the final step we must remove the deleted
     rules from the SPD and recycle the rule objects. */
  if (pm->batch.deletions)
    {
      for (handle = ssh_adt_enumerate_start(pm->batch.deletions);
           handle != SSH_ADT_INVALID;
           handle = next)
        {
          next = ssh_adt_enumerate_next(pm->batch.deletions, handle);
          rule = ssh_adt_get(pm->batch.deletions, handle);

          SSH_ASSERT(rule->flags & SSH_PM_RULE_I_DELETED);

          /* Remove this rule from the sub-rule chain (double-linked
             by the master_rule and sub_rule fields). */
          if (rule->master_rule)
            rule->master_rule->sub_rule = rule->sub_rule;
          if (rule->sub_rule)
            rule->sub_rule->master_rule = rule->master_rule;
          rule->master_rule = NULL;
          rule->sub_rule = NULL;

          /* Remove the rule from its containers */
          if (rule->flags & SSH_PM_RULE_I_IKE_TRIGGER)
            {
              SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
              ssh_adt_detach(pm->rule_ike_trigger,
                             &rule->rule_ike_trigger_hdr);
            }
          else
            {
              ssh_adt_detach(pm->rule_by_precedence,
                             &rule->rule_by_precedence_hdr);
              if (rule->in_auto_start_adt)
                {
                  ssh_adt_detach(pm->rule_by_autostart,
                                 &rule->rule_by_autostart_hdr);
                  rule->in_auto_start_adt = 0;
                }
            }
          ssh_adt_detach(pm->batch.deletions, handle);
          ssh_adt_detach(pm->rule_by_id, &rule->rule_by_index_hdr);

          /* Finally delete the rule */
          ssh_pm_rule_free(pm, rule);
        }
    }

  /* Now we have successfully added new rules and removed the
     deleted ones.  As the final pass we must clear
     SSH_PM_RULE_I_IN_BATCH flags from the new rules. */
  if (pm->batch.additions)
    {
      for (handle = ssh_adt_enumerate_start(pm->batch.additions);
           handle != SSH_ADT_INVALID;
           handle = next)
        {
          next = ssh_adt_enumerate_next(pm->batch.additions, handle);
          rule = ssh_adt_get(pm->batch.additions, handle);

          /* Remove the rule for the batch additions container */
          ssh_adt_detach(pm->batch.additions, handle);

          SSH_ASSERT((rule->flags & SSH_PM_RULE_I_DELETED) == 0);
          if (rule->flags & SSH_PM_RULE_I_IN_BATCH)
            {
              rule->flags &= ~SSH_PM_RULE_I_IN_BATCH;
              /* And wake up possible threads waiting for the batch to
                 complete. */
              SSH_FSM_CONDITION_BROADCAST(&rule->cond);
            }
        }
    }

  /* Handle IKE trigger rules. */
  for (handle = ssh_adt_enumerate_start(pm->rule_ike_trigger);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_ike_trigger, handle))
    {
      rule = ssh_adt_get(pm->rule_ike_trigger, handle);
      SSH_ASSERT(rule != NULL);
      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_IKE_TRIGGER);
      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
      SSH_ASSERT((rule->flags & SSH_PM_RULE_I_DELETED) == 0);
      rule->flags &= ~SSH_PM_RULE_I_IN_BATCH;
    }

  pm->batch_failed = 0;

  if (pm->batch.additions != NULL)
    {
      SSH_ASSERT(ssh_adt_num_objects(pm->batch.additions) == 0);
      ssh_adt_destroy(pm->batch.additions);
      pm->batch.additions = NULL;
   }
  if (pm->batch.deletions != NULL)
    {
      SSH_ASSERT(ssh_adt_num_objects(pm->batch.deletions) == 0);
      ssh_adt_destroy(pm->batch.deletions);
      pm->batch.deletions = NULL;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done_enable_policy_lookup);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_deletions_delete)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  /* Wait until the rule has no references. In addition, delete possible
     active p1 negotiation references. */
  if (rule->refcount > 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Waiting until rule `%@' has no references: refcount=%d",
                 ssh_pm_rule_render, rule, (int) rule->refcount));

#ifdef WITH_IKE
      /* Abort negotiations */
      if (!(rule->flags & SSH_PM_RULE_I_IKE_ABORT))
        ssh_pm_delete_rule_negotiations(pm, rule);
#endif /* WITH_IKE */

      rule->flags |= SSH_PM_RULE_I_IKE_ABORT;

      /* Wake up all users of this thread.  Note that this does not
         wake up IKE negotiations.  They will continue when their IKE
         negotiation is completed. */
      SSH_FSM_CONDITION_BROADCAST(&rule->cond);
      SSH_FSM_CONDITION_BROADCAST(&pm->resume_cond);
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      if (rule->side_to.tunnel && rule->side_to.tunnel->vip)
        {
          rule->side_to.tunnel->vip->rule_deleted = 1;
          SSH_FSM_CONDITION_BROADCAST(&rule->side_to.tunnel->vip->cond);
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      /* And wait that some of the threads are finished. */
      if (rule->refcount > 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Waiting until rule `%@' has no references: refcount=%d",
                     ssh_pm_rule_render, rule, (int) rule->refcount));
          SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
        }
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Deleting rule `%@'", ssh_pm_rule_render, rule));

  /* Does this rule have any more engine-level rules? */
  pm->mt_index = pm_get_next_engine_rule(rule);
  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* No more low-level rules.  Move ahead in the delete batch. */
      pm->mt_current.handle = ssh_adt_enumerate_next(pm->mt_current.container,
                                                     pm->mt_current.handle);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions);
      return SSH_FSM_CONTINUE;
    }

  /* Remove all engine-level rules. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions_delete_rule);
  SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, pm->mt_index,
                                         ssh_pm_delete_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_deletions_delete_rule)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All low level rules (and flows) of this rule deleted.  Move
         to the next high-level rule. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_deletions_delete);
      return SSH_FSM_CONTINUE;
    }

  /* Remove the engine rule `pm->mt_index'. */
  SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, pm->mt_index,
                                         ssh_pm_delete_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_abort)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule, *rulep;
  SshADTHandle handle, next;

  /* The abort operation is potentially expensive, it iterates through
     all rules on the pm->rule_by_id container. */
  if (pm->mt_current.handle != SSH_ADT_INVALID)
    {
      rule = ssh_adt_get(pm->rule_by_id, pm->mt_current.handle);
      SSH_ASSERT(rule != NULL);

      if ((rule->flags & (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED))
          == SSH_PM_RULE_I_IN_BATCH)
        {
          /* This rule was successfully added in this batch.  Let's delete
             it. */
          SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort_delete);
          return SSH_FSM_CONTINUE;
        }

      /* Move ahead. */
      pm->mt_current.handle =
        ssh_adt_enumerate_next(pm->rule_by_id, pm->mt_current.handle);
      return SSH_FSM_CONTINUE;
    }

  /* All additions of this batch have been removed.  Now we are
     ready for final cleanup. */
  for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      next = ssh_adt_enumerate_next(pm->rule_by_id, handle);
      rule = ssh_adt_get(pm->rule_by_id, handle);
      SSH_ASSERT(rule != NULL);

      /* Break all `sub_rule' relations from the added rules. */
      for (rulep = &rule->sub_rule; *rulep; )
        {
          if (((*rulep)->flags & (SSH_PM_RULE_I_DELETED
                                  | SSH_PM_RULE_I_IN_BATCH))
              == SSH_PM_RULE_I_IN_BATCH)
            {
              /* The rule was added in this batch.  Break the sub-rule
                 relation. */
              (*rulep)->master_rule = NULL;
              *rulep = (*rulep)->sub_rule;
            }
          else
            {
              rulep = &(*rulep)->sub_rule;
            }
        }
      if (rule->flags & SSH_PM_RULE_I_DELETED)
        {
          /* The rule was to be deleted in this batch.  Just clear
             the deletion flag, so it will not get deleted.  */
          rule->flags &=
                ~(SSH_PM_RULE_I_DELETED | SSH_PM_RULE_I_IN_BATCH);

          /* Remove the rule from the deletions container. */
          ssh_adt_detach(pm->batch.deletions, &rule->rule_by_index_del_hdr);
        }
      else if (rule->flags & SSH_PM_RULE_I_IN_BATCH)
        {
          SSH_ASSERT((rule->flags & SSH_PM_RULE_I_DELETED) == 0);

          /* The rule was to be added in this batch. */

          /* The engine-level rules have already been deleted. */
#ifdef DEBUG_LIGHT
          {
            SshUInt32 i;

            for (i = 0; i < SSH_PM_RULE_MAX_ENGINE_RULES; i++)
              SSH_ASSERT(rule->rules[i] == SSH_IPSEC_INVALID_INDEX);
          }
#endif /* DEBUG_LIGHT */

          /* Remove the rule from its containers. */
          if (rule->flags & SSH_PM_RULE_I_IKE_TRIGGER)
            {
              SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
              ssh_adt_detach(pm->rule_ike_trigger,
                             &rule->rule_ike_trigger_hdr);
            }
          else
            {
              ssh_adt_detach(pm->rule_by_precedence,
                             &rule->rule_by_precedence_hdr);
              ssh_adt_detach(pm->batch.additions,
                             &rule->rule_by_index_add_hdr);

              if (rule->in_auto_start_adt)
                {
                  ssh_adt_detach(pm->rule_by_autostart,
                                 &rule->rule_by_autostart_hdr);
                  rule->in_auto_start_adt = 0;
                }
            }
          ssh_adt_detach(pm->rule_by_id, &rule->rule_by_index_hdr);

          /* Remove this sub-rule from the master-rule's subrule list. */
          if (rule->master_rule != NULL)
            {
              SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
              for (rulep = &rule->master_rule->sub_rule; *rulep;)
                {
                  if (*rulep == rule)
                    *rulep = (*rulep)->sub_rule;
                  else
                    rulep = &(*rulep)->sub_rule;
                }
            }

          /* Finally free the rule. */
          ssh_pm_rule_free(pm, rule);
        }
    }

  /* Free all pending additions and deletions. */
  ssh_adt_destroy(pm->batch.additions);
  pm->batch.additions = NULL;

  ssh_adt_destroy(pm->batch.deletions);
  pm->batch.deletions = NULL;

  /* And notify user. */
  pm->batch_failed = 1;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done_enable_policy_lookup);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_abort_delete)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;

  rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);

  /* Wait that all sub-threads go away from the rule. */
  if (rule->refcount > 0)
    {
      rule->flags |= SSH_PM_RULE_I_BATCH_F;
      SSH_FSM_CONDITION_BROADCAST(&rule->cond);
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  /* Does this rule have any more engine-level rules? */
  pm->mt_index = pm_get_next_engine_rule(rule);
  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* No, we did not have an old rule.  Let's move ahead. */
      pm->mt_current.handle = ssh_adt_enumerate_next(pm->mt_current.container,
                                                     pm->mt_current.handle);
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort);
      return SSH_FSM_CONTINUE;
    }

  /* Remove all engine level rules. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort_delete_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_abort_delete_rule)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All low level flows of this rule deleted.  Move to the next
         low-level rule. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_abort_delete);
      return SSH_FSM_CONTINUE;
    }

  /* Remove the engine rule `pm->mt_index'. */
  SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, pm->mt_index,
                                         ssh_pm_delete_rule_cb, thread));
  SSH_NOTREACHED;
}

static void
ssh_pm_st_main_batch_check_sa_validity(SshPm pm)
{
  SshPmP1 p1 = NULL;
  SshPmP1 next_p1 = NULL;
  SshUInt32 hash = 0;
  SshPmTunnel tunnel = NULL;

  /* Clear resume queue. This is safe to do since we are looping through
     the whole IKE SA hash table. */
  pm->resume_queue = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Going through IKE SA table. "));

  for (hash = 0; hash < SSH_PM_IKE_SA_HASH_TABLE_SIZE; hash++)
    {
      p1 = pm->ike_sa_hash[hash];

      while (p1)
        {
          Boolean is_ikev1 = FALSE;
          SshUInt32 flags = 0;

          next_p1 = p1->hash_next;

          /* Clear resume queue pointer. */
          p1->resume_queue_next = NULL;
          p1->in_resume_queue = 0;

          /* Do the delayed IPsec delete notifications. */
          tunnel = ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id);

          /* Invalidate p1's tunnel_id if tunnel is not part of the
             active configuration. PM IKE SA timer will handle IKE SA
             deletion in a delayed fashion. */
          if (tunnel == NULL || tunnel->referring_rule_count == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("IKE SA %p was negotiated from a tunnel that does "
                         "not belong to the active policy, "
                         "marking for deletion",
                         p1->ike_sa));
              p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
              if (tunnel && tunnel->vip)
                ssh_pm_virtual_ip_free(pm, SSH_IPSEC_INVALID_INDEX, tunnel);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
            }

#ifdef SSHDIST_IKEV1
          if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
            is_ikev1 = TRUE;
          flags = SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

          /* Send delayed IPsec notification in following cases:
             1. This is IKEv1 SA
             2. IKEv2 and only rules reconfigured. */
          if (p1->delete_notification_requests &&
              (is_ikev1 || (tunnel && tunnel->referring_rule_count > 0)))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Sending delayed IPsec delete notifications for "
                         "P1 %p",
                         p1));

              ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
            }

          /* Otherwise free any pending delete notification requests, as IKEv2
             SA is going to get deleted soon anyway. */
          else
            {
              ssh_pm_free_ipsec_delete_notification_requests(p1);

              /* Delete P1 with no child SA's or vanished tunnel ID's.
                 I.e. tunnel is removed or all the IPsec SA's has been removed
                 for some reason... */
              if ((ssh_pm_peer_num_child_sas_by_p1(pm, p1) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
                   /* ... but don't delete a P1 that is waiting for
                      some cfgmode-based child SA's to appear. */
                   && !(tunnel != NULL && tunnel->vip != NULL &&
                        tunnel->vip->rules != NULL &&
                        (tunnel->vip->rules->rule->flags &
                         SSH_PM_RULE_CFGMODE_RULES) != 0)
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
                   ) || tunnel == NULL || tunnel->referring_rule_count == 0)
                {
                  if (!SSH_PM_P1_DELETED(p1))
                    {
                      int i;

                      /* Aborting all ongoing operations. Not sure
                         if this is really necessary, but playing safe. */
                      for (i = 0; i < PM_IKE_NUM_INITIATOR_OPS; i++)
                        {
                          SshOperationHandle op = p1->initiator_ops[i];

                          /* Clear the operation handle from the p1 to avoid
                             recursive calls aborting the operations. */
                          p1->initiator_ops[i] = NULL;
                          if (op)
                            ssh_operation_abort(op);
                        }

                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Deleting IKE SA %p", p1->ike_sa));
                      SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags,
                                  pm_ike_sa_delete_notification_done_callback);
                    }
                }
            }

          p1 = next_p1;
        }
    }
}

SSH_FSM_STEP(ssh_pm_st_main_batch_done_enable_policy_lookup)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done_resume);

  SSH_ASSERT(pm->batch_active);

  /* Now the engine's rule set is either updated or rolled back to the
     previous state.  Let's enable policy lookups. */
  SSH_FSM_ASYNC_CALL(ssh_pme_enable_policy_lookup(pm->engine,
                                                  pm_batch_policy_lookup_cb,
                                                  thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_done_resume)
{
  SshPm pm = (SshPm) fsm_context;

  /* Resume policy manager */
  if (!ssh_pm_policy_resume(pm))
    SSH_DEBUG(SSH_D_FAIL, ("Policy manager resume failed."));
  else
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager resumed."));

  /* Now loop all the IKE SAs. do all pending IPsec SA delete
     notifications, remove childless IKE SAs and IKE SAs with
     removed tunnels. */
  if (pm->batch_deleted_rules)
    ssh_pm_st_main_batch_check_sa_validity(pm);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_batch_done)
{
  SshPm pm = (SshPm) fsm_context;
  Boolean success;
  SshPmStatusCB status_cb;
  void *status_cb_context;

  /* Signal that the main batch has ended and the
     suspended threads continue. */
  SSH_FSM_CONDITION_BROADCAST(&pm->resume_cond);

  success = pm->batch_failed ? FALSE : TRUE;
  status_cb = pm->batch.status_cb;
  status_cb_context = pm->batch.status_cb_context;

  /* Notify submodules interested on policy changes. */
  if (pm->batch_changes)
    ssh_pm_dpd_policy_change_notify(pm);

#ifdef SSH_PM_BLACKLIST_ENABLED
  /* In successful case commit blacklist changes and otherwise abort them. */
  if (success)
    ssh_pm_blacklist_commit(pm);
  else
    ssh_pm_blacklist_abort(pm);
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /* The batch is completed, cleanup. */
  pm->batch_deleted_rules = 0;
  pm->batch_active = 0;
  pm->batch_failed = 0;
  pm->batch_changes = 0;
  pm->batch.status_cb = NULL_FNPTR;
  pm->batch.status_cb_context = NULL;

  if (pm->batch.ike_triggers_to_ts != NULL)
    ssh_ikev2_ts_free(pm->sad_handle, pm->batch.ike_triggers_to_ts);
  pm->batch.ike_triggers_to_ts = NULL;
  if (pm->batch.ike_triggers_from_ts != NULL)
    ssh_ikev2_ts_free(pm->sad_handle, pm->batch.ike_triggers_from_ts);
  pm->batch.ike_triggers_from_ts = NULL;

  /* Call user callback. */
  if (status_cb)
    (*status_cb)(pm, success, status_cb_context);

  /* Check auto-start rules after policy modifications. */
  pm->auto_start = 1;

  SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);
  SSH_FSM_SET_NEXT(ssh_pm_st_main_run);

  SSH_APE_MARK(1, ("Policy manager resumed"));

  return SSH_FSM_CONTINUE;
}
