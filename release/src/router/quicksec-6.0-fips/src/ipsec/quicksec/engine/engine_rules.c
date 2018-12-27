/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Manipulation of rule objects in the engine (except rule lookup and rule
   execution).
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineRules"

/* Makes the given rule independent.  This does nothing if the rule is already
   independent; otherwise this removes the rule from the dependent rules
   list of the rule that it depends on.  Engine->flow_table_lock must be
   held when this is called. */

void ssh_engine_clear_rule_dependency(SshEngine engine, SshUInt32 rule_index)
{
  SshEnginePolicyRule rule, rule2;

  /* Do nothing if the rule does not depend on another rule. */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  if (rule->depends_on == SSH_IPSEC_INVALID_INDEX)
    return;

  /* Remove the rule from the dependent rules list of the other rule. */
  SSH_ASSERT(rule->depends_on < engine->rule_table_size);
  if (rule->dep_prev == SSH_IPSEC_INVALID_INDEX)
    {
      rule2 = SSH_ENGINE_GET_RULE(engine, rule->depends_on);
      SSH_ASSERT(rule2->dependent_rules == rule_index);
      rule2->dependent_rules = rule->dep_next;
    }
  else
    {
      rule2 = SSH_ENGINE_GET_RULE(engine, rule->dep_prev);
      rule2->dep_next = rule->dep_next;
    }
  if (rule->dep_next != SSH_IPSEC_INVALID_INDEX)
    {
      rule2 = SSH_ENGINE_GET_RULE(engine, rule->dep_next);
      rule2->dep_prev = rule->dep_prev;
    }

  /* Mark that the rule no longer depends on anything. */
  rule->depends_on = SSH_IPSEC_INVALID_INDEX;
#ifdef DEBUG_LIGHT
  rule->dep_next = 0xdeadbeef;
  rule->dep_prev = 0xdeadbeef;
#endif /* DEBUG_LIGHT */
}

static void
ssh_engine_detach_flows(SshEngine engine, SshEnginePolicyRule rule,
                        SshUInt32 trd_index, Boolean match_trd)
{
  SshUInt32 flow_index, next_flow_index;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;

#ifdef SSH_ENGINE_DANGLE_FLOWS
  SshUInt32 rule_index;
  rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);
#endif /* SSH_ENGINE_DANGLE_FLOWS */

  flow_index = rule->flows;

  while (flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
      next_flow_index = c_flow->rule_next;

      d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);

      if (match_trd == TRUE
          && d_flow->forward_transform_index != trd_index
          && d_flow->reverse_transform_index != trd_index)
        {
          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
          flow_index = next_flow_index;
          continue;
        }

      FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

#ifdef SSH_ENGINE_DANGLE_FLOWS
      if (rule->type == SSH_ENGINE_RULE_APPLY
          || (rule->type == SSH_ENGINE_RULE_TRIGGER
              && (rule->transform_index != SSH_IPSEC_INVALID_INDEX
                  || (rule->flags & SSH_ENGINE_RULE_UNDEFINED) != 0)))
        {
          if (ssh_engine_flow_dangle(engine, flow_index) == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Failed to dangle flow %d! Freeing it!",
                         (int) flow_index));
              ssh_engine_free_flow(engine, flow_index);
            }
          else if (c_flow->rule_index == rule_index && match_trd == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("flow failed to find a better rule to dangle "
                         "from. Destroying it."));
              ssh_engine_free_flow(engine, flow_index);
            }
        }
      else
#endif /* SSH_ENGINE_DANGLE_FLOWS */
        {
          ssh_engine_free_flow(engine, flow_index);
        }
      flow_index = next_flow_index;
    }
}


static void
ssh_engine_rule_reset_transform(SshEngine engine, SshEnginePolicyRule rule)

{
  SshUInt32 rule_index, transform_index, *rulep;
  SshEngineTransformControl c_trd;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Save pointers to referenced objects. */
  transform_index = rule->transform_index;
  rule->transform_index = SSH_IPSEC_INVALID_INDEX;
  rule_index = rule->rule_index;

  /* If the rule had a transform, decrement the reference count of the
     transform.  The transform data will be freed when it has no
     references left */
  if (transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Remove this rule from the transform's list of all rules referencing
         it. */
      c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
      SSH_ASSERT(c_trd != NULL);
      for (rulep = &c_trd->rules;
           *rulep != SSH_IPSEC_INVALID_INDEX && *rulep != rule_index;
           rulep = &(SSH_ENGINE_GET_RULE(engine, *rulep)->trd_next))
        ;
      SSH_ASSERT(*rulep == rule_index);
      *rulep = rule->trd_next;
      /* Decrement the reference count of the transform.  This will free
         the transform if there are no other rules referencing it. */
      ssh_engine_decrement_transform_refcnt(engine, transform_index);
    }
}

/* Deletes the specified rule and all of its flows and dependent
   rules.  This may also delete trds if they have no more references.
   Engine->flow_table_lock must be held when this is called. */

void ssh_engine_delete_rule(SshEngine engine, SshUInt32 rule_index)
{
  SshUInt32 dep_rule_index;
  SshEnginePolicyRule rule, parent_rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(rule_index < engine->rule_table_size);
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  SSH_ASSERT(rule->type != SSH_ENGINE_RULE_NONEXISTENT);
  SSH_ASSERT((rule->flags & SSH_ENGINE_RULE_DELETED) == 0);
#ifndef SSH_IPSEC_SMALL
  if (rule->flags & SSH_ENGINE_RULE_PLACEHOLDER)
    {
      SshEnginePolicyRule owner_rule;
      owner_rule = SSH_ENGINE_GET_RULE(engine, rule->depends_on);
      if (owner_rule->flags & SSH_ENGINE_RULE_DELETED
          || rule->type == SSH_ENGINE_RULE_DORMANT_APPLY
          || engine->ipm_open == FALSE)
        {
          /* Remove rule from lookup only if it is not a placeholder
             rule or it's parent rule has been deleted */
          rule->flags &= ~SSH_ENGINE_RULE_PLACEHOLDER;
          ssh_engine_rule_lookup_remove(engine,
                                        engine->policy_rule_set,
                                        (SshEngineLookupPreamble)rule);
        }
    }
  else
#endif /* SSH_IPSEC_SMALL */
    {
      /* Remove the rule from the rule lookup structures. */
      ssh_engine_rule_lookup_remove(engine,
                                    engine->policy_rule_set,
                                    (SshEngineLookupPreamble)rule);
    }

  /* We mark the rule as invalid (which means rule execution will not
     use it), and decrement its reference count so that it will be
     freed when all rule executions are gone (or here if no executions
     are ongoing).  Decrementing rule refcnt will also decrement the
     refcnt of the transform. */
  rule->flags |= SSH_ENGINE_RULE_DELETED;

  /* Delete all flows created by the rule. */
  ssh_engine_detach_flows(engine, rule, SSH_IPSEC_INVALID_INDEX, FALSE);

  /* If the rule still has an inbound ipsec flow, it is an error, it
     should have been destroyed by the rule->flows above */
  SSH_ASSERT(rule->incoming_ipsec_flow == SSH_IPSEC_INVALID_INDEX);

  /* Here we unfortunately must resort to some magic. Since
     appgw trigger rules can induce flows with transforms to be attached
     to the undefined parent trigger rule, we must go to work on the parent
     rule also. */
  if (rule->depends_on != SSH_IPSEC_INVALID_INDEX)
    {
      parent_rule = SSH_ENGINE_GET_RULE(engine, rule->depends_on);
      if (parent_rule->type == SSH_ENGINE_RULE_TRIGGER
          && (parent_rule->flags & SSH_ENGINE_RULE_UNDEFINED)
          && rule->transform_index != SSH_IPSEC_INVALID_INDEX
          && (parent_rule->flags & SSH_ENGINE_RULE_DELETED) == 0)
        {
          SSH_DEBUG(SSH_D_MY, ("detaching flows also from parent rule %d",
                               (int) rule->depends_on));
          ssh_engine_detach_flows(engine, parent_rule,
                                  rule->transform_index, TRUE);
          SSH_DEBUG(SSH_D_MY, ("detaching done"));
        }
    }

  /* Delete all dependent rules. */
  while (rule->dependent_rules != SSH_IPSEC_INVALID_INDEX)
    {
      /* Delete the dependent rule.  This will also free all of its flows
         and any associated trds (if they have no other references). */
      dep_rule_index = rule->dependent_rules;
      ssh_engine_delete_rule(engine, dep_rule_index);
      SSH_ASSERT(rule->dependent_rules != dep_rule_index);
    }

#ifndef SSH_IPSEC_SMALL
  if (!(rule->flags & SSH_ENGINE_RULE_PLACEHOLDER))
#endif /* SSH_IPSEC_SMALL */
    {
      /* If this rule depends on another rule, remove the dependency now.
         As a result, the rule will be independent.  We do this so that
         the rule gets removed from the dependent_rules list of its parent. */
      ssh_engine_clear_rule_dependency(engine, rule_index);
    }

  /* Free rule from transform already here. This simplifies iterations
     over transform hash tables that try free transforms matching
     certain criteria. */
  ssh_engine_rule_reset_transform(engine, rule);

  /* The following references may exist on the rule at this point:
     - a reference for the existence of the rule
     - any references held by ongoing rule execution. */
  ssh_engine_decrement_rule_refcnt(engine, rule);
}

/* Decrements the reference count of the given rule, and if it becomes
   zero, frees the rule.  Any flows associated with the rule are
   silently deleted, and the rule is put on the freelist.  The rule
   cannot have any dependent rule and cannot depend on any other rule
   when this is called.  Engine->flow_table_lock must be held when
   this is called. */

void ssh_engine_decrement_rule_refcnt(SshEngine engine,
                                      SshEnginePolicyRule rule)
{
  SshUInt32 rule_index;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Decrement the reference count of the rule. */
  SSH_ASSERT(rule->type != SSH_ENGINE_RULE_NONEXISTENT);
  SSH_ASSERT(rule->refcnt != 0);
  rule->refcnt--;
  SSH_DEBUG(SSH_D_LOWOK, ("Decrementing rule %lu refcount to %d",
                          (unsigned long) rule->rule_index, rule->refcnt));

  /* If we still have references, do nothing more. */
  if (rule->refcnt != 0)
    return;

  SSH_ASSERT(rule != engine->drop_rule);
  SSH_ASSERT(rule != engine->pass_rule);

  /* Determine the index of the rule. */
  rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);
  SSH_ASSERT(rule_index < engine->rule_table_size);

  /* The rule has no more references. */
  SSH_DEBUG(SSH_D_MIDOK, ("rule %d refcnt becomes zero",
                          (int) rule_index));

  /* If reference count is zero, we know that this rule has neither
     flows nor dependent rules. */
  SSH_ASSERT(rule->flows == SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(rule->dependent_rules == SSH_IPSEC_INVALID_INDEX);

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  ssh_engine_nat_unregister_port(engine, &rule->nat_selector_dst_ip,
                                 rule->nat_selector_dst_port);

  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC) &&
      !(rule->nat_flags & SSH_PM_NAT_SHARE_PORT_SRC))
    {
      ssh_engine_nat_unregister_ports(engine, &rule->nat_src_ip_low,
                                      &rule->nat_src_ip_high,
                                      rule->nat_src_port);
    }

  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST) &&
      (rule->nat_flags & SSH_PM_NAT_NO_SHARE_PORT_DST))
    {
      ssh_engine_nat_unregister_ports(engine, &rule->nat_dst_ip_low,
                                      &rule->nat_dst_ip_high,
                                      rule->nat_dst_port);
    }

  SSH_IP_UNDEFINE(&rule->nat_selector_dst_ip);
  SSH_IP_UNDEFINE(&rule->nat_src_ip_low);
  SSH_IP_UNDEFINE(&rule->nat_src_ip_high);
  SSH_IP_UNDEFINE(&rule->nat_dst_ip_low);
  SSH_IP_UNDEFINE(&rule->nat_dst_ip_high);
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Free rule from transform, if the association is still valid. */
  ssh_engine_rule_reset_transform(engine, rule);

#ifndef SSH_IPSEC_SMALL
  if (rule->flags & SSH_ENGINE_RULE_PLACEHOLDER)
    {
      /* Transform us back into dormant apply rule */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Transforming rule back to dormant rule!"));
      SSH_ASSERT(rule->type == SSH_ENGINE_RULE_APPLY);
      rule->flags &= ~SSH_ENGINE_RULE_DELETED;
      rule->flags &= ~SSH_PM_ENGINE_RULE_SA_OUTBOUND;
      rule->type = SSH_ENGINE_RULE_DORMANT_APPLY;

      if (!(rule->flags & SSH_ENGINE_RULE_USE_ONCE))
        rule->flags &= ~SSH_ENGINE_RULE_USED;




      rule->refcnt = 1;
    }
  else
#endif /* SSH_IPSEC_SMALL */
    {
      ssh_engine_clear_rule_dependency(engine, rule_index);

      /* Put the rule object on the freelist.  But only if the policy
         manager does not have an extra reference to the rule. */
      if ((rule->flags & SSH_ENGINE_RULE_PM_REFERENCE) == 0)
        ssh_engine_rule_free(engine, rule_index);
    }

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.active_rules--;
#endif /* SSH_IPSEC_STATISTICS */
}


























































#ifndef SSH_IPSEC_SMALL
static Boolean
ssh_engine_is_rule_expensive(SshEngine engine,
                             const SshEnginePolicyRule rule)
{
  size_t addrlen;

  if (rule->protocol == SSH_PROTOCOL_IP6)
    addrlen = 16;
  else
    addrlen = 4;

  if (memcmp(rule->dst_ip_low, rule->dst_ip_high, addrlen) != 0)
    {
      return TRUE;
    }
  return FALSE;
}


#endif /* SSH_IPSEC_SMALL */

/* Main workhorse function for ssh_engine_pme_add_rule(). Returns the
   rule_index if the rule addition is successful, otherwise
   SSH_IPSEC_INVALID_INDEX. The 'engine->flow_control_table_lock' MUST
   be held. */
static SshUInt32
ssh_engine_add_rule(SshEngine engine, const SshEnginePolicyRule pm_rule,
                    Boolean require_incoming_flow)
{
  SshUInt32 rule_index;
  SshEnginePolicyRule rule, rule2, rule3;
  SshEngineTransformControl c_trd;
  Boolean was_inactive;
#ifndef SSH_IPSEC_SMALL
  SshEnginePolicyRuleStruct rule_bak;
  Boolean was_dormant = FALSE;
#endif /* SSH_IPSEC_SMALL */

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  rule_index = SSH_IPSEC_INVALID_INDEX;
  rule = NULL;

  /* ssh_engine_pme_add_rule() and ssh_engine_notify_pm_close() may be running
     concurrently on different CPU's... */
  SSH_ASSERT(engine->ipm_open);

  /* First check, do not let pass unmodified rules to be anything else
     than pass type. */
  if (pm_rule->flags & SSH_ENGINE_RULE_PASS_UNMODIFIED)
    {
      if ((pm_rule->type != SSH_ENGINE_RULE_PASS) &&
          (pm_rule->flags & SSH_ENGINE_NO_FLOW) == 0 &&
          pm_rule->transform_index != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Cannot add unmodified rule with type 0x%x",
                     pm_rule->flags));
          goto error;
        }
    }

  /* Check that the rule's transform index is still valid. */
  if (pm_rule->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, pm_rule->transform_index);
      if (c_trd == NULL
          || (c_trd->control_flags & SSH_ENGINE_TR_C_DELETE_PENDING))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("TRD generation expired or pending deletion "));
          goto error;
        }
    }

  if (pm_rule->depends_on != SSH_IPSEC_INVALID_INDEX)
    {
      rule2 = SSH_ENGINE_GET_RULE(engine, pm_rule->depends_on);
      if ((rule2->type == SSH_ENGINE_RULE_TRIGGER)
          && (rule2->flags & SSH_ENGINE_RULE_USE_ONCE))
        rule2->flags |= SSH_ENGINE_RULE_USED;
    }
#ifndef SSH_IPSEC_SMALL
  /* See if we can find a dormant rule already added to the tree */
  if (pm_rule->type == SSH_ENGINE_RULE_APPLY
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
      && (!SSH_IP_DEFINED(&pm_rule->nat_selector_dst_ip))
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
      && ssh_engine_is_rule_expensive(engine, pm_rule) == TRUE)
    {
      rule_bak = *pm_rule;
      rule_bak.flags |= SSH_ENGINE_RULE_PLACEHOLDER;
      rule_bak.type = SSH_ENGINE_RULE_DORMANT_APPLY;
      rule_bak.flags &= ~SSH_PM_ENGINE_RULE_SA_OUTBOUND;


















      rule = ssh_engine_find_equal_rule(engine, &rule_bak);
      if (rule != NULL)
        {
          /* Ok.. we found a placeholder rule!
             Convert it to an apply rule! */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Using a dormant placeholder rule already in lookup!"));
          rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);
          was_dormant = TRUE;
          rule_bak = *rule;
        }
    }
#endif /* SSH_IPSEC_SMALL */

  /* Allocate a rule object. */
  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      rule_index = ssh_engine_rule_allocate(engine);
      if (rule_index == SSH_IPSEC_INVALID_INDEX)
        goto error;
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("adding rule: index=%d flags=0x%08x prec=0x%08x",
             (int) rule_index,
             (unsigned int) pm_rule->flags,
             (unsigned int) pm_rule->precedence));

  /* Copy the rule object supplied by the policy manager. */
  *rule = *pm_rule;
  rule->rule_index = rule_index;
  rule->flows = SSH_IPSEC_INVALID_INDEX;
  rule->incoming_ipsec_flow = SSH_IPSEC_INVALID_INDEX;
  rule->refcnt = 0;

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC) &&
      !(rule->nat_flags & SSH_PM_NAT_SHARE_PORT_SRC))
    if (!ssh_engine_nat_register_ports(engine,
                                       &rule->nat_src_ip_low,
                                       &rule->nat_src_ip_high,
                                       rule->nat_src_port))
      goto error;

  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST) &&
      (rule->nat_flags & SSH_PM_NAT_NO_SHARE_PORT_DST))
    if (!ssh_engine_nat_register_ports(engine,
                                       &rule->nat_dst_ip_low,
                                       &rule->nat_dst_ip_high,
                                       rule->nat_dst_port))
      goto error;

  /* Allocate NAT port for destination selector */
  if (SSH_IP_DEFINED(&pm_rule->nat_selector_dst_ip))
    {
      Boolean is_ipv6;
      size_t len;

      is_ipv6 = SSH_IP_IS6(&pm_rule->nat_selector_dst_ip);

      if (pm_rule->nat_selector_dst_port == 0)
        {
          ssh_kernel_mutex_lock(engine->interface_lock);
          if (ssh_engine_nat_get_unused_map(engine, is_ipv6,
                                            0,    /* src_ifnum */
                                            NULL, /* src_ip */
                                            NULL, /* src_ip_orig */
                                            0,    /* src_src_port */
                                            0,    /* src_src_port_orig */
                                            0,    /* dst_ifnum */
                                            &pm_rule->nat_selector_dst_ip,
                                            pm_rule->nat_selector_dst_port,
                                            NULL,
                                            NULL,
                                            &rule->nat_selector_dst_ip,
                                            &rule->nat_selector_dst_port)
              == FALSE)
            {
              ssh_kernel_mutex_unlock(engine->interface_lock);
              goto error;
            }
          ssh_kernel_mutex_unlock(engine->interface_lock);
        }
      else
        {
          rule->nat_selector_dst_port = pm_rule->nat_selector_dst_port;
        }

      if (!ssh_engine_nat_register_port(engine, &rule->nat_selector_dst_ip,
                                        rule->nat_selector_dst_port))
        goto error;

      /* Use these values as the destination selector */
      rule->dst_port_low = rule->nat_selector_dst_port;
      rule->dst_port_high = rule->nat_selector_dst_port;
      SSH_IP_ENCODE(&rule->nat_selector_dst_ip, rule->dst_ip_low, len);
      SSH_IP_ENCODE(&rule->nat_selector_dst_ip, rule->dst_ip_high, len);
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Add the rule to the lookup structures, but keep it inactive for
     the time being, and activate it after everything else is done.
     Perform the adding here saves us the undoing of the everything
     else in case insertion failed. */
  was_inactive = (rule->flags & SSH_ENGINE_RULE_INACTIVE) ? TRUE : FALSE;
  rule->flags |= SSH_ENGINE_RULE_INACTIVE;

#ifndef SSH_IPSEC_SMALL
  if (was_dormant == TRUE)
    {
      /* Copy fields from the dormant rule that we need to preserve,
         these are basically the fields related to rule dependency
         and rule lookup. */
      rule->dep_next = rule_bak.dep_next;
      rule->dep_prev = rule_bak.dep_prev;
      rule->next = rule_bak.next;
      rule->flags |= SSH_ENGINE_RULE_PLACEHOLDER;

      /* The engine rule lookup uses unused selectors fields in the rule
         structure for it's own purposes. These are set correctly
         in ssh_engine_rule_lookup_prepare(). */
      ssh_engine_rule_lookup_prepare(engine,
                                     engine->policy_rule_set,
                                     (SshEngineLookupPreamble)rule);
    }
  else
#endif /* SSH_IPSEC_SMALL */
    {
      if (!ssh_engine_rule_lookup_add(engine,
                                      engine->policy_rule_set,
                                      (SshEngineLookupPreamble)rule))
        { /* Inserting the rule to the search structures failed. */
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not insert rule into lookup structure."));
#ifndef SSH_IPSEC_SMALL
          /* If SSH_IPSEC_SMALL is defined, then this shouldn't really
             happen - since IPSEC_SMALL does not use any auxiliary data
             structures, it can't run out of them, and hence should never
             fail.
             If SSH_IPSEC_SMALL is not defined, then coming here is most
             probably caused by too small a
             SSH_ENGINE_RULE_VECTOR_POOL_SIZE defined in ipsec_params.h. */
          ssh_warning("Failed to insert rule into lookup structure.  "
                      "Please adjust SSH_ENGINE_RULE_VECTOR_POOL_SIZE or "
                      "SSH_ENGINE_RULE_NODE_POOL_SIZE in your "
                      "ipsec_params.h.");
#endif /* !SSH_IPSEC_SMALL */
          goto error;
        }
    }

#ifndef SSH_IPSEC_SMALL
#ifdef DEBUG_HEAVY
  /* we do not want this to be present at std debug, as it forces
     decision tree build */
  SSH_ASSERT(ssh_engine_find_equal_rule(engine, rule) != NULL);
#endif /* DEBUG_HEAVY */
#endif /* SSH_IPSEC_SMALL */

  rule->refcnt = 1;

  /* If the `depends_on' field is set, then add the rule to that rule's
     dependent_rules list. */
#ifndef SSH_IPSEC_SMALL
  if (was_dormant == FALSE)
#endif /* SSH_IPSEC_SMALL */
    {
      rule->dep_prev = SSH_IPSEC_INVALID_INDEX;
      rule->dep_next = SSH_IPSEC_INVALID_INDEX;
      if (rule->depends_on != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_ASSERT(rule->depends_on < engine->rule_table_size);
          rule2 = SSH_ENGINE_GET_RULE(engine, rule->depends_on);
          SSH_ASSERT(rule2->type != SSH_ENGINE_RULE_NONEXISTENT);
          if (rule2->dependent_rules != SSH_IPSEC_INVALID_INDEX)
            {
              rule3 = SSH_ENGINE_GET_RULE(engine, rule2->dependent_rules);
              rule3->dep_prev = rule_index;
            }
          rule->dep_next = rule2->dependent_rules;
          rule->dep_prev = SSH_IPSEC_INVALID_INDEX;
          rule2->dependent_rules = rule_index;
        }
    }

  rule->dependent_rules = SSH_IPSEC_INVALID_INDEX;

#ifdef SSH_IPSEC_STATISTICS
  memset(&rule->stats, 0, sizeof(rule->stats));
  engine->stats.active_rules++;
  engine->stats.total_rules++;
#endif /* SSH_IPSEC_STATISTICS */

  /* If we refer to a transform record, increment its reference count. */
  if (rule->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshUInt32 flow_index;
      c_trd = SSH_ENGINE_GET_TRD(engine, rule->transform_index);
      SSH_ASSERT(c_trd != NULL);

      /* This rule references the transform */
      SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);

      /* Add the rule to the trd's list of rules referencing it. This
         is used when updating the flows during rekey, and when
         deleting the transform (and thereby its rules) */
      rule->trd_next = c_trd->rules;
      c_trd->rules = rule_index;

      /* if the rule type is an APPLY rule, then create the incoming
         ipsec flow */
      if (rule->type == SSH_ENGINE_RULE_APPLY && (require_incoming_flow))
        {
          SSH_ASSERT(rule->incoming_ipsec_flow == SSH_IPSEC_INVALID_INDEX);

          /* Create the incoming IPSEC flow for the transform.  The
             incoming flow enforces the time-based lifetime limit. */
          flow_index =
            ssh_engine_create_incoming_ipsec_flow(engine,
                                                  rule_index,
                                                  c_trd->life_seconds);
          if (flow_index == SSH_IPSEC_INVALID_INDEX)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Could not create incoming ipsec flow"));
              goto error;
            }
          /* Save the address of the new flow. */
          rule->incoming_ipsec_flow = SSH_ENGINE_FLOW_UNWRAP_INDEX(flow_index);
        }
    }

  /* Clear the temporary disabling of the rule - the rule is now ready
     for action. */
  if (!was_inactive)
    rule->flags &= ~SSH_ENGINE_RULE_INACTIVE;

  /* Untill we can generate "working" triggers from dangling flows in both
     forward and reverse directions, this is required! */
  if (pm_rule->type == SSH_ENGINE_RULE_APPLY)
    engine->undangle_all_pending = 1;




  return rule_index;

 error:

  SSH_DEBUG(SSH_D_FAIL, ("Could not create engine policy rule!"));

  if (rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      if ((rule && rule->refcnt == 1)
#ifndef SSH_IPSEC_SMALL
          || was_dormant == TRUE
#endif /* SSH_IPSEC_SMALL */
          )
        ssh_engine_delete_rule(engine, rule_index);
      else
        ssh_engine_rule_free(engine, rule_index);
    }

  return SSH_IPSEC_INVALID_INDEX;
}

/* This adds the rule `pm_rule' in the engine.  Any information in
   `pm_rule' is copied to internal data structures.  If the rule is a
   SSH_ENGINE_RULE_APPLY rule for a transform, then this also creates
   an inbound flow for processing inbound packets
   (pm_rule->transform_index must be valid, and the
   `inbound_tunnel_id' field of the transform record is used to
   specify tunnel id for inbound firewall processing for packets
   coming in from the tunnel).  The `depends_on' field of the rule
   should be set to either SSH_IPSEC_INVALID_INDEX or to a valid rule
   index returned by a previous call to ssh_engine_pme_add_rule.  If set to a
   rule index, that means that the new rule will depend on the old
   rule, and will be deleted as well if the old rule is later deleted.
   This calls `callback' with `context' and the rule index if
   successful, and with SSH_IPSEC_INVALID_INDEX if the rule could not
   be added. */
void ssh_engine_pme_add_rule(SshEngine engine, Boolean rekey,
                             const SshEnginePolicyRule pm_rule,
                             SshPmeAddRuleCB callback, void *context)
{
  SshUInt32 rule_index;
#ifdef SSHDIST_IPSEC_NAT
  SshUInt32 rule_index2;
#endif /* SSHDIST_IPSEC_NAT */
  SshEnginePolicyRule rule;
  SshEnginePolicyRuleStruct rule_bak;
  Boolean require_incoming_flow = TRUE;

  rule_index = SSH_IPSEC_INVALID_INDEX;
#ifdef SSHDIST_IPSEC_NAT
  rule_index2 = SSH_IPSEC_INVALID_INDEX;
#endif /* SSHDIST_IPSEC_NAT */

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Adding engine rule %@", ssh_engine_policy_rule_render, pm_rule));

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* ssh_engine_pme_add_rule() and ssh_engine_notify_pm_close() may be running
     concurrently on different CPU's... */
  if (engine->ipm_open == FALSE)
    goto error;

  /* When IPSec SA's are rekeyed, we need to remove any rules that were not
     renegotiated in the rekey. If this is an apply rule, then check if the
     rule has been previously installed, and if so mark the rule as no longer
     pending re-installation. When the outbound transform has been rekeyed
     we then remove any rules that still have the SSH_ENGINE_RULE_REKEY_PENDING
     flag set. */
  if (rekey && pm_rule->type == SSH_ENGINE_RULE_APPLY)
    {
      rule = ssh_engine_find_equal_rekey_rule(engine, pm_rule);
      if (rule != NULL)
        {
          rule_bak = *pm_rule;
          rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);

          SSH_DEBUG(SSH_D_LOWOK, ("This rule is a rekey"));

          /* This rule has been re-installed on rekey. */
          if (rule->flags & SSH_PM_ENGINE_RULE_SA_OUTBOUND)
            rule->flags &= ~SSH_ENGINE_RULE_REKEY_PENDING;

          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

          if (pm_rule->flags & SSH_PM_ENGINE_RULE_REPORT)
            (*callback)(engine->pm, rule_index, &rule_bak, context);
          else
            (*callback)(engine->pm, rule_index, NULL, context);
          return;
        }
      else
        SSH_DEBUG(SSH_D_LOWOK, ("This is not a rekey rule"));
    }

#ifdef SSHDIST_IPSEC_NAT
  /* If an APPLY rule is being made for a transform and the "nat_selector_dst"
     is set so that we are to create new destination selectors for the rule,
     then create a placeholder rule to hold the original rules for looking up
     rekeys. */
  if (pm_rule->type == SSH_ENGINE_RULE_APPLY
      && SSH_IP_DEFINED(&pm_rule->nat_selector_dst_ip)
      && pm_rule->nat_selector_dst_port == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Adding nat selector dst placeholder rule"));
      rule_bak = *pm_rule;
      rule_bak.flags &= ~SSH_PM_ENGINE_RULE_REPORT;
      rule_bak.flags &= ~SSH_PM_ENGINE_RULE_SA_OUTBOUND;
      rule_bak.flags |= SSH_ENGINE_RULE_INACTIVE;
      rule_bak.flags |= SSH_ENGINE_RULE_REKEY_PENDING;
      SSH_IP_UNDEFINE(&rule_bak.nat_selector_dst_ip);
      rule_bak.nat_selector_dst_port = 0;

      rule_index2 = ssh_engine_add_rule(engine, &rule_bak, FALSE);
      if (rule_index2 == SSH_IPSEC_INVALID_INDEX)
        goto error;
    }
#endif /* SSHDIST_IPSEC_NAT */

#if 0
  require_incoming_flow =
    (pm_rule->flags & SSH_ENGINE_RULE_NO_IPSEC_FLOW) ?  FALSE : TRUE;
#endif /* 0 */

  /* Always create an incoming IPSec flow for now. Without reference counts
     on flows it's problematic without this restriction, e.g. if two rules
     share the same IPSec flow and one rules gets deleted at rekey, then with
     the current system, the IPSec flow would get deleted. */
  require_incoming_flow = TRUE;

  rule_index = ssh_engine_add_rule(engine, pm_rule, require_incoming_flow);
  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    goto error;

#ifndef SSH_IPSEC_SMALL
  if (pm_rule->type == SSH_ENGINE_RULE_TRIGGER)
    {
      /* Is this a "pure" trigger rule for SA handler ? */
      if (pm_rule->type == SSH_ENGINE_RULE_TRIGGER
          && pm_rule->transform_index == SSH_IPSEC_INVALID_INDEX
          && ssh_engine_is_rule_expensive(engine, pm_rule) == TRUE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding dormant rule!"));
          rule_bak = *pm_rule;
          rule_bak.flags &= ~SSH_PM_ENGINE_RULE_SA_OUTBOUND;
          rule_bak.flags |= SSH_ENGINE_RULE_PLACEHOLDER;
          rule_bak.type = SSH_ENGINE_RULE_DORMANT_APPLY;




          rule_bak.precedence = pm_rule->precedence + 1;
          rule_bak.depends_on = rule_index;

          /* Because the "dormant" rule is merely a vehicle for an
             optimization in time, we do not care if adding it fails. */
          ssh_engine_add_rule(engine, &rule_bak, TRUE);
        }
    }
#endif /* SSH_IPSEC_SMALL */

  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  rule_bak = *rule;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return the index of the rule to the policy manager. */
  if (callback != NULL_FNPTR)
    {
      if (pm_rule->flags & SSH_PM_ENGINE_RULE_REPORT)
        (*callback)(engine->pm, rule_index, &rule_bak, context);
      else
        (*callback)(engine->pm, rule_index, NULL, context);
    }
  return;

 error:

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

#ifdef SSHDIST_IPSEC_NAT
  if (rule_index2 != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_delete_rule(engine, rule_index2);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
    }
#endif /* SSHDIST_IPSEC_NAT */

  SSH_DEBUG(SSH_D_FAIL, ("Could not create engine policy rule!"));

  if (callback != NULL_FNPTR)
    (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX,
                NULL, context);
  return;
}

/* This deletes the given rule and its dependent rules.  However, if
   this finds a rule with a transform, where there are no other rules
   referencing the transform, this does not delete the rule containing
   the transform, but instead returns the index of the transform.
   Engine->flow_table_lock must be held when this is called. */

SshUInt32 ssh_engine_pme_delete_rule_recurse(SshEngine engine,
                                             SshUInt32 rule_index)
{
  SshUInt32 dep_rule_index, next_dep_rule_index, transform_index;
  SshEnginePolicyRule rule, dep_rule;
  SshEngineTransformControl c_trd;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* If we have dependent rules, then recurse into a dependent rule. */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  for (dep_rule_index = rule->dependent_rules;
       dep_rule_index != SSH_IPSEC_INVALID_INDEX;
       dep_rule_index = next_dep_rule_index)
    {
      SSH_ASSERT(dep_rule_index < engine->rule_table_size);
      dep_rule = SSH_ENGINE_GET_RULE(engine, dep_rule_index);
      next_dep_rule_index = dep_rule->dep_next;

      transform_index =
        ssh_engine_pme_delete_rule_recurse(engine, dep_rule_index);
      if (transform_index != SSH_IPSEC_INVALID_INDEX)
        return transform_index;
    }
  SSH_ASSERT(rule->dependent_rules == SSH_IPSEC_INVALID_INDEX);

  /* Check if the rule has a transform. */
  transform_index = rule->transform_index;
  if (transform_index != SSH_IPSEC_INVALID_INDEX)
    { /* Yes, it has a transform. */
      c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
      SSH_ASSERT(c_trd != NULL);
      /* Check if we are the only rule referencing the transform. */
      if (c_trd->rules == rule_index &&
          rule->trd_next == SSH_IPSEC_INVALID_INDEX)
        return transform_index; /* There are no other references. */
    }

  /* Delete the given rule. */
  ssh_engine_delete_rule(engine, rule_index);

  /* Indicate that we found no trd for which delete notifications
     should be sent. */
  return SSH_IPSEC_INVALID_INDEX;
}

/* This frees the specified rule and any flows created by it from the
   engine.  If there are any other rules that depend on the rule
   (i.e., rules that set their `depends_on' field to `rule_index'),
   those rules (and any flows created by them) are removed from the
   engine.  This is designed to work iteratively: the policy manager
   should call this to delete the rule, and this will call `callback'
   back.  See the documentation for the SshPmeDeleteCB callback for
   more information. */

void ssh_engine_pme_delete_rule(SshEngine engine, SshUInt32 rule_index,
                                SshPmeDeleteCB callback, void *context)
{
  SshEnginePolicyRule rule;
  SshUInt32 transform_index;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshUInt32 peer_handle;
  SshEngineTransformStruct tr_ret;
  Boolean done;

 restart:
  SSH_ASSERT(rule_index < engine->rule_table_size);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("rule index=%d",
                               (int) rule_index));

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  rule = SSH_ENGINE_GET_RULE(engine, rule_index);

  if (rule->type == SSH_ENGINE_RULE_NONEXISTENT)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      if (callback)
        (*callback)(engine->pm, TRUE, rule_index, SSH_IPSEC_INVALID_INDEX,
                    NULL, context);
      return;
    }

  if (rule->flags & SSH_ENGINE_RULE_PM_REFERENCE)
    {
      /* Now the policy manager is freeing the rule.  Let's drop the
         reference flag. */
      rule->flags &= ~SSH_ENGINE_RULE_PM_REFERENCE;

      /* Check if the rule is already freed. */
      if ((rule->flags & SSH_ENGINE_RULE_DELETED) && rule->refcnt == 0)
        {
          /* This rule is already deleted.  Let's put it back to the
             freelist now. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Removing policy manager's reference from the rule"));
          ssh_engine_rule_free(engine, rule_index);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          if (callback)
            (*callback)(engine->pm, TRUE, rule_index, SSH_IPSEC_INVALID_INDEX,
                        NULL, context);
          return;
        }
    }

  if (rule->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Check that the transform index is still valid. If the transform
         is undergoing deletion, that will take care of deleting all rules
         that reference the transform. */
      c_trd = SSH_ENGINE_GET_TRD(engine, rule->transform_index);
      if (c_trd == NULL
          || (c_trd->control_flags & SSH_ENGINE_TR_C_DELETE_PENDING))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("TRD is pending deletion"));

          /* Transform is deleted. */
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          if (callback)
            (*callback)(engine->pm, TRUE, rule_index, SSH_IPSEC_INVALID_INDEX,
                        NULL, context);
          return;
        }
    }

  /* Find the next transform from the rule and its subrules.  If there
     are no more transform, this deletes the rule and returns
     SSH_IPSEC_INVALID_INDEX.  If this returns a transform, the
     transform has an extra reference that we must delete. */
  transform_index = ssh_engine_pme_delete_rule_recurse(engine, rule_index);
  if (transform_index == SSH_IPSEC_INVALID_INDEX)
    { /* No more transforms, and the rule and its subrules have been
         deleted. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      if (callback)
        (*callback)(engine->pm, TRUE, rule_index, SSH_IPSEC_INVALID_INDEX,
                    NULL, context);
      return;
    }

  /* Get information about the transform for the completion callback. */
  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);
  SSH_ASSERT(c_trd != NULL);
  peer_handle = c_trd->peer_handle;
  tr_ret.data = *d_trd;
  tr_ret.control = *c_trd;

  FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);

  /* Determine whether deleting the transform will also cause the rule that
     we are deleting to be deleted. */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  done = (rule->transform_index == transform_index);

  /* Remove the extra reference that was taken on the transform.  This will
     also remove any rules referencing the transform. */
  ssh_engine_clear_and_delete_trd(engine, transform_index);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback)
    {
      /* Pass information about the transform to the user callback. */
      ssh_engine_transform_event_normalize_spis(&tr_ret);
      (*callback)(engine->pm, done, rule_index, peer_handle, &tr_ret, context);
    }
  else if (!done)
    {
      /* Not done yet.  Continue rule deletion. */
      goto restart;
    }
}

/* Retrieves the rule object of the give rule index from the engine.
   The callback function `callback' will be called with `context' and
   `rule' either during this call or later.  If the rule index is
   invalid, then `rule' will be NULL.  The callback should copy all
   relevand fields of the returned rule object if they are needed
   after the call. */

void ssh_engine_pme_get_rule(SshEngine engine, SshUInt32 rule_index,
                             SshPmeRuleCB callback, void *context)
{
  SshEnginePolicyRule rule = NULL;
  SshEnginePolicyRuleStruct ruledata;

  SSH_ASSERT(rule_index < engine->rule_table_size);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Fetch the rule, identified by the rule index. */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  if (rule->type == SSH_ENGINE_RULE_NONEXISTENT)
    /* The rule is not in use. */
    rule = NULL;
  else
    {
      /* The rule is in the active configuration.  Copy its data into
         our local variable and set `rule' to point to it. */
      ruledata = *rule;
      rule = &ruledata;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Pass information about the rule to the user callback. */
  (*callback)(engine->pm, rule, context);
}

/* Adds one extra reference to the rule `rule_index' from the policy
   manager.  This has the same effect as setting the
   SSH_ENGINE_RULE_PM_REFERENCE when the rule is created.  When the
   extra reference is added, the rule will not be deleted from the
   engine (by delete or initial contact notifications) until policy
   manager explicitly deletes the rule by calling ssh_engine_pme_delete_rule
   for the rule.  If the argument `transform_index' is valid (not
   SSH_IPSEC_INVALID_INDEX), then the funtion will make an extra check
   that the rule index `rule_index' points to a valid apply rule
   applying the transform `transform_index'.  The function calls the
   callback function `callback' to notify the success of the
   operation.  If the `status' is TRUE, the rule (and optional
   transform) were valid and an extra reference was added.  If the
   `status' is FALSE, then the operation failed, either because the
   `rule_index' and `transform_index' specified an invalid rule or the
   rule already had an extra reference from the policy manager. */

void ssh_engine_pme_add_reference_to_rule(SshEngine engine,
                                          SshUInt32 rule_index,
                                          SshUInt32 transform_index,
                                          SshPmeStatusCB callback,
                                          void *context)
{
  SshEnginePolicyRule rule;
  SshEngineTransformControl c_trd;

  SSH_ASSERT(rule_index < engine->rule_table_size);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Check that the transform index is still valid. */
  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL || (c_trd->control_flags & SSH_ENGINE_TR_C_DELETE_PENDING))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("TRD is pending deletion"));
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  /* Fetch the rule, identified by the rule index. */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);

  /* Check that the rule matches the search criteria. */
  if (rule->type == SSH_ENGINE_RULE_NONEXISTENT
      || (transform_index != SSH_IPSEC_INVALID_INDEX
          && (rule->type != SSH_ENGINE_RULE_APPLY
              || rule->transform_index != transform_index))
      || rule->flags & SSH_ENGINE_RULE_PM_REFERENCE)
    {
      /* The rule was not valid, or it was not of correct type (apply)
         or it applied wrong transform or the reference was already
         set. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  /* The rule is valid.  Let's add the policy manager reference. */
  SSH_ASSERT((rule->flags & SSH_ENGINE_RULE_PM_REFERENCE) == 0);
  rule->flags |= SSH_ENGINE_RULE_PM_REFERENCE;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return success. */
  (*callback)(engine->pm, TRUE, context);
}

/* A `ssh_snprintf'-compatible renderer function for
   `SshEnginePolicyRule's. */

static const char *ssh_rule_type_to_name(SshEnginePolicyRuleType t)
{
  switch (t)
    {
    case SSH_ENGINE_RULE_NONEXISTENT:
      return "nonexistent";
    case SSH_ENGINE_RULE_DROP:
      return "drop";
    case SSH_ENGINE_RULE_REJECT:
      return "reject";
    case SSH_ENGINE_RULE_PASS:
      return "pass";
    case SSH_ENGINE_RULE_APPLY:
      return "apply";
    case SSH_ENGINE_RULE_TRIGGER:
      return "trigger";
#ifndef SSH_IPSEC_SMALL
    case SSH_ENGINE_RULE_DORMANT_APPLY:
      return "dormant apply";
#endif /* SSH_IPSEC_SMALL */
    default:
      return "UNKNOWN";
    }
}


int ssh_engine_policy_rule_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  SshEnginePolicyRule rule = (SshEnginePolicyRule) datum;
  int i, ip_addr_len = (rule->protocol == SSH_PROTOCOL_IP4) ? 4 : 16;
  SshIpAddrStruct ip_low, ip_high;
  int consumed, fail_ret_val = buf_size + 1;
  unsigned char *orig_buf = buf;
  static const SshKeywordStruct ssh_interceptor_protocols[] =
    {
      { "IPv4",          SSH_PROTOCOL_IP4 },
      { "IPv6",          SSH_PROTOCOL_IP6 },
      { "IPX",           SSH_PROTOCOL_IPX },
      { "Ethernet",      SSH_PROTOCOL_ETHERNET },
      { "FDDI",          SSH_PROTOCOL_FDDI },
      { "TokenRing",     SSH_PROTOCOL_TOKENRING },
      { "ARP",           SSH_PROTOCOL_ARP },
      { "Other",         SSH_PROTOCOL_OTHER },
      { NULL,            0 },
    };

  SSH_PRECOND(precision == -1); /* No precision specifiers yet. */

  /* Dump src ip addr */
  if (rule->selectors & SSH_SELECTOR_SRCIP)
    {
      SSH_IP_DECODE(&ip_low, rule->src_ip_low, ip_addr_len);
      if (memcmp(rule->src_ip_low, rule->src_ip_high, ip_addr_len) == 0)
        /* Point src ip rule. */
        consumed = ssh_snprintf(buf, buf_size, "src_ip=%@ ",
                                ssh_ipaddr_render, &ip_low);
      else
        {
          /* Range src ip rule. */
          SSH_IP_DECODE(&ip_high, rule->src_ip_high, ip_addr_len);
          consumed = ssh_snprintf(buf, buf_size, "src_ip=[%@..%@] ",
                                  ssh_ipaddr_render, &ip_low,
                                  ssh_ipaddr_render, &ip_high);
        }
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Dump dst ip addr */
  if (rule->selectors & SSH_SELECTOR_DSTIP)
    {
      SSH_IP_DECODE(&ip_low, rule->dst_ip_low, ip_addr_len);
      if (memcmp(rule->dst_ip_low, rule->dst_ip_high, ip_addr_len) == 0)
        consumed = ssh_snprintf(buf, buf_size, "dst_ip=%@ ",
                                ssh_ipaddr_render, &ip_low);
      else
        {
          SSH_IP_DECODE(&ip_high, rule->dst_ip_high, ip_addr_len);
          consumed = ssh_snprintf(buf, buf_size, "dst_ip=[%@..%@] ",
                                  ssh_ipaddr_render, &ip_low,
                                  ssh_ipaddr_render, &ip_high);
        }
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Dump src port */
  if (rule->selectors & SSH_SELECTOR_SRCPORT)
    {
      if (rule->src_port_low == rule->src_port_high)
        consumed = ssh_snprintf(buf, buf_size, "src_port=%d ",
                                rule->src_port_low);
      else
        consumed = ssh_snprintf(buf, buf_size, "src_port=[%d..%d] ",
                                rule->src_port_low, rule->src_port_high);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Dump dst port */
  if (rule->selectors & SSH_SELECTOR_DSTPORT)
    {
      if (rule->dst_port_low == rule->dst_port_high)
        consumed = ssh_snprintf(buf, buf_size, "dst_port=%d ",
                                rule->dst_port_low);
      else
        consumed = ssh_snprintf(buf, buf_size, "dst_port=[%d..%d] ",
                                rule->dst_port_low, rule->dst_port_high);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Ifnum, omitted if any. */
  if (rule->selectors & SSH_SELECTOR_IFNUM)
    {
      consumed = ssh_snprintf(buf, buf_size, "ifnum=%d ",
                              (int) rule->selector_ifnum);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Routing instance. */
  if (rule->selectors & SSH_SELECTOR_RIID)
    {
      consumed = ssh_snprintf(buf, buf_size, "routing instance=%d ",
                              (int) rule->routing_instance_id);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }


  /* Protocol */
  for (i = 0; ssh_interceptor_protocols[i].name; i++)
    if (ssh_interceptor_protocols[i].code == rule->protocol)
      {
        consumed = ssh_snprintf(buf, buf_size, "%s ",
                                ssh_interceptor_protocols[i].name);
        if (consumed > buf_size)
          return fail_ret_val;
        buf += consumed;
        buf_size -= consumed;
        break;
      }

  /* IPproto, omitted if any. */
  if (rule->selectors & SSH_SELECTOR_IPPROTO)
    for (i = 0; ssh_ip_protocol_id_keywords[i].name != NULL; i++)
      if (ssh_ip_protocol_id_keywords[i].code == rule->ipproto)
        {
          consumed = ssh_snprintf(buf, buf_size, "%s ",
                                  ssh_ip_protocol_id_keywords[i].name);
          if (consumed > buf_size)
            return fail_ret_val;
          buf += consumed;
          buf_size -= consumed;
          break;
        }

  /* Extension selectors. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if (rule->selectors & SSH_SELECTOR_EXTENSIONS)
    {
      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <
              rule->extension_selector_high[i])
            {
              consumed = ssh_snprintf(buf, buf_size, "ext%d=0x%x..0x%x ",
                                      i,
                                      (unsigned int)
                                      rule->extension_selector_low[i],
                                      (unsigned int)
                                      rule->extension_selector_high[i]);
              if (consumed > buf_size)
                return fail_ret_val;
              buf += consumed;
              buf_size -= consumed;
              break;
            }
          else if (rule->extension_selector_low[i] ==
                   rule->extension_selector_high[i])
            {
              consumed = ssh_snprintf(buf, buf_size, "ext%d=0x%x ",
                                      i,
                                      (unsigned int)
                                      rule->extension_selector_low[i]);
              if (consumed > buf_size)
                return fail_ret_val;
              buf += consumed;
              buf_size -= consumed;
              break;
            }
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Some other flags. */
  if (rule->selectors & SSH_SELECTOR_FROMLOCAL)
    {
      consumed = ssh_snprintf(buf, buf_size, "fromlocal ");
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }
  if (rule->selectors & SSH_SELECTOR_TOLOCAL)
    {
      consumed = ssh_snprintf(buf, buf_size, "tolocal ");
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }
  if (rule->flags & SSH_ENGINE_NO_FLOW)
    {
      consumed = ssh_snprintf(buf, buf_size, "no-flow ");
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Dump tunnel id if not initial tunnel. */
  if (rule->tunnel_id != 0)
    {
      consumed = ssh_snprintf(buf, buf_size, "tunnel_id=%u ",
                              (unsigned int) rule->tunnel_id);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }

  /* Dump flags in hex, just in case */
  consumed = ssh_snprintf(buf, buf_size, "flags=0x%08x ",
                          (unsigned int) rule->flags);
  if (consumed > buf_size)
    return fail_ret_val;
  buf += consumed;
  buf_size -= consumed;

  /* Dump selectors in hex, just in case */
  consumed = ssh_snprintf(buf, buf_size, "selectors=0x%04x ", rule->selectors);
  if (consumed > buf_size)
    return fail_ret_val;
  buf += consumed;
  buf_size -= consumed;

  /* Dump precedence, tunnel id, type */
  consumed =
    ssh_snprintf(buf, buf_size, "prec=0x%x %s%s",
                 (unsigned int) rule->precedence,
                 ssh_rule_type_to_name(rule->type),
                 ((rule->flags & SSH_ENGINE_RULE_INACTIVE)
                  ? " INACTIVE" : ""));
  if (consumed > buf_size)
    return fail_ret_val;
  buf += consumed;
  buf_size -= consumed;

#ifdef SSHDIST_IPSEC_NAT
  /* Dump src nat */
  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_SRC))
    {
      consumed =
        ssh_snprintf(buf, buf_size,
                     " src-nat: ip=%@-%@ port=%u flags=0x%x",
                     ssh_ipaddr_render, &(rule->nat_src_ip_low),
                     ssh_ipaddr_render, &(rule->nat_src_ip_high),
                     (unsigned int)rule->nat_src_port,
                     (unsigned int)rule->nat_flags);

      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
      buf_size -= consumed;
    }
  /* Dump dst nat */
  if ((rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST))
    {
      consumed =
        ssh_snprintf(buf, buf_size,
                     " dst-nat: ip=%@-%@ port=%u flags=0x%x",
                     ssh_ipaddr_render, &(rule->nat_dst_ip_low),
                     ssh_ipaddr_render, &(rule->nat_dst_ip_high),
                     (unsigned int)rule->nat_dst_port,
                     (unsigned int)rule->nat_flags);
      if (consumed > buf_size)
        return fail_ret_val;
      buf += consumed;
    }
#endif /* SSHDIST_IPSEC_NAT */
  return (int) (buf - orig_buf);
}
