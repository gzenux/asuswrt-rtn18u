/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Responder side IKE negotiation policy rule lookup.
   Initiator side IKE SA lookup from a policy rule.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmRuleLookup"

static Boolean
pm_check_tunnel_policy(SshPmTunnel tunnel, SshPmP1 p1,
                       SshIkev2PayloadID local_id,
                       SshIkev2PayloadID remote_id,
                       SshUInt32 *failure_mask)
{
  SshUInt32 i;
  SshPmTunnelLocalIp local_ip;

  SSH_PM_ASSERT_P1(p1);

#ifdef SSHDIST_IKEV1
  /* Check the IKE version matches */
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      ((tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) == 0))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("The supported IKE versions do not match"));
      (*failure_mask) |= SSH_PM_E_IKE_VERSION_MISMATCH;
      return FALSE;
    }
#endif /* SSHDIST_IKEV1 */

  /* The local identity must match that of the tunnel */
  if (tunnel->enforce_local_id && local_id != NULL)
    {
      if (!ssh_pm_ikev2_id_compare(local_id, tunnel->local_identity))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("The IKE local identity does not match"));
          (*failure_mask) |= SSH_PM_E_LOCAL_ID_MISMATCH;
          return FALSE;
        }
    }

  /* If the tunnel specifies a remote identity, we need to check that it
     matches that in the Phase-I. */
  if (tunnel->enforce_remote_id
      && tunnel->remote_identity != NULL && remote_id != NULL)
    {
      if (!ssh_pm_ikev2_id_compare(remote_id, tunnel->remote_identity))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("The IKE remote identity does not match"));
          (*failure_mask) |= SSH_PM_E_REMOTE_ID_MISMATCH;
          return FALSE;
        }
    }

  /* Check that local tunnel endpoint matches the local address. */
  if (tunnel->local_ip != NULL || tunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
      || tunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      )
    {
      for (local_ip = tunnel->local_ip;
           local_ip != NULL;
           local_ip = local_ip->next)
        if (SSH_IP_EQUAL(&local_ip->ip, p1->ike_sa->server->ip_address))
          break;

      if (local_ip == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("The tunnel's local address does not match "
                     "the local IKE address"));
          (*failure_mask) |= SSH_PM_E_LOCAL_IP_MISMATCH;
          return FALSE;
        }
    }

  /* Check that remote tunnel endpoint matches one of configured peers.
     Do not check the peers for MOBIKE enabled IKE SA because the peers
     in the tunnel object are just an initial value which may later change
     because of reception of MOBIKE additional addresses notifies. */
  if (tunnel->num_peers > 0
#ifdef SSHDIST_IPSEC_MOBIKE
      && ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED) == 0)
#endif /* SSHDIST_IPSEC_MOBIKE */
#ifdef SSHDIST_IKE_REDIRECT
      && ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_REDIRECTED) == 0)
#endif /* SSHDIST_IKE_REDIRECT */
      )
    {
      for (i = 0; i < tunnel->num_peers; i++)
        {
          if (!SSH_IP_CMP(&tunnel->peers[i], p1->ike_sa->remote_ip))
            break;
        }
      if (i == tunnel->num_peers)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("The tunnel's peers do not match"));
          (*failure_mask) |= SSH_PM_E_PEER_IP_MISMATCH;
          return FALSE;
        }
    }

  return TRUE;
}

/* Check for restrictions imposed by per port or per host rules on traffic
   selectors */
static Boolean
pm_ike_ts_match_granularity(SshIkev2PayloadTS ts,
                            SshPmRule rule, SshPmTunnel tunnel)
{
  SshIkev2PayloadTSItem item;
  SshIpAddrStruct ip;
  SshUInt32 i;

  if (tunnel == NULL)
    return TRUE;

  if (tunnel->flags & SSH_PM_T_PER_PORT_SA)
    {
      if (ts->number_of_items_used > 1)
        return FALSE;

      item = &ts->items[0];

      /* All addresses must be the same */
      if (SSH_IP_CMP(item->start_address, item->end_address) != 0)
        return FALSE;

      /* All ports must be the same */
      if (item->start_port != item->end_port)
        return FALSE;
    }

  /* Check the perhost and transport mode negotiations have only a single
     IP address in the traffic selector. */
  if ((tunnel->flags & SSH_PM_T_TRANSPORT_MODE
        && !(tunnel->transform & SSH_PM_IPSEC_TUNNEL))
      || (tunnel->flags & SSH_PM_T_PER_HOST_SA))
    {
      if (ts->number_of_items_used == 0)
        return TRUE;

      ip = *ts->items[0].start_address;

      /* All addresses must be the same */
      for (i = 0; i < ts->number_of_items_used; i++)
        {
          item = &ts->items[i];

          if (SSH_IP_CMP(item->start_address, item->end_address) != 0)
            return FALSE;

          /* For SCTP multi-homing the addresses are allowed to be different,
             however each traffic selector item contains only a single
             address. */
          if ((SSH_IP_CMP(&ip, item->start_address) != 0)
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
              && !(rule->flags & SSH_PM_RULE_MULTIHOME)
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
              )
            return FALSE;
        }
    }

  return TRUE;
}

Boolean
ssh_pm_ike_tunnel_match_encapsulation(SshPmTunnel tunnel,
                                      SshIkev2ExchangeData ed,
                                      Boolean *transport_mode_requested)
{
  SshIkev2PayloadNotify notify;

  SSH_ASSERT(transport_mode_requested != NULL);
  *transport_mode_requested = FALSE;

  /* Parse the notify payloads to see if transport mode was proposed */
  for (notify = ed->notify; notify; notify = notify->next_notify)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE)
        {
          *transport_mode_requested = TRUE;
          break;
        }
    }

  /* Check the tunnelling encapsulation */
  if (*transport_mode_requested == TRUE
      && (tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
    return TRUE;
  else if (*transport_mode_requested == FALSE
           && (tunnel->transform & SSH_PM_IPSEC_TUNNEL))
    return TRUE;

  SSH_DEBUG(SSH_D_MIDOK,
            ("%s mode proposed but not acceptable to local policy",
             (*transport_mode_requested ? "Transport" : "Tunnel")));

  return FALSE;
}

static Boolean
pm_ike_responder_match_selector(SshPm pm,
                                Boolean is_ikev1,
                                SshIkev2PayloadTS proposed,
                                SshIkev2PayloadTS policy,
                                SshUInt32 rule_lookup_flags)
{
  SshIkev2PayloadTS intersection = NULL;
  Boolean require_match_to_first_ts = FALSE;

  if (rule_lookup_flags & SSH_PM_RULE_LOOKUP_MATCH_TO_FIRST_TS_ITEM)
    require_match_to_first_ts = TRUE;

  if (!ssh_ikev2_ts_narrow(pm->sad_handle,
                           require_match_to_first_ts,
                           &intersection,
                           proposed, policy)
      || (is_ikev1
          && !ssh_ikev2_ts_match(intersection, proposed)))
    {
      if (intersection != NULL)
        ssh_ikev2_ts_free(pm->sad_handle, intersection);
      return FALSE;
    }

  ssh_ikev2_ts_free(pm->sad_handle, intersection);
  return TRUE;
}

/* This function looks for a policy rule that can be used for
   authenticating the IKE negotiation. */
static SshPmRule
pm_responder_rule_lookup(SshPm pm, SshPmP1 p1,
                         SshIkev2ExchangeData ed,
                         SshIkev2PayloadTS proposed_ts_i,
                         SshIkev2PayloadTS proposed_ts_r,
                         SshUInt32 rule_lookup_flags,
                         Boolean *forward,
                         SshUInt32 *failure_mask_return)
{
  SshIkev2PayloadTS local_ts, remote_ts;
  SshADTHandle handle;
  SshPmRule rule = NULL;
  SshPmRule maybe_ok_rule = NULL;
  Boolean maybe_ok_forward = FALSE, is_ikev1 = FALSE;
  SshPmTunnel tunnel;
  SshUInt32 failure_mask = 0;
  Boolean is_forward = FALSE;
  Boolean transport_mode_requested = FALSE;

  *forward = TRUE;
  *failure_mask_return = 0;

#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    is_ikev1 = TRUE;
#endif /* SSHDIST_IKEV1 */

  /* Iterate through all rules. */







  /* Go through all rules and see if we find a matching one in the forward
     direction. */

  for (handle = ssh_adt_enumerate_start(pm->rule_by_precedence);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_precedence, handle))
    {
      rule = ssh_adt_get(pm->rule_by_precedence, handle);

      SSH_DEBUG(SSH_D_LOWSTART,
                ("Considering rule `%@'", ssh_pm_rule_render, rule));

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Rule is not in the active configuration"));
          continue;
        }

      if ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_CHECK_AUTH)
          && !ssh_pm_check_rule_authorization(p1, rule))
        {
          SSH_DEBUG(SSH_D_FAIL, ("The rule's authorization does not match"));
          failure_mask |= SSH_PM_E_ACCESS_GROUP_MISMATCH;
          continue;
        }

      /* Try match in forward direction. */
      is_forward = TRUE;
      tunnel = rule->side_to.tunnel;

    try_again_reverse:

      if (SSH_PM_TUNNEL_IS_IKE(tunnel))
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Checking tunnel '%s' (id %d) in %s direction",
                     tunnel->tunnel_name,
                     (int) tunnel->tunnel_id,
                     (is_forward ? "forward" : "reverse")));

          /* Check if the IKE SA matches the tunnels VRF. */
         if (p1->ike_sa->server->routing_instance_id !=
             tunnel->routing_instance_id)
           {
             SSH_DEBUG(SSH_D_LOWOK, ("Routing instance id mismatch: "
                                     "tunnel routing instance id %d, "
                                     "SA routing instance id %d",
                                     tunnel->routing_instance_id,
                                     p1->ike_sa->server->routing_instance_id));
             goto move_to_next;
           }


          /* Check traffic selectors unless negotiation is in IKEv1 phase 1. */
          if ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_IKEV1_PHASE1) == 0)
            {
              /* In IKEv2 TSr and TSi cannot be NULL. */
              SSH_ASSERT(proposed_ts_r != NULL);
              SSH_ASSERT(proposed_ts_i != NULL);

              /* Get traffic selectors from rule. */
              if (!ssh_pm_rule_get_traffic_selectors(pm, rule, is_forward,
                                                     &local_ts, &remote_ts))
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Cannot construct traffic selectors for rule"));

                  goto move_to_next;
                }

              /* Match proposed TS_r to rules's local traffic selectors. */
              if (!pm_ike_responder_match_selector(pm, is_ikev1,
                                                   proposed_ts_r, local_ts,
                                                   rule_lookup_flags))
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Local traffic selectors do not match"));
                  failure_mask |= SSH_PM_E_LOCAL_TS_MISMATCH;

                  goto move_to_next;
                }

              /* Match proposed TS_i to rule's remote traffic selectors. */
              if (!pm_ike_responder_match_selector(pm, is_ikev1,
                                                   proposed_ts_i, remote_ts,
                                                   rule_lookup_flags))
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Remote traffic selectors do not match"));
                  failure_mask |= SSH_PM_E_REMOTE_TS_MISMATCH;

                  goto move_to_next;
                }

              /* Match granularity of TS_r. */
              if (!pm_ike_ts_match_granularity(proposed_ts_r, rule, tunnel))
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Local traffic selector granularity "
                             "does not match"));
                  failure_mask |= SSH_PM_E_LOCAL_TS_MISMATCH;

                  goto move_to_next;
                }

              /* Match granularity of TS_i. */
              if (!pm_ike_ts_match_granularity(proposed_ts_i, rule, tunnel))
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Remote traffic selector granularity "
                             "does not match"));
                  failure_mask |= SSH_PM_E_REMOTE_TS_MISMATCH;

                  goto move_to_next;
                }
            }

          /* Check the proposal against tunnel policy. */
          if (p1->done)
            {
              if (!pm_check_tunnel_policy(tunnel, p1, p1->local_id,
                                          p1->remote_id, &failure_mask))
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("The tunnel does not match"));
                  goto move_to_next;
                }
            }
          else
            {
              if (!pm_check_tunnel_policy(tunnel, p1, ed->ike_ed->id_r,
                                          ed->ike_ed->id_i, &failure_mask))
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("The tunnel does not match"));
                  goto move_to_next;
                }
            }

          /* Finally check the tunnel's encapsulation match. */
          if ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_IKEV1_PHASE1) ||
              ssh_pm_ike_tunnel_match_encapsulation(tunnel, ed,
                                                    &transport_mode_requested))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("The %s tunnel '%s' (id %d) matches",
                                      (is_forward ? "forward" : "reverse"),
                                      tunnel->tunnel_name,
                                      (int) tunnel->tunnel_id));
              *forward = is_forward;
              break;
            }
          else
            {
              /* Rule matched otherwise excepts for encapsulation mode.
                 Store the rule and fallback to it if no better matching
                 rule is found. See the comments below for more details. */
              if (maybe_ok_rule == NULL)
                {
                  maybe_ok_rule = rule;
                  maybe_ok_forward = is_forward;
                }

              failure_mask |= SSH_PM_E_ENCAPSULATION_MISMATCH;

              SSH_DEBUG(SSH_D_LOWOK,
                        ("The rule's encapsulation does not match"));
            }
        }

    move_to_next:
      /* No match if forward direction, try match in reverse
         direction. */
      if (is_forward == TRUE)
        {
          tunnel = rule->side_from.tunnel;
          is_forward = FALSE;

          goto try_again_reverse;
        }
    }

  if (handle != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Found a matching rule '%@' in the %s direction",
                 ssh_pm_rule_render, rule,
                 (is_forward ? "forward" : "reverse")));
      return rule;
    }
  else
    {
      if (is_ikev1 == FALSE && maybe_ok_rule != NULL
          && (((rule_lookup_flags & SSH_PM_RULE_LOOKUP_MATCH_ENCAP)
               && transport_mode_requested)
              || (rule_lookup_flags & SSH_PM_RULE_LOOKUP_MATCH_ENCAP) == 0))
        {
          /* The policy rule matches in all aspects except for that
             transport was proposed but this rule does not support it. For
             IKEv1 this is a proposal mismatch and we cannot use this rule.
             For IKEv2 we mark that this rule is possibly OK, and continue
             searching for another rule that does support transport mode.
             If no acceptable rule using transport mode is found then we
             use the possibly OK rule found here.

             Note that this check must be done only after the policy rule
             is known to be acceptable with the only possible exception of
             the encapsulation mode. */
          SSH_DEBUG(SSH_D_MIDOK, ("Found a (possibly) matching rule '%@'",
                                  ssh_pm_rule_render, maybe_ok_rule));
          *forward = maybe_ok_forward;
          return maybe_ok_rule;
        }

      SSH_DEBUG(SSH_D_FAIL, ("No matching rule found in the forward or "
                             "reverse direction"));
      if (failure_mask == 0)
        *failure_mask_return = SSH_PM_E_NO_RULES;

      *failure_mask_return = failure_mask;
      return NULL;
    }
}


SshPmRule ssh_pm_ike_responder_rule_lookup(SshPm pm, SshPmP1 p1,
                                           SshIkev2ExchangeData ed,
                                           SshUInt32 rule_lookup_flags,
                                           Boolean *forward,
                                           SshUInt32 *failure_mask_return)
{
  SshPmRule rule = NULL;
  SshIkev2PayloadTS proposed_ts_i = NULL;
  SshIkev2PayloadTS proposed_ts_r = NULL;
  SshPmTunnel tunnel;
  Boolean transport_mode_ts = FALSE;

  if ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_TRANSPORT_MODE_TS)
      && ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_IKEV1_PHASE1) == 0)
      && ssh_ikev2_ipsec_get_ts(pm->sad_handle, ed, TRUE, &proposed_ts_i,
                                &proposed_ts_r) == TRUE)
    transport_mode_ts = TRUE;

 relookup:
  if (transport_mode_ts == FALSE
      && ((rule_lookup_flags & SSH_PM_RULE_LOOKUP_IKEV1_PHASE1) == 0)
      && ssh_ikev2_ipsec_get_ts(pm->sad_handle, ed, FALSE, &proposed_ts_i,
                                &proposed_ts_r) == FALSE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Could not get proposed traffic selectors"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Find a rule matching the first traffic selectors of: "
             "TS_r=%@ and TS_i=%@ routing instance id %d",
             ssh_ikev2_ts_render, proposed_ts_r,
             ssh_ikev2_ts_render, proposed_ts_i,
             p1->ike_sa->server->routing_instance_id));

  rule = pm_responder_rule_lookup(pm, p1, ed, proposed_ts_i, proposed_ts_r,
                                  rule_lookup_flags
                                  | SSH_PM_RULE_LOOKUP_MATCH_TO_FIRST_TS_ITEM,
                                  forward, failure_mask_return);

  if (rule == NULL
#ifdef SSHDIST_IKEV1
      && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
      )
    {
      /* We did not find rule that would match the first traffic selectors,
         so we will start new lookup round and try to match to any of
         the selectors. This is based on draft-ietf-ipsecme-ikev2bis-03 */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Find a rule matching any traffic selectors of: "
                 "TS_r=%@ and TS_i=%@ routing instance id %d",
                 ssh_ikev2_ts_render, proposed_ts_r,
                 ssh_ikev2_ts_render, proposed_ts_i,
                 p1->ike_sa->server->routing_instance_id));

      rule = pm_responder_rule_lookup(pm, p1, ed, proposed_ts_i, proposed_ts_r,
                                      rule_lookup_flags,
                                      forward, failure_mask_return);
    }

  if (proposed_ts_i != NULL)
    ssh_ikev2_ts_free(pm->sad_handle, proposed_ts_i);
  if (proposed_ts_r != NULL)
    ssh_ikev2_ts_free(pm->sad_handle, proposed_ts_r);

  if (transport_mode_ts == TRUE)
    {
      /* Rule lookup with substituted traffic selectors did not find a rule.
         Attempt to relookup SPD with original traffic selectors. */
      if (rule == NULL)
        {
          transport_mode_ts = FALSE;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("No rule found with transport mode NAT-T traffic "
                     "selectors"));
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Redoing rule lookup with normal traffic selectors"));
          goto relookup;
        }

      if (*forward == TRUE)
        tunnel = rule->side_to.tunnel;
      else
        tunnel = rule->side_from.tunnel;

      /* Rule lookup with substituted traffic selectors found a tunnel mode
         rule. Attempt to relookup SPD with original traffic selectors. */
      if ((tunnel->flags & SSH_PM_T_TRANSPORT_MODE) == 0)
        {
          transport_mode_ts = FALSE;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Tunnel mode tunnel found with transport mode NAT-T "
                     "traffic selectors"));
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Redoing rule lookup with normal traffic selectors"));
          goto relookup;
        }

      /* Rule lookup with substituted traffic selectors found a matching
         transport mode rule. Set exchange to transport mode so that IKEv2
         library starts using the transport mode NAT-T substituted traffic
         selectors in subsequent policy calls. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Setting exchange to use transport mode traffic selectors"));
      ssh_ikev2_ipsec_set_transport_mode_ts(ed, TRUE);
    }

  return rule;
}

SshIkev2Error ssh_pm_select_ike_responder_tunnel(SshPm pm , SshPmP1 p1,
                                                 SshIkev2ExchangeData ed)
{
  SshPmTunnel tunnel;
  SshUInt32 failure_mask;
  SshUInt32 rule_lookup_flags = 0;

  SSH_PM_ASSERT_P1N(p1);

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    return SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_LOWOK, ("Searching for a suitable tunnel to "
                          "authenticate the IKE initiator"));

  if (p1->n->rule != NULL)
    {
      SSH_ASSERT(p1->n->tunnel != NULL);
      SSH_DEBUG(SSH_D_LOWOK,
                ("Tunnel '%s' (id %d) has already been chosen",
                 p1->n->tunnel->tunnel_name, (int) p1->n->tunnel->tunnel_id));

      return SSH_IKEV2_ERROR_OK;
    }

#ifdef SSHDIST_IKEV1
  /* For IKEv1 this function is called in the Phase-I negotiation. */
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    rule_lookup_flags |= SSH_PM_RULE_LOOKUP_IKEV1_PHASE1;
#endif /* SSHDIST_IKEV1 */

  if (p1->n->transport_recv
#ifdef SSHDIST_IKEV1
      && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
      )
    rule_lookup_flags |= SSH_PM_RULE_LOOKUP_TRANSPORT_MODE_TS;

  p1->n->rule = ssh_pm_ike_responder_rule_lookup(pm, p1, ed, rule_lookup_flags,
                                                 &p1->n->forward,
                                                 &failure_mask);

  if (p1->n->rule == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("No suitable rule/tunnel found, failing negotiation."
                 " Failure mask %x", failure_mask));
      p1->n->failure_mask |= failure_mask;
      if ((failure_mask & SSH_PM_E_LOCAL_TS_MISMATCH)
          || (failure_mask & SSH_PM_E_REMOTE_TS_MISMATCH))
        return SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
      else
        return SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
    }
  SSH_PM_RULE_LOCK(p1->n->rule);

  if (p1->n->forward == TRUE)
    tunnel = p1->n->rule->side_to.tunnel;
  else
    tunnel = p1->n->rule->side_from.tunnel;
  SSH_ASSERT(tunnel != NULL);

  if (tunnel != p1->n->tunnel)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("IKE Responder is changing tunnels from '%s' (id %d) to "
                 "'%s' (id %d)",
                 (p1->n->tunnel != NULL ? p1->n->tunnel->tunnel_name : "none"),
                 (p1->n->tunnel != NULL ? p1->n->tunnel->tunnel_id : 0),
                 (tunnel != NULL ? tunnel->tunnel_name : "none"),
                 (tunnel != NULL ? tunnel->tunnel_id : 0)));

      if (p1->n->tunnel != NULL)
        SSH_PM_TUNNEL_DESTROY(pm, p1->n->tunnel);

      p1->tunnel_id = tunnel->tunnel_id;
      p1->n->tunnel = tunnel;
      SSH_PM_TUNNEL_TAKE_REF(p1->n->tunnel);
    }

  return SSH_IKEV2_ERROR_OK;
}


/*-----------------------------------------------------------------------*/
/*  Lookup of P1 objects from a policy rule and destination IP address   */
/*-----------------------------------------------------------------------*/

/* Context data for IKE Phase-1 SA lookup functions. */
struct SshPmLookupP1CtxRec
{
  SshPm pm;
  SshPmRule rule;
  SshPmTunnel tunnel;
  SshPmPeer peer;
  SshIpAddr src;
  SshIpAddr dst;
  SshUInt16 port;
  Boolean require_completed;

  SshPmP1 result;
};

typedef struct SshPmLookupP1CtxRec SshPmLookupP1CtxStruct;
typedef struct SshPmLookupP1CtxRec *SshPmLookupP1Ctx;


/* Check whether the IKE peer address of the Phase-1 negotiation
   `p1' matches the remote IKE peer `dst'.  If so, the function also
   checks that the identity constraints of the Phase-1 `p1' match tunnel
   `tunnel' and `peer'.  The function returns TRUE if all checks are
   successful and FALSE otherwise. */
static Boolean
ssh_pm_lookup_match(SshPmP1 p1,
                    SshIpAddr src, SshIpAddr dst, SshPmTunnel tunnel,
                    SshPmRule rule, SshPmPeer peer, Boolean require_completed)
{
  SshUInt32 i;
  SshPmPskStruct psk;
  Boolean found = FALSE;
  SshPmTunnelLocalIp local_ip;
  SshIkev2PayloadID tunnel_ike_id;

  /* Check remote IP address. */
  if (!SSH_IP_EQUAL(p1->ike_sa->remote_ip, dst))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("remote ip does not match"));
      return FALSE;
    }

  /* Check if we have defined src address for the p1 */
  if (src && !SSH_IP_EQUAL(p1->ike_sa->server->ip_address, src))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("source ip does not match"));
      return FALSE;
    }

  if (p1->done)
    {
      SSH_ASSERT(SSH_IP_DEFINED(p1->ike_sa->server->ip_address));
      SSH_ASSERT(SSH_IP_DEFINED(p1->ike_sa->remote_ip));

#ifdef SSHDIST_IKEV1
      /* Check the IKE version matches */
      if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
          ((tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) == 0))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("IKE version does not match"));
          return FALSE;
        }
#endif /* SSHDIST_IKEV1 */

      /* Tunnel is specified, check authentication constraints. The
         local IP must match if it is specified. */
      if (tunnel->local_ip != NULL
          || tunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
          || tunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
          )
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("Checking local IP address"));
          for (local_ip = tunnel->local_ip;
               local_ip != NULL;
               local_ip = local_ip->next)
            if (SSH_IP_EQUAL(&local_ip->ip, p1->ike_sa->server->ip_address))
              break;

          if (local_ip == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Local IP address does not match"));
              return FALSE;
            }
        }
      /* Check identities */
      SSH_DEBUG(SSH_D_MIDSTART, ("Checking identities"));

      tunnel_ike_id = ssh_pm_ike_get_identity(tunnel->pm,
                                              NULL, tunnel, FALSE);
      if (tunnel_ike_id && !ssh_pm_ikev2_id_compare(p1->local_id,
                                                    tunnel_ike_id))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Local identities do not match"));
          ssh_pm_ikev2_payload_id_free(tunnel_ike_id);
          return FALSE;
        }
      ssh_pm_ikev2_payload_id_free(tunnel_ike_id);

      if (tunnel->remote_identity && tunnel->enforce_remote_id  &&
          !ssh_pm_ikev2_id_compare(p1->remote_id,
                                   tunnel->remote_identity))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Remote identities do not match"));
          return  FALSE;
        }

      if (peer)
        {
          if (peer->local_id
              && !ssh_pm_ikev2_id_compare(p1->local_id, peer->local_id))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Local identities do not match"));
              return FALSE;
            }

          if (peer->remote_id
              && !ssh_pm_ikev2_id_compare(p1->remote_id, peer->remote_id))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Remote identities do not match"));
              return FALSE;
            }
        }

      /* Authentication method. */
      SSH_DEBUG(SSH_D_MIDSTART, ("Checking authentication method"));

      switch (p1->local_auth_method)
        {
        case SSH_PM_AUTH_PSK:
#ifdef SSHDIST_IKEV1
          /* IKEv1 Aggressive mode responder we ignore the psk comparison,
             since remote secret is used. */
          if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1 &&
              p1->ike_sa->flags & SSH_IKEV2_FB_IKE_AGGRESSIVE_MODE &&
              (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0)
            {
              found = TRUE;
            }
          else
#endif /* SSHDIST_IKEV1 */
            {
              psk.secret = p1->local_secret;
              psk.secret_len = p1->local_secret_len;

              /* Check if any of the tunnel's PSK's match that in p1. */
              for (i = 0; i < tunnel->u.ike.num_secrets; i++)
                {
                  /* Check if any of the tunnel's PSK's match that in p1. (We
                     have already checked that the identities match).  */
                  if (ssh_pm_psk_compare(&tunnel->u.ike.secrets[i], &psk))
                    {
                      found = TRUE;
                      break;
                    }
                }
            }

          if (!found)
            {
              /* Does not match.  */
              SSH_DEBUG(SSH_D_FAIL, ("The pre-shared key does not match"));
              return FALSE;
            }
          break;

        default:
          break;
        }
      if (!ssh_pm_check_rule_authorization(p1, rule))
        {
          SSH_DEBUG(SSH_D_FAIL, ("The rule's authorization does not match"));
          return FALSE;
        }
    }
  else
    {
      /* The negotiation is still active. */
      if (require_completed)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("negotiation still active"));
          return FALSE;
        }

      /* Check the IP address and IKE port if they are defined. */
      SSH_ASSERT(p1->n != NULL);

      if (tunnel && (p1->n->tunnel != tunnel))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("tunnel does not match"));
          return FALSE;
        }
    }

  return TRUE;
}

/* Check whether the Phase-1 negotiation `p1' using `p1_local_ip' and
   as its local IKE peer and `p1_remote_ip' as its remote IKE peer
   matches the lookup context `ctx'.  The function returns TRUE if
   the negotiation matches and FALSE otherwise. */
static Boolean
ssh_pm_lookup_p1_check_p1(SshPmLookupP1Ctx ctx, SshPmP1 p1)
{
  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_MY,
            ("checking if P1 %p using addresses %@ <-> %@ matches",
             p1,
             ssh_ipaddr_render, p1->ike_sa->server->ip_address,
             ssh_ipaddr_render, p1->ike_sa->remote_ip));

  /* Do not used Phase-I's that have failed or are not usable */
  if (p1->failed || p1->unusable)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("IKE SA not usable"));
      return FALSE;
    }

  /* Check that tunnel matches. */
  if (ctx->tunnel->tunnel_id != p1->tunnel_id)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel ID's differ"));
      return FALSE;
    }

  /* Check the server is not pending deletion. */
  if (ssh_pm_servers_select(ctx->pm, p1->ike_sa->server->ip_address,
                            SSH_PM_SERVERS_MATCH_IKE_SERVER,
                            p1->ike_sa->server,
                            SSH_INVALID_IFNUM,
                            ctx->tunnel->routing_instance_id) == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Server is not usable"));
      return FALSE;
    }

  if (ctx->tunnel->local_port != p1->ike_sa->server->normal_local_port)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel local port mismatch"));
      return FALSE;
    }

  /* Check tunnel's IKE peer addresses if specified. */
  if (ctx->tunnel->num_peers)
    {
      SshUInt32 i;

      for (i = 0; i < ctx->tunnel->num_peers; i++)
        {
          if (ssh_pm_lookup_match(p1, ctx->src, &ctx->tunnel->peers[i],
                                  ctx->tunnel, ctx->rule, ctx->peer,
                                  ctx->require_completed))
            {
            found:
              ctx->result = p1;
              return TRUE;
            }
        }
    }
  else
    {
      /* Use the packet's destination address. */
      SSH_ASSERT(SSH_IP_DEFINED(ctx->dst));
      if (ssh_pm_lookup_match(p1, ctx->src, ctx->dst,
                              ctx->tunnel, ctx->rule, ctx->peer,
                              ctx->require_completed))
        goto found;
    }

  /* No match. */
  return FALSE;
}

SshPmP1
ssh_pm_lookup_p1(SshPm pm, SshPmRule rule, SshPmTunnel tunnel,
                 SshUInt32 peer_handle, SshIpAddr src, SshIpAddr dst,
                 Boolean require_completed)
{
  SshPmLookupP1CtxStruct ctx;
  SshPmP1 p1;
  SshUInt32 hash;

  /* Initialize a search context. */
  memset(&ctx, 0, sizeof(ctx));
  ctx.tunnel = tunnel;
  ctx.rule = rule;
  ctx.peer = ssh_pm_peer_by_handle(pm, peer_handle);
  ctx.pm = pm;
  ctx.require_completed = require_completed;

  /* Use IP addresses from peer if not explicitly specified and peer exists. */
  ctx.src = src;
  if (ctx.src == NULL && ctx.peer != NULL)
    ctx.src = ctx.peer->local_ip;
  ctx.dst = dst;
  if (ctx.dst == NULL && ctx.peer != NULL)
    ctx.dst = ctx.peer->remote_ip;

  /* Peer IP must be defined either explicitly or by peer. Fail lookup if
     it is not defined. */
  if (ctx.dst == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Missing dst IP address"));
      return NULL;
    }

  SSH_ASSERT(rule != NULL);
  SSH_ASSERT(tunnel != NULL);

  if (!require_completed)
    {
      /* Lookup active Phase-1 initiator and responder negotiations. */
      for (p1 = pm->active_p1_negotiations; p1; p1 = p1->n->next)
        {
          if (ssh_pm_lookup_p1_check_p1(&ctx, p1))
            return p1;
        }
    }

  /* Check IKE SA hash table. */
  hash = SSH_PM_IKE_PEER_HASH(ctx.dst);
  for (p1 = pm->ike_sa_hash[hash]; p1; p1 = p1->hash_next)
    {
      if (ssh_pm_lookup_p1_check_p1(&ctx, p1))
        return p1;
    }

  /* No match found. */
  return NULL;
}
