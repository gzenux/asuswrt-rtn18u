/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An implementation of rule lookup based on trivial linked lists kept
   in a decreasing order of precedence.  If SSH_IPSEC_SMALL is not
   defined, this file is essentially empty.  This rule lookup method
   is *not* encouraged if there are significantly more than, say, 20
   rules.
*/

#include "sshincludes.h"
#include "engine_internal.h"


#ifdef SSH_IPSEC_SMALL


#define SSH_DEBUG_MODULE "SshEngineRuleLookupList"


/* Initialize the engine's policy rule lookup mechanism.  Return TRUE
   if successful, otherwise FALSE. */

SshEnginePolicyRuleSet ssh_engine_rule_lookup_allocate(SshEngine engine)
{
  SshEnginePolicyRuleSet  rs;

  rs = ssh_calloc(1, sizeof(*rs));
  if (rs == NULL)
    return NULL;

  rs->policy_rules = NULL;
  return rs;
}


/* Dispose of the engine's policy rule lookup mechanism.  This does
   not free the rules themselves, only the internal data structures of
   the lookup mechanism.  Returns TRUE on success. */

Boolean ssh_engine_rule_lookup_dispose(SshEngine engine,
                                       SshEnginePolicyRuleSet rs)
{
  ssh_free(rs);
  return TRUE;
}


/* Adds the rule to the data structures used for rule lookups.
   This returns TRUE if the rule was successfully added, and FALSE if an
   error occurs.
   engine->flow_control_table_lock must already be held when this is called. */

Boolean ssh_engine_rule_lookup_add(SshEngine engine,
                                   SshEnginePolicyRuleSet rs,
                                   SshEngineLookupPreamble rule)
{
  SshEngineLookupPreamble n_rule, p_rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

#ifdef DEBUG_LIGHT
  {
    SshEngineLookupPreamble r;

    /* Ensure the rule is not inserted twice. */
    for (r = rs->policy_rules; r != NULL; r = r->next)
      SSH_ASSERT(r != rule);
  }
#endif /* DEBUG_LIGHT */

  for (p_rule = NULL, n_rule = rs->policy_rules;
       n_rule != NULL;
       p_rule = n_rule, n_rule = n_rule->next)
    {
      if (rule->precedence >= n_rule->precedence)
        break;
    }

  rule->next = n_rule;
  rule->prev = p_rule;
  if (p_rule != NULL)
    p_rule->next = rule;
  else
    rs->policy_rules = rule;
  if (n_rule != NULL)
    n_rule->prev = rule;

  return TRUE;
}


/* Removes the rule from the data structures used for rule lookups.
   engine->flow_control_table_lock must already be held when this is called. */

void ssh_engine_rule_lookup_remove(SshEngine engine,
                                   SshEnginePolicyRuleSet rs,
                                   SshEngineLookupPreamble rule)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

#ifdef DEBUG_LIGHT
  {
    SshEngineLookupPreamble r;

    /* Ensure the rule is in the linked list. */
    for (r = rs->policy_rules; r != NULL; r = r->next)
      {
        if (r == rule)
          break;
      }
    SSH_ASSERT(r != NULL);
  }
#endif /* DEBUG_LIGHT */

  /* Remove the rule from the linked list of rules. */
  if (rule->next != NULL)
    rule->next->prev = rule->prev;
  if (rule->prev != NULL)
    rule->prev->next = rule->next;
  else
    {
      SSH_ASSERT(rule == rs->policy_rules);
      rs->policy_rules = rule->next;
    }
  rule->next = NULL;
  rule->prev = NULL;
}


#ifdef DEBUG_LIGHT

/* Check that the rule is not present in the policy lookup data
   structures.  It is a fatal error if it is.
   engine->flow_control_table_lock must be held when this is called. */

void ssh_engine_rule_lookup_assert_not_there(SshEngine engine,
                                             SshEnginePolicyRuleSet rs,
                                             SshEngineLookupPreamble rule)
{
  SshEngineLookupPreamble r;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  for (r = rs->policy_rules; r != NULL; r = r->next)
    SSH_ASSERT(r != rule);
}

#endif /* DEBUG_LIGHT */


/* A generic interface for looking up rules.  Return a matching rule
   with the highest precedence, or NULL if not found.

   `src_ip' and `dst_ip' are the source and destination ip numbers,
   correspondingly, and `ip_addr_len' must be the number of bytes in
   the `src_ip' and `dst_ip', i.e. either 4 for IPv4 or 16 for IPv6.
   `extensions' refers to a vector of
   `SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS' of this packet's
   extension values.  If `extensions' is NULL, then the extensions are
   ignored.  `tunnel_id' must be the searched rule's `tunnel_id'.

   `test_fun' is a function which tests whether the given rule
   satisfies the conditions.  `test_fun' may assume that the ip and
   port numbers in the suggested rule match, but because of a distinct
   possibility of hash collisions, it may *not* assume that the values
   used for `flag_hash' match.  If `test_fun' is NULL, then it is
   assumed to return TRUE regardless of the rule.  `ctx' is passed as
   a second argument to `test_fun'.

   engine->flow_control_table_lock must be held when this is called. */

SshEngineLookupPreamble
ssh_engine_rule_generic_lookup(SshEngine engine,
                               SshEnginePolicyRuleSet rs,
                               const unsigned char *src_ip,
                               const unsigned char *dst_ip,
                               size_t ip_addr_len,
                               SshUInt32 tunnel_id,
                               SshUInt16 src_port, SshUInt16 dst_port,
                               const SshUInt32 *extensions,
                               SshEnginePolicyRuleTestFun test_fun,
                               void *ctx)
{
  SshEngineLookupPreamble rule;
  int cmp;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Loop over all rules. */
  for (rule = rs->policy_rules; rule != NULL; rule = rule->next)
    {
      /* Check whether "builtin" selectors match.  If any mismatch is
         encountered, we continue with the next rule. */

      if (tunnel_id != rule->tunnel_id)
        continue;

      if ((rule->selectors & SSH_SELECTOR_SRCPORT) &&
          (src_port < rule->src_port_low || src_port > rule->src_port_high))
        continue;

      if ((rule->selectors & SSH_SELECTOR_DSTPORT) &&
          (dst_port < rule->dst_port_low || dst_port > rule->dst_port_high))
        continue;

      if ((rule->selectors & SSH_SELECTOR_DSTIP) &&
          ((cmp = memcmp(dst_ip, rule->dst_ip_low, ip_addr_len)) < 0 ||
           /* Optimization: All IP-numbers stored in the rules must
              have higher or equal highs than lows.  Therefore, if the
              comparison gives exact match against the low boundary
              value, i.e. cmp == 0, there's no need to test for the
              high boundary value. */
           (cmp != 0 && memcmp(dst_ip, rule->dst_ip_high, ip_addr_len) > 0)))
        continue;
      if ((rule->selectors & SSH_SELECTOR_SRCIP) &&
          ((cmp = memcmp(src_ip, rule->src_ip_low, ip_addr_len)) < 0 ||
           (cmp != 0 && memcmp(src_ip, rule->src_ip_high, ip_addr_len) > 0)))
        continue;

      if (test_fun == NULL_FNPTR || (*test_fun)(engine, rule, extensions, ctx))
        return rule;
    }
  SSH_ASSERT(rule == NULL);
  /* No rule found. */
  return NULL;
}

void
ssh_engine_rule_lookup_prepare(SshEngine engine,
                               SshEnginePolicyRuleSet rs,
                               SshEngineLookupPreamble rule)
{
  return;
}

void
ssh_engine_rule_lookup_flush(SshEngine engine, SshEnginePolicyRuleSet rs)
{
  return;
}

#ifndef KERNEL

void ssh_lookup_dump_file(SshEngine engine, const char *filename)
{
  int buf_used;
  FILE *fp = fopen(filename, "w");

#ifdef BUF_LEN
#undef BUF_LEN
#endif
#define BUF_LEN  1024
#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* To save stack it is assumed that this function is not called from
     multiple threads, and hence `buf' can be static. */
  static char buf[BUF_LEN + 1];
  buf[BUF_LEN] = '\0';
#else
  char *buf = ssh_calloc(BUF_LEN + 1, 1);
  if (buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_calloc failed."));
      return;
    }
#endif

  if (fp == NULL)
    ssh_warning("Could not open file `%s' for writing.", filename);
  else
    {
      SshEngineLookupPreamble r;

      fprintf(fp, "Contents of the rule list:\n");
      for (r = engine->policy_rule_set->policy_rules; r != NULL; r = r->next)
        {
          buf_used = ssh_snprintf(buf, BUF_LEN, "%@",
                                  ssh_engine_policy_rule_render, r);
          if (buf_used <= BUF_LEN)
            fprintf(fp, "  %s\n", buf);
          else
            fprintf(fp, "  TOO LONG LINE\n");
        }
      fclose(fp);
    }
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  ssh_free(buf);
#endif
}

#endif

#else /* !SSH_IPSEC_SMALL */

typedef enum
{
  SSH_DUMMY_0
} SshMakeFileNotEmpty;

#endif
