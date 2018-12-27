/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   An implementation of rule lookup based on a hash table of linked
   lists for point destination ip rules, and a decision tree for range
   destination ip rules.  This is usually the most efficient method
   when there are many rules.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_rule_lookup.h"

#ifndef SSH_IPSEC_SMALL

#define SSH_DEBUG_MODULE "SshEngineRuleLookupTree"


/* Notes on stack usage:
   The rule lookup tree build process is recursive and therefore it is
   important to minimize stack consumption for one level of recursion.
   Stack consumption is decreased in the following ways:
   1) Majority of local variables are stored in SshLookupBuildContext
      which are allocated during initialization of rule lookup tree.
   2) All recursive functions and some utility functions must not be
      declared static, as newer gcc versions (atleast 4.1) tend to inline
      such functions.
*/

/* The type of the two-way associative cache. */
struct SshLookupRuleVectorCacheRec {
  /* NULLs if not valid. */
  SshEngineLookupPreamble *p1, *p2;
  /* Counters to improve replacement in the cache. */
  SshUInt16 p1_prec, p2_prec;
};

#define POINT_DST_IP_RULES(ruleset, ix)                 \
  ((ruleset)->point_dst_ip_rule_hash                    \
        [(ix) / (ruleset)->point_dst_ip_hash_block_size]\
        [(ix) % (ruleset)->point_dst_ip_hash_block_size])

#ifdef DEBUG_LIGHT
/* Forward declaration of a function that is occasionally useful in
   debugging. */
static void ssh_lookup_decision_tree_check(SshEngine engine,
                                           SshEnginePolicyRuleSet rs,
                                           SshLookupRef tree);
#endif /* DEBUG_LIGHT */

#define POINT_DST_IP_RULE_HASH_BLOCK_SIZE               \
  (SSH_ENGINE_MAX_MALLOC / sizeof(SshEngineLookupPreamble))

#define POINT_DST_IP_RULE_HASH_ROOT_SIZE                                      \
  ((SSH_ENGINE_POINT_DST_IP_HASH_SIZE + POINT_DST_IP_RULE_HASH_BLOCK_SIZE - 1)\
   / POINT_DST_IP_RULE_HASH_BLOCK_SIZE)

#if SSH_ENGINE_MAX_RULES > 0xFFFF
typedef SshUInt32 SshLookupRuleCount;
#else
typedef SshUInt16 SshLookupRuleCount;
#endif

/* Number of SshLookupBuildContexts. Better to have a few extra ones.
   Experiments show the following mininum values:
   MAX_TUNNELS  BUILD_CONTEXTS
   150          11
   1500         14
   15000        18
*/
#define SSH_ENGINE_MAX_LOOKUP_BUILD_CONTEXTS 32

/* Context for ssh_lookup_do_build(). */
struct SshLookupBuildContextRec
{
  Boolean in_use;

  /* Parameters for recursive call to ssh_lookup_do_build() */
  SshEnginePolicyRuleSet rs;
  SshLookupRef tree;
  SshEngineLookupPreamble *v;
  SshLookupRuleCount n_rules;
  SshLookupRuleCount n_rules_in_parent;
  SshUInt32 done_ratio;
  SshUInt32 tree_todo_ratio;
  SshUInt32 memory_conservation;
  SshUInt32 level;

  /* Local variables for ssh_lookup_do_build() */
  SshLookupNode n;
  SshLookupRuleCount i;
  SshLookupRuleCount best_n_lt, best_n_eq, best_n_gt;
  SshEngineLookupPreamble *left, *middle, *right;
  SshLookupRuleCount left_ctr, middle_ctr, right_ctr;
  SshUInt32 subtree_todo_ratio, tmp;
};

#ifdef SSH_IPSEC_PREALLOCATE_TABLES

/* Preallocate node pool always when SSH_IPSEC_PREALLOCATE_TABLES is defined.*/
#ifndef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
#define SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL 1
#endif /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */

/* Preallocate rule pool always when SSH_IPSEC_PREALLOCATE_TABLES is defined.*/
#ifndef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
#define SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL 1
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */

static SshEnginePolicyRuleSetStruct ssh_lookup_policy_rule_set;

static SshEngineLookupPreamble *
  ssh_lookup_point_dst_ip_rule_hash_root[POINT_DST_IP_RULE_HASH_ROOT_SIZE];

static SshEngineLookupPreamble
  ssh_lookup_point_dst_ip_rule_hash_block[POINT_DST_IP_RULE_HASH_ROOT_SIZE]
                                         [POINT_DST_IP_RULE_HASH_BLOCK_SIZE];

static SshLookupRuleVectorCacheStruct
  ssh_lookup_rule_pool_cache[
    SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES))];

static SshLookupBuildContextStruct
  ssh_lookup_build_context_pool[SSH_ENGINE_MAX_LOOKUP_BUILD_CONTEXTS];

#endif  /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifdef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
static SshLookupNodeStruct
  ssh_lookup_node_pool[
    SSH_ENGINE_RULE_NODE_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES))];
#endif /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */

#ifdef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
static SshEngineLookupPreamble
  ssh_lookup_rule_vector_pool[
    SSH_ENGINE_RULE_VECTOR_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES))];
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */


#define ENGINE_2D_ALLOC_OR_FAIL(name, ptr, size, blocksize, ofsize)     \
  do {                                                                  \
    void *__ptr;                                                        \
    __ptr = ssh_engine_calloc_2d_table(engine, (size),                  \
                                       (blocksize), (ofsize));          \
    if (__ptr == NULL)                                                  \
      {                                                                 \
        SSH_DEBUG(SSH_D_ERROR, ("allocation of %s failed (size %u)",    \
                                (name), (unsigned int) size));          \
        goto fail;                                                      \
      }                                                                 \
    (ptr) = __ptr;                                                      \
  } while (0)

/* Initialize the engine's policy rule lookup mechanism.  Return TRUE
   if successful, otherwise FALSE. */

SshEnginePolicyRuleSet ssh_engine_rule_lookup_allocate(SshEngine engine)
{
  SshEnginePolicyRuleSet rs;
#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  unsigned long i;

  rs = &ssh_lookup_policy_rule_set;
  rs->point_dst_ip_hash_size = SSH_ENGINE_POINT_DST_IP_HASH_SIZE;
  rs->point_dst_ip_hash_block_size = POINT_DST_IP_RULE_HASH_BLOCK_SIZE;
  rs->point_dst_ip_rule_hash = &ssh_lookup_point_dst_ip_rule_hash_root[0];
  for (i = 0; i < POINT_DST_IP_RULE_HASH_ROOT_SIZE; i++)
    rs->point_dst_ip_rule_hash[i] =
      &ssh_lookup_point_dst_ip_rule_hash_block[i][0];

  rs->rule_pool_cache = &ssh_lookup_rule_pool_cache[0];

  rs->build_context_pool = &ssh_lookup_build_context_pool[0];

#else /* SSH_IPSEC_PREALLOCATE_TABLES */

  rs = ssh_calloc_flags(1, sizeof(SshEnginePolicyRuleSetStruct),
                        SSH_KERNEL_ALLOC_WAIT);
  if (rs == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate policy rule set: size %luB",
                 (unsigned long) sizeof(SshEnginePolicyRuleSetStruct)));
      goto fail;
    }

  rs->point_dst_ip_hash_size = SSH_ENGINE_POINT_DST_IP_HASH_SIZE;
  rs->point_dst_ip_hash_block_size = POINT_DST_IP_RULE_HASH_BLOCK_SIZE;
  ENGINE_2D_ALLOC_OR_FAIL("rule hash table",
                          rs->point_dst_ip_rule_hash,
                          rs->point_dst_ip_hash_size,
                          rs->point_dst_ip_hash_block_size,
                          sizeof(SshEngineLookupPreamble));

  rs->build_context_pool =
    ssh_calloc_flags(SSH_ENGINE_MAX_LOOKUP_BUILD_CONTEXTS,
                     sizeof(SshLookupBuildContextStruct),
                     SSH_KERNEL_ALLOC_WAIT);

#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifdef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
  rs->node_pool_size = SSH_ENGINE_RULE_NODE_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES));
  rs->node_pool = &ssh_lookup_node_pool[0];
#else /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */
  rs->node_pool_size = SSH_ENGINE_RULE_NODE_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES));
  rs->node_pool =
    ssh_calloc_flags(rs->node_pool_size,
                     sizeof(SshLookupNodeStruct),
                     SSH_KERNEL_ALLOC_WAIT);
#endif /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */

#ifdef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
  rs->rule_pool_size = SSH_ENGINE_RULE_VECTOR_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES));
  rs->rule_pool = &ssh_lookup_rule_vector_pool[0];
#else /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */
  rs->rule_pool_size = SSH_ENGINE_RULE_VECTOR_POOL_SIZE(
        SSH_ENGINE_MAX_RULES,
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES));
  rs->rule_pool =
    ssh_calloc_flags(rs->rule_pool_size,
                     sizeof(SshEngineLookupPreamble),
                     SSH_KERNEL_ALLOC_WAIT);
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  if (rs->point_dst_ip_rule_hash == NULL ||
      rs->node_pool == NULL ||
      rs->rule_pool == NULL ||
      rs->build_context_pool == NULL)
    {
      if (rs->point_dst_ip_rule_hash == NULL)
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed to allocate point_dst_ip_rule_hash size %luB",
                   (unsigned long) (sizeof(SshEngineLookupPreamble)
                                    * rs->point_dst_ip_hash_size)));
      if (rs->node_pool == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to allocate rule lookup node_pool size %luB",
                     (unsigned long) (sizeof(SshLookupNodeStruct)
                                      * rs->node_pool_size)));
#ifndef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
          if ((rs->node_pool_size * sizeof(SshLookupNodeStruct)) >
              SSH_ENGINE_MAX_MALLOC)
            SSH_DEBUG(SSH_D_FAIL,
                      ("Consider defining "
                       "SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL "
                       "in ipsec_params.h"));
#endif /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */
        }
      if (rs->rule_pool == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to allocate rule lookup rule_pool size %luB",
                     (unsigned long) (sizeof(SshEngineLookupPreamble)
                                      * rs->rule_pool_size)));
#ifndef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
          if ((rs->rule_pool_size * sizeof(SshEngineLookupPreamble))
              > SSH_ENGINE_MAX_MALLOC)
            SSH_DEBUG(SSH_D_FAIL,
                      ("Consider defining "
                       "SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL "
                       "in ipsec_params.h"));
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */
        }
      if (rs->build_context_pool == NULL)
        SSH_DEBUG(SSH_D_FAIL,
                  ("Failed to allocate rule lookup build_context_pool "
                   "size %luB",
                   (unsigned long)
                   (sizeof(SshLookupBuildContextStruct)
                    * SSH_ENGINE_MAX_LOOKUP_BUILD_CONTEXTS)));
      goto fail;
    }

  /* Note: it is OK if no rule pool cache is around.  Hence it is
     allocated last, and absent from the following tests. */
  rs->rule_pool_cache =
    ssh_calloc_flags(SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
                        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(
                            SSH_ENGINE_MAX_RULES)),
                     sizeof(SshLookupRuleVectorCacheStruct),
                     SSH_KERNEL_ALLOC_WAIT);
  if (rs->rule_pool_cache == NULL)
    SSH_DEBUG(SSH_D_FAIL, ("Memory allocation for rule_pool_cache failed"));
#endif  /* !SSH_IPSEC_PREALLOCATE_TABLES */

  rs->range_dst_ip_rule_tree.kind = RULE_VECTOR;
  rs->range_dst_ip_rule_tree.u.rule = NULL;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Instantiated rule lookup in elements/bytes: "
             " point-dst-hash-size=%d/%d"
             " rule-pool-size=%d/%d"
             " node-pool-size=%d/%d"
             " vector-cache-size=%d/%d",
             rs->point_dst_ip_hash_size,
             rs->point_dst_ip_hash_size * sizeof(SshEngineLookupPreamble),
             rs->rule_pool_size,
             rs->rule_pool_size * sizeof(SshEngineLookupPreamble),
             rs->node_pool_size,
             rs->node_pool_size * sizeof(SshLookupNodeStruct),
             SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
                 SSH_ENGINE_MAX_DST_IP_RANGE_RULES(
                 SSH_ENGINE_MAX_RULES)),
             SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
                 SSH_ENGINE_MAX_DST_IP_RANGE_RULES(
                 SSH_ENGINE_MAX_RULES))
                 * sizeof(SshLookupRuleVectorCacheStruct)));

  return rs;

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
 fail:
  if (rs != NULL)
    {
      ssh_engine_free_2d_table(engine,
                               (void**)rs->point_dst_ip_rule_hash,
                               rs->point_dst_ip_hash_size,
                               rs->point_dst_ip_hash_block_size);
#ifndef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
      ssh_free(rs->node_pool);
#endif /* !SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */
#ifndef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
      ssh_free(rs->rule_pool);
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */
      ssh_free(rs->build_context_pool);

      ssh_free(rs);
    }
  return NULL;
#endif  /* !SSH_IPSEC_PREALLOCATE_TABLES */
}


/* Dispose of the engine's policy rule lookup mechanism.  This does
   not free the rules themselves, only the internal data structures of
   the lookup mechanism.  Returns TRUE on success. */

Boolean ssh_engine_rule_lookup_dispose(SshEngine engine,
                                       SshEnginePolicyRuleSet rs)
{
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  if (rs != NULL)
    {
      ssh_engine_free_2d_table(engine,
                               (void **) rs->point_dst_ip_rule_hash,
                               rs->point_dst_ip_hash_size,
                               rs->point_dst_ip_hash_block_size);
#ifndef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
      if (rs->node_pool != NULL)
        ssh_free(rs->node_pool);
#endif /* !SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */
#ifndef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
      if (rs->rule_pool != NULL)
        ssh_free(rs->rule_pool);
#endif /* !SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */
      if (rs->rule_pool_cache != NULL)
        ssh_free(rs->rule_pool_cache);
      if (rs->build_context_pool != NULL)
        ssh_free(rs->build_context_pool);
      ssh_free(rs);
    }
#endif
  return TRUE;
}


static void ssh_lookup_node_pool_clear(SshEnginePolicyRuleSet rs)
{
  rs->node_pool_allocation_ptr =
    &rs->node_pool[rs->node_pool_size];
}

static SshLookupNode
ssh_lookup_node_allocate(SshEnginePolicyRuleSet rs)
{
  if (rs->node_pool_allocation_ptr > &rs->node_pool[0])
    return --rs->node_pool_allocation_ptr;
  else
    return NULL;
}


static void ssh_lookup_rule_pool_clear(SshEnginePolicyRuleSet rs)
{
  rs->rule_pool_low = &rs->rule_pool[0];
  rs->rule_pool_high = &rs->rule_pool[rs->rule_pool_size];
  if (rs->rule_pool_cache != NULL)
    memset(rs->rule_pool_cache, 0,
           SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
               SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES))
           * sizeof(SshLookupRuleVectorCacheStruct));
}

static SshEngineLookupPreamble *
ssh_lookup_rule_pool_allocate_tmp(SshEnginePolicyRuleSet rs,
                                  SshUInt32 n_rules)
{
  if (rs->rule_pool_high - n_rules >= rs->rule_pool_low)
    {
      rs->rule_pool_high -= n_rules;
      return rs->rule_pool_high;
    }
  else
    return NULL;
}

static void ssh_lookup_rule_pool_free_tmp(SshEnginePolicyRuleSet rs,
                                          SshUInt32 n_rules)
{
  SSH_ASSERT(rs->rule_pool_high + n_rules <=
             &rs->rule_pool[rs->rule_pool_size]);
  rs->rule_pool_high += n_rules;
}

static SshLookupBuildContext
ssh_lookup_build_context_get(SshEnginePolicyRuleSet rs)
{
  int i;

  /* No need to do extra locking as engine->flow_control_table_lock
     is always taken when this is called. */
  for (i = 0; i < SSH_ENGINE_MAX_LOOKUP_BUILD_CONTEXTS; i++)
    {
      if (!rs->build_context_pool[i].in_use)
        {
          memset(&rs->build_context_pool[i], 0,
                 sizeof(rs->build_context_pool[i]));
          rs->build_context_pool[i].in_use = TRUE;
          return &rs->build_context_pool[i];
        }
    }
  return NULL;
}

static void
ssh_lookup_build_context_put(SshEnginePolicyRuleSet rs,
                             SshLookupBuildContext ctx)
{
  /* No need to do extra locking as engine->flow_control_table_lock
     is always taken when this is called. */
  SSH_ASSERT(ctx->in_use == TRUE);
  ctx->in_use = FALSE;
}

SshUInt32
ssh_lookup_rule_vector_hash(SshEngineLookupPreamble *v,
                            SshUInt32 n_rules)
{
  const char *p = (const char *) v;
  SshUInt32 h, i, n_bytes = n_rules * sizeof(SshEngineLookupPreamble);

  /* Smaller rule vectors than two pointer should not be allocated at
     all. */
  SSH_ASSERT(n_rules >= 2);

  for (h = i = 0; i < n_bytes - 3; i += 2)
    {
      h += (((SshUInt32) (p[i])) << 8) | p[i+1];
      h += h << 10;
      h ^= h >> 7;
    }
  for (; i < n_bytes; i++)
    {
      h += p[i];
      h += h << 10;
      h ^= h >> 7;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;
  return h;
}


SshEngineLookupPreamble *
ssh_lookup_rule_pool_stabilize_and_free(SshEnginePolicyRuleSet rs,
                                        SshEngineLookupPreamble *v,
                                        SshUInt32 n_rules)
{
  /* Init `cache_p' to zero in order to prevent compiler complaints. */
  SshLookupRuleVectorCache cp = NULL;

  SSH_ASSERT(v >= rs->rule_pool_high);
  SSH_ASSERT(v + n_rules <= &rs->rule_pool[rs->rule_pool_size]);

  if (rs->rule_pool_cache != NULL)
    {
      /* Probe the rule_vector_cache */
      SshUInt32 h = ssh_lookup_rule_vector_hash(v, n_rules)
        % SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(
        SSH_ENGINE_MAX_DST_IP_RANGE_RULES(SSH_ENGINE_MAX_RULES));
      cp = &rs->rule_pool_cache[h];
      if (cp->p1 != NULL &&
          cp->p1 + n_rules < rs->rule_pool_low &&
          memcmp(cp->p1, v, n_rules * sizeof(SshEngineLookupPreamble)) == 0)
        {
          /* p1 refers to a cache value. */
          rs->rule_pool_low += n_rules;
          cp->p1_prec += (SshUInt16) n_rules;
          if (cp->p1_prec < n_rules)
            /* Handle overflow by setting to maximum value. */
            cp->p1_prec = 0xFFFF;
          rs->n_cache_hits++;
          return cp->p1;
        }
      if (cp->p2 != NULL &&
          cp->p2 + n_rules < rs->rule_pool_low &&
          memcmp(cp->p2, v, n_rules * sizeof(SshEngineLookupPreamble)) == 0)
        {
          /* p2 refers to a cache value. */
          rs->rule_pool_low += n_rules;
          cp->p2_prec += (SshUInt16) n_rules;
          if (cp->p2_prec < n_rules)
            cp->p2_prec = 0xFFFF;
          rs->n_cache_hits++;
          return cp->p2;
        }
      rs->n_cache_misses++;
    }

  /* Since the stabilized and tmp rule vectors may temporarily
     overlap, we can not use `memcpy' here! */
  memmove(rs->rule_pool_low, v, n_rules * sizeof(SshEngineLookupPreamble));
  rs->rule_pool_high = v + n_rules;
  v = rs->rule_pool_low;
  rs->rule_pool_low += n_rules;

  if (cp != NULL)
    {
      /* Store into the cache. */
      if (cp->p1 == NULL)
        {
          cp->p1 = v;
          cp->p1_prec = (n_rules > 0xFFFF) ? 0xFFFF : n_rules;
        }
      else if (cp->p2 == NULL)
        {
          cp->p2 = v;
          cp->p2_prec = (n_rules > 0xFFFF) ? 0xFFFF : n_rules;
        }
      else if (cp->p1_prec < cp->p2_prec)
        {
          cp->p1 = v;
          cp->p1_prec = (n_rules > 0xFFFF) ? 0xFFFF : n_rules;
          /* Age the entry at p2 so that it is more likely to be
             replaced the next time (unless it is hit). */
          if (cp->p2_prec >= 2)
            cp->p2_prec -= 2;
        }
      else
        {
          cp->p2 = v;
          cp->p2_prec = (n_rules > 0xFFFF) ? 0xFFFF : n_rules;
          if (cp->p2_prec >= 2)
            cp->p1_prec -= 2;
        }
    }

  return v;
}


/* The table below is contains approximate values of
    -256 * index * log(index / 256)  */
SSH_RODATA
static const unsigned char ssh_lookup_xlogx[257] = {
  0,   6,  10,  13,  17,  20,  23,  25,  28,  30,  32,  35,  37,  39,  41,  43,
 44,  46,  48,  49,  51,  53,  54,  55,  57,  58,  59,  61,  62,  63,  64,  65,
 67,  68,  69,  70,  71,  72,  72,  73,  74,  75,  76,  77,  77,  78,  79,  80,
 80,  81,  82,  82,  83,  83,  84,  85,  85,  86,  86,  87,  87,  87,  88,  88,
 89,  89,  89,  90,  90,  90,  91,  91,  91,  92,  92,  92,  92,  93,  93,  93,
 93,  93,  93,  93,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  94,
 94,  94,  94,  94,  94,  94,  94,  94,  94,  94,  93,  93,  93,  93,  93,  93,
 93,  92,  92,  92,  92,  92,  91,  91,  91,  91,  90,  90,  90,  90,  89,  89,
 89,  88,  88,  88,  87,  87,  87,  86,  86,  86,  85,  85,  84,  84,  84,  83,
 83,  82,  82,  82,  81,  81,  80,  80,  79,  79,  78,  78,  77,  77,  76,  76,
 75,  75,  74,  74,  73,  72,  72,  71,  71,  70,  70,  69,  68,  68,  67,  67,
 66,  65,  65,  64,  63,  63,  62,  61,  61,  60,  59,  59,  58,  57,  57,  56,
 55,  55,  54,  53,  52,  52,  51,  50,  49,  49,  48,  47,  46,  46,  45,  44,
 43,  42,  42,  41,  40,  39,  38,  38,  37,  36,  35,  34,  33,  32,  32,  31,
 30,  29,  28,  27,  26,  26,  25,  24,  23,  22,  21,  20,  19,  18,  17,  16,
 15,  15,  14,  13,  12,  11,  10,   9,   8,   7,   6,   5,   4,   3,   2,   1,
  0,
};


/* How good is a split which splits a node of `n' rules when the split
   results in `n_lt' rules in the left branch, `n_eq' rules in the
   middle branch and `n_gt' rules in the right branch.

   The original formula is derived from inspections on how imbalance
   and non-determining nodes affects tree depth:

                                     s
        ------------------------------------------------------------
        n * (p_lt * log(p_lt) + p_eq * log(p_eq) + p_gt * log(p_gt))

   where the `p_'s denote relative probabilities of the search going
   into that subtree.  Since we can't assume floating point numbers,
   we have scaled the probabilities up to a fixed point number by a
   factor 256 and the entire result up by 1M, and the computations of
   `x * log(x)' are tabulated above. */

SshUInt32 ssh_lookup_split_goodness(SshUInt32 n,
                                    SshUInt32 n_lt,
                                    SshUInt32 n_eq,
                                    SshUInt32 n_gt)
{
  SshUInt32 s = n_lt + n_eq + n_gt;
  SshUInt32 p_lt = (n_lt * 256) / s;
  SshUInt32 p_eq = (n_eq * 256) / s;
  SshUInt32 p_gt = (n_gt * 256) / s;

  /* Use statements instead of expressions, parts of which could
     otherwise be associated so that integer overflow could occur. */
  SshInt32 result;

  result = -1024 * s;
  result /= (SshInt32) n;       /* The cast to a signed value is necessary. */
  result *= 1024;
  result /=
    ssh_lookup_xlogx[p_lt]
    + ssh_lookup_xlogx[p_eq]
    + ssh_lookup_xlogx[p_gt] + 1; /* Add one to prevent division by zero. */
  return result;

#if 0
  /* This is another approach: the counter number of the expectance of
     the number of rules covered by the subtree the search proceeds
     to.  In practice it was found to produce slightly slower search
     trees than the above rule. */
  return 0xFFFFFFFFUL - n_lt * p_lt - n_eq * p_eq - n_gt * p_gt;
#endif
}


SshUInt32 ssh_lookup_split2_goodness(SshUInt32 n,
                                     SshUInt32 n_le,
                                     SshUInt32 n_gt)
{
  SshUInt32 s = n_le + n_gt;
  SshUInt32 p_le = (n_le * 256) / s;
  SshUInt32 p_gt = (n_gt * 256) / s;
  SshInt32 result;

  result = -1024 * s;
  result /= (SshInt32) n;
  result *= 1024;
  result /= ssh_lookup_xlogx[p_le] + ssh_lookup_xlogx[p_gt] + 1;
  return result;

#if 0
  return 0xFFFFFFFFUL - n_le * p_le - n_gt * p_gt;
#endif
}


typedef int (*SshLookupRuleCmpFun)(SshEngineLookupPreamble *,
                                   SshEngineLookupPreamble *);


/* A quicksort for rule vectors.  Needed on some platforms where
   there's no qsort (such as BSD kernel), but made it default since it
   is some 20% faster than qsort (apparently because this code knows
   that array to be sorted is an aligned array of pointers). */

void ssh_lookup_rule_vector_sort(SshEngineLookupPreamble *v,
                                 SshUInt32 level,
                                 SshUInt32 n_rules,
                                 SshLookupRuleCmpFun cmp_f)
{
  int lo, hi;
  SshEngineLookupPreamble tmp, pivot;

  while (1)
    {
      if (n_rules <= 2)
        {
          if (n_rules == 2 && (*cmp_f)(&v[0], &v[1]) > 0)
            {
              /* An optimization for the case of two rules.  Shaves off
                 some 10% of CPU time. */
              /* Swap v[0] and v[1]. */
              tmp = v[0];
              v[0] = v[1];
              v[1] = tmp;
            }
          return;
        }
      /* Partition.  Could do something smarter, such as a median of
         three. */
      pivot = v[n_rules >> 1];
      lo = -1;
      hi = n_rules;
      while (1)
        {
          do
            {
              lo++;
              if (lo >= hi)
                goto out;
            }
          while (v[lo] != pivot && (*cmp_f)(&v[lo], &pivot) < 0);

          do
            {
              hi--;
              if (lo >= hi)
                goto out;
            }
          while (v[hi] != pivot && (*cmp_f)(&pivot, &v[hi]) < 0);

          SSH_ASSERT(lo < hi);

          tmp = v[lo]; v[lo] = v[hi]; v[hi] = tmp; /* Swap. */
        }
    out:
      /* Apply qsort recursively, but so that we recurse to the
         smaller partition and iterate back to the beginning of the
         outermost while loop for the larger partition.  This ensures
         logarithmic stack consumption. */
      if (lo < (n_rules >> 1))
        {
          ssh_lookup_rule_vector_sort(v, level + 1, lo, cmp_f);
          v += lo;
          n_rules -= lo;
        }
      else
        {
          ssh_lookup_rule_vector_sort(v + lo, level + 1, n_rules - lo, cmp_f);
          n_rules = lo;
        }
    }
}

/* Functions passed to `ssh_lookup_rule_vector_sort'. */

int ssh_lookup_cmp_dst_ip_lo(SshEngineLookupPreamble *r1,
                             SshEngineLookupPreamble *r2)
{
  return memcmp((*r1)->dst_ip_low, (*r2)->dst_ip_low, SSH_IP_ADDR_SIZE);
}

int ssh_lookup_cmp_dst_ip_hi(SshEngineLookupPreamble *r1,
                             SshEngineLookupPreamble *r2)
{
  return memcmp((*r1)->dst_ip_high, (*r2)->dst_ip_high, SSH_IP_ADDR_SIZE);
}

int ssh_lookup_cmp_src_ip_lo(SshEngineLookupPreamble *r1,
                             SshEngineLookupPreamble *r2)
{
  return memcmp((*r1)->src_ip_low, (*r2)->src_ip_low, SSH_IP_ADDR_SIZE);
}

int ssh_lookup_cmp_src_ip_hi(SshEngineLookupPreamble *r1,
                             SshEngineLookupPreamble *r2)
{
  return memcmp((*r1)->src_ip_high, (*r2)->src_ip_high, SSH_IP_ADDR_SIZE);
}

int ssh_lookup_cmp_dst_port_lo(SshEngineLookupPreamble *r1,
                               SshEngineLookupPreamble *r2)
{
  return (int) (*r1)->dst_port_low - (int) (*r2)->dst_port_low;
}

int ssh_lookup_cmp_dst_port_hi(SshEngineLookupPreamble *r1,
                               SshEngineLookupPreamble *r2)
{
  return (int) (*r1)->dst_port_high - (int) (*r2)->dst_port_high;
}

int ssh_lookup_cmp_src_port_lo(SshEngineLookupPreamble *r1,
                               SshEngineLookupPreamble *r2)
{
  return (int) (*r1)->src_port_low - (int) (*r2)->src_port_low;
}

int ssh_lookup_cmp_src_port_hi(SshEngineLookupPreamble *r1,
                               SshEngineLookupPreamble *r2)
{
  return (int) (*r1)->src_port_high - (int) (*r2)->src_port_high;
}

int ssh_lookup_cmp_dec_precedence(SshEngineLookupPreamble *r1,
                                  SshEngineLookupPreamble *r2)
{
  if ((*r1)->precedence < (*r2)->precedence)
    return 1;
  else if ((*r1)->precedence > (*r2)->precedence)
    return -1;
  else
    /* If the rules do not have a total order based on the precedence,
       then enforce any other arbitrary total order, in this case
       based on their relative addresses.  The purpose of this is to
       improve the caching of rule vectors, but nothing would break if
       this wouldn't be done. */
    if (*r1 > *r2)
      return 1;
    else
      return -1;
}


/* Build a decision tree or just a reference to a rule or a vector of
   rules, into `tree' from the `n_rules' rules listed in the vector
   `v', which is freed (or reused) by the callee.  The argument
   `n_rules_in_parent' is used by the heuristic which decides whether
   it is useful to create a decision tree node or leave the rules in a
   vector.  The heuristic is turned off if `n_rules_in_parent' is
   zero.  The argument `done_ratio' tells in 1/DONE_RATIO_BASEth's how
   much of the decision tree has been done, and `tree_todo_ratio'
   tells, again in 1/DONE_RATIO_BASEth's, how much of the decision
   tree the current call is expected to build.  The last argument
   contains input to heuristics which try to balance the memory usage
   with the search speed in the tree.

   On a successfull construction of the decision tree the function
   returns DONE_RATIO_BASE, on failure it returns the `done_ratio' of
   the call at which failure occurred.

   Building globally optimal decision trees is an NP-hard problem, but
   the typical "greedy" algorithms described in many AI text books
   practically always build quite sufficiently optimal decision trees.
   The greedy algorithms work as follows: given a set of rules, pick a
   splitting point which divides the set of rules as well as possible
   according to some measure `split_goodness()', let that splitting
   point be the root of the decision tree, and perform the same
   recursively for both subsets of rules.  Details vary on the
   algorithms and the formulas that evaluate `split_goodness()'.

   In our case the major differences to the standard case are
     - Our decision trees may have a fanout of three (less-than,
       equal, and greater-than) instead of the more typical fanout of
       two (for example greater-than, less-or-equal).  See the macro
       SPLIT3_CONDITION for the heuristic on which node type to use.
     - In our case are not building a decision tree according to a set
       of point data, but for a set of rules which span over possibly
       overlapping ranges.  It is quite possible that a given rule
       can be encountered in all subtrees of a given node.

   If the set of rules is sufficiently small or splits very badly,
   instead of creating a decision tree node, the references to rules
   are simply stored in a array.  In such cases the array must be
   traversed linearly with O(N) cost.  The array is, however, sorted
   according to a descending rule priority level, which allows us to
   stop traversing the array as soon as the first match is found.

   The algorithm for finding the "best" splitting point for N rules
   uses quicksort and therefore has the asymptotic cost of O(N log N).
   Hence the cost of building the whole decision tree is
   O(N log N + 2 * N/2 log N/2 + 4 * N/4 log N/4 + ... + N * 1 log 1)
   = O(N (log N)^2).  If we used radix sorting, we could be even faster. */

#define DONE_RATIO_BASE  0xFFFF

Boolean
ssh_lookup_compute_split(SshEnginePolicyRuleSet rs,
                         SshEngineLookupPreamble *v,
                         SshLookupRuleCount n_rules,
                         SshUInt32 memory_conservation,
                         SshLookupNode n,
                         SshLookupRuleCount *best_n_lt,
                         SshLookupRuleCount *best_n_eq,
                         SshLookupRuleCount *best_n_gt)
{
  /* The algorithm for finding the optimal splitting point works by
     enumerating all candidates for the splitting point, computing
     the number of rules in the left, middle and right subtrees for
     that splitting point candidate, and calling `split_goodness'
     with those values, and memorizing the best split point.

     These are the number of rules in each potential subtree
     candidate for splitting point `x':
     n_lt = Number of rules in `left', i.e. lo < x
     n_eq = Number of rules in `middle', i.e. lo <= x <= hi
     n_gt = Number of rules in `right', i.e. x < hi
     They are summed at each candidate splitting point from the
     intermediate variables below:
     n_l  = Number of rules whose hi < x
     n_le = Number of rules whose lo < x = hi
     n_ex = Number of rules whose lo = x = hi
     n_ge = Number of rules whose lo = x < hi
     n_e  = Number of rules whose lo < x < hi
     n_g  = Number of rules whose x < lo

     They in turn are updated incrementally while traversing two
     arrays of pointers to rules, one of which is sorted according
     to the `*low'-values of selectors, the other which is sorted
     according to the `*high'-values of the selectors.  `x' is the
     candidate splitting point. */
  SshLookupRuleCount n_l, n_le, n_ex, n_ge, n_e, n_g;
  SshLookupRuleCount n_lt, n_eq, n_gt, w_n_rules;
  SshUInt8 have_no_selector = 1, stepped_in, stepped_out;
  SshUInt32 highest_split_goodness = 0, goodness;
  SshEngineLookupPreamble r, *w;
  unsigned char *x_ip_addr = NULL;
  SshUInt16 x_port;
  SshLookupRuleCount i, j;

  SSH_INTERCEPTOR_STACK_MARK();

  w = ssh_lookup_rule_pool_allocate_tmp(rs, n_rules);
  if (w == NULL)
    return FALSE;

  /* Try selection by DST_IP. */
  ssh_lookup_rule_vector_sort(v, 0, n_rules, ssh_lookup_cmp_dst_ip_lo);
  for (i = j = 0; i < n_rules; i++)
    if (!v[i]->is_dst_point_rule)
      /* A minor optimization: Ignore point-rules.  This saves some
         tests later and decreases `w' a little. */
      w[j++] = v[i];
  w_n_rules = j;
  ssh_lookup_rule_vector_sort(w, 0, w_n_rules, ssh_lookup_cmp_dst_ip_hi);

  n_l = n_e = 0;
  n_g = n_rules;
  i = j = 0;
  while (n_g > 0 || n_e > 0)
    {
      n_ex = n_le = n_ge = 0;
      stepped_in = stepped_out = 0;

      /* Pick to `x_ip_addr' the next split point candidate.  It is
         an invariant in this algorithm that every hi and lo of each
         rule has is in its turn in `x_ip_addr', and that iteration
         increases `x_ip_addr'. */
      if (n_g > 0)
        {
          if (n_e > 0)
            {
              x_ip_addr = w[j]->dst_ip_high;
              if (memcmp(v[i]->dst_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE) < 0)
                x_ip_addr = v[i]->dst_ip_low;
            }
          else
            x_ip_addr = v[i]->dst_ip_low;
        }
      else
        x_ip_addr = w[j]->dst_ip_high;

      /* Count how many rules moved from n_e to n_le in the increase
         of `x_ip_addr' above. */
      while (/* j < w_n_rules && D1 */
             n_e > 0 &&
             memcmp(w[j]->dst_ip_high, x_ip_addr, SSH_IP_ADDR_SIZE) == 0)
        {
          /* Point rules should not be included in `w' at all. */
          SSH_ASSERT(memcmp(w[j]->dst_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE)
                     != 0);
          j++;
          n_le++;
          n_e--;
          stepped_out = 1;
        }

      /* Count how many rules moved from n_g to n_ge or n_ex. */
      while (n_g > 0 &&
             memcmp((r = v[i])->dst_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE) == 0)
        {
          i++;
          n_g--;
          stepped_in = 1;
          if (memcmp(r->dst_ip_high, x_ip_addr, SSH_IP_ADDR_SIZE)
              > 0)
            n_ge++;
          else
            {
              n_ex++;
              stepped_out = 1;
            }
        }

      SSH_ASSERT(stepped_in || stepped_out);

      /* Experiments have shown that 3-way nodes are beneficial
         close to the leave nodes whereas 2-way nodes are beneficial
         closer to the root of the decision tree.  That way there
         will be less rule pointer duplicates in the leaves. */
#define SPLIT3_CONDITION  \
          (n_rules + (memory_conservation >> 2) <= 9)

      if (SPLIT3_CONDITION)
        {
          /* Make a 3-way node. */
          n_lt = n_l + n_le + n_e;
          n_eq = n_le + n_ex + n_ge + n_e;
          n_gt = n_ge + n_e + n_g;
          goodness = ssh_lookup_split_goodness(n_rules, n_lt, n_eq, n_gt);
          if (have_no_selector || goodness > highest_split_goodness)
            {
              n->selector_type = DST_IP;
              n->selector_arg.ip_addr = x_ip_addr;
              highest_split_goodness = goodness;
              *best_n_lt = n_lt;
              *best_n_eq = n_eq;
              *best_n_gt = n_gt;
              have_no_selector = 0;
            }
        }
      else
        {
          /* Make a 2-way node. */
          if (stepped_out)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_rules - n_g,
                                                    n_ge + n_e + n_g);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = DST_IP2;
                  n->selector_arg.ip_addr = x_ip_addr;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_rules - n_g;
                  *best_n_eq = 0;
                  *best_n_gt = n_ge + n_e + n_g;
                  have_no_selector = 0;
                }
            }
          if (stepped_in)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_l + n_e + n_le,
                                                    n_rules - n_l);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = DST_IP3;
                  n->selector_arg.ip_addr = x_ip_addr;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_l + n_e + n_le;
                  *best_n_eq = 0;
                  *best_n_gt = n_rules - n_l;
                  have_no_selector = 0;
                }
            }
        }

      /* Since `x_ip_addr' is strictly increasing in this loop, all
         rules which now have hi = x_ip_addr, will be hi < x_ip_addr
         in the next iteration, and similarly all rules in for which
         x_ip_addr = lo < hi will be lo < x_ip_addr <= hi in the
         next iteration. */
      n_l += n_ex + n_le;
      n_e += n_ge;
    }

  /* Try selection by SRC_IP.  The comments from selection by DST_IP
     apply here too. */
  ssh_lookup_rule_vector_sort(v, 0, n_rules, ssh_lookup_cmp_src_ip_lo);
  for (i = j = 0; i < n_rules; i++)
    if (!v[i]->is_src_point_rule)
      w[j++] = v[i];
  w_n_rules = j;
  ssh_lookup_rule_vector_sort(w, 0, w_n_rules, ssh_lookup_cmp_src_ip_hi);

  n_l = n_e = 0;
  n_g = n_rules;
  i = j = 0;
  while (n_g > 0 || n_e > 0)
    {
      n_ex = n_le = n_ge = 0;
      stepped_in = stepped_out = 0;

      if (n_g > 0)
        {
          if (n_e > 0)
            {
              x_ip_addr = w[j]->src_ip_high;
              if (memcmp(v[i]->src_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE) < 0)
                x_ip_addr = v[i]->src_ip_low;
            }
          else
            x_ip_addr = v[i]->src_ip_low;
        }
      else
        x_ip_addr = w[j]->src_ip_high;

      while (n_e > 0 && /* D1 */
             memcmp(w[j]->src_ip_high, x_ip_addr, SSH_IP_ADDR_SIZE) == 0)
        {
          SSH_ASSERT(memcmp(w[j]->src_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE)
                     != 0);
          j++;
          n_le++;
          n_e--;
          stepped_out = 1;
        }

      while (n_g > 0 &&
             memcmp((r = v[i])->src_ip_low, x_ip_addr, SSH_IP_ADDR_SIZE) == 0)
        {
          i++;
          n_g--;
          stepped_in = 1;
          if (memcmp(r->src_ip_high, x_ip_addr, SSH_IP_ADDR_SIZE) > 0)
            n_ge++;
          else
            {
              n_ex++;
              stepped_out = 1;
            }
        }

      SSH_ASSERT(stepped_in || stepped_out);

      if (SPLIT3_CONDITION)
        {
          n_lt = n_l + n_le + n_e;
          n_eq = n_le + n_ex + n_ge + n_e;
          n_gt = n_ge + n_e + n_g;
          goodness = ssh_lookup_split_goodness(n_rules, n_lt, n_eq, n_gt);
          if (have_no_selector || goodness > highest_split_goodness)
            {
              n->selector_type = SRC_IP;
              n->selector_arg.ip_addr = x_ip_addr;
              highest_split_goodness = goodness;
              *best_n_lt = n_lt;
              *best_n_eq = n_eq;
              *best_n_gt = n_gt;
              have_no_selector = 0;
            }
        }
      else
        {
          if (stepped_out)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_rules - n_g,
                                                    n_ge + n_e + n_g);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = SRC_IP2;
                  n->selector_arg.ip_addr = x_ip_addr;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_rules - n_g;
                  *best_n_eq = 0;
                  *best_n_gt = n_ge + n_e + n_g;
                  have_no_selector = 0;
                }
            }
          if (stepped_in)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_l + n_e + n_le,
                                                    n_rules - n_l);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = SRC_IP3;
                  n->selector_arg.ip_addr = x_ip_addr;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_l + n_e + n_le;
                  *best_n_eq = 0;
                  *best_n_gt = n_rules - n_l;
                  have_no_selector = 0;
                }
            }
        }

      n_l += n_ex + n_le;
      n_e += n_ge;
    }

  /* Try selection by DST_PORT. */
  ssh_lookup_rule_vector_sort(v, 0, n_rules, ssh_lookup_cmp_dst_port_lo);
  for (i = j = 0; i < n_rules; i++)
    if (!v[i]->is_dst_point_port_rule)
      w[j++] = v[i];
  w_n_rules = j;
  ssh_lookup_rule_vector_sort(w, 0, w_n_rules, ssh_lookup_cmp_dst_port_hi);

  n_l = n_e = 0;
  n_g = n_rules;
  i = j = 0;
  while (n_g > 0 || n_e > 0)
    {
      n_ex = n_le = n_ge = 0;
      stepped_in = stepped_out = 0;

      if (n_g > 0)
        {
          if (n_e > 0)
            {
              x_port = w[j]->dst_port_high;
              if (v[i]->dst_port_low < x_port)
                x_port = v[i]->dst_port_low;
            }
          else
            x_port = v[i]->dst_port_low;
        }
      else
        x_port = w[j]->dst_port_high;

      while (n_e > 0 && w[j]->dst_port_high == x_port)
        {
          SSH_ASSERT(w[j]->dst_port_low != x_port);
          j++;
          n_le++;
          n_e--;
          stepped_out = 1;
        }

      while (n_g > 0 && (r = v[i])->dst_port_low == x_port)
        {
          i++;
          n_g--;
          if (r->dst_port_high > x_port)
            n_ge++;
          else
            {
              n_ex++;
              stepped_out = 1;
            }
        }

      if (SPLIT3_CONDITION)
        {
          n_lt = n_l + n_le + n_e;
          n_eq = n_le + n_ex + n_ge + n_e;
          n_gt = n_ge + n_e + n_g;
          goodness = ssh_lookup_split_goodness(n_rules, n_lt, n_eq, n_gt);
          if (goodness > highest_split_goodness)
            {
              n->selector_type = DST_PORT;
              n->selector_arg.port = x_port;
              highest_split_goodness = goodness;
              *best_n_lt = n_lt;
              *best_n_eq = n_eq;
              *best_n_gt = n_gt;
            }
        }
      else
        {
          if (stepped_out)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_rules - n_g,
                                                    n_ge + n_e + n_g);
              if (goodness > highest_split_goodness)
                {
                  n->selector_type = DST_PORT2;
                  n->selector_arg.port = x_port;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_rules - n_g;
                  *best_n_eq = 0;
                  *best_n_gt = n_ge + n_e + n_g;
                }
            }
          if (stepped_in)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_l + n_e + n_le,
                                                    n_rules - n_l);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = DST_PORT3;
                  n->selector_arg.port = x_port;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_l + n_e + n_le;
                  *best_n_eq = 0;
                  *best_n_gt = n_rules - n_l;
                  have_no_selector = 0;
                }
            }
        }

      n_l += n_ex + n_le;
      n_e += n_ge;
    }

  /* Try selection by SRC_PORT. */
  ssh_lookup_rule_vector_sort(v, 0, n_rules, ssh_lookup_cmp_src_port_lo);
  for (i = j = 0; i < n_rules; i++)
    if (!v[i]->is_src_point_port_rule)
      w[j++] = v[i];
  w_n_rules = j;
  ssh_lookup_rule_vector_sort(w, 0, w_n_rules, ssh_lookup_cmp_src_port_hi);

  n_l = n_e = 0;
  n_g = n_rules;
  i = j = 0;
  while (n_g > 0 || n_e > 0)
    {
      n_ex = n_le = n_ge = 0;
      stepped_in = stepped_out = 0;

      if (n_g > 0)
        {
          if (n_e > 0)
            {
              x_port = w[j]->src_port_high;
              if (v[i]->src_port_low < x_port)
                x_port = v[i]->src_port_low;
            }
          else
            x_port = v[i]->src_port_low;
        }
      else
        x_port = w[j]->src_port_high;

      while (n_e > 0 && w[j]->src_port_high == x_port)
        {
          SSH_ASSERT(w[j]->src_port_low != x_port);
          j++;
          n_le++;
          n_e--;
          stepped_out = 1;
        }

      while (n_g > 0 && (r = v[i])->src_port_low == x_port)
        {
          i++;
          n_g--;
          stepped_in = 1;
          if (r->src_port_high > x_port)
            n_ge++;
          else
            {
              n_ex++;
              stepped_out = 1;
            }
        }

      if (SPLIT3_CONDITION)
        {
          n_lt = n_l + n_le + n_e;
          n_eq = n_le + n_ex + n_ge + n_e;
          n_gt = n_ge + n_e + n_g;
          goodness = ssh_lookup_split_goodness(n_rules, n_lt, n_eq, n_gt);
          if (goodness > highest_split_goodness)
            {
              n->selector_type = SRC_PORT;
              n->selector_arg.port = x_port;
              highest_split_goodness = goodness;
              *best_n_lt = n_lt;
              *best_n_eq = n_eq;
              *best_n_gt = n_gt;
            }
        }
      else
        {
          if (stepped_out)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_rules - n_g,
                                                    n_ge + n_e + n_g);
              if (goodness > highest_split_goodness)
                {
                  n->selector_type = SRC_PORT2;
                  n->selector_arg.port = x_port;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_rules - n_g;
                  *best_n_eq = 0;
                  *best_n_gt = n_ge + n_e + n_g;
                }
            }
          if (stepped_in)
            {
              goodness = ssh_lookup_split2_goodness(n_rules,
                                                    n_l + n_e + n_le,
                                                    n_rules - n_l);
              if (have_no_selector || goodness > highest_split_goodness)
                {
                  n->selector_type = SRC_PORT3;
                  n->selector_arg.port = x_port;
                  highest_split_goodness = goodness;
                  *best_n_lt = n_l + n_e + n_le;
                  *best_n_eq = 0;
                  *best_n_gt = n_rules - n_l;
                  have_no_selector = 0;
                }
            }
        }

      n_l += n_ex + n_le;
      n_e += n_ge;
    }

  ssh_lookup_rule_pool_free_tmp(rs, n_rules);

  return TRUE;
}

SshUInt32
ssh_lookup_do_build(SshLookupBuildContext param)
{
  SshLookupBuildContext data;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_MY,
            ("Building decision tree (n=%d/%d, done=%d/%d, mem=%d, level=%d)",
             param->n_rules, param->n_rules_in_parent, (int) param->done_ratio,
             (int) param->tree_todo_ratio, (int) param->memory_conservation,
             (int) param->level));

  if (param->n_rules == 0)
    {
      param->tree->kind = RULE;
      param->tree->n_rules = 0;
      param->tree->u.rule = NULL;
      return DONE_RATIO_BASE;
    }
  else if (param->n_rules == 1)
    {
      param->tree->kind = RULE;
      param->tree->n_rules = 1;
      param->tree->u.rule = param->v[0];
      return DONE_RATIO_BASE;
    }
  else if (1 &&
           (param->n_rules < 4 + param->memory_conservation
            || (param->n_rules_in_parent != 0
                && ((param->n_rules + param->memory_conservation)
                    >= param->n_rules_in_parent - 2))))
    {
      /* The condition for not splitting a node is given above. */
      /* make_rule_vector: */
      ssh_lookup_rule_vector_sort(param->v, 0, param->n_rules,
                                  ssh_lookup_cmp_dec_precedence);
      param->tree->kind = RULE_VECTOR;
      param->tree->n_rules = param->n_rules;
      param->tree->u.rule_vector =
        ssh_lookup_rule_pool_stabilize_and_free(param->rs, param->v,
                                                param->n_rules);
      SSH_ASSERT(param->tree->u.rule_vector != NULL);
      return DONE_RATIO_BASE;
    }

  /* Get a build context for local variables and recursive function call. */
  data = ssh_lookup_build_context_get(param->rs);
  if (data == NULL)
    return param->done_ratio;

  data->n = ssh_lookup_node_allocate(param->rs);
  if (data->n == NULL)
    {
      ssh_lookup_build_context_put(param->rs, data);
      return param->done_ratio;
    }

  if (!ssh_lookup_compute_split(param->rs, param->v, param->n_rules,
                                param->memory_conservation, data->n,
                                &data->best_n_lt, &data->best_n_eq,
                                &data->best_n_gt))
    {
      ssh_lookup_build_context_put(param->rs, data);
      return param->done_ratio;
    }















  param->tree->kind = DECISION_NODE;
  param->tree->n_rules = param->n_rules; /* This is actually unused. */
  param->tree->u.node = data->n;

  /* Now `n->selector_type' and `n->selector_arg' contain the best
     selection decision.  Split the given input vector according to
     that criteria to left, middle and right rule vectors, possibly
     call `ssh_lookup_do_build' recursively for those rule vectors,
     and install the results in `n'. */

  {
    data->right = param->v;                  /* Reuse the memory in `v'. */
    data->middle = ssh_lookup_rule_pool_allocate_tmp(param->rs,
                                                     data->best_n_eq);
    data->left = ssh_lookup_rule_pool_allocate_tmp(param->rs,
                                                   data->best_n_lt);
    if (data->middle == NULL || data->left == NULL)
      {
        /* Rule pool memory exhausted. */
        ssh_lookup_build_context_put(param->rs, data);
        return param->done_ratio;
      }

    for (data->i = 0; data->i < param->n_rules; data->i++)
      switch (data->n->selector_type)
        {
        case DST_IP:
          if (memcmp(param->v[data->i]->dst_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) < 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->dst_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) <= 0 &&
              memcmp(param->v[data->i]->dst_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) >= 0)
            data->middle[data->middle_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->dst_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) > 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_IP:
          if (memcmp(param->v[data->i]->src_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) < 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->src_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) <= 0 &&
              memcmp(param->v[data->i]->src_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) >= 0)
            data->middle[data->middle_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->src_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) > 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case DST_PORT:
          if (param->v[data->i]->dst_port_low < data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->dst_port_low <= data->n->selector_arg.port &&
              param->v[data->i]->dst_port_high >= data->n->selector_arg.port)
            data->middle[data->middle_ctr++] = param->v[data->i];
          if (param->v[data->i]->dst_port_high > data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_PORT:
          if (param->v[data->i]->src_port_low < data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->src_port_low <= data->n->selector_arg.port &&
              param->v[data->i]->src_port_high >= data->n->selector_arg.port)
            data->middle[data->middle_ctr++] = param->v[data->i];
          if (param->v[data->i]->src_port_high > data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case DST_IP2:
          if (memcmp(param->v[data->i]->dst_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) <= 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->dst_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) > 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_IP2:
          if (memcmp(param->v[data->i]->src_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) <= 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->src_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) > 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case DST_PORT2:
          if (param->v[data->i]->dst_port_low <= data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->dst_port_high > data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_PORT2:
          if (param->v[data->i]->src_port_low <= data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->src_port_high > data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case DST_IP3:
          if (memcmp(param->v[data->i]->dst_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) < 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->dst_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) >= 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_IP3:
          if (memcmp(param->v[data->i]->src_ip_low,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) < 0)
            data->left[data->left_ctr++] = param->v[data->i];
          if (memcmp(param->v[data->i]->src_ip_high,
                     data->n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE) >= 0)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case DST_PORT3:
          if (param->v[data->i]->dst_port_low < data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->dst_port_high >= data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        case SRC_PORT3:
          if (param->v[data->i]->src_port_low < data->n->selector_arg.port)
            data->left[data->left_ctr++] = param->v[data->i];
          if (param->v[data->i]->src_port_high >= data->n->selector_arg.port)
            data->right[data->right_ctr++] = param->v[data->i];
          break;
        }
    SSH_ASSERT(data->left_ctr == data->best_n_lt);
    SSH_ASSERT(data->middle_ctr == data->best_n_eq);
    SSH_ASSERT(data->right_ctr == data->best_n_gt);

    /* Call recursively `ssh_lookup_do_build's for the above created
       rule vectors in reverse order of their allocation so that they
       can be freed a little earlier. */

    /* Compute into `subtree_todo_ratio' the ratio, expressed in
       1/DONE_RATIO_BASEth's, of the decision tree created so far.  We
       must have two alternative ways of computing it in order to
       avoid integer overflows. */

    /* Build left subtree. */
    if (param->tree_todo_ratio < 1000)
      {
        data->subtree_todo_ratio = param->tree_todo_ratio * data->best_n_lt;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
      }
    else
      {
        data->subtree_todo_ratio = 1024 * data->best_n_lt;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
        data->subtree_todo_ratio *= param->tree_todo_ratio;
        data->subtree_todo_ratio /= 1024;
      }

    data->rs = param->rs;
    data->tree = &data->n->tree[0];
    data->v = data->left;
    data->n_rules = data->left_ctr;
    data->n_rules_in_parent = param->n_rules;
    data->done_ratio = param->done_ratio;
    data->tree_todo_ratio = data->subtree_todo_ratio;
    data->memory_conservation = param->memory_conservation;
    data->level = param->level + 1;
    data->tmp = ssh_lookup_do_build(data);
    if (data->tmp != DONE_RATIO_BASE)
      {
        ssh_lookup_build_context_put(param->rs, data);
        return data->tmp;
      }
    param->done_ratio += data->subtree_todo_ratio;

    /* Build middle subtree. */
    if (param->tree_todo_ratio < 1000)
      {
        data->subtree_todo_ratio = param->tree_todo_ratio * data->best_n_eq;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
      }
    else
      {
        data->subtree_todo_ratio = 1024 * data->best_n_eq;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
        data->subtree_todo_ratio *= param->tree_todo_ratio;
        data->subtree_todo_ratio /= 1024;
      }

    data->rs = param->rs;
    data->tree = &data->n->tree[1];
    data->v = data->middle;
    data->n_rules = data->middle_ctr;
    data->n_rules_in_parent = param->n_rules;
    data->done_ratio = param->done_ratio;
    data->tree_todo_ratio = data->subtree_todo_ratio;
    data->memory_conservation = param->memory_conservation;
    data->level = param->level + 1;
    data->tmp = ssh_lookup_do_build(data);
    if (data->tmp != DONE_RATIO_BASE)
      {
        ssh_lookup_build_context_put(param->rs, data);
        return data->tmp;
      }
    param->done_ratio += data->subtree_todo_ratio;

    /* Build right subtree. */
    if (param->tree_todo_ratio < 1000)
      {
        data->subtree_todo_ratio = param->tree_todo_ratio * data->best_n_gt;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
      }
    else
      {
        data->subtree_todo_ratio = 1024 * data->best_n_gt;
        data->subtree_todo_ratio /=
          data->best_n_lt + data->best_n_eq + data->best_n_gt;
        data->subtree_todo_ratio *= param->tree_todo_ratio;
        data->subtree_todo_ratio /= 1024;
      }

    data->rs = param->rs;
    data->tree = &data->n->tree[2];
    data->v = data->right;
    data->n_rules = data->right_ctr;
    data->n_rules_in_parent = param->n_rules;
    data->done_ratio = param->done_ratio;
    data->tree_todo_ratio = data->subtree_todo_ratio;
    data->memory_conservation = param->memory_conservation;
    data->level = param->level + 1;
    data->tmp = ssh_lookup_do_build(data);
    if (data->tmp != DONE_RATIO_BASE)
      {
        ssh_lookup_build_context_put(param->rs, data);
        return data->tmp;
      }

    /* Unify the 2-way nodes into 3-way nodes. */
    switch (data->n->selector_type)
      {
      case DST_IP:
      case SRC_IP:
      case DST_PORT:
      case SRC_PORT:
        break;

      case DST_IP2:
        data->n->selector_type = DST_IP;
        data->n->tree[1] = data->n->tree[0];
        break;
      case SRC_IP2:
        data->n->selector_type = SRC_IP;
        data->n->tree[1] = data->n->tree[0];
        break;
      case DST_PORT2:
        data->n->selector_type = DST_PORT;
        data->n->tree[1] = data->n->tree[0];
        break;
      case SRC_PORT2:
        data->n->selector_type = SRC_PORT;
        data->n->tree[1] = data->n->tree[0];
        break;

      case DST_IP3:
        data->n->selector_type = DST_IP;
        data->n->tree[1] = data->n->tree[2];
        break;
      case SRC_IP3:
        data->n->selector_type = SRC_IP;
        data->n->tree[1] = data->n->tree[2];
        break;
      case DST_PORT3:
        data->n->selector_type = DST_PORT;
        data->n->tree[1] = data->n->tree[2];
        break;
      case SRC_PORT3:
        data->n->selector_type = SRC_PORT;
        data->n->tree[1] = data->n->tree[2];
        break;
      }
  }

  ssh_lookup_build_context_put(param->rs, data);
  return DONE_RATIO_BASE;
}

void ssh_lookup_decision_tree_build(SshEnginePolicyRuleSet rs)
{
  SshUInt32 memory_conservation, prev_memory_conservation = 0, i;
  SshEngineLookupPreamble r, *v;
  SshLookupBuildContext param;

  rs->highest_precedence_of_range_dst_ip_rules = 0;
  memory_conservation = 0;

 retry:
  ssh_lookup_rule_pool_clear(rs);
  ssh_lookup_node_pool_clear(rs);
  rs->n_cache_hits = rs->n_cache_misses = 0;

  /* Collect the rules from the linked list into a rule vector. */
  v = ssh_lookup_rule_pool_allocate_tmp(rs, rs->n_range_dst_ip_rules);
  SSH_ASSERT(v != NULL);
  for (i = 0, r = rs->range_dst_ip_rule_list;
       r != NULL;
       r = r->next, i++)
    {
      v[i] = r;
      if (r->precedence >= rs->highest_precedence_of_range_dst_ip_rules)
        rs->highest_precedence_of_range_dst_ip_rules = r->precedence;
    }
  SSH_ASSERT(i == rs->n_range_dst_ip_rules);

  /* Get and fill a build context and build the decision tree. */
  param = ssh_lookup_build_context_get(rs);
  SSH_ASSERT(param != NULL);
  param->rs = rs;
  param->tree = &rs->range_dst_ip_rule_tree;
  param->v = v;
  param->n_rules = (SshLookupRuleCount)rs->n_range_dst_ip_rules;
  param->n_rules_in_parent = 0;
  param->done_ratio = 0;
  param->tree_todo_ratio = DONE_RATIO_BASE;
  param->memory_conservation = memory_conservation;
  param->level = 0;

  i = ssh_lookup_do_build(param);

  /* Release the build context. */
  ssh_lookup_build_context_put(rs, param);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("n_cache_hits = %d, n_cache_misses = %d",
             (int) rs->n_cache_hits, (int) rs->n_cache_misses));
  /* If failed, adjust `memory_conservation' and retry. */
  if (i != DONE_RATIO_BASE)
    {
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Decision tree build failed for memory_conservation = %d",
                 (int) memory_conservation));
      /* The if's below increase `memory_conservation' the less the
         closer we were to success. */
      if (i < DONE_RATIO_BASE / 2)
        memory_conservation = 4 + 3 * memory_conservation;
      else if (3 * i < 2 * DONE_RATIO_BASE)
        memory_conservation = 2 + 2 * memory_conservation;
      else if (4 * i < 3 * DONE_RATIO_BASE)
        memory_conservation += memory_conservation / 2;
      else
        memory_conservation += memory_conservation / 8;
      memory_conservation += 2;
      if (memory_conservation <= prev_memory_conservation)
        {
          /* This could occur if `rs->rule_pool_size' or
             `rs->node_pool_size' are too small
             (i.e. never with the default settings).  Otherwise this
             is practically impossible: `memory_conservation' could
             overflow if we have approximately 10^9 range dst ip
             rules. */
          SSH_DEBUG(SSH_D_FAIL,
                    ("memory_conservation reached maximum value!"));
          memory_conservation = 0xFFFFFFFF;
        }
      goto retry;
    }
  SSH_DEBUG(SSH_D_HIGHOK,
            ("Decision tree build succeeded with memory_conservation = %d",
             (int) memory_conservation));

#if RANGE_DST_IP_BUFFER_SIZE > 0
  /* Empty the buffer. */
  for (i = 0; i < RANGE_DST_IP_BUFFER_SIZE; i++)
    {
      rs->range_dst_ip_rule_buffer[i] = NULL;
    }
#endif /* RANGE_DST_IP_BUFFER_SIZE */

  /* Reinit flags and counters. */
  rs->has_pending_range_dst_ip_rule_updates = FALSE;
  rs->n_lookups_before_flush = 0;

  return;
}

void
ssh_engine_rule_lookup_flush(SshEngine engine, SshEnginePolicyRuleSet rs)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  if (rs->has_pending_range_dst_ip_rule_updates)
    ssh_lookup_decision_tree_build(rs);

#ifdef DEBUG_LIGHT
  ssh_lookup_decision_tree_check(engine, rs, &rs->range_dst_ip_rule_tree);
  /* ssh_lookup_render(engine, ssh_lookup_dump_fun, stderr); */
#endif
}


/* This hash function passes at least statistical tests better than
   the one in lib/sshutil/sshnet/sshinet.c */
SshUInt32 ssh_lookup_ip_addr_hash(const unsigned char *ip_addr,
                                  int ip_addr_len)
{
  SshUInt32 h = 0;

  SSH_ASSERT(ip_addr_len <= SSH_IP_ADDR_SIZE);
  SSH_ASSERT(ip_addr_len == 4 || ip_addr_len == 16);

  if (ip_addr_len == 16)
    {
      unsigned int i;

      for (i = 4; i < 12; i += 2)
        {
          h += (((SshUInt32) (ip_addr[i])) << 8) | ip_addr[i+1];
          h += h << 10;
          h ^= h >> 7;
        }
    }

  h += (((SshUInt32) (ip_addr[0])) << 8) | ip_addr[1];
  h += h << 10;
  h ^= h >> 7;
  h += ip_addr[2];
  h += h << 10;
  h ^= h >> 7;
  h += ip_addr[3];
  h += h << 10;
  h ^= h >> 7;

  h += h << 3;
  h ^= h >> 11;
  h += h << 15;

  return h;
}

/* The rule lookup uses unused selector fields for it's own purposes.
   These fields are initialized per the rule contents in this
   function. */
void
ssh_engine_rule_lookup_prepare(SshEngine engine,
                               SshEnginePolicyRuleSet rs,
                               SshEngineLookupPreamble rule)
{
  int ip_addr_len;
  static const unsigned char all_zero[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const unsigned char all_one[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

  if (rule->protocol == SSH_PROTOCOL_IP4)
    ip_addr_len = 4;
  else
    ip_addr_len = 16;

  /* Fill "don't care"-cases of ip addrs with full ranges. */
  if (!(rule->selectors & SSH_SELECTOR_DSTIP))
    {
      memset(rule->dst_ip_low, 0x00, SSH_IP_ADDR_SIZE);
      memset(rule->dst_ip_high, 0xff, SSH_IP_ADDR_SIZE);
      rule->is_dst_wildcard_rule = 0x1;

    }
  if (!(rule->selectors & SSH_SELECTOR_SRCIP))
    {
      memset(rule->src_ip_low, 0x00, SSH_IP_ADDR_SIZE);
      memset(rule->src_ip_high, 0xff, SSH_IP_ADDR_SIZE);
      rule->is_src_wildcard_rule = 0x1;
    }

  /* If port selectors are not used, then we use the
     range [0..0xffff] as the range for the rules. This
     means we will in practice also match the invalid
     port number "0". If this is changed, note that
     equivalent changes must be made to "find_matching_rule"
     in engine_rule_lookup.c */
  if ((rule->selectors & SSH_SELECTOR_IPPROTO) == 0
      || rule->ipproto == SSH_IPPROTO_TCP
      || rule->ipproto == SSH_IPPROTO_UDP
      || rule->ipproto == SSH_IPPROTO_UDPLITE
      || rule->ipproto == SSH_IPPROTO_SCTP)
    {
      if (!(rule->selectors & SSH_SELECTOR_DSTPORT))
        {
          rule->dst_port_low = 0;
          rule->dst_port_high = 0xffff;
        }
      if (!(rule->selectors & SSH_SELECTOR_SRCPORT))
        {
          rule->src_port_low = 0;
          rule->src_port_high = 0xffff;
        }
    }



  else if ((rule->ipproto == SSH_IPPROTO_ICMP) ||
           (rule->ipproto == SSH_IPPROTO_IPV6ICMP))
    {
      if (!(rule->selectors & SSH_SELECTOR_ICMPTYPE) &&
          !(rule->selectors & SSH_SELECTOR_ICMPCODE))
        {
          rule->src_port_low = 0;
          rule->src_port_high = 0xffff;
          rule->dst_port_low = 0;
          rule->dst_port_high = 0xffff;
        }
    }
  else
    {
      rule->dst_port_low = rule->dst_port_high = 0;
      rule->src_port_low = rule->src_port_high = 0;
    }

  if (rule->protocol == SSH_PROTOCOL_IP4)
    {
#if defined (WITH_IPV6)
      /* Filling the last 12 bytes of the IP number in case of IPv4
         with zeros for point rules and 0xff's for range rules should
         never affect rule selection, but abbreviates some code in
         decision tree construction. */
      memset(rule->dst_ip_low + 4, 0x00, 12);
      if (memcmp(rule->dst_ip_low, rule->dst_ip_high, 4) == 0)
        memset(rule->dst_ip_high + 4, 0x00, 12);
      else
        memset(rule->dst_ip_high + 4, 0xff, 12);

      memset(rule->src_ip_low + 4, 0x00, 12);
      if (memcmp(rule->src_ip_low, rule->src_ip_high, 4) == 0)
        memset(rule->src_ip_high + 4, 0x00, 12);
      else
        memset(rule->src_ip_high + 4, 0xff, 12);
#endif /* WITH_IPV6 */
    }
  else
    {
#ifndef WITH_IPV6
      /* Just a sanity check - we shouldn't get any ipv6-rules here
         unless WITH_IPV6 is defined. */
      SSH_NOTREACHED;
#endif /* WITH_IPV6 */
    }
  rule->is_src_wildcard_rule = 0x0;
  if (memcmp(rule->src_ip_low, all_zero, ip_addr_len) == 0 &&
      memcmp(rule->src_ip_high, all_one, ip_addr_len) == 0)
    rule->is_src_wildcard_rule = 0x1;

  rule->is_src_point_rule = 0x0;
  if (memcmp(rule->src_ip_low, rule->src_ip_high, ip_addr_len) == 0)
    rule->is_src_point_rule = 0x1;

  rule->is_src_point_port_rule = 0x0;
  if (rule->src_port_low == rule->src_port_high)
    rule->is_src_point_port_rule = 0x1;

  rule->is_src_wildcard_port_rule = 0x0;
  if (rule->src_port_low == 0 && rule->src_port_high == 0xffff)
    rule->is_src_wildcard_port_rule = 0x1;

  rule->is_dst_wildcard_rule = 0x0;
  if (memcmp(rule->dst_ip_low, all_zero, ip_addr_len) == 0 &&
      memcmp(rule->dst_ip_high, all_one, ip_addr_len) == 0)
    rule->is_dst_wildcard_rule = 0x1;

  rule->is_dst_point_rule = 0x0;
  if (memcmp(rule->dst_ip_low, rule->dst_ip_high, ip_addr_len) == 0)
    rule->is_dst_point_rule = 0x1;

  rule->is_dst_point_port_rule = 0x0;
  if (rule->dst_port_low == rule->dst_port_high)
    rule->is_dst_point_port_rule = 0x1;

  rule->is_dst_wildcard_port_rule = 0x0;
  if (rule->dst_port_low == 0 && rule->dst_port_high == 0xffff)
    rule->is_dst_wildcard_port_rule = 0x1;

  return;
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
  int ip_addr_len;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  ssh_engine_rule_lookup_prepare(engine, rs, rule);

  if (rule->protocol == SSH_PROTOCOL_IP4)
    ip_addr_len = 4;
  else
    ip_addr_len = 16;

  SSH_ASSERT(memcmp(rule->src_ip_low, rule->src_ip_high, ip_addr_len) <= 0);
  SSH_ASSERT(memcmp(rule->dst_ip_low, rule->dst_ip_high, ip_addr_len) <= 0);

  SSH_TRACE(SSH_D_MIDOK,
            ("adding %@", ssh_engine_policy_rule_render, rule));
  SSH_DEBUG(SSH_D_MIDOK, ("has_... = %d, n_look... = %d",
                          rs->has_pending_range_dst_ip_rule_updates,
                          (int) rs->n_lookups_before_flush));

  if (rule->is_dst_point_rule)
    {
      /* Point dst ip rule, put it in the hash table. */
      SshUInt32 h;
      SshEngineLookupPreamble *rulesp;

      h = ssh_lookup_ip_addr_hash(rule->dst_ip_low, ip_addr_len);
      h ^= rule->tunnel_id;
      h %= rs->point_dst_ip_hash_size;
      rulesp = &POINT_DST_IP_RULES(rs, h);
#ifdef DEBUG_HEAVY
      {
        SshEngineLookupPreamble r;

        /* Ensure the rule is not inserted twice. */
        for (r = *rulesp; r != NULL; r = r->next)
          SSH_ASSERT(r != rule);
      }
#endif /* DEBUG_LIGHT */

      for (p_rule = NULL, n_rule = *rulesp;
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
        *rulesp = rule;
      if (n_rule != NULL)
        n_rule->prev = rule;
    }
  else
    {
      /* Range dst ip rule, put it in the list. */
      SshEngineLookupPreamble *rulesp = &rs->range_dst_ip_rule_list;

      if (rs->n_range_dst_ip_rules == rs->rule_pool_size
          || rs->node_pool_size == 0)
        return FALSE;

      /* The addition of the rule succeeds if the above conditions
         are true, although if the number of range dst ip rules is
         close to rs->rule_pool_size, then the
         construction of the decision tree will take longer. */

#ifdef DEBUG_HEAVY
      /* Ensure the rule is not inserted twice. */
      {
        SshEngineLookupPreamble r;

        for (r = *rulesp; r != NULL; r = r->next)
          SSH_ASSERT(r != rule);
      }

      /* If we debug, we insert the rules into the list in
         descending order. */
      for (p_rule = NULL, n_rule = *rulesp;
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
        *rulesp = rule;
      if (n_rule != NULL)
        n_rule->prev = rule;
#else /* !DEBUG_HEAVY */
      /* Insert the rule into the head of list. */
      rule->next = *rulesp;
      rule->prev = NULL;
      if (*rulesp != NULL)
        (*rulesp)->prev = rule;
      *rulesp = rule;
#endif /* !DEBUG_HEAVY */

      rs->n_range_dst_ip_rules++;

#if RANGE_DST_IP_BUFFER_SIZE > 0
      {
        int i;
        /* Try to put the rule into the buffer. */
        for (i = 0; i < RANGE_DST_IP_BUFFER_SIZE; i++)
          {
            if (rs->range_dst_ip_rule_buffer[i] == NULL)
              {
                /* Found an empty slot in the buffer, store the rule
                   there. */
                rs->range_dst_ip_rule_buffer[i] = rule;
                if (rule->precedence >
                    rs->highest_precedence_of_range_dst_ip_rules)
                  rs->highest_precedence_of_range_dst_ip_rules =
                    rule->precedence;
                /* Set the lookup timeout and return. */
                rs->n_lookups_before_flush =
                  N_LOOKUPS_BEFORE_RANGE_DST_IP_BUFFER_FLUSH;
                return TRUE;
              }
          }
      }
#endif /* RANGE_DST_IP_BUFFER_SIZE > 0 */

      /* Did not find an empty slot in the buffer.  Trigger decision
         tree reconstruction before the next lookup. */
      rs->n_lookups_before_flush = 0;
      rs->has_pending_range_dst_ip_rule_updates = TRUE;

      /* Everything else, including accurate maintainance of
         `rs->highest_precedence_of_range_dst_ip_rules', is done in
         the decision tree building code. */
    }

  return TRUE;
}


/* Removes the rule from the data structures used for rule lookups.
   engine->flow_control_table_lock must already be held when this is called. */

void ssh_engine_rule_lookup_remove(SshEngine engine,
                                   SshEnginePolicyRuleSet rs,
                                   SshEngineLookupPreamble rule)
{
  SshEngineLookupPreamble *rulesp;
  int ip_addr_len = (rule->protocol == SSH_PROTOCOL_IP4) ? 4 : 16;

  SSH_ASSERT(ip_addr_len <= SSH_IP_ADDR_SIZE);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_TRACE(SSH_D_MIDOK,
            ("removing %@", ssh_engine_policy_rule_render, rule));

  ssh_engine_rule_lookup_prepare(engine, rs, rule);

  if (rule->is_dst_point_rule)
    {
      /* Point dst ip rule, it should be in the hash table.
         Remove rule from the hash table slot. */
      if (rule->next != NULL)
        rule->next->prev = rule->prev;
      if (rule->prev != NULL)
        rule->prev->next = rule->next;
      else
        {
          SshUInt32 h = ssh_lookup_ip_addr_hash(rule->dst_ip_low, ip_addr_len);
          h ^= rule->tunnel_id;
          h %= rs->point_dst_ip_hash_size;
          rulesp = &POINT_DST_IP_RULES(rs, h);
          SSH_ASSERT(*rulesp == rule);
          *rulesp = rule->next;
        }
      rule->next = NULL;
      rule->prev = NULL;
    }
  else
    {
      /* Range dst ip rule. Remove rule from the range dst ip list. */
      rulesp = &rs->range_dst_ip_rule_list;
      rs->n_range_dst_ip_rules--;

#if RANGE_DST_IP_BUFFER_SIZE > 0
      {
        int i;

        for (i = 0; i < RANGE_DST_IP_BUFFER_SIZE; i++)
          {
            if (rs->range_dst_ip_rule_buffer[i] == rule)
              {
                rs->range_dst_ip_rule_buffer[i] = NULL;
                /* A little heuristics to push the flush a little further. */
                rs->n_lookups_before_flush +=
                  N_LOOKUPS_BEFORE_RANGE_DST_IP_BUFFER_FLUSH / 4;
                if (rs->n_lookups_before_flush >
                    N_LOOKUPS_BEFORE_RANGE_DST_IP_BUFFER_FLUSH)
                  rs->n_lookups_before_flush =
                    N_LOOKUPS_BEFORE_RANGE_DST_IP_BUFFER_FLUSH;
                goto out;
              }
          }
      }
#endif /* RANGE_DST_IP_BUFFER_SIZE */

      /* Not found in buffer, must be in the decision tree.  Trigger
         its rebuilding. */
      rs->n_lookups_before_flush = 0;
      rs->has_pending_range_dst_ip_rule_updates = TRUE;

#if RANGE_DST_IP_BUFFER_SIZE > 0
    out:
#endif /* RANGE_DST_IP_BUFFER_SIZE */
      if (rule->next != NULL)
        rule->next->prev = rule->prev;
      if (rule->prev != NULL)
        rule->prev->next = rule->next;
      else
        {
          SSH_ASSERT(*rulesp == rule);
          *rulesp = rule->next;
        }
      rule->next = NULL;
      rule->prev = NULL;
    }
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

  int ip_addr_len = (rule->protocol == SSH_PROTOCOL_IP4) ? 4 : 16;

  SSH_ASSERT(ip_addr_len <= SSH_IP_ADDR_SIZE);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (memcmp(rule->dst_ip_low, rule->dst_ip_high, ip_addr_len) == 0)
    {
      /* Point dst ip rule. */
      SshUInt32 h = ssh_lookup_ip_addr_hash(rule->dst_ip_low, ip_addr_len);
      h ^= rule->tunnel_id;
      h %= rs->point_dst_ip_hash_size;
      r = POINT_DST_IP_RULES(rs, h);
    }
  else
    {
      /* Range dst ip rule.  We could search the rule in the
         decision trees, but we'll take a simplified approach for
         now and look in the list. */
      r = rs->range_dst_ip_rule_list;
    }

  for (; r != NULL; r = r->next)
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
  SshEngineLookupPreamble best_rule, *rule_vector;
  SshUInt32 h;
  SshLookupRef tree;
  int cmp, i = 0;

  SSH_ASSERT(ip_addr_len <= SSH_IP_ADDR_SIZE);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_MIDOK, ("has_... = %d, n_look... = %d",
                          rs->has_pending_range_dst_ip_rule_updates,
                          (int) rs->n_lookups_before_flush));

  /* Check if there is need to rebuild the range dst ip decision tree. */
  if (rs->has_pending_range_dst_ip_rule_updates)
    {
      ssh_lookup_decision_tree_build(rs);
#ifdef DEBUG_LIGHT
      ssh_lookup_decision_tree_check(engine, rs, &rs->range_dst_ip_rule_tree);
      /* ssh_lookup_render(engine, ssh_lookup_dump_fun, stderr); */
#endif
    }
  SSH_ASSERT(!rs->has_pending_range_dst_ip_rule_updates);

  /* First try to look up the rule in the point dst ip hash table. */
  h = ssh_lookup_ip_addr_hash(dst_ip, ip_addr_len);
  h ^= tunnel_id;
  h %= rs->point_dst_ip_hash_size;
  for (rule = POINT_DST_IP_RULES(rs, h);
       rule != NULL;
       rule = rule->next)
    {
      if (tunnel_id != rule->tunnel_id ||
          src_port < rule->src_port_low ||
          src_port > rule->src_port_high ||
          dst_port < rule->dst_port_low ||
          dst_port > rule->dst_port_high ||
          (cmp = memcmp(dst_ip, rule->dst_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(dst_ip, rule->dst_ip_high, ip_addr_len) > 0) ||
          (cmp = memcmp(src_ip, rule->src_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(src_ip, rule->src_ip_high, ip_addr_len) > 0))
        continue;

      if (test_fun == NULL_FNPTR || (*test_fun)(engine, rule, extensions, ctx))
        break;
    }
  if (rule != NULL &&
      rule->precedence >= rs->highest_precedence_of_range_dst_ip_rules)
    /* No need to go into the decision tree if we've found a
       sufficiently high precedenced rule. */
    return rule;

  /* No rule was found, or there may be a higher precedence rule in
     the decision tree or its buffer. */
  best_rule = rule;
#if RANGE_DST_IP_BUFFER_SIZE > 0
  if (rs->n_lookups_before_flush > 0)
    {
      rs->n_lookups_before_flush--;
      if (rs->n_lookups_before_flush == 0)
        rs->has_pending_range_dst_ip_rule_updates = TRUE;
    }

  /* First look into the buffer.  Note that the rules are in no
     particular order in the buffer, therefore we must traverse
     through the whole buffer and check every rule's precedence. */
  for (i = 0; i < RANGE_DST_IP_BUFFER_SIZE; i++)
    {
      rule = rs->range_dst_ip_rule_buffer[i];

      if (rule == NULL ||
          (best_rule != NULL && best_rule->precedence >= rule->precedence) ||
          tunnel_id != rule->tunnel_id ||
          src_port < rule->src_port_low ||
          src_port > rule->src_port_high ||
          dst_port < rule->dst_port_low ||
          dst_port > rule->dst_port_high ||
          (cmp = memcmp(dst_ip, rule->dst_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(dst_ip, rule->dst_ip_high, ip_addr_len) > 0) ||
          (cmp = memcmp(src_ip, rule->src_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(src_ip, rule->src_ip_high, ip_addr_len) > 0))
        continue;

      if (test_fun == NULL_FNPTR || (*test_fun)(engine, rule, extensions, ctx))
        best_rule = rule;
    }

#endif /* RANGE_DST_IP_BUFFER_SIZE > 0 */

  /* Look into the decision tree. */
  tree = &rs->range_dst_ip_rule_tree;
  while (tree->kind == DECISION_NODE)
    {
      SshLookupNode n = tree->u.node;

      SSH_ASSERT(n != NULL);  /* Empty trees should have kind RULE. */
      switch (n->selector_type) {
      case DST_IP:
        cmp = memcmp(dst_ip, n->selector_arg.ip_addr, ip_addr_len);
        /* Hmm... This would be faster on most modern machines with
           conditional instructions:
             tree = &n->tree[0];
             if (cmp >= 0) &n->tree[1];  or  tree++;
             if (cmp > 0)  &n->tree[2];  or  tree++;
           but it is also harder to read.  Let's just hope the
           compiler does that optimization for us. */
        if (cmp < 0)
          tree = &n->tree[0];
        else if (cmp == 0)
          tree = &n->tree[1];
        else
          tree = &n->tree[2];
        break;
      case SRC_IP:
        cmp = memcmp(src_ip, n->selector_arg.ip_addr, ip_addr_len);
        if (cmp < 0)
          tree = &n->tree[0];
        else if (cmp == 0)
          tree = &n->tree[1];
        else
          tree = &n->tree[2];
        break;
      case DST_PORT:
        if (dst_port < n->selector_arg.port)
          tree = &n->tree[0];
        else if (dst_port == n->selector_arg.port)
          tree = &n->tree[1];
        else
          tree = &n->tree[2];
        break;
      case SRC_PORT:
        if (src_port < n->selector_arg.port)
          tree = &n->tree[0];
        else if (src_port == n->selector_arg.port)
          tree = &n->tree[1];
        else
          tree = &n->tree[2];
        break;
      default:
        /* The other selector types are replaced with the above ones
           in the end of `ssh_lookup_do_build', thereby making the
           lookup code a little smaller. */
        SSH_NOTREACHED;
        break;
      }
    }

  if (tree->kind == RULE)
    {
      if (tree->n_rules == 0)
        /* We come here if there are no dst ip range rules, i.e. the
           decision tree is empty.  Jump to the code that, when
           DEBUG_HEAVY is defined, does the cross-checking with
           list-based implementation, and then returns. */
        goto found;
      rule = tree->u.rule;
      rule_vector = NULL;
      goto test_rule;
      /* The goto saves some duplicate code. */
    }

  SSH_ASSERT(tree->kind == RULE_VECTOR);
  rule_vector = tree->u.rule_vector;
  for (i = 0; rule_vector != NULL && i < tree->n_rules; i++)
    {
      rule = rule_vector[i];
    test_rule:
      if (best_rule != NULL && best_rule->precedence >= rule->precedence)
        {
          goto found;
        }

      /* "Built-in" selectors for rules. */
      if (tunnel_id != rule->tunnel_id ||
          src_port < rule->src_port_low ||
          src_port > rule->src_port_high ||
          dst_port < rule->dst_port_low ||
          dst_port > rule->dst_port_high ||
          (cmp = memcmp(dst_ip, rule->dst_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(dst_ip, rule->dst_ip_high, ip_addr_len) > 0) ||
          (cmp = memcmp(src_ip, rule->src_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(src_ip, rule->src_ip_high, ip_addr_len) > 0))
        continue;

      if (test_fun == NULL_FNPTR || (*test_fun)(engine, rule, extensions, ctx))
        {
          best_rule = rule;
        }
    }

 found:
  /* Use the point dst ip rule whenever possible. */
  SSH_DEBUG(SSH_D_MIDOK,
            ("%s rule after linear scan of %d leafs",
             best_rule ? "Found" : "Missed",
             i));

#ifdef DEBUG_HEAVY
  /* Compare the rule found in the decision tree to the rule in the
       lists. */
  for (rule = rs->range_dst_ip_rule_list; rule != NULL; rule = rule->next)
    {
      if (tunnel_id != rule->tunnel_id ||
          src_port < rule->src_port_low ||
          src_port > rule->src_port_high ||
          dst_port < rule->dst_port_low ||
          dst_port > rule->dst_port_high ||
          (cmp = memcmp(dst_ip, rule->dst_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(dst_ip, rule->dst_ip_high, ip_addr_len) > 0) ||
          (cmp = memcmp(src_ip, rule->src_ip_low, ip_addr_len)) < 0 ||
          (cmp != 0 && memcmp(src_ip, rule->src_ip_high, ip_addr_len) > 0))
        continue;

      if (test_fun == NULL_FNPTR || (*test_fun)(engine, rule, extensions, ctx))
        {
          /* If we found it in the lists, then we must have found it
             also in the decision tree... */
          SSH_ASSERT(best_rule != NULL);
          /* ... and it must have the same precedence (although it
             may not necessarily be the same rule) than `best_rule'. */





          SSH_ASSERT(rule->precedence <= best_rule->precedence);
          break;
        }
    }
#endif /* DEBUG_HEAVY */
  return best_rule;
}

#ifdef DEBUG_LIGHT
/*****************************************************************************
 * Make recursively various checks on the decision tree.  Returns the
 * longest rule vector encountered.
 */

#define SSH_ASSERT_RULE_IS_OK(rule)                     \
  do {                                                  \
    SSH_ASSERT((rule)->transform_index != 0xdeadbeef);  \
    SSH_ASSERT((rule)->depends_on != 0xdeadbeef);       \
  } while (0)

static void ssh_lookup_decision_tree_check(SshEngine engine,
                                           SshEnginePolicyRuleSet rs,
                                           SshLookupRef tree)
{
#if 0
  int i;

  switch (tree->kind)
    {
    case RULE:
      if (tree->n_rules == 0)
        SSH_ASSERT(tree->u.rule == NULL);
      else
        {
          SSH_ASSERT(tree->n_rules == 1);
          SSH_ASSERT_RULE_IS_OK(tree->u.rule);
        }
      break;

    case RULE_VECTOR:
      SSH_ASSERT(tree->n_rules >= 2);
      SSH_ASSERT(tree->n_rules <= SSH_ENGINE_MAX_RULES);
      for (i = 0; i < tree->n_rules; i++)
        {
          SSH_ASSERT_RULE_IS_OK(tree->u.rule_vector[i]);
          if (i > 0)
            {
              /* Assert that the rule vector does not contain
                 duplicates, and that it is correctly ordered. */
              SSH_ASSERT(tree->u.rule_vector[i] != tree->u.rule_vector[i-1]);
              SSH_ASSERT(tree->u.rule_vector[i]->precedence <
                           tree->u.rule_vector[i-1]->precedence ||
                         (tree->u.rule_vector[i]->precedence ==
                            tree->u.rule_vector[i-1]->precedence &&
                          tree->u.rule_vector[i] > tree->u.rule_vector[i-1]));
            }
        }
      break;

    case DECISION_NODE:
      if (engine != NULL)
        {
          SSH_ASSERT(tree->u.node >= &rs->node_pool[0]);
          SSH_ASSERT(tree->u.node <
                     &rs->node_pool[rs->node_pool_size]);
        }
      SSH_ASSERT(tree->u.node->selector_type >= DST_IP);
      SSH_ASSERT(tree->u.node->selector_type <= SRC_PORT3);
      for (i = 0; i < 3; i++)
        ssh_lookup_decision_tree_check(engine, rs, &tree->u.node->tree[i]);
      break;

    default:
      SSH_NOTREACHED;
    }
#endif
}


typedef void (*SshLookupRenderDumpFun)(char *str, void *ctx);

typedef const char *SshSelName;

static void ssh_lookup_decision_tree_render(SshLookupRef tree,
                                            int n_indents,
                                            SshLookupRenderDumpFun dumper,
                                            void *ctx)
{
  static const SshSelName sel_name[] = {
    "DST_IP", "SRC_IP", "DST_PORT", "SRC_PORT",
    "DST_IP2", "SRC_IP2", "DST_PORT2", "SRC_PORT2",
    "DST_IP3", "SRC_IP3", "DST_PORT3", "SRC_PORT3",
  };
  SshLookupNode n;
  int i, buf_used;
  SshIpAddrStruct ip;

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
      (*dumper)("ssh_lookup_decision_tree_render: ssh_calloc failed.", ctx);
      return;
    }
#endif

  if (tree == NULL)
    {
      buf_used = ssh_snprintf(buf, BUF_LEN, "%*s NULL", n_indents, "");
      if (buf_used <= BUF_LEN)
        (*dumper)(buf, ctx);
      else
        (*dumper)("NULL", ctx);
    }
  else
    {
      switch (tree->kind) {
      case RULE:
        if (tree->u.rule == NULL)
          buf_used = ssh_snprintf(buf, BUF_LEN, "%*sNULL",
                                  n_indents, "");
        else
          buf_used = ssh_snprintf(buf, BUF_LEN, "%*s%@",
                                  n_indents, "",
                                  ssh_engine_policy_rule_render,
                                  tree->u.rule);
        if (buf_used <= BUF_LEN)
          (*dumper)(buf, ctx);
        else
          (*dumper)("TOO LONG LINE", ctx);
        break;
      case RULE_VECTOR:
        for (i = 0; i < tree->n_rules; i++)
          {
            buf_used = ssh_snprintf(buf, BUF_LEN, "%*s%@",
                                    n_indents, "",
                                    ssh_engine_policy_rule_render,
                                    tree->u.rule_vector[i]);
            if (buf_used <= BUF_LEN)
              (*dumper)(buf, ctx);
            else
              (*dumper)("TOO LONG LINE", ctx);
          }
        break;
      case DECISION_NODE:
        n = tree->u.node;
        if (n->selector_type == DST_PORT ||
            n->selector_type == SRC_PORT ||
            n->selector_type == DST_PORT2 ||
            n->selector_type == SRC_PORT2 ||
            n->selector_type == DST_PORT3 ||
            n->selector_type == SRC_PORT3)
          {

            buf_used = ssh_snprintf(buf, BUF_LEN, "%*s%s %d",
                                    n_indents, "",
                                    sel_name[n->selector_type],
                                    n->selector_arg.port);
            if (buf_used <= BUF_LEN)
              (*dumper)(buf, ctx);
            else
              (*dumper)("TOO LONG LINE", ctx);
          }
        else
          {
            SSH_IP_DECODE(&ip, n->selector_arg.ip_addr, SSH_IP_ADDR_SIZE);
            buf_used = ssh_snprintf(buf, BUF_LEN, "%*s%s %@",
                                    n_indents, "",
                                    sel_name[n->selector_type],
                                    ssh_ipaddr_render, &ip);
            if (buf_used <= BUF_LEN)
              (*dumper)(buf, ctx);
            else
              (*dumper)("TOO LONG LINE", ctx);
          }
        for (i = 0; i < 3; i++)
          {
            ssh_lookup_decision_tree_render(&n->tree[i], n_indents + 4,
                                            dumper, ctx);
            if (i != 2)
              {
                buf_used = ssh_snprintf(buf, BUF_LEN, "%*s --", n_indents, "");
                if (buf_used <= BUF_LEN)
                  (*dumper)(buf, ctx);
                else
                  (*dumper)("TOO LONG LINE", ctx);
              }
          }
        break;
      default:
        SSH_NOTREACHED;
      }
    }
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  ssh_free(buf);
#endif
}

void ssh_lookup_render(SshEngine engine,
                       SshLookupRenderDumpFun dumper,
                       void *ctx)
{
  int buf_used;
  SshUInt32 i;
  SshEngineLookupPreamble rule;
  SshEnginePolicyRuleSet rs = engine->policy_rule_set;

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
      (*dumper)("ssh_lookup_decision_tree_render: ssh_calloc failed.", ctx);
      return;
    }
#endif

  /* First dump the hash table. */
  (*dumper)("Contents of the point dst ip hash table:", ctx);
  for (i = 0; i < rs->point_dst_ip_hash_size; i++)
    {
      rule = POINT_DST_IP_RULES(rs, i);
      if (rule != NULL)
        {
          ssh_snprintf(buf, BUF_LEN, "Bucket %u:",
                       (unsigned int) i);
          (*dumper)(buf, ctx);
          for (; rule != NULL; rule = rule->next)
            {
              buf_used = ssh_snprintf(buf, BUF_LEN, "    %@",
                                      ssh_engine_policy_rule_render,
                                      rule);
              if (buf_used <= BUF_LEN)
                (*dumper)(buf, ctx);
              else
                (*dumper)("TOO LONG LINE", ctx);
            }
        }
    }

  (*dumper)("Contents of the range dst ip decision tree:", ctx);
  ssh_lookup_decision_tree_render(&rs->range_dst_ip_rule_tree, 0, dumper, ctx);
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  ssh_free(buf);
#endif
}

/* A typical use of ssh_lookup_render_warning is from within gdb with
     call ssh_lookup_render_warning(engine) */

static void ssh_lookup_dump_warning(char *str, void *ctx)
{
  SSH_ASSERT(ctx == NULL);
  ssh_warning(str);
}

void ssh_lookup_render_warning(SshEngine engine)
{
  ssh_lookup_render(engine, ssh_lookup_dump_warning, NULL);
}

#ifndef KERNEL

static void ssh_lookup_dump_fun(char *str, void *ctx)
{
  fprintf((FILE *) ctx, "%s\n", str);
}

void ssh_lookup_dump_file(SshEngine engine, const char *filename)
{
  FILE *fp = fopen(filename, "w");
  if (fp == NULL)
    ssh_warning("Could not open file `%s' for writing.", filename);
  else
    {
      ssh_lookup_render(engine, ssh_lookup_dump_fun, fp);
      fclose(fp);
    }
}

#endif /* !KERNEL */

#endif /* DEBUG_LIGHT */

#else /* SSH_IPSEC_SMALL */

typedef enum
{
  SSH_DUMMY_0
} SshMakeFileNotEmpty;

#endif
