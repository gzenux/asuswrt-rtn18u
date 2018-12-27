/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internals for the engine_rule_lookup_tree.c, data structures
   that may be needed outside of the module.
*/

#ifndef ENGINE_RULE_LOOKUP_H
#define ENGINE_RULE_LOOKUP_H


typedef struct SshEngineLookupPreambleRec
{
  /*******************************************************************
   * Start of fixed preamble; keep in sync with all rule types using
   * engine_rule_lookup functions, and preferrably leave alone.
   */
  /*
   * Selectors for the rule.  All rules must have at least protocol,
   * and tunnelid fields set.  If other selectors are set, the
   * corresponding bits are set in the flags field.  (Note that the
   * selectors have been ordered here so that values smaller than 32
   * bits are grouped together, so that the data structure becomes
   * smaller.  There can be MANY of these rules, so this can be a
   * significant space saving.
   */
  SshUInt32 precedence;
  SshUInt32 tunnel_id; /* 0=initial 1=tr pass 2+: pm can use; not used
                          for IPS*/
  unsigned char dst_ip_low[SSH_IP_ADDR_SIZE], dst_ip_high[SSH_IP_ADDR_SIZE];
  unsigned char src_ip_low[SSH_IP_ADDR_SIZE], src_ip_high[SSH_IP_ADDR_SIZE];
  SshUInt16 dst_port_low, dst_port_high;
  SshUInt16 src_port_low, src_port_high;

  /* is_* are internals to the lookup mechanism, they do not need to
     be filled by caller */
  SshUInt16 is_src_point_rule:1;      /* src_ip_low == src_ip_high */
  SshUInt16 is_src_point_port_rule:1; /* src_port_low == src_port_high */
  SshUInt16 is_dst_point_rule:1;
  SshUInt16 is_dst_point_port_rule:1;
  SshUInt16 is_src_wildcard_rule:1;
  SshUInt16 is_src_wildcard_port_rule:1;
  SshUInt16 is_dst_wildcard_rule:1;
  SshUInt16 is_dst_wildcard_port_rule:1;

  SshUInt16 protocol:4; /* SshInterceptorProtocol */

  SshUInt16 ipproto;

  /* Selectors for the policy rule. Protected by
     engine->flow_table_lock. This controls access to values outside
     of the fixed preamble. */
  SshUInt16 selectors;

  /* space of 16 bits free here */

  /* Next and previous rules in the list of policy rules. Engine will set
     this when the rule is installed.  These fields are only used in
     engine_rule_lookup_[tree|list].c. */
  struct SshEngineLookupPreambleRec *next;
  struct SshEngineLookupPreambleRec *prev;

  /*
   * End of fixed preamble
   *******************************************************************/
} *SshEngineLookupPreamble, SshEngineLookupPreambleStruct;


typedef struct SshLookupNodeRec *SshLookupNode;
typedef struct SshLookupNodeRec  SshLookupNodeStruct;


typedef struct SshLookupRefRec
{

#define DECISION_NODE   0x0
#define RULE            0x1
#define RULE_VECTOR     0x2

  unsigned int kind : 2;        /* DECISION_NODE, RULE, or RULE_VECTOR.
                                   Can't use an enum here because of
                                   some compilers. */
  unsigned int n_rules : 30;
  union
  {
    SshLookupNode node;         /* If kind == DECISION_NODE */
    SshEngineLookupPreamble rule;   /* If kind == RULE */
    SshEngineLookupPreamble *rule_vector; /* If kind == RULE_VECTOR */
  } u;
} SshLookupRefStruct, *SshLookupRef;

struct SshLookupNodeRec
{
  SshLookupRefStruct tree[3];
  enum
    {
      DST_IP, SRC_IP, DST_PORT, SRC_PORT,
      DST_IP2, SRC_IP2, DST_PORT2, SRC_PORT2,
      DST_IP3, SRC_IP3, DST_PORT3, SRC_PORT3
    } selector_type;
  union
  {
    unsigned char *ip_addr;
    SshUInt16 port;
  } selector_arg;
};


typedef struct SshLookupRuleVectorCacheRec  SshLookupRuleVectorCacheStruct;
typedef struct SshLookupRuleVectorCacheRec *SshLookupRuleVectorCache;
typedef struct SshLookupBuildContextRec SshLookupBuildContextStruct;
typedef struct SshLookupBuildContextRec *SshLookupBuildContext;

struct SshEnginePolicyRuleSetRec
{
#ifdef SSH_IPSEC_SMALL
  SshEngineLookupPreamble policy_rules;
#else /* SSH_IPSEC_SMALL */

  /* A possibly large hash table of rules whose dst ip number is not a
     range, but a single point value. */
  size_t point_dst_ip_hash_size;
  size_t point_dst_ip_hash_block_size;
  SshEngineLookupPreamble **point_dst_ip_rule_hash;

  /* The highest possible precedence found elsewhere. */
  SshUInt32 highest_precedence_of_range_dst_ip_rules;

  /* The decision tree of range dst ip rules. */
  SshLookupRefStruct range_dst_ip_rule_tree;

/* The decision tree which indexes all range dst ip rules is efficient
   to search in, but costly to build.  Therefore, in order to amortize
   the cost of building it, we buffer the rules to be added into the
   tree.  Below the buffer's size. */
#define RANGE_DST_IP_BUFFER_SIZE  0

/* Since the buffer (an array) is slow to perform lookups in, we flush
   the buffer to the decision tree and reconstruct it whenever this
   many lookups have been done. */
#define N_LOOKUPS_BEFORE_RANGE_DST_IP_BUFFER_FLUSH   200


  /* A buffer of range dst ip rules waiting to be added to the
     tree. Make it one larger than actually used (just to ease
     compilation on SUNWspro (to avoid zero subscripts). */
  SshEngineLookupPreamble range_dst_ip_rule_buffer[RANGE_DST_IP_BUFFER_SIZE+1];

  /* Linked list of range dst ip rules, stored in arbitrary order, but
     If DEBUG_LIGHT, keep the list in descending order of precedence -
     this helps testing. */
  SshEngineLookupPreamble range_dst_ip_rule_list;

  /* The number of rules in the above list. */
  SshUInt32 n_range_dst_ip_rules;

  /* This flag is TRUE if we have inserted or deleted rules into the
     list but not yet rebuilt the decision trees.  They are rebuilt
     before the first lookup. */
  Boolean has_pending_range_dst_ip_rule_updates;

  /* This tells how many lookups may be performed before the range dst
     ip rule buffer is flushed.  When it reaches zero, the above flag
     `has_pending_range_dst_ip_rule_updates' is set, and the next
     lookup builds the decision tree. */
  SshUInt32 n_lookups_before_flush;

  /* The node pool is a contiguous, and in some cases a fixed size
     vector reserved for the decision tree nodes. */
  size_t node_pool_size;
  SshLookupNode node_pool, node_pool_allocation_ptr;

  /* The rule pool is a contiguous, and in some cases a fixed size
     vector of pointers to rules.  We allocate stack-like temporary
     rule vectors from top of it and occasionally copy ("stabilize")
     such vectors to the bottom of the rule pool.  We can also free
     temporaries, clear the whole rule pool, query for its memory
     usage, and sort rule vectors in it. */
  size_t rule_pool_size;
  SshEngineLookupPreamble *rule_pool, *rule_pool_low, *rule_pool_high;

  /* Rule pool cache is a lookaside buffer used to cause some sharing
     among the vectors of pointers in the rule pool. */
  SshLookupRuleVectorCache rule_pool_cache;

  /* Statistics */
  SshUInt32 n_cache_hits, n_cache_misses;

  /* Context pool is a table of context structures for the rule lookup
     tree build process. */
  SshLookupBuildContext build_context_pool;
#endif /* SSH_IPSEC_SMALL */
};

/* eof */
#endif /* ENGINE_RULE_LOOKUP_H */
