/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Allocation and low-level initialization of the engine object.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */

#define SSH_DEBUG_MODULE "SshEngineInit"

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
/* Allocate large tables as static variables if preallocate_tables has
   been specified. */

#define SSH_ENGINE_FLOW_C_TABLE_ROOT_SIZE \
((SSH_ENGINE_FLOW_TABLE_SIZE + SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE - 1) \
 / (SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE))

static SshEngineFlowControl ssh_engine_flow_control_table_root
                                        [SSH_ENGINE_FLOW_C_TABLE_ROOT_SIZE];

static SshEngineFlowControlStruct ssh_engine_flow_control_table
                                        [SSH_ENGINE_FLOW_C_TABLE_ROOT_SIZE]
                                        [SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE];


#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
static SshUInt32 ssh_engine_next_hop_addr_hash[SSH_ENGINE_NEXT_HOP_HASH_SIZE];
static SshUInt32
ssh_engine_next_hop_ifnum_hash[SSH_ENGINE_NH_C_IFNUM_HASH_SIZE];

#define SSH_ENGINE_NH_C_TABLE_ROOT_SIZE \
((SSH_ENGINE_NEXT_HOP_HASH_SIZE + SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE - 1) \
 / (SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE))

static SshEngineNextHopControl ssh_engine_next_hop_control_table_root[
                                        SSH_ENGINE_NH_C_TABLE_ROOT_SIZE];

static SshEngineNextHopControlStruct ssh_engine_next_hop_control_table
                                        [SSH_ENGINE_NH_C_TABLE_ROOT_SIZE]
                                        [SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE];

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#define SSH_ENGINE_TR_C_TABLE_ROOT_SIZE    \
((SSH_ENGINE_TRANSFORM_TABLE_SIZE         \
  + SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE - 1)  \
 / (SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE))

static SshEngineTransformControl ssh_engine_transform_control_table_root[
                                        SSH_ENGINE_TR_C_TABLE_ROOT_SIZE];

static SshEngineTransformControlStruct ssh_engine_transform_control_table
                                [SSH_ENGINE_TR_C_TABLE_ROOT_SIZE]
                                [SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE];


static SshUInt32 ssh_engine_peer_hash[SSH_ENGINE_PEER_HASH_SIZE];
static SshUInt32 ssh_engine_peer_handle_hash[SSH_ENGINE_PEER_HANDLE_HASH_SIZE];


#define SSH_ENGINE_RULE_TABLE_ROOT_SIZE                         \
((SSH_ENGINE_MAX_RULES + SSH_ENGINE_RULE_TABLE_BLOCK_SIZE - 1)  \
 / (SSH_ENGINE_RULE_TABLE_BLOCK_SIZE))

static SshEnginePolicyRule ssh_engine_rule_table_root[
                                        SSH_ENGINE_RULE_TABLE_ROOT_SIZE];

static SshEnginePolicyRuleStruct ssh_engine_rule_table
                                [SSH_ENGINE_RULE_TABLE_ROOT_SIZE]
                                [SSH_ENGINE_RULE_TABLE_BLOCK_SIZE];


#define SSH_ENGINE_PACKET_CONTEXTS_ROOT_SIZE         \
((SSH_ENGINE_MAX_PACKET_CONTEXTS                     \
  + SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE - 1)       \
 / (SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE))

static SshEnginePacketContext ssh_engine_pc_table_root[
                                   SSH_ENGINE_PACKET_CONTEXTS_ROOT_SIZE];

static SshEnginePacketContextStruct ssh_engine_pc_table
                                [SSH_ENGINE_PACKET_CONTEXTS_ROOT_SIZE]
                                [SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE];

static SshEngineAuditEventStruct ssh_engine_audit_table
                              [SSH_ENGINE_NUM_AUDIT_LEVELS]
                              [SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS];

#ifdef SSHDIST_IPSEC_NAT
#define SSH_ENGINE_FLOW_NAT_ROOT_SIZE         \
((SSH_ENGINE_FLOW_NAT_TABLE_SIZE              \
  + SSH_ENGINE_FLOW_NAT_BLOCK_SIZE - 1)       \
 / (SSH_ENGINE_FLOW_NAT_BLOCK_SIZE))

static SshEngineNatPort ssh_engine_nat_port_table_root[
                                          SSH_ENGINE_FLOW_NAT_ROOT_SIZE];

static SshEngineNatPortStruct ssh_engine_nat_port_table
                                [SSH_ENGINE_FLOW_NAT_ROOT_SIZE]
                                [SSH_ENGINE_FLOW_NAT_BLOCK_SIZE];

static SshEngineNatPort ssh_engine_nat_ports_hash[
                                        SSH_ENGINE_FLOW_NAT_HASH_SIZE];
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_TCPENCAP
static SshEngineTcpEncapsConn
ssh_engine_tcp_encaps_connection_table[SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE];
#endif /* SSH_IPSEC_TCPENCAP */

static SshEngineStruct ssh_engine;
static Boolean ssh_engine_exists = FALSE;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifndef SSH_IPSEC_PREALLOCATE_TABLES

/* Allocate a two-dimension array of 'nelems'
   of size 'elem_size' split into blocks of 'page_size'
   elements. Note that it could be possible to compute
   the "page_size" from the other parameters and
   SSH_ENGINE_MAX_MALLOC, but as most macros indexing
   the tables use this parameter it is kept
   as a parameter. */
void **ssh_engine_calloc_2d_table(SshEngine engine,
                                  SshUInt32 nelems,
                                  SshUInt32 page_size,
                                  SshUInt32 elem_size)
{
  void **ptr;
  SshUInt32 nblocks, i, j, real_size;

  nblocks = (nelems + page_size - 1) / page_size;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("allocating 2d table[%u][%u] (%u elements, elem %u bytes)",
             (unsigned int) nblocks, (unsigned int) page_size,
             (unsigned int) nelems, (unsigned int) elem_size));

  /* Allocate the main table */
  ptr = (void **) ssh_calloc_flags(nblocks, sizeof(void *),
                                   SSH_KERNEL_ALLOC_WAIT);
  if (ptr == NULL)
    return NULL;

  /* Allocate the blocks in the table */
  for (i = 0; i < nblocks; i++)
    {
      /* Do not allocate a block of full size for the last block,
         but only the size required for the whole table to hold
         'nelems'. */
      real_size = page_size;
      if (i == (nblocks-1))
        real_size = nelems % page_size;
      if (real_size == 0)
        real_size = page_size;

      /* A lot of blocks of possibly maximum size are allocated in a
         very short time. The only way this will work if one lets the
         kernel block for a short while. */
      ptr[i] = ssh_calloc_flags(real_size, elem_size, SSH_KERNEL_ALLOC_WAIT);
      if (ptr[i] == NULL)
        {








          SSH_DEBUG(SSH_D_FAIL,
                    ("allocation of page %u of %u*%u = %u bytes failed",
                     i, real_size, elem_size, real_size*elem_size));

          for (j = 0; j < i; j++)
            ssh_free(ptr[j]);
          ssh_free(ptr);
          return NULL;
        }
    }

  return ptr;
}

void ssh_engine_free_2d_table(SshEngine engine,
                              void **ptr,
                              SshUInt32 nelems,
                              SshUInt32 page_size)
{
  SshUInt32 i, nblocks;

  nblocks = (nelems + page_size - 1) / page_size;

  if (ptr == NULL)
    return;

  for (i = 0; i < nblocks; i++)
    ssh_free(ptr[i]);
  ssh_free(ptr);
}
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

/* Initialize data structures common to both the fastpath and the engine,
   but that are not appropriate to initialize inside the fastpath only. */
Boolean
ssh_engine_init_common(SshEngine engine)
{
  SshEnginePacketContext pc;
  SshUInt32 i;

 SSH_ASSERT(engine->num_cpus > 0);

 if (engine->num_cpus + 1 > SSH_ENGINE_MAX_PACKET_CONTEXTS)
   {
     ssh_warning("Fewer packet contexts (%d) than CPU's (%d) in the system."
                 "Increase the value of SSH_ENGINE_MAX_PACKET_CONTEXTS",
                 SSH_ENGINE_MAX_PACKET_CONTEXTS, engine->num_cpus);
     return FALSE;
   }
  /* Initialize packet context table. We use a set of per-CPU freelists of
     packet contexts plus one extra freelist (the last element in the
     engine->pc_freelist array) shared among all processors. Packet Contexts
     can be accessed without locking from the per-CPU freelist list, or if
     there are no available packets in the current CPU freelist, the packet
     is accessed from the shared freelist (which requires taking a lock). */
 engine->pc_freelist = ssh_calloc_flags(engine->num_cpus + 1,
                                        sizeof(SshEnginePacketContext),
                                        SSH_KERNEL_ALLOC_WAIT);
 if (engine->pc_freelist == NULL)
   {
     SSH_DEBUG(SSH_D_ERROR, ("Cannot allocate pc freelist"));
     return FALSE;
   }

  for (i = 0; i < SSH_ENGINE_MAX_PACKET_CONTEXTS; i++)
    {
      pc = SSH_ENGINE_GET_PC(engine, i);
      pc->on_freelist = TRUE;

      pc->next = engine->pc_freelist[i % engine->num_cpus];
      engine->pc_freelist[i % engine->num_cpus] = pc;
    }


 return TRUE;
}


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


SshEngine
ssh_engine_alloc(void)
{
  SshEngine engine;
  unsigned int i;

  /* Allocate an engine object. */
#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  SSH_ASSERT(!ssh_engine_exists);
  ssh_engine_exists = TRUE;
  engine = &ssh_engine;
  memset(engine, 0, sizeof(*engine));
#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  engine = ssh_calloc_flags(1, sizeof(*engine), SSH_KERNEL_ALLOC_WAIT);
  if (engine == NULL)
    return NULL;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  engine->num_cpus = ssh_kernel_num_cpus();
  SSH_ASSERT(engine->num_cpus > 0);

  engine->cpu_ctx = ssh_calloc_flags(engine->num_cpus,
                                     sizeof(SshEngineCpuCtxStruct),
                                     SSH_KERNEL_ALLOC_WAIT);

  if (engine->cpu_ctx == NULL)
    {
      ssh_free(engine);
      return NULL;
    }

  if (ssh_kernel_critical_section_init(&engine->cpu_ctx_critical_section)
      == FALSE)
    {
      ssh_free(engine->cpu_ctx);
      ssh_free(engine);
      return NULL;
    }

  for (i = 0; i < engine->num_cpus; i++)
    ssh_kernel_mutex_init(&engine->cpu_ctx[i].pkt_list_lock);

  engine->flow_control_table_lock = ssh_kernel_mutex_alloc();
  engine->interface_lock = ssh_kernel_mutex_alloc();
  engine->pc_lock = ssh_kernel_mutex_alloc();
  engine->pp_lock = ssh_kernel_mutex_alloc();
#ifdef SSH_IPSEC_TCPENCAP
  engine->tcp_encaps_lock = ssh_kernel_mutex_alloc();
#endif /* SSH_IPSEC_TCPENCAP */
  engine->trigger_lock = ssh_kernel_mutex_alloc();
  if (engine->flow_control_table_lock == NULL ||
      engine->pc_lock == NULL ||
      engine->pp_lock == NULL ||
#ifdef SSH_IPSEC_TCPENCAP
      engine->tcp_encaps_lock == NULL ||
#endif /* SSH_IPSEC_TCPENCAP */
      engine->interface_lock == NULL ||
      engine->trigger_lock == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocating mutexes failed"));
      goto fail;
    }

  if (!ssh_kernel_critical_section_init(engine->engine_critical_section))
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocating critical sections failed"));
      goto fail;
    }
  engine->engine_critical_section_initialized = TRUE;

  if (ssh_ip_init_interfaces(&engine->ifs) == FALSE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("initialization of interface table failed!"));
      goto fail;
    }

  engine->next_packet_id = ssh_calloc_flags(engine->num_cpus,
                                            sizeof(SshUInt16),
                                            SSH_KERNEL_ALLOC_WAIT);
  if (engine->next_packet_id == NULL)
    goto fail;
  for (i = 0; i < engine->num_cpus; i++)
    engine->next_packet_id[i] =
      (i * ((FASTPATH_ENGINE_IP_ID_MAX - FASTPATH_ENGINE_IP_ID_MIN + 1)
            / engine->num_cpus) + FASTPATH_ENGINE_IP_ID_MIN);

  /* Allocate/assign memory for the various tables. */
  engine->flow_table_size = SSH_ENGINE_FLOW_TABLE_SIZE;
  engine->flow_id_hash_size = SSH_ENGINE_FLOW_ID_HASH_SIZE;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  engine->next_hop_hash_size = SSH_ENGINE_NEXT_HOP_HASH_SIZE;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  engine->transform_table_size = SSH_ENGINE_TRANSFORM_TABLE_SIZE;
  engine->rule_table_size = SSH_ENGINE_MAX_RULES;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* Sanity check: only one engine can exist if preallocated tables. */

  /* Initialize 2d flow table */
  engine->flow_control_table_root = ssh_engine_flow_control_table_root;
  for (i = 0; i < SSH_ENGINE_FLOW_C_TABLE_ROOT_SIZE; i++)
    {
      engine->flow_control_table_root[i] =
        &ssh_engine_flow_control_table[i][0];
    }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  engine->next_hop_addr_hash = ssh_engine_next_hop_addr_hash;
  engine->next_hop_ifnum_hash = ssh_engine_next_hop_ifnum_hash;
  engine->next_hop_control_table_root = ssh_engine_next_hop_control_table_root;
  for (i = 0; i < SSH_ENGINE_NH_C_TABLE_ROOT_SIZE; i++)
    {
      engine->next_hop_control_table_root[i] =
        &ssh_engine_next_hop_control_table[i][0];
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Initialize 2d transform data table */
  engine->transform_control_table_root =
    ssh_engine_transform_control_table_root;
  for (i = 0; i < SSH_ENGINE_TR_C_TABLE_ROOT_SIZE; i++)
    {
      engine->transform_control_table_root[i] =
        &ssh_engine_transform_control_table[i][0];
    }

  engine->peer_hash = ssh_engine_peer_hash;

  engine->peer_handle_hash = ssh_engine_peer_handle_hash;

  engine->rule_table_root = ssh_engine_rule_table_root;
  for (i = 0; i < SSH_ENGINE_RULE_TABLE_ROOT_SIZE; i++)
    {
      engine->rule_table_root[i] = &ssh_engine_rule_table[i][0];
    }

  for (i = 0 ; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    engine->audit_table[i] = ssh_engine_audit_table[i];

  engine->audit_table_size = SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS;

  engine->pc_table_root = ssh_engine_pc_table_root;
  for (i = 0; i < SSH_ENGINE_PACKET_CONTEXTS_ROOT_SIZE; i++)
    {
      engine->pc_table_root[i] = &ssh_engine_pc_table[i][0];
    }

#ifdef SSHDIST_IPSEC_NAT
  engine->nat_port_table_root = ssh_engine_nat_port_table_root;
  for (i = 0; i < SSH_ENGINE_FLOW_NAT_ROOT_SIZE; i++)
    {
      engine->nat_port_table_root[i] = &ssh_engine_nat_port_table[i][0];
    }

  engine->nat_ports_hash = ssh_engine_nat_ports_hash;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_TCPENCAP
  engine->tcp_encaps_connection_table = ssh_engine_tcp_encaps_connection_table;
#endif /* SSH_IPSEC_TCPENCAP */

#else /* SSH_IPSEC_PREALLOCATE_TABLES */

  /* Both fastpath_init() and engine_start() prepare the flow tables
     for use. */
  ENGINE_2D_ALLOC_OR_FAIL("engine flow table",
                          engine->flow_control_table_root,
                          engine->flow_table_size,
                          SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE,
                          sizeof(SshEngineFlowControlStruct));

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  engine->next_hop_addr_hash =
    ssh_calloc_flags(engine->next_hop_hash_size,
                     sizeof(engine->next_hop_addr_hash[0]),
                     SSH_KERNEL_ALLOC_WAIT);
  engine->next_hop_ifnum_hash =
    ssh_calloc_flags(SSH_ENGINE_NH_C_IFNUM_HASH_SIZE,
                     sizeof(engine->next_hop_ifnum_hash[0]),
                     SSH_KERNEL_ALLOC_WAIT);

  ENGINE_2D_ALLOC_OR_FAIL("next hop node table",
                          engine->next_hop_control_table_root,
                          engine->next_hop_hash_size,
                          SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE,
                          sizeof(SshEngineNextHopControlStruct));

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* The engine_init() function prepares the transform table for use,
     so memset() is not required. */
  ENGINE_2D_ALLOC_OR_FAIL("engine transform table",
                          engine->transform_control_table_root,
                          engine->transform_table_size,
                          SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE,
                          sizeof(SshEngineTransformControlStruct));

  engine->peer_hash = ssh_calloc_flags(SSH_ENGINE_PEER_HASH_SIZE,
                                       sizeof(engine->peer_hash[0]),
                                       SSH_KERNEL_ALLOC_WAIT);

  if (engine->peer_hash == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of peer hash table failed"));
      goto fail;
    }

  engine->peer_handle_hash =
    ssh_calloc_flags(SSH_ENGINE_PEER_HANDLE_HASH_SIZE,
                     sizeof(engine->peer_handle_hash[0]),
                     SSH_KERNEL_ALLOC_WAIT);

  if (engine->peer_handle_hash == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of IKE SA hash table failed"));
      goto fail;
    }

  /* engine_start() prepares the rule table for use, so calloc()
     is not required. */
  ENGINE_2D_ALLOC_OR_FAIL("rule table",
                          engine->rule_table_root,
                          engine->rule_table_size,
                          SSH_ENGINE_RULE_TABLE_BLOCK_SIZE,
                          sizeof(SshEnginePolicyRuleStruct));

  ENGINE_2D_ALLOC_OR_FAIL("packet context table",
                          engine->pc_table_root,
                          SSH_ENGINE_MAX_PACKET_CONTEXTS,
                          SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE,
                          sizeof(SshEnginePacketContextStruct));

  for (i = 0 ; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    {
      engine->audit_table[i] =
        ssh_calloc_flags(SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS,
                         sizeof(engine->audit_table[i][0]),
                         SSH_KERNEL_ALLOC_WAIT);

      if (engine->audit_table[i] == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("allocation of audit table cache failed"));
          goto fail;
        }
    }
  engine->audit_table_size = SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS;

#ifdef SSHDIST_IPSEC_NAT
  ENGINE_2D_ALLOC_OR_FAIL("port NAT table",
                          engine->nat_port_table_root,
                          SSH_ENGINE_FLOW_NAT_TABLE_SIZE,
                          SSH_ENGINE_FLOW_NAT_BLOCK_SIZE,
                          sizeof(SshEngineNatPortStruct));

  engine->nat_ports_hash = ssh_calloc_flags(SSH_ENGINE_FLOW_NAT_HASH_SIZE,
                                            sizeof(engine->nat_ports_hash[0]),
                                            SSH_KERNEL_ALLOC_WAIT);

  if (engine->nat_ports_hash == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of NAT tables failed"));
      goto fail;
    }
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_TCPENCAP
  engine->tcp_encaps_connection_table =
    ssh_calloc_flags(SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE,
                     sizeof(engine->tcp_encaps_connection_table[0]),
                     SSH_KERNEL_ALLOC_WAIT);
  SSH_DEBUG(SSH_D_LOWOK,
            ("allocated space for TCP encapsulation connection table"));
#endif /* SSH_IPSEC_TCPENCAP */

  if (engine->flow_control_table_root == NULL
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      || engine->next_hop_addr_hash == NULL
      || engine->next_hop_ifnum_hash == NULL
      || engine->next_hop_control_table_root == NULL
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#ifdef SSHDIST_IPSEC_NAT
      || engine->nat_port_table_root == NULL
      || engine->nat_ports_hash == NULL
#endif /* SSHDIST_IPSEC_NAT */
      || engine->transform_control_table_root == NULL
      || engine->peer_hash == NULL
      || engine->peer_handle_hash == NULL
#ifdef SSH_IPSEC_TCPENCAP
      || engine->tcp_encaps_connection_table == NULL
#endif /* SSH_IPSEC_TCPENCAP */
      || engine->rule_table_root == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("allocation of tables failed"));
      goto fail;
    }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
#ifdef USERMODE_ENGINE
  engine->kernelmode_stacksize = SSH_ENGINE_ASSUMED_KERNEL_STACK_SIZE;
#endif /* USERMODE_ENGINE */
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */





  return engine;

 fail:

  ssh_engine_free(engine);
  return NULL;
}

void
ssh_engine_free(SshEngine engine)
{
  unsigned int i;

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  ssh_engine_free_2d_table(engine, (void**)engine->flow_control_table_root,
                           engine->flow_table_size,
                           SSH_ENGINE_FLOW_C_TABLE_BLOCK_SIZE);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_free(engine->next_hop_addr_hash);
  ssh_free(engine->next_hop_ifnum_hash);
  ssh_engine_free_2d_table(engine, (void**)engine->next_hop_control_table_root,
                           engine->next_hop_hash_size,
                           SSH_ENGINE_NH_C_TABLE_BLOCK_SIZE);
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  ssh_engine_free_2d_table(engine,
                           (void**)engine->transform_control_table_root,
                           engine->transform_table_size,
                           SSH_ENGINE_TR_C_TABLE_BLOCK_SIZE);

  ssh_free(engine->peer_hash);
  ssh_free(engine->peer_handle_hash);
  ssh_engine_free_2d_table(engine, (void**)engine->rule_table_root,
                           engine->rule_table_size,
                           SSH_ENGINE_RULE_TABLE_BLOCK_SIZE);
  ssh_engine_free_2d_table(engine, (void**)engine->pc_table_root,
                           SSH_ENGINE_MAX_PACKET_CONTEXTS,
                           SSH_ENGINE_PACKET_CONTEXTS_BLOCK_SIZE);

  for (i = 0 ; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    ssh_free(engine->audit_table[i]);

#ifdef SSHDIST_IPSEC_NAT
  ssh_engine_free_2d_table(engine, (void**)engine->nat_port_table_root,
                           SSH_ENGINE_FLOW_NAT_TABLE_SIZE,
                           SSH_ENGINE_FLOW_NAT_BLOCK_SIZE);


  ssh_free(engine->nat_ports_hash);
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_TCPENCAP
  ssh_free(engine->tcp_encaps_connection_table);
#endif /* SSH_IPSEC_TCPENCAP */

#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  ssh_ip_uninit_interfaces(&engine->ifs);

  if (engine->flow_control_table_lock != NULL)
    ssh_kernel_mutex_free(engine->flow_control_table_lock);

  if (engine->interface_lock != NULL)
    ssh_kernel_mutex_free(engine->interface_lock);

  if (engine->pc_lock != NULL)
    ssh_kernel_mutex_free(engine->pc_lock);

  if (engine->pp_lock != NULL)
    ssh_kernel_mutex_free(engine->pp_lock);

  if (engine->trigger_lock != NULL)
    ssh_kernel_mutex_free(engine->trigger_lock);

#ifdef SSH_IPSEC_TCPENCAP
  if (engine->tcp_encaps_lock != NULL)
    ssh_kernel_mutex_free(engine->tcp_encaps_lock);
#endif /* SSH_IPSEC_TCPENCAP */

  ssh_free(engine->next_packet_id);

  if (engine->engine_critical_section_initialized)
    ssh_kernel_critical_section_uninit(engine->engine_critical_section);

  if (engine->pc_freelist != NULL)
    ssh_free(engine->pc_freelist);

  if (engine->cpu_ctx != NULL)
    {
      for (i = 0; i < engine->num_cpus; i++)
        ssh_kernel_mutex_uninit(&engine->cpu_ctx[i].pkt_list_lock);

      ssh_kernel_critical_section_uninit(&engine->cpu_ctx_critical_section);

      ssh_free(engine->cpu_ctx);
      engine->cpu_ctx = NULL;
    }

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  SSH_ASSERT(ssh_engine_exists);
  ssh_engine_exists = FALSE;
#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  ssh_free(engine);
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */
}

#ifdef USERMODE_ENGINE
/* This function is used to set the runtime context such that it
   corresponds with  usermode mode execution in a unified-usermode
   AND usermode build. Currently this is used for tuning the
   stack size. */
void
ssh_engine_pme_set_context_usermode(SshEngine engine)
{
#ifdef HAVE_GETRLIMIT
#ifdef HAVE_SETRLIMIT
#ifdef RLIMIT_STACK
#ifdef SSH_ENGINE_TOP_OF_STACK
  struct rlimit rlim_struct;

  if (getrlimit(RLIMIT_STACK, &rlim_struct) == 0)
    {
      rlim_struct.rlim_cur = rlim_struct.rlim_max;
      setrlimit(RLIMIT_STACK, &rlim_struct);
    }
#endif /* SSH_ENGINE_TOP_OF_STACK */
#endif /* RLIMIT_STACK */
#endif /* HAVE_SETRLIMIT */
#endif /* HAVE_GETRLIMIT */
}


/* This function is used to set the runtime context such that it
   corresponds with kernel mode execution in a unified-usermode
   AND usermode build. Currently this is used for tuning the
   stack size. */
void
ssh_engine_pme_set_context_kernel(SshEngine engine)
{
#ifdef HAVE_GETRLIMIT
#ifdef HAVE_SETRLIMIT
#ifdef RLIMIT_STACK
#ifdef SSH_ENGINE_TOP_OF_STACK
  struct rlimit rlim_struct;
  long current_stack;

  /* Set stack to hard limit when entering policy manager */
  if (getrlimit(RLIMIT_STACK, &rlim_struct) == 0)
    {
      current_stack = (long)&current_stack - SSH_ENGINE_TOP_OF_STACK;
      if (current_stack < 0)
        current_stack *= -1;
      current_stack = ((current_stack / 4096) + 1) * 4096;

      /* ssh_debug() and other varargs functions are going to eat up
         a lot of stack approx 3 * 8192 bytes. */
      rlim_struct.rlim_cur = current_stack + (8192 * 3) +
        SSH_ENGINE_ASSUMED_KERNEL_STACK_SIZE;
      setrlimit(RLIMIT_STACK, &rlim_struct);
    }

#endif /* SSH_ENGINE_TOP_OF_STACK */
#endif /* RLIMIT_STACK */
#endif /* HAVE_SETRLIMIT */
#endif /* HAVE_GETRLIMIT */
}
#endif /* USERMODE_ENGINE */
