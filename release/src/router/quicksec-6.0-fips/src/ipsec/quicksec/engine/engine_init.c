/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Initialization and uninitialization functions for the packet
   processing engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */

#define SSH_DEBUG_MODULE "SshEngineInit"

#ifdef DEBUG_LIGHT
/* Perform some sanity checks when the engine is started.  These basically
   check that certain compile-time configuration options are properly set. */
void ssh_engine_sanity_checks(void)
{
  SshUInt16 endianness_test;
  /* Sanity check: make sure WORDS_BIGENDIAN is correctly defined.  Failure
     would not prevent compilation, but could create hard-to-debug errors
     (e.g. in IP checksum computations). */
  ((unsigned char *)&endianness_test)[0] = 0x01;
  ((unsigned char *)&endianness_test)[1] = 0x02;
#ifdef WORDS_BIGENDIAN
  SSH_ASSERT(endianness_test == 0x0102);
#else /* WORDS_BIGENDIAN */
  SSH_ASSERT(endianness_test == 0x0201);
#endif /* WORDS_BIGENDIAN */

#define CHECK_SIZE(TYPE,SIZE)                                   \
  do {                                                          \
    if (sizeof(TYPE) != SIZE)                                   \
      {                                                         \
        ssh_fatal("sizeof(%s) is not %d bytes as expected, "    \
                    "but %d bytes in reality", #TYPE,           \
                    SIZE, sizeof(TYPE));                        \
      }                                                         \
  } while (0)

  {
    CHECK_SIZE(short, SIZEOF_SHORT);
    CHECK_SIZE(int, SIZEOF_INT);
    CHECK_SIZE(long, SIZEOF_LONG);
#ifdef HAVE_LONG_LONG
    CHECK_SIZE(long long, SIZEOF_LONG_LONG);
#endif /* HAVE_LONG_LONG */
  }
#undef CHECK_SIZE

  /* Sanity check to make sure the reserved data in each packet is
     large enough. */
  if (SSH_INTERCEPTOR_UPPER_DATA_SIZE < sizeof(struct SshEnginePacketDataRec))
    ssh_fatal("SSH_INTERCEPTOR_UPPER_DATA_SIZE (%d) insufficient to "
              "accomodate SshEnginePacketData (%d)",
              SSH_INTERCEPTOR_UPPER_DATA_SIZE,
              sizeof(struct SshEnginePacketDataRec));

  if (SSH_ENGINE_REPLAY_WINDOW_WORDS == 0)
    ssh_fatal("Replay window size must be nonzero");
}
#endif /* DEBUG_LIGHT */

/* Creates an engine object.  Among other things, this opens the
   interceptor, initializes filters to default values, and arranges to
   send messages to the policy manager using the send procedure.  The
   send procedure will not be called until from the bottom of the
   event loop.  The `machine_context' argument is passed to the
   interceptor and the `send' callback, but is not used otherwise.
   This function can be called concurrently for different machine
   contexts, but not otherwise.  The first packet and interface
   callbacks may arrive before this has returned. */

SshEngine ssh_engine_start(SshEngineSendProc send,
                           void *machine_context,
                           SshUInt32 flags)
{
  SshEngine engine;
  SshUInt32 i, flow_index;
  SshEngineFlowControl c_flow;
  SshEngineTransformControl c_trd;
  SshEnginePolicyRule rule;

#ifdef DEBUG_LIGHT
  /* Perform some sanity checks on the compilation environment. */
  ssh_engine_sanity_checks();
#endif /* DEBUG_LIGHT */

  /* 1. Allocate the main datastructure, including most sub-structures.
        Allocations that would REQUIRE linking in major parts of the
        non-fastpath engine are done later. */
  engine = ssh_engine_alloc();
  if (engine == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate engine object!"));
      return NULL;
    }

  /* 2. Initialize parts common to the engine and the fastpath. */
  if (!ssh_engine_init_common(engine))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize common engine/fastpath!"));
      goto fail;
    }

  /* 3. Create the interceptor */
  if (!ssh_interceptor_create(machine_context, &engine->interceptor))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create the interceptor"));
      goto fail;
    }
  SSH_ASSERT(engine->interceptor != NULL);

  /* 4. Initialize the fastpath */
  if (fastpath_init(engine,
                    engine->interceptor,
                    engine_rule_packet_handler,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                    NULL_FNPTR,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                    engine_address_resolution,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                    &engine->flow_id_hash,
                    &engine->fastpath) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize fastpath!"));
      goto fail;
    }
  SSH_ASSERT(engine->flow_id_hash != NULL_FNPTR);

  /* Do the allocations that we can not place into ssh_engine_alloc(). */
  engine->policy_rule_set = ssh_engine_rule_lookup_allocate(engine);
  if (engine->policy_rule_set == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("initialization of rule lookup failed"));
      goto fail;
    }

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  engine->ipm_open = TRUE;
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  engine->ipm_open = FALSE;
  engine->policy_lookups_disabled = FALSE;
  engine->send = send;
  engine->machine_context = machine_context;
  /* The policy manager connection is actually our engine object. */
  engine->pm = engine;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  engine->flags = flags;

  engine->num_ike_ports = 1;
  engine->local_ike_ports[0] = SSH_IPSEC_IKE_PORT;
  engine->local_ike_natt_ports[0] = SSH_IPSEC_IKE_NATT_PORT;
  engine->remote_ike_ports[0] = SSH_IPSEC_IKE_PORT;
  engine->remote_ike_natt_ports[0] = SSH_IPSEC_IKE_NATT_PORT;

  engine->audit_timeout_scheduled = 0;
  for (i = 0; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    engine->audit_current_rate[i] = 0;

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.flow_table_size = SSH_ENGINE_FLOW_TABLE_SIZE;
  engine->stats.transform_table_size = SSH_ENGINE_TRANSFORM_TABLE_SIZE;
  engine->stats.rule_table_size = SSH_ENGINE_MAX_RULES;
  engine->stats.next_hop_table_size = SSH_ENGINE_NEXT_HOP_HASH_SIZE;

  engine->stats.policy_rule_struct_size = sizeof(SshEnginePolicyRuleStruct);
  engine->stats.transform_data_struct_size
    = sizeof(SshEngineTransformDataStruct);
  engine->stats.flow_struct_size = sizeof(SshEngineFlowStruct);
#endif /* SSH_IPSEC_STATISTICS */

  /* Initialize engine->run_time */
  ssh_interceptor_get_time(&engine->run_time, NULL);
  engine->run_time_usec = 0;
  engine->age_callback_next = 0;

#ifdef SSH_IPSEC_SMALL
  /* In SSH_IPSEC_SMALL configurations there is no periodic engine age
     timeout. The age timeout is scheduled by engine to next transform
     event (soft or hard) and by the fastpath whenever a packet is processed.
     The whole flow table is examined in a single call to engine age timeout
     and there is no rate limiting for transform events sent to policy manager.
  */
  engine->age_full_seconds = 1;
  engine->age_callback_interval = 1000000L;
  engine->age_callback_flows = SSH_ENGINE_FLOW_TABLE_SIZE;
  engine->age_timeout_repetitive = 0;
  engine->age_callback_trd_events = 0;
#else /* SSH_IPSEC_SMALL */

  /* Initialize data for timeouts.  We try to keep the number of flows
     examined per callback reasonable, but at at the same time try to
     keep the frequency of timeouts low in small configurations. */

  /* Set age_full seconds according to flow table size. This determines
     how often a flow gets an event. See ipsec_params.h for how this
     depends on the flow table size. */
  engine->age_full_seconds = SSH_ENGINE_AGE_FULL_SECONDS;

  /* Calculate age_callback_flows. This determines how may flows are
     processed in a single age timeout call. This also limits the
     maximum rate at which events are sent to the policymanager. */
  engine->age_callback_flows =
    (SSH_ENGINE_FLOW_TABLE_SIZE) / engine->age_full_seconds;

  /* Set the maximum rate at which transform events can be sent to policy
     manager. Note that rate limiting may increase the age_full_seconds,
     as the age timeout call is able to process less than age_callback_flows
     when rate limiting hits. If this is 0 then the transform events are not
     rate limited. */
  engine->age_callback_trd_events = SSH_ENGINE_AGE_TRANSFORM_EVENT_RATE;

  /* Use repetitive timer. */
  engine->age_callback_interval = 1000000L;
  engine->age_timeout_repetitive = 1;

  /* If necessary, divide age_callback_flows into smaller chunks and adjust
     age_callback_interval and age_callback_trd_events accordingly. This
     code is here for configurations with insanely large flow tables. */
  if (engine->age_callback_flows >= 2000)
    {
      engine->age_callback_flows /= 4;
      engine->age_callback_interval /= 4;
      engine->age_callback_trd_events /= 4;
    }
#endif /* SSH_IPSEC_SMALL */

  SSH_DEBUG(SSH_D_LOWOK,
            ("Engine age timeout parameters: age_full_seconds %d "
             "age_callback_flows %d age_callback_interval %ld "
             "age_callback_trd_events %d",
             (int) engine->age_full_seconds,
             (int) engine->age_callback_flows,
             (long) engine->age_callback_interval,
             (int) engine->age_callback_trd_events));

  /* Initialize flow table freelist. */
  engine->flow_table_freelist = SSH_IPSEC_INVALID_INDEX;
  engine->flows_dangling_list = SSH_IPSEC_INVALID_INDEX;
  engine->flow_table_freelist_last = SSH_IPSEC_INVALID_INDEX;

  /* Initialize transform data freelist. */
  engine->transform_table_freelist = SSH_IPSEC_INVALID_INDEX;
  engine->transform_table_freelist_tail = SSH_IPSEC_INVALID_INDEX;

  /* Fill in transform data freelist. */
  for (i = 0; i < engine->transform_table_size; i++)
    {
      c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, i);
      /* For sanity checks in TRD index wrapping. */
      c_trd->generation = 1;
      c_trd->refcnt = 0;
      c_trd->rules = engine->transform_table_freelist;
      engine->transform_table_freelist = i;
      if (engine->transform_table_freelist_tail == SSH_IPSEC_INVALID_INDEX)
        engine->transform_table_freelist_tail = i;
    }

#ifdef DEBUG_LIGHT
  /* Mark all flows as not being in the freelist using magic flag value. */
  for (i = 0; i < engine->flow_table_size; i++)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, i);
      c_flow->control_flags = 0xf0f0;
    }
#endif /* DEBUG_LIGHT */

  /* Fill in flow data freelist. Add the flows to freelist in such order
     that flows allocated from freelist scatter equally around the flow table.
     This ensures when that system starts up the active flows are not packed
     in to the beginning of the flow table, and that transform events are not
     generated in bursts by engine_age_timeout(). Note that this code here
     mostly affects system state just after initialization. When the system
     runs for a while the order of the flows in the freelist will eventually
     become random. */
  engine->flow_table_freelist = 0;
  engine->num_free_flows = engine->flow_table_size;
  for (i = 0; i < engine->age_full_seconds; i++)
    {
      for (flow_index = i;
           flow_index < engine->flow_table_size;
           flow_index += engine->age_full_seconds)
        {
          /* Initialize control side flow */
          c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
          SSH_ASSERT(c_flow->control_flags == 0xf0f0);
          c_flow->control_flags = 0;

          if ((flow_index + engine->age_full_seconds)
              < engine->flow_table_size)
            {
              c_flow->control_next = flow_index + engine->age_full_seconds;
            }
          else
            {
              if ((i + 1) < engine->age_full_seconds)
                {
                  c_flow->control_next = (i + 1);
                }
              else
                {
                  engine->flow_table_freelist_last = flow_index;
                  c_flow->control_next = SSH_IPSEC_INVALID_INDEX;
                }
            }
        }
    }

#ifdef DEBUG_LIGHT
  /* Check that all of the flows were inserted in to the freelist
     (i.e. magic flag value was cleared). */
  c_flow = SSH_ENGINE_GET_FLOW(engine, 0);
  SSH_ASSERT(c_flow != NULL);
  i = 1;
  while (c_flow->control_next != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_ASSERT(c_flow->control_flags == 0);
      c_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->control_next);
      SSH_ASSERT(i < engine->flow_table_size);
      i++;
    }
  SSH_ASSERT(i == engine->flow_table_size);
#endif /* DEBUG_LIGHT */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Initialize next hop hash freelist. */
  engine->next_hop_hash_freelist = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (i = 0; i < engine->next_hop_hash_size; i++)
    {
      SshEngineNextHopControl c_nh;

      c_nh = SSH_ENGINE_GET_NH(engine, i);
      c_nh->refcnt = 0;
      c_nh->next = engine->next_hop_hash_freelist;
      c_nh->ifnum_hash_next = SSH_IPSEC_INVALID_INDEX;
      engine->next_hop_hash_freelist = i;

      engine->next_hop_addr_hash[i] = SSH_IPSEC_INVALID_INDEX;
    }
  for (i = 0; i < SSH_ENGINE_NH_C_IFNUM_HASH_SIZE; i++)
    {
      engine->next_hop_ifnum_hash[i] = SSH_IPSEC_INVALID_INDEX;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Initialize transform destroy notify list. */
  engine->transform_destroy_notify_list = SSH_IPSEC_INVALID_INDEX;
  engine->transform_destroy_notify_list_tail = SSH_IPSEC_INVALID_INDEX;

  /* Initialize peer hash. */
  for (i = 0; i < SSH_ENGINE_PEER_HASH_SIZE; i++)
    engine->peer_hash[i] = SSH_IPSEC_INVALID_INDEX;

  /* Initialize IKE SA hash. */
  for (i = 0; i < SSH_ENGINE_PEER_HANDLE_HASH_SIZE; i++)
    engine->peer_handle_hash[i] = SSH_IPSEC_INVALID_INDEX;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Initialize NAT-T keepalive list. */
  engine->natt_keepalive = SSH_IPSEC_INVALID_INDEX;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Initialize the rule freelist. */
  engine->rule_table_freelist = SSH_IPSEC_INVALID_INDEX;

  /* Engine default rules. */

  /* Default no-flow pass rule. */
  engine->pass_rule = SSH_ENGINE_GET_RULE(engine, 0);
  SSH_ENGINE_RULE_INIT(engine->pass_rule);
  engine->pass_rule->rule_index = 0;
  engine->pass_rule->type = SSH_ENGINE_RULE_PASS;
  engine->pass_rule->flags = SSH_ENGINE_NO_FLOW;
  engine->pass_rule->refcnt = 1;
  engine->pass_rule->flow_idle_datagram_timeout = 30;
  engine->pass_rule->flow_idle_session_timeout = 3600;

  /* Default drop rule. */
  engine->drop_rule = SSH_ENGINE_GET_RULE(engine, 1);
  SSH_ENGINE_RULE_INIT(engine->drop_rule);
  engine->drop_rule->rule_index = 1;
  engine->drop_rule->type = SSH_ENGINE_RULE_DROP;
  engine->drop_rule->flags = SSH_ENGINE_NO_FLOW;
  engine->drop_rule->refcnt = 1;
  engine->drop_rule->flow_idle_datagram_timeout = 30;
  engine->drop_rule->flow_idle_session_timeout = 3600;

  /* Default rule for IPv4 DHCP packets. This rule creates
     flows and any packets matching this rule are passed through
     the Engine unmodified. */
  engine->dhcp_ipv4_out_rule = SSH_ENGINE_GET_RULE(engine, 2);
  SSH_ENGINE_RULE_INIT(engine->dhcp_ipv4_out_rule);
  engine->dhcp_ipv4_out_rule->rule_index = 2;
  engine->dhcp_ipv4_out_rule->type = SSH_ENGINE_RULE_PASS;
  engine->dhcp_ipv4_out_rule->flags = SSH_ENGINE_RULE_PASS_UNMODIFIED
    | SSH_ENGINE_NO_FLOW;
  engine->dhcp_ipv4_out_rule->refcnt = 1;
  engine->dhcp_ipv4_out_rule->flow_idle_datagram_timeout = 15;
  engine->dhcp_ipv4_out_rule->flow_idle_session_timeout = 30;
  engine->dhcp_ipv4_out_rule->ipproto = SSH_IPPROTO_UDP;
  engine->dhcp_ipv4_out_rule->protocol = SSH_PROTOCOL_IP4;
  engine->dhcp_ipv4_out_rule->selectors =
    (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT |
     SSH_SELECTOR_FROMLOCAL);
  engine->dhcp_ipv4_out_rule->dst_port_low = 67;
  engine->dhcp_ipv4_out_rule->dst_port_high = 67;

  /* Default rule for IPv4 DHCP packets. This rule creates
     flows and any packets matching this rule are passed through
     the Engine unmodified. */
  engine->dhcp_ipv4_in_rule = SSH_ENGINE_GET_RULE(engine, 3);
  SSH_ENGINE_RULE_INIT(engine->dhcp_ipv4_in_rule);
  engine->dhcp_ipv4_in_rule->rule_index = 3;
  engine->dhcp_ipv4_in_rule->type = SSH_ENGINE_RULE_PASS;
  engine->dhcp_ipv4_in_rule->flags = SSH_ENGINE_RULE_PASS_UNMODIFIED
    | SSH_ENGINE_NO_FLOW;
  engine->dhcp_ipv4_in_rule->refcnt = 1;
  engine->dhcp_ipv4_in_rule->flow_idle_datagram_timeout = 15;
  engine->dhcp_ipv4_in_rule->flow_idle_session_timeout = 30;
  engine->dhcp_ipv4_in_rule->ipproto = SSH_IPPROTO_UDP;
  engine->dhcp_ipv4_in_rule->protocol = SSH_PROTOCOL_IP4;
  engine->dhcp_ipv4_in_rule->selectors =
    (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
     SSH_SELECTOR_TOLOCAL);
  engine->dhcp_ipv4_in_rule->src_port_low = 67;
  engine->dhcp_ipv4_in_rule->src_port_high = 67;

  /* Default rule for IPv6 DHCP packets. This rule creates
     flows and any packets matching this rule are passed through
     the Engine unmodified. */
  engine->dhcp_ipv6_out_rule = SSH_ENGINE_GET_RULE(engine, 4);
  SSH_ENGINE_RULE_INIT(engine->dhcp_ipv6_out_rule);
  engine->dhcp_ipv6_out_rule->rule_index = 4;
  engine->dhcp_ipv6_out_rule->type = SSH_ENGINE_RULE_PASS;
  engine->dhcp_ipv6_out_rule->flags = SSH_ENGINE_RULE_PASS_UNMODIFIED |
    SSH_ENGINE_NO_FLOW;
  engine->dhcp_ipv6_out_rule->refcnt = 1;
  engine->dhcp_ipv6_out_rule->flow_idle_datagram_timeout = 30;
  engine->dhcp_ipv6_out_rule->flow_idle_session_timeout = 3600;
  engine->dhcp_ipv6_out_rule->ipproto = SSH_IPPROTO_UDP;
  engine->dhcp_ipv6_out_rule->protocol = SSH_PROTOCOL_IP6;
  engine->dhcp_ipv6_out_rule->selectors =
    (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL);
  engine->dhcp_ipv6_out_rule->dst_port_low = 547;
  engine->dhcp_ipv6_out_rule->dst_port_high = 547;

  /* Default rule for IPv6 DHCP packets. This rule creates
     flows and any packets matching this rule are passed through
     the Engine unmodified. */
  engine->dhcp_ipv6_in_rule = SSH_ENGINE_GET_RULE(engine, 5);
  SSH_ENGINE_RULE_INIT(engine->dhcp_ipv6_in_rule);
  engine->dhcp_ipv6_in_rule->rule_index = 5;
  engine->dhcp_ipv6_in_rule->type = SSH_ENGINE_RULE_PASS;
  engine->dhcp_ipv6_in_rule->flags = SSH_ENGINE_RULE_PASS_UNMODIFIED |
    SSH_ENGINE_NO_FLOW;
  engine->dhcp_ipv6_in_rule->refcnt = 1;
  engine->dhcp_ipv6_in_rule->flow_idle_datagram_timeout = 30;
  engine->dhcp_ipv6_in_rule->flow_idle_session_timeout = 3600;
  engine->dhcp_ipv6_in_rule->ipproto = SSH_IPPROTO_UDP;
  engine->dhcp_ipv6_in_rule->protocol = SSH_PROTOCOL_IP6;
  engine->dhcp_ipv6_in_rule->selectors =
    (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT | SSH_SELECTOR_TOLOCAL);
  engine->dhcp_ipv6_in_rule->src_port_low = 547;
  engine->dhcp_ipv6_in_rule->src_port_high = 547;

  for (i = SSH_ENGINE_NUM_DEFAULT_RULES; i < engine->rule_table_size; i++)
    {
      rule = SSH_ENGINE_GET_RULE(engine, i);
      rule->rule_index = i;
      rule->type = SSH_ENGINE_RULE_NONEXISTENT;
      rule->refcnt = 0;
      rule->transform_index = engine->rule_table_freelist;
      engine->rule_table_freelist = i;
    }

#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* Clear the routing table. */
  for (i = 0; i < SSH_ENGINE_ROUTE_TABLE_SIZE; i++)
    engine->route_table[i].flags = 0;
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

#ifdef SSHDIST_IPSEC_NAT
 /* Initialize port NAT table. */
  engine->nat_port_freelist = NULL;
  for (i = 0; i < SSH_ENGINE_FLOW_NAT_TABLE_SIZE; i++)
    {
      SshEngineNatPort port = SSH_ENGINE_GET_NAT_PORT(engine, i);

      port->next = engine->nat_port_freelist;
      engine->nat_port_freelist = port;
    }

  for (i = 0; i < SSH_ENGINE_FLOW_NAT_HASH_SIZE; i++)
    engine->nat_ports_hash[i] = NULL;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSH_IPSEC_TCPENCAP
  ssh_kernel_mutex_lock(engine->tcp_encaps_lock);
  for (i = 0; i < SSH_ENGINE_TCP_ENCAPS_CONN_HASH_SIZE; i++)
    engine->tcp_encaps_connection_table[i] = NULL;
  engine->tcp_encaps_configuration_table = NULL;
  ssh_kernel_mutex_unlock(engine->tcp_encaps_lock);
#endif /* SSH_IPSEC_TCPENCAP */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Initialize the ARP cache (which also handles IPv6 Neighbor Discovery). */
  ssh_engine_arp_init(engine, 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Initialize engine trigger timeouts and bitmask.
     Ignore return value for now. */
  ssh_engine_trigger_init(engine);

#ifdef SSH_ENGINE_PRNG
  ssh_engine_random_init(engine);
#endif /* SSH_ENGINE_PRNG */




  ssh_engine_pmtu_init();
  engine_rule_packet_handler_init();

  /* Set default values for engine params */
  ssh_engine_pme_set_engine_params(engine, NULL);

  /* Open the interceptor. */
  if (!ssh_interceptor_open(engine->interceptor,
                            NULL_FNPTR,
                            ssh_engine_interfaces_callback,
                            ssh_engine_route_change_callback,
                            (void *)engine))
    {
      SSH_DEBUG(SSH_D_ERROR, ("opening the interceptor failed"));
      goto fail;
    }

  if (engine->age_callback_interval)
    /* Register the age timeout. */
    ssh_kernel_timeout_register(0L, engine->age_callback_interval,
                                ssh_engine_age_timeout, (void *)engine);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Register the NAT-T keepalive timeout. */
  engine->natt_keepalive_interval = SSH_IPSEC_NATT_KEEPALIVE_INTERVAL;
  if (engine->natt_keepalive_interval > 0)
    ssh_kernel_timeout_register(engine->natt_keepalive_interval, 0,
                                ssh_engine_natt_keepalive_timeout, engine);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.age_callback_flows = engine->age_callback_flows;
  engine->stats.age_callback_interval = engine->age_callback_interval;
#endif /* SSH_IPSEC_STATISTICS */

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Attach virtual adapters to engine. */
  ssh_virtual_adapter_init(engine->interceptor);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  SSH_DEBUG(SSH_D_HIGHOK, ("packet processing engine initialized"));
  return engine;

 fail:
  /* Something went wrong.  Uninitialize and return failure. */

  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS, (void *)engine);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_engine_arp_uninit(engine);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_engine_trigger_uninit(engine);

  if (engine->policy_rule_set)
    ssh_engine_rule_lookup_dispose(engine, engine->policy_rule_set);

  if (engine->interceptor)
    ssh_interceptor_close(engine->interceptor);

  if (engine != NULL)
    {
      if (engine->interceptor)
        ssh_interceptor_close(engine->interceptor);
      if (engine->fastpath)
        fastpath_uninit(engine->fastpath);
      ssh_engine_free(engine);
    }

  SSH_DEBUG(SSH_D_ERROR, ("engine initialization returning failure"));

  return NULL;
}

Boolean ssh_engine_suspend(SshEngine engine)
{
  /* Suspend fastpath. */
  fastpath_suspend(engine->fastpath);

  /* Nothing more to do. */
  return TRUE;
}


Boolean ssh_engine_resume(SshEngine engine)
{
  /* Resume fastpath. */
  fastpath_resume(engine->fastpath);

  /* Nothing more to do. */
  return TRUE;
}

static SshUInt32
engine_pc_freelist_pending_count(SshEngine engine)
{
  SshEnginePacketContext pc;
  int i;
  SshUInt32 pending_cnt = 0;

  for (i = 0; i < SSH_ENGINE_MAX_PACKET_CONTEXTS; i++)
    {
      pc = SSH_ENGINE_GET_PC(engine, i);
      if (!pc->on_freelist)
        pending_cnt++;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("%u packet contexts pending.", pending_cnt));

  return pending_cnt;
}



























/* Stops the engine, closes the interceptor, and destroys the
   engine object.  This does not notify IPM interface of the close;
   that must be done by the caller before calling this.  This returns
   TRUE if the engine was successfully stopped (and the object freed),
   and FALSE if the engine cannot yet be freed because there are
   threads inside the engine or uncancellable callbacks expected to
   arrive.  When this returns FALSE, the engine has started stopping,
   and this should be called again after a while.  This function can
   be called concurrently with packet/interface callbacks or timeouts
   for this engine, or any functions for other engines.*/

Boolean ssh_engine_stop(SshEngine engine)
{
  SshUInt32 pending_pcs = 0;
  static SshUInt32 stop_retry_count = 60;

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE



  engine->ipm_open = FALSE;
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_uninit(engine->interceptor);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */





  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine->policy_lookups_disabled = TRUE;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* In first phase we try to stop and flush all we can without freeing
     any crucial resources. The retry count is hard coded above. We may
     have pending packets, for one reason or another and hence interceptor
     may need to retry multiple times. We force the unload once
     stop_retry_count is exceeded. This may happen in few occasions, e.g.
     a packet that is flushed is retried to be sent and is once again stuck
     in ARP or frag cache or similar... */

  /* Stop the interceptor.  This means that no more new callbacks will
     arrive. */
  if (!ssh_interceptor_stop(engine->interceptor))
    return FALSE;

  /* Stop the fastpath. This means that all packets have been completed. */
  if (!fastpath_stop(engine->fastpath))
    return FALSE;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Uninit ARP cache. */
  ssh_engine_arp_uninit(engine);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Uninit engine trigger timeouts and bitmask. */
  ssh_engine_trigger_uninit(engine);

  ssh_engine_audit_uninit(engine);

  pending_pcs = engine_pc_freelist_pending_count(engine);
  if (pending_pcs > 0 && stop_retry_count-- > 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Packet contexts pending %u, stop retry count %u",
                 pending_pcs, stop_retry_count));

      return FALSE;
    }

  /* Second phase, start really cleaning up. Freeing resources, no matter
     the first phase failed (see stop_retry_count usage above). */

  /* Cancel any timeouts. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS, (void *)engine);
  engine->audit_timeout_scheduled = 0;

#ifdef SSH_ENGINE_PRNG
  ssh_engine_random_uninit(engine);
#endif /* SSH_ENGINE_PRNG */

  ssh_engine_rule_lookup_dispose(engine, engine->policy_rule_set);

  ssh_engine_interfaces_clear(engine);

  ssh_interceptor_close(engine->interceptor);

#ifdef SSH_IPSEC_TCPENCAP
  ssh_engine_tcp_encaps_destroy(engine);
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  if (engine->num_pending_upcall_timeouts > 0)
    {
      /* The engine has pending policy manager upcall timeouts.  We
         must delay the freeing of engine until the timeouts have been
         called.  But we mark the engine stopped so the timeout
         functions will not call policy manager functions. */
      engine->stopped = TRUE;
      return TRUE;
    }
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */






  /* Free the engine now. */
  ssh_engine_stop_now(engine);
  return TRUE;
}

/* Frees the engine structure `engine'.  This must be called when the
   engine is stopped and it has no threads active.  This is the final
   free operation for the engine strucuture.  All fields of the engine
   structure must have been freed before this function is called. */

void ssh_engine_stop_now(SshEngine engine)
{
  if (engine->fastpath != NULL)
    fastpath_uninit(engine->fastpath);

  ssh_engine_free(engine);

}

void
ssh_engine_pme_set_engine_params(SshEngine engine,
                                 const SshEngineParams pm_params)
{
  SshEngineParamsStruct def_params = ENGINE_DEFAULT_PARAMETERS;
  SshEngineParams params;
  SshUInt32 pc_flags;

  if (pm_params == NULL)
    {
      params = &def_params;
      SSH_DEBUG(SSH_D_MIDSTART,
                ("pm_params = NULL, setting default engine parameters"));
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART,
                ("setting user configured engine parameters"));
      params = pm_params;
    }

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  engine->natt_keepalive_interval = params->natt_keepalive_interval;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  engine->min_ttl_value = params->min_ttl_value;

  pc_flags = 0;
  pc_flags |= (params->do_not_decrement_ttl
               ? 0
               : SSH_ENGINE_PC_DECREMENT_TTL);
  pc_flags |= (params->audit_corrupt
               ? SSH_ENGINE_PC_AUDIT_CORRUPT
               : 0);
  pc_flags |= (params->drop_if_cannot_audit
               ? SSH_ENGINE_PC_ENFORCE_AUDIT
               : 0);

  engine->pc_flags = pc_flags;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("initial packet context flags=0x%08x",
                               (unsigned int) engine->pc_flags));

  engine->optimize_routing = (params->optimize_routing ? 1 : 0);

  engine->broadcast_icmp = (params->broadcast_icmp ? 1 : 0);

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  engine->flow_rate_allow_threshold = params->flow_rate_allow_threshold;
  engine->flow_rate_limit_threshold = params->flow_rate_limit_threshold;
  engine->flow_rate_max_share = params->flow_rate_max_share;
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  engine->audit_total_rate_limit = params->audit_total_rate_limit;
  engine->transform_dpd_timeout = params->transform_dpd_timeout;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  ssh_kernel_timeout_cancel(ssh_engine_natt_keepalive_timeout, engine);
  if (params->natt_keepalive_interval > 0)
    ssh_kernel_timeout_register(params->natt_keepalive_interval, 0,
                                ssh_engine_natt_keepalive_timeout, engine);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  fastpath_set_params(engine->fastpath, params);
}

/* Generate a IP identification used when constructing IPv4 headers.
   IP ID is incremented from it's previous value on the same CPU. */
SshUInt16 ssh_engine_get_ip_id(SshEngine engine)
{
  unsigned int cpu;
  SshUInt16 ip_id;

  ssh_kernel_critical_section_start(engine->engine_critical_section);
  cpu = ssh_kernel_get_cpu();

  SSH_ASSERT(cpu < engine->num_cpus);

 again:
  ip_id = engine->next_packet_id[cpu];

  /* Check if packet id is the last value of the CPUs ID range. */
  if (engine->next_packet_id[cpu] >=
      (cpu + 1) * ((FASTPATH_ENGINE_IP_ID_MAX - FASTPATH_ENGINE_IP_ID_MIN + 1)
                   / engine->num_cpus) + FASTPATH_ENGINE_IP_ID_MIN - 1)
    engine->next_packet_id[cpu] =
      (cpu * ((FASTPATH_ENGINE_IP_ID_MAX - FASTPATH_ENGINE_IP_ID_MIN + 1)
              / engine->num_cpus) + FASTPATH_ENGINE_IP_ID_MIN);
  else
    engine->next_packet_id[cpu]++;

  if (ip_id == 0)
    goto again;

  ssh_kernel_critical_section_end(engine->engine_critical_section);
  return ip_id;
}


/* Initialize the const globals */
const char ssh_engine_version[] = SSH_IPSEC_VERSION_STRING_SHORT;
const char ssh_engine_compile_version[] = (
                                           SSH_IPSEC_VERSION
                                           " compiled "
                                           __DATE__ " " __TIME__
                                           );

/* Suffix to add to the name of the device name used for communicating with
   the kernel module in systems that have such a concept.  This is ignored
   on other systems.

   Keep this definition the last thing in this file because of the
   potential #pragma stuff so we affect only this one symbol. */

#if defined(__GNUC__)
const char ssh_device_suffix[] __attribute__ ((weak)) = "";
#elif defined(__SUNPRO_C)
#pragma weak ssh_device_suffix
const char ssh_device_suffix[] = "";
#else
const char ssh_device_suffix[] = "";
#endif
