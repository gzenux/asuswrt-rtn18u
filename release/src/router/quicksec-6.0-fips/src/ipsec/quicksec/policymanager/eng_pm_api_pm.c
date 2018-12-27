/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager side implementation of the engine-policy manager API.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#ifdef USERMODE_ENGINE
#include "usermodeinterceptor.h"
#endif /* USERMODE_ENGINE */
#include "sshdevicestream.h"

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

#include "engine_internal.h"
#include "engine_fastpath.h"

#define SSH_DEBUG_MODULE "SshEnginePmApiPm"

/* Tries to open the connection to the engine.  If successful, then
   this calls `callback' with TRUE; otherwise this calls the callback
   with FALSE.

   The `machine_context' argument specifies which engine to connect
   (e.g., "/dev/sshengine", "/proc/sshipsec/sshengine" or
   "/tmp/sshengine").  For Unix, it is the pathname of the device or
   socket used to communicate with the engine.  For other platforms it
   can be anything defined by the platform; its semantics are
   completely platform-specific.  This function sets pm->engine if
   successful.  `flags' is flags to the engine (as defined for
   ssh_engine_start in engine.h). */

void
ssh_pm_connect_engine(SshPm pm, void *machine_context, SshUInt32 flags,
                      SshUInt16 nat_port_range_low,
                      SshUInt16 nat_port_range_high,
                      SshUInt16 nat_privileged_port_range_low,
                      SshUInt16 nat_privileged_port_range_high,
                      SshUInt16 num_ike_ports,
                      SshUInt16 *local_ike_ports,
                      SshUInt16 *local_ike_natt_ports,
                      SshUInt16 *remote_ike_ports,
                      SshUInt16 *remote_ike_natt_ports,
                      SshPmeStatusCB callback, void *context)
{
#ifdef USERMODE_ENGINE
  /* Usermode interceptor init. */
  if (!ssh_interceptor_init(machine_context))
    {
      (*callback)(pm, FALSE, context);
      return;
    }
#endif /* USERMODE_ENGINE */

  /* Start the engine. */
  pm->engine = ssh_engine_start((SshEngineSendProc)0x88888888,
                                machine_context, flags);
  if (!pm->engine)
    {
      (*callback)(pm, FALSE, context);
      return;
    }
  /* Save back-pointer to policy manager. */
  pm->engine->pm = pm;

#ifdef SSHDIST_IPSEC_NAT
  /* Copy NAT port range into the engine. */
  pm->engine->nat_normal_low_port = nat_port_range_low;
  pm->engine->nat_normal_high_port = nat_port_range_high;
  pm->engine->nat_privileged_low_port =
    nat_privileged_port_range_low;
  pm->engine->nat_privileged_high_port =
    nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */

  pm->engine->num_ike_ports = num_ike_ports;
  *pm->engine->local_ike_ports = *local_ike_ports;
  *pm->engine->local_ike_natt_ports = *local_ike_natt_ports;
  *pm->engine->remote_ike_ports = *remote_ike_ports;
  *pm->engine->remote_ike_natt_ports = *remote_ike_natt_ports;

  /* Call the callback to indicate success. */
  (*callback)(pm, TRUE, context);
}

static void
ssh_pm_disconnect_retry(void *context)
{
  SshPm pm = (SshPm) context;
  SshEngine engine = pm->engine;

  SSH_DEBUG(SSH_D_HIGHOK, ("retrying engine destroy from timeout"));
  if (!ssh_engine_stop(engine))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("scheduling retry of engine destroy"));
      ssh_register_timeout(NULL, 0L, 100000L,
                           ssh_pm_disconnect_retry, (void *) pm);
    }
  else
    {
#ifdef USERMODE_ENGINE
      ssh_interceptor_uninit();
#endif /* USERMODE_ENGINE */

      /* Invalidate pm->engine. */
      pm->engine = NULL;
      SSH_DEBUG(SSH_D_HIGHOK, ("engine destroyed in timeout"));
      (*pm->batch.status_cb)(pm, TRUE, pm->batch.status_cb_context);
    }
}

/* Closes the connection to the engine.  This starts closing the engine,
   and invalidates pm->engine.  The engine data structures may get actually
   freed either during this call or shortly thereafter. */

void ssh_pm_disconnect_engine(SshPm pm,
                              SshPmeStatusCB callback, void *context)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("destroying engine"));

  /* Use batch status callback for shutdown notifier. */
  pm->batch.status_cb = callback;
  pm->batch.status_cb_context = context;

  if (pm->connected)
    {
      ssh_pm_disconnect_retry((void *) pm);
      pm->connected = 0;
    }
  else
    {
      (*callback)(pm, TRUE, context);
      return;
    }
}

void
ssh_pm_salt_to_engine(SshPm pm, SshUInt32 salt[4])
{
  /* Copy salt directly to engine data structures. */
  memcpy(pm->engine->flow_id_salt, (unsigned char *)salt,
         sizeof(pm->engine->flow_id_salt));

#ifdef SSH_ENGINE_PRNG
        ssh_engine_random_add_entropy(pm->engine,
                                      (unsigned char *)
                                      pm->engine->flow_id_salt,
                                      sizeof(pm->engine->flow_id_salt));
        ssh_engine_random_stir(pm->engine);
#endif /* SSH_ENGINE_PRNG */
}



/* The ssh_pme_* functions are implemented directly in the engine. */

#else /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#include "engine_pm_api_marshal.h"
#include "sshencode.h"
#include "sshpacketstream.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshEnginePmApiPm"

/* A message to engine. */
struct SshEngineMessageRec
{
  /* Link field used for freelist and list of pending packets.  The
     value SSH_IPSEC_INVALID_INDEX is the null-value for the lists. */
  SshUInt32 next;

  /* Flags. */
  unsigned int async : 1;       /* An asynchronous operation. */
  unsigned int born_async : 1;  /* Origin of the message */
  unsigned int dynamic : 1;     /* Dynamic message data. */

  /* The type of the message. */
  SshPacketType type;

  /* The length of the message payload. */
  size_t data_len;

  /* The pre-formatted message to send. */
  union
  {
    unsigned char *dynamic_data;
    unsigned char static_data[256]; /* Current max message len is 132 bytes. */
  } data;

  /* Completion callbacks and context data for asynchronous
     operations. */
  union
  {
    SshPmeStatusCB status_cb;
    SshPmeIndexCB index_cb;
    SshPmeAddRuleCB add_rule_cb;
    SshPmeSAIndexCB sa_index_cb;
    SshPmeRuleCB rule_cb;
    SshPmeTransformCB transform_cb;
    SshPmeGlobalStatsCB global_stats_cb;
    SshPmeFlowInfoCB flow_info_cb;
    SshPmeFlowStatsCB flow_stats_cb;
    SshPmeRuleStatsCB rule_stats_cb;
    SshPmeTransformStatsCB transform_stats_cb;
    SshPmeDeleteCB delete_cb;
    SshPmeDeleteTransformCB delete_transform_cb;
    SshPmeRouteCB route_cb;
    SshPmeRouteSuccessCB route_success_cb;
    SshPmeAuditCB audit_cb;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
    SshPmeVirtualAdapterStatusCB virtual_adapter_status_cb;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */



  } cb;
  void *cb_context;
};

typedef struct SshEngineMessageRec SshEngineMessageStruct;
typedef struct SshEngineMessageRec *SshEngineMessage;

/* An engine object, as known by the policy manager.  This is just a
   stub passing and receiving messages between policy manager and
   engine. */
struct SshEngineRec
{
  /* The policy manager object. */
  SshPm pm;

#ifdef SSHDIST_IPSEC_NAT
  /* NAT port ranges. */
  SshUInt16 nat_port_range_low;
  SshUInt16 nat_port_range_high;
  SshUInt16 nat_privileged_port_range_low;
  SshUInt16 nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */

  /* Memory shared with pm object, not allocated for the engine. */
  SshUInt16 num_ike_ports;
  SshUInt16 local_ike_ports[32];
  SshUInt16 local_ike_natt_ports[32];
  SshUInt16 remote_ike_ports[32];
  SshUInt16 remote_ike_natt_ports[32];

  /* The packet wrapper connection to the engine. */
  SshPacketWrapper packet_wrapper;

  /* The message array. */
  SshEngineMessage messages;

  /* The head of the message freelist. */
  SshUInt32 sync_freelist;
  SshUInt32 async_freelist;


  /* List of pending packets to the engine. */
  SshUInt32 pending_head;
  SshUInt32 pending_tail;

  /* Completion callback for the connect operation. */
  SshPmeStatusCB connect_status_cb;
  void *connect_status_cb_context;
};

/*************************** Pre-allocated tables ***************************/

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
SshEngineMessageStruct ssh_pm_messages[SSH_PM_MAX_PENDING_ENGINE_OPERATIONS];
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

/******************** Receiving messages from the engine ********************/


SshEngineMessage
ssh_pm_alloc_message(SshEngine engine, SshEnginePmApiCallType type,
                     Boolean async, Boolean dynamic)
{
  SshEngineMessage message;
  SshUInt32 index;

  if (async == FALSE)
    {
      if ((index = engine->sync_freelist) != SSH_IPSEC_INVALID_INDEX)
        {
          message = &engine->messages[index];
          engine->sync_freelist = message->next;
        }
      else if ((index = engine->async_freelist) != SSH_IPSEC_INVALID_INDEX)
        {
          message = &engine->messages[index];
          engine->async_freelist = message->next;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Run out of messages"));
          return NULL;
        }
    }
  else
    {
      if ((index = engine->async_freelist) != SSH_IPSEC_INVALID_INDEX)
        {
          message = &engine->messages[index];
          engine->async_freelist = message->next;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Run out of messages"));
          return NULL;
        }
    }

  /* The message's index is returned in the `next' field. */
  message->next = index;

  message->async = async;
  message->dynamic = dynamic;
  message->type = type;
  message->data_len = 0;

  return message;
}


/* A prototype for the `can send' callback. */
void ssh_pm_engine_can_send(void *context);

void
ssh_pm_queue_message(SshEngine engine, SshEngineMessage message)
{
  SshUInt32 index = message->next;

  SSH_ASSERT(index != SSH_IPSEC_INVALID_INDEX);
  message->next = SSH_IPSEC_INVALID_INDEX;

  if (engine->pending_tail == SSH_IPSEC_INVALID_INDEX)
    {
      engine->pending_head = index;
      engine->pending_tail = index;
    }
  else
    {
      engine->messages[engine->pending_tail].next = index;
      engine->pending_tail = index;
    }

  ssh_pm_engine_can_send(engine);
}


SshEngineMessage
ssh_pm_get_pending_message(SshEngine engine, SshUInt32 index)
{
  SshEngineMessage message;

  if (index >= SSH_PM_MAX_PENDING_ENGINE_OPERATIONS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid operation identifier %d",
                              (int) index));
      return NULL;
    }

  message = &engine->messages[index];
  if (!message->async)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Message for non-valid operation %d",
                              (int) index));
      return NULL;
    }

  return message;
}


void
ssh_pm_free_message(SshEngine engine, SshEngineMessage message,
                    SshUInt32 index)
{
  SSH_ASSERT(message != NULL);

  if (message->dynamic)
    ssh_free(message->data.dynamic_data);

#ifdef DEBUG_LIGHT
  message->cb.status_cb = NULL_FNPTR;
#endif /* DEBUG_LIGHT */

  if (message->born_async)
    {
      message->next = engine->async_freelist;
      engine->async_freelist = index;
    }
  else
    {
      message->next = engine->sync_freelist;
      engine->sync_freelist = index;
    }
}


void
ssh_pm_receive_interfaces(SshPm pm, const unsigned char *data, size_t data_len)
{
  unsigned int i, k;
  unsigned char *interfaces, *media;
  unsigned char *ifname;
  unsigned char *riidname;
  size_t consumed, interfaces_len, ifnamelen, riidnamelen;
  SshInterceptorInterface *ifp, *interfaces_array;
  SshUInt32 num_interfaces, ifnum, flags;
  SshUInt32 routing_instance_id;
  SshUInt32 protocol_media, protocol_flags;
  SshUInt32 protocol_mtu_ipv4;
  SshUInt32 adapter_media, adapter_flags;
  SshUInt32 adapter_mtu_ipv4;
#ifdef WITH_IPV6
  SshUInt32 adapter_mtu_ipv6, protocol_mtu_ipv6;
#endif /* WITH_IPV6 */
  SshUInt32 num_addrs, temp_proto;
  SshIpInterfacesStruct tmp_interfaces;

  /* Decode the interface array. */

  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32(&num_interfaces),

                       SSH_DECODE_UINT32_STR_NOCOPY(
                       &interfaces, &interfaces_len),

                       SSH_FORMAT_END) != data_len)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Bad interfaces message"));
      return;
    }

  interfaces_array = ssh_calloc(num_interfaces,
                                sizeof(SshInterceptorInterface));
  if (interfaces_array == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Can not allocate space for temporary interface array"));
      return;
    }

  consumed = 0;
  for (i = 0; i < num_interfaces; i++)
    {
      ifp = &interfaces_array[i];

      consumed
        += ssh_decode_array(interfaces + consumed,
                            interfaces_len - consumed,
                            SSH_DECODE_UINT32(&protocol_media),
                            SSH_DECODE_UINT32(&protocol_flags),
                            SSH_DECODE_UINT32(&protocol_mtu_ipv4),
#ifdef WITH_IPV6
                            SSH_DECODE_UINT32(&protocol_mtu_ipv6),
#endif /* WITH_IPV6 */
                            SSH_DECODE_UINT32(&adapter_media),
                            SSH_DECODE_UINT32(&adapter_flags),
                            SSH_DECODE_UINT32(&adapter_mtu_ipv4),
#ifdef WITH_IPV6
                            SSH_DECODE_UINT32(&adapter_mtu_ipv6),
#endif /* WITH_IPV6 */

                            SSH_DECODE_UINT32_STR_NOCOPY(
                            &media, &ifp->media_addr_len),

                            SSH_DECODE_UINT32_STR_NOCOPY(&ifname, &ifnamelen),
                            SSH_DECODE_UINT32(&routing_instance_id),
                            SSH_DECODE_UINT32_STR_NOCOPY(&riidname,
                                                         &riidnamelen),
                            SSH_DECODE_UINT32(&ifnum),
                            SSH_DECODE_UINT32(&flags),
                            SSH_DECODE_UINT32(&num_addrs),
                            SSH_FORMAT_END);

      ifp->ifnum = ifnum;
      ifp->flags = flags;
      ifp->to_protocol.media = protocol_media;
      ifp->to_protocol.flags = protocol_flags;
      ifp->to_protocol.mtu_ipv4 = protocol_mtu_ipv4;

      ifp->to_adapter.media = adapter_media;
      ifp->to_adapter.flags = adapter_flags;
      ifp->to_adapter.mtu_ipv4 = adapter_mtu_ipv4;

#ifdef WITH_IPV6
      ifp->to_protocol.mtu_ipv6 = protocol_mtu_ipv6;
      ifp->to_adapter.mtu_ipv6 = adapter_mtu_ipv6;
#endif /* WITH_IPV6 */

      ifp->num_addrs = num_addrs;
      if (ifnamelen > 0)
        strncpy(ifp->name, ifname, sizeof(ifp->name));
      else
        ifp->name[0]= '\000';

      /* ensure NULL termination */
      ifp->name[sizeof(ifp->name) - 1] = 0;

      if (routing_instance_id > 0)
        ifp->routing_instance_id = routing_instance_id;
      else
        ifp->routing_instance_id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
      if (riidnamelen > 0)
        strncpy(ifp->routing_instance_name, riidname,
                sizeof(ifp->routing_instance_name));
      else
        ifp->routing_instance_name[0]= '\000';

      /* ensure NULL termination */
      ifp->routing_instance_name[sizeof(ifp->routing_instance_name) - 1] = 0;

      if (ifp->media_addr_len &&
          ifp->media_addr_len <= sizeof(ifp->media_addr))
        memcpy(ifp->media_addr, media, ifp->media_addr_len);

      if (ifp->num_addrs)
        {
          ifp->addrs = ssh_calloc(ifp->num_addrs, sizeof(*ifp->addrs));
          if (ifp->addrs == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Out of memory while decoding "
                                      "interface notification"));
              goto out;
            }
        }

      /* Decode the interface addresses. */
      for (k = 0; k < ifp->num_addrs; k++)
        {
          unsigned char *addr, *ip, *mask, *bcast;
          size_t addrlen, ip_size, mask_size, bcast_size;

          consumed += ssh_decode_array(interfaces + consumed,
                                       interfaces_len - consumed,
                                       SSH_DECODE_UINT32(&temp_proto),
                                       SSH_DECODE_UINT32_STR_NOCOPY(
                                        &addr, &addrlen),
                                       SSH_FORMAT_END);

          ifp->addrs[k].protocol = temp_proto;

          ssh_decode_array(addr, addrlen,
                           SSH_DECODE_UINT32_STR_NOCOPY(&ip, &ip_size),
                           SSH_DECODE_UINT32_STR_NOCOPY(&mask, &mask_size),
                           SSH_DECODE_UINT32_STR_NOCOPY(&bcast, &bcast_size),
                           SSH_FORMAT_END);

          ssh_decode_ipaddr_array(ip, ip_size,
                                  &ifp->addrs[k].addr.ip.ip);

          ssh_decode_ipaddr_array(mask, mask_size,
                                  &ifp->addrs[k].addr.ip.mask);

          ssh_decode_ipaddr_array(bcast, bcast_size,
                                  &ifp->addrs[k].addr.ip.broadcast);
        }
    }

  /* Call the interface notification function. */

  if (ssh_ip_init_interfaces_from_table(&tmp_interfaces, interfaces_array,
                                        num_interfaces) == TRUE)
    {
      ssh_pm_pmp_interface_change(pm, &tmp_interfaces);
      ssh_ip_uninit_interfaces(&tmp_interfaces);
    }

  /* Cleanup. */

 out:

  for (i = 0; i < num_interfaces; i++)
    ssh_free(interfaces_array[i].addrs);

  ssh_free(interfaces_array);
}


void
ssh_pm_receive_trigger(SshPm pm, const unsigned char *data, size_t data_len)
{
  SshEnginePolicyRuleStruct rule;
  unsigned char *rule_data;
  size_t rule_data_len;
  SshUInt32 prev_transform_index;
  SshUInt32 packet_ifnum;
  SshUInt32 packet_flags, flow_index;
  unsigned char *packet, *nat_src_buf, *nat_dst_buf;
  size_t packet_len, nat_src_len, nat_dst_len;
  SshIpAddrStruct nat_src_ip, nat_dst_ip;
  SshUInt32 nat_src_port, nat_dst_port, tunnel_id;
  SshUInt32 routing_instance_id;

  if (ssh_decode_array(
                data, data_len,
                SSH_DECODE_UINT32_STR_NOCOPY(&rule_data, &rule_data_len),
                SSH_DECODE_UINT32(&flow_index),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_src_buf, &nat_src_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&nat_dst_buf, &nat_dst_len),
                SSH_DECODE_UINT32(&nat_src_port),
                SSH_DECODE_UINT32(&nat_dst_port),
                SSH_DECODE_UINT32(&tunnel_id),
                SSH_DECODE_UINT32(&routing_instance_id),
                SSH_DECODE_UINT32(&prev_transform_index),
                SSH_DECODE_UINT32(&packet_ifnum),
                SSH_DECODE_UINT32(&packet_flags),
                SSH_DECODE_UINT32_STR(&packet, &packet_len),
                SSH_FORMAT_END) != data_len)
    /* Malformed message or we run out of memory while decoding the
       packet. */
    return;

  ssh_decode_ipaddr_array(nat_src_buf, nat_src_len, &nat_src_ip);
  ssh_decode_ipaddr_array(nat_dst_buf, nat_dst_len, &nat_dst_ip);

  if (!ssh_pm_api_decode_policy_rule(rule_data, rule_data_len, &rule))
    return;

  /* Call the trigger function. */
  ssh_pm_pmp_trigger(pm, &rule,
                     flow_index,
                     &nat_src_ip, (SshUInt16) nat_src_port,
                     &nat_dst_ip, (SshUInt16) nat_dst_port,
                     tunnel_id, (SshVriId) routing_instance_id,
                     prev_transform_index, packet_ifnum, packet_flags,
                     packet, packet_len);
}


void
ssh_pm_receive_transform_event(SshPm pm, const unsigned char *data,
                               size_t data_len)
{
  SshUInt32 event;
  SshUInt32 transform_index;
  SshEngineTransformStruct tr;
  unsigned char *trd_data;
  size_t trd_data_len;
  SshUInt32 rule_index;
  SshEnginePolicyRuleStruct rule;
  unsigned char *rule_data, *run_time_buf;
  size_t rule_data_len, run_time_buf_len;
  SshTime run_time;

  if (ssh_decode_array(
                data, data_len,
                SSH_DECODE_UINT32(&event),
                SSH_DECODE_UINT32(&transform_index),
                SSH_DECODE_UINT32_STR_NOCOPY(&trd_data, &trd_data_len),
                SSH_DECODE_UINT32(&rule_index),
                SSH_DECODE_UINT32_STR_NOCOPY(&rule_data, &rule_data_len),
                SSH_DECODE_UINT32_STR_NOCOPY(&run_time_buf, &run_time_buf_len),
                SSH_FORMAT_END) != data_len)
    /* Malformed message or we run out of memory while decoding the
       packet. */
    return;

  run_time = ssh_pm_api_decode_time(run_time_buf, run_time_buf_len);

  if (!ssh_pm_api_decode_transform_data(trd_data, trd_data_len, &tr))
    return;

  if (rule_data_len
      && !ssh_pm_api_decode_policy_rule(rule_data, rule_data_len, &rule))
    return;

  /* Call the transform event function. */
  ssh_pm_pmp_transform_event(pm, event, transform_index, &tr, rule_index,
                             rule_data_len ? &rule : NULL,
                             run_time);
}

void
ssh_pm_engine_receive_packet(SshPacketType type, const unsigned char *data,
                             size_t data_len, void *context)
{
  SshEngine engine = (SshEngine) context;
  SshEnginePmApiCallType call_type = (SshEnginePmApiCallType) type;
  SshEngineMessage message;
  SshUInt32 operation_index;

  switch (call_type)
    {
    case SSH_EPA_INIT_ERROR:
      {
        SshPm pm = engine->pm;
        SshPmeStatusCB callback = engine->connect_status_cb;
        void *callback_context = engine->connect_status_cb_context;

        if (engine->connect_status_cb == NULL_FNPTR)
          {
            ssh_warning("Unexpected init error notification from engine");
            return;
          }

        ssh_warning("Received an initialization error from the engine. The "
                    "engine data structures are probably in an inconsistent "
                    "state. Reinstall the engine module before continuing.");

        /* non unified, we know the disconnect never fails, and
           can complete within the call, thus do not care about
           the result. */
        ssh_pm_disconnect_engine(pm, NULL_FNPTR, NULL);

        (*callback)(pm, FALSE, callback_context);
        return;
      }
      break;

    case SSH_EPA_VERSION:
      {
        SshPm pm = engine->pm;
        SshPmeStatusCB callback = engine->connect_status_cb;
        void *callback_context = engine->connect_status_cb_context;
        SshUInt32 version_major;
        SshUInt32 version_minor;
        SshUInt32 dummy;
        unsigned char local_ike_ports[64], local_ike_natt_ports[64];
        unsigned char remote_ike_ports[64], remote_ike_natt_ports[64];
        int i;
        Boolean disconnect = FALSE;
        SshUInt32 pm_build_flags, engine_build_flags;
        unsigned char pm_api_calls[64];
        SshPmTransform pm_transforms, engine_transforms;
        unsigned char *engine_api_calls;
        size_t engine_api_calls_len;
        SshUInt32 engine_num_ext_selectors;

        if (engine->connect_status_cb == NULL_FNPTR)
          {
            ssh_warning("Unexpected version notification from engine");
            return;
          }

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&version_major),
                             SSH_DECODE_UINT32(&version_minor),
                             SSH_DECODE_UINT32(&engine_build_flags),
                             SSH_DECODE_UINT32_STR_NOCOPY
                             (&engine_api_calls, &engine_api_calls_len),
                             SSH_DECODE_UINT64(&engine_transforms),
                             SSH_DECODE_UINT32(&engine_num_ext_selectors),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (version_major != SSH_PM_API_RPC_VERSION_MAJOR
            || version_minor != SSH_PM_API_RPC_VERSION_MINOR)
          {
            ssh_warning("Invalid engine version: "
                        "expected %d.%d, received %d.%d",
                        SSH_PM_API_RPC_VERSION_MAJOR,
                        SSH_PM_API_RPC_VERSION_MINOR,
                        (int) version_major,
                        (int) version_minor);
            disconnect = TRUE;
          }

        ssh_pm_api_build_flags(&pm_build_flags);
        if (pm_build_flags != engine_build_flags)
          {
            ssh_warning("Mismatch in build flags between engine "
                        "and policy manager: engine 0x%08lx pm 0x%08lx",
                        (unsigned long) engine_build_flags,
                        (unsigned long) pm_build_flags);
            disconnect = TRUE;
          }

        SSH_VERIFY(ssh_pm_api_supported_api_calls(pm_api_calls,
                                                  sizeof(pm_api_calls)));
        if (engine_api_calls_len < sizeof(pm_api_calls)
            || memcmp(pm_api_calls, engine_api_calls, sizeof(pm_api_calls)))
          {
            ssh_warning("Mismatch in supported PM API call types "
                        "between engine and policy manager");
#ifdef DEBUG_LIGHT
            for (i = 0; i < (8 * sizeof(pm_api_calls)); i++)
              {
                if ((engine_api_calls[i / 8] & (1 << (i % 8))) != 0
                    && (pm_api_calls[i / 8] & (1 << (i % 8))) == 0)
                  SSH_DEBUG(SSH_D_ERROR,
                            ("PM does not support PM API call type %u", i));
                else if ((engine_api_calls[i / 8] & (1 << (i % 8))) == 0
                         && (pm_api_calls[i / 8] & (1 << (i % 8))) != 0)
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Engine does not support PM API call type %u",
                             i));
              }
#endif /* DEBUG_LIGHT */
            disconnect = TRUE;
          }

        ssh_pm_api_supported_transforms(&pm_transforms);
        if (pm_transforms != engine_transforms)
          {
            ssh_warning("Mismatch in supported transforms between engine "
                        "and policy manager: engine 0x%08lx pm 0x%08lx",
                        (unsigned long) engine_transforms,
                        (unsigned long) pm_transforms);
            disconnect = TRUE;
          }

        if (engine_num_ext_selectors
            != SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS)
          {
            ssh_warning("Mismatch in SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS "
                        "between engine and policy manager: engine %d pm %d",
                        (int) engine_num_ext_selectors,
                        (int) SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS);
            disconnect = TRUE;
          }

        if (disconnect == TRUE)
          {
            /* non unified, we know the disconnect never fails, and
               can complete within the call, thus do not care about
               the result. */
            ssh_pm_disconnect_engine(pm, NULL_FNPTR, NULL);

            (*callback)(pm, FALSE, callback_context);
            return;
          }

        /* The connect operation was successful and the engine uses
           correct version.  Let's send an init message to the engine.
           Note that the system is currently starting up and the
           policy manager is not generating any other messages to the
           engine.  Therefore this can't fail. */
        dummy = 0;
        message = ssh_pm_alloc_message(engine, SSH_PEA_ENGINE_INIT, FALSE,
                                       FALSE);
        SSH_VERIFY(message != NULL);

        for (i = 0; i < engine->num_ike_ports; i++)
          {
            SSH_PUT_16BIT(local_ike_ports + i * sizeof(SshUInt16),
                          engine->local_ike_ports[i]);
            SSH_PUT_16BIT(local_ike_natt_ports + i * sizeof(SshUInt16),
                          engine->local_ike_natt_ports[i]);
            SSH_PUT_16BIT(remote_ike_ports + i * sizeof(SshUInt16),
                          engine->remote_ike_ports[i]);
            SSH_PUT_16BIT(remote_ike_natt_ports + i * sizeof(SshUInt16),
                          engine->remote_ike_natt_ports[i]);
          }

        message->data_len
          = ssh_encode_array(message->data.static_data,
                             sizeof(message->data.static_data),
                             SSH_ENCODE_UINT32(dummy),
#ifdef SSHDIST_IPSEC_NAT
                             SSH_ENCODE_UINT32(
                             (SshUInt32) engine->nat_port_range_low),
                             SSH_ENCODE_UINT32(
                             (SshUInt32) engine->nat_port_range_high),
                             SSH_ENCODE_UINT32(
                             (SshUInt32) engine->
                             nat_privileged_port_range_low),
                             SSH_ENCODE_UINT32(
                             (SshUInt32) engine->
                             nat_privileged_port_range_high),
#endif /* SSHDIST_IPSEC_NAT */
                             SSH_ENCODE_UINT32_STR(local_ike_ports,
                                                   engine->num_ike_ports *
                                                   sizeof(SshUInt16)),
                             SSH_ENCODE_UINT32_STR(local_ike_natt_ports,
                                                   engine->num_ike_ports *
                                                   sizeof(SshUInt16)),
                             SSH_ENCODE_UINT32_STR(remote_ike_ports,
                                                   engine->num_ike_ports *
                                                   sizeof(SshUInt16)),
                             SSH_ENCODE_UINT32_STR(remote_ike_natt_ports,
                                                   engine->num_ike_ports *
                                                   sizeof(SshUInt16)),
                             SSH_FORMAT_END);
        SSH_ASSERT(message->data_len != 0);

        ssh_pm_queue_message(engine, message);

        /* Complete the engine connect operation. */

        engine->connect_status_cb = NULL_FNPTR;
        engine->connect_status_cb_context = NULL;

        (*callback)(pm, TRUE, callback_context);
      }
      break;

    case SSH_EPA_INTERFACE:
      ssh_pm_receive_interfaces(engine->pm, data, data_len);
      break;

    case SSH_EPA_DEBUG:
      {
        unsigned char *str;
        size_t len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32_STR_NOCOPY(&str, &len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        ssh_debug("%.*s", (int) len, str);
      }
      break;

    case SSH_EPA_WARNING:
      {
        unsigned char *str;
        size_t len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32_STR_NOCOPY(&str, &len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        ssh_warning("%.*s", (int) len, str);
      }
      break;

    case SSH_EPA_STATUS_CB:
      {
        Boolean status;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_BOOLEAN(&status),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            if (message->cb.status_cb)
              (*message->cb.status_cb)(engine->pm, status,
                                       message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_INDEX_CB:
      {
        SshUInt32 index;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&index),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.index_cb)(engine->pm, index, message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_ADD_RULE_CB:
      {
        SshUInt32 rule_index;
        unsigned char *rule_buf;
        SshEnginePolicyRuleStruct rule;
        size_t rule_len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&rule_index),

                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &rule_buf, &rule_len),

                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (rule_buf && rule_len)
          if (!ssh_pm_api_decode_policy_rule(rule_buf, rule_len, &rule))
            goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.add_rule_cb)(engine->pm,
                                       rule_index,
                                       (rule_len ? &rule : NULL),
                                       message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }

      break;

    case SSH_EPA_SA_INDEX_CB:
      {
        SshUInt32 transform_index;
        SshUInt32 outbound_spi;
        unsigned char *rule_buf;
        size_t rule_len;
        SshEnginePolicyRuleStruct rule_struct;
        SshEnginePolicyRule rule;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &rule_buf, &rule_len),
                             SSH_DECODE_UINT32(&transform_index),
                             SSH_DECODE_UINT32(&outbound_spi),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (rule_buf && rule_len)
          {
            if (!ssh_pm_api_decode_policy_rule(rule_buf, rule_len,
                                               &rule_struct))
              goto format_error;
            rule = &rule_struct;
          }
        else
          rule = NULL;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.sa_index_cb)(engine->pm, rule,
                                       transform_index, outbound_spi,
                                       message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

#ifdef SSH_IPSEC_STATISTICS
    case SSH_EPA_GLOBAL_STATS_CB:
      {
        unsigned char *stats_data;
        size_t stats_data_len;
        SshFastpathGlobalStatsStruct f_stats;
        SshEngineGlobalStatsStruct e_stats;
        Boolean have_e_stats = FALSE, have_f_stats = FALSE;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &stats_data, &stats_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (stats_data_len)
          {
            unsigned char in_octets_comp[8];
            unsigned char in_octets_uncomp[8];
            unsigned char out_octets_comp[8];
            unsigned char out_octets_uncomp[8];
            unsigned char forwarded_octets_comp[8];
            unsigned char forwarded_octets_uncomp[8];
            unsigned char in_packets[8];
            unsigned char out_packets[8];
            unsigned char forwarded_packets[8];
            unsigned char counters[SSH_ENGINE_NUM_GLOBAL_STATS
                                   * sizeof(SshUInt32)];
            int i;

            memset(&e_stats, 0, sizeof(e_stats));
            memset(&f_stats, 0, sizeof(f_stats));

            if (ssh_decode_array(
                stats_data, stats_data_len,
                SSH_DECODE_BOOLEAN(&have_e_stats),
                SSH_DECODE_BOOLEAN(&have_f_stats),
                SSH_DECODE_DATA(in_octets_comp, 8),
                SSH_DECODE_DATA(in_octets_uncomp, 8),
                SSH_DECODE_DATA(out_octets_comp, 8),
                SSH_DECODE_DATA(out_octets_uncomp, 8),
                SSH_DECODE_DATA(forwarded_octets_comp, 8),
                SSH_DECODE_DATA(forwarded_octets_uncomp, 8),
                SSH_DECODE_DATA(in_packets, 8),
                SSH_DECODE_DATA(out_packets, 8),
                SSH_DECODE_DATA(forwarded_packets, 8),

                SSH_DECODE_UINT32(&e_stats.active_nexthops),
                SSH_DECODE_UINT32(&e_stats.total_nexthops),
                SSH_DECODE_UINT32(&e_stats.out_of_nexthops),

                SSH_DECODE_UINT32(&e_stats.active_flows),
                SSH_DECODE_UINT32(&e_stats.total_flows),
                SSH_DECODE_UINT32(&e_stats.out_of_flows),

                SSH_DECODE_UINT32(&e_stats.active_transforms),
                SSH_DECODE_UINT32(&e_stats.total_transforms),
                SSH_DECODE_UINT32(&e_stats.out_of_transforms),

                SSH_DECODE_UINT32(&f_stats.active_transform_contexts),
                SSH_DECODE_UINT32(&f_stats.total_transform_contexts),
                SSH_DECODE_UINT32(&f_stats.out_of_transform_contexts),

                SSH_DECODE_UINT32(&f_stats.active_packet_contexts),
                SSH_DECODE_UINT32(&f_stats.out_of_packet_contexts),

                SSH_DECODE_UINT32(&e_stats.out_of_arp_cache_entries),
                SSH_DECODE_UINT32(&e_stats.total_rekeys),
                SSH_DECODE_UINT32(&e_stats.active_rules),
                SSH_DECODE_UINT32(&e_stats.total_rules),

                SSH_DECODE_DATA(counters, sizeof(counters)),

                SSH_DECODE_UINT32(&e_stats.flow_table_size),
                SSH_DECODE_UINT32(&e_stats.transform_table_size),
                SSH_DECODE_UINT32(&e_stats.rule_table_size),
                SSH_DECODE_UINT32(&e_stats.next_hop_table_size),
                SSH_DECODE_UINT32(&f_stats.packet_context_table_size),
                SSH_DECODE_UINT32(&f_stats.transform_context_table_size),

                SSH_DECODE_UINT32(&e_stats.policy_rule_struct_size),
                SSH_DECODE_UINT32(&e_stats.transform_data_struct_size),
                SSH_DECODE_UINT32(&f_stats.transform_context_struct_size),
                SSH_DECODE_UINT32(&e_stats.flow_struct_size),

                SSH_DECODE_UINT32(&e_stats.age_callback_interval),
                SSH_DECODE_UINT32(&e_stats.age_callback_flows),

                SSH_FORMAT_END) != stats_data_len)
              goto format_error;

            /* Decode counters. */
            for (i = 0; i < SSH_ENGINE_NUM_GLOBAL_STATS; i++)
              f_stats.counters[i] = SSH_GET_32BIT(counters
                                                  + i * sizeof(SshUInt32));

            /* Decode 64 bit values. */
            f_stats.in_octets_comp = ssh_pm_api_decode_uint64(in_octets_comp);
            f_stats.in_octets_uncomp
              = ssh_pm_api_decode_uint64(in_octets_uncomp);
            f_stats.out_octets_comp =
              ssh_pm_api_decode_uint64(out_octets_comp);
            f_stats.out_octets_uncomp
              = ssh_pm_api_decode_uint64(out_octets_uncomp);
            f_stats.forwarded_octets_comp
              = ssh_pm_api_decode_uint64(forwarded_octets_comp);
            f_stats.forwarded_octets_uncomp
              = ssh_pm_api_decode_uint64(forwarded_octets_uncomp);

            f_stats.in_packets = ssh_pm_api_decode_uint64(in_packets);
            f_stats.out_packets = ssh_pm_api_decode_uint64(out_packets);
            f_stats.forwarded_packets =
              ssh_pm_api_decode_uint64(forwarded_packets);
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.global_stats_cb)(engine->pm,
                                           (stats_data_len && have_e_stats) ?
                                           &e_stats : NULL,
                                           (stats_data_len && have_f_stats) ?
                                           &f_stats : NULL,
                                           message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_FLOW_INFO_CB:
      {
        unsigned char *info_data;
        size_t info_data_len;
        SshEngineFlowInfoStruct info;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &info_data, &info_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (info_data_len)
          {
            unsigned char *src;
            size_t src_len;
            unsigned char *dst;
            size_t dst_len;
            SshUInt32 src_port, dst_port, ipproto, is_dangling, is_trigger;
#ifdef SSHDIST_IPSEC_NAT
            unsigned char *nat_src;
            size_t nat_src_len;
            unsigned char *nat_dst;
            size_t nat_dst_len;
            SshUInt32 nat_src_port;
            SshUInt32 nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */
            SshUInt32 routing_instance_id;

            memset(&info, 0, sizeof(info));

            if (ssh_decode_array(
                        info_data, info_data_len,
                        SSH_DECODE_UINT32_STR_NOCOPY(&src, &src_len),
                        SSH_DECODE_UINT32_STR_NOCOPY(&dst, &dst_len),
                        SSH_DECODE_UINT32(&src_port),
                        SSH_DECODE_UINT32(&dst_port),
                        SSH_DECODE_UINT32(&ipproto),
#ifdef SSHDIST_IPSEC_NAT
                        SSH_DECODE_UINT32_STR_NOCOPY(&nat_src, &nat_src_len),
                        SSH_DECODE_UINT32_STR_NOCOPY(&nat_dst, &nat_dst_len),
                        SSH_DECODE_UINT32(&nat_src_port),
                        SSH_DECODE_UINT32(&nat_dst_port),
#endif /* SSHDIST_IPSEC_NAT */
                        SSH_DECODE_UINT32(&info.forward_transform_index),
                        SSH_DECODE_UINT32(&info.reverse_transform_index),
                        SSH_DECODE_UINT32(&info.rule_index),
                        SSH_DECODE_UINT32(&info.protocol_state),
                        SSH_DECODE_UINT32(&info.lru_level),
                        SSH_DECODE_UINT32(&info.idle_time),
                        SSH_DECODE_UINT32(&is_dangling),
                        SSH_DECODE_UINT32(&is_trigger),
                        SSH_DECODE_UINT32(&routing_instance_id),
                        SSH_FORMAT_END) != info_data_len)
              goto format_error;

            ssh_decode_ipaddr_array(src, src_len, &info.src);
            ssh_decode_ipaddr_array(dst, dst_len, &info.dst);
            info.src_port = (SshUInt16) src_port;
            info.dst_port = (SshUInt16) dst_port;
            info.ipproto = (SshUInt8) ipproto;
            info.is_dangling = (Boolean) is_dangling;
            info.is_trigger = (Boolean) is_trigger;
            info.routing_instance_id = (int) routing_instance_id;
#ifdef SSHDIST_IPSEC_NAT
            ssh_decode_ipaddr_array(nat_src, nat_src_len, &info.nat_src);
            ssh_decode_ipaddr_array(nat_dst, nat_dst_len, &info.nat_dst);
            info.nat_src_port = (SshUInt16) nat_src_port;
            info.nat_dst_port = (SshUInt16) nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.flow_info_cb)(engine->pm,
                                        info_data_len ? &info : NULL,
                                        message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_FLOW_STATS_CB:
      {
        unsigned char *stats_data;
        size_t stats_data_len;
        SshEngineFlowStatsStruct stats;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &stats_data, &stats_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (stats_data_len)
          {
            unsigned char forward_octets[8];
            unsigned char reverse_octets[8];
            unsigned char forward_packets[8];
            unsigned char reverse_packets[8];
            unsigned char drop_packets[8];

            memset(&stats, 0, sizeof(stats));

            if (ssh_decode_array(
                        stats_data, stats_data_len,
                        SSH_DECODE_DATA(forward_octets, 8),
                        SSH_DECODE_DATA(reverse_octets, 8),
                        SSH_DECODE_DATA(forward_packets, 8),
                        SSH_DECODE_DATA(reverse_packets, 8),
                        SSH_DECODE_DATA(drop_packets, 8),

                      SSH_FORMAT_END) != stats_data_len)
              goto format_error;

            /* Decode 64 bit values. */
            stats.forward_octets = ssh_pm_api_decode_uint64(forward_octets);
            stats.reverse_octets = ssh_pm_api_decode_uint64(reverse_octets);
            stats.forward_packets = ssh_pm_api_decode_uint64(forward_packets);
            stats.reverse_packets = ssh_pm_api_decode_uint64(reverse_packets);
            stats.drop_packets = ssh_pm_api_decode_uint64(drop_packets);
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.flow_stats_cb)(engine->pm,
                                         stats_data_len ? &stats : NULL,
                                         message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_RULE_STATS_CB:
      {
        unsigned char *stats_data;
        size_t stats_data_len;
        SshEngineRuleStatsStruct stats;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &stats_data, &stats_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (stats_data_len)
          {
            memset(&stats, 0, sizeof(stats));

            if (ssh_decode_array(
                        stats_data, stats_data_len,
                        SSH_DECODE_UINT32(&stats.times_used),
                        SSH_DECODE_UINT32(&stats.num_flows_active),
                        SSH_DECODE_UINT32(&stats.num_flows_total),
                        SSH_FORMAT_END) != stats_data_len)
              goto format_error;
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.rule_stats_cb)(engine->pm,
                                         stats_data_len ? &stats : NULL,
                                         message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_TRANSFORM_STATS_CB:
      {
        unsigned char *stats_data;
        size_t stats_data_len;
        SshEngineTransformStatsStruct stats;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &stats_data, &stats_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (stats_data_len)
          {
            unsigned char in_octets[8];
            unsigned char out_octets[8];
            unsigned char in_packets[8];
            unsigned char out_packets[8];
            unsigned char drop_packets[8];
            unsigned char num_mac_fails[8];

            memset(&stats, 0, sizeof(stats));

            if (ssh_decode_array(
                        stats_data, stats_data_len,
                        SSH_DECODE_DATA(in_octets, 8),
                        SSH_DECODE_DATA(out_octets, 8),
                        SSH_DECODE_DATA(in_packets, 8),
                        SSH_DECODE_DATA(out_packets, 8),
                        SSH_DECODE_DATA(drop_packets, 8),
                        SSH_DECODE_DATA(num_mac_fails, 8),

                        SSH_DECODE_UINT32(&stats.control.num_rekeys),
                        SSH_DECODE_UINT32(&stats.control.num_flows_active),
                        SSH_FORMAT_END) != stats_data_len)
              goto format_error;

            /* Decode 64 bit values. */
            stats.data.in_octets = ssh_pm_api_decode_uint64(in_octets);
            stats.data.out_octets = ssh_pm_api_decode_uint64(out_octets);
            stats.data.in_packets = ssh_pm_api_decode_uint64(in_packets);
            stats.data.out_packets = ssh_pm_api_decode_uint64(out_packets);
            stats.data.drop_packets = ssh_pm_api_decode_uint64(drop_packets);
            stats.data.num_mac_fails = ssh_pm_api_decode_uint64(num_mac_fails);
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.transform_stats_cb)(engine->pm,
                                              stats_data_len ? &stats : NULL,
                                              message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;
#endif /* SSH_IPSEC_STATISTICS */

    case SSH_EPA_DELETE_CB:
      {
        Boolean done;
        SshUInt32 rule_index;
        SshUInt32 peer_handle;
        unsigned char *encoded_tr;
        size_t encoded_tr_len;
        SshEngineTransformStruct tr;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_BOOLEAN(&done),
                             SSH_DECODE_UINT32(&rule_index),
                             SSH_DECODE_UINT32(&peer_handle),
                             SSH_DECODE_UINT32_STR_NOCOPY
                             (&encoded_tr, &encoded_tr_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (encoded_tr_len > 0 &&
            !ssh_pm_api_decode_transform_data(encoded_tr, encoded_tr_len, &tr))
          {
            encoded_tr_len = 0;
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode transform data"));
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            if (message->cb.delete_cb)
              (*message->cb.delete_cb)(engine->pm, done, rule_index,
                                       peer_handle,
                                       (encoded_tr_len > 0 ? &tr : NULL),
                                       message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_DELETE_TRANSFORM_CB:
      {
        Boolean done;
        SshUInt32 peer_handle;
        unsigned char *encoded_tr;
        size_t encoded_tr_len;
        SshEngineTransformStruct tr;
        void *policy_context;
        unsigned char *policy_data;
        size_t policy_data_len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_BOOLEAN(&done),
                             SSH_DECODE_UINT32(&peer_handle),
                             SSH_DECODE_UINT32_STR_NOCOPY
                             (&encoded_tr, &encoded_tr_len),
                             SSH_DECODE_UINT32_STR_NOCOPY
                             (&policy_data, &policy_data_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (encoded_tr_len > 0 &&
            !ssh_pm_api_decode_transform_data(encoded_tr, encoded_tr_len, &tr))
          {
            encoded_tr_len = 0;
            SSH_DEBUG(SSH_D_FAIL, ("Failed to decode transform data"));
          }

        if (policy_data_len > sizeof(policy_context))
          {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Invalid policy data length %d, expected %d",
                       (int) policy_data_len, (int) sizeof(policy_context)));
            policy_data_len = sizeof(policy_context);
          }
        memcpy(&policy_context, policy_data, policy_data_len);

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            if (message->cb.delete_transform_cb)
              (*message->cb.delete_transform_cb)(engine->pm, done,
                                                 peer_handle,
                                                 (encoded_tr_len>0?&tr:NULL),
                                                 policy_context,
                                                 message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_GET_RULE_CB:
      {
        SshEnginePolicyRuleStruct rule;
        unsigned char *rule_data;
        size_t rule_data_len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),

                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &rule_data, &rule_data_len),

                             SSH_FORMAT_END) != data_len)
          goto format_error;

        /* Decode policy rule. */
        if (rule_data_len)
          if (!ssh_pm_api_decode_policy_rule(rule_data, rule_data_len, &rule))
            goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.rule_cb)(engine->pm,
                                   rule_data_len ? &rule : NULL,
                                   message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_GET_TRANSFORM_CB:
      {
        SshEngineTransformStruct trd;
        unsigned char *trd_data;
        size_t trd_data_len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),

                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &trd_data, &trd_data_len),

                             SSH_FORMAT_END) != data_len)
          goto format_error;

        /* Decode transform data. */
        if (trd_data_len)
          if (!ssh_pm_api_decode_transform_data(trd_data, trd_data_len, &trd))
            goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.transform_cb)(engine->pm,
                                        trd_data_len ? &trd : NULL,
                                        message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_ROUTE_CB:
      {
        SshUInt32 flags;
        SshUInt32 ifnum;
        unsigned char *next_hop;
        size_t next_hop_len;
        SshUInt32 mtu;
        SshIpAddrStruct ip;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&flags),
                             SSH_DECODE_UINT32(&ifnum),

                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &next_hop, &next_hop_len),

                             SSH_DECODE_UINT32(&mtu),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        /* The next hop address can be NULL. */
        if (next_hop_len)
          ssh_decode_ipaddr_array(next_hop, next_hop_len, &ip);

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.route_cb)(engine->pm, flags, ifnum,
                                    next_hop_len ? &ip : NULL,
                                    mtu, message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

    case SSH_EPA_ROUTE_SUCCESS_CB:
      {
        SshUInt32 error;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&error),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.route_success_cb)(engine->pm,
                                            (SshInterceptorRouteError) error,
                                            message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
      }
      break;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
    case SSH_EPA_VIRTUAL_ADAPTER_STATUS_CB:
      {
        SshUInt32 num_adapters, i;
        SshPmeVirtualAdapter adapters = NULL;
        SshUInt32 error, adapter_ifnum, adapter_state;
        unsigned char *adapter_name;
        size_t adapter_name_len;
        unsigned char *adapter_ptr;
        size_t adapter_len, len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&error),
                             SSH_DECODE_UINT32(&num_adapters),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &adapter_ptr, &adapter_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK
            && num_adapters > 0)
          {
            adapters = ssh_calloc(num_adapters, sizeof(*adapters));
            if (adapters == NULL)
              error = SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
          }

        if (adapters)
          {
            for (i = 0; i < num_adapters; i++)
              {
                len = ssh_decode_array(adapter_ptr, adapter_len,
                                       SSH_DECODE_UINT32(&adapter_ifnum),
                                       SSH_DECODE_UINT32(&adapter_state),
                                       SSH_DECODE_UINT32_STR_NOCOPY(
                                       &adapter_name, &adapter_name_len),
                                       SSH_FORMAT_END);
                if (len == 0)
                  break;

                adapters[i].adapter_ifnum = adapter_ifnum;
                adapters[i].adapter_state =
                  (SshVirtualAdapterState) adapter_state;
                SSH_ASSERT(adapter_name_len < SSH_INTERCEPTOR_IFNAME_SIZE);
                SSH_ASSERT(adapter_name_len > 0);
                strncpy(adapters[i].adapter_name, adapter_name,
                        adapter_name_len);
                /*
                ssh_snprintf(adapters[i].adapter_name,
                             SSH_INTERCEPTOR_IFNAME_SIZE,
                             "%s", adapter_name);
                */
                adapter_ptr += len;
                adapter_len -= len;
              }
            num_adapters = i;
          }
        else
          num_adapters = 0;

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            (*message->cb.virtual_adapter_status_cb)(engine->pm,
                                                (SshVirtualAdapterError) error,
                                                num_adapters,
                                                adapters,
                                                message->cb_context);
            ssh_pm_free_message(engine, message, operation_index);
          }
        ssh_free(adapters);
      }
      break;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

    case SSH_EPA_TRIGGER:
      ssh_pm_receive_trigger(engine->pm, data, data_len);
      break;

    case SSH_EPA_TRANSFORM_EVENT:
      ssh_pm_receive_transform_event(engine->pm, data, data_len);
      break;

    case SSH_EPA_AUDIT_POLL_REQUEST:
      ssh_pm_audit_get_engine_events(engine->pm);
      break;

    case SSH_EPA_AUDIT_ENGINE_EVENT:
      {
        unsigned char *event_buf;
        SshUInt32 audit_flags, num_events = 0;
        SshEngineAuditEvent events = NULL;
        Boolean more_events;
        size_t event_len;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_BOOLEAN(&more_events),
                             SSH_DECODE_UINT32(&audit_flags),
                             SSH_DECODE_UINT32(&num_events),
                             SSH_DECODE_UINT32_STR_NOCOPY(
                             &event_buf, &event_len),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        if (num_events)
          {
            /* Allocate the events */
            events = ssh_calloc(num_events, sizeof(SshEngineAuditEventStruct));
            if (events == NULL)
              {
                SSH_DEBUG(SSH_D_FAIL, ("Out of memory, cannot decode "
                                       "audit event from engine"));
                goto format_error;
              }

            if (!ssh_pm_api_decode_engine_audit_events(event_buf,
                                                       event_len,
                                                       num_events,
                                                       events))
              {
                ssh_free(events);
                goto format_error;
              }
          }

        message = ssh_pm_get_pending_message(engine, operation_index);
        if (message)
          {
            if (message->cb.audit_cb)
              (*message->cb.audit_cb)(engine->pm, more_events,
                                      audit_flags, num_events,
                                      events, message->cb_context);

            ssh_pm_free_message(engine, message, operation_index);
          }

        if (events)
          ssh_free(events);
      }
      break;

    case SSH_EPA_FLOW_FREE:
      {
        SshUInt32 flow_index;

        if (ssh_decode_array(data, data_len,
                             SSH_DECODE_UINT32(&operation_index),
                             SSH_DECODE_UINT32(&flow_index),
                             SSH_FORMAT_END) != data_len)
          goto format_error;

        ssh_pm_pmp_flow_free_notification(engine->pm, flow_index);
      }
      break;






















    default:
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Received unknown message %d from engine:", type),
                        data, data_len);
      break;
    }

  /* All done. */
  return;

  /* Error handling. */

 format_error:

  SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                    ("Malformed message of type %d from engine", type),
                    data, data_len);
}


void
ssh_pm_engine_can_send(void *context)
{
  SshEngine engine = (SshEngine) context;
  char padding;

  while (engine->pending_head != SSH_IPSEC_INVALID_INDEX
         && ssh_packet_wrapper_can_send(engine->packet_wrapper))
    {
      SshEngineMessage message;
      unsigned char *data;
      SshUInt32 message_index = engine->pending_head;

      message = &engine->messages[message_index];

      if (message->dynamic)
        data = message->data.dynamic_data;
      else
        data = message->data.static_data;









      /* Insert padding if data length is zero. */
      if (!message->data_len)
        {
          data = &padding;
          message->data_len++;
        }

      if (!ssh_packet_wrapper_send(engine->packet_wrapper, message->type,
                                   data, message->data_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Packet wrapper send failed"));
          return;
        }

      /* Message has been sent, now remove it from the message queue. */
      engine->pending_head = message->next;
      if (engine->pending_head == SSH_IPSEC_INVALID_INDEX)
        engine->pending_tail = SSH_IPSEC_INVALID_INDEX;

      /* And check how to recycle the message structure. */
      if (message->async)
        {
          /* There will be a completion message from the engine that
             completes this asynchronous operation.  Do nothing. */
        }
      else
        {
          /* This is a synchronous message; we must free it. */
          ssh_pm_free_message(engine, message, message_index);
        }
    }
}


/********************** Opening and closing the engine **********************/

void
ssh_pm_connect_engine(SshPm pm, void *machine_context, SshUInt32 flags,
                      SshUInt16 nat_port_range_low,
                      SshUInt16 nat_port_range_high,
                      SshUInt16 nat_privileged_port_range_low,
                      SshUInt16 nat_privileged_port_range_high,
                      SshUInt16 num_ike_ports,
                      SshUInt16 *local_ike_ports,
                      SshUInt16 *local_ike_natt_ports,
                      SshUInt16 *remote_ike_ports,
                      SshUInt16 *remote_ike_natt_ports,
                      SshPmeStatusCB callback, void *context)
{
  SshStream stream = NULL;
  SshEngine engine = NULL;
  SshUInt32 i;

  /* The machine context must name a device or similar thing. */
  if (machine_context == NULL)
    goto error;

  stream = ssh_device_open((char *) machine_context);
  if (!stream)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to open the engine device"));
      goto error;
    }
  /* Allocate an engine object. */

  engine = ssh_calloc(1, sizeof(*engine));
  if (engine == NULL)
    goto error;

  engine->pm = pm;

#ifdef SSHDIST_IPSEC_NAT
  engine->nat_port_range_low = nat_port_range_low;
  engine->nat_port_range_high = nat_port_range_high;
  engine->nat_privileged_port_range_low = nat_privileged_port_range_low;
  engine->nat_privileged_port_range_high = nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */
  engine->num_ike_ports = num_ike_ports;
  *engine->local_ike_ports = *local_ike_ports;
  *engine->local_ike_natt_ports = *local_ike_natt_ports;
  *engine->remote_ike_ports = *remote_ike_ports;
  *engine->remote_ike_natt_ports = *remote_ike_natt_ports;

  engine->sync_freelist  = SSH_IPSEC_INVALID_INDEX;
  engine->async_freelist = SSH_IPSEC_INVALID_INDEX;
  engine->pending_head   = SSH_IPSEC_INVALID_INDEX;
  engine->pending_tail   = SSH_IPSEC_INVALID_INDEX;

  /* Wrap the engine connection into a packet stream. */
  engine->packet_wrapper = ssh_packet_wrap(stream,
                                           ssh_pm_engine_receive_packet,
                                           NULL_FNPTR,
                                           ssh_pm_engine_can_send,
                                           engine);
  if (engine->packet_wrapper == NULL)
    goto error;

  /* The packet wrapper consumed our stream. */
  stream = NULL;

  /* Initialize messages. */

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  engine->messages = ssh_pm_messages;
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */
  engine->messages = ssh_calloc(SSH_PM_MAX_PENDING_ENGINE_OPERATIONS,
                                sizeof(SshEngineMessageStruct));
  if (engine->messages == NULL)
    goto error;
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  for (i = 0;
       i < ((SSH_PM_MAX_PENDING_ENGINE_OPERATIONS * 2) / 3);
       i++)
    {
      engine->messages[i].next = engine->async_freelist;
      engine->async_freelist = i;
      engine->messages[i].born_async = 1;
    }

  for (i = ((SSH_PM_MAX_PENDING_ENGINE_OPERATIONS * 2) / 3);
       i < SSH_PM_MAX_PENDING_ENGINE_OPERATIONS;
       i++)
    {
      engine->messages[i].next = engine->sync_freelist;
      engine->sync_freelist = i;
      engine->messages[i].born_async = 0;
    }

  /* Wait for the version message and the connect operation is complete. */

  engine->connect_status_cb = callback;
  engine->connect_status_cb_context = context;

  pm->engine = engine;

  return;

  /* Error handling. */

 error:
  if (engine)
    {
      if (engine->packet_wrapper)
        ssh_packet_wrapper_destroy(engine->packet_wrapper);

      ssh_free(engine);
    }

  if (stream)
    ssh_stream_destroy(stream);

  (*callback)(pm, FALSE, context);
}


void
ssh_pm_disconnect_engine(SshPm pm,
                         SshPmeStatusCB callback, void *context)
{
  SshEngine engine = (SshEngine) pm->engine;
  SshUInt32 i, inext;

  if (engine == NULL)
    {
      if (callback)
        (*callback)(pm, TRUE, context);
      return;
    }

  pm->engine = NULL;
  pm->connected = 0;

  ssh_packet_wrapper_destroy(engine->packet_wrapper);

  /* Free all pending dynamic messages. */
  for (i = engine->pending_head; i != SSH_IPSEC_INVALID_INDEX; i = inext)
    {
      SshEngineMessage message = &engine->messages[i];

      if (message->dynamic)
        ssh_free(message->data.dynamic_data);

      inext = message->next;
    }

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* Nothing here. */
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */
  ssh_free(engine->messages);
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  ssh_free(engine);

  if (callback)
    (*callback)(pm, TRUE, context);
}


/* Forward declaration */
static void ssh_pme_random_salt(SshEngine engine, SshUInt32 salt[4]);

/* Sent the random salt to the engine */
void ssh_pm_salt_to_engine(SshPm pm, SshUInt32 salt[4])
{
  ssh_pme_random_salt(pm->engine, salt);
}


/************************ Generic engine operations *************************/

void
ssh_pme_disable_policy_lookup(SshEngine engine, SshPmeStatusCB callback,
                              void *callback_context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_POLICY_LOOKUP, TRUE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      (*callback)(engine->pm, FALSE, callback_context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       /* Operation index */
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_BOOLEAN((Boolean) FALSE),
                       SSH_FORMAT_END);

  message->cb.status_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_enable_policy_lookup(SshEngine engine, SshPmeStatusCB callback,
                             void *callback_context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_POLICY_LOOKUP, TRUE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      (*callback)(engine->pm, FALSE, callback_context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       /* Operation index */
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_BOOLEAN((Boolean) TRUE),
                       SSH_FORMAT_END);

  message->cb.status_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
}


static void
ssh_pme_random_salt(SshEngine engine, SshUInt32 salt[4])
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ENGINE_SALT, FALSE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(salt[0]),
                       SSH_ENCODE_UINT32(salt[1]),
                       SSH_ENCODE_UINT32(salt[2]),
                       SSH_ENCODE_UINT32(salt[3]),
                       SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  ssh_pm_queue_message(engine, message);
  return;
}

void
ssh_pme_set_debug_level(SshEngine engine, const char *level_string)
{
  SshEngineMessage message;
  unsigned char *data;
  size_t data_len;

  data_len = ssh_encode_array_alloc(&data,
                                    SSH_ENCODE_UINT32_STR(level_string,
                                                          strlen(level_string)
                                                          + 1),
                                    SSH_FORMAT_END);
  if (data_len == 0)
    return;

  message = ssh_pm_alloc_message(engine, SSH_PEA_DEBUG, FALSE, TRUE);
  if (message == NULL)
    {
      ssh_free(data);
      return;
    }

  message->data_len = data_len;
  message->data.dynamic_data = data;

  ssh_pm_queue_message(engine, message);
}

void
ssh_pme_set_engine_params(SshEngine engine,
                          const SshEngineParams params)
{
  SshEngineMessage message;
  unsigned char *data;
  size_t data_len;

  data_len =
    ssh_encode_array_alloc(
        &data,
        SSH_ENCODE_UINT32((params ? TRUE : FALSE)),
        SSH_ENCODE_UINT32((params ? params->min_ttl_value : 0)),
        SSH_ENCODE_BOOLEAN((params ? params->do_not_decrement_ttl : FALSE)),
        SSH_ENCODE_BOOLEAN((params ? params->optimize_routing : FALSE)),
        SSH_ENCODE_BOOLEAN((params ? params->audit_corrupt : 0)),
        SSH_ENCODE_BOOLEAN((params ? params->drop_if_cannot_audit : 0)),
        SSH_ENCODE_BOOLEAN((params ? params->broadcast_icmp : 0)),
        SSH_ENCODE_UINT32((params ? params->audit_total_rate_limit : 0)),
        SSH_ENCODE_UINT32((params ? params->flow_rate_allow_threshold : 0)),
        SSH_ENCODE_UINT32((params ? params->flow_rate_limit_threshold : 0)),
        SSH_ENCODE_UINT32((params ? params->flow_rate_max_share : 0)),
        SSH_ENCODE_UINT32((params ? params->transform_dpd_timeout : 0)),
        SSH_ENCODE_UINT32((params ? params->fragmentation_policy : 0)),
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
        SSH_ENCODE_UINT32((params ? params->natt_keepalive_interval : 0)),
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
        SSH_FORMAT_END);

  if (data_len == 0)
    return;

  message = ssh_pm_alloc_message(engine, SSH_PEA_SET_PARAMS, FALSE, TRUE);
  if (message == NULL)
    {
      ssh_free(data);
      return;
    }

  message->data_len = data_len;
  message->data.dynamic_data = data;

  ssh_pm_queue_message(engine, message);
}


/* Request audit events from the engine. */
void
ssh_pme_get_audit_events(SshEngine engine, SshUInt32 num_events,
                         SshPmeAuditCB callback,
                         void *callback_context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_AUDIT_EVENTS,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, FALSE, 0, 0, NULL, callback_context);
      return;
    }

  SSH_VERIFY((message->data_len =
              ssh_encode_array(message->data.static_data,
                               sizeof(message->data.static_data),
                               SSH_ENCODE_UINT32(message->next),
                               SSH_ENCODE_UINT32(num_events),
                               SSH_FORMAT_END)) != 0);

  message->cb.audit_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
}

void
ssh_pme_process_packet(SshEngine engine,
                       SshUInt32 tunnel_id,
                       SshInterceptorProtocol protocol,
                       SshUInt32 ifnum,
                       SshVriId routing_instance_id,
                       SshUInt32 flags,
                       SshUInt32 prev_transform_index,
                       const unsigned char *packet,
                       size_t packet_len)
{
  SshEngineMessage message;
  unsigned char *data;
  size_t data_len;

  if (flags & SSH_PME_PACKET_DONT_REPROCESS)
    return;

  data_len = ssh_encode_array_alloc(&data,
                                    SSH_ENCODE_UINT32(tunnel_id),
                                    SSH_ENCODE_UINT32((SshUInt32) protocol),
                                    SSH_ENCODE_UINT32(ifnum),
                                    SSH_ENCODE_UINT32(
                                    (SshUInt32) routing_instance_id),
                                    SSH_ENCODE_UINT32(flags),
                                    SSH_ENCODE_UINT32(prev_transform_index),
                                    SSH_ENCODE_UINT32_STR(packet, packet_len),
                                    SSH_FORMAT_END);
  if (data_len == 0)
    return;

  message = ssh_pm_alloc_message(engine, SSH_PEA_PROCESS_PACKET, FALSE, TRUE);
  if (message == NULL)
    {
      ssh_free(data);
      return;
    }

  message->data_len = data_len;
  message->data.dynamic_data = data;

  ssh_pm_queue_message(engine, message);
}

#ifdef SSHDIST_IPSEC_NAT
void
ssh_pme_set_interface_nat(SshEngine engine,
                          SshUInt32 ifnum,
                          SshPmNatType type,
                          SshPmNatFlags flags,
                          const SshIpAddr host_nat_int_base,
                          const SshIpAddr host_nat_ext_base,
                          SshUInt32 host_nat_num_ips)


{
  SshEngineMessage message;
  unsigned char int_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char ext_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t int_ip_len, ext_ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_SET_INTERFACE_NAT, FALSE,
                                 FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  int_ip_len = ext_ip_len = 0;

  if (host_nat_int_base)
    int_ip_len = ssh_encode_ipaddr_array(int_ip_buf,
                                         sizeof(int_ip_buf),
                                         host_nat_int_base);

  if (host_nat_ext_base)
    ext_ip_len = ssh_encode_ipaddr_array(ext_ip_buf,
                                         sizeof(ext_ip_buf),
                                         host_nat_ext_base);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_ENCODE_UINT32((SshUInt32) type),
                       SSH_ENCODE_UINT32((SshUInt32) flags),
                       SSH_ENCODE_UINT32_STR(
                       int_ip_buf, int_ip_len),
                       SSH_ENCODE_UINT32_STR(
                       ext_ip_buf, ext_ip_len),
                       SSH_ENCODE_UINT32(
                       host_nat_num_ips),
                       SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  ssh_pm_queue_message(engine, message);
}

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
void
ssh_pme_configure_internal_nat(SshEngine engine,
                               const SshIpAddr first_ip,
                               const SshIpAddr last_ip,
                               SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char first_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t first_ip_len;
  unsigned char last_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t last_ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_CONFIGURE_INTERNAL_NAT, TRUE,
                                 FALSE);
  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, FALSE, context);
      return;
    }

  first_ip_len = ssh_encode_ipaddr_array(first_ip_buf, sizeof(first_ip_buf),
                                         first_ip);
  SSH_ASSERT(first_ip_len != 0);

  last_ip_len = ssh_encode_ipaddr_array(last_ip_buf, sizeof(last_ip_buf),
                                        last_ip);
  SSH_ASSERT(last_ip_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32_STR(first_ip_buf, first_ip_len),
                       SSH_ENCODE_UINT32_STR(last_ip_buf, last_ip_len),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

/********************** Manipulating transform objects **********************/

void
ssh_pme_create_transform(SshEngine engine,
                         SshEngineTransform params,
                         SshUInt32 life_seconds,
                         SshUInt32 life_kilobytes,
                         SshPmeIndexCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char *trd_data;
  size_t trd_data_len = 0;
  unsigned char *data;
  size_t data_len = 0;

  trd_data_len = ssh_pm_api_encode_transform_data(&trd_data, params);
  if (trd_data_len == 0)
    goto error;

  data_len
    = ssh_encode_array_alloc(&data,
                             /* Operation index. */
                             SSH_ENCODE_UINT32((SshUInt32) 0),

                             SSH_ENCODE_UINT32_STR(trd_data, trd_data_len),
                             SSH_ENCODE_UINT32(life_seconds),
                             SSH_ENCODE_UINT32(life_kilobytes),

                             SSH_FORMAT_END);
  if (data_len == 0)
    goto error;

  message = ssh_pm_alloc_message(engine, SSH_PEA_CREATE_TRANSFORM, TRUE, TRUE);
  if (message == NULL)
    goto error;

  /* Set operation index. */
  SSH_PUT_32BIT(data, message->next);

  message->data_len = data_len;
  message->data.dynamic_data = data;

  message->cb.index_cb = callback;
  message->cb_context = context;

  /* Free the transform data since it is included in to our final
     message data. */
  ssh_free(trd_data);

  ssh_pm_queue_message(engine, message);

  return;


  /* Error handling. */

 error:

  if (data_len)
    ssh_free(data);

  if (trd_data_len)
    ssh_free(trd_data);

  (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, context);
}


void
ssh_pme_delete_transform(SshEngine engine, SshUInt32 transform_index)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_DELETE_TRANSFORM,
                                 FALSE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  ssh_pm_queue_message(engine, message);
}

void
ssh_pme_delete_by_spi(SshEngine engine, SshUInt32 transform_index,
                      SshPmeTransformCB callback, void *context)
{
  SshEngineMessage message;
  Boolean async_op;

  async_op = callback ? TRUE : FALSE;

  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_DELETE_BY_SPI,
                                 async_op, FALSE);
  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, NULL, context);
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_BOOLEAN(async_op),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.transform_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}



void
ssh_pme_rekey_transform_inbound(SshEngine engine,
                                SshUInt32 transform_index,
                                const SshUInt32 new_in_spis[3],
                                const unsigned char
                                keymat_in[SSH_IPSEC_MAX_KEYMAT_LEN / 2],
                                SshUInt32 life_seconds,
                                SshUInt32 life_kilobytes,
                                SshUInt32 flags,
                                SshPmeTransformCB callback,
                                void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_REKEY_INBOUND, TRUE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_ENCODE_UINT32(new_in_spis[0]),
                       SSH_ENCODE_UINT32(new_in_spis[1]),
                       SSH_ENCODE_UINT32(new_in_spis[2]),

                       SSH_ENCODE_DATA(
                       keymat_in, SSH_IPSEC_MAX_KEYMAT_LEN / 2),

                       SSH_ENCODE_UINT32(life_seconds),
                       SSH_ENCODE_UINT32(life_kilobytes),
                       SSH_ENCODE_UINT32(flags),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.transform_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_rekey_transform_outbound(SshEngine engine,
                                 SshUInt32 transform_index,
                                 const SshUInt32 new_out_spis[3],
                                 const unsigned char
                                 keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN/2],
#ifdef SSH_IPSEC_TCPENCAP
                                 unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                 SshUInt32 flags,
                                 SshPmeStatusCB callback,
                                 void *context)
{
  SshEngineMessage message;
#ifdef SSH_IPSEC_TCPENCAP
  size_t tcp_encaps_conn_spi_len = 0;

  if (tcp_encaps_conn_spi)
    tcp_encaps_conn_spi_len = SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH;
#endif /* SSH_IPSEC_TCPENCAP */

  message = ssh_pm_alloc_message(engine, SSH_PEA_REKEY_OUTBOUND, TRUE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_ENCODE_UINT32(new_out_spis[0]),
                       SSH_ENCODE_UINT32(new_out_spis[1]),
                       SSH_ENCODE_UINT32(new_out_spis[2]),

                       SSH_ENCODE_DATA(
                       keymat_out, SSH_IPSEC_MAX_KEYMAT_LEN / 2),
#ifdef SSH_IPSEC_TCPENCAP
                       SSH_ENCODE_UINT32_STR(
                       tcp_encaps_conn_spi, tcp_encaps_conn_spi_len),
#endif /* SSH_IPSEC_TCPENCAP */
                       SSH_ENCODE_UINT32(flags),

                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

void ssh_pme_transform_invalidate_old_inbound(SshEngine engine,
                                              SshUInt32 transform_index,
                                              SshUInt32 inbound_spi,
                                              SshPmeTransformCB callback,
                                              void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_REKEY_INVALIDATE_OLD_INBOUND,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_ENCODE_UINT32(inbound_spi),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.transform_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

#ifdef SSHDIST_L2TP
void
ssh_pme_update_transform_l2tp_info(SshEngine engine,
                                   SshUInt32 transform_index,
                                   SshUInt8 flags,
                                   SshUInt16 local_tunnel_id,
                                   SshUInt16 local_session_id,
                                   SshUInt16 remote_tunnel_id,
                                   SshUInt16 remote_session_id)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_UPDATE_L2TP, FALSE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_ENCODE_UINT32((SshUInt32) flags),
                       SSH_ENCODE_UINT32((SshUInt32) local_tunnel_id),
                       SSH_ENCODE_UINT32((SshUInt32) local_session_id),
                       SSH_ENCODE_UINT32((SshUInt32) remote_tunnel_id),
                       SSH_ENCODE_UINT32((SshUInt32) remote_session_id),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  ssh_pm_queue_message(engine, message);
}
#endif /* SSHDIST_L2TP */


/********************* Creating and manipulating rules **********************/

void
ssh_pme_add_rule(SshEngine engine, Boolean rekey,
                 const SshEnginePolicyRule rule,
                 SshPmeAddRuleCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char *rule_data;
  size_t rule_data_len;
  unsigned char *data;
  size_t data_len;

  data_len = 0;

  rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
  if (rule_data_len == 0)
    goto error;

  data_len
    = ssh_encode_array_alloc(&data,
                             /* Operation index. */
                             SSH_ENCODE_UINT32((SshUInt32) 0),
                             SSH_ENCODE_BOOLEAN(rekey),
                             SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                             SSH_FORMAT_END);
  if (data_len == 0)
    goto error;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ADD_RULE, TRUE, TRUE);
  if (message == NULL)
    goto error;

  /* Set operation index. */
  SSH_PUT_32BIT(data, message->next);

  message->data_len = data_len;
  message->data.dynamic_data = data;

  message->cb.add_rule_cb = callback;
  message->cb_context = context;

  /* Free rule data. */
  ssh_free(rule_data);

  ssh_pm_queue_message(engine, message);

  return;

  /* Error handling. */

 error:

  if (data_len)
    ssh_free(data);

  if (rule_data_len)
    ssh_free(rule_data);

  (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX,
              NULL,
              context);
}



void
ssh_pme_delete_rule(SshEngine engine,
                    SshUInt32 rule_index,
                    SshPmeDeleteCB callback,
                    void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_DELETE_RULE, TRUE, FALSE);
  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, TRUE, SSH_IPSEC_INVALID_INDEX,
                    SSH_IPSEC_INVALID_INDEX, NULL, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(rule_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.delete_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_find_transform_rule(SshEngine engine,
                            SshUInt32 tunnel_id,
                            SshUInt32 ifnum,
                            const SshIpAddr src_ip,
                            const SshIpAddr dst_ip,
                            SshUInt8 ipproto,
                            SshUInt16 src_port,
                            SshUInt16 dst_port,
                            SshUInt32 impl_tunnel_id,
                            SshUInt32 trd_index,
                            SshUInt32 flags,
                            SshPmeSAIndexCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char src_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t src_ip_len;
  unsigned char dst_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t dst_ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_FIND_TRANSFORM_RULE, TRUE,
                                 FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, 0, 0, context);
      return;
    }

  src_ip_len = ssh_encode_ipaddr_array(src_ip_buf, sizeof(src_ip_buf), src_ip);
  SSH_ASSERT(src_ip_len != 0);

  dst_ip_len = ssh_encode_ipaddr_array(dst_ip_buf, sizeof(dst_ip_buf), dst_ip);
  SSH_ASSERT(dst_ip_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(tunnel_id),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_ENCODE_UINT32_STR(src_ip_buf, src_ip_len),
                       SSH_ENCODE_UINT32_STR(dst_ip_buf, dst_ip_len),
                       SSH_ENCODE_UINT32((SshUInt32) ipproto),
                       SSH_ENCODE_UINT32((SshUInt32) src_port),
                       SSH_ENCODE_UINT32((SshUInt32) dst_port),
                       SSH_ENCODE_UINT32(impl_tunnel_id),
                       SSH_ENCODE_UINT32(trd_index),
                       SSH_ENCODE_UINT32(flags),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.sa_index_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_find_matching_transform_rule(SshEngine engine,
                                     const SshEnginePolicyRule rule,
                                     SshPmTransform transform,
                                     SshUInt32 cipher_key_size,
                                     const SshIpAddr peer_ip,
                                     const SshIpAddr local_ip,
                                     SshUInt16 local_port,
                                     SshUInt16 remote_port,
                                     const unsigned char *peer_id,
                                     SshUInt32 flags,
                                     SshPmeSAIndexCB callback,
                                     void *context)
{
  SshEngineMessage message;
  unsigned char *rule_data;
  size_t rule_data_len;
  unsigned char *data;
  size_t data_len;
  unsigned char peer_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char local_ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t peer_ip_len, local_ip_len, peer_id_len;

  data_len = 0;

  rule_data_len = ssh_pm_api_encode_policy_rule(&rule_data, rule);
  if (rule_data_len == 0)
    goto error;

  peer_ip_len = 0;
  peer_id_len = 0;
  if (peer_ip != NULL)
    {
      peer_ip_len = ssh_encode_ipaddr_array(peer_ip_buf, sizeof(peer_ip_buf),
                                            peer_ip);
      SSH_ASSERT(peer_ip_len != 0);
    }

  local_ip_len = 0;
  if (local_ip != NULL)
    {
      local_ip_len = ssh_encode_ipaddr_array(local_ip_buf,
                                             sizeof(local_ip_buf),
                                             local_ip);
      SSH_ASSERT(local_ip_len != 0);
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (peer_id)
    peer_id_len = SSH_ENGINE_PEER_ID_SIZE;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  data_len
    = ssh_encode_array_alloc(&data,
                             /* Operation index. */
                             SSH_ENCODE_UINT32((SshUInt32) 0),
                             SSH_ENCODE_UINT32_STR(rule_data, rule_data_len),
                             SSH_ENCODE_UINT64(transform),
                             SSH_ENCODE_UINT32(cipher_key_size),
                             SSH_ENCODE_UINT32_STR(peer_ip_buf, peer_ip_len),
                             SSH_ENCODE_UINT32_STR(local_ip_buf, local_ip_len),
                             SSH_ENCODE_UINT32((SshUInt32) local_port),
                             SSH_ENCODE_UINT32((SshUInt32) remote_port),
                             SSH_ENCODE_UINT32_STR(peer_id, peer_id_len),
                             SSH_ENCODE_UINT32(flags),
                             SSH_FORMAT_END);
  if (data_len == 0)
    goto error;

  message = ssh_pm_alloc_message(engine, SSH_PEA_FIND_MATCHING_TRANSFORM_RULE,
                                 TRUE, TRUE);
  if (message == NULL)
    goto error;

  /* Set operation index. */
  SSH_PUT_32BIT(data, message->next);

  message->data_len = data_len;
  message->data.dynamic_data = data;

  message->cb.sa_index_cb = callback;
  message->cb_context = context;

  /* Free rule data. */
  ssh_free(rule_data);

  ssh_pm_queue_message(engine, message);

  return;

  /* Error handling. */

 error:

  if (data_len)
    ssh_free(data);

  if (rule_data_len)
    ssh_free(rule_data);

  (*callback)(engine->pm, NULL, 0, 0, context);
}


void
ssh_pme_have_transform_with_peer(SshEngine engine,
                                 const SshIpAddr ip_addr,
                                 SshUInt16 remote_ike_port,
                                 SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_HAVE_TRANSFORM_WITH_PEER,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  ip_len = ssh_encode_ipaddr_array(ip_buf, sizeof(ip_buf), ip_addr);
  SSH_ASSERT(ip_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32_STR(ip_buf, ip_len),
                       SSH_ENCODE_UINT32((SshUInt32) remote_ike_port),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

void ssh_pme_delete_by_peer_handle(SshEngine engine,
                                   SshUInt32 peer_handle,
                                   SshPmeDeleteTransformCB callback,
                                   void *context)
{
  SshEngineMessage message;
  Boolean async_op;

  async_op = callback ? TRUE : FALSE;

  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_DELETE_BY_PEER_HANDLE, async_op,
                                 FALSE);
  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, TRUE, SSH_IPSEC_INVALID_INDEX, NULL, NULL,
                    context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_BOOLEAN(async_op),
                       SSH_ENCODE_UINT32((SshUInt32) peer_handle),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.delete_transform_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

void ssh_pme_update_by_peer_handle(SshEngine engine,
                                   SshUInt32 peer_handle,
                                   Boolean enable_natt,
                                   SshVriId routing_instance_id,
                                   SshIpAddr local_ip,
                                   SshIpAddr remote_ip,
                                   SshUInt16 remote_port,
#ifdef SSH_IPSEC_TCPENCAP
                                   unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                   SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;
  Boolean async_op;
  unsigned char remote[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char local[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t remote_len;
  size_t local_len;
#ifdef SSH_IPSEC_TCPENCAP
  size_t tcp_encaps_conn_spi_len = 0;
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_ASSERT(SSH_IP_DEFINED(local_ip));
  SSH_ASSERT(SSH_IP_DEFINED(remote_ip));

  SSH_ASSERT((SSH_IP_IS6(local_ip) && SSH_IP_IS6(remote_ip)) ||
             (SSH_IP_IS4(local_ip) && SSH_IP_IS4(remote_ip)));

  /* This should never happen but just in case.... */
  if ((SSH_IP_IS6(local_ip) && !SSH_IP_IS6(remote_ip)) ||
      (SSH_IP_IS4(local_ip) && !SSH_IP_IS4(remote_ip)))
    {
      SSH_DEBUG(SSH_D_ERROR, ("IP address families are not the same"));
      if (callback)
        (*callback)(engine->pm, FALSE, context);
      return;
    }

  async_op = callback ? TRUE : FALSE;
  message = ssh_pm_alloc_message(engine, SSH_PEA_UPDATE_BY_PEER_HANDLE,
                                 async_op, FALSE);
  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, FALSE, context);
      return;
    }

  local_len = ssh_encode_ipaddr_array(local, sizeof(local), local_ip);
  remote_len = ssh_encode_ipaddr_array(remote, sizeof(remote), remote_ip);

  SSH_ASSERT(local_len != 0);
  SSH_ASSERT(remote_len != 0);

#ifdef SSH_IPSEC_TCPENCAP
  if (tcp_encaps_conn_spi)
    tcp_encaps_conn_spi_len = SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH;
#endif /* SSH_IPSEC_TCPENCAP */

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_BOOLEAN(async_op),
                       SSH_ENCODE_UINT32(peer_handle),
                       SSH_ENCODE_BOOLEAN(enable_natt),
                       SSH_ENCODE_UINT32((SshUInt32)routing_instance_id),
                       SSH_ENCODE_UINT32_STR(local, local_len),
                       SSH_ENCODE_UINT32_STR(remote, remote_len),
                       SSH_ENCODE_UINT32((SshUInt32)remote_port),
#ifdef SSH_IPSEC_TCPENCAP
                       SSH_ENCODE_UINT32_STR(
                       tcp_encaps_conn_spi, tcp_encaps_conn_spi_len),
#endif /* SSH_IPSEC_TCPENCAP */
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

void
ssh_pme_get_rule(SshEngine engine, SshUInt32 rule_index, SshPmeRuleCB callback,
                 void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_RULE, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  SSH_ASSERT(rule_index < SSH_ENGINE_MAX_RULES);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(rule_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.rule_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_transform(SshEngine engine, SshUInt32 trd_index,
                      SshPmeTransformCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_TRANSFORM, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(trd_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.transform_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_add_reference_to_rule(SshEngine engine, SshUInt32 rule_index,
                              SshUInt32 transform_index,
                              SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ADD_REFERENCE_TO_RULE,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(rule_index),
                       SSH_ENCODE_UINT32(transform_index),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

#ifdef SSH_IPSEC_STATISTICS
/************* Querying statistics information from the engine **************/

void
ssh_pme_get_global_stats(SshEngine engine,
                         SshPmeGlobalStatsCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_GLOBAL_STATS, TRUE,
                                 FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, NULL, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.global_stats_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_next_flow_index(SshEngine engine,
                            SshUInt32 flow_index,
                            SshPmeIndexCB callback,
                            void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_NEXT_FLOW_INDEX,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(flow_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_flow_info(SshEngine engine, SshUInt32 flow_index,
                      SshPmeFlowInfoCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_FLOW_INFO, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(flow_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.flow_info_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_flow_stats(SshEngine engine, SshUInt32 flow_index,
                       SshPmeFlowStatsCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_FLOW_STATS, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(flow_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.flow_stats_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_next_transform_index(SshEngine engine,
                                 SshUInt32 transform_index,
                                 SshPmeIndexCB callback,
                                 void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_NEXT_TRANSFORM_INDEX,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(transform_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_transform_stats(SshEngine engine, SshUInt32 transform_index,
                            SshPmeTransformStatsCB callback,
                            void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_TRANSFORM_STATS, TRUE,
                                 FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(transform_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.transform_stats_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_next_rule_index(SshEngine engine,
                            SshUInt32 rule_index,
                            SshPmeIndexCB callback,
                            void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_NEXT_RULE_INDEX,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(rule_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_get_rule_stats(SshEngine engine, SshUInt32 rule_index,
                       SshPmeRuleStatsCB callback, void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_GET_RULE_STATS, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),
                                       SSH_ENCODE_UINT32(rule_index),
                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.rule_stats_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}
#endif /* SSH_IPSEC_STATISTICS */

/********************** Route handling functions. **********************/

void
ssh_pme_route(SshEngine engine, SshUInt32 flags,
              SshInterceptorRouteKey key,
              SshPmeRouteCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char dst_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char src_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t dst_len, src_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ROUTE, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, 0, 0, NULL, 0, context);
      return;
    }

  dst_len = ssh_encode_ipaddr_array(dst_buf, sizeof(dst_buf), &key->dst);
  SSH_ASSERT(dst_len != 0);

  if (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
    {
      src_len = ssh_encode_ipaddr_array(src_buf, sizeof(src_buf), &key->src);
    }
  else
    {
      SSH_IP_UNDEFINE(&key->src);
      src_len = ssh_encode_ipaddr_array(src_buf, sizeof(src_buf), &key->src);
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(flags),
                       SSH_ENCODE_UINT32_STR(dst_buf, dst_len),
                       SSH_ENCODE_UINT32_STR(src_buf, src_len),
                       SSH_ENCODE_UINT32(key->ipproto),
                       SSH_ENCODE_UINT32(key->ifnum),
                       SSH_ENCODE_UINT32(key->selector),
                       SSH_ENCODE_UINT16(key->th.tcp.dst_port),
                       SSH_ENCODE_UINT16(key->th.tcp.src_port),
                       SSH_ENCODE_UINT32(key->routing_instance_id),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.route_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


static void
ssh_pme_route_modify(SshEngine engine,
                     Boolean add,
                     SshInterceptorRouteKey key,
                     const SshIpAddr gateway,
                     SshUInt32 ifnum,
                     SshRoutePrecedence precedence,
                     SshUInt32 flags,
                     SshPmeRouteSuccessCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char key_dst[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char key_src[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char gw[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t key_dst_len, key_src_len, gw_len;
  SshIpAddrStruct src;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char key_ext[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * 4];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (add)
    message = ssh_pm_alloc_message(engine, SSH_PEA_ROUTE_ADD, TRUE, FALSE);
  else
    message = ssh_pm_alloc_message(engine, SSH_PEA_ROUTE_REMOVE, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, context);
      return;
    }

  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));
  key_dst_len = ssh_encode_ipaddr_array(key_dst, sizeof(key_dst), &key->dst);
  SSH_ASSERT(key_dst_len != 0);

  if ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC) != 0)
    key_src_len = ssh_encode_ipaddr_array(key_src, sizeof(key_src), &key->src);
  else
    {
      SSH_IP_UNDEFINE(&src);
      key_src_len = ssh_encode_ipaddr_array(key_src, sizeof(key_src), &src);
    }
  SSH_ASSERT(key_src_len != 0);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      SSH_PUT_32BIT(key_ext + 4 * i, key->extension[i]);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  gw_len = ssh_encode_ipaddr_array(gw, sizeof(gw), gateway);
  SSH_ASSERT(gw_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32_STR(key_dst, key_dst_len),
                       SSH_ENCODE_UINT32_STR(key_src, key_src_len),
                       SSH_ENCODE_UINT32(key->ipproto),
                       SSH_ENCODE_UINT32(key->ifnum),
                       SSH_ENCODE_UINT32_STR(key->nh.raw,
                                             sizeof(key->nh.raw)),
                       SSH_ENCODE_UINT32_STR(key->th.raw,
                                             sizeof(key->th.raw)),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                       SSH_ENCODE_UINT32_STR(key_ext, sizeof(key_ext)),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                       SSH_ENCODE_UINT32(key->selector),
                       SSH_ENCODE_UINT32_STR(gw, gw_len),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_ENCODE_UINT32(precedence),
                       SSH_ENCODE_UINT32(flags),
                       SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  message->cb.route_success_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_route_add(SshEngine engine,
                  SshInterceptorRouteKey key,
                  const SshIpAddr gateway,
                  SshUInt32 ifnum,
                  SshRoutePrecedence precedence,
                  SshUInt32 flags,
                  SshPmeRouteSuccessCB callback, void *context)
{
  ssh_pme_route_modify(engine, TRUE, key, gateway, ifnum, precedence, flags,
                       callback, context);
}


void
ssh_pme_route_remove(SshEngine engine,
                     SshInterceptorRouteKey key,
                     const SshIpAddr gateway,
                     SshUInt32 ifnum,
                     SshRoutePrecedence precedence,
                     SshUInt32 flags,
                     SshPmeRouteSuccessCB callback, void *context)
{
  ssh_pme_route_modify(engine, FALSE, key, gateway, ifnum, precedence, flags,
                       callback, context);
}

#ifdef SSH_IPSEC_INTERNAL_ROUTING

void
ssh_pme_configure_route_clear(SshEngine engine)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_CONFIGURE_ROUTE_CLEAR,
                                 FALSE, FALSE);
  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  message->data_len = 0;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_configure_route_add(SshEngine engine,
                            const SshIpAddr dst_and_mask,
                            const SshIpAddr next_hop,
                            SshUInt32 ifnum,
                            SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char dst_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t dst_len;
  unsigned char next_hop_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t next_hop_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_CONFIGURE_ROUTE_ADD,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  dst_len = ssh_encode_ipaddr_array(dst_buf, sizeof(dst_buf), dst_and_mask);
  SSH_ASSERT(dst_len != 0);

  next_hop_len = ssh_encode_ipaddr_array(next_hop_buf, sizeof(next_hop_buf),
                                         next_hop);
  SSH_ASSERT(next_hop_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32_STR(dst_buf, dst_len),
                       SSH_ENCODE_UINT32_STR(next_hop_buf, next_hop_len),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

#endif /* SSH_IPSEC_INTERNAL_ROUTING */

/****************************** ARP  functions ******************************/

void
ssh_pme_arp_add(SshEngine engine, const SshIpAddr ip, SshUInt32 ifnum,
                const unsigned char *media_addr, size_t media_addr_len,
                SshUInt32 flags, SshPmeStatusCB callback, void *context)
{
  SshEngineMessage message;
  unsigned char ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ARP_ADD, TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  /* Encode IP address. */
  ip_len = ssh_encode_ipaddr_array(ip_buf, sizeof(ip_buf), ip);
  SSH_ASSERT(ip_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32_STR(ip_buf, ip_len),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_ENCODE_UINT32_STR(media_addr, media_addr_len),
                       SSH_ENCODE_UINT32(flags),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}


void
ssh_pme_arp_remove(SshEngine engine, const SshIpAddr ip, SshUInt32 ifnum)
{
  SshEngineMessage message;
  unsigned char ip_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t ip_len;

  message = ssh_pm_alloc_message(engine, SSH_PEA_ARP_REMOVE, FALSE, FALSE);
  if (message == NULL)
    return;

  /* Encode IP address. */
  ip_len = ssh_encode_ipaddr_array(ip_buf, sizeof(ip_buf), ip);
  SSH_ASSERT(ip_len != 0);

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32_STR(ip_buf, ip_len),
                       SSH_ENCODE_UINT32(ifnum),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  ssh_pm_queue_message(engine, message);
}

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/************************ Virtual adapter functions *************************/

void
ssh_pme_virtual_adapter_configure(SshEngine engine,
                                  SshUInt32 adapter_ifnum,
                                  SshVirtualAdapterState adapter_state,
                                  SshUInt32 num_addresses,
                                  SshIpAddr addresses,
                                  SshVirtualAdapterParams params,
                                  SshPmeVirtualAdapterStatusCB callback,
                                  void *context)
{
  unsigned char *data = NULL;
  size_t data_len = 0;
  SshEngineMessage message;
  SshBufferStruct ip_buffer;
  unsigned char *param_ptr = NULL;
  size_t param_len;
  SshUInt32 i;
  SshIpAddrStruct undefined_ip;

  /* Encode addresses and params. */
  ssh_buffer_init(&ip_buffer);

  /* Encode "clear all addresses" as one undefined address. */
  if (num_addresses == 0 && addresses != NULL)
    {
      SSH_IP_UNDEFINE(&undefined_ip);
      addresses = &undefined_ip;
      num_addresses = 1;
    }

  for (i = 0; i < num_addresses; i++)
    if (!ssh_encode_ipaddr_buffer(&ip_buffer, &addresses[i]))
      goto error;

  param_len = 0;
  if (params)
    {
      if (!ssh_virtual_adapter_param_encode(params, &param_ptr, &param_len))
        goto error;
    }

  data_len
    = ssh_encode_array_alloc(&data,
                             /* Operation index. */
                             SSH_ENCODE_UINT32((SshUInt32) 0),
                             SSH_ENCODE_UINT32(adapter_ifnum),
                             SSH_ENCODE_UINT32(adapter_state),
                             SSH_ENCODE_UINT32(num_addresses),
                             SSH_ENCODE_UINT32_STR(
                             ssh_buffer_ptr(&ip_buffer),
                             ssh_buffer_len(&ip_buffer)),
                             SSH_ENCODE_UINT32_STR(param_ptr, param_len),
                             SSH_FORMAT_END);
  if (data_len == 0)
    goto error;

  message = ssh_pm_alloc_message(engine, SSH_PEA_VIRTUAL_ADAPTER_CONFIGURE,
                                 TRUE, TRUE);
  if (message == NULL)
    goto error;

  /* Set operation index. */
  SSH_PUT_32BIT(data, message->next);
  message->data_len = data_len;
  message->data.dynamic_data = data;
  message->cb.virtual_adapter_status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);

  /* Cleanup. */
  ssh_buffer_uninit(&ip_buffer);
  ssh_free(param_ptr);

  /* All done. */
  return;

  /* Error handling. */
 error:
  if (data_len)
    ssh_free(data);

  ssh_buffer_uninit(&ip_buffer);
  ssh_free(param_ptr);

  (*callback)(engine->pm, SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY, 0, NULL,
              context);
}


void
ssh_pme_virtual_adapter_list(SshEngine engine,
                             SshUInt32 adapter_ifnum,
                             SshPmeVirtualAdapterStatusCB callback,
                             void *context)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_VIRTUAL_ADAPTER_LIST,
                                 TRUE, FALSE);
  if (message == NULL)
    {
      (*callback)(engine->pm, SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                  0, NULL, context);
      return;
    }

  message->data_len
    = ssh_encode_array(message->data.static_data,
                       sizeof(message->data.static_data),
                       SSH_ENCODE_UINT32(message->next),
                       SSH_ENCODE_UINT32(adapter_ifnum),
                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.virtual_adapter_status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/*********************** Flow manipulation functions ************************/

/* Switch flow status between "pass/drop packets". */
void
ssh_pme_flow_set_status(SshEngine engine,
                        SshUInt32 flow_index,
                        SshPmeFlowStatus flow_status,
                        SshPmeStatusCB callback, void *context)
{
  Boolean async_op;
  SshEngineMessage message;

  if (callback)
    async_op = TRUE;
  else
    async_op = FALSE;

  message = ssh_pm_alloc_message(engine, SSH_PEA_FLOW_SET_STATUS,
                                 async_op, FALSE);

  if (message == NULL)
    {
      if (callback)
        (*callback)(engine->pm, FALSE, context);
      return;
    }

  message->data_len = ssh_encode_array(message->data.static_data,
                                   sizeof(message->data.static_data),
                                   SSH_ENCODE_UINT32(message->next),
                                   SSH_ENCODE_BOOLEAN(async_op),
                                   SSH_ENCODE_UINT32(flow_index),
                                   SSH_ENCODE_UINT32((SshUInt32)flow_status),
                                   SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  message->cb.status_cb = callback;
  message->cb_context = context;

  ssh_pm_queue_message(engine, message);
}

/* Grand "repolicy all flows" function */
void
ssh_pme_redo_flows(SshEngine engine)
{
  SshEngineMessage message;

  message = ssh_pm_alloc_message(engine, SSH_PEA_REDO_FLOWS,
                                 FALSE, FALSE);

  if (message == NULL)
    {
      return;
    }

  ssh_pm_queue_message(engine, message);
}

#ifdef SSH_IPSEC_TCPENCAP

Boolean
ssh_pme_tcp_encaps_add_configuration(SshEngine engine,
                                     SshIpAddr local_addr,
                                     SshUInt16 local_port,
                                     SshIpAddr peer_lo_addr,
                                     SshIpAddr peer_hi_addr,
                                     SshUInt16 peer_port,
                                     SshUInt16 local_ike_port,
                                     SshUInt16 remote_ike_port)
{
  SshEngineMessage message;
  unsigned char local_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char peer_lo_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char peer_hi_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t local_addr_len, peer_lo_addr_len, peer_hi_addr_len;
  unsigned char *data;
  size_t data_len;

  SSH_ASSERT(local_addr != NULL);
  SSH_ASSERT(peer_lo_addr != NULL);
  SSH_ASSERT(peer_hi_addr != NULL);

  /* Encode IP addresses. */
  local_addr_len = ssh_encode_ipaddr_array(local_addr_buf,
                                           sizeof(local_addr_buf),
                                           local_addr);
  peer_lo_addr_len = ssh_encode_ipaddr_array(peer_lo_addr_buf,
                                             sizeof(peer_lo_addr_buf),
                                             peer_lo_addr);
  peer_hi_addr_len = ssh_encode_ipaddr_array(peer_hi_addr_buf,
                                             sizeof(peer_hi_addr_buf),
                                             peer_hi_addr);
  SSH_ASSERT(local_addr_len != 0 &&
             peer_lo_addr_len != 0 &&
             peer_hi_addr_len != 0);

  data_len =
    ssh_encode_array_alloc(&data,

                     SSH_ENCODE_UINT32_STR(local_addr_buf, local_addr_len),
                     SSH_ENCODE_UINT16(local_port),

                     SSH_ENCODE_UINT32_STR(peer_lo_addr_buf, peer_lo_addr_len),
                     SSH_ENCODE_UINT32_STR(peer_hi_addr_buf, peer_hi_addr_len),
                     SSH_ENCODE_UINT16(peer_port),

                     SSH_ENCODE_UINT16(local_ike_port),
                     SSH_ENCODE_UINT16(remote_ike_port),

                     SSH_FORMAT_END);

  if (data_len == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate buffer"));
      return FALSE;
    }

  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_TCP_ENCAPS_ADD_CONFIG,
                                 FALSE, TRUE);
  if (message == NULL)
    {
      ssh_free(data);
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return FALSE;
    }

  message->data_len = data_len;
  message->data.dynamic_data = data;

  ssh_pm_queue_message(engine, message);

  return TRUE;
}

void
ssh_pme_tcp_encaps_clear_configurations(SshEngine engine)
{
  SshEngineMessage message =
    ssh_pm_alloc_message(engine,
                         SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG,
                         FALSE, FALSE);

  if (message == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate message"));
      return;
    }

  ssh_pm_queue_message(engine, message);
}

void
ssh_pme_tcp_encaps_create_ike_mapping(SshEngine engine,
                                      SshIpAddr local_addr,
                                      SshIpAddr peer_addr,
                                      SshUInt16 local_port,
                                      SshUInt16 peer_port,
                                      unsigned char *ike_initiator_cookie,
                                      SshUInt16 local_ike_port,
                                      SshUInt16 remote_ike_port,
                                      SshPmeIndexCB callback,
                                      void *callback_context)
{
  SshEngineMessage message;
  size_t local_addr_len, peer_addr_len;
  unsigned char local_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char peer_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];

  SSH_ASSERT(local_addr != NULL);
  SSH_ASSERT(peer_addr != NULL);
  SSH_ASSERT(ike_initiator_cookie != NULL);
  SSH_ASSERT(callback != NULL);

  local_addr_len = ssh_encode_ipaddr_array(local_addr_buf,
                                           sizeof(local_addr_buf),
                                           local_addr);

  peer_addr_len = ssh_encode_ipaddr_array(peer_addr_buf,
                                          sizeof(peer_addr_buf),
                                          peer_addr);

  if (local_addr_len == 0 || peer_addr_len == 0)
    goto error;

  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING,
                                 TRUE, FALSE);
  if (message == NULL)
    goto error;

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),

                                       SSH_ENCODE_UINT32_STR(
                                       local_addr_buf, local_addr_len),
                                       SSH_ENCODE_UINT32_STR(
                                       peer_addr_buf, peer_addr_len),
                                       SSH_ENCODE_UINT16(local_port),
                                       SSH_ENCODE_UINT16(peer_port),
                                       SSH_ENCODE_UINT16(local_ike_port),
                                       SSH_ENCODE_UINT16(remote_ike_port),
                                       SSH_ENCODE_UINT32_STR(
                                       ike_initiator_cookie, 8),

                                       SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
  return;

 error:
  (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, callback_context);
}

void
ssh_pme_tcp_encaps_get_ike_mapping(SshEngine engine,
                                   SshIpAddr local_addr,
                                   SshIpAddr peer_addr,
                                   unsigned char *ike_initiator_cookie,
                                   SshPmeIndexCB callback,
                                   void *callback_context)
{
  SshEngineMessage message;
  size_t local_addr_len = 0, peer_addr_len = 0;
  unsigned char local_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char peer_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];

  SSH_ASSERT(ike_initiator_cookie != NULL);
  SSH_ASSERT(callback != NULL);

  if (local_addr)
    {
      local_addr_len = ssh_encode_ipaddr_array(local_addr_buf,
                                               sizeof(local_addr_buf),
                                               local_addr);
      if (local_addr_len == 0)
        goto error;
    }

  if (peer_addr)
    {
      peer_addr_len = ssh_encode_ipaddr_array(peer_addr_buf,
                                              sizeof(peer_addr_buf),
                                              peer_addr);
      if (peer_addr_len == 0)
        goto error;
    }

  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING,
                                 TRUE, FALSE);
  if (message == NULL)
    goto error;

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),

                                       SSH_ENCODE_UINT32_STR(
                                       local_addr_buf, local_addr_len),
                                       SSH_ENCODE_UINT32_STR(
                                       peer_addr_buf, peer_addr_len),
                                       SSH_ENCODE_UINT32_STR(
                                       ike_initiator_cookie, 8),

                                       SSH_FORMAT_END);
  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
  return;

 error:
  (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, callback_context);
}

void
ssh_pme_tcp_encaps_update_ike_mapping(SshEngine engine,
                                      Boolean keep_address_matches,
                                      SshIpAddr local_addr,
                                      SshIpAddr peer_addr,
                                      unsigned char *ike_initiator_cookie,
                                      unsigned char *new_ike_initiator_cookie,
                                      SshPmeIndexCB callback,
                                      void *callback_context)
{
  SshEngineMessage message;
  Boolean async_op;
  size_t local_addr_len = 0, peer_addr_len = 0;
  unsigned char local_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  unsigned char peer_addr_buf[SSH_MAX_IPADDR_ENCODED_LENGTH];
  size_t new_ike_initiator_cookie_len = 0;

  SSH_ASSERT(ike_initiator_cookie != NULL);

  /* New IKE SPI must be NULL or a valid IKE SPI. */
  SSH_ASSERT(new_ike_initiator_cookie == NULL
             || memcmp(ike_initiator_cookie, new_ike_initiator_cookie,
                       SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH) != 0);

  /* Addresses must be specified if keep_address_matches is TRUE. */
  SSH_ASSERT(keep_address_matches == FALSE ||
             (local_addr != NULL && peer_addr != NULL));

  if (local_addr)
    {
      local_addr_len = ssh_encode_ipaddr_array(local_addr_buf,
                                               sizeof(local_addr_buf),
                                               local_addr);
      if (local_addr_len == 0)
        goto error;
    }

  if (peer_addr)
    {
      peer_addr_len = ssh_encode_ipaddr_array(peer_addr_buf,
                                              sizeof(peer_addr_buf),
                                              peer_addr);
      if (peer_addr_len == 0)
        goto error;
    }

  async_op = (callback ? TRUE : FALSE);
  message = ssh_pm_alloc_message(engine,
                                 SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING,
                                 async_op, FALSE);
  if (message == NULL)
    goto error;

  if (new_ike_initiator_cookie != NULL)
    new_ike_initiator_cookie_len = SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH;

  message->data_len = ssh_encode_array(message->data.static_data,
                                       sizeof(message->data.static_data),
                                       SSH_ENCODE_UINT32(message->next),

                                       SSH_ENCODE_BOOLEAN(async_op),

                                       SSH_ENCODE_BOOLEAN(
                                       keep_address_matches),
                                       SSH_ENCODE_UINT32_STR(
                                       local_addr_buf, local_addr_len),
                                       SSH_ENCODE_UINT32_STR(
                                       peer_addr_buf, peer_addr_len),
                                       SSH_ENCODE_UINT32_STR(
                                       ike_initiator_cookie,
                                       SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH),

                                       SSH_ENCODE_UINT32_STR(
                                       new_ike_initiator_cookie,
                                       new_ike_initiator_cookie_len),

                                       SSH_FORMAT_END);

  SSH_ASSERT(message->data_len != 0);

  message->cb.index_cb = callback;
  message->cb_context = callback_context;

  ssh_pm_queue_message(engine, message);
  return;

 error:
  if (callback)
    (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, callback_context);
}

#endif /* SSH_IPSEC_TCPENCAP */




















































#endif /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
