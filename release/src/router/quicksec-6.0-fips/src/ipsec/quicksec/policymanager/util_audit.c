/**
   @copyright
   Copyright (c) 2003 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager audit callback storing the events into ring buffer
   and optionally sending them into syslog or file.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshaudit.h"
#include "sshaudit_syslog.h"
#include "sshaudit_file.h"

#include "util_engine.h"

#define SSH_DEBUG_MODULE "SshPmAudit"

#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL 0
#define SSH_PM_AUDIT_NUM_REQUESTS (2 * SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS)
#else
#define SSH_PM_AUDIT_MIN_REQUEST_INTERVAL \
        (1000000 / SSH_PM_AUDIT_REQUESTS_PER_SECOND)
#define SSH_PM_AUDIT_NUM_REQUESTS 10
#endif
/* The number of audit events that the policymanager requests the engine
   to send it each time it requests audit events from the engine. */


/************************************************************************/

/* Forward declarations */
static void ssh_pm_remove_audit_module(SshPm pm, SshUInt32 audit_id);

void
ssh_pm_audit_event(SshPm pm, SshUInt32 audit_subsystem,
                   SshAuditEvent event, ...)
{
  SshPmAuditModule module;
  va_list ap;

  module = pm->audit.modules;
  while (module)
    {
      if (module->audit_subsystems & audit_subsystem)
        {
          va_start(ap, event);
          ssh_audit_event_va(module->context, event, ap);
          va_end(ap);
        }
      module = module->next;
    }
}

static void ike_audit_callback(SshAuditEvent event, SshUInt32 argc,
                               SshAuditArgument argv, void *context)
{
  SshPm pm = context;
  SshPmAuditModule module;

  module = pm->audit.modules;
  while (module)
    {
      if (module->audit_subsystems & SSH_PM_AUDIT_IKE)
        {
          ssh_audit_event_array(module->context, event, argc, argv);
        }
      module = module->next;
    }
}

void ssh_pm_audit_get_engine_events_timer(void *context)
{
  SshPm pm = context;
  ssh_pm_audit_get_engine_events(pm);
}

/* Initialize the policy manager's audit framework. */
Boolean ssh_pm_audit_init(SshPm pm)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Initializing the PM audit module"));

  pm->audit.ike_audit = ssh_audit_create(ike_audit_callback, NULL_FNPTR, pm);

  if (pm->audit.ike_audit == NULL)
    return FALSE;

  pm->audit.request_interval = SSH_PM_AUDIT_MIN_REQUEST_INTERVAL;

  pm->audit.last_resource_failure_time = ssh_time();
  pm->audit.last_flood_time = ssh_time();

  if (pm->audit.request_interval != 0)
    ssh_register_timeout(&pm->audit.timer, 0, pm->audit.request_interval,
                         ssh_pm_audit_get_engine_events_timer, pm);

  return TRUE;
}

/* Uninitialize the audit modules from the policy manager `pm'. */
void ssh_pm_audit_uninit(SshPm pm)
{
  SshPmAuditModule module = pm->audit.modules, next_module;

  SSH_DEBUG(SSH_D_LOWOK, ("Uninitializing the PM audit modules"));

  /* Remove all configured audit modules */
  while (module)
    {
      next_module = module->next;
      ssh_pm_remove_audit_module(pm, module->audit_id);
      module = next_module;
    }

  SSH_ASSERT(pm->audit.modules == NULL);

  ssh_audit_destroy(pm->audit.ike_audit);

  /* Cancel timeouts. */
  ssh_cancel_timeout(&pm->audit.timer);
  ssh_cancel_timeout(&pm->audit.retry_timer);
}

void ssh_pm_audit_syslog_destroy(void *context)
{
  SshAuditSyslogContext syslog = context;

  ssh_audit_syslog_destroy(syslog);
}

void ssh_pm_audit_file_destroy(void *context)
{
  SshAuditFileContext file = context;

  ssh_audit_file_destroy(file);
}


SshAuditContext ssh_pm_create_audit_module(SshPm pm,
                                           SshAuditFormatType format,
                                           const char *audit_name)
{
  SshAuditSyslogContext audit_syslog_context;
  SshAuditFileContext audit_file_context;
  SshAuditContext audit;
  Boolean append_newline = FALSE;
  char *filename;

  SSH_DEBUG(SSH_D_HIGHOK, ("Creating audit module with name %s, and "
                           "format (%d)", audit_name, format));

  if (audit_name == NULL || !strcmp(audit_name, "syslog"))
    {
      if (format != SSH_AUDIT_FORMAT_DEFAULT



          )
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid format type for syslog auditing"));

          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Cannot use binary formatting for syslog "
                        "auditing.");
          return NULL;
        }

      audit_syslog_context = ssh_audit_syslog_create(SSH_LOGFACILITY_DAEMON,
                                                     SSH_LOG_INFORMATIONAL,
                                                     format);

      if (audit_syslog_context == NULL)
        return NULL;

      audit = ssh_audit_create(ssh_audit_syslog_cb,
                               ssh_pm_audit_syslog_destroy,
                               audit_syslog_context);
      if (audit == NULL)
        ssh_audit_syslog_destroy(audit_syslog_context);
      return audit;
    }
  else
    {
      filename = ssh_strdup(audit_name);

      if (filename == NULL)
        goto error;

      /* Only append newlines to non-binary (text) output formatters. */
      if (format == SSH_AUDIT_FORMAT_DEFAULT



          )
        append_newline = TRUE;

      SSH_DEBUG(SSH_D_HIGHOK, ("Creating audit file %s", filename));

      audit_file_context = ssh_audit_file_create(filename,
                                                 append_newline,
                                                 format);
      ssh_free(filename);

      if (audit_file_context == NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Cannot create audit file context. Is '%s' a "
                        "valid file name?", audit_name);
          return NULL;
        }
      audit = ssh_audit_create(ssh_audit_file_cb,
                               ssh_pm_audit_file_destroy,
                               audit_file_context);

      return audit;
    }

 error:

  SSH_DEBUG(SSH_D_FAIL, ("Audit module creatiion failed (%s)", audit_name));
  ssh_free(filename);
  return NULL;
}

Boolean ssh_pm_attach_audit_module(SshPm pm,
                                   SshUInt32 audit_subsystems,
                                   SshAuditContext audit)
{
  SshPmAuditModule module;

  SSH_DEBUG(SSH_D_MIDOK, ("Attaching audit module"));

  module = ssh_calloc(1, sizeof(*module));
  if (module == NULL)
    {
      ssh_audit_destroy(audit);
      return FALSE;
    }

  module->audit_subsystems = audit_subsystems;
  module->context = audit;
  module->audit_id = pm->next_audit_id++;

  /* Link the module to the policy managers list of audit modules. */
  module->next = pm->audit.modules;
  pm->audit.modules = module;

  return TRUE;
}

static void ssh_pm_remove_audit_module(SshPm pm, SshUInt32 audit_id)
{
  SshPmAuditModule *module_ptr, module;

  SSH_DEBUG(SSH_D_MIDOK, ("Removing audit module with id %d",
                          (int) audit_id));

  module_ptr = &pm->audit.modules;
  for (module = pm->audit.modules; module; module = module->next)
    {
      if (module->audit_id == audit_id)
        break;

      module_ptr = &module->next;
    }

  if (module)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Destroying audit module"));

      *module_ptr = module->next;

      ssh_audit_destroy(module->context);
      ssh_free(module);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("No configured audit module with this audit "
                             "id (%d)", (int) audit_id));
    }
}


/********************** Auditing of engine events *********************/

/* Mapping from reason code -> reason string */
const static SshKeywordStruct
ssh_pm_pkt_corruption_reasons[] =
  {
    { "none", SSH_PACKET_CORRUPTION_NONE },
    { "short media header", SSH_PACKET_CORRUPTION_SHORT_MEDIA_HEADER },
    { "reserved value received", SSH_PACKET_CORRUPTION_RESERVED_VALUE },
    { "short IPv4 header", SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER },
    { "short IPv6 header", SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER },
    { "packet not IPv4", SSH_PACKET_CORRUPTION_NOT_IPV4 },
    { "packet not IPv6", SSH_PACKET_CORRUPTION_NOT_IPV6 },
    { "checksum mismatch", SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH },
    { "truncated packet", SSH_PACKET_CORRUPTION_TRUNCATED_PACKET },
    { "PDU too small for next protocol",
      SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL },
    { "IP TTL zero", SSH_PACKET_CORRUPTION_TTL_ZERO },
    { "IP TTL less than required", SSH_PACKET_CORRUPTION_TTL_SMALL },
    { "multi/broadcast source address",
      SSH_PACKET_CORRUPTION_MULTICAST_SOURCE },
    { "unknown IP option", SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION },
    { "forbidden option", SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION },
    { "unaligned option", SSH_PACKET_CORRUPTION_UNALIGNED_OPTION },
    { "option overflow", SSH_PACKET_CORRUPTION_OPTION_OVERFLOW },
    { "option format incorrect",
      SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT },
    { "fragment length overflow",
      SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH },
    { "fragment length not multiple of 8",
      SSH_PACKET_CORRUPTION_FRAGMENT_BAD_LENGTH },
    { "fragment too small", SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL },
    { "fragment offset too small",
      SSH_PACKET_CORRUPTION_FRAGMENT_OFFSET_TOO_SMALL },
    { "fragment id collision", SSH_PACKET_CORRUPTION_FRAGMENT_ID_COLLISION },
    { "fragment late and extra fragment",
      SSH_PACKET_CORRUPTION_FRAGMENT_LATE_AND_EXTRA },
    { "next protocol header fragmented",
      SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED },
    { "source and destination host and ports equal",
      SSH_PACKET_CORRUPTION_SRC_DST_SAME },
    { "smurf attack", SSH_PACKET_CORRUPTION_ICMP_BROADCAST },
    { "xmas flags", SSH_PACKET_CORRUPTION_TCP_XMAS },
    { "zero flags", SSH_PACKET_CORRUPTION_TCP_NULL },
    { "FIN flag and no connection", SSH_PACKET_CORRUPTION_TCP_FIN },
    { "bad TCP sequence number", SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE },
    { "AH sequence number overflow",
      SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_OVERFLOW },
    { "AH IP fragment", SSH_PACKET_CORRUPTION_AH_IP_FRAGMENT },
    { "AH SA lookup failure", SSH_PACKET_CORRUPTION_AH_SA_LOOKUP_FAILURE },
    { "AH sequence number failure",
      SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE },
    { "AH ICV failure", SSH_PACKET_CORRUPTION_AH_ICV_FAILURE },
    { "ESP sequence number overflow",
      SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_OVERFLOW },
    { "ESP IP fragment", SSH_PACKET_CORRUPTION_ESP_IP_FRAGMENT },
    { "ESP SA lookup failure", SSH_PACKET_CORRUPTION_ESP_SA_LOOKUP_FAILURE },
    { "ESP sequence number failure",
      SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE },
    { "ESP ICV failure", SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE },
    { "allowed flow creation rate exceeded",
      SSH_PACKET_CORRUPTION_FLOW_RATE_LIMITED },
    { "audit rate limited", SSH_PACKET_CORRUPTION_AUDIT_RATE_LIMITED },
    { "policy: drop", SSH_PACKET_CORRUPTION_POLICY_DROP },
    { "policy: reject", SSH_PACKET_CORRUPTION_POLICY_REJECT },
    { "policy: pass", SSH_PACKET_CORRUPTION_POLICY_PASS },
    { "unsolicited ICMP error message",
      SSH_PACKET_CORRUPTION_UNSOLICITED_ICMP_ERROR },
    { "insufficient checksum coverage",
      SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL },
    { "SA selector mismatch after decapsulation",
      SSH_PACKET_CORRUPTION_IPSEC_INVALID_SELECTORS },
    { "unknown", SSH_PACKET_CORRUPTION_MAX },
    { "internal_error", SSH_PACKET_CORRUPTION_ERROR },
    { NULL, 0 }
  };

/* Mapping from attack type -> name */
const static SshKeywordStruct
ssh_pm_pkt_attacks[] =
  {
    { "land", SSH_ENGINE_ATTACK_LAND },
    { "fragment overflow", SSH_ENGINE_ATTACK_FRAGMENT_DEATH },
    { "smurf", SSH_ENGINE_ATTACK_SMURF },
    { "fraggle", SSH_ENGINE_ATTACK_FRAGGLE },
    { "traceroute", SSH_ENGINE_ATTACK_TRACEROUTE },
    { "xmas scan", SSH_ENGINE_ATTACK_XMAS_SCAN },
    { "null scan", SSH_ENGINE_ATTACK_NULL_SCAN },
    { "fin scan", SSH_ENGINE_ATTACK_FIN_SCAN },
    { "none", SSH_ENGINE_ATTACK_NONE },
    { "unknown", SSH_ENGINE_ATTACK_MAX },
    { "internal error", SSH_ENGINE_ATTACK_INTERNAL_ERROR, },
    { NULL, 0 }
  };


void
ssh_pm_audit_engine_event(SshPm pm, SshEngineAuditEvent event)
{
  unsigned char src_ip_buf[16], dst_ip_buf[16];
  unsigned char src_port_buf[2];
  unsigned char dst_port_buf[2];
  SshUInt8 typecode[2];
  size_t src_ip_len, dst_ip_len, src_port_len, dst_port_len, typecode_len;
  char src_ifname[33], dst_ifname[33]; /* last byte for strncpy() */
  char *src_ifname_ptr, *dst_ifname_ptr;
  SshADTHandle h;
  SshPmTunnel tunnel;
  SshPmTunnelStruct tmp_tunnel;
  Boolean valid_tcp_flags = FALSE;
  unsigned char spi[4], seq[4], flowlabel[4];
  unsigned char *from_tunnel, *to_tunnel;
  char *typecode_ptr, *src_port_ptr, *dst_port_ptr;
  const char *reason_str, *attack_str;
  SshInterceptorInterface *ifp_src, *ifp_dst;

  if (event == NULL)
    return;

  SSH_ASSERT(event->event > 0);
  SSH_ASSERT(event->event < SSH_AUDIT_MAX_VALUE);

  SSH_IP_ENCODE(&event->src_ip, src_ip_buf, src_ip_len);
  SSH_IP_ENCODE(&event->dst_ip, dst_ip_buf, dst_ip_len);

  src_port_len = dst_port_len = typecode_len = 0;
  src_port_ptr = dst_port_ptr = typecode_ptr = "";

  if ((event->ipproto == SSH_IPPROTO_TCP)  &&
      ((event->validity_flags & SSH_ENGINE_AUDIT_NONVALID_TCPFLAGS) == 0))
    valid_tcp_flags = TRUE;

  if (event->ipproto == SSH_IPPROTO_TCP ||
      event->ipproto == SSH_IPPROTO_UDP ||
      event->ipproto == SSH_IPPROTO_UDPLITE ||
      event->ipproto == SSH_IPPROTO_SCTP)
    {
      SSH_PUT_16BIT(src_port_buf, event->src_port);
      SSH_PUT_16BIT(dst_port_buf, event->dst_port);

      /* Check whether we have valid port information */
      if (event->validity_flags & SSH_ENGINE_AUDIT_NONVALID_PORTS)
        {
          src_port_ptr = NULL;
          dst_port_ptr = NULL;
          src_port_len = dst_port_len = 0;
        }
      else
        {
          src_port_ptr = ssh_sstr(src_port_buf);
          dst_port_ptr = ssh_sstr(dst_port_buf);
          src_port_len = dst_port_len = 2;
        }
    }
  else if (event->ipproto == SSH_IPPROTO_ICMP ||
           event->ipproto == SSH_IPPROTO_IPV6ICMP)
    {
      /* Check whether we have valid ICMP type/code information */
      if (event->validity_flags & SSH_ENGINE_AUDIT_NONVALID_PORTS)
        {
          typecode_ptr = NULL;
          typecode_len = 0;
        }
      else
        {
          typecode[0] = event->icmp_type;
          typecode[1] = event->icmp_code;
          typecode_ptr = ssh_sstr(typecode);
          typecode_len = 2;
        }
    }

  SSH_PUT_32BIT(spi, event->spi);
  SSH_PUT_32BIT(seq, event->seq);
  SSH_PUT_32BIT(flowlabel, event->flowlabel);
  src_ifname_ptr = NULL;
  dst_ifname_ptr = NULL;

  ifp_src = ssh_pm_find_interface_by_ifnum(pm, event->src_ifnum);
  ifp_dst = ssh_pm_find_interface_by_ifnum(pm, event->dst_ifnum);

  /* Grab copies of the interface names if possible. */
  if (ifp_src != NULL && ifp_src->name[0])
    {
      /* Copy interface name. */
      strncpy(src_ifname, ifp_src->name, sizeof(src_ifname));
      src_ifname[sizeof(src_ifname) - 1] = '\0';
      src_ifname_ptr = src_ifname;
    }

  if (ifp_dst != NULL && ifp_dst->name[0])
    {
      /* Copy interface name. */
      strncpy(dst_ifname, ifp_dst->name, sizeof(dst_ifname));
      dst_ifname[sizeof(dst_ifname)-1] = '\0';
      dst_ifname_ptr = dst_ifname;
    }

  from_tunnel = to_tunnel = NULL;

  if (event->from_tunnel_id != 0)
    {
      tmp_tunnel.tunnel_id = event->from_tunnel_id;
      h = ssh_adt_get_handle_to_equal(pm->tunnels, &tmp_tunnel);
      if (h != SSH_ADT_INVALID)
        {
          tunnel = ssh_adt_get(pm->tunnels, h);
          SSH_ASSERT(tunnel != NULL);
          from_tunnel = ssh_ustr(tunnel->tunnel_name);
        }
    }

  if (event->to_tunnel_id != 0)
    {
      tmp_tunnel.tunnel_id = event->to_tunnel_id;
      h = ssh_adt_get_handle_to_equal(pm->tunnels, &tmp_tunnel);
      if (h != SSH_ADT_INVALID)
        {
          tunnel = ssh_adt_get(pm->tunnels, h);
          SSH_ASSERT(tunnel != NULL);
          to_tunnel = ssh_ustr(tunnel->tunnel_name);
        }
    }

  if (event->event == SSH_AUDIT_HWACCEL_INITIALIZED ||
      event->event == SSH_AUDIT_HWACCEL_INITIALIZATION_FAILED)
    {
#ifdef SSH_IPSEC_HWACCEL_NAME
      if (strcmp("none", SSH_IPSEC_HWACCEL_NAME))
      {
        SSH_DEBUG(SSH_D_HIGHOK, ("Auditing hardware accelerator event"));
        if (event->event == SSH_AUDIT_HWACCEL_INITIALIZED)
          ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE,
                             event->event,
                             SSH_AUDIT_TXT,
                             "Hardware accelerator initialized",
                             SSH_AUDIT_ARGUMENT_END);
        else
          ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE,
                             event->event,
                             SSH_AUDIT_TXT,
                             "Hardware accelerator initialization failed",
                             SSH_AUDIT_ARGUMENT_END);
      }
#endif /* SSH_IPSEC_HWACCEL_NAME */
    }
  else if (event->event == SSH_AUDIT_ENGINE_SESSION_START
      || event->event == SSH_AUDIT_ENGINE_SESSION_END)
    {
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE, event->event,
                         SSH_AUDIT_SOURCE_INTERFACE, src_ifname_ptr,
                         SSH_AUDIT_DESTINATION_INTERFACE, dst_ifname_ptr,
                         SSH_AUDIT_FROMTUNNEL_ID, from_tunnel,
                         SSH_AUDIT_TOTUNNEL_ID, to_tunnel,
                         SSH_AUDIT_IPPROTO, &event->ipproto, 1,
                         SSH_AUDIT_SPI, spi, event->spi ? sizeof(spi) : 0,
                         SSH_AUDIT_SEQUENCE_NUMBER,
                                        seq, event->seq ? sizeof(seq) : 0,
                         SSH_AUDIT_IPV6_FLOW_ID,
                                        flowlabel, event->flowlabel
                                                   ? sizeof(flowlabel) : 0,
                         SSH_AUDIT_SOURCE_ADDRESS, src_ip_buf, src_ip_len,
                         SSH_AUDIT_DESTINATION_ADDRESS, dst_ip_buf, dst_ip_len,
                         SSH_AUDIT_SOURCE_PORT, src_port_ptr, src_port_len,
                         SSH_AUDIT_DESTINATION_PORT, dst_port_ptr,
                         dst_port_len,
                         (event->ipproto == SSH_IPPROTO_ICMP
                          ? SSH_AUDIT_ICMP_TYPECODE
                          : SSH_AUDIT_IPV6ICMP_TYPECODE),
                         typecode_ptr, typecode_len,
                         SSH_AUDIT_ARGUMENT_END);
    }
  else if (event->event == SSH_AUDIT_RESOURCE_FAILURE)
    {
      SSH_DEBUG(3, ("Audit resource failure event"));
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE,
                         SSH_AUDIT_RESOURCE_FAILURE,
                         SSH_AUDIT_TXT,
                         "Audit messages lost due to resource limitation.",
                         SSH_AUDIT_ARGUMENT_END);
    }
  else if (event->event == SSH_AUDIT_FLOOD)
    {
      ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE,
                         SSH_AUDIT_FLOOD,
                         SSH_AUDIT_TXT,
                         "Audit messages lost due to rate limiting.",
                         SSH_AUDIT_ARGUMENT_END);
    }
  else
    {
      if (event->packet_corruption <= SSH_PACKET_CORRUPTION_MAX)
        reason_str = ssh_find_keyword_name(ssh_pm_pkt_corruption_reasons,
                                           (long) event->packet_corruption);
      else
        reason_str = ssh_find_keyword_name(ssh_pm_pkt_corruption_reasons,
                                           (long) SSH_PACKET_CORRUPTION_ERROR);

      if (event->packet_attack <= SSH_ENGINE_ATTACK_NONE)
        attack_str = NULL;
      else if (event->packet_attack <= SSH_ENGINE_ATTACK_MAX)
        attack_str = ssh_find_keyword_name(ssh_pm_pkt_attacks,
                                           (long) event->packet_attack);
      else
        attack_str = ssh_find_keyword_name(ssh_pm_pkt_attacks,
                                      (long) SSH_ENGINE_ATTACK_INTERNAL_ERROR);

      /* If this is not a pass event, then "to tunnel" and "dst ifnum"
         are meaningless. */
      if (event->packet_corruption != SSH_PACKET_CORRUPTION_POLICY_PASS)
        {
          to_tunnel = NULL;
          dst_ifname_ptr = NULL;
        }

      ssh_pm_audit_event(pm, SSH_PM_AUDIT_ENGINE,
                         event->event,
                         SSH_AUDIT_SOURCE_INTERFACE, src_ifname_ptr,
                         SSH_AUDIT_DESTINATION_INTERFACE, dst_ifname_ptr,
                         SSH_AUDIT_FROMTUNNEL_ID, from_tunnel,
                         SSH_AUDIT_TOTUNNEL_ID, to_tunnel,
                         SSH_AUDIT_IPPROTO, &event->ipproto, 1,
                         SSH_AUDIT_SPI, spi, event->spi ? sizeof(spi) : 0,
                         SSH_AUDIT_SEQUENCE_NUMBER,
                                        seq, event->seq ? sizeof(seq) : 0,
                         SSH_AUDIT_IPV6_FLOW_ID,
                                        flowlabel, event->flowlabel
                                                   ? sizeof(flowlabel) : 0,
                         SSH_AUDIT_SOURCE_ADDRESS, src_ip_buf, src_ip_len,
                         SSH_AUDIT_DESTINATION_ADDRESS, dst_ip_buf, dst_ip_len,
                         SSH_AUDIT_SOURCE_PORT, src_port_ptr, src_port_len,
                         SSH_AUDIT_DESTINATION_PORT, dst_port_ptr,
                         dst_port_len,
                         SSH_AUDIT_TCP_FLAGS, &event->tcp_flags,
                         valid_tcp_flags ? 1 : 0,
                         event->ipproto == SSH_IPPROTO_ICMP
                         ? SSH_AUDIT_ICMP_TYPECODE :
                         SSH_AUDIT_IPV6ICMP_TYPECODE,
                         typecode_ptr, typecode_len,
                         SSH_AUDIT_PACKET_CORRUPTION, reason_str,
                         SSH_AUDIT_PACKET_ATTACK, attack_str,
                         SSH_AUDIT_IPV4_OPTION, &event->ipv4_option,
                         (event->ipv4_option ? 1 : 0),
                         SSH_AUDIT_ARGUMENT_END);
    }
}
