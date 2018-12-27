/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   HTTP interface for IPSec statistics.
*/

#include "sshincludes.h"
#include "quicksecpm_xmlconf_i.h"
#ifdef SSHDIST_HTTP_SERVER
#include "sshhttp.h"
#endif /* SSHDIST_HTTP_SERVER */
#include "sshmatch.h"
#include "ipsec_params.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "quicksecpm_audit.h"
#include "sshglobals.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmXmlConfHttp"

#ifdef SSHDIST_HTTP_SERVER
#ifdef SSH_IPSEC_XML_CONFIGURATION

#define HCELL(data)     "<th>", data, "</th>"
#define LCELL(data)     "<td>", data, "</td>"
#define CCELL(data)     "<td align=\"center\">", data, "</td>"
#define RCELL(data)     "<td align=\"right\">", data, "</td>"

#define SSH_FRIC    "<td align=\"right\">%d</td>"
#define SSH_FCSC    "<td align=\"center\">%s</td>"
#define SSH_FCFC    "<td align=\"center\">%@</td>"

#if SIZEOF_INT == 4
#define SSH_FR32C   "<td align=\"right\">%u</td>"
#define SSH_FR32T   "<td align=\"right\">%u s</td>"
#elif SIZEOF_LONG == 4
#define SSH_FR32C   "<td align=\"right\">%lu</td>"
#define SSH_FR32T   "<td align=\"right\">%lu s</td>"
#else
#error "neither int nor long is 32-bit"
#endif

/* Macros for 64-bit printing. On some platforms/compilers a 32-bit
   type will be used and the high order bits are lost. */
#ifdef HAVE_LONG_LONG
#define SSH_FR64C   "<td align=\"right\">%llu</td>"
#define SSH_V64C(v) ((unsigned long long)(v))
#else
#define SSH_FR64C   "<td align=\"right\">%lu</td>"
#define SSH_V64C(v) ((unsigned long)(v))
#endif

#define SSH_IPM_LINK(url, caption)                                      \
"<a href=\"" url "\"", frames ? " target=\"content\"" : "", ">",        \
(caption), "</a>"

/* Context data for the HTTP interface. */
struct SshIpmHttpStatisticsRec
{
  /* IP address to listen to. */
  SshIpAddrStruct address;

  /* Parameters. */
  SshIpmHttpStatisticsParamsStruct params;

  /* HTTP server context. */
  SshHttpServerContext http_server;
};

/* Object filtering flags. */
#define SSH_IPM_HTTP_F_TRANSFORM        0x00000001
#define SSH_IPM_HTTP_F_FLOW             0x00000002
#define SSH_IPM_HTTP_F_RULE             0x00000004
#define SSH_IPM_HTTP_F_TUNNEL_ID        0x00000008

/* Thread handling HTTP statistics operations. */
struct SshIpmHttpStatsRec
{
  /* FSM thread. */
  SshFSMThreadStruct thread;

  /* Flags. */
  unsigned int error : 1;       /* An error occurred. */
  unsigned int not_found : 1;   /* Requested object not found. */

  /* Object filtering flags. */
  SshUInt32 filter_flags;

  /* URI handler arguments. */
  SshHttpServerContext ctx;
  SshHttpServerConnection conn;
  SshStream stream;

  /* Buffer where the HTML content is generated. */
  SshBuffer buffer;

  /* Temporary buffer for formatting HTML. */
  char buf[1024];

  /* Sequence number. */
  SshUInt32 seqnum;

  /* Indexes of the objects currently processed. */
  SshUInt32 transform_index;
  SshUInt32 flow_index;
  SshUInt32 rule_index;

  /* Tunnel ID for filtering. */
  SshUInt32 tunnel_id;

  /* Hash for computing certificate identifications. */
  SshHash hash;
  size_t hash_digest_len;

  /* Certificate to lookup for the info_cert_cb(). */
  char *cert_id;
};

typedef struct SshIpmHttpStatsRec SshIpmHttpStatsStruct;
typedef struct SshIpmHttpStatsRec *SshIpmHttpStats;

/*************************** Protocol State names ***************************/
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
const SshKeywordStruct ssh_engine_protocol_states[] =
{
  {"None",            SSH_ENGINE_FLOW_PROTOCOL_NONE},
  {"Initial",         SSH_ENGINE_FLOW_TCP_INITIAL},
  {"Syn-Ack",         SSH_ENGINE_FLOW_TCP_SYN_ACK},
  {"Syn-Ack-Ack",     SSH_ENGINE_FLOW_TCP_SYN_ACK_ACK},
  {"Established",     SSH_ENGINE_FLOW_TCP_ESTABLISHED},
  {"Fin-Fwd",         SSH_ENGINE_FLOW_TCP_FIN_FWD},
  {"Fin-Rev",         SSH_ENGINE_FLOW_TCP_FIN_REV},
  {"Fin-Fin",         SSH_ENGINE_FLOW_TCP_FIN_FIN},
  {"Close-Wait",      SSH_ENGINE_FLOW_TCP_CLOSE_WAIT},
  {"Closed",          SSH_ENGINE_FLOW_TCP_CLOSED},
  {NULL, 0}
};
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

/*************************** Formatting functions ***************************/

/* Construct a standard page header. */
static Boolean
ssh_ipm_http_page_header(SshIpmHttpStats ctx,
                         SshIpmHttpStatisticsParams params, SshBuffer buffer,
                         const char *title, Boolean toc)
{
  const char *prefix;
  const char *local_addr, *delim;
  char refresh_buf[128];
  char *refresh = "";

  if (toc)
    {
      prefix = SSH_IPSEC_VERSION_STRING_SHORT;
      delim = "";
    }
  else
    {
      if (params->frames)
        {
          delim = "";
          prefix = NULL;
        }
      else
        {
          prefix = SSH_IPSEC_VERSION_STRING_SHORT;
          delim = " - ";
        }
    }

  local_addr = ssh_http_server_get_local_address(ctx->conn);

  if (title == NULL)
    title = "";

  if (params->refresh)
    {
      ssh_snprintf(refresh_buf, sizeof(refresh_buf),
                   "<META http-equiv=\"Refresh\" content=\"%u\">\n",
                  (unsigned int) params->refresh);
      refresh = refresh_buf;
    }

  if (ssh_buffer_append_cstrs(buffer,
                              "\
<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n\
   \"http://www.w3.org/TR/html4/strict.dtd\">\n\
<html>\n\
<head>\n\
<META http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n",
                              refresh,
                              "<title>",
                              (prefix ? prefix : ""),
                              (prefix ? " - " : ""),
                              (prefix ? local_addr : ""),
                              delim,
                              title,
                              "</title>\n",
                              "</head>\n",
                              "<body>\n",
                              "<h1>",
                              (prefix ? prefix : ""),
                              (prefix ? " - ": ""),
                              (prefix ? local_addr : ""),
                              delim,
                              title,
                              "</h1>\n",
                              NULL) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

/* Construct a standard page trailer. */
static Boolean
ssh_ipm_http_page_trailer(SshIpmHttpStatisticsParams params, SshBuffer buffer,
                          Boolean copyright)
{
  char *copy = "";

  if (copyright)
    copy = "\
<hr>\n\
<p>Copyright &copy; 2001-2014 \
<a href=\"http://www.insidesecure.com\">INSIDE Secure Oy</a></p>\n";

  return ssh_buffer_append_cstrs(buffer,
                                 copy,
                                 "</body>\n",
                                 "</html>\n",
                                 NULL) == SSH_BUFFER_OK;
}

/* Construct a table header for public flow information. */
static Boolean
ssh_ipm_http_flow_info_header(SshIpmHttpStats ctx)
{
  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th rowspan=\"2\">ID</th>",
                              "<th rowspan=\"2\">LRU<br>Level</th>",
                              "<th rowspan=\"2\">Idle<br>(seconds)</th>",
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
                              "<th rowspan=\"2\">Protocol<br>State</th>",
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
                              "<th rowspan=\"2\">IP<br>Protocol</th>",
                              "<th colspan=\"2\">Source</th>",
                              "<th colspan=\"2\">Destination</th>",
                              "<th rowspan=\"2\">Routing Instance</th>",
                              "<th rowspan=\"2\">Statistics</th>",
                              "<th colspan=\"2\">Transform</th>",
                              "<th rowspan=\"2\">Rule</th>",
                              "</tr>\n",
                              "<tr>",
                              HCELL("IP"), HCELL("Port/ID"),
                              HCELL("IP"), HCELL("Port/TC"),
                              HCELL("Forward"), HCELL("Reverse"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

/* Construct a table header for public rule information. */
static Boolean
ssh_ipm_http_rule_info_header(SshIpmHttpStats ctx)
{
  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th rowspan=\"3\">ID</th>",
                              "<th rowspan=\"3\">Type</th>",
                              "<th rowspan=\"3\">Precedence</th>",
                              "<th rowspan=\"3\">IP<br>Protocol</th>",
                              "<th colspan=\"4\">Source</th>",
                              "<th colspan=\"4\">Destination</th>",
                              "<th rowspan=\"3\">Iface</th>",
                              "<th rowspan=\"3\">Routing Instance</th>",
                              "<th colspan=\"2\" rowspan=\"2\">ICMP</th>",
                              "<th rowspan=\"3\">Statistics</th>",
                              "<th rowspan=\"3\">Flows</th>",
                              "<th rowspan=\"3\">Depends<br>On<br>Rule</th>",
                              "<th colspan=\"2\" rowspan=\"2\">Tunnel</th>",
                              "</tr>\n",
                              "<tr>",
                              "<th colspan=\"2\">IP</th>"
                              "<th colspan=\"2\">Port</th>"
                              "<th colspan=\"2\">IP</th>"
                              "<th colspan=\"2\">Port</th>"
                              "</tr>\n",
                              "<tr>",
                              HCELL("Low"), HCELL("High"),
                              HCELL("Low"), HCELL("High"),
                              HCELL("Low"), HCELL("High"),
                              HCELL("Low"), HCELL("High"),

                              HCELL("Type"), HCELL("Code"),
                              HCELL("From"), HCELL("To"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

/************************** Static help functions ***************************/

/* Callback for global statistics querying from the version
   handler. */
static void
ssh_ipm_version_stats_cb(SshPm pm,
                         const SshPmGlobalStats pm_stats,
                         const SshEngineGlobalStats e_stats,
                         const SshFastpathGlobalStats f_stats,
                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (ssh_buffer_append_cstrs(
        ctx->buffer,
        "<table border>\n",
        "<tr><th>QuickSec Version</th>"
        "<td>" SSH_IPSEC_VERSION_STRING_SHORT "</td></tr>\n",

        "<tr><th>Preallocate Tables</th>",
#ifdef SSH_IPSEC_PREALLOCATE_TABLES
        "<td>Yes</td>",
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */
        "<td>No</td>",
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */
        "</tr>\n",

        "<tr><th>Usermode Engine</th>",
#ifdef USERMODE_ENGINE
        "<td>Yes</td>",
#else /* not USERMODE_ENGINE */
        "<td>No</td>",
#endif /* not USERMODE_ENGINE */
        "</tr>\n",

        "<tr><th>IP-only Interceptor</th>",
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
        "<td>Yes</td>",
#else /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
        "<td>No</td>",
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
        "</tr>\n",

        "<tr><th>IPsec Small</th>",
#ifdef SSH_IPSEC_SMALL
        "<td>Yes</td>",
#else /* not SSH_IPSEC_SMALL */
        "<td>No</td>",
#endif /* not SSH_IPSEC_SMALL */
        "</tr>\n",

        "<tr><th>IPv6</th>",
#if defined (WITH_IPV6)
        "<td>Yes</td>",
#else /* WITH_IPV6 */
        "<td>No</td>",
#endif /* WITH_IPV6 */
        "</tr>\n",

        "</table>\n",
        NULL) != SSH_BUFFER_OK)
    goto error;

























































































































  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;


  /* Error handling. */

 error:

  ctx->error = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static Boolean pm_ike_server_stats_cb(SshPm pm, SshIkev2Server server,
                                      void *context)
{
  SshIkev2GlobalStatistics stats = (SshIkev2GlobalStatistics) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Adding statistics from server at %@",
                          ssh_ipaddr_render, server->ip_address));

  stats->total_ike_sas += server->statistics->total_ike_sas;
  stats->total_ike_sas_initiated +=
    server->statistics->total_ike_sas_initiated;
  stats->total_ike_sas_responded +=
    server->statistics->total_ike_sas_responded;

  stats->total_attempts += server->statistics->total_attempts;
  stats->total_attempts_initiated +=
    server->statistics->total_attempts_initiated;
  stats->total_attempts_responded +=
    server->statistics->total_attempts_responded;

  stats->total_packets_in += server->statistics->total_packets_in;
  stats->total_packets_out += server->statistics->total_packets_out;
  stats->total_octets_in += server->statistics->total_octets_in;
  stats->total_octets_out += server->statistics->total_octets_out;
  stats->total_retransmits += server->statistics->total_retransmits;
  stats->total_init_failures += server->statistics->total_init_failures;
  stats->total_init_no_response += server->statistics->total_init_no_response;
  stats->total_resp_failures += server->statistics->total_resp_failures;
  return TRUE;
}


static Boolean pm_ike_global_stats(SshPm pm, SshIkev2GlobalStatistics stats)
{
  return ssh_pm_foreach_ike_server(pm, pm_ike_server_stats_cb, stats);
}

/* Global statistics. */
static void
ssh_ipm_global_stats_cb(SshPm pm,
                        const SshPmGlobalStats pm_stats,
                        const SshEngineGlobalStats e_stats,
                        const SshFastpathGlobalStats f_stats,
                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmContext ipm = (SshIpmContext) ssh_fsm_get_gdata(thread);
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  SshIkev2GlobalStatisticsStruct ike_stats;
  char daystr[64];
  SshTime uptime = ssh_time() - ipm->start_time;
  char *start_time = NULL;
  SshUInt32 hours, minutes;

  /* Format uptime. */

  if (uptime >= 60 * 60 * 24)
    {
      SshUInt32 days = (SshUInt32)(uptime / (60 * 60 * 24));

      uptime -= days * 60 * 60 * 24;
      ssh_snprintf(daystr, sizeof(daystr), "%u day%s, ",
                   (unsigned int) days,
                   days > 1 ? "s" : "");
    }
  else
    {
      daystr[0] = '\0';
    }

  hours = (SshUInt32)(uptime / (60 * 60));
  uptime -= hours * 60 * 60;

  minutes = (SshUInt32)(uptime / 60);
  uptime -= minutes * 60;

  ssh_snprintf(ctx->buf, sizeof(ctx->buf), "%s%02u:%02u:%02u",
               daystr,
               (unsigned int) hours,
               (unsigned int) minutes,
               (unsigned int) uptime);

  /* Format start time. */
  start_time = ssh_readable_time_string(ipm->start_time, TRUE);

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",

                              "<tr><th>Started at</th><td align=\"right\">",
                              start_time ? start_time : "???",
                              "</td></tr>\n",

                              "<tr><th>Uptime</th><td align=\"right\">",
                              ctx->buf,
                              "</td></tr>\n",

                              "</table>\n",
                              "<h2>Policy Manager</h2>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  /* Free the dynamically allocated start time string. */
  ssh_free(start_time);

  memset(&ike_stats, 0, sizeof(ike_stats));
  if (!pm_ike_global_stats(pm, &ike_stats))
    goto error;

  if (pm_stats)
    {
      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   SSH_FR32C SSH_FR32C
                   SSH_FR32C SSH_FR32C
                   SSH_FR32C SSH_FR32C
                   SSH_FR32C SSH_FR32C
                   SSH_FR32C SSH_FR32C SSH_FR32C
                   "</tr>\n",
                   (unsigned int) pm_stats->num_p1_active,
                   (unsigned int) pm_stats->num_qm_active,
                   (unsigned int) pm_stats->num_p1_done,
                   (unsigned int) pm_stats->num_p1_failed,
                   (unsigned int) ike_stats.total_ike_sas_initiated,
                   (unsigned int) ike_stats.total_ike_sas_responded,
                   (unsigned int) pm_stats->num_qm_done,
                   (unsigned int) pm_stats->num_qm_failed,
                   (unsigned int) ike_stats.total_init_failures,
                   (unsigned int) ike_stats.total_init_no_response,
                   (unsigned int) ike_stats.total_resp_failures);


      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"2\">Active</th>",
                                  "<th colspan=\"6\">Total SAs</th>",
                                  "<th colspan=\"3\">IKE Errors</th>",
                                  "</tr>\n",
                                  "<tr>",
                                  "<th rowspan=\"2\">IKE SAs</th>",
                                  "<th colspan=\"1\">Negotiations</th>",

                                  "<th colspan=\"4\">Phase-1</th>",
                                  "<th colspan=\"2\">Quick-Mode</th>",

                                  "<th colspan=\"2\">Initiator</th>",
                                  "<th colspan=\"1\">Responder</th>",

                                  "</tr>\n",
                                  "<tr>",
                                  "<th>Quick-Mode</th>",

                                  "<th>Done</th><th>Failed</th>",
                                  "<th>Initiator</th><th>Responder</th>",
                                  "<th>Done</th><th>Failed</th>",

                                  "<th>Failures</th>",
                                  "<th>No response</th>",
                                  "<th>Failures</th>",

                                  "</tr>\n",
                                  ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;
    }
  else
    {
      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "No statistics available.\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;
    }

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Engine</h2>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  if (e_stats)
    {
      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"3\">Nexthops</th>",
                                  "<th colspan=\"3\">Flows</th>",
                                  "<th colspan=\"3\">Transforms</th>",
                                  "<th colspan=\"2\">Rules</th>",
                                  "<th rowspan=\"2\">Rekeys</th>",
                                  "<th rowspan=\"2\">Timer max error</th>",
                                  "</tr>\n",
                                  "<tr>",

                                  "<th>Active</th>",
                                  "<th>Free</th>",
                                  "<th>Total</th>",

                                  "<th>Active</th>",
                                  "<th>Free</th>",
                                  "<th>Total</th>",

                                  "<th>Active</th>",
                                  "<th>Free</th>",
                                  "<th>Total</th>",

                                  "<th>Active</th>",
                                  "<th>Free</th>",

                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   SSH_FR32C SSH_FR32C SSH_FR32C /* nexthops */
                   SSH_FR32C SSH_FR32C SSH_FR32C /* flows */
                   SSH_FR32C SSH_FR32C SSH_FR32C /* transforms */
                   SSH_FR32C SSH_FR32C           /* rules */
                   SSH_FR32C                     /* rekeys */
                   SSH_FR32T                     /* Timer max error */

                   "</tr>\n",

                   (unsigned int) e_stats->active_nexthops,
                   (unsigned int) (e_stats->next_hop_table_size -
                                   e_stats->active_nexthops),
                   (unsigned int) e_stats->total_nexthops,
                   (unsigned int) e_stats->active_flows,
                   (unsigned int) (e_stats->flow_table_size -
                                   e_stats->active_flows),
                   (unsigned int) e_stats->total_flows,
                   (unsigned int) e_stats->active_transforms,
                   (unsigned int) (e_stats->transform_table_size -
                                   e_stats->active_transforms),
                   (unsigned int) e_stats->total_transforms,
                   (unsigned int) e_stats->active_rules,
                   (unsigned int) (e_stats->rule_table_size -
                                   e_stats->active_rules),
                   (unsigned int) e_stats->total_rekeys,
                   (unsigned int)
                   (e_stats->flow_table_size /
                    ((e_stats->age_callback_interval
                      * e_stats->age_callback_flows)
                     / 1000000L)));


      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<p>\n",
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"4\">Resource Drops</th>",
                                  "</tr>\n",
                                  "<tr>",
                                  "<th>Out of Flows</th>",
                                  "<th>Out of Transform Objects</th>",
                                  "<th>Out of Next Hop Nodes</th>",
                                  "<th>Out of Arp Caches</th>",

                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                   "</tr>\n",
                   (unsigned int) e_stats->out_of_flows,
                   (unsigned int) e_stats->out_of_transforms,
                   (unsigned int) e_stats->out_of_nexthops,
                   (unsigned int) e_stats->out_of_arp_cache_entries);


      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;
    }
  else
    {
      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "No statistics available.\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;
    }

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Fastpath</h2>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  if (f_stats)
    {
      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"3\">Octets</th>",
                                  "<th colspan=\"3\">Packets</th>",
                                  "<th colspan=\"3\">Crypto Transforms</th>",
                                  "<th colspan=\"2\">Packet Contexts</th>",

                                  "</tr>\n",
                                  "<tr>",
                                  "<th>In</th>",
                                  "<th>Out</th>",
                                  "<th>Forwarded</th>",

                                  "<th>In</th>",
                                  "<th>Out</th>",
                                  "<th>Forwarded</th>",

                                  "<th>Active</th>",
                                  "<th>Free</th>",
                                  "<th>Total</th>",

                                  "<th>Active</th>",
                                  "<th>Total</th>",

                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   SSH_FR64C SSH_FR64C SSH_FR64C /* octets */
                   SSH_FR64C SSH_FR64C SSH_FR64C /* packets */
                   SSH_FR32C SSH_FR32C SSH_FR32C /* crypto transforms */
                   SSH_FR32C SSH_FR32C           /* packet contexts */

                   "</tr>\n",
                   SSH_V64C(f_stats->in_octets_uncomp),
                   SSH_V64C(f_stats->out_octets_uncomp),
                   SSH_V64C(f_stats->forwarded_octets_uncomp),
                   SSH_V64C(f_stats->in_packets),
                   SSH_V64C(f_stats->out_packets),
                   SSH_V64C(f_stats->forwarded_packets),

                   (unsigned int) f_stats->active_transform_contexts,
                   (unsigned int)
                   (f_stats->transform_context_table_size -
                    f_stats->active_transform_contexts),
                   (unsigned int) f_stats->total_transform_contexts,

                   (unsigned int) f_stats->active_packet_contexts,
                   (unsigned int)
                   (f_stats->packet_context_table_size -
                    f_stats->active_packet_contexts));


      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<p>\n",
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"4\">Packets</th>",
                                  "<th colspan=\"2\">ESP</th>",
                                  "<th colspan=\"2\">AH</th>",
                                  "<th colspan=\"3\">IPCOMP</th>",
                                  "<th colspan=\"2\">Triggers</th>",
                                  "</tr>\n",
                                  "<tr>",
                                  "<th>IPv4</th>",
                                  "<th>IPv6</th>",
                                  "<th>ARP</th>",
                                  "<th>Other</th>",
                                  "<th>In</th>",
                                  "<th>Out</th>",
                                  "<th>In</th>",
                                  "<th>Out</th>",
                                  "<th>In</th>",
                                  "<th>Out</th>",
                                  "<th>Out uncompressed</th>",
                                  "<th>Sent</th>",
                                  "<th>RateLimit</th>",
                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(
                ctx->buf, sizeof(ctx->buf),
                "<tr>"
                SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                SSH_FR32C SSH_FR32C
                SSH_FR32C SSH_FR32C
                SSH_FR32C SSH_FR32C SSH_FR32C
                SSH_FR32C SSH_FR32C
                "</tr>\n",
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IN_IP4],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IN_IP6],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IN_ARP],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IN_OTHER],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_ESP_IN],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_ESP_OUT],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_AH_IN],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_AH_OUT],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IPCOMP_IN],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_IPCOMP_OUT],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_NOIPCOMP_OUT],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_TRIGGER],
                (unsigned int) f_stats->counters[SSH_ENGINE_STAT_NOTRIGGER]);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;


      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<p>\n",
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"17\">Dropped Packets</th>",
                                  "</tr>\n",
                                  "<tr>",
                                  "<th>Corrupt</th>",
                                  "<th>IP Option</th>",
                                  "<th>Resource</th>",
                                  "<th>No Route</th>",
                                  "<th>Rule Drop</th>",
                                  "<th>Rule Reject</th>",
                                  "<th>ESP MAC</th>",
                                  "<th>AH MAC</th>",
                                  "<th>Replay</th>",
                                  "<th>Internal</th>",
                                  "<th>Reassembly</th>",
                                  "<th>HWAccel</th>",
                                  "<th>No Rule Lookup</th>",
                                  "<th>No Rule</th>",
                                  "<th>Transform Execution Failure</th>",
                                  "<th>Protocol Monitor Drop</th>",
                                  "<th>Drop</th>",
                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(
               ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
               SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
               SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
               "</tr>\n",
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_CORRUPTDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_OPTIONSDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_RESOURCEDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_ROUTEDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_RULEDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_RULEREJECT],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_ESPMACDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_AHMACDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_REPLAYDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_ERRORDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_FRAGDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_HWACCELDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_NOLOOKUP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_NORULE],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_TRANSFORMDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_MONITORDROP],
               (unsigned int) f_stats->counters[SSH_ENGINE_STAT_DROP]);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "<p>\n",
                                  "<table border>\n",
                                  "<tr>",
                                  "<th colspan=\"3\">Resource Drops</th>",
                                  "</tr>\n",
                                  "<tr>",
                                  "<th>Out of Packet Contexts</th>",
                                  "<th>Out of Transform Contexts</th>",

                                  "</tr>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   SSH_FR32C SSH_FR32C
                   "</tr>\n",
                   (unsigned int) f_stats->out_of_packet_contexts,
                   (unsigned int) f_stats->out_of_transform_contexts);


      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,
                                  "</table>\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;

    }
  else
    {
      if (ssh_buffer_append_cstrs(ctx->buffer,
                                  "No statistics available.\n",
                                  NULL) != SSH_BUFFER_OK)
        goto error;
    }

  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;


  /* Error handling. */

 error:

  ctx->error = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

#define IPM_HTTP_RADIUS_STAT(ctx, stats, field)                 \
  do {                                                          \
    ssh_snprintf(                                               \
            (ctx)->buf,                                         \
            sizeof((ctx)->buf),                                 \
            "<tr><th align=\"left\">" #field "</th><td> %u </td></tr>\n", \
            (unsigned) (stats)->field);                         \
    ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL);       \
  } while (0)

void
ssh_ipm_radius_acct_stats_cb(
        SshPm pm,
        const SshPmRadiusAcctStats stats,
        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (stats == NULL)
    {
      if (ssh_buffer_append_cstrs(
                  ctx->buffer,
                  "No RADIUS Accounting stats available.",
                  NULL)
          != SSH_BUFFER_OK)
        goto error;

      /* All done. */
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<table border>\n");


  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
    goto error;

  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_on_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_off_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_start_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_stop_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_response_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_response_invalid_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_failed_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_too_long_ike_id_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_timeout_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_retransmit_count);
  IPM_HTTP_RADIUS_STAT(ctx, stats, acct_request_cancelled_count);

  ssh_snprintf(ctx->buf, sizeof(ctx->buf), "</table>\n");

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
    goto error;

  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;

 error:
    ctx->error = 1;
    SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

#undef IPM_HTTP_RADIUS_STAT

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

/* Compute an unique ID (digest using the hash `hash') for the
   certificate `cert', `cert_len'. */
static Boolean
ssh_ipm_compute_cert_id(SshHash hash, size_t digest_len,
                        const unsigned char *cert, size_t cert_len,
                        char *idbuf, size_t idbuf_len)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t i;

  ssh_hash_reset(hash);
  ssh_hash_update(hash, cert, cert_len);
  if (ssh_hash_final(hash, digest) != SSH_CRYPTO_OK)
    return FALSE;

  if (idbuf_len < 2 * digest_len + 1)
    return FALSE;

  for (i = 0; i < digest_len; i++)
    ssh_snprintf(idbuf + i * 2, 3, "%02X", digest[i]);

  return TRUE;
}

/* Getting IKE certificates. */
static Boolean
ssh_ipm_ike_sa_info_cert_cb(SshPm pm,
                            SshPmIkeSaStats stats,
                            void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  const unsigned char *ca;
  size_t ca_len;
  const unsigned char *cert;
  size_t cert_len;
  SshPmAuthData auth = NULL;
  char id_buf[2 * SSH_MAX_HASH_DIGEST_LENGTH + 1];

  auth = stats->auth;
  if (auth == NULL)
    goto error;

  ca = ssh_pm_auth_get_ca_certificate(auth, &ca_len);
  cert = ssh_pm_auth_get_certificate(auth, &cert_len);

  /* Try CA. */
  if (ca)
    {
      if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                   ca, ca_len, id_buf, sizeof(id_buf)))
        goto error;

      if (strcmp(id_buf, ctx->cert_id) == 0)
        {
          /* Found it. */
          if (ssh_buffer_append(ctx->buffer, ca, ca_len) != SSH_BUFFER_OK)
            goto error;

          /* Stop enumeration.  The error handler is find way to get
             out of here. */
          ctx->error = 1;
          goto error;
        }
    }

  /* Try cert. */
  if (cert)
    {
      if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                   cert, cert_len, id_buf, sizeof(id_buf)))
        goto error;

      if (strcmp(id_buf, ctx->cert_id) == 0)
        {
          /* Found it. */
          if (ssh_buffer_append(ctx->buffer, cert, cert_len) != SSH_BUFFER_OK)
            goto error;

          /* Stop enumeration.  The error handler is find way to get
             out of here. */
          ctx->error = 1;
          goto error;
        }
    }

  return TRUE;


  /* Error handling. */

 error:

  ctx->error = 1;
  return FALSE;
}

/* A callback function for enumerating IKE servers while retrieving
   certificates from IKE SAs. */
static Boolean
ssh_ipm_ike_server_cert_cb(SshPm pm, SshIkev2Server server, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* For each SA in the server. */
  return ssh_pm_ike_foreach_ike_sa(pm, server, ssh_ipm_ike_sa_info_cert_cb,
                                   thread);
}

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */


/* Get IKE SA statistics. */
static Boolean
ssh_ipm_ike_sa_info_cb(SshPm pm,
                       SshPmIkeSaStats stats,
                       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  char ca_buf[256];
  char cert_buf[256];
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  const unsigned char *ca;
  size_t ca_len;
  const unsigned char *cert;
  size_t cert_len;
  char id_buf[2 * SSH_MAX_HASH_DIGEST_LENGTH + 1];
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
  char *created_time = NULL;
  SshPmAuthData auth = NULL;
  SshTime created;
  SshIpAddrStruct local, remote;
  SshIkev2PayloadID local_id, remote_id;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  SshIkev2PayloadID second_local_id, second_remote_id;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  /* When the IKE SA was created */
  created = (SshTime)(stats->created);

  created_time = ssh_time_string(created);
  if (created_time == NULL)
    goto error;

  auth = stats->auth;
  if (auth == NULL)
    goto error;

  ssh_snprintf(ca_buf, sizeof(ca_buf), "");
  ssh_snprintf(cert_buf, sizeof(cert_buf), "");

  ssh_pm_auth_get_local_ip(auth, &local);
  ssh_pm_auth_get_remote_ip(auth, &remote);

  local_id = ssh_pm_auth_get_local_id(auth, 1);
  if (local_id == NULL)
    goto error;

  remote_id = ssh_pm_auth_get_remote_id(auth, 1);
  if (remote_id == NULL)
    goto error;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  second_local_id = ssh_pm_auth_get_local_id(auth, 2);
  second_remote_id = ssh_pm_auth_get_remote_id(auth, 2);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  /* Get trusted CA certificate. */
  ca = ssh_pm_auth_get_ca_certificate(auth, &ca_len);
  if (ca)
    {
      if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                   ca, ca_len, id_buf, sizeof(id_buf)))
        goto error;

      ssh_snprintf(ca_buf, sizeof(ca_buf),
                   "<a href=\"/ike/cert/%s\">CA</a>", id_buf);
    }

  /* Get peer certificate. */
  cert = ssh_pm_auth_get_certificate(auth, &cert_len);
  if (cert)
    {
      if (!ssh_ipm_compute_cert_id(ctx->hash, ctx->hash_digest_len,
                                   cert, cert_len, id_buf, sizeof(id_buf)))
        goto error;

      ssh_snprintf(cert_buf, sizeof(cert_buf),
                   "<a href=\"/ike/cert/%s\">Cert</a>", id_buf);
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_snprintf(ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C
               SSH_FCSC
               SSH_FRIC
               SSH_FRIC
               SSH_FCSC
              "<td align=\"center\">%@</td>"
               "<td align=\"center\">%@</td>"
              "<td align=\"center\">%@</td>"
               "<td align=\"center\">%@</td>"
#ifdef SSH_IKEV2_MULTIPLE_AUTH
              "<td align=\"center\">%@</td>"
               "<td align=\"center\">%@</td>"
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
               SSH_FCSC SSH_FCSC SSH_FCSC
               SSH_FCSC SSH_FCSC
              "<td align=\"center\">%s (%d)</td>"
               "</tr>\n",

               (unsigned int) ++ctx->seqnum,
               "yes",
               (unsigned int) ssh_pm_auth_get_ike_version(auth),
               (unsigned int) stats->num_child_sas,
               created_time,
               ssh_ipaddr_render, &local,
               ssh_ipaddr_render, &remote,
               ssh_pm_ike_id_render, local_id,
               ssh_pm_ike_id_render, remote_id,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
               ssh_pm_ike_id_render, second_local_id,
               ssh_pm_ike_id_render, second_remote_id,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
               stats->encrypt_algorithm,
               stats->mac_algorithm,
               stats->prf_algorithm,

               ca_buf, cert_buf,
               stats->routing_instance_name, stats->routing_instance_id);

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL) != SSH_BUFFER_OK)
    goto error;

  ssh_free(created_time);

  return TRUE;

  /* Error handling. */

 error:

  ctx->error = 1;
  ssh_free(created_time);
  return FALSE;
}

/* A callback function for enumerating IKE servers while retrieving
   IKE SA statistics. */
static Boolean
ssh_ipm_ike_server_cb(SshPm pm, SshIkev2Server server, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* For each SA in the server. */
  return ssh_pm_ike_foreach_ike_sa(pm, server, ssh_ipm_ike_sa_info_cb, thread);
}


/* A callback function for retrieving next transform index. */
static void
ssh_ipm_transform_index_cb(SshPm pm, SshUInt32 ind, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  ctx->transform_index = ind;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting public transform information. */
static void
ssh_ipm_transform_info_cb(SshPm pm, const SshEngineTransformInfo info,
                          void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  char spi_esp_in[12];
  char spi_esp_out[12];
  char spi_ah_in[12];
  char spi_ah_out[12];
  char cpi_ipcomp_in[6];
  char cpi_ipcomp_out[6];
  char cipher_buf[64];
  char mac_buf[64];
  char ipcomp_buf[64];

  if (info
      && (ctx->filter_flags == 0
          || (ctx->filter_flags & SSH_IPM_HTTP_F_TUNNEL_ID
              && info->tunnel_id == ctx->tunnel_id)))
    {
      /* Format protocols. */

      if (info->transform & SSH_PM_IPSEC_ESP)
        {
          ssh_snprintf(spi_esp_in, sizeof(spi_esp_in), "%08lx",
                       (unsigned long) info->spi_esp_in);
          ssh_snprintf(spi_esp_out, sizeof(spi_esp_out), "%08lx",
                       (unsigned long) info->spi_esp_out);
        }
      else
        {
          spi_esp_in[0] = '\0';
          spi_esp_out[0] = '\0';
        }

      if (info->transform & SSH_PM_IPSEC_AH)
        {
          ssh_snprintf(spi_ah_in, sizeof(spi_ah_in), "%08lx",
                       (unsigned long) info->spi_ah_in);
          ssh_snprintf(spi_ah_out, sizeof(spi_ah_out), "%08lx",
                       (unsigned long) info->spi_ah_out);
        }
      else
        {
          spi_ah_in[0] = '\0';
          spi_ah_out[0] = '\0';
        }

      if (info->transform & SSH_PM_IPSEC_IPCOMP)
        {
          ssh_snprintf(cpi_ipcomp_in, sizeof(cpi_ipcomp_in), "%04x",
                       (unsigned long) info->cpi_ipcomp_in);
          ssh_snprintf(cpi_ipcomp_out, sizeof(cpi_ipcomp_out), "%04x",
                       (unsigned long) info->cpi_ipcomp_out);
        }
      else
        {
          cpi_ipcomp_in[0] = '\0';
          cpi_ipcomp_out[0] = '\0';
        }

      /* Format algorithms. */

      if (info->transform & SSH_PM_CRYPT_EXT1)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "ext1/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_EXT2)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "ext2/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_DES)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "des-cbc/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_3DES)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "3des-cbc/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_AES)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "aes-cbc/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_AES_CTR)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "aes-ctr/%u", info->cipher_key_size * 8);
        }
#ifdef SSHDIST_CRYPT_MODE_GCM
      else if (info->transform & SSH_PM_CRYPT_AES_GCM)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "aes-gcm/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_AES_GCM_8)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "aes-gcm-64/%u", info->cipher_key_size * 8);
        }
      else if (info->transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "null-auth-aes-gmac/%u",
                       info->cipher_key_size * 8);
        }
#endif /* SSHDIST_CRYPT_MODE_GCM */
      else if (info->transform & SSH_PM_CRYPT_NULL)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "null");
        }
      else if (info->transform & SSH_PM_CRYPT_MASK)
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "(unknown cipher)");
        }
      else
        {
          ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                       "");
        }

      if (info->transform & SSH_PM_MAC_EXT1)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "ext1/%u", info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_EXT2)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "ext2/%u", info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_HMAC_MD5)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "hmac-md5-96/%u", info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_HMAC_SHA1)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "hmac-sha1-96/%u", info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_HMAC_SHA2)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "hmac-sha2-%u/%u",
                       (info->mac_key_size * 8) / 2,
                       info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_XCBC_AES)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "xcbc-aes-96/%u", info->mac_key_size * 8);
        }
      else if (info->transform & SSH_PM_MAC_MASK)
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "(unknown mac)");
        }
      else
        {
          ssh_snprintf(mac_buf, sizeof(mac_buf),
                       "none");

          if ((info->transform & (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
                                  SSH_PM_IPSEC_AH)) ==
              (SSH_PM_CRYPT_NULL_AUTH_AES_GMAC |
               SSH_PM_IPSEC_AH))
            {
              /* AES_GMAC has been configured to the kernel space
                 as cipher although it is actually used as MAC.
                 Fix the information to show up properly to the user. */

              ssh_snprintf(cipher_buf, sizeof(cipher_buf),
                           "none");

              ssh_snprintf(mac_buf, sizeof(mac_buf),
                           "gmac-aes/%u",
                           info->cipher_key_size * 8);
            }
        }

      if (info->transform & SSH_PM_COMPRESS_DEFLATE)
        {
          ssh_snprintf(ipcomp_buf, sizeof(ipcomp_buf),
                       "deflate");
        }
      else if (info->transform & SSH_PM_COMPRESS_LZS)
        {
          ssh_snprintf(ipcomp_buf, sizeof(ipcomp_buf),
                       "lzs");
        }
      else if (info->transform & SSH_PM_COMPRESS_MASK)
        {
          ssh_snprintf(ipcomp_buf, sizeof(ipcomp_buf),
                       "(unknown compression)");
        }
      else
        {
          ssh_snprintf(ipcomp_buf, sizeof(ipcomp_buf),
                       "none");
        }

      ssh_snprintf(
               ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C
               SSH_FCFC SSH_FCFC
               SSH_FCSC SSH_FCSC
               SSH_FCSC SSH_FCSC
               SSH_FCSC SSH_FCSC
               SSH_FCSC SSH_FCSC SSH_FCSC
               "<td>%s (%d)</td>"
               "<td align=\"left\"><a href=\"detail/0x%08lx\">Info</a></td>"
               "</tr>\n",
                   (unsigned int) ++ctx->seqnum,
               ssh_ipaddr_render, &info->own_addr,
               ssh_ipaddr_render, &info->gw_addr,
               spi_esp_in, spi_esp_out,
               spi_ah_in, spi_ah_out,
               cpi_ipcomp_in, cpi_ipcomp_out,
               cipher_buf, mac_buf, ipcomp_buf,
               info->routing_instance_name, info->routing_instance_id,
               (unsigned long) ctx->transform_index);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
          != SSH_BUFFER_OK)
        ctx->error = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting transform statistics. */
static void
ssh_ipm_transform_stats_cb(SshPm pm, const SshEngineTransformStats stats,
                           void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (stats == NULL)
    goto not_found;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Transform Statistics</h2>\n",
                              "<table border>\n",
                              "<tr>",
                              "<th colspan=\"2\">Octets</th>",
                              "<th colspan=\"2\">Packets</th>"
                              "<th colspan=\"2\">Dropped Packets</th>"
                              "<th rowspan=\"2\">Rekeys</th>"
                              "<th rowspan=\"2\">Flows</th>"
                              "</tr>\n",
                              "<tr>",
                              HCELL("In"), HCELL("Out"),
                              HCELL("In"), HCELL("Out"),
                              HCELL("Drop"), HCELL("MAC Failures"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  ssh_snprintf(ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C SSH_FR32C
               SSH_FR32C SSH_FR32C
               SSH_FR32C SSH_FR32C
               SSH_FR32C
               SSH_FR32C
               "</tr>\n",
               (unsigned int) stats->data.in_octets,
               (unsigned int) stats->data.out_octets,
               (unsigned int) stats->data.in_packets,
               (unsigned int) stats->data.out_packets,
               (unsigned int) stats->data.drop_packets,
               (unsigned int) stats->data.num_mac_fails,
               (unsigned int) stats->control.num_rekeys,
               (unsigned int) stats->control.num_flows_active);

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;


  /* Error handling. */

 error:
  ctx->error = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;

 not_found:
  ctx->not_found = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;
}

/* A callback function for retrieving next flow index. */
static void
ssh_ipm_flow_index_cb(SshPm pm, SshUInt32 ind, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  ctx->flow_index = ind;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting public flow information. */
static void
ssh_ipm_flow_info_cb(SshPm pm, const SshEngineFlowInfo info,
                     void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (info
      && (ctx->filter_flags == 0
          || (ctx->filter_flags & SSH_IPM_HTTP_F_TRANSFORM
              && (info->forward_transform_index == ctx->transform_index
                  || info->reverse_transform_index == ctx->transform_index))
          || (ctx->filter_flags & SSH_IPM_HTTP_F_RULE
              && info->rule_index == ctx->rule_index)))
    {
      char src_port_buf[16];
      char dst_port_buf[16];
      char forward_tr_buf[64];
      char reverse_tr_buf[64];

      if (info->src_port)
        ssh_snprintf(src_port_buf, sizeof(src_port_buf), "%d",
                     (int) info->src_port);
      else
        ssh_snprintf(src_port_buf, sizeof(src_port_buf), "");

      if (info->dst_port)
        ssh_snprintf(dst_port_buf, sizeof(dst_port_buf), "%d",
                     (int) info->dst_port);
      else
        ssh_snprintf(dst_port_buf, sizeof(dst_port_buf), "");

      /* Create transform links. */

      if (info->is_dangling == FALSE && info->is_trigger == FALSE)
        {
          if (info->forward_transform_index == SSH_IPSEC_INVALID_INDEX)
            ssh_snprintf(forward_tr_buf, sizeof(forward_tr_buf), "");
          else
            ssh_snprintf(forward_tr_buf, sizeof(forward_tr_buf),
                         "<a href=\"/sas/ipsec/detail/0x%08lx\">%08lx</a>",
                         (unsigned long) info->forward_transform_index,
                         (unsigned long) info->forward_transform_index);

          if (info->reverse_transform_index == SSH_IPSEC_INVALID_INDEX)
            ssh_snprintf(reverse_tr_buf, sizeof(reverse_tr_buf), "");
          else
            ssh_snprintf(reverse_tr_buf, sizeof(reverse_tr_buf),
                         "<a href=\"/sas/ipsec/detail/0x%08lx\">%lx</a>",
                         (unsigned long) info->reverse_transform_index,
                         (unsigned long) info->reverse_transform_index);
        }
      else if (info->is_trigger)
        {
          ssh_snprintf(forward_tr_buf, sizeof(forward_tr_buf), "TRIGGER");
          ssh_snprintf(reverse_tr_buf, sizeof(reverse_tr_buf), "TRIGGER");
        }
      else
        {
          SSH_ASSERT(info->is_dangling);
          ssh_snprintf(forward_tr_buf, sizeof(forward_tr_buf), "DANGLING");
          ssh_snprintf(reverse_tr_buf, sizeof(reverse_tr_buf), "DANGLING");
        }

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   "<td>%x</td>"
                   "<td>%d</td>"
                   "<td>%d</td>"
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
                   "<td>%s</td>"
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
                   "<td>%s</td>"
                   "<td>%@</td><td>%s</td>"
                   "<td>%@</td><td>%s</td>"
                   "<td>%s (%d)</td>"
                   "<td><a href=\"/flows/detail/0x%08lx\">Statistics</a></td>"
                   "<td>%s</td><td>%s</td>"
                   "<td><a href=\"/rules/detail/0x%08lx\">%lx</a></td>"
                   "</tr>\n",
                   (unsigned int) ctx->flow_index,
                   (int) info->lru_level,
                   (int) info->idle_time,
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
                   ssh_find_keyword_name(ssh_engine_protocol_states,
                                         info->protocol_state),
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
                   ssh_find_keyword_name(ssh_ip_protocol_id_keywords,
                                         info->ipproto),
                   ssh_ipaddr_render, &info->src,
                   src_port_buf,
                   ssh_ipaddr_render, &info->dst,
                   dst_port_buf,
                   info->routing_instance_name,
                   (int) info->routing_instance_id,
                   (unsigned long) ctx->flow_index,
                   forward_tr_buf, reverse_tr_buf,
                   (unsigned long) info->rule_index,
                   (unsigned long) info->rule_index);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
          != SSH_BUFFER_OK)
        ctx->error = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting flow statistics. */
static void
ssh_ipm_flow_stats_cb(SshPm pm, const SshEngineFlowStats stats, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (stats == NULL)
    goto not_found;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th colspan=\"2\">Octets</th>",
                              "<th colspan=\"2\">Packets</th>"
                              "<th rowspan=\"2\">Dropped<br>Packets</th>"
                              "</tr>\n",
                              "<tr>",
                              HCELL("Forward"), HCELL("Reverse"),
                              HCELL("Forward"), HCELL("Reverse"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  ssh_snprintf(ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C SSH_FR32C
               SSH_FR32C SSH_FR32C
               SSH_FR32C
               "</tr>\n",
               (unsigned int) stats->forward_octets,
               (unsigned int) stats->reverse_octets,
               (unsigned int) stats->forward_packets,
               (unsigned int) stats->reverse_packets,
               (unsigned int) stats->drop_packets);

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;


  /* Error handling. */

 error:
  ctx->error = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;

 not_found:
  ctx->not_found = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;
}

/* A callback function for retrieving next rule index. */
static void
ssh_ipm_rule_index_cb(SshPm pm, SshUInt32 ind, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  ctx->rule_index = ind;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting public rule information. */
static void
ssh_ipm_rule_info_cb(SshPm pm, const SshEngineRuleInfo info, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  const char *protoname;
  char protobuf[16];

  if (info
      && (ctx->filter_flags == 0
          || (ctx->filter_flags & SSH_IPM_HTTP_F_TRANSFORM
              && info->transform_index == ctx->transform_index)
          || (ctx->filter_flags & SSH_IPM_HTTP_F_TUNNEL_ID
              && info->tunnel_id == ctx->tunnel_id)))
    {
      char *type = "";
      char *ifname;
      char routing_instance_id[16];
      char icmp_type[16];
      char icmp_code[16];
      char depends_on[256];
      char from_tunnel[256];
      char to_tunnel[256];

      switch (info->type)
        {
        case SSH_PM_ENGINE_RULE_DROP:
          type = "Drop";
          break;

        case SSH_PM_ENGINE_RULE_REJECT:
          type = "Reject";
          break;

        case SSH_PM_ENGINE_RULE_PASS:
          type = "Pass";
          break;

        case SSH_PM_ENGINE_RULE_APPLY:
          type = "Apply";
          break;

#ifndef SSH_IPSEC_SMALL
        case SSH_PM_ENGINE_RULE_DORMANT_APPLY:
          type ="Dormant";
          break;
#endif /* SSH_IPSEC_SMALL */

        case SSH_PM_ENGINE_RULE_TRIGGER:
          type = "Trigger";
          break;
        }

      if ((info->flags & SSH_PM_ENGINE_RULE_SEL_IFNUM) == 0
          || !ssh_pm_get_interface_name(pm, info->ifnum, &ifname))
        ifname = "";

      if (info->routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY)
        ssh_snprintf(routing_instance_id, sizeof(routing_instance_id),
                     "any");
      else
        ssh_snprintf(routing_instance_id, sizeof(routing_instance_id),
                     "%d", info->routing_instance_id);

      if (info->flags & SSH_PM_ENGINE_RULE_SEL_ICMPTYPE)
        ssh_snprintf(icmp_type, sizeof(icmp_type), "%u", info->icmp_type);
      else
        ssh_snprintf(icmp_type, sizeof(icmp_type), "");

      if (info->flags & SSH_PM_ENGINE_RULE_SEL_ICMPCODE)
        ssh_snprintf(icmp_code, sizeof(icmp_code), "%u", info->icmp_code);
      else
        ssh_snprintf(icmp_code, sizeof(icmp_code), "");

      if (info->depends_on != SSH_IPSEC_INVALID_INDEX)
        ssh_snprintf(depends_on, sizeof(depends_on),
                     "<a href=\"/rules/detail/0x%08lx\">%lx</a>",
                     (unsigned long) info->depends_on,
                     (unsigned long) info->depends_on);
      else
        ssh_snprintf(depends_on, sizeof(depends_on), "");

      if (info->tunnel_id > 1)
        ssh_snprintf(from_tunnel, sizeof(from_tunnel),
                     "<a href=\"/sas/ipsec/list/tunnelid/%u\">%u</a>",
                     (unsigned int) info->tunnel_id,
                     (unsigned int) info->tunnel_id);
      else if (info->tunnel_id == 1)
        ssh_snprintf(from_tunnel, sizeof(from_tunnel), "INTERNAL");
      else
        ssh_snprintf(from_tunnel, sizeof(from_tunnel), "");

      if (info->transform_index != SSH_IPSEC_INVALID_INDEX)
        ssh_snprintf(to_tunnel, sizeof(to_tunnel),
                     "<a href=\"/sas/ipsec/detail/0x%08lx\">%lx</a>",
                     (unsigned long) info->transform_index,
                     (unsigned long) info->transform_index);
      else
        ssh_snprintf(to_tunnel, sizeof(to_tunnel), "");

      protoname = ssh_find_keyword_name(ssh_ip_protocol_id_keywords,
                                        info->ipproto);
      if (protoname == NULL)
        {
          ssh_snprintf(protobuf, sizeof(protobuf), "(unknown %3u)",
                       info->ipproto);
          protoname = protobuf;
        }

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr>"
                   "<td>%x</td>"
                   "<td>%s</td>"
                   "<td>%u</td>"
                   "<td>%s</td>"
                   "<td>%@</td><td>%@</td><td>%u</td><td>%u</td>"
                   "<td>%@</td><td>%@</td><td>%u</td><td>%u</td>"
                   "<td>%s</td>"
                   "<td>%s (%s)</td>"
                   "<td>%s</td><td>%s</td>"
                   "<td><a href=\"/rules/detail/0x%08lx\">Statistics</a></td>"
                   "<td><a href=\"/flows/list/rule/0x%08lx\">Flows</a></td>"
                   "<td>%s</td>"
                   "<td>%s</td><td>%s</td>"
                   "</tr>\n",
                   (unsigned int) ctx->rule_index,
                   type,
                   (unsigned int) info->precedence,
                   protoname,
                   ssh_ipaddr_render, &info->src_ip_low,
                   ssh_ipaddr_render, &info->src_ip_high,
                   info->src_port_low, info->src_port_high,

                   ssh_ipaddr_render, &info->dst_ip_low,
                   ssh_ipaddr_render, &info->dst_ip_high,
                   info->dst_port_low, info->dst_port_high,

                   ifname,
                   info->routing_instance_name,
                   routing_instance_id,
                   icmp_type, icmp_code,

                   (unsigned long) ctx->rule_index,
                   (unsigned long) ctx->rule_index,
                   depends_on,
                   from_tunnel,
                   to_tunnel);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
          != SSH_BUFFER_OK)
        ctx->error = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function for formatting rule statistics. */
static void
ssh_ipm_rule_stats_cb(SshPm pm, const SshEngineRuleStats stats, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  if (stats == NULL)
    goto not_found;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th rowspan=\"2\">Times<br>Used</th>",
                              "<th colspan=\"2\">Flows</th>"
                              "</tr>\n",
                              "<tr>",
                              HCELL("Active"), HCELL("Total"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  ssh_snprintf(ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C
               SSH_FR32C SSH_FR32C
               "</tr>\n",
               (unsigned int) stats->times_used,
               (unsigned int) stats->num_flows_active,
               (unsigned int) stats->num_flows_total);

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  /* All done. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;


  /* Error handling. */

 error:
  ctx->error = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;

 not_found:
  ctx->not_found = 1;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* A callback function for formatting address pool statistics. */
static Boolean
ssh_ipm_address_pool_stats_cb(SshPm pm, const SshPmAddressPoolStats stats,
                              void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  char stats_type[30] = {'\0'};

  if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL) != 0)
    ssh_strcpy(stats_type, "DHCPv6 address pool");
  else if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCP_POOL) != 0)
    ssh_strcpy(stats_type, "DHCP address pool");
  else
    ssh_strcpy(stats_type, "Generic address pool");

  if (ssh_buffer_append_cstrs(
                    ctx->buffer,
                    "<h2>Address Pool Statistics</h2>\n",
                    "<table border>\n",
                    "<tr>",
                    "<th>Address Pool Name</th>",
                    LCELL(stats->name),
                    "</tr><tr>",
                    "<th>Type</th>",
                    LCELL(stats_type),
                    "</tr><tr>",
                    "<th>Currently allocated addresses</th>",
                    "</tr>\n",
                    NULL) != SSH_BUFFER_OK)
    goto error;

  ssh_snprintf(ctx->buf, sizeof(ctx->buf),
               "<tr>"
               SSH_FR32C
               "</tr>\n",
               (unsigned int) stats->current_num_allocated_addresses);

  if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
      != SSH_BUFFER_OK)
    goto error;

  if ((stats->type & SSH_PM_REMOTE_ACCESS_DHCP_POOL) != 0 ||
      (stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL) != 0)
    {
        if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "<tr>",
                                    "<th colspan=\"3\">DHCP statistics</th>",
                                    "<tr></tr>"
                                    "<th>DHCP packets transmitted</th>",
                                    "<th>DHCP packets received</th>",
                                    "<th>DHCP packets dropped</th>",
                                    "</tr>\n",
                                    NULL) != SSH_BUFFER_OK)
          goto error;

        ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                     "<tr>"
                     SSH_FR32C SSH_FR32C SSH_FR32C
                     "</tr>\n",
                     (unsigned int) stats->dhcp.packets_transmitted,
                     (unsigned int) stats->dhcp.packets_received,
                     (unsigned int) stats->dhcp.packets_dropped);
        if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
            != SSH_BUFFER_OK)
          goto error;

        if (stats->type & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL)
          {
            if (ssh_buffer_append_cstrs(ctx->buffer,
                                "<tr>",
                                "<th colspan=\"2\">DHCP Relay messages:</th>",
                                "</tr><tr>",
                                "<th>RELAY-FORW sent</th>",
                                "<th>RELAY-REPL received</th>",
                                "</tr>\n",
                                NULL) != SSH_BUFFER_OK)
              goto error;

            ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                     "<tr>"
                     SSH_FR32C SSH_FR32C
                     "</tr>\n",
                     (unsigned int) stats->dhcp.dhcpv6_relay_forward,
                     (unsigned int) stats->dhcp.dhcpv6_relay_reply);
            if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                != SSH_BUFFER_OK)
              goto error;

            if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "<tr>",
                                    "<th colspan=\"7\">Per DHCP message:</th>",
                                    "</tr><tr>",
                                    "<th>SOLICIT sent</th>",
                                    "<th>REPLY received</th>",
                                    "<th>DECLINE sent</th>",
                                    "<th>RENEW sent</th>",
                                    "<th>RELEASE sent</th>",
                                    "</tr>\n",
                                    NULL) != SSH_BUFFER_OK)
              goto error;

            ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                     "<tr>"
                     SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                     SSH_FR32C
                         "</tr>\n",
                     (unsigned int) stats->dhcp.dhcpv6_solicit,
                     (unsigned int) stats->dhcp.dhcpv6_reply,
                     (unsigned int) stats->dhcp.dhcpv6_decline,
                     (unsigned int) stats->dhcp.dhcpv6_renew,
                     (unsigned int) stats->dhcp.dhcpv6_release);
            if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                != SSH_BUFFER_OK)
              goto error;
          }
        else
          {
            if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "<tr>",
                                    "<th colspan=\"7\">Per DHCP message:</th>",
                                    "</tr><tr>",
                                    "<th>DHCPDISCOVER sent</th>",
                                    "<th>DHCPOFFER received</th>",
                                    "<th>DHCPREQUEST sent</th>",
                                    "<th>DHCPACK received</th>",
                                    "<th>DHCPNAK received</th>",
                                    "<th>DHCPDECLINE sent</th>",
                                    "<th>DHCPRELEASE sent</th>",
                                    "</tr>\n",
                                    NULL) != SSH_BUFFER_OK)
              goto error;

            ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                     "<tr>"
                     SSH_FR32C SSH_FR32C SSH_FR32C SSH_FR32C
                     SSH_FR32C SSH_FR32C SSH_FR32C
                     "</tr>\n",
                     (unsigned int) stats->dhcp.discover,
                     (unsigned int) stats->dhcp.offer,
                     (unsigned int) stats->dhcp.request,
                     (unsigned int) stats->dhcp.ack,
                     (unsigned int) stats->dhcp.nak,
                     (unsigned int) stats->dhcp.decline,
                     (unsigned int) stats->dhcp.release);

            if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf,  NULL)
                != SSH_BUFFER_OK)
              goto error;
          }
    }

  if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  return TRUE;

 error:
  return FALSE;

}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Destructor for HTTP threads. */
static void
ssh_ipm_http_thread_destructor(SshFSM fsm, void *context)
{
  SshIpmContext ipm = ssh_fsm_get_gdata_fsm(fsm);
  SshIpmHttpStats ctx = (SshIpmHttpStats) context;

  ipm->http_statistics_refcount--;

  if (ctx->buffer)
    ssh_buffer_free(ctx->buffer);
  if (ctx->hash)
    ssh_hash_free(ctx->hash);
  ssh_free(ctx->cert_id);
  ssh_free(ctx);
}


/******************************* URI handlers *******************************/

/* Index page and Table of Contents. */

SSH_FSM_STEP(ssh_ipm_http_st_index);
SSH_FSM_STEP(ssh_ipm_http_st_toc);

/* Version information. */

SSH_FSM_STEP(ssh_ipm_http_st_version);
SSH_FSM_STEP(ssh_ipm_http_st_version_global_stats);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* Address pools. */
SSH_FSM_STEP(ssh_ipm_http_st_addrpools);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Interface information. */

SSH_FSM_STEP(ssh_ipm_http_st_interfaces);

/* Auditing */
SSH_FSM_STEP(ssh_ipm_http_st_audit);

/* Global statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_global);
SSH_FSM_STEP(ssh_ipm_http_st_global_stats);


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/* RADIUS Accounting statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct);
SSH_FSM_STEP(ssh_ipm_http_st_radius_acct_stats);

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */


/* Rules. */
SSH_FSM_STEP(ssh_ipm_http_st_rules);

/* Flows. */
SSH_FSM_STEP(ssh_ipm_http_st_flows);
SSH_FSM_STEP(ssh_ipm_http_st_flows_flow_index);
SSH_FSM_STEP(ssh_ipm_http_st_flows_flow_info);
SSH_FSM_STEP(ssh_ipm_http_st_flows_detail);
SSH_FSM_STEP(ssh_ipm_http_st_flows_detail_stats);

/* Rules. */
SSH_FSM_STEP(ssh_ipm_http_st_rules);
SSH_FSM_STEP(ssh_ipm_http_st_rules_rule_index);
SSH_FSM_STEP(ssh_ipm_http_st_rules_rule_info);
SSH_FSM_STEP(ssh_ipm_http_st_rules_detail);
SSH_FSM_STEP(ssh_ipm_http_st_rules_detail_stats);

/* IKE SA statistics. */
SSH_FSM_STEP(ssh_ipm_http_st_ike);
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
SSH_FSM_STEP(ssh_ipm_http_st_ike_cert);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist);
SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist_database);
#endif /* SSH_PM_BLACKLIST_ENABLED */

/* IPSec SA info and statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall_tr_index);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall_tr_info);

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_tr_stats);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_rule_index);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_rule_info);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_flow_index);
SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_flow_info);

/* Trailer. */

SSH_FSM_STEP(ssh_ipm_http_st_trailer);

/* Request completed. */

SSH_FSM_STEP(ssh_ipm_http_st_done);

/* Error handling. */

SSH_FSM_STEP(ssh_ipm_http_st_error);
SSH_FSM_STEP(ssh_ipm_http_st_error_not_found);

SSH_FSM_STEP(ssh_ipm_http_st_finish);


/*************************** FSM state functions ****************************/

/* Index page and Table of Contents. */

SSH_FSM_STEP(ssh_ipm_http_st_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (!ipm->http_statistics->params.frames)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_toc);
      return SSH_FSM_CONTINUE;
    }

  /* Frames are enabled. */

  if (ssh_buffer_append_cstrs(
        ctx->buffer,
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\"\n"
        "  \"http://www.w3.org/TR/html4/frameset.dtd\">\n"
        "<html>\n"
        "<head>\n"
        "<title>" SSH_IPSEC_VERSION_STRING_SHORT "</title>\n"
        "</head>\n"
        "<frameset cols=\"20%,80%\">\n"
        "  <frame name=\"toc\" src=\"toc.html\">\n"
        "  <frame name=\"content\" src=\"version.html\">\n"
        "</frameset>\n"
        "</html>\n",
        NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* All done. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_toc)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  Boolean frames = ipm->http_statistics->params.frames;

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                NULL, TRUE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSH_IPSEC_STATISTICS
  if (ssh_buffer_append_cstrs(
        ctx->buffer,
        "<ul>\n",
        "  <li>SA Information\n",
        "  <ul>\n",
        "    <li>", SSH_IPM_LINK("sas/ike/", "IKE"), "\n",
        "    <li>", SSH_IPM_LINK("sas/ipsec/", "IPsec"), "\n",
        "  </ul>\n",
#ifdef SSH_PM_BLACKLIST_ENABLED
        "  <li>", SSH_IPM_LINK("ike-blacklist.html", "IKE Blacklist"), "\n",
#endif /* SSH_PM_BLACKLIST_ENABLED */
        "  <li>", SSH_IPM_LINK("rules/", "Rules"), "\n",
        "  <li>", SSH_IPM_LINK("flows/", "Flows"), "\n",
        "  <li>", SSH_IPM_LINK("audit/", "Audit Events"), "\n",
        "  <li>", SSH_IPM_LINK("global/", "Global Statistics"), "\n",
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
        "  <li>", SSH_IPM_LINK("addrpools/", "Address Pools"), "\n",
#ifdef SSHDIST_RADIUS
        "  <li>", SSH_IPM_LINK("radius_acct/",
                               "Radius Accounting Statistics"), "\n",
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
        "  <li>", SSH_IPM_LINK("ifinfo.html", "Interface Information"), "\n",
        "  <li>", SSH_IPM_LINK("version.html", "Version Information"), "\n",
        "</ul>\n",
        NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
#else /* SSH_IPSEC_STATISTICS */

  if (ssh_buffer_append_cstrs(
        ctx->buffer,
        "<ul>\n",
        "  <li>Statistics Information are not available. To obtain "
        "statistics, recompile with SSH_IPSEC_STATISTICS defined.",
        "</ul>\n",
        NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSH_IPSEC_STATISTICS */

  /* Trailer. */
  if (!ssh_ipm_http_page_trailer(&ipm->http_statistics->params, ctx->buffer,
                                 frames ? FALSE : TRUE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* All done. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);
  return SSH_FSM_CONTINUE;
}

/* Version information. */

SSH_FSM_STEP(ssh_ipm_http_st_version)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);


  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Version Information", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_version_global_stats);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_global_stats(pm, ssh_ipm_version_stats_cb,
                                             thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_version_global_stats)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ctx->error)
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

  return SSH_FSM_CONTINUE;
}


/* Interface information. */

SSH_FSM_STEP(ssh_ipm_http_st_interfaces)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshUInt32 ifnum;
  Boolean retval;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Interface Information", FALSE))
    goto error;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>"
                              "<th>Ifnum</th>"
                              "<th>Name</th>"
                              "<th>Address</th>"
                              "<th>Netmask</th>"
                              "<th>Broadcast</th>"
                              "<th>Routing Instance</th>"
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  for (retval = ssh_pm_interface_enumerate_start(pm, &ifnum);
       retval;
       retval = ssh_pm_interface_enumerate_next(pm, ifnum, &ifnum))
    {
      SshUInt32 i, addrcount;
      char *ifname;
      const char *routing_instance_name;
      SshVriId routing_instance_id;

      if (!ssh_pm_interface_get_number_of_addresses(pm, ifnum,
                                                    &addrcount)
          || !ssh_pm_get_interface_name(pm, ifnum, &ifname))
        goto error;

      /* Format header for this interface. */

      if (ifname == NULL || ifname[0] == '\0')
        continue;

      ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                   "<tr><td rowspan=\"%u\">%u</td><td rowspan=\"%u\">%s</td>",
                   (unsigned int) addrcount,
                   (unsigned int) ifnum,
                   (unsigned int) addrcount, ifname);

      if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
          != SSH_BUFFER_OK)
        goto error;

      /* Add addresses. */
      for (i = 0; i < addrcount; i++)
        {
          SshIpAddrStruct ip, netmask, broadcast;

          if (!ssh_pm_interface_get_address(pm, ifnum, i, &ip)
              || !ssh_pm_interface_get_netmask(pm, ifnum, i, &netmask))
            goto error;

          ssh_snprintf(ctx->buf, sizeof(ctx->buf), "%s<td>%@</td><td>%@</td>",
                       i == 0 ? "" : "<tr>",
                       ssh_ipaddr_render, &ip,
                       ssh_ipmask_render, &netmask);

          if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
              != SSH_BUFFER_OK)
            goto error;

          if (SSH_IP_IS4(&ip))
            {
              if (!ssh_pm_interface_get_broadcast(pm, ifnum, i,
                                                  &broadcast))
                goto error;

              ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<td>%@</td>",
                           ssh_ipaddr_render, &broadcast);
            }
          else
            {
              ssh_snprintf(ctx->buf, sizeof(ctx->buf), "<td></td>");
            }

          if (i == 0)
            {
              if (!ssh_pm_interface_get_routing_instance_id(pm, ifnum,
                                                      &routing_instance_id)
                  || !ssh_pm_get_interface_routing_instance_name(pm, ifnum,
                                                      &routing_instance_name))
                goto error;

              if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, NULL)
                  != SSH_BUFFER_OK)
                goto error;

              ssh_snprintf(ctx->buf, sizeof(ctx->buf),
                           "<td rowspan=\"%u\">%s (%d)</td>",
                           (unsigned int) addrcount,
                           routing_instance_name,
                           routing_instance_id);
            }

          if (ssh_buffer_append_cstrs(ctx->buffer, ctx->buf, "</tr>\n", NULL)
              != SSH_BUFFER_OK)
            goto error;
        }
    }
  if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  /* All done. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
  return SSH_FSM_CONTINUE;


  /* Error handling. */

 error:

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  return SSH_FSM_CONTINUE;
}

/* Audit events */
SSH_GLOBAL_DECLARE(SshPmAuditContext, pm_audit_context);
#define pm_audit_context SSH_GLOBAL_USE(pm_audit_context)

SSH_FSM_STEP(ssh_ipm_http_st_audit)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPmAuditEvent events;
  SshUInt16 nevents = 0;

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Audit Events", FALSE))
    goto error;

  /* Render audit event ring now */
  nevents = ssh_ipsecpm_audit_events(pm_audit_context, &events);
  if (nevents > 0)
    {
      if (ssh_buffer_append_cstrs(ctx->buffer, "<table border>\n", NULL)
          != SSH_BUFFER_OK)
        goto error;
      do {
        nevents -= 1;
        if (ssh_buffer_append_cstrs(ctx->buffer,
                                    "<tr>\n<td>\n",
                                    events[nevents].data,
                                    "</td>\n</tr>\n",
                                    NULL) != SSH_BUFFER_OK)
          goto error;
      } while (nevents != 0);

      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
          != SSH_BUFFER_OK)
        goto error;

      ssh_free(events);
    }
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
  return SSH_FSM_CONTINUE;

 error:
  if (nevents)
    ssh_free(events);

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  return SSH_FSM_CONTINUE;
}


/* Global statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_global)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Global Statistics", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_global_stats);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_global_stats(pm, ssh_ipm_global_stats_cb,
                                             thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_global_stats)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ctx->error)
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/* RADIUS Accounting statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Radius Accounting Statistics", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_radius_acct_stats);

  SSH_FSM_ASYNC_CALL(
          ssh_pm_radius_acct_get_stats(
                  ipm->pm,
                  ssh_ipm_radius_acct_stats_cb,
                  thread));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_radius_acct_stats)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ctx->error)
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

  return SSH_FSM_CONTINUE;
}

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Flows. */

SSH_FSM_STEP(ssh_ipm_http_st_flows)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* List flows. */

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Flows", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (!ssh_ipm_http_flow_info_header(ctx))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_flows_flow_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_flow_index(pm,
                                                SSH_IPSEC_INVALID_INDEX,
                                                ssh_ipm_flow_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_flows_flow_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->flow_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All flows enumerated. */
      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
          != SSH_BUFFER_OK)
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      else
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

      return SSH_FSM_CONTINUE;
    }

  /* Get public flow info. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_flows_flow_info);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_flow_info(pm,
                                          ctx->flow_index,
                                          ssh_ipm_flow_info_cb, thread));
  SSH_NOTREACHED;
}


SSH_FSM_STEP(ssh_ipm_http_st_flows_flow_info)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Continue enumerating flows. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_flows_flow_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_flow_index(pm,
                                                ctx->flow_index,
                                                ssh_ipm_flow_index_cb,
                                                thread));
  SSH_NOTREACHED;
}


SSH_FSM_STEP(ssh_ipm_http_st_flows_detail)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Flow Statistics", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_flows_detail_stats);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_flow_stats(pm,
                                           ctx->flow_index,
                                           ssh_ipm_flow_stats_cb,
                                           thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_flows_detail_stats)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ctx->not_found)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error_not_found);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
/* Address pool */
SSH_FSM_STEP(ssh_ipm_http_st_addrpools)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;


  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params,
                                ctx->buffer,
                                "Address Pool Information",
                                FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }


  if (ssh_pm_address_pool_foreach_get_stats(ipm->pm,
                                            ssh_ipm_address_pool_stats_cb,
                                            thread) == FALSE)
    goto error;

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
  return SSH_FSM_CONTINUE;

 error:
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* Rules. */

SSH_FSM_STEP(ssh_ipm_http_st_rules)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  /* List rules. */

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Rules", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (!ssh_ipm_http_rule_info_header(ctx))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_rules_rule_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_rule_index(pm,
                                                SSH_IPSEC_INVALID_INDEX,
                                                ssh_ipm_rule_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_rules_rule_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All rules enumerated. */
      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
          != SSH_BUFFER_OK)
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      else
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

      return SSH_FSM_CONTINUE;
    }

  /* Get public rule info. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_rules_rule_info);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_rule_info(pm,
                                          ctx->rule_index,
                                          ssh_ipm_rule_info_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_rules_rule_info)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Continue enumerating rules. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_rules_rule_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_rule_index(pm,
                                                ctx->rule_index,
                                                ssh_ipm_rule_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_rules_detail)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Rule Statistics", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_rules_detail_stats);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_rule_stats(pm,
                                           ctx->rule_index,
                                           ssh_ipm_rule_stats_cb,
                                           thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_rules_detail_stats)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ctx->not_found)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error_not_found);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

  return SSH_FSM_CONTINUE;
}

/* IKE SA statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_ike)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ssh_hash_allocate("md5", &ctx->hash) != SSH_CRYPTO_OK)
    goto error;

  ctx->hash_digest_len = ssh_hash_digest_length("md5");

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "IKE SA Information", FALSE))
    goto error;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th rowspan=\"2\"></th>",
                              "<th rowspan=\"2\">P1<br>Done</th>",
                              "<th rowspan=\"2\">IKE version</th>",
                              "<th rowspan=\"2\">Child SAs</th>",
                              "<th rowspan=\"2\">Created</th>",
                              "<th colspan=\"2\">IP Address</th>",
                              "<th colspan=\"2\">Identity</th>",
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                              "<th colspan=\"2\">Second Identity</th>",
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                              "<th colspan=\"3\">Algorithm</th>",
                              "<th colspan=\"2\">Certificate</th>",
                              "<th rowspan=\"2\">Routing Instance</th>",
                              "</tr>\n",

                              "<tr>",
                              HCELL("Local"), HCELL("Remote"),
                              HCELL("Local"), HCELL("Remote"),
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                              HCELL("Local"), HCELL("Remote"),
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                              HCELL("Encryption"), HCELL("Hash"), HCELL("PRF"),
                              HCELL("CA"), HCELL("Peer"),

                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto error;

  /* For each IKE server context in the policy manager. */
  if (!ssh_pm_foreach_ike_server(pm, ssh_ipm_ike_server_cb, thread))
    goto error;

  if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
      != SSH_BUFFER_OK)
    goto error;

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
  return SSH_FSM_CONTINUE;


  /* Error handling. */

 error:

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
SSH_FSM_STEP(ssh_ipm_http_st_ike_cert)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ssh_hash_allocate("md5", &ctx->hash) != SSH_CRYPTO_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  ctx->hash_digest_len = ssh_hash_digest_length("md5");

  /* For each IKE server context in the policy manager. */
  (void) ssh_pm_foreach_ike_server(pm, ssh_ipm_ike_server_cert_cb,
                                   thread);

  /* Did we find the certificate? */
  if (ssh_buffer_len(ctx->buffer) == 0)
    {
      /** No certificates found. */
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error_not_found);
      return SSH_FSM_CONTINUE;
    }

  /* Certificate found. */

  ssh_http_server_set_values(
        ctx->conn,
        SSH_HTTP_HDR_FIELD, "Content-Type", "application/x-x509-ca-cert",
        SSH_HTTP_HDR_END);

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);

  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
static Boolean
ssh_ipm_blacklist_make_stats_row(SshIpmHttpStats ctx,
                                 char *name,
                                 SshUInt32 allowed_cnt,
                                 SshUInt32 blocked_cnt)
{
  ssh_snprintf((unsigned char *)ctx->buf,
               sizeof(ctx->buf),
               SSH_FR32C SSH_FR32C,
               (unsigned int) allowed_cnt,
               (unsigned int) blocked_cnt);

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<tr>",
                              LCELL(name),
                              ctx->buf,
                              "</tr>",
                              NULL) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

static Boolean
ssh_ipm_blacklist_stats_cb(SshPm pm,
                           const SshPmBlacklistStats stats,
                           void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);
  SshUInt32 allowed_cnt;
  SshUInt32 blocked_cnt;

  if (stats == NULL)
    {
      ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Statistics collection disabled</h2>\n",
                              NULL);
      goto out;
    }

  /* Show statistics */
  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Statistics</h2>\n",
                              "<table border>\n",
                              NULL) != SSH_BUFFER_OK)
    goto out;

  /* Append counter of database entries */
  ssh_snprintf((unsigned char *)ctx->buf,
               sizeof(ctx->buf),
               "%u",
               (unsigned int) stats->blacklist_entries);

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<tr>",
                              "<th>Number of database entries</th>",
                              "<td colspan=\"2\" align=\"right\">",
                              ctx->buf,
                              "</td>"
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto out;

  /* Append statistics counters */
  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<tr>",
                              HCELL("Counter"),
                              HCELL("Allowed"),
                              HCELL("Blocked"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    goto out;

  allowed_cnt = stats->allowed_ikev2_r_initial_exchanges;
  blocked_cnt = stats->blocked_ikev2_r_initial_exchanges;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [R] initial exchanges",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev2_r_create_child_exchanges;
  blocked_cnt = stats->blocked_ikev2_r_create_child_exchanges;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [R] create child exchanges",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev2_r_ipsec_sa_rekeys;
  blocked_cnt = stats->blocked_ikev2_r_ipsec_sa_rekeys;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [R] IPsec SA rekeys",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev2_r_ike_sa_rekeys;
  blocked_cnt = stats->blocked_ikev2_r_ike_sa_rekeys;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [R] IKE SA rekeys",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev2_i_ipsec_sa_rekeys;
  blocked_cnt = stats->blocked_ikev2_i_ipsec_sa_rekeys;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [I] IPsec SA rekeys",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev2_i_ike_sa_rekeys;
  blocked_cnt = stats->blocked_ikev2_i_ike_sa_rekeys;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv2 [I] IKE SA rekeys",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev1_r_main_mode_exchanges;
  blocked_cnt = stats->blocked_ikev1_r_main_mode_exchanges;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv1 [R] main mode exchanges",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev1_r_aggressive_mode_exchanges;
  blocked_cnt = stats->blocked_ikev1_r_aggressive_mode_exchanges;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv1 [R] aggressive mode exchanges",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev1_r_quick_mode_exchanges;
  blocked_cnt = stats->blocked_ikev1_r_quick_mode_exchanges;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv1 [R] quick mode exchanges",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev1_i_ipsec_sa_rekeys;
  blocked_cnt = stats->blocked_ikev1_i_ipsec_sa_rekeys;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv1 [I] IPsec SA rekeys",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  allowed_cnt = stats->allowed_ikev1_i_dpd_sa_creations;
  blocked_cnt = stats->blocked_ikev1_i_dpd_sa_creations;
  if (ssh_ipm_blacklist_make_stats_row(ctx,
                                       "IKEv1 [I] DPD SA creations",
                                       allowed_cnt,
                                       blocked_cnt) == FALSE)
    goto out;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "</table>\n",
                              NULL) != SSH_BUFFER_OK)
    goto out;

 out:

  /* All done */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params,
                                ctx->buffer,
                                "Blacklist Information",
                                FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ike_blacklist_database);
  SSH_FSM_ASYNC_CALL(ssh_pm_blacklist_get_stats(ipm->pm,
                                                ssh_ipm_blacklist_stats_cb,
                                                thread));
  SSH_NOTREACHED;
}

static Boolean
ssh_ipm_blacklist_ike_id_info_cb(SshPm pm,
                                 SshPmBlacklistIkeIdInfo info,
                                 void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) ssh_fsm_get_tdata(thread);

  /* Check if iteration has ended */
  if (info == NULL)
    return TRUE;

#ifdef SSH_IPSEC_STATISTICS
  ssh_snprintf((unsigned char *)ctx->buf,
               sizeof(ctx->buf),
               SSH_FR32C,
               info->stat_blocked);
#endif /* SSH_IPSEC_STATISTICS */

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<tr>",
                              LCELL(info->type),
                              LCELL(info->data),
#ifdef SSH_IPSEC_STATISTICS
                              ctx->buf,
#endif /* SSH_IPSEC_STATISTICS */
                              "</tr>\n", NULL) != SSH_BUFFER_OK)
    return FALSE;

  return TRUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_ike_blacklist_database)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<h2>Database</h2>\n",
                              "<table border>\n",
                              "<tr>",
                              "<th>Type</th>",
                              "<th>Data</th>",
#ifdef SSH_IPSEC_STATISTICS
                              "<th>Blocked</th>",
#endif /* SSH_IPSEC_STATISTICS */
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  (void) ssh_pm_blacklist_foreach_ike_id(ipm->pm,
                                         ssh_ipm_blacklist_ike_id_info_cb,
                                         thread);

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "</table>\n",
                              NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
  return SSH_FSM_CONTINUE;
}
#endif /* SSH_PM_BLACKLIST_ENABLED */

/* IPSec SA info and statistics. */

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "IPsec SA Information", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ssh_buffer_append_cstrs(ctx->buffer,
                              "<table border>\n",
                              "<tr>",
                              "<th rowspan=\"2\"></th>",
                              "<th colspan=\"2\">Peer</th>"
                              "<th colspan=\"2\">ESP</th>"
                              "<th colspan=\"2\">AH</th>"
                              "<th colspan=\"2\">IPCOMP</th>"
                              "<th colspan=\"3\">Algorithms</th>"
                              "<th rowspan=\"2\">Routing Instance</th>"
                              "<th rowspan=\"2\">Info</th>"
                              "</tr>\n",
                              "<tr>",
                              HCELL("Local"), HCELL("Remote"),
                              HCELL("SPI In"), HCELL("SPI Out"),
                              HCELL("SPI In"), HCELL("SPI Out"),
                              HCELL("CPI In"), HCELL("CPI Out"),
                              HCELL("Cipher"), HCELL("MAC"),
                              HCELL("Compression"),
                              "</tr>\n",
                              NULL) != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_overall_tr_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_transform_index(
                                                pm,
                                                ctx->transform_index,
                                                ssh_ipm_transform_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall_tr_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->transform_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All transforms enumerated. */
      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
          != SSH_BUFFER_OK)
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      else
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

      return SSH_FSM_CONTINUE;
    }

  /* Get public transform info. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_overall_tr_info);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_transform_info(pm,
                                               ctx->transform_index,
                                               ssh_ipm_transform_info_cb,
                                               thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_overall_tr_info)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Continue enumerating transforms. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_overall_tr_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_transform_index(
                                                pm,
                                                ctx->transform_index,
                                                ssh_ipm_transform_index_cb,
                                                thread));
  SSH_NOTREACHED;

}


SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (!ssh_ipm_http_page_header(ctx,
                                &ipm->http_statistics->params, ctx->buffer,
                                "Detailed IPsec SA Information", FALSE))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_tr_stats);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_transform_stats(pm,
                                                ctx->transform_index,
                                                ssh_ipm_transform_stats_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_tr_stats)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ctx->not_found)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error_not_found);
      return SSH_FSM_CONTINUE;
    }

  /* List rules. */

  if (ssh_buffer_append_cstrs(ctx->buffer, "<h2>Rules</h2>\n", NULL)
      != SSH_BUFFER_OK)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (!ssh_ipm_http_rule_info_header(ctx))
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_rule_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_rule_index(pm,
                                                SSH_IPSEC_INVALID_INDEX,
                                                ssh_ipm_rule_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_rule_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All rules enumerated.  List flows.*/

      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n<h2>Flows</h2>\n",
                                  NULL)
          != SSH_BUFFER_OK)
        {
          SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
          return SSH_FSM_CONTINUE;
        }

      if (!ssh_ipm_http_flow_info_header(ctx))
        {
          SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_flow_index);
      SSH_FSM_ASYNC_CALL(ssh_pm_get_next_flow_index(pm,
                                                    SSH_IPSEC_INVALID_INDEX,
                                                    ssh_ipm_flow_index_cb,
                                                    thread));
      SSH_NOTREACHED;
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);
      return SSH_FSM_CONTINUE;
    }

  /* Get public rule info. */
  ctx->filter_flags = SSH_IPM_HTTP_F_TRANSFORM;
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_rule_info);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_rule_info(pm,
                                          ctx->rule_index,
                                          ssh_ipm_rule_info_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_rule_info)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Continue enumerating rules. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_rule_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_rule_index(pm,
                                                ctx->rule_index,
                                                ssh_ipm_rule_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_flow_index)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->flow_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* All flows enumerated. */
      if (ssh_buffer_append_cstrs(ctx->buffer, "</table>\n", NULL)
          != SSH_BUFFER_OK)
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      else
        SSH_FSM_SET_NEXT(ssh_ipm_http_st_trailer);

      return SSH_FSM_CONTINUE;
    }

  /* Get public flow info. */
  ctx->filter_flags = SSH_IPM_HTTP_F_TRANSFORM;
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_flow_info);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_flow_info(pm,
                                          ctx->flow_index,
                                          ssh_ipm_flow_info_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_ipsec_sas_detail_flow_info)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;
  SshPm pm = (*ipm->cb)(ipm->cb_ctx, SSH_IPM_CONTEXT_GET_PM, NULL_FNPTR, NULL);

  if (ctx->error)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Continue enumerating flows. */
  SSH_FSM_SET_NEXT(ssh_ipm_http_st_ipsec_sas_detail_flow_index);
  SSH_FSM_ASYNC_CALL(ssh_pm_get_next_flow_index(pm,
                                                ctx->flow_index,
                                                ssh_ipm_flow_index_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_http_st_trailer)
{
  SshIpmContext ipm = (SshIpmContext) fsm_context;
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  if (!ssh_ipm_http_page_trailer(&ipm->http_statistics->params, ctx->buffer,
                                 TRUE))
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_error);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_http_st_done);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_done)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  /* Send buffer steals the buffer. */
  ssh_http_server_send_buffer(ctx->conn, ctx->buffer);
  ctx->buffer = NULL;

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_error)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  ssh_http_server_error_code(ctx->conn, SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR);

  if(ctx->stream)
    ssh_stream_destroy(ctx->stream);

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_ipm_http_st_error_not_found)
{
  SshIpmHttpStats ctx = (SshIpmHttpStats) thread_context;

  ssh_http_server_error_not_found(ctx->conn);

  if(ctx->stream)
    ssh_stream_destroy(ctx->stream);

  SSH_FSM_SET_NEXT(ssh_ipm_http_st_finish);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_http_st_finish)
{
  return SSH_FSM_FINISH;
}


/* URI handler for all HTTP interface URIs. */
static  Boolean
ssh_ipm_http_handler(SshHttpServerContext http_ctx,
                     SshHttpServerConnection conn,
                     SshStream stream, void *context)
{
  SshIpmContext ipm = (SshIpmContext) context;
  SshIpmHttpStats ctx;
  const char *uri;
  char *end;
  char *cp;
  SshFSMStepCB first_state;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;

  ctx->buffer = ssh_buffer_allocate();
  if (ctx->buffer == NULL)
    goto error;

  ctx->ctx = http_ctx;
  ctx->conn = conn;
  ctx->stream = stream;

  /* Check what was requested. */
  uri = ssh_http_server_get_uri(conn);
  if (ssh_match_pattern(uri, "/index.html")
      || ssh_match_pattern(uri, "/"))
    {
      first_state = ssh_ipm_http_st_index;
    }
  else if (ssh_match_pattern(uri, "/toc.html"))
    {
      first_state = ssh_ipm_http_st_toc;
    }
  else if (ssh_match_pattern(uri, "/sas/ike/*"))
    {
      first_state = ssh_ipm_http_st_ike;
    }
  else if (ssh_match_pattern(uri, "/sas/ipsec/list/tunnelid/*"))
    {
      /* Detailed SA information. */
      cp = strrchr(uri, '/');
      ctx->filter_flags = SSH_IPM_HTTP_F_TUNNEL_ID;
      ctx->tunnel_id = strtoul(cp + 1, &end, 0);
      if (*end != '\0')
        goto error;

      ctx->transform_index = SSH_IPSEC_INVALID_INDEX;
      first_state = ssh_ipm_http_st_ipsec_sas_overall;
    }
  else if (ssh_match_pattern(uri, "/sas/ipsec/detail/*"))
    {
      /* Detailed SA information. */
      cp = strrchr(uri, '/');
      ctx->transform_index = strtoul(cp + 1, &end, 0);
      if (*end != '\0')
        goto error;

      first_state = ssh_ipm_http_st_ipsec_sas_detail;
    }
  else if (ssh_match_pattern(uri, "/sas/ipsec/*"))
    {
      /* Overall information about IPSec SAs. */
      cp = strrchr(uri, '/');
      if (cp[1])
        {
          ctx->transform_index = strtoul(cp + 1, &end, 0);
          if (*end != '\0')
            goto error;
        }
      else
        {
          ctx->transform_index = SSH_IPSEC_INVALID_INDEX;
        }

      first_state = ssh_ipm_http_st_ipsec_sas_overall;
    }
  else if (ssh_match_pattern(uri, "/audit/*"))
    {
      first_state = ssh_ipm_http_st_audit;
    }
  else if (ssh_match_pattern(uri, "/global/*"))
    {
      first_state = ssh_ipm_http_st_global;
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  else if (ssh_match_pattern(uri, "/radius_acct/*"))
    {
      first_state = ssh_ipm_http_st_radius_acct;
    }
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  else if (ssh_match_pattern(uri, "/flows/list/rule/*"))
    {
      /* List flows by rule. */
      cp = strrchr(uri, '/');
      ctx->filter_flags = SSH_IPM_HTTP_F_RULE;
      ctx->rule_index = strtoul(cp + 1, &end, 0);
      if (*end != '\0')
        goto error;

      first_state = ssh_ipm_http_st_flows;
    }
  else if (ssh_match_pattern(uri, "/flows/detail/*"))
    {
      /* Detailed flow information. */
      cp = strrchr(uri, '/');
      ctx->flow_index = strtoul(cp + 1, &end, 0);
      if (*end != '\0')
        goto error;

      first_state = ssh_ipm_http_st_flows_detail;
    }
  else if (ssh_match_pattern(uri, "/flows/*"))
    {
      first_state = ssh_ipm_http_st_flows;
    }
  else if (ssh_match_pattern(uri, "/rules/detail/*"))
    {
      cp = strrchr(uri, '/');
      ctx->rule_index = strtoul(cp + 1, &end, 0);
      if (*end != '\0')
        goto error;

      first_state = ssh_ipm_http_st_rules_detail;
    }
  else if (ssh_match_pattern(uri, "/rules/*"))
    {
      first_state = ssh_ipm_http_st_rules;
    }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  else if (ssh_match_pattern(uri, "/addrpools/*"))
    {
      first_state = ssh_ipm_http_st_addrpools;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  else if (ssh_match_pattern(uri, "/version.html"))
    {
      first_state = ssh_ipm_http_st_version;
    }
  else if (ssh_match_pattern(uri, "/ifinfo.html"))
    {
      first_state = ssh_ipm_http_st_interfaces;
    }
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  else if (ssh_match_pattern(uri, "/ike/cert/*"))
    {
      cp = strrchr(uri, '/');

      ctx->cert_id = ssh_strdup(cp + 1);
      if (ctx->cert_id == NULL)
        goto error;

      first_state = ssh_ipm_http_st_ike_cert;
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
  else if (ssh_match_pattern(uri, "/ike-blacklist.html"))
    {
      first_state = ssh_ipm_http_st_ike_blacklist;
    }
#endif /* SSH_PM_BLACKLIST_ENABLED */
  else
    {
      first_state = ssh_ipm_http_st_error_not_found;
    }


  /* Start the thread from the start state */
  ipm->http_statistics_refcount++;
  ssh_fsm_thread_init(&ipm->fsm, &ctx->thread, first_state, NULL_FNPTR,
                      ssh_ipm_http_thread_destructor, ctx);

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  if (ctx)
    {
      if (ctx->buffer)
        ssh_buffer_free(ctx->buffer);
      ssh_free(ctx);
    }

  ssh_http_server_error_code(conn, SSH_HTTP_STATUS_INTERNAL_SERVER_ERROR);
  if (stream)
    ssh_stream_destroy(stream);

  return TRUE;
}


/************************ Public interface functions ************************/

Boolean
ssh_ipm_http_statistics_start(SshIpmContext ctx,
                              SshIpmHttpStatisticsParams params)
{
  SshHttpServerParams http_params;
  char portbuf[16];
  SshIpAddrStruct addr;

  memset(&addr, 0, sizeof(addr));

  if (params->address)
    {



      if (!ssh_ipaddr_parse(&addr, ssh_custr(params->address)))
        return FALSE;
    }
  else
    {
      SSH_IP_UNDEFINE(&addr);
    }

  if (ctx->http_statistics)
    {
      if (!SSH_IP_EQUAL(&ctx->http_statistics->address, &addr)
          || ctx->http_statistics->params.port != params->port
          || ctx->http_statistics->params.frames != params->frames
          || ctx->http_statistics->params.refresh != params->refresh)
        /* Stop the old server. */
        (void) ssh_ipm_http_statistics_stop(ctx);
      else
        /* The old server is running with correct parameters. */
        return TRUE;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Starting HTTP interface on %s:%d",
                              params->address ? params->address : "<ANY>",
                              (int) params->port));

  ctx->http_statistics = ssh_calloc(1, sizeof(*ctx->http_statistics));
  if (ctx->http_statistics == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate context"));
      return FALSE;
    }

  /* Store our address. */
  ctx->http_statistics->address = addr;

  /* One more reference to the HTTP statistics. */
  ctx->http_statistics_refcount++;

  /* Store parameters into the context. */
  ctx->http_statistics->params = *params;

  /* Start an HTTP server. */

  memset(&http_params, 0, sizeof(http_params));

  http_params.address = params->address;

  ssh_snprintf(portbuf, sizeof(portbuf), "%u", (unsigned int) params->port);
  http_params.port = portbuf;

  ctx->http_statistics->http_server = ssh_http_server_start(&http_params);
  if (ctx->http_statistics->http_server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not start HTTP server"));
      (void) ssh_ipm_http_statistics_stop(ctx);
      return FALSE;
    }

  /* Set URI handler. */
  ssh_http_server_set_handler(ctx->http_statistics->http_server,
                              "*", 0,
                              ssh_ipm_http_handler, ctx);

  /* HTTP statistics started. */
  return TRUE;
}


Boolean
ssh_ipm_http_statistics_stop(SshIpmContext ctx)
{
  if (ctx->http_statistics)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Stopping HTTP interface"));

      if (ctx->http_statistics->http_server)
        ssh_http_server_stop(ctx->http_statistics->http_server,
                             NULL_FNPTR, NULL);

      ssh_free(ctx->http_statistics);
      ctx->http_statistics = NULL;

      /* Remove our reference to the HTTP statistics. */
      ctx->http_statistics_refcount--;
    }

  if (ctx->http_statistics_refcount > 0)
    /* Still references left. */
    return FALSE;

  /* HTTP statistics stopped. */
  return TRUE;
}

#endif /* SSH_IPSEC_XML_CONFIGURATION */
#endif /* SSHDIST_HTTP_SERVER */
