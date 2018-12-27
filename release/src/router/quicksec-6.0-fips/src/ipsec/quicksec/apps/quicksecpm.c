/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The generic entry-point for the QuickSec policy manager.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshbuffer.h"
#include "sshgetopt.h"
#include "sshfileio.h"
#include "sshdirectory.h"
#include "sshurl.h"
#include "sshnameserver.h"
#include "sshglobals.h"
#include "sshfsm.h"
#include "version.h"

#ifdef SSHDIST_CERT
#include "x509.h"
#endif /* SSHDIST_CERT */

#include "quicksecpm_i.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "quicksec_pm.h"
#include "quicksec_pm_low.h"
#include "engine_pm_api.h"
#include "quicksecpm_xmlconf.h"
#include "quicksecpm_audit.h"

#include "sshape_mark.h"

#ifdef SSHDIST_EXTERNALKEY
#include "genaccprov.h"
#endif /* SSHDIST_EXTERNALKEY */

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifndef WINDOWS
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif /* WINDOWS */

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPm"

/* Amount of time (in 10's of seconds) a dead peer remains in the DPD
   failure cache. The default value below gives 3 minutes. */
#define SSH_QUICKSECPM_DPD_TTL 18

/***************************** Global variables *****************************/

#ifdef SSHDIST_IKEV1
#ifdef DEBUG_LIGHT
/* IKE's logging level.  Only available on debug builds.  This must be
   a global variable since IKE references this that way.  If you
   system does not support global variables, add an appropriate
   pre-processor directives around this variable. */
#undef ssh_ike_logging_level /* In case this is already defined. */
SSH_GLOBAL_DECLARE(int, ssh_ike_logging_level);
#define ssh_ike_logging_level SSH_GLOBAL_USE_INIT(ssh_ike_logging_level)
#endif  /*DEBUG_LIGHT */
#endif /* SSHDIST_IKEV1 */

/* Command line arguments for policy manager. */
SSH_RODATA
static const SshIpmParamsStruct arguments_initial;
SSH_GLOBAL_DECLARE(SshIpmParamsStruct, arguments);
SSH_GLOBAL_DEFINE(SshIpmParamsStruct, arguments);
#define arguments SSH_GLOBAL_USE(arguments)

/* Command line arguments for the IKE library. */
SSH_RODATA
static const struct SshIkev2ParamsRec ike_params_initial;
SSH_GLOBAL_DECLARE(struct SshIkev2ParamsRec, ike_params_glb);
SSH_GLOBAL_DEFINE(struct SshIkev2ParamsRec, ike_params_glb);
#define ike_params_glb SSH_GLOBAL_USE(ike_params_glb)

/* The policy manager object. */
SSH_GLOBAL_DECLARE(SshPm, ipm);
SSH_GLOBAL_DEFINE(SshPm, ipm);
#define ipm SSH_GLOBAL_USE(ipm)

/* Context data for the policy manager and its configuration file
   parser. */
SSH_GLOBAL_DECLARE(SshIpmContext, ipm_ctx);
SSH_GLOBAL_DEFINE(SshIpmContext, ipm_ctx);
#define ipm_ctx SSH_GLOBAL_USE(ipm_ctx)








/* Audit context for displaying audit events to the http interface */
SSH_GLOBAL_DECLARE(SshPmAuditContext, pm_audit_context);
SSH_GLOBAL_DEFINE(SshPmAuditContext, pm_audit_context);
#define pm_audit_context SSH_GLOBAL_USE(pm_audit_context)

SSH_GLOBAL_DECLARE(SshAuditContext, audit_context);
SSH_GLOBAL_DEFINE(SshAuditContext, audit_context);
#define audit_context SSH_GLOBAL_USE(audit_context)

/* A timeout triggering automatic policy reconfiguring. */
SSH_RODATA
const static SshTimeoutStruct reconfigure_timeout_initial;
SSH_GLOBAL_DECLARE(SshTimeoutStruct, reconfigure_timeout);
SSH_GLOBAL_DEFINE(SshTimeoutStruct, reconfigure_timeout);
#define reconfigure_timeout SSH_GLOBAL_USE(reconfigure_timeout)

/* A timeout trigger flow re-evaluation in the engine. */
SSH_RODATA
const static SshTimeoutStruct refresh_flows_timeout_initial;
SSH_GLOBAL_DECLARE(SshTimeoutStruct, refresh_flows_timeout);
SSH_GLOBAL_DEFINE(SshTimeoutStruct, refresh_flows_timeout);
#define refresh_flows_timeout SSH_GLOBAL_USE(refresh_flows_timeout)

SSH_GLOBAL_DECLARE(SshUInt32, refresh_flows_timeout_value);
SSH_GLOBAL_DEFINE(SshUInt32, refresh_flows_timeout_value);
#define refresh_flows_timeout_value SSH_GLOBAL_USE(refresh_flows_timeout_value)

/* FSM controlling policy manager. */
SSH_RODATA
const static SshFSMStruct quicksecpm_fsm_initial;
SSH_GLOBAL_DECLARE(SshFSMStruct, quicksecpm_fsm);
SSH_GLOBAL_DEFINE(SshFSMStruct, quicksecpm_fsm);
#define quicksecpm_fsm SSH_GLOBAL_USE(quicksecpm_fsm)

SSH_RODATA
const static SshFSMThreadStruct quicksecpm_thread_initial;
SSH_GLOBAL_DECLARE(SshFSMThreadStruct, quicksecpm_thread);
SSH_GLOBAL_DEFINE(SshFSMThreadStruct, quicksecpm_thread);
#define quicksecpm_thread SSH_GLOBAL_USE(quicksecpm_thread)

/* Events. */
SSH_GLOBAL_DECLARE(Boolean, event_startup);
SSH_GLOBAL_DEFINE(Boolean, event_startup);
#define event_startup SSH_GLOBAL_USE(event_startup)
SSH_GLOBAL_DECLARE(Boolean, event_reconfigure);
SSH_GLOBAL_DEFINE(Boolean, event_reconfigure);
#define event_reconfigure SSH_GLOBAL_USE(event_reconfigure)
SSH_GLOBAL_DECLARE(Boolean, event_iface_change);
SSH_GLOBAL_DEFINE(Boolean, event_iface_change);
#define event_iface_change SSH_GLOBAL_USE(event_iface_change)
SSH_GLOBAL_DECLARE(Boolean, event_shutdown);
SSH_GLOBAL_DEFINE(Boolean, event_shutdown);
#define event_shutdown SSH_GLOBAL_USE(event_shutdown)
SSH_GLOBAL_DECLARE(Boolean, event_redo_flows);
SSH_GLOBAL_DEFINE(Boolean, event_redo_flows);
#define event_redo_flows SSH_GLOBAL_USE(event_redo_flows)
/* Exit status in case of engine failure */
SSH_GLOBAL_DECLARE(SshUInt32, pm_exit_status);
SSH_GLOBAL_DEFINE(SshUInt32, pm_exit_status);
#define pm_exit_status SSH_GLOBAL_USE(pm_exit_status)










#ifdef SSHDIST_IPSEC_SA_EXPORT
SSH_GLOBAL_DECLARE(Boolean, event_import_sas);
SSH_GLOBAL_DEFINE(Boolean, event_import_sas);
#define event_import_sas SSH_GLOBAL_USE(event_import_sas)
#endif /* SSHDIST_IPSEC_SA_EXPORT */

/* Last event times */
SSH_GLOBAL_DECLARE(SshTime, last_reconfigure_time);
SSH_GLOBAL_DEFINE(SshTime, last_reconfigure_time);
#define last_reconfigure_time SSH_GLOBAL_USE(last_reconfigure_time)
SSH_GLOBAL_DECLARE(SshTime, last_redo_flows_time);
SSH_GLOBAL_DEFINE(SshTime, last_redo_flows_time);
#define last_redo_flows_time SSH_GLOBAL_USE(last_redo_flows_time)






SSH_GLOBAL_DECLARE(SshOperationHandle, event_reconfigure_operation);
SSH_GLOBAL_DEFINE(SshOperationHandle, event_reconfigure_operation);
#define event_reconfigure_operation SSH_GLOBAL_USE(event_reconfigure_operation)

/* A condition variable that is signaled when an event occurs. */
SSH_RODATA
static const SshFSMConditionStruct event_cond_initial;
SSH_GLOBAL_DECLARE(SshFSMConditionStruct, event_cond);
SSH_GLOBAL_DEFINE(SshFSMConditionStruct, event_cond);
#define event_cond SSH_GLOBAL_USE(event_cond)

/* State for the events. */
SSH_GLOBAL_DECLARE(SshUInt32, event_reconfigure_count);
SSH_GLOBAL_DEFINE(SshUInt32, event_reconfigure_count);
#define event_reconfigure_count SSH_GLOBAL_USE(event_reconfigure_count)

/* Externalkey accelerator. */
SSH_GLOBAL_DECLARE(char *, ek_accelerator_type_glb);
SSH_GLOBAL_DEFINE(char *, ek_accelerator_type_glb);
#define ek_accelerator_type_glb SSH_GLOBAL_USE(ek_accelerator_type_glb)
SSH_GLOBAL_DECLARE(char *, ek_accelerator_init_info_glb);
SSH_GLOBAL_DEFINE(char *, ek_accelerator_init_info_glb);
#define ek_accelerator_init_info_glb \
  SSH_GLOBAL_USE(ek_accelerator_init_info_glb)

#ifdef SSHDIST_IPSEC_SA_EXPORT
/* Directory for storing persistent SAs. */
SSH_GLOBAL_DECLARE(char *, persistent_sas_glb);
SSH_GLOBAL_DEFINE(char *, persistent_sas_glb);
#define persistent_sas_glb SSH_GLOBAL_USE(persistent_sas_glb)
#endif /* SSHDIST_IPSEC_SA_EXPORT */

/* Debug file handle */
#ifndef VXWORKS
SSH_GLOBAL_DECLARE(FILE *, pm_debug_file_handle);
SSH_GLOBAL_DEFINE(FILE *, pm_debug_file_handle);
#define pm_debug_file_handle SSH_GLOBAL_USE(pm_debug_file_handle)
#else /* VXWORKS */
/* Needs to be global on VxWorks... */
FILE *pm_debug_file_handle;
#endif /* VXWORKS */

#ifdef SSH_PM_BLACKLIST_ENABLED
/* Configuration file of blacklist */
SSH_GLOBAL_DECLARE(char *, blacklist_conf_file);
SSH_GLOBAL_DEFINE(char *, blacklist_conf_file);
#define blacklist_conf_file SSH_GLOBAL_USE(blacklist_conf_file)

/* Blacklist event */
SSH_GLOBAL_DECLARE(Boolean, event_blacklist_reconfigure);
SSH_GLOBAL_DEFINE(Boolean, event_blacklist_reconfigure);
#define event_blacklist_reconfigure SSH_GLOBAL_USE(event_blacklist_reconfigure)

/* Blacklist reconfigure count */
SSH_GLOBAL_DECLARE(SshUInt32, blacklist_reconfigure_count);
SSH_GLOBAL_DEFINE(SshUInt32, blacklist_reconfigure_count);
#define blacklist_reconfigure_count SSH_GLOBAL_USE(blacklist_reconfigure_count)
#endif /* SSH_PM_BLACKLIST_ENABLED */







/* Long options. */
static const SshLongOptionStruct long_options[] =
{
  {"allow-bootstrap",   SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'a'},
  {"daemon",            SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   'd'},
  {"pass-unknown-ipsec",SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   'u'},
  {"debug",             SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'D'},
  {"debug-output-file", SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'O'},
  {"machine-context",   SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'e'},
  {"file",              SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'f'},
  {"help",              SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   'h'},
  {"http-proxy",        SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'H'},
  {"interface-info",    SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   'i'},
  {"kernel-debug",      SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'K'},
  {"ike-logging-level", SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'n'},
#ifdef SSHDIST_IPSEC_SA_EXPORT
  {"persistent-sas",    SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'p'},
#endif /* SSHDIST_IPSEC_SA_EXPORT */
  {"socks",             SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'S'},
  {"stdin",             SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   't'},
  {"version",           SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   'V'},
  {"ike-bind-list",     SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   'b'},
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IPSEC_DHCP
  {"enable-dhcp-ras-check", SSH_GETOPT_LONG_NO_ARGUMENT,        NULL,   'R'},
#endif /* SSHDIST_IPSEC_DHCP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  {"key-strength-enforced", SSH_GETOPT_LONG_REQUIRED_ARGUMENT,  NULL,   'N'},
  {"accel-type",        SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   129},
  {"accel-init-info",   SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   130},
  {"ike-retry-limit",   SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   140},
  {"ike-retry-timer-msec",
                        SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   141},
  {"ike-retry-timer-max-msec",
                        SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   142},
  {"ike-expire-timer-msec",
                        SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   143},
  {"ike-ports",         SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   144},
  {"no-dns-pass-rule",  SSH_GETOPT_LONG_NO_ARGUMENT,            NULL,   145},
  {"disable-dhcp-client-pass-rule", SSH_GETOPT_LONG_NO_ARGUMENT, NULL,  146},
  {"enable-dhcp-server-pass-rule", SSH_GETOPT_LONG_NO_ARGUMENT, NULL,   147},
#ifdef SSH_PM_BLACKLIST_ENABLED
  {"ike-blacklist-file",SSH_GETOPT_LONG_REQUIRED_ARGUMENT,      NULL,   148},
#endif /* SSH_PM_BLACKLIST_ENABLED */






  {NULL, 0, NULL, 0},
};

/*********************************** DPD ************************************/

static void
ssh_pm_dpd_peer_cb(SshPm pm,
                   const unsigned char *deadpeer,
                   void *context)
{
  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_NOTICE,
                "IKE peer '%s' was found DEAD when performing "
                "IKE Dead Peer Detecting algorithm.",
                deadpeer);
}

#ifdef SSHDIST_IPSEC_SA_EXPORT
/****************************** Persistent SAs ******************************/

/* Create filename for the persistent IKE SA based on the SA's SPI values. */
static void
ssh_ipm_make_ike_sa_filename(char *buf, size_t buflen,
                             SshPmIkeSAEventHandle ike_sa)
{
  size_t len = strlen(persistent_sas_glb);
  char *separator;
  char name[8 * 2 * 2 + 2];
  unsigned char ike_spi_i[8];
  unsigned char ike_spi_r[8];
  size_t i, pos;

  if (len == 0)
    separator = "";
  else if (persistent_sas_glb[len - 1] == '/')
    separator = "";
  else
    separator = "/";

  /* Format cookies. */
  ssh_pm_ike_sa_get_cookies(ipm, ike_sa, ike_spi_i, ike_spi_r);

  pos = 0;
  for (i = 0; i < 8; i++, pos += 2)
    ssh_snprintf(name + pos, 3, "%02X", ike_spi_i[i]);

  name[pos++] = '-';

  for (i = 0; i < 8; i++, pos += 2)
    ssh_snprintf(name + pos, 3, "%02X", ike_spi_r[i]);

  SSH_ASSERT(pos <= sizeof(name));

  /* Create the file name. */
  ssh_snprintf(buf, buflen, "%s%sIKE-SA-%s",
               persistent_sas_glb, separator, name);
}

/* Update exported IPsec SA's after an IKE SA rekey. The new IKE SA is
   'ike_sa'. The implementation below is inefficient, it iterates through
   all exported IPsec SA's each time an IKE SA is rekeyed. To optimize,
   exported IPsec SA's should be stored so they are tied to their parent
   IKE SA, e.g. by putting all exported IPsec SA belonging to an IKE SA
   in a separate directory named by the parent IKE SA. */
static void
persistent_ipsec_sas_update_ike_rekey_by_type(SshPm pm,
                                              SshPmIkeSAEventHandle ike_sa,
                                              SshDirectoryHandle dir,
                                              char *separator,
                                              char *type)
{
  SshBufferStruct buffer[1];
  char namebuf[512];
  const char *name;
  unsigned char *buf;
  size_t buf_len;

  SSH_ASSERT(dir != NULL);
  SSH_ASSERT(type != NULL);

  ssh_buffer_init(buffer);

  while (ssh_directory_read(dir))
    {
      ssh_buffer_clear(buffer);

      name = ssh_directory_file_name(dir);

      if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
          strstr(name, "IPSEC-SA") == NULL || strstr(name, type) == NULL)
        continue;

      ssh_snprintf(namebuf, sizeof(namebuf), "%s%s%s",
                   persistent_sas_glb, separator, name);

      SSH_DEBUG(SSH_D_MIDOK, ("Updating IPsec SA from `%s'", namebuf));

      if (!ssh_read_gen_file(namebuf, &buf, &buf_len))
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not read IPsec SA `%s'", namebuf);
        }
      else
        {
          if (ssh_buffer_append(buffer, buf, buf_len) != SSH_BUFFER_OK)
            {
              ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                            "Could not update IPsec SA `%s'", namebuf);
            }
          else
            {
              buf_len = ssh_pm_ipsec_sa_export_update_ike_sa(ipm, buffer,
                                                             ike_sa);
              if (buf_len > 0 && !ssh_write_gen_file(namebuf, NULL, NULL,
                                                     ssh_buffer_ptr(buffer),
                                                     ssh_buffer_len(buffer)))
                ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                              "Could not save IPsec SA `%s'", namebuf);
            }
          ssh_free(buf);
        }
    }

  ssh_buffer_uninit(buffer);
}

void
ssh_ipm_persistent_ipsec_sas_update_ike_rekey(SshPm pm,
                                              SshPmIkeSAEventHandle ike_sa)
{
  SshDirectoryHandle dir;
  char *separator;
  char *types[] = {"-I", "-R", NULL};
  size_t len = strlen(persistent_sas_glb);
  int i;

  if (len == 0)
    separator = "";
  else if (persistent_sas_glb[len - 1] == '/')
    separator = "";
  else
    separator = "/";

  for (i = 0; types[i] != NULL; i++)
    {
      dir = ssh_directory_open(persistent_sas_glb);

      if (dir == NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not open persistent SA directory `%s'",
                        persistent_sas_glb);
          return;
        }

      persistent_ipsec_sas_update_ike_rekey_by_type(pm, ike_sa,
                                                    dir, separator,
                                                    types[i]);

      ssh_directory_close(dir);
    }

  return;
}


/* A callback function that is called when interesting events occur
   for IKE SAs.  This is registered to the policy manager with the
   `-p', `--persistent-sas' command line option. */
static void
ssh_ipm_ike_sa_callback(SshPm pm,
                        SshPmSAEvent event,
                        SshPmIkeSAEventHandle ike_sa,
                        void *context)
{
  char namebuf[512];
  SshBufferStruct buffer;

  ssh_ipm_make_ike_sa_filename(namebuf, sizeof(namebuf), ike_sa);

  switch (event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_UPDATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_DEBUG(SSH_D_MIDOK, ("Exporting IKE SA `%s'", namebuf));
      ssh_buffer_init(&buffer);
      if (ssh_pm_ike_sa_export(ipm, ike_sa, &buffer) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not export IKE SA `%s'", namebuf);
        }
      else
        {
          if (!ssh_write_gen_file(namebuf, NULL, NULL,
                                  ssh_buffer_ptr(&buffer),
                                  ssh_buffer_len(&buffer)))
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not save IKE SA `%s'", namebuf);
        }
      ssh_buffer_uninit(&buffer);

      /* Update all IPSec SA's belonging to this IKE SA. The IKE SPI's are
         encoded in the exported IPsec SA and these must now be modified. */
      if (event == SSH_PM_SA_EVENT_REKEYED)
        ssh_ipm_persistent_ipsec_sas_update_ike_rekey(ipm, ike_sa);

      break;

    case SSH_PM_SA_EVENT_DELETED:
      SSH_DEBUG(SSH_D_MIDOK, ("Removing IKE SA `%s'", namebuf));
      if (remove(namebuf) < 0)
        ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                      "Could not remove IKE SA `%s'", namebuf);
      break;
    }
}

void
ssh_ipm_persistent_ipsec_sas_update(SshPm pm,
                                    SshPmIPsecSAEventHandle ipsec_sa,
                                    char *pattern,
                                    char *protocol,
                                    SshUInt32 spi)
{
  char namebuf[512];
  SshBufferStruct buffer[1];
  unsigned char *buf = NULL;
  size_t buf_len;

  ssh_buffer_init(buffer);

  /* Try reading initial IPsec SA. */
  ssh_snprintf(namebuf, sizeof(namebuf), pattern, protocol, spi, "I");
  if (ssh_read_gen_file(namebuf, &buf, &buf_len) == FALSE)
    {
      /* No luck, try loading rekeyed IPsec SA. */
      ssh_snprintf(namebuf, sizeof(namebuf), pattern, protocol, spi, "R");
      if (ssh_read_gen_file(namebuf, &buf, &buf_len) == FALSE)
        {
          /* No luck, fail. */
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not read IPsec SA `%s'", namebuf);
          return;
        }
    }

  SSH_ASSERT(buf != NULL);

  /* Update IPsec SA and re-export. */
  SSH_DEBUG(SSH_D_MIDOK, ("Exporting IPsec SA `%s'", namebuf));
  if (ssh_buffer_append(buffer, buf, buf_len) != SSH_BUFFER_OK)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Could not update IPsec SA `%s'", namebuf);
    }
  else
    {
      buf_len = ssh_pm_ipsec_sa_export_update(ipm, buffer, ipsec_sa);
      if (buf_len > 0 && !ssh_write_gen_file(namebuf, NULL, NULL,
                                             ssh_buffer_ptr(buffer),
                                             ssh_buffer_len(buffer)))
        ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                      "Could not save IPsec SA `%s'", namebuf);
    }
  ssh_free(buf);
  ssh_buffer_uninit(buffer);
}

void
ssh_ipm_ipsec_sa_callback(SshPm pm,
                          SshPmSAEvent event,
                          SshPmIPsecSAEventHandle ipsec_sa,
                          void *context)
{
  char initial[512], rekey[512], pattern[512];
  size_t len = strlen(persistent_sas_glb);
  char *separator, *protocol = NULL;
  SshBufferStruct exported_sa[1];
  SshUInt32 spi;

  if (len == 0)
    separator = "";
  else if (persistent_sas_glb[len - 1] == '/')
    separator = "";
  else
    separator = "/";

  ssh_snprintf(pattern, sizeof(pattern),
               "%s%sIPSEC-SA-%%s-%%X-%%s", persistent_sas_glb, separator);

  ssh_buffer_init(exported_sa);
  spi = ssh_pm_ipsec_sa_get_inbound_spi(pm, ipsec_sa);

  switch (ssh_pm_ipsec_sa_get_protocol(pm, ipsec_sa))
    {
    case SSH_IPPROTO_ESP:
      protocol = "ESP";
      break;
    case SSH_IPPROTO_AH:
      protocol = "AH";
      break;
    default:
      SSH_NOTREACHED;
    }

  switch (event)
    {
    case SSH_PM_SA_EVENT_CREATED:
      /* create file with name "<proto>-<spi>-i" */
      ssh_snprintf(initial, sizeof(initial), pattern, protocol, spi, "I");
      SSH_DEBUG(SSH_D_MIDOK, ("Exporting IPsec SA `%s'", initial));
      if (ssh_pm_ipsec_sa_export(pm, ipsec_sa, exported_sa) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not export IPsec SA `%s'", initial);
        }
      else
        {
          if (!ssh_write_gen_file(initial, NULL, NULL,
                                  ssh_buffer_ptr(exported_sa),
                                  ssh_buffer_len(exported_sa)))
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not save IPsec SA `%s'", initial);
        }
      break;
    case SSH_PM_SA_EVENT_REKEYED:
      /* Add new rekey */
      ssh_snprintf(rekey, sizeof(rekey), pattern, protocol, spi, "R");
      SSH_DEBUG(SSH_D_MIDOK, ("Exporting IPsec SA `%s'", rekey));
      if (ssh_pm_ipsec_sa_export(pm, ipsec_sa, exported_sa) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not export IPsec SA `%s'", rekey);
        }
      else
        {
          if (!ssh_write_gen_file(rekey, NULL, NULL,
                                  ssh_buffer_ptr(exported_sa),
                                  ssh_buffer_len(exported_sa)))
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not save IPsec SA `%s'", rekey);
        }
      break;
    case SSH_PM_SA_EVENT_UPDATED:
      ssh_ipm_persistent_ipsec_sas_update(pm, ipsec_sa, pattern, protocol,
                                          spi);
      break;
    case SSH_PM_SA_EVENT_DELETED:
      /* remove files "<proto>-<spi>-i" and
         "<proto>-<spi>-r". Deletion files may fail silently, as rekey
         may have renamed the initial or rekey file is missing due to
         rekey not having been performed. */
      ssh_snprintf(initial, sizeof(initial), pattern, protocol, spi, "I");
      SSH_DEBUG(SSH_D_MIDOK, ("Attempting to remove IPsec SA `%s'", initial));
      (void)remove(initial);

      ssh_snprintf(rekey, sizeof(rekey), pattern, protocol, spi, "R");
      SSH_DEBUG(SSH_D_MIDOK, ("Attempting to remove IPsec SA `%s'", rekey));
      (void)remove(rekey);
      break;
    }

  ssh_buffer_uninit(exported_sa);
}

/* SA loader */

struct SshIpmPersistenSaLoaderRec {
  Boolean aborted;
  char *separator;
  char *persistent_sas;
  char type[4];
  SshDirectoryHandle dir;
  SshOperationHandleStruct op[1];
  SshPmStatusCB callback;
  void *callback_context;
  SshFSMThreadStruct thread[1];
  SshBufferStruct buffer[1];
};

typedef struct SshIpmPersistenSaLoaderRec *SshIpmPersistenSaLoader;

static void pm_sa_loader_destroyed(SshFSM fsm, void *context)
{
  SshIpmPersistenSaLoader loader = context;

  ssh_buffer_uninit(loader->buffer);
  if (loader->dir != NULL)
    ssh_directory_close(loader->dir);
  ssh_free(loader);
}

static void pm_sa_loader_abort(void *context)
{
  SshIpmPersistenSaLoader loader = context;

  loader->callback = NULL_FNPTR;
  loader->aborted = TRUE;
}

/* IKE SA */
static void
ipm_ike_sa_pre_import_cb(SshPm pm,
                         SshPmIkeSAEventHandle ike_sa,
                         SshIpAddr remote_ip,
                         SshPmStatusCB accept_callback, void *accept_context,
                         void *context)
{
  SshPmTunnel tunnel;
  unsigned char sa_tunnel_app_id[512];
  size_t sa_tunnel_app_id_len;
  unsigned char tunnel_app_id[512];
  size_t tunnel_app_id_len;

  /* Lookup the tunnel for the imported IKE SA using the tunnel application
     identifier. */
  sa_tunnel_app_id_len = sizeof(sa_tunnel_app_id);
  if (!ssh_pm_ike_sa_get_tunnel_application_identifier(pm, ike_sa,
                                                       sa_tunnel_app_id,
                                                       &sa_tunnel_app_id_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not get tunnel application identifier for "
                 "imported IKE SA"));
      goto fail;
    }

  /* Tunnel application identifier is set to tunnel_name by xml parser. */
  SSH_ASSERT(sa_tunnel_app_id_len > 0);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("Looking up tunnel for application identifier"),
                    sa_tunnel_app_id, sa_tunnel_app_id_len);

  for (tunnel = ssh_pm_tunnel_get_next(pm, NULL);
       tunnel != NULL;
       tunnel = ssh_pm_tunnel_get_next(pm, tunnel))
    {
      tunnel_app_id_len = sizeof(tunnel_app_id);
      if (ssh_pm_tunnel_get_application_identifier(tunnel, tunnel_app_id,
                                                   &tunnel_app_id_len))
        {
          if (sa_tunnel_app_id_len == tunnel_app_id_len
              && (memcmp(sa_tunnel_app_id, tunnel_app_id, tunnel_app_id_len)
                  == 0))
            {
              ssh_pm_ike_sa_set_tunnel(pm, ike_sa, tunnel);
              (*accept_callback)(pm, TRUE, accept_context);
              return;
            }
        }
    }

  /* No tunnel found for the IKE SA, fail import. */
 fail:
  SSH_DEBUG_HEXDUMP(SSH_D_FAIL, ("No tunnel found for application identifier"),
                    sa_tunnel_app_id, sa_tunnel_app_id_len);
  (*accept_callback)(pm, FALSE, accept_context);
  return;
}

static void
ipm_ike_sa_loader_cb(SshPm pm, SshPmSAImportStatus status,
                     SshPmIkeSAEventHandle ike_sa, void *context)
{
  SshIpmPersistenSaLoader loader = context;
  char namebuf[512];
  SshBufferStruct buffer;

  ssh_snprintf(namebuf, sizeof(namebuf), "%s%s%s",
               loader->persistent_sas, loader->separator,
               ssh_directory_file_name(loader->dir));

  if (status == SSH_PM_SA_IMPORT_OK)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                    "IKE SA `%s' imported",
                    ssh_directory_file_name(loader->dir));

      /* Re-export IKE SA as the SA may have been modified during import. */
      SSH_DEBUG(SSH_D_MIDOK, ("Re-exporting IKE SA `%s'", namebuf));
      ssh_buffer_init(&buffer);
      if (ssh_pm_ike_sa_export(ipm, ike_sa, &buffer) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not export IKE SA `%s'", namebuf);
        }
      else
        {
          if (!ssh_write_gen_file(namebuf, NULL, NULL,
                                  ssh_buffer_ptr(&buffer),
                                  ssh_buffer_len(&buffer)))
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not save IKE SA `%s'", namebuf);
        }
      ssh_buffer_uninit(&buffer);

    }
  else
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Could not import IKE SA `%s'",
                    ssh_directory_file_name(loader->dir));

      /* Remove SA from disk if it has already expired. */
      if (status == SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Removing IKE SA `%s'", namebuf));
          if (remove(namebuf) < 0)
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not remove IKE SA `%s'", namebuf);
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(loader->thread);
}

/* Load the saved IKE SAs from the given directory. */

SSH_FSM_STEP(ipm_st_ike_sa_loader_start)
{
  SshIpmPersistenSaLoader loader = ssh_fsm_get_tdata(thread);

  if (!loader->aborted)
    {
      ssh_buffer_clear(loader->buffer);
      while (loader->dir && ssh_directory_read(loader->dir))
        {
          char namebuf[512];
          const char *name = ssh_directory_file_name(loader->dir);
          unsigned char *buf;
          size_t buf_len;

          if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
              strstr(name, "IKE-SA") == NULL)
            continue;

          ssh_snprintf(namebuf, sizeof(namebuf), "%s%s%s",
                       loader->persistent_sas, loader->separator, name);

          SSH_DEBUG(SSH_D_MIDOK, ("Loading IKE SA from `%s'", namebuf));

          if (!ssh_read_gen_file(namebuf, &buf, &buf_len))
            {
              ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                            "Could not read IKE SA `%s'", namebuf);
            }
          else
            {
              if (ssh_buffer_append(loader->buffer, buf, buf_len)
                  == SSH_BUFFER_OK)
                {
                  ssh_free(buf);
                  SSH_FSM_ASYNC_CALL({
                    ssh_pm_ike_sa_import(ipm,
                                         loader->buffer,
                                         ipm_ike_sa_pre_import_cb,
                                         NULL,
                                         ipm_ike_sa_loader_cb,
                                         loader);
                  });
                }
              else
                {
                  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                                "Could not allocate IKE SA `%s'", namebuf);
                }

              ssh_free(buf);
            }
        }

      (*loader->callback)(ipm, TRUE, loader->callback_context);
      ssh_operation_unregister(loader->op);
    }

  return SSH_FSM_FINISH;
}

static SshOperationHandle
ssh_ipm_load_persistent_ike_sas(SshPmStatusCB callback, void *context)
{
  SshIpmPersistenSaLoader loader;
  size_t len = strlen(persistent_sas_glb);

  loader = ssh_calloc(1, sizeof(*loader));
  if (loader == NULL)
    {
    failure:
      (*callback)(ipm, FALSE, context);
      return NULL;
    }

  loader->aborted = FALSE;
  loader->callback = callback;
  loader->callback_context = context;
  loader->persistent_sas = persistent_sas_glb;

  ssh_buffer_init(loader->buffer);

  if (len == 0)
    loader->separator = "";
  else if (persistent_sas_glb[len - 1] == '/')
    loader->separator = "";
  else
    loader->separator = "/";

  loader->dir = ssh_directory_open(persistent_sas_glb);
  if (loader->dir == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Could not open persistent SA directory `%s'",
                    persistent_sas_glb);
      ssh_free(loader);
      goto failure;
    }

  ssh_operation_register_no_alloc(loader->op, pm_sa_loader_abort, loader);
  ssh_fsm_thread_init(&quicksecpm_fsm,
                      loader->thread, ipm_st_ike_sa_loader_start,
                      NULL_FNPTR, pm_sa_loader_destroyed, loader);
  ssh_fsm_set_thread_name(loader->thread, "Persistent SA loader");

  return loader->op;
}

/* IPsec SAs */

static void
ipm_ipsec_sa_loader_cb(SshPm pm, SshPmSAImportStatus status,
                       SshPmIPsecSAEventHandle ipsec_sa, void *context)
{
  SshIpmPersistenSaLoader loader = context;
  char namebuf[512];
  SshBufferStruct buffer;

  ssh_snprintf(namebuf, sizeof(namebuf), "%s%s%s",
               loader->persistent_sas, loader->separator,
               ssh_directory_file_name(loader->dir));

  if (status == SSH_PM_SA_IMPORT_OK)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                    "IPsec SA `%s' imported",
                    ssh_directory_file_name(loader->dir));

      /* Re-export IPsec SA as the SA may have been modified during import. */
      SSH_DEBUG(SSH_D_MIDOK, ("Re-exporting IPsec SA `%s'", namebuf));
      ssh_buffer_init(&buffer);
      if (ssh_pm_ipsec_sa_export(pm, ipsec_sa, &buffer) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                        "Could not export IPsec SA `%s'", namebuf);
        }
      else
        {
          if (!ssh_write_gen_file(namebuf, NULL, NULL,
                                  ssh_buffer_ptr(&buffer),
                                  ssh_buffer_len(&buffer)))
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not save IPsec SA `%s'", namebuf);
        }
      ssh_buffer_uninit(&buffer);
    }
  else
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Could not import IPsec SA `%s'",
                    ssh_directory_file_name(loader->dir));

      /* Remove SA from disk if it has already expired. */
      if (status == SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Removing IPsec SA `%s'", namebuf));
          if (remove(namebuf) < 0)
            ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                          "Could not remove IPsec SA `%s'", namebuf);
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(loader->thread);
}

/* SA import hook callbacks */

static void
ipm_ipsec_sa_pre_import_cb(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa,
                           SshPmStatusCB accept_callback, void *accept_context,
                           void *context)
{
  SshUInt32 new_seq_low, new_seq_high;
  SshUInt32 seq_low, seq_high;
  SshUInt32 life, remaining_life;
  unsigned char sa_app_id[512];
  size_t sa_app_id_len;
  unsigned char app_id[512];
  size_t app_id_len;
  SshPmRule rule;
  SshPmTunnel tunnel;







  ssh_pm_ipsec_sa_get_outbound_sequence_number(pm, ipsec_sa,
                                               &seq_low, &seq_high);

  /* Increase the sequence number of the transform to a large enough value.

     Calculate sequence under the expectation that the host has sent out
     packets at an average rate of 2^19 pps (0x8000 pps, about 500000 pps)
     since SA installation. For short sequence numbers automatic rekey happens
     when sequence reaches 0xfb000000 which equals 8032 seconds with the above
     rate.

     Please note that this code is here mainly for making testing easier. */

  life = ssh_pm_ipsec_sa_get_life_seconds(pm, ipsec_sa);
  remaining_life = ssh_pm_ipsec_sa_get_remaining_life_seconds(pm, ipsec_sa);

  new_seq_low = 0;
  new_seq_high = seq_high;
  if (life > 0 && (life > remaining_life))
    {
      /* Fix seq_high if extended sequence numbers are used. */
      if (seq_high != SSH_IPSEC_INVALID_INDEX)
        {
          new_seq_high = (life - remaining_life) / 8192;
          if (seq_high > new_seq_high)
            new_seq_high = seq_high + (0xffffffff - seq_high) / 2;

          /* Fix lifetimes used in calculation of seq_low. */
          life &= 8191;
          remaining_life &= 8191;
          if (life < remaining_life)
            life += 8192;
        }

      /* Calculate seq_low. */
      if ((life - remaining_life) < 8032)
        new_seq_low = (life - remaining_life) * (2 << 18);
      else
        new_seq_low = 0xfb000000;
    }

  if (seq_high == SSH_IPSEC_INVALID_INDEX && seq_low > new_seq_low)
    new_seq_low = seq_low + (0xffffffff - seq_low) / 2;

  ssh_pm_ipsec_sa_set_outbound_sequence_number(pm, ipsec_sa,
                                               new_seq_low, new_seq_high);

  /* Lookup tunnel for the imported IPsec SA. */
  sa_app_id_len = sizeof(sa_app_id);
  if (!ssh_pm_ipsec_sa_get_tunnel_application_identifier(pm, ipsec_sa,
                                                         sa_app_id,
                                                         &sa_app_id_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not get tunnel application identifier for imported "
                 "IPsec SA"));
      goto fail;
    }

  /* Tunnel application identifier is set to tunnel_name by xml parser. */
  SSH_ASSERT(sa_app_id_len > 0);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("Looking up tunnel for application identifier"),
                    sa_app_id, sa_app_id_len);

  for (tunnel = ssh_pm_tunnel_get_next(pm, NULL);
       tunnel != NULL;
       tunnel = ssh_pm_tunnel_get_next(pm, tunnel))
    {
      app_id_len = sizeof(app_id);
      if (ssh_pm_tunnel_get_application_identifier(tunnel, app_id,
                                                   &app_id_len))
        {
          if (sa_app_id_len == app_id_len
              && (memcmp(sa_app_id, app_id, app_id_len) == 0))
            {
              ssh_pm_ipsec_sa_set_tunnel(pm, ipsec_sa, tunnel);
              break;
            }
        }
    }
  if (tunnel == NULL)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_FAIL,
                        ("Could not find tunnel for application identifier"),
                        sa_app_id, sa_app_id_len);
      goto fail;
    }

  /* Lookup outer tunnel for the imported IPsec SA. */
  sa_app_id_len = sizeof(sa_app_id);
  if (!ssh_pm_ipsec_sa_get_outer_tunnel_application_identifier(pm, ipsec_sa,
                                                               sa_app_id,
                                                               &sa_app_id_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not get outer tunnel application identifier for "
                 "imported IPsec SA"));
      goto fail;
    }

  /* Outer tunnel might not be configured for the tunnel. In that case the
     returned application identifier length is zero. If there is an outer
     tunnel then the application identifier is the tunnel name (set by xml
     parser). */
  if (sa_app_id_len > 0)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Looking up outer tunnel for application identifier"),
                        sa_app_id, sa_app_id_len);

      for (tunnel = ssh_pm_tunnel_get_next(pm, NULL);
           tunnel != NULL;
           tunnel = ssh_pm_tunnel_get_next(pm, tunnel))
        {
          app_id_len = sizeof(app_id);
          if (ssh_pm_tunnel_get_application_identifier(tunnel, app_id,
                                                       &app_id_len))
            {
              if (sa_app_id_len == app_id_len
                  && (memcmp(sa_app_id, app_id, app_id_len) == 0))
                {
                  ssh_pm_ipsec_sa_set_outer_tunnel(pm, ipsec_sa, tunnel);
                  break;
                }
            }
        }
      if (tunnel == NULL)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_FAIL,
                            ("Could not find outer_tunnel for application "
                             "identifier"),
                            sa_app_id, sa_app_id_len);
          goto fail;
        }
    }

  /* Lookup outer tunnel for the imported IPsec SA. */
  sa_app_id_len = sizeof(sa_app_id);
  if (!ssh_pm_ipsec_sa_get_rule_application_identifier(pm, ipsec_sa,
                                                       sa_app_id,
                                                       &sa_app_id_len))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not get rule application identifier for imported "
                 "IPsec SA"));
      goto fail;
    }

  /* Rule application identifier is set by the xml parser to optional rule
     name if specified. */
  if (sa_app_id_len > 0)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Looking up rule for application identifier"),
                        sa_app_id, sa_app_id_len);

      for (rule = ssh_pm_rule_get_next(pm, NULL);
           rule != NULL;
           rule = ssh_pm_rule_get_next(pm, rule))
        {
          app_id_len = sizeof(app_id);
          if (ssh_pm_rule_get_application_identifier(rule, app_id,
                                                     &app_id_len))
            {
              if (sa_app_id_len == app_id_len
                  && (memcmp(sa_app_id, app_id, app_id_len) == 0))
                {
                  ssh_pm_ipsec_sa_set_rule(pm, ipsec_sa, rule);
                  break;
                }
            }
        }
      if (rule == NULL)
        {
          SSH_DEBUG_HEXDUMP(SSH_D_FAIL,
                            ("Could not find rule for application identifier"),
                            sa_app_id, sa_app_id_len);
          goto fail;
        }
    }































  /* Accept IPsec SA */
  (*accept_callback)(pm, TRUE, accept_context);
  return;

 fail:
  (*accept_callback)(pm, FALSE, accept_context);
  return;
}

SSH_FSM_STEP(ipm_st_ipsec_sa_loader_start)
{
  SshIpmPersistenSaLoader loader = ssh_fsm_get_tdata(thread);

  if (!loader->aborted)
    {
    again:
      ssh_buffer_clear(loader->buffer);
      while (loader->dir && ssh_directory_read(loader->dir))
        {
          char namebuf[512];
          const char *name = ssh_directory_file_name(loader->dir);
          unsigned char *buf;
          size_t buf_len;

          if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
              strstr(name, "IPSEC-SA") == NULL ||
              strstr(name, loader->type) == NULL)
            continue;

          ssh_snprintf(namebuf, sizeof(namebuf), "%s%s%s",
                       loader->persistent_sas, loader->separator, name);

          SSH_DEBUG(SSH_D_MIDOK, ("Loading IPsec SA from `%s'", namebuf));

          if (!ssh_read_gen_file(namebuf, &buf, &buf_len))
            {
              ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                            "Could not read IPsec SA `%s'", namebuf);
            }
          else
            {
              if (ssh_buffer_append(loader->buffer, buf, buf_len)
                  == SSH_BUFFER_OK)
                {
                  ssh_free(buf);
                  SSH_FSM_ASYNC_CALL({
                    ssh_pm_ipsec_sa_import(ipm,
                                           loader->buffer,
                                           ipm_ipsec_sa_pre_import_cb,
                                           NULL,
                                           ipm_ipsec_sa_loader_cb,
                                           loader);
                  });
                }
              else
                {
                  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                                "Could not allocate IPsec SA `%s'", namebuf);
                }
              ssh_free(buf);
            }
        }

      if (strcmp(loader->type, "-I") == 0)
        {
          ssh_directory_close(loader->dir);

          /* Next thing is to load rekeys. */
          strcpy(loader->type, "-R");
          loader->dir = ssh_directory_open(persistent_sas_glb);
          goto again;
        }

      (*loader->callback)(ipm, TRUE, loader->callback_context);
      ssh_operation_unregister(loader->op);
    }

  return SSH_FSM_FINISH;
}

static SshOperationHandle
ssh_ipm_load_persistent_ipsec_sas(SshPmStatusCB callback, void *context)
{
  SshIpmPersistenSaLoader loader;
  size_t len = strlen(persistent_sas_glb);

  loader = ssh_calloc(1, sizeof(*loader));
  if (loader == NULL)
    {
    failure:
      (*callback)(ipm, FALSE, context);
      return NULL;
    }

  loader->aborted = FALSE;
  loader->callback = callback;
  loader->callback_context = context;
  loader->persistent_sas = persistent_sas_glb;
  strcpy(loader->type, "-I");

  ssh_buffer_init(loader->buffer);

  if (len == 0)
    loader->separator = "";
  else if (persistent_sas_glb[len - 1] == '/')
    loader->separator = "";
  else
    loader->separator = "/";

  loader->dir = ssh_directory_open(persistent_sas_glb);
  if (loader->dir == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Could not open persistent SA directory `%s'",
                    persistent_sas_glb);
      ssh_free(loader);
      goto failure;
    }

  ssh_operation_register_no_alloc(loader->op,
                                  pm_sa_loader_abort, loader);
  ssh_fsm_thread_init(&quicksecpm_fsm,
                      loader->thread, ipm_st_ipsec_sa_loader_start,
                      NULL_FNPTR, pm_sa_loader_destroyed, loader);
  ssh_fsm_set_thread_name(loader->thread, "Persistent SA loader");

  return loader->op;
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */


#ifdef SSHDIST_EXTERNALKEY
/******************* Externalkey authentication callback ********************/

static SshOperationHandle
ssh_pm_ek_authentication_cb(const char *keypath, const char *label,
                            SshUInt32 try_number,
                            SshEkAuthenticationStatus status,
                            SshEkAuthenticationReplyCB reply_cb,
                            void *reply_context,
                            void *context)
{
  printf("EK authentication callback: label=%s, keypath=%s\n",
         label, keypath);

  switch (status)
    {
    case SSH_EK_AUTHENTICATION_CODE_NEEDED:
      printf("  Authentication code needed\n");
      (*reply_cb)((unsigned char *) "1234", 4, reply_context);
      break;

    case SSH_EK_AUTHENTICATION_NEEDED_FOR_THE_TOKEN:
      printf("  Authentication code needed for the token\n");
      (*reply_cb)((unsigned char *) "1234", 4, reply_context);
      break;

    case SSH_EK_AUTHENTICATION_CODE_WRONG:
      printf("  Authentication code wrong\n");
      break;

    case SSH_EK_AUTHENTICATION_CODE_BLOCKED:
      printf("  Authentication code blocked\n");
      break;

    case SSH_EK_AUTHENTICATION_CODE_FAILED:
      printf("  Authentication code failed\n");
      break;

    case SSH_EK_AUTHENTICATION_OK:
      printf("  Authentication ok\n");
      break;
    }

  return NULL;
}
#endif /* SSHDIST_EXTERNALKEY */

/************************ Controlling policy manager ************************/

#ifdef VXWORKS
SSH_GLOBAL_DECLARE(Boolean, do_indicate);
#define do_indicate SSH_GLOBAL_USE(do_indicate)
#endif /* VXWORKS */

static
void ssh_ipm_global_init(void)
{
#ifdef VXWORKS
#ifdef HAVE_SIGNAL
  SSH_GLOBAL_INIT(do_indicate, TRUE);
#endif /* HAVE_SIGNAL */
#endif /* VXWORKS */

  SSH_GLOBAL_INIT(arguments, arguments_initial);

  SSH_GLOBAL_INIT(ike_params_glb, ike_params_initial);

  SSH_GLOBAL_INIT(ipm, NULL);

  SSH_GLOBAL_INIT(ipm_ctx, NULL);

  SSH_GLOBAL_INIT(pm_audit_context, NULL);
  SSH_GLOBAL_INIT(audit_context, NULL);

  SSH_GLOBAL_INIT(reconfigure_timeout, reconfigure_timeout_initial);
  SSH_GLOBAL_INIT(refresh_flows_timeout, refresh_flows_timeout_initial);

  SSH_GLOBAL_INIT(refresh_flows_timeout_value, 0);

  SSH_GLOBAL_INIT(quicksecpm_fsm, quicksecpm_fsm_initial);
  SSH_GLOBAL_INIT(quicksecpm_thread, quicksecpm_thread_initial);

  SSH_GLOBAL_INIT(event_startup, FALSE);
  SSH_GLOBAL_INIT(event_reconfigure, FALSE);
  SSH_GLOBAL_INIT(event_iface_change, FALSE);
  SSH_GLOBAL_INIT(event_shutdown, FALSE);
  SSH_GLOBAL_INIT(event_redo_flows, FALSE);
  SSH_GLOBAL_INIT(pm_exit_status, 0);





#ifdef SSHDIST_IPSEC_SA_EXPORT
  SSH_GLOBAL_INIT(event_import_sas, FALSE);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  SSH_GLOBAL_INIT(last_reconfigure_time, 0);
  SSH_GLOBAL_INIT(last_redo_flows_time, 0);




  SSH_GLOBAL_INIT(event_reconfigure_operation, NULL);
  SSH_GLOBAL_INIT(event_cond, event_cond_initial);

  SSH_GLOBAL_INIT(event_reconfigure_count, 0);

  SSH_GLOBAL_INIT(ek_accelerator_type_glb, NULL);
  SSH_GLOBAL_INIT(ek_accelerator_init_info_glb, NULL);

#ifdef SSHDIST_IPSEC_SA_EXPORT
  SSH_GLOBAL_INIT(persistent_sas_glb, NULL);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

#ifndef VXWORKS
  SSH_GLOBAL_INIT(pm_debug_file_handle, NULL);
#endif /* VXWORKS */

#ifdef SSH_PM_BLACKLIST_ENABLED
  SSH_GLOBAL_INIT(blacklist_conf_file, NULL);
  SSH_GLOBAL_INIT(event_blacklist_reconfigure, FALSE);
  SSH_GLOBAL_INIT(blacklist_reconfigure_count, 0);
#endif /* SSH_PM_BLACKLIST_ENABLED */
}

void
ssh_ipm_init(void)
{
  /* Init globals. */
  ssh_global_init();

  ssh_ipm_global_init();

  /* Initialize the event loop. */
  ssh_event_loop_initialize();

  /* Initialize the PM library */
  ssh_pm_library_init();
}


void
ssh_ipm_stop(void)
{
  /* Raise the shutdown event. */

  if (event_reconfigure_operation)
    {
      ssh_operation_abort(event_reconfigure_operation);
      event_reconfigure_operation = NULL;
      SSH_FSM_CONTINUE_AFTER_CALLBACK(&quicksecpm_thread);
    }
  event_shutdown = TRUE;
  ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
}


void
ssh_ipm_reconfigure(void)
{
  if (ssh_time() - last_reconfigure_time > 1)
    {
      last_reconfigure_time = ssh_time();

#ifdef SSH_PM_BLACKLIST_ENABLED
      /* Raise the blacklist reconfigure event */
      event_blacklist_reconfigure = TRUE;
#endif /* SSH_PM_BLACKLIST_ENABLED */

      /* Raise the reconfigure event. */
      event_reconfigure = TRUE;
      ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
    }
  else
    printf("%s: Ignoring policy reconfiguration signal due to rate "
           "limiting \n", arguments.program);
}

void
ssh_ipm_redo_flows(void)
{
  if (ssh_time() - last_redo_flows_time > 1)
    {
      last_redo_flows_time = ssh_time();
      /* Raise the redo flows event. */
      event_redo_flows = TRUE;
      ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
    }
  else
    printf("%s: Ignoring redo flows signal due to rate limiting \n",
           arguments.program);
}





































/******************************* Interface changes **************************/
void
ssh_ipm_interface_cb(SshPm pm, void *context)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,("Interface information has changed"));

  /* Unregister the callback, needed only once. */
  ssh_pm_set_interface_callback(ipm, NULL_FNPTR, NULL);

  event_iface_change = TRUE;
  ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
}

/*********************** FSM handling policy manager ************************/

/* Prototypes for state functions. */
SSH_FSM_STEP(ssh_ipm_st_start);
SSH_FSM_STEP(ssh_ipm_st_disable_policy_lookups);
SSH_FSM_STEP(ssh_ipm_st_wait_interfaces);
SSH_FSM_STEP(ssh_ipm_st_initialize);
SSH_FSM_STEP(ssh_ipm_st_enable_policy_lookups);
SSH_FSM_STEP(ssh_ipm_st_run);
SSH_FSM_STEP(ssh_ipm_st_startup);
#ifdef SSHDIST_IPSEC_SA_EXPORT
SSH_FSM_STEP(ssh_ipm_st_import_sas);
#endif /* SSHDIST_IPSEC_SA_EXPORT */
SSH_FSM_STEP(ssh_ipm_st_startup_done);
#ifdef SSH_PM_BLACKLIST_ENABLED
SSH_FSM_STEP(ssh_ipm_st_blacklist_reconfigure);
#endif /* SSH_PM_BLACKLIST_ENABLED */
SSH_FSM_STEP(ssh_ipm_st_reconfigure);
SSH_FSM_STEP(ssh_ipm_st_redo_flows);



SSH_FSM_STEP(ssh_ipm_st_shutdown);
SSH_FSM_STEP(ssh_ipm_st_shutdown_context);
SSH_FSM_STEP(ssh_ipm_st_shutdown_complete);


static void
ssh_ipm_create_cb(SshPm pm, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  ipm = pm;

  /* Register callback for interface changes. */
  if (ipm != NULL)
    ssh_pm_set_interface_callback(ipm, ssh_ipm_interface_cb, NULL);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A timeout to reconfigure policy periodically. */
static void
ssh_ipm_reconfigure_timeout(void *context)
{
  ssh_ipm_reconfigure();
}

/* A timeout to refresh flows periodically. */
static void
ssh_ipm_refresh_flows_timeout(void *context)
{
  SshUInt32 refresh;

  refresh_flows_timeout_value = 0;
  ssh_ipm_redo_flows();

  refresh = ssh_ipm_get_refresh_flows_timeout(ipm_ctx);
  if (refresh)
    {
      ssh_register_timeout(&refresh_flows_timeout, refresh, 0,
                           ssh_ipm_refresh_flows_timeout, NULL);
      refresh_flows_timeout_value = refresh;
    }
}










/* A completion callback for policy manager configuration
   operation. */
static void
ssh_ipm_reconfigure_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshUInt32 refresh;

  event_reconfigure_operation = NULL;
  if (success)
    {
      ssh_log_event(
        SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL, "Policy rules loaded");
    }
  else
    {
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
                    "Reconfiguration failed");

      /* If this was the initial configuration, stop the policy
         manager. */
      if (event_reconfigure_count == 1)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Stopping policy manager"));
          event_shutdown = TRUE;
          event_startup = FALSE;
          /* Set process exit status for the benefit of shell scripts */
          pm_exit_status = 1;
          ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
        }
    }

  /* Handle automatic policy refreshing. */
  refresh = ssh_ipm_get_refresh_timeout(ipm_ctx);
  if (refresh)
    {
      ssh_cancel_timeout(&reconfigure_timeout);
      ssh_register_timeout(&reconfigure_timeout, refresh, 0,
                           ssh_ipm_reconfigure_timeout, NULL);
    }

  refresh = ssh_ipm_get_refresh_flows_timeout(ipm_ctx);

  /* If refresh timeouts just got canceled, cancel the timeout. */
  if (refresh_flows_timeout_value && refresh == 0)
    {
      ssh_cancel_timeout(&refresh_flows_timeout);
      refresh_flows_timeout_value = 0;
    }

  /* If refresh timeouts just got enabled, then enable the timeout
     with the new timeout value. */
  if (refresh && refresh_flows_timeout_value == 0)
    {
      ssh_register_timeout(&refresh_flows_timeout, refresh, 0,
                           ssh_ipm_refresh_flows_timeout, NULL);
      refresh_flows_timeout_value = refresh;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A timeout callback that continues the thread that registered the
   timeout. */
static void
ssh_ipm_timeout_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A completion callback for disabling high level policy lookups. */
static void
ssh_ipm_disable_policy_lookups_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = context;

  if (status == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to disable high level policy lookups"));
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A completion callback for policy manager destroy operation. */
static void
ssh_ipm_stop_cb(void *context)
{
  SSH_FSM_CONTINUE_AFTER_CALLBACK((SshFSMThread) context);
}

#ifdef SSHDIST_EXTERNALKEY
static Boolean ipm_set_ek_accelerator_info(SshPmParams params)
{
  Boolean status = TRUE;
  char *str;

  /* Take the user specified parameters if they were given. */
  if (ek_accelerator_type_glb != NULL && ek_accelerator_init_info_glb != NULL)
    {
      params->ek_accelerator_type = ssh_strdup(ek_accelerator_type_glb);
      if (params->ek_accelerator_type == NULL)
        return FALSE;

      params->ek_accelerator_init_info =
        ssh_strdup(ek_accelerator_init_info_glb);
      if (params->ek_accelerator_init_info == NULL)
        {
          ssh_free(params->ek_accelerator_type);
          params->ek_accelerator_type = NULL;
          return FALSE;
        }
      return TRUE;
    }

  /* Otherwise take the first configured accelerator, the accelerators are
     listed in a comma separated string. */
  str = ssh_acc_device_get_supported();

  if (str != NULL)
    {
      char *aux, buf[64];
      size_t len;

      strcpy(buf, "name(");
      len = strlen(buf);

      aux = strchr(str, ',');
      if (aux != NULL)
        {
          if (len + (aux - str) + 2 > sizeof(buf))
            goto fail;

          memcpy(buf + len, str, aux - str);
          len += (aux - str);
        }
      else
        {
          if (len + strlen(str) + 2 > sizeof(buf))
            goto fail;
          memcpy(buf + len, str, strlen(str));
          len += strlen(str);
        }

      SSH_ASSERT(len + 2 <= sizeof(buf));

      buf[len] = ')';
      buf[len + 1] = '\0';

      /* Do not use the dummy accelerator */
      if (strcmp(buf, "name(dummy)"))
        {
          params->ek_accelerator_init_info = ssh_strdup(buf);
          if (params->ek_accelerator_init_info == NULL)
            {
              status = FALSE;
              goto fail;
            }

          params->ek_accelerator_type = ssh_strdup("genacc");
          if (params->ek_accelerator_type == NULL)
            {
              ssh_free(params->ek_accelerator_init_info);
              params->ek_accelerator_init_info = NULL;
              status = FALSE;
            }
        }
    fail:
      ssh_free(str);
    }

  return status;
}
#endif /* SSHDIST_EXTERNALKEY */


static void
ipm_free_params(SshPmParams params)
{
#ifdef SSHDIST_EXTERNALKEY
  if (params->ek_accelerator_type)
    ssh_free(params->ek_accelerator_type);

  if (params->ek_accelerator_init_info)
    ssh_free(params->ek_accelerator_init_info);
#endif /* SSHDIST_EXTERNALKEY */

  if (params->socks)
    ssh_free(params->socks);

  if (params->http_proxy)
    ssh_free(params->http_proxy);

  if (params->hostname)
    ssh_free(params->hostname);

  if (params->ike_addrs)
    ssh_free(params->ike_addrs);

  ssh_free(params);
}

/* State functions. */
SSH_FSM_STEP(ssh_ipm_st_start)
{
  SshPmParams params;

  ssh_ipm_report_state(SSH_IPM_STARTING);

  /* Init PM parameters. */

  params = ssh_calloc(sizeof(SshPmParamsStruct), 1);
  if (params == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM parameter allocation failed."));
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_EXTERNALKEY
  if (ipm_set_ek_accelerator_info(params) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Ek accelator info allocation failed."));
      ssh_free(params);
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_EXTERNALKEY */

  params->socks = ssh_strdup(arguments.socks_url);
  params->http_proxy = ssh_strdup(arguments.http_proxy_url);
  params->pass_unknown_ipsec_packets = arguments.pass_unknown_ipsec;

  if (arguments.no_dns_pass_rule)
    params->flags |=  SSH_PM_PARAM_FLAG_NO_DNS_FROM_LOCAL_PASS_RULE;
  if (arguments.disable_dhcp_client_pass_rule)
    params->flags |= SSH_PM_PARAM_FLAG_DISABLE_DHCP_CLIENT_PASSBY_RULE;
  if (arguments.enable_dhcp_server_pass_rule)
    params->flags |= SSH_PM_PARAM_FLAG_ENABLE_DHCP_SERVER_PASSBY_RULE;

  memmove(params->local_ike_ports,
          arguments.local_ike_ports,
          arguments.num_ike_ports * sizeof(SshUInt16));
  memmove(params->local_ike_natt_ports,
          arguments.local_ike_natt_ports,
          arguments.num_ike_ports * sizeof(SshUInt16));
  memmove(params->remote_ike_ports,
          arguments.remote_ike_ports,
          arguments.num_ike_ports * sizeof(SshUInt16));
  memmove(params->remote_ike_natt_ports,
          arguments.remote_ike_natt_ports,
          arguments.num_ike_ports * sizeof(SshUInt16));
  params->num_ike_ports = arguments.num_ike_ports;

  ssh_tcp_get_host_name(arguments.hostname, sizeof(arguments.hostname));
  params->hostname = ssh_strdup(arguments.hostname);

  if (arguments.dhcp_ras_enabled)
    params->dhcp_ras_enabled = TRUE;

  if (arguments.enable_key_restrictions != NULL &&
      strcmp(arguments.enable_key_restrictions, "nist-800-131a") == 0)
      params->enable_key_restrictions |= SSH_PM_PARAM_ALGORITHMS_NIST_800_131A;

  if (arguments.ike_addr)
    {
      unsigned char *addresses, *p;
      void *tmp;
      int i = 0;

      addresses = arguments.ike_addr;
      while (addresses)
        {
          p = ssh_ustrchr(addresses, ',');
          if (p != NULL)
            *p++ = '\0';

          tmp = ssh_realloc(params->ike_addrs, i * sizeof(SshIpAddrStruct),
                            (i + 1) * sizeof(SshIpAddrStruct));
          if (tmp != NULL)
            {
              params->ike_addrs = tmp;
              if (ssh_ipaddr_parse(&params->ike_addrs[i], addresses))
                i++;
              addresses = p;
            }
        }
      params->ike_addrs_count = i;
    }

#ifdef SSHDIST_IKE_MOBIKE
  if (ike_params_glb.retry_limit == 0)
    ike_params_glb.retry_limit = 30;
  if (ike_params_glb.retry_timer_max_msec == 0)
    ike_params_glb.retry_timer_max_msec = 6000;
#endif /* SSHDIST_IKE_MOBIKE */

  ike_params_glb.packet_preallocate_size = SSH_PM_MAX_IKE_SAS_IKE;

  params->ike_params = &ike_params_glb;

  /** Create policy manager. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_disable_policy_lookups);
  SSH_FSM_ASYNC_CALL({
    ssh_pm_create(arguments.machine_context, params,
                  ssh_ipm_create_cb, thread);
    ipm_free_params(params);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_disable_policy_lookups)
{
  SSH_FSM_SET_NEXT(ssh_ipm_st_wait_interfaces);

  /* Disable policy manager high level policy lookups before loading
     the initial configuration and re-enable them only after persistent
     SAs have been imported. */
  SSH_FSM_ASYNC_CALL({
    ssh_pm_disable_policy_lookups(ipm,
                                  ssh_ipm_disable_policy_lookups_cb, thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_wait_interfaces)
{
  /* Wait until we receive the initial interface callback. */
  if (!event_iface_change)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for interfaces"));
      SSH_FSM_CONDITION_WAIT(&event_cond);
    }
  event_iface_change = FALSE;

  SSH_DEBUG(SSH_D_LOWSTART, ("Continuing initialization"));

  SSH_FSM_SET_NEXT(ssh_ipm_st_initialize);
  return SSH_FSM_CONTINUE;
}

void *
ssh_ipm_context_perform_event_cb(void *ctx, SshIpmContextEvent e,
                                 SshIpmPmCommitCB commit_cb, void *cb_ctx)
{
  SSH_ASSERT(ctx != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Ipm Context event %d", e));

  switch (e)
    {
      case SSH_IPM_CONTEXT_GET_PM:
        {
          return ctx;
          break;
        }

      case SSH_IPM_CONTEXT_PM_COMMIT:
        {
          ssh_pm_commit(ctx, commit_cb, cb_ctx);
          break;
        }

      default:
        SSH_DEBUG(SSH_D_ERROR, ("Unknown event"));
        return NULL;
        break;
    }

  return NULL;
}

SSH_FSM_STEP(ssh_ipm_st_initialize)
{
#ifdef SSHDIST_EXTERNALKEY
  SshExternalKey ek;
#endif /* SSHDIST_EXTERNALKEY */
  if (ipm == NULL)
    {
      fprintf(stderr,
              "%s: Could not connect to the packet processing engine\n",
              arguments.program);
      ssh_ipm_report_state(SSH_IPM_STOPPING);
      /** Failed. */
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }

  ssh_ipm_report_state(SSH_IPM_STARTING);


  /* Print information about interfaces. */
  if (arguments.print_interface_info)
    {
      SshUInt32 ifnum;
      Boolean retval;

      printf("%s: Network interfaces:\n", arguments.program);

      for (retval = ssh_pm_interface_enumerate_start(ipm, &ifnum);
           retval;
           retval = ssh_pm_interface_enumerate_next(ipm, ifnum, &ifnum))
        {
          char *ifname;
          SshUInt32 num_addrs;

          if (ssh_pm_get_interface_name(ipm, ifnum, &ifname)
              && ssh_pm_interface_get_number_of_addresses(ipm, ifnum,
                                                          &num_addrs)
              && num_addrs)
            {
              SshUInt32 j;

              printf("%2u: %s:\n", (unsigned int) ifnum, ifname);
              for (j = 0; j < num_addrs; j++)
                {
                  SshIpAddrStruct ip, netmask, broadcast;
                  char buf[256];

                  if (ssh_pm_interface_get_address(ipm, ifnum, j, &ip)
                      && ssh_pm_interface_get_netmask(ipm, ifnum, j, &netmask))
                    {
                      ssh_snprintf(buf, sizeof(buf), "      %@/%@",
                                   ssh_ipaddr_render, &ip,
                                   ssh_ipmask_render, &netmask);
                      printf("%s", buf);

                      if (SSH_IP_IS4(&ip)
                          && ssh_pm_interface_get_broadcast(ipm, ifnum, j,
                                                            &broadcast))
                        {
                          ssh_snprintf(buf, sizeof(buf), " [%@]",
                                       ssh_ipaddr_render, &broadcast);
                          printf("%s", buf);
                        }

                      printf("\n");
                    }
                }
            }
        }
    }

  audit_context = ssh_audit_create(ssh_ipsecpm_audit_cb, NULL_FNPTR,
                                   pm_audit_context);
  if (audit_context == NULL)
    {
      fprintf(stderr, "%s: Could not create audit context\n",
              arguments.program);
      /** Out of memory. */
      ssh_ipm_report_state(SSH_IPM_STOPPING);
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }

  if (!ssh_pm_attach_audit_module(ipm, SSH_PM_AUDIT_ALL, audit_context))
    {
      fprintf(stderr, "%s: Cannot attach audit module to the system\n",
              arguments.program);
      ssh_ipm_report_state(SSH_IPM_STOPPING);
      /** Failed. */
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }

#ifndef VXWORKS
  /* Configuration the kernel debug level. */
  if (arguments.kernel_debug_level)
    ssh_pm_set_kernel_debug_level(ipm, arguments.kernel_debug_level);
#endif /* VXWORKS */

#ifdef SSHDIST_EXTERNALKEY
  /* Set externalkey authentication callback. */
  ek = ssh_pm_get_externalkey(ipm);
  ssh_ek_register_authentication_callback(ek, ssh_pm_ek_authentication_cb,
                                          NULL);
#endif /* SSHDIST_EXTERNALKEY */

  ssh_pm_set_dpd(ipm, 1, SSH_QUICKSECPM_DPD_TTL, ssh_pm_dpd_peer_cb, NULL);

  /* Create a configuration file parser. */
  ipm_ctx = ssh_ipm_context_create(ipm, &arguments,
              ssh_ipm_context_perform_event_cb, ipm);
  if (ipm_ctx == NULL)
    {
      fprintf(stderr, "%s: Could not create configuration file parser\n",
              arguments.program);
      /** Out of memory. */
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }

  /* The policy manager is now successfully created.  Move to the main
     thread processing events.  And we have two initial events:
     1: We set the blacklist from the blacklist configuration file and
     2: We configure the policy manager from the configuration file. */

#ifdef SSH_PM_BLACKLIST_ENABLED
  event_blacklist_reconfigure = TRUE;
#endif /* SSH_PM_BLACKLIST_ENABLED */

  event_reconfigure = TRUE;

  /** Start completed. */
  ssh_log_event(
    SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL, "Loading policy rules...");
  ssh_ipm_report_state(SSH_IPM_RUNNING);
  SSH_FSM_SET_NEXT(ssh_ipm_st_run);

















  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_run)
{
  /* Process events. */

  if (event_startup)
    {
      /** Startup */
      SSH_FSM_SET_NEXT(ssh_ipm_st_startup);
      return SSH_FSM_CONTINUE;
    }
  if (event_shutdown)
    {
      /** Shutdown. */
      ssh_ipm_report_state(SSH_IPM_STOPPING);
      SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown);
      return SSH_FSM_CONTINUE;
    }
#ifdef SSH_PM_BLACKLIST_ENABLED
  if (event_blacklist_reconfigure)
    {
      /** Blacklist reconfigure */
      SSH_FSM_SET_NEXT(ssh_ipm_st_blacklist_reconfigure);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSH_PM_BLACKLIST_ENABLED */
  if (event_reconfigure)
    {
      /** Reconfigure. */
      SSH_FSM_SET_NEXT(ssh_ipm_st_reconfigure);
      return SSH_FSM_CONTINUE;
    }

  if (event_redo_flows)
    {
      /** Re-evaluate policy */
      SSH_FSM_SET_NEXT(ssh_ipm_st_redo_flows);
      return SSH_FSM_CONTINUE;
    }










#ifdef SSHDIST_IPSEC_SA_EXPORT
  if (event_import_sas)
    {
      /** SA import */
      SSH_FSM_SET_NEXT(ssh_ipm_st_import_sas);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  /* Wait for new events. */
  SSH_FSM_CONDITION_WAIT(&event_cond);
}

#ifdef SSHDIST_IPSEC_SA_EXPORT
static void ipm_persistent_sas_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* Clean things up after import is finished. */
  ssh_pm_import_finalize(pm);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ipm_persistent_ipsec_sas_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* Do final initialization now that SAs have been imported. */
  if (event_startup)
    {
  /* Set the SA event callbacks. */
  ssh_pm_set_ike_sa_callback(ipm, ssh_ipm_ike_sa_callback, NULL);
  ssh_pm_set_ipsec_sa_callback(ipm, ssh_ipm_ipsec_sa_callback, NULL);

  /* Enable policy manager high level policy lookups now that persistent
     SAs have been imported. */
      ssh_pm_enable_policy_lookups(pm, ipm_persistent_sas_cb, thread);
    }
  else
    {
      ipm_persistent_sas_cb(pm, TRUE, context);
}
}

static void ipm_persistent_ike_sas_cb(SshPm pm, Boolean success, void *context)
{
  ssh_ipm_load_persistent_ipsec_sas(ipm_persistent_ipsec_sas_cb, context);
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */

SSH_FSM_STEP(ssh_ipm_st_startup)
{
#ifdef SSHDIST_IPSEC_SA_EXPORT
  /* Import SAS on startup. */
  event_import_sas = TRUE;
  SSH_FSM_SET_NEXT(ssh_ipm_st_import_sas);
  return SSH_FSM_CONTINUE;
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  SSH_FSM_SET_NEXT(ssh_ipm_st_startup_done);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_SA_EXPORT
SSH_FSM_STEP(ssh_ipm_st_import_sas)
{
  event_import_sas = FALSE;

  if (event_startup)
    SSH_FSM_SET_NEXT(ssh_ipm_st_startup_done);
  else
    SSH_FSM_SET_NEXT(ssh_ipm_st_run);

  if (persistent_sas_glb)
    {
      printf("%s: Importing SAs from directory '%s'\n",
             arguments.program, persistent_sas_glb);
      SSH_FSM_ASYNC_CALL({
        ssh_ipm_load_persistent_ike_sas(ipm_persistent_ike_sas_cb, thread);
      });
    }
  else
    return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */

SSH_FSM_STEP(ssh_ipm_st_startup_done)
    {
  event_startup = FALSE;
  SSH_FSM_SET_NEXT(ssh_ipm_st_run);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSH_PM_BLACKLIST_ENABLED
static void
ssh_ipm_blacklist_commit_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  if (success == TRUE)
    printf("%s: Blacklist configuration activated\n", arguments.program);
  else
    printf("%s: Blacklist configuration activation failed\n",
           arguments.program);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ssh_ipm_blacklist_commit(SshPmStatusCB callback, void *context)
{
  ssh_pm_commit(ipm, callback, context);
}

SSH_FSM_STEP(ssh_ipm_st_blacklist_reconfigure)
{
  Boolean file_exists = TRUE;
  unsigned char empty_file = '\0';
  unsigned char *config;
  size_t config_len;
  SshPmBlacklistError err;
  struct stat buf;

  /* Clear the event flag and increment counter. */
  event_blacklist_reconfigure = FALSE;
  blacklist_reconfigure_count++;

  SSH_FSM_SET_NEXT(ssh_ipm_st_run);

  /* Just continue if file name has not given. */
  if (blacklist_conf_file == NULL)
    return SSH_FSM_CONTINUE;

  /* File existence check */
  if (stat(blacklist_conf_file, &buf) == 0)
    file_exists = TRUE;
  else
    file_exists = FALSE;

  if (file_exists == FALSE)
    {
      /* Use empty file if real file doesn't exist. */
      err = ssh_pm_blacklist_set(ipm, &empty_file, 0);
      if (err)
        {
          printf("%s: Cannot set empty blacklist configuration\n",
                 arguments.program);
          goto fail;
        }
    }
  else if (ssh_read_file(blacklist_conf_file, &config, &config_len))
    {
      /* Use content of real file if read is successful. */
      err = ssh_pm_blacklist_set(ipm, config, config_len);
      ssh_free(config);
      if (err)
        {
          printf("%s: Cannot set blacklist configuration from file %s\n",
                 arguments.program, blacklist_conf_file);
          goto fail;
        }
    }
  else
    {
      printf("%s: Cannot read blacklist configuration file %s\n",
             arguments.program, blacklist_conf_file);
      goto fail;
    }

  /* Commit new blacklist configuration. */
  SSH_FSM_ASYNC_CALL({
    ssh_ipm_blacklist_commit(ssh_ipm_blacklist_commit_cb, thread);
  });
  SSH_NOTREACHED;

 fail:

  /* If this was the initial configuration, stop the policy manager. */
  if (blacklist_reconfigure_count == 1)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Stopping policy manager"));
      event_shutdown = TRUE;
      event_startup = FALSE;
      ssh_fsm_condition_signal(&quicksecpm_fsm, &event_cond);
    }

  return SSH_FSM_CONTINUE;
}
#endif /* SSH_PM_BLACKLIST_ENABLED */

SSH_FSM_STEP(ssh_ipm_st_reconfigure)
{
  /** Clear the event. */
  event_reconfigure = FALSE;
  event_reconfigure_count++;

  SSH_FSM_SET_NEXT(ssh_ipm_st_run);

  /** Perform startup tasks after initial configuration. */
  if (event_reconfigure_count == 1)
    {
      SSH_FSM_SET_NEXT(ssh_ipm_st_enable_policy_lookups);
      event_startup = TRUE;
    }

  /** Instantiate policy. */
  SSH_FSM_ASYNC_CALL({
    event_reconfigure_operation =
      ssh_ipm_configure(ipm_ctx, ssh_ipm_reconfigure_cb, thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_enable_policy_lookups)
{
  /** Enable policy manager high level policy lookups. */
#ifdef SSHDIST_IPSEC_SA_EXPORT
  /** ... but only after persistent SAs have been imported. */
  if (persistent_sas_glb == NULL)
#endif /* SSHDIST_IPSEC_SA_EXPORT */
    ssh_pm_enable_policy_lookups(ipm, NULL, NULL);

  SSH_FSM_SET_NEXT(ssh_ipm_st_run);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_redo_flows)
{
  event_redo_flows = FALSE;

  if (ipm != NULL)
    {
      printf("%s: Signaling engine to re-evaluate flows\n", arguments.program);
      ssh_pm_redo_flows(ipm);
    }

  SSH_FSM_SET_NEXT(ssh_ipm_st_run);
  return SSH_FSM_CONTINUE;
}





















SSH_FSM_STEP(ssh_ipm_st_shutdown)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Shutting down"));
  ssh_ipm_report_state(SSH_IPM_STOPPING);

  /* Cancel the possible reconfigure/refresh timeouts. */
  ssh_cancel_timeout(&reconfigure_timeout);
  ssh_cancel_timeout(&refresh_flows_timeout);









  /** Notify policy manager context about shutdown. */
  SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown_context);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ipm_st_shutdown_context)
{
  if (ipm_ctx && !ssh_ipm_context_shutdown(ipm_ctx))
    {
      /* Wait for a while that the policy manager context shuts down. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Waiting for policy manager context to shutdown"));
      ssh_ipm_report_state(SSH_IPM_STOPPING);
      SSH_FSM_ASYNC_CALL(ssh_xregister_timeout(1, 0, ssh_ipm_timeout_cb,
                                               thread));
      SSH_NOTREACHED;
    }

  /** Shutdown the policy manager. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Stopping the policy manager"));
  ssh_ipm_report_state(SSH_IPM_STOPPING);
  SSH_FSM_SET_NEXT(ssh_ipm_st_shutdown_complete);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (ipm)
          ssh_pm_destroy(ipm, ssh_ipm_stop_cb, thread);
        else
          ssh_ipm_stop_cb(thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_ipm_st_shutdown_complete)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Policy manager stopped"));
  ipm = NULL;
  ssh_ipm_report_state(SSH_IPM_STOPPING);

  /* Destroy policy manager context. */
  if (ipm_ctx)
    {
      ssh_ipm_context_destroy(ipm_ctx);
      ipm_ctx = NULL;
    }

  event_shutdown = FALSE;

#ifdef HAVE_THREADS
  ssh_threaded_timeouts_uninit();
#endif /* HAVE_THREADS */

  /* We are done. */
  return SSH_FSM_FINISH;
}


/************ The main program entry pont and its help functions ************/

/* Show short usage text. */
static void
usage(void)
{
  printf("\
Usage: %s [OPTION]...\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -a, --allow-bootstrap=TS        allow traffic to TS during PM startup\n\
  -d, --daemon                    run as a daemon\n\
  -u, --pass-unknown-ipsec        pass unknown IPsec packets\n\
  -D, --debug=DEBUG               set the debug level string to DEBUG\n\
  -O, --debug-output-file=FILE    save debug output into FILE\n\
  -e, --machine-context=CONTEXT   machine context argument for the IPsec\n\
                                  engine\n\
  -f, --file=FILE                 read the policy from the file FILE\n\
  -h, --help                      print this help and exit\n\
  -H, --http-proxy=PROXY-URL      use HTTP proxy PROXY-URL\n\
  -i, --interface-info            list names of available network interfaces\n\
  -K, --kernel-debug=DEBUG        set the kernel debug level string to DEBUG\n\
  -n, --ike-logging-level=LEVEL   set the IKEv1 logging level to LEVEL\n\
  -S, --socks=SOCKS-URL           use SOCKS server SOCKS-URL\n\
  -V, --version                   print version number\n\
  -b, --ike-bind-list=IPLIST      list of IP addresses IKE binds to\n",
         arguments.program);
  /* Microsoft's compiler does not accept constant strings longer than 2048
     characters. That's why this help text is splitted into parts. */
  printf("\
  --no-dns-pass-rule              do not install DNS pass rules\n\
  --disable-dhcp-client-pass-rule do not install DHCP client pass rule\n\
  --enable-dhcp-server-pass-rule  install DHCP server pass rule\n\
  --accel-type=TYPE               externalkey accelerator type\n\
  --accel-init-info=INIT_INFO     externalkey accelerator init info\n\
  --ike-ports=NUM:NUM             set IKE normal and nat-t ports\n\
  --ike-retry-limit=VAL           set IKE retry limit to VAL\n\
  --ike-retry-timer-msec=VAL      set IKE retry timer msec to VAL\n\
  --ike-retry-timer-max-msec=VAL  set IKE retry timer max msec to VAL\n\
  --ike-expire-timer-msec=VAL     set IKEv1 expire timer msec to VAL\n");
#ifdef SSH_PM_BLACKLIST_ENABLED
  printf("\
  --ike-blacklist-file=FILE       read blacklisted IKE IDs from the file "
                                 "FILE\n");
#endif /* SSH_PM_BLACKLIST_ENABLED */
#ifdef SSHDIST_IPSEC_SA_EXPORT
  printf("\
  -p, --persistent-sas=DIR        save SAs to the directory DIR\n");
#endif /* SSHDIST_IPSEC_SA_EXPORT */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IPSEC_DHCP
  printf("\
  -R, --enable-dhcp-ras-check     enable sanity check for DHCP "
                                  "address pool\n");
#endif /* SSHDIST_IPSEC_DHCP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  printf("\
  -N, --key-strength-enforced     key and algorithm restrictions enforced, "
                                  "currently NIST 800-131A requirements "
                                  "supported. 'nist-800-131a' must be given "
                                  "as argument to the long option\n");








#ifdef SSHDIST_PLATFORM_WIN32
#if defined(WINDOWS)
  printf("\
  --install-service               install policy manager as Windows service\n\
  --remove-service                remove policy manager service\n");
#endif /* WINDOWS */
#endif /* SSHDIST_PLATFORM_WIN32 */
}

/* Print version information. */
static void
ssh_ipm_version(void)
{
  printf("%s\n"
         "  Copyright:\n"
         "  Copyright (c) 2002 - 2014, INSIDE Secure Oy."
         " All rights reserved..\n",
         SSH_IPSEC_VERSION_STRING_SHORT);
}

/* Log callback function and context currently registered, or NULL. */
SshLogCallback ssh_ipm_registered_log_callback;
void *ssh_ipm_registered_log_context;

/* Debug callback functions and context currently registered, or NULL. */
SshErrorCallback ssh_ipm_registered_fatal_callback;
SshErrorCallback ssh_ipm_registered_warning_callback;
SshErrorCallback ssh_ipm_registered_debug_callback;
void *ssh_ipm_registered_debug_context;

/* Event log callback which reports the events to the stderr. */
static void
ssh_ipm_log_callback(SshLogFacility facility, SshLogSeverity severity,
                     const char *message, void *context)
{
  char *s;

  switch (severity)
    {
    case SSH_LOG_INFORMATIONAL:
      s = "I";
      break;

    case SSH_LOG_NOTICE:
      s = "N";
      break;

    case SSH_LOG_WARNING:
      s = "W";
      break;

    case SSH_LOG_ERROR:
      s = "E";
      break;

    case SSH_LOG_CRITICAL:
      s = "C";
      break;

    default:
      s = "?";
      break;
    }
  fprintf(stderr, "%s: %s; %s\n", arguments.program, s, message);
}

static void
pm_debug_file_cb(const char *prefix, const char *message,
                 const char *filename)
{
  if (!filename)
    return;

  if (pm_debug_file_handle == NULL)
    pm_debug_file_handle = fopen(filename, "a");

  if (pm_debug_file_handle)
    {
      fprintf(pm_debug_file_handle, "%s: ", prefix);
      fprintf(pm_debug_file_handle, "%s\n", message);
      fflush(pm_debug_file_handle);
    }
}

static void
pm_debug_fatal_file_cb(const char *message, void *ctx)
{
  pm_debug_file_cb("FATAL", message, (char *)ctx);
}

static void
pm_debug_warning_file_cb(const char *message, void *ctx)
{
  pm_debug_file_cb("WARNING", message, (char *)ctx);
}

static void
pm_debug_debug_file_cb(const char *message, void *ctx)
{
  pm_debug_file_cb("DEBUG", message, (char *)ctx);
}




















static void
ssh_ipm_log_file_cb(SshLogFacility facility, SshLogSeverity severity,
                    const char *message, void *ctx)
{
  char *s;

  switch (severity)
    {
    case SSH_LOG_INFORMATIONAL:
      s = "LOG-I";
      break;

    case SSH_LOG_NOTICE:
      s = "LOG-N";
      break;

    case SSH_LOG_WARNING:
      s = "LOG-W";
      break;

    case SSH_LOG_ERROR:
      s = "LOG-E";
      break;

    case SSH_LOG_CRITICAL:
      s = "LOG-C";
      break;

    default:
      s = "LOG-?";
      break;
    }

  pm_debug_file_cb(s, message, (char *)ctx);
}

int
ssh_ipm_start(int argc, char *argv[])
{
  SshGetOptDataStruct getopt;
  int opt;

  char *output_file = NULL;
#ifdef __linux__
# ifdef __tilegx__
  struct stat status;
  char machine_context[64];
  char *file_name = "/var/run/quicksec";
  FILE *input_file = fopen(file_name, "rb");

  memset(&machine_context, 0, sizeof(machine_context));

  if (input_file == NULL)
    {
      fprintf (stderr, "Unable to open file: %s\n", file_name);
    }
  else
    {
      if (fstat(fileno(input_file), &status) != 0)
        {
          fprintf(stderr, "Unable to stat file: %s\n", file_name);
        }
      else
        {
          if (status.st_size >= sizeof(machine_context))
            {
              fprintf(stderr, "Machine context string longer than "
                      "reserved space.\n");
            }
          else
            {
              fread (&machine_context, 1, status.st_size - 1, input_file);
            }
        }
    }
# else /* not __tilegx__ */
#  ifdef USERMODE_ENGINE
  char *machine_context = "/proc/quicksec-usermode/engine";
#  else /* USERMODE_ENGINE */
  char *machine_context = "/proc/quicksec/engine";
#  endif /* USERMODE_ENGINE */
# endif /* __tilegx__ */
#else /* not __linux__ */
# ifdef WIN32
  char *machine_context = "\\\\.\\QuickSec";
# else /* not WIN32 */
#  ifdef __sun
#   ifdef USERMODE_ENGINE
  char *machine_context = "/devices/pseudo/sshpmdev@0:sshengine-usermode";
#   else /* USERMODE_ENGINE */
  char *machine_context = "/devices/pseudo/sshpmdev@0:sshengine";
#   endif /* USERMODE_ENGINE */
#  else /* not __sun */
#   ifdef VXWORKS
  char *machine_context = "/ipsec";
#   else /* not VXWORKS */
#    ifdef USERMODE_ENGINE
  char *machine_context = "/dev/quicksec-usermode";
#    else /* USERMODE_ENGINE */
  char *machine_context = "/dev/quicksec";
#    endif /* USERMODE_ENGINE */
#   endif /* not VXWORKS */
#  endif /* not __sun */
# endif /* not WIN32 */
#endif /* not __linux__ */

  /* Init policy manager parameters. */

  memset(&arguments, 0, sizeof(arguments));

  arguments.program = ssh_custr(strrchr(argv[0], '/'));
  if (arguments.program)
    arguments.program++;
  else
    arguments.program = ssh_custr(argv[0]);

  arguments.machine_context = machine_context;
  arguments.config_file = ssh_custr("quicksec.xml");

  /* Parse options. */

  ssh_getopt_init_data(&getopt);

  while ((opt = ssh_getopt_long(argc, argv,
                                "a:duD:O:e:f:b:B:hH:iK:n:p:S:VRN",
                                long_options, NULL, &getopt))
         != EOF)
    {
      switch (opt)
        {
        case 'a':
          arguments.bootstrap_traffic_selector = ssh_ustr(getopt.arg);
          break;

        case 'd':
          if (!ssh_ipm_make_service())
            return 1;
          break;

        case 'u':
          arguments.pass_unknown_ipsec = TRUE;
          break;

        case 'D':
          ssh_debug_set_level_string(getopt.arg);
          break;

        case 'O':
          output_file = getopt.arg;
          break;

        case 'e':
          arguments.machine_context = getopt.arg;
          break;

        case 'f':
          arguments.config_file = ssh_custr(getopt.arg);
          break;

        case 'b':
          arguments.ike_addr = ssh_ustr(getopt.arg);
          break;

        case 'h':
          usage();
          return 0;
          break;

        case 'H':
          {
            unsigned char *scheme = NULL;

            arguments.http_proxy_url = ssh_ustr(getopt.arg);
            if (!ssh_url_parse(arguments.http_proxy_url, &scheme,
                               NULL, NULL, NULL, NULL, NULL)
                || ssh_usstrcmp(scheme, "http") != 0)
              {
                ssh_free(scheme);
                fprintf(stderr, "%s: Malformed HTTP proxy URL `%s'\n",
                        arguments.program, arguments.http_proxy_url);
                return 1;
              }
            ssh_free(scheme);
          }
          break;

        case 'i':
          arguments.print_interface_info = TRUE;
          break;

        case 'K':
          arguments.kernel_debug_level = getopt.arg;
          break;

        case 'n':
#ifdef SSHDIST_IKEV1
#ifdef DEBUG_LIGHT
          ssh_ike_logging_level = atoi(getopt.arg);
#else /* not DEBUG_LIGHT */
          ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_WARNING,
                        "No IKE logging enabled.  The system has not "
                        "been compiled with `--enable-debug'.");
#endif /* not DEBUG_LIGHT */
#endif /* SSHDIST_IKEV1 */
          break;

#ifdef SSHDIST_IPSEC_SA_EXPORT
        case 'p':
          persistent_sas_glb = getopt.arg;
          break;
#endif /* SSHDIST_IPSEC_SA_EXPORT */

        case 'S':
          {
            unsigned char *scheme = NULL;

            arguments.socks_url = ssh_ustr(getopt.arg);
            if (!ssh_url_parse(arguments.socks_url, &scheme,
                               NULL, NULL, NULL, NULL, NULL)
                || ssh_usstrcmp(scheme, "socks") != 0)
              {
                ssh_free(scheme);
                fprintf(stderr, "%s: Malformed SOCKS server URL `%s'\n",
                        arguments.program, arguments.socks_url);
                return 1;
              }
            ssh_free(scheme);
          }
          break;

        case 'V':
          ssh_ipm_version();
          return 0;
          break;

        case 'R':
          arguments.dhcp_ras_enabled = TRUE;
          break;

        case 'N':
            arguments.enable_key_restrictions = ssh_custr(getopt.arg);
            if (arguments.enable_key_restrictions != NULL &&
                strcmp(arguments.enable_key_restrictions, "nist-800-131a")
                != 0)
              {
                fprintf(stderr,
                      "%s: Not supported algorithm restriction scheme\n",
                      arguments.enable_key_restrictions);
                return 1;
              }
            else if (arguments.enable_key_restrictions == NULL)
              arguments.enable_key_restrictions = "nist-800-131a";
          break;

        case 129:
          ek_accelerator_type_glb = getopt.arg;
          break;

        case 130:
          ek_accelerator_init_info_glb = getopt.arg;
          break;

        case 140:
          ike_params_glb.retry_limit = atoi(getopt.arg);
          break;

        case 141:
          ike_params_glb.retry_timer_msec = atoi(getopt.arg);
          break;

        case 142:
          ike_params_glb.retry_timer_max_msec = atoi(getopt.arg);
          break;

        case 143:
#ifdef SSHDIST_IKEV1
          ike_params_glb.expire_timer_msec = atoi(getopt.arg);
#endif /* SSHDIST_IKEV1 */
          break;

        case 144:
          {
            int local_ike_port, local_ike_natt_port;
            int remote_ike_port, remote_ike_natt_port;
            char none;
            if (sscanf(getopt.arg, "%d:%d,%d:%d%c",
                       &local_ike_port, &local_ike_natt_port,
                       &remote_ike_port, &remote_ike_natt_port,
                       &none) == 4)
              {
                ;
              }
            else if (sscanf(getopt.arg, "%d:%d%c",
                            &local_ike_port, &local_ike_natt_port,
                            &none) == 2)
              {
                remote_ike_port = local_ike_port;
                remote_ike_natt_port = local_ike_natt_port;
              }
            else
              {
                printf("Malformed IKE ports '%s'\n", getopt.arg);
                exit(1);
              }

            if (local_ike_port == local_ike_natt_port
                || (local_ike_port <= 1024 && local_ike_port != 500)
                || local_ike_natt_port == 500
                || local_ike_port == 4500
                || local_ike_natt_port <= 1024
                || local_ike_port > 65535
                || local_ike_natt_port > 65535
                || remote_ike_port == remote_ike_natt_port
                || (remote_ike_port <= 1024 && remote_ike_port != 500)
                || remote_ike_natt_port == 500
                || remote_ike_port == 4500
                || remote_ike_natt_port <= 1024
                || remote_ike_port > 65535
                || remote_ike_natt_port > 65535)
              {
                fprintf(stderr, "%s: Invalid IKE ports '%s'\n",
                        arguments.program, getopt.arg);
                return 1;
              }
            if (arguments.num_ike_ports >= SSH_IPSEC_MAX_IKE_PORTS)
              {
                fprintf(stderr, "%s: Too many IKE ports '%d'; %d allowed\n",
                        arguments.program,
                        arguments.num_ike_ports + 1,
                        SSH_IPSEC_MAX_IKE_PORTS);
                return 1;
              }
            arguments.local_ike_ports[arguments.num_ike_ports] =
              local_ike_port;
            arguments.local_ike_natt_ports[arguments.num_ike_ports] =
              local_ike_natt_port;
            arguments.remote_ike_ports[arguments.num_ike_ports] =
              remote_ike_port;
            arguments.remote_ike_natt_ports[arguments.num_ike_ports] =
              remote_ike_natt_port;
            arguments.num_ike_ports++;
          }
          break;

        case 145:
          arguments.no_dns_pass_rule = TRUE;
          break;

        case 146:
          arguments.disable_dhcp_client_pass_rule = TRUE;
          break;

        case 147:
          arguments.enable_dhcp_server_pass_rule = TRUE;
          break;

#ifdef SSH_PM_BLACKLIST_ENABLED
        case 148:
          blacklist_conf_file = getopt.arg;
          break;
#endif /* SSH_PM_BLACKLIST_ENABLED */












        case '?':
          fprintf(stderr, "Try `%s -h' for more information.\n",
                  arguments.program);
          return 1;
          break;

        default:
          fprintf(stderr, "%s: Invalid option `%s'\n",
                  arguments.program, ssh_custr(getopt.arg));
          usage();
          return 0;
          break;
        }
    }

  if (output_file)
    {
      ssh_ipm_registered_fatal_callback = pm_debug_fatal_file_cb;
      ssh_ipm_registered_warning_callback = pm_debug_warning_file_cb;
      ssh_ipm_registered_debug_callback = pm_debug_debug_file_cb;
      ssh_ipm_registered_debug_context = output_file;
    }












  if (ssh_ipm_registered_fatal_callback)
    {
      ssh_debug_register_callbacks(
        ssh_ipm_registered_fatal_callback,
        ssh_ipm_registered_warning_callback,
        ssh_ipm_registered_debug_callback,
        ssh_ipm_registered_debug_context);
    }

  if (getopt.ind != argc)
    {
      usage();
      return 1;
    }

  ssh_ipm_report_state(SSH_IPM_STARTING);

#ifdef HAVE_THREADS
  SSH_DEBUG(SSH_D_HIGHOK, ("Threads are defined."));
  ssh_threaded_timeouts_init();
#endif /* HAVE_THREADS */

  pm_audit_context = ssh_ipsecpm_audit_create(100);
  if (pm_audit_context == NULL)
    {
      ssh_warning("Could not create policy manager audit context");
      ssh_ipm_report_state(SSH_IPM_STOPPED);
      return 1;
    }

#ifdef SSHDIST_CERT
  /* Initialize the certificate library, this will initialize crypto
     as well. */
  {
    if (!ssh_x509_library_initialize_framework(NULL))
      {
        ssh_warning("Could not initialize the certificate library.");
        ssh_ipm_report_state(SSH_IPM_STOPPED);
        return 1;
      }

    if (!ssh_x509_library_register_functions(SSH_X509_PKIX_CERT,
                                             ssh_x509_cert_decode_asn1,
                                             NULL_FNPTR))
      {
        ssh_warning("Could not register x509 library functions.");
        ssh_ipm_report_state(SSH_IPM_STOPPED);
        return 1;

      }
  }
#else /* SSHDIST_CERT */
  {
    printf("%s: Initializing crypto library...\n", arguments.program);

    if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
      {
        ssh_warning("Could not initialize the crypto library.");
        ssh_ipm_report_state(SSH_IPM_STOPPED);
        return 1;
      }
  }
#endif /* SSHDIST_CERT */

  ssh_ipm_report_state(SSH_IPM_STARTING);

  /* Register event log callback unless a daemon (ssh_ipm_make_service
     has forced a syslog callback)  */
  if (output_file)
    {
      ssh_ipm_registered_log_callback = ssh_ipm_log_file_cb;
      ssh_ipm_registered_log_context = output_file;
    }
  else





    {
      ssh_ipm_registered_log_callback = ssh_ipm_log_callback;
      ssh_ipm_registered_log_context = NULL;
    }

  ssh_log_register_callback(
    ssh_ipm_registered_log_callback, ssh_ipm_registered_log_context);

#ifdef SSHDIST_CRYPT_ECP
  if (ssh_pk_provider_register(&ssh_pk_ec_modp) != SSH_CRYPTO_OK)
    ssh_warning("Could not register PK provider.");
#endif /* SSHDIST_CRYPT_ECP */





  ssh_ipm_report_state(SSH_IPM_STARTING);

  /* Initialize FSM. */
  ssh_fsm_init(&quicksecpm_fsm, NULL);
  ssh_fsm_condition_init(&quicksecpm_fsm, &event_cond);

  ssh_log_event(
    SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL, "Connecting to engine...");
  ssh_ipm_report_state(SSH_IPM_STARTING);

  ssh_ipm_report_state(SSH_IPM_STARTING);

  /* Start an FSM thread for controlling the policy manager. */
  ssh_fsm_thread_init(&quicksecpm_fsm, &quicksecpm_thread, ssh_ipm_st_start,
                      NULL_FNPTR, NULL_FNPTR, NULL);

  ssh_event_loop_run();

  ssh_ipm_report_state(SSH_IPM_STOPPING);

  /* Cleanup. */
  SSH_ASSERT(ipm == NULL);
  SSH_ASSERT(ipm_ctx == NULL);

  /* Uninitialize the PM library */
  ssh_pm_library_uninit();

  ssh_event_loop_uninitialize();

  ssh_ipsecpm_audit_destroy(pm_audit_context);

  ssh_ipm_report_state(SSH_IPM_STOPPED);

#ifdef SSHDIST_CERT
  ssh_x509_library_uninitialize();
#else /* SSHDIST_CERT */
  ssh_crypto_library_uninitialize();
#endif /* SSHDIST_CERT */
#ifndef VXWORKS
  ssh_util_uninit();
#endif /* !VXWORKS */

  SSH_APE_MARK(1, ("Policymanager stopped"));
  return pm_exit_status;
}
