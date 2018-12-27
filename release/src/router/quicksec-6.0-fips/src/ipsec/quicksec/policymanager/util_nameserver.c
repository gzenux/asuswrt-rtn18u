/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Configures DNS and WINS addresses obtained though ISAKMP Exchange.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshfileio.h"
#include "util_nameserver.h"

#ifdef SSHDIST_UTIL_DNS_RESOLVER
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshdns.h"
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

#ifdef SSHDIST_PLATFORM_WIN32
#ifdef WINDOWS
#include "ssheloop.h"
#include <windows.h>
#endif /* WINDOWS */
#endif /* SSHDIST_PLATFORM_WIN32 */

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#include <resolvLib.h>
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

#define SSH_DEBUG_MODULE "SshPmUtilNameServer"

#ifdef SSHDIST_PLATFORM_WIN32
#ifdef WINDOWS

typedef void (*SshCmdCompleteCB)(Boolean success, void *context);

/* Context structure for asynchronously completed name server configutation
   command. */
struct SshCmdExecutionContextRec
{
  /* Callback function to be executed when command is completed */
  SshCmdCompleteCB completion_cb;
  void *completion_ctx;

  /* DNS and WINS server IP addresses */
  SshUInt32 num_dns;
  SshIpAddr dns;
  SshUInt32 num_wins;
  SshIpAddr wins;

    /* Windows OS specific data members */
  HANDLE thread;
  Boolean success;
};

typedef struct SshCmdExecutionContextRec SshCmdExecutionContextStruct;
typedef struct SshCmdExecutionContextRec *SshCmdExecutionContext;

static void
ssh_net_add_name_server_win(SshInt32 num_dns,
                            SshIpAddr dns,
                            SshInt32 num_wins,
                            SshIpAddr wins,
                            SshPmAddNameserverCB callback,
                            void *context);

static Boolean
ssh_pm_read_value_from_registry(HKEY root_key,
                                const unsigned char *path,
                                const unsigned char *value_name,
                                unsigned char *value_data,
                                size_t value_size)
{
  HKEY handle;
  SshUInt32 status;

  status = RegOpenKeyExA(root_key,path,0,KEY_QUERY_VALUE,&handle);
  if (status == ERROR_SUCCESS)
    {
      DWORD size = (DWORD)value_size;

      status = RegQueryValueExA(handle, value_name,
                                NULL,NULL,
                                (LPBYTE)value_data, &size);
      RegCloseKey(handle);
      return ((status == ERROR_SUCCESS) ? TRUE : FALSE);
    }

  return FALSE;
}







































static Boolean
ssh_execute_command(char *cmd_line)
{
  PROCESS_INFORMATION pi;
  STARTUPINFO si;

  memset(&pi, 0, sizeof(pi));
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_execute_command(): %s", cmd_line));

  if (!CreateProcess(NULL, cmd_line, NULL, NULL, FALSE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to create process! (error = 0x%08X)",
                 GetLastError()));

      return FALSE;
    }
  else
    {
      DWORD exit_code;

      WaitForSingleObject(pi.hProcess, INFINITE);

      GetExitCodeProcess(pi.hProcess, &exit_code);

      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);

      if (exit_code == ERROR_SUCCESS)
        {
          return TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Command: '%s' failed! (error = 0x%08X)",
                    cmd_line, exit_code));

          return FALSE;
        }
    }
}

/* Executes Microsoft's NETSH tool with the given parameters. Notice that
   we MUST be very carefull and specify the full path for the NETSH.EXE. If
   we don't do that, it would be quite trivial for an attacker to use our
   policy manager to execute some malicious code (with administrative
   privileges!) instead of the intended application! */
static Boolean
ssh_execute_netsh_command(char *parameters)
{
  unsigned char system_dir[MAX_PATH];
  unsigned char cmd_line[MAX_PATH];

  if (!GetSystemDirectory(system_dir, sizeof(system_dir)))
  {
    SSH_DEBUG(SSH_D_FAIL, ("Failed to read system directory"));
    return FALSE;
  }

  ssh_snprintf(cmd_line, sizeof(cmd_line), "\"%s\\NETSH.EXE\" %s",
               system_dir, parameters);
  SSH_DEBUG(SSH_D_LOWOK, ("Executing NETSH with %s", cmd_line));
  return (ssh_execute_command(cmd_line));
}

#endif /* WINDOWS */
#endif /* SSHDIST_PLATFORM_WIN32 */



#ifdef SSHDIST_PLATFORM_WIN32
/* On Windows the following logic has been used for determining the
   name of the virtual adapter to which we shall bind.
       * Read HKLM\System\CurrentControlSet\Services\qsvnic\Enum\
       * Read HKLM\System\CurrentControlSet\Enum\"value obtained from
                 last read"\Driver.
       This will give us the Net class GUID and index.
       * Read the contents of NetCfgInstanceId of the key
         HKLM\System\CurrentControlSet\Control\Class\""value obtained from
                   last read"
      * This will give us the GUID of the virtual adapter.
  Now the various servers are configured as
      * Now DNS address shall be written to NameServer entry under HKLM\
      * System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\"GUID"
      * The WINS address shall be written to NameServer List under HKLM\
        System\CurrentControlSet\Services\NetBT\Tcpip_"GUID"
***********************************************************/
#ifdef WINDOWS
#define VIRT_ENUM_0_KEY "System\\CurrentControlSet\\Services\\qsvnic\\Enum"

#define ENUM_KEY "System\\CurrentControlSet\\Enum"

#define NETCFG_KEY "System\\CurrentControlSet\\Control\\Class"

#define NET_ADAPTERS_KEY  "System\\CurrentControlSet\\Control\\Network\\" \
                          "{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define ADAPTER_KEY_START "System\\CurrentControlSet\\Services\\Tcpip\\" \
                          "Parameters\\Interfaces"

#define WINS_KEY_START "System\\CurrentControlSet\\Services\\NetBT\\" \
                       "Parameters\\Interfaces\\Tcpip_"

static int get_windows_major_version()
{
  OSVERSIONINFO os;
  int winver;

  memset(&os, 0, sizeof(os));

  os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

  GetVersionEx(&os);

  winver = os.dwMajorVersion;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Windows major version: %d",  winver));

  if (winver == 5 || winver == 6)
    return winver;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown Windows major version: %d", winver));
      return 0;
    }
}

static Boolean
ssh_net_get_virtual_adapter_name(unsigned char *output_buffer,
                                 size_t buf_len)
{
  unsigned char buffer[1024]= {0};
  unsigned char value[1024] = {0};
  int winver;

  /* In Vista and 2008 we can always use human-readable interface
     name, but in other versions we use the NetCfgInstanceId
     that must be used with invisible virtual adapters. */
  winver = get_windows_major_version();
  if (winver == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed get Windows version number"));
      return FALSE;
    }

  if (!ssh_pm_read_value_from_registry(HKEY_LOCAL_MACHINE,
                                       VIRT_ENUM_0_KEY,
                                       "0",
                                       value, sizeof(value)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed read value from %s", VIRT_ENUM_0_KEY));
      return FALSE;
    }
  ssh_snprintf(buffer, sizeof(buffer), "%s\\%s", ENUM_KEY, value);
  memset(value, 0, sizeof(value));

  if (!ssh_pm_read_value_from_registry(HKEY_LOCAL_MACHINE,
                                       buffer,
                                       "Driver",
                                       value, sizeof(value)))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed read value from %s", buffer));
      return FALSE;
    }
  ssh_snprintf(buffer, sizeof(buffer), "%s\\%s", NETCFG_KEY, value);
  memset(value, 0, sizeof(value));

  if (!ssh_pm_read_value_from_registry(HKEY_LOCAL_MACHINE,
                                       buffer,
                                       "NetCfgInstanceId",
                                       value, sizeof(value)))
    return FALSE;

  if (winver == 5)
    {
      int value_size;

      /* For Win 2000, 2003 and XP */
      value_size = ssh_ustrlen(value) + 1;
      if (value_size > buf_len)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Virtual adapter has too long name!"));
          return FALSE;
        }
      else
        {
          memcpy(output_buffer, value, value_size);
          return TRUE;
        }
    }

  ssh_snprintf(buffer, sizeof(buffer), "%s\\%s\\Connection",
               NET_ADAPTERS_KEY, value);


  memset(output_buffer, 0, buf_len);

  /* Read the human readable name given to this interface;
     e.g. "Local Area Connection".
  */
  if (!ssh_pm_read_value_from_registry(HKEY_LOCAL_MACHINE,
                                       buffer,
                                       "Name",
                                       output_buffer, buf_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed read value from %s", buffer));
      return FALSE;
    }
  return TRUE;
}


static Boolean
ssh_net_remove_name_servers(const unsigned char *adapter_name,
                            const unsigned char *ns_type, /* "dns"/"wins" */
                            SshInt32 num_servers,
                            SshIpAddr servers)
{
  Boolean success = FALSE;
  unsigned char buffer[512];

  SSH_ASSERT(adapter_name != NULL);
  SSH_ASSERT(ns_type != NULL);

  if (num_servers == 0)
    return TRUE;

  if (SSH_IP_IS4(&servers[0]))
    {
      ssh_snprintf(buffer, sizeof(buffer),
                   "interface ip delete %s \"%s\" all",
                   ns_type, adapter_name);

      success = ssh_execute_netsh_command(buffer);
    }
#if defined (WITH_IPV6)
  else if (SSH_IP_IS6(&servers[0]))
    {
      ssh_snprintf(buffer, sizeof(buffer),
                   "interface ipv6 delete %s \"%s\" all",
                   ns_type, adapter_name);

      success = ssh_execute_netsh_command(buffer);
    }
#endif /* WITH_IPV6 */

  return success;
}


static DWORD
ssh_net_add_name_server_worker_thread(void *context)
{
  SshCmdExecutionContext ctx = (SshCmdExecutionContext)context;
  unsigned char buffer[512];
  unsigned char name[256];
  SshUInt32 i;
  SshUInt32 ipv4_index = 1;
#if defined (WITH_IPV6)
  SshUInt32 ipv6_index = 1;
#endif /* WITH_IPV6 */
  Boolean status;

  if (!ssh_net_get_virtual_adapter_name(name, sizeof(name)))
    {
      ctx->success = FALSE;
      return ERROR_GEN_FAILURE;
    }

  for (i = 0; i < ctx->num_dns; i++)
    {
      if (SSH_IP_IS4(&ctx->dns[i]))
        {
          ssh_snprintf(buffer, sizeof(buffer),
                       "interface ip add dns \"%s\" %@ %u validate=no",
                       name, ssh_ipaddr_render, &ctx->dns[i], ipv4_index);

          status = ssh_execute_netsh_command(buffer);

          if ((status == FALSE) && (i == 0))
            {
              /* The NETSH command can fail if the DNS server address is
                 already configured for this virtual adapter. Let's remove
                 the existing server IPs and try the addition again. */
              ssh_net_remove_name_servers(name, "dns",
                                          ctx->num_dns, ctx->dns);

              status = ssh_execute_netsh_command(buffer);
            }

          if (status == FALSE)
            {
              ctx->success = FALSE;
              return ERROR_GEN_FAILURE;
            }

          ipv4_index++;
        }
#if defined (WITH_IPV6)
      else if (SSH_IP_IS6(&ctx->dns[i]))
       {
          ssh_snprintf(buffer, sizeof(buffer),
                       "interface ipv6 add dns \"%s\" %@ %u validate=no",
                       name, ssh_ipaddr_render, &ctx->dns[i], ipv6_index);

          /* It's OK for this command to fail, because the IPv6 stack is not
             necessarily installed */
          if (!ssh_execute_netsh_command(buffer))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Could not add IPv6 DNS server address: %@",
                         ssh_ipaddr_render, &ctx->dns[i]));
            }
          else
            {
              ipv6_index++;
            }
        }
#endif /* WITH_IPV6 */
    }

  for (i =0; i < ctx->num_wins; i++)
    {
      if (SSH_IP_IS4(&ctx->wins[i]))
        {
          ssh_snprintf(buffer, sizeof(buffer),
                       "interface ip add wins \"%s\" %@ %u",
                       name, ssh_ipaddr_render, &ctx->wins[i], i+1);

          status = ssh_execute_netsh_command(buffer);

          if ((status == FALSE) && (i == 0))
            {
              /* The NETSH command can fail if the WINS server address is
                 already configured for this virtual adapter. Let's remove
                 the existing server IPs and try the addition again. */
              ssh_net_remove_name_servers(name, "wins",
                                          ctx->num_wins, ctx->wins);

              status = ssh_execute_netsh_command(buffer);
            }

          if (status == FALSE)
            {
              ctx->success = FALSE;
              return ERROR_GEN_FAILURE;
            }
        }
#if defined (WITH_IPV6)
      else if (SSH_IP_IS6(&ctx->wins[i]))
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Ignoring IPv6 WINS server address: %@",
                     ssh_ipaddr_render, &ctx->wins[i]));
        }
#endif /* WITH_IPV6 */
    }

  ctx->success = TRUE;

  return ERROR_SUCCESS;
}


static DWORD
ssh_net_remove_name_server_worker_thread(void *context)
{
  SshCmdExecutionContext ctx = (SshCmdExecutionContext)context;
  Boolean success = TRUE;
  unsigned char name[256];

  if (!ssh_net_get_virtual_adapter_name(name, sizeof(name)))
    {
      ctx->success = FALSE;
      return ERROR_GEN_FAILURE;
    }

  if (ctx->num_dns)
    success = ssh_net_remove_name_servers(name, "dns",
                                          ctx->num_dns, ctx->dns);

  if (ctx->num_wins && SSH_IP_IS4(ctx->wins))
    success &= ssh_net_remove_name_servers(name, "wins",
                                           ctx->num_wins, ctx->wins);

  ctx->success = success;
  return ERROR_SUCCESS;
}


static void
ssh_net_thread_complete_cb(void *context)
{
  SshCmdExecutionContext ctx = (SshCmdExecutionContext)context;

  SSH_ASSERT(ctx != NULL);

  ssh_event_loop_unregister_handle(ctx->thread);

  CloseHandle(ctx->thread);

  if (ctx->completion_cb)
    (*ctx->completion_cb)(ctx->success, ctx->completion_ctx);

  ssh_free(ctx);
}


static void
ssh_net_add_name_server_win(SshInt32 num_dns,
                            SshIpAddr dns,
                            SshInt32 num_wins,
                            SshIpAddr wins,
                            SshPmAddNameserverCB callback,
                            void *context)
{
  SshCmdExecutionContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  ctx->num_dns = num_dns;
  ctx->dns = dns;
  ctx->num_wins = num_wins;
  ctx->wins = wins;
  ctx->completion_cb = callback;
  ctx->completion_ctx = context;

  ctx->thread =
    CreateThread(NULL, 0,
                 (LPTHREAD_START_ROUTINE)
                   ssh_net_add_name_server_worker_thread,
                 ctx, 0, NULL);

  if (ctx->thread == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to create worker thread"));

      ssh_free(ctx);

      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);
    }
  else
    {
      ssh_event_loop_register_handle(ctx->thread, FALSE,
                                     ssh_net_thread_complete_cb,
                                     ctx);
    }
}


static void
ssh_net_remove_name_server_win(SshUInt32 num_dns,
                               SshIpAddr dns,
                               SshUInt32 num_wins,
                               SshIpAddr wins,
                               SshPmRemoveNameserverCB callback,
                               void *context)
{
  SshCmdExecutionContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  ctx->num_dns = num_dns;
  ctx->dns = dns;
  ctx->num_wins = num_wins;
  ctx->wins = wins;
  ctx->completion_cb = callback;
  ctx->completion_ctx = context;

  ctx->thread =
    CreateThread(NULL, 0,
                 (LPTHREAD_START_ROUTINE)
                   ssh_net_remove_name_server_worker_thread,
                 ctx, 0, NULL);

  if (ctx->thread == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to create worker thread"));

      ssh_free(ctx);

      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);
    }
  else
    {
      ssh_event_loop_register_handle(ctx->thread, FALSE,
                                     ssh_net_thread_complete_cb,
                                     ctx);
    }
}

#endif /* WINDOWS */
#endif /* SSHDIST_PLATFORM_WIN32 */

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS

typedef struct SshPmSavedDnsConfigRec {
  struct SshPmSavedDnsConfigRec *next;
  void *context;
  RESOLV_PARAMS_S resolv_params;
} *SshPmSavedDnsConfig;

static SshPmSavedDnsConfig ssh_pm_saved_dns_config_head;

static void
ssh_net_add_name_server_vxworks(SshInt32 num_dns,
                                SshIpAddr dns,
                                SshPmAddNameserverCB callback,
                                void *context)
{
  RESOLV_PARAMS_S rp;
  SshInt32 i, n;
  Boolean success = FALSE;
  SshPmSavedDnsConfig sdc, sdc_new, sdc_prev;

  /* Get current DNS config */
  resolvParamsGet(&rp);

  /* Copy current DNS config */
  sdc_new = ssh_calloc(1, sizeof *sdc_new);
  if (sdc_new == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("out of memory saving DNS configuration"));
      goto end;
    }
  memcpy(&sdc_new->resolv_params, &rp, sizeof sdc_new->resolv_params);

  /* Connect copied DNS config with this context (i.e. VIP interface). */
  sdc_new->context = context;

  /* Add copied DNS config at the tail of saved configurations. */
  sdc_prev = NULL;
  for (sdc = ssh_pm_saved_dns_config_head; sdc; sdc = sdc->next)
    sdc_prev = sdc;
  if (sdc_prev)
    sdc_prev->next = sdc_new;
  else
    ssh_pm_saved_dns_config_head = sdc_new;

  memset(&rp.nameServersAddr, 0, sizeof rp.nameServersAddr);
  n = 0;

  for (i = 0; i < num_dns; i++)
    {
      if (n >= MAXNS)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Too many name servers, ignoring one"));
          continue;
        }

      ssh_ipaddr_print(&dns[i],
                       rp.nameServersAddr[n],
                       sizeof rp.nameServersAddr[n]);

      n++;
    }

  if (resolvParamsSet(&rp) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("resolvParamsSet failed"));
      /* Remove copied DNS configuration */
      if (sdc_prev)
        sdc_prev->next = NULL;
      else
        ssh_pm_saved_dns_config_head = NULL;
      ssh_free(sdc_new);
      goto end;
    }

  success = TRUE;

 end:
  if (callback != NULL_FNPTR)
    (*callback)(success, context);
}

static void
ssh_net_remove_name_server_vxworks(SshPmRemoveNameserverCB callback,
                                   void *context)
{
  RESOLV_PARAMS_S rp;
  Boolean success = FALSE;
  SshPmSavedDnsConfig sdc, sdc_prev;

  /* Find saved DNS config corresponding to this context */
  sdc_prev = NULL;
  for (sdc = ssh_pm_saved_dns_config_head; sdc; sdc = sdc->next)
    {
      if (sdc->context == context)
        break;
      sdc_prev = sdc;
    }
  if (!sdc)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Can't find saved DNS config to restore"));
      goto end;
    }

  /* If the saved DNS config is not the last one then the next saved
     DNS config is the one activated by this context and subsequently
     saved and overridden by another context. If this is the case,
     remove the next saved DNS config and connect this one to the
     other context. Sorry I wasn't able to say this in any
     understandable way but at least the code is simple. */
  if (sdc->next)
    {
      sdc->context = sdc->next->context;
      sdc->next = sdc->next->next;
      ssh_free(sdc->next);
      success = TRUE;
      goto end;
    }

  /* The saved DNS config is the last one: we need to restore it. Copy
     it and remove the saved DNS config entry. */
  memcpy(&rp, &sdc->resolv_params, sizeof rp);
  if (sdc_prev)
    sdc_prev->next = NULL;
  else
    ssh_pm_saved_dns_config_head = NULL;
  ssh_free(sdc);

  if (resolvParamsSet(&rp) != OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("resolvParamsSet failed"));
      goto end;
    }

  success = TRUE;

 end:
  if (callback != NULL_FNPTR)
    (*callback)(success, context);
}

#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

#define START_VIRTUAL_CONNECT_IDENT "#nameservers obtained through virtual"\
                                    " connection\n"
#define END_VIRTUAL_CONNECT_IDENT "#end of virtual connection section\n"

#if !defined(WINDOWS) && !defined(VXWORKS)
/* On Linux the contents are written to /etc/resolv.conf file. The DNS
   entries are added so as to maintain the structure of the existing
   file. Markers as comments are inserted so that these entries can be
   removed when the virtual tunnel is shutdown */

static void
ssh_net_add_name_server_unix(SshInt32 num_dns,
                             SshIpAddr dns,
                             SshPmAddNameserverCB callback,
                             void *context)
{
  unsigned char *file_content, *buffer = NULL;
  size_t content_len, buffer_len = 0;
  Boolean success = FALSE;
  int i, len;
  unsigned char one_line[80] = {0};
  unsigned char *curr_pos;

  if (!ssh_read_file_with_limit("/etc/resolv.conf", 65536,
                                &file_content, &content_len))
    { /* Maybe the file does not exist. Try to create one */
      file_content = NULL;
      content_len = 0;
    }
  buffer = ssh_calloc(1, content_len + 1024);
  if (buffer == NULL)
    goto exit_func;

  memcpy (buffer, START_VIRTUAL_CONNECT_IDENT,
                  strlen(START_VIRTUAL_CONNECT_IDENT));
  buffer_len += strlen(START_VIRTUAL_CONNECT_IDENT);

  curr_pos = buffer + buffer_len;
  for (i = 0; i < num_dns; curr_pos += len, i++)
    {
      len = ssh_snprintf(one_line, sizeof(one_line), "%s\t%@\n",
                                 "nameserver",
                                 ssh_ipaddr_render, &dns[i]);
      memcpy(curr_pos, one_line, len);
      buffer_len += len;
    }

  memcpy(buffer + buffer_len, END_VIRTUAL_CONNECT_IDENT,
                    strlen(END_VIRTUAL_CONNECT_IDENT));

  buffer_len += strlen(END_VIRTUAL_CONNECT_IDENT);

  memcpy(buffer + buffer_len, file_content, content_len);
  buffer_len += content_len;

  if (ssh_write_file("/etc/resolv.conf", buffer, buffer_len))
    success = TRUE;

exit_func:
  if (file_content)
    ssh_free(file_content);
  if (buffer)
    ssh_free(buffer);

  if (callback != NULL_FNPTR)
    (*callback)(success, context);
}

static void
ssh_net_remove_name_server_unix(SshPmRemoveNameserverCB callback,
                                void *context)
{
  unsigned char *file_content = NULL, *buffer = NULL;
  size_t content_len, buf_len;
  Boolean success = TRUE;
  unsigned char *dest;
  size_t tail_len;

  if (!ssh_read_file_with_limit("/etc/resolv.conf",65536,
                                 &file_content, &content_len))
    {
      success = FALSE;
      goto exit_func;
    }

  buffer = ssh_memdup(file_content, content_len);
  buf_len = content_len;
  if (NULL == buffer)
    {
      success = FALSE;
      goto exit_func;
    }

  memset(file_content, 0, content_len);

  dest = strstr(ssh_csstr(buffer), START_VIRTUAL_CONNECT_IDENT);
  if (NULL == dest)
    goto exit_func;

  content_len = (size_t)(dest - buffer);
  memcpy(file_content, buffer, content_len);

  dest = strstr(ssh_csstr(buffer), END_VIRTUAL_CONNECT_IDENT);

  if (NULL == dest)
    {
      success = FALSE;
      goto exit_func;
    }

  tail_len = buf_len - ((size_t)(dest - buffer) +
                       strlen(END_VIRTUAL_CONNECT_IDENT));

  memcpy( file_content + content_len, dest + strlen(END_VIRTUAL_CONNECT_IDENT),
            tail_len);
  content_len += tail_len;

  if (!ssh_write_file("/etc/resolv.conf", file_content, content_len))
    success = FALSE;

exit_func:
  if (file_content)
    ssh_free(file_content);
  if (buffer)
    ssh_free(buffer);

  if (callback != NULL_FNPTR)
    (*callback)(success, context);
}
#endif /* !defined(WINDOWS) && !defined(VXWORKS) */

void
ssh_pm_add_name_servers(SshInt32 num_dns,
                        SshIpAddr dns,
                        SshInt32 num_wins,
                        SshIpAddr wins,
                        SshPmAddNameserverCB callback,
                        void *context)
{
#ifdef SSHDIST_UTIL_DNS_RESOLVER
  SshDNSResolver resolver;
  int i;

  resolver = ssh_name_server_resolver();
  if (resolver != NULL)
    {
      for (i = 0; i < num_dns; i++)
        ssh_dns_resolver_safety_belt_add(resolver, 1, &(dns[i]));
    }
#endif /* SSHDIST_UTIL_DNS_RESOLVER */

#ifdef SSHDIST_PLATFORM_WIN32
#if defined(WINDOWS) && !defined(VXWORKS)
  ssh_net_add_name_server_win(num_dns, dns,
                              num_wins, wins,
                              callback, context);
#endif /* defined(WINDOWS) && !defined(VXWORKS) */
#endif  /* SSHDIST_PLATFORM_WIN32 */

#ifdef SSHDIST_PLATFORM_VXWORKS
#if !defined(WINDOWS) && defined(VXWORKS)
  ssh_net_add_name_server_vxworks(num_dns, dns, callback, context);
#endif /* defined(WINDOWS) && !defined(VXWORKS) */
#endif  /* SSHDIST_PLATFORM_VXWORKS */

#if !defined(WINDOWS) && !defined(VXWORKS)
  ssh_net_add_name_server_unix(num_dns, dns,
                               callback, context);
#endif /* !defined(WINDOWS) && !defined(VXWORKS) */
}

void
ssh_pm_remove_name_servers(SshInt32 num_dns,
                           SshIpAddr dns,
                           SshInt32 num_wins,
                           SshIpAddr wins,
                           SshPmRemoveNameserverCB callback,
                           void *context)
{
#ifdef SSHDIST_PLATFORM_WIN32
#if defined(WINDOWS) && !defined(VXWORKS)
  ssh_net_remove_name_server_win(num_dns, dns,
                                 num_wins, wins,
                                 callback, context);
#endif /* defined(WINDOWS) && !defined(VXWORKS) */
#endif  /* SSHDIST_PLATFORM_WIN32 */

#ifdef SSHDIST_PLATFORM_VXWORKS
#if !defined(WINDOWS) && defined(VXWORKS)
  ssh_net_remove_name_server_vxworks(callback, context);
#endif /* defined(WINDOWS) && !defined(VXWORKS) */
#endif  /* SSHDIST_PLATFORM_VXWORKS */

#if !defined(WINDOWS) && !defined(VXWORKS)
  ssh_net_remove_name_server_unix(callback, context);
#endif /* !defined(WINDOWS) && !defined(VXWORKS) */
}
