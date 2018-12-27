/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Driver type (NDIS intermediate driver vs. NDIS filter driver) independent
   (internal) interceptor functions.
*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "event.h"
#include "registry.h"
#include "kernel_timeouts.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#define SSH_DEBUG_MODULE "SshInterceptorAdapterCommon"

static void
ssh_adapter_attach_complete(Boolean status,
                            void *context);

static void
ssh_adapter_detach_complete(void *context);

static void
ssh_adapter_pause_complete(void *context);

static void
ssh_adapter_restart_complete(Boolean status,
                             void *context);


#ifdef DEBUG_LIGHT

const unsigned char *
ssh_adapter_state_str_get(SshAdapterState state)
{
  switch (state)
    {
    case SSH_ADAPTER_STATE_DETACHED:
      return (const unsigned char *)"DETACHED";

    case SSH_ADAPTER_STATE_ATTACHING:
      return (const unsigned char *)"ATTACHING";

    case SSH_ADAPTER_STATE_PAUSED:
      return (const unsigned char *)"PAUSED";

    case SSH_ADAPTER_STATE_RESTARTING:
      return (const unsigned char *)"RESTARTING";

    case SSH_ADAPTER_STATE_RUNNING:
      return (const unsigned char *)"RUNNING";

    case SSH_ADAPTER_STATE_PAUSING:
      return (const unsigned char *)"PAUSING";

    default:
      SSH_NOTREACHED;
      return (const unsigned char *)"<Invalid state>";
    }
}


/* Render function to render adapter identifier (interceptor generated name
   and ifnum) and adapter state for %@ format string for ssh_e*printf */
int 
ssh_adapter_id_st_render(unsigned char *buf, 
                         int buf_size, 
                         int precision,
                         void *datum)
{
  SshAdapter adapter = (SshAdapter)datum;
  const unsigned char *state_str;
  int len;

  state_str = ssh_adapter_state_str_get(adapter->state);

  if (adapter->ssh_name[0])
    ssh_snprintf(buf, buf_size + 1, "'%s' (%u) [%s]", 
                 adapter->ssh_name, adapter->ifnum, state_str);
  else
    ssh_snprintf(buf, buf_size + 1, "0x%p <uninitialized> [%s]",
                 adapter, state_str);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

#endif /* DEBUG_LIGHT */

__forceinline void
ssh_adapter_state_transition(SshAdapter adapter,
                             SshAdapterState from_state,
                             SshAdapterState to_state)
{
  SshAdapterState old_state;

  SSH_ASSERT(sizeof(adapter->state) == sizeof(to_state));

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@ entering state: %s...",
             ssh_adapter_id_st_render, adapter,
             ssh_adapter_state_str_get(to_state)));

  old_state = InterlockedExchange((LONG *)&adapter->state, 
                                  (LONG)to_state);

  if (old_state != from_state)
    {
      if (to_state == SSH_ADAPTER_STATE_RESTARTING)
        {







          SSH_DEBUG(SSH_D_ERROR, 
                    ("Adapter %@: Invalid state transition! (%s -> %s)",
                    ssh_adapter_id_st_render, adapter,
                    ssh_adapter_state_str_get(old_state),
                    ssh_adapter_state_str_get(to_state)));
        }
      else
        {
          SSH_ASSERT(old_state == from_state);
        }
    }

  InterlockedExchange((LONG *)&adapter->enable_flags.all_flags,
                      adapter->state_flags[to_state].all_flags);
}


Boolean
ssh_adapter_init_common(SshAdapter adapter,
                        SshInterceptor interceptor,
                        SshAdapterInitParams init_params)
{
  unsigned int i;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(adapter->state == SSH_ADAPTER_STATE_DETACHED);
  SSH_ASSERT(init_params != NULL);
  SSH_ASSERT(init_params->name != NULL);
  SSH_ASSERT(init_params->name_len > 0);

  /* Init attributes */
  adapter->result = NDIS_STATUS_SUCCESS;
  adapter->interceptor = interceptor;
  adapter->handle = NULL;
  adapter->config_handle = NULL;
  adapter->media_connected = 1;
  adapter->guid = init_params->guid;

  adapter->orig_name.Length = 
    (USHORT)(SSH_ADAPTER_DEV_NAME_PREFIX_SIZE + init_params->name_len);
  adapter->orig_name.MaximumLength = 
    adapter->orig_name.Length + sizeof(WCHAR);
  adapter->orig_name.Buffer = ssh_calloc(1, adapter->orig_name.MaximumLength);
  if (adapter->orig_name.Buffer == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to initialize adapter object!")); 
      return FALSE;
    }
  NdisMoveMemory(adapter->orig_name.Buffer, 
                 SSH_ADAPTER_DEV_NAME_PREFIX,
                 SSH_ADAPTER_DEV_NAME_PREFIX_SIZE);
  NdisMoveMemory(((unsigned char *)adapter->orig_name.Buffer + 
                   SSH_ADAPTER_DEV_NAME_PREFIX_SIZE),
                 init_params->name, 
                 init_params->name_len);

  RtlZeroMemory(adapter->media_addr, sizeof(adapter->media_addr));
  adapter->media_addr_len = 6;

  for (i = 0; i < SSH_NUM_ADAPTER_STATES; i++)
    adapter->state_flags[i] = init_params->feature_flags[i];
  adapter->state = SSH_ADAPTER_STATE_DETACHED;
  adapter->enable_flags = adapter->state_flags[adapter->state];
  adapter->standing_by = 0;
  adapter->power_mgmt_disabled = 0;
  adapter->options = 0L;
  adapter->lookahead_size = 256; /* Default */

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Initialize WAN interface information */
  if (!ssh_kernel_rw_mutex_init(&adapter->wan_if_lock))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to initialize WAN interface lock!")); 
      ssh_free(adapter);
      return FALSE;
    }
  NdisInitializeListHead(&adapter->wan_if);
  adapter->wan_if_cnt = 0L;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Create event object */
  if ((adapter->wait_event = ssh_event_create(0, NULL, NULL)) == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to create event!")); 
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      ssh_kernel_rw_mutex_uninit(&adapter->wan_if_lock);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
      ssh_free(adapter);
      return FALSE;
    }

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  adapter->va = NULL;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */ 

  /* No state transition yet! */
  SSH_ASSERT(adapter->state == SSH_ADAPTER_STATE_DETACHED);

  return TRUE;
}


Boolean 
ssh_adapter_attach_common(SshAdapter adapter,
                          SshAdapterAttachFn attach_fn,
                          void *attach_fn_context)
{
  SshInterceptor interceptor;
  SshInterceptorIfnum i;
#ifdef HAS_INTERFACE_NAME_MAPPINGS 
  SshTime smallest_ts;
  SshInterceptorIfnum smallest_ts_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  SshIfNameMapping if_map;
#endif /* HAS_INTERFACE_NAME_MAPPINGS */
  NDIS_STRING ndis_name;
  ANSI_STRING ansi_name;
  WCHAR name_prefix_buf[] = L"\\Device\\";
  USHORT name_prefix_len =
    sizeof name_prefix_buf / sizeof name_prefix_buf[0] - 1;
  SshRegKey network_adapters, instance, connection;
  NDIS_STRING name_value;

  SSH_ASSERT(adapter != NULL);
  interceptor = adapter->interceptor;
  SSH_ASSERT(interceptor != NULL);

  InterlockedIncrement(&adapter->state_transition_pending);

  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_DETACHED,
                               SSH_ADAPTER_STATE_ATTACHING);

  SSH_ASSERT(SSH_INTERCEPTOR_MAX_ADAPTERS <= SSH_INTERCEPTOR_INVALID_IFNUM);

#ifdef HAS_INTERFACE_NAME_MAPPINGS
  ssh_interceptor_get_time(&smallest_ts, NULL);

  /* Check whether we already know this adapter (i.e. whether we have
     a static name mapping for this adapter) */
  ssh_kernel_rw_mutex_lock_read(&interceptor->if_map_lock);
  for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
    {
      Boolean match = FALSE;

      if_map = interceptor->if_map[i];

      if (if_map == NULL)
        continue;

      switch (if_map->type)
        {
        case SSH_IF_NAME_MAPPING_TYPE_GUID:
          if (memcmp(&adapter->guid, &if_map->u.guid, sizeof(GUID)) == 0) 
            match = TRUE;
          break;

        case SSH_IF_NAME_MAPPING_TYPE_DEVICE:
          /* NOTE! We can not use RtlCompareUnicodeString() at raised IRQL */
          if ((adapter->orig_name.Length == if_map->u.device.Length)
              && (memcmp(adapter->orig_name.Buffer, 
                         if_map->u.device.Buffer, 
                         adapter->orig_name.Length) == 0))
            match = TRUE;
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      if (match)
        {
          /* We found a static mapping for this adapter */
          adapter->ifnum = i;
          SSH_ASSERT(adapter->ifnum == if_map->ifnum);
          SSH_ASSERT(sizeof(adapter->ssh_name) == sizeof(if_map->alias));
          memcpy(adapter->ssh_name, if_map->alias, sizeof(adapter->ssh_name));

          ssh_kernel_rw_mutex_lock_write(&interceptor->adapter_lock);
          goto add_and_continue;
        }
    }
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  /* Insert adapter into global adapter list and table */
  i = 0;
  ssh_kernel_rw_mutex_lock_write(&interceptor->adapter_lock);
#ifdef HAS_INTERFACE_NAME_MAPPINGS
  while (i < SSH_INTERCEPTOR_MAX_ADAPTERS)
    {
      if_map = interceptor->if_map[i];

      if ((interceptor->adapter_table[i] == NULL) && (if_map == NULL))
        {
          if_map = ssh_calloc(1, sizeof(*if_map));
          if (if_map)
            {
              adapter->ifnum = i;
              if_map->tentative = 1;
              interceptor->if_map[i] = if_map;
              goto add_and_continue;
            }
          else
            {
              goto failed;
            }
        }
      else if ((interceptor->if_map[i] != NULL)
               && (smallest_ts > interceptor->if_map[i]->timestamp))
        {
          smallest_ts = interceptor->if_map[i]->timestamp;
          smallest_ts_ifnum = i;  
        }

      i++;
    }
  
  if (smallest_ts_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    goto failed;

  /* Re-use the eldest name mapping entry */
  i = smallest_ts_ifnum;

 add_and_continue:
#else
  while (i < SSH_INTERCEPTOR_MAX_ADAPTERS)
    {
      if (interceptor->adapter_table[i] == NULL)
        {
          adapter->ifnum = i;
          break;
        }
      i++;
    }
#endif /* HAS_INTERFACE_NAME_MAPPINGS */
  SSH_ASSERT(interceptor->adapter_table[i] == NULL);

  InitializeListHead(&adapter->link);
  InsertTailList(&interceptor->adapter_list, &adapter->link);
  interceptor->adapter_table[i] = adapter;
  interceptor->adapter_cnt++; 
  ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock); 
#ifdef HAS_INTERFACE_NAME_MAPPINGS 
  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_map_lock);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  if (attach_fn)
    {
      (*attach_fn)(adapter, attach_fn_context,
                   ssh_adapter_attach_complete, adapter);
    }
  else
    {
      ssh_adapter_attach_complete(TRUE, adapter);
    }

  if (adapter->state == SSH_ADAPTER_STATE_DETACHED)
    return FALSE;

  /* Get the NDIS name of the adapter, i.e. NetCfgInstanceId (or
     something else) prefixed with '\Device\'. */
  ndis_name = adapter->orig_name;

  /* Remove the '\Device\' prefix. */
  if (ndis_name.Length >= name_prefix_len &&
      NdisEqualMemory(ndis_name.Buffer, name_prefix_buf, name_prefix_len))
    {
      ndis_name.Buffer += name_prefix_len;
      ndis_name.MaximumLength -= name_prefix_len * sizeof (WCHAR);
      ndis_name.Length -= name_prefix_len * sizeof (WCHAR);
    }

  /* Init registry value buffer to be allocated dynamically below. */
  NdisZeroMemory(&name_value, sizeof name_value);

  /* Convert NetCfgInstanceId into connection name. If that fails, use
     the NDIS name without the '\Device\' prefix. */
  network_adapters = NULL;
  instance = NULL;
  connection = NULL;
  if ((network_adapters = ssh_registry_key_open(
         HKEY_LOCAL_MACHINE, NULL,
         L"SYSTEM\\CurrentControlSet\\Control\\Network\\"
         L"{4D36E972-E325-11CE-BFC1-08002BE10318}")) &&
      (instance = ssh_registry_key_open_unicode(
         network_adapters, NULL, &ndis_name)) &&
      (connection = ssh_registry_key_open(
         instance, NULL, L"Connection")) &&
      ssh_registry_unicode_string_get(
        connection,
        L"Name",
        &name_value))
    {
      ndis_name = name_value;
    }

  if (connection)
    ssh_registry_key_close(connection);
  if (instance)
    ssh_registry_key_close(instance);
  if (network_adapters)
    ssh_registry_key_close(network_adapters);

  /* Convert UNICODE name to ANSI. If the conversion fails, be happy
     with an empty or truncated name. */
  ansi_name.Buffer = adapter->friendly_name;
  ansi_name.MaximumLength = sizeof adapter->friendly_name - 1;
  ansi_name.Length = 0;
  if (NdisUnicodeStringToAnsiString(&ansi_name, &ndis_name) !=
      NDIS_STATUS_SUCCESS)
    SSH_DEBUG(SSH_D_FAIL, ("Failed convert adapter name to ASCII"));
  ansi_name.Buffer[ansi_name.Length] = '\0';

   /* Free registry value buffer. */
   if (name_value.Buffer)
     ssh_free(name_value.Buffer);

  return TRUE;

#ifdef HAS_INTERFACE_NAME_MAPPINGS 
 failed:
#endif /* HAS_INTERFACE_NAME_MAPPINGS */
  ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);
#ifdef HAS_INTERFACE_NAME_MAPPINGS 
  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_map_lock);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                SSH_LOG_CRITICAL,
                ("Failed to attach adapter %s!",
                 (const char *)adapter->ssh_name));

  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_ATTACHING,
                               SSH_ADAPTER_STATE_DETACHED);

  InterlockedDecrement(&adapter->state_transition_pending);

  return FALSE;
}

void
ssh_adapter_detach_common(SshAdapter adapter,
                          SshAdapterDetachFn detach_fn,
                          void *detach_fn_context)
{
  SshInterceptor interceptor;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  interceptor = adapter->interceptor;

  ssh_adapter_wait_until_state_transition_complete(adapter);

  SSH_ASSERT(adapter->state == SSH_ADAPTER_STATE_PAUSED);

  InterlockedIncrement(&adapter->state_transition_pending);

#ifdef HAS_INTERFACE_NAME_MAPPINGS 
  /* Remove the name mapping if the 'tentative' flag is set */
  SSH_ASSERT(interceptor->if_map[adapter->ifnum] != NULL);
  ssh_kernel_rw_mutex_lock_write(&interceptor->if_map_lock);
  if (interceptor->if_map[adapter->ifnum]->tentative)
    {
      SshIfNameMapping if_map;
      
      if_map = interceptor->if_map[adapter->ifnum];
      interceptor->if_map[adapter->ifnum] = NULL;
      ssh_kernel_rw_mutex_unlock_write(&interceptor->if_map_lock);
  
      ssh_interceptor_free_interface_mapping(interceptor, if_map);
    }
  else
    {
      ssh_kernel_rw_mutex_unlock_write(&interceptor->if_map_lock);
    }
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  /* Remove adapter from global adapter list and table */
  ssh_kernel_rw_mutex_lock_write(&interceptor->adapter_lock);
  interceptor->adapter_table[adapter->ifnum] = NULL;
  RemoveEntryList(&adapter->link);
  interceptor->adapter_cnt--;
  ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);

  /* 'state_transition_pending' will be decremented in 
     ssh_adapter_detach_complete. */
  if (detach_fn)
    (*detach_fn)(adapter, detach_fn_context,
                 ssh_adapter_detach_complete, adapter);
  else
    ssh_adapter_detach_complete(adapter);
}


void
ssh_adapter_uninit_common(SshAdapter adapter)
{
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  SSH_ASSERT(adapter->state == SSH_ADAPTER_STATE_DETACHED);

  /* Free memory allocated for strings */
  if (adapter->orig_name.Buffer != NULL)
    {
      ssh_free(adapter->orig_name.Buffer);
      adapter->orig_name.Buffer = NULL;
    }

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Free spin locks */
  ssh_kernel_rw_mutex_uninit(&adapter->wan_if_lock);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Close event */
  ssh_event_destroy(adapter->wait_event);
}


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC

#pragma warning(push)
#pragma warning(disable : 4100)
static void 
ssh_va_operation_complete(SshVirtualAdapterError error,
                          SshInterceptorIfnum adapter_ifnum,
                          const unsigned char *adapter_name,
                          SshVirtualAdapterState adapter_state,
                          void *adapter_context,
                          void *context)
{
  SshEvent wait_complete = (SshEvent)context;

  ssh_event_signal(wait_complete);
}
#pragma warning(pop)

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


#ifndef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#pragma warning(push)
#pragma warning(disable : 4100)
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
void
ssh_adapter_pause_common(SshAdapter adapter,
                         SshAdapterPauseReason reason,
                         SshAdapterPauseFn pause_fn,
                         void *pause_fn_context)
{
  SshInterceptor interceptor;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  SshEvent wait_event;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  ssh_adapter_wait_until_state_transition_complete(adapter);

  InterlockedIncrement(&adapter->state_transition_pending);
  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_RUNNING,
                               SSH_ADAPTER_STATE_PAUSING);

  SSH_ASSERT(adapter->interceptor != NULL);
  interceptor = adapter->interceptor;

  adapter->pause_fn = pause_fn;

  switch (reason)
    {
    case SSH_ADAPTER_PAUSE_REASON_BIND_IPV4:
    case SSH_ADAPTER_PAUSE_REASON_BIND_IPV6:
    case SSH_ADAPTER_PAUSE_REASON_BIND_PROTOCOL:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ pausing (BIND_PROTOCOL)...",
                 ssh_adapter_id_st_render, adapter));
      break;

    case SSH_ADAPTER_PAUSE_REASON_UNBIND_IPV4:
    case SSH_ADAPTER_PAUSE_REASON_UNBIND_IPV6:
    case SSH_ADAPTER_PAUSE_REASON_UNBIND_PROTOCOL:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ pausing (UNBIND_PROTOCOL)...",
                 ssh_adapter_id_st_render, adapter));
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
      if (adapter->is_vnic && adapter->va)
        {
          wait_event = ssh_event_create(0, NULL, NULL);
          if (wait_event)
            {
              ssh_virtual_adapter_configure(adapter->interceptor, 
                                            adapter->ifnum, 
                                            SSH_VIRTUAL_ADAPTER_STATE_DOWN,
                                            0, NULL, NULL, 
                                            ssh_va_operation_complete,
                                            wait_event);

              ssh_event_wait(1, &wait_event, NULL);
              ssh_event_destroy(wait_event);
            }
        }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
      break;

    case SSH_ADAPTER_PAUSE_REASON_DETACH_INTERCEPTOR:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ pausing (DETACH_INTERCEPTOR)...",
                 ssh_adapter_id_st_render, adapter));
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
      if (adapter->is_vnic && adapter->va)
        {
          wait_event = ssh_event_create(0, NULL, NULL);
          if (wait_event)
            {
              adapter->va->flags |= SSH_VIRTUAL_ADAPTER_FLAG_DEREGISTER;

              ssh_virtual_adapter_detach(adapter->interceptor,
                                         adapter->ifnum,
                                         ssh_va_operation_complete,
                                         wait_event);

              ssh_event_wait(1, &wait_event, NULL);
              ssh_event_destroy(wait_event);
            }
        }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
      break;

    case SSH_ADAPTER_PAUSE_REASON_LOW_POWER:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ pausing (LOW_POWER)...",
                 ssh_adapter_id_st_render, adapter));
      break;

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@ pausing (reason = 0x%X)...",
                 ssh_adapter_id_st_render, adapter, reason));
      break;
    }

  /* 'state_transition_pending' will be decremented in
     ssh_adapter_pause_complete. */
  if (pause_fn)
    {
      ssh_interceptor_suspend_worker_threads(adapter->interceptor);
      (*pause_fn)(adapter, pause_fn_context,
                  ssh_adapter_pause_complete, adapter);
    }
  else
    {
      ssh_adapter_pause_complete(adapter);
    }
}
#ifndef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#pragma warning(pop)
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

Boolean
ssh_adapter_restart_common(SshAdapter adapter,
                           SshAdapterRestartFn restart_fn,
                           void *restart_fn_context)
{
  Boolean status = TRUE;

  SSH_ASSERT(adapter != NULL);

  ssh_adapter_wait_until_state_transition_complete(adapter);

  InterlockedIncrement(&adapter->state_transition_pending);

  adapter->restart_fn = restart_fn;

  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_PAUSED,
                               SSH_ADAPTER_STATE_RESTARTING);

  /* 'state_transition_pending' will be decremented in
     ssh_adapter_restart_complete. */
  if (restart_fn)
    {
      ssh_interceptor_suspend_worker_threads(adapter->interceptor);
      (*restart_fn)(adapter, restart_fn_context,
                    ssh_adapter_restart_complete, adapter);
    }
  else
    {
      ssh_adapter_restart_complete(TRUE, adapter);
    }

  return status;
}


static void
ssh_adapter_pause_delay(void *context)
{
  SshAdapter adapter = (SshAdapter)context;
  SshInterceptor interceptor = adapter->interceptor;

  InterlockedDecrement(&adapter->ref_count);
  InterlockedDecrement(&interceptor->ref_count);

  if (adapter->standing_by)
    ssh_interceptor_suspend_if_idle(interceptor);

  if (adapter->pause_fn)
    ssh_interceptor_resume_worker_threads(interceptor);

  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_PAUSING,
                               SSH_ADAPTER_STATE_PAUSED);

  InterlockedDecrement(&adapter->state_transition_pending);
}


static void
ssh_adapter_attach_complete(Boolean status,
                            void *context)
{
  SshAdapter adapter = (SshAdapter)context;

  /* Set INSIDE Secure specific name for the adapter (if not already set
     in interceptor specific code. */
  if (adapter->ssh_name[0] == 0)
    {
      unsigned char *prefix = NULL;

      switch (adapter->media)
        {
        case NdisMediumWan:
        case NdisMediumCoWan:
          prefix = "wan";
          break;

        case NdisMedium802_3:
          prefix = "lan";
          break;

        case NdisMediumWirelessWan:
          prefix = "wwan";
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      ssh_snprintf(adapter->ssh_name, sizeof(adapter->ssh_name), 
                   "%s%d", prefix, adapter->ifnum); 
    }

  if (status != FALSE)
    {
#ifdef HAS_INTERFACE_NAME_MAPPINGS 
      ssh_interceptor_add_interface_mapping(adapter->interceptor, adapter);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

    }

  ssh_adapter_state_transition(adapter,
                               SSH_ADAPTER_STATE_ATTACHING,
                               SSH_ADAPTER_STATE_PAUSED);
  InterlockedDecrement(&adapter->state_transition_pending);

  if (status == FALSE)
    ssh_adapter_detach_common(adapter, NULL_FNPTR, NULL);
}


static void
ssh_adapter_detach_complete(void *context)
{
  SshAdapter adapter = (SshAdapter)context;
  SshUInt32 tick_count = 20; /* about 2 second timeout */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  SshInterceptor interceptor;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->state == SSH_ADAPTER_STATE_PAUSED);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  SSH_ASSERT(adapter->interceptor != NULL);
  interceptor = adapter->interceptor;
  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  if ((adapter->is_vnic) && (adapter->va))
    {
      void *va = adapter->va;

      adapter->va = NULL;
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

      ssh_virtual_adapter_deregister(va);
    }
  else
    {
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock); 
    }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Wait until all possibly still pending adapter specific timeout
     operations have completed. Assert in debug build if operations 
     haven't completed in a reasonable amount of time */
  while (tick_count
         && InterlockedCompareExchange(&adapter->ref_count, 0, 0))
    {
      NdisMSleep(100000);
      tick_count--;
    }

  SSH_ASSERT(tick_count != 0);

  ssh_adapter_state_transition(adapter,
                               adapter->state,
                               SSH_ADAPTER_STATE_DETACHED);

  InterlockedDecrement(&adapter->state_transition_pending);
}


static void
ssh_adapter_pause_complete(void *context)
{
  SshAdapter adapter = (SshAdapter)context;
  SshInterceptor interceptor;
  SshUInt32 tick_count = 600; /* about one minute timeout */

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  interceptor = adapter->interceptor;

  /* Wait until all pending operations have completed. Assert in
     debug build if operations haven't completed in a reasonable 
     amount of time */
  while (tick_count
         && InterlockedCompareExchange(&adapter->ref_count, 0, 0))
    {
      NdisMSleep(100000);
      tick_count--;
    }

  SSH_ASSERT(tick_count != 0);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Refresh IP interface and routing information */
  SSH_IP_REFRESH_REQUEST(adapter->interceptor);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  InterlockedIncrement(&interceptor->ref_count);
  InterlockedIncrement(&adapter->ref_count);
#if (!defined(SSH_IPSEC_IP_ONLY_INTERCEPTOR))
#if !defined(NDIS630)
  if (interceptor->entering_low_power_state == FALSE)
    {
      ssh_kernel_timeout_register(1, 0, 
                                  ssh_adapter_pause_delay,
                                  adapter);
    }
  else
#endif /* !NDIS630 */
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    {
      ssh_adapter_pause_delay(adapter);
    }
}


static void
ssh_adapter_restart_delay(void *context)
{
  SshAdapter adapter = (SshAdapter)context;
  SshInterceptor interceptor = adapter->interceptor;

  InterlockedDecrement(&adapter->ref_count);
  InterlockedDecrement(&interceptor->ref_count);

  if (adapter->restart_fn)
    ssh_interceptor_resume_worker_threads(interceptor);

  ssh_adapter_state_transition(adapter,
                               adapter->state,
                               SSH_ADAPTER_STATE_RUNNING);

  InterlockedDecrement(&adapter->state_transition_pending);
}


static void
ssh_adapter_restart_complete(Boolean status,
                             void *context)
{
  SshAdapter adapter = (SshAdapter)context;
  SshInterceptor interceptor;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  interceptor = adapter->interceptor;

  if (status == FALSE)
    {
      adapter->state = SSH_ADAPTER_STATE_PAUSED;
      InterlockedDecrement(&adapter->state_transition_pending);
    }
  else
    {
      ssh_interceptor_resume(interceptor);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      /* Refresh IP interface and routing information */
      SSH_IP_FORCE_REFRESH_REQUEST(adapter->interceptor,
                                   (SSH_IP_REFRESH_INTERFACES 
                                    | SSH_IP_REFRESH_REPORT));
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

      InterlockedIncrement(&interceptor->ref_count);
      InterlockedIncrement(&adapter->ref_count);
#if (!defined(SSH_IPSEC_IP_ONLY_INTERCEPTOR))
#if !defined(NDIS630)
      if (interceptor->entering_low_power_state == FALSE)
        {
          ssh_kernel_timeout_register(0, 200000, 
                                      ssh_adapter_restart_delay,
                                      adapter);
        }
      else
#endif /* !NDIS630 */
#endif /* !SSH_IP_ONLY_INTERCEPTOR */
        {
          ssh_adapter_restart_delay(adapter);
        }
    }
}

void
ssh_adapter_wait_until_state_transition_complete(SshAdapter adapter)
{
  SshUInt32 ticks_left = 2000UL;  

  SSH_ASSERT(adapter != NULL);

  while ((ticks_left > 0) && 
         (InterlockedCompareExchange(&adapter->state_transition_pending,
                                     0, 0) != 0))
    {
      if (SSH_GET_IRQL() >= SSH_DISPATCH_LEVEL)
	{
	  NdisStallExecution(20);
	}
      else
	{
	  NdisMSleep(1000);
	}

      ticks_left--;
    }

  SSH_ASSERT(ticks_left > 0); 
}


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC

/*--------------------------------------------------------------------------
  ssh_adapter_device_object_name_get()
  
  Returns the name of device object where we are bound to.
  
  Arguments:
  adapter - adapter object
  name - pointer into Unicode string where the name is copied
  
  Returns:
  TRUE - success, FALSE - otherwise
  
  Notes:
  This function is called when registering SSH Virtual Adapter
  --------------------------------------------------------------------------*/
Boolean
ssh_adapter_device_object_name_get(SshAdapter adapter, 
                                   PNDIS_STRING name)
{
  NDIS_STRING dev_guid;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(name != NULL);

  /* Note: We cannot copy the original name as such because it might
     contain the device name prefix ("Device") as upper-case and this
     does not work when trying to add the reference count of SSH
     Virtual Adapter */

  /* GUID = "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} */
  NdisInitUnicodeString(&dev_guid, 
                        adapter->orig_name.Buffer +
                        SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET);

  /* Allocate memory for name buffer */
  if (name->Buffer)
    ssh_free(name->Buffer);

  name->Length = SSH_DEVICE_OBJ_NAME_PREFIX_SIZE + dev_guid.Length;
  name->MaximumLength = name->Length + sizeof(WCHAR);
  name->Buffer = ssh_calloc(1, name->MaximumLength);
  if (!name->Buffer)
    return (FALSE);

  NdisMoveMemory(name->Buffer, 
                 SSH_DEVICE_OBJ_NAME_PREFIX,
                 SSH_DEVICE_OBJ_NAME_PREFIX_SIZE);
  NdisMoveMemory(((unsigned char *)name->Buffer 
                   + SSH_DEVICE_OBJ_NAME_PREFIX_SIZE),
                 (adapter->orig_name.Buffer 
                   + SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET),
                 (adapter->orig_name.Length
                   - SSH_ADAPTER_DEV_NAME_PREFIX_SIZE));

  return (TRUE);
}

static SshRegKey
ssh_adapter_open_tcpip_config(SshAdapter adapter)
{
  SshRegKey adapter_key = NULL;
  UNICODE_STRING adapter_name;
  SshRegKey tcp_if_key;
  SshUInt16 offset;

  /* Open TCP/IP interfaces key */
  tcp_if_key = 
    ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL,
      L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");
  
  if (tcp_if_key == NULL)
    return NULL;

  /* "Remove" the "\DEVICE\" prefix (if exists) from Adapter->orig_name. */
  offset = SSH_ADAPTER_DEV_NAME_PREFIX_SIZE; 
  adapter_name.Buffer = 
    (WCHAR *)(((char *)adapter->orig_name.Buffer) + offset);
  adapter_name.Length = adapter->orig_name.Length - offset;
  adapter_name.MaximumLength = adapter->orig_name.MaximumLength - offset;

  adapter_key = ssh_registry_key_open_unicode(tcp_if_key, NULL, 
                                              &adapter_name);

  ssh_registry_key_close(tcp_if_key);

  return (adapter_key);
}

Boolean
ssh_adapter_set_ip_config(SshAdapter adapter,
                          SshIpAddr addrs,
                          SshUInt16 num_addrs)
{
  SshIpAddrStruct zero_ip;
  SshRegKey config_key;
  NDIS_STRING ip_multi_str;
  NDIS_STRING mask_multi_str;
  SshUInt16 size;
  SshUInt16 i;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT((addrs != NULL) || (num_addrs == 0));

  config_key = ssh_adapter_open_tcpip_config(adapter);
  if (config_key == NULL)
    return FALSE;

  if (num_addrs == 0)
    {
      SshUInt32 zero_num = 0;

      SSH_IP4_MASK_DECODE(&zero_ip, &zero_num, 0);

      addrs = &zero_ip;
      num_addrs = 1;
    }

  /* Calculate the maximum size the IP address and sub-net multi-strings 
     containing specified amount of IPv4 addresses could need. */
  size = (num_addrs * 16 * sizeof(WCHAR)) + sizeof(UNICODE_NULL); 

  ip_multi_str.Buffer = ssh_calloc(1, size);
  if (ip_multi_str.Buffer == NULL)
    return FALSE;

  mask_multi_str.Buffer = ssh_calloc(1, size);
  if (mask_multi_str.Buffer == NULL)
    {
      ssh_free(ip_multi_str.Buffer);
      return FALSE;
    }

  ip_multi_str.Length = 0;
  ip_multi_str.MaximumLength = size;
  mask_multi_str.Length = 0;
  mask_multi_str.MaximumLength = size;

  for (i = 0; i < num_addrs; i++, addrs++)
    {
      NDIS_STRING uc_str;
      ANSI_STRING ansi_str;
      SshIpAddr ip = addrs;
      char addr_str[64];
      unsigned long mask;
      char netmask[4];
      SshIpAddrStruct mask_ip;

      /* Only IPv4 is supported by this function! */
      if (SSH_IP_IS6(ip))
        continue;

      SSH_ASSERT(SSH_IP_IS4(ip));

      /* Add the IP address */
      ssh_ipaddr_print(ip, (unsigned char *)addr_str, sizeof(addr_str));
      NdisInitAnsiString(&ansi_str, addr_str);

      uc_str = ip_multi_str;
      uc_str.Buffer = 
        (void *)(((char *)ip_multi_str.Buffer) + ip_multi_str.Length);
      uc_str.Length = 0;
      uc_str.MaximumLength -= ip_multi_str.Length;

      if (NdisAnsiStringToUnicodeString(&uc_str, 
                                        &ansi_str) != NDIS_STATUS_SUCCESS)
        goto failed;
     
      ip_multi_str.Length += uc_str.Length + sizeof(UNICODE_NULL);
      
      SSH_ASSERT(ip_multi_str.Length <= ip_multi_str.MaximumLength);

      /* Add the subnet mask */
      if (ip->mask_len >= sizeof mask * 8)
        mask = ~0U;
      else
        mask = ~(~0U >> ip->mask_len);
      SSH_PUT_32BIT(netmask, mask);

      SSH_IP4_DECODE(&mask_ip, netmask);

      ssh_ipaddr_print(&mask_ip, (unsigned char *)addr_str, sizeof(addr_str));
      NdisInitAnsiString(&ansi_str, addr_str);

      uc_str = mask_multi_str;
      uc_str.Buffer = 
        (void *)(((char *)mask_multi_str.Buffer) + mask_multi_str.Length);
      uc_str.Length = 0;
      uc_str.MaximumLength -= mask_multi_str.Length;

      if (NdisAnsiStringToUnicodeString(&uc_str, 
                                        &ansi_str) != NDIS_STATUS_SUCCESS)
        goto failed;
     
      mask_multi_str.Length += uc_str.Length + sizeof(UNICODE_NULL);
    }

  /* Multi-strings are terminated with one extra unicode-NULL */
  ip_multi_str.Length += sizeof(UNICODE_NULL);
  mask_multi_str.Length += sizeof(UNICODE_NULL);

  SSH_ASSERT(ip_multi_str.Length <= ip_multi_str.MaximumLength);
  SSH_ASSERT(mask_multi_str.Length <= mask_multi_str.MaximumLength);

  /* Write the IP address(es) into system registry */  
  if (!ssh_registry_multi_string_set(config_key, L"IPAddress",
                                     ip_multi_str.Buffer, 
                                     ip_multi_str.Length)) 
    goto failed;

  if (!ssh_registry_multi_string_set(config_key, L"SubnetMask",
                                     mask_multi_str.Buffer, 
                                     mask_multi_str.Length)) 
    goto failed;

  ssh_free(ip_multi_str.Buffer);
  ssh_free(mask_multi_str.Buffer);
  ssh_registry_key_close(config_key);

  return TRUE;

 failed:

  ssh_free(ip_multi_str.Buffer);
  ssh_free(mask_multi_str.Buffer);
  ssh_registry_key_close(config_key);

  return FALSE;
}


Boolean
ssh_adapter_reset_ip_config(SshAdapter adapter)
{
  WCHAR zero_multi_ipv4[] = {'0', '.', '0', '.', '0', '.', '0', 0, 0};
  WCHAR empty_multi_str[] = {0, 0};
  SshRegKey adapter_key;
  SshRegKey netbt_if_key = NULL;

  adapter_key = ssh_adapter_open_tcpip_config(adapter);
  if (adapter_key == NULL)
    goto failed;

  /* Disable DCHP */
  if (!ssh_registry_dword_set(adapter_key, L"EnableDHCP", 0))
    goto failed;

#pragma warning(disable : 6209) /* FALSE positive Prefast warning */
#ifdef NDIS60
  /* Disable Autoconfiguration (APIPA) */
  ssh_registry_dword_set(adapter_key, L"IPAutoconfigurationEnabled", 0);
  /* Clear the APIPA address */
  ssh_registry_multi_string_set(adapter_key, 
                                L"IPAutoconfigurationAddress",
                                zero_multi_ipv4, 
                                sizeof(zero_multi_ipv4));

  /* Clear the static IP address and subnet mask. (The correct address will 
     be set when virtual adapter is "created" by engine) */
  if (!ssh_registry_multi_string_set(adapter_key, L"IPAddress",
                                     empty_multi_str, 
                                     sizeof(empty_multi_str)))
    goto failed;

  if (!ssh_registry_multi_string_set(adapter_key, L"SubnetMask",
                                     empty_multi_str, 
                                     sizeof(empty_multi_str)))
    goto failed;
#else 
  /* Clear the static IP address and subnet mask. (The correct address will 
     be set when virtual adapter is "created" by engine) */
  if (!ssh_registry_multi_string_set(adapter_key, L"IPAddress",
                                     zero_multi_ipv4, 
                                     sizeof(zero_multi_ipv4)))
    goto failed;

  if (!ssh_registry_multi_string_set(adapter_key, L"SubnetMask",
                                     zero_multi_ipv4, 
                                     sizeof(zero_multi_ipv4)))
    goto failed;
#endif /* NDIS60 */

  /* Clear default GW */
  if (!ssh_registry_multi_string_set(adapter_key, L"DefaultGateway",
                                     empty_multi_str,
                                     sizeof(empty_multi_str)))
    goto failed;
  /* Clear DNS server addresses */
  if (!ssh_registry_string_set(adapter_key, L"NameServer", L""))
    goto failed;

  /* Open NETBIOS over TCP/IP interfaces key */
  netbt_if_key =
    ssh_registry_key_open(HKEY_LOCAL_MACHINE, NULL,
      L"System\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces");

  if (netbt_if_key != NULL)
    {
      /* This time the interface name contains "Tcpip_" prefix... */
      WCHAR name_buffer[46] = L"Tcpip_";
      UNICODE_STRING if_name;
      UNICODE_STRING adapter_name;
      SshRegKey if_key;
      SshUInt16 offset;

      /* Adapter->orig_name contains the interface name we are interested.
         We just need to "remove" the "\DEVICE\" prefix. */
      offset = 16; /* skip eight UNICODE characters from the beginning */
      adapter_name.Buffer = 
        (WCHAR *)(((char *)adapter->orig_name.Buffer) + offset);
      adapter_name.Length = adapter->orig_name.Length - offset;
      adapter_name.MaximumLength = adapter->orig_name.MaximumLength - offset;

      SSH_ASSERT(sizeof(name_buffer) >= (adapter_name.MaximumLength + 12));

      if_name.Buffer = name_buffer;
      memcpy(&name_buffer[6], adapter_name.Buffer, adapter_name.Length);
      if_name.Length = adapter_name.Length + 12;
      if_name.MaximumLength = sizeof(name_buffer);

      SSH_ASSERT(if_name.Length <= if_name.MaximumLength);

      /* Open the adapter specific key */
      if_key = ssh_registry_key_open_unicode(netbt_if_key, NULL, &if_name);

      if (if_key != NULL)
        {
          /* Clear WINS server addresses */
          ssh_registry_multi_string_set(if_key, L"NameServerList",
                                        empty_multi_str,
                                        sizeof(empty_multi_str));

          ssh_registry_key_close(if_key);
        }

      ssh_registry_key_close(netbt_if_key);
    }
#pragma warning(default : 6209) 

  ssh_registry_key_close(adapter_key);

  return TRUE;

 failed:

  if (netbt_if_key)
    ssh_registry_key_close(netbt_if_key);

  if (adapter_key)
    ssh_registry_key_close(adapter_key);

  return FALSE;
}

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

