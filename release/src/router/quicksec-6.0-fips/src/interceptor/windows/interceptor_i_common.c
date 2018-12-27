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
#include "event_log.h"
#include "kernel_timeouts.h"
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#include "win_ip_interface.h"
#include "win_ip_route.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


#define SSH_DEBUG_MODULE "SshInterceptorCommon"

/* Single Interceptor object */
SshInterceptor the_interceptor = NULL;

static GUID zero_guid;

CALLBACK_FUNCTION ssh_interceptor_power_state_callback;

static void
ssh_interceptor_warning_cb(const char *message,
                           void *context);

static void
ssh_interceptor_debug_cb(const char *message,
                         void *context);

static void
ssh_interceptor_fatal_cb(const char *message,
                         void *context);

static SshOsVersion
ssh_interceptor_get_os_version(void);

#ifdef HAS_INTERFACE_NAME_MAPPINGS
static Boolean 
ssh_interceptor_read_interface_mappings(SshInterceptor interceptor);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

static void
ssh_interceptor_ip_cfg_thread_event_cb(SshTask task, 
                                       SshTaskState new_state,
                                       void *context);

static void
ssh_interceptor_ip_cfg_changed(SshInterceptor interceptor);

static Boolean __fastcall
ssh_interceptor_ipm_device_recv_msg(int len,
                                    unsigned char *buf,
                                    void *context);

Boolean
ssh_interceptor_init_common(SshInterceptor interceptor,
                            SshInterceptorInitParams init_params,
                            SshInterceptorInitFn init_fn,
                            void *init_fn_context)
{
  OBJECT_ATTRIBUTES obj_attr;
  UNICODE_STRING uc_name;
  SshOsVersion os_version;
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  SshTCBStruct tcb;
  const unsigned char *ipm_device_name = "QuickSec";
  Boolean exclusive_access = TRUE;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
#ifdef NDIS620
  SshQueryActiveProcessorCount query_cpu_count_fn;
  UNICODE_STRING fn_name;
#endif /* NDIS620 */


  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(init_params != NULL);
  SSH_ASSERT(init_params->registry_path != NULL);
  SSH_ASSERT(init_params->driver_object != NULL);
  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  interceptor->state = SSH_INTERCEPTOR_STATE_INITIALIZING;

  the_interceptor = interceptor;

#ifdef DEBUG_LIGHT
  interceptor->debug_trace = 
    ssh_debug_trace_create(init_params->registry_path);
#endif /* DEBUG_LIGHT */

  /* Register callbacks for debug messages */
  ssh_debug_register_callbacks(ssh_interceptor_fatal_cb,
                               ssh_interceptor_warning_cb,
                               ssh_interceptor_debug_cb,
                               interceptor);

  ssh_event_log_activate(init_params->driver_object);

  ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                SSH_LOG_NOTICE, ("Loading INSIDE Secure QuickSec driver"));

  /* Save driver object, set initial state and query system size */
  interceptor->driver_object = init_params->driver_object;
  interceptor->net_ready = FALSE;
  interceptor->low_power_state = FALSE;
  interceptor->entering_low_power_state = FALSE;
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  interceptor->if_report_disable_count = 0;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
  interceptor->ref_count = 0;
#ifdef NDIS620






  RtlInitUnicodeString(&fn_name, L"KeQueryActiveProcessorCountEx");
  query_cpu_count_fn = MmGetSystemRoutineAddress(&fn_name);

  RtlInitUnicodeString(&fn_name, L"KeGetCurrentProcessorNumberEx");
  interceptor->get_current_cpu_fn = MmGetSystemRoutineAddress(&fn_name);
  if (interceptor->get_current_cpu_fn && query_cpu_count_fn)
    {
      interceptor->processor_count = 
        (*query_cpu_count_fn)(ALL_PROCESSOR_GROUPS);
    }
  else
#endif /* NDIS620 */
    {
      interceptor->processor_count = NdisSystemProcessorCount();
    }
#ifdef HAS_IEEE802_3_PASSTHRU
  interceptor->pass_ieee802_3 = FALSE;
#endif /* HAS_IEEE802_3_PASSTHRU */
#ifdef INTERCEPTOR_PASS_PROMISCUOUS_PACKETS
  interceptor->pass_promiscuous = FALSE;
#endif /* INTERCEPTOR_PASS_PROMISCUOUS_PACKETS */
#ifdef INTERCEPTOR_PASS_LOOPBACK_PACKETS
  interceptor->pass_loopback = FALSE;
#endif /* INTERCEPTOR_PASS_LOOPBACK_PACKETS */
#ifdef HAS_INTERFACE_NAME_MAPPINGS
  interceptor->if_map_key = NULL;
#endif /* HAS_INTERFACE_NAME_MAPPINGS */
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  interceptor->va_configure_running = 0;
  interceptor->va_interface_cnt     = 0;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
  interceptor->routing_disable_count = 0;

  if (interceptor->processor_count == 0)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to query processor count, driver not loaded"));
      goto failed;
    }

  interceptor->cpu_ctx = ssh_calloc(interceptor->processor_count,
                                    sizeof(*(interceptor->cpu_ctx)));
  if (interceptor->cpu_ctx == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to alocate per-CPU context, driver not loaded"));
      goto failed;
    }

  /* Allocate OS resources for locks */
  NdisInitializeListHead(&interceptor->adapter_list);
  ssh_kernel_rw_mutex_init(&interceptor->adapter_lock);
#ifdef HAS_INTERFACE_NAME_MAPPINGS
  ssh_kernel_rw_mutex_init(&interceptor->if_map_lock);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_kernel_rw_mutex_init(&interceptor->if_lock);
  ssh_kernel_mutex_init(&interceptor->ip_refresh_lock);
  ssh_kernel_rw_mutex_init(&interceptor->ip4_route_lock);
  NdisInitializeListHead(&interceptor->if_list);
  NdisInitializeListHead(&interceptor->ip4_route_list);
#if defined (WITH_IPV6)
  ssh_kernel_rw_mutex_init(&interceptor->ip6_route_lock);
  NdisInitializeListHead(&interceptor->ip6_route_list);
#endif /* WITH_IPV6 */
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Check the OS version */
  os_version = ssh_interceptor_get_os_version();
  if (!ssh_interceptor_is_supported_os_version(os_version))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Unsupported operating system, driver not loaded"));
      goto failed;
    }

  interceptor->os_version = os_version;

#ifdef SSH_IM_INTERCEPTOR
  /* Obtain the handle to the NDIS wrapper */
  NdisMInitializeWrapper(&interceptor->wrapper_handle, 
                         init_params->driver_object, 
                         init_params->registry_path, 
                         NULL);

  if (interceptor->wrapper_handle == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to initialize NDIS Wrapper"));
      goto failed;
    }
#endif /* SSH_IM_INTERCEPTOR */

#if (defined(HAS_IEEE802_3_PASSTHRU) || defined(HAS_INTERFACE_NAME_MAPPINGS))
  if (init_params->registry_path)
    {
      SshRegKey conf_key;

      /* Read additional configuration parameters */
      conf_key = ssh_registry_key_open_unicode(NULL, NULL, 
                                               init_params->registry_path);
      if (conf_key)
        {
          SshRegKey param_key;

          param_key = ssh_registry_key_open(conf_key, NULL, L"Parameters");
          if (param_key)
            {
              SshRegDWord value = 0;

#ifdef HAS_IEEE802_3_PASSTHRU
              if (ssh_registry_dword_get(param_key, L"PassIEEE802_3", &value))
                {
                  if (value != 0)
                    interceptor->pass_ieee802_3 = TRUE;
                }
#endif /* HAS_IEEE802_3_PASSTHRU */

#ifdef INTERCEPTOR_PASS_PROMISCUOUS_PACKETS
              if (ssh_registry_dword_get(param_key, L"PassPromiscuous",
					 &value))
                {
                  if (value != 0)
                    interceptor->pass_promiscuous = TRUE;
                }
#endif /* INTERCEPTOR_PASS_PROMISCUOUS_PACKETS */

#ifdef INTERCEPTOR_PASS_LOOPBACK_PACKETS
              if (ssh_registry_dword_get(param_key, L"PassLoopback", &value))
                {
                  if (value != 0)
                    interceptor->pass_loopback = TRUE;
                }
#endif /* INTERCEPTOR_PASS_LOOPBACK_PACKETS */

              ssh_registry_key_close(param_key);
            }
#ifdef HAS_INTERFACE_NAME_MAPPINGS
          interceptor->if_map_key = 
            ssh_registry_key_open(conf_key, NULL, L"Interfaces");

          if (interceptor->if_map_key)
            {
              ssh_interceptor_read_interface_mappings(interceptor);
            }
          else
            {
              interceptor->if_map_key = 
                ssh_registry_key_create(conf_key, L"Interfaces");
            }
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

          ssh_registry_key_close(conf_key);
        }
    }
#endif /* HAS_IEEE802_3_PASSTHRU || HAS_INTERFACE_NAME_MAPPINGS */

  interceptor->packet_pool_constructor = init_params->packet_pool_constructor;
  interceptor->packet_pool_destructor = init_params->packet_pool_destructor;

  /* Create timeout manager */
  if (!ssh_kernel_timeouts_init(interceptor))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to initialize timeouts"));
      goto failed;
    }

  if (interceptor->packet_pool_constructor)
    {
      /* Also the destructor must be specified! */
      SSH_ASSERT(interceptor->packet_pool_destructor != NULL_FNPTR);

      if (!(*interceptor->packet_pool_constructor)(interceptor))
        {
          ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                        SSH_LOG_CRITICAL,
                        ("Could not create packet pools"));
          goto failed;
        }
    }

  if (!ssh_interceptor_iodevice_alloc(interceptor, 
                                      ipm_device_name,  
                                      exclusive_access,
                                      ssh_interceptor_ipm_device_status,
                                      ssh_interceptor_ipm_device_recv_msg,
                                      interceptor))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Could not allocate I/O device object"));
      goto failed;
    }

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Initialize IP stack communication devices */
  if (!ssh_ipdev_init(&interceptor->ip4_dev, interceptor, SSH_DD_ID_IP4))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Could not initialize IPv4 protocol stack interface"));
      goto failed;
    }
  interceptor->ipv4_dev_initialized = 1;
#if defined (WITH_IPV6)
  if (!ssh_ipdev_init(&interceptor->ip6_dev, interceptor, SSH_DD_ID_IP6))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Could not initialize IPv6 protocol stack interface"));
      goto failed;
    }
  interceptor->ipv6_dev_initialized = 1;
#endif /* WITH_IPV6 */
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Initialize mechanism for queuing asynchronous function calls */
  if (!ssh_ndis_wrkqueue_initialize(&interceptor->work_queue, 
                                    SSH_WORK_QUEUE_THREAD_ID,
                                    0, 5))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to create work queue!"));
      goto failed;
    }

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Initialize IP config thread */
  memset(&tcb, 0x00, sizeof(tcb));
  tcb.priority = SSH_TASK_PRIORITY_NOCHANGE;
  tcb.exec_type = SSH_TASK_TYPE_EVENT_MONITOR;
  tcb.period_ms = SSH_TASK_EVENT_WAIT_INFINITE;
  tcb.state_change_cb = ssh_interceptor_ip_cfg_thread_event_cb;
  tcb.state_change_context = interceptor;
  if (!ssh_task_init(&interceptor->ip_cfg_thread,
                     SSH_IP_CONFIG_THREAD_ID, 
                     ssh_interceptor_ip_cfg_changed, 
                     interceptor, &tcb))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to create worker thread!"));
      goto failed;
    }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Try to register callback function for power state change indications */
  RtlInitUnicodeString(&uc_name, L"\\Callback\\PowerState");

  InitializeObjectAttributes(&obj_attr, &uc_name,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL, NULL);

  if (NT_SUCCESS(ExCreateCallback(&interceptor->power_state_cb_obj, 
                                  &obj_attr, 
                                  FALSE, 
                                  TRUE)))
    {
      interceptor->power_state_cb_handle = 
        ExRegisterCallback(interceptor->power_state_cb_obj, 
                           ssh_interceptor_power_state_callback,
                           interceptor);
    }

  /* Execute (optional) interceptor dependent initialization function */
  if (init_fn)
    {
      if (!((*init_fn)(interceptor, init_fn_context)))
        goto failed;
    }

  interceptor->state = SSH_INTERCEPTOR_STATE_PAUSED;
  return TRUE;

 failed:

  ssh_interceptor_uninit_common(interceptor, NULL_FNPTR, NULL);
  the_interceptor = NULL;

  return FALSE;
}


Boolean
ssh_interceptor_restart_common(SshInterceptor interceptor,
                               SshInterceptorStartParams start_params,
                               SshInterceptorStartFn start_fn,
                               void *start_fn_context)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(start_params != NULL);
  SSH_ASSERT(interceptor->state == SSH_INTERCEPTOR_STATE_PAUSED);

  interceptor->state = SSH_INTERCEPTOR_STATE_RESTARTING;
  interceptor->raise_irql_on_pm_engine_calls = 
    start_params->raise_irql_on_pm_engine_calls;
  interceptor->asynch_interceptor_route =
    start_params->asynch_interceptor_route;
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  interceptor->use_polling_ip_refresh = start_params->use_polling_ip_refresh;
  interceptor->ip_refresh_interval = start_params->ip_refresh_interval;
  interceptor->pre_ip_refresh_fn = start_params->pre_ip_refresh_fn;
  interceptor->post_ip_refresh_fn = start_params->post_ip_refresh_fn;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  if (interceptor->asynch_interceptor_route
      && (!ssh_ndis_wrkqueue_initialize(&interceptor->routing_queue, 
                                        SSH_ROUTING_QUEUE_THREAD_ID,
                                        0, 10)))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to create asynchronous routing queue"));
      goto failed;
    }

  /* Start the IPSec engine */
  interceptor->engine = ssh_engine_start(ssh_interceptor_ipm_device_send_msg, 
                                         interceptor, 
                                         SSH_WINDOWS_ENGINE_FLAGS);
  if (interceptor->engine == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to start packet processing engine!"));
      goto failed;
    }

  ssh_interceptor_suspend_worker_threads(interceptor);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Actually the IP config thread won't be executed before 
     ssh_interceptor_resume_worker_threads() is called */
  ssh_task_start(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  if (start_fn)
    {
      if (!(*start_fn)(interceptor, start_fn_context))
        {
          ssh_interceptor_resume_worker_threads(interceptor);
          goto failed;
        }
    }

  if (start_params->create_io_device)
    {
      if (!ssh_interceptor_ipm_device_create(interceptor))
        {
          ssh_interceptor_resume_worker_threads(interceptor);
          goto failed;
        }
    }

  interceptor->state = SSH_INTERCEPTOR_STATE_RUNNING;

  ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                SSH_LOG_NOTICE,
                ("INSIDE Secure QuickSec driver up and running"));

  ssh_interceptor_resume_worker_threads(interceptor);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Generate first interface report */
  SSH_IP_REFRESH_REQUEST(interceptor);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
  return TRUE;

 failed:

  ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                SSH_LOG_CRITICAL,
                ("Failed to start INSIDE Secure QuickSec driver!")); 

  ssh_interceptor_pause_common(interceptor, NULL_FNPTR, NULL);
  SSH_ASSERT(interceptor->state == SSH_INTERCEPTOR_STATE_PAUSED);
  return FALSE;
}


void 
ssh_interceptor_pause_common(SshInterceptor interceptor,
                             SshInterceptorPauseFn pause_fn,
                             void *pause_fn_context)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT((interceptor->state == SSH_INTERCEPTOR_STATE_RUNNING)
             || (interceptor->state == SSH_INTERCEPTOR_STATE_RESTARTING));

  interceptor->state = SSH_INTERCEPTOR_STATE_PAUSING;

  ssh_interceptor_suspend_worker_threads(interceptor);

  /* Remove I/O device for PM communication */
  if (interceptor->ipm_device != NULL)
    {
      SSH_ASSERT(
        ssh_interceptor_iodevice_is_open(interceptor->ipm_device) == FALSE);

      ssh_interceptor_ipm_device_destroy(interceptor);
      ssh_interceptor_iodevice_free(interceptor->ipm_device);

      SSH_ASSERT(interceptor->ipm_device == NULL);
    }

  if (pause_fn)
    {
      (*pause_fn)(interceptor, pause_fn_context);
    }

  ssh_interceptor_resume_worker_threads(interceptor);

  /* Wait until all pending operations have completed */
  while (InterlockedCompareExchange(&interceptor->ref_count, 0, 0))
    NdisMSleep(1000);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_task_stop(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  /* Stop the engine */
  if (interceptor->engine != NULL)
    {
      if (interceptor->raise_irql_on_pm_engine_calls)
        {
          SSH_IRQL old_irql;

          SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
          ssh_engine_stop(interceptor->engine);
          SSH_LOWER_IRQL(old_irql);
        }
      else
        {
          ssh_engine_stop(interceptor->engine);
        }
      interceptor->engine = NULL;
    }

  if (interceptor->routing_queue)
    {
      ssh_ndis_wrkqueue_uninitialize(interceptor->routing_queue);
    }

  interceptor->state = SSH_INTERCEPTOR_STATE_PAUSED;
}


void
ssh_interceptor_uninit_common(SshInterceptor interceptor,
                              SshInterceptorUninitFn uninit_fn,
                              void *uninit_fn_context)
{
#ifdef HAS_INTERFACE_NAME_MAPPINGS
  SshInterceptorIfnum ifnum;
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor == the_interceptor);
  SSH_ASSERT((interceptor->state == SSH_INTERCEPTOR_STATE_PAUSED)
             || (interceptor->state == SSH_INTERCEPTOR_STATE_INITIALIZING));

  SSH_ASSERT(interceptor != NULL);

  interceptor->state = SSH_INTERCEPTOR_STATE_HALTING;

  /* Unregister power state callback */
  if (interceptor->power_state_cb_obj != NULL)
    {
      if (interceptor->power_state_cb_handle)
        ExUnregisterCallback(interceptor->power_state_cb_handle);

      ObDereferenceObject(interceptor->power_state_cb_obj);
    }

  if (uninit_fn)
    (*uninit_fn)(interceptor, uninit_fn_context);

  if (interceptor->packet_pool_destructor)
    (*interceptor->packet_pool_destructor)(interceptor);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_ip_interface_list_free(interceptor);
  ssh_ip_routing_table_free(interceptor);

  /* Uninitialize IP stack communication devices */
  if (interceptor->ipv4_dev_initialized)
    {
      if (ssh_ipdev_is_connected(&interceptor->ip4_dev))
        ssh_ipdev_disconnect(&interceptor->ip4_dev);

      ssh_ipdev_uninit(&interceptor->ip4_dev);
    }
#if defined (WITH_IPV6)
  if (interceptor->ipv6_dev_initialized)
    {
      if (ssh_ipdev_is_connected(&interceptor->ip6_dev))
        ssh_ipdev_disconnect(&interceptor->ip6_dev);

      ssh_ipdev_uninit(&interceptor->ip6_dev);
    }
#endif /* WITH_IPV6 */

  ssh_task_uninit(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  if (interceptor->work_queue)
    ssh_ndis_wrkqueue_uninitialize(interceptor->work_queue);

  /* Destroy the timeout manager */
  if (interceptor->timeout_mgr)
    ssh_kernel_timeouts_uninit(interceptor);

#ifdef HAS_INTERFACE_NAME_MAPPINGS
  /* Close interface name mappings registry key */
  if (interceptor->if_map_key)
    ssh_registry_key_close(interceptor->if_map_key);

  ssh_kernel_rw_mutex_uninit(&interceptor->if_map_lock);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  /* Release spin locks and clean lists */
  ssh_kernel_rw_mutex_uninit(&interceptor->adapter_lock);
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_kernel_rw_mutex_uninit(&interceptor->if_lock);
  ssh_kernel_mutex_uninit(&interceptor->ip_refresh_lock);
  ssh_kernel_rw_mutex_uninit(&interceptor->ip4_route_lock);
#if defined (WITH_IPV6)
  ssh_kernel_rw_mutex_uninit(&interceptor->ip6_route_lock);
#endif /* WITH_IPV6 */
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

#ifdef SSH_IM_INTERCEPTOR
  if (interceptor->wrapper_handle)
    NdisTerminateWrapper(interceptor->wrapper_handle, NULL);
#endif /* SSH_IM_INTERCEPTOR */

  ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                SSH_LOG_NOTICE,
                ("INSIDE Secure QuickSec driver unloaded"));

#ifdef DEBUG_LIGHT
  ssh_debug_trace_destroy(interceptor->debug_trace);
#endif /* DEBUG_LIGHT */

#ifdef HAS_INTERFACE_NAME_MAPPINGS
  for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
    ssh_interceptor_free_interface_mapping(interceptor,
                                           interceptor->if_map[ifnum]);
#endif /* HAS_INTERFACE_NAME_MAPPINGS */

  ssh_free(interceptor->cpu_ctx);
  interceptor->state = SSH_INTERCEPTOR_STATE_HALTED;
  the_interceptor = NULL;

  ssh_debug_uninit();
}



/*--------------------------------------------------------------------------
  ssh_interceptor_ipm_device_create()
  
  Initializes our interceptor so that it is ready for communication with
  Policy Manager.
  
  Arguments:
  interceptor - interceptor object
 
  Returns:
  NDIS_STATUS_SUCCESS - succeed
  NDIS_STATUS_FAILURE - otherwise
  
  Notes:
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_ipm_device_create(SshInterceptor interceptor)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_ipm_device_create()"));

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->ipm_device != NULL);

  /* Create and initialize the I/O device */
  if (!ssh_interceptor_iodevice_create_device(interceptor->ipm_device))
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Failed to create PM communication channel!"));
      return FALSE;
    }


  return TRUE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_ipm_device_destroy()
   
  Removes the internal I/O device object that is used for Policy Manager 
  communication.
  
  Arguments:
  interceptor - interceptor object
 
  Returns:
  NDIS_STATUS_SUCCESS - succeed
  NDIS_STATUS_FAILURE - otherwise
  
  Notes:
  --------------------------------------------------------------------------*/
void
ssh_interceptor_ipm_device_destroy(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->ipm_device != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_ipm_device_destroy()"));


  ssh_interceptor_iodevice_close_device(interceptor->ipm_device);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_ipm_device_status()
  
  This function gets called whenever the state of our internal I/O device
  object is changed. Policy Manager either opens(closes) our I/O device for
  communication.
  
  Arguments:
  opened - I/O device state
  context - interceptor object
 
  Returns:
  TRUE - success
  FALSE - engine does not exist
  
  Notes:
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_ipm_device_status(INT opened,
                                  PVOID context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  SshAdapter adapter;
  SshInterceptorIfnum ifnum;
  SshUInt16 ticks = 300;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(interceptor != NULL);

  if (interceptor->engine == NULL)
    return (FALSE);

  /* Update I/O device status */
  if (opened)
    {
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
      for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
        {
          adapter = ssh_adapter_ref_by_ifnum(interceptor, ifnum);

          if (adapter == NULL)
            continue;

          if (adapter->is_vnic)
            {
              /* Modify the registry settings of our virtual adapter to use 
                 static IP address instead of dynamically allocated one. */
              ssh_adapter_reset_ip_config(adapter);

              SSH_ASSERT(adapter->va == NULL);
              adapter->va = 
                ssh_virtual_adapter_register(interceptor,
                                             adapter, 
                                             adapter->vnic_interface,
                                             adapter->vnic_interface_size);
            }

          ssh_adapter_release(adapter);
        }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

      interceptor->net_ready = TRUE;
      ssh_engine_notify_ipm_open(interceptor->engine);
    }
  else
    {
      SSH_IRQL irql;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
      /* First update the virtual adapter that they'll have to 
         deregister when detaching, i.e. set the flag. */
      for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
        {
          adapter = ssh_adapter_ref_by_ifnum(interceptor, ifnum);

          if (adapter == NULL)
            continue;

          if ((adapter->is_vnic) && (adapter->va))
            adapter->va->flags |= SSH_VIRTUAL_ADAPTER_FLAG_DEREGISTER;

          ssh_adapter_release(adapter);
        }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

      /* Notify engine. */
      if (interceptor->raise_irql_on_pm_engine_calls)
        {
          SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &irql);
        }

      ssh_engine_notify_ipm_close(interceptor->engine);

      if (interceptor->raise_irql_on_pm_engine_calls)
        {
          SSH_LOWER_IRQL(irql);
        }

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
      /* Wait after notifying to the engine that all va related operations
         have ended and all the interfaces have been released. This keeps
         the pm - engine communication channel open until everything has
         been cleaned. */
      while (InterlockedCompareExchange(&interceptor->va_interface_cnt,
             1, 1) && ticks)
        {
          NdisMSleep(100000);
          ticks--;
        }

      SSH_ASSERT(ticks != 0);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
    }

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  /* Refresh interface info */
  InterlockedExchange(&interceptor->if_report_disable_count, 0);
  SSH_IP_FORCE_REFRESH_REQUEST(interceptor, SSH_IP_REFRESH_ALL);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  return (TRUE);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_ipm_device_send_msg()
  
  Sends a message to Policy Manager using interceptor's I/O device object.
  
  Arguments:
  data - message data
  len - message length
  reliable - ???
  machine_context - ???
 
  Returns:
  TRUE - send succeeded
  FALSE - otherwise
  
  Notes:
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_ipm_device_send_msg(PUCHAR data,
                                    size_t len,
                                    Boolean reliable,
                                    void *machine_context)
{
  SshInterceptor interceptor = (SshInterceptor)machine_context;

  SSH_ASSERT(data != NULL);
  SSH_ASSERT(len > 0);
  SSH_ASSERT(interceptor != NULL);

  return (ssh_interceptor_iodevice_send(interceptor->ipm_device, 
                                        (SshUInt32)len, data, reliable));
}


/*--------------------------------------------------------------------------
 Suspends the interceptor if all adapters are ready to enter low power state.
 --------------------------------------------------------------------------*/
void
ssh_interceptor_suspend_if_idle(SshInterceptor interceptor)
{
  SshAdapter adapter;
  PLIST_ENTRY entry;
  Boolean all_in_D3 = TRUE;

  SSH_ASSERT(interceptor != NULL);

  /* Protect also the interceptor's 'low_power_state' flag with adapter_lock 
     (just to prevent potential race condition) */
  ssh_kernel_rw_mutex_lock_write(&interceptor->adapter_lock);

  if (interceptor->low_power_state)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Interceptor already suspended!"));
      ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);
      return;
    }

  /* Power state is adapter specific. All adapters must be in state D3 
     before we can assume that the system is going to hibernate/supend. */
  for (entry = interceptor->adapter_list.Flink; 
       (all_in_D3 == TRUE) && (entry != &interceptor->adapter_list); 
       entry = entry->Flink)
    {
      adapter = CONTAINING_RECORD(entry, SshAdapterStruct, link);

      if (adapter->power_mgmt_disabled)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Adapter %@: power management disabled; allow "
                     "interceptor to suspend",
                     ssh_adapter_id_st_render, adapter));

          continue;
        }

      if (adapter->standing_by == 1)
        {
          switch (adapter->state)
            {
            case SSH_ADAPTER_STATE_DETACHED:
            case SSH_ADAPTER_STATE_PAUSED:
              all_in_D3 = SSH_ADAPTER_CAN_SUSPEND(adapter);
              break;

            default:
              all_in_D3 = FALSE;
              break;
            }

          if (all_in_D3)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Adapter %@: interceptor can suspend!",
                         ssh_adapter_id_st_render, adapter));
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Adapter %@: still busy; interceptor not allowed "
                         "to suspend!",
                         ssh_adapter_id_st_render, adapter));
            }
        }
      else
        {
          all_in_D3 = FALSE;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Adapter %@: NIC still powered up; interceptor not "
                     "allowed to suspend!",
                     ssh_adapter_id_st_render, adapter));
        }
    }

  if (all_in_D3)
    {
      interceptor->low_power_state = 1;
    }

  ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);

  if (all_in_D3)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Entering Standby/Hibernate..."));

      ssh_interceptor_suspend_worker_threads(interceptor);



#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      ssh_engine_suspend(interceptor->engine);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
      ssh_interceptor_get_time(&interceptor->low_power_start_time_sec, NULL);
      ssh_kernel_timeouts_suspend(interceptor);
    }
}


/*-------------------------------------------------------------------------
  Resumes the interceptor. This function must be called when OS is returning
  from a low power state.
  -------------------------------------------------------------------------*/
void
ssh_interceptor_resume(SshInterceptor interceptor) 
{
  SshUInt32 suspend_time_sec = 0;
  SshTime now;

  /* Protect also the interceptor's 'low_power_state' flag with adapter_lock 
     (just to prevent potential race condition) */
  ssh_kernel_rw_mutex_lock_write(&interceptor->adapter_lock);

  if (!interceptor->low_power_state)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Interceptor already resumed!"));
      ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);
      return;
    }

  interceptor->low_power_state = 0;
  ssh_kernel_rw_mutex_unlock_write(&interceptor->adapter_lock);

  if (InterlockedExchange(&interceptor->entering_low_power_state, 
                          FALSE) != FALSE)
    {
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      /* Actually this only decrements the suspend count (which was previously
         incremented in power state callback before system entered low power 
         state). Later called ssh_interceptor_resume_worker_threads() will
         resume the IP config thread. Currently our Windows Mobile/CE 
         interceptor doesn't have power state callbacks, so we MUST NOT
         call ssh_task_resume() here on Windows Mobile platform! */
      ssh_task_resume(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
    }

  ssh_interceptor_get_time(&now, NULL);

  /* Current system time should be later than the hibernation/
     standby starting time - except when mainboards backup battery
     is empty, BIOS has been reset or some other similar event
     has caused the real-time-clock to stop/reset. */
  if (now > interceptor->low_power_start_time_sec)
    suspend_time_sec = 
      (SshUInt32)(now - interceptor->low_power_start_time_sec);

  ssh_kernel_timeouts_resume(interceptor, suspend_time_sec, 0);



#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_engine_resume(interceptor->engine);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
  ssh_interceptor_resume_worker_threads(interceptor);
}


/*-------------------------------------------------------------------------
  ssh_interceptor_ipm_device_recv_msg()

  Indicates that a new packetized message has been received from Policy 
  Manager via our internal device object.

  The message is forwarded to the engine object and after engine has 
  processed the message, the memory allocated for the message is 
  released.

  Arguments:
  len - message length 
  buf - packetized message received from policy manager
  context - interceptor object
  
  Returns:
  TRUE - success
  FALSE - engine does not exist
  
  Notes:
  ------------------------------------------------------------------------*/
static Boolean __fastcall
ssh_interceptor_ipm_device_recv_msg(int len,
                                    unsigned char *buf,
                                    void *context)
{
  SshInterceptor interceptor = context;
  UCHAR type = 0;
  SSH_IRQL irql;

  SSH_ASSERT(interceptor->engine != NULL);
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(len > 0);

  type = *buf;
  buf++;
  len--;

  if (interceptor->raise_irql_on_pm_engine_calls)
    {
      SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &irql);
    }

  ssh_engine_packet_from_ipm(interceptor->engine, type, buf, len);

  if (interceptor->raise_irql_on_pm_engine_calls)
    {
      SSH_LOWER_IRQL(irql);
    }

  return (TRUE);
}

static void
ssh_interceptor_warning_cb(const char *msg, 
                           void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;

  /* Check that Interceptor, opened I/O device and Engine exist */
  if ((interceptor == NULL) || (msg == NULL))
    return;

#ifdef DEBUG_LIGHT
  ssh_debug_trace(interceptor->debug_trace, (const unsigned char *)msg);

  DbgPrint("%s\n", msg);
#endif /* DEBUG_LIGHT */

  if (!ssh_interceptor_iodevice_is_open(interceptor->ipm_device))
    return;

  ssh_engine_send_warning(interceptor->engine, msg);
}


static void
ssh_interceptor_debug_cb(const char *msg, 
                         void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;

#ifdef DEBUG_LIGHT
  static Boolean dump_to_kd = FALSE;
#endif /* DEBUG_LIGHT */

  if ((interceptor == NULL) || (msg == NULL))
    return;

#ifdef DEBUG_LIGHT
  ssh_debug_trace(interceptor->debug_trace, (const unsigned char *)msg);

  if (dump_to_kd)
    DbgPrint("%s\n", msg); 
#endif /* DEBUG_LIGHT */

  /* Check that opened I/O device exist */
  if (!ssh_interceptor_iodevice_is_open(interceptor->ipm_device))
    return;

  ssh_engine_send_debug(interceptor->engine, msg);
}


static void
ssh_interceptor_fatal_cb(const char *msg, 
                         void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;

#ifdef DEBUG_LIGHT
  if (interceptor != NULL)
    ssh_debug_trace(interceptor->debug_trace, (const unsigned char *)msg);

  if (msg != NULL)
    DbgPrint("%s", msg);
#endif /* DEBUG_LIGHT */

  /* We should NOT try to write error log entry if we are already at
     raised IRQL. Otherwise the operting system will neither write the
     error log nor generate crash dump (because OS will crash in our
     ssh_kernel_log_cb!). */
  if (SSH_GET_IRQL() == SSH_PASSIVE_LEVEL)
    ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_CRITICAL, msg);

#pragma warning(disable : 28159)
  KeBugCheckEx('TNFS', 0xBAD, 0xBAD, 0xBAD, (ULONG_PTR)msg);
#pragma warning(default : 28159)
}

static SshOsVersion
ssh_interceptor_get_os_version(void)
{
  SshOsVersion os_version = 0;
  RTL_OSVERSIONINFOW version;

  RtlZeroMemory(&version, sizeof(version));
  version.dwOSVersionInfoSize = sizeof(version);
  RtlGetVersion(&version);

  os_version = ((version.dwMajorVersion << 4) | version.dwMinorVersion);

  return os_version;
}


static Boolean
ssh_interceptor_create_if_map_key_name(SshInterceptorIfnum ifnum,
                                       UNICODE_STRING *key_name_out)
{
  Boolean status = FALSE;
  char ansi_buffer[5];
  ANSI_STRING astr;

  SSH_ASSERT(ifnum <= 9999);
  ssh_snprintf((unsigned char *)ansi_buffer, 
               sizeof(ansi_buffer), "%04u", ifnum);
  ansi_buffer[4] = 0;  /* Just to keep Prefast happy... */

  RtlInitAnsiString(&astr, ansi_buffer);

  if (key_name_out->MaximumLength >= ((astr.Length + 1) * sizeof(WCHAR)))
    {
      if (RtlAnsiStringToUnicodeString(key_name_out, 
                                       &astr, FALSE) == STATUS_SUCCESS)
        {
          key_name_out->Buffer[strlen(ansi_buffer)] = 0;
          status = TRUE;
        }
    }

  return status;
}


#ifdef HAS_INTERFACE_NAME_MAPPINGS
static Boolean
ssh_interceptor_open_if_map_key(SshInterceptor interceptor,
                                SshInterceptorIfnum ifnum,
                                Boolean create_if_not_exist,
                                SshRegKey *key_out)
{
  WCHAR uc_buffer[128];
  UNICODE_STRING ustr; 
  Boolean status = FALSE;

  ustr.Buffer = uc_buffer;
  ustr.MaximumLength = sizeof(uc_buffer);
  ustr.Length = 0;

  if (ssh_interceptor_create_if_map_key_name(ifnum, &ustr))
    {
      *key_out = ssh_registry_key_open_unicode(interceptor->if_map_key,
                                               NULL, &ustr);
      if (!(*key_out) && create_if_not_exist)
        {
          *key_out = 
            ssh_registry_key_create_unicode(interceptor->if_map_key, &ustr);
        }

      if (*key_out)
        status = TRUE;
    }

  return status;
}


static Boolean
ssh_interceptor_read_interface_mappings(SshInterceptor interceptor)
{
  Boolean status = FALSE;

  SSH_ASSERT(interceptor != NULL);

  /* We don't need to use any locks (yet), because the 
     interceptor is not running yet and thus there can't be
     any race condition. */
  SSH_ASSERT(interceptor->state == SSH_INTERCEPTOR_STATE_INITIALIZING);

  if (interceptor->if_map_key)
    {
      SshInterceptorIfnum ifnum;

      for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
        {
          SshIfNameMapping if_map;
          SshRegKey key;

          if (!ssh_interceptor_open_if_map_key(interceptor, ifnum, 
                                               FALSE, &key))
            continue;

          if_map = ssh_calloc(1, sizeof(*if_map));
          if (if_map)
            {
              WCHAR name[SSH_ADAPTER_NAME_SIZE_MAX];
              UNICODE_STRING ustr;
              ANSI_STRING astr;

              ustr.Buffer = name;
              ustr.Length = 0;
              ustr.MaximumLength = sizeof(name);

              astr.Buffer = (PCHAR)if_map->alias;
              astr.Length = 0;
              astr.MaximumLength = sizeof(if_map->alias);

              if (!ssh_registry_unicode_string_get(key, L"Name", &ustr)
                  || (RtlUnicodeStringToAnsiString(
                        &astr, &ustr, FALSE)!= STATUS_SUCCESS))
                {
                  ssh_free(if_map);
                  continue;
                }

              memset(&ustr, 0, sizeof(ustr));
              if (ssh_registry_unicode_string_get(key, L"GUID", &ustr))
                {
                  NTSTATUS st = RtlGUIDFromString(&ustr, &if_map->u.guid);
                  ssh_free(ustr.Buffer);
                  if ((st != STATUS_SUCCESS)
                      || (memcmp(&if_map->u.guid, 
                                 &zero_guid, sizeof(GUID)) == 0))
                    {
                      ssh_free(if_map);
                      continue;
                    }
                  if_map->type = SSH_IF_NAME_MAPPING_TYPE_GUID;
                }
              else
              if (ssh_registry_unicode_string_get(key, L"Device",
                                                  &if_map->u.device))
                {
                  if_map->type = SSH_IF_NAME_MAPPING_TYPE_DEVICE;
                }
              else
                {
                  ssh_free(if_map);
                  continue;
                }

              ssh_registry_binary_data_get(key, L"timestamp", 
                                           &if_map->timestamp, 
                                           sizeof(if_map->timestamp));

              if_map->ifnum = ifnum;
              if_map->tentative = 0;
              interceptor->if_map[ifnum] = if_map;

              status = TRUE;
            }

          ssh_registry_key_close(key);
        }
    }

  return status;
}


Boolean
ssh_interceptor_add_interface_mapping(SshInterceptor interceptor,
                                      SshAdapter adapter)
{
  Boolean status = FALSE;
  SshIfNameMapping if_map;
  UNICODE_STRING device_name;
  void *old_device_name = NULL;
  Boolean use_guid = TRUE;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(adapter != NULL);

  if (memcmp(&adapter->guid, &zero_guid, sizeof(GUID)) == 0)
    {
      use_guid = FALSE;
      device_name.Buffer = ssh_calloc(1, adapter->orig_name.MaximumLength);
      if (device_name.Buffer)
        {
          memcpy(device_name.Buffer, adapter->orig_name.Buffer,
                 adapter->orig_name.Length);
          device_name.Length = adapter->orig_name.Length;
          device_name.MaximumLength = adapter->orig_name.MaximumLength;
        }
      else
        {
          SshIfNameMapping old_map;

          ssh_kernel_rw_mutex_lock_write(&interceptor->if_map_lock);
          old_map = interceptor->if_map[adapter->ifnum];
          interceptor->if_map[adapter->ifnum] = NULL;
          ssh_kernel_rw_mutex_unlock_write(&interceptor->if_map_lock);
          ssh_interceptor_free_interface_mapping(interceptor, old_map);
          return FALSE;
        }
    }

  ssh_kernel_rw_mutex_lock_write(&interceptor->if_map_lock);
  if_map = interceptor->if_map[adapter->ifnum];
  SSH_ASSERT(if_map != NULL);
  if_map->tentative = 0;

  /* We need to free the old device name if we are re-using old mapping */
  if (if_map->type == SSH_IF_NAME_MAPPING_TYPE_DEVICE)
    old_device_name = if_map->u.device.Buffer;
    
  if (use_guid)
    {
      if_map->type = SSH_IF_NAME_MAPPING_TYPE_GUID;
      if_map->u.guid = adapter->guid;
    }
  else
    {
      if_map->type = SSH_IF_NAME_MAPPING_TYPE_DEVICE;
      if_map->u.device = device_name;
    }
  if_map->ifnum = adapter->ifnum;
  SSH_ASSERT(sizeof(if_map->alias) >= sizeof(adapter->ssh_name));
  memcpy(if_map->alias, adapter->ssh_name, sizeof(adapter->ssh_name));
  ssh_interceptor_get_time(&if_map->timestamp, NULL);
  ssh_kernel_rw_mutex_unlock_write(&interceptor->if_map_lock);
  ssh_free(old_device_name);

  if (interceptor->if_map_key)
    {
      SshRegKey key;
      UNICODE_STRING guid_str;

      if (RtlStringFromGUID(&if_map->u.guid, &guid_str) != STATUS_SUCCESS)
        return FALSE;

      if (ssh_interceptor_open_if_map_key(interceptor, 
                                          if_map->ifnum,
                                          TRUE, &key))
        {
          UNICODE_STRING ustr;
          ANSI_STRING astr;

          RtlInitAnsiString(&astr, (PCSZ)if_map->alias);
          if (RtlAnsiStringToUnicodeString(&ustr, 
                                           &astr, TRUE) == STATUS_SUCCESS)
            {
              ssh_registry_unicode_string_set(key, L"Name", &ustr);

              switch (if_map->type)
                {
                case SSH_IF_NAME_MAPPING_TYPE_GUID:
                  ssh_registry_unicode_string_set(key, L"GUID", &guid_str);
                  break;

                case SSH_IF_NAME_MAPPING_TYPE_DEVICE:
                  ssh_registry_unicode_string_set(key, L"Device",
                                                  &if_map->u.device);
                  break;

                default:
                  SSH_NOTREACHED;
                  break;
                }

              ssh_registry_binary_data_set(key, L"timestamp", 
                                           &if_map->timestamp, 
                                           sizeof(if_map->timestamp));

              RtlFreeUnicodeString(&ustr);

              status = TRUE;
            }

          ssh_registry_key_close(key);
        }

      RtlFreeUnicodeString(&guid_str);
    }

  return status;
}


void
ssh_interceptor_free_interface_mapping(SshInterceptor interceptor,
                                       SshIfNameMapping if_map)
{
  SSH_ASSERT(interceptor != NULL);

  if (if_map == NULL)
    return;

  switch (if_map->type)
    {
    case SSH_IF_NAME_MAPPING_TYPE_GUID:
      break;

    case SSH_IF_NAME_MAPPING_TYPE_DEVICE:
      ssh_free(if_map->u.device.Buffer);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_free(if_map);
}
#endif /* HAS_INTERFACE_NAME_MAPPINGS */


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC

#pragma warning(push)
#pragma warning(disable : 4100)
static void 
ssh_va_ic_operation_complete(SshVirtualAdapterError error,
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

static void 
ssh_interceptor_power_state_callback(SshInterceptor interceptor,
                                     void *argument1,
                                     void *argument2)
{
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
  SshAdapter adapter;
  SshInterceptorIfnum ifnum;
  SshEvent wait_event;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_ASSERT(interceptor != NULL);

  switch ((SshUInt32)argument1)
    {
    case PO_CB_SYSTEM_STATE_LOCK:
      if (argument2 == 0)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("PowerStateCallback: System is going to low power "
                     "state soon!"));

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
          for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
            {
              adapter = ssh_adapter_ref_by_ifnum(interceptor, ifnum);

              if (adapter == NULL)
                continue;

              if (adapter->is_vnic && adapter->va != NULL)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Configuring down Virtual Adapter %d",
                             adapter->ifnum));

                  wait_event = ssh_event_create(0, NULL, NULL);
                  if (wait_event)
                    {
                      ssh_virtual_adapter_configure(
                                          adapter->interceptor,
                                          adapter->ifnum,
                                          SSH_VIRTUAL_ADAPTER_STATE_DOWN,
                                          0, NULL, NULL,
                                          ssh_va_ic_operation_complete,
                                          wait_event);

                      ssh_event_wait(1, &wait_event, NULL);
                      ssh_event_destroy(wait_event);
                    }
                }

              ssh_adapter_release(adapter);
            }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

          if (InterlockedExchange(&interceptor->entering_low_power_state, 
                                  TRUE) == FALSE)
            {
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("PowerStateCallback: suspending IP config thread"));

              ssh_task_suspend(&interceptor->ip_cfg_thread, 
                               SSH_TASK_WAIT_INFINITE);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("PowerStateCallback: System returned back from low "
                     "power state!"));

          if (InterlockedExchange(&interceptor->entering_low_power_state, 
                                  FALSE) != FALSE)
            {
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
              SSH_DEBUG(SSH_D_HIGHSTART,
                        ("PowerStateCallback: resuming IP config thread"));

              ssh_task_resume(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
            }
        }
      break;

    default:
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("PowerStateCallback: argument1=%u, argument2=%u",
                argument1, argument2));
      break;
    }
}


#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
static void
ssh_interceptor_ip_refresh_callback(SshInterceptor interceptor)
{
  SSH_IP_REFRESH_REQUEST(interceptor);
}

/* The "IP devices" associated with the IP config thread should be 
   suspended during pause and restart operations. */
#pragma warning(push)
#pragma warning(disable : 4100)
static void
ssh_interceptor_ip_cfg_thread_event_cb(SshTask task,
                                       SshTaskState new_state,
                                       void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;

  SSH_ASSERT(interceptor != NULL);

  switch (new_state)
    {
    case SSH_TASK_STATE_INITIALIZING:
    case SSH_TASK_STATE_PAUSING:
    case SSH_TASK_STATE_RESTARTING:
      ssh_ipdev_suspend(&interceptor->ip4_dev);
#if defined (WITH_IPV6)
      ssh_ipdev_suspend(&interceptor->ip6_dev);
#endif /* WITH_IPV6 */
      break;

    case SSH_TASK_STATE_PAUSED:
    case SSH_TASK_STATE_RUNNING:
      ssh_ipdev_resume(&interceptor->ip4_dev);
#if defined (WITH_IPV6)
      ssh_ipdev_resume(&interceptor->ip6_dev);
#endif /* WITH_IPV6 */
      break;
    
    case SSH_TASK_STATE_HALTED:
      break;

    default:
      SSH_NOTREACHED;
      break;
    }
}
#pragma warning(pop)

static void
ssh_interceptor_ip_cfg_changed(SshInterceptor interceptor)
{
  SshUInt32 changed = 0;
  SshUInt32 forced_refresh;
  SshUInt32 new_forced_refresh = 0;

  if (interceptor->use_polling_ip_refresh)
    {
      ssh_kernel_timeout_cancel(ssh_interceptor_ip_refresh_callback,
                                interceptor);
    }

  if (interceptor->pre_ip_refresh_fn != NULL_FNPTR)
    {
      if ((interceptor->pre_ip_refresh_fn)(interceptor) == FALSE)
        goto done;
    }

  if (ssh_ipdev_is_connected(&interceptor->ip4_dev) 
      || ssh_ipdev_connect(&interceptor->ip4_dev))
    {
      if (!ssh_ipdev_refresh(&interceptor->ip4_dev, &changed))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 refresh failed!"));
          NdisMSleep(10000);
          SSH_IP_REFRESH_REQUEST(interceptor);
          goto done;
        }
    }

#if defined (WITH_IPV6)
  if (ssh_ipdev_is_connected(&interceptor->ip6_dev) 
      || ssh_ipdev_connect(&interceptor->ip6_dev))
    {
      if (!ssh_ipdev_refresh(&interceptor->ip6_dev, &changed))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv6 refresh failed!"));
          NdisMSleep(10000);
          SSH_IP_REFRESH_REQUEST(interceptor);
          goto done;
        }
    }
#endif /* WITH_IPV6 */

  forced_refresh = InterlockedExchange(&interceptor->ip_refresh_type, 0);

  if ((forced_refresh & SSH_IP_REFRESH_INTERFACES)
      || (changed & (SSH_IP_CHANGED_INTERFACES | SSH_IP_CHANGED_ADDRESSES)))
    {
      if (!ssh_ip_interface_list_refresh(interceptor))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to refresh interface lists!"));
          new_forced_refresh |= SSH_IP_REFRESH_ALL;
          goto done;
        }
    }

  if ((forced_refresh & SSH_IP_REFRESH_ROUTES)
      || (changed & (SSH_IP_CHANGED_ROUTES | SSH_IP_CHANGED_ADDRESSES)))
    {
      if (!ssh_ip_routing_table_refresh(interceptor))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to refresh routing tables!"));
          new_forced_refresh |= SSH_IP_REFRESH_ROUTES | SSH_IP_REFRESH_REPORT;
          goto done;
        }
    }
  
  if ((forced_refresh & SSH_IP_REFRESH_REPORT)
      || (changed & (SSH_IP_CHANGED_INTERFACES | SSH_IP_CHANGED_ADDRESSES)))
    {
      if (!ssh_ip_interface_report_send(interceptor))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to generate interface report!"));
          new_forced_refresh |= SSH_IP_REFRESH_REPORT;
          goto done;
        }
    }

  SSH_DEBUG(SSH_D_MIDOK, ("ip_cfg_changed: success"));

  if (interceptor->post_ip_refresh_fn != NULL_FNPTR)
    (interceptor->post_ip_refresh_fn)(interceptor);

 done:
  if (new_forced_refresh)
    {
      NdisMSleep(10000);
      SSH_IP_FORCE_REFRESH_REQUEST(interceptor, new_forced_refresh);
    }

  if (interceptor->use_polling_ip_refresh)
    {
      ssh_kernel_timeout_register(interceptor->ip_refresh_interval, 0, 
                                  ssh_interceptor_ip_refresh_callback,
                                  interceptor);
    }
}
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */


void
ssh_interceptor_suspend_worker_threads(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Suspending worker threads"));

  InterlockedIncrement(&interceptor->routing_disable_count);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  if (interceptor->low_power_state)
    ssh_task_suspend(&interceptor->ip_cfg_thread, 5);
  else
    ssh_task_suspend(&interceptor->ip_cfg_thread, SSH_TASK_WAIT_INFINITE);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  if (interceptor->work_queue)
    ssh_ndis_wrkqueue_suspend(interceptor->work_queue);
}


void
ssh_interceptor_resume_worker_threads(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Resuming worker threads"));

  if (interceptor->work_queue)
    ssh_ndis_wrkqueue_resume(interceptor->work_queue);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  ssh_task_resume(&interceptor->ip_cfg_thread);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  InterlockedDecrement(&interceptor->routing_disable_count);
}

#ifdef DEBUG_LIGHT
int ssh_guid_render(unsigned char *buf, 
                    int buf_size, 
                    int precision,
                    void *datum)
{
  GUID *guid = (GUID *)datum;
  int len;

  ssh_snprintf(buf, buf_size + 1, 
               "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               guid->Data1, guid->Data2, guid->Data3,
               guid->Data4[0], guid->Data4[1],
               guid->Data4[2], guid->Data4[3],
               guid->Data4[4], guid->Data4[5],
               guid->Data4[6], guid->Data4[7]);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}
#endif /* DEBUG_LIGHT */


