/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of routines for loading, unloading
   and registering the kernel-mode NDIS intermediate driver for Windows 2000,
   Windows XP and Windows Server 2003 platforms. Also the functions that are
   specific to W2K interceptor are implemented here.

   Notes about the interceptor:

   1. Approach

   The implementation of W2K interceptor has been done using information
   provided by Microsoft(DDK documents, MS newgroups) and using public
   API (NDIS, OS kernel) provided by MS.

   2. Architechture

   The W2K interceptor is implemented as a kernel-mode, deserialized,
   intermediate NDIS Filter driver (SSHIPSEC.SYS) that is layered between
   protocol drivers and real network device drivers (Ethernet) or
   Microsoft's NDISWAN driver (NDISWAN.SYS). The NDISWAN driver
   is an NDIS intermediate driver that manages all dial-up connections
   (modem, ISDN etc...).

   2.1 Interfacing with Protocol Driver and Network Driver

   The driver includes the lower-edge API (lower_edge.h,lower_edge.c) that
   NDIS uses for communication with lower layer driver and the upper-edge
   API (upper_edge.h,upper_edge.c) that NDIS uses for communication with
   upper layer driver, respectively. These API functions are registered
   with NDIS when the driver is loaded.

   The driver creates "virtual adapter" objects (adapter.h, adapter.c)
   whenever the Windows PnP Manager notices that a networking device
   (ethernet adapter, modem, isdn adapter, etc...) where we are allowed
   to bind becomes available (dynamic binding). The binding rules are
   described in the installation scripts. The NDIS then uses these
   adapter objects to interpret all the communication between upper layer
   protocols and lower layer networking devices by using driver's upper
   layer and lower layer API functions.

   2.2 Network Packet Management

   For the NDIS packet management, each adapter object contains a
   Packet Manager (packet.h, packet.c) object that is utilized
   for NDIS_PACKET and NDIS_BUFFER processing.

   2.3 Network Packet Processing

   The driver creates interceptor object (interceptor_i.h, interceptor.c)
   when driver is loaded and this interceptor object acts as a placeholder
   for the adapter objects, engine object and I/O device object for
   policy manager communication. SshEngine is started when driver is
   loaded and stopped when driver is unloaded from the memory.

   The engine object (engine.h) does the actual work ie. it makes the
   encryption(decryption) of IP packets according to the rules set by the
   policy manager(PM). The implementation of engine is generic so that
   it does not contain any platform-specific code.

   2.4 Policy Manager Communication

   Policy Manager is a user-mode process that communicates with the
   engine via driver's I/O device object (iodevice.h, iodevice.c).
   This device object is created when IPSec driver is loaded.

   2.5 TCP/IPv4 (TCP/IPv6) stack communication

   To retrieve the IP network configuration (network interface and
   routing parameters) of local host the driver uses TDI API query
   information calls and device I/O calls when communicating with TCP/IP
   device driver.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor_i.h"
#include "sshencode.h"
#include "event_log.h"
#include "debug_trace.h"
#include "upper_edge.h"
#include "lower_edge.h"
#include "event.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorMain"


/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

NDIS_STATUS
DriverEntry(PDRIVER_OBJECT driver,
            PUNICODE_STRING reg_path);

static Boolean
ssh_winim_interceptor_init(SshInterceptor gen_interceptor,
                           void *init_context);

static void
ssh_winim_interceptor_uninit(SshInterceptor interceptor,
                             void *uninit_context);

static Boolean
ssh_winim_interceptor_start(SshInterceptor interceptor,
                              void *start_context);

static void
ssh_winim_interceptor_stop(SshInterceptor interceptor,
                           void *pause_context);

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DriverEntry()
  
  Driver loading routine. Driver is initialized by creating SshInterceptor
  object and then activating it.

  Arguments:
  driver - driver object reserved for us by OS
  registry_path - path into the W2K registry entry of this driver

  Returns:
  STATUS_SUCCESS - driver load succeeded
  STATUS_UNSUCCESSFUL - otherwise

  Notes:
  --------------------------------------------------------------------------*/
#pragma NDIS_INIT_FUNCTION(DriverEntry)
NDIS_STATUS
DriverEntry(PDRIVER_OBJECT driver,
            PUNICODE_STRING reg_path)
{
  SshInterceptorInitParamsStruct init_params;
  SshInterceptorStartParamsStruct start_params;
  SshNdisIMInterceptor interceptor;

  SSH_ASSERT(driver != NULL);
  SSH_ASSERT(reg_path != NULL);

  interceptor = ssh_calloc(1, sizeof(*interceptor));
  if (interceptor == NULL)
    return NDIS_STATUS_RESOURCES;

  memset(&init_params, 0x00, sizeof(init_params));
  init_params.driver_object = driver;
  init_params.registry_path = reg_path;
  init_params.packet_pool_constructor = ssh_packet_pools_create;
  init_params.packet_pool_destructor = ssh_packet_pools_destroy;

  if (!ssh_interceptor_init_common((SshInterceptor)interceptor, 
                                   &init_params, 
                                   ssh_winim_interceptor_init,
                                   NULL))
    return NDIS_STATUS_FAILURE;

  memset(&start_params, 0x00, sizeof(start_params));
  start_params.raise_irql_on_pm_engine_calls = 1;
  start_params.use_polling_ip_refresh = 1;
  start_params.ip_refresh_interval = 2;
  if (!ssh_interceptor_restart_common((SshInterceptor)interceptor,
                                      &start_params,
                                      ssh_winim_interceptor_start,
                                      NULL))
   {
      ssh_interceptor_uninit_common((SshInterceptor)interceptor,
                                    ssh_winim_interceptor_uninit,
                                    NULL);
      return NDIS_STATUS_FAILURE; 
    }





  interceptor->init_complete = TRUE;

  return NDIS_STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
  DriverUnload()
  
  This function is executed when OS unloads this driver or if the driver 
  loading is failed. All the resources allocated for the driver are freed.

  Arguments:
  driver - driver object

  Returns:
  Notes:
  --------------------------------------------------------------------------*/
VOID
DriverUnload(PDRIVER_OBJECT driver)
{
  SshNdisIMInterceptor interceptor;

  interceptor = (SshNdisIMInterceptor)the_interceptor;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Unloading interceptor, state = %u", interceptor->state));

  SSH_ASSERT(interceptor != NULL);

  ssh_interceptor_pause_common((SshInterceptor)interceptor,
                               ssh_winim_interceptor_stop,
                               NULL);
  ssh_interceptor_uninit_common((SshInterceptor)interceptor,
                                ssh_winim_interceptor_uninit,
                                NULL);
  ssh_free(interceptor);




}

/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static Boolean
ssh_winim_interceptor_init(SshInterceptor gen_interceptor,
                           void *init_context)
{
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)gen_interceptor;
  SshTCBStruct tcb;
  char* err_msg = "\0";

  SSH_ASSERT(interceptor != NULL);

  /* Set initial state */
  interceptor->delayed_sends = 0;
  interceptor->net_providers = 0;
  interceptor->net_ready = FALSE;
  interceptor->init_complete = FALSE;

  NdisZeroMemory(&tcb, sizeof(tcb));
  tcb.priority = SSH_TASK_PRIORITY_HIGH;
  tcb.exec_type = SSH_TASK_TYPE_EVENT_MONITOR;
  tcb.period_ms = SSH_TASK_EVENT_WAIT_INFINITE;
  if (!ssh_task_init(&interceptor->delayed_send_thread,
                     SSH_DELAYED_SEND_THREAD_ID,
                     ssh_driver_delayed_send_thread, 
                     interceptor, &tcb))
    {
      err_msg = "Interceptor: Failed to create delayed send thread!";
      goto failed;
    }

  return TRUE;

failed:

  ssh_winim_interceptor_uninit((SshInterceptor)interceptor, NULL);
  ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_CRITICAL, err_msg);
  return FALSE;
}


static void
ssh_winim_interceptor_uninit(SshInterceptor gen_interceptor,
                             void *uninit_context)
{
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)gen_interceptor;

  SSH_ASSERT(interceptor != NULL);

  ssh_task_uninit(&interceptor->delayed_send_thread);

}


static Boolean
ssh_winim_interceptor_start(SshInterceptor gen_interceptor,
                            void *start_context)
{
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)gen_interceptor;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  char* err_msg = "\0";

  SSH_ASSERT(interceptor != NULL);

  /* Register upper edge handlers with NDIS to enable communication
     with protocol driver */
  status = ssh_interceptor_register_upper_edge(interceptor, TRUE);
  if (!NT_SUCCESS(status))
    {
      err_msg = "Interceptor: Miniport handler registration failed"; 
      goto failed;
    }

  /* Register lower edge handlers with NDIS to enable communication
     with network device driver */
  status = ssh_interceptor_register_lower_edge(interceptor, TRUE);
  if (!NT_SUCCESS(status))
    {
      err_msg = "Interceptor: Protocol handler registration failed"; 
      goto failed;
    }

  /* Associate upper and lower edge so that NDIS knows that they 
     belong to the same driver */
  NdisIMAssociateMiniport(interceptor->miniport_handle,
                          interceptor->protocol_handle);

  /* TDI registration */
  status = ssh_interceptor_register_stack_notifications(interceptor, TRUE);
  if (!NT_SUCCESS(status))
    {
      err_msg = "Interceptor: TDI handler registration failed";
      goto failed;
    }

  ssh_task_start(&interceptor->delayed_send_thread);

  return TRUE;

 failed:
  ssh_log_event(SSH_LOGFACILITY_LOCAL0, SSH_LOG_CRITICAL, err_msg);
  return FALSE;
}


static void
ssh_winim_interceptor_stop(SshInterceptor gen_interceptor,
                           void *pause_context)
{
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)gen_interceptor;

  SSH_ASSERT(interceptor != NULL);

  ssh_interceptor_register_stack_notifications(interceptor, FALSE);
  ssh_interceptor_register_lower_edge(interceptor, FALSE);
  ssh_interceptor_register_upper_edge(interceptor, FALSE);

  ssh_task_stop(&interceptor->delayed_send_thread);

}


