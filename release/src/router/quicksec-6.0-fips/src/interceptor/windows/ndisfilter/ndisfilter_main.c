/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of routines for loading, unloading
   and registering the NDIS 6.0 filter driver for Windows Vista client and
   Windows Server 2008 platforms.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  ------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#include "wan_interface.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
#include "event.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "sshvnic_def.h"
#include "virtual_adapter_private.h"
#include "device_io.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#include "kernel_timeouts.h"
#include <netioapi.h>

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorMain"

typedef struct SshAddressAddContextRec
{
  SshNdisFilterInterceptor interceptor;
  MIB_UNICASTIPADDRESS_ROW row;
  SshUInt32 ttl;
} SshAddressAddContextStruct, *SshAddressAddContext;

/*--------------------------------------------------------------------------
  EXTERNAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

extern Boolean
ssh_interceptor_packet_done_iteration_read(SshInterceptorPacket ip,
  const UCHAR** buf,
  size_t* len);

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#define SSH_FILTER_FRIENDLY_NAME  L"INSIDE Secure QuickSec"
/* Unique name MUST be equal to NetCfgInstanceId in QuickSec.inf */
#define SSH_FILTER_UNIQUE_NAME    L"{1f6466bb-6e61-4626-bed7-c09c7708ad22}" 
#define SSH_FILTER_SERVICE_NAME   L"QUICKSEC"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */


/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static inline Boolean 
packet_is_ieee802_3_passthrough_allowed(SshNdisPacket packet)
{
  Boolean pass = FALSE;

  SSH_ASSERT(packet != NULL);

  /* Windows HCK testing - PacketMTUSize: 
     Ethernet header has ethernet type/length field (2 bytes)
     that is used to identify ethernet type or packet length.
     Maximum packet size for ethernet frames is 1500.
     If underlaying adapter supports large receive offload
     then ethernet header of received packet seems to
     contain packet size.
  
     Packet processing engine does not recognize these large packets and 
     drops them so we have to pass them. */

  if (packet->eth_type <= 1500)
    {
      pass = TRUE;
    }
  else
    {
      /* pass all but IPv4, IPv6, ARP, RARP */
      pass = ((packet->eth_type != SSH_ETHERTYPE_IP)
        && (packet->eth_type != SSH_ETHERTYPE_IPv6)
        && (packet->eth_type != SSH_ETHERTYPE_ARP)
        && (packet->eth_type != SSH_ETHERTYPE_REVARP));
    }
  return pass;
}

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

NDIS_STATUS
DriverEntry(PDRIVER_OBJECT driver,
            PUNICODE_STRING reg_path);

DRIVER_UNLOAD ssh_filter_unload;

/* Mandatory NDIS 6.0 filter driver functions */
static NDIS_STATUS
ssh_filter_attach(NDIS_HANDLE ndis_filter_handle,
                  NDIS_HANDLE filter_driver_context,
                  PNDIS_FILTER_ATTACH_PARAMETERS attach_params);

static VOID
ssh_filter_detach(NDIS_HANDLE filter_module_context);

static NDIS_STATUS
ssh_filter_pause(NDIS_HANDLE filter_module_context,
                 PNDIS_FILTER_PAUSE_PARAMETERS pause_params); 

static NDIS_STATUS
ssh_filter_restart(NDIS_HANDLE filter_module_context,
                   PNDIS_FILTER_RESTART_PARAMETERS restart_params);


/* Optional NDIS 6.0 filter driver functions implemented by our
   packet interceptor. */
static NDIS_STATUS
ssh_filter_oid_request(NDIS_HANDLE filter_module_context,
                       PNDIS_OID_REQUEST oid_request);

static VOID
ssh_filter_cancel_oid_request(NDIS_HANDLE filter_module_context,
                              PVOID request_id);

static VOID
ssh_filter_oid_request_complete(NDIS_HANDLE filter_module_context,
                                PNDIS_OID_REQUEST oid_request,
                                NDIS_STATUS status);

static VOID
ssh_filter_send(NDIS_HANDLE filter_module_context,
                PNET_BUFFER_LIST net_buffer_lists,
                NDIS_PORT_NUMBER port_number,
                ULONG send_flags);

static VOID
ssh_filter_cancel_send(NDIS_HANDLE filter_module_context,
                       PVOID cancel_id);

static VOID
ssh_filter_send_complete(NDIS_HANDLE filter_module_context,
                         PNET_BUFFER_LIST net_buffer_lists,
                         ULONG send_complete_flags);

static VOID
ssh_filter_receive(NDIS_HANDLE filter_module_context,
                   PNET_BUFFER_LIST net_buffer_lists,
                   NDIS_PORT_NUMBER port_number,
                   ULONG number_of_nblists,
                   ULONG receive_flags);

static VOID
ssh_filter_receive_complete(NDIS_HANDLE filter_module_context,
                            PNET_BUFFER_LIST net_buffer_lists,
                            ULONG return_flags);

static NDIS_STATUS
ssh_filter_net_pnp_event(NDIS_HANDLE filter_module_context,
                         PNET_PNP_EVENT_NOTIFICATION pnp_event);

static VOID
ssh_filter_status(NDIS_HANDLE filter_module_context,
                  PNDIS_STATUS_INDICATION status_indication);


/* Optional NDIS 6.1 filter driver functions implemented by our
   packet interceptor. */
static NDIS_STATUS
ssh_filter_direct_oid_request(NDIS_HANDLE filter_module_context,
                              PNDIS_OID_REQUEST oid_request);

static VOID
ssh_filter_cancel_direct_oid_request(NDIS_HANDLE filter_module_context,
                                     PVOID request_id);

static VOID
ssh_filter_direct_oid_request_complete(NDIS_HANDLE filter_module_context,
                                       PNDIS_OID_REQUEST oid_request,
                                       NDIS_STATUS status);

/* Interceptor specific functions that are called from common interceptor
   code to perform NDIS filter driver specific initialization/
   uninitialization. */
static Boolean
ssh_filter_init_interceptor(SshInterceptor generic_interceptor,
                            void *context);

static Boolean
ssh_filter_restart_interceptor(SshInterceptor generic_interceptor,
                               void *context);

static void
ssh_filter_pause_interceptor(SshInterceptor generic_interceptor,
                             void *context);

static void
ssh_filter_uninit_interceptor(SshInterceptor generic_interceptor,
                              void *context);

/* Interceptor specific functions that are called from common adapter 
   code to perform NDIS filter driver specific operations. */
static void
ssh_filter_attach_adapter(SshAdapter generic_adapter,
                          void *context,
                          SshAdapterAttachCompleteCb callback,
                          void *callback_context);

static void
ssh_filter_pause_adapter(SshAdapter generic_adapter,
                         void *pause_context,
                         SshAdapterPauseCompleteCb callback,
                         void *callback_context);

static void
ssh_filter_restart_adapter(SshAdapter generic_adapter,
                           void *restart_context,
                           SshAdapterRestartCompleteCb callback,
                           void *callback_context);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
static void
ssh_address_valid_timeout(void *context);

/* IP address and routing table notification handlers */
static void
ssh_filter_address_change_notify(SshNdisFilterInterceptor interceptor,
                                 PMIB_UNICASTIPADDRESS_ROW row,
                                 MIB_NOTIFICATION_TYPE notification_type);

static void
ssh_filter_route_change_notify(SshNdisFilterInterceptor interceptor,
                               PMIB_IPFORWARD_ROW2 row,
                               MIB_NOTIFICATION_TYPE notification_type);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  -------------------------------------------------------------------------*/

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
  SshNdisFilterInterceptor interceptor;

  interceptor = ssh_calloc(1, sizeof(*interceptor));
  if (interceptor == NULL)
    return NDIS_STATUS_RESOURCES;

  NdisZeroMemory(&init_params, sizeof(init_params));
  init_params.driver_object = driver;
  init_params.registry_path = reg_path;
  init_params.packet_pool_constructor = ssh_packet_pools_create;
  init_params.packet_pool_destructor = ssh_packet_pools_destroy;
  if (!ssh_interceptor_init_common((SshInterceptor)interceptor, 
                                   &init_params, 
                                   ssh_filter_init_interceptor,
                                   NULL))
    {
      return NDIS_STATUS_FAILURE; 
    }

  NdisZeroMemory(&start_params, sizeof(start_params));
  start_params.create_io_device = 1;
  start_params.raise_irql_on_pm_engine_calls = 1;
  start_params.asynch_interceptor_route = 1;
  start_params.use_polling_ip_refresh = 0;
  if (!ssh_interceptor_restart_common((SshInterceptor)interceptor,
                                      &start_params,
                                      ssh_filter_restart_interceptor,
                                      NULL))
   {
      ssh_interceptor_uninit_common((SshInterceptor)interceptor,
                                    ssh_filter_uninit_interceptor,
                                    NULL);
      return NDIS_STATUS_FAILURE; 
    }





  return NDIS_STATUS_SUCCESS;
}                     

/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/
#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_unload)

#pragma warning(disable : 4100)
VOID
ssh_filter_unload(PDRIVER_OBJECT driver)
{
  SshNdisFilterInterceptor interceptor;

  interceptor = (SshNdisFilterInterceptor)the_interceptor;

  PAGED_CODE();
  SSH_ASSERT(interceptor != NULL);

  ssh_interceptor_pause_common((SshInterceptor)interceptor,
                               ssh_filter_pause_interceptor,
                               NULL);
  ssh_interceptor_uninit_common((SshInterceptor)interceptor,
                                ssh_filter_uninit_interceptor,
                                NULL);
  ssh_free(interceptor);




}
#pragma warning(default : 4100)

#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_attach)

static NDIS_STATUS
ssh_filter_attach(NDIS_HANDLE ndis_filter_handle,
                  NDIS_HANDLE filter_driver_context,
                  PNDIS_FILTER_ATTACH_PARAMETERS attach_params)
{
  SshInterceptor interceptor = (SshInterceptor)filter_driver_context;
  SshAdapterInitParamsStruct init_params;
  SshAdapterEnableFlags features;
  SshNdisFilterAdapter adapter;

  PAGED_CODE();
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor == the_interceptor);

  adapter = ssh_calloc(1, sizeof(*adapter));
  if (adapter == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0, 
                    SSH_LOG_CRITICAL,
                    ("Failed to allocate adapter object!")); 
      return NDIS_STATUS_RESOURCES;
    }

  InitializeListHead(&adapter->oid_request_list);
  ssh_kernel_mutex_init(&adapter->oid_request_list_lock);

  memset(&init_params, 0x00, sizeof(init_params));
  init_params.name = attach_params->BaseMiniportName->Buffer
                       + SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET;
  init_params.name_len = attach_params->BaseMiniportName->Length
                           - (SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET 
                              * sizeof(WCHAR));
  ConvertInterfaceLuidToGuid(&attach_params->NetLuid, &init_params.guid);

  /* Everything disabled in DETACHED state */

  /* Everything disabled in ATTACHING state */

  /* Features enabled in PAUSED state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_PAUSED];
  features->flags.allow_oid_requests = 1;

  /* Features enabled in RESTARTING state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];
  features->flags.allow_initiate_oid_requests = 1;
  features->flags.allow_oid_requests = 1;
  features->flags.allow_initiate_status_indications = 1;
  features->flags.allow_status_indications = 1;  

  /* Everything enabled in RUNNING state */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_RUNNING];
  *features = init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];
  features->flags.allow_initiate_receive_indications = 1;
  features->flags.allow_receive = 1;
  features->flags.allow_initiate_send = 1;
  features->flags.allow_send = 1;

  /* Features enabled in PAUSING state (same than restarting) */
  features = &init_params.feature_flags[SSH_ADAPTER_STATE_PAUSING];
  *features = init_params.feature_flags[SSH_ADAPTER_STATE_RESTARTING];

  if (!ssh_adapter_init_common((SshAdapter)adapter,
                               interceptor,
                               &init_params))  
    {
      ssh_free(adapter);
      return NDIS_STATUS_FAILURE;
    }

  adapter->handle = ndis_filter_handle;

  if (!ssh_adapter_attach_common((SshAdapter)adapter,
                                 ssh_filter_attach_adapter,
                                 attach_params))
    {
      ssh_adapter_uninit_common((SshAdapter)adapter);
      ssh_free(adapter);
      return NDIS_STATUS_FAILURE;
    }

  return NDIS_STATUS_SUCCESS;
}


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_detach)

static VOID
ssh_filter_detach(NDIS_HANDLE filter_module_context)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;

  PAGED_CODE();
  SSH_ASSERT(adapter != NULL);

  ssh_adapter_detach_common((SshAdapter)adapter, NULL_FNPTR, NULL);
  ssh_adapter_uninit_common((SshAdapter)adapter);

  ssh_kernel_mutex_uninit(&adapter->oid_request_list_lock);

  ssh_free(adapter);
}

#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_pause)

static NDIS_STATUS
ssh_filter_pause(NDIS_HANDLE filter_module_context,
                 PNDIS_FILTER_PAUSE_PARAMETERS pause_params)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  SshAdapterPauseReason reason;

  PAGED_CODE();
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(pause_params != NULL);

  switch (pause_params->PauseReason)
    {
    case NDIS_PAUSE_BIND_PROTOCOL:
      reason = SSH_ADAPTER_PAUSE_REASON_BIND_PROTOCOL;
      break;

    case NDIS_PAUSE_UNBIND_PROTOCOL:
      reason = SSH_ADAPTER_PAUSE_REASON_UNBIND_PROTOCOL;
      break;

    case NDIS_PAUSE_ATTACH_FILTER:
      reason = SSH_ADAPTER_PAUSE_REASON_ATTACH_INTERCEPTOR;
      break;

    case NDIS_PAUSE_DETACH_FILTER:
      reason = SSH_ADAPTER_PAUSE_REASON_DETACH_INTERCEPTOR;
      break;

    case NDIS_PAUSE_FILTER_RESTART_STACK:
      reason = SSH_ADAPTER_PAUSE_REASON_RESTART_STACK;
      break;

    case NDIS_PAUSE_LOW_POWER:
      reason = SSH_ADAPTER_PAUSE_REASON_LOW_POWER;
      break;

    case NDIS_PAUSE_NDIS_INTERNAL:
    case NDIS_PAUSE_MINIPORT_DEVICE_REMOVE:
    default:
      reason = SSH_ADAPTER_PAUSE_REASON_UNSPECIFIED;
      break;
    }

  ssh_adapter_pause_common((SshAdapter)adapter, reason,
                           ssh_filter_pause_adapter, pause_params);

  return NDIS_STATUS_SUCCESS;
}


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_restart)

static NDIS_STATUS
ssh_filter_restart(NDIS_HANDLE filter_module_context,
                   PNDIS_FILTER_RESTART_PARAMETERS restart_params)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  NDIS_STATUS status;

  PAGED_CODE();
  SSH_ASSERT(adapter != NULL);

  if (!ssh_adapter_restart_common((SshAdapter)adapter,
                                  ssh_filter_restart_adapter,
                                  restart_params))
    status = NDIS_STATUS_FAILURE;
  else
    status = NDIS_STATUS_SUCCESS;

  return status;
}


static NDIS_STATUS
ssh_filter_oid_request(NDIS_HANDLE filter_module_context,
                       PNDIS_OID_REQUEST request)
{
  NDIS_STATUS status;
  PNDIS_OID_REQUEST clone;
  PNDIS_OID_REQUEST *context;
  NDIS_OID oid;

  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: OID request(%@, OID=%@)",
             ssh_adapter_id_st_render, adapter,
             ssh_ndis_oid_request_type_render, &request->RequestType,
             ssh_ndis_oid_render, &request->DATA.SET_INFORMATION.Oid));
  
  /* If this adapter is less than major version 6, 
     disable offloads. */
  if (adapter->ndis_version < SSH_NDIS_VERSION_6)
    {
      oid = 0;
      if (request->RequestType == NdisRequestQueryInformation)
        oid = request->DATA.QUERY_INFORMATION.Oid;
      else if (request->RequestType == NdisRequestSetInformation)
        oid = request->DATA.SET_INFORMATION.Oid;

      switch (oid)
        {
        case OID_TCP_OFFLOAD_CURRENT_CONFIG:
        case OID_TCP_OFFLOAD_HARDWARE_CAPABILITIES:
        case OID_TCP_OFFLOAD_PARAMETERS:
        case OID_OFFLOAD_ENCAPSULATION:
        case OID_TCP_CONNECTION_OFFLOAD_CURRENT_CONFIG:
        case OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES:
        case OID_TCP_CONNECTION_OFFLOAD_PARAMETERS:
          return NDIS_STATUS_NOT_SUPPORTED;
        }
    }

  status = NdisAllocateCloneOidRequest(adapter->handle, 
                                       request, 'TNFS', &clone);
  if (status != NDIS_STATUS_SUCCESS)
    {
      switch (request->RequestType)
        {
        case NdisRequestMethod:
          request->DATA.METHOD_INFORMATION.BytesRead = 0;
          request->DATA.METHOD_INFORMATION.BytesWritten = 0;
          request->DATA.METHOD_INFORMATION.BytesNeeded = 0;
          break;

        case NdisRequestSetInformation:
          request->DATA.SET_INFORMATION.BytesRead = 0;
          request->DATA.SET_INFORMATION.BytesNeeded = 0;
          break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
        default:
          request->DATA.QUERY_INFORMATION.BytesWritten = 0;
          request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
          break;
        }

      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to clone OID request!",
                 ssh_adapter_id_st_render, adapter));
      return status;
    }

  SSH_ASSERT(sizeof(*context) <= sizeof(clone->SourceReserved));
  context = (PNDIS_OID_REQUEST *)&clone->SourceReserved[0];
  *context = request;
  clone->RequestId = request->RequestId;

  status = NdisFOidRequest(adapter->handle, clone);
  if (status != NDIS_STATUS_PENDING)
    ssh_filter_oid_request_complete(filter_module_context, clone, status);

  return NDIS_STATUS_PENDING;
}


static VOID
ssh_filter_oid_request_complete(NDIS_HANDLE filter_module_context,
                                PNDIS_OID_REQUEST request,
                                NDIS_STATUS status)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  PNDIS_OID_REQUEST *context;
  PNDIS_OID_REQUEST orig;
  PLIST_ENTRY entry;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: OID request (%@, OID=%@) complete, status=%@",
             ssh_adapter_id_st_render, adapter,
             ssh_ndis_oid_request_type_render, &request->RequestType,
             ssh_ndis_oid_render, &request->DATA.SET_INFORMATION.Oid,
             ssh_ndis_status_render, &status));

  ssh_kernel_mutex_lock(&adapter->oid_request_list_lock);
  entry = adapter->oid_request_list.Flink;
  while (entry != &adapter->oid_request_list)
    {
      SshInterceptorOidRequest oid_request;

      oid_request = 
        CONTAINING_RECORD(entry, SshInterceptorOidRequestStruct, link);

      if (request == &oid_request->native_oid_request)
        {
          ssh_kernel_mutex_unlock(&adapter->oid_request_list_lock);
          oid_request->request->status = status;
          ssh_event_signal(oid_request->completion_event);
          return;
        }

      entry = entry->Flink;
    }
  ssh_kernel_mutex_unlock(&adapter->oid_request_list_lock);

  SSH_ASSERT(sizeof(*context) <= sizeof(request->SourceReserved));
  context = (PNDIS_OID_REQUEST *)&request->SourceReserved[0];
  orig = *context;
  *context = NULL;

  SSH_ASSERT(orig != NULL);

  /* Copy the information from cloned request to the original one */
  switch (request->RequestType)
    {
    case NdisRequestMethod:
      {
        struct _METHOD *dst = &orig->DATA.METHOD_INFORMATION;
        struct _METHOD *src = &request->DATA.METHOD_INFORMATION;

        dst->OutputBufferLength = src->OutputBufferLength;
        dst->BytesRead = src->BytesRead;
        dst->BytesWritten = src->BytesWritten;
        dst->BytesNeeded = src->BytesNeeded;
      }
      break;

    case NdisRequestSetInformation:
      {
        struct _SET *dst = &orig->DATA.SET_INFORMATION;
        struct _SET *src = &request->DATA.SET_INFORMATION;

        dst->BytesRead = src->BytesRead;
        dst->BytesNeeded = src->BytesNeeded;

        switch (src->Oid)
          {
          case OID_PNP_SET_POWER:
            {
              NDIS_DEVICE_POWER_STATE power;

              power = *((PNDIS_DEVICE_POWER_STATE)src->InformationBuffer);

              if (power == NdisDeviceStateD3)
                {
                  ssh_adapter_wait_until_state_transition_complete(
                                                     (SshAdapter)adapter);
                  ssh_interceptor_suspend_if_idle(adapter->interceptor);
                }
            }
            break;

          case OID_GEN_CURRENT_PACKET_FILTER:
            if (status == NDIS_STATUS_SUCCESS)
              {









                /* Look if someone tries to set adapter into promisc mode. 
                   Look for more in ssh_filter_receive how the packet can
                   be handled. */
                SshUInt32 *data;

                data = request->DATA.SET_INFORMATION.InformationBuffer;
                if ((*data) & NDIS_PACKET_TYPE_PROMISCUOUS)
                  adapter->promiscuous_mode = 1;
                else
                  adapter->promiscuous_mode = 0;

                SSH_DEBUG(SSH_D_NICETOKNOW, 
                          ("Adapter %@: packet filter = 0x%08X {%@}",
                           ssh_adapter_id_st_render, adapter,
                           *data,
                           ssh_ndis_packet_filter_bits_render, data));
              }
            break;

          default:
            break;
          }
      }
      break;

    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    default:
      {
        struct _QUERY *dst = &orig->DATA.QUERY_INFORMATION;
        struct _QUERY *src = &request->DATA.QUERY_INFORMATION;

        dst->BytesWritten = src->BytesWritten;
        dst->BytesNeeded = src->BytesNeeded;
      }
      break;
    }

  NdisFreeCloneOidRequest(adapter->handle, request);
  NdisFOidRequestComplete(adapter->handle, orig, status);
}


static VOID
ssh_filter_cancel_oid_request(NDIS_HANDLE filter_module_context,
                              PVOID request_id)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;





  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: Trying to cancel OID request (ID=0x%p)",
             ssh_adapter_id_st_render, adapter, request_id));
}


static NDIS_STATUS
ssh_filter_direct_oid_request(NDIS_HANDLE filter_module_context,
                              PNDIS_OID_REQUEST request)
{
  NDIS_STATUS status;
  PNDIS_OID_REQUEST clone;
  PNDIS_OID_REQUEST *context;

  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Direct OID request(%@, OID=%@)",
             ssh_adapter_id_st_render, adapter,
             ssh_ndis_oid_request_type_render, &request->RequestType,
             ssh_ndis_oid_render, &request->DATA.SET_INFORMATION.Oid));

  status = NdisAllocateCloneOidRequest(adapter->handle, 
                                       request, 'TNFS', &clone);
  if (status != NDIS_STATUS_SUCCESS)
    {
      switch (request->RequestType)
        {
        case NdisRequestMethod:
          request->DATA.METHOD_INFORMATION.BytesRead = 0;
          request->DATA.METHOD_INFORMATION.BytesWritten = 0;
          request->DATA.METHOD_INFORMATION.BytesNeeded = 0;
          break;

        case NdisRequestSetInformation:
          request->DATA.SET_INFORMATION.BytesRead = 0;
          request->DATA.SET_INFORMATION.BytesNeeded = 0;
          break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
        default:
          request->DATA.QUERY_INFORMATION.BytesWritten = 0;
          request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
          break;
        }

      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to clone direct OID request!",
                 ssh_adapter_id_st_render, adapter));
      return status;
    }

  SSH_ASSERT(sizeof(*context) <= sizeof(clone->SourceReserved));
  context = (PNDIS_OID_REQUEST *)&clone->SourceReserved[0];
  *context = request;
  clone->RequestId = request->RequestId;

  status = NdisFDirectOidRequest(adapter->handle, clone);
  if (status != NDIS_STATUS_PENDING)
    {
      ssh_filter_direct_oid_request_complete(filter_module_context, 
                                             clone, 
                                             status);
    }

  return NDIS_STATUS_PENDING;
}


static VOID
ssh_filter_direct_oid_request_complete(NDIS_HANDLE filter_module_context,
                                       PNDIS_OID_REQUEST request,
                                       NDIS_STATUS status)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  PNDIS_OID_REQUEST *context;
  PNDIS_OID_REQUEST orig;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
           ("Adapter %@: direct OID request (%@, OID=%@) complete, status=%@",
            ssh_adapter_id_st_render, adapter,
            ssh_ndis_oid_request_type_render, &request->RequestType,
            ssh_ndis_oid_render, &request->DATA.SET_INFORMATION.Oid,
            ssh_ndis_status_render, &status));

  SSH_ASSERT(sizeof(*context) <= sizeof(request->SourceReserved));
  context = (PNDIS_OID_REQUEST *)&request->SourceReserved[0];
  orig = *context;
  *context = NULL;

  SSH_ASSERT(orig != NULL);

  /* Copy the information from cloned request to the original one */
  switch (request->RequestType)
    {
    case NdisRequestMethod:
      {
        struct _METHOD *dst = &orig->DATA.METHOD_INFORMATION;
        struct _METHOD *src = &request->DATA.METHOD_INFORMATION;

        dst->OutputBufferLength = src->OutputBufferLength;
        dst->BytesRead = src->BytesRead;
        dst->BytesWritten = src->BytesWritten;
        dst->BytesNeeded = src->BytesNeeded;
      }
      break;

    case NdisRequestSetInformation:
      {
        struct _SET *dst = &orig->DATA.SET_INFORMATION;
        struct _SET *src = &request->DATA.SET_INFORMATION;

        dst->BytesRead = src->BytesRead;
        dst->BytesNeeded = src->BytesNeeded;

        if (src->Oid == OID_PNP_SET_POWER)
          {
            NDIS_DEVICE_POWER_STATE power;

            power = *((PNDIS_DEVICE_POWER_STATE)src->InformationBuffer);

            if (power == NdisDeviceStateD3)
              {
                ssh_adapter_wait_until_state_transition_complete(
                                                   (SshAdapter)adapter);
                ssh_interceptor_suspend_if_idle(adapter->interceptor);
              }
          }
      }
      break;

    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    default:
      {
        struct _QUERY *dst = &orig->DATA.QUERY_INFORMATION;
        struct _QUERY *src = &request->DATA.QUERY_INFORMATION;

        dst->BytesWritten = src->BytesWritten;
        dst->BytesNeeded = src->BytesNeeded;
      }
      break;
    }

  NdisFreeCloneOidRequest(adapter->handle, request);
  NdisFDirectOidRequestComplete(adapter->handle, orig, status);
}


static VOID
ssh_filter_cancel_direct_oid_request(NDIS_HANDLE filter_module_context,
                                     PVOID request_id)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;





  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: Trying to cancel direct OID request (ID=0x%p)",
             ssh_adapter_id_st_render, adapter, request_id));
}

void
ssh_interceptor_flush_packet_queue(SshInterceptor interceptor,
				   SshPacketQueue queue,
				   Boolean send)
{
  SshNdisFilterAdapter adapter;
  NET_BUFFER_LIST *nbl_list;
  NET_BUFFER_LIST *prev_nbl;
  NDIS_PORT_NUMBER port_number; 
  SshNdisPacket packet;
  SshUInt32 i;
  SshUInt32 packet_count;
  SshUInt32 packets_left;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Processing queued packets now..."));
  
  if (send == TRUE)
    {
      for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
	{
	  adapter = (SshNdisFilterAdapter)interceptor->adapter_table[i];
	  
	  if (adapter != NULL)
	    {
	      ULONG send_flags; 
	      
	      packet = 
		(SshNdisPacket)ssh_net_packet_list_dequeue(&queue[i],
							   &packets_left);
	      while (packet)
		{
		  prev_nbl = NULL;
		  nbl_list = NULL;
#ifdef DEBUG_LIGHT
		  packet_count = 0;
#endif /* DEBUG_LIGHT */
		  
		  while (packet)
		    {
		      if (prev_nbl)
			{
			  if ((packet->port_number != port_number)
			      || (packet->transfer_flags != send_flags))
			    {
			      /* Port number or flags differ; we must 
				 send collected NBL list now (before 
				 processing this packet) */
			      break;
			    }
			  
			  prev_nbl->Next = packet->np;
			}
		      else
			{
			  nbl_list = packet->np;
			  port_number = packet->port_number;
			  send_flags = packet->transfer_flags;
			}
		      prev_nbl = packet->np;
		      
#ifdef DEBUG_LIGHT
		      packet->f.flags.in_send_queue = 0;
		      packet->f.flags.in_miniport = 1;
		      packet_count++;
		      packets_left--;
#endif /* DEBUG_LIGHT */
		      packet = packet->next;
		    }
		  
		  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Adapter %@: sending %u NET_BUFFER_LIST(s), "
			     "%u NBL(s) remaining",
			     ssh_adapter_id_st_render, adapter, 
			     packet_count, packets_left));
		  
		  NdisFSendNetBufferLists(adapter->handle,
					  nbl_list,
					  port_number,
					  send_flags);
		}
	      
	      SSH_ASSERT(packets_left == 0);
	    }
	}
    }
  else
    {
      for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
	{
	  adapter = (SshNdisFilterAdapter)interceptor->adapter_table[i];
	  
	  if (adapter != NULL)
	    {
	      ULONG receive_flags;
	      
	      packet = 
		(SshNdisPacket)ssh_net_packet_list_dequeue(&queue[i],
							   &packets_left);
	      while (packet)
		{
		  SshNdisPacket synch_packet = NULL;
		  
		  prev_nbl = NULL;
		  nbl_list = NULL;
		  packet_count = 0;
		  
		  while (packet && (synch_packet == NULL))
		    { 
		      if (packet->f.flags.can_not_pend)
			{
			  SSH_DEBUG(SSH_D_NICETOKNOW, 
				    ("Adapter %@: packet 0x%p must be "
				     "completed synchronously",
				     ssh_adapter_id_st_render, adapter,
				     packet));
			  synch_packet = packet;
			}
		      
		      if (prev_nbl)
			{
			  if ((packet->port_number != port_number)
			      || (packet->transfer_flags != receive_flags))
			    {
			      /* Port number or flags differ; we must 
				 indicate collected NBL list now (before 
				 processing this packet) */
			      synch_packet = NULL;
			      break;
			    }
			  
			  prev_nbl->Next = packet->np;
			}
		      else
			{
			  nbl_list = packet->np;
			  port_number = packet->port_number;
			  receive_flags = packet->transfer_flags;
			}
		      prev_nbl = packet->np;
		      
		      packet_count++;
#ifdef DEBUG_LIGHT
		      packet->f.flags.in_recv_queue = 0;
		      packet->f.flags.in_protocol = 1;
		      packets_left--;
#endif /* DEBUG_LIGHT */
		      packet = packet->next;
		    }
		  
		  SSH_DEBUG(SSH_D_NICETOKNOW, 
			    ("Adapter %@: indicating %u NET_BUFFER_LIST(s) "
			     "to protocol, %u NBL(s) remaining",
			     ssh_adapter_id_st_render, adapter, 
			     packet_count, packets_left));
		  
		  NdisFIndicateReceiveNetBufferLists(adapter->handle,
						     nbl_list,
						     port_number,
						     packet_count,
						     receive_flags);
		  
		  if (synch_packet)
		    {
#ifdef DEBUG_LIGHT
		      synch_packet->f.flags.in_protocol = 0; 
#endif /* DEBUG_LIGHT */
		      ssh_interceptor_packet_free(&synch_packet->ip);
		    }
		}
	      
	      SSH_ASSERT(packets_left == 0);
	    }
	}
    }
}

static VOID
ssh_filter_process_enqueued_packets(SshInterceptor interceptor,
                                    SshCpuContext cpu_ctx)
{
  /* Return immediately if the current CPU is already executing this
     function. (This will happen e.g. if protocol stack sends a new packet
     before it returns from NdisMIndicateReceivePacket()) */
  if (cpu_ctx->in_queue_flush)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring recursive flush request"));
      return;
    }

  cpu_ctx->in_queue_flush = 1;
  while (cpu_ctx->packets_in_recv_queue || cpu_ctx->packets_in_send_queue)
    {
      if (cpu_ctx->packets_in_send_queue)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Flushing send queues..."));
	  
	  cpu_ctx->packets_in_send_queue = 0;
	  
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->send_queue,
					     TRUE);
	}
      
      if (cpu_ctx->packets_in_recv_queue)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Flushing receive queues..."));
	  
	  cpu_ctx->packets_in_recv_queue = 0;
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->recv_queue,
					     FALSE);
	}
    }
  cpu_ctx->in_queue_flush = 0;
}


static VOID
ssh_filter_send(NDIS_HANDLE filter_module_context,
                PNET_BUFFER_LIST net_buffer_lists,
                NDIS_PORT_NUMBER port_number,
                ULONG send_flags)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  SshInterceptor interceptor;
  ULONG send_complete_flags = 0;
  ULONG send_packet_cnt = 0;
  PNET_BUFFER_LIST current_nbl;
  SshCpuContext cpu_ctx;
  Boolean dispatch_level;
  KIRQL old_irql;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(net_buffer_lists != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("SEND: Adapter %@, list=0x%p, port=%u, flags=%08x {%@}", 
             ssh_adapter_id_st_render, adapter,
             net_buffer_lists, port_number, send_flags,
             ssh_ndis_send_flags_render, &send_flags));

  dispatch_level = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(send_flags);

  if (dispatch_level)
    send_complete_flags = NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;

  /* If the send operation is currently, we should complete all net buffer
     lists with NDIS_STATUS_PAUSED status. */
  if (!ssh_adapter_can_accept_send(adapter)
      || adapter->interceptor->entering_low_power_state)
    {
#ifdef DEBUG_LIGHT
      if (adapter->interceptor->entering_low_power_state)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("SEND: Interceptor entering low power state; completing "
                     "NBLs immediately with NDIS_STATUS_PAUSED"));
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("SEND: Adapter %@ not in RUNNING state; completing NBLs "
                     "immediately with NDIS_STATUS_PAUSED",
                     ssh_adapter_id_st_render, adapter));
        }
#endif /* DEBUG_LIGHT */

      current_nbl = net_buffer_lists;
      while (current_nbl)
        {
          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_PAUSED;
          current_nbl = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
        }

      NdisFSendNetBufferListsComplete(adapter->handle, 
                                      net_buffer_lists,
                                      send_complete_flags);
      return;
    }

  if (!dispatch_level)
    {
      /* Raise IRQL so we can safely touch the CPU specific packet pools... */
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
      NDIS_SET_SEND_FLAG(send_flags, NDIS_SEND_FLAGS_DISPATCH_LEVEL);
      send_complete_flags = NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

  interceptor = adapter->interceptor;
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  /* We may not ever get here so that we are already in packet callback. */
  SSH_ASSERT(cpu_ctx->in_packet_cb == 0);





  current_nbl = net_buffer_lists;
  while (current_nbl)
    {
      unsigned char temp[SSH_ETHERH_HDRLEN];  
      const unsigned char *header;
      PNET_BUFFER_LIST next_nbl;
      PNET_BUFFER_LIST nbl;
      SshNdisPacket packet;
      SshUInt16 eth_type;
      Boolean pass = FALSE; 
      SshPacketPool pool = &cpu_ctx->packet_pool;
      SshInterceptorProtocol protocol = SSH_PROTOCOL_ETHERNET;

      /* We have to process packets one at a time. */
      next_nbl = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
      NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;

      /* Check the type of the packet */
      header = NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(current_nbl),
                                 sizeof(temp), temp, 1, 0);
      if (header == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid source NBL"));
          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_FAILURE;
          NdisFSendNetBufferListsComplete(adapter->handle, 
                                          current_nbl,
                                          send_complete_flags);
          current_nbl = next_nbl;
          continue;
        }

      if (adapter->media == NdisMediumWirelessWan)
        {
          /* Special case for Windows 7 Mobile Broadband drivers */
          switch (header[0] >> 4)
            {
            case 4:
              protocol = SSH_PROTOCOL_IP4;
              break;

            case 6:
              protocol = SSH_PROTOCOL_IP6;
              break;

            default:
              protocol = SSH_PROTOCOL_OTHER;
              break;
            }
        }
      else
        {
          eth_type = SSH_GET_16BIT(header + SSH_ETHERH_OFS_TYPE);

          if (eth_type == SSH_ETHERTYPE_8021X)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Adapter %@: WPA packet; action=pass",
                         ssh_adapter_id_st_render, adapter));
              pass = TRUE;
            }
        }
      
      if ((pass == FALSE)
          && (current_nbl->NdisPoolHandle == pool->packet_list_context))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Adapter %@: Already filtered packet; action=pass",
                     ssh_adapter_id_st_render, adapter));
          pass = TRUE;
        }
 
      packet = ssh_packet_list_clone(adapter->interceptor, pool,
                                     SSH_PACKET_FROMPROTOCOL, 
                                     protocol, current_nbl, FALSE); 
      if (packet)
        {
          LONG new_value;
          SshNdisPacket p = packet;





          /* Increment the reference count of the original NBL once per
             every fragment, so the NBL won't be freed before the whole 
             packet has been processed. */
          while (p)
            {
              new_value = InterlockedIncrement(&adapter->ref_count);
              SSH_ASSERT(new_value > 0);
              current_nbl->ChildRefCount++;
              p = p->next;
            }

          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Adapter %@: %u operations pending",
                     ssh_adapter_id_st_render, adapter, new_value));

          while (packet)
            {
              NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO cksum_info;
              SshNdisPacket next = packet->next;

              SSH_DUMP_PACKET(SSH_D_MY5, ("Cloned packet:"), packet);

              packet->next = NULL;
              packet->f.flags.from_local_stack = 1;
              nbl = packet->np;
              NdisCopySendNetBufferListInfo(packet->np, current_nbl);

              cksum_info.Value = 
                NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

              packet->ip.ifnum_in = adapter->ifnum;
              packet->ip.flags |= SSH_PACKET_FROMPROTOCOL;
              if (cksum_info.Value)
                {
                  /* Checksum calculation of the first IP header is done 
                     by NIC hardware? Consider the packets ip header
                     checksum as valid, since it's going to be calculated
                     only in send. */
                  if (cksum_info.Transmit.IsIPv4 &&
                      cksum_info.Transmit.IpHeaderChecksum)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
	                        ("Adapter %@, packet 0x%p: "
                           "Requesting HW checksum for IPv4",
                           ssh_adapter_id_st_render, adapter, 
                           packet));

                      /* This flag well have to set in order to 
                         ensure that fastpath does not drop this packet, 
                         because of invalid IPv4 header checksum. */
                      packet->ip.flags |= SSH_PACKET_IP4HDRCKSUMOK;
                      
                      /* And this is just indication that we'll have 
                         to calculate the checksum in HW later on. */
                      packet->ip.flags |= SSH_PACKET_IP4HHWCKSUM;
                    }
		      
                  if (cksum_info.Transmit.TcpChecksum || 
                      cksum_info.Transmit.UdpChecksum)
                    packet->ip.flags |= SSH_PACKET_HWCKSUM;
                }

              packet->adapter_in = (SshAdapter)adapter;
              packet->port_number = port_number;
              packet->transfer_flags = send_flags;
              packet->complete_cb = ssh_filter_send_complete;
              packet->complete_cb_handle = adapter;
              packet->complete_cb_param = send_flags;

              packet->parent_complete_cb = 
                NdisFSendNetBufferListsComplete;
              packet->parent_complete_handle = adapter->handle;
              packet->parent_complete_np = current_nbl;
              packet->parent_complete_param = 
                NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;

              nbl->SourceHandle = adapter->handle;
              nbl->ParentNetBufferList = current_nbl;

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
              if (adapter->media == NdisMediumWan ||
	          adapter->media == NdisMediumCoWan)
                ssh_wan_packet_decapsulate((SshAdapter)adapter, 
                                           &packet->ip);

              if (packet->ip.protocol == SSH_PROTOCOL_ETHERNET)
                {
                  if ((eth_type == SSH_ETHERTYPE_PPPOE_DISCOVERY)
                      || (eth_type == SSH_ETHERTYPE_PPPOE_SESSION))
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Adapter %@: PPPoE packet; action=pass",
                                 ssh_adapter_id_st_render, adapter));
                      pass = TRUE;
                    }

#ifdef HAS_IEEE802_3_PASSTHRU
#ifdef NDIS630





                  if (interceptor->pass_ieee802_3
                      && packet_is_ieee802_3_passthrough_allowed(packet))
#else
                  if (interceptor->pass_ieee802_3 
                      && (packet->eth_type <= 0x5dc))
#endif
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Adapter %@: IEEE 802.3 packet; action=pass",
                                 ssh_adapter_id_st_render, adapter));
                      pass = TRUE;
                    }
#endif /* HAS_IEEE802_3_PASSTHRU */
                }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */


              if (pass == FALSE)
                {
#ifdef DEBUG_LIGHT
                  packet->f.flags.in_engine = 1;
#endif /* DEBUG_LIGHT */
                  cpu_ctx->in_packet_cb = 1;
                  interceptor->packet_cb(&packet->ip,
                                         interceptor->packet_cb_ctx);
                  cpu_ctx->in_packet_cb = 0;
                }
              else
                {
#ifdef DEBUG_LIGHT
                  packet->f.flags.in_miniport = 1;
#endif /* DEBUG_LIGHT */
                  NdisFSendNetBufferLists(adapter->handle, 
                                          packet->np, 
                                          port_number, 
                                          send_flags);
                }

              packet = next;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: Failed to clone packet!",
                      ssh_adapter_id_st_render, adapter));

          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_RESOURCES;
          NdisFSendNetBufferListsComplete(adapter->handle, 
                                          current_nbl,
                                          send_complete_flags);
        }

      current_nbl = next_nbl;
    }

  /* process packets queued by engine */
  ssh_filter_process_enqueued_packets(interceptor, cpu_ctx);

  /* lower IRQL if necessary */
  if (!dispatch_level)
    NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);
}

static VOID
ssh_filter_send_complete(NDIS_HANDLE filter_module_context,
                         PNET_BUFFER_LIST net_buffer_lists,
                         ULONG complete_flags)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  ULONG sends_completed = 0;
  Boolean dispatch_level;
  PNET_BUFFER_LIST current_nbl;
  SshInterceptor interceptor;
  KIRQL old_irql;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(net_buffer_lists != NULL);
   
  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("SEND_COMPLETE: Adapter %@, list=0x%p, flags=%08x {%@}", 
             ssh_adapter_id_st_render, adapter, 
             net_buffer_lists, complete_flags,
             ssh_ndis_send_complete_flags_render, &complete_flags));

  dispatch_level = NDIS_TEST_SEND_COMPLETE_AT_DISPATCH_LEVEL(complete_flags);

  if (!dispatch_level)
    {
      /* Raise IRQL so we can safely touch the CPU specific packet pools... */
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
    }

  interceptor = adapter->interceptor;
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  current_nbl = net_buffer_lists;
  while (current_nbl)
    {
      SshNdisPacket packet;
      PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
      PNET_BUFFER_LIST parent = current_nbl->ParentNetBufferList;

      NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;
      sends_completed++;

      packet = SSH_PACKET_CTX(current_nbl);
#ifdef DEBUG_LIGHT
      SSH_ASSERT(packet->f.flags.in_free_list == 0);
#endif /* DEBUG_LIGHT */

      if (parent)
        {
          SSH_ASSERT(parent->ChildRefCount > 0);
          SSH_ASSERT(parent == packet->parent_complete_np);
          parent->ChildRefCount--;
          if (parent->ChildRefCount == 0 && packet->parent_complete_cb)
            {
              NET_BUFFER_LIST_STATUS(parent) = NET_BUFFER_LIST_STATUS(current_nbl);
              (*packet->parent_complete_cb)(
                                   packet->parent_complete_handle,
                                   packet->parent_complete_np,
                                   packet->parent_complete_param);
            }
          packet->parent_complete_cb = NULL_FNPTR;
        }

#ifdef DEBUG_LIGHT
      packet->f.flags.in_miniport = 0;
#endif /* DEBUG_LIGHT */
      ssh_packet_free((SshNetDataPacket)packet, &(cpu_ctx->packet_pool));

      current_nbl = next;
    }

  if (!dispatch_level)
    NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: %u sends completed",
             ssh_adapter_id_st_render, adapter, sends_completed));
}


static VOID
ssh_filter_cancel_send(NDIS_HANDLE filter_module_context,
                       PVOID cancel_id)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;

  SSH_ASSERT(adapter != NULL);






  NdisFCancelSendNetBufferLists(adapter->handle, cancel_id);
}


static VOID
ssh_filter_receive(NDIS_HANDLE filter_module_context,
                   PNET_BUFFER_LIST net_buffer_lists,
                   NDIS_PORT_NUMBER port_number,
                   ULONG number_of_nblists,
                   ULONG receive_flags)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  SshInterceptor interceptor;
  PNET_BUFFER_LIST current_nbl;
  Boolean dispatch_level;  
  Boolean can_not_pend;
  KIRQL old_irql;
  SshCpuContext cpu_ctx;
  ULONG receive_flags_orig = receive_flags;
  ULONG pass_queue_cnt = 0;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);
  SSH_ASSERT(net_buffer_lists != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("RECEIVE: "
             "Adapter %@, list=0x%p (%u packets), port=%u, flags=%08x {%@}",
             ssh_adapter_id_st_render, adapter, 
             net_buffer_lists, number_of_nblists, 
             port_number, receive_flags,
             ssh_ndis_receive_flags_render, &receive_flags));

  dispatch_level = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(receive_flags);

  /* Check whether we need to copy the received data. We need to do so if
     NDIS_STATUS_RESOURCES flag is set. (Notice that our engine can queue
     the packet e.g. in fragmagic.) */
  can_not_pend = NDIS_TEST_RECEIVE_CANNOT_PEND(receive_flags);

  /* If the send operation is currently, we should complete all net buffer
     lists with NDIS_STATUS_PAUSED status. */
  if (!ssh_adapter_can_accept_receive(adapter)
      || adapter->interceptor->entering_low_power_state)
    {
      ULONG return_flags = 0;

      if (dispatch_level)
        NDIS_SET_RETURN_FLAG(return_flags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);

#ifdef DEBUG_LIGHT
      if (adapter->interceptor->entering_low_power_state)
        {
          SSH_DEBUG(SSH_D_HIGHSTART, 
                    ("RECEIVE: Interceptor entering low power state; "
                     "ignoring received data"));
        }
      else
        {
          SSH_DEBUG(SSH_D_HIGHSTART, 
                    ("RECEIVE: Adapter %@ not in RUNNING state; "
                     "ignoring received data",
                     ssh_adapter_id_st_render, adapter));
        }
#endif /* DEBUG_LIGHT */

      current_nbl = net_buffer_lists;
      while (current_nbl)
        {
          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_FAILURE;
          current_nbl = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
        }

      if (!can_not_pend)
        {
          NdisFReturnNetBufferLists(adapter->handle, 
                                    net_buffer_lists, 
                                    return_flags);
        }
      return ;
    }

  if (!dispatch_level)
    {
      /* Raise IRQL so we can safely touch the CPU specific packet pools... */
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
      NDIS_SET_RECEIVE_FLAG(receive_flags, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
    }

  interceptor = adapter->interceptor;
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  /* We may not ever get here so that we are already in packet callback. */
  SSH_ASSERT(cpu_ctx->in_packet_cb == 0);





  current_nbl = net_buffer_lists;
  while (current_nbl)
    {
      unsigned char temp[SSH_ETHERH_HDRLEN];  
      const unsigned char *header;
      PNET_BUFFER_LIST next_nbl;
      PNET_BUFFER_LIST nbl;
      SshNdisPacket packet;
      SshUInt16 eth_type;
      SshPacketPool pool = &(cpu_ctx->packet_pool);
      Boolean pass = FALSE; 
      SshInterceptorProtocol proto = SSH_PROTOCOL_ETHERNET;

      /* We have to process packets one at a time. */
      next_nbl = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
      NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;

      /* Check the type of the packet */
      header = NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(current_nbl),
                                 sizeof(temp), temp, 1, 0);

      /* Sanity check for packet header */
      if (header == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Receive: Invalid NBL, drop packet"));
          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_FAILURE;
          goto drop_now;
        }

      if (NdisTestNblFlags(current_nbl, NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET))
        {
#ifdef INTERCEPTOR_PASS_LOOPBACK_PACKETS 
          if (interceptor->pass_loopback == TRUE)
            pass = TRUE;
          else
            {
#endif /* INTERCEPTOR_PASS_LOOPBACK_PACKETS */
              SSH_DEBUG(SSH_D_FAIL, ("Receive: Loopback packet, drop packet"));
              NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_SUCCESS;
            goto drop_now;
        }
        }

      if (adapter->media == NdisMediumWirelessWan)
        {
          /* Special case for Windows 7 Mobile Broadband drivers */
          switch (header[0] >> 4)
            {
            case 4:
              proto = SSH_PROTOCOL_IP4;
              break;

            case 6:
              proto = SSH_PROTOCOL_IP6;
              break;

            default:
              proto = SSH_PROTOCOL_OTHER;
              break;
            }
        }
      else
        {
          eth_type = SSH_GET_16BIT(header + SSH_ETHERH_OFS_TYPE);

          if (eth_type == SSH_ETHERTYPE_8021X)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Adapter %@: WPA packet; action=pass",
                         ssh_adapter_id_st_render, adapter));
              pass = TRUE;
            }

          /* If we are in promiscuous mode, we take only multicast,
             direct addressed and broadcast packet to engine. */
          else if (adapter->promiscuous_mode)
            {
              /* Check if the engine is intrested in this packet, 
                 i.e. adapter media address matches the packets dst,
                 dst MAC address has multicast group address bit set or
                 the dst MAC address is broadcast. */
              if (adapter->media_addr_len == 6 &&
                  (memcmp(header, adapter->media_addr, 
                          adapter->media_addr_len) != 0) &&
                  ((header[0] & 0x1) == 0))
                {
                  /* Here we can decide whether to pass the packet to 
                     stack or drop it now. By default we pass the packet
                     to stack. */
#ifdef INTERCEPTOR_PASS_PROMISCUOUS_PACKETS 
                  if (interceptor->pass_promiscuous == TRUE)
                    pass = TRUE;
                  else
#endif /* INTERCEPTOR_PASS_PROMISCUOUS_PACKETS */
                    goto drop_now;
                }
            }
        }

      if ((pass == FALSE)
          && (current_nbl->NdisPoolHandle == pool->packet_list_context))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Adapter %@: Already filtered packet; action=pass",
                     ssh_adapter_id_st_render, adapter));
          pass = TRUE;
        }
 
      packet = ssh_packet_list_clone(adapter->interceptor, pool, 
                                     SSH_PACKET_FROMADAPTER,
                                     proto, current_nbl, FALSE);
      if (packet)
        {
          LONG new_value = 0;
          SshNdisPacket p = packet;





          /* Initialize packets */
          while (p)
            {
              NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO cksum_info;

              nbl = p->np;
              nbl->SourceHandle = adapter->handle;
              NdisCopyReceiveNetBufferListInfo(nbl, current_nbl);

              cksum_info.Value = 
                NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

              p->ip.ifnum_in = adapter->ifnum;
              p->ip.flags |= SSH_PACKET_FROMADAPTER;
              if (cksum_info.Value)
                {
                  if (cksum_info.Receive.IpChecksumSucceeded)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Adapter %@, packet 0x%p: "
                                 "IPv4 checksum verified by HW",
                                 ssh_adapter_id_st_render, adapter,
                                 packet));
		      
                      p->ip.flags |= SSH_PACKET_IP4HDRCKSUMOK;
                    }

                  if (cksum_info.Receive.TcpChecksumSucceeded ||
                      cksum_info.Receive.UdpChecksumSucceeded)
                    p->ip.flags |= SSH_PACKET_HWCKSUM;
                }
              p->port_number = port_number;
              p->transfer_flags = receive_flags;
              p->adapter_in = (SshAdapter)adapter;

              new_value = InterlockedIncrement(&adapter->ref_count);
              SSH_ASSERT(new_value > 0);
              if (can_not_pend)
                {
                  nbl->ParentNetBufferList = NULL;
                  SSH_ASSERT(p->complete_cb == NULL_FNPTR);
                  SSH_ASSERT(p->parent_complete_cb == NULL_FNPTR);
                }
              else
                {
                  nbl->ParentNetBufferList = current_nbl;
                  current_nbl->ChildRefCount++;
                  p->complete_cb = ssh_filter_receive_complete;
                  p->complete_cb_handle = adapter;
                  p->complete_cb_param = receive_flags;

                  p->parent_complete_cb = NdisFReturnNetBufferLists;
                  p->parent_complete_handle = adapter->handle;
                  p->parent_complete_np = current_nbl;
                  p->parent_complete_param = NDIS_RETURN_FLAGS_DISPATCH_LEVEL;
                }
              p = p->next;
            }

          if (new_value)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Adapter %@: %u asynchronous operations pending",
                         ssh_adapter_id_st_render, adapter, new_value));
            }
     
          /* Forward the IP fragments to engine for processing */
          while (packet)
            {
              SshNdisPacket next = packet->next;

              SSH_DUMP_PACKET(SSH_D_MY5, ("Cloned packet:"), packet);

              packet->next = NULL;

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
              if (adapter->media == NdisMediumWan ||
			      adapter->media == NdisMediumCoWan)
                ssh_wan_packet_decapsulate((SshAdapter)adapter, 
                                           &packet->ip);

              if (packet->ip.protocol == SSH_PROTOCOL_ETHERNET)
                {
                  if ((eth_type == SSH_ETHERTYPE_PPPOE_DISCOVERY)
                      || (eth_type == SSH_ETHERTYPE_PPPOE_SESSION))
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Adapter %@: PPPoE packet; action=pass",
                                 ssh_adapter_id_st_render, adapter));
                      pass = TRUE;
                    }

#ifdef HAS_IEEE802_3_PASSTHRU
#ifdef NDIS630
                  if (interceptor->pass_ieee802_3 
                      && packet_is_ieee802_3_passthrough_allowed(packet))
#else
                  if (interceptor->pass_ieee802_3 
                      && (packet->eth_type <= 0x5dc))
#endif
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Adapter %@: IEEE 802.3 packet; action=pass",
                                 ssh_adapter_id_st_render, adapter));
                      pass = TRUE;
                    }
#endif /* HAS_IEEE802_3_PASSTHRU */
                }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */


              if (pass == FALSE)
                {
#ifdef DEBUG_LIGHT
                  packet->f.flags.in_engine = 1;
#endif /* DEBUG_LIGHT */
                  cpu_ctx->in_packet_cb = 1;
                  interceptor->packet_cb(&packet->ip, 
                                         interceptor->packet_cb_ctx);
                  cpu_ctx->in_packet_cb = 0;
                }
              else
                {
#ifdef DEBUG_LIGHT
                  packet->f.flags.in_protocol = 1;
#endif /* DEBUG_LIGHT */
                  NdisFIndicateReceiveNetBufferLists(adapter->handle,
                                                     packet->np,
                                                     port_number,
                                                     1,
                                                     receive_flags);
                  if (can_not_pend)
                    {
#ifdef DEBUG_LIGHT
                      packet->f.flags.in_protocol = 0;
#endif /* DEBUG_LIGHT */
                      ssh_interceptor_packet_free(&packet->ip);
                    }
                }

              packet = next;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: Failed to clone packet",
                     ssh_adapter_id_st_render, adapter));
          NET_BUFFER_LIST_STATUS(current_nbl) = NDIS_STATUS_RESOURCES;

        drop_now:
          if (!can_not_pend)
            {
              NdisFReturnNetBufferLists(adapter->handle, 
                                        current_nbl, 
                                        NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
            }
        }

      /* Restore the NBL linking. */
      if (can_not_pend)
	NET_BUFFER_LIST_NEXT_NBL(current_nbl) = next_nbl;
	
      current_nbl = next_nbl;
    }

  ssh_filter_process_enqueued_packets(interceptor, cpu_ctx);

  if (!dispatch_level)    
    NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);
}

static VOID
ssh_filter_receive_complete(NDIS_HANDLE filter_module_context,
                            PNET_BUFFER_LIST net_buffer_lists,
                            ULONG return_flags)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  PNET_BUFFER_LIST current_nbl;
  Boolean dispatch_level;
  ULONG receives_completed = 0;
  SshCpuContext cpu_ctx;
  KIRQL old_irql;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(net_buffer_lists != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("RECEIVE_COMPLETE: Adapter %@, list=0x%p, flags=%08x {%@}", 
             ssh_adapter_id_st_render, adapter, 
             net_buffer_lists, return_flags,
             ssh_ndis_return_flags_render, &return_flags));

  dispatch_level = NDIS_TEST_RETURN_AT_DISPATCH_LEVEL(return_flags);

  if (!dispatch_level)
    {
      /* Raise IRQL so we can safely touch the CPU specific packet pools... */
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
    }

  cpu_ctx = &adapter->interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  current_nbl = net_buffer_lists;
  while (current_nbl)
    {
      SshNdisPacket packet;
      PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(current_nbl);
      PNET_BUFFER_LIST parent = current_nbl->ParentNetBufferList;

      NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;

      packet = SSH_PACKET_CTX(current_nbl); 
#ifdef DEBUG_LIGHT
      SSH_ASSERT(packet->f.flags.in_free_list == 0);
#endif /* DEBUG_LIGHT */

      receives_completed++;

      current_nbl->ParentNetBufferList = NULL;

      if (parent)
        {
          SSH_ASSERT(parent->ChildRefCount > 0);
          SSH_ASSERT(parent == packet->parent_complete_np);
          parent->ChildRefCount--;
          if (parent->ChildRefCount == 0 && packet->parent_complete_cb)
            {
              NET_BUFFER_LIST_STATUS(parent) = NET_BUFFER_LIST_STATUS(current_nbl);
              (*packet->parent_complete_cb)(packet->parent_complete_handle,
                                            packet->parent_complete_np,
                                            packet->parent_complete_param);
            }
          packet->parent_complete_cb = NULL_FNPTR;
        }

#ifdef DEBUG_LIGHT
      packet->f.flags.in_protocol = 0;
#endif /* DEBUG_LIGHT */
      ssh_packet_free((SshNetDataPacket)packet, &(cpu_ctx->packet_pool));

      current_nbl = next;
    }

  if (!dispatch_level)    
    NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adapter %@: %u receives completed",
             ssh_adapter_id_st_render, adapter, receives_completed));
}


static NDIS_STATUS
ssh_filter_net_pnp_event(NDIS_HANDLE filter_module_context,
                         PNET_PNP_EVENT_NOTIFICATION pnp_event)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  NDIS_DEVICE_POWER_STATE *power_state;
  NDIS_STATUS status;

  status = NdisFNetPnPEvent(adapter->handle, pnp_event);

  switch (pnp_event->NetPnPEvent.NetEvent)
    {
    case NetEventSetPower:
      power_state = pnp_event->NetPnPEvent.Buffer;
      if (pnp_event->NetPnPEvent.BufferLength >= sizeof(*power_state))
        {
          if (*power_state == NdisDeviceStateD0)
            {
              adapter->standing_by = FALSE;

              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Adapter %@ waking up from low power state.",
                         ssh_adapter_id_st_render, adapter));
            }
          else
            {
              adapter->standing_by = TRUE;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Adapter %@ entering low power state.",
                         ssh_adapter_id_st_render, adapter));

              ssh_adapter_wait_until_state_transition_complete(
                                                       (SshAdapter)adapter);
              ssh_interceptor_suspend_if_idle(adapter->interceptor);
            }
        }
      break;

    default:
      break;
    }

  return status;
}


static VOID
ssh_filter_status(NDIS_HANDLE filter_module_context,
                  PNDIS_STATUS_INDICATION status_indication)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)filter_module_context;
  NDIS_OFFLOAD *offload;
  NDIS_LINK_STATE *link_state;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->handle != NULL);

  switch (status_indication->StatusCode)
    {
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
    case NDIS_STATUS_WAN_LINE_UP:
      NdisFIndicateStatus(adapter->handle, status_indication);
      ssh_wan_line_up((SshAdapter)adapter, status_indication->StatusBuffer);
      return;

    case NDIS_STATUS_WAN_LINE_DOWN:
      ssh_wan_line_down((SshAdapter)adapter, status_indication->StatusBuffer);
      NdisFIndicateStatus(adapter->handle, status_indication);
      return;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

    case NDIS_STATUS_LINK_STATE:
      link_state = status_indication->StatusBuffer;
      if (status_indication->StatusBufferSize >= sizeof(*link_state))
        {
          if (link_state->MediaConnectState == MediaConnectStateConnected)
            adapter->media_connected = 1;
          else
            adapter->media_connected = 0; 
        }
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      /* Refresh IP interface and routing information */
      SSH_IP_FORCE_REFRESH_REQUEST(adapter->interceptor, SSH_IP_REFRESH_ALL);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
      break;

    case NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG:
      /* If major version is less than 6, make the request
         mysteriously disappear. */
      if (adapter->ndis_version >= SSH_NDIS_VERSION_6)
        {
          offload = status_indication->StatusBuffer;

          if (status_indication->StatusBufferSize >= sizeof(*offload))
            {
              /* Disable TCP segmentation and IPSec transform offloads. */
              NdisZeroMemory(&offload->IPsecV1, sizeof(offload->IPsecV1));
              NdisZeroMemory(&offload->LsoV1, sizeof(offload->LsoV1));
              NdisZeroMemory(&offload->LsoV2, sizeof(offload->LsoV2));
#ifdef NDIS61
              if (adapter->ndis_version >= SSH_NDIS_VERSION_6_1)
                {
                  NdisZeroMemory(&offload->IPsecV2, sizeof(offload->IPsecV2));
                }
#endif
#ifdef NDIS630
              if (adapter->ndis_version >= SSH_NDIS_VERSION_6_30)
                {
                  offload->Rsc.IPv4.Enabled = FALSE;
                  offload->Rsc.IPv6.Enabled = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.LsoV2Supported = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.MaxHeaderSizeSupported = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.ReceiveChecksumOffloadSupported = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.RssSupported = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.TransmitChecksumOffloadSupported = FALSE;
                  offload->EncapsulatedPacketTaskOffloadGre.VmqSupported = FALSE;
                }
#endif
            }
        }
      else
        {
          return;
        }
      break;

    case NDIS_STATUS_TASK_OFFLOAD_HARDWARE_CAPABILITIES:
    case NDIS_STATUS_OFFLOAD_ENCASPULATION_CHANGE:
    case NDIS_STATUS_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES:
      /* Make them mysteriously disappear if ndis major version
         is less than 6. */
      if (adapter->ndis_version >= SSH_NDIS_VERSION_6)
        break;
      else
       return;

    default:
      break;
    }

  NdisFIndicateStatus(adapter->handle, status_indication);
}



#pragma NDIS_INIT_FUNCTION(ssh_filter_init_interceptor)

#pragma warning(disable : 4100)
static Boolean
ssh_filter_init_interceptor(SshInterceptor generic_interceptor,
                            void *context)
{
  PDRIVER_OBJECT driver_obj;
  SshNdisFilterInterceptor interceptor;

  interceptor = (SshNdisFilterInterceptor)generic_interceptor;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->driver_object != NULL);

  driver_obj = (PDRIVER_OBJECT)interceptor->driver_object;













#pragma warning(disable : 28175)
  driver_obj->DriverUnload = ssh_filter_unload;
#pragma warning(default : 28175)
  interceptor->filter_driver_handle = NULL;

  return TRUE;
}
#pragma warning(default : 4100)

#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_restart_interceptor)

#pragma warning(disable : 4100)
static Boolean
ssh_filter_restart_interceptor(SshInterceptor generic_interceptor,
                               void *context)
{
  SshNdisFilterInterceptor interceptor;
  NDIS_FILTER_DRIVER_CHARACTERISTICS filter_chars;
  NDIS_STRING service_name;
  NDIS_STRING unique_name;
  NDIS_STRING friendly_name;
  NDIS_STATUS status;

  interceptor = (SshNdisFilterInterceptor)generic_interceptor;

  PAGED_CODE();
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->driver_object != NULL);

  RtlInitUnicodeString(&service_name, SSH_FILTER_SERVICE_NAME);
  RtlInitUnicodeString(&friendly_name, SSH_FILTER_FRIENDLY_NAME);
  RtlInitUnicodeString(&unique_name, SSH_FILTER_UNIQUE_NAME);

  NdisZeroMemory(&filter_chars, sizeof(filter_chars));
  filter_chars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
  filter_chars.MajorNdisVersion = 6;
  filter_chars.Header.Size = 
    NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;
  filter_chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#ifdef NDIS630
  switch (interceptor->os_version)
  {
  case SSH_OS_VERSION_WINDOWS_7:
    filter_chars.MinorNdisVersion = 20;
    break;

  case SSH_OS_VERSION_WINDOWS_8:
  case SSH_OS_VERSION_WINDOWS_8_1:
    filter_chars.MinorNdisVersion = 30;
    break;

  default:
    filter_chars.MinorNdisVersion = 1;
    break;
  }
#elif defined(NDIS620)
  switch (interceptor->os_version)
    {
    case SSH_OS_VERSION_WINDOWS_7:
      filter_chars.MinorNdisVersion = 20;
      break;

    default:
      filter_chars.MinorNdisVersion = 1;
      break;
    }
#elif defined(NDIS61)
  filter_chars.MinorNdisVersion = 1;
#else
  filter_chars.MinorNdisVersion = 0;
#endif /* NDIS620 */
  filter_chars.MajorDriverVersion = 5;
  filter_chars.MinorDriverVersion = 1;
  filter_chars.Flags = 0;
  filter_chars.FriendlyName = friendly_name;
  filter_chars.UniqueName = unique_name;
  filter_chars.ServiceName = service_name;
#if 0
  /* Not implemented */
  filter_chars.SetOptionsHandler = ssh_filter_register_options;        
#endif /* 0 */
  filter_chars.AttachHandler = ssh_filter_attach;
  filter_chars.DetachHandler = ssh_filter_detach;
  filter_chars.PauseHandler = ssh_filter_pause;
  filter_chars.RestartHandler = ssh_filter_restart;
#if 0
  /* Not implemented */
  filter_chars.SetFilterModuleOptionsHandler = ssh_filter_set_module_options;
#endif /* 0 */

  filter_chars.OidRequestHandler = ssh_filter_oid_request;
  filter_chars.OidRequestCompleteHandler = ssh_filter_oid_request_complete;

  filter_chars.CancelOidRequestHandler = ssh_filter_cancel_oid_request;
  filter_chars.SendNetBufferListsHandler = ssh_filter_send;
  filter_chars.SendNetBufferListsCompleteHandler = ssh_filter_send_complete;
  filter_chars.ReceiveNetBufferListsHandler = ssh_filter_receive;
  filter_chars.ReturnNetBufferListsHandler = ssh_filter_receive_complete;
#if 0 
  filter_chars.DevicePnPEventNotifyHandler = ssh_filter_pnp_event_notify;
#endif /* 0 */
  filter_chars.NetPnPEventHandler = ssh_filter_net_pnp_event;
  filter_chars.StatusHandler = ssh_filter_status;
  filter_chars.CancelSendNetBufferListsHandler = ssh_filter_cancel_send;
  /* NDIS 6.1: Optional functions */
  filter_chars.DirectOidRequestHandler = 
    ssh_filter_direct_oid_request;
  filter_chars.DirectOidRequestCompleteHandler = 
    ssh_filter_direct_oid_request_complete;
  filter_chars.CancelDirectOidRequestHandler = 
    ssh_filter_cancel_direct_oid_request;
  interceptor->filter_driver_handle = NULL;

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  status = NotifyUnicastIpAddressChange(AF_UNSPEC, 
                                        ssh_filter_address_change_notify,
                                        interceptor, 
                                        TRUE, 
                                        &interceptor->address_change_handle);
  if (status != STATUS_SUCCESS)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_ERROR,
                    ("Could not register address change notification"));
      interceptor->address_change_handle = NULL;
    }

  status = NotifyRouteChange2(AF_UNSPEC,
                              ssh_filter_route_change_notify,
                              interceptor,
                              TRUE,
                              &interceptor->route_change_handle);
  if (status != STATUS_SUCCESS)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_ERROR,
                    ("Could not register route change notification"));
      interceptor->route_change_handle = NULL;
    }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

  status = NdisFRegisterFilterDriver(interceptor->driver_object,
                                     interceptor,
                                     &filter_chars,
                                     &interceptor->filter_driver_handle);
  if (status != NDIS_STATUS_SUCCESS)
    {
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      if (interceptor->route_change_handle)
        CancelMibChangeNotify2(interceptor->route_change_handle);

      if (interceptor->address_change_handle)
        CancelMibChangeNotify2(interceptor->address_change_handle);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    ("Could not register as a NDIS filter driver"));
      return FALSE;
    }

  return TRUE;
}
#pragma warning(default : 4100)


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_pause_interceptor)

#pragma warning(disable : 4100)
static VOID
ssh_filter_pause_interceptor(SshInterceptor generic_interceptor,
                             void *context)
{
  SshNdisFilterInterceptor interceptor;

  interceptor = (SshNdisFilterInterceptor)generic_interceptor;

  PAGED_CODE();
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->filter_driver_handle != NULL);

  NdisFDeregisterFilterDriver(interceptor->filter_driver_handle);

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  if (interceptor->route_change_handle)
    CancelMibChangeNotify2(interceptor->route_change_handle);

  if (interceptor->address_change_handle)
    CancelMibChangeNotify2(interceptor->address_change_handle);
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
}
#pragma warning(default : 4100)


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_uninit_interceptor)

#pragma warning(disable : 4100)
static void
ssh_filter_uninit_interceptor(SshInterceptor generic_interceptor,
                              void *context)
{
  PAGED_CODE();
}
#pragma warning(default : 4100)

static void 
ssh_filter_adapter_query_ndis_version(SshNdisFilterAdapter adapter)
{ 
  SshOidRequestStruct oid_request;

  memset(&oid_request, 0, sizeof(oid_request));
  oid_request.type = SSH_OID_REQUEST_QUERY_INFORMATION;
  oid_request.oid = OID_GEN_DRIVER_VERSION;
  oid_request.buffer = &adapter->ndis_version;
  oid_request.buffer_len = sizeof(adapter->ndis_version);

  if (!ssh_adapter_oid_request_send((SshAdapter)adapter, &oid_request))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: failed to query NDIS version (status = %@)",
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &oid_request.status));
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: NDIS version = %u.%u",
                 ssh_adapter_id_st_render, adapter,
                 ((adapter->ndis_version & 0xFF00) >> 8),
                 (adapter->ndis_version & 0x00FF)));
    }
}

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
static Boolean 
ssh_filter_adapter_query_vnic(SshNdisFilterAdapter adapter)
{ 
  SshOidRequestStruct oid_request;
  SshVnicDrvIf vnic_if;

  memset(&oid_request, 0, sizeof(oid_request));
  oid_request.type = SSH_OID_REQUEST_QUERY_INFORMATION;
  oid_request.oid = OID_SSH_QUERY_INTERFACE;
  oid_request.buffer = &adapter->info_buffer;
  oid_request.buffer_len = sizeof(adapter->info_buffer);

  if (!ssh_adapter_oid_request_send((SshAdapter)adapter, &oid_request))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: failed to query VNIC (status = %@)",
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &oid_request.status));
      return FALSE;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: VNIC query responded with len %u",
                 ssh_adapter_id_st_render, adapter,
                 oid_request.bytes_transferred));

      vnic_if = (SshVnicDrvIf) adapter->info_buffer;

      /* Accept only VNIC_VERSION_1 for now. */
      if ((vnic_if->version != SSH_ICEPT_VNIC_IF_VERSION_1)
          || (vnic_if->size != sizeof(SshVnicDrvIfStruct_V1)))
        return FALSE;

      adapter->is_vnic = 1;
      adapter->vnic_interface = adapter->info_buffer;
      adapter->vnic_interface_size = oid_request.bytes_transferred;
      
      return TRUE;
    }
}
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

static void
ssh_filter_disable_adapter_offloads(SshNdisFilterAdapter adapter)
{
  NDIS_OFFLOAD_PARAMETERS offload;
  SshOidRequestStruct oid_request;
  SshUInt32 ndis_version;
  SshUInt32 bytes_needed = 0;
  SshUInt32 try_cnt = 5;

  SSH_ASSERT(adapter != NULL);
  ndis_version = adapter->ndis_version;
  SSH_ASSERT(ndis_version >= SSH_NDIS_VERSION_6);

  while (try_cnt-- > 0)
    {
      RtlSecureZeroMemory(&offload, sizeof(offload));
      offload.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;

  /* Disable TCP segmentation, TCP Chimney and IPsec trasform offlods */   

#ifdef NDIS61
      if (ndis_version >= SSH_NDIS_VERSION_6_30)
        {
#ifdef NDIS630
          /* If the adapter is NDIS 6.30 or higher, try with revision
             3 parameters of the OID. */
          offload.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_3;
          offload.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_3;
#else
        offload.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_2;
        offload.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_2;
#endif
        }
      else if (ndis_version >= SSH_NDIS_VERSION_6_1)
        {
  /* If the adapter is NDIS 6.10 or higher, try with revision 
     2 parameters of the OID. */
      offload.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_2;
      offload.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_2;
    }
  else
    {
      offload.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_1;   
      offload.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1;
    }
#else
  offload.Header.Revision = NDIS_OFFLOAD_PARAMETERS_REVISION_1;   
  offload.Header.Size = NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1;
#endif /* NDIS61 */

  /* Disable large send offloads */   
  offload.LsoV1 = NDIS_OFFLOAD_PARAMETERS_LSOV1_DISABLED;   
  offload.LsoV2IPv4 = NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED;   
  offload.LsoV2IPv6 = NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED;   
  /* Disable IPsec transform offload */   
  offload.IPsecV1 = NDIS_OFFLOAD_PARAMETERS_IPSECV1_DISABLED;   

  /* Disable TCP Chimney offload */   
  offload.TcpConnectionIPv4 =   
    offload.TcpConnectionIPv6 =   
    NDIS_OFFLOAD_PARAMETERS_CONNECTION_OFFLOAD_DISABLED;   

  /* Keep default settings for checksum offloads */   
  offload.IPv4Checksum =   
    offload.TCPIPv4Checksum =   
    offload.UDPIPv4Checksum =   
    offload.TCPIPv6Checksum =   
    offload.UDPIPv6Checksum =   
    NDIS_OFFLOAD_PARAMETERS_NO_CHANGE;   

#ifdef NDIS61
  if (ndis_version >= SSH_NDIS_VERSION_6_1)
    {
      offload.IPsecV2 = NDIS_OFFLOAD_PARAMETERS_IPSECV2_DISABLED;
      offload.IPsecV2IPv4 = NDIS_OFFLOAD_PARAMETERS_IPSECV2_DISABLED;
    }
#endif /* NDIS61 */

#ifdef NDIS630
      /* disable large receive offload and encapsulated packet task offloads */
      if (ndis_version >= SSH_NDIS_VERSION_6_30)
        {
          offload.RscIPv4 = NDIS_OFFLOAD_PARAMETERS_RSC_DISABLED;
          offload.RscIPv6 = NDIS_OFFLOAD_PARAMETERS_RSC_DISABLED;
          offload.EncapsulatedPacketTaskOffload = NDIS_OFFLOAD_SET_OFF;
          offload.EncapsulationTypes = NDIS_ENCAPSULATION_NOT_SUPPORTED;
        }
#endif /* NDIS630 */

      RtlSecureZeroMemory(&oid_request, sizeof(oid_request));
  oid_request.type = SSH_OID_REQUEST_SET_INFORMATION;
  oid_request.oid = OID_TCP_OFFLOAD_PARAMETERS;
  oid_request.buffer = &offload;
      oid_request.buffer_len =
        (bytes_needed == 0 ? offload.Header.Size : bytes_needed);

  if (ssh_adapter_oid_request_send((SshAdapter)adapter, &oid_request))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Adapter %@: IPSec and TCP segmentation offloads "
                 "successfully disabled",
                 ssh_adapter_id_st_render, adapter));
          break;
    }

      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: IPSec and TCP segmentation offloads could not "
                 "be disabled, status=%@",
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &oid_request.status)); 












      /* In case of buffer size error, retrieve the buffer length needed 
         and try with it */
      if ((oid_request.status == NDIS_STATUS_INVALID_LENGTH ||
            oid_request.status == NDIS_STATUS_BUFFER_TOO_SHORT)
            && (oid_request.bytes_needed < sizeof(offload)))
        {
          bytes_needed = oid_request.bytes_needed;
          continue;
        }

      /* In case of other errors, we try with lower revisions */
      if (ndis_version >= SSH_NDIS_VERSION_6_30)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Trying again offload disabling "
            "with revision 2 offload parameters."));
          ndis_version = SSH_NDIS_VERSION_6_1;
          continue;
        }

      if (ndis_version >= SSH_NDIS_VERSION_6_1)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Trying again offload disabling "
                                       "with revision 1 offload parameters."));
          ndis_version = SSH_NDIS_VERSION_6;
          continue;
        }
    }
}

#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_attach_adapter)

static void
ssh_filter_attach_adapter(SshAdapter generic_adapter,
                          void *context,
                          SshAdapterAttachCompleteCb callback,
                          void *callback_context)
{
  NDIS_FILTER_ATTRIBUTES filter_attrs;
  PNDIS_FILTER_ATTACH_PARAMETERS attach_params;
  SshNdisFilterAdapter adapter;
  NDIS_STATUS status;

  adapter = (SshNdisFilterAdapter)generic_adapter;
  attach_params = (PNDIS_FILTER_ATTACH_PARAMETERS)context;

  PAGED_CODE();
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(attach_params != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Attaching...",
             ssh_adapter_id_st_render, adapter));

  if ((attach_params->MiniportMediaType != NdisMedium802_3)
      && (attach_params->MiniportMediaType != NdisMediumWan)
      && (attach_params->MiniportMediaType != NdisMediumCoWan)
      && (attach_params->MiniportMediaType != NdisMediumWirelessWan))
    {





      goto failed;
    }
        
  /* Collect required information from the attach_params */
  adapter->media = attach_params->MiniportMediaType;

  if (attach_params->MediaConnectState == MediaConnectStateDisconnected)
    adapter->media_connected = 0;
  else
    adapter->media_connected = 1;

  SSH_ASSERT(attach_params->MacAddressLength <= sizeof(adapter->media_addr));
  adapter->media_addr_len = attach_params->MacAddressLength;
  NdisMoveMemory(adapter->media_addr, 
                 attach_params->CurrentMacAddress,
                 adapter->media_addr_len);

  adapter->luid = attach_params->BaseMiniportNetLuid.Value;
  adapter->own_luid = attach_params->NetLuid.Value;

  /* Disable TCP segmentation and IPSec transform task offloads. */
  if (attach_params->DefaultOffloadConfiguration)
    {
      NDIS_OFFLOAD *offload = attach_params->DefaultOffloadConfiguration;

      NdisZeroMemory(&offload->IPsecV1, sizeof(offload->IPsecV1));
      NdisZeroMemory(&offload->LsoV1, sizeof(offload->LsoV1));
      NdisZeroMemory(&offload->LsoV2, sizeof(offload->LsoV2));

#ifdef NDIS61
      NdisZeroMemory(&offload->IPsecV2, sizeof(offload->IPsecV2));
#endif

#ifdef NDIS630
      /* Disable receive segment coalescing */
      if (attach_params->Header.Revision >= 
            NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4)
        {
          offload->Rsc.IPv4.Enabled = FALSE;
          offload->Rsc.IPv6.Enabled = FALSE;
        }

      /* Disable encapsulated packet task offload for network virtualization */
      if (attach_params->Header.Revision >= 
            NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4)
        {
          offload->EncapsulatedPacketTaskOffloadGre.LsoV2Supported = 
            NDIS_ENCAPSULATED_PACKET_TASK_OFFLOAD_NOT_SUPPORTED;
          offload->EncapsulatedPacketTaskOffloadGre.ReceiveChecksumOffloadSupported = 
            NDIS_ENCAPSULATED_PACKET_TASK_OFFLOAD_NOT_SUPPORTED;
          offload->EncapsulatedPacketTaskOffloadGre.RssSupported =
            NDIS_ENCAPSULATED_PACKET_TASK_OFFLOAD_NOT_SUPPORTED;
          offload->EncapsulatedPacketTaskOffloadGre.TransmitChecksumOffloadSupported =
            NDIS_ENCAPSULATED_PACKET_TASK_OFFLOAD_NOT_SUPPORTED;
          offload->EncapsulatedPacketTaskOffloadGre.VmqSupported =
            NDIS_ENCAPSULATED_PACKET_TASK_OFFLOAD_NOT_SUPPORTED;
          offload->EncapsulatedPacketTaskOffloadGre.MaxHeaderSizeSupported = 0;
        }
#endif
    }

  if ((attach_params->Header.Revision 
                                  >= NDIS_FILTER_ATTACH_PARAMETERS_REVISION_2)
      && (attach_params->HDSplitCurrentConfig != NULL))
    {
      PNDIS_HD_SPLIT_CURRENT_CONFIG split_config;

      split_config = attach_params->HDSplitCurrentConfig;





      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: Current header split configuration:\n"
                 " - HardwareCapabilities = 0x%08X\n"
                 " - CurrentCapabilities = 0x%08X\n"
                 " - HDSplitFlags = 0x%08X\n"
                 " - HDSplitCombineFlags = 0x%08X\n"
                 " - BackfillSize = %u\n"
                 " - MaxHeaderSize = %u",
                 ssh_adapter_id_st_render, adapter,
                 split_config->HardwareCapabilities,
                 split_config->CurrentCapabilities,
                 split_config->HDSplitFlags,
                 split_config->HDSplitCombineFlags,
                 split_config->BackfillSize,
                 split_config->MaxHeaderSize));
    }
#ifdef NDIS620
  if (attach_params->Header.Revision 
                                  >= NDIS_FILTER_ATTACH_PARAMETERS_REVISION_3)
    {
      if (attach_params->ReceiveFilterCapabilities)
        {
          PNDIS_RECEIVE_FILTER_CAPABILITIES rc;

          rc = attach_params->ReceiveFilterCapabilities; 

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Adapter %@: Receive filter capabilities:\n"
                     "- EnabledFilterTypes = 0x%08X\n"
                     "- EnabledQueueTypes = 0x%08X\n"
                     "- NumQueues = %u\n"
                     "- SupportedQueueProperties = 0x%08X\n"
                     "- SupportedFilterTests = 0x%08X\n"
                     "- SupportedHeaders = 0x%08X\n"
                     "- SupportedMacHeaderFields = 0x%08X\n"
                     "- MaxMacHeaderFilters = %u\n"
                     "- MaxQueueGroups = %u\n"
                     "- MaxQueuesPerQueueGroup = %u\n"
                     "- MinLookaheadSplitSize = %u\n"
                     "- MaxLookaheadSplitSize = %u",
                     ssh_adapter_id_st_render, adapter,
                     rc->EnabledFilterTypes,
                     rc->EnabledQueueTypes,
                     rc->NumQueues,
                     rc->SupportedQueueProperties,
                     rc->SupportedFilterTests,
                     rc->SupportedHeaders,
                     rc->SupportedMacHeaderFields,
                     rc->MaxMacHeaderFilters,
                     rc->MaxQueueGroups,
                     rc->MaxQueuesPerQueueGroup,
                     rc->MinLookaheadSplitSize,
                     rc->MaxLookaheadSplitSize));
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Adapter %@: MiniportPhysicalDeviceObject = 0x%p",
                 ssh_adapter_id_st_render, adapter,
                 attach_params->MiniportPhysicalDeviceObject));

      if (attach_params->NicSwitchCapabilities)
        {
          PNDIS_NIC_SWITCH_CAPABILITIES sc;

          sc = attach_params->NicSwitchCapabilities;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Adapter %@: NIC switch capabilities:\n"
                     "- NumTotalMacAddresses = %u\n"
                     "- NumMacAddressesPerPort = %u\n"
                     "- NumVlansPerPort = %u",
                     ssh_adapter_id_st_render, adapter,
                     sc->NumTotalMacAddresses,
                     sc->NumMacAddressesPerPort,
                     sc->NumVlansPerPort));
        }
    }
#endif /* NDIS620 */

  /* Set filter attributes */
  NdisZeroMemory(&filter_attrs, sizeof(filter_attrs));
  filter_attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
  filter_attrs.Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
  filter_attrs.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
  filter_attrs.Flags = 0;

  status = NdisFSetAttributes(adapter->handle, adapter, &filter_attrs);
  if (status != NDIS_STATUS_SUCCESS)
    {
      ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                    SSH_LOG_CRITICAL,
                    "Failed to set filter attributes");
      goto failed;
    }

  if (callback)
    (*callback)(TRUE, callback_context);

  return;

 failed:
  if (callback)
    (*callback)(FALSE, callback_context);
}


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_restart_adapter)

static void
ssh_filter_restart_adapter(SshAdapter generic_adapter,
                           void *restart_context,
                           SshAdapterRestartCompleteCb callback,
                           void *callback_context)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)generic_adapter;
  PNDIS_RESTART_ATTRIBUTES attributes;
  PNDIS_FILTER_RESTART_PARAMETERS params;
  Boolean status = TRUE;

  PAGED_CODE();
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Restarting...",
             ssh_adapter_id_st_render, adapter));

  params = (PNDIS_FILTER_RESTART_PARAMETERS)restart_context;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(params != NULL);

  attributes = params->RestartAttributes;

  /* Query NDIS version used by the underlying adapter. For 
     now if it is NDIS6 or above, we may use some offloading
     capabilities, for NDIS5 we disable those. */
  ssh_filter_adapter_query_ndis_version(adapter);

  /* If the adapter major version is 6 or higher, disable
     only TCP segmentation and IPSec transform offloads 
     from the adapter. */
  if (adapter->ndis_version >= SSH_NDIS_VERSION_6)
    ssh_filter_disable_adapter_offloads(adapter);

  while (attributes)
    {
      PNDIS_RESTART_GENERAL_ATTRIBUTES gen_attrib;

      switch (attributes->Oid)
        {
          case OID_GEN_MINIPORT_RESTART_ATTRIBUTES:
            if (attributes->DataLength >= sizeof(*gen_attrib))
              {
                PNDIS_RECEIVE_SCALE_CAPABILITIES rss;
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
                SshUInt32 num_oids;
                SshUInt32 i;
                NDIS_OID *oid;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

                gen_attrib = 
                  (PNDIS_RESTART_GENERAL_ATTRIBUTES)attributes->Data;
                adapter->options = gen_attrib->MacOptions;
                adapter->lookahead_size = gen_attrib->LookaheadSize;

                /* Ask NDIS to allocate enough backfill space for the headers 
                   we could add */
                if (adapter->interceptor->pass_ieee802_3)
                  {
#ifndef NDIS630
                    /* WHQL's HeaderPayloadSplit test fails if we use "too 
                       much" backfill space. This looks very much like a bug 
                       in current WHQL test kit or then there really is some 
                       totally undocumented 256 bytes limit... */
                    /* HCK CheckConnectivity tests fail if we change backfill
                       space. */
                    SSH_DEBUG(SSH_D_UNCOMMON, 
                              ("Adapter %@: Adding 64 bytes of backfill "
                               "space in WHQL test mode!",
                               ssh_adapter_id_st_render, adapter));

                    gen_attrib->DataBackFillSize += 64;
#endif
                  }
                else
                  {
                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Adpater %@: Adding %u bytes of "
                               "backfill space.", 
                               ssh_adapter_id_st_render, adapter,
                               SSH_NET_PACKET_BACKFILL_SIZE));

                    gen_attrib->DataBackFillSize += 
                      SSH_NET_PACKET_BACKFILL_SIZE; 
                  }

                /* Does the NIC support Receive Side Scaling? */
                rss = gen_attrib->RecvScaleCapabilities;
                if (rss && rss->CapabilitiesFlags)
                  {
                    SSH_DEBUG(SSH_D_NICETOKNOW, 
                              ("Adapter %@: "
                               "NIC supports Receive Side Scaling:\n"
                               " - capabilities_flags = 0x%X\n" 
                               " - interrupts = %u\n"
                               " - queues = %u",
                               ssh_adapter_id_st_render, adapter,
                               rss->CapabilitiesFlags,
                               rss->NumberOfInterruptMessages,
                               rss->NumberOfReceiveQueues));
                  }
                else
                  {
                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Adapter %@: NIC does not support "
                               "Receive Side Scaling",
                               ssh_adapter_id_st_render, adapter));
                  }

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
                oid = gen_attrib->SupportedOidList;
                num_oids = gen_attrib->SupportedOidListLength / 
                             sizeof(gen_attrib->SupportedOidList[0]);
                for (i = 0; i < num_oids; i++, oid++)
                  {
                    if (*oid == OID_SSH_QUERY_INTERFACE)
                      {
                        SshDeviceIoContextStruct vnic_dev;
                        SshDeviceIoOpenParamsStruct vnic_open_params;

                        NdisZeroMemory(&vnic_open_params, 
                                       sizeof(vnic_open_params));
                        vnic_open_params.write_access = FALSE;
                        vnic_open_params.exclusive_access = TRUE;


                        /* Look at the OS version. In windows 7 we use 
                           NDIS 5 based virtual adapter. */
                        if ((adapter->interceptor->os_version == 
                             SSH_OS_VERSION_WINDOWS_7))
                          {
                            if (!ssh_filter_adapter_query_vnic(adapter))
                              {
                                SSH_DEBUG(SSH_D_FAIL,
					  ("Failed to query VNIC information"
					   " from adapter %@",
					   ssh_adapter_id_st_render,
					   adapter));
                              }
                            else
                              {
                                SSH_DEBUG(SSH_D_FAIL,
					  ("Adapter %@ is VNIC",
					   ssh_adapter_id_st_render,
					   adapter));
                              }
                          }
                        else if (ssh_device_open(&vnic_dev,
                                                 SSH_VNIC_IO_DEVICE_NAME,
                                                 &vnic_open_params))
                          {
                            SshDeviceIoRequestStruct req;
                            ULONG bytes_read;

                            NdisZeroMemory(&req, sizeof(req));
                            req.ioctl_code = IOCTL_SSH_QUERY_INTERFACE;
                            req.internal_device_control = TRUE;
                            req.output_buffer = adapter->info_buffer;
                            req.output_buff_len = 
                              sizeof(adapter->info_buffer);
                            req.output_size_return = &bytes_read;

                            if (NT_SUCCESS(ssh_device_ioctl_request(&vnic_dev,
                                                                    &req)))
                              {
                                if (ssh_is_virtual_adapter_interface(
                                            adapter->info_buffer, 
                                            bytes_read))
                                  {
                                    SSH_DEBUG(SSH_D_NICETOKNOW,
                                              ("'%s' is a QuickSec Virtual "
                                               "Adapter", 
                                               adapter->ssh_name));

                                    adapter->is_vnic = 1;
                                    adapter->vnic_interface = 
                                      adapter->info_buffer;
                                    adapter->vnic_interface_size = bytes_read;
                                  }
                              }

                            ssh_device_close(&vnic_dev);
                          }
                        break;
                      }
                  }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
              }
            break;

          default:
            SSH_DEBUG(SSH_D_NICETOKNOW, 
                      ("Adapter %@: Restart attributes: OID=%@",
                       ssh_adapter_id_st_render, adapter,
                       ssh_ndis_oid_render, &attributes->Oid));
            break;
        }

      attributes = attributes->Next;
    }


  if (callback)
    (*callback)(status, callback_context);
}


#pragma NDIS_PAGEABLE_FUNCTION(ssh_filter_pause_adapter)

static void
ssh_filter_pause_adapter(SshAdapter generic_adapter,
                         void *pause_context,
                         SshAdapterPauseCompleteCb callback,
                         void *callback_context)
{
  PNDIS_FILTER_PAUSE_PARAMETERS pause_params;
  SshNdisFilterAdapter adapter;

  PAGED_CODE();
  adapter = (SshNdisFilterAdapter)generic_adapter;
  pause_params = (PNDIS_FILTER_PAUSE_PARAMETERS)pause_context;

  SSH_ASSERT(generic_adapter != NULL);
  SSH_ASSERT(pause_params != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: Pausing...",
             ssh_adapter_id_st_render, adapter));

  if (callback)
    (*callback)(callback_context);
}

Boolean
ssh_interceptor_is_supported_os_version(SshOsVersion os)
{
  if ((os == SSH_OS_VERSION_VISTA)
    || (os == SSH_OS_VERSION_WINDOWS_7)
    || (os == SSH_OS_VERSION_WINDOWS_8)
    || (os == SSH_OS_VERSION_WINDOWS_8_1))
  {
    return TRUE;
  }
  
  return FALSE;
}

#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
static void __fastcall
ssh_address_valid_check(SshAddressAddContext ctx)
{
  SshIpAddrStruct ip;
  NTSTATUS status;

  if (ctx->row.Address.si_family == AF_INET)
    SSH_IP4_DECODE(&ip, &ctx->row.Address.Ipv4.sin_addr.S_un.S_un_b); 
  else if (ctx->row.Address.si_family == AF_INET6)
    SSH_IP6_DECODE(&ip, &ctx->row.Address.Ipv6.sin6_addr.u.Byte); 

  status = GetUnicastIpAddressEntry(&ctx->row);
  if (status == STATUS_SUCCESS)
    {
      if ((ctx->row.DadState != IpDadStatePreferred)
          && (ctx->ttl))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IP address[%@], DAD state=%u (retry count=%u)", 
                     ssh_ipaddr_render, &ip, 
                     ctx->row.DadState,
                     ctx->ttl));

          /* DAD is still pending and this address is still tentative.
             Let's check it again after 100 milliseconds. */
          ctx->ttl--;
          ssh_kernel_timeout_register(0, 100000, 
                                      ssh_address_valid_timeout,
                                      ctx);
          return;
        }
    }
 
  /* done */
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Address change: IP address[%@] added", 
             ssh_ipaddr_render, &ip));
  SSH_IP_REFRESH_REQUEST(ctx->interceptor);
  InterlockedDecrement(&ctx->interceptor->ref_count);
  ssh_free(ctx);
}


static void
ssh_address_valid_timeout(void *context)
{
  SshAddressAddContext ctx = (SshAddressAddContext)context;
 
  SSH_ASSERT(ctx != NULL);
  SSH_ASSERT(ctx->interceptor != NULL);

  /* continue execution at IRQL passive level */
  if (!ssh_ndis_wrkqueue_queue_item(ctx->interceptor->work_queue,
                                    ssh_address_valid_check, ctx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to schedule work item"));
      InterlockedDecrement(&ctx->interceptor->ref_count);
      ssh_free(ctx);
    }
}


static void
ssh_filter_address_change_notify(SshNdisFilterInterceptor interceptor,
                                 PMIB_UNICASTIPADDRESS_ROW row,
                                 MIB_NOTIFICATION_TYPE notification_type)
{
  SshAddressAddContext add_ctx;
  SshIpAddrStruct ip;
   
  switch (notification_type)
    {
    case MibParameterNotification:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Address parameter change notification"));
      return;

    case MibInitialNotification:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Initial address change notification"));
      return;

    case MibAddInstance:
      /* We get the address addition notification immediately when a new IP
         address is added. We should not, however, report this address while
         it's in tentative state (i.e. while the duplicate address detection
         is still pending). */
      add_ctx = ssh_calloc(1, sizeof(*add_ctx));
      if (add_ctx)
        {
          InterlockedIncrement(&interceptor->ref_count);
          add_ctx->interceptor = interceptor;
          add_ctx->row = *row;
          add_ctx->ttl = 50;
          ssh_address_valid_timeout(add_ctx);
        }
      else
        {
          SSH_IP_REFRESH_REQUEST(interceptor);
        }
      break;

    case MibDeleteInstance:
      if (row->Address.si_family == AF_INET)
        {
          SSH_IP4_DECODE(&ip, &row->Address.Ipv4.sin_addr.S_un.S_un_b); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Address change: IPv4 address[%@] deleted", 
                     ssh_ipaddr_render, &ip));
        }
      else if (row->Address.si_family == AF_INET6)
        {
          SSH_IP6_DECODE(&ip, &row->Address.Ipv6.sin6_addr.u.Byte); 
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Address change: IPv6 address[%@] deleted", 
                     ssh_ipaddr_render, &ip));
        }
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Address delete notification; "
                 "refreshing IP and routing information"));
      SSH_IP_REFRESH_REQUEST(interceptor);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }
}


static void
ssh_filter_route_change_notify(SshNdisFilterInterceptor interceptor,
                               PMIB_IPFORWARD_ROW2 row,
                               MIB_NOTIFICATION_TYPE notification_type)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, 
    ("Route change notification; refreshing IP and routing information"));

  SSH_IP_REFRESH_REQUEST(interceptor);
}

#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */












































































































































































































































































































































































































