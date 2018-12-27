/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the type definitions and function declarations
   for SSH Adapter object.

   This "virtual adapter" intercepts all the NDIS supplied function calls
   (upper_edge.h, lower_edge.h) between a specified networking device
   driver and a transport protocol driver.

   For the dial-up connections one virtual adapter object is created that
   is layered above MS NDISWAN driver. The MS NDISWAN driver manages all
   dial-up connections by using the real WAN device drivers below it.

   NDISWAN driver sends an indication to SSH IPSEC driver whenever a
   dial-up connection is established (removed).
*/

#ifndef SSH_ADAPTER_H
#define SSH_ADAPTER_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "interceptor_i.h"
#include "adapter_common.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ENUMERATIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/* Forward declarations */
typedef struct SshNdisIMAdapterRec SshNdisIMAdapterStruct, *SshNdisIMAdapter;
typedef struct SshRequestRec SshRequestStruct, *SshRequest;
typedef struct SshIPInterfaceRec SshIPInterfaceStruct, *SshIPInterface;

/* Request completion routine */
typedef VOID (*SshRequestDone)(SshNdisIMAdapter, PNDIS_REQUEST, NDIS_STATUS);

/*--------------------------------------------------------------------------
  SSH Request

  Description:
  Type definition for a structure containing the information
  that is needed for protocol-supplied NDIS Request operations.

  Notes:
  --------------------------------------------------------------------------*/
typedef struct SshRequestRec 
{
  /* The request information */
  NDIS_REQUEST orig_request;

  /* Request completion routine */
  SshRequestDone request_done_cb;

  /* Storage for pointers that are filled when request is completed */
  ULONG *bytes_read_written;
  ULONG *bytes_needed;

  /* Flag indicating whether the request was completed asynchronously */
  Boolean asynch_completion;

  /* Flag indicating whether the request was queued by our interceptor */
  Boolean queued;
} SshRequestStruct, *SshRequest;

/*--------------------------------------------------------------------------
  SSH Adapter

  Description:
  Type definition for adapter objects that are layered between
  protocol driver and network driver. These adapter objects intercept
  all the network I/O operations between the protocol and the real
  networking device.

  Notes:
  --------------------------------------------------------------------------*/
typedef struct SshNdisIMAdapterRec 
{
  /* Generic adapter object. DO NOT move! */
  SshAdapterStruct ;

  /* Adapter name */
  NDIS_STRING name;

  /* Handle for data transfer with underlaying device */
  NDIS_HANDLE binding_handle;

  /* Handle for protocol binding context */
  NDIS_HANDLE bind_context;

  /* Enabled/Disabled flag */
  Boolean enabled; 

  /* Is this a WAN adapter */
  Boolean is_wan_adapter;

  /* Non-zero if NdisIMInitializeDeviceInstanceEx() called but 
     'MiniportInitialize' haven't been executed yet. */
  LONG init_pending;

  /* List of packets queued in "MiniportSendPackets" */
  LIST_ENTRY send_wait_queue;
  NDIS_SPIN_LOCK send_wait_queue_lock;

  /* List for sending request messages to underlaying device.
     A new request message is created when NDIS calls our SET/QUERY info
     handlers to request changes in adapter state. */
  NPAGED_LOOKASIDE_LIST request_list;

  /* Spin lock for ensuring the data integrity during the processing of 
     power management events. */
  NDIS_SPIN_LOCK power_mgmt_lock;

  /* According to DDK documentation, we must queue first request when 
     the power state of underlying miniport is not D0. */
  PNDIS_REQUEST pending_query_request;
  PNDIS_REQUEST pending_set_request;

  /* Number of outstanding requests */
  LONG outstanding_requests;

  /* Flag indicating that one or more status indications have been
     propagated to the upper layer but status indication complete has
     not yet been propagated. */
  Boolean status_indicated;

  /* Adapter's ssh_task_supend() count for IP config thread for ensuring that
     IP config thread is resumed also in case when interceptor is unbound 
     from the adapter when reset is still pending in the underlying NIC. (i.e. 
     we haven't received NDIS_STATUS_RESET_END indication before the adpater 
     object is destroyed. */
  LONG ip_cfg_thread_suspended;

  /* Power states and standing_by flag */
  NDIS_DEVICE_POWER_STATE virtual_mp_power_state;
  NDIS_DEVICE_POWER_STATE underlying_mp_power_state;

  /* VLAN ID configured to the underlying NIC */
  unsigned short vlan_id : 12;
  unsigned short vlan_id_known : 1;

  /* Cached system specific interface identifiers to speed up adapter
     lookups */
  GUID if_guid;
  unsigned char *if_description;
  SshUInt16 if_description_len;
} SshNdisIMAdapterStruct;

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GENERAL FUNCTIONS FOR ADAPTER CONTROL
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Constructor for SSH Adapter object.
  --------------------------------------------------------------------------*/
SshNdisIMAdapter
ssh_adapter_create(PCWSTR name,
                   USHORT name_len,
                   SshNdisIMInterceptor interceptor);

/*--------------------------------------------------------------------------
  Destructor for SSH Adapter object.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_destroy(SshNdisIMAdapter adapter);

/*--------------------------------------------------------------------------
  Creates binding between SSH Adapter object and underlaying NIC.

  'wan_adapter' must be set to TRUE _only_ if we are opening at adapter 
  at WAN miniport layer (currently Windows CE only).
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_open(SshNdisIMAdapter adapter,
                 NDIS_HANDLE bind_context,
                 PVOID system_specific1,
                 Boolean wan_adapter); 
 
/*--------------------------------------------------------------------------
  Removes previously created binding.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_close(SshNdisIMAdapter adapter);

/*--------------------------------------------------------------------------
  Enables/Disables SSH Adapter object.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_enable(SshNdisIMAdapter adapter,
                   BOOLEAN enable);

/*--------------------------------------------------------------------------
  Returns TRUE if adapter is ready for low power state, FALSE otherwise.
  --------------------------------------------------------------------------*/
/* Replace default check with IM interceptor specific one */
#undef SSH_ADAPTER_CAN_SUSPEND
__inline Boolean
SSH_ADAPTER_CAN_SUSPEND(SshAdapter gen_adapter)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)gen_adapter;

  if ((adapter->virtual_mp_power_state != NdisDeviceStateD3) 
      || (adapter->underlying_mp_power_state != NdisDeviceStateD3))
    return FALSE;
  else
    return TRUE;
}


/*--------------------------------------------------------------------------
  Returns TRUE if adapter is enabled, FALSE otherwise.
  --------------------------------------------------------------------------*/
__inline BOOLEAN
ssh_adapter_is_enabled(SshNdisIMAdapter adapter)
{
  return (adapter->state == SSH_ADAPTER_STATE_RUNNING 
          && adapter->enabled == TRUE  
          && adapter->virtual_mp_power_state == NdisDeviceStateD0
          && adapter->underlying_mp_power_state == NdisDeviceStateD0
          && adapter->handle != NULL);
}

/*--------------------------------------------------------------------------
  Prepares SSH Adapter object for network data processing.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_initialize(SshNdisIMAdapter adapter,
                       NDIS_HANDLE miniport_adapter_handle,
                       NDIS_HANDLE config_handle,
                       UINT medium_array_size,
                       PNDIS_MEDIUM medium_array,
                       PUINT medium_index);

/*--------------------------------------------------------------------------
  Deinitializes SSH Adapter object.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_deinitialize(SshNdisIMAdapter adapter);


/*--------------------------------------------------------------------------
  Waits until all pending requests and packets have been processed and 
  returned back to original pools. 
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_wait_until_idle(SshNdisIMAdapter adapter);


/*--------------------------------------------------------------------------
  FUNCTIONS FOR INTERCEPTING NDIS OID REQUESTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Sends a queued NDIS OID Set/Query request into the network device.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_send_queued_requests(SshNdisIMAdapter adapter);

/*--------------------------------------------------------------------------
  Completes the queued NDIS OID Set/Query requests with the given error
  status. This function can be called e.g. before delivering reset request
  to underlying miniport driver.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_complete_queued_requests(SshNdisIMAdapter adapter,
                                     NDIS_STATUS error_code);

/*--------------------------------------------------------------------------
  Handles NDIS OID_PNP_QUERY_POWER request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_query_power(SshNdisIMAdapter adapter, 
                               PVOID info,
                               ULONG info_len,
                               PULONG bytes_written,
                               PULONG bytes_needed);

/*--------------------------------------------------------------------------
  Handles NDIS OID Query request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_query_request(SshNdisIMAdapter adapter, 
                                 NDIS_REQUEST *request);

/*--------------------------------------------------------------------------
  Handles NDIS OID_PNP_SET_POWER request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_set_power(SshNdisIMAdapter adapter,
                             PVOID info,
                             ULONG info_len,
                             PULONG bytes_written,
                             PULONG bytes_needed);

/*--------------------------------------------------------------------------
  Handles NDIS OID Set request.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_adapter_handle_set_request(SshNdisIMAdapter adapter, 
                               NDIS_REQUEST *request);

/*--------------------------------------------------------------------------
  Completes NDIS OID Set request.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_set_request_done(SshNdisIMAdapter adapter,
                             NDIS_REQUEST *request,
                             NDIS_STATUS status);

/*--------------------------------------------------------------------------
  Completes NDIS OID Query request.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_query_request_done(SshNdisIMAdapter adapter,
                               NDIS_REQUEST *request,
                               NDIS_STATUS status);

/*--------------------------------------------------------------------------
  FUNCTIONS FOR WAN CONNECTION CONTROL
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Establishes a new WAN connection.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_wan_line_up(SshNdisIMAdapter adapter,
                        PNDIS_WAN_LINE_UP line_up,
                        UINT line_up_len);

/*--------------------------------------------------------------------------
  Removes a WAN connection.
  --------------------------------------------------------------------------*/
VOID
ssh_adapter_wan_line_down(SshNdisIMAdapter adapter,
                          PNDIS_WAN_LINE_DOWN line_down,
                          UINT line_down_len);


/*--------------------------------------------------------------------------
  FUNCTIONS FOR ADAPTER INTERFACE INFORMATION HANDLING
  --------------------------------------------------------------------------*/

VOID
ssh_adapter_name_copy(SshNdisIMAdapter adapter,
                      PCHAR name,
                      SIZE_T name_len);

SshNdisIMAdapter
ssh_adapter_find_by_name(SshNdisIMInterceptor interceptor,
                         PNDIS_STRING name);

SshNdisIMAdapter
ssh_adapter_find_by_state(SshNdisIMInterceptor interceptor,
                          UINT state);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */ 

#ifdef __cplusplus
}
#endif

#endif /* SSH_ADAPTER_H */

