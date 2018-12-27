/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of upper-edge (miniport) functions. NDIS calls these
   functions when upper layer driver wants to communicate with the real
   network adapter (NIC) where it has been bound.
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor_i.h"
#include "adapter.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorUpperEdge"

/*-------------------------------------------------------------------------
  EXTERNALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  GLOBALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

static NDIS_STATUS
ssh_driver_reset(PBOOLEAN addressing_reset,
		 NDIS_HANDLE miniport_adapter_context);


static NDIS_STATUS
ssh_driver_initialize(PNDIS_STATUS open_error_status,
                      PUINT selected_medium_index,
                      PNDIS_MEDIUM medium_array,
                      UINT medium_array_size,
                      NDIS_HANDLE miniport_context,
                      NDIS_HANDLE configuration_context);

static VOID
ssh_driver_deinitialize(NDIS_HANDLE miniport_context);


static VOID
ssh_driver_send_packets(NDIS_HANDLE miniport_context,
                        PPNDIS_PACKET packet_array,
                        UINT number_of_packets);

static NDIS_STATUS 
ssh_driver_query_information(NDIS_HANDLE miniport_context,
                             NDIS_OID oid,
                             PVOID info_buffer,
                             ULONG info_buffer_length,
                             PULONG bytes_written,
                             PULONG bytes_needed);

static NDIS_STATUS
ssh_driver_set_information(NDIS_HANDLE miniport_context,
                           NDIS_OID oid,
                           PVOID info_buffer,
                           ULONG info_buffer_length,
                           PULONG bytes_read,
                           PULONG bytes_needed);

static VOID
ssh_driver_return_packet(NDIS_HANDLE miniport_context,
                         PNDIS_PACKET packet);

static NDIS_STATUS
ssh_driver_transfer_data(PNDIS_PACKET packet,
                         PUINT bytes_transferred,
                         NDIS_HANDLE miniport_context,
                         NDIS_HANDLE receive_context,
                         UINT byte_offset,
                         UINT bytes_to_transfer);

static BOOLEAN
ssh_driver_check_for_hang(NDIS_HANDLE miniport_context);

/*-------------------------------------------------------------------------
  EXPORTS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  UPPER EDGE(MINIPORT) HANDLERS
  -------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_interceptor_register_upper_edge()
  
  Registers(Deregisters) the upper-edge (miniport) handlers of driver with 
  NDIS. After registration is done, NDIS can use these handlers for 
  communication with upper layer device (protocol) driver.
  
  Arguments:
  interceptor - SshInterceptor object,
  enable - Register/Deregister flag.
 
  Returns:
  NDIS_STATUS_SUCCESS - operation succeeded
  NDIS_STATUS_FAILURE - otherwise
  
  Notes:
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_interceptor_register_upper_edge(SshNdisIMInterceptor interceptor,
                                    BOOLEAN enable)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NDIS_MINIPORT_CHARACTERISTICS mp_chars;

  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_register_upper_edge()"));

  if (enable == TRUE && interceptor->miniport_handle == NULL)
    {
      NdisZeroMemory(&mp_chars,sizeof(mp_chars));

      mp_chars.MajorNdisVersion = SSH_MAJOR_NDIS_VERSION;
      mp_chars.MinorNdisVersion = SSH_MINOR_NDIS_VERSION;

      mp_chars.CheckForHangHandler = ssh_driver_check_for_hang;
      mp_chars.HaltHandler = ssh_driver_deinitialize;
      mp_chars.InitializeHandler = ssh_driver_initialize;
      mp_chars.ResetHandler = ssh_driver_reset;
      mp_chars.SendHandler = NULL;
      mp_chars.SendPacketsHandler = ssh_driver_send_packets;
      mp_chars.TransferDataHandler = ssh_driver_transfer_data;
      mp_chars.ReturnPacketHandler = ssh_driver_return_packet;
      mp_chars.QueryInformationHandler = ssh_driver_query_information;
      mp_chars.SetInformationHandler = ssh_driver_set_information;

      status = NdisIMRegisterLayeredMiniport(interceptor->wrapper_handle,
                                             &mp_chars,
                                             sizeof(mp_chars),
                                             &interceptor->miniport_handle);

      if (status != NDIS_STATUS_SUCCESS)
        {
          interceptor->miniport_handle = NULL;
          SSH_DEBUG(SSH_D_ERROR, ("  - failed!"));
        }

      NdisMRegisterUnloadHandler(interceptor->wrapper_handle, DriverUnload); 
    }

  if (enable == FALSE && interceptor->miniport_handle != NULL)
    {
      /* Deregister upper edge API */
      NdisIMDeregisterLayeredMiniport(interceptor->miniport_handle);
      interceptor->miniport_handle = NULL;
      status = NDIS_STATUS_SUCCESS;
    }

  return (status);
}

/*-------------------------------------------------------------------------
  ssh_driver_reset()
  
  Resets the software status of the driver. 

  Arguments:
  addressing_reset - returns TRUE or FALSE depending on the status
                     of the call.
  miniport_adapter_context NDIS_HANDLE to the miniport driver.

  Returns:
  NDIS_STATUS_SUCCESS - reset succeeded
  NDIS_STATUS_PENDING - the call is left in asynchronous operation
  NDIS_STATUS_FAILURE - otherwise

  Notes:
  
  Default IRQL: <= DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_reset(PBOOLEAN addressing_reset,
		 NDIS_HANDLE miniport_adapter_context)
{
  SSH_ASSERT(addressing_reset != NULL);
  SSH_ASSERT(miniport_adapter_context != NULL);

  if (addressing_reset)
    *addressing_reset = FALSE;

  return NDIS_STATUS_SUCCESS;
}

/*-------------------------------------------------------------------------
  ssh_driver_initialize()
  
  Sets up virtual NIC so that it is ready for network I/O operations.

  Arguments:
  open_error_status - additional error information
  selected_medium_index - index to specified media type in medium array 
  medium_array - media array
  medium_array_size - length of media array
  miniport_handle - handle that identifies virtual NIC
  configuration_context -  handle to registry configuration of virtual NIC

  Returns:
  NDIS_STATUS_SUCCESS - initialization succeeded
  NDIS_STATUS_FAILURE - otherwise

  Notes:
  This handler is called after successful binding creation with 
  underlaying NIC.

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_initialize(PNDIS_STATUS open_error_status,
                      PUINT selected_medium_index,
                      PNDIS_MEDIUM medium_array,
                      UINT medium_array_size,
                      NDIS_HANDLE miniport_handle,
                      NDIS_HANDLE configuration_context)
{
  NDIS_STATUS status;
  SshNdisIMAdapter adapter;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);

  /* Retrieve the adapter context and then initialize our adapter */
  adapter = (SshNdisIMAdapter) NdisIMGetDeviceContext(miniport_handle);

  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Adapter %@ MiniportInitialize", 
             ssh_adapter_id_st_render, adapter));

  status = ssh_adapter_initialize(adapter,
                                  miniport_handle,
                                  configuration_context,
                                  medium_array_size,
                                  medium_array,
                                  selected_medium_index);

  if (status == NDIS_STATUS_SUCCESS)
    SSH_DEBUG(SSH_D_HIGHOK,
              ("Adapter %@ MiniportInitialize: status=%@, "
               "selected medium index %u",
               ssh_adapter_id_st_render, adapter,
               ssh_ndis_status_render, &status, 
               *selected_medium_index));
  else if (status == NDIS_STATUS_OPEN_FAILED)
    SSH_DEBUG(SSH_D_FAIL,
              ("Adapter %@ MiniportInitialize: status=%@, "
               "open error status %@",
               ssh_adapter_id_st_render, adapter,
               ssh_ndis_status_render, &status, 
               ssh_ndis_status_render, open_error_status));
  else
    SSH_DEBUG(SSH_D_FAIL,
              ("Adapter %@ MiniportInitialize: status=%@", 
               ssh_adapter_id_st_render, adapter,
               ssh_ndis_status_render, &status));

  return (status);
}

/*-------------------------------------------------------------------------
  ssh_driver_deinitialize()
  
  Deallocates virtual NIC resources after binding with underlaying NIC has
  been removed.

  Arguments:
  miniport_context - virtual NIC object
  
  Returns:
  Notes:
  This handler is called after successful removal of binding with 
  underlaying NIC.

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_deinitialize(NDIS_HANDLE miniport_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter) miniport_context;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Adapter %@: MiniportHalt",
             ssh_adapter_id_st_render, adapter));

  ssh_adapter_deinitialize(adapter);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("MiniportHalt: return"));
}

/*-------------------------------------------------------------------------
  ssh_driver_query_information()
  
  Returns information about the capabilities and status of virtual NIC.
  All but OID_PNP_SET_POWER, OID_PNP_ENABLE_WAKE_UP and 
  OID_TCP_TASK_OFFLOAD queries are passed down to the underlaying NIC.

  Arguments:                                   
  miniport_context - virtual NIC object
  oid - query operation ID
  info - data for query information
  info_len - query info buffer length
  bytes_written - how many bytes adapter has written to info buffer
  bytes_needed - how many bytes is needed at info buffer to complete the 
                 query operation successfully
                  
  Returns:
  NDIS_STATUS_SUCCESS - query completed successfully,
  NDIS_STATUS_PENDING - query completion pending,
  NDIS_STATUS_RESOURCES - resource allocation for query failed
  
  Notes:
  NDIS calls this function either on its own behalf, such as to determine
  which options the driver supports or to manage binding-specific 
  information for the underlaying NIC, or when a bound protocol driver
  calls NdisRequest.
  
  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS 
ssh_driver_query_information(NDIS_HANDLE miniport_context,
                             NDIS_OID oid,
                             PVOID info,
                             ULONG info_len,
                             PULONG bytes_written,
                             PULONG bytes_needed)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;
  struct _QUERY_INFORMATION *query;
  SshRequest request;
  NDIS_STATUS status;
  PVOID info_buf = info;

  SSH_ASSERT(SSH_GET_IRQL() <= SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Adapter %@ MiniportQueryInformation: oid=%@",
             ssh_adapter_id_st_render, adapter,
             ssh_ndis_oid_render, &oid));

  /* OID_PNP_QUERY_POWER must be handled by us (not forwarded to underlyng
     miniport driver). */
  if (oid == OID_PNP_QUERY_POWER)
    {
      status = ssh_adapter_handle_query_power(adapter, info, info_len,
                                              bytes_written, bytes_needed);
      goto end;
    }

  if (MmIsAddressValid(bytes_written))
    *bytes_written = 0;
  if (MmIsAddressValid(bytes_needed))
    *bytes_needed = 0;

  /* Check if the address for operation is within user space */ 
  if (info_len > 0 && info <= MM_HIGHEST_USER_ADDRESS)
    {
      /* Map user space address to system address */
      PMDL mdl = IoAllocateMdl(info, info_len, FALSE, FALSE, NULL);
      if (!mdl)
        {
          info_buf = NULL;
        }
      else
        {
          info_buf = MmGetSystemAddressForMdlSafe(mdl, LowPagePriority);
          IoFreeMdl(mdl);
        }
    }

  /* Check if address is valid */
  if (info_len > 0 && !MmIsAddressValid(info_buf))
    {
      status = NDIS_STATUS_NOT_ACCEPTED;
      goto end;
    }
  
  /* Allocate memory for the request */
  request = NdisAllocateFromNPagedLookasideList(&adapter->request_list);
  if (request == NULL)
    {
      status = NDIS_STATUS_RESOURCES;
      goto end;
    }

  /* Fill the data for our request */
  request->orig_request.RequestType = NdisRequestQueryInformation;
  request->bytes_read_written = bytes_written;
  request->bytes_needed = bytes_needed;
  request->request_done_cb = ssh_adapter_query_request_done;
  request->asynch_completion = TRUE;
  request->queued = FALSE;

  query = &(request->orig_request.DATA.QUERY_INFORMATION);
  query->Oid = oid;
  query->InformationBuffer = info_buf;
  query->InformationBufferLength = info_len;
  query->BytesWritten = 0;
  query->BytesNeeded = 0;

  status = ssh_adapter_handle_query_request(adapter, &request->orig_request);

 end:
  if (status == NDIS_STATUS_SUCCESS)
    SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                      ("Adapter %@ MiniportQueryInformation: returning data:",
                       ssh_adapter_id_st_render, adapter),
                      info, *bytes_written);
  else
    SSH_DEBUG(SSH_D_MIDOK,
              ("Adapter %@ MiniportQueryInformation: status=%@",
               ssh_adapter_id_st_render, adapter, 
               ssh_ndis_status_render, &status));

  return (status);
}

/*-------------------------------------------------------------------------
  ssh_driver_set_information()

  Request changes in the state of virtual NIC. All but OID_PNP_SET_POWER,
  OID_PNP_ENABLE_WAKE_UP and OID_TCP_TASK_OFFLOAD change requests are 
  passed down to the underlaying NIC.

  
  Arguments:
  miniport_context - virtual NIC object
  oid - change request operation identifier
  info - data for change operation
  info_len - data buffer length
  bytes_read - how many bytes has been read from info buffer
  bytes_needed - how many bytes is needed to complete the set operation
                 successfully

  Returns:
  NDIS_STATUS_SUCCESS - query completed successfully,
  NDIS_STATUS_PENDING - change request completion pending,
  NDIS_STATUS_RESOURCES - resource allocation for change request failed
  
  Notes:                                                         
  
  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_set_information(NDIS_HANDLE miniport_context,
                           NDIS_OID oid,
                           PVOID info,
                           ULONG info_len,
                           PULONG bytes_read,
                           PULONG bytes_needed)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;
  struct _SET_INFORMATION *set;
  SshRequest request;
  NDIS_STATUS status;
  PVOID info_buf = info;

  SSH_ASSERT(SSH_GET_IRQL() <= SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);

  if (info)
    SSH_DEBUG_HEXDUMP(SSH_D_MIDSTART,
                      ("Adapter %@ MiniportSetInformation: oid=%@, data:",
                       ssh_adapter_id_st_render, adapter, 
                       ssh_ndis_oid_render, &oid),
                      info, info_len);
  else
    SSH_DEBUG(SSH_D_MIDSTART,
              ("Adapter %@ MiniportSetInformation: oid=%@",
               ssh_adapter_id_st_render, adapter, 
               ssh_ndis_oid_render, &oid));

  /* OID_PNP_SET_POWER must be handled by us (not forwarded to underlyng
     miniport driver). */
  if (oid == OID_PNP_SET_POWER)
    {
      status = ssh_adapter_handle_set_power(adapter, info, info_len,
                                            bytes_read, bytes_needed);
      goto end;
    }

  if (MmIsAddressValid(bytes_read))
    *bytes_read = 0;
  if (MmIsAddressValid(bytes_needed))
    *bytes_needed = 0;
  
  /* Check if the address for operation is within user space */ 
  if (info_len > 0 && info <= MM_HIGHEST_USER_ADDRESS)
    {
      /* Map user space address to system address */
      PMDL mdl = IoAllocateMdl(info, info_len, FALSE, FALSE, NULL);
      if (!mdl)
        {
          info_buf = NULL;
        }
      else
        {
          info_buf = MmGetSystemAddressForMdlSafe(mdl, LowPagePriority);
          IoFreeMdl(mdl);
        }
    }

  /* Check if address is valid */
  if (info_len > 0 && !MmIsAddressValid(info_buf))
    {
      status = NDIS_STATUS_NOT_ACCEPTED;
      goto end;
    }
  
  /* Allocate memory for the request */
  request = NdisAllocateFromNPagedLookasideList(&adapter->request_list);
  if (request == NULL)
    {
      status = NDIS_STATUS_RESOURCES;
      goto end;
    }

  /* Fill the data for our request */
  request->orig_request.RequestType = NdisRequestSetInformation;
  request->bytes_read_written = bytes_read;
  request->bytes_needed = bytes_needed;
  request->request_done_cb = ssh_adapter_set_request_done;
  request->asynch_completion = TRUE;
  request->queued = FALSE;

  set = &(request->orig_request.DATA.SET_INFORMATION);
  set->Oid = oid;
  set->InformationBuffer = info_buf;
  set->InformationBufferLength = info_len;
  set->BytesRead = 0;
  set->BytesNeeded = 0;

  status = ssh_adapter_handle_set_request(adapter, &request->orig_request);

 end:
  SSH_DEBUG(SSH_D_MIDOK,
            ("Adapter %@ MiniportSetInformation: status=%@", 
             ssh_adapter_id_st_render, adapter, 
             ssh_ndis_status_render, &status));

  return (status);
}

/*-------------------------------------------------------------------------
  ssh_driver_check_for_hang()
  
  Reports the operational state of virtual NIC.
 
  Arguments:
        miniport_context - virtual NIC object
  
  Returns:
        FALSE - always (virtual NIC is operating normally)
  
  Notes:

  Default IRQL: DISPATCH_LEVEL
  --------------------------------------------------------------------------*/
static BOOLEAN
ssh_driver_check_for_hang(NDIS_HANDLE miniport_context)
{

  SSH_DEBUG(SSH_D_HIGHSTART, ("MiniportCheckForHang: miniport context 0x%p",
                              miniport_context));

  SSH_ASSERT(SSH_GET_IRQL() <= SSH_DISPATCH_LEVEL);
  SSH_ASSERT(miniport_context != NULL);

  return (FALSE);
}


/*-------------------------------------------------------------------------
        NDIS PACKET PROCESSING FUNCTIONS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_driver_send_complete_cb()

  Callback function to be called when asynchronous processing of network
  packet is completed (i.e. when we can free the cloned packet).
  -------------------------------------------------------------------------*/
static void
ssh_driver_send_complete_cb(NDIS_HANDLE handle,
                            NDIS_PACKET *ndis_pkt,
                            void *context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)handle;
  SshNdisIMInterceptor interceptor;
  SshCpuContext cpu_ctx;
  SshNdisPacket packet;

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  packet = SSH_PACKET_CTX(ndis_pkt);

  if (packet->parent_complete_cb != NULL_FNPTR)
    {
      (*(packet->parent_complete_cb))(packet->parent_complete_handle,
                                      packet->parent_complete_np,
                                      packet->parent_complete_param);

      packet->parent_complete_cb = NULL_FNPTR;
    }

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  SSH_ASSERT(interceptor != NULL);
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  ssh_packet_free((SshNetDataPacket)packet, &cpu_ctx->packet_pool);

#ifdef HAS_DELAYED_SEND_THREAD
  if (interceptor->delayed_sends)
    ssh_task_notify(&interceptor->delayed_send_thread, 
                    SSH_TASK_SIGNAL_NOTIFY);
#endif /* HAS_DELAYED_SEND_THREAD */
}

/*-------------------------------------------------------------------------
  ssh_driver_parent_send_complete_cb()

  Callback function to be called when asynchronous processing of network
  packet is completed (i.e. when we can return the original packet to 
  caller).
  -------------------------------------------------------------------------*/
static void
ssh_driver_parent_send_complete_cb(NDIS_HANDLE handle,
                                   NDIS_PACKET *ndis_pkt,
                                  void *context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)handle;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adapter %@: Completing send operation for NDIS packet 0x%p",
             ssh_adapter_id_st_render, adapter, ndis_pkt));

#pragma warning(disable : 4311)
  NdisMSendComplete(adapter->handle, ndis_pkt, (NDIS_STATUS)context);
#pragma warning(default : 4311)
}


/*-------------------------------------------------------------------------
  ssh_driver_send_packets()

  Sends multiple NDIS packet into the network via virtual NIC. 
  The packets are copied and then saved into a queue. The interceptor
  thread then processes the packets later.

  Arguments:
  miniport_context - virtual NIC object
  packet_array - array of NDIS packets
  packet_cnt - number of packets in the array
        
  Returns:
        
  Notes:
  To ensure that the sequential ordering of packets is not changed in
  error conditions we interrupt processing packets in the array whenever 
  we notice that we cannot handle the packet. All the remaining packets in 
  the array are then completed with FAILURE status.

  If we are running low of NDIS_PACKET resources then return with failure
  so that upper layer notices our lack of resources and the traffic then
  decreases.

  Default IRQL: <= DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static Boolean
ssh_driver_copy_and_send(SshNdisIMAdapter adapter,
                         PNDIS_PACKET src)
{
  SshNdisIMInterceptor interceptor;
  SshCpuContext cpu_ctx;
  SshNdisPacket packet;
  ULONG new_value;
  UINT flags;
  SSH_IRQL old_irql;
  Boolean status = FALSE;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(src != NULL);

  SSH_RAISE_IRQL(DISPATCH_LEVEL, &old_irql);

  new_value = InterlockedIncrement(&adapter->ref_count);
  SSH_ASSERT(new_value > 0);

  if (!ssh_adapter_can_accept_send(adapter))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: not in running state!", 
                 ssh_adapter_id_st_render, adapter));
      InterlockedDecrement(&adapter->ref_count);
      goto end;
    }

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  /* Try to clone the original packet's descriptors */
  packet = ssh_packet_clone((SshInterceptor)interceptor, 
                            &cpu_ctx->packet_pool, 
                            SSH_PROTOCOL_ETHERNET, 
                            src, 
                            FALSE);

  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to clone packet",
                 ssh_adapter_id_st_render, adapter));
      InterlockedDecrement(&adapter->ref_count);
      goto end;
    }

  NDIS_SET_PACKET_STATUS(src, NDIS_STATUS_PENDING);

  packet->complete_cb = ssh_driver_send_complete_cb;
  packet->complete_cb_handle = adapter;
  packet->complete_cb_param = NULL;

  packet->parent_complete_cb = ssh_driver_parent_send_complete_cb;
  packet->parent_complete_handle = adapter;
  packet->parent_complete_np = src;
  packet->parent_complete_param = (void *)NDIS_STATUS_SUCCESS;

  /* Set don't loopback flag and per packet info */
  flags = NdisGetPacketFlags(packet->np);
  flags |= NDIS_FLAGS_DONT_LOOPBACK;
  NdisSetPacketFlags(packet->np, flags);
  NdisIMCopySendPerPacketInfo(packet->np, src);

  /* Set the information that engine uses */
  SSH_DUMP_PACKET(SSH_D_MY5, "Cloned packet:", packet);

  packet->f.flags.from_local_stack = 1;
  packet->ip.ifnum_in = adapter->ifnum;
  packet->ip.flags |= SSH_PACKET_FROMPROTOCOL;
  packet->adapter_in = (SshAdapter)adapter;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("Adapter %@: %u operations pending", 
             ssh_adapter_id_st_render, adapter, new_value));

  ssh_interceptor_send_to_engine(interceptor, adapter, packet);
  ssh_interceptor_process_enqueued_packets(interceptor, cpu_ctx);

  status = TRUE;

end:
  if (old_irql < SSH_DISPATCH_LEVEL)
    SSH_LOWER_IRQL(old_irql);

  return status;
}


VOID 
ssh_driver_delayed_send_thread(SshNdisIMInterceptor interceptor)
{
  SshNdisIMAdapter adapter_lookup_table[32];
  SshNdisIMAdapter adapter;
  PLIST_ENTRY entry;
  SSH_IRQL old_irql;
  SshUInt32 i;
  SshUInt32 packets_sent;
  SshUInt32 adapter_cnt;

  SSH_ASSERT(interceptor != NULL);

  if (interceptor->adapter_cnt == 0)
    return;

  SSH_RAISE_IRQL(SSH_APC_LEVEL, &old_irql);

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);

  for (adapter_cnt = 0, entry = interceptor->adapter_list.Flink; 
       (entry != &interceptor->adapter_list) && (adapter_cnt < 32); 
       entry = entry->Flink)
    {
      adapter = CONTAINING_RECORD(entry, SshNdisIMAdapterStruct, link);

      if (!IsListEmpty(&adapter->send_wait_queue))
        {
          adapter_lookup_table[adapter_cnt] = adapter;
          adapter_cnt++;
        }
    }

  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  do
    {
      packets_sent = 0;

      for (i = 0; i < adapter_cnt; i++)
        {
          PLIST_ENTRY  pkt_entry;
          PNDIS_PACKET pkt;

          adapter = adapter_lookup_table[i];

          if (adapter == NULL)
            continue;

          pkt_entry = 
            NdisInterlockedRemoveHeadList(&adapter->send_wait_queue,
                                          &adapter->send_wait_queue_lock);
          if (pkt_entry == NULL)
            {
              adapter_lookup_table[i] = NULL;
              continue;
            }

            {
              pkt = CONTAINING_RECORD(pkt_entry, NDIS_PACKET,
                                      MiniportReserved);

              if (!ssh_driver_copy_and_send(adapter, pkt))
                {
                  /* Put this packet back to list. */
                  NdisInterlockedInsertHeadList(&adapter->send_wait_queue,
                                  (PLIST_ENTRY)&(pkt->MiniportReserved[0]),
                                  &adapter->send_wait_queue_lock);

                  adapter_lookup_table[i] = NULL;
                }
              else
                {
                  InterlockedDecrement(&interceptor->delayed_sends);
                  packets_sent++;
                }
            }
        }
    }
  while (packets_sent);

  SSH_LOWER_IRQL(old_irql);
}


static VOID
ssh_driver_send_packets(NDIS_HANDLE miniport_context,
                        PPNDIS_PACKET packet_array,
                        UINT packet_cnt)
{
  UINT i;
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;
  PNDIS_PACKET pkt;

  SSH_ASSERT(SSH_GET_IRQL() <= SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(packet_cnt > 0);
  SSH_ASSERT(packet_array != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("Adapter %@ MiniportSendPackets: packet count = %u",
             ssh_adapter_id_st_render, adapter, packet_cnt));

  if (!IsListEmpty(&adapter->send_wait_queue))
    {
      SshNdisIMInterceptor interceptor;

 buffer_packets:
      interceptor = (SshNdisIMInterceptor)adapter->interceptor;

      NdisAcquireSpinLock(&adapter->send_wait_queue_lock);
      for (i = 0; i < packet_cnt; i++)
        {
          pkt = packet_array[i];

          SSH_DEBUG(SSH_D_LOWSTART, 
                    ("Adapter %@ MiniportSendPackets: "
                     "queuing NDIS packet 0x%p", 
                     ssh_adapter_id_st_render, adapter, pkt));

          /* Mark packet pending */
          NDIS_SET_PACKET_STATUS(pkt, NDIS_STATUS_PENDING);

          /* Queue this packet. */
          InsertTailList(&adapter->send_wait_queue,
                         (PLIST_ENTRY)&(pkt->MiniportReserved[0]));
        }
      NdisReleaseSpinLock(&adapter->send_wait_queue_lock);

      InterlockedExchangeAdd(&interceptor->delayed_sends, packet_cnt);
      return;
    }

  /* Loop through the packet array */
  for (i = 0; i < packet_cnt; i++)
    {
      pkt = packet_array[i];

      /* Check if we are ready to process the packet */
      if (ssh_adapter_is_enabled(adapter) == FALSE)
        {
          NDIS_STATUS status;

          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Adapter %@ MiniportSendPackets: adapter not enabled",
                     ssh_adapter_id_st_render, adapter));

          /* Complete the send operation immediately with error code */
          status = NDIS_STATUS_FAILURE;
          NDIS_SET_PACKET_STATUS(pkt, status);
          NdisMSendComplete(adapter->handle, pkt, status);
          continue;
        }

      /* Handling of previous packet was successful so continue */
      if (!ssh_driver_copy_and_send(adapter, pkt))
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Adapter %@ MiniportSendPackets: "
                     "can't send packet to engine",
                     ssh_adapter_id_st_render, adapter));
          /* We have run out of packet descriptors of buffers; let's queue 
             rest of the packets */
          packet_array = &packet_array[i];
          packet_cnt -= i;
          goto buffer_packets;
        }
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Adapter %@ MiniportSendPackets: "
                 "sent packet to engine",
                 ssh_adapter_id_st_render, adapter));
    }
}




/*-------------------------------------------------------------------------
  ssh_driver_return_packet()

  Previously indicated NDIS packet is returned so that it can be reused.
  
  Arguments:
  miniport_context - virtual NIC object
  pkt - NDIS packet
        
  Returns:
  
  Notes:
  NDIS calls this function when the protocol layer above has processed
  the received packet and the resources allocated for the packet can be
  freed (reused).

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static void
ssh_driver_return_packet(NDIS_HANDLE miniport_context,
                         NDIS_PACKET *ndis_pkt)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;
  SshNdisPacket packet;

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  packet = SSH_PACKET_CTX(ndis_pkt);

  ssh_interceptor_packet_free(&packet->ip);
}

/*-------------------------------------------------------------------------
  ssh_driver_transfer_data()

  Copies received network data to a given upper layer supplied NDIS packet.
  
  Arguments:
  pkt - NDIS packet for data  
  bytes_transferred - how many bytes has been written into the packet
  miniport_context - virtual NIC object
  receive_context - ???
  byte_offset - where to start copy operation
  bytes_to_transfer -   how may bytes to copy

  Returns:
  NDIS_STATUS_FAILURE - always
  
  Notes:
  This function is not supported because we always indicate complete 
  NDIS packets to the upper layer. So upper layer should never call this 
  function but we anyway return the FAILURE status code to upper layer.

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_transfer_data(PNDIS_PACKET pkt,
                         PUINT bytes_transferred,
                         NDIS_HANDLE miniport_context,
                         NDIS_HANDLE receive_context,
                         UINT byte_offset,
                         UINT bytes_to_transfer)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;

  SSH_ASSERT(SSH_GET_IRQL() <= SSH_DISPATCH_LEVEL);
  SSH_ASSERT(miniport_context != NULL);
  SSH_ASSERT(receive_context != NULL);
  SSH_ASSERT(pkt != NULL);
  SSH_ASSERT(bytes_transferred != NULL);

  *bytes_transferred = 0;

  SSH_DEBUG(SSH_D_ERROR, 
            ("Adapter %@: Unexpected MiniportTransferData() call.",
             ssh_adapter_id_st_render, adapter));

  NDIS_SET_PACKET_STATUS(pkt, NDIS_STATUS_FAILURE);

  return (NDIS_STATUS_FAILURE);
}
