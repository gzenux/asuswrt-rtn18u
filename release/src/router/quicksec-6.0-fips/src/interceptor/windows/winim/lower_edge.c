/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains implementation of functions for SSH IPSEC driver's
   lower-edge (protocol) portion. The NDIS calls these handlers whenever the
   underlaying NDIS miniport driver or NDIS intermediate driver wants to
   communicate with the protocol layers where they are bound.
*/

/*-------------------------------------------------------------------------
  INCLUDE FILES
  -------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor_i.h"
#include "adapter.h"
#include "lower_edge.h"
#include "event.h"

/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE            "SshInterceptorLowerEdge"

/*-------------------------------------------------------------------------
  EXTERNALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  GLOBALS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  LOCAL VARIABLES
  -------------------------------------------------------------------------*/

/* Name for our protocol(s) */
static NDIS_STRING ssh_protocol_name = NDIS_STRING_CONST("quicksec");
PNDIS_STRING ssh_interceptor_service_name = &ssh_protocol_name;

/*-------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  -------------------------------------------------------------------------*/

static VOID
ssh_driver_do_adapter_bind(PNDIS_STATUS status,
			   NDIS_HANDLE bind_context,
			   PNDIS_STRING name,
			   PVOID system_specific1,
			   PVOID system_specific2,
			   Boolean wan_adapter);

static VOID
ssh_interceptor_protocol_unload(void);

static VOID
ssh_driver_adapter_bind(PNDIS_STATUS status,
                        NDIS_HANDLE bind_context,
                        PNDIS_STRING device_name,
                        PVOID system_specific1,
                        PVOID system_specific2);

static VOID
ssh_driver_adapter_unbind(PNDIS_STATUS status,
                          NDIS_HANDLE bind_context,
                          NDIS_HANDLE unbind_context);

static VOID
ssh_driver_adapter_open_done(NDIS_HANDLE protocol_binding_context,
                             NDIS_STATUS status,
                             NDIS_STATUS open_status);

static VOID
ssh_driver_adapter_close_done(NDIS_HANDLE protocol_binding_context,
                              NDIS_STATUS status);

static VOID
ssh_driver_reset_done(NDIS_HANDLE protocol_binding_context,
                      NDIS_STATUS status);

static VOID
ssh_driver_request_done(NDIS_HANDLE protocol_binding_context,
                        PNDIS_REQUEST ndis_request,
                        NDIS_STATUS status);

static VOID
ssh_driver_status(NDIS_HANDLE protocol_binding_context,
                  NDIS_STATUS general_status,
                  PVOID status_buffer,
                  UINT status_buffer_size);

static VOID
ssh_driver_status_done(NDIS_HANDLE protocol_binding_context);

static VOID
ssh_driver_send_done(NDIS_HANDLE protocol_binding_context,
                     PNDIS_PACKET packet,
                     NDIS_STATUS status);

static VOID
ssh_driver_transfer_data_done(NDIS_HANDLE protocol_binding_context,
                              PNDIS_PACKET packet,
                              NDIS_STATUS status,
                              UINT bytes_transferred);

static NDIS_STATUS
ssh_driver_receive(NDIS_HANDLE protocol_binding_context,
                   NDIS_HANDLE receive_context,
                   PVOID header_buffer,
                   UINT header_buffer_size,
                   PVOID lookahead_buffer,
                   UINT lookahead_bufferSize,
                   UINT packet_size);

static VOID
ssh_driver_receive_done(NDIS_HANDLE protocol_binding_context);

static INT
ssh_driver_receive_packet(NDIS_HANDLE protocol_binding_context,
                          PNDIS_PACKET packet);

static NDIS_STATUS
ssh_driver_handle_pnp_event(NDIS_HANDLE protocol_binding_context,
                            PNET_PNP_EVENT net_pnp_event);

/*-------------------------------------------------------------------------
  LOWER EDGE (PROTOCOL) HANDLERS
  -------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_interceptor_register_lower_edge()
  
  Registers the lower-edge (protocol) handlers of driver with NDIS. After
  registration is done, NDIS can use these handlers for communication with
  lower layer device (miniport) driver.
  
  Arguments:
  interceptor - SshInterceptor object
  enable - register/deregister flag
 
  Returns:
  NDIS_STATUS_SUCCESS - operation succeeded
  NDIS_STATUS_FAILURE - otherwise
  
  Notes:
  The name of our protocol must be the same as service name in our
  installation script file.
  --------------------------------------------------------------------------*/
NDIS_STATUS
ssh_interceptor_register_lower_edge(SshNdisIMInterceptor interceptor,
                                    BOOLEAN enable)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NDIS_PROTOCOL_CHARACTERISTICS prot_chars;

  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_register_lower_edge()"));

  if (enable == TRUE && interceptor->protocol_handle == NULL)
    {
      NdisZeroMemory(&prot_chars, sizeof(prot_chars));

      prot_chars.MajorNdisVersion = SSH_MAJOR_NDIS_VERSION;
      prot_chars.MinorNdisVersion = SSH_MINOR_NDIS_VERSION;

      prot_chars.Name = ssh_protocol_name;

      /* Init the handlers */
      prot_chars.BindAdapterHandler = ssh_driver_adapter_bind;
      prot_chars.UnbindAdapterHandler = ssh_driver_adapter_unbind;
      prot_chars.UnloadHandler = ssh_interceptor_protocol_unload;
      prot_chars.OpenAdapterCompleteHandler  = ssh_driver_adapter_open_done;
      prot_chars.CloseAdapterCompleteHandler = ssh_driver_adapter_close_done;
      prot_chars.ReceiveHandler = ssh_driver_receive;
      prot_chars.ReceiveCompleteHandler = ssh_driver_receive_done;
      prot_chars.ReceivePacketHandler = ssh_driver_receive_packet;
      prot_chars.TransferDataCompleteHandler = ssh_driver_transfer_data_done;
      prot_chars.SendCompleteHandler = ssh_driver_send_done;
      prot_chars.RequestCompleteHandler = ssh_driver_request_done;
      prot_chars.ResetCompleteHandler = ssh_driver_reset_done;
      prot_chars.StatusHandler = ssh_driver_status;
      prot_chars.StatusCompleteHandler = ssh_driver_status_done;
      prot_chars.PnPEventHandler = ssh_driver_handle_pnp_event;

      /* Register our protocol */
      NdisRegisterProtocol(&status, 
                           &interceptor->protocol_handle,
                           &prot_chars, 
                           sizeof(prot_chars));

      if (status != NDIS_STATUS_SUCCESS)
        {
          interceptor->protocol_handle = NULL;

          SSH_DEBUG(SSH_D_ERROR, 
                    ("  - failed! (status = %@)", 
                     ssh_ndis_status_render, &status));

          return status;
        }

    }

  if (enable == FALSE)
    {
      if (interceptor->protocol_handle != NULL)
        {
          NdisDeregisterProtocol(&status, interceptor->protocol_handle);
          interceptor->protocol_handle = NULL;
        }

      /* Wait until all bindings have been removed */
      while (ssh_adapter_find_by_state(interceptor, 
                                       SSH_ADAPTER_STATE_RUNNING) ||
             ssh_adapter_find_by_state(interceptor, 
                                       SSH_ADAPTER_STATE_PAUSING))
        {
          NdisMSleep(100);
        }
    }

  return (status);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_protocol_unload()
  
  Protocol unload handler.
  --------------------------------------------------------------------------*/
static VOID
ssh_interceptor_protocol_unload(void)
{
  ssh_interceptor_register_lower_edge((SshNdisIMInterceptor)the_interceptor, 
                                      FALSE);
}


/*-------------------------------------------------------------------------
  ssh_driver_adapter_bind()

  Creates a new binding between SSH IPSEC driver and a given miniport
  adapter (NIC) that is identified by device name. The handler creates
  internal object (SshAdapter) and then starts the binding process by
  opening the underlaying NIC.


  Arguments:
  status - binding operation result
  bind_context - binding context
  dev_name - name of the underlaying NIC device being bound
  system_specific1 - system specific information #1
  system_specific2 - system specific information #2

  Returns:

  Notes:
  This handler is called first by NDIS when an underlying NIC to which the
  SSH IPSEC driver can bind itself becomes available.

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_adapter_bind(PNDIS_STATUS status,
                        NDIS_HANDLE bind_context,
                        PNDIS_STRING name,
                        PVOID system_specific1,
                        PVOID system_specific2)
{

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(status != NULL);
  SSH_ASSERT(bind_context != NULL);
  SSH_ASSERT(name != NULL);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHSTART,
                    ("ProtocolBindAdapter: enter, device name:"),
                    (unsigned char *)name->Buffer, name->Length);

  *status = NDIS_STATUS_SUCCESS;

  ssh_driver_do_adapter_bind(status, bind_context, name,
                             system_specific1, system_specific2, FALSE);
}

/*-------------------------------------------------------------------------
  ssh_driver_adapter_open_done()

  Signals that the binding operation to the underlaying NIC has been
  completed.

  Arguments:
  protocol_binding_context - binding context
  status - binding operation result
  open_status - Additional error status

  Returns:

  Notes:
  This handler is called by NDIS after initialization of the underlaying
  NIC has been completed (MiniportInitialize() handler). The underlaying
  device is now ready to communicate with our "virtual" device.

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_adapter_open_done(NDIS_HANDLE protocol_binding_context,
                             NDIS_STATUS status,
                             NDIS_STATUS open_status)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);

  if (status == NDIS_STATUS_OPEN_FAILED)
    SSH_DEBUG(SSH_D_FAIL,
              ("Adapter %@ ProtocolOpenAdapterComplete: "
               "status %@, open error status %@",
               ssh_adapter_id_st_render, adapter,
               ssh_ndis_status_render, &status,
               ssh_ndis_status_render, &open_status));
  else 
    SSH_DEBUG(SSH_D_HIGHOK,
              ("Adapter %@ ProtocolOpenAdapterComplete: status %@",
               ssh_adapter_id_st_render, adapter,
               ssh_ndis_status_render, &status));

  /* Save the open operation result */
  adapter->result = status;

  /* Signal event so that adapter open process can continue */
  ssh_event_signal(adapter->wait_event);
}

/*-------------------------------------------------------------------------
  ssh_driver_adapter_unbind()

  Removes existing binding between SSH IPSEC driver and underlaying NIC.

  Arguments:
  status - unbind operation result
  protocol_binding_context - binding to be removed
  unbind_context - unbind context

  Returns:

  Notes:
  This handler is called by NDIS when underlaying NIC is not available
  anymore.

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_adapter_unbind(PNDIS_STATUS status,
                          NDIS_HANDLE protocol_binding_context,
                          NDIS_HANDLE unbind_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
#ifdef DEBUG_LIGHT
  SshInterceptorIfnum ifnum;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(status != NULL);
  SSH_ASSERT(unbind_context != NULL);

  ifnum = adapter->ifnum;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Adapter %@ ProtocolUnbindAdapter",
             ssh_adapter_id_st_render, adapter));

  /* Start the unbind operation by closing the adapter below */
  ssh_adapter_close(adapter);
  ssh_adapter_destroy(adapter);

  *status = NDIS_STATUS_SUCCESS;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Adapter (%u) ProtocolUnbindAdapter: leave, status %@",
             ifnum, ssh_ndis_status_render, status));
}


/*-------------------------------------------------------------------------
  ssh_driver_adapter_close_done()

  Signals that the unbind operation to the underlaying NIC has been
  completed.

  Arguments:
  protocol_binding_context - binding context
  status - unbind operation result

  Returns:

  Notes:
  This handler gets called by NDIS after the halt of the underlaying NIC
  has been completed (MiniportHalt() handler).

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_adapter_close_done(NDIS_HANDLE protocol_binding_context,
                              NDIS_STATUS status)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_ASSERT(SSH_GET_IRQL() < SSH_DISPATCH_LEVEL);
  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(status == NDIS_STATUS_SUCCESS ? SSH_D_HIGHOK : SSH_D_FAIL,
            ("Adapter %@ ProtocolCloseAdapterComplete: status %@", 
             ssh_adapter_id_st_render, adapter, 
             ssh_ndis_status_render, &status));

  /* Save the close operation result */
  adapter->result = status;

  /* Raise event so that adapter close process can continue */
  ssh_event_signal(adapter->wait_event);
}

/*-------------------------------------------------------------------------
  ssh_driver_reset_done()

  Signals that reset operation of underlaying NIC has been completed.

  Arguments:
  protocol_binding_context - binding context
  status - reset operation result

  Returns:

  Notes:
  This handler gets called by NDIS after the reset of the underlaying NIC
  has been completed (MiniportReset() handler).

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_reset_done(NDIS_HANDLE protocol_binding_context,
                      NDIS_STATUS status)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_DEBUG(status == NDIS_STATUS_SUCCESS ? SSH_D_HIGHOK : SSH_D_FAIL,
            ("Adapter %@ ProtocolResetComplete: status %@", 
             ssh_adapter_id_st_render, adapter, 
             ssh_ndis_status_render, &status));

  SSH_ASSERT(adapter != NULL);

  /* Notify upper layer that RESET operation is completed */
  NdisMResetComplete(adapter->handle, status, TRUE);
}

/*-------------------------------------------------------------------------
  ssh_driver_request_done()

  Signals that pending NDIS OID request submitted to underlaying NIC has
  been completely processed.

  Arguments:
  protocol_binding_context - binding context
  orig_request - completed request
  status - request processing result

  Returns:
  Notes:

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_request_done(NDIS_HANDLE protocol_binding_context,
                        PNDIS_REQUEST request,
                        NDIS_STATUS status)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  SshRequest temp;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(request != NULL);

  if (status == NDIS_STATUS_SUCCESS &&
      request->RequestType == NdisRequestQueryInformation)
    {
#ifdef DEBUG_LIGHT
      SshUInt32 items;
      SshUInt32 i;
      NDIS_OID *oid_ptr;

      switch (request->DATA.QUERY_INFORMATION.Oid)
        {
        case OID_GEN_SUPPORTED_LIST:
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Adapter %@ ProtocolRequestComplete: "
                     "QUERY, oid=%@, status=%@, supported OIDs:",
                         ssh_adapter_id_st_render, adapter,
                         ssh_ndis_oid_render, 
                           &request->DATA.QUERY_INFORMATION.Oid,
                         ssh_ndis_status_render, &status));
          items = request->DATA.QUERY_INFORMATION.BytesWritten;
          items /= sizeof(NDIS_OID);
          oid_ptr = 
            (NDIS_OID *)request->DATA.QUERY_INFORMATION.InformationBuffer;
          
          for (i = 0; i < items; i++, oid_ptr++)
            {
              SSH_DEBUG(SSH_D_MIDOK, ("%@", ssh_ndis_oid_render, oid_ptr));
            }
          break;

        default:
          SSH_DEBUG_HEXDUMP(SSH_D_MIDOK,
                        ("Adapter %@ ProtocolRequestComplete: "
                         "QUERY, oid=%@, status=%@, data:",
                         ssh_adapter_id_st_render, adapter,
                         ssh_ndis_oid_render, 
                           &request->DATA.QUERY_INFORMATION.Oid,
                         ssh_ndis_status_render, &status),
                        request->DATA.QUERY_INFORMATION.InformationBuffer,
                        request->DATA.QUERY_INFORMATION.BytesWritten);
          break;
        }
#endif /* DEBUG_LIGHT */
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Adapter %@ ProtocolRequestComplete: "
                 "%s, oid=%@, status=%@",
                 ssh_adapter_id_st_render, adapter,
                 (request->RequestType == NdisRequestQueryInformation)
                   ? "QUERY" : "SET",
                 ssh_ndis_oid_render, &request->DATA.QUERY_INFORMATION.Oid,
                 ssh_ndis_status_render, &status));
    }

  temp = CONTAINING_RECORD(request, SshRequestStruct, orig_request);

  temp->request_done_cb(adapter, request, status);
}

/*-------------------------------------------------------------------------
  ssh_driver_status()

  Indicates general state-change notification raised by underlaying NIC.

  Arguments:
  protocol_binding_context - binding context
  status - status identifier
  buf - additional status information
  buf_size - additional status information length

  Returns:
  Notes:

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_status(NDIS_HANDLE protocol_binding_context,
                  NDIS_STATUS status,
                  PVOID buf,
                  UINT buf_size)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  SshNdisIMInterceptor interceptor;
  PNDIS_WAN_LINE_UP line_up = buf;
  PNDIS_WAN_LINE_DOWN line_down = buf;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(adapter->interceptor != NULL);

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
                    ("Adapter %@ ProtocolStatus: status %@, data:",
                     ssh_adapter_id_st_render, adapter,
                     ssh_ndis_status_render, &status),
                    buf, buf_size);

  switch (status)
    {
    default:
      /* Underlaying networking device is closing */
    case NDIS_STATUS_CLOSING:
      break;

      /* Reset operation of underlying NIC started */
    case NDIS_STATUS_RESET_START:
      if (ssh_kernel_num_cpus() > 1)
        {
          ssh_task_suspend(&interceptor->ip_cfg_thread,
                           SSH_TASK_WAIT_INFINITE);
          InterlockedIncrement(&adapter->ip_cfg_thread_suspended);
        }
      ssh_adapter_enable(adapter, FALSE);
      break;

      /* Reset operation of underlying NIC completed */
    case NDIS_STATUS_RESET_END:
      ssh_adapter_enable(adapter, TRUE);
      if (ssh_kernel_num_cpus() > 1)
        {
          InterlockedDecrement(&adapter->ip_cfg_thread_suspended);
          ssh_task_resume(&interceptor->ip_cfg_thread);
        }
      break;

      /* Network cable connected */
    case NDIS_STATUS_MEDIA_CONNECT:
      adapter->media_connected = 1;
      ssh_adapter_enable(adapter, TRUE);
      break;

      /* Network cable disconnected */
    case NDIS_STATUS_MEDIA_DISCONNECT:
      adapter->media_connected = 0;
      ssh_adapter_enable(adapter, FALSE);
      break;

      /* A new WAN connection established */
    case NDIS_STATUS_WAN_LINE_UP:
      ssh_adapter_wan_line_up(adapter, line_up, buf_size);
      break;

      /* Previously established WAN connection shutting down */
    case NDIS_STATUS_WAN_LINE_DOWN:
      ssh_adapter_wan_line_down(adapter, line_down, buf_size);
      break;
    }

  switch (status)
    {
    /* Functions ssh_adapter_wan_line_up() and ssh_adapter_wan_line_down()
       have already propagated the indications to upper layer, so we shoud
       not do it here any more! */
    case NDIS_STATUS_WAN_LINE_UP:
    case NDIS_STATUS_WAN_LINE_DOWN:
      break;

    /* Because we never call NdisReset, these indications are sent us only
       as an indication that NDIS is resetting an underlying NIC driver.
       We should not forward this indication to upper layers. */
    case NDIS_STATUS_RESET_START:
    case NDIS_STATUS_RESET_END:
      break;

    default:
      /* Ignore the indication if the adapter is either not initialized
         yet or not fully powered. */
      if ((adapter->handle != NULL)
          && (adapter->virtual_mp_power_state == NdisDeviceStateD0)
          && (adapter->underlying_mp_power_state == NdisDeviceStateD0))
        {
          /* Propagate the status notification into the upper layer */
          NdisMIndicateStatus(adapter->handle, status, buf, buf_size);
          adapter->status_indicated = 1;
        }
      break;
    }
}

/*-------------------------------------------------------------------------
  ssh_driver_status_done()

  Signals that state-change operation of underlaying NIC has been completed.

  Arguments:
  protocol_binding_context - binding context

  Returns:
  Notes:

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_status_done(NDIS_HANDLE protocol_binding_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Adapter %@ ProtocolStatusComplete ",
             ssh_adapter_id_st_render, adapter));

  SSH_ASSERT(adapter != NULL);

  /* Notify upper layer that handling of status-change operation is
     completed */
  if (adapter->handle != NULL && adapter->status_indicated)
    {
      adapter->status_indicated = 0;
      NdisMIndicateStatusComplete(adapter->handle);
    }
}

/*-------------------------------------------------------------------------
  ssh_driver_handle_pnp_event()

  Indicates that PnP state of underlaying NIC has changed.

  Arguments:
  protocol_binding_context - binding context
  event - PnP event identifier

  Returns:
  NDIS_STATUS_SUCCESS - always

  Notes:

  Default IRQL: ??
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_handle_pnp_event(NDIS_HANDLE protocol_binding_context,
                            PNET_PNP_EVENT event)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  SshNdisIMInterceptor interceptor;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  SSH_ASSERT(event != NULL);

  if (adapter)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_HIGHSTART,
                        ("Adapter %@ ProtocolPnPEvent: event %u, data:",
                         ssh_adapter_id_st_render, adapter,
                         (unsigned)event->NetEvent),
                        event->Buffer, event->BufferLength);
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_HIGHSTART,
                        ("ProtocolPnPEvent: binding context 0x%p, "
                         "event %u, data:",
                         protocol_binding_context,
                         (unsigned)event->NetEvent),
                        event->Buffer, event->BufferLength);
    }

  switch (event->NetEvent)
    {
    default:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_handle_pnp_event(), Unknown event = %d",
                 event->NetEvent));
      status  = NDIS_STATUS_FAILURE;
      break;

    case NetEventSetPower:
      /* Indicates that Power Manager has sent the Set Power request  */
      {
        NDIS_DEVICE_POWER_STATE *power_state = event->Buffer;

        SSH_ASSERT(adapter != NULL);
        SSH_ASSERT(adapter->interceptor != NULL);

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("ssh_driver_pnp_event:NetEventSetPower"));

        interceptor = (SshNdisIMInterceptor)adapter->interceptor;

        if (adapter->underlying_mp_power_state != *power_state)
          {
            adapter->underlying_mp_power_state = *power_state;

            if (*power_state == NdisDeviceStateD0)
              {
                adapter->standing_by = FALSE;
                ssh_adapter_send_queued_requests(adapter);
              }
            else
              {
                adapter->standing_by = TRUE;
                ssh_interceptor_suspend_if_idle(adapter->interceptor);
              }
          }











#if 0
#endif /* 0 */
      }
      break;

    case NetEventReconfigure:
      /* Indicates that the configuration for network component has
         changed */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventReconfigure"));
      interceptor = (SshNdisIMInterceptor)the_interceptor;
      NdisReEnumerateProtocolBindings(interceptor->protocol_handle);
      break;

    case NetEventQueryPower:
      /* Indicates that Power Manager has sent the Query Power request */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventQueryPower"));
      break;

    case NetEventQueryRemoveDevice:
      /* Indicates that Windows PnP engine has sent Query Remove Device
         request */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventQueryRemoveDevice"));
      break;

    case NetEventCancelRemoveDevice:
      /* Indicates that Windows PnP engine has sent Cancel Remove Device
         request */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventCancelRemoveDevice"));
      break;

    case NetEventBindList:
      /* Indicates that binding list has changed */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventBindList"));
      /* NdisReEnumerateProtocolBindings(the_interceptor->protocol_handle); */
      break;

    case NetEventBindsComplete:
      /* Indicates that binding of protocols and adapters is completed */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventBindComplete"));
      break;

    case NetEventPnPCapabilities:
      /* Indicates whether the PnP capabilities of the networking
         device have been changed */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ssh_driver_pnp_event:NetEventPnPCapabilities"));
      break;
    }

  if (adapter)
    {
      SSH_DEBUG(status == NDIS_STATUS_SUCCESS ? SSH_D_HIGHOK : SSH_D_FAIL,
                ("Adapter %@ ProtocolPnPEvent: status %@", 
                 ssh_adapter_id_st_render, adapter,
                 ssh_ndis_status_render, &status));
    }
  else
    {
      SSH_DEBUG(status == NDIS_STATUS_SUCCESS ? SSH_D_HIGHOK : SSH_D_FAIL,
                ("ProtocolPnPEvent: status %@", 
                 ssh_ndis_status_render, &status));
    }

  return (status);
}

/*-------------------------------------------------------------------------
  NDIS PACKET PROCESSING FUNCTIONS
  -------------------------------------------------------------------------*/

#pragma optimize("t", on)

/*-------------------------------------------------------------------------
  ssh_driver_send_done()

  Indicates that previously submitted NDIS packet to the underlaying NIC
  has been complete processed.

  Arguments:
  protocol_binding_context - binding context
  pkt - reclaimed NDIS packet
  status - NDIS packet processing result

  Returns:
  Notes:

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static void
ssh_driver_send_done(NDIS_HANDLE protocol_binding_context,
                     PNDIS_PACKET ndis_pkt,
                     NDIS_STATUS status)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  SshNdisPacket packet;

  /* Sanity checks */
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  packet = SSH_PACKET_CTX(ndis_pkt);

  SSH_DEBUG(status == NDIS_STATUS_SUCCESS ? SSH_D_LOWOK : SSH_D_FAIL,
            ("Adapter %@ ProtocolSendComplete: packet 0x%p, status=%@",
             ssh_adapter_id_st_render, adapter, packet, 
             ssh_ndis_status_render, &status));

  ssh_interceptor_packet_free(&packet->ip);
}


/*-------------------------------------------------------------------------
  ssh_driver_receive_done()

  Indicates that data receive operations of underlaying NIC has been
  completed.

  Arguments:
  protocol_binding_context - binding context

  Returns:
  Notes:

  Default IRQL: PASSIVE_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_receive_done(NDIS_HANDLE protocol_binding_context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Adapter %@ ProtocolReceiveComplete",
             ssh_adapter_id_st_render, adapter));

  if (adapter->state != SSH_ADAPTER_STATE_RUNNING)
    return;

  switch (adapter->media)
    {
    default:
      SSH_ASSERT(0);
      break;

    case NdisMedium802_3:
    case NdisMediumWan:
      /* Ethernet or Wan */
      NdisMEthIndicateReceiveComplete(adapter->handle);
      break;
    }
}

/*-------------------------------------------------------------------------
  ssh_driver_receive_complete_cb()

  Callback function to be called when asynchronous processing of network
  packet is completed (i.e. when we can free the cloned packet).
  -------------------------------------------------------------------------*/
static void
ssh_driver_receive_complete_cb(NDIS_HANDLE miniport_context,
                               NDIS_PACKET *ndis_pkt,
                               void *context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)miniport_context;
  SshNdisIMInterceptor interceptor;
  SshCpuContext cpu_ctx;
  SshNdisPacket packet;

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;

  packet = SSH_PACKET_CTX(ndis_pkt);

  if (packet->parent_complete_cb != NULL_FNPTR)
    {
      (*(packet->parent_complete_cb))(packet->parent_complete_handle,
                                      packet->parent_complete_np,
                                      packet->parent_complete_param);

      packet->parent_complete_cb = NULL_FNPTR;
    }

  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  ssh_packet_free((SshNetDataPacket)packet, &cpu_ctx->packet_pool);

#ifdef HAS_DELAYED_SEND_THREAD
  if (interceptor->delayed_sends)
    ssh_task_notify(&interceptor->delayed_send_thread, 
                    SSH_TASK_SIGNAL_NOTIFY);
#endif /* HAS_DELAYED_SEND_THREAD */
}

/*-------------------------------------------------------------------------
  ssh_driver_parent_receive_complete_cb()

  Callback function to be called when asynchronous processing of network
  packet is completed (i.e. when we can return the original packet to 
  caller).
  -------------------------------------------------------------------------*/
static void
ssh_driver_parent_receive_complete_cb(NDIS_HANDLE protocol_binding_context,
                                      NDIS_PACKET *packet,
                                      void *context)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(packet != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adapter %@: Returning original NDIS packet 0x%p to caller",
             ssh_adapter_id_st_render, adapter, packet));

  NdisReturnPackets(&packet, 1);
}

/*-------------------------------------------------------------------------
  ssh_driver_copy_and_process()

  Copies and processes the given NDIS_PACKET received from network.
  -------------------------------------------------------------------------*/
ssh_driver_copy_and_process(SshNdisIMAdapter adapter,
                            PNDIS_PACKET ndis_pkt,
                            Boolean async_completion)
{
  SshNdisIMInterceptor interceptor;
  SshCpuContext cpu_ctx;
  SshNdisPacket packet;
  LONG new_value;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ndis_pkt != NULL);

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);  

  /* Silently drop this packet e.g. when we are entering low power state */
  if (!ssh_adapter_is_enabled(adapter))
    return FALSE;

  /* Make a copy of the original packet */
  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  SSH_ASSERT(interceptor != NULL);

  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  packet = ssh_packet_clone(adapter->interceptor, 
                            &cpu_ctx->packet_pool,
                            SSH_PROTOCOL_ETHERNET, 
                            ndis_pkt, 
                            ((!async_completion) ? TRUE : FALSE));
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to clone packet"));
      return FALSE;
    }

  if (async_completion)
    {
      NDIS_SET_PACKET_STATUS(ndis_pkt, NDIS_STATUS_PENDING);
      packet->parent_complete_cb = ssh_driver_parent_receive_complete_cb;
      packet->parent_complete_handle = adapter;
      packet->parent_complete_np = ndis_pkt;
      packet->parent_complete_param = NULL;
    }
  else
    {
      NDIS_SET_PACKET_STATUS(ndis_pkt, NDIS_STATUS_SUCCESS);
      SSH_ASSERT(packet->parent_complete_cb == NULL_FNPTR);
    }

  packet->complete_cb = ssh_driver_receive_complete_cb;
  packet->complete_cb_handle = adapter;
  packet->complete_cb_param = NULL;

  packet->ip.ifnum_in = adapter->ifnum;
  packet->ip.flags |= SSH_PACKET_FROMADAPTER;
  packet->adapter_in = (SshAdapter)adapter;

  new_value = InterlockedIncrement(&adapter->ref_count);
  SSH_ASSERT(new_value > 0);

  SSH_DUMP_PACKET(SSH_D_MY5, ("Cloned packet:"), packet);

  ssh_interceptor_send_to_engine(interceptor, adapter, packet);
  ssh_interceptor_process_enqueued_packets(interceptor, cpu_ctx);

  return TRUE;
}

/*-------------------------------------------------------------------------
  ssh_driver_receive()

  Indicates that new network data (hdr_buf + la_buf) is available on
  underlaying NIC.

  Arguments:
  protocol_binding_context - binding context
  mac_context - ???
  hdr_buf - media header of received data
  hdr_buf_size - media header length
  la_buf - lookahead buffer containing received data
  la_buf_size - lookahead buffer length

  Returns:
  NDIS_STATUS_SUCCESS - data received successfully
  NDIS_STATUS_NOT_ACCEPTED - data rejected
  NDIS_STATUS_PENDING - data receive pending

  Notes:
  The indicated lookahead data must be copied using the memory access
  operations that the underlaying NIC supports.

  The indicated lookahead data is valid until this function returns control
  so the data must be copied immediately into our own NDIS_BUFFERs.

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static NDIS_STATUS
ssh_driver_receive(NDIS_HANDLE protocol_binding_context,
                   NDIS_HANDLE mac_context,
                   PVOID hdr_buf,
                   UINT hdr_buf_size,
                   PVOID la_buf,
                   UINT la_buf_size,
                   UINT pkt_data_size)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  PNDIS_PACKET np;
  UINT bytes_read;
  SshInterceptorPacket ip;
  SshNdisPacket packet;
  UINT bytes_avail, bytes_left;
  NDIS_STATUS status = NDIS_STATUS_NOT_ACCEPTED;

  SSH_ASSERT(adapter != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adapter %@ ProtocolReceive: "
             "mac rx context 0x%p, packet data size %u",
             ssh_adapter_id_st_render, adapter,
             mac_context, (unsigned)pkt_data_size));
  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, 
                    ("Adapter %@ ProtocolReceive: header",
                     ssh_adapter_id_st_render, adapter),
                    hdr_buf, hdr_buf_size);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWSTART, 
                    ("Adapter %@ ProtocolReceive: lookahead data:",
                     ssh_adapter_id_st_render, adapter),
                    la_buf, la_buf_size);

  bytes_avail = hdr_buf_size + la_buf_size;
  bytes_left = pkt_data_size - la_buf_size;

  /* Check if complete packet is available */
  if (bytes_left == 0)
    {
      /* Try to retrieve packet from underlaying layer */
      np = NdisGetReceivedPacket(adapter->binding_handle, mac_context);
      if (np != NULL)
        {
          if (ssh_driver_copy_and_process(adapter, np, FALSE))
            status = NDIS_STATUS_SUCCESS;
          goto end;
        }
    }

  /* Could not retrieve the whole packet */
  ip = ssh_interceptor_packet_alloc(adapter->interceptor, 
                                    SSH_PACKET_FROMADAPTER,
                                    SSH_PROTOCOL_ETHERNET,
                                    adapter->ifnum,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    (bytes_avail + bytes_left));
  if (ip == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate packet"));
      goto end;
    }
  
  packet = CONTAINING_RECORD(ip, SshNdisPacketStruct, ip);

  NDIS_SET_PACKET_HEADER_SIZE(packet->np, hdr_buf_size);

  /* Add the header buffer and lookahead buffer contents into packet */
  if (!ssh_packet_copyin((SshNetDataPacket)packet, 0, hdr_buf, hdr_buf_size)
      || !ssh_packet_copyin((SshNetDataPacket)packet, 
                            hdr_buf_size, la_buf, la_buf_size))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to copy data"));
      goto end;
    }
  packet->transfer_data_offset = bytes_avail;

  /* Check if whole packet has been received */
  if (bytes_left == 0)
    {
      packet->transfer_data_len = 0;
      status = NDIS_STATUS_SUCCESS;
      bytes_read = 0;
    }
  else
    {
      if (!ssh_packet_advance_data_start((SshNetDataPacket)packet, 
                                         bytes_avail, NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to advance data start"));
          ssh_interceptor_packet_free(&packet->ip);
          goto end;
        }

      packet->transfer_data_len = bytes_left;

      /* Ask underlaying NIC to give us the remainder of the data */
      NdisTransferData(&status,
                       adapter->binding_handle,
                       mac_context,
                       la_buf_size,
                       bytes_left,
                       packet->np,
                       &bytes_read);
    }

  SSH_ASSERT(status != NDIS_STATUS_PENDING);

  ssh_driver_transfer_data_done(adapter, packet->np, status, bytes_read);
  status = NDIS_STATUS_SUCCESS;

 end:
  return status;
}

/*-------------------------------------------------------------------------
  ssh_driver_transfer_data_done()

  Indicates that data transfer request submitted to underlaying NIC has
  been completed and requested data is available at indicated NDIS packet.

  Arguments:
  protocol_binding_context - binding context
  pkt - NDIS packet that contains the transferred data
  status - data transfer result
  bytes_transferred - how many bytes has been transferred

  Returns:
  Notes:

  Default IRQL: DISPATCH_LEVEL
  -------------------------------------------------------------------------*/
static VOID
ssh_driver_transfer_data_done(NDIS_HANDLE protocol_binding_context,
                              PNDIS_PACKET pkt,
                              NDIS_STATUS status,
                              UINT bytes_transferred)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  SshNdisIMInterceptor interceptor;
  SshCpuContext cpu_ctx;
  SshNdisPacket packet;
  ULONG new_value; 
  SshMediaHeader media_hdr;

  /* Sanity checks */
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(pkt != NULL);

  SSH_ASSERT(SSH_GET_IRQL() == SSH_DISPATCH_LEVEL);

  packet = SSH_PACKET_CTX(pkt);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adapter %@ ProtocolTransferDataComplete: "
             "packet=0x%p, status=%@, bytes transferred %u",
             ssh_adapter_id_st_render, adapter, packet, 
             ssh_ndis_status_render, &status, bytes_transferred));

  if ((status != NDIS_STATUS_SUCCESS)
      || (bytes_transferred != packet->transfer_data_len))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Adapter %@: Failed to transfer data!",
                 ssh_adapter_id_st_render, adapter));
      ssh_interceptor_packet_free(&packet->ip);
      return;
    }

  if (packet->transfer_data_len)
    {
      if (!ssh_packet_retreat_data_start((SshNetDataPacket)packet, 
                                          packet->transfer_data_offset, 
                                          NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Adapter %@: Failed to retreat data start",
                     ssh_adapter_id_st_render, adapter));
          ssh_interceptor_packet_free(&packet->ip);
          return;
        }
    }

  NDIS_SET_PACKET_STATUS(packet->np, NDIS_STATUS_SUCCESS);
  SSH_ASSERT(packet->parent_complete_cb == NULL_FNPTR);

  packet->complete_cb = ssh_driver_receive_complete_cb;
  packet->complete_cb_handle = adapter;
  packet->complete_cb_param = NULL;

  packet->adapter_in = (SshAdapter)adapter;

  new_value = InterlockedIncrement(&adapter->ref_count);
  SSH_ASSERT(new_value > 0);

  SSH_DUMP_PACKET(SSH_D_MY5, ("Copied packet:"), packet);

  ssh_packet_query_media_header(packet->np, &media_hdr);
  if (media_hdr != NULL)
    {
      if (SSH_ETHER_IS_MULTICAST(media_hdr->dst))
        packet->ip.flags |= SSH_PACKET_MEDIABCAST;

      packet->eth_type = SSH_GET_16BIT(media_hdr->type);
    }

  interceptor = (SshNdisIMInterceptor)adapter->interceptor;
  SSH_ASSERT(interceptor != NULL);
  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

  ssh_interceptor_send_to_engine(interceptor, adapter, packet);
  ssh_interceptor_process_enqueued_packets(interceptor, cpu_ctx);
}

/*-------------------------------------------------------------------------
  ssh_driver_receive_packet()

  Indicates that new complete NDIS Packet is available on underlaying NIC.

  Arguments:
  protocol_binding_context - binding context
  packet - received NDIS packet

  -------------------------------------------------------------------------*/
static INT
ssh_driver_receive_packet(NDIS_HANDLE protocol_binding_context,
                          PNDIS_PACKET pkt)
{
  SshNdisIMAdapter adapter = (SshNdisIMAdapter)protocol_binding_context;
  Boolean pending = 0;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(pkt != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adapter %@ ProtocolReceivePacket: NDIS packet 0x%p",
             ssh_adapter_id_st_render, adapter, pkt));

  if (NDIS_GET_PACKET_STATUS(pkt) == NDIS_STATUS_RESOURCES)
    {
      ssh_driver_copy_and_process(protocol_binding_context, pkt, FALSE);
    }
  else
    {
      if (ssh_driver_copy_and_process(protocol_binding_context, pkt, TRUE))
        pending = 1;
    }

  return pending;
}


/*-------------------------------------------------------------------------
  LOCAL FUNCTIONS
  -------------------------------------------------------------------------*/

static VOID
ssh_driver_do_adapter_bind(PNDIS_STATUS status,
                           NDIS_HANDLE bind_context,
                           PNDIS_STRING name,
                           PVOID system_specific1,
                           PVOID system_specific2,
                           Boolean wan_adapter)
{
  SshNdisIMAdapter adapter = NULL;
  SshNdisIMInterceptor interceptor = (SshNdisIMInterceptor)the_interceptor;
  PWSTR buffer = name->Buffer + SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET;
  USHORT length = name->Length;

  length -= (SSH_ADAPTER_DEV_NAME_BEGIN_OFFSET * sizeof(WCHAR));

  adapter = ssh_adapter_create(buffer, length, interceptor);
  if (adapter == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ProtocolBindAdapter: can't create adapter"));
      *status = NDIS_STATUS_RESOURCES;
      return;
    }

  /* Start the binding process by opening the underlaying device */
  *status = ssh_adapter_open(adapter, bind_context,
                             system_specific1, wan_adapter);




  SSH_DEBUG(*status == NDIS_STATUS_SUCCESS ? SSH_D_HIGHOK : SSH_D_FAIL,
            ("ProtocolBindAdapter: leave, status %@", 
             ssh_ndis_status_render, status));
}
