/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of functions for the virtual
   adapter object that is layered above a real NDIS networking device
   driver.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#include "wan_interface.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE                 "SshInterceptorAdapter"

/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

#pragma warning(disable : 4100)
SshInterceptorIfnum
ssh_adapter_ifnum_lookup(SshInterceptor interceptor,
                         unsigned char *mac_address,
                         size_t mac_address_len,
                         SshIPInterfaceID id)
{
  SshInterceptorIfnum ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  PLIST_ENTRY entry;
  SshAdapter adapter = NULL;

  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Performing adapter lookup..."));

  /* Interface ID type must be LUID */
  if (id->id_type != SSH_IF_ID_LUID)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Adapter identifier is not LUID!"));
      return SSH_INTERCEPTOR_INVALID_IFNUM;
    }

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  if (IsListEmpty(&interceptor->adapter_list) == TRUE)
    {
      ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Interceptor not bound to any adapters!"));
      return SSH_INTERCEPTOR_INVALID_IFNUM;
    }

  /* Check whether we already know this description */
  for (entry = interceptor->adapter_list.Flink; 
       (entry != &interceptor->adapter_list) && (adapter == NULL); 
       entry = entry->Flink)
    {
      SshNdisFilterAdapter a;
      
      a = CONTAINING_RECORD(entry, SshNdisFilterAdapterStruct, link);

      if ((a->luid == id->u.luid) || (a->own_luid == id->u.luid))
        {
          adapter = (SshAdapter)a;
          break;
        }
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
      else
        {
          ssh_kernel_rw_mutex_lock_read(&a->wan_if_lock);
          if (a->wan_if_cnt > 0)
            {
              SshWanInterface wi;
              PLIST_ENTRY wi_entry;

              for (wi_entry = a->wan_if.Flink;
                   wi_entry != &(a->wan_if);
                   wi_entry = wi_entry->Flink)
                {
                  wi = CONTAINING_RECORD(wi_entry, 
                                         SshWanInterfaceStruct, link);

                  if (wi->luid == id->u.luid) 
                    {
                      adapter = (SshAdapter)a;
                      break;
                    }
                }
            }
          ssh_kernel_rw_mutex_unlock_read(&a->wan_if_lock);
        }
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
    }

  if (adapter != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Interface LUID 0x%08llx matches adapter '%s'",
                 id->u.luid, adapter->ssh_name));
      ifnum = adapter->ifnum;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Didn't find any bound adapter matching the "
                 "search criteria (LUID 0x%08llx).",
                 id->u.luid));
    }

  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  return ifnum;
}
#pragma warning(default : 4100)


Boolean
ssh_adapter_oid_request_send(SshAdapter gen_adapter,
                             SshOidRequest oid_request)
{
  SshNdisFilterAdapter adapter = (SshNdisFilterAdapter)gen_adapter;
  SshInterceptorOidRequest request;
  NDIS_OID_REQUEST *native_req;
  NDIS_STATUS status;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(oid_request != NULL);

  request = ssh_calloc(1, sizeof(*request));
  if (request == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate memory for OID request!"));
      return FALSE;
    }

  request->completion_event = 
    ssh_event_create(oid_request->oid, NULL_FNPTR, NULL);
  if (request->completion_event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to create completion event for OID request"));
      ssh_free(request);
      return FALSE;
    }

  request->request = oid_request;
  native_req = &request->native_oid_request;
  native_req->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
  native_req->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;
  native_req->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
  native_req->Timeout = 3;
  native_req->RequestId = adapter;
  native_req->RequestHandle = adapter->handle; 

  switch (oid_request->type)
    {
    case SSH_OID_REQUEST_QUERY_INFORMATION:
      native_req->RequestType = NdisRequestQueryInformation;
      native_req->DATA.QUERY_INFORMATION.Oid = oid_request->oid;
      native_req->DATA.QUERY_INFORMATION.InformationBuffer = 
        oid_request->buffer;
      native_req->DATA.QUERY_INFORMATION.InformationBufferLength = 
        oid_request->buffer_len;
      break;

    case SSH_OID_REQUEST_SET_INFORMATION:
      native_req->RequestType = NdisRequestSetInformation;
      native_req->DATA.SET_INFORMATION.Oid = oid_request->oid;
      native_req->DATA.SET_INFORMATION.InformationBuffer = 
        oid_request->buffer;
      native_req->DATA.SET_INFORMATION.InformationBufferLength = 
        oid_request->buffer_len;
      break;
    
    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_kernel_mutex_lock(&adapter->oid_request_list_lock);
  InitializeListHead(&request->link);
  InsertTailList(&adapter->oid_request_list, &request->link);
  ssh_kernel_mutex_unlock(&adapter->oid_request_list_lock);

  ssh_event_reset(request->completion_event);
  status = NdisFOidRequest(adapter->handle, native_req);
  if (status == NDIS_STATUS_PENDING)
    ssh_event_wait(1, &request->completion_event, NULL);

  ssh_kernel_mutex_lock(&adapter->oid_request_list_lock);
  RemoveEntryList(&request->link);
  ssh_kernel_mutex_unlock(&adapter->oid_request_list_lock);

  switch (oid_request->type)
    {
    case SSH_OID_REQUEST_QUERY_INFORMATION:
      oid_request->bytes_needed = 
        native_req->DATA.QUERY_INFORMATION.BytesNeeded;
      oid_request->bytes_transferred =
        native_req->DATA.QUERY_INFORMATION.BytesWritten;
      break;

    case SSH_OID_REQUEST_SET_INFORMATION:
      oid_request->bytes_needed = 
        native_req->DATA.SET_INFORMATION.BytesNeeded;
      oid_request->bytes_transferred =
        native_req->DATA.SET_INFORMATION.BytesRead;
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_event_destroy(request->completion_event);
  ssh_free(request);

  if (oid_request->status == NDIS_STATUS_SUCCESS)
    return TRUE;
  else
    return FALSE;
}


