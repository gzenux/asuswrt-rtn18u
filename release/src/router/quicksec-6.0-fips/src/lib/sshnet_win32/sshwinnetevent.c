/**
   @copyright
   Copyright (c) 2008 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows implementation of sshnetevent.h API. This implementation
   uses the IP Helper library and the SSH eventloop.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetevent.h"
#include "ssheloop.h"
#include "sshtimeouts.h"

#ifdef WINDOWS

#define SSH_DEBUG_MODULE "SshWinNetEvent"

/* Event Listener handle */
struct SshNetconfigEventHandleRec
{
  HANDLE interface_event;
  HANDLE route_event;
#if WINVER >= 0x0600
  SshTimeout state;
#else
  OVERLAPPED interface_olp;
  OVERLAPPED route_olp;
#endif /* WINVER < 0x0600 */
  SshNetconfigEventCallback callback;
  void * callback_context;
};

#if WINVER >= 0x0600
typedef struct SshNetconfigEventAddrInfoRec
{
  SshNetconfigEventHandle handle;
  MIB_UNICASTIPADDRESS_ROW row;
}SshNetconfigEventAddrInfoStruct, *SshNetconfigEventAddrInfo;

static void
netconfig_event_check_dad_state(void *context)
{
  SshNetconfigEventAddrInfo addr_info = context;

  if (GetUnicastIpAddressEntry(&addr_info->row) == NO_ERROR)
    {
      if (addr_info->row.DadState != IpDadStatePreferred)
        {
          ssh_register_timeout(addr_info->handle->state,
                               1, 0,
                               netconfig_event_check_dad_state,
                               addr_info);
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Address addition notification"));
          (*addr_info->handle->callback)
                              (SSH_NETCONFIG_EVENT_ADDRESS_CHANGED,
                              addr_info->row.InterfaceIndex,
                              addr_info->handle->callback_context);
          ssh_free(addr_info);
        }
    }
}

static void WINAPI
netconfig_ip_addr_change_callback(PVOID context,
                                  PMIB_UNICASTIPADDRESS_ROW row,
                                  MIB_NOTIFICATION_TYPE notification_type)
{
  SshNetconfigEventHandle handle = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
           ("Address change notification. Calling appropriate callback"));

  switch(notification_type)
    {
    case MibParameterNotification:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Address parameter change notification"));
      return;

    case MibInitialNotification:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Initial notification"));
      return;

    case MibAddInstance:
      /* Check for DAD state */
      if (row->DadState != IpDadStatePreferred)
        {
          SshNetconfigEventAddrInfo addr_info;
          addr_info = ssh_calloc(1, sizeof(SshNetconfigEventAddrInfoStruct));
          if (addr_info == NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Unable to process notification"));
              return;
            }
          addr_info->handle = handle;
          addr_info->row = *row;
          ssh_register_timeout(handle->state,
                               1, 0,
                               netconfig_event_check_dad_state,
                               addr_info);
          return;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Address addition notification"));
          (*handle->callback)(SSH_NETCONFIG_EVENT_ADDRESS_CHANGED,
                              row->InterfaceIndex,
                              handle->callback_context);
        }
        return;
    case MibDeleteInstance:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Address delete notification"));
      (*handle->callback)(SSH_NETCONFIG_EVENT_ADDRESS_CHANGED,
                          row->InterfaceIndex, handle->callback_context);
    }
}





#define ROUTE_WORKAROUND WINAPI

static void ROUTE_WORKAROUND
netconfig_route_change_callback(SshNetconfigEventHandle handle,
                                PMIB_IPFORWARD_ROW2 row,
                                MIB_NOTIFICATION_TYPE notification_type)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
             ("Route change notification. Calling appropriate callback"));
  if (notification_type == MibInitialNotification)
    {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Initial route change notification received"));
          return; /* Ignore initial notification */
    }

  (*handle->callback)(SSH_NETCONFIG_EVENT_ROUTES_CHANGED,
                      SSH_INVALID_IFNUM,
                      handle->callback_context);
}

#else /* WINVER >= 0x0600 */
static void
net_config_event_notify_interface_change(void * context)
{
  HANDLE addr_handle;
  SshNetconfigEventHandle handle = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
             ("Address change notification. Calling appropriate callback"));
  (*handle->callback)(SSH_NETCONFIG_EVENT_ADDRESS_CHANGED,
                         SSH_INVALID_IFNUM, handle->callback_context);
  if (NotifyAddrChange(&addr_handle,
                       &handle->interface_olp) !=
                                ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to register for interface change event"));
    }
}

static void
net_config_event_notify_route_change(void *context)
{
  HANDLE route_handle;
  SshNetconfigEventHandle handle = context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
             ("Route change notification. Calling appropriate callback"));
  (*handle->callback)(SSH_NETCONFIG_EVENT_ROUTES_CHANGED,
                      SSH_INVALID_IFNUM,
                      handle->callback_context);
  if (NotifyRouteChange(&route_handle,
                        &handle->route_olp) !=
                             ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to register for route change event"));
    }
}
#endif /* WINVER >= 0x0600 */

static void
net_config_event_handle_destroy(SshNetconfigEventHandle handle)
{
  if (handle)
    {
#if WINVER >= 0x0600
      if (handle->state)
        {
          ssh_cancel_timeout(handle->state);
          ssh_free(handle->state);
        }
      if (handle->interface_event)
        CancelMibChangeNotify2(handle->interface_event);
      if (handle->route_event)
        CancelMibChangeNotify2(handle->route_event);
#else /* WINVER >= 0x0600 */
      if (handle->interface_event)
        {
          ssh_event_loop_unregister_handle(handle->interface_event);
          CancelIPChangeNotify(&handle->interface_olp);
          CloseHandle(handle->interface_event);
        }
      if (handle->route_event)
        {
          ssh_event_loop_unregister_handle(handle->route_event);
          CancelIPChangeNotify(&handle->route_olp);
          CloseHandle(handle->route_event);
        }
#endif /* WINVER >= 0x0600 */
      ssh_free(handle);
    }
}

SshNetconfigEventHandle
ssh_netconfig_register_event_callback(SshNetconfigEventCallback callback,
                                      void *context)
{
  SshNetconfigEventHandle handle;



#if WINVER < 0x0600
  HANDLE addr_handle, route_handle;
#endif /* WINVER < 0x0600 */

  handle = ssh_calloc(1, sizeof (struct SshNetconfigEventHandleRec));
  if (handle == NULL)
    goto error;
  handle->callback = callback;
  handle->callback_context = context;

#if WINVER >= 0x0600
  handle->state = ssh_calloc(1, sizeof(SshTimeoutStruct));
  if (handle->state == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to create timeout structure"));
      goto error;
    }
  if (NotifyUnicastIpAddressChange(AF_UNSPEC,
                                   netconfig_ip_addr_change_callback,
                                   handle,
                                   FALSE,
                                   &handle->interface_event) != NO_ERROR)
  {
    SSH_DEBUG(SSH_D_FAIL, ("Unable to register for interface change event"));
    handle->interface_event = NULL;
    goto error;
  }
  if (NotifyRouteChange2(AF_UNSPEC,
                         (PIPFORWARD_CHANGE_CALLBACK)
                         netconfig_route_change_callback,
                         handle,
                         TRUE,
                         &handle->route_event) != NO_ERROR)
  {
    SSH_DEBUG(SSH_D_FAIL, ("Unable to register for route change event"));
    handle->route_event = NULL;
    goto error;
  }
#else /* WINVER >= 0x0600 */
  handle->interface_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (handle->interface_event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to create interface change event"));
      goto error;
    }
  handle->interface_olp.hEvent = handle->interface_event;
  if (NotifyAddrChange(&addr_handle,
                       &handle->interface_olp) !=
                                ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to register for interface change event"));
      goto error;
    }
  ssh_event_loop_register_handle(handle->interface_event,
                                 TRUE,
                                 net_config_event_notify_interface_change,
                                 handle);
  handle->route_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (handle->route_event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to create route change event"));
      goto error;
    }
  handle->route_olp.hEvent = handle->route_event;
  if (NotifyRouteChange(&route_handle,
                        &handle->route_olp) !=
                             ERROR_IO_PENDING)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to register for route change event"));
      goto error;
    }

  ssh_event_loop_register_handle(handle->route_event,
                                 TRUE,
                                 net_config_event_notify_route_change,
                                 handle);
#endif /* WINVER >= 0x0600 */
  return handle;
error:
  net_config_event_handle_destroy(handle);
  return NULL;
}

SshNetconfigError
ssh_netconfig_unregister_event_callback(SshNetconfigEventHandle handle)
{
  if (handle == NULL)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  net_config_event_handle_destroy(handle);
  return SSH_NETCONFIG_ERROR_OK;
}
#endif /* WINDOWS */
