/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the implementation of IP address and route change
   notification functions for Windows Vista, Windows Server 2008 and
   Windows 7.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  ------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "ip_notify.h"
#include "kernel_timeouts.h"
#include <netioapi.h>

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorIpNotify"


typedef struct SshAddressAddContextRec
{
  SshInterceptor interceptor;
  MIB_UNICASTIPADDRESS_ROW row;
  SshUInt32 ttl;
} SshAddressAddContextStruct, *SshAddressAddContext;

/*--------------------------------------------------------------------------
  CONSTANTS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

static void
ssh_address_valid_timeout(void *context);

/* IP address and routing table notification handlers */
static void
ssh_address_change_notify(SshInterceptor interceptor,
                          PMIB_UNICASTIPADDRESS_ROW row,
                          MIB_NOTIFICATION_TYPE notification_type);

static void
ssh_route_change_notify(SshInterceptor interceptor,
                        PMIB_IPFORWARD_ROW2 row,
                        MIB_NOTIFICATION_TYPE notification_type);


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  -------------------------------------------------------------------------*/

Boolean
ssh_register_ip_notifications(SshInterceptor generic_interceptor)
{
  SshNt6Interceptor interceptor = (SshNt6Interceptor)generic_interceptor;
  NTSTATUS status;

  interceptor->address_change_handle = NULL;
  interceptor->route_change_handle = NULL;

  status = NotifyUnicastIpAddressChange(AF_UNSPEC, 
                                        ssh_address_change_notify,
                                        interceptor, 
                                        TRUE, 
                                        &interceptor->address_change_handle);
  if (status == STATUS_SUCCESS)
    {
      status = NotifyRouteChange2(AF_UNSPEC,
                                  ssh_route_change_notify,
                                  interceptor,
                                  TRUE,
                                  &interceptor->route_change_handle);
    }

  if (status != STATUS_SUCCESS)
    {
      ssh_cancel_ip_notifications(generic_interceptor);
      return FALSE;
    }

  return TRUE;
}


void
ssh_cancel_ip_notifications(SshInterceptor generic_interceptor)
{
  SshNt6Interceptor interceptor = (SshNt6Interceptor)generic_interceptor;

  if (interceptor->route_change_handle)
    {
      CancelMibChangeNotify2(interceptor->route_change_handle);
      interceptor->route_change_handle = NULL;
    }

  if (interceptor->address_change_handle)
    {
      CancelMibChangeNotify2(interceptor->address_change_handle);
      interceptor->address_change_handle = NULL;
    }
}


/*---------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

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
      switch (ctx->row.DadState)
        {
        case IpDadStateTentative:
          if (ctx->ttl)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("IP address[%@], DAD state = TENTATIVE "
                         "(retry count=%u)", 
                         ssh_ipaddr_render, &ip, 
                         ctx->ttl));

              /* DAD is still pending and this address is still tentative.
                 Let's check it again after 100 milliseconds. */
              ctx->ttl--;
              ssh_kernel_timeout_register(0, 100000, 
                                          ssh_address_valid_timeout,
                                          ctx);
              return;
            }
          break;
        
        case IpDadStatePreferred:
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Address change: IP address[%@] added", 
                     ssh_ipaddr_render, &ip));
          SSH_IP_REFRESH_REQUEST(ctx->interceptor);
          break;

        case IpDadStateInvalid:
        case IpDadStateDuplicate:
        case IpDadStateDeprecated:
        default:
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("IP address[%@], DAD state=%u "
                     "(address addition failed)", 
                     ssh_ipaddr_render, &ip, 
                     ctx->row.DadState,
                     ctx->ttl));
          break;
        }
    }
 
  /* done */
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
ssh_address_change_notify(SshInterceptor interceptor,
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
ssh_route_change_notify(SshInterceptor interceptor,
                        PMIB_IPFORWARD_ROW2 row,
                        MIB_NOTIFICATION_TYPE notification_type)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, 
    ("Route change notification; refreshing IP and routing information"));

  SSH_IP_REFRESH_REQUEST(interceptor);
}



