/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode IP routing table retrieval and modification functions
   for Windows NT4, Windows 2000 and Windows XP packet interceptor
   drivers.
*/

#ifndef SSH_WIN_IP_ROUTE_H
#define SSH_WIN_IP_ROUTE_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_ip_routing_table_refresh()

  Refreshes the packet interceptor driver's internal routing table by
  re-reading routes from IP device. This function should be called by the
  interceptor whenever it has a reason to suspect that the operating
  system's routing table has been changed.

  --------------------------------------------------------------------------*/

Boolean
ssh_ip_routing_table_refresh(SshInterceptor interceptor);


/*--------------------------------------------------------------------------
  ssh_ip_routing_table_free()

  Destroys the interceptor driver's internal routing table and frees all
  memory blocks allocated for it.  
  --------------------------------------------------------------------------*/

void
ssh_ip_routing_table_free(SshInterceptor interceptor);


/*--------------------------------------------------------------------------
  ssh_ip_route_lookup()
  
  Retrieves routing information for a given destination IP address and
  then calls the completion routine.
  --------------------------------------------------------------------------*/

void __fastcall
ssh_ip_route_lookup(SshInterceptor interceptor,
                    SshInterceptorRouteKey key,
                    SshInterceptorRouteCompletion completion,
                    PVOID context);


/*--------------------------------------------------------------------------
  ssh_ip_route_add()
  
  Add a route to `ip' through gateway `gateway_or_local_ip'. 
  --------------------------------------------------------------------------*/

void
ssh_ip_route_add(SshInterceptor interceptor,
                 SshIpAddr ip,
                 SshIpAddr gw_or_local_ip,
                 SshInterceptorIfnum ifnum,
                 SshIPDeviceCompletionCB callback,
                 void *context);


/*--------------------------------------------------------------------------
  ssh_ip_route_remove()
  
  Remove the route to 'ip' (including netmask) through the gateway
  'gateway_or_local_ip'.
  --------------------------------------------------------------------------*/

void
ssh_ip_route_remove(SshInterceptor interceptor,
                    SshIpAddr ip,
                    SshIpAddr gw_or_local_ip,
                    SshInterceptorIfnum ifnum,
                    SshIPDeviceCompletionCB callback,
                    void *context);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_WIN_IP_ROUTE_H */

