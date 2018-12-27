/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode IP interface information retrieval and modification functions
   for Windows NT4, Windows 2000, Windows XP an Windows Server 2003 packet
   interceptor drivers.
*/

#ifndef SSH_WIN_IP_INTERFACE_H
#define SSH_WIN_IP_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_ip_interface_list_refresh()

  Refreshes the packet interceptor driver's internal IP interface list 
  by re-reading interface information from IP device. This function should 
  be called by the interceptor whenever it has a reason to suspect that 
  some of the IP interfaces has gone up or down.
  --------------------------------------------------------------------------*/

Boolean
ssh_ip_interface_list_refresh(SshInterceptor interceptor);


/*--------------------------------------------------------------------------
  ssh_ip_interface_report_send()

  Composes an interface report and sends it to IPSec engine. Returns FALSE
  if memory could not be allocated for the interface report.
  --------------------------------------------------------------------------*/

Boolean
ssh_ip_interface_report_send(SshInterceptor interceptor);


/*--------------------------------------------------------------------------
  ssh_ip_interface_list_free()

  Destroys the interceptor driver's internal IP interface list and frees all
  memory blocks allocated for it.  
  --------------------------------------------------------------------------*/

void
ssh_ip_interface_list_free(SshInterceptor interceptor);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_WIN_IP_INTERFACE_H */

