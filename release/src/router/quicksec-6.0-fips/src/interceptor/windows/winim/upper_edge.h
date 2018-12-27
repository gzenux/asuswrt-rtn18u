/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the prototypes for functions that are called by NDIS
   when a protocol tries to communicate with a network device (miniport)
   where it is bound.

   See the Windows DDK documentation for detailed decription of these
   functions.
*/

#ifndef SSH_UPPER_EDGE_H
#define SSH_UPPER_EDGE_H

#ifdef __cplusplus
extern "C" {
#endif

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
                                    BOOLEAN enable);

/*--------------------------------------------------------------------------
  Worker thread restarting delayed send operations.
  --------------------------------------------------------------------------*/
VOID
ssh_driver_delayed_send_thread(SshNdisIMInterceptor interceptor);

#ifdef __cplusplus
}
#endif

#endif /* SSH_UPPER_EDGE_H */
