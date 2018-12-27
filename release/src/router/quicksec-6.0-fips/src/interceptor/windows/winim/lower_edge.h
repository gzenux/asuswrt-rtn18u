/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the prototypes for functions that are called by NDIS when
   a networking device tries to communicate with a protocol where it is bound.

   See the MS DDK documentation for detailed decription of these functions.
*/

#ifndef SSH_LOWER_EDGE_H
#define SSH_LOWER_EDGE_H

#ifdef __cplusplus
extern "C" {
#endif

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
                                    BOOLEAN enable);


PNDIS_STRING ssh_interceptor_service_name;

#ifdef __cplusplus
}
#endif

#endif /* SSH_LOWER_EDGE_H */

