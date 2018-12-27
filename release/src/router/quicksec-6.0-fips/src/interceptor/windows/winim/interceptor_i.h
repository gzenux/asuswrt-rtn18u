/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains definitions for SSH Interceptor object.
*/

#ifndef SSH_INTERCEPTOR_I_H
#define SSH_INTERCEPTOR_I_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#define HAS_DELAYED_SEND_THREAD  
#define HAS_IEEE802_3_PASSTHRU
#define HAS_INTERFACE_NAME_MAPPINGS
#define SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE    800
#define SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE    1600


/* This compilation flag must be defined for NDIS intermediate driver */
#define SSH_IM_INTERCEPTOR

#include "interceptor_i_common.h"
#include "ndis5_packet_pool.h"
#ifdef DEBUG_LIGHT
#include "ndis_render.h"
#endif /* DEBUG_LIGHT */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DELAYED_SEND_THREAD_ID    (SSH_LAST_COMMON_THREAD_ID + 1)
#define SSH_ADDRESS_CHANGE_THREAD_ID  (SSH_LAST_COMMON_THREAD_ID + 2)
#define SSH_ROUTE_CHANGE_THREAD_ID    (SSH_LAST_COMMON_THREAD_ID + 3)

typedef KIRQL SSH_IRQL;

#define SSH_PASSIVE_LEVEL      PASSIVE_LEVEL
#define SSH_APC_LEVEL          APC_LEVEL
#define SSH_DISPATCH_LEVEL     DISPATCH_LEVEL

#define SSH_GET_IRQL()         KeGetCurrentIrql()
#define SSH_RAISE_IRQL(n,o)    do { KeRaiseIrql((n),(o)); } while (0);
#define SSH_LOWER_IRQL(n)      do { KeLowerIrql((n)); } while (0);

/* NDIS REV. 4.0 - */  
#define SSH_MAJOR_NDIS_VERSION        0x04
#define SSH_MINOR_NDIS_VERSION        0x00

/* NDIS_MAC_OPTION_8021Q_VLAN not defined in Win2K DDK */
#ifndef NDIS_MAC_OPTION_8021Q_VLAN
#define NDIS_MAC_OPTION_8021Q_VLAN       0x00000200
#endif /* NDIS_MAC_OPTION_8021Q_VLAN */

/* Macro for setting IP configuration refresh request */

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  SshNdisIMInterceptor

  "Controller" object that contains the Windows 2000 specific global 
  attributes, adapter and network connection lists, transform engine and 
  I/O device for policy manager communication.
  --------------------------------------------------------------------------*/

typedef struct SshNdisIMInterceptorRec
{
  /* Generic interceptor object. DO NOT move! */
  SshInterceptorStruct ;

  /* Interceptor initialization completed (i.e. DriverEntry returned) */
  BOOLEAN init_complete;

  /* Number of network providers initialized */
  SshUInt16 net_providers;

  /* Handle to TDI interface */
  HANDLE tdi_handle;
  
  /* Handles that are global to our driver */
  NDIS_HANDLE miniport_handle;
  NDIS_HANDLE protocol_handle;

} SshNdisIMInterceptorStruct, *SshNdisIMInterceptor;

#include "adapter.h"

/*--------------------------------------------------------------------------
  MACROS AND INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  ssh_interceptor_register_stack_notifications()
  
  Registers some callbacks with IP protocol stack so that we get 
  notifications from some transport protocol specific events.
  
  Arguments:
  interceptor - SshInterceptor object
  enable - register/deregister flag
  
  Returns:
  NDIS_STATUS_SUCCESS - operation succeeded
  NDIS_STATUS_FAILURE - otherwise

  Notes:
  ------------------------------------------------------------------------*/
NDIS_STATUS
ssh_interceptor_register_stack_notifications(SshNdisIMInterceptor interceptor,
                                             BOOLEAN enable);


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Unload handler for SSH Interceptor driver.
  --------------------------------------------------------------------------*/
DRIVER_UNLOAD DriverUnload;

/*--------------------------------------------------------------------------
  Sends the given packet to IPSec engine.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_send_to_engine(SshNdisIMInterceptor interceptor,
                               SshNdisIMAdapter adapter,
                               SshNdisPacket packet);

/*--------------------------------------------------------------------------
  Processes all packets previously enqued by the current CPU.

  This function must be called after engine callback returns (either once
  per each captured packet or when the last packet of multi-packet send
  receive operation has been sent to engine). 
  --------------------------------------------------------------------------*/
void
ssh_interceptor_process_enqueued_packets(SshNdisIMInterceptor interceptor, 
                                         SshCpuContext cpu_ctx);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_INTERCEPTOR_I_H */
