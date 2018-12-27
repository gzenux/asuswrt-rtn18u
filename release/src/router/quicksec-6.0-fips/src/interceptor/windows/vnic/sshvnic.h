/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definition of the interface between interceptor and virtual NIC.
*/

#ifndef _SSHVNIC_H
#define _SSHVNIC_H

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
  INCLUDE_FILES
  --------------------------------------------------------------------------*/

#include "sshvnic_def.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_ICEPT_VNIC_IF_VERSION_1 1
#define SSH_ICEPT_VNIC_IF_VERSION_2 2
#define SSH_ICEPT_VNIC_IF_VERSION   SSH_ICEPT_VNIC_IF_VERSION_2
#define SSH_ICEPT_VNIC_SIGNATURE    0x21485353 /* SSH! */

/* Definitions for SshVnicConfigureCB */
#define SSH_VNIC_CONF_ETH_ADDRESS   1

#pragma pack(push, SSHVNIC_H)
#pragma pack(8)

/*--------------------------------------------------------------------------
  Interceptor functions called by Virtual NIC
  --------------------------------------------------------------------------*/

/* Increment interface reference count */
typedef void (*SshInterfaceLockCB)(void *context);

/* Decrement interface reference count */
typedef void (*SshInterfaceReleaseCB)(void *context);

/* forward outgoing packet to correct destination */
typedef NDIS_STATUS (*SshMiniportSendCB)(void *context,
                                         unsigned char *flat_packet,
                                         unsigned int _packet_len);

/* Interface version 1 */
typedef struct SshIceptDrvIfRec_V1
{
  unsigned int    signature;  /* SSH! */
  unsigned short  version;    /* Interface version */
  unsigned short  size;       /* Size of structure */
  void *          cb_context; /* Context parameter for callback functions */
  SshInterfaceLockCB    lock_cb;
  SshInterfaceReleaseCB release_cb;
  SshMiniportSendCB     send_cb;
} SshIceptDrvIfStruct_V1;

/* Current version */
typedef SshIceptDrvIfStruct_V1 SshIceptDrvIfStruct;
typedef SshIceptDrvIfStruct *  SshIceptDrvIf;



/*--------------------------------------------------------------------------
  Virtual NIC functions called by the interceptor
  --------------------------------------------------------------------------*/

typedef enum
{
  VNIC_CONNECT_ID_MEDIA_ADDRESS
} SshVnicConnectIdType;

typedef struct SshVnicConnectIdRec
{
  SshVnicConnectIdType type;

  union
  {
    struct
    {
      unsigned int addr_len;
      unsigned char *addr;
    } media_addr;
  };
} SshVnicConnectIdStruct, *SshVnicConnectId;

/* establish connection from interceptor to  vnic. inform
   vnic about interceptor interface */
typedef BOOLEAN (*SshInterceptorConnectCB)(void *context,
                                           SshIceptDrvIf);

typedef void * (*SshInterceptorConnectV2CB)(SshVnicConnectId vnic_id,
                                            SshIceptDrvIf);

/* disconnect interceptor from vnic */
typedef void (*SshInterceptorDisconnectCB)(void *context);

/* send configuration data */
typedef BOOLEAN (*SshVnicConfigureCB)(void *context,
                                      UINT type,
                                      void *data);

/* plug in the cable */
typedef BOOLEAN (*SshVnicEnableCB)(void *context);

/* unplug the cable */
typedef void (*SshVnicDisableCB)(void *context);

/* send packets upstream stack */
typedef void (*SshVnicIndicateReceiveCB)(void *context,
                                         unsigned char *flat_packet,
                                         unsigned int flat_packet_len);

/* Interface version 1 */
typedef struct SshVnicDrvIfRec_V1
{
  unsigned int    signature;  /* SSH! */
  unsigned short  version;    /* Interface version */
  unsigned short  size;       /* Size of structure */
  void *          cb_context; /* Context parameter for callback functions */
  SshInterceptorConnectCB     connect_cb;
  SshInterceptorDisconnectCB  disconnect_cb;
  SshVnicEnableCB             enable_cb;
  SshVnicDisableCB            disable_cb;
  SshVnicConfigureCB          configure_cb;
  SshVnicIndicateReceiveCB    receive_cb;
} SshVnicDrvIfStruct_V1, *SshVnicDrvIf_V1;

/* Interface version 2 (compatible with Windows 7) */
typedef struct SshVnicDrvIfRec_V2
{
  unsigned int    signature;  /* SSH! */
  unsigned short  version;    /* Interface version */
  unsigned short  size;       /* Size of structure */
  SshInterceptorConnectV2CB   connect_cb;
  SshInterceptorDisconnectCB  disconnect_cb;
  SshVnicEnableCB             enable_cb;
  SshVnicDisableCB            disable_cb;
  SshVnicConfigureCB          configure_cb;
  SshVnicIndicateReceiveCB    receive_cb;
} SshVnicDrvIfStruct_V2, *SshVnicDrvIf_V2;

/* Current version */
typedef SshVnicDrvIfStruct_V2  SshVnicDrvIfStruct;
typedef SshVnicDrvIfStruct     *SshVnicDrvIf;

#pragma pack(pop, SSHVNIC_H)

#ifdef __cplusplus
}
#endif


#endif /* _SSHVNIC_H */
