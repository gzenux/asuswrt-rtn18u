/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains internal definitions for Windows Vista/"Longhorn"
   Interceptor object.
*/

#ifndef SSH_INTERCEPTOR_I_H
#define SSH_INTERCEPTOR_I_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#define HAS_INTERFACE_NAME_MAPPINGS
#define HAS_IEEE802_3_PASSTHRU
#define HAS_PER_CPU_PACKET_POOLS

#include "interceptor_i_common.h"
#include "ndis6_packet_pool.h"
#include "ndis_render.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

typedef KIRQL SSH_IRQL;

#define SSH_PASSIVE_LEVEL      PASSIVE_LEVEL
#define SSH_APC_LEVEL          APC_LEVEL
#define SSH_DISPATCH_LEVEL     DISPATCH_LEVEL

#define SSH_GET_IRQL()         KeGetCurrentIrql()
#define SSH_RAISE_IRQL(n,o)    do { KeRaiseIrql((n),(o)); } while (0);
#define SSH_LOWER_IRQL(n)      do { KeLowerIrql((n)); } while (0);


/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

typedef struct SshInterceptorOidRequestRec
{
  /* For linked lists */
  LIST_ENTRY link;

  /* Native NDIS OID request structure */
  NDIS_OID_REQUEST native_oid_request;

  /* Pointer to platfor independent OID request structure */
  SshOidRequest request;

  /* Completion event */
  SshEvent completion_event;
} SshInterceptorOidRequestStruct, *SshInterceptorOidRequest;


typedef struct SshNdisFilterAdapterRec
{
#pragma warning(push)
#pragma warning(disable : 4201)
  /* Generic Windows adapter object; DO NOT move! */
  SshNt6AdapterStruct ;
#pragma warning(pop)

  /* The underlying adapter ndis version. */
  SshUInt16 ndis_version;

  unsigned char info_buffer[256];

  /* List of our own pending OID requests */
  LIST_ENTRY oid_request_list;
  SshKernelMutexStruct oid_request_list_lock;

} SshNdisFilterAdapterStruct, *SshNdisFilterAdapter;


typedef struct SshNdisFilterInterceptorRec
{
#pragma warning(push)
#pragma warning(disable : 4201)
  /* Generic Windows interceptor object; DO NOT move! */
  SshNt6InterceptorStruct ;
#pragma warning(pop)

  /* NDIS Filter driver specific data */
  NDIS_HANDLE filter_driver_handle;
} SshNdisFilterInterceptorStruct, *SshNdisFilterInterceptor;


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_INTERCEPTOR_I_H */
