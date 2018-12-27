/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS 6.0 (and later) compatible packet pool definitions
   and inline functions for Windows Vista/"Longhorn" Interceptor object.
*/

#ifndef SSH_NDIS6_PACKET_POOL_H
#define SSH_NDIS6_PACKET_POOL_H










#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

typedef MDL              SshNativeDataBlockStruct;
typedef NET_BUFFER       SshNativeNetDataBufferStruct;
typedef NET_BUFFER_LIST  SshNativeNetDataPacketStruct;
typedef ULONG            SshTransferCompleteParam;

#define SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET    8

#define  SSH_PACKET_POOL_USE_INLINE_FUNCTIONS  

#include "packet_pool_common.h"

typedef SshNetDataBufferHeaderStruct  SshNdisBufferHeaderStruct;
typedef SshNetDataBufferHeader        SshNdisBufferHeader;

typedef struct SshNdisBufferRec
{
  /* NDIS version independent data members. */
  SshNetDataBufferStruct ;
} SshNdisBufferStruct, *SshNdisBuffer;


typedef struct SshNdisPacketRec
{
  /* NDIS version independent data members. */
  SshNetDataPacketStruct ;

  /* Source/destination port number and transfer flags */
  NDIS_PORT_NUMBER port_number; 
  ULONG transfer_flags; 

} SshNdisPacketStruct, *SshNdisPacket;


/*--------------------------------------------------------------------------
  MACROS AND INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshInterceptorPacketPool"

#define SSH_PACKET_CTX(nbl) \
  (SshNdisPacket)NET_BUFFER_LIST_CONTEXT_DATA_START((nbl))

#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS 

SshNdisPacket SSH_PACKET_POOL_API
ssh_packet_clone(SshInterceptor interceptor,
                 SshPacketPool pool,
                 SshInterceptorProtocol protocol,
                 PNET_BUFFER src,
                 Boolean copy_data);


SshNdisPacket SSH_PACKET_POOL_API
ssh_packet_list_clone(SshInterceptor interceptor,
                      SshPacketPool pool,
                      SshInterceptorProtocol protocol,
                      PNET_BUFFER_LIST nbl,
                      Boolean copy_data);

#else

#include "ndis6_packet_pool_impl.c"

#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */


#undef SSH_DEBUG_MODULE

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_packet_pools_create(SshInterceptor interceptor);

void
ssh_packet_pools_destroy(SshInterceptor interceptor);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_NDIS6_PACKET_POOL_H */
