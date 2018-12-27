/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS 5.x compatible packet pool definitions and inline
   functions for Windows 2K/XP/2K3 interceptor object.
*/

#ifndef SSH_NDIS5_PACKET_POOL_H
#define SSH_NDIS5_PACKET_POOL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/* Maximum number of stacked VLAN tags. If set to one, IEEE 802.1ad is not
   supported. */
#define SSH_VLAN_MAX_VLAN_TAGS  4
#define SSH_VLAN_INVALID_ID     0xFFF
#define SSH_ETHERTYPE_VLAN      0x8100

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

#define NEED_PROTOCOL_RESERVED_IN_PACKET

typedef MDL          SshNativeDataBlockStruct;
typedef NDIS_BUFFER  SshNativeNetDataBufferStruct;
typedef NDIS_PACKET  SshNativeNetDataPacketStruct;
typedef void         *SshTransferCompleteParam;

/* These buffer descriptors can be used for efficient packet manipulations
   (i.e. we can modify the buffer chain without moving the original data) */
#define SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET    5

/* Use inline packet processing functions on Desktop Windows for improved 
   performance. */
#define SSH_PACKET_POOL_USE_INLINE_FUNCTIONS 

#include "packet_pool_common.h"

/* Type definition for structure that contains IEEE 802.1q QoS and 
   VLAN IDs. */
typedef struct SshVlanTagRec
{
  unsigned short vlan_id : 12;    /* VLAN ID */
  unsigned short qos : 3;         /* QoS */
} SshVlanTagStruct, *SshVlanTag;

#pragma pack(push, mh, 1)

/*--------------------------------------------------------------------------
  SSH Media Header

  Description:
  Type definition for network packet media header. 

  Notes:
  --------------------------------------------------------------------------*/
typedef struct SshMediaHeaderRec
{
  /* Destination MAC address */
  UCHAR dst[6];

  /* Source MAC address */
  UCHAR src[6];

  /* Protocol type of packet: IPv4, IPv6, ARP, etc... */
  UCHAR type[2];
} SshMediaHeaderStruct, *SshMediaHeader;

#pragma pack(pop, mh)


typedef SshNetDataBufferHeaderStruct  SshNdisBufferHeaderStruct;
typedef SshNetDataBufferHeader        SshNdisBufferHeader;

/* NDIS 5.x specific network data buffer */
typedef struct SshNdisBufferRec
{
  /* NDIS version independent data members. */
  SshNetDataBufferStruct ;
} SshNdisBufferStruct, *SshNdisBuffer;


/* NDIS 5.x specific network data packet structure */
typedef struct SshNdisPacketRec
{
  /* NDIS version independent data members. */
  SshNetDataPacketStruct ;

  /* VLAN support */
  SshVlanTagStruct vlan_tags[SSH_VLAN_MAX_VLAN_TAGS];
  SshUInt16 vlan_tag_count;

  /* Variables used during NdisTransferData operation */
  SshUInt32 transfer_data_offset;
  SshUInt32 transfer_data_len;

} SshNdisPacketStruct, *SshNdisPacket;

/*--------------------------------------------------------------------------
  MACROS AND INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

#define SSH_NB_DESCRIPTOR(nb) ((void *)(nb)->Process)

/* Media header length of network packet */
#define SSH_MEDIA_HDR_LEN    (sizeof(SshMediaHeaderStruct))

#define SSH_PACKET_CTX(np)   ((SshNdisPacket)(np)->ProtocolReserved)

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshInterceptorPacketPool"

/*--------------------------------------------------------------------------
  Retrieves the media header from NDIS packet.
  --------------------------------------------------------------------------*/






#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS


SshNdisPacket SSH_PACKET_POOL_API 
ssh_packet_clone(SshInterceptor interceptor,
                 SshPacketPool pool,
                 SshInterceptorProtocol protocol,
                 SshNativeNetDataPacket src,
                 Boolean copy_data);

void SSH_PACKET_POOL_API 
ssh_packet_query_media_header(PNDIS_PACKET pkt,
                              SshMediaHeader *media_hdr);


#else

#include "ndis5_packet_pool_impl.c"

#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */

#undef SSH_DEBUG_MODULE


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/* Allocates CPU specific packet pools */
Boolean
ssh_packet_pools_create(SshInterceptor interceptor);

/* Frees CPU specific packet pools */
void
ssh_packet_pools_destroy(SshInterceptor interceptor);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_NDIS5_PACKET_POOL_H */
