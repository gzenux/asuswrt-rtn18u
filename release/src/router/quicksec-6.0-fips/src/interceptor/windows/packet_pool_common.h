/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS version independent packet pool definitions and
   inline functions for Windows Interceptor objects.
*/

#ifndef SSH_PACKET_POOL_COMMON_H
#define SSH_PACKET_POOL_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/













#ifndef SSH_NET_PACKET_BACKFILL_SIZE
#define SSH_NET_PACKET_BACKFILL_SIZE      112 
#endif /* SSH_NET_PACKET_BACKFILL_SIZE */
#ifndef SSH_NET_PACKET_PADDING_SIZE
#define SSH_NET_PACKET_PADDING_SIZE       64
#endif /* SSH_NET_PACKET_PADDING_SIZE */
#ifndef SSH_NET_PACKET_DATA_SIZE
#ifdef HAS_IEEE802_3_PASSTHRU
#define SSH_NET_PACKET_DATA_SIZE          9500
#else
#define SSH_NET_PACKET_DATA_SIZE          1600
#endif
#endif /* SSH_NET_PACKET_DATA_SIZE */
#define SSH_NET_PACKET_BUFFER_SIZE \
  (SSH_NET_PACKET_BACKFILL_SIZE + SSH_NET_PACKET_DATA_SIZE)

#ifndef SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET
#define SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET  0
#endif /* SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET */

#ifdef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS
#define SSH_PACKET_POOL_API    __forceinline
#else
#define SSH_PACKET_POOL_API    __fastcall  
#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/* This is most probably always a MDL */
typedef SshNativeDataBlockStruct     *SshNativeDataBlock;

/* SshNativeNetDataBufferStruct and SshNativeNetDataPacketStruct types must
   be defined BEFORE including packet_pool_commmon.h */
typedef SshNativeNetDataBufferStruct *SshNativeNetDataBuffer;
typedef SshNativeNetDataPacketStruct *SshNativeNetDataPacket;

/* Callback function that will be executed when send/receive operation is
   completed or the packet is dropped (ssh_interceptor_packet_free()). */
typedef void (*SshPacketTransferCompleteCB)(void *handle,
                                            SshNativeNetDataPacket np,
                                            SshTransferCompleteParam param);

typedef struct SshNetDataBufferHeaderRec
{
  /* For linked lists */
  union 
  {
    struct
    {
      void *prev;
      void *next;
    };
    LIST_ENTRY list_entry;
  };

  /* Pointer to owner pool of this buffer */
  SshPacketPool pool;

  /* Pointer to native (NDIS version dependent) network data buffer */
  SshNativeNetDataBuffer nb;

  /* Offset to beginning of data */
  SshUInt32 offset;
  /* Length of data buffer in use */
  SshUInt32 data_len;
  /* Total size of the buffer (including offset) */
  SshUInt32 total_size;

  /* Set when this buffer in plain header (containing only descriptors, no
     actual data) */
  unsigned int plain_header : 1;
#ifdef DEBUG_LIGHT
  /* Set when this buffer is returned to free list */
  unsigned int in_free_list : 1;
#endif /* DEBUG_LIGHT */
} SshNetDataBufferHeaderStruct, *SshNetDataBufferHeader;


typedef struct SshNetDataBufferRec
{
  SshNetDataBufferHeaderStruct ; /* Do NOT move! */

  struct 
  {




    PMDL mdl;  /* Original MDL, will be copied to nb when data is copied.*/
    MDL orig_mdl;   /* Backup copy of the original MDL */




    unsigned char buffer[SSH_NET_PACKET_BUFFER_SIZE];



  } copy;

} SshNetDataBufferStruct, *SshNetDataBuffer;


typedef struct SshNetDataPacketRec
{
#ifdef NEED_PROTOCOL_RESERVED_IN_PACKET
  unsigned char protocol_reserved[PROTOCOL_RESERVED_SIZE_IN_PACKET];
#endif /* NEED_PROTOCOL_RESERVED_IN_PACKET */

  /* Generic interceptor packet structure */
  SshInterceptorPacketStruct ip;

  /* Interceptor object */
  SshInterceptor interceptor;

  /* Linked list of SshNetDataBuffer structures belonging to this packet */
  SshNetDataBuffer buff;

  /* For linked lists */
  union 
    {
      void *next;
      LIST_ENTRY list_entry;
    };







  /* Pointer to owner pool of this packet */
  SshPacketPool pool;

  /* Pointer to native (NDIS version dependent) network data packet */
  SshNativeNetDataPacket np;

  /* Send/receive completion callback */
  SshPacketTransferCompleteCB complete_cb;
  void *complete_cb_handle;
  SshTransferCompleteParam complete_cb_param;

  /* Send/receive completions callback for the original packet */
  SshPacketTransferCompleteCB parent_complete_cb;
  NDIS_HANDLE parent_complete_handle;
  SshNativeNetDataPacket parent_complete_np;
  SshTransferCompleteParam parent_complete_param;

  /* Flags helping us to prevent un-necessary copy operations */
  union
    {
      struct 
        {
          /* Copy the original packet if more modifications than just media
             header deletion/addition. (Otherwice we could encrypt the same
             data multiple times when TCP retransmit occurs) */
          unsigned int from_local_stack : 1;

          /* Set when media header is deleted (ssh_interceptor_packet_delete,
             offset=0, size=14) */
          unsigned int media_header_deleted : 1;

          /* Set when we have copied the data of original network packet */
          unsigned int packet_copied : 1;

          /* Set when this packet has been allocated by engine calling
             ssh_interceptor_packet_alloc(). */
          unsigned int allocated_packet : 1;

	  /* This flag is set when ssh_interceptor_packet_detach() 
	     has been called. */
	  unsigned int detached : 1;

          /* Set when this packet must be either completed synchronously 
             or copied. */
          unsigned int can_not_pend : 1;

#ifdef DEBUG_LIGHT
          /* Set when packet is "owned" by QuickSec engine */
          unsigned int in_engine : 1;

          /* Set when packet is internally enqueued by the interceptor */
          unsigned int in_send_queue : 1;
          unsigned int in_recv_queue : 1;

          /* Set when packet is "owned" by lower layer miniport/filter */
          unsigned int in_miniport : 1;

          /* Set when packet is "owned" by lower layer miniport/filter */
          unsigned int in_protocol : 1;

          /* Set when this packet is returned to free list */
          unsigned int in_free_list : 1;
#endif /* DEBUG_LIGHT */
        } flags;

      unsigned int all_flags;
    } f;

  /* Protocol type read from media header */
  SshUInt16 eth_type;








  /* Originating WAN interface number */
  UINT orig_wan_ifnum;

  /* Source/destination adapter when packet was intercepted. NULL if this is 
     an engine allocated packet. */
  SshAdapter adapter_in;
  SshAdapter adapter_out;

  /* Packet length and buffer chain lengths. We cache them here, so we need 
     to go through the buffer list only once. (Not a big deal but wasted 
     CPU cycle is wasted CPU cycle...) */
  SshUInt32 packet_len;
  SshUInt32 backfill_space;
  SshUInt32 data_space;

  /* Packet iteration */
  SshUInt32 iter_remaining;
  SshUInt32 iter_offset;
  SshNativeDataBlock iter_next;

  /* Temporary data buffer for ssh_interceptor_pullup_read(). */
  unsigned char pullup_buffer[SSH_INTERCEPTOR_MAX_PULLUP_LEN];

#if (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0)
  /* Spare buffer descriptor for efficient packet manipulations. */
  SshNetDataBufferHeaderStruct 
    clone_buffers[SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET];
  SshUInt16 clone_buffers_in_use;

  /* Store original sizes of the allocated buffer chain */
  SshUInt32 buf_chain_backfill;
  SshUInt32 buf_chain_data_space;
#endif /* (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0) */

} SshNetDataPacketStruct, *SshNetDataPacket;

/*--------------------------------------------------------------------------
  MACROS AND INLINE FUNCTIONS
  --------------------------------------------------------------------------*/

#undef SSH_DEBUG_MODULE
#define SSH_DEBUG_MODULE "SshInterceptorPacketPool"

#ifdef DEBUG_LIGHT

#define SSH_MARK_NET_PACKET_FREE(p)                 \
do                                                  \
{                                                   \
  SSH_ASSERT((p)->f.flags.in_free_list == 0);       \
  (p)->f.flags.in_free_list = 1;                    \
} while (0);

#define SSH_MARK_NET_PACKET_ALLOCATED(p)            \
do                                                  \
{                                                   \
  SSH_ASSERT((p)->f.flags.in_free_list == 1);       \
  (p)->f.flags.in_free_list = 0;                    \
} while (0);

#define SSH_MARK_NET_BUFFER_FREE(b)                 \
do                                                  \
{                                                   \
  SSH_ASSERT((b)->plain_header == 0);               \
  SSH_ASSERT((b)->in_free_list == 0);               \
  (b)->in_free_list = 1;                            \
} while (0);

#define SSH_MARK_NET_BUFFER_ALLOCATED(b)            \
do                                                  \
{                                                   \
  SSH_ASSERT((b)->in_free_list == 1);               \
  (b)->in_free_list = 0;                            \
} while (0);

#else

#define SSH_MARK_NET_PACKET_ALLOCATED(p)
#define SSH_MARK_NET_PACKET_FREE(p)
#define SSH_MARK_NET_BUFFER_ALLOCATED(b)
#define SSH_MARK_NET_BUFFER_FREE(b)

#endif /* DEBUG_LIGHT */

#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS

void SSH_PACKET_POOL_API
SSH_RESET_NET_BUFFER(SshNetDataBuffer buffer,
                     SshUInt32 backfill);

void SSH_PACKET_POOL_API
SSH_RESET_NET_PACKET(SshNetDataPacket packet,
                     SshNetDataBuffer buff_chain);

SshUInt32 SSH_PACKET_POOL_API 
ssh_return_net_packets_to_original_pool(SshPacketPool orig_pool,
                                        SshPacketPool global_pool);

SshNetDataBuffer SSH_PACKET_POOL_API 
ssh_net_buffer_alloc(SshInterceptor interceptor,
                     SshPacketPool pool);

void SSH_PACKET_POOL_API 
ssh_net_buffer_free(SshInterceptor interceptor,
                    SshPacketPool pool,
                    SshNetDataBuffer buffer);

void SSH_PACKET_POOL_API 
ssh_net_buffer_chain_free(SshInterceptor interceptor,
                          SshPacketPool pool,
                          SshNetDataBuffer buffer_chain);

void SSH_PACKET_POOL_API 
ssh_net_packet_free(SshNetDataPacket packet,
                    SshPacketPool current_pool);

SshNetDataPacket SSH_PACKET_POOL_API 
ssh_net_packet_alloc(SshInterceptor interceptor,
                     SshPacketPool pool,
                     SshUInt32 total_len);

void SSH_PACKET_POOL_API 
ssh_net_packet_enqueue(SshPacketQueue queue,
                       SshNetDataPacket packet);

SshNetDataPacket SSH_PACKET_POOL_API 
ssh_net_packet_list_dequeue(SshPacketQueue queue,
                            SshUInt32 *packet_count_return);

/* These are implemented in interceptor / NDIS version specific code: */
Boolean SSH_PACKET_POOL_API 
ssh_query_data_block(SshNativeDataBlock dblk, 
                     unsigned char **data,
                     SshUInt32 *data_len);

SshNativeDataBlock SSH_PACKET_POOL_API 
ssh_get_first_data_block(SshNetDataBufferHeader buf_hdr);

SshNativeDataBlock SSH_PACKET_POOL_API 
ssh_get_next_data_block(SshNativeDataBlock dblk);

void SSH_PACKET_POOL_API
ssh_adjust_data_block_length(SshNativeDataBlock dblk,
                             SshUInt32 length);

Boolean SSH_PACKET_POOL_API
ssh_advance_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes);

Boolean SSH_PACKET_POOL_API
ssh_retreat_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes);

void SSH_PACKET_POOL_API
ssh_unchain_first_data_block(SshNetDataBufferHeader buf_hdr);

void SSH_PACKET_POOL_API
ssh_chain_at_front(SshNetDataBufferHeader buf_hdr,
                   SshNativeDataBlock new_first_dblk);

void SSH_PACKET_POOL_API
ssh_refresh_packet(SshNativeNetDataPacket np,
                   SshUInt32 packet_len);

void SSH_PACKET_POOL_API
SSH_RESET_BUFFER(SshNetDataBuffer nb,
                 SshUInt32 backfill);

void SSH_PACKET_POOL_API
SSH_RESET_PACKET(SshNetDataPacket np,
                 SshNetDataBuffer buff_chain);

Boolean SSH_PACKET_POOL_API 
ssh_packet_move_head(SshNetDataPacket packet,
                     SshUInt32 len,
                     SshInt32 move);


Boolean SSH_PACKET_POOL_API 
ssh_packet_move_tail(SshNetDataPacket packet,
                     SshUInt32 offset,
                     SshInt32 move);


Boolean SSH_PACKET_POOL_API 
ssh_packet_copyin(SshNetDataPacket packet,
                  SshUInt32 offset,
                  const unsigned char *buf,
                  SshUInt32 len);


Boolean SSH_PACKET_POOL_API 
ssh_packet_copyout(SshNetDataPacket packet,
                   SshUInt32 offset,
                   unsigned char *buf,
                   SshUInt32 len);

Boolean SSH_PACKET_POOL_API 
ssh_packet_get_buffer(SshNetDataPacket packet,
                      SshUInt32 offset,
                      SshNetDataBufferHeader *buf_return,
                      SshNativeDataBlock *data_return,
                      SshUInt32 *data_offset_return);


Boolean SSH_PACKET_POOL_API 
ssh_packet_advance_data_start(SshNetDataPacket packet,
                              SshUInt32 bytes,
                              unsigned char **buffer_addr);


Boolean SSH_PACKET_POOL_API 
ssh_packet_retreat_data_start(SshNetDataPacket packet,
                              SshUInt32 bytes,
                              unsigned char **buffer_addr);

Boolean SSH_PACKET_POOL_API 
ssh_packet_resize(SshNetDataPacket packet,
                  SshUInt32 new_size);


Boolean SSH_PACKET_POOL_API 
ssh_packet_move_data(SshNetDataPacket packet,
                     SshUInt32 from_offset,
                     SshUInt32 to_offset,
                     SshUInt32 length);


void SSH_PACKET_POOL_API 
ssh_packet_free(SshNetDataPacket net_packet, 
                SshPacketPool pool);


SshNetDataPacket SSH_PACKET_POOL_API 
ssh_packet_alloc(SshInterceptor interceptor,
                 SshPacketPool pool,
                 SshUInt32 total_len);


Boolean SSH_PACKET_POOL_API 
ssh_packet_copy_original_data(SshNetDataPacket net_packet);


PUCHAR SSH_PACKET_POOL_API 
ssh_packet_get_contiguous_data(SshNetDataPacket packet,
                               SshUInt32 offset,
                               SshUInt32 bytes,
                               Boolean read_only);

#else

#include "packet_pool_common.c"

#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_PACKET_POOL_COMMON_H */
