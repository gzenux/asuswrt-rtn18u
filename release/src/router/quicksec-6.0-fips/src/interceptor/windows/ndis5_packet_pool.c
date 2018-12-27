/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the NDIS 5.x packet pool creation and destruction
   functions. The actual packet manipulation functions are inlined to
   packet processing paths from ndis5_packet_pool.h (doesn't make any
   sense to have extra function calls there).
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  ------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "ndis5_packet_pool.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorPacketPool"

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_packet_pools_create(SshInterceptor interceptor)
{
  SshCpuContext cpu_ctx;
  SshPacketPool pool;
  int i;
  int j;
  NDIS_HANDLE pool_handle;
  NDIS_STATUS status; 
  ULONG pkt_ctx_size = sizeof(SshNdisPacketStruct);

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  for (i = 0; i < interceptor->processor_count; i++)
    {
      cpu_ctx = &interceptor->cpu_ctx[i];

      ssh_kernel_mutex_init(&cpu_ctx->global_packet_pool_lock);

      for (j = 0; j < 2; j++)
        {
          if (j == 0)
            pool = &cpu_ctx->global_packet_pool;
          else
            pool = &cpu_ctx->packet_pool;            

          InitializeListHead(&pool->free_packet_list);
          InitializeListHead(&pool->free_buffer_list);






          pool->cpu_index = i;
          pool->packet_list_size = 0;
          pool->buffer_list_size = 0;
          pool->packet_count = 0;
          pool->buffer_count = 0;
          pool->packet_list_context = NULL;
          pool->buffer_list_context = NULL;
          pool->use_runtime_np_alloc = FALSE;
          pool->runtime_np_alloc = NULL_FNPTR;
          pool->runtime_np_free = NULL_FNPTR;
        }
    }

  for (i = 0; i < interceptor->processor_count; i++)
    {
      cpu_ctx = &interceptor->cpu_ctx[i];
      pool = &cpu_ctx->packet_pool;

      NdisAllocatePacketPool(&status,
                             &pool_handle,
                             SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE, 
                             pkt_ctx_size);
      if (status != NDIS_STATUS_SUCCESS)
        goto failed; 

      pool->packet_list_context = pool_handle;

      NdisAllocateBufferPool(&status,
                             &pool_handle,
                             SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE);
      if (status != NDIS_STATUS_SUCCESS)
        goto failed;

      pool->buffer_list_context = pool_handle;

      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE; j++)
        {
          SshNdisPacket packet;
          NDIS_PACKET *ndis_pkt;
          unsigned int k;

          NdisAllocatePacket(&status, &ndis_pkt, pool->packet_list_context);
          if (status != NDIS_STATUS_SUCCESS)
            goto failed;

          packet = SSH_PACKET_CTX(ndis_pkt);

          packet->np = ndis_pkt;
          packet->pool = pool;

#ifdef DEBUG_LIGHT
          packet->f.flags.in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->packet_list_size++;
          pool->packet_count++;
          InsertTailList(&pool->free_packet_list, &packet->list_entry);

          for (k = 0; k < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; k++) 
            packet->clone_buffers[k].plain_header = 1;
        }

      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE; j++)
        {
          SshNdisBuffer buffer;

          buffer = ssh_calloc(1, sizeof(*buffer));
          if (buffer == NULL)
            goto failed;

          NdisAllocateBuffer(&status, &buffer->copy.mdl, 
                             pool->buffer_list_context,
                             buffer->copy.buffer, 
                             sizeof(buffer->copy.buffer));
          if (status != NDIS_STATUS_SUCCESS)
            {
              ssh_free(buffer);
              goto failed;
            }

          SSH_NB_DESCRIPTOR(buffer->copy.mdl) = buffer;
          buffer->copy.orig_mdl = *buffer->copy.mdl;






          SSH_RESET_BUFFER((SshNetDataBuffer)buffer, 0);

          buffer->pool = pool;
#ifdef DEBUG_LIGHT
          buffer->in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->buffer_list_size++;
          pool->buffer_count++;
          InsertTailList(&pool->free_buffer_list, &buffer->list_entry);
        }
    }

  return TRUE;

 failed:

  ssh_log_event(SSH_LOGFACILITY_LOCAL0,
                SSH_LOG_CRITICAL,
                ("Failed to create Packet pool!"));
  ssh_packet_pools_destroy(interceptor);

  return FALSE;
}


void
ssh_packet_pools_destroy(SshInterceptor interceptor)
{
  int i, j;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  for (j = 0; j < 2; j++)
    {
      for (i = 0; i < interceptor->processor_count; i++)
        {
          SshCpuContext cpu_ctx;
          SshPacketPool pool;
          PLIST_ENTRY entry;

          cpu_ctx = &interceptor->cpu_ctx[i];

          if (j == 0)
            {
              pool = &cpu_ctx->global_packet_pool;
              ssh_kernel_mutex_uninit(&cpu_ctx->global_packet_pool_lock);
            }
          else
            {
              pool = &cpu_ctx->packet_pool;
            }

          while (!IsListEmpty(&pool->free_packet_list))
            {
              SshNdisPacket packet;
              unsigned int k;

#ifdef DEBUG_LIGHT
              SSH_ASSERT(pool->packet_count > 0);
              pool->packet_count--;
#endif /* DEBUG_LIGHT */
              entry = RemoveHeadList(&pool->free_packet_list);

              packet = CONTAINING_RECORD(entry, 
                                         SshNdisPacketStruct, 
                                         list_entry);

              for (k = 0; k < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; k++)
                {
                  SshNdisBufferHeader header = &packet->clone_buffers[k];

                  if (header->nb)
                    NdisFreeBuffer(header->nb);
                }

              NdisFreePacket(packet->np);
            }

          while (!IsListEmpty(&pool->free_buffer_list))
            {
              SshNdisBuffer buffer;

#ifdef DEBUG_LIGHT
              SSH_ASSERT(pool->buffer_count > 0);
              pool->buffer_count--;
#endif /* DEBUG_LIGHT */
              entry = RemoveHeadList(&pool->free_buffer_list);

              buffer = CONTAINING_RECORD(entry, 
                                         SshNdisBufferStruct, 
                                         list_entry);

              SSH_ASSERT(buffer->copy.mdl != NULL);
              NdisFreeBuffer(buffer->copy.mdl);





              ssh_free(buffer);
            }

          if (pool->buffer_list_context)
            NdisFreeBufferPool(pool->buffer_list_context);

          if (pool->packet_list_context)
            NdisFreePacketPool(pool->packet_list_context);
        }
    }
}

#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS
#include "packet_pool_common.c"
#include "ndis5_packet_pool_impl.c"
#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */
