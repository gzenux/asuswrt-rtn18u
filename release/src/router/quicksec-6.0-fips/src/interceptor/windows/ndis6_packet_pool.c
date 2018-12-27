/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the (NDIS 6.0) packet pool creation and destruction
   functions. The actual packet manipulation functions are inlined to
   packet processing paths from ndis_packet_pool.h (doesn't make any
   sense to have extra function calls there).
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  ------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#include <fwpsk.h>
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE          "SshInterceptorPacketPool"

static SshUInt16
ssh_get_context_size(void)
{
  SshNdisPacket packet;

  SshUInt16 context_size;
  context_size = (sizeof(*packet) / MEMORY_ALLOCATION_ALIGNMENT);
  if (sizeof(*packet) % MEMORY_ALLOCATION_ALIGNMENT)
    context_size++;
  context_size *= MEMORY_ALLOCATION_ALIGNMENT;

  return context_size;
}

static void
ssh_init_net_buffer(PNET_BUFFER nb)
{
  nb->stDataLength = 0;
  NdisZeroMemory(&nb->ProtocolReserved, sizeof(nb->ProtocolReserved));
  NdisZeroMemory(&nb->MiniportReserved, sizeof(nb->MiniportReserved));
  NdisZeroMemory(&nb->DataPhysicalAddress, sizeof(nb->DataPhysicalAddress));
}


static void
ssh_packet_pool_free_np(SshNdisPacket packet,
                        SshPacketPool pool)
{
  int i;

  for (i = 0; i < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; i++)
    {
      SshNdisBufferHeader header = &packet->clone_buffers[i];

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if ((i == 0) && (packet->np))
        {
          NET_BUFFER_LIST_FIRST_NB(packet->np) = header->nb;
        }
      else
        {
          NdisFreeNetBuffer(header->nb);
        }
#else
      if (header->nb)
        NdisFreeNetBuffer(header->nb);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }

  if (packet->np)
    {
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR 
      FwpsFreeNetBufferList0(packet->np);
#else
      NdisFreeNetBufferList(packet->np);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }
}


static SshNdisPacket 
ssh_packet_pool_alloc_np(SshPacketPool pool)
{
  SshNdisPacket packet = NULL;
  NET_BUFFER_LIST *nbl;
  int i;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  NTSTATUS status;

  status = 
    FwpsAllocateNetBufferAndNetBufferList0(pool->packet_list_context,
                                           ssh_get_context_size(), 
                                           0, NULL, 0, 0, &nbl);
  if (!NT_SUCCESS(status))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate NET_BUFFER_LIST"));
      return NULL;
    }
#else
  nbl = NdisAllocateNetBufferList(pool->packet_list_context, 
                                  ssh_get_context_size(), 
                                  (USHORT)0);
  if (nbl == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate NET_BUFFER_LIST"));
      return NULL;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  NdisZeroMemory(&nbl->MiniportReserved, 
                 sizeof(nbl->MiniportReserved));
  NdisZeroMemory(&nbl->ProtocolReserved,
                 sizeof(nbl->ProtocolReserved));

  packet = SSH_PACKET_CTX(nbl);
  NdisZeroMemory(packet, sizeof(*packet));
  packet->np = nbl;
  packet->pool = pool;

  /* NDIS630: init list entries to avoid kernel-mode scurity check crashes */
  InitializeListHead(&packet->list_entry);







  for (i = 0; i < SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET; i++) 
    {
      SshNdisBufferHeader header = &packet->clone_buffers[i];

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (i == 0)
        {
          header->nb = NET_BUFFER_LIST_FIRST_NB(nbl);
          NET_BUFFER_LIST_FIRST_NB(nbl) = NULL;
        }
      else
        {
          header->nb = NdisAllocateNetBuffer(pool->buffer_list_context,
                                             NULL, 0, 0);
        }
#else
      header->nb = 
        NdisAllocateNetBuffer(pool->buffer_list_context, NULL, 0, 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      if (header->nb == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate NET_BUFFER"));
          ssh_packet_pool_free_np(packet, pool);
          return NULL;
        }

      ssh_init_net_buffer(header->nb);

      header->plain_header = 1;
    }

  return packet;
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/


Boolean
ssh_packet_pools_create(SshInterceptor interceptor)
{
  PNDIS_GENERIC_OBJECT gen_obj;
  SshCpuContext cpu_ctx;
  SshPacketPool pool;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshNdisPacket packet;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  unsigned int i, j;
  NDIS_HANDLE nbl_pool_handle;
  NDIS_HANDLE nb_pool_handle;
  NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params;
  NET_BUFFER_POOL_PARAMETERS nb_pool_params;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  gen_obj = NdisAllocateGenericObject(interceptor->driver_object, 'HTUA', 0);
  interceptor->cpu_ctx[0].global_packet_pool.ext_context = gen_obj;

  NdisZeroMemory(&nbl_pool_params, sizeof(nbl_pool_params));
  nbl_pool_params.ContextSize = ssh_get_context_size();
  nbl_pool_params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR 
  nbl_pool_params.fAllocateNetBuffer = TRUE;
#else
  nbl_pool_params.fAllocateNetBuffer = FALSE;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  nbl_pool_params.DataSize = 0;
  nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  nbl_pool_params.Header.Size = 
    NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
  nbl_pool_params.Header.Revision = 
    NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
  nbl_pool_params.PoolTag = 'KPTA'; /* "INSIDE Secure PacKet" */

  nbl_pool_handle = NdisAllocateNetBufferListPool(gen_obj, &nbl_pool_params);
  if (nbl_pool_handle == NULL)
    goto failed;

  NdisZeroMemory(&nb_pool_params, sizeof(nb_pool_params));
  nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  nb_pool_params.Header.Size = 
    NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
  nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
  nb_pool_params.DataSize = 0;
  nb_pool_params.PoolTag = 'FBTA'; /* "INSIDE Secure BufFer" */

  nb_pool_handle = NdisAllocateNetBufferPool(gen_obj, &nb_pool_params);
  if (nb_pool_handle == NULL)
    {
      NdisFreeNetBufferListPool(nbl_pool_handle);
      goto failed;
    }

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
          pool->packet_list_context = nbl_pool_handle;
          pool->buffer_list_context = nb_pool_handle;
          pool->use_runtime_np_alloc = FALSE;
          pool->runtime_np_alloc = NULL_FNPTR;
          pool->runtime_np_free = NULL_FNPTR;
        }
    }

  for (i = 0; i < interceptor->processor_count; i++)
    {
      cpu_ctx = &interceptor->cpu_ctx[i];
      pool = &cpu_ctx->packet_pool;

      /* Windows filtering platform is used for IP only interceptor. */






#if defined(SSH_IPSEC_IP_ONLY_INTERCEPTOR) || (NTDDI_VERSION > NTDDI_WIN7)
      pool->use_runtime_np_alloc = TRUE;
      pool->runtime_np_alloc = ssh_packet_pool_alloc_np;
      pool->runtime_np_free = ssh_packet_pool_free_np;
#else
      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_PACKET_POOL_SIZE; j++)
        {
          packet = ssh_packet_pool_alloc_np(pool);

          if (packet == NULL)
            goto failed;

#ifdef DEBUG_LIGHT
          packet->f.flags.in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->packet_list_size++;
          pool->packet_count++;
          InitializeListHead(&packet->list_entry);
          InsertTailList(&pool->free_packet_list, &packet->list_entry);
        }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      for (j = 0; j < SSH_INTERCEPTOR_PER_CPU_BUFFER_POOL_SIZE; j++)
        {
          SshNdisBuffer buffer = ssh_calloc(1, sizeof(*buffer));

          if (buffer == NULL)
            goto failed;

          buffer->copy.mdl = IoAllocateMdl(buffer->copy.buffer, 
                                           sizeof(buffer->copy.buffer), 
                                           FALSE, FALSE, NULL);
          if (buffer->copy.mdl == NULL)
            {
              ssh_free(buffer);
              goto failed;
            }

          MmBuildMdlForNonPagedPool(buffer->copy.mdl);
          buffer->copy.orig_mdl = *buffer->copy.mdl;






          buffer->nb = NdisAllocateNetBuffer(nb_pool_handle, NULL, 0, 0);
          if (buffer->nb == NULL)
            {
              IoFreeMdl(buffer->copy.mdl);
              ssh_free(buffer);
              goto failed;
            }

          ssh_init_net_buffer(buffer->nb);

          SSH_RESET_BUFFER((SshNetDataBuffer)buffer, 0);

          buffer->pool = pool;
#ifdef DEBUG_LIGHT
          buffer->in_free_list = 1;
#endif /* DEBUG_LIGHT */
          pool->buffer_list_size++;
          pool->buffer_count++;
          InitializeListHead(&buffer->list_entry);
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
  NDIS_HANDLE pool_handle;
  SshCpuContext cpu_ctx;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(interceptor->processor_count > 0);

  for (j = 0; j < 2; j++)
    {
      for (i = 0; i < interceptor->processor_count; i++)
        {
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

#ifdef DEBUG_LIGHT
              SSH_ASSERT(pool->packet_count > 0);
              pool->packet_count--;
#endif /* DEBUG_LIGHT */
              entry = RemoveHeadList(&pool->free_packet_list);

              packet = CONTAINING_RECORD(entry, 
                                         SshNdisPacketStruct, 
                                         list_entry);

              ssh_packet_pool_free_np(packet, pool);
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

              SSH_ASSERT(buffer->nb != NULL);
              NdisFreeNetBuffer(buffer->nb);

              SSH_ASSERT(buffer->copy.mdl != NULL);
              IoFreeMdl(buffer->copy.mdl);






              ssh_free(buffer);
            }
        }
    }

  cpu_ctx = &interceptor->cpu_ctx[0];

  pool_handle = cpu_ctx->global_packet_pool.buffer_list_context;
  if (pool_handle)
    {
      NdisFreeNetBufferPool(pool_handle);
      cpu_ctx->global_packet_pool.buffer_list_context = NULL;
    }

  pool_handle = cpu_ctx->global_packet_pool.packet_list_context;
  if (pool_handle)
    {
      NdisFreeNetBufferListPool(pool_handle);
      cpu_ctx->global_packet_pool.packet_list_context = NULL;
    }

  if (cpu_ctx->global_packet_pool.ext_context)
    {
      NdisFreeGenericObject(cpu_ctx->global_packet_pool.ext_context);
      cpu_ctx->global_packet_pool.ext_context = NULL;
    }
}

#ifndef SSH_PACKET_POOL_USE_INLINE_FUNCTIONS
#include "packet_pool_common.c"
#include "ndis6_packet_pool_impl.c"
#endif /* SSH_PACKET_POOL_USE_INLINE_FUNCTIONS */
