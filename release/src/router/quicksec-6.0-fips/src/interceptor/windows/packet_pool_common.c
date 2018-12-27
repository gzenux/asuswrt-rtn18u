/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS version independent packet pool functions for
   Windows Interceptor objects.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  FUNCTIONS
  --------------------------------------------------------------------------*/

void SSH_PACKET_POOL_API 
SSH_RESET_NET_BUFFER(SshNetDataBuffer buffer,
                     SshUInt32 backfill)
{
  SSH_ASSERT(buffer != NULL);

  buffer->next = NULL;
  buffer->prev = NULL;
  *(buffer->copy.mdl) = buffer->copy.orig_mdl;

  buffer->offset = backfill;
  buffer->total_size = buffer->copy.orig_mdl.ByteCount;
  buffer->data_len = 0;
}


void SSH_PACKET_POOL_API
SSH_RESET_NET_PACKET(SshNetDataPacket packet,
                     SshNetDataBuffer buff_chain)
{
  SSH_ASSERT(packet != NULL);

  packet->next = NULL;
  packet->buff = buff_chain;

  packet->f.all_flags = 0;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memset(packet->ip.extension, 0, sizeof(packet->ip.extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  packet->packet_len = 0;
  packet->adapter_in = NULL;
  packet->adapter_out = NULL;
  packet->ip.ifnum_out = SSH_INTERCEPTOR_INVALID_IFNUM;
  packet->ip.protocol = SSH_PROTOCOL_ETHERNET;
  packet->ip.next = NULL;
  packet->ip.pmtu = 0;
  packet->ip.flags = 0; 

  packet->complete_cb = NULL_FNPTR;
  packet->complete_cb_handle = NULL;
  memset(&packet->complete_cb_param, 0, sizeof(packet->complete_cb_param));

  packet->parent_complete_cb = NULL_FNPTR;
  packet->parent_complete_handle = NULL;
  packet->parent_complete_np = NULL;
  memset(&packet->parent_complete_param, 0, 
         sizeof(packet->parent_complete_param));

#if (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0)
  packet->clone_buffers_in_use = 0;
  packet->buf_chain_backfill = 0;
  packet->buf_chain_data_space = 0;
#endif /* (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0) */
}

SshUInt32 SSH_PACKET_POOL_API 
ssh_return_net_packets_to_original_pool(SshPacketPool orig_pool,
                                        SshPacketPool global_pool)
{
  SshUInt32 packets_moved = 0;
  SshUInt32 buffers_moved = 0;

  if (!IsListEmpty(&global_pool->free_packet_list))
    {
      if (IsListEmpty(&orig_pool->free_packet_list))
        InitializeListHead(&orig_pool->free_packet_list);
        
      ssh_append_tail_list(&orig_pool->free_packet_list,
                           &global_pool->free_packet_list);

      InitializeListHead(&global_pool->free_packet_list);

      packets_moved = global_pool->packet_count;
      orig_pool->packet_count += global_pool->packet_count;
      global_pool->packet_count = 0;
    }

  if (!IsListEmpty(&global_pool->free_buffer_list))
    {
      if (IsListEmpty(&orig_pool->free_buffer_list))
        InitializeListHead(&orig_pool->free_buffer_list);

      ssh_append_tail_list(&orig_pool->free_buffer_list,
                           &global_pool->free_buffer_list);

      InitializeListHead(&global_pool->free_buffer_list);

      buffers_moved = global_pool->buffer_count;
      orig_pool->buffer_count += global_pool->buffer_count;
      global_pool->buffer_count = 0;
    }

  if (packets_moved || buffers_moved)
    {
      SSH_DEBUG(SSH_D_MY5, 
                ("%u packets and %u buffers returned from global pool to "
                 "cpu specific pool 0x%p", 
                 packets_moved, buffers_moved, orig_pool));
    }

  return packets_moved;
}


SshNetDataBuffer SSH_PACKET_POOL_API 
ssh_net_buffer_alloc(SshInterceptor interceptor,
                     SshPacketPool pool)
{
  SshNetDataBuffer net_buffer = NULL;
  PLIST_ENTRY entry;

  if (IsListEmpty(&pool->free_buffer_list))
    {
      SshCpuContext cpu_ctx;

      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

      ssh_kernel_mutex_lock(&cpu_ctx->global_packet_pool_lock);
      ssh_return_net_packets_to_original_pool(pool,
                                              &cpu_ctx->global_packet_pool);
      ssh_kernel_mutex_unlock(&cpu_ctx->global_packet_pool_lock);

      if (pool->use_runtime_np_alloc)
        {
          SSH_ASSERT(pool->runtime_np_free != NULL_FNPTR);

          /* Free packets from global pool (now it's safe to do it) */
          while (!IsListEmpty(&pool->free_packet_list))
            {
              SshNetDataPacket packet;

              entry = RemoveHeadList(&pool->free_packet_list);
              packet = 
                CONTAINING_RECORD(entry, SshNetDataPacketStruct, list_entry);

              (pool->runtime_np_free)(packet, pool);
            }
        }
    }

  if (!IsListEmpty(&pool->free_buffer_list))
    {
      entry = RemoveHeadList(&pool->free_buffer_list);
      net_buffer = 
        CONTAINING_RECORD(entry, SshNetDataBufferStruct, list_entry);

      SSH_MARK_NET_BUFFER_ALLOCATED(net_buffer);
      pool->buffer_count--;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of buffer pool!"));
    }

  return net_buffer;
}


void SSH_PACKET_POOL_API 
ssh_net_buffer_free(SshInterceptor interceptor,
                    SshPacketPool pool,
                    SshNetDataBuffer buffer)
{





  SSH_MARK_NET_BUFFER_FREE(buffer);
  pool->buffer_count++;
  InitializeListHead(&buffer->list_entry);
  InsertTailList(&pool->free_buffer_list, &buffer->list_entry);
}


void SSH_PACKET_POOL_API 
ssh_net_buffer_chain_free(SshInterceptor interceptor,
                          SshPacketPool pool,
                          SshNetDataBuffer buffer_chain)
{
  SshNetDataBuffer buffer = buffer_chain;

  while (buffer)
    {
      SshNetDataBuffer next = buffer->next;
      ssh_net_buffer_free(interceptor, pool, buffer);
      buffer = next;
    }
}


/* Caller of this function is responsible for the concurrency control! */
void SSH_PACKET_POOL_API 
ssh_net_packet_free(SshNetDataPacket packet,
                    SshPacketPool current_pool)
{
  SshInterceptor interceptor = packet->interceptor;
  SshPacketPool pool = packet->pool;
  SshCpuContext other_cpu_ctx = NULL;
  Boolean use_global_pool = FALSE;
  SshAdapter adapter_out;
  SshAdapter adapter_in;
  LONG new_value;

  adapter_in = packet->adapter_in;
  adapter_out = packet->adapter_out;
  packet->adapter_in = NULL;
  packet->adapter_out = NULL;

  if (pool != current_pool)
    {
      SSH_DEBUG(SSH_D_MY5, 
                ("Current CPU has changed during packet processing; "
                 "freeing packet 0x%p to global pool",
                 packet));
      use_global_pool = TRUE;
      other_cpu_ctx = &interceptor->cpu_ctx[pool->cpu_index];
      pool = &other_cpu_ctx->global_packet_pool;
    }
  else
    {
      SSH_DEBUG(SSH_D_MY5, 
                ("Freeing packet 0x%p to original pool",
                 packet));
    }

  if (use_global_pool)
    {
      ssh_kernel_mutex_lock(&other_cpu_ctx->global_packet_pool_lock);
    }

  ssh_net_buffer_chain_free(interceptor, pool, packet->buff);
  packet->buff = NULL;

  SSH_MARK_NET_PACKET_FREE(packet);









  if (pool->use_runtime_np_alloc)
    {
      SSH_ASSERT(pool->runtime_np_free != NULL_FNPTR);

      (pool->runtime_np_free)(packet, pool);
    }
  else
    {
      pool->packet_count++;
      InitializeListHead(&packet->list_entry);
      InsertTailList(&pool->free_packet_list, &packet->list_entry);
    }

  if (use_global_pool)
    {
      ssh_kernel_mutex_unlock(&other_cpu_ctx->global_packet_pool_lock);
    }

  if (adapter_in)
    {
      new_value = InterlockedDecrement(&adapter_in->ref_count);
      SSH_ASSERT(new_value >= 0);
    }

  if (adapter_out)
    {
      new_value = InterlockedDecrement(&adapter_out->ref_count);
      SSH_ASSERT(new_value >= 0);
    }
}


SshNetDataPacket SSH_PACKET_POOL_API 
ssh_net_packet_alloc(SshInterceptor interceptor,
                     SshPacketPool pool,
                     SshUInt32 total_len)
{
  SshNetDataPacket packet = NULL;
  PLIST_ENTRY entry = NULL;

  if (pool->use_runtime_np_alloc)
    {
      SSH_ASSERT(pool->runtime_np_alloc != NULL_FNPTR);

      packet = (pool->runtime_np_alloc)(pool);

      if (packet == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Out of packet pool!"));
          return NULL;
        }

#ifdef DEBUG_LIGHT
      /* Set the 'in_free_list' so we will pass the check in 
         SSH_MARK_NET_PACKET_ALLOCATED() */
      packet->f.flags.in_free_list = 1;
#endif /* DEBUG_LIGHT */
    }
  else
    {
      if (IsListEmpty(&pool->free_packet_list) ||
          IsListEmpty(&pool->free_buffer_list))
        {
          SshUInt32 num_items;
          SshCpuContext cpu_ctx;

          cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];

          ssh_kernel_mutex_lock(&cpu_ctx->global_packet_pool_lock);
          num_items = 
            ssh_return_net_packets_to_original_pool(pool,
                                                &cpu_ctx->global_packet_pool);
          ssh_kernel_mutex_unlock(&cpu_ctx->global_packet_pool_lock);

          if (num_items == 0)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Out of packet pool!"));
              return NULL;
            }
        }
  
        entry = RemoveHeadList(&pool->free_packet_list);
        packet = CONTAINING_RECORD(entry, SshNetDataPacketStruct, list_entry);
        pool->packet_count--;
    }

  packet->interceptor = interceptor;
  SSH_MARK_NET_PACKET_ALLOCATED(packet);













  return packet;
}

void SSH_PACKET_POOL_API 
ssh_net_packet_enqueue(SshPacketQueue queue,
                       SshNetDataPacket packet)
{
  if (queue->list_head == NULL)
    {
      queue->list_head = packet;
      queue->list_tail = queue->list_head;
    }
  else
    {
      SshNetDataPacket prev = queue->list_tail;

      prev->next = packet;
      queue->list_tail = packet;
    }
  queue->packets_in_queue++;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("%u packet(s) in queue 0x%p", queue->packets_in_queue, queue));
}


SshNetDataPacket SSH_PACKET_POOL_API 
ssh_net_packet_list_dequeue(SshPacketQueue queue,
                            SshUInt32 *packet_count_return)
{
  SshNetDataPacket packet_list = NULL;

  if (queue->list_head == NULL)
    {
/*      SSH_DEBUG(SSH_D_NICETOKNOW, ("Queue 0x%p is empty", queue));  */
      SSH_ASSERT(queue->packets_in_queue == 0);

      if (packet_count_return)
        *packet_count_return = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Queue 0x%p contains %u packet(s)",
                 queue, queue->packets_in_queue));

      if (packet_count_return)
        *packet_count_return = queue->packets_in_queue;

      packet_list = queue->list_head;
      queue->list_head = NULL;
      queue->list_tail = NULL;
      queue->packets_in_queue = 0;
    }

  return packet_list;
}

