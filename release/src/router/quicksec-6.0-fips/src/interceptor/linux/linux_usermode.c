/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "linux_internal.h"
#include "linux_packet_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorPacketDstCache"

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
Boolean
ssh_interceptor_dst_entry_cache_init(SshInterceptor interceptor)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Initialising dst entry cache"));

  /* When the IPM is open, we cache dst entries with usermode engine. */
  interceptor->dst_entry_cache_lock = ssh_kernel_mutex_alloc();
  if (interceptor->dst_entry_cache_lock == NULL)
    return FALSE;

  interceptor->dst_entry_cache_timeout_registered = FALSE;
  memset(interceptor->dst_entry_table, 0x0,
         sizeof(SshDstEntry) * SSH_DST_ENTRY_TBL_SIZE);

  interceptor->dst_entry_id = 1;
  interceptor->dst_entry_cached_items = 0;

  return TRUE;
}

/* How long the dst entry can live in the cache. */
#define DST_ENTRY_MAX_CACHE_TIME 15
static void
ssh_interceptor_dst_entry_cache_timeout(void *context)
{
  SshInterceptor interceptor = (SshInterceptor)context;
  SshTime time_now;
  SshUInt32 slot;
  SshDstEntry tmp, prev = NULL;

  ssh_kernel_mutex_lock(interceptor->dst_entry_cache_lock);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Dst entry cache timeout %u items in cache",
             interceptor->dst_entry_cached_items));
  SSH_ASSERT(interceptor->dst_entry_cache_timeout_registered == TRUE);

  if (interceptor->dst_entry_cached_items == 0)
    {
      interceptor->dst_entry_cache_timeout_registered = FALSE;
      ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);
      return;
    }

  ssh_interceptor_get_time(&time_now, &slot);
  for (slot = 0; slot < SSH_DST_ENTRY_TBL_SIZE; slot++)
    {
    restart:
      prev = NULL;
      for (tmp = interceptor->dst_entry_table[slot];
           tmp != NULL;
           tmp = tmp->next)
        {
          /* Do we have a match? */
          if ((tmp->allocation_time + DST_ENTRY_MAX_CACHE_TIME) < time_now)
            {
              /* Head of list. */
              if (tmp == interceptor->dst_entry_table[slot])
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Dst entry cache timeout freeing head ID %u",
                             tmp->dst_entry_id));
                  interceptor->dst_entry_table[slot] = tmp->next;

                  interceptor->dst_entry_cached_items--;

                  dst_release(tmp->dst_entry);
                  ssh_free(tmp);

                  goto restart;
                }

              /* Any other place in the list. */
              else
                {
                  prev->next = tmp->next;

                  interceptor->dst_entry_cached_items--;

                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Dst entry cache timeout freeing ID %u",
                             tmp->dst_entry_id));

                  dst_release(tmp->dst_entry);
                  ssh_free(tmp);

                  goto restart;
                }
            }

          prev = tmp;
        }
    }

  if (interceptor->dst_entry_cached_items > 0)
    {
      ssh_kernel_timeout_move(DST_ENTRY_MAX_CACHE_TIME, 0,
                              ssh_interceptor_dst_entry_cache_timeout,
                              interceptor);
    }
  else
    {
      interceptor->dst_entry_cache_timeout_registered = FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Left %u items in dst cache",
                               interceptor->dst_entry_cached_items));

  ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);
}

void
ssh_interceptor_dst_entry_cache_flush(SshInterceptor interceptor)
{
  SshUInt32 slot;
  SshDstEntry tmp;

  SSH_DEBUG(SSH_D_MIDOK, ("Dst entry cache flush, %u items in cache",
                          interceptor->dst_entry_cached_items));

  ssh_kernel_mutex_lock(interceptor->dst_entry_cache_lock);
  if (interceptor->dst_entry_cache_timeout_registered == TRUE)
    {
      ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);
      ssh_kernel_timeout_cancel(ssh_interceptor_dst_entry_cache_timeout,
                                interceptor);
      ssh_kernel_mutex_lock(interceptor->dst_entry_cache_lock);
    }

  interceptor->dst_entry_cache_timeout_registered = FALSE;

  /* Free all entries that are left in the table. */
  for (slot = 0; slot < SSH_DST_ENTRY_TBL_SIZE; slot++)
    {
    restart:
      for (tmp = interceptor->dst_entry_table[slot];
           tmp != NULL;
           tmp = tmp->next)
        {
          interceptor->dst_entry_table[slot] = tmp->next;

          interceptor->dst_entry_cached_items--;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Releasing dst cache entry ID %u"));

          dst_release(tmp->dst_entry);
          ssh_free(tmp);

          goto restart;
        }
    }
  SSH_ASSERT(interceptor->dst_entry_cached_items == 0);
  ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);
}

void
ssh_interceptor_dst_entry_cache_uninit(SshInterceptor interceptor)
{
  /* Something failed during initialization. */
  if (interceptor->dst_entry_cache_lock == NULL)
    return;

  SSH_DEBUG(SSH_D_MIDOK, ("Dst entry cache uninit, %u items in cache",
                          interceptor->dst_entry_cached_items));

  ssh_interceptor_dst_entry_cache_flush(interceptor);
  ssh_kernel_mutex_uninit(interceptor->dst_entry_cache_lock);
  ssh_kernel_mutex_free(interceptor->dst_entry_cache_lock);
}

/* Cache a dst entry for later purposes. This is required by the
   pass unmodified to work. If we lose the dst entry, we basically
   cannot return the packet as unmodified to the linux. Return 0
   if the caching fails. If it succeeds, return a valid cache ID. */
SshUInt32
ssh_interceptor_packet_cache_dst_entry(SshInterceptor interceptor,
                                       SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SshDstEntry cache_dst;
  SshDstEntry tmp;
  SshUInt32 slot;
  SshTime time_now;
  SshUInt32 microseconds;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Dst entry cache, caching dst for pp 0x%p, %u items in cache",
             pp, interceptor->dst_entry_cached_items));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet flags 0x%08x", pp->flags));

  if (ipp->skb == NULL || skb_dst(ipp->skb) == NULL)
    return 0;

  cache_dst = ssh_calloc(1, sizeof(SshDstEntryStruct));
  if (cache_dst == NULL)
    return 0;

  ssh_interceptor_get_time(&time_now, &microseconds);
  cache_dst->allocation_time = time_now;
  cache_dst->next = NULL;

  cache_dst->dst_entry = skb_dst(ipp->skb);
  dst_hold(cache_dst->dst_entry);

  ssh_kernel_mutex_lock(interceptor->dst_entry_cache_lock);

  cache_dst->dst_entry_id = interceptor->dst_entry_id++;
  slot = cache_dst->dst_entry_id % SSH_DST_ENTRY_TBL_SIZE;

  interceptor->dst_entry_cached_items++;

  SSH_ASSERT(slot < SSH_DST_ENTRY_TBL_SIZE);

  /* Head of list. */
  if (interceptor->dst_entry_table[slot] == NULL)
    {
      interceptor->dst_entry_table[slot] = cache_dst;
    }
  else
    {
      /* We do not care about potential collisions. These are highly unlikely
         to happen and in the end, this interceptor is anyway only for
         developmental purposes. */
      for (tmp = interceptor->dst_entry_table[slot];
           tmp->next != NULL;
           tmp = tmp->next)
        SSH_ASSERT(cache_dst->dst_entry_id != tmp->dst_entry_id);

      tmp->next = cache_dst;
    }

  /* Handle special case, the id is overflowing. 0 is used for special
     purposes, i.e. for 'real' engine created packets. */
  if (interceptor->dst_entry_id == 0)
    interceptor->dst_entry_id = 1;

  if (interceptor->dst_entry_cache_timeout_registered == FALSE)
    {
      SSH_ASSERT(interceptor->dst_entry_cached_items > 0);
      ssh_kernel_timeout_register(DST_ENTRY_MAX_CACHE_TIME, 0,
                                  ssh_interceptor_dst_entry_cache_timeout,
                                  interceptor);
      interceptor->dst_entry_cache_timeout_registered = TRUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Cache ID %u, left %u items in dst cache",
                               cache_dst->dst_entry_id,
                               interceptor->dst_entry_cached_items));

  ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);

  return cache_dst->dst_entry_id;
}

void
ssh_interceptor_packet_return_dst_entry(SshInterceptor interceptor,
                                        SshUInt32 dst_entry_id,
                                        SshInterceptorPacket pp,
                                        Boolean remove_only)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SshUInt32 slot = dst_entry_id % SSH_DST_ENTRY_TBL_SIZE;
  SshDstEntry tmp, prev = NULL;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Returning dst entry ID %u, pp 0x%p, %u items in cache, "
             "update %s",
             dst_entry_id, pp, interceptor->dst_entry_cached_items,
             remove_only == TRUE ? "no" : "yes"));

  if (pp != NULL)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet flags 0x%08x", pp->flags));

  /* Special case, 'real' engine created packets. */
  if (dst_entry_id == 0)
    return;

  SSH_ASSERT(slot < SSH_DST_ENTRY_TBL_SIZE);

  ssh_kernel_mutex_lock(interceptor->dst_entry_cache_lock);
  for (tmp = interceptor->dst_entry_table[slot]; tmp != NULL; tmp = tmp->next)
    {
      /* Do we have a match? */
      if (tmp->dst_entry_id == dst_entry_id)
        {
          /* Head of list. */
          if (tmp == interceptor->dst_entry_table[slot])
            {
              interceptor->dst_entry_table[slot] = tmp->next;

              interceptor->dst_entry_cached_items--;
              ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);

              if (remove_only == FALSE && pp != NULL)
                skb_dst_set(ipp->skb, tmp->dst_entry);
              else
                dst_release(tmp->dst_entry);

              ssh_free(tmp);

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Removed cache ID %u, left %u items in dst cache",
                         dst_entry_id, interceptor->dst_entry_cached_items));

              return;
            }

          /* Any other place in the list. */
          else
            {
              prev->next = tmp->next;

              interceptor->dst_entry_cached_items--;
              ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);

              if (remove_only == FALSE)
                skb_dst_set(ipp->skb, tmp->dst_entry);
              else
                dst_release(tmp->dst_entry);

              ssh_free(tmp);

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Removed cache ID %u, left %u items in dst cache",
                         dst_entry_id, interceptor->dst_entry_cached_items));

              return;
            }
        }

      prev = tmp;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Cache ID %u was not found, left %u items in dst cache",
             dst_entry_id, interceptor->dst_entry_cached_items));

  ssh_kernel_mutex_unlock(interceptor->dst_entry_cache_lock);
}
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
