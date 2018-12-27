/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of virtual adapter API for Windows.
*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "registry.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#include "win_ip_route.h"
#include "win_ip_interface.h"
#include "kernel_timeouts.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

#define SSH_DEBUG_MODULE "SshInterceptorVirtualAdapter"

typedef struct SshVaRouteModifyCtxRec
{
  SshInterceptor interceptor;
  SshIpAddrStruct dst;
  SshIpAddrStruct gateway;
  
  SshInterceptorIfnum ifnum;
  
  SshInterceptorRouteSuccessCB callback;
  void *context;
} SshVaRouteModifyCtxStruct, *SshVaRouteModifyCtx;

/* Configuration context structure used for virtual 
 * adapter configuration. 
 */
typedef struct SshVirtualAdapterConfigureCtxRec {
  /* General items for the caller. */
  SshInterceptor interceptor;
  SshVirtualAdapterStatusCB status_cb;
  void *context;

  /* Identification for the VA to be configured. */
  SshInterceptorIfnum va_ifnum;
  SshVirtualAdapterState va_state;

  /* Address related items. */
  SshUInt16 num_addresses_ipv4;
  SshUInt16 num_addresses_ipv6;
  SshUInt16 num_addresses_set;
  SshIpAddr ip_addrs;

  /* Possible parameters */
  SshVirtualAdapterParams params;

  /* Timeout */
  LONG expiry_timeout_running; /* Timeout notifying the userland. */
  LONG hard_timeout_running;   /* Hard timeout for releasing the 
                                  virtual adapter configuration. */

  LONG      ip_cfg_thread_suspended; /* is the ip cfg_thread suspended? */
  LONG      va_context_active; /* Is this still active? */
  SshUInt8  va_configuration_aborted:1; /* Aborting operation? */
  SshUInt8  va_call_pending:1; /* Is there active call for windows? */
} SshVirtualAdapterConfigureCtxStruct, *SshVirtualAdapterConfigureCtx;

/* Internal function declarations. */
static void __fastcall
ssh_virtual_adapter_clear_addresses(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_add_addresses(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_configure_abort(SshVirtualAdapterConfigureCtx c);
static void 
ssh_virtual_adapter_configure_hard_timeout(void *context);
static void 
ssh_virtual_adapter_configure_timeout(void *context);
static inline void
ssh_virtual_adapter_configure_cleanup(SshVirtualAdapterConfigureCtx c,
                                      SshVirtualAdapterError error,
                                      LONG was_active);
static void __fastcall
ssh_virtual_adapter_start_configure(Boolean status, void *context);
static void __fastcall
ssh_virtual_adapter_clear_addresses_cb(Boolean status, void *context);
static void __fastcall
ssh_virtual_adapter_clear_addresses(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_clear_registry(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_wait_addresses(SshVirtualAdapterConfigureCtx c);

#if !defined(NDIS60) 
static void __fastcall
ssh_virtual_adapter_clear_primary_cb(Boolean status, 
                                     SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_clear_primary(SshVirtualAdapterConfigureCtx c);
#endif /* NDIS60 */
static void __fastcall
ssh_virtual_adapter_add_primary(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_start_add_addresses(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_add_addresses_cb(Boolean status, void *context);
static void __fastcall
ssh_virtual_adapter_add_addresses(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_update_registry(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_configure_params(SshVirtualAdapterConfigureCtx c);
static void __fastcall
ssh_virtual_adapter_configure_state(SshVirtualAdapterConfigureCtx c);

/*
 * Find the virtual adapter corresponding to the given interface
 * number, add a reference to it and return pointer to it. If not
 * found, return NULL. */
static SshVirtualAdapter
ssh_virtual_adapter_ref_by_ifnum(SshInterceptor interceptor,
                                 SshInterceptorIfnum adapter_ifnum)
{
  SshAdapter a;
  SshVirtualAdapter va = NULL;

  /* Get adapter by ifnum. */
  a = ssh_adapter_ref_by_ifnum(interceptor, adapter_ifnum);
  if (a != NULL)
    {
      /* Fail adapters with no virtual adapter part. */
      va = a->va;
      ssh_adapter_release(a);  

      if (va != NULL)
        {
          SSH_ASSERT(va->adapter == a);

          /* Valid virtual adapter found. Add reference to it. */
          InterlockedIncrement(&va->ref_count);
        }
    }

  return va;
}


static void __fastcall
ssh_route_modification_complete(Boolean success,
                                SshVaRouteModifyCtx ctx)
{
  SshInterceptorRouteError error;
  SSH_IRQL old_irql;

  SSH_ASSERT(ctx != NULL);

  if (success)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Route modification completed successfully"));
    error = SSH_INTERCEPTOR_ROUTE_ERROR_OK;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Route modification failed"));
    error = SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED;
    }

  if (ctx->callback != NULL_FNPTR)
    {
      SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
    (*(ctx->callback))(error, ctx->context);
      SSH_LOWER_IRQL(old_irql);
    }

  ssh_free(ctx);
}


void
ssh_virtual_adapter_send(SshInterceptor interceptor,
                         SshInterceptorPacket pp)
{
  SshVirtualAdapter va;

  va = ssh_virtual_adapter_ref_by_ifnum(interceptor, pp->ifnum_out);

  SSH_DEBUG(SSH_D_HIGHSTART, ("ssh_virtual_adapter_send(), "
                              "ifnum_out=%d, va=0x%p\n", pp->ifnum_out, va));

  if (va != NULL)
    {
      SshAdapter adapter;
      unsigned char * flat_packet;
      size_t flat_packet_len;

      SSH_ASSERT(va->adapter != NULL);
      adapter = va->adapter;

      /* Check the type of the source packet. */
      if (pp->protocol == SSH_PROTOCOL_ETHERNET)
        {
          /* We can send this directly. */
        }
      else if (pp->protocol == SSH_PROTOCOL_IP4
               || pp->protocol == SSH_PROTOCOL_IP6)
        {
          unsigned char ether_hdr[SSH_ETHERH_HDRLEN];
          SshIpAddrStruct src;
          SshIpAddrStruct dst;
          SshUInt16 ethertype;
          unsigned char *cp;
          size_t packet_len;

          /* Add ethernet framing. */

          /* Resolve packet's source and the ethernet type to use. */
          packet_len = ssh_interceptor_packet_len(pp);

          if (pp->protocol == SSH_PROTOCOL_IP4)
            {
              if (packet_len < SSH_IPH4_HDRLEN)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Packet is too short to contain IPv4 header"));
                  goto error;
                }
              cp = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);
              if (cp == NULL)
                goto error_already_free;

              SSH_IPH4_DST(&dst, cp);
              SSH_IPH4_SRC(&src, cp);
              ethertype = SSH_ETHERTYPE_IP;
            }
          else                      /* IPv6 */
            {
              if (packet_len < SSH_IPH6_HDRLEN)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Packet too short to contain IPv6 header"));
                  goto error;
                }
              cp = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN);
              if (cp == NULL)
                goto error_already_free;

              SSH_IPH6_DST(&dst, cp);
              SSH_IPH6_SRC(&src, cp);
              ethertype = SSH_ETHERTYPE_IPv6;
            }

          /* Finalize ethernet header. */

          /* If destination IP is not broadcast, use virtual adapter's 
             ethernet address in ether header. Otherwise use broadcast
             ether address */
          if (!SSH_IP_IS_BROADCAST(&dst))
              memcpy(ether_hdr + SSH_ETHERH_OFS_DST, 
                     adapter->media_addr, SSH_ETHERH_ADDRLEN);
          else
              memset(ether_hdr + SSH_ETHERH_OFS_DST, 
                     0xff, SSH_ETHERH_ADDRLEN);

          ssh_virtual_adapter_ip_ether_address(&src,
                                             ether_hdr + SSH_ETHERH_OFS_SRC);
          SSH_PUT_16BIT(ether_hdr + SSH_ETHERH_OFS_TYPE, ethertype);

          /* Insert header to the packet. */
          cp = ssh_interceptor_packet_insert(pp, 0, SSH_ETHERH_HDRLEN);
          if (cp == NULL)
            goto error_already_free;
          memcpy(cp, ether_hdr, SSH_ETHERH_HDRLEN);

          /* Just to be pedantic. */
          pp->protocol = SSH_PROTOCOL_ETHERNET;
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, 
                    ("Can not handle protocol %d", pp->protocol));
        }

      flat_packet_len = ssh_interceptor_packet_len(pp);
      flat_packet = ssh_malloc(flat_packet_len);

      if (flat_packet != NULL)
        {
          ssh_interceptor_packet_copyout(pp, 0, flat_packet, flat_packet_len);

          if (va->vnic_receive_cb != NULL_FNPTR)
            {
              (*va->vnic_receive_cb)(va->vnic_cb_context,
                                     flat_packet, 
                                     (unsigned int)flat_packet_len);
            }

          ssh_free(flat_packet);
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, 
                    ("Can not allocate memory for VNIC packet"));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("send without valid adapter, DROP"));
    }

 error:
  ssh_interceptor_packet_free(pp);
 error_already_free:
  if (va)
    ssh_virtual_adapter_release(va);
  return;
}


void
ssh_virtual_adapter_get_status(SshInterceptor interceptor,
                               SshInterceptorIfnum adapter_ifnum,
                               SshVirtualAdapterStatusCB callback,
                               void *context)
{
  SshUInt32 i;
  SshVirtualAdapter va;

  if (adapter_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Reporting status of all virtual adapters"));

      for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS; i++)
        {
          if (!(va = ssh_virtual_adapter_ref_by_ifnum(interceptor, i)))
            continue;

          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Reporting status of virtual adapter %u (%s)",
                     (unsigned)i, va->adapter_name));
          (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE,
                      i, va->adapter_name, va->adapter_state,
                      va->adapter_context, context);

          ssh_virtual_adapter_release(va);
        }

      SSH_DEBUG(SSH_D_HIGHSTART, ("No more virtual adapters"));
      (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                  SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                  SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                  NULL, context);
      return;
    }
  else
    {
      va = ssh_virtual_adapter_ref_by_ifnum(interceptor, adapter_ifnum);  

      if (va != NULL)
        {
          SSH_DEBUG(SSH_D_HIGHSTART,
                    ("Reporting status of virtual adapter %u (%s)",
                     (unsigned)adapter_ifnum, va->adapter_name));
          (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OK,
                      adapter_ifnum, va->adapter_name, va->adapter_state,
                      va->adapter_context, context);
          ssh_virtual_adapter_release(va);
          return;
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Nonexistent virtual adapter %u",
                     (unsigned)adapter_ifnum));
          (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                      SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                      SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                      NULL, context);
          return;
        }
    }
}


void
ssh_virtual_adapter_attach(SshInterceptor interceptor,
                           SshInterceptorIfnum adapter_ifnum,
                           SshVirtualAdapterPacketCB packet_cb,
                           SshVirtualAdapterDetachCB detach_cb,
                           void *adapter_context,
                           SshVirtualAdapterStatusCB callback,
                           void *context)
{
  SshVirtualAdapter va;

  va = ssh_virtual_adapter_ref_by_ifnum(interceptor, adapter_ifnum);  
  if (va == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Nonexistent virtual adapter %u",
                 (unsigned)adapter_ifnum));
      if (callback)
        (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                    SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                    SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                    NULL, context);
      goto end;
    }

  if (va->adapter_context != NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Virtual adapter %u already attached",
                 (unsigned)adapter_ifnum));
      if (callback)
        (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_PARAM_FAILURE,
                    SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                    SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                    NULL, context);
      goto end;
    }

  va->adapter_context = adapter_context;
  va->packet_cb = packet_cb;
  va->detach_cb = detach_cb;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Attached virtual adapter %u (%s)",
                              (unsigned)adapter_ifnum, va->adapter_name));

  /* Add an extra reference to the virtual adapter. This will be
     released by ssh_virtual_adapter_detach(). */
  ssh_virtual_adapter_add_ref(va);

  if (callback)
    (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OK,
                adapter_ifnum, va->adapter_name, va->adapter_state,
                va->adapter_context, context);
 end:
  if (va)
    ssh_virtual_adapter_release(va);
  return;
}

void ssh_virtual_adapter_detach_cb(SshVirtualAdapterError error,
                                   SshInterceptorIfnum adapter_ifnum,
                                   const unsigned char *adapter_name,
                                   SshVirtualAdapterState adapter_state,
                                   void *adapter_context, 
                                   void *context)
{
  SshInterceptor interceptor = (SshInterceptor) context;
  SshAdapter        adapter  = NULL;
  SshVirtualAdapter va       = NULL;

  SSH_DEBUG(SSH_D_ERROR, ("Virtual adapter %u clearing status %u.", 
                          error, adapter_ifnum));

  adapter = ssh_adapter_ref_by_ifnum(interceptor, adapter_ifnum);
  if (adapter == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Adapter %u disappeared during"
                              " detaching", adapter_ifnum));
      return;
    }
    
  /* A fatal error, with this kind of situation we may not  
     ever get here. */
  SSH_ASSERT(adapter->va != NULL);
  va = adapter->va;
    
  if (va->flags & SSH_VIRTUAL_ADAPTER_FLAG_DEREGISTER)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Deregistering virtual adapter."));
      adapter->va = NULL;
      ssh_virtual_adapter_deregister(va);
    }
  ssh_adapter_release(adapter);
}

void
ssh_virtual_adapter_detach(SshInterceptor interceptor,
                           SshInterceptorIfnum adapter_ifnum,
                           SshVirtualAdapterStatusCB callback,
                           void *context)
{
  SshVirtualAdapter va;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;

  va = ssh_virtual_adapter_ref_by_ifnum(interceptor, adapter_ifnum);  
  if (va == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Nonexistent virtual adapter %u",
                 (unsigned)adapter_ifnum));
      if (callback)
        (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                    SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                    SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                    NULL, context);
      goto end;
    }

  adapter_context = va->adapter_context;
  detach_cb = va->detach_cb;

  va->detach_cb = NULL;
  va->adapter_context = NULL;
  va->packet_cb = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Detaching virtual adapter %u (%s)",
                              (unsigned)adapter_ifnum, va->adapter_name));
  if (detach_cb)
    (*detach_cb)(adapter_context);

  /* Remove the extra reference taken by
     ssh_virtual_adapter_attach(). */
  ssh_virtual_adapter_release(va);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Detached virtual adapter %u (%s)",
                              (unsigned)adapter_ifnum, va->adapter_name));
  if (callback)
    (*callback)(SSH_VIRTUAL_ADAPTER_ERROR_OK,
                adapter_ifnum, va->adapter_name, va->adapter_state,
                adapter_context, context);

 end:
  if (va)
    ssh_virtual_adapter_release(va);

  /* Clear the addresses etc... from the virtual adapter. First wait
     that we are OK to go with the configuration and the configure. */
  while (InterlockedCompareExchange(&interceptor->va_configure_running, 1, 1))
    NdisMSleep(1000);

  ssh_virtual_adapter_configure(interceptor, adapter_ifnum, 
                                SSH_VIRTUAL_ADAPTER_STATE_DOWN,
                                0, NULL, NULL, 
                                ssh_virtual_adapter_detach_cb,
                                interceptor);
}

static void 
ssh_virtual_adapter_detach_deregister(SshInterceptor interceptor)
{
  SshAdapter adapter;
  SshInterceptorIfnum ifnum;

  for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS;  ifnum++)
    {
      adapter = ssh_adapter_ref_by_ifnum(interceptor, ifnum);
      
      if (adapter == NULL)
        continue;

      if (adapter->va && 
          (adapter->va->flags & SSH_VIRTUAL_ADAPTER_FLAG_DEREGISTER))
        {
          SshVirtualAdapter va;

          va = adapter->va;
          adapter->va = NULL;

          ssh_virtual_adapter_deregister(va);
        }

      ssh_adapter_release(adapter);
    }  

  SSH_DEBUG(SSH_D_LOWOK, ("Finished deregistering virtual adapters."));
}

static void 
ssh_virtual_adapter_i_detach_all(SshInterceptor interceptor)
{
  SshUInt32 i;
  SshVirtualAdapter va;
  SshVirtualAdapterDetachCB detach_cb;
  void *adapter_context;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Detaching all virtual adapters"));

  for (i = 0; i < SSH_INTERCEPTOR_MAX_ADAPTERS;  i++)
    {
      if (!(va = ssh_virtual_adapter_ref_by_ifnum(interceptor, i)))
        continue;

      detach_cb = va->detach_cb;
      adapter_context = va->adapter_context;

      va->detach_cb = NULL;
      va->adapter_context = NULL;
      va->packet_cb = NULL;

      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Detaching virtual adapter %u", (unsigned)i));
      if (detach_cb)
        {
          (*detach_cb)(adapter_context);
          /* Remove reference made by attach. */
          ssh_virtual_adapter_release(va);
        }

      /* Release the previous ref. */
      ssh_virtual_adapter_release(va);
    }
  
  /* Proceed to final stage, check if we'll have to deregister. */
  ssh_virtual_adapter_detach_deregister(interceptor);
}

void 
ssh_virtual_adapter_configure_all_down_cb(SshVirtualAdapterError error,
                                          SshInterceptorIfnum adapter_ifnum,
                                          const unsigned char *adapter_name,
                                          SshVirtualAdapterState adapter_state,
                                          void *adapter_context, 
                                          void *context)
{
  SshInterceptor interceptor  = (SshInterceptor) context;
  SshInterceptorIfnum ifnum   = 0;
  SshVirtualAdapter   va      = NULL;
  SshAdapter          adapter = NULL;
  
  SSH_DEBUG(SSH_D_LOWOK, ("%u virtual adapter configured with status %u",
                          adapter_ifnum, error));
  if (adapter_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    goto end;

  /* Find the next adapter. If the configuration has failed for the 
     previous, this restarts the configuration. */
  for (ifnum = (adapter_ifnum + 1); 
       ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
    {
      adapter = ssh_adapter_ref_by_ifnum(interceptor,ifnum);

      if (adapter == NULL)
        continue;

      if (adapter->va)
        {
          /* Wait for the configuration to be free. */
          while (InterlockedCompareExchange(
                                          &interceptor->va_configure_running, 
                                          1, 1))
            NdisMSleep(1000);

          ssh_virtual_adapter_configure(interceptor, ifnum, 
                                   SSH_VIRTUAL_ADAPTER_STATE_DOWN,
                                   0, NULL, NULL, 
                                   ssh_virtual_adapter_configure_all_down_cb,
                                   interceptor);
          ssh_adapter_release(adapter);
          return;
        }

      ssh_adapter_release(adapter);
    }

 end:
  SSH_DEBUG(SSH_D_LOWOK, ("Finished configuring virtual adapters."));
  ssh_virtual_adapter_i_detach_all(interceptor);
}

static void __fastcall
ssh_virtual_adapter_configure_all_down(SshInterceptor interceptor)
{
  SshInterceptorIfnum ifnum   = 0;
  SshAdapter          adapter = NULL;

  /* Start with the first virtual adapter, callback 
     proceeds to the next one. */
  SSH_DEBUG(SSH_D_LOWOK, ("Starting to configure all virtual adapters down"));

  for (ifnum = 0; ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS; ifnum++)
  {
    adapter = ssh_adapter_ref_by_ifnum(interceptor, ifnum);

    if (adapter == NULL)
      continue;

    if (adapter->va)
      {
        /* Wait for the configuration to be free. */
        while (InterlockedCompareExchange(
                                        &interceptor->va_configure_running,
                                        1, 1))
          NdisMSleep(1000);

        ssh_virtual_adapter_configure(interceptor, ifnum, 
                                 SSH_VIRTUAL_ADAPTER_STATE_DOWN,
                                 0, NULL, NULL, 
                                 ssh_virtual_adapter_configure_all_down_cb,
                                 interceptor);

        ssh_adapter_release(adapter);
        return;
      }

    ssh_adapter_release(adapter);
  }

  /* If we got here, we don't have any virtual adapters.*/  
  ssh_virtual_adapter_i_detach_all(interceptor);
}

void ssh_virtual_adapter_detach_all(SshInterceptor interceptor)
{
  /* We proceed in following mannor: 
   * - clear all addresses from all virtual adapters (using 
       ssh_virtual_adapter_configure)
   * - detach all adapters
   * - deregister adapters if necessary
   */
  if (!ssh_ndis_wrkqueue_queue_item(interceptor->work_queue,
                                    ssh_virtual_adapter_configure_all_down,
                                    interceptor))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to configure Virtual adapter down."));
    }
}

#define SSH_VIRTUAL_ADAPTER_CONFIGURE_TIMEOUT 10

/* Abort the virtual adapter configuration and start 
   clearing added addresses. */
static void __fastcall
ssh_virtual_adapter_configure_abort(SshVirtualAdapterConfigureCtx c)
{
  SSH_ASSERT(c->va_call_pending == 0);
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Aborting virtual adapter configuration"));

  InterlockedExchange(&c->va_context_active, 0);
  c->va_configuration_aborted = 1;
  /* we need to clear these also, since we
     are only clearing the adapters IP addresses. */
  c->num_addresses_ipv4       = 0;
  c->num_addresses_ipv6       = 0;
  c->num_addresses_set        = 0;

  ssh_virtual_adapter_clear_addresses(c);
}

/* Hard timeout is used for releasing the virtual adapter 
 * configuration even the previous context did not 
 * succeed to finish. I.e. call has left pending and it did 
 * not succeed to finish within given timeframe. Memory
 * allocated is left unfreed. 
 */
static void
ssh_virtual_adapter_configure_hard_timeout(void *context)
{
  SshVirtualAdapterConfigureCtx c = context;
  int i = 0;

  InterlockedExchange(&c->hard_timeout_running, 1);

  /* Possible case when this is called while we are cleaning
     up the configuration. Just leave. */
  if (InterlockedCompareExchange(&c->interceptor->va_configure_running, 0, 1))
    SSH_DEBUG(SSH_D_ERROR, ("Hard timeout got, calls still pending on "
			    "windows. Leaving context %p behind.", context));

  InterlockedExchange(&c->hard_timeout_running, 0);
}

/* A timeout cancelling virtual adapter configuration if 
 * it takes too long. Userland is notified in this stage. 
 */
static void
ssh_virtual_adapter_configure_timeout(void *context)
{
  SshVirtualAdapterConfigureCtx c = context;
  LONG was_active;

  /* We are running now. */
  InterlockedExchange(&c->expiry_timeout_running, 1);

  /* Possible case when this is called while we are cleaning
     up the configuration. */
  if (!InterlockedCompareExchange(&c->interceptor->va_configure_running, 0, 0))
    {
      InterlockedExchange(&c->expiry_timeout_running, 0);
      return;
    }

  /* Check if the context is active, if not, go away. */
  was_active = InterlockedCompareExchange(&c->va_context_active, 0, 1);
  
  /* Insert hard timeout, no matter what. This is the timeout when 
     we release new configuration for the virtual adapter, if the cleaning
     get's stuck for some reason. */
  ssh_kernel_timeout_register(SSH_VIRTUAL_ADAPTER_CONFIGURE_TIMEOUT,
                              0L, ssh_virtual_adapter_configure_hard_timeout,
                              (void *)c);

  /* If we were active in here, we'll inform userland for the timeout
     and let the other code take care of cleaning up. */
  if (was_active)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Virtual adapter configuration timed out"));
      
      /* Inform the userland that we failed (timeouted). */
      (*c->status_cb)(SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE,
                      SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
                      SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                      NULL, c->context);
    }

  /* We are not running anymore. */
  InterlockedExchange(&c->expiry_timeout_running, 0);
}

/* Cleanup the configuration context. Inform the status to userland
   if the context was still active. */
static inline void
ssh_virtual_adapter_configure_cleanup(SshVirtualAdapterConfigureCtx c,
                                      SshVirtualAdapterError error,
                                      LONG was_active)
{
  SshVirtualAdapter va = NULL;
  SshInterceptor interceptor = c->interceptor;

  SSH_ASSERT(SSH_GET_IRQL() == SSH_PASSIVE_LEVEL);

  SSH_DEBUG(SSH_D_LOWOK, ("Cleaning up virtual adapter configuration"
                          " context"));

  /* Try to cancel all the timeouts. */
  ssh_kernel_timeout_cancel(ssh_virtual_adapter_configure_timeout, c);
  ssh_kernel_timeout_cancel(ssh_virtual_adapter_configure_hard_timeout, c);

  /* Make sure we have executed all the code in timeout's. */
  while (InterlockedCompareExchange(&c->expiry_timeout_running, 1, 1))
    NdisMSleep(1000);

  while (InterlockedCompareExchange(&c->hard_timeout_running, 1, 1))
    NdisMSleep(1000);

  InterlockedExchange(&interceptor->va_configure_running, 0);
  
  /* If we are active at the time of calling this function, notify userland. 
     Otherwise we have already userland from expiry_timeout. */
  if (was_active)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Notifying user with status %u", error));
  
      if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
        {
          va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor,
                                                c->va_ifnum);
  
          (*c->status_cb)(error, c->va_ifnum, va->adapter_name,
                       va->adapter_state, va->adapter_context, c->context);
        }
      else
        {
  
          va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor,
                                                c->va_ifnum);
  
          /* If something failed, make sure that the adapter is disabled. */
          if (va)
            (*va->vnic_disable_cb)(va->vnic_cb_context);
          (*c->status_cb)(error, c->va_ifnum, NULL,
                       SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED, NULL, c->context);
        }
      if (va)
        ssh_virtual_adapter_release(va);
    }

  /* Free all allocated memory. Timeout's aren't running anymore, 
     so the memory is completely our's now. */
  if (c->ip_addrs)
    ssh_free(c->ip_addrs);
  
  if (c->params)
    ssh_free(c->params);
  
  c->ip_addrs = NULL;
  c->params   = NULL;
  
  if (InterlockedCompareExchange(&c->ip_cfg_thread_suspended, 0, 1))
    ssh_task_resume(&c->interceptor->ip_cfg_thread);

  ssh_free(c);
}


/* Start the whole virtual adapter configuration processing. 
 * The configuration proceeds in following mannor (in successful
 * case):
 *    - clear all the addresses
 *    - clear the registry
 *    - clear the primary IP address (XP, WinCE, ..., !NDIS60)
 *    - add the primary IP address (XP, WinCE, ..., !NDIS60)
 *    - add the alias addresses
 *    - set the virtual adapter parameters
 *    - set the virtual adapter state
 *    - cleanup the configuration context and inform userland
 * 
 * Configuration may be cancelled due to several reasons at any
 * given stage. This is handled by calling ssh_virtual_adapter_
 * configure_abort. Also timers play a significant role in this.
 */
static void __fastcall
ssh_virtual_adapter_start_configure(Boolean status, void *context)
{
  SshVirtualAdapterConfigureCtx c = context;

  InterlockedIncrement(&c->ip_cfg_thread_suspended);
  ssh_task_suspend(&c->interceptor->ip_cfg_thread, SSH_TASK_WAIT_INFINITE);

  ssh_virtual_adapter_clear_addresses(c);
}

/* Callback for the address deletion from the virtual adapter.
 */
static void __fastcall
ssh_virtual_adapter_clear_addresses_cb(Boolean status,
                                       void *context)
{
  SshVirtualAdapterConfigureCtx  c = context;
  SshVirtualAdapter             va = NULL;

  c->va_call_pending = 0;
  if (status == FALSE)
    {
      /* Remove the IP address from VA's internal structures. */
      if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, 
						  c->va_ifnum)))
        goto cleanup;

      /* IP address clearing failed for some reason. */
      SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter address clearing"
                             "failed. Aborting operation, garbage "
                              "may have been left..."));

      SSH_ASSERT(va->num_addresses > 0);
      va->num_addresses--;

      va->addresses[va->num_addresses].active = 0;
      if (va->num_addresses_active)
        va->num_addresses_active--;
      memset(&va->addresses[va->num_addresses].ip, 0x0, 
             sizeof(SshIpAddrStruct));

      ssh_virtual_adapter_release(va);

    cleanup:

      ssh_virtual_adapter_configure_cleanup(c, 
                         SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE, 
                         InterlockedExchange(&c->va_context_active, 0));
      return;
    }
  else
    {
      /* Remove the IP address from VA's internal structures. */
      if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, 
						  c->va_ifnum)))
        goto end;

      SSH_ASSERT(va->num_addresses > 0);

      va->num_addresses--;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Removed address %@ from virtual adapter, "
                                   "active addresses %u, "
				   "installed addresses %u",
                                   ssh_ipaddr_render, 
                                   &va->addresses[va->num_addresses].ip,
                                   va->num_addresses_active,
				   va->num_addresses));
      
      va->addresses[va->num_addresses].active = 0;
      if (va->num_addresses_active)
        va->num_addresses_active--;
      memset(&va->addresses[va->num_addresses].ip, 0x0, 
             sizeof(SshIpAddrStruct));
      
      ssh_virtual_adapter_release(va);
    }

 end:
  ssh_virtual_adapter_clear_addresses(c);
}

/* Clear all the current IP addresses from the Virtual adapter. 
 * Addresses are read from the SshVirtualAdapter structure.
 *
 * When we have finished with this, proceed to the next stage,
 * clear registry of the addresses. 
 *
 * As a deviation in this deletion, the last IP address in WinXP, 
 * WinCE, etc..., !NDIS60 is deleted after registry is cleared.
 */
static void __fastcall
ssh_virtual_adapter_clear_addresses(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va = NULL;
  SshVirtualAdapterAddress vaa = NULL;

  /* Is the configuration aborted? */
  if (InterlockedCompareExchange(&c->va_context_active, 0, 0) == 0
      && !c->va_configuration_aborted)
    {
      /* If the configuration is aborted, we don't have to do anything
         else, but cleanup our own memory. The IP addresses assigned
         to the VA and etc... stuff is cleared when we come here again. */
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE, 0);
      return;
    }

  /* If we are configuring only parameters, move on to next state. */
  if (c->va_state == SSH_VIRTUAL_ADAPTER_STATE_KEEP_OLD && !c->ip_addrs)
    goto add_addresses;
  
  /* A fatal error, should not happen. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, 
                                              c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT, 
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }
  
  if (va->num_addresses)
    vaa = &va->addresses[va->num_addresses - 1];
  else
    vaa = &va->addresses[0];

#ifndef NDIS60
  /* The primary IP address is deleted after registry is cleared. 
   * If the last IP address is IPv6, delete it and move only 
   * after that to the registry and primary IP address clearing.
   */
  if (va->num_addresses == 0 || 
      (va->num_addresses == 1 && SSH_IP_IS4(&vaa->ip)))
    {
      ssh_virtual_adapter_release(va);
      ssh_virtual_adapter_clear_registry(c);
      return;
    }
#endif /* NDIS60 */

  /* On NDIS60 all the IP addresses are considered as alias addresses. */
  if (va->num_addresses > 0)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Deleting IP address %@",
                                 ssh_ipaddr_render, &vaa->ip));
      c->va_call_pending = 1;

#if defined(WITH_IPV6)
      if (SSH_IP_IS6(&vaa->ip))
        ssh_ipdev_delete_address(&c->interceptor->ip6_dev, vaa->id,
                                 ssh_virtual_adapter_clear_addresses_cb, c);
      else
#endif /* WITH_IPV6 */
        ssh_ipdev_delete_address(&c->interceptor->ip4_dev, vaa->id,
                                 ssh_virtual_adapter_clear_addresses_cb, c);

      ssh_virtual_adapter_release(va);
      return;
    }
  
  /* Move on to next state*/
  ssh_virtual_adapter_release(va);
  ssh_virtual_adapter_clear_registry(c);
  return;

 add_addresses:
  ssh_virtual_adapter_add_addresses(c);
}

/* Remove IP addresses from registry. 
 */
static void __fastcall
ssh_virtual_adapter_clear_registry(SshVirtualAdapterConfigureCtx c)
{
  SshIpAddrStruct addr;
  SshVirtualAdapter va = NULL;  

  /* If we are going to add new addresses, we don't need
     to clear the old ones, since we are anyway going to  
     add new ones on top of the old ones. */
  if (c->num_addresses_ipv4 && c->ip_addrs && 
      c->va_state != SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Registry not cleared, since adding" 
                              " new IPv4 addresses."));
      goto next_stage;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing IPv4 addresses from system"
                          " registry."));

  memset(&addr, 0, sizeof(addr));
  addr.type = SSH_IP_TYPE_IPV4;

  /* A fatal error, should not happen. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, 
                                              c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                   SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                   InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  if (!ssh_adapter_set_ip_config(va->adapter, &addr, 1))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot clear IP configuration"));
      ssh_virtual_adapter_release(va);
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  va->num_addresses_active = 0;
  ssh_virtual_adapter_release(va);

 next_stage:
#ifndef NDIS60
  /* On !NDIS60 clear primary IP address. */
  ssh_virtual_adapter_clear_primary(c);
#else /* NDIS60 */
  ssh_virtual_adapter_start_add_addresses(c);
#endif /* NDIS60 */
}

#if !defined(NDIS60)
static void __fastcall
ssh_virtual_adapter_clear_primary_cb(Boolean status, 
                                     SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va = NULL;

  c->va_call_pending = 0;
  if (status == FALSE)
    {
      /* Not much to do. Just go away, since this failed. */
      ssh_virtual_adapter_configure_cleanup(c,
                          SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, 
                                              c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                  SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                  InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  if (va->num_addresses)
    {
      SSH_ASSERT(va->num_addresses == 1);
      va->num_addresses = 0;  
  
      memset(&va->addresses[0].ip, 0x0, sizeof(SshIpAddrStruct));
      va->addresses[0].active = 0;
    }
  
  ssh_virtual_adapter_release(va);
  ssh_virtual_adapter_start_add_addresses(c);
}

/* Clear primary IP address in WinXP and other NDIS5 platforms
 * except WinCE.
 */
static void __fastcall
ssh_virtual_adapter_clear_primary(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapterAddress vaa = NULL;
  SshVirtualAdapter        va  = NULL;
  SshIpAddrStruct addr;

  /* If we are going to add IPv4 addresses, we don't have
     to clear the old ones away. */  
  if ((c->num_addresses_ipv4 && c->ip_addrs) &&
       c->va_state != SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("IPv4 primary not removed since "
                              " there is new."));
      ssh_virtual_adapter_clear_primary_cb(TRUE, c);
      return;
    }

  memset(&addr, 0, sizeof(addr));
  addr.type = SSH_IP_TYPE_IPV4;
  
  /* A fatal error, should not happen. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                   SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                   InterlockedExchange(&c->va_context_active, 0));
      return;
    }
  vaa = &va->addresses[0];

  /* Virtual adapter needs to be in media connected state
     at the time of setting the primary address. */
  (*va->vnic_enable_cb)(va->vnic_cb_context);
  SSH_DEBUG(SSH_D_LOWSTART, ("Clearing primary IP address (%@)",
                             ssh_ipaddr_render, &addr));
  
  if (ssh_ipdev_find_first_address(&c->interceptor->ip4_dev, 
                                   va->adapter, &vaa->id))
    {
      c->va_call_pending = 1;
      ssh_ipdev_set_address(&c->interceptor->ip4_dev, vaa->id, &addr,
                            ssh_virtual_adapter_clear_primary_cb, c);
      ssh_virtual_adapter_release(va);
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not clear primary IP address, "
                              "ipdev first address not found."));
      ssh_virtual_adapter_release(va);
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
    }
}

#endif /* !NDIS60 */

/* Main call for adding addresses.
 */
static void __fastcall
ssh_virtual_adapter_start_add_addresses(SshVirtualAdapterConfigureCtx c)
{
  /* Abortion code. When the configuration has been aborted, 
     the addresses are cleaned and return is done here. */
  if (c->va_configuration_aborted)
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                  SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE, 
                  InterlockedCompareExchange(&c->va_context_active, 1, 1));
      return;
    }

  ssh_virtual_adapter_update_registry(c);
}

#ifndef NDIS60
/* WinXP and etc... NDIS5 version of adding primary IP. 
 */
static void __fastcall
ssh_virtual_adapter_add_primary(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter         va = NULL;
  SshVirtualAdapterAddress vaa = NULL;

  /* If there is no ipv4 addresses, we don't have 
     to do anything. */
  if (!c->num_addresses_ipv4 || !c->ip_addrs ||
      c->va_state == SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Skipping primary IP address setting"));
      goto next_stage;
    }
    
  /* A fatal error, should not happen. We have already cleared 
     the IP addresses, but not yet added anything, so just 
     cleanup and go away. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }
  vaa = &va->addresses[0];

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting primary address %@", 
                               ssh_ipaddr_render, 
                               &c->ip_addrs[0]));

  /* Adapter has to be in media connected state at this point. */
  (*va->vnic_enable_cb)(va->vnic_cb_context);

  if (ssh_ipdev_find_first_address(&c->interceptor->ip4_dev, va->adapter,
                                   &vaa->id))
    {
      c->va_call_pending = 1;

      memcpy(&vaa->ip, &c->ip_addrs[0], sizeof(SshIpAddrStruct));

      /* Set the primary IP address and go directly to the 
         add_addresses_cb, from where we continue adding the
         possible alias addresses. */
      ssh_ipdev_set_address(&c->interceptor->ip4_dev, vaa->id, 
                            &c->ip_addrs[0],
                            ssh_virtual_adapter_add_addresses_cb, c);
    }
  else 
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Moving directly to add addresses."));
      goto next_stage;
    }

  ssh_virtual_adapter_release(va);
  return;
  
 next_stage:
  ssh_virtual_adapter_add_addresses(c);
}
#else /* NDIS60 */
static void __fastcall
ssh_virtual_adapter_add_primary(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va;
  /* On Vista we only enable the interface and continue to next
     next stage (adding addresses). */

  /* A fatal error, should not happen. We have already cleared 
     the IP addresses, but not yet added anything, so just 
     cleanup and go away. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }  

  /* Adapter has to be in media connected state at this point. */
  (*va->vnic_enable_cb)(va->vnic_cb_context);  
  ssh_virtual_adapter_release(va);

  ssh_virtual_adapter_add_addresses(c);
}
#endif /* NDIS60 */

/* Callback for the virtual adapter IP address setting.  
 */
static void __fastcall
ssh_virtual_adapter_add_addresses_cb(Boolean status,
                                     void *context)
{
  SshVirtualAdapterConfigureCtx c = context;
  SshVirtualAdapterAddress vaa = NULL;
  SshVirtualAdapter va = NULL;
  register int i = 0;

  c->va_call_pending = 0;

  /* A fatal error really if this has happened. Can't clean anything.
     Just return and hope we can survive. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  vaa = &va->addresses[va->num_addresses];

  if (status == FALSE)
    {
      memset(&vaa->ip, 0x0, sizeof(SshIpAddrStruct));
      /* Clear the last, since it has failed. */

      SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter address adding "
                             "failed."));

      ssh_virtual_adapter_release(va);
      ssh_virtual_adapter_configure_abort(c);
      return;
    }
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Address %@ added to virtual adapter.",
                               ssh_ipaddr_render, 
                               &c->ip_addrs[c->num_addresses_set]));
  
  c->num_addresses_set++;
  va->num_addresses++;

  ssh_virtual_adapter_release(va);
  ssh_virtual_adapter_add_addresses(c);
}

/* Add the given IP addresses to the Virtual adapter. 
 */
static void __fastcall
ssh_virtual_adapter_add_addresses(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter        va  = NULL;
  SshVirtualAdapterAddress vaa = NULL;
  
  /* Is the configuration aborted? */
  if (InterlockedCompareExchange(&c->va_context_active, 0, 0) == 0)
    {
      ssh_virtual_adapter_configure_abort(c);
      return;
    }

  /* If there is no addresses to be set, go to next stage. */
  if ((!c->num_addresses_ipv4 && !c->num_addresses_ipv6) ||
      c->va_state == SSH_VIRTUAL_ADAPTER_STATE_DOWN)
      goto next_stage;

  /* Is all addresses added? */
  if (c->num_addresses_set == 
      (c->num_addresses_ipv4 + c->num_addresses_ipv6))
    goto next_stage;

  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }
    
  vaa = &va->addresses[va->num_addresses];
  c->va_call_pending = 1;
  
  SSH_DEBUG(SSH_D_LOWSTART, ("Adding IP address %@ to virtual adapter",
                             ssh_ipaddr_render, 
                             &c->ip_addrs[c->num_addresses_set]));
    
  /* Copy the address already here to the relevant structures, 
     since on some OS's these calls are synchronous. */
  memcpy(&vaa->ip, &c->ip_addrs[c->num_addresses_set], 
          sizeof(SshIpAddrStruct));

#if defined(WITH_IPV6)
  if (SSH_IP_IS6(&c->ip_addrs[c->num_addresses_set]))
    ssh_ipdev_add_address(&c->interceptor->ip6_dev, va->adapter,
                          &c->ip_addrs[c->num_addresses_set], &vaa->id,
                          ssh_virtual_adapter_add_addresses_cb, c);
  else
#endif /* WITH_IPV6 */
    ssh_ipdev_add_address(&c->interceptor->ip4_dev, va->adapter,
                          &c->ip_addrs[c->num_addresses_set], &vaa->id,
                          ssh_virtual_adapter_add_addresses_cb, c);
  
  ssh_virtual_adapter_release(va);
  return;

 next_stage:
  ssh_virtual_adapter_configure_params(c);
}

/* Update IPv4 addresses to the registry.
 */
static void __fastcall
ssh_virtual_adapter_update_registry(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va = NULL;

  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT, 
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  /* Set all the IP addresses to the registry. */
  if (!ssh_adapter_set_ip_config(va->adapter, c->ip_addrs, 
                                 c->num_addresses_ipv4))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot set IP configuration to registry"));
      ssh_virtual_adapter_release(va);
      ssh_virtual_adapter_configure_abort(c);
      return;
    }

  ssh_virtual_adapter_release(va);

  ssh_virtual_adapter_add_primary(c);
}

/* Set the parameters to the virtual adapter. 
 */
static void __fastcall
ssh_virtual_adapter_configure_params(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapterParams params = c->params;
  SshVirtualAdapter va;
  SshIPDevice ip_dev = NULL;

  if (c->params && c->params->mtu > 0)
    {
      va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor,
                                            c->va_ifnum);
      if (!va)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter disappeared during"
                                 " MTU configuration."));
          ssh_virtual_adapter_configure_cleanup(c, 
                               SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                               InterlockedExchange(&c->va_context_active, 0));
          return;
        }

      SSH_DEBUG(SSH_D_LOWSTART,
                ("Setting MTU to %u", (unsigned)c->params->mtu));

      ip_dev = &c->interceptor->ip4_dev;
      if (c->num_addresses_ipv4 &&
          ip_dev && 
          ssh_ipdev_configure(ip_dev, va->adapter, 
                             SSH_IPDEV_CONFIGURE_TYPE_MTU,
                             &c->params->mtu) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter MTU configuration failed"));
        }

#if defined(WITH_IPV6)
      ip_dev = &c->interceptor->ip6_dev;
      if (c->num_addresses_ipv6 && 
          ip_dev &&
          ssh_ipdev_configure(ip_dev, va->adapter, 
                              SSH_IPDEV_CONFIGURE_TYPE_MTU,
                              &c->params->mtu) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Virtual adapter MTU configuration failed"));
        }
#endif /* WITH_IPV6 */

      ssh_virtual_adapter_release(va);
    }

  ssh_virtual_adapter_configure_state(c);
}

/* Configure the virtual adapter state. 
 */
static void __fastcall
ssh_virtual_adapter_configure_state(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va = NULL;

  /* Configuration aborted? */
  if (InterlockedCompareExchange(&c->va_context_active, 0, 0) == 0)
    {
      ssh_virtual_adapter_configure_abort(c);
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Configuring virtual adapter to state %u",
                                c->va_state));

  /* Does the virtual adapter exist? If not, go away. */
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                              SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                              InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  /* Set the state down. */
  if (c->va_state == SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    (*va->vnic_disable_cb)(va->vnic_cb_context);

  /* All done, check that all addresses are active. */
  ssh_virtual_adapter_release(va);

  /* Free the IP cfg thread. */
  InterlockedDecrement(&c->ip_cfg_thread_suspended);
  ssh_task_resume(&c->interceptor->ip_cfg_thread);
  
  ssh_virtual_adapter_wait_addresses(c);
}

static void __fastcall
ssh_virtual_adapter_wait_addresses_cb(Boolean status,
                                      SshVirtualAdapterConfigureCtx c)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Address update received from virtual adapter"));

  if (status == FALSE)
    {
      ssh_virtual_adapter_configure_abort(c);
      return;
    }

  ssh_virtual_adapter_wait_addresses(c);
}

/* Wait for all addresses to become active. 
 */
static void __fastcall
ssh_virtual_adapter_wait_addresses(SshVirtualAdapterConfigureCtx c)
{
  SshVirtualAdapter va = NULL;
  
  if (!(va = ssh_virtual_adapter_ref_by_ifnum(c->interceptor, c->va_ifnum)))
    {
      ssh_virtual_adapter_configure_cleanup(c, 
                          SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                          InterlockedExchange(&c->va_context_active, 0));
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("%u of %u addresses active",
                          va->num_addresses_active,
                          va->num_addresses));

  if (c->ip_addrs && c->num_addresses_set && 
     (va->num_addresses_active < va->num_addresses))
    {
      va->address_context = c;
      va->address_callback = ssh_virtual_adapter_wait_addresses_cb;
      
      /* Recheck if this has just been updated. */
      if (va->num_addresses_active < va->num_addresses)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("%u of %u addresses active, "
                                  "waiting for the rest to activate",
                                   va->num_addresses_active,
                                   va->num_addresses));
          ssh_virtual_adapter_release(va);
          return;
        }
    }

  va->address_context = NULL;
  va->address_callback = NULL;  
  
  SSH_DEBUG(SSH_D_LOWOK, ("All addresses active"));
  ssh_virtual_adapter_release(va);

  /* Check if the configuration is to be aborted at the final stage... I.e. 
     timeout just happens to be executed and it has marked the context not
     to be active and has already informed userland. */
  if (InterlockedExchange(&c->va_context_active, 0))
    ssh_virtual_adapter_configure_cleanup(c, SSH_VIRTUAL_ADAPTER_ERROR_OK, 1);
  else
    ssh_virtual_adapter_configure_abort(c);

  return;  
}

/* Copy relevant information to the configuration context.  
 */
static inline int
ssh_virtual_adapter_copy_configure_ctx(SshInterceptor interceptor,
                                       SshIpAddr ip_addrs,
                                       SshUInt32 num_of_addresses, 
                                       SshVirtualAdapterParams params,
                                       SshVirtualAdapterConfigureCtx cfg_ctx)
{
  SshIpAddr ctx_addr = NULL;
  SshUInt16        i = 0;

  if (ip_addrs)
    {
      if (!(cfg_ctx->ip_addrs = 
            ssh_calloc(1, num_of_addresses * sizeof(*ctx_addr))))
        return SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;

      /* If there are any IPv4 addresses, select the first of them as
       * the "primary" address. Otherwise, 0.0.0.0 will be used to set
       * the primary IPv4 address of the interface. This is done in orderly
       * fashion so that the IPv4 addresses are first and then IPv6 addresses. 
       */
      for (i = 0; i < num_of_addresses; i++)
        {
          ctx_addr = &cfg_ctx->ip_addrs[cfg_ctx->num_addresses_ipv4];

          if (SSH_IP_IS4(&ip_addrs[i]))
            {
              memcpy(ctx_addr, &ip_addrs[i], sizeof(ip_addrs[i]));
              cfg_ctx->num_addresses_ipv4++;
            }
        }

      for (i = 0; i < num_of_addresses; i++)
        {
          ctx_addr = &cfg_ctx->ip_addrs[cfg_ctx->num_addresses_ipv4 + 
                                        cfg_ctx->num_addresses_ipv6];

#if defined(WITH_IPV6)
          if (!ssh_ipdev_is_connected(&interceptor->ip6_dev))
#endif /* WITH_IPV6 */
            {
              if (!cfg_ctx->num_addresses_ipv4)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("IPv6 support not available."
                                         " Failing virtual adapter "
                                         "configuration since no IPv4 "
                                         "addresses configured."));
		              goto fail;
                }
              SSH_DEBUG(SSH_D_FAIL, ("IPv6 support not available, "
                                     "ignoring IPv6 address."));
              continue;
            }

          if (SSH_IP_IS6(&ip_addrs[i]))
            {
              memcpy(ctx_addr, &ip_addrs[i], sizeof(ip_addrs[i]));
              cfg_ctx->num_addresses_ipv6++;
            }
        }
    }
  
  if (params)
    {
      if (!(cfg_ctx->params = ssh_calloc(1, sizeof(*params))))
        {
          if (cfg_ctx->ip_addrs)
            ssh_free(cfg_ctx->ip_addrs);

          return SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
        }
      memcpy(cfg_ctx->params, params, sizeof(*params));
    }
  
  return SSH_VIRTUAL_ADAPTER_ERROR_OK;

 fail:

  return SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
}

/*
 * Main call for the virtual adapter configuration. 
 */
void
ssh_virtual_adapter_configure(SshInterceptor interceptor,
                              SshInterceptorIfnum adapter_ifnum,
                              SshVirtualAdapterState adapter_state,
                              SshUInt32 num_addresses,
                              SshIpAddr addresses,
                              SshVirtualAdapterParams params,
                              SshVirtualAdapterStatusCB callback,
                              void *context)
{
  SshVirtualAdapterConfigureCtx cfg_ctx = NULL;
  SshVirtualAdapter                  va = NULL;
  int error                             = 0;

  SSH_ASSERT(callback != NULL_FNPTR);

  /* Make sure we're the only instance configuring the 
     virtual adapters at the moment. If a new one comes, 
     fail it. */
  if (InterlockedCompareExchange(&interceptor->va_configure_running,
				 1, 0) == 1)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("VA configuration already in progress."));

      error = SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
      goto error;
    }
  
  SSH_DEBUG(SSH_D_LOWSTART, ("Starting virtual adapter configuration"));

  if (num_addresses > SSH_VIRTUAL_ADAPTER_MAX_ADDRESSES)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Too many IP addresses"));
      error = SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
      goto error;
    }
  
  /* Take a reference to the virtual adapter if it exists. */
  va = ssh_virtual_adapter_ref_by_ifnum(interceptor, adapter_ifnum);
  if (va == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Configure request for nonexistent virtual"
                              " adapter %u", (unsigned)adapter_ifnum));
      
      error = SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT;
      goto error;
    }
  
  if (va->vnic_cb_context == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("VNIC CB context is null"));
      
      error = SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT;
      goto error;
    }

  /* Allocate temporary context for the configuration. */
  if (!(cfg_ctx = ssh_calloc(1, sizeof(*cfg_ctx))))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failed for Virtual adapter"
                              "configure context."));
    
      error = SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  /* Store necessary parameters for later usage. */
  cfg_ctx->interceptor   = interceptor;
  cfg_ctx->status_cb     = callback;
  cfg_ctx->context       = context;
  cfg_ctx->va_ifnum      = adapter_ifnum;
  cfg_ctx->va_state      = adapter_state;
  /* Save the last active configuration context as a pointer
     to the interceptor. This way we can abort the operation point. */

  error = ssh_virtual_adapter_copy_configure_ctx(interceptor,
                                                 addresses,
                                                 num_addresses,
                                                 params,
                                                 cfg_ctx);
 
  if (error != SSH_VIRTUAL_ADAPTER_ERROR_OK)
    goto error;
  
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Configuring virtual adapter %u to state " 
              "%u with %u IPv4 addresses and %u IPv6 addresses",
             (unsigned)adapter_ifnum, adapter_state, 
              cfg_ctx->num_addresses_ipv4, cfg_ctx->num_addresses_ipv6));

  /* Register a timeout, this way we can timeout from the 
     configuration at some point and let the user know the status. */
  ssh_kernel_timeout_register(SSH_VIRTUAL_ADAPTER_CONFIGURE_TIMEOUT,
                              0L, ssh_virtual_adapter_configure_timeout,
                              (void *)cfg_ctx);
  InterlockedExchange(&cfg_ctx->va_context_active, 1);

  if (!ssh_ndis_wrkqueue_queue_raw_item(interceptor->work_queue,
                                        ssh_virtual_adapter_start_configure,
                                        SSH_WORKQUEUE_FN_2_ARGS,
                                        TRUE, cfg_ctx))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot schedule work item"));
      goto error;
    }

  /* Release the reference from here. Let the 
     dispatch to take it's own. */
  ssh_virtual_adapter_release(va);
  return;

 error:
  /* Cancel the timeout, since we had an error. */

  /* Release the lock for the virtual adapter. Otherwise we'll
     block all the future requests. */
  InterlockedExchange(&interceptor->va_configure_running, 0);
  
  /* Free all allocated memory. */
  if (va)
    ssh_virtual_adapter_release(va);

  if (cfg_ctx && cfg_ctx->ip_addrs)
    ssh_free(cfg_ctx->ip_addrs);

  if (cfg_ctx && cfg_ctx->params)
    ssh_free(cfg_ctx->params);

  if (cfg_ctx)
    ssh_free(cfg_ctx);

  (*callback)(error,
              SSH_INTERCEPTOR_INVALID_IFNUM, NULL,
              SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
              NULL, context);
}

static void __fastcall
ssh_interceptor_add_route_internal(void *context)
{
  SshVaRouteModifyCtx ctx = (SshVaRouteModifyCtx)context;

  SSH_ASSERT(ctx != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting to add route"));
  ssh_ip_route_add(ctx->interceptor, &ctx->dst, &ctx->gateway, ctx->ifnum,
                   ssh_route_modification_complete, ctx); 
}

void 
ssh_interceptor_add_route(SshInterceptor interceptor,
                          SshInterceptorRouteKey key,
                          SshIpAddr gateway,
                          SshInterceptorIfnum ifnum,
                          SshRoutePrecedence precedence,
                          SshUInt32 flags,
                          SshInterceptorRouteSuccessCB success_cb,
                          void *success_cb_context)
{
  SshVaRouteModifyCtx ctx = NULL;

  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));





  if (key->selector != 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unsupported route key selector"));
      goto failed;
    }

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for route ctx"));
    goto failed;
    }

  ctx->callback = success_cb;
  ctx->context = success_cb_context;
  ctx->dst = key->dst;
  ctx->gateway = *gateway;
  ctx->ifnum = ifnum;
  ctx->interceptor = interceptor;

  if (!ssh_ndis_wrkqueue_queue_item(interceptor->work_queue,
				    ssh_interceptor_add_route_internal,
				    ctx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Work item scheduling failed."));
      goto failed;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Scheduled route add"));
  return;

 failed:
  ssh_free(ctx);

  if (success_cb != NULL)
    (*success_cb)(FALSE, success_cb_context);
}


static void __fastcall
ssh_interceptor_remove_route_internal(void *context)
{
  SshVaRouteModifyCtx ctx = (SshVaRouteModifyCtx)context;

  SSH_ASSERT(ctx != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting to remove route"));
  ssh_ip_route_remove(ctx->interceptor, &ctx->dst, &ctx->gateway, ctx->ifnum,
                      ssh_route_modification_complete, ctx); 
}

void 
ssh_interceptor_remove_route(SshInterceptor interceptor,
                             SshInterceptorRouteKey key,
                             SshIpAddr gateway,
                             SshInterceptorIfnum ifnum,
                             SshRoutePrecedence precedence,
                             SshUInt32 flags,
                             SshInterceptorRouteSuccessCB success_cb,
                             void *success_cb_context)
{
  SshVaRouteModifyCtx ctx = NULL;

  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));








  if (key->selector != 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unsupported route key selector"));
      goto failed;
    }

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for route ctx"));
    goto failed;
    }

  ctx->callback = success_cb;
  ctx->context = success_cb_context;
  ctx->dst = key->dst;
  ctx->gateway = *gateway;
  ctx->ifnum = ifnum;
  ctx->interceptor = interceptor;

  if (!ssh_ndis_wrkqueue_queue_item(interceptor->work_queue,
				    ssh_interceptor_remove_route_internal,
				    ctx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Work item scheduling failed."));
      goto failed;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Scheduled route removal"));
  return;

 failed:
  ssh_free(ctx);

  if (success_cb != NULL)
    (*success_cb)(FALSE, success_cb_context);
}
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
