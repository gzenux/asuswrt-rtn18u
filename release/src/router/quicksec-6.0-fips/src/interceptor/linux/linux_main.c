/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_IS_MAIN_MODULE

#include "linux_internal.h"
#include "sshinet.h"

#include "linux_license.h"

#ifdef SSHDIST_IPSEC_HWACCEL
#include "engine_hwaccel.h"
#endif /* SSHDIST_IPSEC_HWACCEL */

#include <linux/kernel.h>

#ifndef SSH_LINUX_KBUILD_COMPILATION
#include <linux/vermagic.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

static const char __module_depends[]
__used
__attribute((section(".modinfo"))) = "depends=";

#endif /* SSH_LINUX_KBUILD_COMPILATION */

#define SSH_DEBUG_MODULE "SshInterceptorMain"

/* Global interceptor object */
SshInterceptor ssh_interceptor_context = NULL;

/* Preallocated interceptor object */
static SshInterceptorStruct interceptor_struct;

/******************************** Utility functions *************************/

/* Returns version of interceptor API implemented. */
SshUInt32
ssh_interceptor_get_api_version(void)
{
  return 1;
}

/* Returns wall clock time */
void ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *useconds)
{
  struct timeval now;

  do_gettimeofday(&now);

  if (seconds)
    *seconds = (SshTime)now.tv_sec;

  if (useconds)
    *useconds = (SshUInt32)now.tv_usec;
}

void
ssh_interceptor_notify_ipm_open(SshInterceptor interceptor)
{
  local_bh_disable();

  /* Tell engine the PM connection is open. */
  ssh_engine_notify_ipm_open(interceptor->engine);

  local_bh_enable();
}

void
ssh_interceptor_notify_ipm_close(SshInterceptor interceptor)
{
  local_bh_disable();

  /* Tell engine the PM connection is closed. */
  ssh_engine_notify_ipm_close(interceptor->engine);


  ssh_interceptor_restore_debug_level(interceptor);

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  ssh_interceptor_dst_entry_cache_flush(interceptor);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  local_bh_enable();
}

/******************************* Interceptor API ****************************/

Boolean
ssh_interceptor_create(void *machine_context,
                       SshInterceptor *interceptor_return)
{
  /* Return the global interceptor object. */
  *interceptor_return = ssh_interceptor_context;

  return TRUE;
}

Boolean
ssh_interceptor_set_packet_cb(SshInterceptor interceptor,
                              SshInterceptorPacketCB packet_cb,
                              void *callback_context)
{
  if (interceptor == NULL)
    return FALSE;

  interceptor->packet_callback = packet_cb;
  interceptor->packet_callback_context = callback_context;

  return TRUE;
}

/* Opens the packet interceptor.  This must be called before using any
   other interceptor functions.  This registers the callbacks that the
   interceptor will use to notify the higher levels of received packets
   or changes in the interface list.  The interface callback will be called
   once either during this call or soon after this has returned.
   The `packet_cb' callback will be called whenever a packet is received
   from either a network adapter or a protocol stack.  It is guaranteed that
   this will not be called until from the bottom of the event loop after the
   open call has returned.

   The `interfaces_cb' callback will be called once soon after opening the
   interceptor, however earliest from the bottom of the event loop after the
   open call has returned.  From then on, it will be called whenever there is
   a change in the interface list (e.g., the IP address of an interface is
   changed, or a PPP interface goes up or down).

   The `callback_context' argument is passed to the callbacks. */

Boolean
ssh_interceptor_open(SshInterceptor interceptor,
                     SshInterceptorPacketCB packet_cb,
                     SshInterceptorInterfacesCB interfaces_cb,
                     SshInterceptorRouteChangeCB route_cb,
                     void *callback_context)
{
#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  SshUInt32 cpu_id;
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

  if (interceptor == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid interceptor"));
      return FALSE;
    }

  if (interceptor->engine_open)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Interceptor is already open"));
      return FALSE;
    }

  local_bh_disable();

  SSH_DEBUG(2, ("interceptor opened"));

#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  /* Reset packet callback function pointers. These are used for detecting
     if active packets are in engine processing when interceptor is closed. */
  for (cpu_id = 0; cpu_id < SSH_LINUX_INTERCEPTOR_NR_CPUS; cpu_id++)
    interceptor->active_packet_callback[cpu_id] = NULL_FNPTR;
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

  /* Set packet callback if defined. Note that the accelerated fastpath
     might have already set the packet callback using
     ssh_interceptor_set_packet_cb(). */
  if (packet_cb != NULL_FNPTR)
    {
      interceptor->packet_callback = packet_cb;
      interceptor->packet_callback_context = callback_context;
    }
  SSH_ASSERT(interceptor->packet_callback != NULL_FNPTR);

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* Set interface callback. */
  interceptor->nf->interfaces_callback = interfaces_cb;
  interceptor->nf->callback_context = callback_context;
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  /* Set route changed callback, allthough linux interceptor never calls it. */
  interceptor->nf->route_callback = route_cb;
  interceptor->nf->callback_context = callback_context;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
#ifdef SSH_BUILD_IPSEC
  /* Initialize octeon packet hooks. */
  ssh_interceptor_octeon_init(interceptor);
#endif /* SSH_BUILD_IPSEC */
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

  /* Mark interceptor opened. */
  interceptor->engine_open = TRUE;

  local_bh_enable();
  return TRUE;
}

/* Closes the packet interceptor.  No more packet or interface callbacks
   will be received from the interceptor after this returns.  Destructors
   may still get called even after this has returned.

   It is illegal to call any packet interceptor functions (other than
   ssh_interceptor_open) after this call.  It is, however, legal to call
   destructors for any previously returned packets even after calling this.
   Destructors for any packets previously supplied to one of the send
   functions will get called before this function returns. */

void
ssh_interceptor_close(SshInterceptor interceptor)
{
  /* all closing is done in ssh_interceptor_uninit() */
  interceptor->engine_open = FALSE;
  return;
}

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
/* Dummy function callback after interceptor has been stopped */
static void
ssh_interceptor_dummy_interface_cb(SshUInt32 num_interfaces,
                                   SshInterceptorInterface *ifs,
                                   void *context)
{
  /* Do nothing */
  return;
}
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

/* Dummy function which packets get routed to after ssh_interceptor_stop()
   has been called. */
static void
ssh_interceptor_dummy_packet_cb(SshInterceptorPacket pp, void *ctx)
{
  ssh_interceptor_packet_free(pp);
}

static void
interceptor_detach_packet_callback(SshInterceptor interceptor)
{
#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  SshUInt32 cpu_id;
  Boolean still_running;
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */

  /* Set packet_callback to point to our dummy_db */
  interceptor->packet_callback = ssh_interceptor_dummy_packet_cb;
  wmb();

#if (SSH_LINUX_INTERCEPTOR_NR_CPUS > 1)
  /* Wait for all the kernel threads to return from packet_callback. */
  do
    {
      still_running = FALSE;
      for (cpu_id = 0; cpu_id < SSH_LINUX_INTERCEPTOR_NR_CPUS; cpu_id++)
        if (interceptor->active_packet_callback[cpu_id] != NULL_FNPTR &&
            interceptor->active_packet_callback[cpu_id]
            != ssh_interceptor_dummy_packet_cb)
          {
            /* Found a kernel thread that is still using the old
               function pointer. Wait for a while and recheck. */
            still_running = TRUE;
            local_bh_enable();
            schedule();
            mdelay(300);
            local_bh_disable();
            break;
          }
    }
  while (still_running);
#endif /* SSH_LINUX_INTERCEPTOR_NR_CPUS > 1 */
}

/* Stops the packet interceptor.  After this call has returned, no new
   calls to the packet and interfaces callbacks will be made.  The
   interceptor keeps track of how many threads are processing packet,
   interface, or have pending route callbacks, and this function
   returns TRUE if there are no callbacks/pending calls to those functions.
   This returns FALSE if threads are still executing in those callbacks
   or routing callbacks are pending.

   After calling this function, the higher-level code should wait for
   packet processing to continue, free all packet structures received
   from that interceptor, and then close ssh_interceptor_close.  It is
   not an error to call this multiple times (the latter calls are
   ignored). */

Boolean
ssh_interceptor_stop(SshInterceptor interceptor)
{
  SSH_ASSERT(in_softirq());

  SSH_DEBUG(2, ("interceptor stopping"));

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Check if there are packets queued for asynchronous sending. */
  ssh_kernel_mutex_lock(interceptor->async_send_queue_lock);
  if (interceptor->async_send_queue != NULL)
    {
      ssh_kernel_mutex_unlock(interceptor->async_send_queue_lock);
      SSH_DEBUG(SSH_D_FAIL,
                ("Packets are queued for asynchronous sending, "
                 "can't stop"));
      return FALSE;
    }
  ssh_kernel_mutex_unlock(interceptor->async_send_queue_lock);
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* 'interceptor_lock protects the 'interfaces_callback'
     and 'num_interface_callbacks'. */
  ssh_kernel_mutex_lock(interceptor->interceptor_lock);

  if (interceptor->nf->num_interface_callbacks)
    {
      ssh_kernel_mutex_unlock(interceptor->interceptor_lock);
      SSH_DEBUG(SSH_D_ERROR,
                ("%d interface callbacks pending, can't stop",
                 interceptor->nf->num_interface_callbacks));
      return FALSE;
    }

  /* No more interfaces are delivered to the engine after this. */
  interceptor->nf->interfaces_callback = ssh_interceptor_dummy_interface_cb;

  ssh_kernel_mutex_unlock(interceptor->interceptor_lock);
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  /* After this the engine will receive no more packets from
     the interceptor, although the netfilter hooks are still
     installed. */
  interceptor_detach_packet_callback(interceptor);

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
#ifdef SSH_BUILD_IPSEC
  ssh_interceptor_octeon_uninit(interceptor);
#endif /* SSH_BUILD_IPSEC */
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

  /* Cancel any timeouts for the interceptor. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS, (void *) interceptor);

  if (ssh_kernel_timeouts_stop(interceptor) == FALSE)
    return FALSE;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  /* Route callback is currently not used. */
  interceptor->nf->route_callback = NULL_FNPTR;
  interceptor->nf->callback_context = NULL;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

  /* Callback contexts can now be safely zeroed, as both
     the interface_callback and the packet_callback point to
     our dummy_cb, and all kernel threads have returned from
     the engine. */
  interceptor->packet_callback_context = NULL;
#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  interceptor->nf->callback_context = NULL;
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  SSH_DEBUG(2, ("interceptor stopped"));

  return TRUE;
}

/************** Interceptor uninitialization break-down. *******************/


static void
ssh_interceptor_uninit_external_interfaces(SshInterceptor interceptor)
{
  SSH_ASSERT(!in_softirq());

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  /* Destroy all virtual adapters. This must be called before
     ip_glue_uninit(), so that the interface change event will be
     handled by quicksec and the device reference is freed. */
  ssh_interceptor_virtual_adapter_uninit(interceptor);
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
  /* Remove netfilter hooks */
  ssh_interceptor_ip_glue_uninit(interceptor);
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */

}

static void
ssh_interceptor_uninit_engine(SshInterceptor interceptor)
{
  SSH_ASSERT(in_softirq());

  /* Stop packet processing engine */
  if (interceptor->engine != NULL)
    {
      while (ssh_engine_stop(interceptor->engine) == FALSE)
        {
          local_bh_enable();
          schedule();
          mdelay(300);
          local_bh_disable();
        }
      interceptor->engine = NULL;
    }

  /* Free packet data structure */
  ssh_interceptor_packet_freelist_uninit(interceptor);
}

static void
ssh_interceptor_uninit_kernel_services(void)
{
  SSH_ASSERT(in_softirq());

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* Remove interface event handlers and free interface table. */
  ssh_interceptor_iface_uninit(ssh_interceptor_context);
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */


#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  ssh_interceptor_dst_entry_cache_uninit(ssh_interceptor_context);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  /* Uninitialize ipm channel */
  ssh_interceptor_ipm_uninit(ssh_interceptor_context);

  /* Cancel all timeouts, since we are shutting down. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS,
                            SSH_KERNEL_ALL_CONTEXTS);

  /* Empty timeout freelist */
  ssh_kernel_timeouts_uninit(ssh_interceptor_context);

  /* Free locks */
  ssh_kernel_mutex_free(ssh_interceptor_context->interceptor_lock);
  ssh_interceptor_context->interceptor_lock = NULL;
  ssh_kernel_mutex_free(ssh_interceptor_context->packet_lock);
  ssh_interceptor_context->packet_lock = NULL;
#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  ssh_kernel_mutex_free(ssh_interceptor_context->nf->route_lock);
  ssh_interceptor_context->nf->route_lock = NULL;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

  ssh_interceptor_debug_uninit(ssh_interceptor_context);

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  if (ssh_interceptor_context->cpu_ctx != NULL)
    ssh_free(ssh_interceptor_context->cpu_ctx);
  ssh_interceptor_context->cpu_ctx = NULL;

  if (ssh_interceptor_context->async_send_queue_lock != NULL)
    ssh_kernel_mutex_free(ssh_interceptor_context->async_send_queue_lock);
  ssh_interceptor_context->async_send_queue_lock = NULL;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

#ifdef ENGINE_MEMORY_DEBUG
  ssh_kmalloc_debug_uninit();
#endif /* ENGINE_MEMORY_DEBUG */




















  ssh_interceptor_mutexes_uninit(ssh_interceptor_context);

  ssh_interceptor_kernel_alloc_uninit(ssh_interceptor_context);

  ssh_interceptor_context = NULL;
}

/* Interceptor uninitialization. Called by cleanup_module() with
   softirqs disabled. */
static int
ssh_interceptor_uninit(void)
{
  SSH_ASSERT(!in_softirq());

  /* Uninitialize external interfaces. We enable softirqs for this
     as we have to make calls into the netfilter API that will
     execute scheduling in Linux 2.6. */
  ssh_interceptor_uninit_external_interfaces(ssh_interceptor_context);

  /* Uninitialize engine. Via ssh_interceptor_stop() this
     function makes sure that no callouts to the interceptor
     are in progress after it returns. ssh_interceptor_stop()
     _WILL_ grab the interceptor_lock, so make sure that it
     is not held.*/
  local_bh_disable();
  ssh_interceptor_uninit_engine(ssh_interceptor_context);
  local_bh_enable();

#ifdef SSHDIST_IPSEC_HWACCEL
  ssh_hwaccel_uninit();
#endif /* SSHDIST_IPSEC_HWACCEL */

  /* Uninitialize basic kernel services to the engine and the
     interceptor. This frees all remaining memory. Note that all locks
     are also freed here, so none of them can be held. */
  local_bh_disable();
  ssh_interceptor_uninit_kernel_services();
  local_bh_enable();

  return 0;
}


/************** Interceptor initialization break-down. *********************/


int
ssh_interceptor_init_kernel_services(void)
{
  SSH_ASSERT(!in_softirq());

  /* Interceptor object is always preallocated. */
  SSH_ASSERT(ssh_interceptor_context == NULL);
  memset(&interceptor_struct, 0, sizeof(interceptor_struct));
  ssh_interceptor_context = &interceptor_struct;

#ifdef DEBUG_LIGHT
  spin_lock_init(&ssh_interceptor_context->statistics_lock);
#endif /* DEBUG_LIGHT */

#ifdef ENGINE_MEMORY_DEBUG
  ssh_kmalloc_debug_init();
#endif /* ENGINE_MEMORY_DEBUG */

  /* Initialize kernel memory alloc module. */
  if (!ssh_interceptor_kernel_alloc_init(ssh_interceptor_context))
    goto error;

  /* Initialize kernel mutex module. */
  if (!ssh_interceptor_mutexes_init(ssh_interceptor_context))
    goto error;

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  /* Allocate CPU context for recursion breaking, etc... purposes. */
  ssh_interceptor_context->cpu_ctx =
    ssh_calloc(1, sizeof(SshCpuContextStruct) * ssh_kernel_num_cpus());
  if (ssh_interceptor_context->cpu_ctx == NULL)
    goto error;

  /* Allocate lock for protecting asynchrounous packet list. */
  ssh_interceptor_context->async_send_queue_lock = ssh_kernel_mutex_alloc();
  if (ssh_interceptor_context->async_send_queue_lock == NULL)
    goto error;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  if (ssh_kernel_timeouts_init(ssh_interceptor_context) != TRUE)
    goto error;

  /* General init */
  ssh_interceptor_context->interceptor_lock = ssh_kernel_mutex_alloc();
  ssh_interceptor_context->packet_lock = ssh_kernel_mutex_alloc();
#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  ssh_interceptor_context->nf->route_lock = ssh_kernel_mutex_alloc();
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

  if (ssh_interceptor_context->interceptor_lock == NULL
      || ssh_interceptor_context->packet_lock == NULL
#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
      || ssh_interceptor_context->nf->route_lock == NULL
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */
      )
    goto error;

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  rwlock_init(&ssh_interceptor_context->nf->if_table_lock);
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  /* Init packet data structure */
  if (!ssh_interceptor_packet_freelist_init(ssh_interceptor_context))
    {
      printk(KERN_ERR
             "INSIDE Secure Quicksec packet processing engine failed to start "
             "(out of memory).\n");
      goto error;
    }

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  if (ssh_interceptor_dst_entry_cache_init(ssh_interceptor_context) == FALSE)
    {
      printk(KERN_ERR "INSIDE Secure QuickSec packet processing engine "
             "failed to start, dst cache initialization failed.");
      goto error;
    }
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  /* Initialize ipm channel */
  if (!ssh_interceptor_ipm_init(ssh_interceptor_context))
    {
      printk(KERN_ERR
             "INSIDE Secure QuickSec packet processing engine failed to start "
             "(proc filesystem initialization error)\n");
      goto error1;
    }

  if (!ssh_interceptor_debug_init(ssh_interceptor_context))
   {
      printk(KERN_ERR
             "INSIDE Secure Quicksec packet processing engine failed to start "
             "(debug initialization error).\n");
      goto error2;
    }

  return 0;

 error2:
  local_bh_disable();
  ssh_interceptor_ipm_uninit(ssh_interceptor_context);
  local_bh_enable();

 error1:
  local_bh_disable();
  ssh_interceptor_packet_freelist_uninit(ssh_interceptor_context);
  local_bh_enable();

 error:
#ifdef ENGINE_MEMORY_DEBUG
  ssh_kmalloc_debug_uninit();
#endif /* ENGINE_MEMORY_DEBUG */

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  ssh_interceptor_dst_entry_cache_uninit(ssh_interceptor_context);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  ssh_kernel_mutex_free(ssh_interceptor_context->interceptor_lock);
  ssh_interceptor_context->interceptor_lock = NULL;

  ssh_kernel_mutex_free(ssh_interceptor_context->packet_lock);
  ssh_interceptor_context->packet_lock = NULL;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
  ssh_kernel_mutex_free(ssh_interceptor_context->nf->route_lock);
  ssh_interceptor_context->nf->route_lock = NULL;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

#ifdef SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION
  if (ssh_interceptor_context->cpu_ctx != NULL)
    ssh_free(ssh_interceptor_context->cpu_ctx);
  ssh_interceptor_context->cpu_ctx = NULL;

  if (ssh_interceptor_context->async_send_queue_lock != NULL)
    ssh_kernel_mutex_free(ssh_interceptor_context->async_send_queue_lock);
  ssh_interceptor_context->async_send_queue_lock = NULL;
#endif /* SSH_LINUX_SEND_QUEUE_RECURSION_ELIMINATION */

  ssh_interceptor_mutexes_uninit(ssh_interceptor_context);

  ssh_interceptor_kernel_alloc_uninit(ssh_interceptor_context);

  ssh_interceptor_context = NULL;

  return -ENOMEM;
}

int
ssh_interceptor_init_external_interfaces(SshInterceptor interceptor)
{
  SSH_ASSERT(!in_softirq());

  /* Enable proc entries. */
  ssh_interceptor_proc_enable(interceptor);

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* Register interface notifiers. */
  if (!ssh_interceptor_iface_init(interceptor))
    {
      printk(KERN_ERR
             "INSIDE Secure QuickSec packet processing engine failed to start "
             "(interface notifier installation error).\n");
      goto error0;
    }
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
  /* Register the firewall hooks. */
  if (!ssh_interceptor_ip_glue_init(interceptor))
    {
      printk(KERN_ERR
             "INSIDE Secure QuickSec packet processing engine failed to start "
             "(firewall glue installation error).\n");
      goto error1;
    }
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */


  return 0;


#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
 error1:
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  local_bh_disable();
  ssh_interceptor_iface_uninit(interceptor);
  local_bh_enable();
 error0:
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  return -EBUSY;
}

int
ssh_interceptor_init_engine(SshInterceptor interceptor)
{
  int start_cnt;

  SSH_ASSERT(!in_softirq());

  /* Initialize the IPsec engine */

  /* The linux kernel might not be able to steal sufficient
     amounts of memory from all slab caches quickly enough
     to satisfy the engine's memory requirements. Therefore
     we try to start the engine upto three times at
     .5s intervals if possible. */

  interceptor->engine = NULL;
  for (start_cnt = 0;
       start_cnt < 3 && interceptor->engine == NULL;
       start_cnt++)
    {
      /* In theory, it would be nice and proper to disable softirqs
         here and enable them after we exit engine_start(), but then
         we could not allocate memory without GFP_ATOMIC in the
         engine initialization, which would not be nice. Therefore
         we leave softirqs open here, and disable them for the
         duration of ssh_interceptor_open(). */
      interceptor->engine = ssh_engine_start(ssh_interceptor_send_to_ipm,
                                             interceptor,
                                             SSH_LINUX_ENGINE_FLAGS);
      if (interceptor->engine == NULL)
        {
          schedule();
          mdelay(500);
        }
    }

  if (interceptor->engine == NULL)
    {
      printk(KERN_ERR
             "INSIDE Secure QuickSec packet processing engine failed to start "
             "(engine start error).\n");
      goto error;
    }

  return 0;

 error:
  if (interceptor->engine != NULL)
    {
      local_bh_disable();
      while (ssh_engine_stop(interceptor->engine) == FALSE)
        {
          local_bh_enable();
          schedule();
          mdelay(300);
          local_bh_disable();
        }
      local_bh_enable();
      interceptor->engine = NULL;
    }

  return -EBUSY;
}

/* Interceptor initialization. Called by init_module(). */
int ssh_interceptor_init(void)
{
  int ret;

  SSH_ASSERT(!in_softirq());

  /* Print version info for log files */
  printk(KERN_INFO
         "INSIDE Secure %s built on "
         __DATE__ " " __TIME__ "\n", ssh_engine_version);

  ret = ssh_interceptor_init_kernel_services();
  if (ret != 0)
    goto error0;

  SSH_ASSERT(ssh_interceptor_context != NULL);

#ifdef SSHDIST_IPSEC_HWACCEL
  (void) ssh_hwaccel_init();
#endif /* SSHDIST_IPSEC_HWACCEL */

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
  ret = ssh_interceptor_hook_magic_init();
  if (ret != 0)
    goto error1;
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */


#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  ret = ssh_interceptor_virtual_adapter_init(ssh_interceptor_context);
  if (ret != 0)
    goto error3;
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  ret = ssh_interceptor_init_engine(ssh_interceptor_context);
  if (ret != 0)
    goto error4;

  ret = ssh_interceptor_init_external_interfaces(ssh_interceptor_context);
  if (ret != 0)
    goto error5;

  return 0;

 error5:
  local_bh_disable();
  ssh_interceptor_uninit_engine(ssh_interceptor_context);
  local_bh_enable();

 error4:
#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  ssh_interceptor_clear_ifaces(ssh_interceptor_context);
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
  ssh_interceptor_virtual_adapter_uninit(ssh_interceptor_context);
 error3:
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#ifdef SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS
 error1:
#endif /* SSH_LINUX_INTERCEPTOR_NETFILTER_HOOKS */

#ifdef SSHDIST_IPSEC_HWACCEL
  ssh_hwaccel_uninit();
#endif /* SSHDIST_IPSEC_HWACCEL */

  local_bh_disable();
  ssh_interceptor_uninit_kernel_services();
  local_bh_enable();

 error0:
  return ret;
}

MODULE_DESCRIPTION(SSH_LINUX_INTERCEPTOR_MODULE_DESCRIPTION);


int __init ssh_init_module(void)
{
  if (ssh_interceptor_init() != 0)
    return -EIO;
  return 0;
}

void __exit ssh_cleanup_module(void)
{
  if (ssh_interceptor_uninit() != 0)
    {
      printk("ssh_interceptor: module can't be removed.");
      return;
    }
}

void ssh_linux_module_dec_use_count()
{
  module_put(THIS_MODULE);
}

int
ssh_linux_module_inc_use_count()
{
  return try_module_get(THIS_MODULE);
}

MODULE_LICENSE(SSH_LINUX_LICENSE);
module_init(ssh_init_module);
module_exit(ssh_cleanup_module);

#ifndef SSH_LINUX_KBUILD_COMPILATION
struct module
__this_module __attribute((section(".gnu.linkonce.this_module"))) =
{
  .name = "quicksec",
  .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
  .exit = cleanup_module
#endif /* CONFIG_MODULE_UNLOAD */
};
#endif /* SSH_LINUX_KBUILD_COMPILATION */
