/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements a dummy IPSEC engine that simply forwards all
   packets to a user-mode module that looks like an interceptor
   (usermodeinterceptor.c).  This mechanism is intended only for
   testing the IPSEC engine, and should not be compiled into
   production application.
*/

#include "sshincludes.h"
#include "interceptor.h"
#include "engine.h"
#include "kernel_encode.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "usermodeforwarder.h"
#include "sshinetencode.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


#define SSH_DEBUG_MODULE "SshUserModeForwarder"

#define SSH_ENGINE_VERSION "User-Mode Forwarder 1.0"

const char ssh_engine_version[] = SSH_ENGINE_VERSION;

/* Suffix to add to the name of the device name used for communicating
   with the kernel module in systems that have such a concept.  This
   is ignored on other systems. */
const char ssh_device_suffix[] = "-usermode";

/* Data structures for the user mode forwarder engine. */
struct SshEngineRec
{
  /* Lock for the engine. */
  SshKernelMutex lock;

  /* Function and context for sending packets to the user mode code. */
  SshEngineSendProc send;
  void *machine_context;

  /* Flag indicating that packets should be dropped if the user mode
     code is not connected.  Otherwise packets will be passed through in this
     situation. */
  Boolean drop_if_no_ipm;

  /* Flag indicating whether the user mode connection is currently open. */
  Boolean ipm_open;

  /* Flag indicating whether the IPM connection is "dead". It is
     declared dead when "watchdog reset" packets have not been
     received in sufficient time interval */
  Boolean ipm_dead;

  /* The watchdog counter -- this counts seconds, from a value given
     in a "keepalive" packet from the PM down to 0. If it ever reaches
     0, then ipm_dead is set to TRUE (a keepalive packet then resets
     ipm_dead). */
  SshUInt32 watchdog_timer;

  /* Value used as an initial watchdog timer when IPM is opened */
#define SSH_INITIAL_WATCHDOG_VALUE 10

  /* Packet interceptor. */
  SshInterceptor interceptor;

  /* Saved interfaces message (to be sent when ipm opens). */
  unsigned char *queued_interfaces_message;
  size_t queued_interfaces_len;

  /* List of registered control message handlers */
  struct SshEngineControlHandlerRec * control_handlers;
  size_t control_handlers_num;
};

/* Formats the message, and tries to send it to the policy manager.  This
   returns FALSE if sending the message fails (e.g., the queue is full).
   Every argument list should start with SSH_FORMAT_UINT32, (SshUInt32) 0,
   SSH_FORMAT_CHAR, type.  The first integer will be set to the length
   of the resulting packet.  This function can be called concurrently.

   If the usermode engine hasn't sent watchdog reset packets in a
   reasonable time, we straightforwardly drop all non-reliable
   packets. (We can't do that for reliable packets, since if we miss a
   route reply for instance, the usermode engine will drop packets on
   those missed routes..)*/

Boolean ssh_engine_send(SshEngine engine, Boolean locked,
                        Boolean reliable, ...)
{
  va_list ap;
  unsigned char *ucp;
  size_t len;

  if (!locked)
    ssh_kernel_mutex_lock(engine->lock);
  if (!engine->ipm_open || (engine->ipm_dead && !reliable))
    {
      if (!locked)
        ssh_kernel_mutex_unlock(engine->lock);
      return FALSE;
    }

  if (!locked)
    ssh_kernel_mutex_unlock(engine->lock);

  /* WARNING: this function is called from ssh_debug callback, which
     means that no debug functions can be called here or we'll end up
     with infinite recursion. */

  /* Construct the final packet to send to ipm. */
  va_start(ap, reliable);
  len = ssh_encode_array_alloc_va(&ucp, ap);
  va_end(ap);
  SSH_ASSERT(len >= 5); /* must have at least len+type */

  /* Update the length of the packet. */
  SSH_PUT_32BIT(ucp, len - 4);

  /* Send and/or queue the packet to the ipm.  This will free the buffer. */
  return (*engine->send)(ucp, len, reliable, engine->machine_context);
}

/* ssh_engine_send_debug and ssh_engine_send_warning are used by some
   interceptors for ssh_debug_cb etc. */

void ssh_engine_send_debug(SshEngine engine, const char *msg)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserve for length */
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_DEBUG,
                  SSH_FORMAT_UINT32_STR, msg, strlen(msg),
                  SSH_FORMAT_END);
}

void ssh_engine_send_warning(SshEngine engine, const char *msg)
{
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserve for length */
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_WARNING,
                  SSH_FORMAT_UINT32_STR, msg, strlen(msg),
                  SSH_FORMAT_END);
}

/* Watchdog timer */
static void ssh_engine_watchdog_timer(void *ctx)
{
    SshEngine engine = ctx;
    SshUInt32 value;
    Boolean was_dead;

    ssh_kernel_mutex_lock(engine->lock);

    if ((value = engine->watchdog_timer) != 0)
      engine->watchdog_timer--;

    was_dead = engine->ipm_dead;

    if (value == 0)
      engine->ipm_dead = TRUE;

    ssh_kernel_mutex_unlock(engine->lock);

    if (value == 0 && !was_dead)
      /* Yeah, this is most likely not to appear anywhere (ipm down
         -- can't send the debug message to it :-) but try anyway */
      SSH_DEBUG(SSH_D_ERROR,
                ("IPM open, but watchdog timer expired -- IPM is dead"));

    ssh_kernel_timeout_register(1, 0, ssh_engine_watchdog_timer,
                                (void *) engine);
}




























/* Callback function called by the real interceptor whenever a packet
   is received.  This passes the packet to the user mode
   interceptor. */
void ssh_engine_packet_callback(SshInterceptorPacket pp, void *context)
{
  SshEngine engine = (SshEngine) context;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[4 * SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  unsigned char *packetbuf, *internalbuf;
  size_t packet_len, internal_len, mediahdr_len;

  /* Check if the user mode connection is open. */
  ssh_kernel_mutex_lock(engine->lock);
  if (!engine->ipm_open || engine->ipm_dead)
    {
      /* The user-mode connection is not open (or it is dead).  Either
         drop the packet or pass it through. */
      ssh_kernel_mutex_unlock(engine->lock);
      if (engine->drop_if_no_ipm)
        ssh_interceptor_packet_free(pp);
      else
        {
          /* Determine media header length. */
          if (pp->protocol == SSH_PROTOCOL_ETHERNET)
            mediahdr_len = SSH_ETHERH_HDRLEN;
          else
            if (pp->protocol == SSH_PROTOCOL_FDDI ||
                pp->protocol == SSH_PROTOCOL_TOKENRING)
              mediahdr_len = 22;



            else
              mediahdr_len = 0;

          /* Send it through. */
          /* Set 'pp->ifnum_out' to the inbound interface 'pp->ifnum_in'. */
          pp->ifnum_out = pp->ifnum_in;

          ssh_interceptor_send(engine->interceptor, pp, mediahdr_len);
        }
      return;
    }
  ssh_kernel_mutex_unlock(engine->lock);

  /* Format the extension selectors into a buffer. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      SSH_PUT_32BIT(extbuf + 4 * i, pp->extension[i]);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Copy the packet into a linear buffer.  This is not fast, but is easy. */
  packet_len = ssh_interceptor_packet_len(pp);
  if (!(packetbuf = ssh_malloc(packet_len)))
    {
      ssh_interceptor_packet_free(pp);
      return;
    }

  ssh_interceptor_packet_copyout(pp, 0, packetbuf, packet_len);

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  if (!ssh_interceptor_packet_export_internal_data(pp, &internalbuf,
                                                   &internal_len))
    {
      ssh_free(packetbuf);
      return;
    }
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  /* Send a packet to the user mode code. */
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_PACKET,
                  SSH_FORMAT_UINT32, (SshUInt32) pp->flags,
                  SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_in,
                  SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_out,
                  SSH_FORMAT_UINT32, (SshUInt32) pp->routing_instance_id,
                  SSH_FORMAT_UINT32, (SshUInt32) pp->protocol,
                  SSH_FORMAT_UINT32_STR, packetbuf, packet_len,
                  SSH_FORMAT_UINT32_STR, internalbuf, internal_len,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                  SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                  SSH_FORMAT_END);

  /* Free the temporary buffer. */
  ssh_free(packetbuf);

  /* Free internal data representation */
  ssh_free(internalbuf);

  /* Free the packet object. */
  ssh_interceptor_packet_free(pp);
}

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION

/* This function is called whenever the interface list changes. */
void ssh_engine_interfaces_callback(SshUInt32 num_interfaces,
                                    SshInterceptorInterface *ifs,
                                    void *context)
{
  SshEngine engine = (SshEngine) context;
  unsigned char * packet, * packet_new;
  size_t len, packet_len;
  unsigned char *ucp;
  SshUInt32 i, k;

  /* Prepare the packet to send.  Loop over all interfaces and create data
     for each. */
  packet = NULL;
  packet_len = 0;
  for (i = 0; i < num_interfaces; i++)
    {
      /* Complete the data for the interface. */
      if (ifs[i].to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        len = ssh_encode_array_alloc(
                                &ucp,

                                SSH_FORMAT_UINT32,
                                (SshUInt32) SSH_INTERCEPTOR_MEDIA_NONEXISTENT,

                                SSH_FORMAT_UINT32, (SshUInt32) 0,
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
#ifdef WITH_IPV6
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
#endif /* WITH_IPV6 */

                                SSH_FORMAT_UINT32,
                                (SshUInt32) SSH_INTERCEPTOR_MEDIA_NONEXISTENT,

                                SSH_FORMAT_UINT32, (SshUInt32) 0,
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
#ifdef WITH_IPV6
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
#endif /* WITH_IPV6 */

                                SSH_FORMAT_UINT32_STR, "", (size_t)0L,
                                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].ifnum,
                                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].flags,
                                SSH_FORMAT_UINT32_STR, "", (size_t)0L,
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
                                SSH_FORMAT_UINT32_STR, "", (size_t)0L,
                                SSH_FORMAT_UINT32, (SshUInt32) 0,
                                SSH_FORMAT_END);
      else
        len = ssh_encode_array_alloc(
                &ucp,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_protocol.media,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_protocol.flags,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_protocol.mtu_ipv4,
#ifdef WITH_IPV6
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_protocol.mtu_ipv6,
#endif /* WITH_IPV6 */
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_adapter.media,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_adapter.flags,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_adapter.mtu_ipv4,
#ifdef WITH_IPV6
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].to_adapter.mtu_ipv6,
#endif /* WITH_IPV6 */

                SSH_FORMAT_UINT32_STR,
                ifs[i].media_addr, ifs[i].media_addr_len,

                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].ifnum,
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].flags,
                SSH_FORMAT_UINT32_STR, ifs[i].name, strlen(ifs[i].name),
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].routing_instance_id,
                SSH_FORMAT_UINT32_STR, ifs[i].routing_instance_name,
                strlen(ifs[i].routing_instance_name),
                SSH_FORMAT_UINT32, (SshUInt32) ifs[i].num_addrs,
                SSH_FORMAT_END);

      if (!ucp)
        {
          ssh_free(packet);
          return;
        }

      packet_new = ssh_realloc(packet, packet_len, packet_len + len);

      if (!packet_new)
        {
            ssh_free(packet);
            ssh_free(ucp);
            return;
        }

      packet = packet_new;

      memcpy(packet + packet_len, ucp, len);
      packet_len += len;

      ssh_free(ucp);

      for (k = 0; k < ifs[i].num_addrs; k++)
        {
          unsigned char *addr;
          size_t addr_size;

          if (ifs[i].addrs[k].protocol == SSH_PROTOCOL_IP4 ||
              ifs[i].addrs[k].protocol == SSH_PROTOCOL_IP6)
            {
              unsigned char *ip, *mask, *bcast;
              size_t ip_size, mask_size, bcast_size;

              ip_size =
                ssh_encode_ipaddr_array_alloc(&ip,
                                              &ifs[i].addrs[k].addr.ip.ip);

              mask_size =
                ssh_encode_ipaddr_array_alloc(&mask,
                                              &ifs[i].addrs[k].addr.ip.mask);

              bcast_size =
                ssh_encode_ipaddr_array_alloc(&bcast,
                                         &ifs[i].addrs[k].addr.ip.broadcast);

              /* Out of memory */
              if (!ip_size || !mask_size || !bcast_size)
                {
                failure:
                  ssh_free(ip);
                  ssh_free(mask);
                  ssh_free(bcast);
                  ssh_free(packet);
                  return;
                }

              addr_size = ssh_encode_array_alloc(&addr,
                                                 SSH_FORMAT_UINT32_STR,
                                                        ip, ip_size,
                                                 SSH_FORMAT_UINT32_STR,
                                                        mask, mask_size,
                                                 SSH_FORMAT_UINT32_STR,
                                                        bcast, bcast_size,
                                                 SSH_FORMAT_END);

              if (!addr_size)
                goto failure;

              ssh_free(ip);
              ssh_free(mask);
              ssh_free(bcast);
            }
          else
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("ifs[i].addrs[%d].protocol == %d is not supported",
                         (int) k, ifs[i].addrs[k].protocol));

              addr = ssh_strdup("");

              if (!addr)
                {
                  ssh_free(packet);
                  return;
                }

              addr_size = 0;
            }

          len = ssh_encode_array_alloc(&ucp,
                                       SSH_FORMAT_UINT32,
                                        ifs[i].addrs[k].protocol,
                                       SSH_FORMAT_UINT32_STR, addr, addr_size,
                                       SSH_FORMAT_END);

          ssh_free(addr);

          if (!ucp)
            {
              ssh_free(packet);
              return;
            }

          packet_new = ssh_realloc(packet, packet_len, packet_len + len);

          if (!packet_new)
            {
              ssh_free(packet);
              ssh_free(ucp);
              return;
            }

          packet = packet_new;
          memcpy(packet + packet_len, ucp, len);
          packet_len += len;

          ssh_free(ucp);
        }
    }

  /* Send the interfaces packet. */
  len = ssh_encode_array_alloc(&ucp,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_INTERFACES,
                  SSH_FORMAT_UINT32, num_interfaces,
                  SSH_FORMAT_DATA, packet, packet_len,
                  SSH_FORMAT_END);

  ssh_free(packet);

  if (!ucp)
      return;

  /* Save the interfaces message so that we can send it again when the
     ipm is next opened. */
  ssh_kernel_mutex_lock(engine->lock);
  if (engine->queued_interfaces_message)
    ssh_free(engine->queued_interfaces_message);
  engine->queued_interfaces_message = ucp;
  engine->queued_interfaces_len = len;
  ssh_kernel_mutex_unlock(engine->lock);

  /* Send the message now (assuming the user mode connection is open). */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_FORMAT_DATA, ucp, len,
                  SSH_FORMAT_END);

  /* ucp is not freed here, since it is stored in queued_interfaces_message */
}
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */


#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING

/* Function that is called whenever routing information changes.  There
   is no guarantee that this ever gets called. */
void ssh_engine_route_change_callback(void *context)
{
  SshEngine engine = (SshEngine) context;

  /* Send a simple notification. */
  ssh_engine_send(engine, FALSE, FALSE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_ROUTECHANGE,
                  SSH_FORMAT_END);
}
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

/* Creates the engine object.  Among other things, this opens the
   interceptor, initializes filters to default values, and arranges to send
   messages to the policy manager using the send procedure.  The send
   procedure will not be called until from the bottom of the event loop.
   The `machine_context' argument is passed to the interceptor and the
   `send' callback, but is not used otherwise.  This function can be
   called concurrently for different machine contexts, but not otherwise.
   The first packet and interface callbacks may arrive before this has
   returned. */

SshEngine ssh_engine_start(SshEngineSendProc send,
                           void *machine_context,
                           SshUInt32 flags)
{
  SshEngine engine;

  engine = ssh_calloc(1, sizeof(*engine));
  if (engine == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("failed to allocate engine object"));
      goto fail;
    }

  /* Transform data pointers are already all zero (assumed to equal NULL). */
  /* Fragment magic data initialized to zero. */
  engine->lock = ssh_kernel_mutex_alloc();
  engine->send = send;
  engine->machine_context = machine_context;
  engine->drop_if_no_ipm = (flags & SSH_ENGINE_DROP_IF_NO_IPM) != 0;
  engine->ipm_open = FALSE;
  engine->interceptor = NULL;
  engine->ipm_dead = TRUE;
  engine->watchdog_timer = 0;

  /* Create the interceptor. */
  if (!ssh_interceptor_create(machine_context, &engine->interceptor))
    {
      SSH_DEBUG(SSH_D_FAIL, ("creating the real interceptor failed"));
      goto fail;
    }
  SSH_ASSERT(engine->interceptor != NULL);

  /* Open the interceptor. */
  if (!ssh_interceptor_open(engine->interceptor,
                            ssh_engine_packet_callback,
#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
                            ssh_engine_interfaces_callback,
#else /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */
                            NULL_FNPTR,
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */
#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
                            ssh_engine_route_change_callback,
#else /* INTERCEPTOR_PROVIDES_IP_ROUTING */
                            NULL_FNPTR,
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */
                            (void *)engine))
    {
      SSH_DEBUG(1, ("opening the real interceptor failed"));
      goto fail;
    }

  SSH_DEBUG(1, ("SSH forwarder engine started"));
  return engine;

 fail:
  if (engine != NULL)
    {
      if (engine->interceptor)
        ssh_interceptor_close(engine->interceptor);
      ssh_kernel_mutex_free(engine->lock);
      ssh_free(engine);
    }
  return NULL;
}

/* Stops the engine, closes the interceptor, and destroys the
   engine object.  This does not notify IPM interface of the close;
   that must be done by the caller before calling this.  This returns
   TRUE if the engine was successfully stopped (and the object freed),
   and FALSE if the engine cannot yet be freed because there are
   threads inside the engine or uncancellable callbacks expected to
   arrive.  When this returns FALSE, the engine has started stopping,
   and this should be called again after a while.  This function can
   be called concurrently with packet/interface callbacks or timeouts
   for this engine, or any functions for other engines.*/

Boolean ssh_engine_stop(SshEngine engine)
{
  /* Stop the interceptor.  This means that no more new callbacks will
     arrive. */
  if (!ssh_interceptor_stop(engine->interceptor))
    return FALSE;

  /* Close the packet interceptor. */
  ssh_interceptor_close(engine->interceptor);

  /* Free the engine data structures. */
  ssh_free(engine->control_handlers);
  ssh_free(engine->queued_interfaces_message);
  ssh_kernel_mutex_free(engine->lock);
  memset(engine, 'F', sizeof(*engine));
  ssh_free(engine);
  return TRUE;
}

/* The machine-specific main program should call this when the policy
   manager has opened the connection to the engine.  This also
   sends the version packet to the policy manager.  This function can
   be called concurrently with packet/interface callbacks or timeouts. */

void ssh_engine_notify_ipm_open(SshEngine engine)
{
  SSH_DEBUG(1, ("User level module opened connection."));

  /* Update state information about the policy manager connection. */
  ssh_kernel_mutex_lock(engine->lock);
  SSH_ASSERT(!engine->ipm_open);
  engine->ipm_open = TRUE;
  ssh_kernel_mutex_unlock(engine->lock);

  /* The policy manager just connected to us.  It can't be dead. */
  engine->ipm_dead = FALSE;

  /* Send a version packet to the policy manager. */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_VERSION,
                  SSH_FORMAT_UINT32_STR,
                  SSH_ENGINE_VERSION, strlen(SSH_ENGINE_VERSION),
                  SSH_FORMAT_END);

#ifdef INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION
  /* If there is a saved interfaces message, send it now. */
  if (engine->queued_interfaces_message)
    {
      ssh_engine_send(engine, FALSE, TRUE,
                      SSH_FORMAT_DATA,
                      engine->queued_interfaces_message,
                      engine->queued_interfaces_len,
                      SSH_FORMAT_END);

      /* queued_interfaces_message is not freed, as it either will be
         freed on _stop or next interfaces callback */
    }
#endif /* INTERCEPTOR_PROVIDES_INTERFACE_INFORMATION */

  /* Set the watchdog timer */
  engine->watchdog_timer = SSH_INITIAL_WATCHDOG_VALUE;
#if 0
  ssh_kernel_timeout_register(1, 0, ssh_engine_watchdog_timer,
                              (void *) engine);
#endif
}

/* This function is called whenever the policy manager closes the
   connection to the engine.  This is also called when the engine is
   stopped.  This function can be called concurrently with
   packet/interface callbacks or timeouts. */

void ssh_engine_notify_ipm_close(SshEngine engine)
{
  SSH_DEBUG(1, ("User level module closed connection."));

  /* Lock the engine. */
  ssh_kernel_mutex_lock(engine->lock);

#ifdef DEBUG_LIGHT
  /* Set debug level to default *=0 */
  ssh_debug_set_level_string(ssh_custr("*=0"));
#endif /* DEBUG_LIGHT */

  /* Mark the policy interface not open. */
  engine->ipm_open = FALSE;

  /* Cancel watchdog timer */
  ssh_kernel_timeout_cancel(ssh_engine_watchdog_timer, (void*) engine);

  /* Unlock the engine. */
  ssh_kernel_mutex_unlock(engine->lock);
}

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING

/* Context structure for route lookups in the kernel. */

typedef struct SshEngineFromIpmRouteRec
{
  SshEngine engine;
  SshUInt32 id;
} *SshEngineFromIpmRoute;

/* Callback function to be called when a route lookup completes.  This sends
   a response to the user-mode interceptor. */

void ssh_engine_route_completion(Boolean reachable,
                                 SshIpAddr next_hop_gw,
                                 SshInterceptorIfnum ifnum,
                                 SshVriId routing_instance_id,
                                 size_t mtu,
                                 void *context)
{
  SshEngineFromIpmRoute rr = (SshEngineFromIpmRoute)context;
  unsigned char *buf;
  size_t len;

  buf = NULL;
  len = 0;

  if (next_hop_gw)
    len = ssh_encode_ipaddr_array_alloc(&buf, next_hop_gw);
  else
    {
      SshIpAddrStruct ip;
      SSH_IP_UNDEFINE(&ip);
      len = ssh_encode_ipaddr_array_alloc(&buf, &ip);
    }

  if (reachable)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("sending route reply id=%d reachable=%d ifnum=%d mtu=%zd "
               "next_hop=%@",
               (int) rr->id, reachable, (int) ifnum, mtu,
               ssh_ipaddr_render, next_hop_gw));
  else
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("sending route reply id=%d not reachable", (int) rr->id));

  ssh_engine_send(rr->engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0,
                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_ROUTEREPLY,
                  SSH_FORMAT_UINT32, (SshUInt32) rr->id,
                  SSH_FORMAT_UINT32, (SshUInt32) reachable,
                  SSH_FORMAT_UINT32, (SshUInt32) ifnum,
                  SSH_FORMAT_UINT32, (SshUInt32) mtu,
                  SSH_FORMAT_UINT32_STR, buf, len,
                  SSH_FORMAT_END);

  ssh_free(buf);

  memset(rr, 'F', sizeof(*rr));
  ssh_free(rr);
}

/* Processes a route lookup message received from the user-mode
   interceptor. */

void ssh_engine_from_ipm_route(SshEngine engine,
                               const unsigned char *data, size_t len)
{
  SshEngineFromIpmRoute rr;
  SshUInt32 id;
  SshInterceptorRouteKeyStruct key;
  unsigned char *dst_ptr, *src_ptr;
  SshUInt32 ipproto, ifnum, selector;
  size_t dst_len, src_len;
  SshUInt32 routing_instance_id;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[4 * SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);

  /* Decode the packet. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &id,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &dst_ptr, &dst_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &src_ptr, &src_len,
                       SSH_FORMAT_UINT32, &ipproto,
                       SSH_FORMAT_UINT32, &ifnum,
                       SSH_FORMAT_DATA, key.nh.raw, sizeof(key.nh.raw),
                       SSH_FORMAT_DATA, key.th.raw, sizeof(key.th.raw),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                       SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                       SSH_FORMAT_UINT32, &routing_instance_id,
                       SSH_FORMAT_UINT32, &selector,
                       SSH_FORMAT_END) != len || !dst_ptr)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipm route packet len=%d", len), data, len);
      return;
    }

  /* Copy addresses to the structure. */

  if (!ssh_decode_ipaddr_array(dst_ptr, dst_len, &key.dst))
  {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encoding"), dst_ptr, dst_len);
      return;
  }
  if (!ssh_decode_ipaddr_array(src_ptr, src_len, &key.src))
  {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encoding"), src_ptr, src_len);
      return;
  }

  /* Set ipproto, ifnum, and selector */
  key.ipproto = (SshInetIPProtocolID) ipproto;
  key.ifnum = (SshInterceptorIfnum) ifnum;
  key.selector = (SshUInt16) selector;

  /* Copy extension selectors */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      key.extension[i] = SSH_GET_32BIT(extbuf + 4 * i);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (routing_instance_id >= 0)
    SSH_INTERCEPTOR_ROUTE_KEY_SET_RIID(&key, routing_instance_id);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("route request to %@ (id %d)",
             ssh_ipaddr_render, &key.dst,
             (int) id));

  /* Allocate and initialize a context structure. */
  rr = ssh_calloc(1, sizeof(*rr));
  if (rr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate routing context."));
      return;
    }
  rr->engine = engine;
  rr->id = id;
  ssh_interceptor_route(engine->interceptor, &key,
                        ssh_engine_route_completion, (void *)rr);
}


void
ssh_engine_ipm_route_success(SshInterceptorRouteError error, void *context)
{
  SshEngineFromIpmRoute rr = context;

  /* Send success notification. */
  ssh_engine_send(rr->engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserved for len */

                  SSH_FORMAT_CHAR,
                  (unsigned int) SSH_ENGINE_IPM_FORWARDER_ROUTE_SUCCESS,

                  SSH_FORMAT_UINT32, rr->id,
                  SSH_FORMAT_UINT32, error,
                  SSH_FORMAT_END);

  /* Free the context. */
  ssh_free(rr);
}


void ssh_engine_from_ipm_modify_route(SshEngine engine, Boolean add,
                                      const unsigned char *data, size_t len)
{
  SshEngineFromIpmRoute rr;
  SshUInt32 id;
  SshInterceptorRouteKeyStruct key;
  unsigned char *key_dst, *key_src, *gw_ptr;
  SshUInt32 key_ipproto, key_ifnum, key_selector, precedence, flags, ifnum;
  size_t key_dst_len, key_src_len, gw_len;
  SshIpAddrStruct gw;
  SshUInt32 routing_instance_id;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  unsigned char extbuf[4 * SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SSH_INTERCEPTOR_ROUTE_KEY_INIT(&key);

  /* Decode the packet. */
  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &id,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &key_dst, &key_dst_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &key_src, &key_src_len,
                       SSH_FORMAT_UINT32, &key_ipproto,
                       SSH_FORMAT_UINT32, &key_ifnum,
                       SSH_FORMAT_DATA, key.nh.raw, sizeof(key.nh.raw),
                       SSH_FORMAT_DATA, key.th.raw, sizeof(key.th.raw),
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                       SSH_FORMAT_DATA, extbuf, sizeof(extbuf),
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                       SSH_FORMAT_UINT32, &key_selector,
                       SSH_FORMAT_UINT32, &routing_instance_id,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &gw_ptr, &gw_len,
                       SSH_FORMAT_UINT32, &ifnum,
                       SSH_FORMAT_UINT32, &precedence,
                       SSH_FORMAT_UINT32, &flags,
                       SSH_FORMAT_END) != len || !key_dst)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipm route modify packet len=%d", len),
                        data, len);
      return;
    }

  /* Copy addresses to the structure. */

  if (!ssh_decode_ipaddr_array(key_dst, key_dst_len, &key.dst))
  {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encoding"), key_dst, key_dst_len);
      return;
  }
  if (!ssh_decode_ipaddr_array(key_src, key_src_len, &key.src))
  {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encoding"), key_src, key_src_len);
      return;
  }
  if (!ssh_decode_ipaddr_array(gw_ptr, gw_len, &gw))
  {
      SSH_DEBUG_HEXDUMP(0, ("bad ipaddr encoding"), gw_ptr, gw_len);
      return;
  }

  /* Set ipproto, ifnum, and selector */
  key.ipproto = (SshInetIPProtocolID) key_ipproto;
  key.ifnum = (SshInterceptorIfnum) key_ifnum;
  key.selector = (SshUInt16) key_selector;

  /* Copy extension selectors */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      key.extension[i] = SSH_GET_32BIT(extbuf + 4 * i);
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  if (routing_instance_id >= 0)
    SSH_INTERCEPTOR_ROUTE_KEY_SET_RIID(&key, routing_instance_id);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("route %s request to %@ (id %d)",
             (add ? "add" : "remove"),
             ssh_ipaddr_render, &key.dst,
             (int) id));

  /* Allocate and initialize a context structure. */
  rr = ssh_calloc(1, sizeof(*rr));
  rr->engine = engine;
  rr->id = id;


#ifdef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  if (add)
    ssh_interceptor_add_route(engine->interceptor, &key, &gw, ifnum,
                              (SshRoutePrecedence) precedence,
                              flags,
                              ssh_engine_ipm_route_success, (void *)rr);
  else
    ssh_interceptor_remove_route(engine->interceptor, &key, &gw, ifnum,
                                 (SshRoutePrecedence) precedence,
                                 flags,
                                 ssh_engine_ipm_route_success, (void *)rr);
#else /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
  /* Interceptor does not implement kernel level routing table modify. Fail. */
  ssh_engine_ipm_route_success(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, rr);
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
}
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

/* Processes a packet to send received from the user-mode interceptor. */

void ssh_engine_from_ipm_packet(SshEngine engine,
                                const unsigned char *data, size_t len)
{
  SshInterceptorPacket pp;
  SshUInt32 flags, ifnum_in, ifnum_out, protocol, media_header_len;
  SshUInt32 routing_instance_id;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extensions[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 i;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  unsigned char *packet_ptr, *internal_ptr;
  size_t packet_len, internal_len, bytes;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt16 route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Decode the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32, &flags,
                           SSH_FORMAT_UINT32, &ifnum_in,
                           SSH_FORMAT_UINT32, &ifnum_out,
                           SSH_FORMAT_UINT32, &routing_instance_id,
                           SSH_FORMAT_UINT32, &protocol,
                           SSH_FORMAT_UINT32, &media_header_len,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                           SSH_FORMAT_UINT16, &route_selector,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                           SSH_FORMAT_UINT16, NULL,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                           SSH_FORMAT_UINT32_STR_NOCOPY,
                           &packet_ptr, &packet_len,
                           SSH_FORMAT_UINT32_STR_NOCOPY,
                           &internal_ptr, &internal_len,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipm_packet fixed part"), data, len);
      return;
    }
  data += bytes;
  len -= bytes;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      bytes = ssh_decode_array(data, len,
                                      SSH_FORMAT_UINT32, &extensions[i],
                                      SSH_FORMAT_END);
      if (bytes == 0)
        {
          SSH_DEBUG_HEXDUMP(0, ("bad extension selector in ipm_packet"),
                            data, len);
          return;
        }
      data += bytes;
      len -= bytes;
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (len != 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("garbage at end of ipm_packet"), data, len);
      return;
    }

  /* Assert that interface numbers fit into SshInterceptorIfnum. */
  SSH_ASSERT(((SshUInt32)ifnum_in) <= ((SshUInt32)SSH_INTERCEPTOR_MAX_IFNUM));
  SSH_ASSERT(((SshUInt32)ifnum_out) <= ((SshUInt32)SSH_INTERCEPTOR_MAX_IFNUM));

  /* Allocate a packet object and copy data into it. */
  flags &= (SSH_PACKET_FROMADAPTER |
            SSH_PACKET_FROMPROTOCOL |
            SSH_PACKET_FORWARDED |
            SSH_PACKET_UNMODIFIED);
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    flags, protocol,
                                    ifnum_in, ifnum_out,
                                    packet_len);
  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("failed to allocate packet"));
      return;
    }

  if (!ssh_interceptor_packet_copyin(pp, 0, packet_ptr, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      return;
    }

  pp->routing_instance_id = (SshVriId) routing_instance_id;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  pp->route_selector = route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  if (!ssh_interceptor_packet_import_internal_data(pp,
                                                   internal_ptr, internal_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("internal import failed, dropping packet"));
      return;
    }
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      pp->extension[i] = extensions[i];
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Send the packet out. */
  ssh_interceptor_send(engine->interceptor, pp, media_header_len);
}

void ssh_engine_from_ipm_internal_data_discarded(SshEngine engine,
                                                 const unsigned char *data,
                                                 size_t len)
{
  unsigned char *data_ptr;
  size_t data_len, bytes;

  /* Decode the packet. */
  bytes = ssh_decode_array(data, len,
                           SSH_FORMAT_UINT32_STR_NOCOPY,
                           &data_ptr, &data_len,
                           SSH_FORMAT_END);
  if (bytes == 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipm_packet fixed part"), data, len);
      return;
    }
  data += bytes;
  len -= bytes;

  if (len != 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("garbage at end of ipm_packet"), data, len);
      return;
    }

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  ssh_interceptor_packet_discard_internal_data(data_ptr, data_len);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
}

/* Process watchdog reset request */
void ssh_engine_from_ipm_watchdog_reset(SshEngine engine,
                                        const unsigned char *data, size_t len)
{
  size_t bytes;
  SshUInt32 seconds;
  Boolean was_dead;

  bytes =
    ssh_decode_array(data, len,
                     SSH_FORMAT_UINT32, &seconds,
                     SSH_FORMAT_END);

  if (bytes == 0)
    {
      SSH_DEBUG_HEXDUMP(0, ("bad ipm_watchdog_reset packet"), data,len);
      return;
    }

  ssh_kernel_mutex_lock(engine->lock);

  engine->watchdog_timer = seconds;
  was_dead = engine->ipm_dead;
  engine->ipm_dead = FALSE;
  ssh_kernel_mutex_unlock(engine->lock);

  if (was_dead)
    SSH_DEBUG(SSH_D_ERROR,
              ("Watchdog reset received from dead IPM: "
               "PM is back on the stage!"));

  SSH_DEBUG(SSH_D_LOWOK, ("Watchdog reset to %d seconds",
                          (int) seconds));
}

void ssh_engine_from_ipm_set_debug(SshEngine engine,
                                   const unsigned char *data, size_t len)
{
  unsigned char *s;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &s, NULL,
                       SSH_FORMAT_END) != len)
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Setting debug level to \"%s\"", s));

  ssh_debug_set_level_string(s);
}

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
/**************** Creating and manipulating virtual adapters ****************/

typedef struct SshEngineIpmVirtualAdapterOpCtxRec
{
  SshEngine engine;
  SshUInt32 operation_id;
  Boolean dynamic;
} *SshEngineIpmVirtualAdapterOpCtx, SshEngineIpmVirtualAdapterOpCtxStruct;


/* Interceptor to Engine */

void
ssh_engine_ipm_virtual_adapter_packet_cb(SshInterceptor interceptor,
                                         SshInterceptorPacket pp,
                                         void *adapter_context)
{
  SshEngine engine = adapter_context;
  unsigned char *packet, *internal;
  size_t packet_len, internal_len;

  /* Copy the packet into a linear buffer. */
  packet_len = ssh_interceptor_packet_len(pp);
  packet = ssh_malloc(packet_len);
  if (packet == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return;
    }

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  if (!ssh_interceptor_packet_export_internal_data(pp,
                                                   &internal, &internal_len))
    {
      ssh_free(packet);
      return;
    }
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);

  /* Send the packet to the user-mode engine. */
  ssh_engine_send(
        engine, FALSE, FALSE,
        SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserved for length */

        SSH_FORMAT_CHAR,
        (unsigned int) SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_PACKET_CB,

        SSH_FORMAT_UINT32, (SshUInt32) pp->flags,
        SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_in,
        SSH_FORMAT_UINT32, (SshUInt32) pp->ifnum_out,
        SSH_FORMAT_UINT32, (SshUInt32) pp->protocol,
        SSH_FORMAT_UINT32_STR, packet, packet_len,
        SSH_FORMAT_UINT32_STR, internal, internal_len,

        SSH_FORMAT_END);

  /* Free the temporary buffer. */
  ssh_free(packet);

  /* Free internal data representation */
  ssh_free(internal);

  /* Free the interceptor packet. */
  ssh_interceptor_packet_free(pp);
}


void
ssh_engine_ipm_virtual_adapter_status_cb(SshVirtualAdapterError error,
                                         SshInterceptorIfnum adapter_ifnum,
                                         const unsigned char *adapter_name,
                                         SshVirtualAdapterState adapter_state,
                                         void *adapter_context,
                                         void *context)
{
  SshEngineIpmVirtualAdapterOpCtx ctx =
    (SshEngineIpmVirtualAdapterOpCtx) context;
  size_t adapter_name_len = 0;

  if (adapter_name != NULL)
    adapter_name_len = strlen(adapter_name);

  /* Send success notification. */
  ssh_engine_send(ctx->engine, FALSE, TRUE,
                  SSH_FORMAT_UINT32, (SshUInt32) 0, /* reserved for len */
                  SSH_FORMAT_CHAR, (unsigned int)
                  SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_STATUS_CB,
                  SSH_FORMAT_UINT32, ctx->operation_id,
                  SSH_FORMAT_UINT32, error,
                  SSH_FORMAT_UINT32, adapter_ifnum,
                  SSH_FORMAT_UINT32_STR, adapter_name, adapter_name_len,
                  SSH_FORMAT_UINT32, adapter_state,
                  SSH_FORMAT_END);

  /* Free the context if it is dynamically allocated and no more callbacks
     are expected. */
  if (error != SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE && ctx->dynamic)
    ssh_free(ctx);
}


/* Engine to Interceptor */

void
ssh_engine_from_ipm_virtual_adapter_send(SshEngine engine,
                                         const unsigned char *data,
                                         size_t len)
{
  SshUInt32 ifnum_in, ifnum_out;
  SshUInt32 protocol;
  const unsigned char *packet, *internal;
  size_t packet_len, internal_len;
  SshInterceptorPacket pp;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt16 route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &ifnum_in,
                       SSH_FORMAT_UINT32, &ifnum_out,
                       SSH_FORMAT_UINT32, &protocol,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                       SSH_FORMAT_UINT16, &route_selector,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                       SSH_FORMAT_UINT16, NULL,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                       SSH_FORMAT_UINT32_STR_NOCOPY, &packet, &packet_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &internal, &internal_len,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Bad virtual adapter send request from PM"),
                        data, len);
      return;
    }

  /* Allocate an interceptor packet. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    SSH_PACKET_FROMADAPTER,
                                    protocol,
                                    ifnum_in,
                                    ifnum_out,
                                    packet_len);
  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("failed to allocate packet"));
      return;
    }

  if (!ssh_interceptor_packet_copyin(pp, 0, packet, packet_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("copyin failed, dropping packet"));
      return;
    }

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  pp->route_selector = route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
  if (!ssh_interceptor_packet_import_internal_data(pp, internal, internal_len))
    {
      SSH_DEBUG(SSH_D_ERROR, ("internal import failed, dropping packet"));
      return;
    }
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_send(engine->interceptor, pp);
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  ssh_interceptor_packet_free(pp);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}


void
ssh_engine_from_ipm_virtual_adapter_attach(SshEngine engine,
                                            const unsigned char *data,
                                            size_t len)
{
  SshUInt32 operation_id;
  SshUInt32 adapter_ifnum;
  SshEngineIpmVirtualAdapterOpCtx ctx;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &operation_id,
                       SSH_FORMAT_UINT32, &adapter_ifnum,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Bad virtual adapter attach request from PM"),
                        data, len);
      return;
    }

  /* Attach virtual adapter. */

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SshEngineIpmVirtualAdapterOpCtxStruct ctx_struct;

      ctx_struct.engine = engine;
      ctx_struct.operation_id = operation_id;
      ctx_struct.dynamic = FALSE;

      ssh_engine_ipm_virtual_adapter_status_cb(
                                       SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                                       (SshInterceptorIfnum) adapter_ifnum,
                                       NULL,
                                       SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                       NULL, &ctx_struct);
      return;
    }

  ctx->engine = engine;
  ctx->operation_id = operation_id;
  ctx->dynamic = TRUE;

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_attach(engine->interceptor,
                             (SshInterceptorIfnum) adapter_ifnum,
                             ssh_engine_ipm_virtual_adapter_packet_cb,
                             NULL_FNPTR,
                             engine,
                             ssh_engine_ipm_virtual_adapter_status_cb, ctx);
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  ssh_engine_ipm_virtual_adapter_status_cb(
                                         SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                                         (SshInterceptorIfnum) adapter_ifnum,
                                         NULL,
                                         SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                         NULL, ctx);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}


void
ssh_engine_from_ipm_virtual_adapter_detach(SshEngine engine,
                                           const unsigned char *data,
                                           size_t len)
{
  SshUInt32 operation_id;
  SshUInt32 adapter_ifnum;
  SshEngineIpmVirtualAdapterOpCtx ctx;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &operation_id,
                       SSH_FORMAT_UINT32, &adapter_ifnum,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Bad virtual adapter detach request from PM"),
                        data, len);
      return;
    }

  /* Detach virtual adapter. */

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SshEngineIpmVirtualAdapterOpCtxStruct ctx_struct;

      ctx_struct.engine = engine;
      ctx_struct.operation_id = operation_id;
      ctx_struct.dynamic = FALSE;

      ssh_engine_ipm_virtual_adapter_status_cb(
                                       SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                                       (SshInterceptorIfnum) adapter_ifnum,
                                       NULL,
                                       SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                       NULL, &ctx_struct);
      return;
    }

  ctx->engine = engine;
  ctx->operation_id = operation_id;
  ctx->dynamic = TRUE;

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_detach(engine->interceptor,
                             (SshInterceptorIfnum) adapter_ifnum,
                             ssh_engine_ipm_virtual_adapter_status_cb, ctx);
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  ssh_engine_ipm_virtual_adapter_status_cb(
                                         SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                                         (SshInterceptorIfnum) adapter_ifnum,
                                         NULL,
                                         SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                         NULL, ctx);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}


void
ssh_engine_from_ipm_virtual_adapter_detach_all(SshEngine engine,
                                               const unsigned char *data,
                                               size_t len)
{
#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  /* Detach all virtual adapters. */
  ssh_virtual_adapter_detach_all(engine->interceptor);
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}


void
ssh_engine_from_ipm_virtual_adapter_configure(SshEngine engine,
                                              const unsigned char *data,
                                              size_t len)
{
  SshUInt32 operation_id;
  SshUInt32 adapter_ifnum, adapter_state;
  SshUInt32 num_addresses = 0;
  SshIpAddrStruct addresses[16];
  SshVirtualAdapterParamsStruct p;
  const unsigned char *ip_ptr, *param_ptr;
  size_t ip_len, param_len;
  size_t decode_len;
  SshUInt32 i;
  SshEngineIpmVirtualAdapterOpCtxStruct ctx_struct;
  SshEngineIpmVirtualAdapterOpCtx ctx;
  SshVirtualAdapterError error = SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR;

  memset(&addresses, 0, (sizeof(SshIpAddrStruct) * 16));

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &operation_id,
                       SSH_FORMAT_UINT32, &adapter_ifnum,
                       SSH_FORMAT_UINT32, &adapter_state,
                       SSH_FORMAT_UINT32, &num_addresses,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &ip_ptr, &ip_len,
                       SSH_FORMAT_UINT32_STR_NOCOPY, &param_ptr, &param_len,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Bad virtual adapter configure request from PM"),
                        data, len);
      return;
    }

  /* Decode IP addresses. */
  if (ip_len)
    {
      for (i = 0; i < num_addresses && i < 16; i++)
        {
          decode_len = ssh_decode_ipaddr_array(ip_ptr, ip_len, &addresses[i]);
          if (decode_len == 0)
            {
              error = SSH_VIRTUAL_ADAPTER_ERROR_ADDRESS_FAILURE;
              goto error;
            }
          ip_ptr += decode_len;
          ip_len -= decode_len;
        }
    }
  /* A single undefined address "means clear all addresses". */
  if (num_addresses == 1 && !SSH_IP_DEFINED(&addresses[0]))
    num_addresses = 0;

  /* Decode params. */
  memset(&p, 0, sizeof(p));
  if (param_len)
    {
      if (!ssh_virtual_adapter_param_decode(&p, param_ptr, param_len))
        goto error;
    }

  /* Create context. */
  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      error = SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  ctx->engine = engine;
  ctx->operation_id = operation_id;
  ctx->dynamic = TRUE;

#if defined(INTERCEPTOR_HAS_VIRTUAL_ADAPTERS) && \
    defined(INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE)
  /* Configure virtual adapter. */
  ssh_virtual_adapter_configure(engine->interceptor,
                                (SshInterceptorIfnum) adapter_ifnum,
                                (SshVirtualAdapterState) adapter_state,
                                num_addresses, addresses,
                                (param_len > 0 ? &p : NULL),
                                ssh_engine_ipm_virtual_adapter_status_cb, ctx);
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS && ... */
  /* Interceptor does not implement kernel level virtual adapter configure. */
  ssh_engine_ipm_virtual_adapter_status_cb(
                                         SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                                         (SshInterceptorIfnum) adapter_ifnum,
                                         NULL,
                                         SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                         NULL, ctx);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS && ... */
  /* All done here.  The callback finishes everything. */
  return;

  /* Error handling. */
 error:
  ctx_struct.engine = engine;
  ctx_struct.operation_id = operation_id;
  ctx_struct.dynamic = FALSE;

  ssh_engine_ipm_virtual_adapter_status_cb(error,
                                           (SshInterceptorIfnum) adapter_ifnum,
                                           NULL,
                                           SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                           NULL, &ctx_struct);
}


void
ssh_engine_from_ipm_virtual_adapter_get_status(SshEngine engine,
                                               const unsigned char *data,
                                               size_t len)
{
  SshUInt32 operation_id;
  SshUInt32 adapter_ifnum;
  SshEngineIpmVirtualAdapterOpCtx ctx;

  if (ssh_decode_array(data, len,
                       SSH_FORMAT_UINT32, &operation_id,
                       SSH_FORMAT_UINT32, &adapter_ifnum,
                       SSH_FORMAT_END) != len)
    {
      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("Bad virtual adapter get status request from PM"),
                        data, len);
      return;
    }

  /* Get virtual adapter status. */

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SshEngineIpmVirtualAdapterOpCtxStruct ctx_struct;

      ctx_struct.engine = engine;
      ctx_struct.operation_id = operation_id;
      ctx_struct.dynamic = FALSE;

      ssh_engine_ipm_virtual_adapter_status_cb(
                                       SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                                       (SshInterceptorIfnum) adapter_ifnum,
                                       NULL,
                                       SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                       NULL, &ctx_struct);
      return;
    }

  ctx->engine = engine;
  ctx->operation_id = operation_id;
  ctx->dynamic = TRUE;

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  ssh_virtual_adapter_get_status(engine->interceptor,
                                 (SshInterceptorIfnum) adapter_ifnum,
                                 ssh_engine_ipm_virtual_adapter_status_cb,
                                 ctx);
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  ssh_engine_ipm_virtual_adapter_status_cb(
                                         SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT,
                                         (SshInterceptorIfnum) adapter_ifnum,
                                         NULL,
                                         SSH_VIRTUAL_ADAPTER_STATE_UNDEFINED,
                                         NULL, ctx);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}

#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


/***************************** Packet Multiplexing ***************************/

/* This function should be called by the machine-dependent main
   program whenever a packet for this engine is received from
   the policy manager.  The data should not contain the 32-bit length
   or the type (they have already been processed at this stage, to
   check for possible machine-specific packets).  The `data' argument
   remains valid until this function returns; it should not be freed
   by this function.  This function can be called concurrently. */

void ssh_engine_packet_from_ipm(SshEngine engine,
                                SshUInt32 type,
                                const unsigned char *data, size_t len)
{
  switch (type)
    {
    case SSH_ENGINE_IPM_FORWARDER_PACKET:
      ssh_engine_from_ipm_packet(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_INTERNAL_DATA_DISCARDED:
      ssh_engine_from_ipm_internal_data_discarded(engine, data, len);
      break;

#ifdef INTERCEPTOR_PROVIDES_IP_ROUTING
    case SSH_ENGINE_IPM_FORWARDER_ROUTEREQ:
      ssh_engine_from_ipm_route(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_ADD_ROUTE:
      ssh_engine_from_ipm_modify_route(engine, TRUE, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_REMOVE_ROUTE:
      ssh_engine_from_ipm_modify_route(engine, FALSE, data, len);
      break;
#endif /* INTERCEPTOR_PROVIDES_IP_ROUTING */

    case SSH_ENGINE_IPM_WATCHDOG_RESET:
      ssh_engine_from_ipm_watchdog_reset(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_SET_DEBUG:
      ssh_engine_from_ipm_set_debug(engine, data, len);
      break;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_SEND:
      ssh_engine_from_ipm_virtual_adapter_send(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_ATTACH:
      ssh_engine_from_ipm_virtual_adapter_attach(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH:
      ssh_engine_from_ipm_virtual_adapter_detach(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH_ALL:
      ssh_engine_from_ipm_virtual_adapter_detach_all(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_CONFIGURE:
      ssh_engine_from_ipm_virtual_adapter_configure(engine, data, len);
      break;

    case SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_GET_STATUS:
      ssh_engine_from_ipm_virtual_adapter_get_status(engine, data, len);
      break;
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


    default:
      ssh_warning("ssh_engine_packet_from_ipm: unexpected packet %u in "
                  "kernel; probably wrong policy manager",
                  (unsigned int) type);

      SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                        ("invalid packet from engine, type=%u",
                         (unsigned int) type),
                        data, len);
      break;
    }
}
