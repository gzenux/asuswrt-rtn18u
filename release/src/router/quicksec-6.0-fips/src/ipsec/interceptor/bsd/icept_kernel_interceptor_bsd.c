/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This code implements the packet interceptor for a kernel-mode IPSEC Engine.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#include "sshincludes.h"
#include "kernel_timeouts.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "icept_chardev.h"
#include "icept_internal.h"
#include "sshinetencode.h"

#define SSH_DEBUG_MODULE "SshInterceptor"

const char ssh_ident_mode[] = "kernel mode";

/* the packet freelist locking stubs if we have a singlethreaded
   implementation */
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_INIT()
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_UNINIT()
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK()
#define SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK()

#ifndef VXWORKS
#define SSH_MCLGET(m, wait, size) MCLGET((m),(wait))
#define SSH_MCLBYTES(m) MCLBYTES
#ifdef SSH_FreeBSD_46
#define SSH_MFREE(m,n) ((n) = m_free(m))
#else /* !SSH_FreeBSD_46 */
#define SSH_MFREE(m,n) MFREE(m,n)
#endif /* SSH_FreeBSD_46 */
#else /* VXWORKS */
/* Allocated cluster size may vary in VxWorks */
#include "icept_vxworks.h"
#include "kernel_mutex.h"
/* if we are not wrapping all packets to the VxWorks tNetTask, we have
   multithreaded access. Although this is global, lock this guards
   access to ic->packet_freelist. */
static SshKernelMutex ssh_interceptor_packet_freelist_lock = NULL;
#undef SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_INIT
#undef SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_UNINIT
#undef SSH_INTERCEPTOR_PACKET_FREELIST_LOCK
#undef SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_INIT() \
  ssh_interceptor_packet_freelist_lock = ssh_kernel_mutex_alloc()
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_UNINIT() \
  ssh_kernel_mutex_free(ssh_interceptor_packet_freelist_lock);
#define SSH_INTERCEPTOR_PACKET_FREELIST_LOCK() \
  ssh_kernel_mutex_lock(ssh_interceptor_packet_freelist_lock);
#define SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK() \
  ssh_kernel_mutex_unlock(ssh_interceptor_packet_freelist_lock);
#endif /* VXWORKS */

/* Pointer to the single interceptor object.  This version does not
   support more than one interceptor. */
#ifdef VIRTUAL_STACK
SshInterceptor ssh_interceptors[VSNUM_MAX];
#else /* VIRTUAL_STACK */
SshInterceptor ssh_interceptor = NULL;
#endif /* VIRTUAL_STACK */

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
#define SSH_INTERCEPTOR_PACKET_TABLE_SIZE SSH_ENGINE_MAX_PACKET_CONTEXTS
static struct SshInterceptorInternalPacketRec
ssh_interceptor_packet_table[SSH_INTERCEPTOR_PACKET_TABLE_SIZE];
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

/* Constructs the SshInterceptorInterface array and calls the interface
   callback. */

void ssh_interceptor_call_interfaces_cb(SshInterceptor ic)
{
  SshInterceptorInterface *ifs;
  SshUInt32 nifs, i, k, num_addrs;
  SshInterfaceAddressStruct *addrs, *addrs_new;
  struct ifnet *ifp;
  SshInterceptorMedia media;
  struct ifaddr *ifa;
  struct sockaddr *saddr = NULL;
  struct sockaddr_in ba;
#if defined(__FreeBSD__) || (defined(VXWORKS) && VXWORKS_NETVER >= 55122)
  struct sockaddr_dl *sdl;
#endif /* __FreeBSD__ || (VXWORKS && VXWORKS_NETVER >= 55122) */
#ifdef VXWORKS
  int s;
#endif /* VXWORKS */
#ifdef VIRTUAL_STACK
#define myStackNum (ic->vsNum)
#endif /* VIRTUAL_STACK */
  SSH_DEBUG(SSH_D_HIGHSTART, ("calling interfaces_cb"));

#ifdef VXWORKS
  s = splnet();
#endif

  /* Initialize the interfaces array. */
#if defined(VXWORKS) && VXWORKS_NETVER < 55122 && VXWORKS_NETVER != 55111
  for (nifs = 0, ifp = ifnet;
       ifp;
       ifp = ifp->if_next)
    nifs++;
#elif SSH_NetBSD > 199
  for (nifs = 0, ifp = TAILQ_FIRST(&ifnet);
       ifp;
       ifp = TAILQ_NEXT(ifp, if_list))
    nifs++;
#elif defined(VXWORKS) && VXWORKS_NETVER == 55111
  for (nifs = 0, ifp = TAILQ_FIRST(&ifnet);
       ifp;
       ifp = TAILQ_NEXT(ifp, if_link))
    nifs++;
#elif defined(VXWORKS)
    for (nifs = 0, ifp = TAILQ_FIRST(&ifnet_head);
	 ifp;
	 ifp = TAILQ_NEXT(ifp, if_link))
      nifs++;
#else
  nifs = if_index;
#endif

  ifs = ssh_calloc(nifs, sizeof(ifs[0]));
  if (ifs == NULL)
    {
#ifdef VXWORKS
      splx(s);
#endif
      printf("Could not allocate memory for interfaces array");
      return;
    }

  for (i = 0; i < nifs; i++)
    {
      /* Get interface pointer and type. */
      ifp = ssh_interceptor_id_to_if(ic, i);
      if (ifp == NULL ||
          !(ifp->if_flags & IFF_UP) ||
          (ifp->if_flags & IFF_LOOPBACK))
        media = SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
      else
        media = ssh_interceptor_iftype(ifp);

      /* If the interface is nonexistent, just set the media type. */
      ifs[i].ifnum = i;
      ifs[i].to_protocol.media = media;
      ifs[i].to_adapter.media = media;
      if (media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        continue;

#ifdef __FreeBSD__
#if defined(SSH_FreeBSD_22)
      /* Find the link-level address if any. */
      sdl = NULL;
      for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
          sdl = (struct sockaddr_dl *)ifa->ifa_addr;
          if (sdl->sdl_family != AF_DLI)
            {
              sdl = NULL;
              continue;
            }
          break;
        }
#elif SSH_FreeBSD == 3 || SSH_FreeBSD == 4 || SSH_Darwin == 10300
      /* Find the link-level address if any. */
      sdl = NULL;
      for (ifa = ifp->if_addrhead.tqh_first;
           ifa;
           ifa = ifa->ifa_link.tqe_next)
        {
          sdl = (struct sockaddr_dl *)ifa->ifa_addr;
          if (sdl->sdl_family !=
#if defined(SSH_FreeBSD_46)
              AF_LINK
#else /* !SSH_FreeBSD_46 */
              AF_DLI
#endif /* SSH_FreeBSD_46 */
              )
            {
              sdl = NULL;
              continue;
            }
          break;
        }
#else
#error Unknown FreeBSD release.
#endif
#endif /* __FreeBSD__ */

      /* Set remaining fields of the interface structure. */

      ifs[i].to_protocol.mtu_ipv4 = ifp->if_mtu;
#ifdef WITH_IPV6
      ifs[i].to_protocol.mtu_ipv6 = ifp->if_mtu;
#endif /* WITH_IPV6 */
      ifs[i].to_protocol.flags = SSH_INTERCEPTOR_MEDIA_INFO_NO_FRAGMENT;

      ifs[i].to_adapter.mtu_ipv4 = ifp->if_mtu;
#ifdef WITH_IPV6
      ifs[i].to_adapter.mtu_ipv6 = ifp->if_mtu;
#endif /* WITH_IPV6 */
      ifs[i].to_adapter.flags = 0;

#ifdef VXWORKS
      ifs[i].to_protocol.flags &= ~SSH_INTERCEPTOR_MEDIA_INFO_NO_FRAGMENT;
#endif /* VXWORKS */

#if defined(__FreeBSD__) || defined(DARWIN)
      ssh_snprintf(ifs[i].name, sizeof(ifs[i].name), "%s%d", ifp->if_name,
                   (int) ifp->if_unit);
#elif defined(VXWORKS)
      ssh_snprintf(ifs[i].name, sizeof(ifs[i].name), "%s%d", ifp->if_name,
                   (int) ifp->if_unit);
#else /* defined(__FreeBSD__) */
      strncpy(ifs[i].name, ifp->if_xname, sizeof(ifs[i].name));
#endif /* defined(__FreeBSD__) */

      /* Construct address list. */
      num_addrs = 0;
      addrs = NULL;
#if defined(__NetBSD__)
      for (ifa = ifp->if_addrlist.tqh_first; ifa != NULL;
           ifa = ifa->ifa_list.tqe_next)
#elif defined(__FreeBSD__) || defined(VXWORKS)
#if defined(SSH_FreeBSD_22) || (defined(VXWORKS) && VXWORKS_NETVER < 55122)
      for (ifa = ifp->if_addrlist; ifa != NULL;
           ifa = ifa->ifa_next)
#elif SSH_FreeBSD == 3 || SSH_FreeBSD == 4 || SSH_Darwin == 10300 || \
  defined(VXWORKS)
      for (ifa = ifp->if_addrhead.tqh_first;
           ifa;
           ifa = ifa->ifa_link.tqe_next)
#else
#error Unknown FreeBSD release.
#endif
#elif defined(DARWIN)
      for (ifa = ifp->if_addrhead.tqh_first;
           ifa;
           ifa = ifa->ifa_link.tqe_next)
#else
#error Check if address list type for your platform.
#endif
        {
#if defined(WITH_IPV6)
#if defined(VXWORKS) && VXWORKS_NETVER >= 55122
          /* Skip tentative or otherwise unusable IPv6 address. */
          if (ifa->ifa_addr->sa_family == AF_INET6)
            {
              struct in6_ifaddr *ifa6 = (void *)ifa;
              if ((ifa6->ia6_flags &
                   (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|IN6_IFF_DETACHED)))
                continue;
            }
#endif
#endif
          saddr = ifa->ifa_addr;

          /* Skip non-ip addresses for now. */
          if (saddr->sa_family != AF_INET
#if defined (WITH_IPV6)
#ifdef SSH_INTERCEPTOR_IPV6
              && saddr->sa_family != AF_INET6
#endif /* SSH_INTERCEPTOR_IPV6 */
#endif /* WITH_IPV6 */
              )
            continue;

          /* Expand our address array. */

          addrs_new = ssh_malloc((num_addrs + 1) * sizeof(addrs[0]));
          if (addrs_new == NULL)
            {
              printf("Could not allocate memory for addresses");
              continue;
            }
          /* Copy old addresses if any. */
          if (addrs)
            {
              memcpy(addrs_new, addrs, num_addrs * sizeof(addrs[0]));
              ssh_free(addrs);
            }
          addrs = addrs_new;

          if (saddr->sa_family == AF_INET)
            {
              addrs[num_addrs].protocol = SSH_PROTOCOL_IP4;
              SSH_IP4_DECODE(&addrs[num_addrs].addr.ip.ip,
                             &((struct sockaddr_in *)saddr)->sin_addr.s_addr);
              saddr = ifa->ifa_netmask;
              SSH_IP4_DECODE(&addrs[num_addrs].addr.ip.mask,
                             &((struct sockaddr_in *)saddr)->sin_addr.s_addr);
              saddr = ifa->ifa_broadaddr;
              if (!saddr)
                {
                  struct sockaddr_in *m, *a;

                  memcpy(&ba, ifa->ifa_addr, sizeof(ba));
                  saddr = (struct sockaddr *)&ba;
                  a = &ba;
                  m = (struct sockaddr_in *)ifa->ifa_netmask;
                  a->sin_addr.s_addr
                    = ((a->sin_addr.s_addr & m->sin_addr.s_addr) +
                       ~m->sin_addr.s_addr);
                }
              SSH_IP4_DECODE(&addrs[num_addrs].addr.ip.broadcast,
                             &((struct sockaddr_in *)saddr)->sin_addr.s_addr);
            }
#if defined (WITH_IPV6)
#ifdef SSH_INTERCEPTOR_IPV6
          if (saddr->sa_family == AF_INET6)
            {
              addrs[num_addrs].protocol = SSH_PROTOCOL_IP6;
              SSH_IP6_DECODE(&addrs[num_addrs].addr.ip.ip,
                             &(((struct sockaddr_in6 *)saddr)
                               ->sin6_addr.s6_addr));
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(VXWORKS)
              /* Clear embedded scope IDs from link-local
                 addresses. */
              if (SSH_IP6_IS_LINK_LOCAL(&addrs[num_addrs].addr.ip.ip))
                {
                  unsigned char data[SSH_MAX_IPADDR_ENCODED_LENGTH];
                  SshUInt32 scopeid;

                  SSH_IP6_ENCODE(&addrs[num_addrs].addr.ip.ip, data);
                  scopeid = (data[2] << 8) | data[3];
                  data[2] = 0;
                  data[3] = 0;
                  SSH_IP6_DECODE(&addrs[num_addrs].addr.ip.ip, data);
		  addrs[num_addrs].addr.ip.ip.scope_id.
                    scope_id_union.ui32 = scopeid;
                }
#endif /* __NetBSD__ or __FreeBSD__ or VXWORKS */
              saddr = ifa->ifa_netmask;
              SSH_IP6_DECODE(&addrs[num_addrs].addr.ip.mask,
                             &(((struct sockaddr_in6 *)saddr)
                               ->sin6_addr.s6_addr));
              saddr = ifa->ifa_broadaddr;
              if (saddr)
                SSH_IP6_DECODE(&addrs[num_addrs].addr.ip.broadcast,
                               &(((struct sockaddr_in6 *)saddr)
                                 ->sin6_addr.s6_addr));
              else
                SSH_IP6_DECODE(&addrs[num_addrs].addr.ip.broadcast,
                               "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
            }
#endif /* SSH_INTERCEPTOR_IPV6 */
#endif /* WITH_IPV6 */
          num_addrs++;
        }
      ifs[i].num_addrs = num_addrs;
      ifs[i].addrs = addrs;

      /* Get media address. */
#if defined(__NetBSD__)
      ifs[i].media_addr_len = ifp->if_sadl->sdl_alen;
      SSH_ASSERT(ifp->if_sadl->sdl_alen <= sizeof(ifs[i].media_addr));
      memcpy(ifs[i].media_addr, LLADDR(ifp->if_sadl), ifp->if_sadl->sdl_alen);
#elif defined(VXWORKS) && VXWORKS_NETVER < 55122
      if (media == SSH_INTERCEPTOR_MEDIA_ETHERNET)
	{
	  struct arpcom *ac = (struct arpcom *)ifp;
	  ifs[i].media_addr_len = 6;
	  memcpy(ifs[i].media_addr, ac->ac_enaddr, 6);
	}
      else
	{
          ifs[i].media_addr_len = 0;
          memset(ifs[i].media_addr, 0, sizeof (ifs[i].media_addr));
	}
#elif defined(__FreeBSD__) || defined(DARWIN) || defined(VXWORKS)
#ifdef VXWORKS
      sdl = (struct sockaddr_dl *)ifnet_addrs[ifp->if_index - 1]->ifa_addr;
#endif
      if (sdl)
        {
          ifs[i].media_addr_len = sdl->sdl_alen;
          SSH_ASSERT(sdl->sdl_alen <= sizeof(ifs[i].media_addr));
          memcpy(ifs[i].media_addr, LLADDR(sdl), sdl->sdl_alen);
        }
      else
        {
          ifs[i].media_addr_len = 0;
          memset(ifs[i].media_addr, 0, sizeof (ifs[i].media_addr));
        }
#else
#error Check how to get link-level address on this platform;
#endif
    }

#ifdef VXWORKS
  splx(s);
#endif /* VXWORKS */

#ifdef VXWORKS
  ssh_vxworks_attach_interfaces();
#endif

  /* Take out down and loopback interfaces. */
  k = 0;
  for (i = 0; i < nifs; i++)
    {
      if (ifs[i].to_protocol.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          ssh_free(ifs[i].addrs);
        }
      else
        {
          if (i != k)
            ifs[k] = ifs[i];

          k++;
        }
    }
  nifs = k;

  /* Call the interfaces callback. */
  if (!ic->stopped)
    {
      ic->num_callbacks_out++;
      (*ic->interfaces_cb)(nifs, ifs, ic->context);
      ic->num_callbacks_out--;
    }

  /* Free the interfaces structure. */
  for (i = 0; i < nifs; i++)
    ssh_free(ifs[i].addrs);

  ssh_free(ifs);
#ifdef VIRTUAL_STACK
#undef myStackNum
#endif /* VIRTUAL_STACK */
}

/* This is called by a timeout to schedule an interfaces callback after
   open. */

void ssh_interceptor_call_interfaces(void *context)
{
  SshInterceptor ic = (SshInterceptor)context;

  if (ic)
    ssh_interceptor_call_interfaces_cb(ic);
}

/* This function is called by the networking stack interface to notify
   that a change has occurred in the configuration of network interfaces. */

void ssh_interceptor_notify_interface_change(void)
{
#ifdef VIRTUAL_STACK
  int i;
  for (i = 0; i < VSNUM_MAX; i++)
    if (ssh_interceptors[i])
      ssh_interceptor_call_interfaces_cb(ssh_interceptors[i]);
#else /* VIRTUAL_STACK */
  if (ssh_interceptor)
    ssh_interceptor_call_interfaces_cb(ssh_interceptor);
#endif /* VIRTUAL_STACK */
}

/** Creates the packet interceptor. This must be called before using
    any other interceptor functions.

    The `machine_context' argument is intended to be meaningful only
    to machine-specific code.  It is passed through from the
    machine-specific main program.  One example of its possible uses
    is to identify a virtual router in systems that implement multiple
    virtual routers in a single software environment.  Most
    implementations will ignore this argument.

    This function returns TRUE if creation of the interceptor was
    successful.  The interceptor object is returned in the
    `interceptor_return' argument.  Most systems will only allow a
    single interceptor to be created; however, some systems may support
    multiple interceptors identified by the `machine_context'
    argument.  This returns FALSE if an error occurs (e.g., no
    interceptor kernel module is loaded on this system, or the
    interceptor is already open). */

Boolean ssh_interceptor_create(void *machine_context,
                               SshInterceptor *interceptor_return)
{
  SshInterceptor ic;
#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  int i;
  SshInterceptorInternalPacket ipp;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */
#ifdef VIRTUAL_STACK
  int vsNum;
#endif /* VIRTUAL_STACK */

  SSH_DEBUG(SSH_D_HIGHSTART, ("create called"));

#ifndef VXWORKS
  SSH_ASSERT(MHLEN >= 80 && MLEN >= 80);
#endif /* VXWORKS */

  /* Sanity check: the interceptor can only be opened once (this
     implementation does not support multiple interfaces). */
#ifdef VIRTUAL_STACK
  SSH_ASSERT(machine_context); /* Machine context must define virtual stack
				  to use. */
  vsNum = atoi(machine_context);
  SSH_DEBUG(SSH_D_MIDSTART, ("Attaching to virtual stack: %d\n", vsNum));
  if (ssh_interceptors[vsNum] != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("SSH Packet interceptor already open!\n"));
      return FALSE;
    }
#else /* VIRTUAL_STACK */
  if (ssh_interceptor != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("SSH Packet interceptor already open!\n"));
      return FALSE;
    }
#endif /* VIRTUAL_STACK */

  /* Allocate and initialize an interceptor object. */
  ic = ssh_calloc(1, sizeof(*ic));
  if (ic == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate context for the SSH "
                             "Packet interceptor"));
      return FALSE;
    }

  ic->machine_context = machine_context;
  ic->packet_cb = NULL_FNPTR;
  ic->interfaces_cb = NULL_FNPTR;
  ic->route_change_cb = NULL_FNPTR;
  ic->packet_cb_context = NULL;
  ic->context = NULL;
  ic->stopped = FALSE;
  ic->num_packets_out = 0;
  ic->num_callbacks_out = 0;
  ic->header_blocks = NULL;
  ic->packet_freelist = NULL;

  /* Make it the global interceptor object, and return it. */
#ifdef VIRTUAL_STACK
  ic->vsNum = vsNum;
  ssh_interceptors[ic->vsNum] = ic;
#else /* VIRTUAL_STACK */
  ssh_interceptor = ic;
#endif /* VIRTUAL_STACK */

  *interceptor_return = ic;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  memset(ssh_interceptor_packet_table, 0, sizeof ssh_interceptor_packet_table);
  for (i = 0; i < SSH_INTERCEPTOR_PACKET_TABLE_SIZE; i++)
    {
      ipp = &ssh_interceptor_packet_table[i];
      ipp->pp.next = (SshInterceptorPacket)ic->packet_freelist;
      ic->packet_freelist = ipp;
    }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  /* intialize the packet freelist lock if on a multithreaded platform */
  SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_INIT();

  return TRUE;
}

/** Sets the `packet_cb' callback that will be called whenever a packet
    is received from either a network adapter, a protocol stack or an
    underlying hardware packet processor. The callback is guaranteed
    be to called only after ssh_interceptor_open() has been called.

    This function should be used in configurations where the interceptor
    initialization is performed by the Engine but where the packets are
    processed by another module (such as an accelerated Fastpath).

    The `callback_context' argument is passed to the packet callback. */

Boolean ssh_interceptor_set_packet_cb(SshInterceptor interceptor,
                                      SshInterceptorPacketCB packet_cb,
                                      void *callback_context)
{
  SSH_ASSERT(interceptor != NULL);

  interceptor->packet_cb = packet_cb;
  interceptor->packet_cb_context = callback_context;

  return TRUE;
}

/** Opens the packet interceptor. This registers the callbacks
    that the interceptor will use to notify the higher levels of
    received packets or changes in the interface list.  The interface
    callback will be called once either during this call or soon after
    this has returned.

    The `packet_cb' callback will be called whenever a packet is
    received from either a network adapter or a protocol stack.  The
    first calls may arrive already before this function has returned.
    If this is non-NULL then this will override the packet callback
    set earlier using ssh_interceptor_set_packet_cb().

    The `interfaces_cb' callback will be called once soon after
    opening the interceptor (possibly before this call returns).  From
    then on, it will be called whenever there is a change in the
    interface list (e.g., the IP address of an interface is changed,
    or a PPP interface goes up or down).

    The `route_change_cb' callback should be called whenever there is
    a change in routing information.  Implementing this callback is
    optional but beneficial in e.g. router environments (the
    information is not easily available on all systems).

    The `callback_context' argument is passed to the callbacks.

    This function returns TRUE if opening the interceptor was successful.
    This returns FALSE if an error occurs (e.g., no interceptor kernel
    module is loaded on this system), in which case the caller must release
    the previously created interceptor by calling ssh_interceptor_close().

    It is a fatal error to call ssh_interceptor_open() for an already
    opened interceptor.

    Care must be taken regarding concurrency control in systems that have
    multithreaded IP stacks.  In particular:
     - packet_cb and interfaces_cb may get called before this function
       returns.
     - the interceptor cannot be closed while there are calls or packets
       out.  The ssh_interceptor_stop function must be used.
     In such systems, additional concurrency may be introduced by timeouts
     and actions from the policy manager connection. */

Boolean ssh_interceptor_open(SshInterceptor interceptor,
                             SshInterceptorPacketCB packet_cb,
                             SshInterceptorInterfacesCB interfaces_cb,
                             SshInterceptorRouteChangeCB route_change_cb,
                             void *callback_context)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("open called"));

  if (packet_cb != NULL_FNPTR)
    {
      interceptor->packet_cb = packet_cb;
      interceptor->packet_cb_context = callback_context;
    }
  SSH_ASSERT(interceptor->packet_cb != NULL_FNPTR);

  interceptor->interfaces_cb = interfaces_cb;
  interceptor->route_change_cb = route_change_cb;
  interceptor->context = callback_context;

  /* Schedule an interfaces callback. */
  ssh_kernel_timeout_register(0L, 1000L,
                              ssh_interceptor_call_interfaces,
                              (void *)interceptor);
  return TRUE;
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
   ignored).  */

Boolean ssh_interceptor_stop(SshInterceptor interceptor)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("stop called"));

  /* Stop sending callbacks. */
  interceptor->stopped = TRUE;
  interceptor->packet_cb = NULL;
  interceptor->interfaces_cb = NULL;

  /* Cancel any timeouts for the interceptor. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS,
                            (void *)interceptor);

  if (interceptor->num_callbacks_out != 0)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("interceptor->num_callbacks_out=%ld",
                 (long)interceptor->num_callbacks_out));
    }

  /* Return true if there are no more callbacks remaining. */
  return interceptor->num_callbacks_out == 0;
}

/* Closes the packet interceptor.  No more packet or interface callbacks
   will be received from the interceptor after this returns.  Destructors
   may still get called even after this has returned.

   It is illegal to call any packet interceptor functions (other than
   ssh_interceptor_open) after this call.  It is, however, legal to call
   destructors for any previously returned packets even after calling this.
   Destructors for any packets previously supplied to one of the send
   functions will get called before this function returns. */

void ssh_interceptor_close(SshInterceptor interceptor)
{
  SshInterceptorInternalPacket ipp;
  long packets_out;

  SSH_DEBUG(SSH_D_HIGHSTART, ("close called"));

  SSH_ASSERT(interceptor);
#ifdef VIRTUAL_STACK
  SSH_ASSERT(interceptor == ssh_interceptors[interceptor->vsNum]);
#else /* VIRTUAL_STACK */
  SSH_ASSERT(interceptor == ssh_interceptor);
#endif /* VIRTUAL_STACK */

  /* The interface requires that ssh_interceptor_stop must be called first. */
  SSH_ASSERT(interceptor->stopped);

  /* The interface requires that this function cannot be called until all
     packets out there have been fully processed and packets stored in
     data structures have been freed.  If this fails, it means that there
     are still packets out there. */
  if ((packets_out = interceptor->num_packets_out) != 0)
    ssh_warning("%d non-free packets, not able to free all memory\n",
                packets_out);

  /* Mark that the interceptor is not open. */
#ifdef VIRTUAL_STACK
  ssh_interceptors[interceptor->vsNum] = NULL;
#else /* VIRTUAL_STACK */
  ssh_interceptor = NULL;
#endif /* VIRTUAL_STACK */

  /* Free all packet headers associated with this interceptor. */
  if (packets_out == 0)
    while (interceptor->header_blocks)
      {
        ipp = interceptor->header_blocks;
        interceptor->header_blocks =
	  (SshInterceptorInternalPacket)ipp->pp.next;

        ssh_free(ipp);
      }
  interceptor->packet_freelist = NULL;

  /* unintialize the packet freelist lock */
  SSH_INTERCEPTOR_PACKET_FREELIST_LOCK_UNINIT();

  /* Free the interceptor object. */
  memset(interceptor, 'F', sizeof(*interceptor));
  ssh_free(interceptor);
}

/* Sends a packet to the network or to the protocol stacks.  This will
   eventually free the packet by calling ssh_interceptor_packet_free.
   The `media_header_len' argument specifies how many bytes from the
   start of the packet are media (link-level) headers.  It will be 0 if the
   interceptor operates directly at protocol level. */

SSH_FASTTEXT
void ssh_interceptor_send(SshInterceptor ic,
                          SshInterceptorPacket pp,
                          size_t mediahdr_len)
{
  unsigned char mediahdr_buf[64];
  struct mbuf *m;
  struct ifnet *ifp;
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("send called, pp 0x%p, mediahdr_len 0x%lx, len = 0x%0lx",
             pp, (unsigned long)mediahdr_len,
	     (ipp != NULL && ipp->head != NULL) ?
	     (unsigned long) ipp->head->m_pkthdr.len : -1));

  SSH_ASSERT(ic != NULL);
#ifdef VIRTUAL_STACK
  SSH_ASSERT(ic == ssh_interceptors[ic->vsNum]);
#else
  SSH_ASSERT(ic == ssh_interceptor);
#endif /* VIRTUAL_STACK */
  SSH_ASSERT((pp->flags & SSH_PACKET_FROMADAPTER) ||
             (pp->flags & SSH_PACKET_FROMPROTOCOL));
  SSH_ASSERT(ipp->head != NULL);

  /* Look up the interface pointer. */
  ifp = ssh_interceptor_id_to_if(ic, pp->ifnum_out);

  /* Sanity check: it should not be NULL. */
  if (SSH_PREDICT_FALSE(ifp == NULL))
    {
      ssh_warning("ssh_interceptor_send: bad if %d", (int)pp->ifnum_out);
      ssh_interceptor_packet_free(pp);
      return;
    }

#ifndef VXWORKS
  if (mediahdr_len > 0)
    {
      unsigned char *ucp;
      /* Copy the media header to a separate buffer. */
      SSH_ASSERT(mediahdr_len <= sizeof(mediahdr_buf));
      ucp = ssh_interceptor_packet_pullup(pp, mediahdr_len);
      if (ucp == NULL)
        return;

      memcpy(mediahdr_buf, ucp, mediahdr_len);
      if (!ssh_interceptor_packet_delete(pp, (size_t)0, mediahdr_len))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Packet delete failed, packet dropped"));
          return;
        }
    }
#endif /* VXWORKS */

  /* Get the mbuf chain. */
  m = ipp->head;
  ipp->head = NULL;
  m->m_pkthdr.rcvif = ifp;

  /* Send the packet out.  The mbuf will eventually get freed. */
  if (SSH_PREDICT_FALSE(pp->flags & SSH_PACKET_FROMADAPTER))
    ssh_interceptor_mbuf_send_to_protocol(pp->protocol, ifp, mediahdr_buf,
                                          mediahdr_len, m);
  else
    ssh_interceptor_mbuf_send_to_network(pp->protocol, ifp, mediahdr_buf,
                                         mediahdr_len, m);

  /* Free the original packet. */
  ssh_interceptor_packet_free_header(ipp);
}

/* Return API version implemented by the interceptor.
   Currently defined values are:
   0 - Original.
   1 - Implements SshInterceptorInterface.ifnum. */

SshUInt32 ssh_interceptor_get_api_version(void)
{
  return 1;
}

/* Copy the mbuf block, setting the first mbuf to *mp, and returning
   the last (assigned to m).  The next pointer of the last mbuf is set
   to point to the mbuf following the original.  The original mbuf
   block is freed.  This does not affect the remaining mbufs.
   However, if an error occurs, this returns NULL, and the caller
   should free m. */

struct mbuf *ssh_interceptor_mbuf_copyext(struct mbuf *m, struct mbuf **mp)
{
  struct mbuf *m2, *start;
  size_t len, mlen;
  const unsigned char *src;

  start = NULL;
  m2 = NULL;
  len = m->m_len;
  src = mtod(m, const unsigned char *);

  /* Loop copying to new mbufs until we have copied all data from the old
     mbuf. */
  do
    {
      if (!start && (m->m_flags & M_PKTHDR))
        {
          /* Allocate a new packet header node. */
          MGETHDR(m2, M_DONTWAIT, m->m_type);
          if (m2 == NULL)
            goto fail;
          mlen = MHLEN;
          M_COPY_PKTHDR(m2, m);
        }
      else
        {
          /* Allocate a new ordinary mbuf. */
          MGET(m2, M_DONTWAIT, m->m_type);
          if (m2 == NULL)
            goto fail;
          mlen = MLEN;
        }
      if (start == NULL)
        start = m2;

      /* If there is enough data left, allocate a cluster. */
      if (len >= MINCLSIZE)
        {
          SSH_MCLGET(m2, M_DONTWAIT, len);
          if (!(m2->m_flags & M_EXT))
            goto fail;
          mlen = SSH_MCLBYTES(m2);
        }

      /* Don't copy more data than fits in the new mbuf. */
      if (mlen > len)
        mlen = len;

      /* Set mbuf len. */
      m2->m_len = mlen;

      SSH_DEBUG(SSH_D_LOWOK,
                ("recv: mext copy %d to new buf m_flags=0x%x",
                 mlen, m2->m_flags));

      /* Copy data into the mbuf. */
      memcpy(mtod(m2, unsigned char *), src, mlen);

      /* Save pointer to the new mbuf, and arrange to store the next pointer
         in this mbuf. */
      *mp = m2;
      mp = &m2->m_next;

      /* Adjust pointers and length in case we must allocate more mbufs. */
      src += mlen;
      len -= mlen;
    }
  while (len > 0);


  /* Fix the next pointer and free the original mbuf. */
  *mp = m->m_next;
  m->m_next = NULL;
  m_freem(m);

  /* Return the pointer to the last mbuf in the copied mbuf chain. *mp
     has already been set. */
  return m2;

fail:
  SSH_DEBUG(SSH_D_ERROR, ("recv: mext copy failed %p", m2));
  /* Allocation failed.  m2 may be new node or NULL. */
  if (m2)
    m_freem(m2);

  /* Arrange for already allocated nodes plus the new one to be freed. */
  *mp = m;
  return NULL;
}

/* Get reference count of mbuf chain */
#ifdef VXWORKS
SSH_FASTTEXT
int ssh_interceptor_packet_ref_cnt(struct mbuf *m)
{
  int ref_cnt = 1;
  while (m)
    {
      if (SSH_PREDICT_FALSE(m->m_extRefCnt > ref_cnt))
        ref_cnt = m->m_extRefCnt;
      m = m->m_next;
    }
  return ref_cnt;
}
#endif /* VXWORKS */

/* Processes a packet received from a media-specific interface, and passes
   it on to the user-level application.
     protocol          header format (e.g., SSH_PROTOCOL_IP)
     flags             SSH_ICEPT_F_* flags
     ifp               pointer to network interface
     mediahdr          pointer to media header
     mediahdr_len      size of media header
     m                 mbuf chain containing the packet (without media hdr)
   This will pass the packet up to the interceptor or drop it.
   This will call m_freem(m) to free the packet, either during this call
   or some time later.  If this processes global queues, this must protect
   them using splimp. */

SSH_FASTTEXT
void ssh_interceptor_receive(SshInterceptorProtocol protocol,
                             unsigned int flags,
                             struct ifnet *ifp, void *mediahdr,
                             size_t mediahdr_len, struct mbuf *m)
{
  size_t payload_len;
  SshInterceptorInternalPacket ipp;
  SshInterceptor ic;

#ifdef INTERCEPTOR_HANDLES_LOOPBACK_PACKETS
  /* Let's take care of the loopback packets here. */
  if (SSH_PREDICT_FALSE(ifp->if_flags & IFF_LOOPBACK))
    {
      /* This packet came or was going to a loopback interface.  Let's
         pass it by here. */
      SSH_DEBUG(SSH_D_MIDSTART, ("passing by %s loopback packet",
                                 ((flags & SSH_ICEPT_F_FROM_PROTOCOL)
                                  ? "outbound" : "inbound")));

      if (flags & SSH_ICEPT_F_FROM_PROTOCOL)
        ssh_interceptor_mbuf_send_to_network(protocol, ifp, mediahdr,
                                             mediahdr_len, m);
      else
        ssh_interceptor_mbuf_send_to_protocol(protocol, ifp, mediahdr,
                                              mediahdr_len, m);
      return;
    }
#endif /* INTERCEPTOR_HANDLES_LOOPBACK_PACKETS */

#if defined(SSH_NetBSD) && SSH_NetBSD >= 150
  /* In NetBSD-1.5.0 and later, virtual interfaces have the interface
     index 0.  Let's pass these since they will be seen later when the
     virtual interface (like MDECAP) has handled the packet. */
  if (ifp->if_index == 0)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("passing by %s VIF packet",
                                 ((flags & SSH_ICEPT_F_FROM_PROTOCOL)
                                  ? "outbound" : "inbound")));
      if (flags & SSH_ICEPT_F_FROM_PROTOCOL)
        ssh_interceptor_mbuf_send_to_network(protocol, ifp, mediahdr,
                                             mediahdr_len, m);
      else
        ssh_interceptor_mbuf_send_to_protocol(protocol, ifp, mediahdr,
                                              mediahdr_len, m);
      return;
    }
#endif /* SSH_NetBSD >= 150 */

  SSH_DEBUG(SSH_D_MIDSTART,
            ("receive, m=0x%lx, mediahdr_len %d, flags=0x%lx",
             (long) m, (int) mediahdr_len, (unsigned long) flags));

#ifdef VXWORKS
  /* In VxWorks it is not necessary nor desirable (because of
     alignment) to copy packets coming from network. END network
     driver has already inserted incoming frame into mbuf and
     transfers ownership of the packet to a protocol. In out direction
     however, TCP generates mbuf clusters that have reference count
     greater >1 indicating that protocol is keeping reference to the
     data. Those packets have to be copied in order to avoid
     encrypting twice in case of retransmission. */
  if (SSH_PREDICT_TRUE(ssh_interceptor_packet_ref_cnt(m) == 1))
    {
#if VXWORKS_NETVER == 55111
      /* PCD 1.1, set m_extSize to correct value */
      if (flags & SSH_ICEPT_F_FROM_PROTOCOL)
        ssh_vx_set_ext_size(m);
#endif
      ;
    }
  else
#endif
    {
      struct mbuf *m2, **mp;

      /* Copy any M_EXT mbufs */
      for (mp = &m; *mp; mp = &m2->m_next)
        {
          m2 = *mp;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("m_flags = 0x%x len=%d", m2->m_flags, m2->m_len));

          if (!(m2->m_flags & M_EXT))
            continue;

          /* Copy the mbuf block, setting the first mbuf to *mp, and
            returning the last (assigned to m2).  The next pointer of the
            last mbuf is set to point to the mbuf following the original.
            The original mbuf block is freed.  This does not affect the
            remaining mbufs.  However, if an error occures, this returns
            NULL, and the whole packet should be freed. */
          m2 = ssh_interceptor_mbuf_copyext(m2, mp);
          if (m2 == NULL)
            {
              ssh_warning("ssh_interceptor_receive: "
			  "out of mbufs copying M_EXT.");
              /* Free the whole packet. */
              m_freem(m);
              return;
	    }
	}
    }
  /* Get the interceptor.  If the interceptor is not open, just pass the
     packet through (for robustness). */
#ifdef VIRTUAL_STACK
  ic = ssh_interceptors[ifp->vsNum];
#else /* VIRTUAL_STACK */
  ic = ssh_interceptor;
#endif /* VIRTUAL_STACK */

  if (SSH_PREDICT_FALSE(ic == NULL) || SSH_PREDICT_FALSE(ic->stopped))
    {
      if (SSH_PREDICT_TRUE(flags & SSH_ICEPT_F_FROM_PROTOCOL))
        ssh_interceptor_mbuf_send_to_network(protocol, ifp, mediahdr,
                                             mediahdr_len, m);
      else
        ssh_interceptor_mbuf_send_to_protocol(protocol, ifp, mediahdr,
                                              mediahdr_len, m);
      return;
    }

  /* Compute the total length of the resulting packet. */
  payload_len = m->m_pkthdr.len + mediahdr_len;

  /* Allocate a packet structure.  Note that this may fail in case of
     overload. */
  ipp = ssh_interceptor_packet_alloc_header(ic,
                                            ((flags
                                              & SSH_ICEPT_F_FROM_PROTOCOL)
                                             ? SSH_PACKET_FROMPROTOCOL
                                             : SSH_PACKET_FROMADAPTER),
                                            protocol,
                                            ssh_interceptor_if_to_id(ic, ifp),
					    SSH_INTERCEPTOR_INVALID_IFNUM);
  if (SSH_PREDICT_FALSE(ipp == NULL))
    {
      ssh_warning("ssh_interceptor_receive: could not allocate packet hdr");
      m_freem(m);
      return;
    }

#ifdef INTERCEPTOR_SETS_IP_FORWARDING
  /* Set the forwarding flag if our interceptor knows and reports it. */
  if (flags & SSH_ICEPT_F_FORWARDED)
    ipp->pp.flags |= SSH_PACKET_FORWARDED;
#endif /* INTERCEPTOR_SETS_IP_FORWARDING */

  /* Mark media broadcast packets. */
  if (SSH_PREDICT_FALSE(m->m_flags & M_BCAST)
#ifdef M_MCAST
      || SSH_PREDICT_FALSE(m->m_flags & M_MCAST)
#endif /* M_MCAST */
#ifdef M_ANYCAST6
      || SSH_PREDICT_FALSE(m->m_flags & M_ANYCAST6)
#endif /* M_ANYCAST6 */
      )
    ipp->pp.flags |= SSH_PACKET_MEDIABCAST;

#ifndef VXWORKS
  /* Prepend the media header to the packet. */
  if (mediahdr_len > 0)
    {
      M_PREPEND(m, mediahdr_len, M_DONTWAIT);
      if (m == NULL)
        {
          ssh_warning("ssh_interceptor_receive: M_PREPEND failed");
          ssh_interceptor_packet_free_header(ipp);
          return;
        }
      memcpy(mtod(m, unsigned char *), mediahdr, mediahdr_len);
    }
#endif /* VXWORKS */

  /* Attach the mbuf chain into the packet. */
  ipp->head = m;

  /* Call the packet callback.  This eventually will free `pp'. */
  if (SSH_PREDICT_TRUE(!ic->stopped))
    {
      ic->num_callbacks_out++;
      (*ic->packet_cb)((SshInterceptorPacket)ipp, ic->packet_cb_context);
      ic->num_callbacks_out--;
    }
  else
    ssh_interceptor_packet_free((SshInterceptorPacket)ipp);
}

#ifndef VXWORKS
/* Looks up routing information for the routing key specified
   by `key'.  Calls the callback function either during this call
   or some time later.  The purpose of the callback function is to allow
   this function to perform asynchronous operations, such as forwarding
   the routing request to a user-level process.  This function will not
   be very efficient on some systems, and calling this on a per-packet
   basis should be avoided if possible.

   Note: on some platforms, this function will probably be implemented
   by keeping a smallish cache of recently used routes in the kernel,
   and forwarding all other requests to a user-mode policy manager.
   The reason is that routing information isn't reasonably available
   in many operating systems.  To do so, this would send a packet to the
   policy manager, the policy manager's platform-dependent code would
   recognize the packet number and process it without passing to
   the generic code, and would send a reply back the same way.

   This ssh_interceptor_route implementation uses only the 'dst' field
   of the SshInterceptorRouteKey. It is a fatal error to call this
   function with a routing key that does not specify the destination
   address. */

void ssh_interceptor_route(SshInterceptor ic,
                           SshInterceptorRouteKey key,
                           SshInterceptorRouteCompletion completion,
                           void *context)
{
  SshIpAddrStruct next_hop_gw;
  SshUInt32 ifnum;
  size_t mtu;
  struct rtentry *rt;

  SSH_DEBUG(SSH_D_HIGHSTART, ("route called"));

  /* It is a fatal error to call ssh_interceptor_route with
     a routing key that does not specify the destination address. */
  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));

  /* Note that if this implementation was asynchronous, the number of
     callbacks should keep track of pending callbacks (i.e., it should
     be incremented in the ssh_interceptor_route function, and
     decremented after the completion function has returned. */
  ic->num_callbacks_out++;

  if (SSH_IP_IS4(&key->dst))
    {
      struct sockaddr_in dst;

      /* Convert address into the sockaddr_in format. */
      memset(&dst, 0, sizeof(dst));
      dst.sin_family = AF_INET;
      dst.sin_len = sizeof(dst);
      SSH_IP4_ENCODE(&key->dst, (unsigned char *)&dst.sin_addr);

      /* Look up a route to the destination. */
#if defined(__FreeBSD__)
      rt = rtalloc1((struct sockaddr *)&dst, 1, 0);
#else
      rt = rtalloc1((struct sockaddr *)&dst, 1);
#endif
      if (rt == NULL)
        {
          (*completion)(FALSE, NULL, 0, 0, context);
          ic->num_callbacks_out--;
          return;
        }

      /* Extract needed data from the route. */
      if ((rt->rt_flags & RTF_GATEWAY)
#ifdef __FreeBSD__
          && !IN_MULTICAST(ntohl(dst.sin_addr.s_addr))
#else /* __FreeBSD__ */
          && !IN_MULTICAST(dst.sin_addr.s_addr)
#endif /* __FreeBSD__ */
          )
        {
          SSH_IP4_DECODE(&next_hop_gw,
                         &((struct sockaddr_in *)rt->rt_gateway)->sin_addr);
        }
      else
        next_hop_gw = key->dst;
      ifnum = ssh_interceptor_if_to_id(ic, rt->rt_ifp);
      mtu = rt->rt_rmx.rmx_mtu;

      /* Free the route. */
      rt->rt_use++;
      rtfree(rt);
    }
#if defined (WITH_IPV6)
#ifdef SSH_INTERCEPTOR_IPV6
  else if (SSH_IP_IS6(&key->dst))
    {
      struct sockaddr_in6 dst;

      /* Convert address into the sockaddr_in format. */
      memset(&dst, 0, sizeof(dst));
      dst.sin6_family = AF_INET6;
      dst.sin6_len = sizeof(dst);
      SSH_IP6_ENCODE(&key->dst, (unsigned char *)&dst.sin6_addr.s6_addr);

      /* Look up a route to the destination. */
#if defined(__FreeBSD__)
      rt = rtalloc1((struct sockaddr *)&dst, 1, 0);
#else
      rt = rtalloc1((struct sockaddr *)&dst, 1);
#endif
      if (rt == NULL)
        {
          (*completion)(FALSE, NULL, 0, 0, context);
          ic->num_callbacks_out--;
          return;
        }

      /* Extract needed data from the route. */
      if ((rt->rt_flags & RTF_GATEWAY)
          && !IN6_IS_ADDR_MULTICAST(&dst.sin6_addr))
        {
          SSH_IP6_DECODE(&next_hop_gw,
                         &(((struct sockaddr_in6 *)rt->rt_gateway)
                           ->sin6_addr.s6_addr));

#if defined(__NetBSD__) || defined(__FreeBSD__)
          /* Clear embedded scope IDs from link-local
             addresses. */
          if (SSH_IP6_IS_LINK_LOCAL(&next_hop_gw))
            {
              unsigned char data[SSH_MAX_IPADDR_ENCODED_LENGTH];
              SshUInt32 scopeid;

              SSH_IP6_ENCODE(&next_hop_gw, data);
              scopeid = (data[2] << 8) | data[3];
              data[2] = 0;
              data[3] = 0;
              SSH_IP6_DECODE(&next_hop_gw, data);
              next_hop_gw.scope_id.scope_id_union.ui32 = scopeid;
            }
#endif /* __NetBSD__ || __FreeBSD__ */
        }
      else
        next_hop_gw = key->dst;
      ifnum = ssh_interceptor_if_to_id(ic, rt->rt_ifp);
      mtu = rt->rt_rmx.rmx_mtu;

      /* Free the route. */
      rt->rt_use++;
      rtfree(rt);
    }
#endif /* SSH_INTERCEPTOR_IPV6 */
#endif /* WITH_IPV6 */
  else
    {
      /* An unknown address type. */
      (*completion)(FALSE, NULL, 0, 0, context);
      ic->num_callbacks_out--;
      return;
    }

  /* Resolve the path MTU to use.  If the route entry did not contain
     MTU value, we will default to the MTU of the outgoing
     interface. */
  if (mtu == 0)
    {
      struct ifnet *ifp = ssh_interceptor_id_to_if(ic, ifnum);

      if (ifp)
        {
          mtu = ifp->if_mtu;
        }
      else
        {
          /* The interface seems to be down.  Let's use the minimum
             value we know.  This should go through without
             fragmentation. */
          if (SSH_IP_IS4(&key->dst))
            mtu = 68;
          else
            mtu = 1280;
        }
    }

  /* Call the completion function to return the values. */
  (*completion)(TRUE, &next_hop_gw, ifnum, mtu, context);
  ic->num_callbacks_out--;
}
#endif /* VXWORKS */

/**********************************************************************
 * Packet management
 **********************************************************************/

/* Allocates a packet header without attaching an mbuf chain.  Sets the
   flags, protocol, and ifnum fields of the packet, but otherwise it is
   not initialized.  This returns NULL if no more packets can be allocated. */

SSH_FASTTEXT SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor ic,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out)
{
  SshInterceptorInternalPacket ipp;
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  unsigned int num_to_allocate, i;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  SSH_INTERCEPTOR_PACKET_FREELIST_LOCK();

  /* Increment count of packets allocated from this interceptor. */
  ic->num_packets_out++;

  /* If we have packet headers on the free list, return one from there. */
  if (SSH_PREDICT_TRUE(ic->packet_freelist))
    {
      ipp = ic->packet_freelist;
      ic->packet_freelist =
        (SshInterceptorInternalPacket)ipp->pp.next;
      ipp->pp.flags = flags;
      ipp->pp.ifnum_in = ifnum_in;
      ipp->pp.ifnum_out = ifnum_out;
      ipp->pp.protocol = protocol;
      ipp->pp.pmtu = 0;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
      memset(ipp->pp.extension, 0, sizeof(ipp->pp.extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
      ipp->interceptor = ic;
      ipp->head = NULL;

      SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK();

      SSH_DEBUG(SSH_D_LOWOK, ("header from freelist 0x%lx", (long)ipp));
      return ipp;
    }

  SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK();

#ifdef SSH_IPSEC_PREALLOCATE_TABLES

  SSH_DEBUG(SSH_D_ERROR, ("Out of packet headers"));
  return NULL;

#else /* not SSH_IPSEC_PREALLOCATE_TABLES */

  /* Allocate some more packet header.  We try to keep the allocations
     multiples of page size to keep it efficient even in embedded kernels
     with slow or poor memory management. */
  num_to_allocate = 8150 / sizeof(*ipp);
  if (num_to_allocate < 2)
    num_to_allocate = 2;
  ipp = ssh_malloc(num_to_allocate * sizeof(*ipp));
  if (ipp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate more packet headers"));
      return NULL;
    }

  /* The first header on the array is put on the ic->header_blocks list
     so that we can easily free all headers. */
  ipp->pp.next = (SshInterceptorPacket)ic->header_blocks;
  ic->header_blocks = ipp;

  /* The second header will be returned below. */

  SSH_INTERCEPTOR_PACKET_FREELIST_LOCK();

  /* Put any additional headers on the freelist. */
  for (i = 2; i < num_to_allocate; i++)
    {
      ipp[i].pp.next = (SshInterceptorPacket)ic->packet_freelist;
      ic->packet_freelist = &ipp[i];
    }

  SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK();

  /* Initialize and return the second header in the array. */
  ipp = &ipp[1];
  ipp->pp.flags = flags;
  ipp->pp.ifnum_in = ifnum_in;
  ipp->pp.ifnum_out = ifnum_out;
  ipp->pp.protocol = protocol;
  ipp->pp.pmtu = 0;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memset(ipp->pp.extension, 0, sizeof(ipp->pp.extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  ipp->interceptor = ic;
  ipp->head = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("new header allocated 0x%lx", (long)ipp));
  return ipp;

#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */
}

/* Allocates a packet of at least the given size.  Packets can only be
   allocated using this function (either internally by the interceptor or
   by other code by calling this function).  Typically, this takes a
   packet header from a free list, stores a pointer to a
   platform-specific packet object, and returns the packet header.
   This should be re-entrant and support concurrent operations if the
   IPSEC engine is re-entrant on the target platform.  Other functions
   in this interface should be re-entrant for different packet
   objects, but only one operation will be in progress at any given
   time for a single packet object.  This returns NULL if no more packets
   can be allocated. */

SshInterceptorPacket ssh_interceptor_packet_alloc(SshInterceptor ic,
                                                 SshUInt32 flags,
                                                 SshInterceptorProtocol proto,
                                                 SshInterceptorIfnum ifnum_in,
                                                 SshInterceptorIfnum ifnum_out,
                                                 size_t total_len)
{
  SshInterceptorInternalPacket ipp;
  struct mbuf *m;
  size_t len;

  SSH_DEBUG(SSH_D_MIDSTART, ("packet_alloc total_len %ld", (long)total_len));

  SSH_ASSERT((flags & SSH_PACKET_FROMADAPTER) ||
             (flags & SSH_PACKET_FROMPROTOCOL));

  ipp = ssh_interceptor_packet_alloc_header(ic, flags, proto,
					    ifnum_in, ifnum_out);
  if (!ipp)
    {
      ssh_warning("ssh_interceptor_alloc: failed to get packet hdr");
      return NULL;
    }

  /* Attach an mbuf header. */
  MGETHDR(m, M_DONTWAIT, MT_DATA);
  if (m == NULL)
    {
      ssh_warning("ssh_interceptor_alloc: failed to get mbuf hdr");
      ssh_interceptor_packet_free_header(ipp);
      return NULL;
    }
  ipp->head = m;

  /* Allocate enough space for the mbuf chain. */
  m->m_pkthdr.len = total_len;
  m->m_pkthdr.rcvif = NULL; /* set in send based on ifnum */
  m->m_len = 0;
  len = MHLEN;

  while (total_len > 0)
    {
      if (total_len > len)
        {
          SSH_MCLGET(m, M_DONTWAIT, total_len);
          if ((m->m_flags & M_EXT) == 0)
            {
              ssh_warning("ssh_interceptor_alloc: failed to get mbuf cluster");
              m_freem(ipp->head);
              ipp->head = NULL;
              ssh_interceptor_packet_free_header(ipp);
              return NULL;
            }
          len = SSH_MCLBYTES(m);
        }
      if (len > total_len)
        len = total_len;
      m->m_len = len;
      total_len -= len;

      if (total_len > 0)
        {
          MGET(m->m_next, M_DONTWAIT, m->m_type);
          if (m->m_next == NULL)
            {
              ssh_warning("ssh_interceptor_alloc: failed to get mbuf");
              m_freem(ipp->head);
              ipp->head = NULL;
              ssh_interceptor_packet_free_header(ipp);
              return NULL;
            }
          m = m->m_next;
          len = MLEN;
        }
    }

  return (SshInterceptorPacket)ipp;
}

#ifdef INTERCEPTOR_HAS_PACKET_ALLOC_AND_COPY_EXT_DATA
SshInterceptorPacket ssh_interceptor_packet_alloc_and_copy_ext_data(
                                                SshInterceptor interceptor,
                                                SshInterceptorPacket pp,
                                                size_t total_len)
{
  SshInterceptorPacket new_pp;
  SshInterceptorInternalPacket ipp, inew_pp;

  /* Actually, only the `total_length' argument is interesting.
     Everything else will be reset when the public data is copied. */
  new_pp = ssh_interceptor_packet_alloc(interceptor,
                                        pp->flags
                                        & (SSH_PACKET_FROMPROTOCOL
                                           | SSH_PACKET_FROMADAPTER),
                                        pp->protocol,
                                        pp->ifnum_in,
                                        pp->ifnum_out,
                                        total_len);
  if (new_pp == NULL)
    return NULL;

  /* Copy all public data from the source packet. */
  memcpy(new_pp, pp, sizeof(*pp));

  /* Copy internal packet data. */

  ipp = (SshInterceptorInternalPacket)pp;
  inew_pp = (SshInterceptorInternalPacket)new_pp;

  /* Copy multicast and broadcast flags. */
  inew_pp->head->m_flags |= (ipp->head->m_flags & (M_BCAST | M_MCAST));

  return new_pp;
}
#endif /* INTERCEPTOR_HAS_PACKET_ALLOC_AND_COPY_EXT_DATA */

/* Frees the packet header.  It is assumed that the buffer list has already
   been freed. */

void ssh_interceptor_packet_free_header(SshInterceptorInternalPacket ipp)
{
  SshInterceptor ic;
  SSH_DEBUG(SSH_D_LOWSTART, ("free_header 0x%lx", (long)ipp));

  SSH_ASSERT(ipp->head == NULL);

  SSH_INTERCEPTOR_PACKET_FREELIST_LOCK();

  ic = ipp->interceptor;
  /* Decrement the count of packets out. */
  SSH_ASSERT(ic->num_packets_out > 0);
  ic->num_packets_out--;

#ifdef DEBUG_LIGHT
  memset(ipp, 0xff, sizeof(*ipp));
#endif /* DEBUG_LIGHT */

  /* Put the header on freelist. */
  ipp->pp.next = (SshInterceptorPacket)ic->packet_freelist;
  ic->packet_freelist = ipp;

  SSH_INTERCEPTOR_PACKET_FREELIST_UNLOCK();
}

/* Frees the packet.  All packets allocated by
   ssh_interceptor_packet_alloc must eventually be freed using this
   function by either calling this explicitly or by passing the packet
   to the interceptor send function.  Typically, this calls a suitable
   function to free/release the platform-specific packet object, and
   puts the packet header on a free list.  This function should be
   re-entrant, so if a free list is used, it should be protected by a
   lock in systems that implement concurrency in the IPSEC Engine (the
   lock should actually be in ssh_interceptor_packet_free_header). */

void ssh_interceptor_packet_free(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

  SSH_DEBUG(SSH_D_MIDSTART, ("packet_free 0x%lx", (long)pp));

  SSH_ASSERT((pp->flags & SSH_PACKET_FROMADAPTER) ||
             (pp->flags & SSH_PACKET_FROMPROTOCOL));

  /* Free the native packet. */
  m_freem(ipp->head);
  ipp->head = NULL;

  /* Put the header on freelist. */
  ssh_interceptor_packet_free_header(ipp);
}

/* Returns the total length of the packet in bytes.  Multiple threads may
   call this function concurrently, but not for the same packet. */

size_t ssh_interceptor_packet_len(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

  SSH_ASSERT(ipp->head != NULL);
  SSH_DEBUG(SSH_D_MIDSTART, ("packet 0x%lx, len = %ld", (long)pp,
			     (unsigned long) ipp->head->m_pkthdr.len));

  return ipp->head->m_pkthdr.len;
}

/* Makes sure the first `bytes' bytes of the packet are in a
   contiguous section of the buffer.  Returns a pointer to the first
   byte of the packet, or NULL if an error occurs.  It is a fatal
   error to call this for `bytes' greater than SSH_INTERCEPTOR_MAX_PULLUP_LEN
   or the length of the packet. */

SSH_FASTTEXT
unsigned char *ssh_interceptor_packet_pullup(SshInterceptorPacket pp,
                                             size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  struct mbuf *m;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("pullup 0x%lx bytes=%ld",
             (long)pp, (long)bytes));

  m = ipp->head;
  SSH_ASSERT(m != NULL);
  SSH_ASSERT(bytes <= m->m_pkthdr.len);
#ifndef VXWORKS
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);
#endif /* VXWORKS */

#ifdef VXWORKS
  /* This is needed because of the m_pullup VxWorks implementation */
  if (SSH_PREDICT_TRUE(bytes <= m->m_len))
    return mtod(m, unsigned char *);
#endif /* VXWORKS */

  m = m_pullup(m, bytes);
  ipp->head = m;
  if (SSH_PREDICT_FALSE(ipp->head == NULL))
    {
      ssh_warning("ssh_interceptor_packet_pullup: m_pullup failed");
      ssh_interceptor_packet_free_header(ipp);
      return NULL;
    }
  SSH_ASSERT(m->m_flags & M_PKTHDR);
  SSH_ASSERT(m->m_len >= bytes);
  return mtod(m, unsigned char *);
}

/* Inserts data at the given offset in the packet.  Returns a pointer
   to the first inserted byte, or NULL (and frees pp) if an error
   occurs.  The space for the data is guaranteed to be contiguous,
   starting at the returned address.  At most 80 bytes can be
   inserted at a time.  Implementation note: most of the time, the
   insertion will take place near the start of the packet, and only
   twenty or so bytes are typically inserted. */

SSH_FASTTEXT
unsigned char *ssh_interceptor_packet_insert(SshInterceptorPacket pp,
                                             size_t offset,
                                             size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  struct mbuf *m, *newm;
  size_t leading, trailing, mlen;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("insert pp 0x%lx, ofs %ld, bytes %ld",
             (long)pp, (long)offset, (long)bytes));

  SSH_ASSERT(bytes <= 80 && ipp->head != NULL);

  /* Get mbuf chain. */
  m = ipp->head;
  SSH_ASSERT(m->m_flags & M_PKTHDR);

  SSH_DEBUG(SSH_D_LOWOK,
            ("head=0x%x, total_len=%d, offset=%d, bytes=%d, m_flags=0x%lx",
             (int)m, (int)m->m_pkthdr.len, (int)offset, (int)bytes,
             (long)m->m_flags));

  /* Special case for prepending data. */
  if (offset == 0)
    {
      M_PREPEND(m, bytes, M_DONTWAIT);
      if (SSH_PREDICT_FALSE(m == NULL))
        {
          ssh_warning("ssh_interceptor_packet_insert: M_PREPEND failed");
          ipp->head = NULL;
          ssh_interceptor_packet_free_header(ipp);
          return NULL;
        }
      ipp->head = m;
      SSH_ASSERT(m->m_flags & M_PKTHDR);
      return mtod(m, unsigned char *);
    }

  /* Add to total length. */
  m->m_pkthdr.len += bytes;

  /* Find the mbuf starting from which we will insert. */
  while (m && offset > m->m_len)
    {
      offset -= m->m_len;
      m = m->m_next;
    }
  if (SSH_PREDICT_FALSE(m == NULL))
    ssh_fatal("ssh_interceptor_packet_insert: beyond packet end by %ld",
              (long)offset);

  /* Check if we should put it all in leading. */
  leading = M_LEADINGSPACE(m);
  if (leading >= bytes && offset <= 64)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("inserting in %d bytes of leading space, "
                 "bytes=%d, offset=%d, m_len=%d",
                 (int)leading, (int)bytes, (int)offset, (int)m->m_len));
      m->m_data -= bytes;
      m->m_len += bytes;
      memmove(m->m_data, m->m_data + bytes, offset);
      return mtod(m, unsigned char *) + offset;
    }

  /* Check if we should put it all in trailing. */
  trailing = M_TRAILINGSPACE(m);
  if (trailing >= bytes && m->m_len - offset <= 64)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("inserting in %d bytes of trailing space, "
                 "bytes=%d, offset=%d, m_len=%d",
                 (int)trailing, (int)bytes, (int)offset, (int)m->m_len));
      memmove(m->m_data + offset + bytes, m->m_data + offset,
              m->m_len - offset);
      m->m_len += bytes;
      return mtod(m, unsigned char *) + offset;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("insert: leading %ld, trailing %ld, offset %ld, "
             "bytes %ld, m_len %ld",
             (long)leading, (long)trailing, (long)offset,
             (long)bytes, (long)m->m_len));

  /* Allocate new mbufs after the current mbuf until all data beyond the
     insertion point has been moved away. */
  while (m->m_len > offset)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("insert: inserting new node to move out %zd bytes",
                 m->m_len - offset));

      /* Allocate a new mbuf node. */
      MGET(newm, M_DONTWAIT, MT_DATA);
      if (SSH_PREDICT_FALSE(newm == NULL))
        {
          ssh_warning("ssh_interceptor_packet_insert: mget failed");
          ssh_interceptor_packet_free(pp);
          return NULL;
        }
      mlen = MLEN;

      /*  Get a cluster (MCLGET) if there is lots of data.  (Should
         really be able to add a small block at the front when
         appropriate.) */
#ifdef VXWORKS
      SSH_MCLGET(newm, M_DONTWAIT, m->m_len - offset);
      if (SSH_PREDICT_FALSE((newm->m_flags & M_EXT) == 0))
        {
          ssh_warning("ssh_interceptor_packet_insert: mclget failed");
          m_freem(newm);
          ssh_interceptor_packet_free(pp);
          return NULL;
        }
      mlen = SSH_MCLBYTES(newm);
#endif /* VXWORKS */

      /* Link it after the current node in the mbuf chain. */
      newm->m_next = m->m_next;
      m->m_next = newm;

      /* Copy as much data in the new mbuf as possible, but no more than
         we have after the insertion point. */
      newm->m_len = m->m_len - offset;
      if (newm->m_len > mlen)
        newm->m_len = mlen;
      memcpy(mtod(newm, unsigned char *), m->m_data + m->m_len - newm->m_len,
             newm->m_len);
      m->m_len -= newm->m_len;
      trailing += newm->m_len;
      SSH_ASSERT(trailing == M_TRAILINGSPACE(m));
    }
  SSH_ASSERT(m->m_len == offset);

  /* If there isn't enough space in the current node, allocate a new node
     and move to it. */
  if (trailing < bytes)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("inserting one more mbuf"));
      /* Allocate a new mbuf node. */
      MGET(newm, M_DONTWAIT, MT_DATA);
      if (newm == NULL)
        {
          ssh_warning("ssh_interceptor_packet_insert: mget failed");
          ssh_interceptor_packet_free(pp);
          return NULL;
        }
      mlen = MLEN;
#ifdef VXWORKS
      SSH_MCLGET(newm, M_DONTWAIT, 128);
      if ((newm->m_flags & M_EXT) == 0)
        {
          ssh_warning("ssh_interceptor_packet_insert: mclget failed");
          m_freem(newm);
          ssh_interceptor_packet_free(pp);
          return NULL;
        }
      mlen = SSH_MCLBYTES(newm);
#endif /* VXWORKS */

      /* Link it after the current node in the mbuf chain. */
      newm->m_next = m->m_next;
      m->m_next = newm;
      newm->m_len = 0;

      /* Move to the new node. */
      m = newm;
      trailing = mlen;
      SSH_ASSERT(trailing == M_TRAILINGSPACE(m));
      offset = 0;
    }

  /* There should now be enough space in the current node. */
  SSH_ASSERT(trailing == M_TRAILINGSPACE(m));
  SSH_ASSERT(trailing >= bytes);

  /* Mark the new space used. */
  m->m_len += bytes;

  /* Return pointer to the allocated space. */
  return mtod(m, unsigned char *) + offset;
}

/* Deletes data from the given offset in the packet.  It is a fatal error
   to delete more bytes than there are counting from that offset. */

SSH_FASTTEXT
Boolean ssh_interceptor_packet_delete(SshInterceptorPacket pp, size_t offset,
                                      size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  struct mbuf *m, *m0;
  size_t len;
  Boolean do_pullup;

  SSH_DEBUG(SSH_D_MIDSTART, ("delete pp 0x%lx, ofs %ld, bytes %ld",
                             (long)pp, (long)offset, (long)bytes));

  /* If deleting from the beginning of the packet, do a pullup after
     the delete operation so the IP header is in the packet header. */
  if (offset < SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    do_pullup = TRUE;
  else
    do_pullup = FALSE;

  m = ipp->head;
  SSH_ASSERT(m != NULL);
  SSH_ASSERT(m->m_flags & M_PKTHDR);

  /* Substract from total length. */
  m->m_pkthdr.len -= bytes;

  /* Find the mbuf starting from which we will delete. */
  while (m && offset > m->m_len)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("skip mbuf len %ld", (long)m->m_len));
      offset -= m->m_len;
      m = m->m_next;
    }
  if (SSH_PREDICT_FALSE(m == NULL))
    ssh_fatal("ssh_interceptor_packet_delete: beyond packet end by %ld",
              (long)offset);

  /* Delete the desired amount of data. */
  for (m0 = m; bytes > 0; bytes -= len)
    {
      if (offset == m->m_len)
        {
          SSH_ASSERT(m == m0);
          m = m->m_next;
          offset = 0;
        }
      len = m->m_len - offset;
      if (len > bytes)
        len = bytes;
      if (len == m->m_len && m != m0)
        {
          /* Free the whole mbuf node.  Note that the first node (containing
             header) is never freed. */
          SSH_DEBUG(SSH_D_LOWOK, ("freenode %p", m));
          SSH_MFREE(m, m0->m_next);
          m = m0->m_next;
          offset = 0;
        }
      else
        if (offset < m->m_len - offset - len)
          {
            /* Offset is smaller; move beginning forward. */
            SSH_DEBUG(SSH_D_LOWOK,
                      ("forward %p %zd bytes", m, offset));
            memmove(m->m_data + len, m->m_data, offset);
            m->m_data += len;
            m->m_len -= len;
            offset = m->m_len;
          }
        else
          {
            /* Offset is larger; move end towards the start. */
            SSH_DEBUG(SSH_D_LOWOK, ("backward %p %zd bytes",
                                    m, m->m_len - offset - len));
            memmove(m->m_data + offset, m->m_data + offset + len,
                    m->m_len - offset - len);
            m->m_len -= len;
            offset = m->m_len;
          }
    }
  if (SSH_PREDICT_FALSE(bytes != 0))
    SSH_DEBUG(SSH_D_ERROR,
              ("more than requested amount deleted, bytes=%d",
               (int)bytes));

  if (do_pullup)
    {
      size_t pullup_len = ipp->head->m_pkthdr.len;

      if (pullup_len > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
        pullup_len = SSH_INTERCEPTOR_MAX_PULLUP_LEN;

      if (ssh_interceptor_packet_pullup(pp, pullup_len) == NULL)
        return FALSE;
    }

  return TRUE;
}

/* These functions iterate over contiguous segments of the packet,
   starting from offset `offset', continuing for a total of
   `total_bytes' bytes.  It is guaranteed that `*len_return' will
   not be set to a value that would exceed `len' minus sum of previous
   lengths.  Also, previous pointers are guaranteed to stay valid if
   no other ssh_interceptor_packet_* functions are used during
   iteration for the same packet.  At each iteration, these functions
   return a pointer to the first byte of the contiguous segment inside
   the `*data_ret', and set `*len_return' to the number of bytes available at
   that address.

   The ssh_interceptor_packet_reset_iteration function will just reset the
   internal pointers to new offset and number of bytes without changing
   anything else. After that you need to call the
   ssh_interceptor_packet_next_iteration function to get the first block.
   After each call to ssh_interceptor_packet_next_iteration, one needs to
   call ssh_interceptor_packet_done_iteration.

   The loop ends when the iteration function returns FALSE, and then after the
   loop you need to check the value of the `*data_ret'. If it is NULL then the
   whole packet was processed and the operation was ended because there was no
   more data available. If it is not NULL then the there was an error and the
   underlaying packet buffer has already been freed and all the pointers
   pointing to that memory area (returned by previous calls to this function)
   are invalidated.

   These functions are used as follows:

     ssh_interceptor_packet_reset_iteration(pp, offset, total_bytes);
     while (ssh_interceptor_packet_next_iteration(pp, &ptr, &len))
       {
         code that uses ptr and len;
	 ssh_interceptor_packet_done_iteration(pp, &ptr, &len);
       }
     if (ptr != NULL)
       {
         code that will clean up the state and return. Note that the pp has
         already been freed at this point.
         return ENOBUF;
       }

   Only one operation can be in progress on a single packet concurrently,
   but multiple iterations may be executed simultaneously for different
   packet buffers.  Thus, the implementation must keep any state in the
   packet object, not in global variables.

   Multiple threads may call these functions concurrently,
   but not for the same packet.

   There is two different versions of next_iteration function, one to get data
   that you can modify (ssh_interceptor_packet_next_iteration) and one to get
   read only version of the data (ssh_interceptor_packet_next_iteration_read).
   The read only version should be used in all cases where the packet is not
   modifed, so interceptor can optimize extra copying of the packets away.
   */
void ssh_interceptor_packet_reset_iteration(SshInterceptorPacket pp,
                                            size_t offset,
                                            size_t total_len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  struct mbuf *m;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("start_iteration pp 0x%lx, ofs %ld, total_len %ld",
             (long)pp, (long)offset, (long)total_len));

  SSH_ASSERT(ipp->head != NULL);
  SSH_ASSERT(offset <= ipp->head->m_pkthdr.len);

  for (m = ipp->head;
       m && offset >= m->m_len;
       offset -= m->m_len, m = m->m_next)
    ;

  ipp->iter_next = m;
  ipp->iter_offset = offset;
  ipp->iter_remaining = total_len;
  return;
}

Boolean ssh_interceptor_packet_next_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  struct mbuf *m;

  SSH_DEBUG(SSH_D_MIDSTART, ("next_iteration 0x%lx", (long)pp));

  SSH_ASSERT(ipp->head != NULL);

  /* Check if we are at the end of iteration. */
  m = ipp->iter_next;
  if (m == 0 || ipp->iter_remaining == 0)
    {
      (*data_ret) = NULL;
      return FALSE;
    }

  /* Get return value. */
  (*data_ret) = mtod(m, unsigned char *) + ipp->iter_offset;
  if (ipp->iter_remaining < m->m_len - ipp->iter_offset)
    *len_return = ipp->iter_remaining;
  else
    *len_return = m->m_len - ipp->iter_offset;

  /* Adjust for next call. */
  ipp->iter_next = m->m_next;
  ipp->iter_offset = 0;
  ipp->iter_remaining -= *len_return;

  return TRUE;
}

Boolean ssh_interceptor_packet_done_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  return TRUE;
}

/*********************** Manipulating routing tables ************************/

#ifndef VXWORKS
static Boolean
do_route(int request, SshIpAddr ip, SshIpAddr netmask, SshIpAddr gateway,
         int flags)
{
  int error;
  unsigned char *dstcp, *maskcp;
  size_t i;

  if (SSH_IP_IS4(ip) && SSH_IP_IS4(netmask) && SSH_IP_IS4(gateway))
    {
      struct sockaddr_in dst;
      struct sockaddr_in gw;
      struct sockaddr_in mask;

      memset(&dst, 0, sizeof(dst));
      dst.sin_len = sizeof(dst);
      dst.sin_family = AF_INET;
      SSH_IP4_ENCODE(ip, &dst.sin_addr.s_addr);

      memset(&gw, 0, sizeof(gw));
      gw.sin_len = sizeof(gw);
      gw.sin_family = AF_INET;
      SSH_IP4_ENCODE(gateway, &gw.sin_addr.s_addr);

      memset(&mask, 0, sizeof(mask));
      mask.sin_len = sizeof(mask);
      mask.sin_family = AF_INET;
      SSH_IP4_ENCODE(netmask, &mask.sin_addr.s_addr);

      /* Mask destination IP address with the netmask. */

      dstcp = (unsigned char *) &dst.sin_addr.s_addr;
      maskcp = (unsigned char *) &mask.sin_addr.s_addr;

      for (i = 0; i < 4; i++)
        dstcp[i] &= maskcp[i];

      /* Do the request. */
      error = rtrequest(request,
                        (struct sockaddr *) &dst,
                        (struct sockaddr *) &gw,
                        (struct sockaddr *) &mask,
                        flags,
                        (struct rtentry **) 0);
    }
#if defined (WITH_IPV6)
#ifdef SSH_INTERCEPTOR_IPV6
  else if (SSH_IP_IS6(ip) && SSH_IP_IS6(netmask) && SSH_IP_IS6(gateway))
    {
      struct sockaddr_in6 dst;
      struct sockaddr_in6 gw;
      struct sockaddr_in6 mask;

      memset(&dst, 0, sizeof(dst));
      dst.sin6_len = sizeof(dst);
      dst.sin6_family = AF_INET6;
      SSH_IP6_ENCODE(ip, &dst.sin6_addr.s6_addr);

      memset(&gw, 0, sizeof(gw));
      gw.sin6_len = sizeof(gw);
      gw.sin6_family = AF_INET6;
      SSH_IP6_ENCODE(gateway, &gw.sin6_addr.s6_addr);

      memset(&mask, 0, sizeof(mask));
      mask.sin6_len = sizeof(mask);
      mask.sin6_family = AF_INET6;
      SSH_IP6_ENCODE(netmask, &mask.sin6_addr.s6_addr);

      /* Mask destination IP address with the netmask. */

      dstcp = (unsigned char *) &dst.sin6_addr.s6_addr;
      maskcp = (unsigned char *) &mask.sin6_addr.s6_addr;

      for (i = 0; i < 16; i++)
        dstcp[i] &= maskcp[i];

      /* Do the request. */
      error = rtrequest(request,
                        (struct sockaddr *) &dst,
                        (struct sockaddr *) &gw,
                        (struct sockaddr *) &mask,
                        flags,
                        (struct rtentry **) 0);
    }
#endif /* SSH_INTERCEPTOR_IPV6 */
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Destination, gateway, and netmask must be of the same "
                 "IP address type (IPv4 or IPv6)"));
      return FALSE;
    }

  if (error)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not %s route to %@/%@ through gateway %@: %d",
                 request == RTM_ADD ? "add" : "remove",
                 ssh_ipaddr_render, ip,
                 ssh_ipmask_render, netmask,
                 ssh_ipaddr_render, gateway,
                 error));
      return FALSE;
    }

  return TRUE;
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
  int rt_flags = RTF_STATIC;
  Boolean success;
  SshIpAddrStruct netmask, tmp;
  SshInterceptorRouteError error = SSH_INTERCEPTOR_ROUTE_ERROR_OK;

  /* Mark route as a gateway route if it is not an interface route. */
  if (ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    rt_flags |= RTF_GATEWAY;

  /* Gateway must be specified in either case. */
  if (gateway == NULL || !SSH_IP_DEFINED(gateway))
    {
      error = SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED;
      goto out;
    }

  /* Format netmask. */
  ssh_ipaddr_set_bits(&tmp, &key->dst, 0, 1);
  ssh_ipaddr_set_bits(&netmask, &tmp, SSH_IP_MASK_LEN(&key->dst), 0);

  success = do_route(RTM_ADD, &key->dst, &netmask, gateway, rt_flags);
  if (!success)
    error = SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED;

 out:
  if (success_cb)
    (*success_cb)(error, success_cb_context);
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
  int rt_flags = RTF_STATIC;
  Boolean success;
  SshIpAddrStruct netmask, tmp;
  SshInterceptorRouteError error = SSH_INTERCEPTOR_ROUTE_ERROR_OK;

  /* Mark route as a gateway route if it is not an interface route. */
  if (ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
    rt_flags |= RTF_GATEWAY;

  /* Gateway must be specified in either case. */
  if (gateway == NULL || !SSH_IP_DEFINED(gateway))
    {
      error = SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED;
      goto out;
    }

  /* Format netmask. */
  ssh_ipaddr_set_bits(&tmp, &key->dst, 0, 1);
  ssh_ipaddr_set_bits(&netmask, &tmp, SSH_IP_MASK_LEN(&key->dst), 0);

  success = do_route(RTM_DELETE, &key->dst, &netmask, gateway, rt_flags);

  if (!success)
    {
      if (flags & SSH_INTERCEPTOR_ROUTE_FLAG_IGNORE_NONEXISTENT)
	error = SSH_INTERCEPTOR_ROUTE_ERROR_OK;
      else
	error = SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED;
    }

 out:
  if (success_cb)
    (*success_cb)(error, success_cb_context);
}
#endif /* VXWORKS */
