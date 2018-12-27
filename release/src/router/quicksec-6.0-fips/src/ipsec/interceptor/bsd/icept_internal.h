/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for the SSH packet interceptor.
*/

#ifndef ICEPT_INTERNAL_H
#define ICEPT_INTERNAL_H

#include "ipsec_params.h"

#include "interceptor.h"
#include "engine.h"







#ifdef time
#undef time
#endif

#ifdef VXWORKS

#define _KERNEL

#include <vxWorks.h>
#include <muxLib.h>

/* 5.4 or earlier */
#if !defined(_WRS_VXWORKS_MAJOR) && !defined(_WRS_VXWORKS_5_X)
#define VXWORKS_NETVER 54000

/* plain 5.5.1 */
#elif defined(_WRS_VXWORKS_5_X) && _WRS_VXWORKS_MAJOR < 6 && \
  !defined(STACK_VERSION_MAJOR)
#define VXWORKS_NETVER 55100

/* 5.5.1 & PNE 2.0 */
#elif defined(_WRS_VXWORKS_5_X) && _WRS_VXWORKS_MAJOR < 6 && \
  STACK_VERSION_MAJOR == 1 && STACK_VERSION_MINOR == 2
#define VXWORKS_NETVER 55120

/* 5.5.1 & PCD 1.1 (probably) */
#elif defined(_WRS_VXWORKS_5_X) && _WRS_VXWORKS_MAJOR < 6 && \
   STACK_VERSION_MAJOR == 1
#define VXWORKS_NETVER 55111

/* 5.5.1 & PNE 2.2 */
#elif defined(_WRS_VXWORKS_5_X) && _WRS_VXWORKS_MAJOR < 6 && \
   STACK_VERSION_MAJOR == 2
#define VXWORKS_NETVER 55122

/* 6.1 or greater */
#elif _WRS_VXWORKS_MAJOR > 6 || \
  (_WRS_VXWORKS_MAJOR == 6 && _WRS_VXWORKS_MINOR >= 1)
#define VXWORKS_NETVER 61000

/* something else */
#else
#error unsupported VxWorks/Platform version

#endif

#endif /* VXWORKS */

#ifndef VXWORKS
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#else /* VXWORKS */
#include <types/vxParams.h>
#include <net/systm.h>
#include <net/mbuf.h>
#include <net/protosw.h>
#include <sys/socket.h>
#include <errno.h>
#include <muxLib.h>
#if VXWORKS_NETVER < 55122
#include <netinet/if_ether.h>
#else /* VXWORKS_NETVER < 55122 */
#include <net/if_var.h>
#ifndef VIRTUAL_STACK
extern struct ifnethead ifnet_head;
#endif /* VIRTUAL_STACK */
struct rtentry *rtalloc1(struct sockaddr *, int, u_long);
void ipRouteFree(struct rtentry * pRoute, BOOL inTable);
#define rtfree(x) \
do {\
  int s = splnet();\
  RTFREE(x);\
  splx(s);\
} while (0)
#endif /* VXWORKS_NETVER < 55122 */
#if VXWORKS_NETVER == 55111
extern struct ifnethead ifnet;
struct rtentry *rtalloc1(struct sockaddr *, int, u_long);
void rtfree(struct rtentry *);
#endif /* VXWORKS_NETVER == 55111 */
#include "icept_mbuf_vxworks.h"
#endif /* VXWORKS */

#include <net/if.h>
#include <net/if_dl.h>
#ifndef VXWORKS
#include <net/netisr.h>
#endif /* VXWORKS */
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#ifdef DARWIN
#include <machine/spl.h>
#include <sys/systm.h>
#endif /* DARWIN */

#include "sshsimplehashtable.h"
#include "sshdlqueue.h"

/* Import some kernel data structures to help in mapping interfaces. */

extern int if_index;            /* from if.c */
#ifndef VXWORKS
extern struct ifaddr **ifnet_addrs; /* from if.c */
#else /* VXWORKS */
#if VXWORKS_NETVER >= 55120
#ifndef VIRTUAL_STACK
extern struct ifaddr **ifnet_addrs; /* from if.c */
#endif /* VIRTUAL_STACK */
#endif /* VXWORKS_NETVER >= 55120 */
struct ifnet * ifIndexToIfp(int ifIndex); /* from if.c */
#endif /* VXWORKS */

/* Maps an interface number to a struct ifnet pointer. */
#ifndef VXWORKS
#if SSH_NetBSD >= 150
#define ssh_interceptor_id_to_if(ic, interface)                     \
(ifnet_addrs[(interface) + 1] \
 ? ifnet_addrs[(interface) + 1]->ifa_ifp                        \
 : NULL)
#else /* SSH_NetBSD >= 150 */
#define ssh_interceptor_id_to_if(ic, interface)         \
(((interface) < if_index) && ifnet_addrs[(interface)]   \
 ? ifnet_addrs[(interface)]->ifa_ifp                    \
 : NULL)
#endif /* SSH_NetBSD >= 150 */
#else /* VXWORKS */
#ifdef VIRTUAL_STACK
#undef ifindex2ifnet
#define ssh_interceptor_id_to_if(ic,interface) \
  ((struct ifnet *)(((VS_IF *)vsTbl[(ic)->vsNum]->pIfGlobals)-> \
   ifindex2ifnet[(interface) + 1]))
#else
#define ssh_interceptor_id_to_if(ic,interface) ifIndexToIfp((interface) + 1)
#endif /* VIRTUAL_STACK */
#endif /* VXWORKS */

/* Maps a struct ifnet pointer to an interface number or if/stack pair. */
#ifdef VIRTUAL_STACK
#define ssh_interceptor_if_to_id(ic,ifp) ((ifp)->if_index - 1)
#else
#define ssh_interceptor_if_to_id(ic,ifp) ((ifp)->if_index - 1)
#endif /* VIRTUAL_STACK */

/* Is the IPv6 supported on this BSD platform? */
#if SSH_NetBSD >= 150 || SSH_FreeBSD >= 4 || \
  VXWORKS_NETVER >= 55122 || VXWORKS_NETVER == 55111
#define SSH_INTERCEPTOR_IPV6
#endif

/* The global interceptor object. */
#ifdef VIRTUAL_STACK
extern SshInterceptor ssh_interceptors[VSNUM_MAX];
#else /* VIRTUAL_STACK */
extern SshInterceptor ssh_interceptor;
#endif /* VIRTUAL_STACK */

/* The internal packet structure. */
typedef struct SshInterceptorInternalPacketRec
{
  /* Generic packet structure. */
  struct SshInterceptorPacketRec pp;

  /* Pointer to the interceptor to which this packet belongs.  Note that
     this field should not be accessed by higher-level code. */
  SshInterceptor interceptor;

  /* Machine-dependent buffer chain.  This should only be accessed
     using the ssh_interceptor_packet_* functions. */
  struct mbuf *head;

  /* Data for the iteration functions. */
  void *iter_next;
  size_t iter_offset;
  size_t iter_remaining;
} *SshInterceptorInternalPacket;


/* Data structure for the kernel-mode packet interceptor. */
struct SshInterceptorRec
{
  /* The machine context argument used to create this interceptor. */
  void *machine_context;

  /* Callback to be called whenever a packet is received. */
  SshInterceptorPacketCB packet_cb;

  /* Context for packet callback. */
  void *packet_cb_context;

  /* Callback to be called whenever the interface list changes. */
  SshInterceptorInterfacesCB interfaces_cb;

  /* Callback to be called whenever routing information changes.
     Implementing this callback is optional, but beneficial in
     e.g. router environments.  This is currently not implemented in
     the BSD interceptor. */
  SshInterceptorRouteChangeCB route_change_cb;

  /* Context argument to be passed to the callbacks. */
  void *context;

  /* Flag indicating whether ssh_interceptor_stop has been called. */
  Boolean stopped;

  /* Number of packets out (i.e., sent via packet_cb, and not yet returned
     to ssh_interceptor_send or ssh_interceptor_packet_free). */
  SshUInt32 num_packets_out;

  /* Number of packet, interface, or routing callbacks out there in
     user mode code. */
  SshUInt32 num_callbacks_out;

  /* List of pointers to packet header blocks associated with this
     interceptor.  This list contains the first packet header in each
     array of packet headers.  Freeing the headers on this list frees
     all packet headers associated with the interceptor. */
  SshInterceptorInternalPacket header_blocks;

  /* List of pointer to free packet headers of this interceptor.
     In beginning this list contains all headers except first. */
  SshInterceptorInternalPacket packet_freelist;

#ifdef VIRTUAL_STACK
  /* Virtual stack this interceptor is bound to. */
  int vsNum;
#endif /* VIRTUAL_STACK */
};

/* Function to set the appropriate spl level.  This depends on the type
   of the interceptor and the platform.  This returns a value that can be
   passed to splx. */
int ssh_interceptor_spl(void);

/* Functions to allocate and free internal packet headers. */
SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor ic,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out);
void ssh_interceptor_packet_free_header(SshInterceptorInternalPacket ipp);

/* Possible value for ssh_interceptor_receive()'s flags argument. */
#define SSH_ICEPT_F_FROM_PROTOCOL       0x001 /* from protocol */
#define SSH_ICEPT_F_FORWARDED           0x002 /* packet was forwarded */

/* Prototypes for functions called from media-specific files.  These
   will only be called at ssh_interceptor_spl. */
void ssh_interceptor_receive(SshInterceptorProtocol proto, unsigned int flags,
                             struct ifnet *ifp, void *mediahdr,
                             size_t mediahdr_len, struct mbuf *m);
void ssh_interceptor_notify_interface_change(void);

/* Prototypes for media-specific functions.  These can only be called at
   ssh_interceptor_spl. */
void ssh_interceptor_mbuf_send_to_network(SshInterceptorProtocol protocol,
                                          struct ifnet *ifp,
                                          void *mediahdr,
                                          size_t mediahdr_len,
                                          struct mbuf *m);
void ssh_interceptor_mbuf_send_to_protocol(SshInterceptorProtocol protocol,
                                           struct ifnet *ifp,
                                           void *mediahdr,
                                           size_t mediahdr_len,
                                           struct mbuf *m);

/* Returns the type of the interface, to be reported to higher-level code.
   This should be one of the values defined in interceptor.h.  This
   can return SSH_INTERCEPTOR_NONEXISTENT if the interface type is not
   supported. */
int ssh_interceptor_iftype(struct ifnet *ifp);

/* Indentification strings. */

/* Attachment type, defined in subst-*.c */
extern const char *ssh_ident_attach;

/* Kernel vs. user mode, defined in usermodeintc.c or kernelmodeintc.c. */
extern const char ssh_ident_mode[];

/* Name of the device used for communicating with user-mode processes.
   This is defined by the interceptor main module. */
extern const char *ssh_device_name;


/**********************************************************************/

/* This function is called when the kernel module has been loaded. This
   should initialize kernel code above the interceptor, if any. */
void ssh_upper_initialize(void);

/* This function is called when the kernel module is being unloaded. This
   should uninitialize kernel code above the interceptor, if any. */
void ssh_upper_uninitialize(void);

#endif /* ICEPT_INTERNAL_H */
