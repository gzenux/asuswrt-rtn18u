/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file is an (internal) header file for the usermode
   interceptor interface implemented in usermodeinterceptor.c.
*/

#ifndef USERMODEINTERCEPTOR_H
#define USERMODEINTERCEPTOR_H 1

#include "interceptor.h"
#include "engine.h"
#include "kernel_mutex.h"
#include "kernel_timeouts.h"
#include "sshencode.h"
#include "usermodeforwarder.h"
#include "sshtimeouts.h"
#include "sshpacketstream.h"
#include "sshdevicestream.h"
#include "sshlocalstream.h"
#include "ssheloop.h"
#include "sshgetopt.h"
#include "sshinetencode.h"
#include "sshmutex.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#endif /* INTERCEPTOR_PROVIDES_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


/** Flags for the usermode interceptor.  These can be used to cause it
    to generate fake errors at random. */
extern SshUInt32 ssh_usermode_interceptor_flags;


/** Data structure for the user-mode interceptor.  This implements a
    fake interceptor for the Engine.  The real interceptor is in the
    kernel, and this communicates with it. */
typedef struct SshInterceptorPacketMgrRec
{
  /** Number of allocated packets.  This is used for sanity
      checks. Protected by icept mutex. */
  SshUInt32 num_packets;


  /** Head to (doubly) linked list of allocated packets. If any packet
      is not released by the engine, it will end up here which can then
      be inspected with the debugger.

      Do *not* free this list in ssh_interceptor_close, as that would
      hide the real memory leak from any memory debuggers (purify,
      efence et al). Protected by icept mutex. */
  void *packet_head;
} SshInterceptorPacketMgrStruct, *SshInterceptorPacketMgr;

/* Bit masks for ssh_usermode_interceptor_flags. */
#define SSH_USERMODE_FAIL_ALLOC       0x01 /** Alloc should fail at random. */
#define SSH_USERMODE_FAIL_PACKET_OP   0x02 /** Packet manipulation functions
                                               should fail at random. */
#define SSH_USERMODE_SHUFFLE_PULLUP   0x04 /** Shuffle at every pullup. */
#define SSH_USERMODE_MANY_NODES       0x08 /** Data is spread over
                                               multiple nodes. */

#ifndef SSH_USERMODE_DEFAULT_FLAGS
#ifdef WITH_PURIFY
/** Use single node to make getting data out of leaks easier. Don't
    shuffle at pullups neither, since that erases the original
    allocation point information. */
#define SSH_USERMODE_DEFAULT_FLAGS 0
#else /* WITH_PURIFY */
#define SSH_USERMODE_DEFAULT_FLAGS (SSH_USERMODE_SHUFFLE_PULLUP |       \
                                    SSH_USERMODE_MANY_NODES)
#endif /* WITH_PURIFY */
#endif /* SSH_USERMODE_DEFAULT_FLAGS */

/** Number of threads to use in usermodeinterceptor. */
#ifdef SSH_USERMODE_INTERCEPTOR_NUM_THREADS
#if SSH_USERMODE_INTERCEPTOR_NUM_THREADS > 0
#error "Multithreaded usermodeinterceptor is not supported"
#endif
#else /* SSH_USERMODE_INTERCEPTOR_NUM_THREADS */
#define SSH_USERMODE_INTERCEPTOR_NUM_THREADS 0
#endif /* SSH_USERMODE_INTERCEPTOR_NUM_THREADS */

/* Get packet manager handle. */
SshInterceptorPacketMgr
ssh_usermodeinterceptor_get_pktmgr(SshInterceptor interceptor);

/** Low-level interceptor init routine. Notice that in the
    normal initialization process the interceptor is the one which
    starts the engine -- here however it is the scaffolding which start
    engine, which open interceptor, at which point only we get the
    interceptor state up. So for timeouts etc. we must actually get
    some initialization *before* Engine is started. */
Boolean ssh_interceptor_init(void *machine_context);

/** Low-level interceptor uninit routine. */
void ssh_interceptor_uninit(void);

/** Allocation of SshInterceptor context. Called by ssh_interceptor_init().
    Can be used separately if ONLY the SshInterceptorPacket functions
    are going to be used. */

SshInterceptor
ssh_interceptor_alloc(void *machine_context);

/** Counterpart to ssh_interceptor_alloc().
    Is called by ssh_interceptor_uninit(). */
void
ssh_interceptor_free(SshInterceptor interceptor);

#ifdef DEBUG_LIGHT
#define SSH_ASSERT_THREAD() \
        SSH_ASSERT(ssh_threaded_mbox_is_thread(thread_mbox))
#define SSH_ASSERT_ELOOP() \
        SSH_ASSERT(!ssh_threaded_mbox_is_thread(thread_mbox))
#else /* !DEBUG_LIGHT */
#define SSH_ASSERT_THREAD() do {} while (0)
#define SSH_ASSERT_ELOOP() do {} while (0)
#endif /* DEBUG_LIGHT */

#endif /* USERMODEINTERCEPTOR_H */
