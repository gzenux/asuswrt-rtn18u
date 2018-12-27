/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements a dummy IPsec engine that simply forwards all
   packets to a user-mode module that looks like an Interceptor
   (usermodeinterceptor.c).  This mechanism is intended only for
   testing the IPSEC engine, and should not be compiled into
   production application.
*/

#ifndef USERMODEFORWARDER_H
#define USERMODEFORWARDER_H

/* Allocate message numbers from the platform-specific portion. */

/** Received packet or packet to be sent.
      - uint32 flags
      - uint32 ifnum
      - uint32 protocol
      - uint32 media_header_len    (0 for packets going up)
      - string packet data
      - uint32 extension
        repeats SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS times. */
#define SSH_ENGINE_IPM_FORWARDER_PACKET         201

/** Routing request from user mode.
      - string destination
      - uint32 request id */
#define SSH_ENGINE_IPM_FORWARDER_ROUTEREQ       202

/** Routing reply from kernel.
      - uint32 id
      - uint32 reachable
      - uint32 ifnum
      - uint32 mtu
      - string next_hop_gw */
#define SSH_ENGINE_IPM_FORWARDER_ROUTEREPLY     203

/** Interfaces information from kernel:
      - uint32 num_interfaces.

      Repeats:
        - uint32 media
        - uint32 mtu
        - string name
        - string media_addr
        - uint32 num_addrs
        - string addrs array as binary data */
#define SSH_ENGINE_IPM_FORWARDER_INTERFACES     204

/** Route change notification.  No data. */
#define SSH_ENGINE_IPM_FORWARDER_ROUTECHANGE    205

/** Kernel version string.
      string version */
#define SSH_ENGINE_IPM_FORWARDER_VERSION        206

/** Watchdog timer reset. Sets the reset timer to 'seconds' uint32 seconds. */
#define SSH_ENGINE_IPM_WATCHDOG_RESET           207

#define SSH_ENGINE_IPM_FORWARDER_SET_DEBUG              208

#define SSH_ENGINE_IPM_FORWARDER_DEBUG                  210
#define SSH_ENGINE_IPM_FORWARDER_WARNING                211

/** Route modification. */
#define SSH_ENGINE_IPM_FORWARDER_ADD_ROUTE      212
#define SSH_ENGINE_IPM_FORWARDER_REMOVE_ROUTE   213

#define SSH_ENGINE_IPM_FORWARDER_ROUTE_SUCCESS  214

#define SSH_ENGINE_IPM_FORWARDER_INTERNAL_DATA_DISCARDED         215

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/** Send a packet to local stack. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_SEND           220
/** Attach a virtual adapter to Engine. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_ATTACH         221
/** Detach a virtual adapter from Engine. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH         222
/** Detach all virtual adapters from Engine. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_DETACH_ALL     223
/** Configure virtual adapter. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_CONFIGURE      224
/** Enumerate virtual adapters. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_GET_STATUS     225
/** Virtual adapter status callback. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_STATUS_CB      226
/** Virtual adapter packet callback. */
#define SSH_ENGINE_IPM_FORWARDER_VIRTUAL_ADAPTER_PACKET_CB      227

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


#endif /* USERMODEFORWARDER_H */
