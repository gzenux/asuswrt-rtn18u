/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This header file contains extensions to Interceptor API that are
   specific to the Linux Octeon Interceptor. The Octeon Accelerated
   Fastpath uses this API for interacting with the linux OS. This
   file is included from platform_interceptor.h.
*/

#ifndef LINUX_OCTEON_INTERCEPTOR_H
#define LINUX_OCTEON_INTERCEPTOR_H 1

/** Octeon packet handler */

/** The accelerated fastpath registers this type of function that the
    Octeon Interceptor uses for passing exception packets to the fastpath. */
typedef void (*SshInterceptorOcteonPacketCB)(SshInterceptorPacket pp,
                                             SshUInt32 tunnel_id,
                                             SshUInt32 prev_transform_index,
                                             void *context);

/** Register exception packet handler to the Octeon Interceptor. */
void
ssh_interceptor_octeon_set_packet_cb(SshInterceptor interceptor,
                                     SshInterceptorOcteonPacketCB
                                     packet_callback,
                                     void *callback_context);


/** Interface index conversion */

/** Convert linux interface index `ifnum' to Octeon port number. */
uint8_t
ssh_interceptor_octeon_ifnum_to_port(SshInterceptor interceptor,
                                     SshInterceptorIfnum ifnum);

/** Convert Octeon port number `port' to linux interface index. */
SshInterceptorIfnum
ssh_interceptor_octeon_port_to_ifnum(SshInterceptor interceptor, uint8_t port);


/** Octeon system information */

/** Return the number of Octeon SE fastpath instances running in the system. */
uint8_t
ssh_interceptor_octeon_get_num_fastpaths(SshInterceptor interceptor);

#endif /* LINUX_OCTEON_INTERCEPTOR_H */
