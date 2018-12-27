/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for sending and receiving MAC frames. This API requires
   the SSH eventloop runtime environment.
*/

#ifndef SSHNETMAC_H
#define SSHNETMAC_H

#include "sshnetconfig.h"

/** Callback function type for indicating a received MAC frame to the
    application.

    The contents of the buffers may be accessed during the call only.

    @param dst
    Point to a 6-octet buffer containing the destination MAC address
    of the frame.

    @param src
    Points to 6-octet buffer containing the source MAC address of the
    frame.

    @param data_buf
    Specifies a buffer containing the MAC client data of the frame,
    i.e. octets between and not including the length/type field and
    the frame check sequence.

    @param data_len
    Length of the buffer data.

    @param context
    The callback context
    given to ssh_netmac_register().

    */
typedef void
(*SshNetmacReceiveCallback)(const unsigned char *dst,
                            const unsigned char *src,
                            const unsigned char *data_buf,
                            size_t data_len,
                            void *context);

/** Type of the handle returned by ssh_netconfig_register() and used
    by other sshnetconfig_* functions. */
typedef struct SshNetmacHandleRec *SshNetmacHandle;

/** Function for sending a MAC frame.

    The contents of the buffers may be accessed during the call only.

    @param handle
    A handle created using ssh_netmac_register().

    @param dst
    Point to a 6-octet buffer containing the destination MAC address
    of the frame.

    @param src
    Points to 6-octet buffer containing the source MAC address of the
    frame.

    @param data_buf
    Specifies a buffer containing the MAC client data of the frame,
    i.e. octets between and not including the length/type field and
    the frame check sequence.

    @param data_len
    Length of the buffer data.

    */
SshNetconfigError
ssh_netmac_send(SshNetmacHandle handle,
                const unsigned char *dst,
                const unsigned char *src,
                const unsigned char *data_buf,
                size_t data_len);

/** Get a handle for sending and receiving MAC frames . The handle
    must be unregistered using ssh_netmac_unregister().

    @param ifnum
    Specifies the LAN interface to use.

    @param proto
    Specifies an IEEE 802.3 protocol number in host order, used to
    filter received packets and fill the length/type field of
    transmitted frames.

    @param receive_callback
    Specifies the function to use for indicating received frames.

    @param receive_context
    Specifies the value of the context parameter passed to the
    callback function.

    @return
    On error this function returns NULL.

    */
SshNetmacHandle
ssh_netmac_register(SshUInt32 ifnum,
                    SshUInt16 proto,
                    SshNetmacReceiveCallback receive_callback,
                    void *receive_context);

/** Unregister a MAC handle. */
SshNetconfigError
ssh_netmac_unregister(SshNetmacHandle handle);

#endif /* SSHNETMAC_H */
