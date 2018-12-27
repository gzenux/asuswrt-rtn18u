/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_connection.h
*/

#ifndef UTIL_CONNECTION_H
#define UTIL_CONNECTION_H

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
typedef HANDLE SshConnection;
#else /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */
typedef void *SshConnection;
#endif /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */

/** Request network connection in order to communicate with the
    specified remote host. When the connection is available, call the
    callback function with a handle to the connection and the given
    context. If a connection could not be acquired pass NULL
    connection handle to the callback. If the callback was called
    synchronously within the context of this function, return NULL
    operation handle. Otherwise return an operation handle that can be
    used to abort connection setup. */
SshOperationHandle
ssh_pm_connection_request(SshIpAddr dst,
                          void (*callback)(SshConnection conn_handle,
                                           void *context),
                          void *context);

/** Release a network connection acquired using
    ssh_pm_connection_request(). */
void
ssh_pm_connection_release(SshConnection conn_handle);

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#endif /* UTIL_CONNECTION_H */
