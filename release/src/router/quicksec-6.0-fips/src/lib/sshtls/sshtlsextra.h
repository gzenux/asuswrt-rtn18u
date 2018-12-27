/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHTLSEXTRA_H_INCLUDED
#define SSHTLSEXTRA_H_INCLUDED

typedef void (* SshTlsGenericNotification)(void *context);

#define SSH_TLS_EXTRA_UNRESPONSIVE              0x0001
                                /* When set will cause the local party
                                   to jam the key exchange. Can be
                                   used to test that the key exchange
                                   timeout works correctly. */

void ssh_tls_set_destroy_callback(SshStream stream,
                                  SshTlsGenericNotification callback,
                                  void *context);

void ssh_tls_set_extra_flags(SshStream stream,
                             SshUInt32 flags);

#endif /* SSHTLSEXTRA_H_INCLUDED */
