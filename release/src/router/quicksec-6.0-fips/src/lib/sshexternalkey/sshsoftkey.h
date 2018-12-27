/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SOFTWAREKEY_H_INCLUDED
#define SOFTWAREKEY_H_INCLUDED

#include "sshcrypt.h"
/* Warning: This API is a preliminary, it is subject to change in some
   future releases. */

/* This header implemens some software key functions with externalkey. */

/* Adds a key and certificate into the software provider. The key and
   the certificate is reported using the externalkey notification
   callback and the key and certificate is available for the
   application through the standard externakey API functions.

   This function may be called multiple times with the same key,
   possible with a different certificate. Each call, if succesfull,
   results into a call to the application specified notification
   callback.

   The ek points to an allocated externalkey provider.

   provider_short_name is a string identifying the software provider
   to be used in this operation. If it is NULL, the first available
   software provider will be used.

   The priv is a software key returned from SSH cryptographic
   library.

   The key label is some printable label for the key, it will be
   provided in the notification callback. The label may be NULL.

   The cert points to a BER/DER encoded x.509 buffer. The cert_len is
   the length of the certificate data. The cert may be NULL.

   Returns SSH_EK_OK on success, or some other SshEkStatus enums on
   failure cases.
*/
SshEkStatus ssh_sk_add_key_and_cert(SshExternalKey ek,
                                    const char *provider_short_name,
                                    SshPrivateKey priv,
                                    const char *key_label,
                                    const unsigned char *cert,
                                    size_t cert_len);

#endif /* SOFTWAREKEY_H_INCLUDED */
