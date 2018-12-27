/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encode and decode ssh2 public key blobs.
*/

#ifndef PUBKEYENCODE_H
#define PUBKEYENCODE_H

#include "sshbuffer.h"
#include "sshmp.h"
#include "sshcrypt.h"

/* the "ssh-dss" type and related formats */
#define SSH_SSH_DSS    "ssh-dss"
#define SSH_SSH_X509_DSS    "x509v3-sign-dss"
#define SSH_CRYPTO_DSS "dl-modp{sign{dsa-nist-sha1},dh{plain}}"
#define SSH_CRYPTO_DSS_SHORT "dl-modp"

/* the "ssh-rsa" type and related formats */
#define SSH_SSH_RSA    "ssh-rsa"
#define SSH_SSH_X509_RSA    "x509v3-sign-rsa"
#define SSH_CRYPTO_RSA \
"if-modn{\
sign{rsa-pkcs1-sha1,rsa-pkcs1-md5,rsa-pkcs1-none},\
encrypt{rsa-pkcs1v2-oaep,rsa-pkcs1-none,rsa-none-none}}"

#define SSH_CRYPTO_RSA_SHORT "if-modn"

/* Encode a public key into a SSH2 format blob. Return size or 0 on
   failure. */

size_t ssh_encode_pubkeyblob(SshPublicKey pubkey, unsigned char **blob);

/* Decode a public key blob. Return NULL on failure. */

SshPublicKey ssh_decode_pubkeyblob(const unsigned char *blob, size_t bloblen);

/* Decode a public key blob or certificate. Return NULL on failure.
   pk_format should be set to "ssh_dss", "x509v3-sign-dss", etc.
   (as defined in ssh2 transport layer document) */
SshPublicKey ssh_decode_pubkeyblob_general(const unsigned char *blob,
                                           size_t bloblen,
                                           const unsigned char *pk_format);

/* Type of the encoded public key in blob.  Have to be freed with
   ssh_xfree. */
char *ssh_pubkeyblob_type(const unsigned char *blob, size_t bloblen);

/* Returns TRUE if pk_format matches one of the defined plain pubkey
   formats */
Boolean
ssh_pubkeyblob_type_plain(const unsigned char *pk_format);

#ifdef SSHDIST_CERT
/* Returns TRUE if pk_format matches one of the defined X.509 formats */
Boolean
ssh_pubkeyblob_type_x509(const unsigned char *pk_format);

/* Decodes an X.509 format certificate and returns the
   public key and public key format ("x509v3-sign-dss", etc.
   as defined in ssh2 transport layer document). If returns
   FALSE, the operation failed and return variables stay
   unchanged. Return variables can also be NULL, in which case
   they are ignored. */
Boolean
ssh_pki_decode_x509cert(const unsigned char *ber,
                        size_t ber_len,
                        SshPublicKey *pk_return,
                        char **pk_format_return);


#endif /* SSHDIST_CERT */

void
ssh_bufaux_put_mp_int_ssh2style(SshBuffer buffer, SshMPInteger mp);

Boolean
ssh_bufaux_get_mp_int_ssh2style(SshBuffer buffer, SshMPInteger mp);

/* The following function converts from an linearized msb first positive
   mp integer, 'buf', to SSH2 style integers which are encoded in the
   SshBuffer 'buffer'. */
void
ssh_bufaux_put_msb_encoded_mp_int_ssh2style(SshBuffer buffer,
                                            const unsigned char *buf,
                                            size_t len);

/* The reverse of the above function. This allocates 'buf' which contains
   the mp integer msb first. This returns FALSE if the SSH2 style integer
   encoded in 'buffer' is negative or incorrectly encoded, and returns TRUE
   otherwise. */
Boolean
ssh_bufaux_get_msb_encoded_mp_int_ssh2style(SshBuffer buffer,
                                            unsigned char **buf,
                                            size_t *len);

#endif /* PUBKEYENCODE_H */
