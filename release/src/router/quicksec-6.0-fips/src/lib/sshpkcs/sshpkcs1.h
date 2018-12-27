/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of RSA PKCS 1 public key and private key encodings from
   SSH internal data structures.
*/

#ifndef PKCS1_FORMATS_H
#define PKCS1_FORMATS_H

/* Following routines do the encoding and decoding of private and public
   keys from/to SSH Private Key and Public Key formats into PKCS 1
   ASN.1 encoded blobs. */

/* Encode SSH private key into PKCS 1 blob. The blob returned
   is allocated with ssh_xmalloc. Should be freed by application.
   Returns FALSE if fails, TRUE if succeeds. */
Boolean ssh_pkcs1_encode_private_key(SshPrivateKey private_key,
                                     unsigned char **buf,
                                     size_t *buf_len);

/* The decode routine for SSH private keys. Returns NULL if fails. */
SshPrivateKey ssh_pkcs1_decode_private_key(const unsigned char *buf,
                                           size_t buf_len);

/* Encode SSH public key into PKCS 1 blob. Similar to the private key
   version. */
Boolean ssh_pkcs1_encode_public_key(SshPublicKey public_key,
                                    unsigned char **buf,
                                    size_t *buf_len);
/* Similar to the private key version. */
SshPublicKey ssh_pkcs1_decode_public_key(const unsigned char *buf,
                                         size_t buf_len);


#endif /* PKCS1_FORMATS_H */
