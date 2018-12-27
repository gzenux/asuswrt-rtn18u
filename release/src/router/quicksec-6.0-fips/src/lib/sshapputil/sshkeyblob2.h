/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encode and decode SSH2 format keyblob.
*/

#ifndef _SSHKEYBLOB2_H_
#define _SSHKEYBLOB2_H_

/* Magic identifying codes for private and public key files. */

#define SSH_KEY_MAGIC_FAIL                      0
#define SSH_KEY_MAGIC_PUBLIC                    0x73736801
#define SSH_KEY_MAGIC_PRIVATE                   0x73736802
#define SSH_KEY_MAGIC_PRIVATE_ENCRYPTED         0x73736803
#define SSH_KEY_MAGIC_SSH1_PUBLIC               0x73733101
#define SSH_KEY_MAGIC_SSH1_PRIVATE              0x73733102
#define SSH_KEY_MAGIC_SSH1_PRIVATE_ENCRYPTED    0x73733103

/* This function parses the SSH1/SSH2 keyblob given as `data'. It will
   read the possible comment string into `comment' and return the
   actual PEM encoded key data as `blob'. If the key is an SSH1 public
   key and `try_convert_ssh1_cert´ is true, the key is converted into
   SSH2 format public key. The function frees `data'.

   The function returns kind of the key as SSH_KEY_MAGIC number
   above. */
unsigned long
ssh2_key_blob_decode(unsigned char *data, size_t len,
                     Boolean try_convert_ssh1_cert,
                     char **subject,
                     char **comment,
                     unsigned char **blob, size_t *bloblen);

/* Encoding of the SSH2 ascii key blob format. The format is
   as follows:

   ---- BEGIN SSH2 PUBLIC KEY ----
   Subject: login-name
   Comment: "Some explanatorial message."
   Base64 encoded blob.... =
   ---- END SSH2 PUBLIC KEY  ----

   */
Boolean
ssh2_key_blob_encode(unsigned long magic,
                     const char *subject, const char *comment,
                     const unsigned char *key, size_t keylen,
                     unsigned char **encoded, size_t *encoded_len);


/*
  This function parses and returns the string after the "Comment: "
  tag in ssh2 pem blob.
 */
size_t
ssh_key_blob_get_string(const unsigned char *buf, size_t len,
                        char **string);

#endif /* _SSHKEYBLOB2_H_ */
