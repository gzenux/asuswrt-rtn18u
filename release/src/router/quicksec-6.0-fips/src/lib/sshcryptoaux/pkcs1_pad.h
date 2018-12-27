/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   (This module is a copy of sshcrypto/sshpk/pkcs1.[c|h], which is cryptolib
   internal module, and which are not made public.)
*/

#ifndef PKCS1_H_INCLUDE
#define PKCS1_H_INCLUDE

/* Wrap and pad the DER encoded hash oid 'encoded_oid' and hash
   digest 'digest' using the PKCS1 scheme identified by 'tag_number'.
   This copies the output to 'output_buffer'. Returns FALSE if
   'output_buffer' is of insufficient length. */
Boolean ssh_aux_pkcs1_wrap_and_pad(const unsigned char *encoded_oid,
                                   size_t encoded_oid_len,
                                   const unsigned char *digest,
                                   size_t digest_len,
                                   unsigned int tag_number,
                                   unsigned char *output_buffer,
                                   size_t output_buffer_len);

/* Pads 'input_buffer' using the PKCS1 scheme identified by 'tag_number' and
   copies the output to 'output_buffer'. Returns FALSE if 'output_buffer' is
   of insufficient length. This is the same  as the above function where
   'input_buffer' is the concatenation of 'encoded_oid' and 'digest'. */
Boolean ssh_aux_pkcs1_pad(const unsigned char *input_buffer,
                          size_t input_buffer_len,
                          unsigned int tag_number,
                          unsigned char *output_buffer,
                          size_t output_buffer_len);

/* Unpads 'input_buffer' using the PKCS1 scheme identified by 'tag_number'
   and copies the output to 'output_buffer'. Returns FALSE if
   'output_buffer' is of insufficient length. */
Boolean ssh_aux_pkcs1_unpad(const unsigned char *input_buffer,
                            size_t input_buffer_len,
                            unsigned int tag_number,
                            unsigned char *output_buffer,
                            size_t output_buffer_len,
                            size_t *return_len);

#endif /* PKCS1_H_INCLUDE */
