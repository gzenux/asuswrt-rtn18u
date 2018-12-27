/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   AES Key Wrap as specified in RFC 3394
*/

#ifndef AES_KEYWRAP_H
#define AES_KEYWRAP_H

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcipher.h"


/** Perform AES Key Wrap of the input buffer 'src' of length 'src_len'.
    The wrapped data is returned in 'dest' of length 'dest_len'.
    'src_len' must be a multiple of 8 and at least 16. 'dest_len' must
    be equal to 'src_len' + 8. The key used for AES key wrap is 'kek'
    and has length 'kek_len'. 'kek_len'must be 16, 24 or 32 bytes.

    If 'iv' is not NULL then this specifies the IV and 'iv_len' must
    be 8. If 'iv' is NULL, the default IV is used (A6A6A6A6A6A6A6A6).

    Returns SSH_CRYPTO_OK on success. */
SshCryptoStatus ssh_aes_key_wrap_kek(const unsigned char *kek,
                                     size_t kek_len,
                                     const unsigned char *iv,
                                     size_t iv_len,
                                     unsigned char *dest,
                                     size_t dest_len,
                                     const unsigned char *src,
                                     size_t src_len);

/** Perform AES Key Unwrap of the input buffer 'src' of length 'src_len'.
    The unwrapped data is returned in 'dest' of length 'dest_len'.
    'src_len' must be a multiple of 8 and at least 24. 'dest_len' must
    be equal to 'src_len' - 8. The key used for AES key unwrap is 'kek'
    and has length 'kek_len'. 'kek_len' must be 16, 24 or 32 bytes.

    If 'iv' is not NULL then this specifies the IV to compare against
    when doing the data integrity check, and 'iv_len' must be 8. If 'iv'
    is NULL, the default IV is used (A6A6A6A6A6A6A6A6).

    Returns SSH_CRYPTO_OK on success, and SSH_CRYPTO_OPERATION_FAILED if
    the data integrity check fails. */
SshCryptoStatus ssh_aes_key_unwrap_kek(const unsigned char *kek,
                                       size_t kek_len,
                                       const unsigned char *iv,
                                       size_t iv_len,
                                       unsigned char *dest,
                                       size_t dest_len,
                                       const unsigned char *src,
                                       size_t src_len);

/** This function behaves exactly as ssh_aes_key_wrap_kek with the exception
    that a SshCipher object 'cipher' is provided as input. 'cipher'
    must be the AES encryption cipher initialized with the appropriate
    key length from the KEK. */
SshCryptoStatus ssh_aes_key_wrap(SshCipher cipher,
                                 const unsigned char *iv,
                                 size_t iv_len,
                                 unsigned char *dest,
                                 size_t dest_len,
                                 const unsigned char *src,
                                 size_t src_len);

/** This function behaves exactly as ssh_aes_key_unwrap_kek with the exception
    that a SshCipher object 'cipher' is provided as input. 'cipher'
    must be the AES decryption cipher initialized with the appropriate
    key length from the KEK. */
SshCryptoStatus ssh_aes_key_unwrap(SshCipher cipher,
                                   const unsigned char *iv,
                                   size_t iv_len,
                                   unsigned char *dest,
                                   size_t dest_len,
                                   const unsigned char *src,
                                   size_t src_len);

#endif /* !AES_KEYWRAP_H */
