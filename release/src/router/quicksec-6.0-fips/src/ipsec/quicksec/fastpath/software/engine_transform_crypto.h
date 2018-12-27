/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Declarations and definitions private to the software FastPath
   implementation.
*/

#ifndef ENGINE_FASTPATH_CRYPTO_H
#define ENGINE_FASTPATH_CRYPTO_H


typedef enum
{
  SSH_TRANSFORM_SUCCESS,
  SSH_TRANSFORM_FAILURE
}
SshTransformResult;

/*
  Initializes the transform crypto library.
*/
void
transform_crypto_init(void);

/*
  Allocates memory structures required for the cryptographic
  operations specified by trr and transform parameters. On success,
  the allocated memory is stored in sw_crypto pointer in tc.
  On failure no memory is allocated.
 */
SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshPmTransform transform);

/*
  Frees all memory allocated by transform_crypto_alloc and sets
  sw_crypto pointer from in tc to NULL. Does nothing, if sw_crypto is
  already NULL.
 */
void
transform_crypto_free(
        SshFastpathTransformContext tc);


/*
  Resets state of allocated cryptographic structures of MAC computation.
 */
void
transform_esp_mac_start(
        SshFastpathTransformContext tc);


/*
  Updates mac computation state. The function is used for plain macs
  (e.g. hmac).
 */
SshTransformResult
transform_esp_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len);

/*
  Finalizes ICV computation and returns the ICV result. Used for both
  normal macs and authenticating ciphers. In case of authenticating
  ciphers all encrypted data i.e. all calls to transform_esp_cipher_update
  and transform_esp_cipher_update_remaining must be already done.
 */
SshTransformResult
transform_esp_icv_result(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len);

/*
  Verifies the ICV value given as parameter and comparing it to the computed
  value.
 */
SshTransformResult
transform_esp_icv_verify(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len);

/*
  Start encryption of cipher. The current sequence number is passed via
  `seq_num_low' and `seq_num_high'. For combined algorithms AAD can be
  passed via `aad' and `aad_len'.
 */
SshTransformResult
transform_esp_cipher_start_encrypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        size_t crypt_len,
        unsigned char *iv,
        unsigned int iv_len);

/*
  Start decryption of cipher. The IV received from packet and its length is
  passed via `iv' and `iv_len'. For combined algorithms AAD can be passed
  via `aad' and `aad_len'.
 */
SshTransformResult
transform_esp_cipher_start_decrypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        unsigned char *iv,
        unsigned int iv_len,
        size_t crypt_len);

/*
  Update cipher state. Depending on the parameters to
  transform_crypto_alloc the function performs either decryption or
  encryption. In case of authenticating ciphers the mac computation
  state is also updated. The size in data should be cipher block size
  aligned.
 */
SshTransformResult
transform_esp_cipher_update(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len);

/*
  Handles input data lengths that are not cipher block size aligned.
  Can only be called once per input data sequence. After calling this
  function the transform_esp_cipher_update can not be called.
 */
SshTransformResult
transform_esp_cipher_update_remaining(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len);


#ifdef SSH_IPSEC_AH

/* Public functions used with AH. */

/*
  Starts ICV computaion in outbound direction. For authenticating ciphers
  current low and high sequence numbers must be given via 'seq_num_low' and
  'seq_num_high' arguments. These numbers are used for IV generation.
 */
SshTransformResult
transform_ah_start_computation(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high);

/*
  Finalizes ICV computation and returns the ICV value. Used for both
  normal MACs and authenticating ciphers.
 */
SshTransformResult
transform_ah_result(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned int icv_len);

/*
  Starts ICV verify in inbound direction. The ICV received from AH packet is
  passed via 'icv' argument and its length via 'icv_len' argument.
 */
SshTransformResult
transform_ah_start_verify(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned int icv_len);

/*
  Finalizes the ICV verify in inbound direction. Function verifies computed
  ICV with ICV value given in 'icv' parameter of transform_ah_start_verify
  function.
 */
SshTransformResult
transform_ah_verify(
        SshFastpathTransformContext tc);

/*
  Updates mac computation state. The function is used for plain MACs
  (e.g. hmac) and authenticating ciphers.
 */
SshTransformResult
transform_ah_update(
        SshFastpathTransformContext tc,
        const unsigned char *buf,
        size_t len);

#endif /* SSH_IPSEC_AH */

#endif /* ENGINE_FASTPATH_CRYPTO_H */
