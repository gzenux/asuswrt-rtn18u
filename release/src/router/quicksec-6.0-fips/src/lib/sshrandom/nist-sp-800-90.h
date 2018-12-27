/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to use NIST SP 800-90 DRBG functionality.
*/

/** Handle for the current DRBG state. */
typedef struct SshDrbgStateRec *SshDrbgState;


/** Function to be called when entropy or nonce is needed by the DRBG.

    @param buffer
    Buffer for the data.

    @param buffer_size
    Size of the buffer.

    @param input_size
    Amount of data inserted to the buffer. If input_size is 0, the
    call failed.

    @param entropy_size
    Estimated amount of entropy the returned buffer has

 */
typedef void (*SshDrbgDataInput)(unsigned char *buffer,
                                 size_t buffer_size,
                                 size_t *input_size,
                                 size_t *entropy_size);

/** Function to instantiate a DRBG state.

    @param requested_security_strength
    Security strength needed to be used with this instantiation.

    @param prediction_resistance
    Boolean to indicate if prediction resistance should be used.

    @param personalization_string
    Optional personalization information.

    @param personalization_string_size
    Size of personalization string, must be less than
    the DRBG_MAX_PERSONALIZATION_STRING_LENGTH value.

    @param entropy_func
    Function to be used for getting entropy for the instantiation,
    if NULL the default function is used.

    @param nonce_func
    Function to be used for getting nonce for the instantiation,
    if NULL the default function is used.

    @param state_handle
    Pointer for the returned state handle on success.

    @return
    SSH_CRYPTO_OK on successful operation.

*/
SshCryptoStatus
ssh_drbg_instantiate(SshUInt32 requested_security_strength,
                     Boolean prediction_resistance,
                     unsigned char *personalization_string,
                     size_t personalization_string_size,
                     SshDrbgDataInput entropy_func,
                     SshDrbgDataInput nonce_func,
                     SshDrbgState *state_handle);


/** Function to reseed the DRBG state.

    @param additional_input
    Optional input for the seed.

    @param additional_input_size
    Size of additional_input.

    @param state_handle
    Handle for the DRBG state used.

    @return
    SSH_CRYPTO_OK on successful operation.

*/
SshCryptoStatus
ssh_drbg_reseed(unsigned char *additional_input,
                size_t additional_input_size,
                SshDrbgState state_handle);

/** Function to generate pseudorandom data.

    @param requested_number_of_bits
    Requested size of the pseudorandom data.

    @param requested_security_strength
    Security strength needed to be used with this operation.

    @param prediction_resistance_request
    Boolean to indicate if prediction resistance should be used.

    @param additional_input
    Optional input for the seed.

    @param additional_input_size
    Size of additional_input.

    @param pseudorandom_bits
    Array to store the pseudorandom data, must be at least the size of
    the requested_number_of_bits value.

    @param state_handle
    Handle for the DRBG state used.

    @return
    SSH_CRYPTO_OK on successful operation.

*/

SshCryptoStatus
ssh_drbg_generate(SshUInt32 requested_number_of_bits,
                  SshUInt32 requested_security_strength,
                  Boolean prediction_resistance_request,
                  unsigned char *additional_input,
                  size_t additional_input_size,
                  unsigned char *pseudorandom_bits,
                  SshDrbgState state_handle);

/** Function to set DRBG state. This is needed e.g. during
    DRBG health check.

    @param reseed_counter
    Counter for the reseed-operations

    @param v
    New value for v, if NULL the value is unchanged

    @param v_len
    Size of v

    @param key
    New value for key, if NULL the value is unchanged

    @param key_len
    Size of key

    @param state_handle
    Handle for the DRBG state

    @return
    SSH_CRYPTO_OK on successfull operation

*/

SshCryptoStatus
ssh_drbg_set_state(SshUInt32 reseed_counter,
                   unsigned char *v,
                   size_t v_len,
                   unsigned char *key,
                   size_t key_len,
                   SshDrbgState state_handle);


/** Function to uninstantiate the DRBG.

    @param state_handle
    Handle for the DRBG state.

    @return
    SSH_CRYPTO_OK on successful operation.

*/
SshCryptoStatus
ssh_drbg_uninstantiate(SshDrbgState state_handle);

/** Run the health check self-test function.
 */
Boolean
ssh_drbg_health_test();
