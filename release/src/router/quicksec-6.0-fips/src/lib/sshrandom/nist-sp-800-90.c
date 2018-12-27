/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Deterministic Random Bit Generator (DRBG)
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"
#include "sshentropy.h"
#include "sshgetput.h"
#include "rijndael.h"

#include "nist-sp-800-90.h"

#ifdef SSHDIST_CRYPT_NIST_SP_800_90

#define SSH_DEBUG_MODULE "SshRandomNistDRBG"

#define DRBG_AES256_SECURITY_STRENGTH 256

#define DRBG_AES256_SEEDLEN 48
#define DRBG_AES256_KEYLEN 32
#define DRBG_AES256_NONCELEN 32
#define DRBG_AES_BLOCKLEN 16

#define DRBG_MAX_DF_OUTPUT_LENGTH 64

#define DRBG_RESEED_INTERVAL 16384

#define DRBG_MAX_PERSONALIZATION_STRING_LENGTH 1024
#define DRBG_MAX_ADDITIONAL_INPUT_LENGTH 1024
#define DRBG_MAX_REQUEST_SIZE 131072

/* NIST SP 800-90 10.2.1.1 */
typedef struct SshDrbgStateRec {
  SshDrbgDataInput nonce_function;
  SshDrbgDataInput entropy_function;
  Boolean prediction_resistance;
  SshUInt32 security_strength;
  SshUInt32 reseed_counter;
  unsigned char v[DRBG_AES_BLOCKLEN];
  unsigned char key[DRBG_AES256_KEYLEN];

  void *aes_context;

  /* This value is used by the SSH gluelayer to fetch entropy when
     required by the SSH API. */
  SshUInt32 output_bytes;
} SshDrbgStateStruct;


/* *************************** Util **************************************/

static void
increment_block(unsigned char *block,
                int block_len)
{
  int i;

  for (i = block_len - 1; i >= 0; i--)
    {
      block[i]++;

      /* Check overflow */
      if (block[i] == 0x00)
        continue;
      else
        break;
    }
}

/* ******************* CRT_DRBG Derivation Function **********************/

/* NIST SP 800-90 10.4.3 */
static SshCryptoStatus df_bcc(unsigned char *iv,
                              SshUInt32 l_len,
                              SshUInt32 n_len,
                              unsigned char *data,
                              size_t data_len,
                              unsigned char *output,
                              size_t output_len,
                              void *aes_context)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  unsigned char input_block[DRBG_AES_BLOCKLEN];
  unsigned char chaining_value[DRBG_AES_BLOCKLEN];
  SshUInt32 n, i, j;
  size_t data_offset = 0;

  SSH_ASSERT(output_len == DRBG_AES_BLOCKLEN);
  SSH_ASSERT(data_len >= 8);

  memset(chaining_value, 0x00, DRBG_AES_BLOCKLEN);

  /* n = ceiling(( len(IV || iunt32 || uint32 || data || 0x08) / outlen ) */
  n = ((DRBG_AES_BLOCKLEN + 4 + 4 + data_len) / DRBG_AES_BLOCKLEN) + 1;

  for (i = 0; i < n; i++)
    {
      if (i == 0)
        {
          /* First AES block is IV */
          memcpy(input_block, iv, DRBG_AES_BLOCKLEN);
        }
      else if (i == 1)
        {
          /* Second AES block: L || N || 8 bytes of data */
          SSH_PUT_32BIT(input_block, l_len);
          SSH_PUT_32BIT(input_block + 4, n_len);
          memcpy(input_block + 8, data, 8);
          data_offset = 8;
        }
      else if (data_offset + DRBG_AES_BLOCKLEN <= data_len)
        {
          /* Not the last block */
          memcpy(input_block, data + data_offset, DRBG_AES_BLOCKLEN);
          data_offset += DRBG_AES_BLOCKLEN;
        }
      else
        {
          /* Last block, add 0x80 and pad 0x00 */
          memset(input_block, 0x00, DRBG_AES_BLOCKLEN);
          memcpy(input_block, data + data_offset, data_len - data_offset);
          input_block[data_len - data_offset] = 0x80;
        }

      for (j = 0; j < DRBG_AES_BLOCKLEN; j++)
        input_block[j] = chaining_value[j] ^ input_block[j];

      status = ssh_rijndael_ecb(aes_context,
                                chaining_value,
                                input_block,
                                DRBG_AES_BLOCKLEN);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed transform"));
          return status;
        }
    }

  memcpy(output, chaining_value, DRBG_AES_BLOCKLEN);
  return status;
}

/* NIST SP 800-90 10.4.2 */
static SshCryptoStatus
block_cipher_df(unsigned char *input_data,
                SshUInt32 input_data_len,
                unsigned char *return_data,
                SshUInt32 return_data_len,
                SshDrbgState state)
{
  SshCryptoStatus status;
  unsigned char iv[DRBG_AES_BLOCKLEN];
  unsigned char x[DRBG_AES_BLOCKLEN];
  unsigned char temp[DRBG_MAX_DF_OUTPUT_LENGTH];
  size_t temp_len = 0;
  unsigned char df_final_key[DRBG_AES256_KEYLEN];
  const unsigned char df_bcc_key[] =
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  if (return_data_len > DRBG_MAX_DF_OUTPUT_LENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid requested df output length: '%u'",
                              return_data_len));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  status = ssh_aes_init(state->aes_context,
                        df_bcc_key,
                        DRBG_AES256_KEYLEN,
                        TRUE);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize AES cipher"));
      return status;
    }

  memset(iv, 0x00, DRBG_AES_BLOCKLEN);
  memset(temp, 0x00, DRBG_MAX_DF_OUTPUT_LENGTH);

  for (temp_len = 0;
       temp_len < DRBG_AES256_KEYLEN + DRBG_AES_BLOCKLEN;
       temp_len += DRBG_AES_BLOCKLEN)
    {
      SSH_ASSERT(temp_len + DRBG_AES_BLOCKLEN <= DRBG_MAX_DF_OUTPUT_LENGTH);

      status = df_bcc(iv,
                      input_data_len, return_data_len,
                      input_data, input_data_len,
                      temp + temp_len, DRBG_AES_BLOCKLEN,
                      state->aes_context);

      if (status != SSH_CRYPTO_OK)
        goto exit;

      /* Increment first 32-bits */
      increment_block(iv, 4);
    }

  memcpy(df_final_key, temp, DRBG_AES256_KEYLEN);
  memcpy(x, temp + DRBG_AES256_KEYLEN, DRBG_AES_BLOCKLEN);
  memset(temp, 0x00, DRBG_MAX_DF_OUTPUT_LENGTH);

  status = ssh_aes_init(state->aes_context,
                        df_final_key,
                        DRBG_AES256_KEYLEN,
                        TRUE);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to init AES cipher"));
      return status;
    }

  for (temp_len = 0;
       temp_len < return_data_len;
       temp_len += DRBG_AES_BLOCKLEN)
    {
      status = ssh_rijndael_ecb(state->aes_context,
                                x,
                                x,
                                DRBG_AES_BLOCKLEN);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed transform"));
          goto exit;
        }

      if (temp_len + DRBG_AES_BLOCKLEN <= return_data_len)
        memcpy(return_data + temp_len, x, DRBG_AES_BLOCKLEN);
      else
        memcpy(return_data + temp_len, x, return_data_len - temp_len);
    }

 exit:
  return status;
}

/* ********************** CRT_DRBG Mechanism *************************** */

/* NIST SP 800-90 10.2.1.2 */
static SshCryptoStatus
ctr_drbg_update(unsigned char *provided_data,
                const unsigned char *key,
                const unsigned char *v,
                SshDrbgState state)
{
  SshCryptoStatus status;
  unsigned char temp[DRBG_AES256_SEEDLEN * 2];
  SshUInt32 i, temp_len;

  memset(temp, 0x00, DRBG_AES256_SEEDLEN * 2);

  status = ssh_aes_init(state->aes_context,
                        key,
                        DRBG_AES256_KEYLEN,
                        TRUE);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to init AES cipher"));
      return status;
    }

  for (temp_len = 0;
       temp_len < DRBG_AES256_SEEDLEN;
       temp_len += DRBG_AES_BLOCKLEN)
    {
      increment_block((unsigned char *) v, DRBG_AES_BLOCKLEN);

      status = ssh_rijndael_ecb(state->aes_context,
                                temp + temp_len,
                                v,
                                DRBG_AES_BLOCKLEN);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed transform"));
          goto exit;
        }
    }

  SSH_ASSERT(temp_len == DRBG_AES256_SEEDLEN);

  for (i = 0; i < DRBG_AES256_SEEDLEN; i++)
    temp[i] ^= provided_data[i];

  memcpy(state->key, temp, DRBG_AES256_KEYLEN);
  memcpy(state->v, temp + DRBG_AES256_KEYLEN, DRBG_AES_BLOCKLEN);

 exit:
  return status;
}

/* NIST SP 800-90 10.2.1.3 */
static SshCryptoStatus
ctr_drbg_instantiate_algorithm(unsigned char *entropy_input,
                               size_t entropy_input_size,
                               unsigned char *nonce,
                               size_t nonce_size,
                               unsigned char *personalization_string,
                               size_t personalization_string_size,
                               SshDrbgState *initial_state)
{
  SshCryptoStatus status;
  void *aes_context = NULL;
  unsigned char key[DRBG_AES256_KEYLEN];
  unsigned char v[DRBG_AES_BLOCKLEN];
  unsigned char seed_material[DRBG_AES256_SEEDLEN];
  unsigned char *temp = NULL;
  size_t temp_len;

  *initial_state = ssh_calloc(1, sizeof(**initial_state));

  if (*initial_state == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  temp_len = entropy_input_size + nonce_size + personalization_string_size;
  temp = ssh_malloc(temp_len);

  if (temp == NULL)
    {
      ssh_free(*initial_state);
      return SSH_CRYPTO_NO_MEMORY;
    }

  aes_context = ssh_crypto_malloc_i(ssh_rijndael_ctxsize());

  if (aes_context == NULL)
    {
      ssh_free(*initial_state);
      ssh_free(temp);
      return SSH_CRYPTO_NO_MEMORY;
    }

  (*initial_state)->reseed_counter = 1;
  (*initial_state)->aes_context = aes_context;

  memcpy(temp, entropy_input, entropy_input_size);
  memcpy(temp + entropy_input_size, nonce, nonce_size);
  memcpy(temp + entropy_input_size + nonce_size,
         personalization_string, personalization_string_size);

  status = block_cipher_df(temp,
                           (SshUInt32) temp_len,
                           seed_material,
                           DRBG_AES256_SEEDLEN,
                           *initial_state);

  if (status != SSH_CRYPTO_OK)
    goto exit;

  memset(key, 0x00, DRBG_AES256_KEYLEN);
  memset(v, 0x00, DRBG_AES_BLOCKLEN);

  status = ctr_drbg_update(seed_material, key, v,
                           *initial_state);

 exit:
  ssh_free(temp);
  return status;
}

/* NIST SP 800-90 10.2.1.4 */
static SshCryptoStatus
ctr_drbg_reseed_algorithm(unsigned char *entropy_input,
                          size_t entropy_input_size,
                          unsigned char *additional_input,
                          size_t additional_input_size,
                          SshDrbgState state)
{
  SshCryptoStatus status;
  unsigned char seed_material[DRBG_AES256_SEEDLEN];
  unsigned char *temp = NULL;
  size_t temp_len;

  temp_len = entropy_input_size + additional_input_size;
  temp = ssh_malloc(temp_len);

  if (temp == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  memcpy(temp, entropy_input, entropy_input_size);
  memcpy(temp + entropy_input_size, additional_input, additional_input_size);

  memset(seed_material, 0x00, DRBG_AES256_SEEDLEN);

  status = block_cipher_df(temp,
                           (SshUInt32) temp_len,
                           seed_material,
                           DRBG_AES256_SEEDLEN,
                           state);

  if (status != SSH_CRYPTO_OK)
    goto exit;

  status = ctr_drbg_update(seed_material, state->key, state->v, state);

  state->reseed_counter = 1;

 exit:
  ssh_free(temp);
  return status;
}

/* NIST SP 800-90 10.2.1.5 */
static SshCryptoStatus
ctr_drbg_generate(unsigned char *return_buffer,
                  size_t requested_size,
                  size_t *returned_size,
                  unsigned char *additional_input,
                  size_t additional_input_size,
                  SshDrbgState state)
{
  SshCryptoStatus status;
  unsigned char seed_material[DRBG_AES256_SEEDLEN];
  unsigned char output_block[DRBG_AES_BLOCKLEN];
  size_t temp_len;

  if (state->reseed_counter > DRBG_RESEED_INTERVAL)
    return SSH_CRYPTO_RNG_ENTROPY_NEEDED;

  memset(seed_material, 0x00, DRBG_AES256_SEEDLEN);

  if (additional_input != NULL && additional_input_size > 0)
    {
      status = block_cipher_df(additional_input,
                               (SshUInt32) additional_input_size,
                               seed_material,
                               DRBG_AES256_SEEDLEN,
                               state);

      if (status != SSH_CRYPTO_OK)
        return status;

      status = ctr_drbg_update(seed_material, state->key, state->v, state);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  status = ssh_aes_init(state->aes_context,
                        state->key,
                        DRBG_AES256_KEYLEN,
                        TRUE);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to init AES cipher"));
      return status;
    }

  for (temp_len = 0;
       temp_len < requested_size;
       temp_len += DRBG_AES_BLOCKLEN)
    {
      increment_block(state->v, DRBG_AES_BLOCKLEN);

      status = ssh_rijndael_ecb(state->aes_context,
                                output_block,
                                state->v,
                                DRBG_AES_BLOCKLEN);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed transform"));
          goto exit;
        }

      if (requested_size < temp_len + DRBG_AES_BLOCKLEN)
        memcpy(return_buffer + temp_len, output_block,
               requested_size - temp_len);
      else
        memcpy(return_buffer + temp_len, output_block,
               DRBG_AES_BLOCKLEN);
    }

  status = ctr_drbg_update(seed_material, state->key, state->v, state);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to update"));
      goto exit;
    }

  state->reseed_counter++;

  *returned_size = requested_size;

 exit:
  return status;
}

/* ******************** Default entropy function *************************/

static void
drbg_default_entropy_input(unsigned char *buffer,
                           size_t buffer_size,
                           size_t *input_size,
                           size_t *entropy_size)
{
  if (!ssh_get_system_entropy(buffer,
                              buffer_size,
                              input_size,
                              entropy_size))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Retrieving system entropy failed"));
      SSH_ASSERT(*input_size == 0);
    }

  return;
}

static void
drbg_default_nonce_input(unsigned char *buffer,
                         size_t buffer_size,
                         size_t *input_size,
                         size_t *entropy_size)
{
  if (!ssh_get_system_entropy(buffer,
                              buffer_size,
                              input_size,
                              entropy_size))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Retrieving system entropy failed"));
      SSH_ASSERT(*input_size == 0);
    }

  return;
}


/* ************************** DRBG API ***********************************/

/* NIST SP 800-90 9.1 */
SshCryptoStatus
ssh_drbg_instantiate(SshUInt32 requested_security_strength,
                     Boolean prediction_resistance,
                     unsigned char *personalization_string,
                     size_t personalization_string_size,
                     SshDrbgDataInput entropy_func,
                     SshDrbgDataInput nonce_func,
                     SshDrbgState *state_handle)
{
  SshCryptoStatus status;
  SshUInt32 security_strength = 0;
  SshDrbgState initial_working_state = NULL;
  unsigned char entropy_input[DRBG_AES256_SECURITY_STRENGTH];
  unsigned char nonce_input[DRBG_AES256_SECURITY_STRENGTH];
  size_t nonce_return_size = 0;
  size_t entropy_return_size = 0;
  size_t nonce_return_entropy = 0;
  size_t entropy_return_entropy = 0;

  if (requested_security_strength > DRBG_AES256_SECURITY_STRENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid requested security strength '%u'",
                              requested_security_strength));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (prediction_resistance)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Prediction resistance not supported"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (personalization_string_size > DRBG_MAX_PERSONALIZATION_STRING_LENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too long personalization string"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Only AES256 is currently supported */
  security_strength = DRBG_AES256_SECURITY_STRENGTH;

  if (entropy_func != NULL)
    (*entropy_func)(entropy_input,
                    DRBG_AES256_SECURITY_STRENGTH,
                    &entropy_return_size,
                    &entropy_return_entropy);
  else
    drbg_default_entropy_input(entropy_input,
                               DRBG_AES256_SECURITY_STRENGTH,
                               &entropy_return_size,
                               &entropy_return_entropy);

  if (entropy_return_size == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get entropy"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  if (entropy_return_entropy < DRBG_AES256_SECURITY_STRENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to get enough entropy for instantiate-operation"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  if (nonce_func != NULL)
    (*nonce_func)(nonce_input,
                  DRBG_AES256_SECURITY_STRENGTH,
                  &nonce_return_size,
                  &nonce_return_entropy);
  else
    drbg_default_nonce_input(nonce_input,
                             DRBG_AES256_SECURITY_STRENGTH,
                             &nonce_return_size,
                             &nonce_return_entropy);

  if (nonce_return_size == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to get nonce"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  if (nonce_return_entropy < (DRBG_AES256_SECURITY_STRENGTH / 2))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to get enough entropy for nonce"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  status = ctr_drbg_instantiate_algorithm(entropy_input,
                                          entropy_return_size,
                                          nonce_input,
                                          nonce_return_size,
                                          personalization_string,
                                          personalization_string_size,
                                          &initial_working_state);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to initiate algorithm"));
      return status;
    }

  /* Store values, if nonce and entropy functions are not set use
     default entropy function instead. */
  initial_working_state->prediction_resistance = prediction_resistance;
  initial_working_state->security_strength = security_strength;
  initial_working_state->nonce_function =
    nonce_func ? nonce_func : drbg_default_nonce_input;
  initial_working_state->entropy_function =
    entropy_func ? entropy_func : drbg_default_entropy_input;

  *state_handle = initial_working_state;

  return status;
}

/* NIST SP 800-90 9.2 */
SshCryptoStatus
ssh_drbg_reseed(unsigned char *additional_input,
                size_t additional_input_size,
                SshDrbgState state_handle)
{
  SshCryptoStatus status;
  unsigned char entropy_input[DRBG_AES256_SECURITY_STRENGTH];
  size_t entropy_input_size = 0;
  size_t entropy_input_entropy = 0;

  if (state_handle == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid handle"));
      return SSH_CRYPTO_HANDLE_INVALID;
    }

  if (additional_input_size > DRBG_MAX_ADDITIONAL_INPUT_LENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too long additional input"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  SSH_ASSERT(state_handle->entropy_function != NULL);

  (*state_handle->entropy_function)(entropy_input,
                                    DRBG_AES256_SECURITY_STRENGTH,
                                    &entropy_input_size,
                                    &entropy_input_entropy);

  if (entropy_input_size == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get entropy"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  if (entropy_input_entropy < DRBG_AES256_SECURITY_STRENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to get enough entropy for reseed-operation"));
      return SSH_CRYPTO_INVALID_OPERATION;
    }

  status = ctr_drbg_reseed_algorithm(entropy_input,
                                     entropy_input_size,
                                     additional_input,
                                     additional_input_size,
                                     state_handle);

  return status;
}

/* NIST SP 800-90 9.3 */
SshCryptoStatus
ssh_drbg_generate(SshUInt32 requested_number_of_bits,
                  SshUInt32 requested_security_strength,
                  Boolean prediction_resistance_request,
                  unsigned char *additional_input,
                  size_t additional_input_size,
                  unsigned char *pseudorandom_bits,
                  SshDrbgState state_handle)
{
  SshCryptoStatus status;
  size_t returned_size;
  Boolean reseed_required = FALSE;

  if (state_handle == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid handle"));
      return SSH_CRYPTO_HANDLE_INVALID;
    }

  if (requested_number_of_bits > DRBG_MAX_REQUEST_SIZE * 8)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Too large random buffer required (%u)",
                              requested_number_of_bits / 8));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (requested_number_of_bits % 8 != 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid number of bits requested (%u)",
                              requested_number_of_bits));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (requested_security_strength > state_handle->security_strength)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Requested security strength of '%d', but %d is the "
                 "maximum supported by this instantiation.",
                 requested_security_strength,
                 state_handle->security_strength));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (additional_input_size > DRBG_MAX_ADDITIONAL_INPUT_LENGTH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too long additional input"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  if (prediction_resistance_request)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Prediction resistance not supported"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

 reseed:
  if (reseed_required)
    {
      status = ssh_drbg_reseed(additional_input,
                               additional_input_size,
                               state_handle);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Reseeding for generate-function failed"));
          return status;
        }

      reseed_required = FALSE;
      additional_input = NULL;
      additional_input_size = 0;
    }

  status = ctr_drbg_generate(pseudorandom_bits,
                             requested_number_of_bits / 8,
                             &returned_size,
                             additional_input,
                             additional_input_size,
                             state_handle);

  if (status == SSH_CRYPTO_RNG_ENTROPY_NEEDED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Reseed required before drbg can operate"));
      reseed_required = TRUE;
      goto reseed;
    }

  return status;
}

/* NIST SP 800-90 9.3 */
SshCryptoStatus
ssh_drbg_uninstantiate(SshDrbgState state_handle)
{
  if (state_handle == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid handle"));
      return SSH_CRYPTO_HANDLE_INVALID;
    }

  if (state_handle->aes_context != NULL)
    ssh_crypto_free_i(state_handle->aes_context);

  /* Zeroize */
  memset(state_handle, 0x00, sizeof(*state_handle));

  ssh_free(state_handle);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_drbg_set_state(SshUInt32 reseed_counter,
                   unsigned char *v,
                   size_t v_len,
                   unsigned char *key,
                   size_t key_len,
                   SshDrbgState state_handle)
{
  if (state_handle == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid handle"));
      return SSH_CRYPTO_HANDLE_INVALID;
    }

  if (v != NULL)
    {
      SSH_ASSERT(v_len == DRBG_AES_BLOCKLEN);
      memcpy(state_handle->v, v, v_len);
    }

  if (key != NULL)
    {
      SSH_ASSERT(key_len == DRBG_AES256_KEYLEN);
      memcpy(state_handle->key, key, key_len);
    }

  state_handle->reseed_counter = reseed_counter;

  return SSH_CRYPTO_OK;
}


/* ************************** SSH gluelayer *******************************/

#define SSH_NIST_DRBG_MAX_BYTES_PER_RESEED 16384

/* Use INSIDE Secure QuickSec IKEv2 vendor id as personalization string */
const unsigned char personalization_string[] =
  {0x4f, 0x85, 0x58, 0x17, 0x1d, 0x21, 0xa0, 0x8d,
   0x69, 0xcb, 0x5f, 0x60, 0x9b, 0x3c, 0x06, 0x00};
const size_t personalization_string_len = 16;


static SshCryptoStatus
ssh_random_nist_sp_800_90_init(void **context_ret)
{
  SshCryptoStatus status;
  SshDrbgState state_handle;

  status = ssh_drbg_instantiate(DRBG_AES256_SECURITY_STRENGTH,
                                FALSE,
                                (unsigned char *)personalization_string,
                                personalization_string_len,
                                NULL,
                                NULL,
                                &state_handle);

  if (status != SSH_CRYPTO_OK)
    return status;

  *context_ret = state_handle;

  state_handle->output_bytes = 0;

  return status;
}

static void
ssh_random_nist_sp_800_90_uninit(void *context)
{
  SshDrbgState state_handle = (SshDrbgState) context;

  ssh_drbg_uninstantiate(state_handle);
}

static SshCryptoStatus
ssh_random_nist_sp_800_90_add_entropy(void *context,
                                      const unsigned char *buf,
                                      size_t buflen,
                                      size_t estimated_entropy_bits)
{
  SshCryptoStatus status;
  SshDrbgState state_handle = (SshDrbgState) context;

  status = ssh_drbg_reseed((unsigned char *) buf,
                           buflen,
                           state_handle);

  return status;
}

static SshCryptoStatus
ssh_random_nist_sp_800_90_get_bytes(void *context,
                                    unsigned char *buf, size_t buflen)
{
  SshDrbgState state_handle = (SshDrbgState) context;
  SshCryptoStatus status;

  /* Ask for more entropy to satisfy the needs of SSH API */
  if (state_handle->output_bytes + buflen > SSH_NIST_DRBG_MAX_BYTES_PER_RESEED)
    {
      ssh_crypto_library_request_noise();
      state_handle->output_bytes = 0;
    }
  else
    {
      state_handle->output_bytes += buflen;
    }

  status = ssh_drbg_generate(buflen * 8,
                             DRBG_AES256_SECURITY_STRENGTH,
                             FALSE,
                             NULL,
                             0,
                             buf,
                             state_handle);

  return status;
}

const SshRandomDefStruct ssh_random_nist_sp_800_90 = {
  "nist-sp-800-90",
  ssh_random_nist_sp_800_90_init,
  ssh_random_nist_sp_800_90_uninit,
  ssh_random_nist_sp_800_90_add_entropy,
  ssh_random_nist_sp_800_90_get_bytes
};

#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */
