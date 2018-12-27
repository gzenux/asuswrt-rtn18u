/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functionality for testing NIST DRBG health during its use. Follows
   NIST SP 800-90 11.3
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "nist-sp-800-90.h"

#ifdef SSHDIST_CRYPT_NIST_SP_800_90

#define SSH_DEBUG_MODULE "SshRandomNistDRBGHealth"

#define DRBG_TEST_BUFFER_SIZE 64
#define DRBG_TEST_SECURITY_STRENGTH 256
#define DRBG_TEST_ENTROPY_SIZE 32
#define PSEUDORANDOM_BUFFER_LEN 16

#define DRBG_TEST_MAX_INPUT_LEN 1024
#define DRBG_RESEED_INTERVAL 16384


/* ********************** Test vectors ****************************** */

typedef struct SshDrbgKnownAnswerTestRec {
  size_t entropy_len;
  size_t nonce_len;
  size_t personalization_string_len;
  size_t additional_input_len;
  unsigned char entropy_input[DRBG_TEST_BUFFER_SIZE];
  unsigned char nonce[DRBG_TEST_BUFFER_SIZE];
  unsigned char personalization_string[DRBG_TEST_BUFFER_SIZE];
  unsigned char additional_input[DRBG_TEST_BUFFER_SIZE];
  unsigned char entropy_input_reseed[DRBG_TEST_BUFFER_SIZE];
  unsigned char additional_input_reseed[DRBG_TEST_BUFFER_SIZE];
  unsigned char additional_input_final[DRBG_TEST_BUFFER_SIZE];
  unsigned char returned_bits[DRBG_TEST_BUFFER_SIZE];
} SshDrbgKnownAnswerTestStruct;

/* Taken from The NIST SP 800-90 Deterministic Random Bit Generator
   Validation System (DRBGVS) */
static const SshDrbgKnownAnswerTestStruct drbg_test_cases[] =
  {
    {
      32,
      16,
      0,
      0,
      {0xec, 0x01, 0x97, 0xa5, 0x5b, 0x0c, 0x99, 0x62,
       0xd5, 0x49, 0xb1, 0x61, 0xe9, 0x6e, 0x73, 0x2a,
       0x0e, 0xe3, 0xe1, 0x77, 0x00, 0x4f, 0xe9, 0x5f,
       0x5d, 0x61, 0x20, 0xbf, 0x82, 0xe2, 0xc0, 0xea},
      {0x9b, 0x13, 0x1c, 0x60, 0x1e, 0xfd, 0x6a, 0x7c,
       0xc2, 0xa2, 0x1c, 0xd0, 0x53, 0x4d, 0xe8, 0xd8},
      {0x00},
      {0x00},
      {0x61, 0x81, 0x0b, 0x74, 0xd2, 0xed, 0x76, 0x36,
       0x5a, 0xe7, 0x0e, 0xe6, 0x77, 0x2b, 0xba, 0x49,
       0x38, 0xee, 0x38, 0xd8, 0x19, 0xec, 0x1a, 0x74,
       0x1f, 0xb3, 0xff, 0x4c, 0x35, 0x2f, 0x14, 0x0c},
      {0x00},
      {0x00},
      {0x7e, 0xa8, 0x9c, 0xe6, 0x13, 0xe1, 0x1b, 0x5d,
       0xe7, 0xf9, 0x79, 0xe1, 0x4e, 0xb0, 0xda, 0x4d}
    },
    {
      32,
      16,
      0,
      32,
      {0x0d, 0xa2, 0x90, 0x46, 0xad, 0x8f, 0x67, 0x40,
       0xcb, 0x74, 0xe0, 0x79, 0x90, 0x55, 0x4a, 0xbd,
       0x89, 0x68, 0x8c, 0xf9, 0xe0, 0x03, 0x86, 0xc9,
       0xde, 0xca, 0xa5, 0x42, 0x9f, 0x18, 0xc6, 0xff},
      {0x61, 0x0e, 0x45, 0x01, 0x5c, 0x0c, 0xeb, 0xfe,
       0x9a, 0x31, 0xa8, 0x03, 0x97, 0xba, 0xb8, 0x37},
      {0x00},
      {0x59, 0x21, 0xa8, 0xe4, 0x0b, 0x17, 0x3e, 0x7a,
       0xc9, 0x0f, 0x60, 0xcf, 0x85, 0xf3, 0xe5, 0x56,
       0x6b, 0x99, 0x01, 0x0e, 0x74, 0x94, 0xfc, 0xee,
       0x4a, 0x3a, 0x35, 0x92, 0x5d, 0xf8, 0x58, 0x25},
      {0x80, 0x7e, 0x7b, 0xb8, 0x7c, 0xca, 0xb4, 0xd8,
       0x3d, 0x94, 0xf4, 0xc8, 0x72, 0x32, 0x44, 0x96,
       0xbc, 0x55, 0xe5, 0xe7, 0x89, 0x11, 0x4a, 0xa5,
       0x32, 0x2f, 0x55, 0xe8, 0x52, 0xb6, 0xd4, 0x28},
      {0x48, 0xff, 0xd9, 0x27, 0xd6, 0x93, 0x60, 0x7d,
       0x31, 0xf0, 0xd8, 0x8e, 0xa0, 0xba, 0x05, 0xfd,
       0xbb, 0x78, 0xb5, 0xc0, 0xad, 0x81, 0x1b, 0xad,
       0xa7, 0x2b, 0x6b, 0x41, 0xa6, 0x30, 0xb5, 0xb3},
      {0x6d, 0x40, 0x5c, 0x5e, 0x71, 0x9f, 0x6a, 0x7c,
       0x38, 0x10, 0x02, 0x3c, 0xf5, 0x91, 0x1e, 0x31,
       0xf3, 0x1c, 0x65, 0xb1, 0x8e, 0x49, 0x4b, 0x29,
       0x73, 0x47, 0x65, 0x9f, 0x1a, 0xfc, 0x0b, 0x86},
      {0xf0, 0xad, 0xce, 0xd8, 0x03, 0x2d, 0x5d, 0xc3,
       0x9d, 0x2a, 0xb2, 0x99, 0xf7, 0x1f, 0x9d, 0x1a}
    },
    {
      32,
      16,
      32,
      0,
      {0xae, 0x82, 0x81, 0xa5, 0xcf, 0x86, 0x1f, 0x6e,
       0x6a, 0x02, 0xd0, 0xe2, 0x8f, 0x2a, 0x55, 0xd4,
       0x4a, 0x36, 0x6a, 0x12, 0xfb, 0xeb, 0x48, 0x9c,
       0xf1, 0x6a, 0x60, 0x05, 0x4c, 0x37, 0x54, 0x28},
      {0xa8, 0x2b, 0xce, 0xd5, 0xd5, 0x2b, 0x17, 0xd6,
       0x53, 0x09, 0x35, 0x30, 0x46, 0xc8, 0x22, 0x20},
      {0x6e, 0x58, 0x2f, 0xb2, 0xcc, 0x3c, 0x14, 0xc0,
       0xdb, 0xb8, 0xd5, 0x80, 0xb0, 0xd4, 0xc0, 0xbd,
       0xd8, 0x73, 0x2e, 0xe9, 0x52, 0xf9, 0xa3, 0x68,
       0xcd, 0x3d, 0x29, 0x1d, 0x22, 0xb0, 0xe8, 0x35},
      {0x00},
      {0xba, 0x1a, 0x34, 0xd2, 0x0b, 0xd6, 0x8a, 0xef,
       0x59, 0x25, 0xd3, 0xca, 0xd4, 0x09, 0x5f, 0x30,
       0xb3, 0x2a, 0x9c, 0xe1, 0x2f, 0x83, 0x2f, 0xdf,
       0xc3, 0x52, 0x54, 0xfe, 0xa4, 0x40, 0x79, 0xa7},
      {0x00},
      {0x00},
      {0x97, 0x96, 0xfb, 0xb6, 0xff, 0xd3, 0x11, 0x51,
       0x54, 0x6a, 0x1f, 0xc0, 0x67, 0xd9, 0xab, 0xa7}
    },
    {
      32,
      16,
      32,
      32,
      {0x78, 0x7e, 0x5c, 0xbb, 0x7a, 0x80, 0xfe, 0x0f,
       0xd4, 0x6d, 0xc1, 0x88, 0xd8, 0x39, 0xa3, 0x61,
       0x98, 0x99, 0xb8, 0x25, 0x62, 0x2f, 0xc5, 0x77,
       0x78, 0xf3, 0x1c, 0x20, 0x13, 0xe4, 0xb8, 0x5d},
      {0xbb, 0xb7, 0xef, 0x4c, 0x3b, 0x93, 0x0e, 0xc2,
       0x8c, 0x81, 0x26, 0x90, 0x32, 0xbc, 0x73, 0xdd},
      {0xa2, 0xdb, 0xa7, 0x9b, 0xc0, 0x55, 0x13, 0x22,
       0x6f, 0x91, 0xed, 0xf5, 0xa7, 0x4d, 0xf0, 0x0f,
       0x8e, 0x38, 0xde, 0x6c, 0xf5, 0x1a, 0x18, 0xd0,
       0x17, 0x47, 0x7d, 0xd5, 0x8f, 0x44, 0x87, 0x3a},
      {0x5f, 0xbe, 0x2d, 0x3e, 0x04, 0x2b, 0x59, 0xb8,
       0x52, 0x8d, 0x08, 0xdc, 0x58, 0x45, 0x14, 0x47,
       0xb3, 0x2e, 0xd9, 0xbf, 0x46, 0x0d, 0x10, 0x41,
       0x37, 0x3a, 0xed, 0x4c, 0x2c, 0x8e, 0x76, 0x6f},
      {0x04, 0x6f, 0xb3, 0x8a, 0xee, 0x23, 0xfd, 0xe8,
       0x4a, 0xd4, 0x92, 0x4d, 0x0b, 0xeb, 0x4a, 0xad,
       0x06, 0x88, 0x14, 0x9c, 0x2c, 0x69, 0x56, 0xde,
       0x0e, 0x19, 0x87, 0x30, 0x92, 0x5c, 0x0c, 0x57},
      {0xc9, 0x4f, 0xc4, 0xdb, 0x72, 0xa9, 0xfc, 0xc0,
       0x93, 0xab, 0xd4, 0x7f, 0x4a, 0xdc, 0x98, 0x61,
       0x24, 0x47, 0x6a, 0x18, 0x37, 0xc9, 0x7b, 0xa1,
       0x7d, 0xa1, 0x88, 0x7a, 0x72, 0x34, 0x92, 0x06},
      {0x74, 0xc7, 0xd3, 0xe0, 0x51, 0xf8, 0xcc, 0x2d,
       0x6c, 0x0f, 0x79, 0xcd, 0xcb, 0xef, 0x60, 0xf6,
       0x00, 0xa4, 0xf7, 0xe8, 0x47, 0xa8, 0xe6, 0xd0,
       0xe0, 0x76, 0x7d, 0xf8, 0xae, 0x53, 0x76, 0x32},
      {0xcf, 0x86, 0x66, 0x39, 0xea, 0x39, 0x6d, 0xcb,
       0x5e, 0xef, 0x46, 0xcd, 0xd8, 0x1b, 0xc4, 0x7b}
    }
  };

/*
  0, Entropy len
  0, Nonce len
  0, Personalization len
  0, Additional len
  {0x00}, Entropy
  {0x00}, Nonce
  {0x00}, Personalization string
  {0x00}, Additional input
  {0x00}, Entropy input reseed
  {0x00}, Additional input reseed
  {0x00}, Additional input final
  {0x00}  Result
*/

/* ********************* Data input functions *********************** */

static unsigned char default_entropy_block[] =
  {0xaa, 0xed, 0xf0, 0xbd, 0x12, 0x37, 0xe5, 0x0b,
   0x2e, 0xa3, 0x3e, 0xbd, 0xe0, 0xf5, 0x08, 0x5e,
   0xc8, 0xb3, 0x69, 0xc9, 0xc5, 0x4d, 0x34, 0xf0,
   0xa9, 0x8c, 0xcd, 0xee, 0x3d, 0x3f, 0x3e, 0x4f};

static SshUInt32 entropy_function_used;

static unsigned char *next_entropy;
static size_t next_entropy_len;

static void entropy_input(unsigned char *buffer,
                          size_t buffer_size,
                          size_t *input_size,
                          size_t *entropy_size)
{
  SSH_ASSERT(buffer_size >= next_entropy_len);

  memcpy(buffer, next_entropy, next_entropy_len);
  *input_size = next_entropy_len;
  *entropy_size = next_entropy_len * 8;
  entropy_function_used++;
}

static unsigned char *next_nonce;
static size_t next_nonce_len;

static void nonce_input(unsigned char *buffer,
                        size_t buffer_size,
                        size_t *input_size,
                        size_t *entropy_size)
{
  SSH_ASSERT(buffer_size >= next_nonce_len);

  memcpy(buffer, next_nonce, next_nonce_len);
  *input_size = next_nonce_len;
  *entropy_size = next_nonce_len * 8;
}

/* ********************** Known answer tests ************************ */

static Boolean
drbg_known_answer_test_run(const SshDrbgKnownAnswerTestStruct *test_case_p)
{
  SshDrbgState state_handle = NULL;
  unsigned char pseudorandom_buffer[PSEUDORANDOM_BUFFER_LEN];
  SshDrbgKnownAnswerTestStruct test_case;
  Boolean rv = TRUE;

  memcpy(&test_case,  test_case_p, sizeof (test_case));
  next_entropy = test_case.entropy_input;
  next_entropy_len = test_case.entropy_len;
  next_nonce = test_case.nonce;
  next_nonce_len = test_case.nonce_len;

  if (ssh_drbg_instantiate(DRBG_TEST_SECURITY_STRENGTH,
                           FALSE,
                           test_case.personalization_string,
                           test_case.personalization_string_len,
                           entropy_input,
                           nonce_input,
                           &state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to instantiate"));
      rv = FALSE;
      goto exit;
    }

  if (ssh_drbg_generate(PSEUDORANDOM_BUFFER_LEN * 8,
                        DRBG_TEST_SECURITY_STRENGTH,
                        FALSE,
                        test_case.additional_input,
                        test_case.additional_input_len,
                        pseudorandom_buffer,
                        state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed first generate"));
      rv = FALSE;
      goto exit;
    }

  next_entropy = test_case.entropy_input_reseed;

  if (ssh_drbg_reseed(test_case.additional_input_reseed,
                      test_case.additional_input_len,
                      state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed reseed generate"));
      rv = FALSE;
      goto exit;
    }

  if (ssh_drbg_generate(PSEUDORANDOM_BUFFER_LEN * 8,
                        DRBG_TEST_SECURITY_STRENGTH,
                        FALSE,
                        test_case.additional_input_final,
                        test_case.additional_input_len,
                        pseudorandom_buffer,
                        state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed second generate"));
      rv = FALSE;
      goto exit;
    }

  if (memcmp(test_case.returned_bits, pseudorandom_buffer,
             PSEUDORANDOM_BUFFER_LEN))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Wrong result in known answer test"));
      rv = FALSE;
    }

 exit:
  if (ssh_drbg_uninstantiate(state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to uninstantiate"));
      rv = FALSE;
    }

  return rv;
}

/* ************************* Tests ********************************* */

Boolean ssh_drbg_known_answer_tests()
{
  SshUInt32 number_of_tests, i;

  number_of_tests =
    sizeof(drbg_test_cases) / sizeof(SshDrbgKnownAnswerTestStruct);

  for (i = 0; i < number_of_tests; i++)
    {
      if (!drbg_known_answer_test_run(&drbg_test_cases[i]))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed known test case %u/%u",
                                  i+1, number_of_tests));
          return FALSE;
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Passed %u known answer test cases", i));
  return TRUE;
}

Boolean ssh_drbg_instantiate_tests()
{
  SshDrbgState state_handle = NULL;

  next_entropy = NULL;
  next_entropy_len = 0;

  /* Test with invalid entropy source */
  if (ssh_drbg_instantiate(DRBG_TEST_SECURITY_STRENGTH,
                           FALSE,
                           NULL,
                           0,
                           entropy_input,
                           NULL,
                           &state_handle)
      == SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Instantiated without working entropy source"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Passed instantiate test"));
  return TRUE;
}

Boolean ssh_drbg_generate_tests()
{
  SshDrbgState state_handle = NULL;
  SshUInt32 entropy_count_before;
  unsigned char pseudorandom_buffer[PSEUDORANDOM_BUFFER_LEN];
  Boolean rv = TRUE;

  next_entropy = default_entropy_block;
  next_entropy_len = DRBG_TEST_ENTROPY_SIZE;

  /* Create instantiation, use default entropy source */
  if (ssh_drbg_instantiate(DRBG_TEST_SECURITY_STRENGTH,
                           FALSE,
                           NULL,
                           0,
                           entropy_input,
                           NULL,
                           &state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed instantiation in generate-tests"));
      return FALSE;
    }

  /* Invalid security strength */
  if (ssh_drbg_generate(PSEUDORANDOM_BUFFER_LEN * 8,
                        DRBG_TEST_SECURITY_STRENGTH + 1,
                        FALSE,
                        NULL,
                        0,
                        pseudorandom_buffer,
                        state_handle)
      != SSH_CRYPTO_UNSUPPORTED)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Accepted invalid security strength"));
      rv = FALSE;
      goto exit;
    }

  /* Invalid personalization string strength */
  if (ssh_drbg_generate(PSEUDORANDOM_BUFFER_LEN * 8,
                        DRBG_TEST_SECURITY_STRENGTH,
                        FALSE,
                        NULL,
                        DRBG_TEST_MAX_INPUT_LEN + 1,
                        pseudorandom_buffer,
                        state_handle)
      != SSH_CRYPTO_UNSUPPORTED)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Accepted invalid personalization data size"));
      rv = FALSE;
      goto exit;
    }

  if (ssh_drbg_uninstantiate(state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to uninstatiate"));
      return FALSE;
    }


  /* Reseed frequency, instantiate with test entropy source */
  next_entropy = default_entropy_block;
  next_entropy_len = DRBG_TEST_ENTROPY_SIZE;

  if (ssh_drbg_instantiate(DRBG_TEST_SECURITY_STRENGTH,
                           FALSE,
                           NULL,
                           0,
                           entropy_input,
                           NULL,
                           &state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed instantiation in generate-tests"));
      return FALSE;
    }

  if (ssh_drbg_set_state(DRBG_RESEED_INTERVAL + 1,
                         NULL,
                         0,
                         NULL,
                         0,
                         state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to set state"));
      rv = FALSE;
      goto exit;
    }

  entropy_count_before = entropy_function_used;

  if (ssh_drbg_generate(PSEUDORANDOM_BUFFER_LEN * 8,
                        DRBG_TEST_SECURITY_STRENGTH,
                        FALSE,
                        NULL,
                        0,
                        pseudorandom_buffer,
                        state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Generate functionality failed"));
      rv = FALSE;
      goto exit;
    }

  if (entropy_count_before + 1 != entropy_function_used)
    {
      SSH_DEBUG(SSH_D_ERROR, ("DRBG-state not reseeded"));
      rv = FALSE;
      goto exit;
    }

 exit:
  if (ssh_drbg_uninstantiate(state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to uninstatiate"));
      return FALSE;
    }

  return rv;
}

#define DRBG_STAT_BUFFER_SIZE 2500
#define MIN_ONES 9500
#define MAX_ONES 10500
#define MIN_POKER 2.0
#define MAX_POKER 50.0

/* This table lists the number of ones (ones[i]) in the byte i. */
const static unsigned char ones[] = {
  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
  4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

static Boolean ssh_drbg_statistical_tests()
{
  SshDrbgState state_handle = NULL;
  unsigned char bytes[DRBG_STAT_BUFFER_SIZE];
  int poker[16];
  int c, i;
  double chi = 0.0;

  /* Create bytes to test with default entropy source */
  if (ssh_drbg_instantiate(DRBG_TEST_SECURITY_STRENGTH,
                           FALSE,
                           NULL,
                           0,
                           NULL,
                           NULL,
                           &state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed instantiation in generate-tests"));
      return FALSE;
    }

  if (ssh_drbg_generate(DRBG_STAT_BUFFER_SIZE * 8,
                        DRBG_TEST_SECURITY_STRENGTH,
                        FALSE,
                        NULL,
                        0,
                        bytes,
                        state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Generate functionality failed"));
      ssh_drbg_uninstantiate(state_handle);
      return FALSE;
    }

  if (ssh_drbg_uninstantiate(state_handle)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to uninstatiate"));
      return FALSE;
    }

  /* Run statistical tests */

  /* The Monobit Test */
  c = 0;

  /* Count the number of ones in the sample */
  for (i = 0; i < sizeof(bytes); i++)
    c += ones[bytes[i]];

  /* The condition for an error */
  if (c <= MIN_ONES || c >= MAX_ONES)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Monobit test failed, got %d ones in %d bit buffer",
                 c, DRBG_STAT_BUFFER_SIZE * 8));
      return FALSE;
    }

  /* The Poker Test */
  for (i = 0; i < 16; i++)
    poker[i] = 0;

  for (i = 0; i < sizeof(bytes); i++)
    {
      poker[bytes[i] & 0xf]++;
      poker[(bytes[i] >> 4) & 0xf]++;
    }

  for (i = 0; i < 16; i++)
    chi += (double) poker[i] * poker[i];

  chi = (16.0 * chi / 5000.0) - 5000.0;

  /* The condition for an error */
  if (chi <= MIN_POKER || chi >= MAX_POKER)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Poker test failed, chi %f", chi));
      return FALSE;
    }

  return TRUE;
}

Boolean ssh_drbg_health_test()
{
  entropy_function_used = 0;

  if (!ssh_drbg_instantiate_tests())
    return FALSE;

  if (!ssh_drbg_known_answer_tests())
    return FALSE;

  if (!ssh_drbg_generate_tests())
    return FALSE;

  /* Tests for reseed and uninstantiate functionality
     are done in the functions above */

  if (!ssh_drbg_statistical_tests())
    return FALSE;

  return TRUE;
}

#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */
