/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains generic functions to generate random
   multiple-precision integers.
*/

#include "sshincludes.h"

#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"

#define SSH_DEBUG_MODULE "SshGenMPInteger"

/* Generate a random integer (using the cryptographically strong
   random number generator). */

void ssh_mprz_random_integer(SshMPInteger ret, unsigned int bits)
{
  unsigned int i, bytes;
  unsigned char *buf;

  ssh_mprz_set_ui(ret, 0);

  bytes = (bits + 7) / 8;
  if ((buf = ssh_malloc(bytes)) == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  for (i = 0; i < bytes; i++)
    buf[i] = ssh_random_object_get_byte();

  ssh_mprz_set_buf(ret, buf, bytes);
  ssh_free(buf);

  /* Cut unneeded bits off */
  ssh_mprz_mod_2exp(ret, ret, bits);
}


/* Get random number mod 'modulo' */

/* Random number with some sense in getting only a small number of
   bits. This will avoid most of the extra bits. However, we could
   do it in many other ways too. Like we could distribute the random bits
   in reasonably random fashion around the available size. This would
   ensure that cryptographical use would be slightly safer. */
void ssh_mprz_mod_random_entropy(SshMPInteger op, SshMPIntegerConst modulo,
                               unsigned int bits)
{
  ssh_mprz_random_integer(op, bits);
  ssh_mprz_mod(op, op, modulo);
}

/* Just plain _modular_ random number generation. */
void ssh_mprz_mod_random(SshMPInteger op, SshMPIntegerConst modulo)
{
  unsigned int bits;

  bits = ssh_mprz_bit_size(modulo);
  ssh_mprz_random_integer(op, bits);
  ssh_mprz_mod(op, op, modulo);
}

#ifdef SSHDIST_CRYPT_DSA

/* This is max bitlen of q + 64 bits in octets */
#define FCC_RANDOM_BUFFER_LEN_MAX 40

/* FIPS PUB 186-3 B.1.1 */
SshCryptoStatus
ssh_mp_fips186_ffc_keypair_generation(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger x,
                                      SshMPInteger y)
{
  SshMPIntegerStruct c, temp;
  unsigned char random_buffer[FCC_RANDOM_BUFFER_LEN_MAX];
  size_t random_return_len;
  unsigned int p_bits, q_bits;
  int i;

  p_bits = ssh_mprz_get_size(p, 2);
  q_bits = ssh_mprz_get_size(q, 2);

  /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
  if (!((p_bits == 1024) && (q_bits == 160)) &&
      !((p_bits == 2048) && (q_bits == 224)) &&
      !((p_bits == 2048) && (q_bits == 256)) &&
      !((p_bits == 3072) && (q_bits == 256)))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid prime length pair for p and q (%u,%u)",
                 p_bits, q_bits));
      return SSH_CRYPTO_KEY_INVALID;
    }


  random_return_len = (q_bits / 8) + 8;
  SSH_ASSERT(random_return_len <= FCC_RANDOM_BUFFER_LEN_MAX);

  for (i = 0; i < random_return_len; i++)
    random_buffer[i] = ssh_random_object_get_byte();

  ssh_mprz_init(&c);
  ssh_mprz_init(&temp);

  ssh_mprz_set_buf(&c, random_buffer, random_return_len);

  /* Step 6 */
  ssh_mprz_sub_ui(&temp, q, 1);
  ssh_mprz_mod(x, &c, &temp);
  ssh_mprz_add_ui(x, x, 1);

  /* Step 7 */
  ssh_mprz_powm(y, g, x, p);

  ssh_mprz_clear(&c);
  ssh_mprz_clear(&temp);
  memset(random_buffer, 0x00, FCC_RANDOM_BUFFER_LEN_MAX);

  return SSH_CRYPTO_OK;
}

/* FIPS PUB 186-3 B.2.1 */
SshCryptoStatus
ssh_mp_fips186_ffc_per_message_secret(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger k,
                                      SshMPInteger k_inverse)
{
  SshMPIntegerStruct c, temp;
  unsigned char random_buffer[FCC_RANDOM_BUFFER_LEN_MAX];
  size_t random_return_len;
  unsigned int p_bits, q_bits;
  int i, success;

  p_bits = ssh_mprz_get_size(p, 2);
  q_bits = ssh_mprz_get_size(q, 2);

  /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
  if (!((p_bits == 1024) && (q_bits == 160)) &&
      !((p_bits == 2048) && (q_bits == 224)) &&
      !((p_bits == 2048) && (q_bits == 256)) &&
      !((p_bits == 3072) && (q_bits == 256)))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid prime length pair for p and q (%u,%u)",
                 p_bits, q_bits));
      return SSH_CRYPTO_KEY_INVALID;
    }


  random_return_len = (q_bits / 8) + 8;
  SSH_ASSERT(random_return_len <= FCC_RANDOM_BUFFER_LEN_MAX);

  for (i = 0; i < random_return_len; i++)
    random_buffer[i] = ssh_random_object_get_byte();

  ssh_mprz_init(&c);
  ssh_mprz_init(&temp);

  ssh_mprz_set_buf(&c, random_buffer, random_return_len);

  /* Step 6 */
  ssh_mprz_sub_ui(&temp, q, 1);
  ssh_mprz_mod(k, &c, &temp);
  ssh_mprz_add_ui(k, k, 1);

  /* Step 7 */
  success = ssh_mprz_mod_invert(k_inverse, k, q);

  ssh_mprz_clear(&c);
  ssh_mprz_clear(&temp);
  memset(random_buffer, 0x00, FCC_RANDOM_BUFFER_LEN_MAX);

  if (success)
    return SSH_CRYPTO_OK;
  else
    return SSH_CRYPTO_NO_MEMORY;
}
#endif /* SSHDIST_CRYPT_DSA */

/* Basic modular enhancements. Due the nature of extended euclids algorithm
   it sometimes returns integers that are negative. For our cases positive
   results are better. */

int ssh_mprz_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                      SshMPIntegerConst modulo)
{
  int status;

  status = ssh_mprz_invert(op_dest, op_src, modulo);

  if (ssh_mprz_cmp_ui(op_dest, 0) < 0)
    ssh_mprz_add(op_dest, op_dest, modulo);

  return status;
}
