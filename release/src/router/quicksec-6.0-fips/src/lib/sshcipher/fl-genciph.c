/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshcipher_i.h"

#ifdef SSHDIST_CRYPT_MODE_GCM
#include "mode-gcm.h"
#include "fl-cipher.h"
#endif /* SSHDIST_CRYPT_MODE_GCM */

#ifdef SSHDIST_CRYPT_MODE_CCM
#include "fl-cipher.h"
#endif /* SSHDIST_CRYPT_MODE_CCM */


#ifdef SSHDIST_CRYPT_RIJNDAEL
#include "rijndael.h"
#endif /* SSHDIST_CRYPT_RIJNDAEL */

#include "nociph.h"





#if defined SSHDIST_CRYPT_DES || \
    defined SSHDIST_CRYPT_RIJNDAEL
#include "fl-cipher.h"
#endif /* SSHDIST_CRYPT_DES || SSHDIST_CRYPT_RIJNDAEL */

#ifndef KERNEL
/* These ciphers can only be used in user-mode code, not in the kernel.
   To add a cipher to be used in the kernel, you must add its object
   file to CRYPT_LNOBJS in src/ipsec/engine/Makefile.am, and move it
   outside the #ifndef KERNEL directive both here and later in this file. */

#endif /* !KERNEL */

#define SSH_DEBUG_MODULE "SshGenCiph"

/* Algorithm definitions */
static const SshCipherDefStruct ssh_cipher_algorithms[] = {

#ifdef SSHDIST_CRYPT_DES
  { "3des-ecb",
    8, 8, { 24, 24, 24 }, fl_cipher_des3_ctxsize,
    fl_cipher_des3_init_ecb,  fl_cipher_des3_init_ecb_with_key_check,
    fl_cipher_des3_start_ecb, fl_cipher_des3_transform_ecb,
    fl_cipher_des3_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
  { "3des-cbc",
    8, 8, { 24, 24, 24 }, fl_cipher_des3_ctxsize,
    fl_cipher_des3_init_cbc, fl_cipher_des3_init_cbc_with_key_check,
    fl_cipher_des3_start_cbc, fl_cipher_des3_transform_cbc,
    fl_cipher_des3_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL

  /* AES specifies three key sizes: 128, 192 and 256 bits. We specify
     the min and default as 128 bits, maximum as 256. AES init
     function then verifies that the key length is one of
     128/192/256. */

#define AES_INIT_BASIC(ks_min, ks_def, ks_max, mode) \
  16, 16, { (ks_min), (ks_def), (ks_max) }, fl_cipher_aes_ctxsize, \
  fl_cipher_aes_init_ ## mode, fl_cipher_aes_init_ ## mode, \
  fl_cipher_aes_start_ ## mode, fl_cipher_aes_transform_ ## mode, \
  fl_cipher_aes_uninit, FALSE, 0, \
  NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
#define AES_INIT_FEEDBACK(ks_min, ks_def, ks_max, mode1, mode2) \
  16, 16, { (ks_min), (ks_def), (ks_max) }, ssh_rijndael_ctxsize, \
  ssh_aes_init ## mode1, ssh_aes_init ## mode1, NULL_FNPTR, \
  ssh_rijndael_ ## mode2, ssh_aes_uninit, FALSE, 0, \
  NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
#define AES_INIT_COUNTER(ks_min, ks_def, ks_max, mode1, mode2) \
  1, 16, { (ks_min), (ks_def), (ks_max) }, fl_cipher_aes_ctxsize, \
  fl_cipher_aes_init_ ## mode1, fl_cipher_aes_init_ ## mode1, \
  fl_cipher_aes_start_ ## mode1, fl_cipher_aes_transform_ ## mode2, \
  fl_cipher_aes_uninit, FALSE, 0, \
  NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR

  { "aes-ecb", AES_INIT_BASIC(16, 16, 32, ecb) },
  { "aes128-ecb", AES_INIT_BASIC(16, 16, 16, ecb) },
  { "aes192-ecb", AES_INIT_BASIC(24, 24, 24, ecb) },
  { "aes256-ecb", AES_INIT_BASIC(32, 32, 32, ecb) },
  { "aes-cbc", AES_INIT_BASIC(16, 16, 32, cbc) },
  { "aes128-cbc", AES_INIT_BASIC(16, 16, 16, cbc) },
  { "aes192-cbc", AES_INIT_BASIC(24, 24, 24, cbc) },
  { "aes256-cbc", AES_INIT_BASIC(32, 32, 32, cbc) },
  { "aes-cfb", AES_INIT_FEEDBACK(16, 16, 32, _fb, cfb) },
  { "aes128-cfb", AES_INIT_FEEDBACK(16, 16, 16, _fb, cfb) },
  { "aes192-cfb", AES_INIT_FEEDBACK(24, 24, 24, _fb, cfb) },
  { "aes256-cfb", AES_INIT_FEEDBACK(32, 32, 32, _fb, cfb) },
  { "aes-ofb", AES_INIT_FEEDBACK(16, 16, 32, _fb, ofb) },
  { "aes128-ofb", AES_INIT_FEEDBACK(16, 16, 16, _fb, ofb) },
  { "aes192-ofb", AES_INIT_FEEDBACK(24, 24, 24, _fb, ofb) },
  { "aes256-ofb", AES_INIT_FEEDBACK(32, 32, 32, _fb, ofb) },
  { "aes-ctr", AES_INIT_COUNTER(16, 16, 32, ctr, ctr) },
  { "aes128-ctr", AES_INIT_COUNTER(16, 16, 16, ctr, ctr) },
  { "aes192-ctr", AES_INIT_COUNTER(24, 24, 24, ctr, ctr) },
  { "aes256-ctr", AES_INIT_COUNTER(32, 32, 32, ctr, ctr) },

#ifdef SSHDIST_CRYPT_MODE_GCM
  /* Basic definition of GCM */
  { "aes-gcm",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_16, fl_cipher_aes_gcm_init_16,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 16,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes128-gcm",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_16, fl_cipher_aes_gcm_init_16,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 16,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes192-gcm",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_16, fl_cipher_aes_gcm_init_16,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 16,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes256-gcm",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_16, fl_cipher_aes_gcm_init_16,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 16,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  /* GCM with 8 byte authentication tag */
  { "aes-gcm-8",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_8, fl_cipher_aes_gcm_init_8,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 8,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes128-gcm-8",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_8, fl_cipher_aes_gcm_init_8,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 8,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes192-gcm-8",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_8, fl_cipher_aes_gcm_init_8,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 8,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes256-gcm-8",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_8, fl_cipher_aes_gcm_init_8,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 8,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  /* GCM with 12 byte authentication tag */
  { "aes-gcm-12",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_12, fl_cipher_aes_gcm_init_12,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 12,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes128-gcm-12",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_12, fl_cipher_aes_gcm_init_12,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 12,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes192-gcm-12",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_12, fl_cipher_aes_gcm_init_12,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 12,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  { "aes256-gcm-12",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_12, fl_cipher_aes_gcm_init_12,
    NULL_FNPTR, fl_cipher_aes_gcm_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 12,
    fl_cipher_aes_gcm_start, NULL_FNPTR,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },

  /* GMAC definitions */
#ifdef SSHDIST_FIPSLIB_1_1
  { "gmac-aes",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_gcm_ctxsize,
    fl_cipher_aes_gcm_init_16, fl_cipher_aes_gcm_init_16,
    NULL_FNPTR, fl_cipher_aes_gmac_transform,
    fl_cipher_aes_gcm_uninit,
    TRUE, 16,
    fl_cipher_aes_gmac_start, fl_cipher_aes_gmac_update,
    fl_cipher_aes_gcm_final, fl_cipher_aes_gcm_final_verify, NULL_FNPTR },
#else /* SSHDIST_FIPSLIB_1_1 */
  { "gmac-aes",
    1, 16, { 16, 16, 32 }, ssh_gcm_aes_ctxsize,
    ssh_gcm_aes_init, ssh_gcm_aes_init,
    NULL_FNPTR, ssh_gmac_transform, NULL_FNPTR,
    TRUE, 16,
    ssh_gcm_auth_start, ssh_gcm_update,
    ssh_gcm_final, ssh_gcm_final_verify, NULL_FNPTR },
#endif /* SSHDIST_FIPSLIB_1_1 */
#endif /* SSHDIST_CRYPT_MODE_GCM */

#ifdef SSHDIST_CRYPT_MODE_CCM
  /* Basic definition of CCM */
  { "aes-ccm",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_16, fl_cipher_aes_ccm_init_16,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 16,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes128-ccm",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_16, fl_cipher_aes_ccm_init_16,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 16,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes192-ccm",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_16, fl_cipher_aes_ccm_init_16,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 16,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes256-ccm",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_16, fl_cipher_aes_ccm_init_16,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 16,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  /* CCM with 8 byte authentication tag */
  { "aes-ccm-8",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_8, fl_cipher_aes_ccm_init_8,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 8,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes128-ccm-8",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_8, fl_cipher_aes_ccm_init_8,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 8,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes192-ccm-8",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_8, fl_cipher_aes_ccm_init_8,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 8,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes256-ccm-8",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_8, fl_cipher_aes_ccm_init_8,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 8,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  /* CCM with 12 byte authentication tag */
  { "aes-ccm-12",
    1, 16, { 16, 16, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_12, fl_cipher_aes_ccm_init_12,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 12,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes128-ccm-12",
    1, 16, { 16, 16, 16 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_12, fl_cipher_aes_ccm_init_12,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 12,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes192-ccm-12",
    1, 16, { 24, 24, 24 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_12, fl_cipher_aes_ccm_init_12,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 12,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

  { "aes256-ccm-12",
    1, 16, { 32, 32, 32 }, fl_cipher_aes_ccm_ctxsize,
    fl_cipher_aes_ccm_init_12, fl_cipher_aes_ccm_init_12,
    NULL_FNPTR, fl_cipher_aes_ccm_transform, NULL_FNPTR,
    TRUE, 12,
    fl_cipher_aes_ccm_start, NULL_FNPTR,
    fl_cipher_aes_ccm_final, fl_cipher_aes_ccm_final_verify, NULL_FNPTR },

#endif /* SSHDIST_CRYPT_MODE_CCM */

  /* Rijndael itself is defined in range 128..256 bits, however our
     implementation seems to accept 0 bit keys too. */
  { "rijndael-ecb",
    16, 16, { 0, 16, 32 }, ssh_rijndael_ctxsize,
    ssh_rijndael_init, ssh_rijndael_init,
    NULL_FNPTR, ssh_rijndael_ecb, ssh_rijndael_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
  { "rijndael-cbc",
    16, 16, { 0, 16, 32 }, ssh_rijndael_ctxsize,
    ssh_rijndael_init, ssh_rijndael_init,
    NULL_FNPTR, ssh_rijndael_cbc, ssh_rijndael_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
  { "rijndael-cfb",
    16, 16, { 0, 16, 32 }, ssh_rijndael_ctxsize,
    ssh_rijndael_init_fb, ssh_rijndael_init_fb,
    NULL_FNPTR, ssh_rijndael_cfb, ssh_rijndael_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
  { "rijndael-ofb",
    16, 16, { 0, 16, 32 }, ssh_rijndael_ctxsize,
    ssh_rijndael_init_fb, ssh_rijndael_init_fb,
    NULL_FNPTR, ssh_rijndael_ofb, ssh_rijndael_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },
  { "rijndael-ctr",
    16, 16, { 0, 16, 32 }, ssh_rijndael_ctxsize,
    ssh_rijndael_init_fb, ssh_rijndael_init_fb,
    NULL_FNPTR, ssh_rijndael_ctr, ssh_rijndael_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },

#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifndef KERNEL
  /* The ciphers below can only be used in user-level code.  See
     the comments above for adding ciphers to the kernel. */

#endif /* !KERNEL */

  { "none",
    1, 1, { 0, 0, 0 }, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR,
    NULL_FNPTR, ssh_none_cipher, NULL_FNPTR,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR },

  { NULL }
  };


typedef struct SshCipherObjectRec {
  SSH_CRYPTO_OBJECT_HEADER
  const SshCipherDefStruct *ops;
  unsigned char iv[SSH_CIPHER_MAX_IV_SIZE];
  void *context;
  size_t context_size;
} SshCipherObjectStruct;


/* Get corresponding cipher def record by cipher name */
const SshCipherDefStruct *
ssh_cipher_get_cipher_def_internal(const char *name)
{
  int i;

  if (name == NULL)
    return NULL;

  for (i = 0; ssh_cipher_algorithms[i].name; i++)
    {
      if (strcmp(ssh_cipher_algorithms[i].name, name) == 0)
        return &(ssh_cipher_algorithms[i]);
    }

  return NULL;
}

/* Check if given cipher name belongs to the set of supported ciphers
   aliases included. */

Boolean
ssh_cipher_supported(const char *name)
{
  if (ssh_cipher_get_cipher_def_internal(name) != NULL)
    return TRUE;

  return FALSE;
}

/* Return a comma-separated list of supported cipher algorithm names
   alias names included. */

char *
ssh_cipher_get_supported(void)
{
  int i;
  unsigned char *list, *tmp;
  size_t offset, list_len;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; ssh_cipher_algorithms[i].name != NULL; i++)
    {
      size_t newsize;

      newsize = offset + 1 + !!offset + strlen(ssh_cipher_algorithms[i].name);

      if (list_len < newsize)
        {
          newsize *= 2;

          if ((tmp = ssh_realloc(list, list_len, newsize)) == NULL)
            {
              ssh_free(list);
              return NULL;
            }

          list = tmp;
          list_len = newsize;
        }

      SSH_ASSERT(list_len > 0);
      SSH_ASSERT(list != NULL);

      offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                             offset ? "," : "",
                             ssh_cipher_algorithms[i].name);

    }

  return (char *) list;
}

/* The following function checks whether a cipher is a variable-length
   cipher or not. It returns TRUE if the cipher corresponding to 'name'
   has a fixed key length (i.e. the cipher is not a variable-length cipher)
   and returns FALSE otherwise. */
Boolean ssh_cipher_has_fixed_key_length(const char *name)
{
  if (!ssh_cipher_supported(name))
    return FALSE;

  if ((ssh_cipher_get_min_key_length(name) ==
       ssh_cipher_get_max_key_length(name)) &&
      (ssh_cipher_get_min_key_length(name) != 0))
    return TRUE;

  return FALSE;
}

/* Allocates and initializes a cipher of the specified name. */

SshCryptoStatus
ssh_cipher_object_allocate(const char *name,
                           const unsigned char *key,
                           size_t keylen,
                           Boolean for_encryption,
                           SshCipherObject *cipher_ret)
{
  const SshCipherDefStruct *cipher_def;
  SshCryptoStatus status;
  SshCipherObject cipher;

  *cipher_ret = NULL;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  /* min<max && (def<max || max == 0) && min <= def */
  SSH_ASSERT(cipher_def->key_lengths.min_key_len
             <= cipher_def->key_lengths.def_key_len);
  SSH_ASSERT(cipher_def->key_lengths.min_key_len
             <= cipher_def->key_lengths.max_key_len);
  SSH_ASSERT(cipher_def->key_lengths.max_key_len == 0 ||
             (cipher_def->key_lengths.def_key_len <=
              cipher_def->key_lengths.max_key_len));

  /* Check for error in key expansion. No keys shorter than the key length
     of the cipher is allowed. Longer are allowed, but only the first
     bytes are used. */
  if (keylen < cipher_def->key_lengths.min_key_len)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  if (keylen > cipher_def->key_lengths.max_key_len)
    return SSH_CRYPTO_KEY_TOO_LONG;

  /* Initialize the cipher. */
  if (!(cipher = ssh_crypto_malloc_i(sizeof(*cipher))))
    return SSH_CRYPTO_NO_MEMORY;

  /* Set up the cipher definition. */
  cipher->ops = cipher_def;
  /* Clean the IV. */
  memset(cipher->iv, 0, sizeof(cipher->iv));

  /* The "ctxsize" can be NULL if and only if the cipher is the none cipher. */
  if (cipher_def->ctxsize)
    {
      cipher->context_size = (*cipher_def->ctxsize)();

      /* Allocate the context of the cipher. */
      if (!(cipher->context = ssh_crypto_malloc_i(cipher->context_size)))
        {
          ssh_crypto_free_i(cipher);

          return SSH_CRYPTO_NO_MEMORY;
        }
    }
  else
    {
      cipher->context_size = 0;
      cipher->context = NULL;
    }

  if (cipher_def->init_with_check)
    {
      /* Initialize the cipher with a weak key check performed first.
         Not all ciphers have key classes that are easy or practical to
         test for. For those ciphers this function may perform
         as the plain initialization. */
      status = (*cipher_def->init_with_check)(cipher->context,
                                              key, keylen, for_encryption);
    }
  else if (cipher_def->init)
    {
      /* Initialize the cipher without weak key checks. */
      status = (*cipher_def->init)(cipher->context,
                                   key, keylen, for_encryption);
    }
  else
    status = SSH_CRYPTO_OK;

  if (status != SSH_CRYPTO_OK)
    {
      ssh_crypto_free_i(cipher->context);
      ssh_crypto_free_i(cipher);
      return status;
    }

  *cipher_ret = cipher;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_cipher_allocate(const char *name,
                    const unsigned char *key,
                    size_t keylen,
                    Boolean for_encryption,
                    SshCipher *cipher_ret)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  *cipher_ret = NULL;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  status = ssh_cipher_object_allocate(name, key, keylen, for_encryption,
                                      &cipher);

  if (status != SSH_CRYPTO_OK)
    return status;

  /* Add a handle ref to the current state */
  if (!ssh_crypto_library_object_use(cipher, SSH_CRYPTO_OBJECT_TYPE_CIPHER))
    {
      ssh_cipher_object_free(cipher);
      return SSH_CRYPTO_NO_MEMORY;
    }

  *cipher_ret = SSH_CRYPTO_CIPHER_TO_HANDLE(cipher);
  return SSH_CRYPTO_OK;
}

/* Free the cipher context */
void
ssh_cipher_object_free(SshCipherObject cipher)
{
  if (!cipher)
    return;

  if (cipher->ops->uninit)
    (*cipher->ops->uninit)(cipher->context);

  ssh_crypto_free_i(cipher->context);
  ssh_crypto_free_i(cipher);
}


void
ssh_cipher_free(SshCipher handle)
{
  SshCipherObject cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle);

  if (!cipher)
    return;

  /* Release cipher object */
  ssh_crypto_library_object_release(cipher);

  ssh_cipher_object_free(cipher);
}

const char *
ssh_cipher_name(SshCipher handle)
{
  SshCipherObject cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle);

  if (!cipher)
    return NULL;

  return cipher->ops->name;
}

size_t
ssh_cipher_get_key_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return 0;

  if (strcmp(name, "none") != 0)
    SSH_ASSERT(cipher_def->key_lengths.def_key_len != 0);

  return cipher_def->key_lengths.def_key_len;
}

size_t
ssh_cipher_get_min_key_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->key_lengths.min_key_len;
}

size_t
ssh_cipher_get_max_key_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->key_lengths.max_key_len;
}

size_t
ssh_cipher_get_block_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->block_length;
}

size_t
ssh_cipher_get_iv_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->iv_length;
}

SshCryptoStatus
ssh_cipher_set_iv(SshCipher handle, const unsigned char *iv)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  memcpy(cipher->iv, iv, cipher->ops->iv_length);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_cipher_start(SshCipher handle)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (cipher->ops->is_auth_cipher)
    return SSH_CRYPTO_UNSUPPORTED;

  if (cipher->ops->start && cipher->context)
    (*cipher->ops->start)(cipher->context, cipher->iv);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_cipher_transform(SshCipher handle,
                     unsigned char *dest,
                     const unsigned char *src,
                     size_t len)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  /* Check that the src length is divisible by block length of the cipher. */
  if (len % cipher->ops->block_length == 0)
    (*cipher->ops->transform)(cipher->context, dest, src, len);
  else
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_cipher_transform_remaining(SshCipher handle,
                               unsigned char *dest,
                               const unsigned char *src,
                               size_t len)
{
  unsigned char tmp[ SSH_CIPHER_MAX_BLOCK_SIZE ];
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  /* Check that the src length is divisible by block length of the cipher. */
  if ((len <= cipher->ops->block_length || cipher->ops->block_length == 1) &&
      len < sizeof(tmp))
    {
      (*cipher->ops->transform)(cipher->context, tmp, src, len);
      memcpy(dest, tmp, len);
    }
  else
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  return SSH_CRYPTO_OK;
}


Boolean ssh_cipher_is_auth_cipher(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return FALSE;

  return cipher_def->is_auth_cipher;
}


SshCryptoStatus
ssh_cipher_auth_start(SshCipher handle,
                      const unsigned char *aad,
                      size_t aad_len,
                      size_t crypt_len)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;;

  if (!cipher->ops->is_auth_cipher)
    return SSH_CRYPTO_UNSUPPORTED;

  return (*cipher->ops->auth_start)
              (cipher->context, cipher->iv, aad, aad_len, crypt_len);
}

SshCryptoStatus
ssh_cipher_auth_continue(SshCipher handle,
                        const unsigned char *data,
                        size_t len)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (!cipher->ops->is_auth_cipher)
    return SSH_CRYPTO_UNSUPPORTED;

  if (!cipher->ops->update)
    return SSH_CRYPTO_INVALID_OPERATION;

  (*cipher->ops->update)(cipher->context, data, len);

  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_cipher_auth_final(SshCipher handle, unsigned char *digest)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (!cipher->ops->is_auth_cipher)
    return SSH_CRYPTO_UNSUPPORTED;

  (*cipher->ops->final)(cipher->context, digest);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_cipher_auth_final_verify(SshCipher handle, unsigned char *digest)
{
  SshCryptoStatus status;
  SshCipherObject cipher;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(cipher = SSH_CRYPTO_HANDLE_TO_CIPHER(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (!cipher->ops->is_auth_cipher)
    return SSH_CRYPTO_UNSUPPORTED;

  if (cipher->ops->final_verify)
    return (*cipher->ops->final_verify)(cipher->context, digest);
  else
    return SSH_CRYPTO_UNSUPPORTED;
}

size_t
ssh_cipher_auth_digest_length(const char *name)
{
  const SshCipherDefStruct *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  if (!cipher_def->is_auth_cipher)
    return -1;

  return cipher_def->digest_length;
}
