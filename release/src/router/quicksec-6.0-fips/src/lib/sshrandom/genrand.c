/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"

#define SSH_DEBUG_MODULE "GenRand"

#ifdef SSHDIST_VPNCLIENT
#else
extern const SshRandomDefStruct ssh_random_pool;
#endif /* SSHDIST_VPNCLIENT */
#ifdef SSHDIST_CRYPT_NIST_SP_800_90
extern const SshRandomDefStruct ssh_random_nist_sp_800_90;
#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */

static const SshRandomDefStruct * const ssh_random_algorithms[] = {
#ifdef SSHDIST_CRYPT_NIST_SP_800_90
  &ssh_random_nist_sp_800_90,
#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */
#ifdef SSHDIST_VPNCLIENT
#else
  &ssh_random_pool,
#endif /* SSHDIST_VPNCLIENT */
  NULL
};

/************************************************************************/

static const SshRandomDefStruct *
ssh_random_get_random_def_internal(const char *name)
{
  unsigned int i;

  if (name == NULL)
    return FALSE;

  for (i = 0; ssh_random_algorithms[i] != NULL; i++)
    {
      if (strcmp(ssh_random_algorithms[i]->name, name) == 0)
        return ssh_random_algorithms[i];
    }

  return NULL;
}


/* Return a comma-separated list of supported (P)RNG names. The caller
   must free the returned value with ssh_free() */
char *ssh_random_get_supported(void)
{
  unsigned char *list, *tmp;
  int i;
  size_t offset, list_len;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; ssh_random_algorithms[i] != NULL; i++)
    {
      size_t newsize;

      newsize = offset + 1 + !!offset + strlen(ssh_random_algorithms[i]->name);

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
                             ssh_random_algorithms[i]->name);
    }

  return (char *) list;
}

/* Return TRUE or FALSE dependeing whether the (P)RNG called `name' is
   supported with this version of crypto library (and current fips
   mode). */
Boolean ssh_random_supported(const char *name)
{
  if (ssh_random_get_random_def_internal(name))
    return TRUE;

  return FALSE;
}

/* Allocates and initializes a random number generator
   context. Notice: It is valid to pass NULL as `name': in that case
   some "default" (P)RNG is allocated (however it is guaranteed it is
   FIPS compliant if FIPS mode is enabled). */
SshCryptoStatus
ssh_random_object_allocate(const char *name,
                           SshRandomObject *random_ret)
{
  const SshRandomDefStruct *random_def;
  SshRandomObject random;
  SshCryptoStatus status;

  random_def = ssh_random_get_random_def_internal(name);
  if (!random_def)
    return SSH_CRYPTO_UNSUPPORTED;

  if (!(random = ssh_crypto_malloc_i(sizeof(*random))))
    return SSH_CRYPTO_NO_MEMORY;

  random->ops = random_def;

  if (random->ops->init)
    {
      status = (*random_def->init)(&random->context);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_crypto_free_i(random);
          return status;
        }
    }

  *random_ret = random;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_random_allocate(const char *name,
                    SshRandom *random_ret)
{
  SshRandomObject random = NULL;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  status = ssh_random_object_allocate(name, &random);

  if (status != SSH_CRYPTO_OK)
    return status;

  if (!ssh_crypto_library_object_use(random, SSH_CRYPTO_OBJECT_TYPE_RANDOM))
    {
      ssh_random_object_free(random);
      return SSH_CRYPTO_NO_MEMORY;
    }

  *random_ret = SSH_CRYPTO_RANDOM_TO_HANDLE(random);

  return SSH_CRYPTO_OK;
}

/* Frees a (P)RNG */
void ssh_random_object_free(SshRandomObject random)
{
  if (random->ops->uninit)
    (*random->ops->uninit)(random->context);

  ssh_crypto_free_i(random);
}

/* Frees a (P)RNG */
void ssh_random_free(SshRandom handle)
{
  SshRandomObject random;

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return;

  ssh_crypto_library_object_release(random);
  ssh_random_object_free(random);
}

const char *
ssh_random_object_name(SshRandomObject random)
{
  return random->ops->name;
}


const char *
ssh_random_name(SshRandom handle)
{
  SshRandomObject random;

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return NULL;

  return ssh_random_object_name(random);
}

/* Fill a buffer with bytes from the (P)RNG output */
SshCryptoStatus
ssh_random_object_get_bytes(SshRandomObject random,
                            unsigned char *buf, size_t buflen)
{
  return (*random->ops->get_bytes)(random->context, buf, buflen);
}

/* Fill a buffer with bytes from the (P)RNG output */
SshCryptoStatus
ssh_random_get_bytes(SshRandom handle,
                     unsigned char *buf, size_t buflen)
{
  SshCryptoStatus status;
  SshRandomObject random;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return ssh_random_object_get_bytes(random, buf, buflen);
}



/* Add noise to the RNG */

SshCryptoStatus
ssh_random_object_add_entropy(SshRandomObject random,
                              const unsigned char *buf, size_t buflen,
                              size_t estimated_entropy_bits)
{
  if (random->ops->add_noise == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  return (*random->ops->add_noise)(random->context, buf, buflen,
                                   estimated_entropy_bits);
}

SshCryptoStatus
ssh_random_add_entropy(SshRandom handle,
                       const unsigned char *buf, size_t buflen,
                       size_t estimated_entropy_bits)
{
  SshRandomObject random;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return ssh_random_object_add_entropy(random, buf, buflen,
                                       estimated_entropy_bits);
}
