/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the cipher aliases interface.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "SshCipherAlias"

/* Mapping from common cipher names to `canonical' ones. */
struct SshCipherAliasRec {
  const char *name;
  const char *real_name;
};

/* Common cipher names. */
const struct SshCipherAliasRec ssh_cipher_aliases[] =
{
#ifdef SSHDIST_CRYPT_DES
  { "des", "des-cbc" },
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_DES
  { "3des", "3des-cbc" },
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_RIJNDAEL
  { "rijndael", "rijndael-cbc" },
  { "aes", "aes-cbc" },
  { "aes128", "aes-cbc" },
  { "aes192", "aes-cbc" },
  { "aes256", "aes-cbc" },
  { "aes128-cbc", "aes-cbc" },
  { "aes192-cbc", "aes-cbc" },
  { "aes256-cbc", "aes-cbc" },
#endif /* SSHDIST_CRYPT_RIJNDAEL */
  { NULL, NULL }
};

/* Return a list of ciphers, including native names and aliases. The
   caller must free the returned string with ssh_free. Can return NULL
   on memory allocation failure (if no ciphers are supported, then
   just an empty string is returned). */
char *ssh_cipher_alias_get_supported(void)
{
  int i;
  unsigned char *list, *tmp;
  size_t offset, list_len;

  list = ssh_ustr(ssh_cipher_get_supported());

  if (!list)
    return NULL;

  tmp = ssh_strdup(list);

  if (!tmp)
    return NULL;

  list = tmp;
  offset = ssh_ustrlen(list);
  list_len = offset + 1;

  for (i = 0; ssh_cipher_aliases[i].name != NULL; i++)
    {
      size_t newsize;

      /* It is possible that our alias list has ciphers which are not
         supported by the crypto core */
      if (!ssh_cipher_supported(ssh_cipher_aliases[i].real_name))
        continue;

      newsize = offset + 1 + !!offset + strlen(ssh_cipher_aliases[i].name);

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
                             ssh_cipher_aliases[i].name);

    }

  return (char *) list;
}

/* Is the cipher supported. Takes aliases into account, eg. both alias
   and the native name will return TRUE if they are supported. */
Boolean ssh_cipher_alias_supported(const char *name)
{
  int i;

  if (ssh_cipher_supported(name))
    return TRUE;

  for (i = 0; ssh_cipher_aliases[i].name != NULL; i++)
    if (strcmp(ssh_cipher_aliases[i].name, name) == 0)
      if (ssh_cipher_supported(ssh_cipher_aliases[i].real_name))
        return TRUE;

  return FALSE;
}

/* Return the native name of a cipher alias. If given native name,
   returns the native name. The returned value is static or the passed
   argument, and must not be modified or freed. Returns NULL if cipher
   `name' is not supported.

   Clarification: The returned value MAY be the same as what was
   passed as an argument. What this means that the following might be
   incorrect:

        char * x = ssh_strdup("des");
        char * y = ssh_cipher_alias_get_native(x);
        ssh_free(x);
        SshCipher z = ssh_cipher_allocate(y, ...);

   since after ssh_cipher_alias_get_native x could be equal to y, and
   after ssh_free(x) y would also be invalid. You should not modify x
   or invalidate it until after there is no need for y, or strdup y
   explicitly. */
const char *ssh_cipher_alias_get_native(const char *name)
{
  int i;

  if (ssh_cipher_supported(name))
    return name;

  for (i = 0; ssh_cipher_aliases[i].name != NULL; i++)
    if (strcmp(ssh_cipher_aliases[i].name, name) == 0)
      if (ssh_cipher_supported(ssh_cipher_aliases[i].real_name))
        return ssh_cipher_aliases[i].real_name;

  return NULL;
}
