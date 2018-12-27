/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface code for public key cryptosystems.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"

#define SSH_DEBUG_MODULE "SshCryptoGenpkcs"

/************************************************************************/

SSH_GLOBAL_DEFINE_INIT(SshPkTypeConstPtrArray, ssh_pk_type_slots) =
{
  NULL, /* ... continued to the end. */
};

SshCryptoStatus
ssh_pk_provider_register(const SshPkType *type)
{
  int i;

  if (type == NULL)
    return SSH_CRYPTO_OPERATION_FAILED;

  for (i = 0; i < SSH_PK_TYPE_MAX_SLOTS; i++)
    {
      if (ssh_pk_type_slots[i] == NULL)
        {
          /* Empty slot detected. */
          ssh_pk_type_slots[i] = type;
          return SSH_CRYPTO_OK;
        }

      if (ssh_pk_type_slots[i] == type)
        /* Same type added already. */
        return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_PROVIDER_SLOTS_EXHAUSTED;
}

/* Search from action list an entry with the given format and
   that has at least 'flags' on. */
const SshPkAction *ssh_pk_find_action(const SshPkAction *list,
                                      SshPkFormat format,
                                      SshPkActionFlag flags)
{
  unsigned int i;

  for (i = 0; list[i].format != SSH_PKF_END; i++)
    {
      /* Check whether the format and flags match. */
      if (list[i].format == format && (list[i].flags & flags) == flags)
        {
          /* Found a correct match (because they are assumed to be unique
             this must be correct). */
          return &list[i];
        }
    }
  /* Failed to find a match. */
  return NULL;
}



/****** Functions for getting and setting the scheme information. *********/


/* Returns a pointer to the scheme in type characterized by format
   and with name scheme_name. We treat the signature, encryption and
   diffie-hellman scheme seperately, rather than a generic approach using
   void pointers. We are assuming that the number of schemes will in the
   future stay small, and this seems likely. */
void * ssh_pk_find_scheme(const SshPkType *type,
                          SshPkFormat format,
                          const char *scheme_name)

{
  unsigned int i;

  if (type == NULL || scheme_name == NULL)
    return NULL;

  if (format == SSH_PKF_SIGN && type->signature_list)
    {
      for (i = 0; type->signature_list[i].name != NULL; i++)
        {
          if (strcmp(type->signature_list[i].name, scheme_name) == 0)
            return (void *) &type->signature_list[i];
        }
    }

  if (format == SSH_PKF_ENCRYPT && type->encryption_list)
    {
      for (i = 0; type->encryption_list[i].name; i++)
        {
          if (strcmp(type->encryption_list[i].name, scheme_name) == 0)
            return (void *) &type->encryption_list[i];
        }
    }

  if (format == SSH_PKF_DH && type->diffie_hellman_list)
    {
      for (i = 0; type->diffie_hellman_list[i].name; i++)
        {
          if (strcmp(type->diffie_hellman_list[i].name, scheme_name) == 0)
            return (void *) &type->diffie_hellman_list[i];
        }
    }

  return NULL;
}


/* Parse key_name to return the scheme name corresponding to to
   scheme_class, the caller shall free this. key_name should be in the
   form of a valid key name, namely a{b{c},d{e},f{g,h,i},j,...,m{n}}.
   a is the key type, the pairs b and c in b{c} are the
   scheme classes and scheme names respectively. The scheme
   name can be optionally omitted, e.g. h, in the above example
   When the scheme_class contains multiple scheme names, the first
   scheme name found is returned, e.g. in f{g,h,i} in the above example
   the string g is returned if called with scheme_class set to f.

   Failure on memory allocation is treated as key name being invalid -
   e.g. NULL is returned. */
char * ssh_pk_get_scheme_name(const char *key_name,
                              const char *scheme_class)
{
  char *ptr, *start, *str = NULL;
  size_t len = 0;

  /* Search for the string scheme_class in key_name. */
  ptr = (char *)(strstr(key_name, scheme_class));

  if (ptr)
    {
      ptr += strlen(scheme_class);

      /* Invalid key name */
      if (*ptr == '\0' || strchr(ptr, '}') == NULL)
        return NULL;

     if (*ptr != '{')
       return ssh_strdup(SSH_PK_USUAL_NAME);

     /* Step over the '{' character */
     ptr++;
     start = ptr;
     while (*ptr != '}' && *ptr != ',')
       ptr++, len++;

     if ((str = ssh_malloc(len + 1)) != NULL)
       {
         memcpy(str, start, len);
         str[len] = '\0';
       }
    }

  return str;
}

/* Returns a mallocated string describing the key-type (e.g. "if-modn" or
   "dl-modp") from the key name.  The key name is assumed to be of the form
   key-type{scheme-type1{algorithm-name1},scheme-type2{algorithm-name2},...}
   This function will then return the string key-type.
*/
char * ssh_pk_get_key_type(const char *key_name)
{
  const char *c;
  char *str;
  size_t len = 0;

  if (!strstr(key_name, "{"))
    return ssh_strdup(key_name);

  for (c = key_name; *c != '{'; c++)
    len++;

  if ((str = (char *) ssh_malloc(len + 1)) == NULL)
    return NULL;

  memcpy(str, key_name, len);
  str[len] = '\0';

  return str;
}
