/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface code for public key groups.
*/

#include "sshincludes.h"
#include "sshdsprintf.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"
#include "sshrandom_i.h"
#ifdef SSHDIST_CRYPT_SELF_TESTS
#include "crypto_tests.h"
#endif /* SSHDIST_CRYPT_SELF_TESTS */

#define SSH_DEBUG_MODULE "SshCryptoPKGroup"

void ssh_pk_group_object_free(SshPkGroupObject group);

/* Generate the full name of a particular pk group. */
char *ssh_pk_group_object_name(SshPkGroupObject group)
{
  unsigned char *str = NULL;

  if (group->diffie_hellman == NULL_FNPTR)
    ssh_dsprintf(&str, "%s", group->type->name);
  else
    ssh_dsprintf(&str, "%s{dh{%s}}", group->type->name,
                 group->diffie_hellman->name);

  return (char *) str;
}

/* Generate the full name of a particular pk group. */
char *ssh_pk_group_name(SshPkGroup handle)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return NULL;

  return ssh_pk_group_object_name(group);
}

SshCryptoStatus
ssh_pk_group_set_scheme(SshPkGroupObject group,
                        SshPkFormat format, const char *scheme)
{
  void *scheme_ptr;

  scheme_ptr = ssh_pk_find_scheme(group->type, format, scheme);

  if (!scheme && scheme_ptr)
    return SSH_CRYPTO_SCHEME_UNKNOWN;

  /* Set the corresponding scheme. */
  switch (format)
    {
    case SSH_PKF_SIGN:
    case SSH_PKF_ENCRYPT:
      /* Lets just ignore these, not considered errorneous. Main reason for
         this is the fact that some of these might want to add some
         information to the action_make context and we don't want to
         restrict that. */
      break;
    case SSH_PKF_DH:
      group->diffie_hellman = scheme_ptr;
      break;
    default:
      return SSH_CRYPTO_SCHEME_UNKNOWN;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Set the scheme of the pk group from  key_name. This is called
   when generating or importing pk groups. */
SshCryptoStatus
ssh_pk_group_set_scheme_from_key_name(SshPkGroupObject group,
                                      const char *key_name)
{
  char *scheme_name;
  SshCryptoStatus status;

  if ((scheme_name = ssh_pk_get_scheme_name(key_name, "dh")) != NULL)
    {
      status = ssh_pk_group_set_scheme(group, SSH_PKF_DH, scheme_name);
      ssh_free(scheme_name);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_pk_group_select_scheme(SshPkGroup handle, ...)
{
  SshPkFormat format;
  const char *scheme;
  va_list ap;
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (group->type == NULL)
    return SSH_CRYPTO_KEY_UNINITIALIZED;

  va_start(ap, handle);

  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      scheme = va_arg(ap, const char *);
      if (ssh_pk_group_set_scheme(group, format, scheme) != SSH_CRYPTO_OK)
        {
          va_end(ap);
          return SSH_CRYPTO_SCHEME_UNKNOWN;
        }
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

const char * ssh_pk_group_find_default_scheme(SshPkGroupObject group,
                                              SshPkFormat format)
{
  const SshPkType *type = group->type;

  if (type == NULL)
    return NULL;

  if (format == SSH_PKF_DH && type->diffie_hellman_list)
    return type->diffie_hellman_list[0].name;

  return NULL;

}


SshCryptoStatus ssh_pk_group_get_scheme_name(SshPkGroupObject group,
                                             SshPkFormat format,
                                             const char **name)
{
  switch (format)
    {
    case SSH_PKF_DH:
      if (group->diffie_hellman)
        *name = group->diffie_hellman->name;
      else
        *name = NULL;
      break;
    default:
      return SSH_CRYPTO_SCHEME_UNKNOWN;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Function to retrieve a comma separated list of supported predefined
   groups for this particular key type. */
char *
ssh_public_key_get_predefined_groups(const char *key_type)
{
  char *tmp;
  unsigned int i;

  /* Get the key type. */
  if ((tmp = ssh_pk_get_key_type(key_type)) == NULL)
    return NULL;

  for (i = 0; ssh_pk_type_slots[i] && ssh_pk_type_slots[i]->name; i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, tmp) == 0)
        {
          if (ssh_pk_type_slots[i]->pk_group_get_predefined_groups
              != NULL_FNPTR)
            {
              ssh_free(tmp);
              return (*ssh_pk_type_slots[i]->pk_group_get_predefined_groups)();
            }
        }
    }
  ssh_free(tmp);
  return NULL;
}

/* Parameter functions named here as ssh pk group (standing for
   ssh public key group). Function to generate the pk group object. This
   is needed in the power up tests. Note that this does NOT perform the
   group consistency test (the function ssh_crypto_test_pk_group) */
SshCryptoStatus
ssh_pk_group_object_generate(SshPkGroupObject *group_ret,
                             const char *group_type, ...)
{

  SshCryptoStatus status;
  unsigned int i;
  const SshPkAction *action;
  SshPkGroupObject pk_group;
  void *context = NULL;
  SshPkFormat format;
  const char *name, *r;
  char consumed[128], *tmp;
  va_list ap;

  /* Get the key type (i.e. strip the scheme information from group_type). */
  if ((tmp = ssh_pk_get_key_type(group_type)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  for (i = 0;
       ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name;
       i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, tmp) != 0)
        continue;
      ssh_free(tmp);
      tmp = NULL;

      /* Type matches i.e. we've found our key type, so continue with
         finding schemes and parameters. */

      /* Allocate group context. */
      if ((pk_group = ssh_malloc(sizeof(*pk_group))) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      pk_group->type = ssh_pk_type_slots[i];
      pk_group->diffie_hellman = NULL;

      status = (*pk_group->type->pk_group_action_init)(&context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(pk_group);
          return status;
        }

      /* Run through all preselected schemes in the group_type. */
      status = ssh_pk_group_set_scheme_from_key_name(pk_group, group_type);

      if (status != SSH_CRYPTO_OK)
        {
          if (pk_group != NULL)
            {
              (*pk_group->type->pk_group_action_free)(context);
              ssh_free(pk_group);
            }
          return status;
        }

      /* Start reading the vararg list. */
      consumed[0] = '\000';
      while (TRUE)
        {
          va_start(ap, group_type);
          PROCESS(ap, consumed);

          format = va_arg(ap, SshPkFormat);
          strcat(consumed, "i");
          if (format == SSH_PKF_END)
            break;

          /* If the va list contains scheme parameters, we need to
             set the scheme again. */
          if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
              format == SSH_PKF_DH)
            {
              name = va_arg(ap, const char *);
              strcat(consumed, "p");
              status = ssh_pk_group_set_scheme(pk_group, format, name);

              if (status != SSH_CRYPTO_OK)
                {
                  (*pk_group->type->pk_group_action_free)(context);
                  ssh_free(pk_group);
                  va_end(ap);
                  return status;
                }
              va_end(ap);
              continue;
            }

          /* Search name from command lists. */
          action = ssh_pk_find_action(pk_group->type->action_list,
                                      format, SSH_PK_ACTION_FLAG_PK_GROUP);
          if (!action)
            {
              /* Free the action context. */
              (*pk_group->type->pk_group_action_free)(context);
              ssh_free(pk_group);
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
            }

          /* Supported only scheme selection and special operations. */
          switch (action->flags & SSH_PK_ACTION_FLAG_GET_PUT)
            {
            case SSH_PK_ACTION_FLAG_GET_PUT:
              r = (*action->action_put)(context, ap, NULL, format);

              if (r == NULL ||
                  (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
                {
                  (*pk_group->type->pk_group_action_free)(context);
                  ssh_free(pk_group);
                  va_end(ap);
                  return SSH_CRYPTO_INTERNAL_ERROR;
                }
              else
                strcat(consumed, r);
              break;
            default:
              ssh_fatal("ssh_pk_group_generate: internal error.");
              break;
            }
          va_end(ap);
        }

      /* Make the key and remove context. (One could incorporate making
         and freeing, however this way things seem to work also). */
      status =
        (*pk_group->type->pk_group_action_make)(context, &pk_group->context);
      (*pk_group->type->pk_group_action_free)(context);

      /* Quit unhappily. */
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(pk_group);
          va_end(ap);
          return status;
        }

      /* Set the address of the group into its context. */
      if (pk_group->type->set_key_pointer_to_context)
        {
          status =
            (*pk_group->type->set_key_pointer_to_context)(pk_group,
                                                          pk_group->context);
          if (status != SSH_CRYPTO_OK)
            {
              ssh_free(pk_group);
              va_end(ap);
              return status;
            }
        }

      /* Quit happily. */
      *group_ret = pk_group;
      va_end(ap);

      return SSH_CRYPTO_OK;
    }

  ssh_free(tmp);
  va_end(ap);

  return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
}


/* Parameter functions named here as ssh pk group (standing for
   ssh public key group). Unfortunately dues to the use of the va arg
   we need to duplicate the almost identical ssh_pk_group_object_generate
   function here.
*/
SshCryptoStatus
ssh_pk_group_generate(SshPkGroup *group_ret,
                      const char *group_type, ...)
{
  SshCryptoStatus status;
  unsigned int i;
  const SshPkAction *action;
  SshPkGroupObject pk_group;
  void *context = NULL;
  SshPkFormat format;
  const char *name, *r;
  char consumed[128], *tmp;
  va_list ap;
  SshPkGroup group;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  /* Get the key type (i.e. strip the scheme information from group_type). */
  if ((tmp = ssh_pk_get_key_type(group_type)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  for (i = 0;
       ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name;
       i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, tmp) != 0)
        continue;
      ssh_free(tmp);
      tmp = NULL;

      /* Type matches i.e. we've found our key type, so continue with
         finding schemes and parameters. */

      /* Allocate group context. */
      if ((pk_group = ssh_malloc(sizeof(*pk_group))) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      pk_group->type = ssh_pk_type_slots[i];
      pk_group->diffie_hellman = NULL;

      status = (*pk_group->type->pk_group_action_init)(&context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(pk_group);
          return status;
        }

      /* Run through all preselected schemes in the group_type. */
      status = ssh_pk_group_set_scheme_from_key_name(pk_group, group_type);

      if (status != SSH_CRYPTO_OK)
        {
          if (pk_group != NULL)
            {
              (*pk_group->type->pk_group_action_free)(context);
              ssh_free(pk_group);
            }
          return status;
        }

      /* Start reading the vararg list. */
      consumed[0] = '\000';
      while (TRUE)
        {
          va_start(ap, group_type);
          PROCESS(ap, consumed);

          format = va_arg(ap, SshPkFormat);
          strcat(consumed, "i");
          if (format == SSH_PKF_END)
            break;

          /* If the va list contains scheme parameters, we need to
             set the scheme again. */
          if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
              format == SSH_PKF_DH)
            {
              name = va_arg(ap, const char *);
              strcat(consumed, "p");
              status = ssh_pk_group_set_scheme(pk_group, format, name);

              if (status != SSH_CRYPTO_OK)
                {
                  (*pk_group->type->pk_group_action_free)(context);
                  ssh_free(pk_group);
                  va_end(ap);
                  return status;
                }
              va_end(ap);
              continue;
            }

          /* Search name from command lists. */
          action = ssh_pk_find_action(pk_group->type->action_list,
                                      format, SSH_PK_ACTION_FLAG_PK_GROUP);
          if (!action)
            {
              /* Free the action context. */
              (*pk_group->type->pk_group_action_free)(context);
              ssh_free(pk_group);
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
            }

          /* Supported only scheme selection and special operations. */
          switch (action->flags & SSH_PK_ACTION_FLAG_GET_PUT)
            {
            case SSH_PK_ACTION_FLAG_GET_PUT:
              r = (*action->action_put)(context, ap, NULL, format);

              if (r == NULL ||
                  (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
                {
                  (*pk_group->type->pk_group_action_free)(context);
                  ssh_free(pk_group);
                  va_end(ap);
                  return SSH_CRYPTO_INTERNAL_ERROR;
                }
              else
                strcat(consumed, r);
              break;
            default:
              ssh_fatal("ssh_pk_group_generate: internal error.");
              break;
            }
          va_end(ap);
        }

      /* Make the key and remove context. (One could incorporate making
         and freeing, however this way things seem to work also). */
      status =
        (*pk_group->type->pk_group_action_make)(context, &pk_group->context);
      (*pk_group->type->pk_group_action_free)(context);

      /* Quit unhappily. */
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(pk_group);
          va_end(ap);
          return status;
        }

      /* Set the address of the group into its context. */
      if (pk_group->type->set_key_pointer_to_context)
        {
          status =
            (*pk_group->type->set_key_pointer_to_context)(pk_group,
                                                          pk_group->context);
          if (status != SSH_CRYPTO_OK)
            {
              ssh_free(pk_group);
              va_end(ap);
              return status;
            }
        }
#ifdef SSHDIST_CRYPT_GENPKCS_DH
#ifdef SSHDIST_CRYPT_SELF_TESTS
      status = ssh_crypto_test_pk_group(pk_group);

      if (status == SSH_CRYPTO_NO_MEMORY)
        {
          ssh_pk_group_object_free(pk_group);
          va_end(ap);
          return SSH_CRYPTO_NO_MEMORY;
        }
      else if (status != SSH_CRYPTO_OK)
        {
          ssh_pk_group_object_free(pk_group);
          va_end(ap);
          ssh_crypto_library_error(SSH_CRYPTO_ERROR_GROUP_TEST_FAILURE);
          return SSH_CRYPTO_LIBRARY_ERROR;
        }
#endif /* SSHDIST_CRYPT_SELF_TESTS */
#endif /* SSHDIST_CRYPT_GENPKCS_DH */

      if (!ssh_crypto_library_object_use(pk_group,
                                         SSH_CRYPTO_OBJECT_TYPE_PK_GROUP))
        {
          ssh_free(pk_group);
          return SSH_CRYPTO_NO_MEMORY;
        }

      group = SSH_CRYPTO_PK_GROUP_TO_HANDLE(pk_group);

      /* Quit happily. */
      *group_ret = group;
      va_end(ap);

      return SSH_CRYPTO_OK;
    }

  ssh_free(tmp);
  va_end(ap);

  return SSH_CRYPTO_UNKNOWN_GROUP_TYPE;
}

/* Doing copy of the group_src, so that both groups can be altered without
   affecting the other. Note, that although groups might seem to be totally
   separate some features might be implemeted with reference counting. */
SshCryptoStatus
ssh_pk_group_object_copy(SshPkGroupObject group_src,
                         SshPkGroupObject *group_dest)
{
  SshPkGroupObject created;
  SshCryptoStatus status;

  /* check that the copy function is defined */
  if (group_src->type->pk_group_copy == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  /* create a new group */
  if ((created = ssh_malloc(sizeof(*created))) != NULL)
    {
      /* First copy all basic internal stuff and then
         the context explicitly. */
      memcpy(created, group_src, sizeof(*created));
      status = (*group_src->type->pk_group_copy)(group_src->context,
                                                 &created->context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(created);
          return status;
        }

      /* Set the address of the copied group into its context. */
      if (group_src->type->set_key_pointer_to_context)
        {
          status =
            (*group_src->type->set_key_pointer_to_context)(created,
                                                           created->context);
          if (status != SSH_CRYPTO_OK)
            {
              ssh_pk_group_object_free(created);
              return status;
            }
        }

      *group_dest = created;
      return SSH_CRYPTO_OK;
    }
  else
    return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_pk_group_copy(SshPkGroup handle_src, SshPkGroup *group_dest)
{
  SshPkGroupObject created, group_src;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(group_src = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle_src)))
    return SSH_CRYPTO_HANDLE_INVALID;

  status = ssh_pk_group_object_copy(group_src, &created);

  if (status != SSH_CRYPTO_OK)
    return status;

  if (!ssh_crypto_library_object_use(created,
                                     SSH_CRYPTO_OBJECT_TYPE_PK_GROUP))
    {
      ssh_pk_group_object_free(created);
      return SSH_CRYPTO_NO_MEMORY;
    }

  *group_dest = SSH_CRYPTO_PK_GROUP_TO_HANDLE(created);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_pk_group_object_allocate(const char *type, SshPkGroupObject *key)
{
  SshPkGroupObject pk_group;
  char *name;
  int i;

  /* Get the key type (i.e. strip the scheme information from key_type). */
  if (!(name = ssh_pk_get_key_type(type)))
    return SSH_CRYPTO_NO_MEMORY;

  /* Find correct key type. */
  for (i = 0, pk_group = NULL;
       ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name;
       i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, name) == 0)
        {
          /* Allocate. */
          if ((pk_group = ssh_calloc(1, sizeof(*pk_group))) != NULL)
            {
              pk_group->type = ssh_pk_type_slots[i];
            }
          else
            {
              ssh_free(name);
              return SSH_CRYPTO_NO_MEMORY;
            }
          break;
        }
    }

  ssh_free(name);
  *key = pk_group;

  if (pk_group == NULL)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  return SSH_CRYPTO_OK;
}

void
ssh_pk_group_object_free(SshPkGroupObject group)
{
  if (group->type->pk_group_free && group->context)
    (*group->type->pk_group_free)(group->context);
  group->context = NULL;
  ssh_free(group);
}

void
ssh_pk_group_free(SshPkGroup handle)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return;

  ssh_crypto_library_object_release(group);
  ssh_pk_group_object_free(group);
}

SshCryptoStatus
ssh_pk_group_get_info(SshPkGroup handle, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char **name_ptr, *r;
  char consumed[128];
  va_list ap;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  consumed[0] = '\000';
  while (TRUE)
    {
      va_start(ap, handle);
      PROCESS(ap, consumed);

      format = va_arg(ap, SshPkFormat);
      strcat(consumed, "i");
      if (format == SSH_PKF_END)
        break;

      /* If looking for scheme information. */
      if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
          format == SSH_PKF_DH)
            {
              name_ptr = va_arg(ap, const char **);
              strcat(consumed, "p");
              status = ssh_pk_group_get_scheme_name(group, format, name_ptr);
              if (status != SSH_CRYPTO_OK)
                {
                  va_end(ap);
                  return status;
                }
              va_end(ap);
              continue;
            }

      /* Seek for the action. */
      action = ssh_pk_find_action(group->type->action_list,
                                  format, SSH_PK_ACTION_FLAG_PK_GROUP);
      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      switch (action->flags & (SSH_PK_ACTION_FLAG_GET_PUT |
                               SSH_PK_ACTION_FLAG_KEY_TYPE))
        {
        case SSH_PK_ACTION_FLAG_KEY_TYPE:
          name_ptr = va_arg(ap, const char **);
          strcat(consumed, "p");
          *name_ptr = strchr(group->type->name, ':');
          if (*name_ptr)
            (*name_ptr)++;
          else
            *name_ptr = group->type->name;
          break;

        case SSH_PK_ACTION_FLAG_GET_PUT:
          r = (*action->action_get)(group->context, ap, NULL, format);
          if (r == NULL ||
              (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
            {
              va_end(ap);
              return SSH_CRYPTO_INTERNAL_ERROR;
            }
          strcat(consumed, r);
          break;

        default:
          ssh_fatal("ssh_pk_group_get_info: internal error.");
          break;
        }
      va_end(ap);
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_pk_group_precompute(SshPkGroup handle)
{
  SshPkGroupObject group;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle);
  if (!group)
    return SSH_CRYPTO_HANDLE_INVALID;

  if (group->type->pk_group_precompute)
    return (*group->type->pk_group_precompute)(group->context);
  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_pk_group_generate_randomizer(SshPkGroup handle)
{
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle);
  if (!group)
    return SSH_CRYPTO_HANDLE_INVALID;

  if (group->type->pk_group_generate_randomizer)
    return (*group->type->pk_group_generate_randomizer)(group->context);
  return SSH_CRYPTO_OK;
}

unsigned int
ssh_pk_group_count_randomizers(SshPkGroup handle)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return 0;

  if (group->type->pk_group_count_randomizers)
    return (*group->type->pk_group_count_randomizers)(group->context);

  return 0;
}

void
ssh_pk_group_dh_return_randomizer(SshPkGroup handle,
                                  SshPkGroupDHSecret secret,
                                  const unsigned char *exchange_buffer,
                                  size_t exchange_buffer_length)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    {
      ssh_pk_group_dh_secret_free(secret);
      return;
    }

  if (group->type->pk_group_dh_return_randomizer)
    (*group->type->pk_group_dh_return_randomizer)(group->context,
                                                  secret,
                                                  exchange_buffer,
                                                  exchange_buffer_length);
  else
    ssh_pk_group_dh_secret_free(secret);

  return;
}

void
ssh_pk_group_dh_secret_free(SshPkGroupDHSecret secret)
{
  SshUInt32 len;

  if (secret)
    {
      len = secret->len;

      memset(secret->buf, 0, len);
      ssh_free(secret);
    }
}

#ifdef SSHDIST_MATH
SshPkGroupDHSecret ssh_mprz_to_dh_secret(SshMPIntegerConst k)
{
  SshPkGroupDHSecret secret;
  size_t len = ssh_mprz_byte_size(k);

  secret = ssh_malloc(sizeof(struct SshPkGroupDHSecretRec) + len);
  if (!secret)
    return NULL;

  secret->buf = (unsigned char *)secret + sizeof(struct SshPkGroupDHSecretRec);

  secret->len = len;
  ssh_mprz_get_buf(secret->buf, len, k);
  return secret;
}

void ssh_dh_secret_to_mprz(SshMPInteger k, SshPkGroupDHSecret secret)
{
  ssh_mprz_set_buf(k, secret->buf, secret->len);
}
#endif /* SSHDIST_MATH */

SshPkGroupDHSecret
ssh_buf_to_dh_secret(const unsigned char *buf, size_t buf_len)
{
  SshPkGroupDHSecret secret;

  secret = ssh_malloc(sizeof(struct SshPkGroupDHSecretRec) + buf_len);
  if (!secret)
    return NULL;

  secret->buf = (unsigned char *)secret + sizeof(struct SshPkGroupDHSecretRec);
  secret->len = buf_len;

  memcpy(secret->buf, buf, buf_len);
  return secret;
}



SshPkGroupDHSecret ssh_pk_group_dup_dh_secret(SshPkGroupDHSecret secret)
{
  SshPkGroupDHSecret dup;

  if (secret == NULL)
    return NULL;

  dup = ssh_malloc(sizeof(struct SshPkGroupDHSecretRec) + secret->len);
  if (!dup)
    return NULL;

  dup->buf = (unsigned char *)dup + sizeof(struct SshPkGroupDHSecretRec);
  dup->len = secret->len;
  memcpy(dup->buf, secret->buf, dup->len);
  return dup;
}
