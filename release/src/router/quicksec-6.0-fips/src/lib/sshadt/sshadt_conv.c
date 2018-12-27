/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshadt_i.h"
#include "sshadt_map.h"
#include "sshadt_conv.h"
#include "sshadt_xmap.h"
#include "sshadt_strmap.h"
#include "sshadt_intmap.h"

#define SSH_DEBUG_MODULE "SshADTConv"



/**************************************** Callbacks that are frequently used */

void ssh_adt_callback_destroy_free(void *obj, void *context)
{
  ssh_free(obj);
}

void ssh_adt_callback_destroy_free_null(void *obj, void *context)
{
  if (obj == NULL) return;
  ssh_free(obj);
}

int ssh_adt_callback_compare_str(const void *obj1, const void *obj2, void *ctx)
{
  const char *s1 = obj1, *s2 = obj2;
  return strcmp(s1, s2);
}

void *ssh_adt_callback_duplicate_str(const void *obj, void *ctx)
{
  const char *s = obj;
  return ssh_strdup(s);
}

SshUInt32 ssh_adt_callback_hash_str(const void *obj, void *ctx)
{
  SshUInt32 hash = 0;
  const char *c = obj;
  while (*c)
    {
      hash += *c++;
      hash += hash << 10;
      hash ^= hash >> 6;
    }

  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

int ssh_adt_callback_compare_int(const void *obj1, const void *obj2, void *ctx)
{
  return (SshInt32) (* (SshUInt32 *) obj1 - * (SshUInt32 *) obj2);
}

SshUInt32 ssh_adt_callback_hash_int(const void *__obj, void *__context)
{
  unsigned char *__s;
  SshUInt32 __hash = 0;

  __s = (unsigned char *)__obj;

  __hash = __hash ^ *__s;          __s++;
  __hash = __hash ^ (*__s << 8);   __s++;
  __hash = __hash ^ (*__s << 16);  __s++;
  __hash = __hash ^ (*__s << 24);  __s++;

  __hash = (__hash << 3) ^ (__hash >> 17);
  __hash = __hash ^ (__hash >> 8);
  __hash = (__hash << 4) ^ (__hash >> 16);
  __hash = __hash ^ (__hash >> 16);
  __hash = (__hash << 5) ^ (__hash >> 15);
  __hash = __hash ^ (__hash >> 24);

  return __hash;
}


/************************************************* An abstract map interface */

SshADTHandle ssh_adt_xmap_add(SshADTContainer c, void *key, void *value)
{
  SSH_ASSERT(c->static_data->methods.map_attach != NULL_FNPTR);
  SSH_ASSERT(c->static_data->methods.map_lookup != NULL_FNPTR);

  {
    SshADTHandle h;
    SSH_ASSERT(!(ssh_adt_xmap_exists(c, key)));

    if (c->flags & SSH_ADT_FLAG_ALLOCATE)   /* abstract objects */
      h = ssh_adt_put(c, key);
    else                                    /* concrete objects */
      h = ssh_adt_duplicate(c, key);

    if (h != SSH_ADT_INVALID)
      {
        SSH_ASSERT(ssh_adt_xmap_exists(c, key));
        ssh_adt_map_attach(c, h, value);
      }
    return h;
  }
}

void ssh_adt_xmap_remove(SshADTContainer c, void *key)
{
  SSH_ASSERT(c->static_data->methods.map_attach != NULL_FNPTR);
  SSH_ASSERT(c->static_data->methods.map_lookup != NULL_FNPTR);

  {
    SshADTHandle h = ssh_adt_get_handle_to_equal(c, key);
    if (h != SSH_ADT_INVALID)
      ssh_adt_delete(c, h);
  }
}

void ssh_adt_xmap_set(SshADTContainer c, void *key, void *value)
{
  SSH_ASSERT(c->static_data->methods.map_attach != NULL_FNPTR);
  SSH_ASSERT(c->static_data->methods.map_lookup != NULL_FNPTR);

  {
    SshADTHandle h;
    if ((h = ssh_adt_get_handle_to_equal(c, key)) != SSH_ADT_INVALID)
      ssh_adt_map_attach(c, h, value);
    else
      ssh_adt_xmap_add(c, key, value);
  }
}

void *ssh_adt_xmap_get(SshADTContainer c, void *key)
{
  SSH_ASSERT(c->static_data->methods.map_attach != NULL_FNPTR);
  SSH_ASSERT(c->static_data->methods.map_lookup != NULL_FNPTR);

  {
    SshADTHandle h = ssh_adt_get_handle_to_equal(c, key);
    if (h == SSH_ADT_INVALID)
      return NULL;
    else
      return ssh_adt_map_lookup(c, h);
  }
}

Boolean ssh_adt_xmap_exists(SshADTContainer c, void *key)
{
  SSH_ASSERT(c->static_data->methods.map_attach != NULL_FNPTR);
  SSH_ASSERT(c->static_data->methods.map_lookup != NULL_FNPTR);

  {
    return (ssh_adt_get_handle_to_equal(c, key) != SSH_ADT_INVALID);
  }
}


/************************** Maps from strings to something (sshadt_strmap.h) */

SshADTContainer ssh_adt_create_strmap(void)
{
  return ssh_adt_create_generic
    (SSH_ADT_MAP,
     SSH_ADT_HASH,         ssh_adt_callback_hash_str,
     SSH_ADT_DUPLICATE,    ssh_adt_callback_duplicate_str,
     SSH_ADT_DESTROY,      ssh_adt_callback_destroy_free,
     SSH_ADT_COMPARE,      ssh_adt_callback_compare_str,
     SSH_ADT_ARGS_END);
}

SshADTContainer ssh_adt_xcreate_strmap(SshADTMapAttachFunc attach,
                                       SshADTMapDetachFunc detach)
{
  return ssh_adt_create_generic
    (SSH_ADT_MAP,
     SSH_ADT_MAP_ATTACH,   attach,
     SSH_ADT_MAP_DETACH,   detach,
     SSH_ADT_HASH,         ssh_adt_callback_hash_str,
     SSH_ADT_DUPLICATE,    ssh_adt_callback_duplicate_str,
     SSH_ADT_DESTROY,      ssh_adt_callback_destroy_free,
     SSH_ADT_COMPARE,      ssh_adt_callback_compare_str,
     SSH_ADT_ARGS_END);
}


/************************* Maps from integers to something (sshadt_intmap.h) */

SshADTContainer ssh_adt_create_intmap(void)
{
  return ssh_adt_create_generic(SSH_ADT_MAP,
                                SSH_ADT_HASH, ssh_adt_callback_hash_int,
                                SSH_ADT_COMPARE, ssh_adt_callback_compare_int,
                                SSH_ADT_SIZE, sizeof(SshUInt32),
                                SSH_ADT_ARGS_END);
}

SshADTContainer ssh_adt_xcreate_intmap(SshADTMapAttachFunc attach,
                                       SshADTMapDetachFunc detach)
{
  return ssh_adt_create_generic(SSH_ADT_MAP,
                                SSH_ADT_MAP_ATTACH, attach,
                                SSH_ADT_MAP_DETACH, detach,
                                SSH_ADT_HASH, ssh_adt_callback_hash_int,
                                SSH_ADT_COMPARE, ssh_adt_callback_compare_int,
                                SSH_ADT_SIZE, sizeof(SshUInt32),
                                SSH_ADT_ARGS_END);
}

SshADTHandle ssh_adt_intmap_add(SshADTContainer c, SshUInt32 key, void *value)
{
  return ssh_adt_xmap_add(c, &key, value);
}

void ssh_adt_intmap_remove(SshADTContainer c, SshUInt32 key)
{
  ssh_adt_xmap_remove(c, &key);
}

void ssh_adt_intmap_set(SshADTContainer c, SshUInt32 key, void *value)
{
  ssh_adt_xmap_set(c, &key, value);
}

void *ssh_adt_intmap_get(SshADTContainer c, SshUInt32 key)
{
  return ssh_adt_xmap_get(c, &key);
}

Boolean ssh_adt_intmap_exists(SshADTContainer c, SshUInt32 key)
{
  return ssh_adt_xmap_exists(c, &key);
}
