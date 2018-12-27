/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAP result object freeing and copying. This is memory allocation
   error safe.
*/

#include "sshincludes.h"
#include "sshldap.h"
#include "ldap-internal.h"

#ifdef SSHDIST_LDAP

#define SSH_DEBUG_MODULE "SshLdapObject"

/* Free LDAP object */
void ssh_ldap_free_object(SshLdapObject object)
{
  int i, j;

  SSH_DEBUG(SSH_D_MIDOK, ("object/free(%p)", object));

  for (i = 0; i < object->number_of_attributes; i++)
    {
      ssh_free(object->attributes[i].attribute_type);
      for (j = 0; j < object->attributes[i].number_of_values; j++)
        ssh_free(object->attributes[i].values[j]);
      ssh_free(object->attributes[i].values);
      ssh_free(object->attributes[i].value_lens);
    }
  ssh_free(object->attributes);
  ssh_free(object->object_name);
  ssh_free(object);
}

/* Duplicate a LDAP object */
SshLdapObject
ssh_ldap_duplicate_object(const SshLdapObject object,
                          Boolean null_terminated)
{
  int i, j;
  SshLdapObject new_ob;

  SSH_DEBUG(SSH_D_MIDOK, ("object/duplicate(%p)", object));

#define COPYSTRING(d, s, t)                                       \
  do {                                                            \
    if (t) { d = ssh_strdup(s); d ## _len = strlen((char *)d); }  \
    else { d = ssh_memdup(s, s ## _len); d ## _len = s ## _len; } \
    if (d == NULL) {                                              \
      ssh_ldap_free_object(new_ob); return NULL;                  \
    }                                                             \
  } while(0)

  if ((new_ob = ssh_calloc(1, sizeof(*new_ob))) == NULL)
    return NULL;

  COPYSTRING(new_ob->object_name, object->object_name, null_terminated);

  if ((new_ob->attributes =
       ssh_calloc(object->number_of_attributes,
                  sizeof(struct SshLdapAttributeRec))) == NULL)
    {
      ssh_ldap_free_object(new_ob);
      return NULL;
    }

  for (i = 0; i < object->number_of_attributes; i++)
    {
      COPYSTRING(new_ob->attributes[i].attribute_type,
                 object->attributes[i].attribute_type,
                 null_terminated);

      new_ob->number_of_attributes += 1;

      new_ob->attributes[i].number_of_values =
        object->attributes[i].number_of_values;
      new_ob->attributes[i].values =
        ssh_calloc(object->attributes[i].number_of_values, sizeof(char *));
      new_ob->attributes[i].value_lens =
        ssh_calloc(object->attributes[i].number_of_values, sizeof(size_t));

      if (new_ob->attributes[i].value_lens == NULL ||
          new_ob->attributes[i].values == NULL)
        {
          ssh_ldap_free_object(new_ob);
          return NULL;
        }

      for (j = 0; j < object->attributes[i].number_of_values; j++)
        {
          new_ob->attributes[i].value_lens[j] =
            (null_terminated) ?
            strlen((char *)object->attributes[i].values[j]) :
            object->attributes[i].value_lens[j];
          if ((new_ob->attributes[i].values[j] =
               ssh_memdup(object->attributes[i].values[j],
                          new_ob->attributes[i].value_lens[j])) == NULL)
            {
              ssh_ldap_free_object(new_ob);
              return NULL;
            }

        }
    }

#undef COPYSTRING

  return new_ob;
}
#endif /* SSHDIST_LDAP */
