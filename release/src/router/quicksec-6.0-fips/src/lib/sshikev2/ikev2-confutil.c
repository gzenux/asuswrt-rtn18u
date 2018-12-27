/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 Conf payload utility functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2ConfUtil"

/* Duplicate Configuration payload. This will take new entry from the
   free list and copy data from the current Configuration data in to
   it. This will return NULL if no free Configuration payloads
   available. */
SshIkev2PayloadConf
ssh_ikev2_conf_dup(SshSADHandle sad_handle,
                   SshIkev2PayloadConf conf)
{
  SshIkev2PayloadConf conf_copy;
  SshIkev2ConfAttribute attributes_copy;
  int i;

  conf_copy = ssh_ikev2_conf_allocate(sad_handle, conf->conf_type);
  if (conf_copy == NULL)
    return NULL;

  /* Copy items. */
  if (conf->number_of_conf_attributes_used >
      conf_copy->number_of_conf_attributes_allocated)
    {
      attributes_copy =
        ssh_realloc(conf_copy->conf_attributes,
                    conf_copy->number_of_conf_attributes_allocated *
                    sizeof(*(conf_copy->conf_attributes)),
                    conf->number_of_conf_attributes_used *
                    sizeof(*(conf_copy->conf_attributes)));
      if (attributes_copy == NULL)
        {
          ssh_ikev2_conf_free(sad_handle, conf_copy);
          return NULL;
        }
      /* Initialize dynamic buffer pointers for newly allocated
         attributes that are uninitialized. */
      for (i = conf_copy->number_of_conf_attributes_allocated;
           i < conf->number_of_conf_attributes_used;
           i++)
        {
          attributes_copy[i].dynamic_buffer = NULL;
        }

      conf_copy->conf_attributes = attributes_copy;
      conf_copy->number_of_conf_attributes_allocated =
        conf->number_of_conf_attributes_used;
    }

  for (i = 0; i < conf->number_of_conf_attributes_used; i++)
    {
      if (conf->conf_attributes[i].dynamic_buffer != NULL)
        {
          SSH_ASSERT(conf->conf_attributes[i].length >
                     SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE);
          conf_copy->conf_attributes[i].dynamic_buffer =
            ssh_memdup(conf->conf_attributes[i].dynamic_buffer,
                       conf->conf_attributes[i].length);
          if (conf_copy->conf_attributes[i].dynamic_buffer == NULL)
            {
              ssh_ikev2_conf_free(sad_handle, conf_copy);
              return NULL;
            }
          conf_copy->conf_attributes[i].value =
            conf_copy->conf_attributes[i].dynamic_buffer;
        }
      else
        {
          SSH_ASSERT(conf->conf_attributes[i].length <=
                     SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE);
          memcpy(conf_copy->conf_attributes[i].buffer,
                 conf->conf_attributes[i].buffer,
                 SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE);
          conf_copy->conf_attributes[i].value =
            conf_copy->conf_attributes[i].buffer;
        }
      conf_copy->conf_attributes[i].attribute_type =
        conf->conf_attributes[i].attribute_type;
      conf_copy->conf_attributes[i].length = conf->conf_attributes[i].length;
    }

  conf_copy->number_of_conf_attributes_used =
    conf->number_of_conf_attributes_used;

  return conf_copy;
}

/* Take extra reference to the configuration payload. */
void
ssh_ikev2_conf_take_ref(SshSADHandle sad_handle,
                        SshIkev2PayloadConf conf)
{
  conf->ref_cnt++;
}

/* Add attribute to the configuration payload. This will add
   new entry to the end of the list. */
SshIkev2Error
ssh_ikev2_conf_add(SshIkev2PayloadConf conf,
                   SshIkev2ConfAttributeType attribute_type,
                   size_t length,
                   const unsigned char *value)
{
  SshIkev2ConfAttribute attribute;
  int i;

  if (conf->number_of_conf_attributes_used >=
      conf->number_of_conf_attributes_allocated)
    {
      /* NOTE: Check memory limits here */
      attribute = ssh_realloc(conf->conf_attributes,
                              conf->number_of_conf_attributes_allocated
                              * sizeof(*(conf->conf_attributes)),
                              (conf->number_of_conf_attributes_allocated +
                               SSH_IKEV2_CONF_ATTRIBUTES_ADD)
                              * sizeof(*(conf->conf_attributes)));
      if (attribute == NULL)
        {
          return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
        }
      conf->conf_attributes = attribute;
      conf->number_of_conf_attributes_allocated +=
        SSH_IKEV2_CONF_ATTRIBUTES_ADD;

      /* Update the static buffer pointers for attributes that
         were reallocated. */
      for (i = 0; i < conf->number_of_conf_attributes_used; i++)
        {
          if (conf->conf_attributes[i].dynamic_buffer == NULL)
            conf->conf_attributes[i].value = conf->conf_attributes[i].buffer;
        }
      /* Initialize dynamic buffer pointers for newly allocated
         attributes that are uninitialized. */
      for (i = conf->number_of_conf_attributes_used;
           i < conf->number_of_conf_attributes_allocated;
           i++)
        conf->conf_attributes[i].dynamic_buffer = NULL;
    }

  attribute = &(conf->conf_attributes[conf->number_of_conf_attributes_used]);
  attribute->attribute_type = attribute_type;
  attribute->length = length;
  if (attribute->length > SSH_IKEV2_CONF_ATTRIBUTE_PREALLOC_SIZE)
    {
      SSH_ASSERT(attribute->dynamic_buffer == NULL);
      attribute->dynamic_buffer = ssh_memdup(value, length);
      if (attribute->dynamic_buffer == NULL)
        return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      attribute->value = attribute->dynamic_buffer;
    }
  else
    {
      memcpy(attribute->buffer, value, attribute->length);
      attribute->value = attribute->buffer;
    }
  conf->number_of_conf_attributes_used++;
  return SSH_IKEV2_ERROR_OK;
}



void
ssh_ikev2_conf_free_attributes(SshIkev2PayloadConf conf)
{
  int i;

  for (i = conf->number_of_conf_attributes_used;
       i < conf->number_of_conf_attributes_allocated;
       i++)
    {
      if (conf->conf_attributes[i].dynamic_buffer != NULL)
        {
          ssh_free(conf->conf_attributes[i].dynamic_buffer);
          conf->conf_attributes[i].dynamic_buffer = NULL;
        }
    }

  conf->number_of_conf_attributes_used = 0;
}

