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
#include "sad_ike.h"

#define SSH_DEBUG_MODULE "SshPmIkev2ConfUtil"





/* The maximum number of Conf payloads that will be stored in the freelist. */
#define SSH_PM_MAX_CONF_PAYLOADS (2 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS + 5)

/***********************************************************************/
/*                      Internal functions.                            */
/***********************************************************************/

/* Allocate new configuration payload. */
SshIkev2PayloadConf
ssh_ikev2_conf_allocate_new(SshSADHandle sad_handle)
{
  SshIkev2PayloadConf conf;




  conf = ssh_calloc(1, sizeof(*conf));
  if (conf == NULL)
    return conf;
  /* Preallocate some attributes. */



  conf->number_of_conf_attributes_allocated =
    SSH_IKEV2_CONF_ATTRIBUTES_PREALLOC;
  conf->conf_attributes = ssh_calloc(conf->number_of_conf_attributes_allocated,
                                     sizeof(*(conf->conf_attributes)));
  if (conf->conf_attributes == NULL)
    conf->number_of_conf_attributes_allocated = 0;

  return conf;
}

/* Free configuration payload, it must not be in the free list
   anymore. */
void
ssh_ikev2_conf_destroy(SshSADHandle sad_handle, SshIkev2PayloadConf conf)
{



  ssh_free(conf->conf_attributes);
  conf->conf_attributes = NULL;
  ssh_free(conf);
}

/* Init free list of configuration payloads. Return TRUE if
   successfull. */
Boolean
ssh_ikev2_conf_freelist_create(SshSADHandle sad_handle)
{
  SshIkev2PayloadConf conf;
  SshUInt32 i;

  sad_handle->conf_free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshIkev2PayloadConfStruct,
                                             free_list_header),
                           SSH_ADT_ARGS_END);
  if (sad_handle->conf_free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server_list"));
      return FALSE;
    }

  for (i = 0; i < SSH_PM_MAX_CONF_PAYLOADS; i++)
    {
      conf = ssh_ikev2_conf_allocate_new(sad_handle);
      if (conf != NULL)
        ssh_adt_insert(sad_handle->conf_free_list, conf);
    }

  return TRUE;
}

/* Destroy free list of configuration payloads.  */
void
ssh_ikev2_conf_freelist_destroy(SshSADHandle sad_handle)
{
  if (sad_handle->conf_free_list)
    {
      SshIkev2PayloadConf conf;
      SshADTHandle h;

      while ((h = ssh_adt_enumerate_start(sad_handle->conf_free_list)) !=
             SSH_ADT_INVALID)
        {
          conf = ssh_adt_get(sad_handle->conf_free_list, h);
          SSH_ASSERT(conf != NULL);
          ssh_adt_detach_object(sad_handle->conf_free_list, conf);
          ssh_ikev2_conf_destroy(sad_handle, conf);
        }
      SSH_ASSERT(ssh_adt_num_objects(sad_handle->conf_free_list) == 0);
      ssh_adt_destroy(sad_handle->conf_free_list);
    }
  sad_handle->conf_free_list = NULL;
}

/***********************************************************************/
/*                      External functions.                            */
/***********************************************************************/

/* Allocate configuration payload. The initial configuration
   payload is empty. This will take it from the free list in
   SAD, or return NULL if no entries available. */
SshIkev2PayloadConf
ssh_ikev2_conf_allocate(SshSADHandle sad_handle,
                        SshIkev2ConfType conf_type)
{
  SshIkev2PayloadConf conf;

  conf = NULL;
  if (ssh_adt_num_objects(sad_handle->conf_free_list) > 0)
    conf = ssh_adt_detach_from(sad_handle->conf_free_list, SSH_ADT_BEGINNING);
  if (conf == NULL)
    conf = ssh_ikev2_conf_allocate_new(sad_handle);
  if (conf == NULL)
    return NULL;
  conf->ref_cnt = 1;
  conf->conf_type = conf_type;
  conf->number_of_conf_attributes_used = 0;
  return conf;
}

/* Free configuration payload. This will return it back to the free
   list if this was last reference */
void
ssh_ikev2_conf_free(SshSADHandle sad_handle,
                    SshIkev2PayloadConf conf)
{
  size_t num_objects;
  SSH_ASSERT(conf->ref_cnt != 0);

  /* Decrement reference count, and check whether we still have references. */
  conf->ref_cnt--;
  if (conf->ref_cnt != 0)
    {
      /* Yes. */
      return;
    }

  /* No references, free or move it to free list. */
  num_objects = ssh_adt_num_objects(sad_handle->conf_free_list);

  if (num_objects > SSH_PM_MAX_CONF_PAYLOADS)
    ssh_ikev2_conf_destroy(sad_handle, conf);
  else
    ssh_adt_insert(sad_handle->conf_free_list, conf);
  return;
}
