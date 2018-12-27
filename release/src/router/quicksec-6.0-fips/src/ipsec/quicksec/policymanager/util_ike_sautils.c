/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 SA utility functions.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"
#include "sad_ike.h"

#define SSH_DEBUG_MODULE "SshPmIkev2SaUtil"

/* The maximum number of SA payloads that will be stored in the freelist. */
#define SSH_PM_MAX_SA_PAYLOADS (2 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS + 5)


/***********************************************************************/
/*                      Internal functions.                            */
/***********************************************************************/

/* Allocate new SA payload. */
SshIkev2PayloadSA
ssh_ikev2_sa_allocate_new(SshSADHandle sad_handle)
{
  SshIkev2PayloadSA sa;




  sa = ssh_calloc(1, sizeof(*sa));
  if (sa == NULL)
    return sa;
  /* Preallocate some transforms. */




  sa->number_of_transforms_allocated = SSH_IKEV2_SA_TRANSFORMS_PREALLOC;
  sa->transforms = ssh_calloc(sa->number_of_transforms_allocated,
                             sizeof(*(sa->transforms)));
  if (sa->transforms == NULL)
    sa->number_of_transforms_allocated = 0;

  return sa;
}

/* Free SA payload, it must not be in the free list anymore. */
void
ssh_ikev2_sa_destroy(SshSADHandle sad_handle, SshIkev2PayloadSA sa)
{



#ifdef DEBUG_LIGHT
  memset(sa->transforms, 'F',
         sa->number_of_transforms_allocated * sizeof(*(sa->transforms)));
#endif /* DEBUG_LIGHT */
  ssh_free(sa->transforms);
  sa->transforms = NULL;
#ifdef DEBUG_LIGHT
  memset(sa, 'F', sizeof(*sa));
#endif /* DEBUG_LIGHT */
  ssh_free(sa);
}

/* Init free list of SA payloads. Return TRUE if successful. */
Boolean
ssh_ikev2_sa_freelist_create(SshSADHandle sad_handle)
{
  SshIkev2PayloadSA sa;
  SshUInt32 i;

  sad_handle->sa_free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshIkev2PayloadSAStruct,
                                             free_list_header),
                           SSH_ADT_ARGS_END);
  if (sad_handle->sa_free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory, allocating server_list"));
      return FALSE;
    }

  for (i = 0; i < SSH_PM_MAX_SA_PAYLOADS; i++)
    {
      sa = ssh_ikev2_sa_allocate_new(sad_handle);
      if (sa != NULL)
        ssh_adt_insert(sad_handle->sa_free_list, sa);
    }

  return TRUE;
}

/* Destroy free list of SA payloads.  */
void
ssh_ikev2_sa_freelist_destroy(SshSADHandle sad_handle)
{
  if (sad_handle->sa_free_list)
    {
      SshIkev2PayloadSA sa;
      SshADTHandle h;

      while ((h = ssh_adt_enumerate_start(sad_handle->sa_free_list)) !=
             SSH_ADT_INVALID)
        {
          sa = ssh_adt_get(sad_handle->sa_free_list, h);
          SSH_ASSERT(sa != NULL);
          ssh_adt_detach_object(sad_handle->sa_free_list, sa);
          ssh_ikev2_sa_destroy(sad_handle, sa);
        }
      SSH_ASSERT(ssh_adt_num_objects(sad_handle->sa_free_list) == 0);
      ssh_adt_destroy(sad_handle->sa_free_list);
    }
  sad_handle->sa_free_list = NULL;
}

/***********************************************************************/
/*                      External functions.                            */
/***********************************************************************/

/* Allocate SA payload. The initial SA is empty. This will
   take it from the free list in SAD, or return NULL if no
   entries available. */
SshIkev2PayloadSA
ssh_ikev2_sa_allocate(SshSADHandle sad_handle)
{
  SshIkev2PayloadSA sa;

  sa = NULL;
  if (ssh_adt_num_objects(sad_handle->sa_free_list) > 0)
    sa = ssh_adt_detach_from(sad_handle->sa_free_list, SSH_ADT_BEGINNING);
  if (sa != NULL)
    {
      SshIkev2PayloadTransform transforms;
      SshUInt32 number_of_transforms_allocated;

      transforms = sa->transforms;
      number_of_transforms_allocated = sa->number_of_transforms_allocated;
      memset(sa->transforms, 0,
             sa->number_of_transforms_allocated * sizeof(*(sa->transforms)));
      memset(sa, 0, sizeof(*sa));
      sa->transforms = transforms;
      sa->number_of_transforms_allocated = number_of_transforms_allocated;
    }
  else
    sa = ssh_ikev2_sa_allocate_new(sad_handle);
  if (sa == NULL)
    return NULL;
  sa->ref_cnt = 1;
  sa->number_of_transforms_used = 0;

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated SA payload %p", sa));

  return sa;
}

/* Free SA payload. This will return it back to the free list if this was
   last reference */
void
ssh_ikev2_sa_free(SshSADHandle sad_handle,
                  SshIkev2PayloadSA sa)
{
  size_t num_objects;

  SSH_ASSERT(sa->ref_cnt != 0);
  /* Decrement reference count, and check whether we still have references. */
  sa->ref_cnt--;
  if (sa->ref_cnt != 0)
    {
      /* Yes. */
      SSH_DEBUG(SSH_D_LOWOK, ("SA payload %p has still %d references",
                              sa, (int) sa->ref_cnt));
      return;
    }

  num_objects = ssh_adt_num_objects(sad_handle->sa_free_list);
  if (num_objects > SSH_PM_MAX_SA_PAYLOADS)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Destroying SA payload %p", sa));
      ssh_ikev2_sa_destroy(sad_handle, sa);
    }
  else
    {
#ifdef DEBUG_LIGHT
      /* Mark structure freed. Note, that 'transforms' and
         'number_of_transforms_allocated' must be preserved. */
      SshIkev2PayloadTransform transforms;
      SshUInt32 number_of_transforms_allocated;

      transforms = sa->transforms;
      number_of_transforms_allocated = sa->number_of_transforms_allocated;
      memset(sa->transforms, 'F',
             sa->number_of_transforms_allocated * sizeof(*(sa->transforms)));
      memset(sa, 'F', sizeof(*sa));
      sa->transforms = transforms;
      sa->number_of_transforms_allocated = number_of_transforms_allocated;
      SSH_DEBUG(SSH_D_LOWOK, ("Returning SA payload %p to freelist", sa));
#endif /* DEBUG_LIGHT */
      ssh_adt_insert(sad_handle->sa_free_list, sa);
    }
  return;
}
