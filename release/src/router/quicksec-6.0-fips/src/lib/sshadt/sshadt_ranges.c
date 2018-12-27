/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   NOTE: This file does not implement a container in the same sense as
   sshadt_list.c does, but an application to the ranges container that
   is implemented in sshadt_avltree.c.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_i.h"
#include "sshadt_avltree.h"
#include "sshadt_ranges.h"
#include "sshadt_xmap.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTRanges"


typedef struct {
  SshUInt32 i;
  SshADTHeaderStruct h;
} *Bound;

static int bound_compare(const void *o1, const void *o2, void *ctx)
{
  return (*(SshUInt32 *)o1 - *(SshUInt32 *)o2);
}

static void *bound_duplicate(const void *o1, void *ctx)
{
  Bound o2 = ssh_malloc(sizeof(*o2));
  o2->i = ((Bound)o1)->i;
  return (void *)o2;
}

SshADTContainer ssh_adt_resource_allocator_create(void)
{
  SshADTContainer c;

  c = ssh_adt_create_generic
    (SSH_ADT_RANGES,
     SSH_ADT_COMPARE, bound_compare,
     SSH_ADT_DUPLICATE, bound_duplicate,  /* (needed for xmap) */
     SSH_ADT_ARGS_END);

  if (c != NULL)
    {
      SshADTHandle h;
      Bound r;

      r = ssh_xmalloc(sizeof(*r));
      r->i = 0;

      h = ssh_adt_insert(c, r);
      ssh_adt_map_attach(c, h, SSH_ADT_RANGES_FREE);
      ssh_adt_ranges_merge(c);  /* just to purge the cache; perhaps
                                   this is not strictly necessary.  */
    }

  return c;
}

static Boolean set_single_slot(SshADTContainer c, SshUInt32 slot, void *value)
{
  SshADTHandle h;
  Bound r;

  if ((r = ssh_malloc(sizeof(*r))) == NULL)
    {
      SSH_DEBUG(0, ("out of memory!"));
      return FALSE;
    }

  /* Make slot + 1 an interval bound.  */
  r->i = slot + 1;
  h = ssh_adt_get_handle_to_glb(c, r);

  /* (special case (-inf, min)) */
  if (h == SSH_ADT_INVALID)
    ssh_adt_xmap_set(c, r, SSH_ADT_RANGES_ALLOCATED);

  /* (slot + 1 is already a lower range bound) */
  else if (*(SshUInt32 *)ssh_adt_get(c, h) == slot + 1)
    ;

  /* (slot and slot + 1 are in the same range, but slot + 1 is not a
     lower bound) */
  else
    ssh_adt_xmap_set(c, r, ssh_adt_map_lookup(c, h));

  /* Update slot value.  */
  r->i = slot;
  ssh_adt_xmap_set(c, r, value);

  /* Cleanup.  */
  ssh_free(r);
  ssh_adt_ranges_merge(c);
  return TRUE;
}

Boolean ssh_adt_resource_allocator_allocate(SshADTContainer c, SshUInt32 *i)
{
  SshADTHandle h;
  Bound r;

  if ((r = ssh_malloc(sizeof(*r))) == NULL)
    {
      SSH_DEBUG(0, ("out of memory!"));
      return FALSE;
    }

  /* Find first free i.  */
  r->i = 0;
  h = ssh_adt_get_handle_to_equal(c, r);
  ssh_free(r);

  if (h == SSH_ADT_INVALID)
    h = ssh_adt_enumerate_start(c);
  else if (ssh_adt_map_lookup(c, h) == SSH_ADT_RANGES_ALLOCATED)
    h = ssh_adt_enumerate_next(c, h);

  SSH_ASSERT(h != SSH_ADT_INVALID);
  SSH_ASSERT(ssh_adt_map_lookup(c, h) == SSH_ADT_RANGES_FREE);

  *i = ((Bound)ssh_adt_get(c, h))->i;

  return set_single_slot(c, *i, SSH_ADT_RANGES_ALLOCATED);
}

Boolean ssh_adt_resource_allocator_free(SshADTContainer c, SshUInt32 i)
{
  return set_single_slot(c, i, SSH_ADT_RANGES_FREE);
}
