/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshadt_assoc.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTAssoc"

/* The hook context for an associated container pair (domain, range).  */

typedef struct {
  SshADTContainer domain;
  SshADTContainer range;
} *SshADTAssociationContext;

/* The actual hooks.  */

static void hook_domain_unmap(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  SshADTHandle image = ssh_adt_map_lookup(a->domain, h);

  if (image != SSH_ADT_INVALID)
    {
      ssh_adt_delete(a->range, image);
    }
}

static void hook_range_unmap2(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  SshADTHandle image = ssh_adt_map_lookup(a->range, h);

  if (image != SSH_ADT_INVALID)
    {
      ssh_adt_map_attach(a->domain, image, SSH_ADT_INVALID);
    }
}

static void hook_domain_unmap2(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  SshADTHandle image = ssh_adt_map_lookup(a->domain, h);

  if (image != SSH_ADT_INVALID)
    {
      ssh_adt_map_attach(a->range, image, SSH_ADT_INVALID);
    }
}

static void hook_domain_detach(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  ssh_adt_map_attach(a->domain, h, SSH_ADT_INVALID);
}

static void hook_range_detach(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  ssh_adt_map_attach(a->range, h, SSH_ADT_INVALID);
}

static void hook_destroy(void *ctx)
{
  SshADTAssociationContext a = ctx;
  ssh_adt_unassociate(a->domain, a->range);
}

static void hook_domain_map2(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  SshADTHandle image, revimage;
  image = ssh_adt_map_lookup(a->domain, h);
  if (image != SSH_ADT_INVALID)
    {
      revimage = ssh_adt_map_lookup(a->range, image);
      if (revimage != h)
        {
          ssh_adt_map_attach(a->range, image, h);
        }
    }
}

static void hook_range_map2(SshADTHandle h, void *ctx)
{
  SshADTAssociationContext a = ctx;
  SshADTHandle image, revimage;
  image = ssh_adt_map_lookup(a->range, h);
  if (image != SSH_ADT_INVALID)
    {
      revimage = ssh_adt_map_lookup(a->domain, image);
      if (revimage != h)
        {
          ssh_adt_map_attach(a->domain, image, h);
        }
    }
}

/* The associators. */

Boolean ssh_adt_associate_unimap(SshADTContainer domain, SshADTContainer range)
{
  SshADTAssociationContext ctx;

  if (!(ctx = ssh_malloc(sizeof(*ctx))))
    return FALSE;

  ctx->domain = domain;
  ctx->range  = range;

  ssh_adt_initialize_hooks(domain);
  ssh_adt_initialize_hooks(range);

  domain->hooks->unmap = hook_domain_unmap;
  domain->hooks->unmap_ctx = ctx;

  domain->hooks->detach = hook_domain_detach;
  domain->hooks->detach_ctx = ctx;

  domain->hooks->destr = hook_destroy;
  domain->hooks->destr_ctx = ctx;

  range->hooks->destr = hook_destroy;
  range->hooks->destr_ctx = ctx;

  return TRUE;
}

Boolean ssh_adt_associate_bimap(SshADTContainer domain, SshADTContainer range)
{
  SshADTAssociationContext ctx;

  if (!(ctx = ssh_malloc(sizeof(*ctx))))
    return FALSE;

  ctx->domain = domain;
  ctx->range  = range;

  ssh_adt_initialize_hooks(domain);
  ssh_adt_initialize_hooks(range);

  domain->hooks->unmap = hook_domain_unmap2;
  domain->hooks->unmap_ctx = ctx;

  domain->hooks->map = hook_domain_map2;
  domain->hooks->map_ctx = ctx;

  domain->hooks->detach = hook_domain_detach;
  domain->hooks->detach_ctx = ctx;

  range->hooks->unmap = hook_range_unmap2;
  range->hooks->unmap_ctx = ctx;

  range->hooks->map = hook_range_map2;
  range->hooks->map_ctx = ctx;

  range->hooks->detach = hook_range_detach;
  range->hooks->detach_ctx = ctx;

  domain->hooks->destr = hook_destroy;
  domain->hooks->destr_ctx = ctx;

  range->hooks->destr = hook_destroy;
  range->hooks->destr_ctx = ctx;

  return TRUE;
}

void ssh_adt_unassociate(SshADTContainer c1, SshADTContainer c2)
{
  /* Delete the association context. */
  ssh_free(c1->hooks->destr_ctx);

  ssh_adt_uninitialize_hooks(c1);
  ssh_adt_uninitialize_hooks(c2);
}
