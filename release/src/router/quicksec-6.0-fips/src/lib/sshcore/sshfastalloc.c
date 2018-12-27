/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshfastalloc.h"

#define SSH_DEBUG_MODULE "SshFastalloc"

/* This routine works also when a->free_chain != NULL. This is necessary for
   `ssh_fastalloc_reserve'. */
static Boolean make_more_blobs(SshFastMemoryAllocator a)
{
  SshFastallocBlobs *newp;

  newp = ssh_malloc(sizeof(*newp));

  /* Check the return value. */
  if (newp == NULL)
    {
      return FALSE;
    }

  newp->blobs = ssh_malloc(a->blob_quant * a->blob_size);

  /* Check the return value. */
  if (newp->blobs == NULL)
    {
      ssh_free(newp);
      return FALSE;
    }

  newp->next = a->blobs;
  a->blobs = newp;
  a->total_size += a->blob_quant;

  /* Add the new blobs to the chain of free blobs. */
  {
    unsigned char *ptr = newp->blobs;
    unsigned char *end = ptr + a->blob_size * (a->blob_quant - 1);
    int step = a->blob_size;

    while (ptr < end)
      {
        ((SshFastallocProtoBlob *)ptr)->free_chain =
          (ptr + step);
        ptr += step;
      }
    ((SshFastallocProtoBlob *)ptr)->free_chain = a->free_chain;
    a->free_chain = newp->blobs;
  }

  return TRUE;
}

static void *get_blob(SshFastMemoryAllocator a)
{
  void *r;

  if (a->free_chain == NULL)
    {
      if (!make_more_blobs(a))
        {
          return NULL;
        }
    }

  r = a->free_chain;
  a->free_chain = a->free_chain->free_chain;
  a->allocated++;
  return r;
}

static void release_blob(SshFastMemoryAllocator a, void *ptr)
{
  ((SshFastallocProtoBlob *)ptr)->free_chain = a->free_chain;
  a->free_chain = (SshFastallocProtoBlob *)ptr;
  a->allocated--;
  SSH_ASSERT(a->allocated >= 0);
}

SshFastMemoryAllocator ssh_fastalloc_initialize(int blob_size,
                                                int blob_quant)
{
  SshFastMemoryAllocator newp;

  SSH_VERIFY(blob_size > 0);
  SSH_VERIFY(blob_quant > 0);

  /* Ensure correct alignment: round the `blob_size' up to be a
     multiple of sizeof(void *). */
  if (blob_size % sizeof(void *))
    {
      blob_size += sizeof(void *) - (blob_size % sizeof(void *));
    }

  if ((newp = ssh_malloc(sizeof(*newp))) == NULL)
    return NULL;

  newp->blob_size = blob_size;
  newp->blob_quant = blob_quant;
  newp->allocated = 0;
  newp->total_size = 0;
  newp->blobs = NULL;
  newp->free_chain = NULL;
  return newp;
}

void ssh_fastalloc_uninitialize(SshFastMemoryAllocator a)
{
  if (a->allocated > 0)
    {
      ssh_fatal("%d blobs not freed in ssh_fastalloc_uninitialize",
                a->allocated);
    }

  while (a->blobs != NULL)
    {
      SshFastallocBlobs *b = a->blobs;
      a->blobs = a->blobs->next;
      ssh_free(b->blobs);
      ssh_free(b);
    }

  ssh_free(a);
}

void *ssh_fastalloc_alloc(SshFastMemoryAllocator a)
{
  return get_blob(a);
}

void ssh_fastalloc_free(SshFastMemoryAllocator a, void *ptr)
{
  release_blob(a, ptr);
}

Boolean ssh_fastalloc_reserve(SshFastMemoryAllocator a, int objects)
{
  while (a->total_size - a->allocated < objects)
    {
      if (!(make_more_blobs(a)))
        return FALSE;
    }
  return TRUE;
}
