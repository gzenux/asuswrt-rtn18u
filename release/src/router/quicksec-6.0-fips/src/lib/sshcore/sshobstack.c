/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Memory allocation from a context. These routines allocate data to a
   context, to be freed by one call to ssh_obstack_free. There is no
   other way of freeing data, than freeing it all.
*/

#include "sshincludes.h"
#include "sshobstack.h"

#ifdef SSH_DEBUG_MALLOC
#ifndef SSH_DEBUG_MALLOC_HEAVY
#define SSH_DEBUG_MALLOC_HEAVY
#endif /* not SSH_DEBUG_MALLOC_HEAVY */
#endif /* SSH_DEBUG_MALLOC */

#define SSH_DEBUG_MODULE "SshObstack"

/* The obstack entries in the first list are in the order of space available.
   The first entry has most available space in it. When we allocate something
   from it, it will be moved forward in the list until it reaches its own
   place. */
typedef struct SshObStackDataRec
{
  struct SshObStackDataRec *next;
  unsigned char *ptr;
  size_t free_bytes;
  size_t alloc_bytes;
} *SshObStackData, SshObStackDataStruct;

/* Main context for all allocated data through obstack. */

typedef struct SshObStackContextRec
{
  SshObStackData first;
  size_t current_alloc_size;
  size_t memory_allocated;
  size_t memory_used;
  size_t memory_limit;
  SshObStackDataStruct internal_first;
} SshObStackContextStruct;

/* Initialize the obstack context. Clear all buckets. */
SshObStackContext ssh_obstack_create(SshObStackConf config)
{
  SshObStackContext created;
  size_t prealloc;

  prealloc  = ((config != NULL) ? config->prealloc_size : 4000);
  prealloc += sizeof(SshObStackContextStruct);

  if (config != NULL && config->max_size != 0 && prealloc > config->max_size)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("prealloc_size + sizeof(SshObStackContextStruct) "
                 "is larger than max_size allowed for the object"));
      return NULL;
    }
  created = ssh_malloc(prealloc);

  if (created != NULL)
    {
      created->current_alloc_size = 4096;
      created->first = &created->internal_first;
      created->first->next = NULL;
      created->first->ptr = (void *) &(created[1]);
      created->first->free_bytes = ((unsigned char *) created + prealloc) -
        created->first->ptr;
      created->first->alloc_bytes = created->first->free_bytes;
      created->memory_limit = ((config != NULL) ? config->max_size : 0);
      created->memory_allocated = prealloc;
      created->memory_used = sizeof(SshObStackContextStruct);
    }
  return created;
}

void ssh_obstack_clear(SshObStackContext context)
{
  SshObStackData temp, next;

  temp = context->first;
  while (temp != NULL)
    {
      next = temp->next;
      if (temp != &context->internal_first)
        ssh_free(temp);
      temp = next;
    }
  context->current_alloc_size = 4096;
  context->first = &context->internal_first;
  context->first->next = NULL;
  context->first->ptr = (void *) &(context[1]);
  context->first->free_bytes = context->first->alloc_bytes;
  context->memory_allocated = context->first->free_bytes +
    sizeof(SshObStackContextStruct);
  context->memory_used = sizeof(SshObStackContextStruct);
#ifdef SSH_DEBUG_MALLOC_HEAVY
  SSH_CLEAR_MEMORY(context->first->ptr, context->first->free_bytes);
#endif /* SSH_DEBUG_MALLOC_HEAVY */
}

void ssh_obstack_destroy(SshObStackContext context)
{
  ssh_obstack_clear(context);

  /* Free the context also. */
  ssh_free(context);
}

static unsigned char *
ssh_obstack_internal(SshObStackContext context, size_t size, size_t align)
{
  unsigned char *ptr;
  SshObStackData data, prev, next;
  size_t alignment;

  if (size == 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Tried to allocate ZERO bytes"));
      return NULL;
    }

  /* Find the item where we can fit the data in. */
  prev = NULL;
  data = NULL;
  next = context->first;
  while (next != NULL)
    {
      /* Compute extra alignment needed */
      alignment = (unsigned long)(next->ptr) & (align - 1);
      if (alignment != 0)
        alignment = align - alignment;
      /* Does not fit, so it must be put to the previous block. */
      if (next->free_bytes < size + alignment)
        break;
      prev = data;
      data = next;
      next = data->next;
    }

  /* Ok, check if we have buffer. */
  if (data == NULL)
    {
      /* Didn't fit to any buffer, allocate new buffer and put in the
         begining of the list. */

      /* If the size we want to allocate is way bigger than the
         current_alloc_size then allocate block for just this entry,
         and do not adjust the current_alloc_size. */
      if (size > context->current_alloc_size * 4)
        {
          size_t len;

          len = size + align - 1;
          if (len % 8 != 0)
            len += (8 - (len % 8));
          if (context->memory_limit != 0 &&
              sizeof(SshObStackDataStruct) + len + context->memory_allocated
              > context->memory_limit)
            return NULL;
          data = ssh_malloc(sizeof(SshObStackDataStruct) + len);
          if (data == NULL)
            return NULL;
          context->memory_allocated += sizeof(SshObStackDataStruct) + len;
          context->memory_used += sizeof(SshObStackDataStruct);
          data->next = NULL;
          data->ptr = (void *) &(data[1]);
          data->free_bytes = len;
          data->alloc_bytes = len;
        }
      else
        {
          size_t len;

          len = context->current_alloc_size;
          len += (len >> 1);
          while (size + align > len)
            len += (len >> 1);
          if (context->memory_limit != 0 &&
              sizeof(SshObStackDataStruct) + len + context->memory_allocated
              > context->memory_limit)
            {
              if (sizeof(SshObStackDataStruct) + size + align +
                  context->memory_allocated > context->memory_limit)
                return NULL;
              len = size + align;
            }
          data = ssh_malloc(sizeof(SshObStackDataStruct) + len);
          if (data == NULL)
            return NULL;
          context->current_alloc_size = len;
          context->memory_allocated += sizeof(SshObStackDataStruct) + len;
          context->memory_used += sizeof(SshObStackDataStruct);
          data->next = NULL;
          data->ptr = (void *) &(data[1]);
          data->free_bytes = len;
          data->alloc_bytes = len;
        }
      /* Add it to the beginning of the list. */
      data->next = next;
      context->first = data;
    }

  /* Ok, now we have block that can take the current blob to be allocated. */

  /* Adjust the alignment for pointer. */
  alignment = (unsigned long)(data->ptr) & (align - 1);
  if (alignment != 0)
    alignment = align - alignment;
  data->ptr += alignment;
  SSH_ASSERT(data->free_bytes >= alignment);
  data->free_bytes -= alignment;
  context->memory_used += alignment;

  /* Allocate object. */
  ptr = data->ptr;
  data->ptr += size;
  SSH_ASSERT(data->free_bytes >= size);
  data->free_bytes -= size;
  context->memory_used += size;

  /* Move the object forward. */
  for(next = data;
      next->next != NULL && next->next->free_bytes > data->free_bytes;
      next = next->next)
    ;
  if (data != next)
    {
      /* Remove it from the old place. */
      if (prev == NULL)
        context->first = data->next;
      else
        prev->next = data->next;

      /* Add it after next. */
      data->next = next->next;
      next->next = data;
    }
  for (next = context->first; next->next != NULL; next = next->next)
    SSH_ASSERT(next->free_bytes >= next->next->free_bytes);
  return ptr;
}

unsigned char *
ssh_obstack_alloc_unaligned(SshObStackContext context, size_t size)
{
  return ssh_obstack_internal(context, size, 1);
}

void *ssh_obstack_alloc(SshObStackContext context, size_t size)
{
  return (void *)ssh_obstack_internal(context, size, size >= 8 ? 8 :
                                      (size >= 4 ? 4 :
                                       (size >= 2 ? 2 : 1)));
}

void *ssh_obstack_calloc(SshObStackContext context, size_t size)
{
  char *ptr;

  ptr = ssh_obstack_alloc(context, size);
  if (ptr != NULL)
    memset(ptr, 0, size);
  return ptr;
}

size_t ssh_obstack_size(SshObStackContext context)
{
  return context->memory_used;
}


/* Allocate space for the data, and copy the memory buffer to the newly
   allocated data. If size is 0 then use strlen on the ptr to get the length
   of the string. The string will always be nul terminated (just like
   ssh_memdup). */
unsigned char *ssh_obstack_memdup(SshObStackContext context,
                                  const void *ptr, size_t size)
{
  unsigned char *new_ptr;

  if (ptr == NULL)
    return ssh_obstack_calloc(context, 1);
  if (size == 0)
    size = strlen(ptr);

  new_ptr = ssh_obstack_alloc(context, size + 1);
  if (new_ptr == NULL)
    return NULL;
  memcpy(new_ptr, ptr, size);
  new_ptr[size] = '\0';
  return new_ptr;
}

/* sshobstack.c */
