/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Memory allocation utility functions.

   <keywords memory allocation, allocation/memory,
   utility functions/memory allocation>

   @internal
*/

#ifndef SSHFASTALLOC_H_INCLUDED
#define SSHFASTALLOC_H_INCLUDED

typedef struct SshFastMemoryAllocatorRec *SshFastMemoryAllocator;

/** Initialize a new memory allocator for fixed-sized blobs.

    @param blob_size
    The size of the blobs. Must be larger than zero.

    @param blob_quant
    The number of blobs for which room will be reserved atomically.
    Must be larger than zero.

    */
SshFastMemoryAllocator ssh_fastalloc_initialize(int blob_size,
                                                int blob_quant);

/**  Uninitialize a memory allocator. All allocated blobs must have been
     freed, otherwise ssh_fatal() may be triggered. */
void ssh_fastalloc_uninitialize(SshFastMemoryAllocator allocator);

/**  Uninitialize a memory allocator, with the provision that some of the blobs
     can be unfreed at this point.  No error will be triggered for that.
     Should be used only if it is clearly not an error to have unfreed
     blobs. */
void ssh_fastalloc_uninitialize_forced(SshFastMemoryAllocator allocator);

/**  Allocate a new blob of the size 'blob_size'. The returned data is
     correctly aligned for all kinds of purposes. The data is not
     necessarily initialized.

     @return
     This can return NULL if lower-level memory allocation can. */
void *ssh_fastalloc_alloc(SshFastMemoryAllocator allocator);

/**  Free an individual blob. */
void ssh_fastalloc_free(SshFastMemoryAllocator allocator, void *data);

/**  Reserve room for allocating at least 'objects' new objects.

     @return
     If this call returns TRUE, then the allocator has reserved room
     for 'objects' new objects and it is guaranteed that they can be
     allocated without failures. If the call returns FALSE then there
     isn't currently enough memory available.

     */
Boolean ssh_fastalloc_reserve(SshFastMemoryAllocator allocator, int objects);

/*  Two macros. */
#define ssh_fastalloc_alloc_m(allocator, result)                              \
do                                                                            \
{                                                                             \
  if ((allocator)->free_chain == NULL)                                        \
    {                                                                         \
      result = ssh_fastalloc_alloc(allocator);                                \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      result = ((void *)((allocator)->free_chain));                           \
      (allocator)->free_chain =                                               \
        (allocator)->free_chain->free_chain;                                  \
      (allocator)->allocated++;                                               \
    }                                                                         \
}                                                                             \
while (0)

#define ssh_fastalloc_free_m(allocator, blob)                                 \
do                                                                            \
{                                                                             \
  SSH_ASSERT((allocator)->allocated > 0);                                     \
  ((SshFastallocProtoBlob *)(blob))->free_chain = (allocator)->free_chain;    \
  (allocator)->free_chain = (void *)(blob);                                   \
  (allocator)->allocated--;                                                   \
}                                                                             \
while (0)

/*  You do not need to access these structures directly but the
     declarations must be public so that the macros above can work. */
typedef struct {
  void *free_chain;
} SshFastallocProtoBlob;

typedef struct ssh_fastalloc_blobs {
  void *blobs;
  struct ssh_fastalloc_blobs *next;
} SshFastallocBlobs;

struct SshFastMemoryAllocatorRec {
  int total_size;
  int allocated;
  int blob_size;
  int blob_quant;
  SshFastallocBlobs *blobs;
  SshFastallocProtoBlob *free_chain;
};

#endif /* SSHFASTALLOC_H_INCLUDED */
