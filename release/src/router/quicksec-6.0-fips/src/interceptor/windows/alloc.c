/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Adapted from earlier xmalloc.c to the new allocation interface.

   Contains the implementation of ssh_kernel_alloc and ssh_kernel_free
   for the Windows platforms.

   This source file contains also a implementation of simple memory
   manager. The purpose of the memory manager is to prevent kernel
   heap fragmentation, which is a major broblem in Windows 9X environemts.

   The memory manager can be taken into use by defining a conditional
   compilation flag SSH_MM_IN_USE.

   To prevent kernel heap fragmentation, memory manager doesn't allocate
   any small blocks from OS kernel. The memory is always allocated in
   bigger blocks (several linear memory pages at a one time).

   If function ssh_kernel_alloc() is requested to allocate a memory block
   larger than SSH_MM_LARGEST_BLOCK size, it allocates a following kind of
   memory block:

     +------+================================================+
     | size |AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|
     +------+================================================+

     ("AAA..." represent a memory block "visible" to the caller of
      ssh_kernel_alloc())

   The caller of ssh_kernel_alloc() receives a pointer to a requested memory
   block. (Memory manager adds the size of the memory block at the beginning
   of actually allocated block, but this extra field is not visible for
   the caller of ssh_kernel_alloc())

   On the other hand, if ssh_kernel_alloc() is being requested to allocate
   a memory block smaller or equal than SSH_MM_LARGEST_BLOCK_SIZE, the
   memory manager first tries to fetch a previously allocated (free) memory
   block from its internal memory pools. If this pool lookup fails (i.e.
   the memory pool is empty), the memory manager allocates a new larger
   "parent block" containing a bunch of fixed size (currently either 32, 128,
   512, 2048, 8192 or 32768 bytes) "child blocks". After that "extra" child
   blocks are are stored into the memory pools and one of the allocated child
   blocks" is returned to the caller of ssh_kernel_alloc().

   Every parent block has a reference counter, which is incremented every
   time a child block is "allocated" and decremented when a child block is
   "freed". The parent block can be deleted only when the value of the
   reference counter is equal to zero (i.e. none of the child blocks is
   currently "allocated").

       +------+------------------------------------------------+
       | size | "parent block"                                 |
       +------+------------------------------------------------+
              |
          /---/
          |
          +-----------------+--------------+--------------+------
          | "parent header" | child block1 | child block2 | ...
          +-----------------+--------------+--------------+------
                            |              |
                    /-------/              \---------------\
                   |                                        |
                   +----------------+=======================+
                   | "Child header" |AAAAAAAAAAAAAAAAAAAAAAA|
                   +----------------+=======================+
                   |                                        |
                   |                                        |
                   +-----------+----+=======================+
                   |XXXXXXXXXXX|size|AAAAAAAAAAAAAAAAAAAAAAA|
                   +-----------+----+=======================+

   It's important to notice that the last field before the "payload" field
   is always the size of the memory block, so ssh_kernel_free() knows
   whether the block was allocated from memory manger's own pool or directly
   from the OS kernel heap. (If the size is greater than
   SSH_MM_LARGEST_BLOCK_SIZE, the memory had been allocated from OS kernel
   heap.)

   The memory manager maintains the "states" of parent blocks according to
   the following drawing.

                                  NdisAllocateMemory
                                          |
                                          |
                                          V
               (ref_count == 0)    +-------------+
              +--------------------| active list |<-------------+
              |                    +-------------+              |
              |                           A                     |
              |                           |                     |
              V                           |                     |
       +--------------+  (ref_count > 0)  |                     |
       | standby list |-------------------+                     |
       +--------------+                                         |
              |                                                 |
              |                                                 |
              | (timeout)  +-------------+ (allocation request) |
              +----------->| delete list |----------------------+
                           +-------------+
                                   |
                                   | (timeout)
                                   |
                                   V
                             NdisFreeMemory

   In fact, the memory manager has "two-level" memory pool implementation. The
   primary pool contains child blocks which should be used next and the
   secondary pool contains members of parent blocks which are to be deleted
   soon (if they haven't been referenced before a timeout occurs). After the
   primary pool gets empty, child blocks will be popped from the secondary
   pool.

   When a parent block is moved from active list to standby list, all of it's
   child blocks are also moved to secondary pool. Similarly, when a memory
   block is popped out from secondary pool, the corresponding parent block
   is moved back to active list (usually this happens after a short delay
   time).

   If parent block haven't been referenced at the time a timeout occurs, the
   parent block is moved to a delete list. At the same time all of the child
   blocks are popped out from the memory pools.

   If memory manager runs out of pre-allocated child blocks, it checks whether
   there are any parent blocks in the delete list. If a "deleted" parent block
   exists, the memory manager re-initializes it, stores the child blocks into
   the primary pool and returns one block to the caller of ssh_kernel_alloc().
   On the other case, (when there is no blocks in the delete list,) the memory
   manager allocates a new parent block using the services of the OS kernel
   (i.e. calls NdisAllocateMemory()).

   Memory blocks are freed from delete list if they haven't been re-used
   before a "delete timeout" occurs.

   The memory manager uses still another optimization trick to decrease the
   amount of fragmentation of the allocated parent blocks. When a child block
   is "freed", it's added either to head or to tail of the primary pool
   depending from the "usage level" of the corresponding parent block. (This
   simple optimization tries to "fill" some parent blocks, while increasing
   the possibility of some other parent blocks to become "empty" (i.e.
   reference count is equal to zero). Sure, this is not a "perfect solution"
   (like a "sorted" list would be), but it's some kind of compromise between
   performance and the fragmentation of parent blocks.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "kernel_alloc.h"
#ifdef WIN95
#include "mempages.h"
#endif /* WIN95 */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorAlloc"
#define SSH_MEM_BLOCK_HAS_BEEN_FREED 0xFFFFFFFF

#ifdef _WIN64
/* Ensure correct 16 byte alignment for 64-bit windows platforms */
#define SSH_MEM_BLOCK_HEADER_BYTES    16
#else
#define SSH_MEM_BLOCK_HEADER_BYTES    (sizeof(unsigned long))
#endif /* _WIN64 */
#ifdef DEBUG_LIGHT
#define SSH_MEM_BLOCK_TRAILER_BYTES   (sizeof(unsigned long))
#else
#define SSH_MEM_BLOCK_TRAILER_BYTES   0
#endif /* DEBUG_LIGHT */

#define SSH_MEM_BLOCK_EXTRA_BYTES  \
  (SSH_MEM_BLOCK_HEADER_BYTES + SSH_MEM_BLOCK_TRAILER_BYTES)

/* definitions for debugging memory leaks */
#ifdef DEBUG_LIGHT
#define SSH_MEM_BLOCK_SIGNATURE_VALUE 0xDABBADAA
#define SSH_MEM_BLOCK_SIGNATURE_SET(ADDR,SIZE,VALUE)  \
  NdisStoreUlong((PULONG)((char *)(ADDR) + (SIZE) +   \
  SSH_MEM_BLOCK_HEADER_BYTES), (VALUE))
#define SSH_MEM_BLOCK_SIGNATURE_GET(ADDR,SIZE,VALUEP)            \
  NdisRetrieveUlong((VALUEP), (PULONG)((char *)(ADDR) + (SIZE) + \
 SSH_MEM_BLOCK_HEADER_BYTES))
#endif /* defined DEBUG_LIGHT */


/* Define this if you want to use our own "memory manager" */ 
#ifdef SSH_MM_IN_USE

/* Larger blocks are allocated from OS kernel heap */
#define SSH_MM_LARGEST_BLOCK_SIZE 32768

/* Specifies how often memory manager's timeout callback function is being
   executed. */
#define SSH_MM_TIMEOUT            5   /* 5 sec. */ 

/* Specifies the maximum time "deleted" parent blocks are held in
   delete list before they are actually freed. */ 
#define SSH_MM_DELETE_TICK_COUNT  12  /* 12 * 5 sec. = 1 min. */  

/* We use either spinlocks (Windows NT/2K/XP) or "critical sections" (Windows 
   9X) for protecting shared data structures. */ 
#ifdef WINNT
#define ssh_mm_lock(lock)   NdisAcquireSpinLock(lock)
#define ssh_mm_unlock(lock) NdisReleaseSpinLock(lock)
#else
#define ssh_mm_lock(lock)   ssh_interceptor_enter_critical_section()
#define ssh_mm_unlock(lock) ssh_interceptor_leave_critical_section()
#endif


/* Calculates the actual size of 'child blocks' (i.e. the total size including
   header structure) */
#define SSH_MM_REAL_BLOCK_SIZE(block_size) \
  (block_size + sizeof(SshMemBlockRec))

/* Calculates the "payload" size of a 'parent block' (i.e. the size which can 
   be used by 'child blocks') */ 
#define SSH_MM_USABLE_PARENT_SIZE(total_size) \
  (total_size - sizeof(SshParentHeaderRec) - sizeof(unsigned long))

/* Calculates the allocation size of a parent block (i.e. the correct value
   for ssh_kernel_alloc() - the actual size the allocated block will also
   contain space for the extra "size" field) */ 
#define SSH_MM_PARENT_ALLOC_SIZE(child_size,count)  \
  ((SSH_MM_REAL_BLOCK_SIZE(child_size) * count) + sizeof(SshParentHeaderRec))

/* Calculates the amount of child blocks which can fit into a memory block
   having the specified maximum size. */ 
#define SSH_MM_ALLOC_ITEM_STEP(block_size,total_size)  \
  (SSH_MM_USABLE_PARENT_SIZE(total_size) / SSH_MM_REAL_BLOCK_SIZE(block_size))


/* Type definition of the memory manager structure */ 
typedef struct
{
#ifdef DEBUG_LIGHT
  /* For sanity checks... */ 
  Boolean initialized;

  /* How many bytes the memory manager has allocated from system heap */ 
  unsigned long   allocated_bytes;

  /* How many bytes the interceptor & engine had currently "allocated" from
     memory manager's pools */ 
  unsigned long   reserved_bytes;
#endif DEBUG_LIGHT

  /* Active list stores currently used (reference count > 0) 'parent
     blocks' */ 
  LIST_ENTRY      active_list;

  /* Standby list stores currently unreferenced 'parent blocks'. */
  LIST_ENTRY      standby_list;

  /* Protects memory manager's data structures. This spinlock is not actually 
     used in Windows 9X environment! ("Critical sections" are being used
     instead of spin locks) */ 
  NDIS_SPIN_LOCK  lock; 
} SshMemoryManagerRec;


/* Type definition of a memory pool data structure */
typedef struct
{
  /* Size of one 'child block' */
  unsigned long block_size;     
 
  /* Amount of blocks to be allocated at one time */ 
  unsigned long alloc_items;

  /* Primary memory pool */ 
  LIST_ENTRY    primary_pool;

  /* Secondary memory pool */ 
  LIST_ENTRY    secondary_pool;

  /* "Deleted" 'parent blocks' are kept in this list for a while before the
     block is actually freed. */ 
  LIST_ENTRY    delete_list;
} SshMemoryPoolRec, * SshMemoryPool;


/* Type definition for the header of a 'parent' block (i.e. a memory block 
   which is split into smaller 'child' blocks) */ 
typedef struct
{
  LIST_ENTRY      list_entry;

  /* This reference count tells us when the parent block can be freed. */ 
  unsigned long   ref_count;  

  /* Size (in bytes) of a child block (including SshMemBlockRec header) */ 
  unsigned long   child_block_size;

  /* Total amount of child blocks "allocated" from a parent block */ 
  unsigned long   child_blocks;  

  /* Pointer to owner memory pool */ 
  SshMemoryPool   pool;

  /* Memory manager "tick count", after which the block will be finally
     freed from owner memory pool's delete_list */ 
  unsigned long   delete_tick_count;
} SshParentHeaderRec, * SshParentHeader;


/* Type definition of the header of a "child block". */ 
typedef struct _SshMemBlockRec
{
  LIST_ENTRY      list_entry;

  /* Pointer to parent block */ 
  SshParentHeader parent;

  /*--- Don't change! ---*/
  unsigned long   size;   
  char            ptr[4]; /* Actual block size varies... */ 
  /*--- Don't change! ---*/
} SshMemBlockRec, * SshMemBlock;


/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/* Configuration of memory pools. If you modify this, you should also check
   the value of SSH_MM_LARGEST_BLOCK_SIZE and the correct operation of 
   (optimized) index calculation code in ssh_mm_block_allocate(). */
static SshMemoryPoolRec  ssh_mm_pool[] = {
  {32, SSH_MM_ALLOC_ITEM_STEP(32, 9*PAGE_SIZE), {0}, {0}},   
  {128, SSH_MM_ALLOC_ITEM_STEP(128, 9*PAGE_SIZE), {0}, {0}},    
  {512, SSH_MM_ALLOC_ITEM_STEP(512, 9*PAGE_SIZE), {0}, {0}},    
  {2048, SSH_MM_ALLOC_ITEM_STEP(2048, 17*PAGE_SIZE), {0}, {0}},
  {8192, SSH_MM_ALLOC_ITEM_STEP(8192, 33*PAGE_SIZE), {0}, {0}},
  {32768, SSH_MM_ALLOC_ITEM_STEP(32768, 65*PAGE_SIZE), {0}, {0}}};

/* This is our "memory manager"... */ 
static SshMemoryManagerRec  ssh_mmgr;

#endif /* SSH_MM_IN_USE */ 

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

#ifdef SSH_MM_IN_USE

void ssh_mm_timer(void * context);

/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_mm_timer()

  Timer callback function, which handles the "state transitions" and final
  deletions of parent blocks.

  Arguments:
    context - unused context parameter (pointer to memory_manager's standby
              list)

  Returns:
    -

  Notes:
    -
  --------------------------------------------------------------------------*/

void ssh_mm_timer(void * context)
{
  unsigned int  i;

  ssh_mm_lock(&ssh_mmgr.lock);

  if (IsListEmpty(&ssh_mmgr.standby_list) == FALSE)
    {
      do
        {
          SshParentHeader parent;

          PLIST_ENTRY entry = RemoveHeadList(&ssh_mmgr.standby_list);

          parent = CONTAINING_RECORD(entry, SshParentHeaderRec, list_entry);

          if (parent->ref_count == 0)
            {
              /* All 'child blocks' must be removed from memory pools */ 
              for (i = 0; i < parent->child_blocks; i++)
                {
                  SshMemBlock child;

                  child = (SshMemBlock)((unsigned char *)(parent) + 
                                           sizeof(SshParentHeaderRec) +
                                           (i * parent->child_block_size));

                  /* It doesn't matter whether the item is actually stored
                     to primary or secondary pool. We just pull it out! */ 
                  RemoveEntryList(&child->list_entry);
                }

#ifdef DEBUG_LIGHT
              ssh_mmgr.allocated_bytes -= parent->child_blocks *
                                          parent->child_block_size;
#endif /* DEBUG_LIGHT */ 

              /* Move the 'parent block' to delete_list (so it can still be 
                 re-used before it's actually freed). */ 
              parent->delete_tick_count = SSH_MM_DELETE_TICK_COUNT; 

              InitializeListHead(&parent->list_entry);  
              InsertTailList(&parent->pool->delete_list, &parent->list_entry);
            }
          else
            {
              /* This block has been "re-activated", so let's move it back
                 to active list. */
              InitializeListHead(&parent->list_entry); 
              InsertTailList(&ssh_mmgr.active_list, &parent->list_entry);
            }
        }
      while (IsListEmpty(&ssh_mmgr.standby_list) == FALSE);
    }
  else
    {
      PLIST_ENTRY entry = ssh_mmgr.active_list.Flink;

      do
        {
          SshParentHeader parent;

          parent = CONTAINING_RECORD(entry, SshParentHeaderRec, list_entry);

          entry = entry->Flink;

          if (parent->ref_count == 0)
            {
              /* Move parent block to standby_list */ 
              RemoveEntryList(&parent->list_entry);
              InitializeListHead(&parent->list_entry);
              InsertTailList(&ssh_mmgr.standby_list, &parent->list_entry);

              /* Move child blocks to secondary_pool */ 
              for (i = 0; i < parent->child_blocks; i++)
                {
                  SshMemBlock child;
  
                  child = (SshMemBlock)((unsigned char *)(parent) + 
                                           sizeof(SshParentHeaderRec) +
                                           (i * parent->child_block_size));

                  RemoveEntryList(&child->list_entry);
                  InitializeListHead(&child->list_entry);
                  InsertTailList(&parent->pool->secondary_pool,
                                 &child->list_entry);
                }

            }
        }
      while (entry != &ssh_mmgr.active_list);
    }

  /* Free 'expired' blocks from the delete_lists... */ 
  for (i = 0; i < (sizeof(ssh_mm_pool) / sizeof(ssh_mm_pool[0])); i++)
    {
      if (IsListEmpty(&ssh_mm_pool[i].delete_list) == FALSE)
        {
          PLIST_ENTRY entry = ssh_mm_pool[i].delete_list.Flink;

          do
            {
              SshParentHeader parent = CONTAINING_RECORD(entry, 
                                                    SshParentHeaderRec, 
                                                    list_entry);

              entry = entry->Flink;

              if (parent->delete_tick_count == 0)
                {
                  /* Nobody re-used the block, so now it's time to
                     deallocate it */ 
                  RemoveEntryList(&parent->list_entry);

                  ssh_kernel_free(parent);
                }
              else
                parent->delete_tick_count--;
            }
          while (entry != &ssh_mm_pool[i].delete_list);
        }
    }

  ssh_mm_unlock(&ssh_mmgr.lock);

  ssh_kernel_timeout_register(SSH_MM_TIMEOUT, 0, ssh_mm_timer, context);
}


/*--------------------------------------------------------------------------
  ssh_mm_blocks_add()

  Allocates and inserts new "child blocks" to memory pool. Re-uses "deleted"
  "parent blocks" whenever possible.

  Arguments:
    pool  - pointer to (block size specific) memory pool

  Returns:
    TRUE  More blocks successfully added.
    FALSE Some error occurred.

  Notes:
    -
  --------------------------------------------------------------------------*/

__inline Boolean ssh_mm_blocks_add(SshMemoryPool pool)
{
  unsigned char * new_block;
  Boolean         status = FALSE;

  ssh_mm_lock(&ssh_mmgr.lock);

  if (IsListEmpty(&pool->delete_list) == FALSE)
    {
      PLIST_ENTRY entry = RemoveHeadList(&pool->delete_list);

      /* We can re-use "deleted" one */ 
      new_block = (unsigned char *) CONTAINING_RECORD(entry,
                                          SshParentHeaderRec, list_entry);

      ssh_mm_unlock(&ssh_mmgr.lock);
    }
  else
    {
      /* We must allocate more memory */ 
      ssh_mm_unlock(&ssh_mmgr.lock);

      new_block = ssh_kernel_alloc(SSH_MM_PARENT_ALLOC_SIZE(pool->block_size,
                                                      pool->alloc_items), 0);
    }

  if (new_block != NULL)
    {
      unsigned int    i;
      SshParentHeader parent = (SshParentHeader)new_block;

      parent->ref_count = 0;
      parent->pool = pool;
      parent->child_blocks = pool->alloc_items;
      parent->child_block_size = SSH_MM_REAL_BLOCK_SIZE(pool->block_size);

      new_block += sizeof(SshParentHeaderRec);

      ssh_mm_lock(&ssh_mmgr.lock);

      InitializeListHead(&parent->list_entry);
      InsertTailList(&ssh_mmgr.active_list, &parent->list_entry);

      for (i = 0; i < parent->child_blocks; i++)
        {
          SshMemBlock child_block = (SshMemBlock)(new_block + 
                                        (i * parent->child_block_size));

          child_block->parent = parent;
          InitializeListHead(&child_block->list_entry);
          InsertTailList(&parent->pool->primary_pool, 
                         &child_block->list_entry);
        }

#ifdef DEBUG_LIGHT
      ssh_mmgr.allocated_bytes += parent->child_blocks *
                                  parent->child_block_size;
#endif /* DEBUG_LIGHT */ 

      ssh_mm_unlock(&ssh_mmgr.lock);

      status = TRUE;
    }

  return status;
}


/*--------------------------------------------------------------------------
  ssh_mm_block_allocate()

  Allocates a meory block from a memory manager's pool. Allocates more
  memory from OS kernel when necessary.

  Arguments:
    size  - size (in bytes) of the memory block to be allocated.

  Returns:
    Pointer to "allocated" memory block or NULL pointer if the specified
    amount of memory can't be allocated.

  Notes:
    When you modify this function, you should be careful with the stack 
    usage, because "ssh_mm_blocks_add" could be a recursive call to
    ssh_kernel_alloc().
  --------------------------------------------------------------------------*/

__inline void * ssh_mm_block_allocate(unsigned long size)
{
  SshMemBlock   mem_block = NULL;
  unsigned int  i = 0;
  unsigned long temp = (size-1) >> 5; /* Smallest block == 32 bytes */ 

  SSH_ASSERT(ssh_mmgr.initialized);
  SSH_ASSERT(size > 0);

  /* Calculate the index to ssh_mm_pool table... */
  while (temp)
    {
      temp >>= 2; 
      i++;
    };

  SSH_ASSERT(i < sizeof(ssh_mm_pool) / sizeof(ssh_mm_pool[0]));

  do
    {
      ssh_mm_lock(&ssh_mmgr.lock);

      /* Lookup/memory allocation order */ 
      /* 1. Primary pool */ 
      /* 2. Secondary pool */ 
      /* 3. Add more blocks to primary pool */ 
      if (IsListEmpty(&(ssh_mm_pool[i].primary_pool)) == FALSE)
        {
          PLIST_ENTRY entry = RemoveHeadList(&(ssh_mm_pool[i].primary_pool));

          mem_block = CONTAINING_RECORD(entry, SshMemBlockRec, 
                                        list_entry);
        }
      else if (IsListEmpty(&(ssh_mm_pool[i].secondary_pool)) == FALSE)
        {
          PLIST_ENTRY entry = RemoveHeadList(&(ssh_mm_pool[i].secondary_pool));

          mem_block = CONTAINING_RECORD(entry, SshMemBlockRec, 
                                        list_entry);
        }
      else
        {
          ssh_mm_unlock(&ssh_mmgr.lock);

          if (ssh_mm_blocks_add(&(ssh_mm_pool[i])) == FALSE)
            return NULL;  /* failed */ 
        }
    }
  while (mem_block == NULL);

  /* Reference count must be incremented before the lock is released */
  mem_block->parent->ref_count++;

#ifdef DEBUG_LIGHT
  ssh_mmgr.reserved_bytes += mem_block->parent->child_block_size;
#endif /* DEBUG_LIGHT */ 

  ssh_mm_unlock(&ssh_mmgr.lock);

  mem_block->size = size;

  return (mem_block->ptr);
}


/*--------------------------------------------------------------------------
  ssh_mm_block_free()

  Frees a memory block by storing it back into the primary memory pool.

  Arguments:
    ptr - pointer to memory block to be "freed".

  Returns:
    -

  Notes:
    -
  --------------------------------------------------------------------------*/

__inline void ssh_mm_block_free(void * ptr)
{
  SshMemBlock mem_block = CONTAINING_RECORD(ptr, SshMemBlockRec, size);

  ssh_mm_lock(&ssh_mmgr.lock);

  mem_block->parent->ref_count--;

#ifdef DEBUG_LIGHT
  ssh_mmgr.reserved_bytes -= mem_block->parent->child_block_size;
#endif /* DEBUG_LIGHT */

  /* This simple 'sorting' decreases the fragmentation of 'parent blocks'. */
  switch ((mem_block->parent->ref_count << 3) /
          mem_block->parent->child_blocks)
    {
    case 0: /* < 50 % used */ 
    case 1:
    case 2:
    case 3:
      InitializeListHead(&mem_block->list_entry);
      InsertTailList(&mem_block->parent->pool->primary_pool, 
                     &mem_block->list_entry);
      break;

    default:
      InitializeListHead(&mem_block->list_entry);
      InsertHeadList(&mem_block->parent->pool->primary_pool, 
                     &mem_block->list_entry);
      break;
    }

  ssh_mm_unlock(&ssh_mmgr.lock);
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_mm_initialize()

  Initializes the memory manager.

  Arguments:
    -

  Returns:
    -

  Notes:
    This function must be called before any memory allocations happen, so 
    it's better to call this function immediately at the beginning of your 
    DriverEntry/WhatEverEntryPointFunction.
  --------------------------------------------------------------------------*/

void ssh_mm_initialize(void)
{
  unsigned int  i;

  NdisAllocateSpinLock(&ssh_mmgr.lock);

  for (i = 0; i < sizeof(ssh_mm_pool) / sizeof(ssh_mm_pool[0]); i++)
    {
      InitializeListHead(&(ssh_mm_pool[i].primary_pool));
      InitializeListHead(&(ssh_mm_pool[i].secondary_pool));
      InitializeListHead(&(ssh_mm_pool[i].delete_list));
    }

  InitializeListHead(&ssh_mmgr.active_list);
  InitializeListHead(&ssh_mmgr.standby_list);

#ifdef DEBUG_LIGHT
  ssh_mmgr.initialized = TRUE;
#endif
}


/*--------------------------------------------------------------------------
  ssh_mm_uninitialize()

  Un-initializes the memory manager and frees all allocated resources.

  Arguments:
    -

  Returns:
    -

  Notes:
    This function must be called just before your driver is being unloaded,
    so it's better to call this function just before your DriverUnload
    routine returns.
  --------------------------------------------------------------------------*/

void ssh_mm_uninitialize(void)
{
  SshParentHeader parent;
  PLIST_ENTRY   entry;
  unsigned int  i;

  /* 1. Active list */
  while (IsListEmpty(&ssh_mmgr.active_list) == FALSE)
    {
      entry = RemoveHeadList(&ssh_mmgr.active_list);
      parent = CONTAINING_RECORD(entry, SshParentHeaderRec, list_entry);
      ssh_kernel_free(parent);
    };
  
  /* 2. Standby list */ 
  while (IsListEmpty(&ssh_mmgr.standby_list) == FALSE)
    {
      entry = RemoveHeadList(&ssh_mmgr.standby_list);
      parent = CONTAINING_RECORD(entry, SshParentHeaderRec, list_entry);
      ssh_kernel_free(parent);
    };
  

  /* 3. Delete lists */ 
  for (i = 0; i < (sizeof(ssh_mm_pool) / sizeof(ssh_mm_pool[0])); i++)
    {
      while (IsListEmpty(&ssh_mm_pool[i].delete_list) == FALSE)
        {
          entry = RemoveHeadList(&ssh_mm_pool[i].delete_list);
          parent = CONTAINING_RECORD(entry, SshParentHeaderRec, list_entry);
          ssh_kernel_free(parent);
        };
    }

  NdisFreeSpinLock(&ssh_mmgr.lock);
  NdisZeroMemory(&ssh_mmgr, sizeof(ssh_mmgr));
}


/*--------------------------------------------------------------------------
  ssh_mm_start()

  "Starts" the memory manager. If memory manager is not "started", memory
  can be allocated, but free blocks are never given back to OS kernel heap.

  Arguments:
    -

  Returns:
    -

  Notes:
    You must not call this function before your interceptor's timeout handling
    code is up and running.
  --------------------------------------------------------------------------*/

void ssh_mm_start(void)
{
  SSH_ASSERT(ssh_mmgr.initialized);

  ssh_kernel_timeout_register(SSH_MM_TIMEOUT, 0, 
                              ssh_mm_timer, &ssh_mmgr.standby_list);
}


/*--------------------------------------------------------------------------
  ssh_mm_stop()

  "Stops" the memory manager.

  Arguments:
    -

  Returns:
    -

  Notes:
    You must call this function before you stop your interceptor's timeout 
    handling code.
  --------------------------------------------------------------------------*/

void ssh_mm_stop(void)
{
  ssh_kernel_timeout_cancel(ssh_mm_timer, &ssh_mmgr.standby_list);
}

#endif /* SSH_MM_IN_USE */


/*--------------------------------------------------------------------------
  ssh_kernel_alloc()

  Allocate 'size' amount of memory, with the 'flag' parameters. 

  Arguments:
    size  - size (in bytes) of memory block to be allocated
    flags - optional flags (not used by this function)

  Returns:
    Returns a either a valid pointer to the allocated memory block or NULL 
    value if the allocation request cannot be satisfied for some reason.

  Notes:
    -
  --------------------------------------------------------------------------*/

#pragma warning(disable : 4100 6011 6014) 

void * ssh_kernel_alloc(size_t size, SshUInt32 flags)
{
  char * addr;

#ifdef SSH_MM_IN_USE
  if (size <= SSH_MM_LARGEST_BLOCK_SIZE)
    return ssh_mm_block_allocate(size);
#endif /* SSH_MM_IN_USE */

#if defined(NDIS_SUPPORT_NDIS6)
  addr = ExAllocatePoolWithTagPriority(NonPagedPool, 
          (size + SSH_MEM_BLOCK_EXTRA_BYTES), 
          'TNFS', 
          NormalPoolPriority);
  if (addr == NULL) 
    return NULL;
#else
  if (NdisAllocateMemoryWithTag(&addr, 
                                (ULONG)size + SSH_MEM_BLOCK_EXTRA_BYTES, 
                                'TNFS') != NDIS_STATUS_SUCCESS)
    return NULL;
#endif

  NdisStoreUlong((PULONG)addr, (ULONG)size);
#ifdef DEBUG_LIGHT  
  SSH_MEM_BLOCK_SIGNATURE_SET(addr,size,SSH_MEM_BLOCK_SIGNATURE_VALUE);
#endif /* defined DEBUG_LIGHT */  
  return (void*)(addr + SSH_MEM_BLOCK_HEADER_BYTES);
}

#pragma warning(default : 4100 6011 6014) 

/*--------------------------------------------------------------------------
  ssh_kernel_free()

  Frees a previously allocated block of memory.

  Arguments:
    addr  - pointer to memory block to be freed.

  Returns:
    -

  Notes:
    -
  --------------------------------------------------------------------------*/

void ssh_kernel_free(void * addr)
{
  unsigned long size;
#ifdef DEBUG_LIGHT
#ifndef SSH_MM_IN_USE
  ULONG signature;
#endif /* not defined SSH_MM_IN_USE */
#endif /* defined DEBUG_LIGHT */
  
  addr = (unsigned char *)addr - SSH_MEM_BLOCK_HEADER_BYTES;
  NdisRetrieveUlong(&size, addr);

#ifdef DEBUG_LIGHT
#ifndef SSH_MM_IN_USE
  /* check if end of the block is overwritten by somebody */
  SSH_MEM_BLOCK_SIGNATURE_GET(addr,size,&signature);
  if (signature != SSH_MEM_BLOCK_SIGNATURE_VALUE)
    {
      SSH_DEBUG(SSH_D_ERROR,
		("Memory block signature or size overwritten"
		 " - addr %p, size %d",
		 addr, size));
      SSH_NOTREACHED;
    }
#endif /* not defined SSH_MM_IN_USE */
#endif /* defined DEBUG_LIGHT */
  
  SSH_ASSERT(size != SSH_MEM_BLOCK_HAS_BEEN_FREED);
  NdisStoreUlong((PULONG)addr, SSH_MEM_BLOCK_HAS_BEEN_FREED);

#ifdef SSH_MM_IN_USE
  if (size <= SSH_MM_LARGEST_BLOCK_SIZE)
    ssh_mm_block_free(addr);
  else 
#endif /* SSH_MM_IN_USE */ 
    {
#if defined(NDIS_SUPPORT_NDIS6)
    ExFreePool(addr);
#else
      size += SSH_MEM_BLOCK_EXTRA_BYTES;
      NdisFreeMemory(addr, size, 0);
#endif
    }
}

