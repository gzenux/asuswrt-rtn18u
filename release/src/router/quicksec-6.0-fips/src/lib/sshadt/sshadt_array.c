/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshadt_array.h"
#include "sshadt_array_i.h"
#include "sshadt_std_i.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTArray"

#define ROOT(c)     ((SshADTArrayRoot *)(c->container_specific))


#ifdef HAVE_SEGMENTED_MEMORY

/* If we have segmented memory, then the latter trick to encode a
   (smallish) integer value to a pointer may not work.  But this
   should work.  */
#define PTRTOUINT(ptr) (((unsigned char *)(ptr)) - ((unsigned char *)c))
#define UINTTOPTR(i)   (&(((unsigned char *)c)[i]))

#else /* !HAVE_SEGMENTED_MEMORY */

/* We need to add and subtract one because otherwise the index zero
   would actually correspond to SSH_ADT_INVALID, which would be
   confusing. */
#define PTRTOUINT(ptr) ((((unsigned char *)(ptr)) - ((unsigned char *)0)) - 1)
#define UINTTOPTR(i) (&(((unsigned char *)0)[i + 1]))

#endif /* !HAVE_SEGMENTED_MEMORY */


static Boolean init(SshADTContainer c)
{
  /* Handles are of type (void *)idx.  */
#if SIZEOF_VOID_P < SIZEOF_INT
#error "SIZEOF_VOID_P < SIZEOF_INT"
#endif

  /* The dynamic array type has zero-sized headers so they should
     not be 'contained'. */
  SSH_ASSERT(!(c->flags & SSH_ADT_FLAG_CONTAINED_HEADER) &&
             "See documentation (array specifics section).");

  if ((c->container_specific = ssh_malloc(sizeof(*ROOT(c)))) == NULL)
    return FALSE;

  ROOT(c)->array = NULL;
  ROOT(c)->array_size = 0;

  return TRUE;
}

/* $$METHOD(array, clear) */
static void clear(SshADTContainer c)
{
  int i;
  for (i = 0; i < ROOT(c)->array_size; i++)
    {
      if (ROOT(c)->array[i] != NULL)
        ssh_adt_delete(c, UINTTOPTR(i));
    }
}

/* $$METHOD(pq, clear) */
static void pq_clear(SshADTContainer c)
{
  SshADTHandle h = UINTTOPTR(0);

  while (c->num_objects > 0)
    {
      ssh_adt_delete(c, h);
    }
}

/* $$METHOD(array, container_init) */
/* $$METHOD(pq, container_init) */
SSH_ADT_STD_INIT(container_init, init(c))

static void uninit(SshADTContainer c)
{
  clear(c);
  ssh_free(ROOT(c)->array);
  ssh_free(ROOT(c));
}

static void pq_uninit(SshADTContainer c)
{
  pq_clear(c);
  ssh_free(ROOT(c)->array);
  ssh_free(ROOT(c));
}

/* $$METHOD(array, destr) */
SSH_ADT_STD_DESTROY(destr, uninit(c);)

/* $$METHOD(pq, destr) */
SSH_ADT_STD_DESTROY(pq_destr, pq_uninit(c);)

/* After calling initialize_cell(c, n), the nth (0-based) cell is
   valid and empty. The array is expanded if necessary, and if there
   was an object at the nth cell, the object has been deleted.

   In usermode or if enough memory is available, initialize_cell
   always succeeds and returns TRUE.  In kernel mode and if
   ssh_calloc returns NULL, the new cell is not allocated and
   FALSE is returned. */
static Boolean initialize_cell(SshADTContainer c, unsigned int idx)
{
  size_t i, old_size, new_size;
  void **array;

  if (ROOT(c)->array_size <= idx)
    {
      old_size = ROOT(c)->array_size;
      new_size = idx + (idx / 4) + 1;

      if ((array =
           ssh_realloc(ROOT(c)->array,
                       old_size * sizeof(ROOT(c)->array[0]),
                       new_size * sizeof(ROOT(c)->array[0]))) == NULL)
        return FALSE;

      ROOT(c)->array = array;

      for (i = old_size; i < new_size ; i++)
        array[i] = NULL;

      ROOT(c)->array_size = new_size;
      return TRUE;
    }
  else
    {
      if (ROOT(c)->array[idx] != NULL)
        ssh_adt_delete(c, UINTTOPTR(idx));
    }

  return TRUE;
}

/* Translate special and index absolute locations into integer indices
   needed for the internal access to a cell.  The cell might still
   need to be allocated.  */
static unsigned int get_index(SshADTContainer c,
                              SshADTAbsoluteLocation location)
{
  switch (location)
    {
      case SSH_ADT_BEGINNING:
      case SSH_ADT_DEFAULT:
        return 0;
      case SSH_ADT_END:
        if (c->num_objects > 0)
          return c->num_objects - 1;
        else
          return 0;
      default:
        return SSH_ADT_GET_INDEX(location);
    }
}

/* Initialize a new cell, using arbitrary absolute locations as input.
   This function at the same time loads the index into the third
   argument so that it can be used by the caller.  */
static Boolean empty_idx(SshADTContainer c,
                         SshADTAbsoluteLocation location,
                         unsigned int *idx)
{
  *idx = get_index(c, location);
  return initialize_cell(c, *idx);
}

/* $$METHOD(array, insert_to) */
static SshADTHandle insert_to(SshADTContainer c,
                              SshADTAbsoluteLocation location,
                              void *object)
{
  unsigned int idx;
  SshADTHandle h;

  if (!empty_idx(c, location, &idx))
    return SSH_ADT_INVALID;

  ROOT(c)->array[idx] = object;
  c->num_objects++;
  h = UINTTOPTR(idx);
  SSH_ADT_CALL_HOOK(c, insert, h);
  return h;
}

/* the percolation functions implement a binary tree structure inside
   the array.  the tree is stored in breadth-first-search order, ie.
   the left child of idx is stored in (idx << 1 + 1) and the right
   child is stored in (idx << 1 + 2).  eg., the tree

              A
             / \
            B   C
           / \
          D   E
               \
                F

   would be stored as

        0   1   2   3   4   5   6   7   8   9  10  11  12  13  14
     -------------------------------------------------------------
     | A | B | C | D | E | * | * | * | * | * | F | * | * | * | * |
     -------------------------------------------------------------

   If a new object is inserted at idx, percolate_up reenforces the
   order of the tree by moving it "up" the path to the root until its
   parent is smaller; if an object is removed from idx, percolate_down
   moves it down the tree until it ends up in a leaf, maintaining the
   invariant that left children are always smaller than their parents
   and right children are always greater.  */

static void percolate_up(SshADTContainer c, int idx)
{
  int parent;
  int cmp;
  void *tmp;

  while (idx > 0)
    {
      parent = (idx - 1) >> 1;
      SSH_ADT_CALL_APP_MANDATORY(c, compare,
                                 (ROOT(c)->array[idx],
                                  ROOT(c)->array[parent],
                                  SSH_ADT_APPCTX(c)),
                                 cmp);
      SSH_DEBUG(9, ("Comp %d %d == %d\n", idx, parent, cmp));
      if (cmp >= 0) return;
      tmp = ROOT(c)->array[parent];
      ROOT(c)->array[parent] = ROOT(c)->array[idx];
      ROOT(c)->array[idx] = tmp;
      idx = parent;
    }
}

static void percolate_down(SshADTContainer c, int idx)
{
  int left, right, child;
  int cmp, child_cmp;
  void *tmp;

  while (left = (idx << 1) + 1,
         right = left + 1,
         left < c->num_objects)
    {
      if (right < c->num_objects)
        {
          SSH_ADT_CALL_APP_MANDATORY(c, compare,
                                     (ROOT(c)->array[left],
                                      ROOT(c)->array[right],
                                      SSH_ADT_APPCTX(c)),
                                     child_cmp);
        }
      else
        {
          child_cmp = -1; /* use the left branch anyway */
        }
      if (child_cmp < 0) child = left; else child = right;

      SSH_ADT_CALL_APP_MANDATORY(c, compare,
                                 (ROOT(c)->array[idx],
                                  ROOT(c)->array[child],
                                  SSH_ADT_APPCTX(c)),
                                 cmp);
      if (cmp <= 0) return;
      tmp = ROOT(c)->array[child];
      ROOT(c)->array[child] = ROOT(c)->array[idx];
      ROOT(c)->array[idx] = tmp;

      idx = child;
    }
}

/* $$METHOD(pq, insert_to) */
static SshADTHandle pq_insert_to(SshADTContainer c,
                                 SshADTAbsoluteLocation location,
                                 void *object)
{
  unsigned int idx;

  SSH_ASSERT(location == SSH_ADT_DEFAULT);

  idx = c->num_objects; /* Add to the end. */
  if (!initialize_cell(c, idx))
    return SSH_ADT_INVALID;

  ROOT(c)->array[idx] = object;
  c->num_objects++;
  percolate_up(c, idx);
  return UINTTOPTR(0);
}

/* $$METHOD(array, get) */
/* $$METHOD(pq, get) */
static void *get(SshADTContainer c, SshADTHandle h)
{
  size_t idx = PTRTOUINT(h);
  SSH_ASSERT(idx < ROOT(c)->array_size);
  return ROOT(c)->array[idx];
}

/* $$METHOD(array, get_handle_to_location) */
static SshADTHandle get_handle_to_location(SshADTContainer c,
                                           SshADTAbsoluteLocation location)
{
  unsigned int idx = get_index(c, location);

  if (idx >= ROOT(c)->array_size) return SSH_ADT_INVALID;
  else return UINTTOPTR(idx);
}

/* $$METHOD(pq, get_handle_to_location) */
static SshADTHandle pq_get_handle_to_location(SshADTContainer c,
                                              SshADTAbsoluteLocation location)
{
  SSH_ASSERT(location == SSH_ADT_DEFAULT);

  if (c->num_objects == 0) return SSH_ADT_INVALID;
  else return UINTTOPTR(0);
}

/* $$METHOD(array, alloc_n_to) */
static SshADTHandle alloc_n_to(SshADTContainer c,
                               SshADTAbsoluteLocation location,
                               size_t size)
{
  unsigned int idx;
  SshADTHandle h;
  void *newp;

  if (!empty_idx(c, location, &idx))
    return SSH_ADT_INVALID;
  if ((ROOT(c)->array[idx] = newp = ssh_malloc(size)) == NULL)
    return SSH_ADT_INVALID;

  c->num_objects++;
  h = UINTTOPTR(idx);
  SSH_ADT_CALL_APP(c, init, (newp, size, SSH_ADT_APPCTX(c)));
  SSH_ADT_CALL_HOOK(c, insert, h);
  return h;
}

/* $$METHOD(array, put_n_to) */
static SshADTHandle put_n_to(SshADTContainer c,
                             SshADTAbsoluteLocation location,
                             size_t size,
                             void *object)
{
  unsigned int idx;
  SshADTHandle h;
  void *newp;

  if (!empty_idx(c, location, &idx))
    return SSH_ADT_INVALID;
  if ((ROOT(c)->array[idx] = newp = ssh_malloc(size)) == NULL)
    return SSH_ADT_INVALID;

  c->num_objects++;
  h = UINTTOPTR(idx);
  SSH_ADT_CALL_APP(c, copy, (newp, size, object, SSH_ADT_APPCTX(c)));
  SSH_ADT_CALL_HOOK(c, insert, h);
  return h;
}

/* $$METHOD(pq, alloc_n_to) */
static SshADTHandle pq_alloc_n_to(SshADTContainer c,
                                  SshADTAbsoluteLocation location,
                                  size_t size)
{
  unsigned int idx;
  SshADTHandle h;
  void *newp;

  SSH_ASSERT(location == SSH_ADT_DEFAULT);

  idx = c->num_objects;
  if (!initialize_cell(c, idx))
    return SSH_ADT_INVALID;
  if ((ROOT(c)->array[idx] = newp = ssh_malloc(size)) == NULL)
    return SSH_ADT_INVALID;

  c->num_objects++;
  h = UINTTOPTR(idx);
  SSH_ADT_CALL_APP(c, init, (newp, size, SSH_ADT_APPCTX(c)));
  percolate_up(c, idx);
  return h;
}

/* $$METHOD(pq, put_n_to) */
static SshADTHandle pq_put_n_to(SshADTContainer c,
                                SshADTAbsoluteLocation location,
                                size_t size,
                                void *object)
{
  unsigned int idx;
  SshADTHandle h;
  void *newp;

  SSH_ASSERT(location == SSH_ADT_DEFAULT);

  idx = c->num_objects;
  if (!initialize_cell(c, idx))
    return SSH_ADT_INVALID;
  if ((ROOT(c)->array[idx] = newp = ssh_malloc(size)) == NULL)
    return SSH_ADT_INVALID;

  c->num_objects++;
  h = UINTTOPTR(idx);
  SSH_ADT_CALL_APP(c, copy, (newp, size, object, SSH_ADT_APPCTX(c)));
  percolate_up(c, idx);
  return h;
}

/* $$METHOD(array, num_objects) */
/* $$METHOD(pq,    num_objects) */
SSH_ADT_STD_NUM_OBJECTS(num_objects)

/* $$METHOD(array, get_handle_to) */
/* $$METHOD(pq,    get_handle_to) */
static SshADTHandle get_handle_to(SshADTContainer c, void *object)
{
  unsigned int i;
  for (i = 0; i < ROOT(c)->array_size; i++)
    {
      if (ROOT(c)->array[i] == object)
        return UINTTOPTR(i);
    }
  return SSH_ADT_INVALID;
}

/* $$METHOD(array, enumerate_start) */
/* $$METHOD(pq, enumerate_start) */
static SshADTHandle enum_start(SshADTContainer c)
{
  if (c->num_objects == 0) return SSH_ADT_INVALID;
  else return UINTTOPTR(0);
}

/* $$METHOD(array, enumerate_next) */
static SshADTHandle enum_next(SshADTContainer c, SshADTHandle h)
{
  size_t idx = PTRTOUINT(h);
  SSH_ASSERT(h != SSH_ADT_INVALID);
  idx++;
  if (idx >= ROOT(c)->array_size) return SSH_ADT_INVALID;
  else return UINTTOPTR(idx);
}

/* $$METHOD(pq, enumerate_next) */
static SshADTHandle pq_enum_next(SshADTContainer c, SshADTHandle h)
{
  size_t idx = PTRTOUINT(h);
  SSH_ASSERT(h != SSH_ADT_INVALID);
  idx++;
  if (idx >= c->num_objects) return SSH_ADT_INVALID;
  else return UINTTOPTR(idx);
}

/* $$METHOD(array, detach) */
static void *detach(SshADTContainer c, SshADTHandle h)
{
  void *object;
  size_t idx = PTRTOUINT(h);

  SSH_ASSERT(h != SSH_ADT_INVALID);
  SSH_ASSERT(idx < ROOT(c)->array_size);

  SSH_ADT_CALL_HOOK(c, detach, h);

  c->num_objects--;

  object = ROOT(c)->array[idx];
  ROOT(c)->array[idx] = NULL;
  return object;
}

/* $$METHOD(pq, detach) */
static void *pq_detach(SshADTContainer c, SshADTHandle h)
{
  void *object;
  size_t idx = PTRTOUINT(h);

  SSH_ASSERT(h != SSH_ADT_INVALID);
  SSH_ASSERT(idx < ROOT(c)->array_size);

  SSH_ADT_CALL_HOOK(c, detach, h);

  object = ROOT(c)->array[idx];

  c->num_objects--;
  ROOT(c)->array[idx] = ROOT(c)->array[c->num_objects];
  ROOT(c)->array[c->num_objects] = NULL;
  percolate_down(c, idx);

  return object;
}

/* $$METHOD(array, delet) */
/* $$METHOD(pq, delet) */
static void delet(SshADTContainer c, SshADTHandle handle)
{
  void *object = ssh_adt_detach_i(c, handle);
  SSH_ADT_CALL_APP(c, destr, (object, SSH_ADT_APPCTX(c)));
  if (c->flags & SSH_ADT_FLAG_ALLOCATE)
    {
      ssh_free(object);
    }
}

const SshADTStaticData ssh_adt_array_static_data =
{
  {
    /* $$METHODS(array) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    clear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    insert_to, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    alloc_n_to, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    put_n_to, /* put_n_to */
    get, /* get */
    num_objects, /* num_objects */
    get_handle_to, /* get_handle_to */
    get_handle_to_location, /* get_handle_to_location */
    NULL_FNPTR, /* next */
    NULL_FNPTR, /* previous */
    enum_start, /* enumerate_start */
    enum_next, /* enumerate_next */
    NULL_FNPTR, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    detach, /* detach */
    delet, /* delet */
    NULL_FNPTR, /* map_lookup */
    NULL_FNPTR, /* map_attach */
    /* $$ENDMETHODS */
  },
  0,
  0
};

const SshADTStaticData ssh_adt_pq_static_data =
{
  {
    /* $$METHODS(pq) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    pq_clear, /* clear */
    pq_destr, /* destr */
    NULL_FNPTR, /* insert_at */
    pq_insert_to, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    pq_alloc_n_to, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    pq_put_n_to, /* put_n_to */
    get, /* get */
    num_objects, /* num_objects */
    get_handle_to, /* get_handle_to */
    pq_get_handle_to_location, /* get_handle_to_location */
    NULL_FNPTR, /* next */
    NULL_FNPTR, /* previous */
    enum_start, /* enumerate_start */
    pq_enum_next, /* enumerate_next */
    NULL_FNPTR, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    pq_detach, /* detach */
    delet, /* delet */
    NULL_FNPTR, /* map_lookup */
    NULL_FNPTR, /* map_attach */
    /* $$ENDMETHODS */
  },
  0,
  0
};


const SshADTContainerType ssh_adt_array_type = &ssh_adt_array_static_data;
const SshADTContainerType ssh_adt_priority_queue_type =
                            &ssh_adt_pq_static_data;
