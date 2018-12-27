/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshadt_map.h"
#include "sshadt_bag.h"
#include "sshadt_map_i.h"
#include "sshadt_std_i.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTMap"

/* how big is the array initially, also, see init() for prev_array_size. */
#define SSH_ADT_MAP_INITIAL_SLOTS   13

/* How many objects must be in one slot before rehashing the array?
   if (objects > X * slots), naturally grow the array size. The array
   size is never decreased. Of course this statistical method does not
   guarantee chain lengths ... */
#define SSH_ADT_MAP_RATIO           30

/* convenience macros */
#define ROOT(c)  ((SshADTMapRoot *)(c->container_specific))
#define NODE(x)  ((SshADTMapNode *)(x))


static void free_node(SshADTContainer c, void *node)
{
  ssh_free(node);
}

static Boolean init_to_size(SshADTContainer c, SshADTMapRoot *r, int size)
{
  int i;
  SshADTMapNode **nodes;

# ifdef _KERNEL
  SSH_ASSERT((c->flags & SSH_ADT_FLAG_CONTAINED_HEADER));
# endif

  if (!(nodes = ssh_malloc(sizeof(r->nodes[0]) * size)))
    return FALSE;

  r->array_size = size;
  r->nodes = nodes;

  for (i = 0; i < r->array_size; i++)
    r->nodes[i] = NULL;

  return TRUE;
}

static Boolean init(SshADTContainer c)
{
  if (!(c->container_specific = ssh_malloc(sizeof(SshADTMapRoot))))
    return FALSE;

  if (!init_to_size(c, ROOT(c), SSH_ADT_MAP_INITIAL_SLOTS))
    {
      ssh_free(c->container_specific);
      c->container_specific = NULL;
      return FALSE;
    }
  ROOT(c)->prev_array_size = 8;
  ROOT(c)->num_objects = 0;
  return TRUE;
}

/* $$METHOD(map, container_init) */
/* $$METHOD(bag, container_init) */
SSH_ADT_STD_INIT(container_init, init(c))

/* $$METHOD(map, clear) */
/* $$METHOD(bag, clear) */
static void clear(SshADTContainer c)
{
  int i;
  SshADTMapNode *node;

  for (i = 0; i < ROOT(c)->array_size; i++)
    {
      node = ROOT(c)->nodes[i];

      while (node != NULL)
        {
          SshADTHandle handle = node;
          void *extra_node = ((unsigned char *)handle) - sizeof(void *);
          void *object = ssh_adt_get(c, handle);

          if (node->is_last_in_rib)
            node = NULL;
          else
            node = node->u.next;

          if (c->f.app_methods.map_detach != NULL_FNPTR)
            {
              void *old = ssh_adt_map_lookup(c, handle);
              if (old != NULL)
                (*(c->f.app_methods.map_detach))(old, SSH_ADT_APPCTX(c));
            }
          SSH_ADT_CALL_APP(c, destr, (object, SSH_ADT_APPCTX(c)));
          if (c->flags & SSH_ADT_FLAG_ALLOCATE)
            SSH_ADT_STD_FREE_I(c, handle);
          if (c->flags & SSH_ADT_FLAG_NEED_EXTRA_NODES)
            {
              free_node(c, extra_node);
            }
        }
      ROOT(c)->nodes[i] = NULL;
    }
  ROOT(c)->num_objects = c->num_objects = 0;
  SSH_DEBUG(9, ("map cleared."));
}

static void uninit(SshADTContainer c)
{
  clear(c);
  ssh_free(ROOT(c)->nodes);
  ssh_free(c->container_specific);
}

/* $$METHOD(map, destr) */
/* $$METHOD(bag, destr) */
SSH_ADT_STD_DESTROY(destr, uninit(c);)

static SshADTHandle next_rib_start(SshADTContainer c, int start_idx)
{
  int i;
  for (i = start_idx; i < ROOT(c)->array_size; i++)
    {
      if (ROOT(c)->nodes[i] != NULL)
        {
          return ROOT(c)->nodes[i];
        }
    }
  return SSH_ADT_INVALID;
}

/* $$METHOD(map, enumerate_start) */
/* $$METHOD(bag, enumerate_start) */
static SshADTHandle enum_start(SshADTContainer c)
{
  return next_rib_start(c, 0);
}

static SshADTHandle forward(SshADTContainer c, SshADTHandle h)
{
  SshADTMapNode *d = h;

  if (d->is_last_in_rib)
    {
      SshADTMapNode **ptr = d->u.rib_start;
      int idx = ((unsigned char *)ptr - (unsigned char *)(ROOT(c)->nodes))
        / (sizeof(ROOT(c)->nodes[0]));
      return next_rib_start(c, idx + 1);
    }
  else
    {
      return d->u.next;
    }
}

/* $$METHOD(map, enumerate_next) */
/* $$METHOD(bag, enumerate_next) */
static SshADTHandle enum_next(SshADTContainer c, SshADTHandle h)
{
  SSH_ASSERT(h != SSH_ADT_INVALID);
  return forward(c, h);
}


/* changing the array size, rehashing and insertion are closely
   entangled. */

#define INSERT_WITHOUT_REHASH(c, n)                                           \
do                                                                            \
{                                                                             \
  SshUInt32 hash_value;                                                       \
                                                                              \
  SSH_ADT_STD_HASH(c, n, hash_value);                                         \
  hash_value %= (ROOT(c)->array_size);                                        \
                                                                              \
  if (ROOT(c)->nodes[hash_value] == NULL)                                     \
    {                                                                         \
      n->is_last_in_rib = TRUE;                                               \
      n->u.rib_start = &(ROOT(c)->nodes[hash_value]);                         \
      ROOT(c)->nodes[hash_value] = n;                                         \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      n->is_last_in_rib = FALSE;                                              \
      n->u.next = ROOT(c)->nodes[hash_value];                                 \
      ROOT(c)->nodes[hash_value] = n;                                         \
    }                                                                         \
}                                                                             \
while (0)

static void rehash(SshADTContainer c, size_t new_size)
{
  SshADTMapNode **old;
  SshADTMapNode *n, *next;
  int old_size;
  int i;

  SSH_DEBUG(9, ("Rehashing, old size %ld, new size %ld.",
                (long)ROOT(c)->array_size,
                (long)new_size));

  old = ROOT(c)->nodes;
  old_size = ROOT(c)->array_size;

  /* If we cannot resize, we'll just use the old hash. Performance
     will degrade, though. */
  if (!init_to_size(c, ROOT(c), new_size))
    return;

  /* move objects */
  for (i = 0; i < old_size; i++)
    {
      n = old[i];
      if (n == NULL) continue;
      while (1)
        {
          SSH_DEBUG(99, ("i=%d (%d) [%p].", i, ROOT(c)->num_objects, n));
          if (n->is_last_in_rib)
            {
              INSERT_WITHOUT_REHASH(c, n);
              break;
            }
          else
            {
              next = n->u.next;
              INSERT_WITHOUT_REHASH(c, n);
              n = next;
            }
        }
    }

  /* clean up */
  ssh_free(old);
}

static Boolean insert(SshADTContainer c, SshADTMapNode *n)
{
  if (n == NULL)  /* E.g. if the duplicate callback returns it. */
    return FALSE;

  INSERT_WITHOUT_REHASH(c, n);
  ROOT(c)->num_objects++;

  if (ROOT(c)->num_objects / SSH_ADT_MAP_RATIO > ROOT(c)->array_size)
    {
      size_t nextsize;

      nextsize = ROOT(c)->array_size + ROOT(c)->prev_array_size;
      ROOT(c)->prev_array_size = ROOT(c)->array_size;
      rehash(c, nextsize);
    }

  return TRUE;
}

static Boolean my_insert_absolute(SshADTContainer c,
                                  SshADTAbsoluteLocation location,
                                  SshADTHandle h)
{
  SSH_ASSERT(location == SSH_ADT_DEFAULT);
  NODE(h)->image = NULL;
  return (insert(c, h));
}

/* $$METHOD(map, insert_to) */
/* $$METHOD(bag, insert_to) */
SSH_ADT_STD_INSERT_TO(insert_absolute,
                      my_insert_absolute(c, location, h),
                      __handle = ssh_malloc(sizeof(SshADTMapENode));)


/* $$METHOD(map, alloc_n_to) */
/* $$METHOD(bag, alloc_n_to) */
SSH_ADT_STD_ALLOC_N_TO(alloc_n_to,
                       my_insert_absolute(c, location, h);)

/* $$METHOD(map, put_n_to) */
/* $$METHOD(bag, put_n_to) */
SSH_ADT_STD_PUT_N_TO(put_n_to,
                     my_insert_absolute(c, location, h);)

/* $$METHOD(map, get) */
/* $$METHOD(bag, get) */
SSH_ADT_STD_GET(get)

/* $$METHOD(map, num_objects) */
/* $$METHOD(bag, num_objects) */
SSH_ADT_STD_NUM_OBJECTS(num_objects)

static SshADTHandle find_node(SshADTContainer c, void *object)
{
  SshADTMapNode *i;
  SshUInt32 hash_value;
  void *result;

  SSH_ADT_HASH_OBJECT(c, object, hash_value);
  hash_value %= ROOT(c)->array_size;
  if (ROOT(c)->nodes[hash_value] == NULL) return SSH_ADT_INVALID;

  for (i = ROOT(c)->nodes[hash_value]; ; i = i->u.next)
    {
      SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(c, i, result);

      if (result == object)
        return (SshADTHandle)i;

      if (i->is_last_in_rib)
        return SSH_ADT_INVALID;
    }
  /*NOTREACHED*/
}

/* $$METHOD(map, get_handle_to) */
/* $$METHOD(bag, get_handle_to) */
SSH_ADT_STD_GET_HANDLE_TO(get_handle_to, handle = find_node(c, object);)

/* $$METHOD(map, get_handle_to_equal) */
/* $$METHOD(bag, get_handle_to_equal) */
static SshADTHandle to_equal(SshADTContainer c, void *object)
{
  SshADTMapNode *i;
  SshUInt32 hash_value;
  int result;

  SSH_ADT_HASH_OBJECT(c, object, hash_value);
  hash_value %= ROOT(c)->array_size;
  if (ROOT(c)->nodes[hash_value] == NULL) return SSH_ADT_INVALID;

  for (i = ROOT(c)->nodes[hash_value]; ; i = i->u.next)
    {
      SSH_ADT_STD_COMPARE_H_O(c, i, object, result);

      if (!result)
        return (SshADTHandle)i;

      if (i->is_last_in_rib)
        return SSH_ADT_INVALID;
    }

  /*NOTREACHED*/
}

static Boolean my_detach(SshADTContainer c, SshADTHandle handle)
{
  SshADTMapNode *target = handle;  /* what we want to remove */
  SshADTMapNode *prior = handle;   /* the list predecessor of target */

  /* We need to find the node prior to that being detached and change
     it. This is a muddy algorithm. */

  while (1)
    {
      /* If 'prior' does not point to the last item in the chain... */
      if (!(prior->is_last_in_rib))
        {
          /* If the next item is the target... */
          if (prior->u.next == target)
            {
              /* If the target is last in the chain... */
              if (target->is_last_in_rib)
                {
                  /* ... then set the 'prior' to be the last item in
                     the chain and copy the rib start backpointer from
                     'target'. */
                  prior->is_last_in_rib = TRUE;
                  prior->u.rib_start = target->u.rib_start;
                }
              else
                {
                  /* Otherwise 'prior' won't be the last in the chain
                     and the next pointer is just copied. */
                  prior->u.next = target->u.next;
                }
              break;            /* Stop scanning. */
            }
          /* Otherwise move to the next item, which exists because
             'prior' wasn't the last one in the chain. */
          prior = prior->u.next;
          continue;             /* Continue scanning. */
        }
      else  /* if 'prior' is the last item in the chain... */
        {
          /* if 'target' is actually the first one in the chain... */
          if (*(prior->u.rib_start) == target)
            {
              /* If 'target' is also the last... */
              if (target->is_last_in_rib)
                {
                  /* ... then the chain is now empty. */
                  *(prior->u.rib_start) = NULL;
                }
              else
                {
                  /* Otherwise the chain start pointer must be changed
                     to point to the item after 'target', which now
                     must exist. */
                  *(prior->u.rib_start) = target->u.next;
                }
              break;            /* Stop scanning. */
            }
          /* Otherwise set 'prior' to be the first item in the chain... */
          prior = *(prior->u.rib_start);
          continue;             /* Continue scanning. */
        }
    }

  ROOT(c)->num_objects--;

  return TRUE;  /* my_detach never fails, it rather explodes... :) */
}

/* $$METHOD(map, detach) */
/* $$METHOD(bag, detach) */
SSH_ADT_STD_DETACH(detach, my_detach(c, handle);, free_node(c, node);)

/* $$METHOD(map, delet) */
/* $$METHOD(bag, delet) */
SSH_ADT_STD_DELETE(delet)

/* $$METHOD(map, map_attach) */
SSH_ADT_STD_MAP_ATTACH(map_attach, NODE(handle)->image)

/* $$METHOD(map, map_lookup) */
SSH_ADT_STD_MAP_LOOKUP(map_lookup, NODE(handle)->image)


const SshADTStaticData ssh_adt_map_static_data =
{
  {
    /* $$METHODS(map) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    clear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    insert_absolute, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    alloc_n_to, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    put_n_to, /* put_n_to */
    get, /* get */
    num_objects, /* num_objects */
    get_handle_to, /* get_handle_to */
    NULL_FNPTR, /* get_handle_to_location */
    NULL_FNPTR, /* next */
    NULL_FNPTR, /* previous */
    enum_start, /* enumerate_start */
    enum_next, /* enumerate_next */
    to_equal, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    detach, /* detach */
    delet, /* delet */
    map_lookup, /* map_lookup */
    map_attach, /* map_attach */
    /* $$ENDMETHODS */
  },
  sizeof(SshADTMapNode),
  0
};

const SshADTContainerType ssh_adt_map_type = &ssh_adt_map_static_data;

const SshADTStaticData ssh_adt_bag_static_data =
{
  {
    /* $$METHODS(bag) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    clear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    insert_absolute, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    alloc_n_to, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    put_n_to, /* put_n_to */
    get, /* get */
    num_objects, /* num_objects */
    get_handle_to, /* get_handle_to */
    NULL_FNPTR, /* get_handle_to_location */
    NULL_FNPTR, /* next */
    NULL_FNPTR, /* previous */
    enum_start, /* enumerate_start */
    enum_next, /* enumerate_next */
    to_equal, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    detach, /* detach */
    delet, /* delet */
    NULL_FNPTR, /* map_lookup */
    NULL_FNPTR, /* map_attach */
    /* $$ENDMETHODS */
  },
  sizeof(SshADTMapNode),
  0
};

const SshADTContainerType ssh_adt_bag_type = &ssh_adt_bag_static_data;
