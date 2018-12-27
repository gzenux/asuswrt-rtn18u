/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshadt_list_i.h"
#include "sshadt_std_i.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTList"

#define ROOT(c)     ((SshADTListRootStruct *)(c->container_specific))
#define NODE(x)     ((SshADTListNodeStruct *)(x))

static Boolean init(SshADTContainer c)
{
# ifdef _KERNEL
  SSH_ASSERT((c->flags & SSH_ADT_FLAG_CONTAINED_HEADER));
# endif

  if (!(c->container_specific = ssh_malloc(sizeof(*ROOT(c)))))
    return FALSE;
  ROOT(c)->first_node = ROOT(c)->last_node = NULL;

  if (c->f.app_methods.hash != ssh_adt_default_hash)
    {
      SSH_DEBUG(0, ("*** You have provided a hash callback for a list."));
      SSH_DEBUG(0, ("*** Please report to maintainer."));
    }

  return TRUE;
}

/* $$METHOD(list, container_init) */
SSH_ADT_STD_INIT(container_init, init(c))


static void uninit(SshADTContainer c)
{
  while (ROOT(c)->first_node != NULL)
    ssh_adt_delete_from(c, SSH_ADT_BEGINNING);
  ssh_free(ROOT(c));
}

/* $$METHOD(list, destr) */
SSH_ADT_STD_DESTROY(destr, uninit(c);)

/* $$METHOD(list, clear) */
static void clear(SshADTContainer c)
{
  while (ROOT(c)->first_node != NULL)
    ssh_adt_delete_from(c, SSH_ADT_BEGINNING);
}

#if 0
static void sanity_dump(SshADTListRootStruct *r)
{
  SshADTListNodeStruct *n = r->first_node;
  while (n != NULL)
    {
      fprintf(stderr, "%p next:%p prev:%p\n",
              n, n->next, n->prev);
      n = n->next;
    }
}

static void sanity_check(SshADTListRootStruct *r)
{
  SshADTListNodeStruct *n = r->first_node;
  while (n != NULL)
    {
      if ((n->prev != NULL && n->prev->next != n)
          ||
          (n->next != NULL && n->next->prev != n)
          ||
          (n->prev == NULL && r->first_node != n)
          ||
          (n->next == NULL && r->last_node != n))
        {
          fprintf(stderr, "Sanity check failed for node %p\n", n);
          sanity_dump(r);
          abort();
        }
      n = n->next;
    }
}
#endif

/* $$METHOD(list, num_objects) */
SSH_ADT_STD_NUM_OBJECTS(num_objects)

static void insert_at_beginning(SshADTListRootStruct *r,
                                SshADTListNodeStruct *n)
{
  SSH_ADT__LIST_INSERT_TO_BEGINNING(r, n);
}

static void insert_at_end(SshADTListRootStruct *r,
                          SshADTListNodeStruct *n)
{
  SSH_ADT__LIST_INSERT_TO_END(r, n);
}

static Boolean insert_prior_to_node(SshADTListRootStruct *r,
                                    SshADTListNodeStruct *p,
                                    SshADTListNodeStruct *n)
{
  if (n == NULL)
    return FALSE;

  if (p->prev == NULL)
    {
      insert_at_beginning(r, n);
    }
  else
    {
      n->prev = p->prev;
      n->prev->next = n;
      n->next = p;
      p->prev = n;
    }

  return TRUE;
}

static Boolean insert_after_node(SshADTListRootStruct *r,
                                 SshADTListNodeStruct *p,
                                 SshADTListNodeStruct *n)
{
  if (n == NULL)
    return FALSE;

  if (p->next == NULL)
    {
      insert_at_end(r, n);
    }
  else
    {
      n->next = p->next;
      n->next->prev = n;
      n->prev = p;
      p->next = n;
    }

  return TRUE;
}

static Boolean my_insert_relative(SshADTContainer c, SshADTRelativeLocation l,
                                  SshADTHandle where, SshADTHandle newp)
{
  switch (l)
    {
    case SSH_ADT_BEFORE:
      return (insert_prior_to_node(ROOT(c), where, newp));
    case SSH_ADT_AFTER:
      return (insert_after_node(ROOT(c), where, newp));
    default:
      SSH_NOTREACHED;
      return FALSE;
    }
}

/* $$METHOD(list, insert_at) */
SSH_ADT_STD_INSERT_AT(insert_relative,
                      my_insert_relative(c, location, handle, h),
                      __handle = ssh_malloc(sizeof(SshADTListENodeStruct));)


/* return the handle of the nth object in a list.  returns
 * SSH_ADT_INVALID if nth object does not exist (list too short or n <
 * 0). */
static SshADTHandle get_nth(SshADTContainer c, int location)
{
  SshADTListNodeStruct *n;

  if (location >= num_objects(c) || location < 0)
    {
      SSH_DEBUG(9, ("WARNING: list does not contain element %i.", location));
      return SSH_ADT_INVALID;
    }

  if (location <= (num_objects(c) >> 1))
    {
      n = ROOT(c)->first_node;
      SSH_ASSERT(n != NULL);

      while (location--) {
        n = n->next;
        SSH_ASSERT(n != NULL);
      }
    }
  else
    {
      /* if the location is closer to the end of the list, start
         searching from there.  */
      location = num_objects(c) - 1 - location;
      n = ROOT(c)->last_node;
      SSH_ASSERT(n != NULL);

      while (location--) {
        n = n->prev;
        SSH_ASSERT(n != NULL);
      }
    }

  return n;
}

static Boolean my_insert_absolute(SshADTContainer c, SshADTAbsoluteLocation l,
                                  SshADTHandle newp)
{
  SshADTHandle where;

  /* (SshADTHandle == SshADTListNodeStruct *) */

  if (newp == NULL)
    return FALSE;

  switch (l)
    {
    case SSH_ADT_BEGINNING:
      insert_at_beginning(ROOT(c), newp);
      return TRUE;

    case SSH_ADT_END:
    case SSH_ADT_DEFAULT:
      insert_at_end(ROOT(c), newp);
      return TRUE;

    default:
      where = get_nth(c, SSH_ADT_GET_INDEX(l));
      if (where == SSH_ADT_INVALID)
        {
          /* catch special case 'append to end of list' */
          if (SSH_ADT_GET_INDEX(l) == num_objects(c))
            {
              insert_at_end(ROOT(c), newp);
              return TRUE;
            }
          else
            {
              SSH_DEBUG(9, ("insert: bad position '%i'.",
                            (int) SSH_ADT_GET_INDEX(l)));
              return FALSE;
            }
        }
      else
        {
          insert_prior_to_node(ROOT(c), where, newp);
          return TRUE;
        }
    }
}

/* $$METHOD(list, insert_to) */
SSH_ADT_STD_INSERT_TO(insert_absolute,
                      my_insert_absolute(c, location, h),
                      __handle = ssh_malloc(sizeof(SshADTListENodeStruct));)

/* $$METHOD(list, alloc_n_at) */
SSH_ADT_STD_ALLOC_N_AT(alloc_n_at,
                       my_insert_relative(c, location, handle, h);)

/* $$METHOD(list, alloc_n_to) */
SSH_ADT_STD_ALLOC_N_TO(alloc_n_to,
                       my_insert_absolute(c, location, h);)

/* $$METHOD(list, put_n_at) */
SSH_ADT_STD_PUT_N_AT(put_n_at,
                     my_insert_relative(c, location, handle, h);)

/* $$METHOD(list, put_n_to) */
SSH_ADT_STD_PUT_N_TO(put_n_to,
                     my_insert_absolute(c, location, h);)

/* $$METHOD(list, get) */
SSH_ADT_STD_GET(get)

static SshADTHandle find_node(SshADTContainer c, void *object)
{
  SshADTListNodeStruct *n = ROOT(c)->first_node;

  while (n != NULL)
    {
      if (SSH_ADT_OBJECT_AT_NODE(n) == object)
        {
          return n;
        }
      n = n->next;
    }
  return SSH_ADT_INVALID;
}

/* $$METHOD(list, get_handle_to) */
SSH_ADT_STD_GET_HANDLE_TO(get_handle_to, handle = find_node(c, object);)

/* $$METHOD(list, get_handle_to_location) */
static SshADTHandle get_location(SshADTContainer c,
                                 SshADTAbsoluteLocation location)
{
  switch (location)
    {
    case SSH_ADT_BEGINNING:
      if (ROOT(c)->first_node == NULL) return SSH_ADT_INVALID;
      return ROOT(c)->first_node;

    case SSH_ADT_END:
    case SSH_ADT_DEFAULT:
      if (ROOT(c)->last_node == NULL) return SSH_ADT_INVALID;
      return ROOT(c)->last_node;

    default:
      return get_nth(c, SSH_ADT_GET_INDEX(location));
    }
}

/* $$METHOD(list, enumerate_start) */
static SshADTHandle enum_start(SshADTContainer c)
{
  return ROOT(c)->first_node;
}

/* $$METHOD(list, enumerate_next) */
/* $$METHOD(list, next) */
static SshADTHandle enum_next(SshADTContainer c, SshADTHandle h)
{
  SSH_PRECOND(h != SSH_ADT_INVALID);
  h = NODE(h)->next;
  return h;
}

/* $$METHOD(list, previous) */
static SshADTHandle to_previous(SshADTContainer c, SshADTHandle h)
{
  SSH_PRECOND(h != SSH_ADT_INVALID);
  h = NODE(h)->prev;
  return h;
}

static void detach_at_beginning(SshADTListRootStruct *r)
{
  SshADTListNodeStruct *n;
  n = r->first_node;

  if (r->last_node == r->first_node)
    {
      SSH_ASSERT(n->next == NULL);
      r->first_node = NULL;
      r->last_node = NULL;
    }
  else
    {
      SSH_ASSERT(n->next != NULL);
      r->first_node = n->next;
      n->next->prev = NULL;
    }
}

static void detach_at_end(SshADTListRootStruct *r)
{
  SshADTListNodeStruct *n;
  n = r->last_node;

  if (r->last_node == r->first_node)
    {
      SSH_ASSERT(n->prev == NULL);
      r->first_node = NULL;
      r->last_node = NULL;
    }
  else
    {
      SSH_ASSERT(n->prev != NULL);
      r->last_node = n->prev;
      n->prev->next = NULL;
    }
}

static void detach_at(SshADTListRootStruct *r,
                      SshADTListNodeStruct *n)
{
  SSH_PRECOND(r != NULL);
  SSH_PRECOND(n != NULL);

  if (n == r->last_node)  { detach_at_end(r);       return; }
  if (n == r->first_node) { detach_at_beginning(r); return; }

  SSH_ASSERT(n->next != NULL);
  SSH_ASSERT(n->prev != NULL);
  SSH_ASSERT(n->next->prev == n);
  SSH_ASSERT(n->prev->next == n);

  n->next->prev = n->prev;
  n->prev->next = n->next;
}

/* $$METHOD(list, detach) */
SSH_ADT_STD_DETACH(detach, detach_at(ROOT(c), handle);, ssh_free(node);)

/* $$METHOD(list, get_handle_to_equal) */
static SshADTHandle to_equal(SshADTContainer c, void *object)
{
  SshADTHandle h;
  int result;

  for (h = ROOT(c)->first_node; h != SSH_ADT_INVALID; h = NODE(h)->next)
    {
      SSH_ADT_STD_COMPARE_H_O(c, h, object, result);

      if (!result)
        return h;
    }

  return SSH_ADT_INVALID;
}

/* $$METHOD(list, delet) */
SSH_ADT_STD_DELETE(delet)

const SshADTStaticData ssh_adt_list_static_data =
{
  {
    /* $$METHODS(list) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    clear, /* clear */
    destr, /* destr */
    insert_relative, /* insert_at */
    insert_absolute, /* insert_to */
    alloc_n_at, /* alloc_n_at */
    alloc_n_to, /* alloc_n_to */
    put_n_at, /* put_n_at */
    put_n_to, /* put_n_to */
    get, /* get */
    num_objects, /* num_objects */
    get_handle_to, /* get_handle_to */
    get_location, /* get_handle_to_location */
    enum_next, /* next */
    to_previous, /* previous */
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
  sizeof(SshADTListNodeStruct),
  0
};

const SshADTContainerType ssh_adt_list_type = &ssh_adt_list_static_data;

/* (The sorting code below was originally written by Mika Kojo.) */

#define MERGE(extra)                                                          \
  for (tail = NULL; t1 && t2; tail = t1, t1 = t1->next)                       \
    {                                                                         \
      SSH_ADT_STD_COMPARE(c, t1, t2, result);                                 \
      if (result > 0)                                                         \
        {                                                                     \
          /* Remove. */                                                       \
          t = t2;                                                             \
          t2 = t->next;                                                       \
                                                                              \
          /* Join. */                                                         \
          t->next = t1;                                                       \
          if (tail == NULL)                                                   \
            extra = t;                                                        \
          else                                                                \
            tail->next = t;                                                   \
          t1 = t;                                                             \
          continue;                                                           \
        }                                                                     \
    }                                                                         \
  if (t1 == NULL && tail)                                                     \
    tail->next = t2;

void ssh_adt_list_sort(SshADTContainer c)
{
  SshADTListNodeStruct *table[64];    /* Enough to sort around 2^64
                                       * entries... */
  SshADTListNodeStruct *cursor;
  SshADTListNodeStruct *t1, *t2, *t, *tail;
  int i;
  int result;

  SSH_ASSERT(c->static_data == ssh_adt_list_type);

  cursor = ROOT(c)->first_node;

  if (cursor == NULL || cursor->next == NULL) return;

  /* Clear the table. */
  for (i = 0; i < 64; i++)
    table[i] = NULL;

  while (cursor != NULL)
    {
      SshADTListNodeStruct *op1, *op2;

      op1 = cursor;
      op2 = cursor->next;

      if (op2 != NULL)
        {
          cursor = op2->next; op2->next = NULL;
          SSH_ADT_STD_COMPARE(c, op1, op2, result);
          if (result > 0)
            {
              SshADTListNodeStruct *t;

              /* Swap. */
              t = op2; op2 = op1; op1 = t;

              /* Now op1 is smaller but later in the list. Must link. */
              op1->next = op2; op2->next = NULL;
            }
        }
      else
        {
          cursor = NULL;
        }

      if (table[0] == NULL)
        {
          table[0] = op1;
          continue;
        }

      for (i = 0; i < 64; i++)
        {
          if (table[i] == NULL)
            {
              table[i] = op1;
              break;
            }

          t1 = table[i];
          t2 = op1;
          op1 = t1;

          MERGE(op1);

          table[i] = NULL;

          SSH_ASSERT(i < 64);
        }
    }

  /* Merge left-overs. */
  cursor = NULL;
  for (i = 0; i < 64; i++)
    {
      if (table[i] != NULL && cursor != NULL)
        {
          t1 = table[i];
          t2 = cursor;
          cursor = t1;

          MERGE(cursor);

          table[i] = NULL;
        }
      else
        {
          if (cursor == NULL)
            cursor = table[i];
        }
    }

  /* 'cursor' now points to the first element. */

  ROOT(c)->first_node = cursor;
  cursor->prev = NULL;
  while ((t1 = cursor->next) != NULL)
    {
      t1->prev = cursor;
      cursor = t1;
    }
  ROOT(c)->last_node = cursor;
}
