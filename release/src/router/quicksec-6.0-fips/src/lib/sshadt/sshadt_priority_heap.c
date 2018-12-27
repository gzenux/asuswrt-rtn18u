/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements a priority heap, which behaves like a priority
   queue but it is additionally possible to remove arbitrary items
   from the middle of the heap, and it is possible to move all items
   from one priority queue to another.  All of those operations take
   logarithmic time.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshadt_priority_heap_i.h"
#include "sshadt_std_i.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTPriorityHeap"

#define ROOT(c)     ((SshADTPriorityHeapRootStruct *) (c->container_specific))
#define NODE(x)     ((SshADTPriorityHeapNode) (x))


#if 0
/* A section of code used for testing. */
#ifndef MAX
#define MAX(a, b)   ((a) > (b) ? (a) : (b))
#endif

/* These routines are only for debugging. */
static void ph_print(SshADTPriorityHeapENode n, int depth)
{
  if (n == NULL)
    {
      /* fprintf(stderr, "%*cNULL\n", 4 * depth, ' '); */
      return;
    }

  ph_print(n->left, depth+1);
  fprintf(stderr, "%*c%d (h = %d)\n", 4 * depth, ' ',
          *((int *) n->object), n->height);

  SSH_ASSERT(depth == 0 || n->parent != NULL);
  SSH_ASSERT(n->left == NULL || n->left->parent == n);
  SSH_ASSERT(n->left == NULL
             || *((int *) n->object) <= *((int *) n->left->object));

  ph_print(n->right, depth+1);

  SSH_ASSERT(n->right == NULL || n->right->parent == n);
  SSH_ASSERT(n->right == NULL
             || *((int *) n->object) <= *((int *) n->right->object));
  SSH_ASSERT(n->height ==
             MAX((n->left == NULL ? 0 : n->left->height + 1),
                 (n->right == NULL ? 0 : n->right->height + 1)));
}

void priority_heap_print(SshADTContainer c)
{
  ph_print(ROOT(c)->min, 0);
}
#endif


static Boolean init(SshADTContainer c)
{
# ifdef _KERNEL
  SSH_ASSERT((c->flags & SSH_ADT_FLAG_CONTAINED_HEADER));
# endif

  c->container_specific = ssh_malloc(sizeof(*ROOT(c)));
  if (ROOT(c) == NULL)
    return FALSE;
  ROOT(c)->min = NULL;
  return TRUE;
}

/* $$METHOD(priority_heap, container_init) */
SSH_ADT_STD_INIT(container_init, init(c))


static void uninit(SshADTContainer c)
{
  while (ROOT(c)->min != NULL)
    ssh_adt_delete_from(c, SSH_ADT_DEFAULT);
  ssh_free(ROOT(c));
}

/* $$METHOD(priority_heap, destr) */
SSH_ADT_STD_DESTROY(destr, uninit(c);)


/* $$METHOD(priority_heap, clear) */
static void clear(SshADTContainer c)
{
  while (ROOT(c)->min != NULL)
    ssh_adt_delete_from(c, SSH_ADT_DEFAULT);
}


/* $$METHOD(priority_heap, num_objects) */
SSH_ADT_STD_NUM_OBJECTS(num_objects)


static Boolean
ssh_adt_priority_heap_do_insert(SshADTContainer c, SshADTPriorityHeapNode n)
{
  SshADTPriorityHeapNode p, prev_p, tmp_p, *pp;
  /* void *p_data, *n_data; */
  SshUInt32 height;
  int cmp = 1;

  if (n == NULL)
    return FALSE;

  /* Traverse the shortest path from root to a the shallowest leaf,
     keeping in 'n' the node to be inserted into the heap. */
  pp = &ROOT(c)->min;
  p = *pp;
  prev_p = NULL;
  while (p != NULL)
    {
      SSH_ASSERT(p->parent == prev_p);
      SSH_ASSERT(p->left == NULL || p->height > p->left->height);
      SSH_ASSERT(p->right == NULL || p->height > p->right->height);

      if (cmp > 0)
        {
          /* The tree condition ensures we don't need to perform the
             comparison once we get the first greater-than result. */
          SSH_ADT_STD_COMPARE(c, n, p, cmp);
        }

      if (cmp <= 0)
        {
          /* Link 'n' in the place of 'p'.  (Note that because we use
             addresses of nodes as their handles, we can not merely
             swap 'p_data' and 'object' and allocate 'n' to the new
             leaf.) */
          n->parent = prev_p;
          *pp = n;

          n->left = p->left;
          if (n->left != NULL)
            n->left->parent = n;
          n->right = p->right;
          if (n->right != NULL)
            n->right->parent = n;
          /* Leave the height-field unassigned, it will be recomputed
             later. */

          tmp_p = p;
          p = n;
          n = tmp_p;
        }

      if (p->left == NULL)
        pp = &p->left;
      else if (p->right == NULL)
        pp = &p->right;
      else if (p->left->height < p->right->height)
        pp = &p->left;
      else
        pp = &p->right;
      prev_p = p;
      p = *pp;
    }

  *pp = n;
  n->parent = prev_p;
  n->left = n->right = NULL;
  n->height = 0;

  p = prev_p;
  /* Traverse back up and update height fields. */
  while (p != NULL)
    {
      height = 0;
      if (p->left != NULL && p->left->height >= height)
        height = p->left->height + 1;
      if (p->right != NULL && p->right->height >= height)
        height = p->right->height + 1;
      p->height = height;
      p = p->parent;
    }

  return TRUE;
}


/* $$METHOD(priority_heap, insert_to) */
SSH_ADT_STD_INSERT_TO(
  ssh_adt_priority_heap_insert_to,
  (SSH_ASSERT(location == SSH_ADT_DEFAULT),
   ssh_adt_priority_heap_do_insert(c, h)),
  __handle = ssh_malloc(sizeof(SshADTPriorityHeapENodeStruct));)

/* $$METHOD(priority_heap, put_n_to) */
SSH_ADT_STD_PUT_N_TO(
  ssh_adt_priority_heap_put_n_to,
  (SSH_ASSERT(location == SSH_ADT_DEFAULT),
   ssh_adt_priority_heap_do_insert(c, h));)


static void ssh_adt_priority_heap_do_remove(SshADTContainer c,
                                            SshADTHandle h)
{
  SshADTPriorityHeapNode n, p, tmp, left, right, *pp;
  /* void *left_data, *right_data; */
  int height, cmp;

  if (NODE(h)->parent == NULL)
    pp = &ROOT(c)->min;
  else
    if (NODE(h)->parent->left == NODE(h))
      pp = &NODE(h)->parent->left;
    else
      {
        SSH_ASSERT(NODE(h)->parent->right == NODE(h));
        pp = &NODE(h)->parent->right;
      }
  n = NODE(h);
  p = n->parent;
  left = n->left;
  right = n->right;
  while (left != NULL && right != NULL)
    {
      SSH_ADT_STD_COMPARE(c, left, right, cmp);

      if (cmp < 0)
        {
          /* Lift 'left' upwards, make 'right' its child. */
          *pp = left;
          left->parent = p;
          tmp = left->right;
          left->right = right;
          right->parent = left;
          pp = &left->left;
          p = left;
          left = *pp;
          right = tmp;
        }
      else
        {
          /* Lift 'right' upwards, make 'left' its child. */
          *pp = right;
          right->parent = p;
          tmp = right->left;
          right->left = left;
          left->parent = right;
          pp = &right->right;
          p = right;
          right = *pp;
          left = tmp;
        }
    }
  if (left == NULL)
    {
      *pp = right;
      if (right != NULL)
        right->parent = p;
    }
  else
    {
      *pp = left;
      left->parent = p;
    }

  while (p != NULL)
    {
      /* Unless we entirely emptied the priority heap, them traverse
         the path upwards and update heights. */
      height = 0;
      if (p->left != NULL && p->left->height >= height)
        height = p->left->height + 1;
      if (p->right != NULL && p->right->height >= height)
        height = p->right->height + 1;
      p->height = height;
      p = p->parent;
    }
}


/* $$METHOD(priority_heap, detach) */
SSH_ADT_STD_DETACH(
  ssh_adt_priority_heap_detach,
  ssh_adt_priority_heap_do_remove(c, handle);,
  ssh_free(node);)


/* $$METHOD(priority_heap, delet) */
SSH_ADT_STD_DELETE(ssh_adt_priority_heap_delete)


/* $$METHOD(priority_heap, get_handle_to_location) */
static SshADTHandle get_handle_to_location(SshADTContainer c,
                                           SshADTAbsoluteLocation location)
{
  SSH_ASSERT(location == SSH_ADT_DEFAULT);

  if (c->num_objects == 0)
    return SSH_ADT_INVALID;
  else
    return (SshADTHandle) ROOT(c)->min;
}


/* $$METHOD(priority_heap, get) */
SSH_ADT_STD_GET(ssh_adt_priority_heap_get)


/* $$METHOD(priority_heap, enumerate_start) */
static SshADTHandle ssh_adt_priority_heap_enum_start(SshADTContainer c)
{
  if (c->num_objects == 0)
    return SSH_ADT_INVALID;
  else
    return (SshADTHandle) ROOT(c)->min;
}


/* $$METHOD(priority_heap, enumerate_next) */
/* $$METHOD(priority_heap, next) */
static SshADTHandle
ssh_adt_priority_heap_enum_next(SshADTContainer c, SshADTHandle h)
{
  SSH_PRECOND(h != SSH_ADT_INVALID);
  SSH_ASSERT(h != NULL);        /* Same as above? */

  if (NODE(h)->left != NULL)
    return NODE(h)->left;
  if (NODE(h)->right != NULL)
    return NODE(h)->right;
  while (NODE(h)->parent != NULL)
    {
      if (NODE(h)->parent->left == NODE(h))
        if (NODE(h)->parent->right != NULL)
          return NODE(h)->parent->right;
      h = NODE(h)->parent;
    }
  return NULL;
}


/* $$METHOD(priority_heap, previous) */
static SshADTHandle
ssh_adt_priority_heap_previous(SshADTContainer c, SshADTHandle h)
{
  SSH_PRECOND(h != SSH_ADT_INVALID);

  if (NODE(h)->parent == NULL)
    return NULL;
  if (NODE(h)->parent->right == NODE(h))
    {
      if (NODE(h)->parent->left == NULL)
        return NODE(h)->parent;
      h = NODE(h)->parent->left;
      while (1)
        if (NODE(h)->right != NULL)
          h = NODE(h)->right;
        else if (NODE(h)->left == NULL)
          return h;
        else
          h = NODE(h)->left;

      /*NOTREACHED*/
    }
  SSH_ASSERT(NODE(h)->parent->left == NODE(h));
  return NODE(h)->parent;
}


#if 0

/* Major changes elsewhere in the code made it necessary to disable
   this code until its checked. */

/* Move all objects from the priority heap 'from' to the priority heap
   'to'.  This is accomplished in logarithmic time.  No memory is
   allocated or freed. */
void ssh_adt_priority_heap_move(SshADTContainer to, SshADTContainer from)
{
  SshADTPriorityHeapNode n;
  SshUInt32 height;
  int cmp;

  SSH_NOTREACHED;

  /* Assert the two comparison functions of the two priority heaps are
     equal.  */
  SSH_ASSERT(to->f.app_methods.compare == from->f.app_methods.compare);

  /* Handle trivial cases. */
  if (ROOT(from)->min == NULL)
    return;
  if (ROOT(to)->min == NULL)
    {
      ROOT(to)->min = ROOT(from)->min;
      ROOT(from)->min = NULL;
      to->num_objects = from->num_objects;
      from->num_objects = 0;
      return;
    }

  SSH_ADT_STD_COMPARE(to, ROOT(to)->min, ROOT(from)->min, cmp);

  /* Remove the smallest element of both heaps.  This is the new root
     of 'to'.  This is the only thing in this function that takes
     super-constant time (log n).  */
  if (cmp < 0)
    {
    /* n = */ ssh_adt_priority_heap_do_remove(to, ROOT(to)->min); /* ,TRUE */
    }
  else
    {
    /* n = */ ssh_adt_priority_heap_do_remove(from,
                                              ROOT(from)->min); /* ,TRUE */
    }

  /* Attach the two heaps as children to the new root.  */
  n->left = ROOT(to)->min;
  if (n->left != NULL)
    n->left->parent = n;
  n->right = ROOT(from)->min;
  if (n->right != NULL)
    n->right->parent = n;
  n->parent = NULL;
  ROOT(to)->min = n;

  /* Cleanup.  */
  height = 0;
  if (n->left != NULL && n->left->height >= height)
    height = n->left->height + 1;
  if (n->right != NULL && n->right->height >= height)
    height = n->right->height + 1;
  n->height = height;

  to->num_objects += from->num_objects;
  from->num_objects = 0;
}

#endif /* 0 */

const SshADTStaticData ssh_adt_priority_heap_static_data =
{
  {
    /* $$METHODS(priority_heap) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init, /* container_init */
    clear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    ssh_adt_priority_heap_insert_to, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    NULL_FNPTR, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    ssh_adt_priority_heap_put_n_to, /* put_n_to */
    ssh_adt_priority_heap_get, /* get */
    num_objects, /* num_objects */
    NULL_FNPTR, /* get_handle_to */
    get_handle_to_location, /* get_handle_to_location */
    ssh_adt_priority_heap_enum_next, /* next */
    ssh_adt_priority_heap_previous, /* previous */
    ssh_adt_priority_heap_enum_start, /* enumerate_start */
    ssh_adt_priority_heap_enum_next, /* enumerate_next */
    NULL_FNPTR, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    ssh_adt_priority_heap_detach, /* detach */
    ssh_adt_priority_heap_delete, /* delet */
    NULL_FNPTR, /* map_lookup */
    NULL_FNPTR, /* map_attach */
    /* $$ENDMETHODS */
  },
  sizeof(SshADTPriorityHeapNodeStruct),
  0
};

const SshADTContainerType ssh_adt_priority_heap_type =
  &ssh_adt_priority_heap_static_data;
