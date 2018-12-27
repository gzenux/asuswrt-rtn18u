/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   (see comments in sshadt_avltree.h and sshadt_ranges.h.)
*/

#include "sshincludes.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADTAvlTree"

#include "sshadt.h"
#include "sshbuffer.h"
#include "sshadt_i.h"
#include "sshadt_std_i.h"
#include "sshadt_avltree.h"
#include "sshadt_ranges.h"
#include "sshadt_avltree_i.h"


/**************************************************  Container construction. */

static Boolean avl_init(SshADTContainer c, void *container_specific)
{
# ifdef _KERNEL
  SSH_ASSERT((c->flags & SSH_ADT_FLAG_CONTAINED_HEADER));
# endif

  /* For some reason, Irix CC doesn't like casts on the left side, so don't
     use the CROOT() macro here. Please, don't. //sjl */
  if (!(c->container_specific = container_specific))
    return FALSE;

  ROOT(c) = NULL;

  if (c->f.app_methods.hash != ssh_adt_default_hash)
    {
      SSH_DEBUG(0, ("*** You have provided a hash callback for an avltree."));
      SSH_DEBUG(0, ("*** Please report to maintainer."));
    }

  return TRUE;
}

static Boolean avl_ranges_init(SshADTContainer c)
{
  if (!avl_init(c, ssh_malloc(sizeof(SshADTRangesCRootStruct))))
    return FALSE;

  if ((RROOT(c)->merge_additions = ssh_buffer_allocate()) == NULL ||
      (RROOT(c)->merge_deletions = ssh_buffer_allocate()) == NULL)
    return FALSE;

  return TRUE;
}

/* $$METHOD(avltree, container_init) */
SSH_ADT_STD_INIT(container_init_tree,
                 avl_init(c, ssh_malloc(sizeof(SshADTAvlCRootStruct))))
/* $$METHOD(ranges, container_init) */
SSH_ADT_STD_INIT(container_init_ranges, avl_ranges_init(c))


/********************************************************* Object insertion. */

static Boolean avl_insert_(SshADTContainer c,
                           SshADTAbsoluteLocation l,
                           SshADTHandle h);

/* $$METHOD(avltree, insert_to) */
SSH_ADT_STD_INSERT_TO(avl_insert_to,
                      avl_insert_(c, location, h),
                      __handle = ssh_malloc(sizeof(SshADTAvlENodeStruct));)

/* $$METHOD(ranges, insert_to) */
SSH_ADT_STD_INSERT_TO(avl_insert_to_ranges,
                      avl_insert_(c, location, h),
                      __handle = ssh_malloc(sizeof(SshADTAvlENodeStruct));)

/* $$METHOD(avltree, put_n_to) */
SSH_ADT_STD_PUT_N_TO(avl_put_to,
                     avl_insert_(c, location, h);)

/* $$METHOD(ranges, put_n_to) */
SSH_ADT_STD_PUT_N_TO(avl_put_to_ranges,
                     avl_insert_(c, location, h);)


/* Now for the algorithmic stuff: given a handle containing an object,
   inject it into the tree.  First, we need some macros for balancing.
   Note: (i) these macros are very delicate and need to be called
   according to the definitions of AVL trees (double rotate and such);
   (ii) the balance information is updated by the callee because it
   depends on context.  */

#define rot_aux_reset_n(c, n, m)                                              \
{                                                                             \
  if ((m)->flags & AVL_RIGHT_CHILD)                                           \
    {                                                                         \
      SSH_ASSERT((m)->parent != NULL);                                        \
      (n)->parent = (m)->parent;                                              \
      (n)->parent->right = (n);                                               \
      AVL_SET_CHILD_SLOT((n), AVL_RIGHT_CHILD);                               \
    }                                                                         \
  else if ((m)->flags & AVL_LEFT_CHILD)                                       \
    {                                                                         \
      SSH_ASSERT((m)->parent != NULL);                                        \
      (n)->parent = (m)->parent;                                              \
      (n)->parent->left = (n);                                                \
      AVL_SET_CHILD_SLOT((n), AVL_LEFT_CHILD);                                \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      SSH_ASSERT((m)->parent == NULL);                                        \
      (n)->parent = NULL;                                                     \
      AVL_SET_CHILD_SLOT((n), AVL_NO_CHILD);                                  \
      ROOT((c)) = (n);                                                        \
    }                                                                         \
}

#define rotleft(c, n)                                                         \
{                                                                             \
  SshADTAvlNode m;                                                            \
                                                                              \
  SSH_DEBUG(9, ("rotleft."));                                                 \
  AVL_ASSERT_NODE(n);                                                         \
  AVL_ASSERT_NODE(n->right);                                                  \
                                                                              \
  /* rotate */                                                                \
  (m)         = (n);                                                          \
  (n)         = (n)->right;                                                   \
  (m)->right  = (n)->left;                                                    \
  (n)->left   = (m);                                                          \
                                                                              \
  /* reset n */                                                               \
  rot_aux_reset_n((c), (n), (m));                                             \
                                                                              \
  /* reset n->left == m */                                                    \
  (m)->parent = (n);                                                          \
  AVL_SET_CHILD_SLOT((m), AVL_LEFT_CHILD);                                    \
                                                                              \
  /* reset n->left->right == m->right (if not NULL) */                        \
  if ((m)->right)                                                             \
    {                                                                         \
      AVL_SET_CHILD_SLOT((m)->right, AVL_RIGHT_CHILD);                        \
      (m)->right->parent = (m);                                               \
    }                                                                         \
                                                                              \
  SSH_DEBUG(9, ("rotleft/x."));                                               \
}

#define rotright(c, n)                                                        \
{                                                                             \
  SshADTAvlNode m;                                                            \
                                                                              \
  SSH_DEBUG(9, ("rotright."));                                                \
  AVL_ASSERT_NODE(n);                                                         \
  AVL_ASSERT_NODE(n->left);                                                   \
                                                                              \
  /* rotate */                                                                \
  (m)         = (n);                                                          \
  (n)         = (n)->left;                                                    \
  (m)->left   = (n)->right;                                                   \
  (n)->right  = (m);                                                          \
                                                                              \
  /* reset n */                                                               \
  rot_aux_reset_n((c), (n), (m));                                             \
                                                                              \
  /* reset n->right == m */                                                   \
  (m)->parent = (n);                                                          \
  AVL_SET_CHILD_SLOT((m), AVL_RIGHT_CHILD);                                   \
                                                                              \
  /* reset n->right->left == m->left (if not NULL) */                         \
  if ((m)->left)                                                              \
    {                                                                         \
      AVL_SET_CHILD_SLOT((m)->left, AVL_LEFT_CHILD);                          \
      (m)->left->parent = (m);                                                \
    }                                                                         \
                                                                              \
  SSH_DEBUG(9, ("rotright/x."));                                              \
}

#define rot_ll(c, n)                                                          \
{                                                                             \
  rotright((c), (n));                                                         \
  AVL_SET_SKEW((n), AVL_BALANCED);                                            \
  AVL_SET_SKEW((n)->right, AVL_BALANCED);                                     \
}

#define rot_rr(c, n)                                                          \
{                                                                             \
  rotleft((c), (n));                                                          \
  AVL_SET_SKEW((n), AVL_BALANCED);                                            \
  AVL_SET_SKEW((n)->left, AVL_BALANCED);                                      \
}

#define rot_lr(c, n)                                                          \
{                                                                             \
  rotleft((c), (n)->left);                                                    \
  rotright((c), (n));                                                         \
                                                                              \
  /* Updating the skew flags is a little messy here.  (Is                     \
     there a clearer way?)  n was known as n->left->right                     \
     previous to the rotleft/rotright just performed.  */                     \
  switch (AVL_GET_SKEW((n)))                                                  \
    {                                                                         \
    case AVL_RIGHTSKEW:                                                       \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_LEFTSKEW);                                  \
      AVL_SET_SKEW((n)->right, AVL_BALANCED);                                 \
      break;                                                                  \
    case AVL_LEFTSKEW:                                                        \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_BALANCED);                                  \
      AVL_SET_SKEW((n)->right, AVL_RIGHTSKEW);                                \
      break;                                                                  \
    case AVL_BALANCED:                                                        \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_BALANCED);                                  \
      AVL_SET_SKEW((n)->right, AVL_BALANCED);                                 \
      break;                                                                  \
    }                                                                         \
}

#define rot_rl(c, n)                                                          \
{                                                                             \
  rotright((c), (n)->right);                                                  \
  rotleft((c), (n));                                                          \
                                                                              \
  switch (AVL_GET_SKEW((n)))                                                  \
    {                                                                         \
    case AVL_RIGHTSKEW:                                                       \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_LEFTSKEW);                                  \
      AVL_SET_SKEW((n)->right, AVL_BALANCED);                                 \
      break;                                                                  \
    case AVL_LEFTSKEW:                                                        \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_BALANCED);                                  \
      AVL_SET_SKEW((n)->right, AVL_RIGHTSKEW);                                \
      break;                                                                  \
    case AVL_BALANCED:                                                        \
      AVL_SET_SKEW((n), AVL_BALANCED);                                        \
      AVL_SET_SKEW((n)->left, AVL_BALANCED);                                  \
      AVL_SET_SKEW((n)->right, AVL_BALANCED);                                 \
      break;                                                                  \
    }                                                                         \
}


/* The actual balancing function.  If called, the skew of n has just
   changed, so it might need to be balanced or not.  grown_child
   denotes the child slot in which the growth of the total height of n
   has taken place.  */

static void avl_balance_i(SshADTContainer c,
                          SshADTAvlNode n, SshInt16 grown_child)
{
  SSH_DEBUG(9, ("in"));

  while (TRUE)
    {
      if (n == NULL)
        {
          SSH_DEBUG(9, ("out (reached root)"));
          return;
        }

      SSH_DEBUG(9, ("n=%p, grown child=%x balance=%x",
                    n, grown_child, AVL_GET_SKEW(n)));
      AVL_ASSERT_NODE(n);

      switch (grown_child | AVL_GET_SKEW(n))
        {
          /* The shorter subtree of n has grown by one -> do nothing.  */
        case (AVL_RIGHT_CHILD | AVL_LEFTSKEW):
        case (AVL_LEFT_CHILD | AVL_RIGHTSKEW):
          AVL_SET_SKEW(n, AVL_BALANCED);
          SSH_DEBUG(9, ("out"));
          return;

          /* n->left has grown, n previously balanced.  n has now left
             skew -> iteration required.  (Symmetric cases are not
             commented.)  */
        case (AVL_LEFT_CHILD | AVL_BALANCED):
          AVL_SET_SKEW(n, AVL_LEFTSKEW);
          goto CONT;

        case (AVL_RIGHT_CHILD | AVL_BALANCED):
          AVL_SET_SKEW(n, AVL_RIGHTSKEW);
          goto CONT;

          /* Rebalancing: the left child of n has grown, n previously
             having left skew.  If the left child has not right skew,
             a simple LL-rotation does the job (rotright(n)).
             Otherwise, two simple rotates are required.  Only one
             node needs to be rotated to rebalance the tree, so we can
             return after this case.  */
        case (AVL_LEFT_CHILD | AVL_LEFTSKEW):
          switch (AVL_GET_SKEW(n->left))
            {
            case AVL_LEFTSKEW:   rot_ll(c, n); SSH_DEBUG(9, ("out")); return;
            case AVL_RIGHTSKEW:  rot_lr(c, n); SSH_DEBUG(9, ("out")); return;
            case AVL_BALANCED:
              /* n->left is the subtree that has been grown previous
                 to the current balancing operation.  If it were
                 balanced, we would not be here in the first place.
                 Similar arguments hold for the other SSH_NOTREACHED
                 marks below.  */
              SSH_NOTREACHED;
            }
          break;

        case (AVL_RIGHT_CHILD | AVL_RIGHTSKEW):
          switch (AVL_GET_SKEW(n->right))
            {
            case AVL_RIGHTSKEW:  rot_rr(c, n); SSH_DEBUG(9, ("out")); return;
            case AVL_LEFTSKEW:   rot_rl(c, n); SSH_DEBUG(9, ("out")); return;
            case AVL_BALANCED:   SSH_NOTREACHED;
            }
          break;

        default:
          SSH_NOTREACHED;
        }
    CONT:
      grown_child = n->flags & AVL_CHILD_MASK;
      n = n->parent;
    }
  /*NOTREACHED*/
}


/* Inject a new node into the tree.  The node appears to be of type
   SshADTHandle but actually is a Node.  When this function returns,
   the tree is consistent and balanced.  */

static Boolean avl_insert_(SshADTContainer c,
                           SshADTAbsoluteLocation location,
                           SshADTHandle new_handle)
{
  /* There are two pointers for traversing the tree in addition to
     that to the new object.  */
  SshADTAvlNode new_node, this_node, parent_node;
  int cmp;

  SSH_ASSERT(c != NULL);
  SSH_ASSERT(location == SSH_ADT_DEFAULT);
  SSH_ASSERT(new_handle != NULL);

  new_node = (SshADTAvlNode)new_handle;
  SSH_DEBUG(9, ("new node: %p.", new_node));

  AVL_SET_SKEW(new_node, AVL_BALANCED);
  new_node->left  = NULL;
  new_node->right = NULL;
  new_node->image = NULL;  /* the mapping value */

  if (ROOT(c) == NULL)
    {
      AVL_SET_CHILD_SLOT(new_node, AVL_NO_CHILD);
      new_node->parent = NULL;
      ROOT(c) = new_node;
      SSH_DEBUG(9, ("parent: %p.", NULL));
    }
  else
    {
      /* find location of new node */
      this_node = ROOT(c);
      SSH_ASSERT(this_node != NULL);
      do
        {
          parent_node = this_node;
          SSH_ADT_STD_COMPARE(c, new_node, this_node, cmp);
          if (cmp > 0) this_node = this_node->right; /* new_node > this_node */
          else         this_node = this_node->left; /* new_node <= this_node */
        }
      while (this_node != NULL);

      SSH_DEBUG(9, ("parent: %p (child slot: %s).",
                    parent_node, cmp > 0 ? "->" : "<-"));

      /* update & balance */
      new_node->parent = parent_node;

      if (cmp > 0)
        {
          parent_node->right = new_node;
          AVL_SET_CHILD_SLOT(new_node, AVL_RIGHT_CHILD);
          avl_balance_i(c, parent_node, AVL_RIGHT_CHILD);
        }
      else
        {
          parent_node->left = new_node;
          AVL_SET_CHILD_SLOT(new_node, AVL_LEFT_CHILD);
          avl_balance_i(c, parent_node, AVL_LEFT_CHILD);
        }
    }

  AVL_ASSERT_NODE(new_node);
  AVL_ASSERT_TREE(c);
  return TRUE;
}


/********************************************************* Object retrieval. */

static SshADTHandle avl_geth_(SshADTContainer c, void *o)
{
  SshADTHandle h;
  void *result;

  SSH_DEBUG(0, ("*** Linear runtime alert."));

  h = ssh_adt_enumerate_start(c);
  while (h != SSH_ADT_INVALID)
    {
      SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(c, h, result);
      if (result == o)
        return h;
      h = ssh_adt_enumerate_next(c, h);
    }

  return SSH_ADT_INVALID;
}

/* $$METHOD(avltree, get_handle_to) */
/* $$METHOD(ranges, get_handle_to) */
SSH_ADT_STD_GET_HANDLE_TO(avl_geth, handle = avl_geth_(c, object);)


/* $$METHOD(avltree, get_handle_to_equal) */
/* $$METHOD(ranges, get_handle_to_equal) */
static SshADTHandle avl_geth_eq(SshADTContainer c, void *o)
{
  SshADTAvlNode n = ROOT(c);
  int cmp;

  while (n != NULL)
    {
      SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);  /* cmp = key - cursor */
      if (cmp < 0)        n = n->right;
      else if (cmp > 0)   n = n->left;
      else return (SshADTHandle)n;
    }

  return SSH_ADT_INVALID;
}


/* $$METHOD(avltree, get_handle_to_location) */
/* $$METHOD(ranges, get_handle_to_location) */
static SshADTHandle avl_geth_loc(SshADTContainer c,
                                 SshADTAbsoluteLocation l)
{
  SshADTAvlNode n = ROOT(c);

  if (ROOT(c) == NULL)
    return SSH_ADT_INVALID;

  if (l == SSH_ADT_BEGINNING || l == SSH_ADT_DEFAULT)
    {
      while (n->left)  n = n->left;
      return (SshADTHandle)n;
    }
  else if (l == SSH_ADT_END)
    {
      while (n->right)  n = n->right;
      return (SshADTHandle)n;
    }
  else
    {
      /* this is not very efficient but rather convenient: simply
         enumerate the first l elements and return the last.  */

      SshADTHandle h;
      int i = 0, k = SSH_ADT_GET_INDEX(l);

      SSH_DEBUG(0, ("*** Linear runtime alert."));
      SSH_ASSERT(k >= 0);

      h = ssh_adt_enumerate_start(c);
      while (h != SSH_ADT_INVALID && i++ < k)
        h = ssh_adt_enumerate_next(c, h);

      return h;
    }
}


/* $$METHOD(avltree, get) */
/* $$METHOD(ranges, get) */
SSH_ADT_STD_GET(get)


/* forward enumeration */

#define fall_left(n, m) \
  while ((n) != NULL) { (m) = (n); (n) = (n)->left; }

#define climb_left(n)                                                   \
{                                                                       \
  while ((n)->flags & AVL_RIGHT_CHILD)                                  \
    (n) = (n)->parent;                                                  \
  if ((n) != NULL)  /* (if root has not been reached already) */        \
    (n) = (n)->parent;                                                  \
}

/* $$METHOD(avltree, enumerate_start) */
/* $$METHOD(ranges, enumerate_start) */
static SshADTHandle enumerate_start(SshADTContainer c)
{
  SshADTAvlNode n = NULL, m = NULL;

  n = ROOT(c);
  fall_left(n, m);

  AVL_ASSERT_NODE_MAYBE(m);
  return ((SshADTHandle)m);
}

/* $$METHOD(avltree, enumerate_next) */
/* $$METHOD(avltree, next) */
/* $$METHOD(ranges, enumerate_next) */
/* $$METHOD(ranges, next) */
static SshADTHandle avl_next(SshADTContainer c, SshADTHandle h)
{
  SshADTAvlNode n, m;
  SSH_ASSERT(h != SSH_ADT_INVALID);

  n = (SshADTAvlNode)h;
  m = NULL;

  if (n->right != NULL)
    {
      n = n->right;
      fall_left(n, m);

      AVL_ASSERT_NODE(m);
      return ((SshADTHandle)m);
    }
  else
    {
      climb_left(n);

      AVL_ASSERT_NODE_MAYBE(n);
      return ((SshADTHandle)n);
    }
}


/* backward enumeration (only the previous method, actually) */

#define fall_right(n, m)                        \
{                                               \
  while ((n) != NULL)                           \
    {                                           \
      (m) = (n);                                \
      (n) = (n)->right;                         \
    }                                           \
}

#define climb_right(n)                                                   \
{                                                                        \
  while (n->flags & AVL_LEFT_CHILD)                                      \
    n = n->parent;                                                       \
  if (n != NULL)  /* (if root has not been reached from left subtree) */ \
    n = n->parent;                                                       \
}

/* $$METHOD(avltree, previous) */
/* $$METHOD(ranges, previous) */
static SshADTHandle avl_previous(SshADTContainer c, SshADTHandle h)
{
  SshADTAvlNode n, m;
  SSH_ASSERT(h != SSH_ADT_INVALID);

  n = (SshADTAvlNode)h;
  m = NULL;

  if (n->left != NULL)
    {
      n = n->left;
      fall_right(n, m);
      return ((SshADTHandle)m);
    }
  else
    {
      climb_right(n);
      return ((SshADTHandle)n);
    }
}


/* $$METHOD(avltree, num_objects) */
/* $$METHOD(ranges, num_objects) */
SSH_ADT_STD_NUM_OBJECTS(avl_num_objects)


/******************************************************* Object destruction. */

static void avl_detach_(SshADTContainer c, SshADTHandle h);

/* $$METHOD(avltree, detach) */
SSH_ADT_STD_DETACH(avl_detach, avl_detach_(c, handle);, ssh_free(node);)

/* $$METHOD(ranges, detach) */
static void *avl_detach_range(SshADTContainer c, SshADTHandle handle)
{
  merge_detach_prepare(c, handle);
  return avl_detach(c, handle);
}

/* $$METHOD(avltree, delet) */
/* $$METHOD(ranges, delet) */
SSH_ADT_STD_DELETE(avl_delete)


/* Balancing.  This is the equivalent of avl_balance_i.  (See there
   for more comments.)  */

static void avl_balance_d(SshADTContainer c,
                          SshADTAvlNode n, SshInt16 shrinked_child)
{
  SSH_DEBUG(9, ("in"));

  while (TRUE)
    {
      if (n == NULL)
        {
          SSH_DEBUG(9, ("out (reached root)"));
          return;
        }

      SSH_DEBUG(9, ("n=%p, shrinked child=%x balance=%x",
                    n, shrinked_child, AVL_GET_SKEW(n)));
      AVL_ASSERT_NODE(n);

      switch (shrinked_child | AVL_GET_SKEW(n))
        {
          /* Any subtree has shrinked, n previously balanced.  n has
             now some skew, but no iteration is required.  */
        case (AVL_LEFT_CHILD | AVL_BALANCED):
          AVL_SET_SKEW(n, AVL_RIGHTSKEW);
          SSH_DEBUG(9, ("out"));
          return;

        case (AVL_RIGHT_CHILD | AVL_BALANCED):
          AVL_SET_SKEW(n, AVL_LEFTSKEW);
          SSH_DEBUG(9, ("out"));
          return;

          /* The higher subtree of n has shrinked by one -> mark n as
             balanced and iterate (because of decrease in total height
             by one).  */
        case (AVL_RIGHT_CHILD | AVL_RIGHTSKEW):
        case (AVL_LEFT_CHILD | AVL_LEFTSKEW):
          AVL_SET_SKEW(n, AVL_BALANCED);
          goto CONT;

          /* Changes in the rotation cases regarging avl_balance_i:
             (i) the conditions have been flipped; (ii) we cannot
             return but must iterate because the overall height might
             have shrinked; (iii) n->left may actually be balanced (if
             it, say, had left skew and was shrinked in its left
             subtree), in which case we need to update the skew
             slightly differently.  */
        case (AVL_RIGHT_CHILD | AVL_LEFTSKEW):
          switch (AVL_GET_SKEW(n->left))
            {
            case AVL_LEFTSKEW:   rot_ll(c, n); goto CONT;
            case AVL_RIGHTSKEW:  rot_lr(c, n); goto CONT;
            case AVL_BALANCED:
              SSH_DEBUG(9, ("Deletion LL rotation with balanced subtree."));
              rotright((c), (n));
              AVL_SET_SKEW((n), AVL_RIGHTSKEW);
              AVL_SET_SKEW((n)->right, AVL_LEFTSKEW);
              SSH_DEBUG(9, ("out"));
              return;
            }
          SSH_NOTREACHED;

        case (AVL_LEFT_CHILD | AVL_RIGHTSKEW):
          switch (AVL_GET_SKEW(n->right))
            {
            case AVL_RIGHTSKEW:  rot_rr(c, n); goto CONT;
            case AVL_LEFTSKEW:   rot_rl(c, n); goto CONT;
            case AVL_BALANCED:
              SSH_DEBUG(9, ("Deletion RR rotation with balanced subtree."));
              rotleft((c), (n));
              AVL_SET_SKEW((n), AVL_LEFTSKEW);
              AVL_SET_SKEW((n)->left, AVL_RIGHTSKEW);
              SSH_DEBUG(9, ("out"));
              return;
            }
          SSH_NOTREACHED;
        }

      SSH_NOTREACHED;

    CONT:
      shrinked_child = n->flags & AVL_CHILD_MASK;
      n = n->parent;
    }
  /*NOTREACHED*/
}


/* If a node has changed location: inform all neighbours.  */
#define AVL_FIX_PARENT(n)                                                     \
{                                                                             \
  if ((n)->flags & AVL_LEFT_CHILD)        (n)->parent->left = (n);            \
  else if ((n)->flags & AVL_RIGHT_CHILD)  (n)->parent->right = (n);           \
  else if ((n)->flags & AVL_NO_CHILD)     ROOT(c) = (n);                      \
  else SSH_NOTREACHED;                                                        \
}

#define AVL_FIX_CHILDREN(n)                                                   \
{                                                                             \
  if ((n)->left != NULL)   (n)->left->parent = (n);                           \
  if ((n)->right != NULL)  (n)->right->parent = (n);                          \
}

static void avl_detach_(SshADTContainer c, SshADTHandle h)
{
  SshADTAvlNode n, p;
  SSH_ASSERT(h != SSH_ADT_INVALID);

  SSH_DEBUG(9, ("in"));

  n = (SshADTAvlNode)h;
  SSH_DEBUG(9, ("n=%p, n->left=%p, n->right=%p.", n, n->left, n->right));

  /* If there is no left child, raising the right child and
     rebalancing will do.  */

  if (n->left == NULL)
    {
      p = n->parent;

      if (n->right != NULL)
        {
          n->right->parent = p;
          AVL_SET_CHILD_SLOT(n->right, AVL_GET_CHILD_SLOT(n));
          AVL_FIX_PARENT(n->right);
          AVL_ASSERT_NODE(n->right);
        }
      else
        {
          /* If there is not even a right child, find the parent and
             tell him that it has lost an entire subtree.  */

          switch(AVL_GET_CHILD_SLOT(n))
            {
            case AVL_LEFT_CHILD:    p->left = NULL; break;
            case AVL_RIGHT_CHILD:   p->right = NULL; break;
            case AVL_NO_CHILD:      ROOT(c) = NULL; break;
            default: SSH_NOTREACHED;
            }
        }

      avl_balance_d(c, p, (SshInt16)AVL_GET_CHILD_SLOT(n));
    }
  else
    {
      /* With two non-empty subtrees, we need to find a node k with
         which we can flip n so that removal will be easier (say, no
         right child).  */

      if (n->right != NULL)
        {
          SshADTAvlNode k, b = &(CROOT(c)->buffer);
          Boolean direct_neighbours = TRUE;

          k = n->left;
          while (k->right != NULL)
            {
              k = k->right;
              direct_neighbours = FALSE;
            }

          SSH_DEBUG(9, ("k=%p.", k));

          /* Flip n and k.  CROOT(c)->buffer is used here so that if
             memory is tight we can at least clean up without causing
             more allocation failures.  */
          b->flags  = k->flags;  k->flags  = n->flags;  n->flags  = b->flags;
          b->left   = k->left;   k->left   = n->left;   n->left   = b->left;
          b->right  = k->right;  k->right  = n->right;  n->right  = b->right;
          b->parent = k->parent; k->parent = n->parent; n->parent = b->parent;

          /* If k and n were direct neighbours, k->left and n->parent
             need fixing.  Also, the neighourhood needs to be informed
             about the changes.  */
          if (direct_neighbours)
            {
              k->left = n;
              n->parent = k;
            }

          AVL_FIX_PARENT(k);
          AVL_FIX_CHILDREN(k);
          AVL_ASSERT_NODE(k);
        }

      /* Now deal with n, which has sunk to the bottom where it can be
         easily removed.  */

      SSH_ASSERT(n->right == NULL);

      p = n->parent;

      if (n->left != NULL)
        {
          n->left->parent = p;
          AVL_SET_CHILD_SLOT(n->left, AVL_GET_CHILD_SLOT(n));
          AVL_FIX_PARENT(n->left);
          AVL_ASSERT_NODE(n->left);
        }
      else
        {
          switch(AVL_GET_CHILD_SLOT(n))
            {
            case AVL_LEFT_CHILD:    p->left = NULL; break;
            case AVL_RIGHT_CHILD:   p->right = NULL; break;
            case AVL_NO_CHILD:      ROOT(c) = NULL; break;
            default: SSH_NOTREACHED;
            }
        }

      avl_balance_d(c, p, (SshInt16)AVL_GET_CHILD_SLOT(n));
    }

  AVL_ASSERT_TREE(c);
  SSH_DEBUG(9, ("out"));
}


/**************************************************** Container destruction. */

/* $$METHOD(avltree, clear) */
/* $$METHOD(ranges, clear) */
static void avlclear(SshADTContainer c)
{
  SshADTAvlNode n;
  while ((n = ROOT(c)) != NULL)
    avl_delete(c, n);




}

/* $$METHOD(avltree, destr) */
/* $$METHOD(ranges, destr) */
SSH_ADT_STD_DESTROY(destr, avlclear(c);ssh_free(CROOT(c));)


/****************************************************************** Mapping. */

/* $$METHOD(avltree, map_attach) */
SSH_ADT_STD_MAP_ATTACH(avl_map_attach, ((SshADTAvlNode)handle)->image)

/* $$METHOD(ranges, map_attach) */
static void avl_map_attach_ranges(SshADTContainer c, SshADTHandle h, void *i)
{
  avl_map_attach(c, h, i);
  merge_map_attach_prepare(c, h);
}

/* $$METHOD(avltree, map_lookup) */
/* $$METHOD(ranges, map_lookup) */
SSH_ADT_STD_MAP_LOOKUP(avl_map_lookup, ((SshADTAvlNode)handle)->image)


/********************************** Find greatest lower / least upper bound. */

SshADTHandle ssh_adt_get_handle_to_glb(SshADTContainer c, void *o)
{
  SshADTAvlNode n = ROOT(c);
  int cmp;

  SSH_ASSERT(c != NULL);
  SSH_ASSERT(c->static_data == SSH_ADT_AVLTREE ||
             c->static_data == SSH_ADT_RANGES);
  SSH_ASSERT(o != NULL);

  /* special case: empty tree */
  if (n == NULL) return SSH_ADT_INVALID;

  /* special case: root is exact match */
  SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
  if (cmp == 0) return (SshADTHandle)n;

  /* default: find some n greater or equal than o... */
  while (cmp <= 0)
    {
      if (n->right == NULL)
        {
          /* (no larger n found, so return the maximum element) */
          return (SshADTHandle)n;
        }

      n = n->right;
      SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
    }

  SSH_ASSERT(n != NULL);

  /* ... and move back until it is no longer greater than o. */
  while (cmp > 0)
    {
      n = (SshADTAvlNode)avl_previous(c, (SshADTHandle)n);

      if (n == NULL)  /* (no minium element is found)  */
        return (SshADTHandle)SSH_ADT_INVALID;
      else
        SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
    }

  return (SshADTHandle)n;
}

/* Same for least upper bound.  */

SshADTHandle ssh_adt_get_handle_to_lub(SshADTContainer c, void *o)
{
  SshADTAvlNode n = ROOT(c);
  int cmp;

  SSH_ASSERT(c != NULL);
  SSH_ASSERT(c->static_data == SSH_ADT_AVLTREE ||
             c->static_data == SSH_ADT_RANGES);
  SSH_ASSERT(o != NULL);

  if (n == NULL) return SSH_ADT_INVALID;

  SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
  if (cmp == 0) return (SshADTHandle)n;

  while (cmp >= 0)
    {
      if (n->left == NULL)
        return (SshADTHandle)n;

      n = n->left;
      SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
    }

  SSH_ASSERT(n != NULL);

  while (cmp < 0)
    {
      n = (SshADTAvlNode)avl_next(c, (SshADTHandle)n);

      if (n == NULL)
        return (SshADTHandle)SSH_ADT_INVALID;
      else
        SSH_ADT_STD_COMPARE_H_O(c, n, o, cmp);
    }

  return (SshADTHandle)n;
}


/**************************************************** Ranges specific stuff. */

/* Merging.  Merge the two neighboring intervals [a, b) and [b, c) if
   appropriate.  If a merge occurs, a is returned.  Otherwise, b is
   returned.  */

static SshADTAvlNode merge_ab(SshADTContainer c,
                              SshADTAvlNode a, SshADTAvlNode b)
{
  void *ai, *bi;  /* images */

  /* SSH_DEBUG(0, ("%p %p.", a, b));
     ssh_adt_ranges_dump("merge_ab: entering!", c); */

  SSH_ASSERT(a == NULL || avl_next(c, (SshADTHandle)a) == b);
  SSH_ASSERT(b == NULL || avl_previous(c, (SshADTHandle)b) == a);

  if (b == NULL)
    {
      /* if b does not exist, a extends all the way to +inf.  */
      return a;
    }

  if (a == NULL && b != NULL)
    {
      /* If [a, b) is [-inf, b), check whether [b, c) maps to NULL
         and delete it in case it does.  */

      bi = ssh_adt_map_lookup(c, (SshADTHandle)b);
      if (bi == NULL)
        {
          avl_delete(c, (SshADTHandle)b);
          b = NULL;
        }

      return b;
    }

  if (a != NULL && b != NULL)
    {
      /* If both a and b are defined, do a standard merge.  */

      ai = ssh_adt_map_lookup(c, (SshADTHandle)a);
      bi = ssh_adt_map_lookup(c, (SshADTHandle)b);

      if (ai == bi)
        {
          avl_delete(c, (SshADTHandle)b);
          return a;
        }
      else
        return b;
    }

  SSH_NOTREACHED;
  return NULL;
}


/* This function is called (ie. registered in the merge cache) when
   range [N, M) has been mapped to a new value V by
   ssh_adt_map_attach.  If range [K, N) maps to V, [K, N) and [N, M)
   are merged to [K, M); similarly for [M, L).  (-inf, min) is
   implicitly mapped to NULL.  This means that if a smallest node is
   inserted and mapped to NULL, it is discared during the next merge.  */

static Boolean merge_map_attach(SshADTContainer c, SshADTHandle h)
{
  SshADTAvlNode k = NULL, n = NULL, m = NULL;

  SSH_DEBUG(9, ("in."));

  n = (SshADTAvlNode)h;
  SSH_ASSERT(n != NULL);

  k = (SshADTAvlNode)avl_previous(c, (SshADTHandle)n);
  m = (SshADTAvlNode)avl_next(c, (SshADTHandle)n);

  n = merge_ab(c, k, n);
  merge_ab(c, n, m);

  SSH_DEBUG(9, ("done."));
  return TRUE;
}


/* If [N, M) is going to be removed in a second, so [K, N) and [M, L)
   need to be merged if appropriate.  This operation leaves N
   untouched.  It is triggered (ie. prepared) by ssh_adt_detach and
   thus also by ssh_adt_delete.  */

static Boolean merge_detach(SshADTContainer c, SshADTHandle h)
{
  SshADTAvlNode k, m;

  SSH_DEBUG(9, ("in."));

  k = (SshADTAvlNode)h;
  m = k != NULL
    ? (SshADTAvlNode)avl_next(c, (SshADTHandle)k)
    : (SshADTAvlNode)enumerate_start(c);

  merge_ab(c, k, m);

  SSH_DEBUG(9, ("done."));
  return TRUE;
}

/* Before the actual merging takes place, a sequence of change can be
   made.  Those changes are registered in the container_specifics
   field and merged by ssh_adt_ranges_merge.  */

static Boolean merge_map_attach_prepare(SshADTContainer c, SshADTHandle h)
{
  SshADTHandle *hp;
  SshBufferStatus s;

  SSH_DEBUG(9, ("in."));

  if ((hp = ssh_malloc(sizeof(*hp))) == NULL)
    {
      SSH_DEBUG(0, ("out of memory!"));
      return FALSE;
    }
  *hp = h;
  s = ssh_buffer_append(RROOT(c)->merge_additions,
                        (const unsigned char *)hp, sizeof(*hp));
  ssh_free(hp);

  SSH_DEBUG(9, ("out: %i.", s));
  return (s == SSH_BUFFER_OK);
}

static Boolean merge_detach_prepare(SshADTContainer c, SshADTHandle h)
{
  SshADTHandle *hp;
  SshBufferStatus s;

  SSH_DEBUG(9, ("in."));

  /* find the previous node and store it in merge_deletions.  */
  if ((hp = ssh_malloc(sizeof(*hp))) == NULL)
    {
      SSH_DEBUG(0, ("out of memory!"));
      return FALSE;
    }
  *hp = avl_previous(c, h);
  s = ssh_buffer_append(RROOT(c)->merge_deletions,
                        (const unsigned char *)hp, sizeof(*hp));

  {
    /* Remove h and previous(h) from both merge_additions and
       merge_deletions if they are found there.  */

    SshBuffer b;
    SshADTHandle *hs;
    int len, i;

#   define GN                                                                 \
    hs = (SshADTHandle *)ssh_buffer_ptr(b);                                   \
    len = ssh_buffer_len(b) / sizeof(SshADTHandle);                           \
    SSH_DEBUG(99, ("%p / %i.", hs, len));                                     \
    for (i = 0; i < len; i++)                                                 \
      {                                                                       \
        SSH_DEBUG(99, ("%i.", i));                                            \
        if (h == hs[i] || h == *hp)                                           \
          {                                                                   \
            hs[i] = hs[len-1];  /* (also works for i == len-1) */             \
            ssh_buffer_consume_end(b, sizeof(SshADTHandle));                  \
            len--;                                                            \
          }                                                                   \
      }

    b = RROOT(c)->merge_additions; GN;
    b = RROOT(c)->merge_deletions; GN;

#   undef GN
  }

  ssh_free(hp);
  SSH_DEBUG(9, ("out: %i.", s));
  return (s == SSH_BUFFER_OK);
}

void ssh_adt_ranges_merge(SshADTContainer c)
{
  SshBuffer b;
  SshADTHandle *hs;
  int len, i;

  SSH_DEBUG(9, ("in."));

# define NG(op)                                                               \
  hs = (SshADTHandle *)ssh_buffer_ptr(b);                                     \
  len = ssh_buffer_len(b) / sizeof(SshADTHandle);                             \
  for (i = 0; i < len; i++)                                                   \
    op(c, hs[i]);                                                             \
  ssh_buffer_clear(b);

  b = RROOT(c)->merge_additions; NG(merge_map_attach);
  b = RROOT(c)->merge_deletions; NG(merge_detach);

# undef NG

  SSH_ASSERT(ssh_buffer_len(RROOT(c)->merge_additions) == 0);
  SSH_ASSERT(ssh_buffer_len(RROOT(c)->merge_deletions) == 0);

  SSH_DEBUG(9, ("out."));
}


/************************************************** exported container types */

const SshADTStaticData ssh_adt_avltree_static_data =
{
  {
    /* $$METHODS(avltree) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init_tree, /* container_init */
    avlclear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    avl_insert_to, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    NULL_FNPTR, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    avl_put_to, /* put_n_to */
    get, /* get */
    avl_num_objects, /* num_objects */
    avl_geth, /* get_handle_to */
    avl_geth_loc, /* get_handle_to_location */
    avl_next, /* next */
    avl_previous, /* previous */
    enumerate_start, /* enumerate_start */
    avl_next, /* enumerate_next */
    avl_geth_eq, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    avl_detach, /* detach */
    avl_delete, /* delet */
    avl_map_lookup, /* map_lookup */
    avl_map_attach, /* map_attach */
    /* $$ENDMETHODS */
  },
  sizeof(SshADTAvlNodeStruct),
  0
};

const SshADTContainerType ssh_adt_avltree_type = &ssh_adt_avltree_static_data;


const SshADTStaticData ssh_adt_ranges_static_data =
{
  {
    /* $$METHODS(ranges) */
    /* DO NOT EDIT THIS, edit METHODS.h and
       the method implementations above instead. */
    container_init_ranges, /* container_init */
    avlclear, /* clear */
    destr, /* destr */
    NULL_FNPTR, /* insert_at */
    avl_insert_to_ranges, /* insert_to */
    NULL_FNPTR, /* alloc_n_at */
    NULL_FNPTR, /* alloc_n_to */
    NULL_FNPTR, /* put_n_at */
    avl_put_to_ranges, /* put_n_to */
    get, /* get */
    avl_num_objects, /* num_objects */
    avl_geth, /* get_handle_to */
    avl_geth_loc, /* get_handle_to_location */
    avl_next, /* next */
    avl_previous, /* previous */
    enumerate_start, /* enumerate_start */
    avl_next, /* enumerate_next */
    avl_geth_eq, /* get_handle_to_equal */
    NULL_FNPTR, /* reallocate */
    avl_detach_range, /* detach */
    avl_delete, /* delet */
    avl_map_lookup, /* map_lookup */
    avl_map_attach_ranges, /* map_attach */
    /* $$ENDMETHODS */
  },
  sizeof(SshADTAvlNodeStruct),
  0
};

const SshADTContainerType ssh_adt_ranges_type = &ssh_adt_ranges_static_data;


#ifdef DEBUG_LIGHT
/***************************************************************** debugging */

#if 0
static int avl_maxheight(SshADTAvlNode n)
{
  int r, l;

  if (n == NULL)
    return 0;
  else
    {
      r = avl_maxheight(n->right);
      l = avl_maxheight(n->left);
      return ((r > l ? r : l) + 1);
    }
}

static Boolean avl_consistent(SshADTAvlNode n)
{
  int l, r;

  SSH_DEBUG(9, ("%p.", n));
  if (n == NULL)  return TRUE;

  /* the basic stuff */
  AVL_ASSERT_NODE(n);

  /* check that the skew flag is telling the truth */
  l = avl_maxheight(n->left);
  r = avl_maxheight(n->right);

  if (n->flags & AVL_LEFTSKEW && !(l == r + 1))
    {
      SSH_DEBUG(0, ("%p does not have left skew.", n));
      return FALSE;
    }
  if (n->flags & AVL_RIGHTSKEW && !(l + 1 == r))
    {
      SSH_DEBUG(0, ("%p does not have right skew.", n));
      return FALSE;
    }
  if (n->flags & AVL_BALANCED && !(l == r))
    {
      SSH_DEBUG(0, ("%p is not balanced.", n));
      return FALSE;
    }

  /* recurse */
  return (avl_consistent(n->left) && avl_consistent(n->right));
}
#endif /* 0 */

/*
   Other invariants not checked here:

  - for each node n, all nodes in the left subtree of n are smaller
    than n, and all nodes in the right subtree are larger.

*/


void ssh_adt_avltree_int_dump(int debug_level, SshADTContainer c)
{
  SshADTAvlNode n;
  int o;

  SSH_DEBUG(debug_level, ("dumping c=%p (ROOT=%p, %i objects).",
                          c, ROOT(c), avl_num_objects(c)));
  n = ssh_adt_enumerate_start(c);
  while (n != NULL)
    {
      o = *((int *)ssh_adt_get(c, n));
      SSH_DEBUG(debug_level,
                ("node: %i s[%p] l[%p] r[%p] p[%p]"
                 " [child slot: %s balance: %s]",
                 o, n, n->left, n->right, n->parent,

                 (n->flags & AVL_LEFT_CHILD
                  ? "<-"
                  : (n->flags & AVL_RIGHT_CHILD
                     ? "->"
                     : "- ")),

                 (n->flags & AVL_BALANCED
                  ? "- "
                  : (n->flags & AVL_LEFTSKEW
                     ? "<-"
                     : (n->flags & AVL_RIGHTSKEW
                        ? "->"
                        : (SSH_NOTREACHED, ""))))));

      n = ssh_adt_enumerate_next(c, n);
    }
}

/* The visual compiler graph (VCG) tool can be found at
   http://rw4.cs.uni-sb.de/users/sander/html/gsvcg1.html */

static void ssh_adt_avltree_int_dump_xvcg_aux(SshADTContainer c,
                                              SshADTAvlNode n, FILE *fp)
{
  fprintf(fp,
          "node: { title: \"%p\""
          " label: \"%p [0x%2x][%i]\""
          " }\n",
          n, n, n->flags, *((int *)ssh_adt_get(c, n)));

  if (n->left != NULL)
    {
      fprintf(fp,
              "edge: { sourcename: \"%p\""
              " targetname: \"%p\""
              " label: \"<\""
              " }\n",
              n, n->left);
      ssh_adt_avltree_int_dump_xvcg_aux(c, n->left, fp);
    }

  if (n->right != NULL)
    {
      fprintf(fp,
              "edge: { sourcename: \"%p\""
              " targetname: \"%p\""
              " label: \">=\""
              " }\n",
              n, n->right);
      ssh_adt_avltree_int_dump_xvcg_aux(c, n->right, fp);
    }
}

void ssh_adt_avltree_int_dump_xvcg(SshADTContainer c, FILE *fp)
{
  fprintf(fp, "graph: {\n");
  fprintf(fp, "title: \"%p\"\n", c);
  fprintf(fp, "label: \"c=%p (ROOT=%p, %lu objects)\"\n",
          c, ROOT(c), (unsigned long)avl_num_objects(c));
  fprintf(fp, "display_edge_labels: yes\n");
  fprintf(fp, "shrink: 1\n");
  ssh_adt_avltree_int_dump_xvcg_aux(c, ROOT(c), fp);
  fprintf(fp, "}\n");
}

void ssh_adt_avltree_int_display_xvcg(SshADTContainer c)
{
  FILE *fp;
  char tmpfile[] = "/tmp/a.vcg";
  int x;

  SSH_DEBUG(3, ("writing graph file to '%s'.", tmpfile));
  if (!(fp = fopen(tmpfile, "w"))) SSH_NOTREACHED;
  ssh_adt_avltree_int_dump_xvcg(c, fp);
  fclose(fp);

  SSH_DEBUG(3, ("running xvcg."));

  x = system("xvcg /tmp/a.vcg -d tree");
  if (x)
    exit(x);
}

void ssh_adt_ranges_dump(unsigned char *msg, SshADTContainer c)
{
  SshADTHandle h, *hs;
  SshBuffer b;
  int len, i;

  SSH_DEBUG(0, ("%s>> [", msg));

  for (h = ssh_adt_enumerate_start(c);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(c, h))
    {
      SSH_DEBUG(0, ("%s>> h=%p key=%i val=%i.",
                    msg,
                    h,
                    *(int *) ssh_adt_get(c, h),
                    *(int *) ssh_adt_map_lookup(c, h)));
    }

  /* merge cache */
# define GN(slot)                                                             \
  {                                                                           \
    b = RROOT(c)->merge_ ## slot;                                             \
    hs = (SshADTHandle *)ssh_buffer_ptr(b);                                   \
    len = ssh_buffer_len(b) / sizeof(SshADTHandle);                           \
    SSH_DEBUG(0, ("%s>> %s: [%i].", msg, #slot, len));                        \
    for (i = 0; i < len; i++)                                                 \
      SSH_DEBUG(0, ("%s>>     %p.", msg, hs[i]));                             \
  }

  GN(additions);
  GN(deletions);

  SSH_DEBUG(0, ("%s>> ]", msg));

# undef GN
}
#endif /* DEBUG_LIGHT */
