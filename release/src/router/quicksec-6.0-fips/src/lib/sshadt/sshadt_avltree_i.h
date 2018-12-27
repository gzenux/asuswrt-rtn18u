/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_avltree_i.h
*/

#ifndef SSHADT_AVLTREE_I_H_INCLUDED
#define SSHADT_AVLTREE_I_H_INCLUDED


/* Inlined header type.  */

typedef struct SshADTAvlNodeRec {
  SshInt8 flags;
  struct SshADTAvlNodeRec *left, *right, *parent;
  void *image;
} *SshADTAvlNode, SshADTAvlNodeStruct;


/* SshADTAvlENode is a tuple of header and object.  The object is
   placed first so that ENodeStruct can be used as an object pointer
   in case of inlined headers.  This structure is mostly used by the
   macros in sshadt_std_i.h.  See also documentation for
   NEED_EXTRA_NODE flag in sshadt_i.h.  */

typedef struct {
  void *object;
  SshADTAvlNodeStruct i;
} *SshADTAvlENode, SshADTAvlENodeStruct;


/* The container type specific control structure contains two nodes,
   the root and a buffer node.  (The buffer node is very convenient in
   avl_detach_.)  We call this control structure CRoot (container root
   or control root) as opposed to Root (the root node of the tree).  */

typedef struct {
  SshADTAvlNode root;
  SshADTAvlNodeStruct buffer;
} *SshADTAvlCRoot, SshADTAvlCRootStruct;

#define CROOT(c) ((SshADTAvlCRoot)(c->container_specific))
#define ROOT(c) (CROOT(c)->root)

typedef struct {
  SshADTAvlNode root;
  SshADTAvlNodeStruct buffer;

  /* The following two fields are ranges-specific and contain a
     sequence of SshADTHandle.  SSH_ADT_INVALID signifies -inf.  They
     are used to store changes in the container until the next merging
     takes place.  the key handles stored here are processed by
     ssh_adt_ranges_merge.  */
  SshBuffer merge_additions;
  SshBuffer merge_deletions;
} *SshADTRangesCRoot, SshADTRangesCRootStruct;

#define RROOT(c) ((SshADTRangesCRoot)(c->container_specific))

/* The flags in each node require some syntactic sugar.  */

#define AVL_LEFT_CHILD    0x01
#define AVL_RIGHT_CHILD   0x02
#define AVL_NO_CHILD      0x04
#define AVL_CHILD_MASK     (AVL_LEFT_CHILD | AVL_RIGHT_CHILD | AVL_NO_CHILD)

#define AVL_LEFTSKEW      0x10
#define AVL_RIGHTSKEW     0x20
#define AVL_BALANCED      0x40
#define AVL_BALANCE_MASK   (AVL_LEFTSKEW | AVL_RIGHTSKEW | AVL_BALANCED)

#define AVL_GET_CHILD_SLOT(n) \
  ((n)->flags & AVL_CHILD_MASK)
#define AVL_GET_SKEW(n) \
  ((n)->flags & AVL_BALANCE_MASK)

#define AVL_SET_CHILD_SLOT(n, s) \
  (n)->flags = ((n)->flags & AVL_BALANCE_MASK) | (s)
#define AVL_SET_SKEW(n, s) \
  (n)->flags = ((n)->flags & AVL_CHILD_MASK) | (s)


#ifdef SSH_DEBUG

/* Node invariants.  */

#define AVL_ASSERT_NODE(n)                                                    \
{                                                                             \
  /* all nodes should exist (-: */                                            \
  SSH_ASSERT(n != NULL);                                                      \
                                                                              \
  /* node it not root iff exactly one of AVL_*_CHILD is high */               \
  SSH_ASSERT((n->parent != NULL)                                              \
             || ((n->flags & AVL_CHILD_MASK) == AVL_NO_CHILD));               \
                                                                              \
  SSH_ASSERT((n->parent == NULL)                                              \
             || ((n->flags & AVL_CHILD_MASK) == AVL_RIGHT_CHILD               \
                 || (n->flags & AVL_CHILD_MASK) == AVL_LEFT_CHILD));          \
                                                                              \
  /* all pointers are symmetrically sound */                                  \
  SSH_ASSERT(n->left == NULL || (n->left->parent == n));                      \
  SSH_ASSERT(n->right == NULL || (n->right->parent == n));                    \
  SSH_ASSERT(n->parent == NULL ||                                             \
             (((n->flags & AVL_CHILD_MASK) == AVL_LEFT_CHILD)                 \
              ? (n->parent->left == n)                                        \
              : (n->parent->right == n)));                                    \
}

/* Check node invariants if node exists, but tolerate NULL pointer.  */

#define AVL_ASSERT_NODE_MAYBE(n)  { if (n != NULL) AVL_ASSERT_NODE(n); }


/* Tree invariants.  This macro multiplies time complexity of any
   insert or detach operation by O((log n)^2).  */

#if 0
static Boolean avl_consistent(SshADTAvlNode n);
#define AVL_ASSERT_TREE(c)                                                    \
{                                                                             \
  if (ROOT(c) != NULL)                                                        \
    SSH_ASSERT(ROOT(c)->parent == NULL);                                      \
                                                                              \
  if (!(avl_consistent(ROOT(c))))                                             \
    {                                                                         \
      SSH_DEBUG(0, ("*** INCONSISTENCE IN TREE DETECTED!"));                  \
      ssh_adt_avltree_int_dump(9, c);                                         \
      ssh_adt_avltree_int_display_xvcg(c);                                    \
                                                                              \
      SSH_NOTREACHED;                                                         \
    }                                                                         \
}
#else
#define AVL_ASSERT_TREE(c)
#endif

#else  /* SSH_DEBUG */

#define AVL_ASSERT_NODE(n)
#define AVL_ASSERT_NODE_MAYBE(n)
#define AVL_ASSERT_TREE(c)
#endif


/* Range specific things.  */

static Boolean merge_map_attach_prepare(SshADTContainer c, SshADTHandle h);
static Boolean merge_detach_prepare(SshADTContainer c, SshADTHandle h);


#endif /* SSHADT_AVLTREE_I_H_INCLUDED */
