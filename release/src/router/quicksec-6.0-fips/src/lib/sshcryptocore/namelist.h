/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Compute the section between two name lists.
*/

#ifndef NAMELIST_H
#define NAMELIST_H

/* Attack can be launched against this system. The name tree is of form

   identifier{idenfifier{...},identifier{...},...},...

   thus having very large trees eats lots of memory while parsing them!
   Clearly some limit for maximum level of recursion allowed should be
   given.
 */

#define SSH_NTREE_MAX_LEVEL 5

typedef enum
{
  SSH_NTREE_OK,
  SSH_NTREE_ERROR
} SshNameTreeStatus;

/* Types for handling name trees. */
typedef struct SshNameNodeRec *SshNameNode;
typedef struct SshNameTreeRec *SshNameTree;

/* Allocation of a name tree context. */
void ssh_ntree_allocate(SshNameTree *tree);
/* How to free name tree context. */
void ssh_ntree_free(SshNameTree tree);

/* Routine for parsing a namelist (or tree) to a name tree. Tree have been
   cleared before calling this, or just allocated. Tree uses namelist for
   holding actual identifiers, thus you should NOT free namelist before
   the tree. */
SshNameTreeStatus ssh_ntree_parse(const char *namelist, SshNameTree tree);

/* Compute intersection between two name tree's. */
SshNameTreeStatus ssh_ntree_intersection(SshNameTree ret,
                                         SshNameTree a, SshNameTree b);

/* Print name tree with function that outputs single characters. */
void ssh_ntree_print(SshNameTree tree,
                     void (*print_char)(const char byte));

/* Generate valid namelist from name tree. */
void ssh_ntree_generate_string(SshNameTree tree, char **namelist);

/* Free one particular node and it's children. Tree containing it will be
   still valid, although this node will be gone forever. If given node
   does not belong to given tree, operation is undefined. */
void ssh_nnode_free(SshNameTree tree, SshNameNode node);

/* Routines for handling particular nodes. */

SshNameNode ssh_nnode_find_identifier(SshNameNode node,
                                      const char *identifier);
SshNameNode ssh_ntree_add_child(SshNameTree tree, SshNameNode node,
                                const char *identifier);
SshNameNode ssh_ntree_add_next(SshNameTree tree, SshNameNode node,
                               const char *identifier);
/* Get the identifier contained in a node. */
char *ssh_nnode_get_identifier(SshNameNode node);
const char *ssh_nnode_get_identifier_pointer(SshNameNode node, size_t *len);

/* Get nodes parent. */
SshNameNode ssh_nnode_get_parent(SshNameNode node);
/* Get nodes child. */
SshNameNode ssh_nnode_get_child(SshNameNode node);
/* Get next node in a row. */
SshNameNode ssh_nnode_get_next(SshNameNode node);
/* Get previous node in a row. */
SshNameNode ssh_nnode_get_prev(SshNameNode node);
/* Get root node from a tree. */
SshNameNode ssh_ntree_get_root(SshNameTree tree);

/* Namelist generic interface. */

/* Get the name following to 'namelist' pointer and ending with the next
   comma separator. Name string returned is zero terminated and is to
   be freed by caller with ssh_xfree.  Returns NULL if there are no more names
   or namelist is NULL. */
char *ssh_name_list_get_name(const char *namelist);

/* Step over to the next name. Returns the pointer to the next name, or NULL
   if there are no more names in the list. */
const char *ssh_name_list_step_forward(const char *namelist);

/* Compute the intersection between string `src1' and `src2'.
   Format for inputs and output is "name1,name2,...,namen".
   The caller must free the returned string with ssh_xfree.
   The output list will contain the names in the order in which they
   are listed in the first list. */
char *ssh_name_list_intersection(const char *src1, const char *src2);

#endif /* NAMELIST_H */
