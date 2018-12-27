/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This container implements AVL (Adelson-Velskii and Landis) search
   trees.  I use loops and pointer structures instead of the stack to
   store all the information I need, with the effect that each node has
   2+3*4 bytes control information (flags and pointers to left child,
   right child and parent).  Some benchmarking remains to be done to
   prove that this was a good design decision.

   External material on AVL trees:

   linux-2.4.3/mm/mmap_avl.c by Bruno Haible
   http://www.pads.uwaterloo.ca/Bruno.Preiss/books/opus5/html/page319.html.
*/

#ifndef SSH_ADT_AVLTREE_H_INCLUDED
#define SSH_ADT_AVLTREE_H_INCLUDED

#include "sshadt.h"

#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_avltree_type;

#define SSH_ADT_AVLTREE (ssh_adt_avltree_type)

/* Greatest lower bound of o (greatest n such that n <= o).  If there
   is no such n, SSH_ADT_INVALID is returned.  o does not need to be
   in the container (i.e. have a valid header structure attached to
   it), it only needs to make the compare callback happy.  */
SshADTHandle ssh_adt_get_handle_to_glb(SshADTContainer c, void *o);

/* Least upper bound of o.  Analogous to ssh_adt_get_handle_to_glb.  */
SshADTHandle ssh_adt_get_handle_to_lub(SshADTContainer c, void *o);

#ifdef DEBUG_LIGHT

void ssh_adt_avltree_int_dump(int debug_level, SshADTContainer c);
void ssh_adt_avltree_int_dump_xvcg(SshADTContainer c, FILE *fp);
void ssh_adt_avltree_int_display_xvcg(SshADTContainer c);

/* dump a ranges container.  this works only for (int *) objects and
   (int) values.  */
void ssh_adt_ranges_dump(unsigned char *msg, SshADTContainer c);

#endif /* DEBUG_LIGHT */

#endif /* SSH_ADT_AVLTREE_H_INCLUDED */
