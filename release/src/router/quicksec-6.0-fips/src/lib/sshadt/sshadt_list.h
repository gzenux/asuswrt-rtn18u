/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_list.h
*/

#ifndef SSH_ADT_LIST_H_INCLUDED
#define SSH_ADT_LIST_H_INCLUDED

#include "sshadt.h"

#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_list_type;

#define SSH_ADT_LIST (ssh_adt_list_type)

/* Sort a list destructively in ascending order (smallest objects
   first). */
void ssh_adt_list_sort(SshADTContainer c);

/* Type for inlined list headers.  (Users only need to know the type
   of this; it is only provided so that one doesn't need to store the
   20 bytes of SshADTHeader.)  */
typedef struct {
  void *a, *b;
} SshADTListHeaderStruct;

#endif /* SSH_ADT_LIST_H_INCLUDED */
