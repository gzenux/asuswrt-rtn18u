/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_map.h
*/

#ifndef SSH_ADT_MAP_H_INCLUDED
#define SSH_ADT_MAP_H_INCLUDED

#include "sshadt.h"


#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_map_type;

#define SSH_ADT_MAP (ssh_adt_map_type)

/* Use this instead of SshADTHeaderStruct (it's smaller).  */
typedef struct {
  Boolean a; void *b, *c;
} SshADTMapHeaderStruct;


#endif /* SSH_ADT_MAP_H_INCLUDED */
