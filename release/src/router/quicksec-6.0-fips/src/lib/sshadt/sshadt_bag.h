/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_bag.h
*/

#ifndef SSH_ADT_BAG_H_INCLUDED
#define SSH_ADT_BAG_H_INCLUDED

#include "sshadt.h"


#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_bag_type;

#define SSH_ADT_BAG (ssh_adt_bag_type)

/* Use this instead of SshADTHeaderStruct if you want to save 8 bytes
   of memory per header.  */
typedef struct {
  Boolean a; void *b, *c;
} SshADTBagHeaderStruct;


#endif /* SSH_ADT_BAG_H_INCLUDED */
