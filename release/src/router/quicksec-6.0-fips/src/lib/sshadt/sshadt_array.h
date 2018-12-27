/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_array.h
*/

#ifndef SSH_ADT_ARRAY_H_INCLUDED
#define SSH_ADT_ARRAY_H_INCLUDED

#include "sshadt.h"

#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_array_type;

#define SSH_ADT_ARRAY (ssh_adt_array_type)

#endif /* SSH_ADT_ARRAY_H_INCLUDED */
