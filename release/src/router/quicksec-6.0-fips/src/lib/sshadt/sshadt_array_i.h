/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_array_i.h
*/

#ifndef SSH_ADT_ARRAY_I_H_INCLUDED
#define SSH_ADT_ARRAY_I_H_INCLUDED

#include "sshadt.h"

typedef struct {
  void **array;
  size_t array_size;
} SshADTArrayRoot;

#endif /* SSH_ADT_ARRAY_I_H_INCLUDED */
