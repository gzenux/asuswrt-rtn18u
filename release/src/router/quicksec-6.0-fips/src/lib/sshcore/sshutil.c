/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility library unitialization routines
*/

#include "sshincludes.h"
#include "sshglobals.h"

void
ssh_util_uninit(void)
{
  ssh_debug_uninit();
  ssh_global_uninit();






}

/* eof */
