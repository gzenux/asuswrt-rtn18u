/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Util library split part I: moved files to their directories.
   Created also misc/ to contain files that should disappear with
   all due haste.
*/

#ifndef VXWORKS
#include <stdio.h>

int remove(const char *filename)
{
  return unlink(filename);
}
#endif /* VXWORKS */
