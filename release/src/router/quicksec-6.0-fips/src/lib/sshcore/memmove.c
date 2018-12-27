/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is a replacement function for memmove for systems that do not
   have this function.
*/

#include "sshincludes.h"

#ifndef VXWORKS

void *memmove(void *dest0, const void *src0, size_t len)
{
  unsigned char *dest = dest0;
  const unsigned char *src = src0;
  size_t i;

  if (len == 0 || dest == src)
    return dest0;

  if ((unsigned long)dest < (unsigned long)src)
    {
      for (i = 0; i < len; i++)
        dest[i] = src[i];
    }
  else
    {
      for (i = len; i > 0; i--)
        dest[i - 1] = src[i - 1];
    }

  return dest0;
}

#endif /* VXWORKS */
