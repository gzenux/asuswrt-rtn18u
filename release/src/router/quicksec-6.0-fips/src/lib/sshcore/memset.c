/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef VXWORKS

#include "sshincludes.h"

void *memset(void *b, int ch, size_t len)
{
  unsigned char *p = (unsigned char *)b;

  if (ch == 0)
    {
      bzero(b, len);
      return b;
    }
  while (len-- > 0)
    {
      *p++ = ch;
    }
  return b;
}
#endif /* VXWORKS */
