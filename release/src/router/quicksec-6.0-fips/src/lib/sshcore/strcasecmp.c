/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Replacement functions for strcasecmp.
*/

#include "sshincludes.h"

int strcasecmp(const char *s1, const char *s2)
{
  while (*s1 && (*s1 == *s2 ||
                 tolower(*(unsigned char *)s1) ==
                 tolower(*(unsigned char *)s2)))
    {
      s1++;
      s2++;
    }
  return (int) *(unsigned char *)s1 - (int) *(unsigned char *)s2;
}
