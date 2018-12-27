/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Replacement functions for strncasecmp
*/

#include "sshincludes.h"

int strncasecmp(const char *s1, const char *s2, size_t len)
{
  if (len==0)
    return 0;

  while (len-- > 1 && *s1 &&
         (*s1 == *s2 ||
          tolower(*(unsigned char *)s1) ==
          tolower(*(unsigned char *)s2)))
    {
      s1++;
      s2++;
    }
  return (int) tolower(*(unsigned char *)s1)
       - (int) tolower(*(unsigned char *)s2);
}
