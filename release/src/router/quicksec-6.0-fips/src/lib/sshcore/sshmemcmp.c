/**
   @copyright
   Copyright (c) 2003 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Trivial replacement memcmp for environments where the system one
   is broken. (especially with some versions of nucleus)
*/

#ifdef WITH_REPLACEMENT_MEMCMP

#include "sshincludes.h"

int ssh_memcmp(const void *p1, const void *p2, size_t n)
{
  unsigned char *s1 = (unsigned char *) p1;
  unsigned char *s2 = (unsigned char *) p2;
  int d;

  while (n > 0)
    {
      d = ((int) *s1) - ((int) *s2);
      if (d != 0)
        return d;
      n--;
      s1++;
      s2++;
    }
  return 0;
}

#else /* WITH_REPLACEMENT_MEMCMP */

typedef enum
{
  SSH_DUMMY_0
} SshMakeFileNotEmpty;

#endif /* WITH_REPLACEMENT_MEMCMP */
