/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc routines for the interceptor, these are mainly needed
   by the engine.
*/

#include "linux_internal.h"

#define SSH_DEBUG_MODULE "SshInterceptorMisc"

int
atoi(const char *cp)
{
  int value;

  for (value = 0; *cp >= '0' && *cp <= '9'; cp++)
    value = 10 * value + *cp - '0';
  return value;
}

#define tolower(ch) \
  (((unsigned char)(ch) >= 'A' && (unsigned char)(ch) <= 'Z') ? \
   ((ch) + 32) : (ch))

#ifndef __PPC__
int
strncasecmp(const char *s1, const char *s2, size_t len)
{
  if (len == 0)
    return 0;

  while (len-- > 1 && *s1 && (*s1 == *s2 || tolower(*s1) == tolower(*s2)))
    {
      s1++;
      s2++;
    }
  return (int) tolower(*(unsigned char *) s1)
    - (int) tolower(*(unsigned char *) s2);
}
#endif /* __PPC__ */

void
exit(int value)
{
  panic("interceptor: exit called.\n");
}

/* ssh replacement for memchr, needed on non-i386 linux platforms. */

void *
ssh_memchr(const void *s, int c, size_t n)
{
  const unsigned char *s1;
  s1 = s;

  while (n-- > 0)
    {
      if (*s1 == (unsigned char) c)
        return (void *) s1;

      s1++;
    }

  return NULL;
}
