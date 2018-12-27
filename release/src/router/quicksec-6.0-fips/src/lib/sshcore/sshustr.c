/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for casting between unsigned and signed character strings.
*/

#include "sshincludes.h"

/* Cast functions between unsigned and signed character strings. */

unsigned char *ssh_ustr(char *string)
{
  return (unsigned char *) string;
}

const unsigned char *ssh_custr(const char *string)
{
  return (const unsigned char *) string;
}

const char *ssh_csstr(const unsigned char *string)
{
  return (const char *) string;
}

char *ssh_sstr(unsigned char *string)
{
  return (char *) string;
}

/* Variants of the C library string functions that take unsigned charancter
   strings as input. */
int ssh_ustrlen(const unsigned char *str)
{
  return ((int)strlen((const char *)str));
}

#if !defined (KERNEL) && !defined(_KERNEL)
unsigned char *ssh_ustrncpy(unsigned char *str1,
                            const unsigned char *str2,
                            size_t len)
{
  return (unsigned char *)strncpy((char *)str1, (const char *)str2, len);
}

int ssh_ustrcmp(const unsigned char *str1, const unsigned char *str2)
{
  return strcmp((const char *)str1, (const char *)str2);
}

int ssh_usstrcmp(const unsigned char *str1, const char *str2)
{
  return strcmp((const char *)str1, str2);
}

int ssh_ustrncmp(const unsigned char *str1, const unsigned char *str2,
                 size_t len)
{
  return strncmp((const char *)str1, (const char *)str2, len);
}

int ssh_usstrncmp(const unsigned char *str1, const char *str2, size_t len)
{
  return strncmp((const char *)str1, str2, len);
}

unsigned char *ssh_ustrcpy(unsigned char *str1,
                           const unsigned char *str2)
{
  return (unsigned char *)strcpy((char *)str1, (const char *)str2);
}


unsigned char *ssh_ustrcat(unsigned char *str1,
                           const unsigned char *str2)
{
  return (unsigned char *)strcat((char *)str1, (const char *)str2);
}

unsigned char *ssh_ustrchr(const unsigned char *str, int c)
{
  return (unsigned char *)strchr((const char *)str, c);
}

int ssh_ustrcasecmp(const unsigned char *str1, const unsigned char *str2)
{
  return strcasecmp((const char *)str1, (const char *)str2);
}

int ssh_usstrcasecmp(const unsigned char *str1, const char *str2)
{
  return strcasecmp((const char *)str1, str2);
}

int ssh_ustrncasecmp(const unsigned char *str1, const unsigned char *str2,
                    size_t n)
{
  return strncasecmp((const char *)str1, (const char *)str2, n);
}

int ssh_usstrncasecmp(const unsigned char *str1, const char *str2,
                    size_t n)
{
  return strncasecmp((const char *)str1, str2, n);
}

unsigned char *ssh_ustrdup(const unsigned char *str)
{
  return (unsigned char *)ssh_strdup((const char *)str);
}

int ssh_uatoi(const unsigned char *str)
{
  return atoi((const char *) str);
}

long ssh_uatol(const unsigned char *str)
{
  return atol((const char *) str);
}

int ssh_ustrtol(const unsigned char *nptr, char **endptr, int base)
{
  return strtol((const char *) nptr, (char **) endptr, base);
}

int ssh_ustrtoul(const unsigned char *nptr, char **endptr, int base)
{
  return strtoul((const char *) nptr, (char **) endptr, base);
}

char *ssh_strcpy(char *dest, const char *src)
{
  return strcpy(dest, src);
}

char *ssh_strncpy(char *dest, const char *src, size_t n)
{
  return strncpy(dest, src, n);
}

#else /* !KERNEL && !_KERNEL */


char *ssh_strcpy(char *dest, const char *src)
{
  do
    {
      *dest = *src;
      ++dest;
    }
  while (*src++ != 0);

  return dest;
}


char *ssh_strncpy(char *dest, const char *src, size_t n)
{
  while (n > 0 && *src != 0)
    {
      *dest = *src;

      ++dest;
      ++src;
      --n;
    }

  while (n > 0)
    {
      *dest = 0;
      ++dest;
      --n;
    }

  return dest;
}

unsigned char *ssh_ustrncpy(unsigned char *str1,
                            const unsigned char *str2,
                            size_t len)
{
  return (unsigned char *)ssh_strncpy((char *)str1, (const char *)str2, len);
}

#endif /* KERNEL || _KERNEL */
