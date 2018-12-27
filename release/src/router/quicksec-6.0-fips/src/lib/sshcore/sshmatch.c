/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple pattern matching, with '*' and '?' as wildcards.
*/

#include "sshincludes.h"
#include "sshmatch.h"

/* Define as macros, because ctype.h is not available in the kernel. */
#undef isdigit
#define isdigit(ch) ((ch) >= '0' && (ch) <= '9')

/* Returns true if the given string matches the pattern (which may contain
   ? and * as wildcards), and zero if it does not match. */

Boolean ssh_match_pattern(const char *s, const char *pattern)
{
  Boolean escaped = FALSE;

  for (;;)
    {
      escaped = FALSE;

      /* If at end of pattern, accept if also at end of string. */
      if (*pattern == '\0')
        return (*s == '\0');

      /* Process '*'. */

      if (*pattern == '\\')
        {
          escaped = TRUE;
          pattern++;
        }

      if (*pattern == '*' && !escaped)
        {
          /* Skip the asterisk. */
          pattern++;

          /* If at end of pattern, accept immediately. */
          if (*pattern == '\0')
            return TRUE;

          /* If next character in pattern is known, optimize. */
          if (*pattern != '?' && *pattern != '*')
            {
              /* Look instances of the next character in pattern, and try
                 to match starting from those. */
              for (; *s != '\0'; s++)
                if (*s == *pattern &&
                    ssh_match_pattern(s + 1, pattern + 1))
                  return TRUE;
              /* Failed. */
              return FALSE;
            }

          /* Move ahead one character at a time and try to match at each
             position. */
          for (; *s != '\0'; s++)
            if (ssh_match_pattern(s, pattern))
              return TRUE;
          /* Failed. */
          return FALSE;
        }

      /* There must be at least one more character in the string.  If we are
         at the end, fail. */
      if (*s == '\0')
        return FALSE;

      /* Check if the next character of the string is acceptable. */
      if ((*pattern != '?' || (*pattern == '?' && escaped)) && *pattern != *s)
        return FALSE;

      /* Move to the next character, both in string and in pattern. */
      s++;
      pattern++;
    }
  /*NOTREACHED*/
}

/* Returns true if given port matches the port number pattern
   (which may contain '*' as wildcard for all ports, or <xxx, >xxx or
   xxx..yyy formats to specify less than, greater than or port range),
   and zero if it does not match. */

Boolean ssh_match_port(SshUInt32 port, const char *pattern)
{
  SshUInt32 lower_port, upper_port;

  /* Check for '*' wildcard */
  if (strcmp(pattern, "*") == 0)
    return 1;

  lower_port = 0;
  upper_port = 65535;

  if (*pattern == '<')
    {
      pattern++;
      upper_port = atoi(pattern);
      if (upper_port == 0)
        goto invalid_number;
      upper_port--;             /* Make range inclusive */
      for (; *pattern && isdigit(*pattern); pattern++)
        ;
    }
  else if (*pattern == '>')
    {
      pattern++;
      lower_port = atoi(pattern);
      if (lower_port == 0)
        goto invalid_number;
      lower_port++;             /* Make range inclusive */
      for (; *pattern && isdigit(*pattern); pattern++)
        ;
    }
  else
    {
      lower_port = atoi(pattern);
      if (lower_port == 0)
        goto invalid_number;
      for (; *pattern && isdigit(*pattern); pattern++)
        ;
      if (*pattern == '.' && *(pattern + 1) == '.')
        {
          pattern += 2;
          upper_port = atoi(pattern);
          if (upper_port == 0)
            goto invalid_number;
          for (; *pattern && isdigit(*pattern); pattern++)
            ;
        }
      else
        {
          upper_port = lower_port;
        }
    }
  if (*pattern)
    {
      ssh_warning("Junk after port pattern: %.20s", pattern);
      return FALSE;
    }

  if ((SshUInt32)lower_port <= (SshUInt32)port &&
      (SshUInt32)port <= (SshUInt32)upper_port)
    return TRUE;

  return FALSE;

invalid_number:
  ssh_warning("Invalid number in port pattern: %.20s", pattern);
  return FALSE;
}
