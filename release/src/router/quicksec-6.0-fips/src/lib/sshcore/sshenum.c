/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for mapping keywords to numbers and vice versa. This uses case
   sensetive comparison. Note that the strcasecmp might use toupper/tolower,
   which  might not work in the kernel, and this file MUST be kernel
   compatible, so it cannot use them. The case insensetive functions are
   moved to the sshenumcase.c.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshenum.h"

#define SSH_DEBUG_MODULE "SshEnum"

/* Finds the name of a keyword corresponding to the numeric value.
   Returns a pointer to a constant name string, or NULL if there is no
   keyword matching the numeric value. */

const char *ssh_find_keyword_name(const SshKeywordStruct *keywords, long code)
{
  int i;

  for (i = 0; keywords[i].name; i++)
    if (keywords[i].code == code)
      return keywords[i].name;
  return NULL;
}

/* Finds the number corresponding to the given keyword.  Returns the number,
   or -1 if there is no matching keyword.  The comparison is case-sensitive. */

long ssh_find_keyword_number(const SshKeywordStruct *keywords,
                             const char *name)
{
  int i;

  SSH_ASSERT(name != NULL);

  for (i = 0; keywords[i].name; i++)
    if (strcmp(keywords[i].name, name) == 0)
      return keywords[i].code;
  return -1;
}

/* Finds the longist prefix from keyword table. Returns the assisiated number,
   or -1 if there is no matching keyword. The comparison is case-sensitive.
   The `endp' pointer is modifier to points to the end of found keyword if
   it is not NULL. */
long ssh_find_partial_keyword_number(const SshKeywordStruct * keywords,
                                     const char *name, const char **endp)
{
  int i, len, max_len;
  long ret;

  if (endp)
    *endp = name;
  max_len = 0;
  ret = -1;
  for (i = 0; keywords[i].name; i++)
    {
      len = strlen(keywords[i].name);
      if (strncmp(keywords[i].name, name, len) == 0)
        {
          if (len > max_len)
            {
              max_len = len;
              if (endp)
                *endp = name + max_len;
              ret = keywords[i].code;
            }
        }
    }
  return ret;
}

