/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for mapping keywords to numbers and vice versa. This uses case
   insensetive comparison, and the strcasecmp might use toupper/tolower, which
   might not work in the kernel.
*/

#include "sshincludes.h"
#include "sshenum.h"

/* Finds the number corresponding to the given keyword.  Returns the number,
   or -1 if there is no matching keyword.  The comparison is
   incase-sensitive. */

long ssh_find_keyword_number_case_insensitive(const SshKeywordStruct *keywords,
                                              const char *name)
{
  int i;

  for (i = 0; keywords[i].name; i++)
    if (strcasecmp(keywords[i].name, name) == 0)
      return keywords[i].code;
  return -1;
}

/* Finds the longist prefix from keyword table. Returns the assisiated number,
   or -1 if there is no matching keyword. The comparison is incase-sensitive.
   The `endp' pointer is modifier to points to the end of found keyword if
   it is not NULL. */
long ssh_find_partial_keyword_number_case_insensitive(const
                                                      SshKeywordStruct *
                                                      keywords,
                                                      const char *name,
                                                      const char **endp)
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
      if (strncasecmp(keywords[i].name, name, len) == 0)
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
