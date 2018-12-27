/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple Namelist. Compute the section between two name lists, SSHv2
   style.

   Inspired by namelist in sshcrypto.
*/

#include "sshincludes.h"
#include "sshsnlist.h"
#include "sshdsprintf.h"

#define SSH_DEBUG_MODULE "SshSNList"

/* Simple ways of travelling the namelist. */
static int ssh_snlist_name_len(const char *namelist)
{
  int i;
  if (namelist == NULL)
    return 0;

  for (i = 0; namelist[i] != ',' && namelist[i] != '\0'; i++)
    ;

  return i;
}

char *ssh_snlist_get_name(const char *namelist)
{
  int len = ssh_snlist_name_len(namelist);
  char *name = NULL;

  if (len > 0)
    name = ssh_xmemdup(namelist, len);

  return name;
}

const char *ssh_snlist_step_forward(const char *namelist)
{
  int len = ssh_snlist_name_len(namelist);

  if (len > 0)
    {
      if (namelist[len] != '\0')
        return namelist + len + 1;
    }

  return NULL;
}

char *ssh_snlist_intersection(const char *src1,
                              const char *src2)
{
  int total_len1, total_len2, name_len1, name_len2, max_len1, max_len2;
  Boolean prev;
  const char *tmp;
  char *dest, *dest_start;

  SSH_PRECOND(src1 != NULL);
  SSH_PRECOND(src2 != NULL);

  /* Set up the destination buffer. */

  prev = FALSE;

  dest = ssh_malloc(strlen(src1) + 1);
  if (dest == NULL)
    return NULL;

  dest_start = dest;

  /* Start looping the two namelists. And seek for names of same
     length and only then compare. */

  max_len1 = strlen(src1);
  max_len2 = strlen(src2);
  for (total_len1 = 0; total_len1 < max_len1; )
    {
      /* Get name lenght */
      name_len1 = ssh_snlist_name_len(src1);

      /* Start inner loop */
      for (tmp = src2, total_len2 = 0; total_len2 < max_len2; )
        {
          name_len2 = ssh_snlist_name_len(tmp);

          if (name_len2 == name_len1)
            {
              if (memcmp(src1, tmp, name_len1) == 0)
                {
                  if (prev)
                    *dest++ = ',';
                  prev = TRUE;
                  memcpy(dest, src1, name_len1);
                  dest += name_len1;
                  break;
                }
            }
          total_len2 += name_len2;

          /* Tricky part is to notice that we need to check for terminating
             zero, and quit if found. */
          tmp += name_len2;
          if (*tmp == '\0')
            break;
          /* Not zero so get past that comma. */
          tmp++;
        }

      total_len1 += name_len1;

      src1 += name_len1;
      if (*src1 == '\0')
        break;
      src1++;
    }
  /* In any case place zero terminator to the namelist. */
  *dest = '\0';
  return dest_start;
}

Boolean ssh_snlist_contains(const char *namelist,
                            const char *item)
{
  char *current;
  const char *ptr;

  for (ptr = namelist; ptr != NULL; ptr = ssh_snlist_step_forward(ptr))
    {
      current = ssh_snlist_get_name(ptr);
      if (!strcmp(item, current))
        {
          ssh_xfree(current);
          return TRUE;
        }
      ssh_xfree(current);
    }

  return FALSE;
}

void ssh_snlist_append(char **list, const char *item)
{
  char *to_be_deleted;

  if (*list == NULL)
    {
      *list = ssh_xstrdup(item);
      return;
    }
  if (strlen(*list) == 0)
    {
      ssh_xfree(*list);
      *list = ssh_xstrdup(item);
      return;
    }

  to_be_deleted = *list;
  ssh_xdsprintf((unsigned char **)list, "%s,%s", *list, item);
  ssh_xfree(to_be_deleted);
}

char *ssh_snlist_exclude(const char *original,
                         const char *excluded)
{
  const char *ptr;
  char *current;
  char *new_list;

  new_list = ssh_xstrdup("");

  for (ptr = original; ptr != NULL; ptr = ssh_snlist_step_forward(ptr))
    {
      current = ssh_snlist_get_name(ptr);
      if (!ssh_snlist_contains(excluded, current))
        {
          ssh_snlist_append(&new_list, current);
        }
      ssh_xfree(current);
    }
  return new_list;
}
