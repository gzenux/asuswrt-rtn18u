/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Render names in DNS format to dotted format.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshfsm.h"
#include "sshinet.h"
#include "sshdns.h"

#define SSH_DEBUG_MODULE "SshDnsRender"

/* Render function to render names in dns format for %@ format string for
   ssh_e*printf */
int ssh_dns_name_render(unsigned char *buf, int buf_size, int precision,
                        void *datum)
{
  const unsigned char *name = datum;
  int label_len, len;
  int i;

  if (name == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  if (*name >= 'a' && *name <= 'z' && name[1] == '\0')
    {
      len = ssh_snprintf(buf, buf_size + 1, "<safety belt %c>", *name);
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

  len = 0;
  if (*name == 0)
    {
      if (buf_size > 0)
        {
          buf[0] = '.';
        }
      return 1;
    }
  while ((label_len = *name) != 0 && len < buf_size)
    {
      if (label_len > 63)
        {
          len += ssh_snprintf(buf + len, buf_size - len + 1, "<error %.4s>",
                              name);
          if (len >= buf_size)
            return buf_size + 1;
          return len;
        }
      else
        name++;
      if (precision > 0 && name - (unsigned char *) datum > precision)
        {
          len += ssh_snprintf(buf + len, buf_size - len + 1, "<overflow>");
          if (len >= buf_size)
            return buf_size + 1;
          return len;
        }
      for(i = 1; i <= label_len && len < buf_size; i++)
        {
          if (isprint(*name))
            {
              buf[len++] = *name++;
            }
          else
            {
              buf[len++] = '\\';
              if (len >= buf_size)
                break;
              buf[len++] = 'x';
              if (len >= buf_size)
                break;
              buf[len++] = "0123456789abcdef"[*name >> 4];
              if (len >= buf_size)
                break;
              buf[len++] = "0123456789abcdef"[*name & 0xf];
              if (len >= buf_size)
                break;
              name++;
            }
        }
      if (i > label_len && len < buf_size)
        buf[len++] = '.';
    }
  if (len >= buf_size)
    return buf_size + 1;
  return len;
}

