/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Converting buffers to and from base64.
*/

#include "sshincludes.h"
#include "sshbase64.h"

/* Convert from buffer of base 256 to base 64. */

const unsigned char ssh_base64[64] =
{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

const unsigned char ssh_inv_base64[128] =
{
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255,  62, 255, 255, 255,  63,
   52,  53,  54,  55,  56,  57,  58,  59,
   60,  61, 255, 255, 255, 255, 255, 255,
  255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,
   15,  16,  17,  18,  19,  20,  21,  22,
   23,  24,  25, 255, 255, 255, 255, 255,
  255,  26,  27,  28,  29,  30,  31,  32,
   33,  34,  35,  36,  37,  38,  39,  40,
   41,  42,  43,  44,  45,  46,  47,  48,
   49,  50,  51, 255, 255, 255, 255, 255,
};

size_t ssh_is_base64_buf(const unsigned char *buf, size_t buf_len)
{
  size_t i;

  for (i = 0; i < buf_len; i++)
    {
      /* Accept equal sign. */
      if (buf[i] == '=')
        continue;
      /* Don't accept anything else which isn't in base64. */
      if (buf[i] > 127)
        break;
      if (ssh_inv_base64[buf[i]] == 255)
        break;
    }
  return i;
}

unsigned char *ssh_buf_to_base64(const unsigned char *buf, size_t buf_len)
{
  unsigned char *out;
  size_t i, j;
  SshUInt32 limb;

  if ((out = ssh_malloc(((buf_len * 8 + 5) / 6) + 5)) == NULL)
    return NULL;

  for (i = 0, j = 0, limb = 0; i + 2 < buf_len; i += 3, j += 4)
    {
      limb =
        ((SshUInt32)buf[i] << 16) |
        ((SshUInt32)buf[i + 1] << 8) |
        ((SshUInt32)buf[i + 2]);

      out[j] = ssh_base64[(limb >> 18) & 63];
      out[j + 1] = ssh_base64[(limb >> 12) & 63];
      out[j + 2] = ssh_base64[(limb >> 6) & 63];
      out[j + 3] = ssh_base64[(limb) & 63];
    }

  switch (buf_len - i)
    {
    case 0:
      break;
    case 1:
      limb = ((SshUInt32)buf[i]);
      out[j++] = ssh_base64[(limb >> 2) & 63];
      out[j++] = ssh_base64[(limb << 4) & 63];
      out[j++] = '=';
      out[j++] = '=';
      break;
    case 2:
      limb = ((SshUInt32)buf[i] << 8) | ((SshUInt32)buf[i + 1]);
      out[j++] = ssh_base64[(limb >> 10) & 63];
      out[j++] = ssh_base64[(limb >> 4) & 63];
      out[j++] = ssh_base64[(limb << 2) & 63];
      out[j++] = '=';
      break;
    default:
      ssh_fatal("ssh_buf_to_base64: internal error.");
      break;
    }
  out[j] = '\0';

  return out;
}

unsigned char *ssh_base64_to_buf(const unsigned char *str, size_t *buf_len)
{
  unsigned char *buf;
  int i, j, len;
  SshUInt32 limb;

  len = strlen((char *) str);
  *buf_len = (len * 6 + 7) / 8;

  if ((buf = ssh_malloc(*buf_len)) == NULL)
    return NULL;

  for (i = 0, j = 0, limb = 0; i + 3 < len; i += 4)
    {
      if (str[i] == '=' || str[i + 1] == '=' ||
          str[i + 2] == '=' || str[i + 3] == '=')
        {
          if (str[i] == '=' || str[i + 1] == '=')
            break;

          if (str[i + 2] == '=')
            {
              limb =
                ((SshUInt32)ssh_inv_base64[str[i]] << 6) |
                ((SshUInt32)ssh_inv_base64[str[i + 1]]);
              buf[j] =(unsigned char)(limb >> 4) & 0xff;
              j++;
            }
          else
            {
              limb =
                ((SshUInt32)ssh_inv_base64[str[i]] << 12) |
                ((SshUInt32)ssh_inv_base64[str[i + 1]] << 6) |
                ((SshUInt32)ssh_inv_base64[str[i + 2]]);
              buf[j] = (unsigned char)(limb >> 10) & 0xff;
              buf[j + 1] = (unsigned char)(limb >> 2) & 0xff;
              j += 2;
            }
        }
      else
        {
          limb =
            ((SshUInt32)ssh_inv_base64[str[i]] << 18) |
            ((SshUInt32)ssh_inv_base64[str[i + 1]] << 12) |
            ((SshUInt32)ssh_inv_base64[str[i + 2]] << 6) |
            ((SshUInt32)ssh_inv_base64[str[i + 3]]);

          buf[j] = (unsigned char)(limb >> 16) & 0xff;
          buf[j + 1] = (unsigned char)(limb >> 8) & 0xff;
          buf[j + 2] = (unsigned char)(limb) & 0xff;
          j += 3;
        }
    }

  *buf_len = j;

  return buf;
}

/* Remove unneeded whitespace (everything that is not in base64!).
 * Returns new xmallocated string containing the string. If len is 0
 * use strlen(str) to get length of data. */

unsigned char *ssh_base64_remove_whitespace(const unsigned char *str,
                                            size_t len)
{
  unsigned char *cp;
  size_t i, j;

  if (len == 0)
    len = strlen((char *) str);

  if ((cp = ssh_malloc(len + 1)) == NULL)
    return NULL;

  for (i = 0, j = 0; i < len; i++)
    {
      unsigned char c = str[i];

      if (c < 128)
        {
          if (ssh_inv_base64[c] != 255 || c == '=')
            cp[j++] = c;
        }
    }

  cp[j] = '\0';

  return cp;
}

/* Remove headers/footers (and other crud) before and after the
 * base64-encoded data.  Pointer to the string is supplied in str and
 * length in len. Stores the starting and ending indexes of the
 * base64-data to start_ret and end_ret and returns TRUE if
 * successful. In case of an error, returns FALSE.  */

Boolean
ssh_base64_remove_headers(const unsigned char *str,
                          size_t len,
                          size_t *start_ret,
                          size_t *end_ret)
{
  size_t i, end, start, header, inside, skip, bol;

  /* Remove all before and after headers. */
  for (i = 0, skip = 0, end = 0, start = 0, header = 0, inside = 0, bol = 1;
       i < len;
       i++)
    {
      switch (str[i])
        {
        case '-':
          if (skip)
            break;

          if (bol)
            {
              if (inside)
                end = i;
              header = 1;
              inside ^= 1;
              skip = 1;
              bol = 0;
            }
          break;
        case '\n':
        case '\r':
          bol = 1;
          if (header)
            {
              header = 0;
              if (inside)
                start = i + 1;
            }
          skip = 0;
          break;
        case ' ':
        case '\t':
          break;

        default:
          bol = 0;
          break;
        }
    }

  if (end == 0 && start == 0)
    {
      start = 0;
      end = len;
    }

  if (end == start)
    return FALSE;

  if (end <= start)
    return FALSE;

  *start_ret = start;
  *end_ret = end;

  return TRUE;
}
