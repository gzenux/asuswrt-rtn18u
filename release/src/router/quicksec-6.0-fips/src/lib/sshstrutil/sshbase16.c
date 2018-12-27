/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encode to/from hexadecimal.
*/

#include "sshincludes.h"
#include "sshbase16.h"

/* My own hex table. */
static const unsigned char ssh_base16_table_dec[128] =
{
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const SshCharPtr ssh_base16_table_enc = "0123456789ABCDEF";

int ssh_is_base16(unsigned char byte)
{
  if (byte > 127)
    return 0;
  if (ssh_base16_table_dec[(unsigned int)byte] != 0xff)
    return 1;
  return 0;
}

unsigned char *ssh_base16_to_buf(const char *str,
                                 size_t *buf_len)
{
  unsigned char *buf;
  size_t len, skip, pos, i;

  /* Compute the length of the input string. */
  len = strlen(str);

  /* Check whether the length is odd. */
  if (len & 1)
    skip = 1;
  else
    skip = 0;

  /* Now deduce the length of the output and allocate it. */
  *buf_len = (len / 2) + skip;
  if ((buf = ssh_malloc(*buf_len)) == NULL)
    goto failed;

  /* Clean the first. */
  buf[0] = 0;

  for (i = 0, pos = 0; i < len; i++)
    {
      unsigned char byte;
      if (((unsigned char)str[i]) > 127)
        {
        failed:
          /* Unfortunately the string is not valid Hex string. */
          ssh_free(buf);
          *buf_len = 0;
          return NULL;
        }
      byte = ssh_base16_table_dec[(unsigned int)str[i]];
      if (byte == 0xff)
        goto failed;
      if (skip)
        {
          buf[pos] |= byte;
          pos++;
        }
      else
        {
          buf[pos] = (byte << 4);
        }
      skip = 1 - skip;
    }

  return buf;
}

char *ssh_buf_to_base16(const unsigned char *buf, size_t buf_len)
{
  char *str;
  size_t i;

  if ((str = ssh_malloc(buf_len*2 + 1)) == NULL)
    return NULL;

  for (i = 0; i < buf_len; i++)
    {
      unsigned char byte;
      byte = buf[i];
      str[i*2+0] = ssh_base16_table_enc[(unsigned int)(byte & 0xf0)>>4];
      str[i*2+1] = ssh_base16_table_enc[(unsigned int)(byte & 0x0f)>>0];
    }
  str[i*2] = '\0';
  return str;
}

/* End. */
