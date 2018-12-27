/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "pkcs1_pad.h"

#define SSH_DEBUG_MODULE "Pkcs1"


/* Fails if output_buffer is of insufficient length. */
static Boolean ssh_pkcs1_pad_prepare(size_t input_buffer_len,
                                     unsigned int tag_number,
                                     unsigned char *output_buffer,
                                     size_t output_buffer_len)
{
  unsigned int padding_length, i;

  padding_length = output_buffer_len - input_buffer_len;

  if (output_buffer_len < input_buffer_len || padding_length < 11)
    {
      SSH_DEBUG(SSH_D_FAIL, ("input len is too long: input_len = %u, "
                             "output_len = %u",
                             input_buffer_len, output_buffer_len));
      return FALSE;
    }

  output_buffer[0] = 0x0;
  output_buffer[1] = tag_number;

  /* Check the block type. */
  switch (tag_number)
    {
      /* Block type 0. Unused. */
    case 0x0:
      memset(output_buffer + 2, 0x0, padding_length - 3);
      break;
      /* Block type 1 (used with signatures). */
    case 0x1:
      memset(output_buffer + 2, 0xff, padding_length - 3);
      break;
      /* Block type 2 (used with encryption). */
    case 0x2:
      for (i = 2; i < padding_length - 1; i++)
        {
          unsigned int byte;
          do
            byte = ssh_random_get_byte();
          while (byte == 0);
          output_buffer[i] = byte;
        }
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("block type unknown %d.", tag_number));
      return FALSE;
    }

  /* The final padding byte is always zero. */
  output_buffer[padding_length - 1] = 0x0;
  return TRUE;
}


/* Fails if output_buffer is of insufficient length. */
Boolean ssh_aux_pkcs1_pad(const unsigned char *input_buffer,
                          size_t input_buffer_len,
                          unsigned int tag_number,
                          unsigned char *output_buffer,
                          size_t output_buffer_len)
{
  unsigned int padding_length = output_buffer_len - input_buffer_len;

  if (!ssh_pkcs1_pad_prepare(input_buffer_len, tag_number,
                             output_buffer, output_buffer_len))
    return FALSE;

  SSH_ASSERT(padding_length > 0);
  memcpy(output_buffer + padding_length, input_buffer, input_buffer_len);
  return TRUE;
}

Boolean ssh_aux_pkcs1_wrap_and_pad(const unsigned char *encoded_oid,
                                   size_t encoded_oid_len,
                                   const unsigned char *digest,
                                   size_t digest_len,
                                   unsigned int tag_number,
                                   unsigned char *output_buffer,
                                   size_t output_buffer_len)

{
  unsigned int padding_length, input_buffer_len;

  input_buffer_len = encoded_oid_len + digest_len;
  padding_length = output_buffer_len - input_buffer_len;

  if (!ssh_pkcs1_pad_prepare(input_buffer_len, tag_number,
                             output_buffer, output_buffer_len))
    return FALSE;

  SSH_ASSERT(padding_length > 0);
  memcpy(output_buffer + padding_length, encoded_oid, encoded_oid_len);
  memcpy(output_buffer + padding_length + encoded_oid_len, digest,
         digest_len);
  return TRUE;
}



Boolean ssh_aux_pkcs1_unpad(const unsigned char *input_buffer,
                            size_t input_buffer_len,
                            unsigned int tag_number,
                            unsigned char *output_buffer,
                            size_t output_buffer_len,
                            size_t *return_len)
{
  unsigned int i;

  /* Check for valid block. */
  if (input_buffer[0] != 0 || input_buffer[1] != tag_number)
      return FALSE;

  /* Check the block type. */
  switch (tag_number)
    {
      /* Block type 0. */
    case 0x0:
      /* This block type needs further handling at later time... We just
         get it out as is. */
      memcpy(output_buffer, input_buffer + 2, output_buffer_len - 2);
      *return_len = output_buffer_len - 2;
      break;
      /* Block type 1 (used with signatures). */
    case 0x1:
      for (i = 2; i < input_buffer_len; i++)
        {
          if (input_buffer[i] != 0xff)
            break;
        }

      /* Check there is enough padding and the output buffer is big enough. */
      if (i < 10 || input_buffer[i] != 0x0 ||
          output_buffer_len < input_buffer_len - i - 1)
        return FALSE;

      /* Step over the final 0 padding byte. */
      i++;

      /* Copy. */
      memcpy(output_buffer, input_buffer + i,
             input_buffer_len - i);
      *return_len = input_buffer_len - i;
      break;
      /* Block type 2 (used with encryption). */
    case 0x2:
      for (i = 2; i < input_buffer_len; i++)
        {
          if (input_buffer[i] == 0x0)
            break;
        }

      /* Same as the tag_number = 1 case. */
      if (i < 10 || input_buffer[i] != 0x0 ||
          output_buffer_len < input_buffer_len - i - 1)
        return FALSE;

      /* Step over the final 0 padding byte. */
      i++;

      memcpy(output_buffer, input_buffer + i,
             input_buffer_len - i);
      *return_len = input_buffer_len - i;

      break;
    default:
      SSH_DEBUG(SSH_D_NETGARB, ("block type unknown %d.", tag_number));
      return FALSE;
    }

  return TRUE;
}

