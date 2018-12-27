/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for encoding/decoding binary data.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshencode.h"

#define SSH_DEBUG_MODULE "SshEncode"




































































































































































































































































































































































































































































































static size_t
encode_buffer_va_internal(SshBuffer buffer, va_list ap)
{
 SshEncodingFormat format;
  unsigned int intvalue;
  SshUInt64 u64;
  SshUInt32 u32;
  SshUInt16 u16;
  size_t i, orig_len, space;
  Boolean b;
  const unsigned char *p;
  SshEncodeDatum fn;
  void *datum;
  unsigned char *buf;





























  orig_len = ssh_buffer_len(buffer);
  for (;;)
    {
      format = va_arg(ap, SshEncodingFormat);
      SSH_DEBUG(SSH_D_LOWOK, ("Format = 0x%X", format));
      switch (format)
        {
        case SSH_FORMAT_UINT32_STR:
          p = va_arg(ap, unsigned char *);
          i = va_arg(ap, size_t);
          if (ssh_buffer_append_space(buffer, &buf, 4 + i) != SSH_BUFFER_OK)
            return 0;
          memcpy(buf + 4, p, i);










          SSH_PUT_32BIT(buf, i);

          break;

        case SSH_FORMAT_DATA:
          p = va_arg(ap, unsigned char *);
          i = va_arg(ap, size_t);
          if (ssh_buffer_append(buffer, p, i) != SSH_BUFFER_OK)
            return 0;
          break;

        case SSH_FORMAT_BOOLEAN:
          b = va_arg(ap, Boolean);
          if (ssh_buffer_append_space(buffer, &buf, 1) != SSH_BUFFER_OK)
            return 0;
          b = (b == 0 ? 0 : 1);










          *buf = (unsigned char) b;

          break;

        case SSH_FORMAT_CHAR:
          intvalue = va_arg(ap, unsigned int);
          if (ssh_buffer_append_space(buffer, &buf, 1) != SSH_BUFFER_OK)
            return 0;










          *buf = (unsigned char) intvalue;

          break;

        case SSH_FORMAT_UINT16:
          u16 = va_arg(ap, unsigned int);
          if (ssh_buffer_append_space(buffer, &buf, 2) != SSH_BUFFER_OK)
            return 0;








          SSH_PUT_16BIT(buf, u16);
          break;

        case SSH_FORMAT_UINT32:
          u32 = va_arg(ap, SshUInt32);
          if (ssh_buffer_append_space(buffer, &buf, 4) != SSH_BUFFER_OK)
            return 0;








          SSH_PUT_32BIT(buf, u32);
          break;

        case SSH_FORMAT_UINT64:
          u64 = va_arg(ap, SshUInt64);
          if (ssh_buffer_append_space(buffer, &buf, 8) != SSH_BUFFER_OK)
            return 0;






          SSH_PUT_64BIT(buf, u64);
          break;

        case SSH_FORMAT_SPECIAL:
          fn = va_arg(ap, SshEncodeDatum);
          datum = va_arg(ap, void *);

          /* See how much free room there is, then take it to use. */
          space = ssh_buffer_space(buffer);
        retry:
          buf = NULL;
          if (space > 0 &&
              ssh_buffer_append_space(buffer, &buf, space) != SSH_BUFFER_OK)
            {
              SSH_NOTREACHED;
              return 0;
            }
          SSH_DEBUG(SSH_D_MIDOK, ("Before renderer: b->end = %d, space = %d",
                                  buffer->end, space));
          i = (*fn)(buf, space, datum);
          SSH_DEBUG(SSH_D_MIDOK, ("After renderer: b->end = %d, i = %d",
                                  buffer->end, i));
          if (i > space)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Insufficient buffer space"));
              /* Force the buffer to grow by appending to i (> space)
                 bytes, see how much space there is in that case, then
                 immediately free those bytes and go to retry. */
              if (ssh_buffer_append_space(buffer, &buf, i - space)
                  != SSH_BUFFER_OK)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Unable to allocate more buffer space"));
                  return 0;
                }
              space = i + ssh_buffer_space(buffer);
              ssh_buffer_consume_end(buffer, i);
              goto retry;
            }
          /* Discard all unused bytes from the end. */
          ssh_buffer_consume_end(buffer, space - i);
          break;

        case SSH_FORMAT_END:
          /* Return the number of bytes added. */
          return ssh_buffer_len(buffer) - orig_len;

        default:
          SSH_NOTREACHED;
#if 0
          /* Which is better?  NOTREACHED or a possibly showing debug
             output? */
          SSH_DEBUG(SSH_D_ERROR, ("invalid format code %d", (int) format));
#endif
          return 0;
        }





    }
}

size_t ssh_encode_buffer_va(SshBuffer buffer, va_list ap)
{
  return encode_buffer_va_internal(buffer, ap);
}

size_t ssh_encode_buffer(SshBuffer buffer, ...)
{
  size_t bytes;
  va_list ap;

  va_start(ap, buffer);
  bytes = encode_buffer_va_internal(buffer, ap);
  va_end(ap);

  return bytes;
}

size_t ssh_encode_array_va(unsigned char *buf, size_t buflen, va_list ap)
{
  SshBufferStruct buffer = { 0 };

  if (buf == NULL)
    return 0;

  ssh_buffer_wrap(&buffer, buf, buflen);
  return encode_buffer_va_internal(&buffer, ap);
}

size_t ssh_encode_array(unsigned char *buf, size_t buflen, ...)
{
  va_list ap;
  size_t bytes;

  va_start(ap, buflen);
  bytes = ssh_encode_array_va(buf, buflen, ap);
  va_end(ap);

  return bytes;
}

size_t ssh_encode_array_alloc(unsigned char **buf_return, ...)
{
  size_t bytes;
  SshBufferStruct buffer;
  va_list ap;

  ssh_buffer_init(&buffer);

  va_start(ap, buf_return);
  bytes = encode_buffer_va_internal(&buffer, ap);
  va_end(ap);

  if (bytes == 0)
    {
      if (buf_return != NULL)
        *buf_return = NULL;

      ssh_buffer_uninit(&buffer);
      return 0;
    }

  if (buf_return != NULL)
    *buf_return = ssh_buffer_steal(&buffer, &bytes);
  else
    ssh_buffer_uninit(&buffer);
  return bytes;
}

size_t ssh_encode_array_alloc_va(unsigned char **buf_return, va_list ap)
{
  size_t bytes;
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);

  bytes = encode_buffer_va_internal(&buffer, ap);

  if (bytes == 0)
    {
      if (buf_return != NULL)
        *buf_return = NULL;

      ssh_buffer_uninit(&buffer);
      return 0;
    }

  if (buf_return != NULL)
    *buf_return = ssh_buffer_steal(&buffer, &bytes);
  else
    ssh_buffer_uninit(&buffer);
  return bytes;
}

/* Allocates a buffer of the given size with ssh_malloc and record it
   into allocsp[num_allocs_p], possibly expanding array allocsp to do
   this. Advance num_allocs_p.

   Return NULL in case of memory allocation failure. */

static unsigned char *
decode_alloc(unsigned int *num_allocs_p, unsigned char ***allocsp,
             size_t size)
{
  unsigned char *p, **tmpa;

  /* Check if we need to enlarge the pointer array.  We enlarge it in chunks
     of 16 pointers. */
  if (*num_allocs_p == 0)
    {
      if ((tmpa = ssh_malloc(16 * sizeof(unsigned char *))) == NULL)
        goto failure;
      else
        *allocsp = tmpa;
    }
  else
    {
      if (*num_allocs_p % 16 == 0)
        {
          if ((tmpa = ssh_realloc(*allocsp,
                                  *num_allocs_p,
                                  (*num_allocs_p + 16) *
                                  sizeof(unsigned char *)))
              == NULL)
            goto failure;
          else
            *allocsp = tmpa;
        }
    }

  if ((p = ssh_malloc(size)) == NULL)
    goto failure;

  /* Store it in the array. */
  (*allocsp)[*num_allocs_p] = p;
  (*num_allocs_p)++;
  return p;

 failure:
  return NULL;
}

size_t ssh_decode_array_va(const unsigned char *buf, size_t len, va_list ap)
{
  SshEncodingFormat format;
  unsigned long longvalue;
  SshUInt64 *u64p;
  SshUInt32 *u32p;
  SshUInt16 *u16p;
  Boolean *bp;
  size_t size, *sizep;
  unsigned int *uip;
  unsigned char *p, **pp;
  const unsigned char **cpp;
  size_t offset;
  unsigned int i, num_allocs;
  unsigned char **allocs = NULL;
  SshDecodeDatum fn;
  void **datump;

  offset = 0;
  num_allocs = 0;

  for (;;)
    {
      /* Get the next format code. */
      format = va_arg(ap, SshEncodingFormat);
      SSH_DEBUG(SSH_D_LOWOK, ("Format = 0x%X", format));
      switch (format)
        {
        case SSH_FORMAT_UINT32_STR:
          pp = va_arg(ap, unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Check if the buffer can fit the 32 bit string length,
             and grab it.*/
          if (len - offset < 4)
            goto fail;
          longvalue = SSH_GET_32BIT(buf + offset);
          offset += 4;

          /* Check if the buffer can fit the string data and get it. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length if requested. */
          if (sizep != NULL)
            *sizep = longvalue;

          /* Retrieve the data if requested. */
          if (pp != NULL)
            {
              *pp = decode_alloc(&num_allocs, &allocs, (size_t)longvalue + 1);
              if (!*pp)
                  goto fail;
              memcpy(*pp, buf + offset, (size_t)longvalue);
              (*pp)[longvalue] = '\0';
            }

          /* Consume the data. */
          offset += longvalue;
          break;

        case SSH_FORMAT_UINT32_STR_NOCOPY:
          /* Get length and data pointers. */
          cpp = va_arg(ap, const unsigned char **);
          sizep = va_arg(ap, size_t *);

          /* Decode string length and skip the length. */
          if (len - offset < 4)
            goto fail;
          longvalue = SSH_GET_32BIT(buf + offset);
          offset += 4;

          /* Check that the string is all in the buffer. */
          if (longvalue > len - offset)
            goto fail;

          /* Store length and data if requested. */
          if (sizep != NULL)
            *sizep = longvalue;
          if (cpp != NULL)
            *cpp = buf + offset;

          /* Consume the data. */
          offset += longvalue;
          break;

        case SSH_FORMAT_DATA:
          p = va_arg(ap, unsigned char *);
          size = va_arg(ap, size_t);
          if (len - offset < size)
            goto fail;
          if (p)
            memcpy(p, buf + offset, size);
          offset += size;
          break;

        case SSH_FORMAT_BOOLEAN:
          bp = va_arg(ap, Boolean *);
          if (len - offset < 1)
            goto fail;
          if (bp != NULL)
            *bp = buf[offset] != 0;
          offset++;
          break;

        case SSH_FORMAT_CHAR:
          uip = va_arg(ap, unsigned int *);
          if (len - offset < 1)
            goto fail;
          if (uip)
            *uip = buf[offset];
          offset++;
          break;

        case SSH_FORMAT_UINT16:
          u16p = va_arg(ap, SshUInt16 *);
          if (len - offset < 2)
            goto fail;
          if (u16p)
            *u16p = SSH_GET_16BIT(buf + offset);
          offset += 2;
          break;

        case SSH_FORMAT_UINT32:
          u32p = va_arg(ap, SshUInt32 *);
          if (len - offset < 4)
            goto fail;
          if (u32p)
            *u32p = SSH_GET_32BIT(buf + offset);
          offset += 4;
          break;

        case SSH_FORMAT_UINT64:
          u64p = va_arg(ap, SshUInt64 *);
          if (len - offset < 8)
            goto fail;
          if (u64p)
            *u64p = SSH_GET_64BIT(buf + offset);
          offset += 8;
          break;

        case SSH_FORMAT_SPECIAL:
          fn = va_arg(ap, SshDecodeDatum);
          datump = va_arg(ap, void **);

          size = (*fn)(buf + offset, len - offset, datump);
          if (size > len - offset)
            goto fail;
          /* Nasty feature here. Actually encoding may fail after this
             tag has been processed, and now it is up the caller to
             free datump allocated by the decoder (as we do not know
             its structure. (as you see, strings allocated here are
             freed at failure handler but datums are not). */
          offset += size;
          break;

        case SSH_FORMAT_END:
          /* Free the allocs array. */
          if (num_allocs > 0)
            ssh_free(allocs);
          /* Return the number of bytes consumed. */
          SSH_DEBUG(SSH_D_LOWOK, ("offset = %d", offset));
          return offset;

        default:
          SSH_DEBUG(SSH_D_ERROR, ("invalid format code %d", (int) format));
          return 0;
        }
    }
  /*NOTREACHED*/

 fail:
  /* An error was encountered.  Free all allocated memory and return zero. */
  for (i = 0; i < num_allocs; i++)
    ssh_free(allocs[i]);
  if (allocs)
    ssh_free(allocs);
  return 0;
}

size_t ssh_decode_array(const unsigned char *buf, size_t len, ...)
{
  va_list ap;
  size_t bytes;

  va_start(ap, len);
  bytes = ssh_decode_array_va(buf, len, ap);
  va_end(ap);

  return bytes;
}

size_t ssh_decode_buffer_va(SshBuffer buffer, va_list ap)
{
  size_t bytes;

  bytes = ssh_decode_array_va(ssh_buffer_ptr(buffer),
                              ssh_buffer_len(buffer),
                              ap);

  ssh_buffer_consume(buffer, bytes);
  return bytes;
}

size_t ssh_decode_buffer(SshBuffer buffer, ...)
{
  va_list ap;
  size_t bytes;

  va_start(ap, buffer);
  bytes = ssh_decode_array_va(ssh_buffer_ptr(buffer),
                              ssh_buffer_len(buffer),
                              ap);
  va_end(ap);

  ssh_buffer_consume(buffer, bytes);
  return bytes;
}
