/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Character set conversion routines. Complies with draft-yergeay-utf8-01.txt,
   (which will obsolete RFC 2044, the current UTF-8 spec).
*/

#include "sshincludes.h"
#include "sshutf8.h"

#define SSH_DEBUG_MODULE "SshUtf8"

/* the standard data types for native representations of 16- and 32-bit
   unicode data */

#ifndef SSH_CHARSET_NATIVE_UNICODE16
#define SSH_CHARSET_NATIVE_UNICODE16 unsigned short int
#endif /* SSH_CHARSET_NATIVE_UNICODE16 */

#ifndef SSH_CHARSET_NATIVE_UNICODE32
#define SSH_CHARSET_NATIVE_UNICODE32 unsigned int
#endif /* SSH_CHARSET_NATIVE_UNICODE32 */

/* An unknown character */
#define SSH_CHARACTER_UNKNOWN 0xffffffff

struct SshChrConvRec
{
  SshCharsetEncoding input_encoding;
  SshCharsetEncoding output_encoding;
  SshChUCS4 partial[8];
  int resume_pt;
  size_t partial_size;
  unsigned char *input_buf;
  size_t input_pos;
  size_t input_len;
  unsigned char *output_buf;
  size_t output_max;
  size_t output_pos;
  Boolean resuming;
  Boolean output_not_full;
};

/* Initialize a context for charset conversion
   (this way the conversion can be done in parts).
   Returns NULL on failure. */

SshChrConv ssh_charset_init(SshCharsetEncoding input_encoding,
                            SshCharsetEncoding output_encoding)
{
  SshChrConv ctx;

  if (input_encoding < SSH_CHARSET_FIRST ||
      input_encoding > SSH_CHARSET_LAST)
    return NULL;
  if (output_encoding < SSH_CHARSET_FIRST ||
      output_encoding > SSH_CHARSET_LAST)
    return NULL;

  if ((ctx = ssh_calloc(1, sizeof(struct SshChrConvRec))) != NULL)
    {
      ctx->input_encoding = input_encoding;
      ctx->output_encoding = output_encoding;
      ctx->partial_size = 0;
      ctx->resume_pt = 0;
      ctx->input_buf = NULL;
      ctx->input_pos = 0;
      ctx->input_len = 0;
      ctx->output_buf = NULL;
      ctx->output_max = 0;
      ctx->output_pos = 0;
      ctx->resuming = FALSE;
      ctx->output_not_full = FALSE;
    }
  return ctx;
}


/* Free the charset conversion context */

void ssh_charset_free(SshChrConv ctx)
{
  if (ctx != NULL)
    ssh_free(ctx);
}

/* Get a byte with buffering. Return TRUE, when the input buffer is empty. */

Boolean ssh_charset_get_byte(SshChrConv ctx, SshChUCS4 *bp)
{
  SshChUCS4 ch;

  /* see if we're resuming.. */

  if (ctx->resuming)
    {
      if (ctx->resume_pt < ctx->partial_size)
        {
          *bp = (SshChUCS4) ctx->partial[ctx->resume_pt++];
          return FALSE;
        }
      else
        {
          ctx->resuming = FALSE;
          ctx->resume_pt = 0;
        }
    }

  /* not resuming; check if our input buffer is empty.. */

  if (ctx->input_pos >= ctx->input_len)
    return TRUE;

  /* ok, read a byte and increase the resume buffer */

  ch = ((SshChUCS4) (ctx->input_buf)[ctx->input_pos++]) & 0xff;
  if (ctx->partial_size >= 8)
    {
#if 0
      /* we can not call fatal here */
      ssh_fatal("ssh_charset_get_byte: partial buffer overfull.");
#endif
      /* mark the buffer as "read" */
      ctx->input_pos = ctx->input_len;

    }

  SSH_ASSERT(ctx->partial_size <
             (sizeof(ctx->partial) / sizeof(ctx->partial[0])));

  ctx->partial[ctx->partial_size++] = ch;

  *bp = ch;
  return FALSE;
}

/* try to resume from the point after the last flush */

void ssh_charset_resume(SshChrConv ctx)
{
  if (ctx->partial_size > 0)
    {
      ctx->resuming = TRUE;
      ctx->resume_pt = 0;
    }
}

/* flush the partial buffer */

void ssh_charset_flush(SshChrConv ctx)
{
  ctx->partial_size = 0;
}

/* put out a byte. return TRUE if this can not be performed. */

Boolean ssh_charset_put_byte(SshChrConv ctx, SshChUCS4 b)
{
  b &= 0xff;
  if (!(ctx->output_not_full))
    return TRUE;
  (ctx->output_buf)[ctx->output_pos++] = (unsigned char) b;
  ctx->output_not_full = ctx->output_pos < ctx->output_max;
  return FALSE;
}

/* Convert max. input_len bytes starting from input_buf. The output is
   written to output_buf which is an array capable of holding output_max
   bytes. The actual number of bytes written is returned.

   This function can not fail. */

size_t ssh_charset_convert(SshChrConv ctx,
                           void *input_buf, size_t input_len,
                           void *output_buf, size_t output_max)
{
  int i, utf8size;
  SshChUCS4 ch = 0, t;

  /* used for native representation conversions. */

  union {
    SSH_CHARSET_NATIVE_UNICODE16 x;
    unsigned char y[sizeof(SSH_CHARSET_NATIVE_UNICODE16)];
  } union_u16;

  union {
    SSH_CHARSET_NATIVE_UNICODE32 x;
    unsigned char y[sizeof(SSH_CHARSET_NATIVE_UNICODE32)];
  } union_u32;

  /* set the new buffer to the context */

  ctx->input_buf = input_buf;
  ctx->input_pos = 0;
  ctx->input_len = input_len;
  ssh_charset_resume(ctx);
  ctx->output_buf = output_buf;
  ctx->output_pos = 0;
  ctx->output_max = output_max;
  ctx->output_not_full = output_max > 0;

  /* ok, now loop over the entire data */

  while (ctx->output_not_full)
    {

      /* read a character into ch */

      switch(ctx->input_encoding)
        {

          /* no conversion for these */

        case SSH_CHARSET_USASCII:
        case SSH_CHARSET_ISO_LATIN_1:
          if (ssh_charset_get_byte(ctx, &ch))
            goto done;
          break;

          /* utf-8 conversion */

        case SSH_CHARSET_UTF8:

          if (ssh_charset_get_byte(ctx, &ch))
            goto done;
          if (ch < 0x80)
            break;

          /* ok, not a single character, try to determine size */

          t = ch;
          for (utf8size = 0;
               utf8size < 8 && ((t << utf8size) & 0x80) != 0;
               utf8size++);

          if (utf8size < 2 || utf8size > 6)
            {
              ch = SSH_CHARACTER_UNKNOWN;
              break;
            }

          /* mask out extra bits and roll the first byte to the correct
             position */

          ch = (ch & (0x7f >> utf8size)) << (6 * (utf8size-1));

          /* ok, now read consecutive bytes that make up the UCS4 character */

          for (i = utf8size-2; i >= 0; i--)
            {
              if (ssh_charset_get_byte(ctx, &t))
                goto done;
              if ((t & 0xc0) != 0x80)
                {
                  ch = SSH_CHARACTER_UNKNOWN;
                  break;
                }
              ch |= (t & 0x3f) << (6 * i);
            }


          /* check that the character is in appropriate range. */

          if (ch != SSH_CHARACTER_UNKNOWN)
            {
              switch (utf8size)
                {
                case 2:
                  if (ch < 0x80 || ch > 0x7ff)
                    ch = SSH_CHARACTER_UNKNOWN;
                  break;

                case 3:
                  if (ch < 0x800 || ch > 0xffff)
                    ch = SSH_CHARACTER_UNKNOWN;
                  break;

                case 4:
                  if (ch < 0x10000 || ch > 0x1fffff)
                    ch = SSH_CHARACTER_UNKNOWN;
                  break;

                case 5:
                  if (ch < 0x200000 || ch > 0x3ffffff)
                    ch = SSH_CHARACTER_UNKNOWN;
                  break;

                case 6:
                  if (ch < 0x4000000)
                    ch = SSH_CHARACTER_UNKNOWN;
                  break;
                }
            }
          break;  /* utf-8 done */


          /* 16-bit unicode in native byte order */

        case SSH_CHARSET_UNICODE16:

          for (i = 0; i < sizeof(union_u16.x); i++)
            {
              if (ssh_charset_get_byte(ctx, &t))
                goto done;
              union_u16.y[i] = (unsigned char) t;
            }
          ch = union_u16.x;
          break;


          /* 16-bit unicode in little endian byte order */

        case SSH_CHARSET_UNICODE16_LBO:

          if (ssh_charset_get_byte(ctx, &t))
            goto done;
          if (ssh_charset_get_byte(ctx, &ch))
            goto done;
          ch = (ch << 8) | t;
          break;


          /* 16-bit unicode in network byte order (two big endian bytes) */

        case SSH_CHARSET_UNICODE16_NBO:

          if (ssh_charset_get_byte(ctx, &t))
            goto done;
          if (ssh_charset_get_byte(ctx, &ch))
            goto done;
          ch = (t << 8) | ch;
          break;


          /* 32-bit unicode in native byte order */

        case SSH_CHARSET_UNICODE32:

          for (i = 0; i < sizeof(union_u32.x); i++)
            {
              if (ssh_charset_get_byte(ctx, &t))
                goto done;
              union_u32.y[i] = (unsigned char) t;
            }
          ch = union_u32.x;
          break;

          /* 32-bit unicode in little endian byte order */

        case SSH_CHARSET_UNICODE32_LBO:
          ch = 0;
          for (i = 0; i < 4; i++)
            {
              if (ssh_charset_get_byte(ctx, &t))
                goto done;
              ch |= t << (i * 8);
            }
          break;

          /* 32-bit unicode in network byte order (four big endian bytes) */

        case SSH_CHARSET_UNICODE32_NBO:
          ch = 0;
          for (i = 0; i < 4; i++)
            {
              if (ssh_charset_get_byte(ctx, &t))
                goto done;
              ch |= t << ((3-i) * 8);
            }
          break;

          /* input encoding not recognized. */

        default:
          /* We can not call fatal here.. we'll simply bail out */
#if 0
          ssh_fatal("ssh_charset_convert: Illegal input encoding %d",
                    ctx->input_encoding);
#endif
          /* mark the whole buffer as "read" */
          ctx->input_pos = ctx->input_len;
        }



      /* ok, we have a character. now try to write it out */

      switch(ctx->output_encoding)
        {

        case SSH_CHARSET_USASCII:
          if (ch >= 0x80)
            ch = '?';
          if (ssh_charset_put_byte(ctx, ch))
            goto done;
          break;

        case SSH_CHARSET_ISO_LATIN_1:
          if (ch >= 0x100)
            ch = '?';
          if (ssh_charset_put_byte(ctx, ch))
            goto done;
          break;


          /* utf-8 encoding */

        case SSH_CHARSET_UTF8:

          /* the 7-bit common case */

          if (ch < 0x80)
            {
              if (ssh_charset_put_byte(ctx, ch))
                goto done;
              break;
            }

          /* determine the size of the utf8 representation (1..6 bytes) */

          utf8size = 6;
          if (ch < 0x4000000)
            utf8size--;
          if (ch < 0x200000)
            utf8size--;
          if (ch < 0x10000)
            utf8size--;
          if (ch < 0x800)
            utf8size--;

          /* write the first byte */

          t = (0xfc << (6 - utf8size)) | (ch >> (6 * (utf8size - 1)));
          if (ssh_charset_put_byte(ctx, t))
            goto done;

          /* ok, now write consecutive bytes */

          for (i = utf8size - 2; i >= 0; i--)
            {
              t = 0x80 | ((ch >> (6 * i)) & 0x3f);
              if (ssh_charset_put_byte(ctx, t))
                goto done;
            }
          break; /* utf-8 */


          /* 16-bit unicode in native byte order */

        case SSH_CHARSET_UNICODE16:

          if (ch > 0x10000)
            ch = '?';
          union_u16.x = (SSH_CHARSET_NATIVE_UNICODE16) ch;
          for (i = 0; i < sizeof(union_u16.x); i++)
            {
              if (ssh_charset_put_byte(ctx, union_u16.y[i]))
                goto done;
            }
          break;


          /* 16-bit unicode in little endian byte order */

        case SSH_CHARSET_UNICODE16_LBO:

          if (ch > 0x10000)
            ch = '?';
          if (ssh_charset_put_byte(ctx, ch & 0xff))
            goto done;
          if (ssh_charset_put_byte(ctx, (ch >> 8) & 0xff))
            goto done;
          break;


          /* 16-bit unicode in network byte order */

        case SSH_CHARSET_UNICODE16_NBO:

          if (ch > 0x10000)
            ch = '?';
          if (ssh_charset_put_byte(ctx, (ch >> 8) & 0xff))
            goto done;
          if (ssh_charset_put_byte(ctx, ch & 0xff))
            goto done;
          break;


          /* 32-bit unicode in native byte order */

        case SSH_CHARSET_UNICODE32:

          union_u32.x = (SSH_CHARSET_NATIVE_UNICODE16) ch;
          for (i = 0; i < sizeof(union_u32.x); i++)
            {
              if (ssh_charset_put_byte(ctx, union_u32.y[i]))
                goto done;
            }
          break;


          /* 32-bit unicode in little endian byte order */

        case SSH_CHARSET_UNICODE32_LBO:

          for (i = 0; i < 4; i++)
            {
              if (ssh_charset_put_byte(ctx,
                                       (ch >> (8 * i)) & 0xff))
                goto done;
            }
          break;


          /* 32-bit unicode in network byte order */

        case SSH_CHARSET_UNICODE32_NBO:

          for (i = 0; i < 4; i++)
            {
              if (ssh_charset_put_byte(ctx,
                                       (ch >> (8 * (3 - i))) & 0xff))
                goto done;
            }
          break;

          /* unknown encoding.. */

        default:
#if 0
          ssh_fatal("ssh_charset_convert: Illegal output encoding %d",
                     ctx->output_encoding);
#endif
          /* mark the buffer as "read" */
          ctx->input_pos = ctx->input_len;
        }

      /* the character has been read and written. it can be discarded. */

      ssh_charset_flush(ctx);
    }

  /* apparently either one of the buffers ran out */

done:

  return ctx->output_pos;
}

/* Get the number of bytes of the input consumed in the latest
   operation. */

size_t ssh_charset_input_consumed(SshChrConv ctx)
{
  return ctx->input_pos;
}
