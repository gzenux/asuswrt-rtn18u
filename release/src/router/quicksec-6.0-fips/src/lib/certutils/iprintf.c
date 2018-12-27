/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshfileio.h"
#include "sshpem.h"

/* Global context for the iprintf. */
int ipf_width   = 80;
int ipf_indent  = 0;
int ipf_step    = 2;

#define IPF_MAX_STR 2048
#define IPF_MAX_ROW 2048

#define SSH_DEBUG_MODULE "SshIPrintf"

void iprintf_get(int *line_width, int *indent_level, int *indent_step)
{
  if (line_width)   *line_width   = ipf_width;
  if (indent_level) *indent_level = ipf_indent;
  if (indent_step)  *indent_step  = ipf_step;
  return;
}


void iprintf_set(int line_width, int indent_level, int indent_step)
{
  if (line_width)
    {
      if (line_width > IPF_MAX_ROW)
        ssh_fatal("error: max row width %u, non-negotiable.",
                  IPF_MAX_ROW);

      if (line_width < 3)
        ssh_fatal("error: row width %u must be greater than 3.");

      ipf_width   = line_width;
    }
  if (indent_level >= 0)
    {
      if (indent_level + 4 > ipf_width)
        ssh_fatal("error: indentation too large.");
      ipf_indent  = indent_level;
    }
  if (indent_step > 0)
    {
      ipf_step = indent_step;
    }
}

void iprintf(const char *str, ...)
{
  va_list ap;
  static char genbuf[IPF_MAX_STR + IPF_MAX_ROW + 2] = { 0x00 };
  static char outbuf[IPF_MAX_ROW+2] = { 0x00 };
  static int  stored_genbuf_len = 0;

  int out_indent, out_pos, i, len;
  int lb_indent, lb_genpos, lb_outpos;

  int cont_val, line_break, line_indent;

  va_start(ap, str);
  ssh_vsnprintf(genbuf + stored_genbuf_len, IPF_MAX_STR-1, str, ap);
  va_end(ap);

  len = strlen(genbuf);

  out_pos    = 0;
  out_indent = ipf_indent;

  /* The algorithm basically runs through the input string, removes
     the indentation tabs and copies to the output buffer. At the same
     time it also remembers the last position where line break can be
     made. */

  lb_indent   = ipf_indent;
  lb_genpos   = 0;
  lb_outpos   = 0;
  line_break  = 0;
  line_indent = ipf_indent;

  cont_val   = 0;

  for (i = 0; genbuf[i] != '\0'; i++)
    {
      if (out_pos > IPF_MAX_ROW)
        ssh_fatal("error: indent space exhausted.");

      /* Handle format strings. */
      if (genbuf[i] == '#')
        {
          if (genbuf[i+1] == 'I')
            {
              out_indent += ipf_step;
              i++;
              continue;
            }

          if (genbuf[i+1] == 'i')
            {
              out_indent -= ipf_step;
              if (out_indent < 0)
                ssh_fatal("error: negative indentation.");
              i++;
              continue;
            }
        }

      /* Add indentation to output. Gets done only on fresh lines. */
      for (; out_pos < out_indent; out_pos++)
        outbuf[out_pos] = ' ';

      /* Check if we got beyond end of output line */
      if (out_pos  > ipf_width)
        {
          if (lb_outpos == 0)
            {
              if (out_pos < 3)
                SSH_NOTREACHED;

              outbuf[out_pos-3] = '.';
              outbuf[out_pos-2] = '.';
              outbuf[out_pos-1] = '.';
              /* Print the outbuf. */
              outbuf[out_pos] = '\0';
              printf("%s\n", outbuf);
              return;
            }
          else
            {
              out_pos = lb_outpos;
              /* Print the outbuf. */
              outbuf[out_pos] = '\0';
              printf("%s\n", outbuf);
            }

          /* Start again. */
          out_pos     = 0;
          out_indent  = lb_indent;
          i           = lb_genpos;
          cont_val    = 0;

          line_indent = lb_indent;

          if (genbuf[i] != '\0' && genbuf[i] != ' ')
            i++;

          /* Skip whitespace. */
          for (; genbuf[i] != '\0' && genbuf[i] == ' '; i++)
            ;

          line_break = i;
          lb_outpos = 0;
          i--;
          continue;
        }

      if (genbuf[i] == '\n')
        {
          outbuf[out_pos] = '\0';
          printf("%s\n", outbuf);

          out_pos     = 0;
          cont_val    = 0;

          lb_outpos   = 0;
          lb_indent   = out_indent;

          line_indent = out_indent;

          i++;

          /* Skip whitespace. */
          for (; genbuf[i] != '\0' && genbuf[i] == ' '; i++)
            ;

          lb_genpos   = i;
          line_break  = i;

          i--;
          continue;
        }

      /* Remember the value. */
      outbuf[out_pos] = genbuf[i];
      out_pos++;

      if (genbuf[i] == ' ')
        {
          if (i > 0 && genbuf[i-1] == ' ')
            continue;

          lb_genpos = i;
          lb_indent = out_indent;
          lb_outpos = out_pos;
          cont_val  = 0;
        }

      if ((genbuf[i] != ' ') && (genbuf[i] != '\n'))
        {
          cont_val++;

          if (cont_val > ipf_width - out_indent - 2)
            {
              lb_genpos = i;
              lb_indent = out_indent;
              lb_outpos = out_pos;
              cont_val  = 0;
            }
        }
    }

  if (len - line_break)
    {
      memmove(genbuf, &genbuf[line_break], len - line_break + 1);
      stored_genbuf_len = len - line_break;
    }
  else
    {
      genbuf[0] = '\0';
      stored_genbuf_len = 0;
    }

  /* Set up the ipf values. */
  ipf_indent   = line_indent;
}
