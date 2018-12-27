/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of functions ssh_snprintf() and ssh_vsnprintf()
*/

#include "sshincludes.h"
#include "sshsnprintf.h"
#include "sshdsprintf.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshSPrintf"

#undef isdigit
#define isdigit(ch) ((ch) >= '0' && (ch) <= '9')

#define SSH_SNPRINTF_FLAG_MINUS         0x1
#define SSH_SNPRINTF_FLAG_PLUS          0x2
#define SSH_SNPRINTF_FLAG_SPACE         0x4
#define SSH_SNPRINTF_FLAG_HASH          0x8
#define SSH_SNPRINTF_FLAG_CONV_TO_SHORT 0x10
#define SSH_SNPRINTF_FLAG_LONG_INT      0x20
#define SSH_SNPRINTF_FLAG_LONG_LONG_INT 0x40
#define SSH_SNPRINTF_FLAG_LONG_DOUBLE   0x80
#define SSH_SNPRINTF_FLAG_X_UPCASE      0x100
#define SSH_SNPRINTF_FLAG_IS_NEGATIVE   0x200
#define SSH_SNPRINTF_FLAG_UNSIGNED      0x400
#define SSH_SNPRINTF_FLAG_ZERO_PADDING  0x800
#define SSH_SNPRINTF_FLAG_SIZE_T        0x1000

#undef sprintf
#ifdef VXWORKS
static int (*sprintf_func)(char *str, const char *format, ...) = sprintf;
#endif


#if defined(HAVE_LONG_LONG)
  #define LLTYPE        long long
  #define ULLTYPE        unsigned long long
#elif defined(HAVE_LONG)
  #define LLTYPE        long
  #define ULLTYPE       unsigned long
#else
  #error "No long long or long defined."
#endif


/* Convert a integer from unsigned long int representation
   to string representation. This will insert prefixes if needed
   (leading zero for octal and 0x or 0X for hexadecimal) and
   will write at most buf_size characters to buffer.
   tmp_buf is used because we want to get correctly truncated
   results.
   */

static int
ssh_snprintf_convert_unumber(unsigned char *buffer, size_t buf_size,
                             ULLTYPE base, const char *digits,
                             ULLTYPE ulong_val, int flags,
                             int width, int precision)
{
  int tmp_buf_len = 100 + width, written = 0;
  size_t len;
  unsigned char *tmp_buf_ptr, prefix[2];
  unsigned char tmp_buf[200];

  if (tmp_buf_len > sizeof(tmp_buf))
    {
      ssh_warning("Trying to print number with width more than %d",
                  sizeof(tmp_buf) - 100);
      return 0;
    }

  prefix[0] = '\0';
  prefix[1] = '\0';

  /* Make tmp_buf_ptr point just past the last char of buffer */
  tmp_buf_ptr = tmp_buf + tmp_buf_len;

  if (precision < 0)
    precision = 0;

  /* Main conversion loop */
  do
    {
      switch ((SshUInt8)base) {
      case 2:
        *--tmp_buf_ptr = digits[ulong_val & 0x1];
        ulong_val >>= 1;
        break;
      case 8:
        *--tmp_buf_ptr = digits[ulong_val & 0x7];
        ulong_val >>= 3;
        break;
      case 10:
#if defined(HAVE_LONG_LONG)
        {
          /* Perform division by ten. */
          ULLTYPE a = ulong_val, q = 0, b = 0xA000000000000000ULL;

          while (b >= 10) {
            q <<= 1;
            if (a >= b) {
              q++;
              a -= b;
            }
            b >>= 1;
          }

          *--tmp_buf_ptr = digits[a];
          ulong_val = q;
        }
#else
        *--tmp_buf_ptr = digits[ulong_val % 10];
        ulong_val /= 10;
#endif
        break;
      case 16:
        *--tmp_buf_ptr = digits[ulong_val & 0xF];
        ulong_val >>= 4;
        break;
      default:
        SSH_NOTREACHED;
#if 0
        /* This was painful in some embedded systems, because not the
           code requires linking some gcc-specific libraries.
           Disabled for now. */
        *--tmp_buf_ptr = digits[ulong_val % base];
        ulong_val /= base;
#endif
      }
      precision--;
    }
  while ((ulong_val != 0 || precision > 0) && tmp_buf_ptr > tmp_buf);

  /* Get the prefix */
  if (!(flags & SSH_SNPRINTF_FLAG_IS_NEGATIVE))
    {
      if (base == 16 && (flags & SSH_SNPRINTF_FLAG_HASH))
        {
          if (flags & SSH_SNPRINTF_FLAG_X_UPCASE)
            {
              prefix[0] = 'X';
              prefix[1] = '0';
            }
          else
            {
              prefix[0] = 'x';
              prefix[1] = '0';
            }
        }

      if (base == 8 && (flags & SSH_SNPRINTF_FLAG_HASH))
        prefix[0] = '0';

      if (base == 10
          && !(flags & SSH_SNPRINTF_FLAG_UNSIGNED)
          && (flags & SSH_SNPRINTF_FLAG_PLUS))
        prefix[0] = '+';
      else
        {
          if (base == 10
              && !(flags & SSH_SNPRINTF_FLAG_UNSIGNED)
              && (flags & SSH_SNPRINTF_FLAG_SPACE))
            prefix[0] = ' ';
        }
    }
  else
      prefix[0] = '-';

  if ((flags & SSH_SNPRINTF_FLAG_MINUS)
      || !(flags & SSH_SNPRINTF_FLAG_ZERO_PADDING))
    {
      /* Left-justified */
      if (prefix[0] != '\0' && tmp_buf_ptr > tmp_buf)
        {
          *--tmp_buf_ptr = prefix[0];
          if (prefix[1] != '\0' && tmp_buf_ptr > tmp_buf)
            *--tmp_buf_ptr = prefix[1];
        }
    }
  else
    {
      /* Right-justified */
      if (prefix[1] != '\0' && buf_size - written > 0)
        buffer[written++] = prefix[1];
      if (prefix[0] != '\0' && buf_size - written > 0)
        buffer[written++] = prefix[0];
    }

  len = (tmp_buf + tmp_buf_len) - tmp_buf_ptr;

  /* Now:
     - len is the length of the actual converted number,
       which is pointed to by tmp_buf_ptr.
     - buf_size is how much space we have.
     - width is the minimum width requested by the user.
     The following code writes the number and padding into
     the buffer and returns the number of characters written.
     If the SSH_SNPRINTF_FLAG_MINUS is set, the number will be left-justified,
     and if it is not set, the number will be right-justified.
     */

  while (buf_size - written > 0)
    {
      /* Write until the buffer is full. If stuff to write is exhausted
         first, return straight from the loop. */
      if (flags & SSH_SNPRINTF_FLAG_MINUS)
        {
          if (written < len)
            buffer[written] = tmp_buf_ptr[written];
          else
            {
              if (written >= width)
                {
                  return written;
                }
              buffer[written] =
                (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING) ? '0': ' ';
            }
          written++;
        }
      else
        {
          if (width > len && written < width - len)
            buffer[written] =
              (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING) ? '0': ' ';
          else
            {
              if (width > len)
                buffer[written] = tmp_buf_ptr[written - (width - len)];
              else
                buffer[written] = tmp_buf_ptr[written];
            }
          written++;
          if (written >= width && written >= len)
            {
              return written;
            }
        }
    }
  return written + 1;
}

#ifndef KERNEL

static int
ssh_snprintf_convert_float(unsigned char *buffer, size_t buf_size,
                           double dbl_val, int flags, int width,
                           int precision, char format_char)
{
  unsigned char print_buf[160];
  size_t print_buf_len = 0;
  char format_str[80], *format_str_ptr;

  format_str_ptr = format_str;

  if (width > 155)
    width = 155;
  if (precision < 0)
    precision = 6;
  if (precision > 120)
    precision = 120;

  /* Construct the formatting string and let system's sprintf
     do the real work. */

  *format_str_ptr++ = '%';

  if (flags & SSH_SNPRINTF_FLAG_MINUS)
    *format_str_ptr++ = '-';
  if (flags & SSH_SNPRINTF_FLAG_PLUS)
    *format_str_ptr++ = '+';
  if (flags & SSH_SNPRINTF_FLAG_SPACE)
    *format_str_ptr++ = ' ';
  if (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING)
    *format_str_ptr++ = '0';
  if (flags & SSH_SNPRINTF_FLAG_HASH)
    *format_str_ptr++ = '#';

#ifndef VXWORKS
  sprintf(format_str_ptr, "%d.%d", width, precision);
#else
  (*sprintf_func)(format_str_ptr, "%d.%d", width, precision);
#endif
  format_str_ptr += strlen(format_str_ptr);

  if (flags & SSH_SNPRINTF_FLAG_LONG_DOUBLE)
    *format_str_ptr++ = 'L';
  *format_str_ptr++ = format_char;
  *format_str_ptr++ = '\0';

#ifndef VXWORKS
  sprintf(ssh_sstr(print_buf), format_str, dbl_val);
#else
  (*sprintf_func)(ssh_sstr(print_buf), format_str, dbl_val);
#endif
  print_buf_len = ssh_ustrlen(print_buf);

  if (print_buf_len > buf_size)
    {
      print_buf_len = buf_size + 1;
      ssh_ustrncpy(buffer, print_buf, print_buf_len - 1);
    }
  else
    {
      ssh_ustrncpy(buffer, print_buf, print_buf_len);
    }
  return print_buf_len;
}

#endif /* !KERNEL */

int ssh_snprintf(unsigned char *str, size_t size, const char *format, ...)
{
  int ret;
  va_list ap;

  va_start(ap, format);
  ret = ssh_vsnprintf(str, size, format, ap);
  va_end(ap);

  return ret;
}

static void
ssh_snprintf_realloc(unsigned char **orig_str, size_t *size_ptr,
                     int bytes_to_expand)
{
  unsigned char *str;

  str = ssh_realloc(*orig_str, *size_ptr, *size_ptr + bytes_to_expand);
  if (str == NULL)
    {
      *size_ptr = -1;
      ssh_free(*orig_str);
      *orig_str = NULL;
    }
  *orig_str = str;
  *size_ptr += bytes_to_expand;
}

#define SSH_SNPRINTF_INCREMENT(ofs)     \
do                                      \
{                                       \
  if (ofs)                              \
    {                                   \
      str += ofs;                       \
      left -= ofs;                      \
      SSH_ASSERT(left >= 0);            \
    }                                   \
} while(0)

#define SSH_SNPRINTF_RETURN_NOT_NEGATIVE(n)     \
do {                                            \
  int __return_value = (n);                     \
  if (__return_value < 0) __return_value = 0;   \
  return __return_value;                        \
 } while(0)

#define SSH_SNPRINTF_NEED_MORE_SPACE_BASE(ofs,need)     \
do                                                      \
{                                                       \
  int __shift_ofs = ofs;                                \
                                                        \
  SSH_ASSERT(__shift_ofs >= 0);                         \
                                                        \
  SSH_SNPRINTF_INCREMENT(__shift_ofs);                  \
  if (!allow_realloc)                                   \
    {                                                   \
      if (left >= 0 && str != NULL)                     \
        *str = 0;                                       \
      SSH_SNPRINTF_RETURN_NOT_NEGATIVE(*size_ptr - 1);  \
    }                                                   \
  pos = str - *str_ptr;                                 \
  ssh_snprintf_realloc(str_ptr, size_ptr,               \
                       pos + (need));                   \
  if (*str_ptr == NULL)                                 \
    return -1;                                          \
  str = *str_ptr + pos;                                 \
  left = *size_ptr - pos - 1;                           \
  SSH_SNPRINTF_INCREMENT(-__shift_ofs);                 \
} while(0)

#define SSH_SNPRINTF_NEED_MORE_SPACE(ofs)                    \
 SSH_SNPRINTF_NEED_MORE_SPACE_BASE(ofs, 400)

#define SSH_SNPRINTF_PROCESS(funcall)           \
do                                              \
{                                               \
  while (1)                                     \
    {                                           \
      status = funcall;                         \
      if (status != left + 1)                   \
        {                                       \
          SSH_SNPRINTF_INCREMENT(status);       \
          break;                                \
        }                                       \
      SSH_SNPRINTF_NEED_MORE_SPACE(left);       \
    }                                           \
} while(0)

int ssh_vsnprintf_internal(unsigned char **str_ptr, size_t *size_ptr,
                           Boolean allow_realloc,
                           const char *format,
                           va_list ap)
{
  int status, left;
  size_t pos;
  const char *format_ptr;
  int flags, width, precision, i;
  char format_char;
  unsigned char *str;
  size_t format_len;
  ULLTYPE ulong_long_val;
  LLTYPE long_long_val;
  int *int_ptr;
  const char *str_val;
  int value;
  size_t length;
  const char *format_start;
#ifndef KERNEL
  double dbl_val;
#endif /* KERNEL */
  const char *render_format_data = NULL;
  size_t render_format_data_len = 0;

  left = (int)*size_ptr - 1;
  format_ptr = format;
  str = *str_ptr;
  format_len = strlen(format);
  while (format_ptr < format + format_len)
    {
      if (left <= 0)
        SSH_SNPRINTF_NEED_MORE_SPACE(0);

      SSH_ASSERT(left > 0);
      SSH_ASSERT(str != NULL);

      /* Non-% is trivial to handle; just copy it */
      if (*format_ptr != '%')
        {
          *str++ = *format_ptr++;
          left--;
          continue;
        }

      /* First character is '%'. */
      /* If second character is also %, it turns to % on output. */
      if (format_ptr[1] == '%')
        {
          /* Format `%%' at format string as `%' */
          *str++ = '%';
          left--;
          format_ptr += 2;
          continue;
        }
      format_start = format_ptr;

      /* Other format directive. */

      flags = 0;
      width = 0;
      precision = -1;

      /* Get the flags */
      format_ptr++;
      while (*format_ptr == '-' || *format_ptr == '+' ||
             *format_ptr == ' ' || *format_ptr == '#' ||
             *format_ptr == '0')
        {
          switch (*format_ptr)
            {
            case '-':
              flags |= SSH_SNPRINTF_FLAG_MINUS;
              break;
            case '+':
              flags |= SSH_SNPRINTF_FLAG_PLUS;
              break;
            case ' ':
              flags |= SSH_SNPRINTF_FLAG_SPACE;
              break;
            case '#':
              flags |= SSH_SNPRINTF_FLAG_HASH;
              break;
            case '0':
              flags |= SSH_SNPRINTF_FLAG_ZERO_PADDING;
              break;
            }
          format_ptr++;
        }

      /* Don't pad left-justified numbers withs zeros */
      if ((flags & SSH_SNPRINTF_FLAG_MINUS)
          && (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING))
        flags &= ~SSH_SNPRINTF_FLAG_ZERO_PADDING;

      /* Is width field present? */
      if (isdigit(*format_ptr))
        {
          for (value = 0;
               *format_ptr && isdigit(*format_ptr);
               format_ptr++)
            value = 10 * value + *format_ptr - '0';

          width = value;
        }
      else
        {
          if (*format_ptr == '*')
            {
              width = va_arg(ap, int);
              format_ptr++;
            }
        }

      /* Is the precision field present? */
      if (*format_ptr == '.')
        {
          format_ptr++;
          if (isdigit(*format_ptr))
            {
              for (value = 0;
                   *format_ptr && isdigit(*format_ptr);
                   format_ptr++)
                value = 10 * value + *format_ptr - '0';

              precision = value;
            }
          else
            {
              if (*format_ptr == '*')
                {
                  precision = va_arg(ap, int);
                  format_ptr++;
                }
              else
                precision = 0;
            }
        }

      /* Is format data for render functions available? */
      render_format_data = NULL;
      render_format_data_len = 0;
      if (*format_ptr == '(')
        {
          int b = 1;
          format_ptr++;
          render_format_data = format_ptr;
          while (format_ptr < format + format_len)
            {
              if (*format_ptr == '(') b++;
              if (*format_ptr == ')') b--;
              if (b == 0)
                {
                  render_format_data_len = format_ptr - render_format_data;
                  break;
                }
              format_ptr++;
            }
          if (*format_ptr != ')')
            format_ptr = render_format_data;
          else
            format_ptr++;
        }

      switch (*format_ptr)
        {
        case 'h':
          flags |= SSH_SNPRINTF_FLAG_CONV_TO_SHORT;
          format_ptr++;
          break;
        case 'l':
          if (*(format_ptr + 1) == 'l')
            {
              format_ptr++;
              flags |= SSH_SNPRINTF_FLAG_LONG_LONG_INT;
            }
          else
            flags |= SSH_SNPRINTF_FLAG_LONG_INT;
          format_ptr++;
          break;
        case 'z':
          flags |= SSH_SNPRINTF_FLAG_SIZE_T;
          format_ptr++;
          break;
        case 'q':
          flags |= SSH_SNPRINTF_FLAG_LONG_LONG_INT;
          format_ptr++;
          break;
        case 'L':
          flags |= SSH_SNPRINTF_FLAG_LONG_DOUBLE;
          format_ptr++;
          break;
        default:
          break;
        }

      /* Get and check the formatting character */
      format_char = *format_ptr;
      format_ptr++;
      length = format_ptr - format_start;

      switch (format_char)
        {
        case 'c':
        case 's':
        case 'p':
        case 'n':
        case 'd':
        case 'i':
        case 'o':
        case 'u':
        case 'x':
        case 'X':
        case 'f':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
        case '@':
          if (format_char == 'X')
            flags |= SSH_SNPRINTF_FLAG_X_UPCASE;
          if (format_char == 'o')
            flags |= SSH_SNPRINTF_FLAG_UNSIGNED;
          status = length;
          break;

        default:
          status = 0;
        }

      if (status == 0)
        {
          /* Invalid format directive. Fail with zero return. */
          *str = '\0';
          return 0;
        }

      /* Print argument according to the directive. */
      switch (format_char)
        {
        case 'i':
        case 'd':
          /* Convert to unsigned long int before
             actual conversion to string */
          if (flags & SSH_SNPRINTF_FLAG_LONG_LONG_INT)
            long_long_val = va_arg(ap, LLTYPE);
          else if (flags & SSH_SNPRINTF_FLAG_LONG_INT)
            long_long_val = (LLTYPE) va_arg(ap, long int);
          else if (flags & SSH_SNPRINTF_FLAG_SIZE_T)
            long_long_val = va_arg(ap, size_t);
          else
            long_long_val = (LLTYPE) va_arg(ap, int);

          if (long_long_val < 0)
            {
              ulong_long_val = (ULLTYPE) -long_long_val;
              flags |= SSH_SNPRINTF_FLAG_IS_NEGATIVE;
            }
          else
            {
              ulong_long_val = (ULLTYPE) long_long_val;
            }

          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_unumber(str, left, 10,
                                               "0123456789",
                                               ulong_long_val, flags,
                                               width, precision));
          break;

        case 'p':
          ulong_long_val = (ULLTYPE) (size_t) va_arg(ap, void *);
          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_unumber(str, left, 16,
                                            "0123456789abcdef",
                                            ulong_long_val, flags,
                                            width, precision));
          break;

        case 'x':
        case 'X':

          if (flags & SSH_SNPRINTF_FLAG_LONG_LONG_INT)
            ulong_long_val = va_arg(ap, ULLTYPE);
          else if (flags & SSH_SNPRINTF_FLAG_LONG_INT)
            ulong_long_val = va_arg(ap, unsigned long int);
          else if (flags & SSH_SNPRINTF_FLAG_SIZE_T)
            ulong_long_val = va_arg(ap, size_t);
          else
            ulong_long_val =
              (ULLTYPE) va_arg(ap, unsigned int);
          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_unumber(str, left, 16,
                                               (format_char == 'x') ?
                                               "0123456789abcdef" :
                                               "0123456789ABCDEF",
                                               ulong_long_val, flags,
                                               width, precision));
          break;

        case 'o':
          if (flags & SSH_SNPRINTF_FLAG_LONG_LONG_INT)
            ulong_long_val = va_arg(ap, ULLTYPE);
          else if (flags & SSH_SNPRINTF_FLAG_LONG_INT)
            ulong_long_val =
              (ULLTYPE) va_arg(ap, unsigned long int);
          else if (flags & SSH_SNPRINTF_FLAG_SIZE_T)
            ulong_long_val = va_arg(ap, size_t);
          else
            ulong_long_val =
              (ULLTYPE) va_arg(ap, unsigned int);
          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_unumber(str, left, 8,
                                               "01234567",
                                               ulong_long_val,
                                               flags, width,
                                               precision));
          break;

        case 'u':
          if (flags & SSH_SNPRINTF_FLAG_LONG_LONG_INT)
            ulong_long_val = va_arg(ap, ULLTYPE);
          else if (flags & SSH_SNPRINTF_FLAG_LONG_INT)
            ulong_long_val = (ULLTYPE)
              va_arg(ap, unsigned long int);
          else if (flags & SSH_SNPRINTF_FLAG_SIZE_T)
            ulong_long_val = va_arg(ap, size_t);
          else
            ulong_long_val =
              (unsigned long int) va_arg(ap, unsigned int);

          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_unumber(str, left, 10,
                                               "0123456789",
                                               ulong_long_val,
                                               flags, width,
                                               precision));
          break;

        case 'c':
          if (flags & SSH_SNPRINTF_FLAG_LONG_LONG_INT)
            ulong_long_val = va_arg(ap, ULLTYPE);
          else if (flags & SSH_SNPRINTF_FLAG_LONG_INT)
            ulong_long_val = (ULLTYPE)
              va_arg(ap, unsigned long int);
          else if (flags & SSH_SNPRINTF_FLAG_SIZE_T)
            ulong_long_val = va_arg(ap, size_t);
          else
            ulong_long_val =
              (ULLTYPE) va_arg(ap, unsigned int);
          *str++ = (unsigned char)ulong_long_val;
          left--;
          break;

        case '@':
          {
            SshSnprintfRenderer renderer =
              va_arg(ap, SshSnprintfRenderer);
            void *arg = va_arg(ap, void *);
            int return_value;

            while (1)
              {
                if (render_format_data_len)
                  {
                    if (render_format_data_len > left)
                      {
                        unsigned char *tmp_str;
                        tmp_str = ssh_malloc(render_format_data_len + 1);
                        /* On memory error, fail with return value -1 */
                        if (tmp_str == NULL)
                          return -1;

                        ssh_ustrncpy(tmp_str, ssh_custr(render_format_data),
                                     render_format_data_len);

                        return_value =
                          (* renderer) (tmp_str, left,
                                        render_format_data_len, arg);
                        ssh_ustrncpy(str, tmp_str, left);
                        ssh_free(tmp_str);
                      }
                    else {
                      ssh_ustrncpy(str, ssh_custr(render_format_data), left);
                      return_value =
                        (* renderer) (str, left, render_format_data_len, arg);
                    }
                  }
                else
                  return_value =
                    (* renderer) (str, left, precision, arg);

                SSH_ASSERT(return_value <= left + 1);

                if (return_value == left + 1)
                  SSH_SNPRINTF_NEED_MORE_SPACE(left);
                else
                  break;
              }
            SSH_ASSERT(return_value >= 0);
            SSH_ASSERT(return_value <= left);

            if (width > left)
              {
                if (allow_realloc)
                  SSH_SNPRINTF_NEED_MORE_SPACE_BASE(return_value,
                                       width-left+100); /* 100 is ad hoc */
                else
                  width = left;
              }
            if (width < return_value)
              width = return_value;
            else if (width > return_value)
              {
                /* We have room for formatting, if any. */
                if (flags & SSH_SNPRINTF_FLAG_MINUS)
                  {
                    memset(str + return_value,
                           ' ',
                           (width - return_value));
                  }
                else
                  {
                    memmove(str + (width - return_value),
                            str, return_value);
                    memset(str,
                           ' ',
                           (width - return_value));
                  }
              }
            SSH_SNPRINTF_INCREMENT(width);
          }
          break;

        case 's':
          {
            size_t bytes_to_alloc = 0;

            str_val = va_arg(ap, char *);

            if (str_val == NULL)
              str_val = "(null)";

            if (precision == -1)
              precision = strlen(str_val);
            else
              {
                /* If a precision is given, no null character needs to be
                   present, unless the array is shorter than the precision. */
                char *end = (char *)(memchr(str_val, '\0', precision));
                if (end != NULL)
                  precision = (int) (end - str_val);
              }
            if (precision > left)
              {
                /* Either reallocate more space or
                   concatenate the string */
                if (allow_realloc)
                  bytes_to_alloc = precision - left + 16;
                else
                  precision = left;
              }

            if (width > (left + bytes_to_alloc))
              {
                /* The width is specified to be longer than left.
                   Allocate more if allowed. */
                if (allow_realloc)
                  {
                    bytes_to_alloc += 16 +
                      width - (left + bytes_to_alloc);
                  }
                else
                  {
                    width = left;
                  }
              }
            if (bytes_to_alloc)
              {
                pos = str - *str_ptr;
                /* Alocate new space for the rest of %s and
                   16 bytes extra. */
                ssh_snprintf_realloc(str_ptr, size_ptr,
                                     bytes_to_alloc);
                if (*str_ptr == NULL)
                  return -1;
                str = *str_ptr + pos;
                left = *size_ptr - pos - 1;
              }
            if (width < precision)
              width = precision;
            i = width - precision;

            if (flags & SSH_SNPRINTF_FLAG_MINUS)
              {
                ssh_ustrncpy(str, ssh_custr(str_val), precision);
                memset(str + precision,
                       (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING) ? '0' : ' ',
                       i);
              }
            else
              {
                memset(str,
                       (flags & SSH_SNPRINTF_FLAG_ZERO_PADDING) ? '0' : ' ',
                       i);
                ssh_ustrncpy(str + i, ssh_custr(str_val), precision);
              }
            SSH_SNPRINTF_INCREMENT(width);
            break;
          }
        case 'n':
          int_ptr = va_arg(ap, int *);
          *int_ptr = (int) (str - *str_ptr);
          break;

#ifndef KERNEL
        case 'f':
        case 'e':
        case 'E':
        case 'g':
        case 'G':
          if (flags & SSH_SNPRINTF_FLAG_LONG_DOUBLE)
            dbl_val = (double) va_arg(ap, long double);
          else
            dbl_val = va_arg(ap, double);
          SSH_SNPRINTF_PROCESS(ssh_snprintf_convert_float(str, left,
                                                          dbl_val,
                                                          flags, width,
                                                          precision,
                                                          format_char));
          break;
#endif /* KERNEL */

        default:
          break;
        }
    }
  if (left == -1 && allow_realloc)
    SSH_SNPRINTF_NEED_MORE_SPACE_BASE(0,1);
  if (left >= 0 && str != NULL)
    *str = '\0';
  SSH_SNPRINTF_RETURN_NOT_NEGATIVE(*size_ptr - left - 1);
}

int ssh_vsnprintf(unsigned char *str, size_t size,
                  const char *format, va_list ap)
{
  return ssh_vsnprintf_internal(&str, &size, FALSE, format, ap);
}

int ssh_dsprintf(unsigned char **str, const char *format, ...)
{
  va_list ap;
  int result;

  va_start(ap, format);
  result = ssh_dvsprintf(str, format, ap);
  va_end(ap);

  return result;
}

int ssh_dvsprintf(unsigned char **str, const char *format, va_list ap)
{
  size_t size;

  SSH_PRECOND(str != NULL);
  SSH_PRECOND(format != NULL);
  size = 0;
  *str = NULL;

  return ssh_vsnprintf_internal(str, &size, TRUE, format, ap);
}

int ssh_xdsprintf(unsigned char **str, const char *format, ...)
{
  va_list ap;
  int result;

  va_start(ap, format);
  result = ssh_xdvsprintf(str, format, ap);
  va_end(ap);

  return result;
}

int ssh_xdvsprintf(unsigned char **str, const char *format, va_list ap)
{
  size_t size;
  int ret;

  SSH_PRECOND(str != NULL);
  SSH_PRECOND(format != NULL);
  size = 0;
  *str = NULL;

  ret = ssh_vsnprintf_internal(str, &size, TRUE, format, ap);

  if (ret == -1)
    ssh_fatal("ssh_xdvsprintf(): memory allocation failed.");

  return ret;
}
