/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc string functions.
*/

#include "sshincludes.h"
#include "sshmiscstring.h"
#include "sshgetput.h"

char *ssh_string_concat_2(const char *s1, const char *s2)
{
  int l1, l2;
  char *r;

  l1 = s1 ? strlen(s1) : 0;
  l2 = s2 ? strlen(s2) : 0;

  r = ssh_malloc(l1 + l2 + 1);

  if (r == NULL)
    return NULL;

  if (l1 > 0)
    strcpy(r, s1);
  else
    *r = '\000';
  if (l2 > 0)
    strcpy(&(r[l1]), s2);

  return r;
}

char *ssh_string_concat_3(const char *s1, const char *s2, const char *s3)
{
  int l1, l2, l3;
  char *r;

  l1 = s1 ? strlen(s1) : 0;
  l2 = s2 ? strlen(s2) : 0;
  l3 = s3 ? strlen(s3) : 0;
  r = ssh_malloc(l1 + l2 + l3 + 1);

  if (r == NULL)
    return NULL;

  if (l1 > 0)
    strcpy(r, s1);
  else
    *r = '\000';
  if (l2 > 0)
    strcpy(&(r[l1]), s2);
  if (l3 > 0)
    strcpy(&(r[l1 + l2]), s3);

  return r;
}

char *ssh_replace_in_string(const char *str, const char *src, const char *dst)
{
  char *hlp1, *hlp2, *hlp3, *strx;

  if (src == NULL)
    src = "";
  if (dst == NULL)
    dst = "";
  strx = ssh_strdup(str ? str : "");

  if ((*src == '\0') || ((hlp1 = strstr(strx, src)) == NULL))
    return strx;

  *hlp1 = '\0';
  hlp2 = ssh_string_concat_2(strx, dst);
  hlp1 = ssh_replace_in_string(&(hlp1[strlen(src)]), src, dst);
  hlp3 = ssh_string_concat_2(hlp2, hlp1);
  ssh_free(strx);
  ssh_free(hlp1);
  ssh_free(hlp2);
  return hlp3;
}

size_t ssh_strnlen(const char *str, size_t len)
{
  size_t l;

  for (l = 0; len > 0 && *str != '\0'; l++, len--, str++)
    ;

  return l;
}

size_t ssh_ustrnlen(const unsigned char *str, size_t len)
{
  size_t l;

  for (l = 0; len > 0 && *str != '\0'; l++, len--, str++)
    ;

  return l;
}

/*
 * Pretty print numbers using kilo/mega etc abbrevs to `buffer'. The resulting
 * string is at maximum 3 numbers + letter (kMGTPE) + null, so the buffer must
 * be large enough to hold at least 5 characters. Scale can be either 1024, or
 * 1000, and it will specify if the kMGTPE are for 2^10 or for 10^3 multiples.
 */
unsigned char *ssh_format_number(unsigned char *buffer, size_t len,
                                 SshUInt64 number, int scale)
{
  const char *scale_str = " kMGTPE";
  SshUInt64 num = 0L;
  int d;

  if (scale != 1000 && scale != 1024)
    ssh_fatal("Invalid scale in the ssh_format_number, must be 1024 or 1000");

  if (number < scale)
    {
      ssh_snprintf(buffer, len, "%d", (int) number);
      return buffer;
    }
  while (number >= 1000)
    {
      num = number;
      number /= scale;
      scale_str++;
    }
  if (num < 995 * scale / 100)
    {
      d = (int)(((num * 100 / scale) + 5) / 10);
      ssh_snprintf(buffer, len, "%d.%d%c", d / 10, d % 10, *scale_str);
    }
  else
    {
      d = (int)(((num * 10 / scale) + 5) / 10);
      ssh_snprintf(buffer, len, "%d%c", d, *scale_str);
    }
  return buffer;
}

/*
 * Pretty print numbers using kilo/mega etc abbrevs as snprintf renderer. The
 * resulting string is at maximum 3 numbers + letter (kMGTPE) + null, so the
 * buffer must be large enough to hold at least 5 characters. Scale is given in
 * the precision field, and it can be either 1024, or 1000, and it will specify
 * if the kMGTPE are for 2^10 or for 10^3 multiples. If it is omitted, then
 * 1024 is used. Datums is pointer to SshUInt64.
 */
int ssh_format_number64_render(unsigned char *buf, int buf_size, int precision,
                               void *datum)
{
  SshUInt64 *ptr = datum;
  ssh_format_number(buf, buf_size + 1, *ptr, precision < 0 ? 1024 : precision);
  return ssh_ustrnlen(buf, buf_size);
}

/*
 * Pretty print numbers using kilo/mega etc abbrevs as snprintf renderer. The
 * resulting string is at maximum 3 numbers + letter (kMGTPE) + null, so the
 * buffer must be large enough to hold at least 5 characters. Scale is given in
 * the precision field, and it can be either 1024, or 1000, and it will specify
 * if the kMGTPE are for 2^10 or for 10^3 multiples. If it is omitted, then
 * 1024 is used. Datums is pointer to SshUInt32.
 */
int ssh_format_number32_render(unsigned char *buf, int buf_size, int precision,
                               void *datum)
{
  SshUInt32 *ptr = datum;
  ssh_format_number(buf, buf_size + 1,
                    *ptr, precision < 0 ? 1024 : precision);
  return ssh_ustrnlen(buf, buf_size);
}

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format to
 * the `buffer'. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters.
 */
unsigned char *ssh_format_time(unsigned char *buffer, size_t len, SshTime t)
{
  if (t < 60 * 60 * 24)
    ssh_snprintf(buffer, len, "%02d:%02d:%02d",
                 (int)(t / 60 / 60), (int)((t / 60) % 60),(int) (t % 60));
  else
    if (t < 60 * 60 * 24 * 100)
      ssh_snprintf(buffer, len, "%d+%02d:%02d",
                   (int) (t / 24 / 60 / 60), (int)((t / 60 / 60) % 24),
                   (int)((t / 60) % 60));
    else
      if (t / (60 * 60 * 24) < 100000)
        ssh_snprintf(buffer, len, "%d+%02d",
                     (int) (t / 24 / 60 / 60), (int)((t / 60 / 60) % 24));
      else
        ssh_snprintf(buffer, len, "%d",
                     (int)(t / 24 / 60 / 60));
  return buffer;
}

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * SshTime.
 */
int ssh_format_time_render(unsigned char *buf, int buf_size, int precision,
                           void *datum)
{
  SshTime *t = datum;
  ssh_format_time(buf, buf_size + 1, *t);
  return ssh_ustrnlen(buf, buf_size);
}

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * SshUInt32.
 */
int ssh_format_time32_render(unsigned char *buf, int buf_size, int precision,
                             void *datum)
{
  SshUInt32 *t = datum;
  ssh_format_time(buf, buf_size + 1, *t);
  return ssh_ustrnlen(buf, buf_size);
}

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * unsigned char * pointing to buffer having the number in network byte order.
 */
int ssh_format_time32buf_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  unsigned char *ptr = datum;
  ssh_format_time(buf, buf_size + 1, SSH_GET_32BIT(ptr));
  return ssh_ustrnlen(buf, buf_size);
}

/* Returns an item inside brackets. For "(foo(test(bar())))" returns
   "foo(test(bar()))". */
static char *
ssh_mstr_get_next_item(const char *str)
{
  int c = 0;
  char *ptr, *start, *r;

  ptr = start = (char *)str;

  do {
    if (*ptr == '(') c++;
    if (*ptr == ')' && --c == 0) break;
  } while(*(++ptr) && c > 0);

  r = ssh_malloc(ptr - start);
  if (r)
    {
      memcpy(r, start + 1, ptr - start - 1);
      r[ptr - start - 1] = '\0';
    }
  return r;
}


/* Get the data from a string. Component identifies the data which to get.
   The source string is assumed to be in format
   "component1(component1_data), component2(component2_data)".

   Occurance identifies which occurance of the data to get, 0 giving
   the first occurance.

   Returns NULL, if the component is not found in the string and an empty
   string, if the component is empty. */
char *ssh_get_component_data_from_string(const char *source,
                                         const char *component,
                                         SshUInt32 occurance)
{
  const char *s = (char *)source, *c = (char *)component;
  int count = 0, c_len;
  SshUInt32 occ = 0;

  if (source == NULL ||
      component == NULL)
    return NULL;

  c_len = strlen(component);

  while (*s)
    {
      if (*s++ == *c)
        {
          if (++count == c_len)
            {
              if (*s == '(')
                {
                  if (occ == occurance)
                    break;
                  occ++;
                }
              c = (char *)component;
              count = 0;
            }
          else c++;
        }
      else if (count)
        {
          s--;
          c = (char *)component;
          count = 0;
        }
    }

  if (*s == '\0') return NULL;
  /* Now s points to the opening bracket of the compoent. */
  return ssh_mstr_get_next_item(s);
}

/* Free an array of strings. The strings of the array are freed individually
 * using ssh_xfree and the list is freed at last.
 */
void ssh_str_array_free(char **list, SshUInt32 num_items)
{
  for (; num_items > 0; num_items--)
    ssh_xfree(list[num_items - 1]);

  ssh_xfree(list);

}

/* Text render function, which will convert all control etc characters to
   hex. The length of the string is given in the precision, or if it is -1 then
   use the strlen of buffer. */
int ssh_safe_text_render(unsigned char *buf, int buf_size, int precision,
                         void *datum)
{
  unsigned char *buffer = datum;
  size_t len;
  int i;

  len = 0;
  if (precision < 0)
    precision = strlen((char *) buffer);
  if (len >= buf_size)
    return buf_size + 1;
  for(i = 0; i < precision; i++)
    {
      if (isprint(buffer[i]))
        buf[len++] = buffer[i];
      else
        {
          buf[len++] = '\\';
          if (len >= buf_size)
            return buf_size + 1;
          buf[len++] = 'x';
          if (len >= buf_size)
            return buf_size + 1;
          buf[len++] = "0123456789abcdef"[buffer[i] >> 4];
          if (len >= buf_size)
            return buf_size + 1;
          buf[len++] = "0123456789abcdef"[buffer[i] & 0xf];
        }
      if (len >= buf_size)
        return buf_size + 1;
    }
  return len;
}


/* Hex render function, which print the buffer in hex. The length of the string
   is given in the precision, or if it is -1 then use the strlen of buffer. */
int ssh_hex_render(unsigned char *buf, int buf_size, int precision,
                   void *datum)
{
  unsigned char *buffer = datum;
  size_t len;
  int i;

  len = 0;
  if (precision < 0)
    precision = strlen((char *) buffer);
  if (len >= buf_size)
    return buf_size + 1;
  for(i = 0; i < precision; i++)
    {
      if (i % 4 == 0 && i != 0)
        {
          buf[len++] = ' ';
          if (len >= buf_size)
            return buf_size + 1;
        }
      buf[len++] = "0123456789abcdef"[buffer[i] >> 4];
      if (len >= buf_size)
        return buf_size + 1;
      buf[len++] = "0123456789abcdef"[buffer[i] & 0xf];
      if (len >= buf_size)
        return buf_size + 1;
    }
  return len;
}

/* SshUInt32 array render, which renders the numbers in hex
   if the precision is negative, and otherwise in decimal.
   The number of items in the array is taken from then
   precision. */
int ssh_uint32_array_render(unsigned char *buf, int buf_size, int precision,
                            void *datum)
{
  SshUInt32 *array = datum;
  const char *format = "%lu";
  size_t len;
  int i;

  len = 0;
  if (precision < 0)
    {
      format = "%08lx";
      precision = -precision;
    }
  if (len >= buf_size)
    return buf_size + 1;
  for(i = 0; i < precision; i++)
    {
      len += ssh_snprintf(buf + len, buf_size - len + 1, format,
                          (unsigned long) array[i]);
      if (len >= buf_size)
        return buf_size + 1;
      if (i != precision - 1)
        {
          len += ssh_snprintf(buf + len, buf_size - len + 1, " ");
          if (len >= buf_size)
            return buf_size + 1;
        }
    }
  return len;
}

/* SshUInt32 bitmap renderer. Renders a SshUInt32 bitmask field as a comma
   separated list of symbolic names. The string of symbolic names is in 'buf'
   and the length of the string is given in 'precision'. */
int ssh_uint32_bm_render(unsigned char *buf, int buf_size, int precision,
                         void *datum)
{
  SshUInt32 bm_value;
  char *format_data;
  char *ptr, *symbol_start, *symbol_end, *mask_start;
  SshUInt32 mask = 0;
  size_t len = 0;

  bm_value = *((SshUInt32 *) datum);

  format_data = ssh_malloc(precision + 1);
  /* On memory error, fail with return value -1 */
  if (format_data == NULL)
    return -1;

  strncpy(format_data, (char *)buf, precision);

  ptr = format_data;
  while (ptr < format_data + precision)
    {

      symbol_start = NULL;
      symbol_end = NULL;
      mask_start = NULL;

      while (ptr < format_data + precision)
        {

          /* Find start of symbolic name */
          if (symbol_start == NULL && isalnum((int)*ptr))
            symbol_start = ptr;

          /* Find start of bitmask value */
          if (symbol_end == NULL && *ptr == '=')
            {
              symbol_end = ptr;
              ptr++;
              if (ptr < format_data + precision)
                {
                  mask_start = ptr;
                  for (;
                       *ptr != ',' && ptr < format_data + precision;
                       ptr++);
                  ptr++;
                  break;
                }
            }

          /* Find separator */
          if (symbol_end == NULL && *ptr == ',')
            {
              symbol_end = ptr;
              ptr++;
              break;
            }

          ptr++;
        }
      if (symbol_end == NULL && ptr >= format_data + precision)
        symbol_end = format_data + precision;

      /* Parse bitmask value */
      if (mask_start)
        {
          mask = strtol(mask_start, NULL, 0);
        }
      else
        {
          if (mask)
            mask = mask << 1;
          else
            mask = 1;
        }

      /* Check for match */
      if ((bm_value & mask) == mask)
        {
          if (len > 0)
            len += ssh_snprintf(buf + len, buf_size - len + 1, ",");
          if (symbol_start && symbol_end)
            len += ssh_snprintf(buf + len, buf_size - len + 1, "%.*s",
                                symbol_end - symbol_start, symbol_start);
          else
            len += ssh_snprintf(buf + len, buf_size - len + 1,
                                "0x%lx",
                                bm_value & mask);
        }
      if (len >= buf_size)
        {
          ssh_free(format_data);
          return buf_size + 1;
        }
    }

  ssh_free(format_data);
  return len;
}

/* eof (sshmiscstring.c) */
