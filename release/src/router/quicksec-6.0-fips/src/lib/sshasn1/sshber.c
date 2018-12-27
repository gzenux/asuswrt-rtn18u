/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Coding rules for BER/DER as in
   ISO/EIC 8825-1:1995 (E) and ISO/EIC 8825-1:1995/Cor.1 : 1996 (E)
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshber.h"
#include "sshasn1.h"
#include "sshmp.h"

#ifdef SSHDIST_ASN1
#define SSH_DEBUG_MODULE "SshAsn1Ber"

/* Simple date/secs conversion. */

unsigned int ssh_ber_date_to_days(unsigned int year, unsigned int month,
                                  unsigned int day)
{
  unsigned int total;
  unsigned int month_days[13] =
    { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  unsigned int months_added[13] =
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };

  if (month < 1 || month > 12)
    return 0;

  /* Rough estimate the number of days. */
  total = (year*365 + (year / 4) - (year / 100) + (year/400));

  /* Handle the leap year. */
  if ((year % 4) == 0 && ((year % 100) != 0 ||
                          (year % 400) == 0))
    {
      total -= 1;
      if (month > 2)
        total += 1;
      if (day < 1 || (month == 2 && day > month_days[month] + 1) ||
          (month != 2 && day > month_days[month]))
        return 0;
    }
  else
    if (day < 1 || day > month_days[month])
      return 0;

  /* Add together the days. */
  return total + day + months_added[month - 1] - 1;
}

void ssh_ber_days_to_date(unsigned int total,
                          unsigned int *year,
                          SshUInt8 *month,
                          SshUInt8 *day)
{
  unsigned int y, m, d, t, step, old, leap;
  unsigned int month_days[13] =
    { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

  /*
    If we'd had doubles, the following could be used instead of while
    loop on integer implementation:

    double ratio = 0.00273790700698851;
    y = (unsigned int)((double)total * ratio);
    t = y*365 + (y / 4) - (y / 100) + (y / 400);
  */

  /* Get a year, which is less than the correct year, but reasonable
     approximation, then fix it a bit. */
  y = total / 366;
  while (1)
    {
      t = y*365 + (y / 4) - (y / 100) + (y / 400);
      if (total >= t && (total - t) <= 366)
        break;
      y++;
    }

  /* We need to know whether this is a leap year. */
  leap = 0;
  if ((y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0))
    {
      leap = 1;
      t--;
    }

  /* Check whether we are off by few days. In double arithmetic we could
     be off few days, and with integer arithmetic at most 1 day. It seems
     that this holds for a very long time indeed. */
  if (leap && total - t >= 366)
    {
      y++;
      t += 366;
    }
  else if (!leap && total - t >= 365)
    {
      y++;
      t += 365;
    }

  if (total - t > 365)
    {
      *year = 0; *month = *day = 0;
      return;
    }

  /* Compute the month. */
  for (m = 0, old = 0, step = 0; m < 13; m++)
    {
      old = step;
      step += month_days[m];
      if (m == 2 && leap)
        step++;

      if (step > (total - t))
        {
          m--;
          break;
        }
    }

  /* Compute the day. */
  d = total - t - old;

  /* Output. */
  *year  = y;
  *month = (SshUInt8) (m + 1);
  *day   = (SshUInt8) (d + 1);
}

/* Routines for BER time.

This does not handle local and GMT times correctly if intertwined!
*/

int ssh_ber_time_cmp(const SshBerTime a, const SshBerTime b)
{
  /* Brute force attack to date comparison. Note that this is not exactly
     correct. */

  if (a->year > b->year)
    return 1;
  if (a->year < b->year)
    return -1;

  if (a->month > b->month)
    return 1;
  if (a->month < b->month)
    return -1;

  if (a->day > b->day)
    return 1;
  if (a->day < b->day)
    return -1;

  if (a->hour > b->hour)
    return 1;
  if (a->hour < b->hour)
    return -1;

  if (a->minute > b->minute)
    return 1;
  if (a->minute < b->minute)
    return -1;

  if (a->second > b->second)
    return 1;
  if (a->second < b->second)
    return -1;

  if (a->msecond > b->msecond)
    return 1;
  if (a->msecond < b->msecond)
    return -1;

  return 0;
}

SshTime ssh_ber_time_get_unix_time(const SshBerTime x)
{
  SshTime secs;
  unsigned int days;

  secs  = x->second + (x->minute + x->hour*60)*60;
  days  = ssh_ber_date_to_days(x->year, x->month, x->day);
  days -= 719527;
  if (days > (unsigned int) 0xffffffff / (24*60*60))
    {
      days = (unsigned int) 0xffffffff / (24*60*60);
    }

  secs += days * 24*60*60;

  return secs;
}

void ssh_ber_time_add_secs(SshBerTime x, unsigned long secs)
{
  unsigned long t, days;

  /* Handle first the clock. */

  /* Add secs to secs. */
  t = (x->second + secs);
  x->second = (SshUInt8)(t % 60);
  t /= 60;
  /* Add to minutes. */
  t = (x->minute + t);
  x->minute = (SshUInt8)(t % 60);
  t /= 60;
  /* Add to hours. */
  t = (x->hour + t);
  x->hour = (SshUInt8)(t % 24);
  t /= 24;

  /* Nothing more to do. */
  if (t == 0)
    return;

  /* Now handle the date. */

  /* Add to days. */

  /* Now we want to convert the date to days, for easier addition. */
  days = ssh_ber_date_to_days(x->year, x->month, x->day);
  days += t;
  {
    unsigned int year;
    SshUInt8 month, day;

    ssh_ber_days_to_date(days, &year, &month, &day);

    x->year = year;
    x->month = month;
    x->day = day;
  }
  /* Finished! */
}

void ssh_ber_time_set(SshBerTime x, const SshBerTime v)
{
  /* Lets do it manually, its more fun this way. */
  x->year = v->year;
  x->month = v->month;
  x->day = v->day;
  x->hour = v->hour;
  x->minute = v->minute;
  x->second = v->second;
  x->msecond = v->msecond;
  x->local = v->local;
  x->absolute_hours = v->absolute_hours;
  x->absolute_minutes = v->absolute_minutes;
}

void ssh_ber_time_set_from_unix_time(SshBerTime ber_time,
                                     SshTime unix_time)
{
  struct SshCalendarTimeRec t[1];

  ssh_calendar_time(unix_time, t, FALSE);

  ber_time->year = t->year;
  ber_time->month = t->month + 1;
  ber_time->day = t->monthday;
  ber_time->hour = t->hour;
  ber_time->minute = t->minute;
  ber_time->second = t->second;
  ber_time->msecond = 0;
  ber_time->local = FALSE;
  ber_time->absolute_hours = 0;
  ber_time->absolute_minutes = 0;
}

char *ssh_str_bertime_to_date_str(const SshBerTime b_time)
{
  unsigned char tmp_buf[32];

  ssh_snprintf(tmp_buf, sizeof(tmp_buf), "%d/%d/%d",
               b_time->day, b_time->month, b_time->year);

  return (char *)ssh_strdup(tmp_buf);
}

#if 0

void ssh_ber_time_intersect(const SshBerTime not_before,
                            const SshBerTime not_after,
                            const SshBerTime start, const SshBerTime end,
                            SshBerTime *min_start,
                            SshBerTime *min_end)
{
  if (ssh_ber_time_cmp(not_before, start) >= 0)
    *min_start = not_before;
  else
    *min_start = start;
  if (ssh_ber_time_cmp(not_after, end) >= 0)
    *min_end = end;
  else
    *min_end = not_after;
}

#endif

int ssh_ber_time_render(unsigned char *buf, int buf_size,
                        int precision, void *datum)
{
  SshBerTime bt = datum;
  int len = 0;
  char *str;

  if (datum)
    {
      ssh_ber_time_to_string(bt, &str);
      if (str)
        len = strlen(str);

      if (ssh_snprintf(buf, buf_size, "%s", str) < len)
        len = buf_size + 1;

      ssh_free(str);
      return len;
    }
  else
    {
      const char *m = "<not available>";

      len = strlen(m);
      if (ssh_snprintf(buf, buf_size, "%s", m) < len)
        len = buf_size + 1;
      return len;
    }
}

void ssh_ber_time_zero(SshBerTime ber_time)
{
  ber_time->year   = 0;
  ber_time->month  = 0;
  ber_time->day    = 0;
  ber_time->hour   = 0;
  ber_time->minute = 0;
  ber_time->second = 0;
  ber_time->msecond = 0;

  ber_time->local  = FALSE;
  ber_time->absolute_hours   = 0;
  ber_time->absolute_minutes = 0;
}

Boolean ssh_ber_time_available(const SshBerTime ber_time)
{
  if (ber_time->month != 0)
    return TRUE;
  return FALSE;
}

/* end of time routines. */

/* Some simple routines for encoding and decoding BER OID strings. */

static unsigned long *
ssh_ber_oid_string_decode(const char *str, size_t *oid_len)
{
  size_t len, i, j;
  unsigned long *oid;
  unsigned long val, tmp;

  /* Compute the length of the oid string. */
  for (i = 0, len = 1; str[i] != '\0'; i++)
    if (str[i] == '.')
      len++;

  if ((oid = ssh_malloc(sizeof(unsigned long)*len)) == NULL)
    return NULL;

  /* Parse the given string. */
  for (j = 0, i = 0; j < len; j++)
    {
      /* Decode the integer, keeping in mind that it should not be
         let to overflow! */
      for (val = 0; str[i] != '\0'; i++)
        {
          if (!isdigit((unsigned char)str[i]))
            break;
          tmp = val;
          val *= 10;
          val += (str[i] - '0');
          if (tmp != val/10)
            {
              /* Overflow. */
              ssh_free(oid);
              return NULL;
            }
        }
      oid[j] = val;

      if (str[i] != '.')
        break;
      i++;
    }

  /* Check for formatting error. */
  if (j >= len)
    {
      ssh_free(oid);
      return NULL;
    }

  /* Return the OID in unsigned long table. */
  *oid_len = len;
  return oid;
}

static char *
ssh_ber_oid_string_encode(const unsigned long *oid, size_t oid_len)
{
  SshBufferStruct buffer;
  char temp[10];
  unsigned long val;
  unsigned char *out_str = NULL;
  size_t i, j;

  ssh_buffer_init(&buffer);
  for (i = 0; i < oid_len; i++)
    {
      if (i > 0)
        {
          if (ssh_buffer_append(&buffer, (const unsigned char *)".", 1)
              != SSH_BUFFER_OK)
            {
              ssh_buffer_uninit(&buffer);
              return NULL;
            }
        }
      val = oid[i];
      for (j = 0; j < 10; j++)
        {
          temp[9 - j] = (unsigned char)((val % 10) + '0');
          val /= 10;
          if (val == 0)
            break;
        }
      if (val != 0)
        {
          ssh_buffer_uninit(&buffer);
          return NULL;
        }
      if (ssh_buffer_append(&buffer,
                            (const unsigned char *)&temp[9 - j], j + 1)
          != SSH_BUFFER_OK)
        {
          ssh_buffer_uninit(&buffer);
          return NULL;
        }
    }

  if (ssh_buffer_append(&buffer, (const unsigned char *)"\0", 1)
      == SSH_BUFFER_OK)
    out_str = ssh_buffer_steal(&buffer, NULL);
  ssh_buffer_uninit(&buffer);
  return (char *) out_str;
}

/* Compute the length of an ASN.1 BER encoded object (8.1.2) */
size_t ssh_ber_compute_tag_length(SshAsn1Class a_class,
                                  SshAsn1Encoding encoding,
                                  SshAsn1Tag tag_number,
                                  SshAsn1LengthEncoding length_encoding,
                                  size_t length)
{
  size_t tag_len = 1;

  /* Compute the length needed by tag_number unless short format can
     be used (in which case class and tag fit into single octet). */
  if (tag_number >= 0x1f)
    {
      while (tag_number)
        {
          tag_len++;
          tag_number >>= 7;
        }
    }

  /* Compute the space taken by length from the tag area. */
  if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
    {
      if (length < 0x80)
        {
          /* Short form for content length less than 128. */
          tag_len++;
        }
      else
        {
          /* Else long form must be used (initial octet followed by
             one or more subsequent octets. It is legal to use more
             octets than actually needed. */
          tag_len++;
          while (length)
            {
              length >>= 8;
              tag_len++;
            }
        }
    }
  else
    {
      /* Indefinite length encoding starts with single octet 10000000 */
      tag_len++;
    }
  return tag_len;
}

SshBerStatus ssh_ber_set_tag(unsigned char *buf, size_t len,
                             SshAsn1Class a_class, SshAsn1Encoding encoding,
                             SshAsn1Tag tag_number,
                             SshAsn1LengthEncoding length_encoding,
                             size_t length)
{
  size_t buf_pos;
  unsigned int i, mask, shift;

  if (ssh_ber_compute_tag_length(a_class, encoding,
                                 tag_number, length_encoding,
                                 length) > len)
    {
      return SSH_BER_STATUS_BUFFER_TOO_SMALL;
    }

  buf_pos = 0;

  /* Set class and encoding bit fields (bits [8-6]). */
  buf[buf_pos] = (a_class << 6) | (encoding << 5);

  /* Set tag number (bits [5-1] if tagnum less than 31. */
  if (tag_number < 0x1f)
    {
      buf[buf_pos] |= tag_number;
      buf_pos++;
    }
  else
    {
      /* Longer tag numbers; rest of the first octet as ones. */
      buf[buf_pos] |= 0x1f;
      buf_pos++;

      /* Count length for the tag_number (how many octets it
         requires) into i.*/
      for (i = 0, mask = tag_number; mask; mask >>= 7, i++)
        ;

      /* Assign tag into subsequent i octets. Bit 8 of each octet
         shall be 1 unless it is the last of tag octets. */
      for (i--, shift = i * 7; i; i--, shift -= 7, buf_pos++)
        {
          buf[buf_pos] =
            (unsigned char) (0x80 | ((tag_number >> shift) & 0x7f));
        }

      buf[buf_pos] = (unsigned char)tag_number & 0x7f;
      buf_pos++;
    }

  /* Encode the length value. */
  if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
    {
      if (length < 0x80)
        {
          /* Short form. Bit 8 is zero, rest is the length. */
          buf[buf_pos] = length;
        }
      else
        {
          /* Long format; First octet indicates the number of
             subsequent length octets. Value 0xff must not be used.
             Of course on this implementation we never get value of
             `i' greater than 8 (as the lenght is 64 bit entity). */
          for (i = 0, mask = length; mask; mask >>= 8, i++)
            ;

          buf[buf_pos] = 0x80 | i;
          buf_pos++;

          /* The following octets shall be the length. */
          for (shift = (i - 1) * 8; i; i--, shift -= 8, buf_pos++)
            {
              buf[buf_pos] = (length >> shift) & 0xff;
            }
        }
    }
  else
    {
      /* Indefinite length encoding. Bit 8 is one, bits [7-1] are
         zeros. */
      buf[buf_pos] = 0x80;
    }

  return SSH_BER_STATUS_OK;
}

/* Assign class, encoding, tagnum, length encoding, tag (and its
   length), content data (and its length) from BER encoded buffer
   `buf' whose length is `len'. Return SSH_BER_STATUS_OK if the buffer
   was large enough to contain data identifier and length octets
   describe. */
SshBerStatus ssh_ber_open_element(unsigned char *buf, size_t len,
                                  SshAsn1Class *a_class,
                                  SshAsn1Encoding *encoding,
                                  SshAsn1Tag *tag_number,
                                  SshAsn1LengthEncoding *length_encoding,
                                  size_t *tag_length,
                                  unsigned char **tag,
                                  size_t *length,
                                  unsigned char **data)
{
  size_t buf_pos = 0;
  unsigned int i, tag_bits;

  if (len == 0)
    return SSH_BER_STATUS_BUFFER_OVERFLOW;

  /* Get class and encoding (constructed/primitive). */
  *a_class  = (buf[buf_pos] >> 6) & 0x3;
  *encoding = (buf[buf_pos] >> 5) & 0x1;

  /* Get tag number. For longer tag nums the 5 least significant bits
     are all set, for smaller tagnum they encode the tag value. */
  if ((buf[buf_pos] & 0x1f) != 0x1f)
    {
      *tag_number = buf[buf_pos] & 0x1f;
      buf_pos++;
    }
  else
    {
      /* Long tag; skip this as it does not contain any more
         information. */
      buf_pos++;

      /* Read 7-bit 'windows' of the tag number. All but the last has
         the bit 8 as one. Beware of overflows. This assumes that
         tag contains at most 32 bits. */
      *tag_number = 0;
      tag_bits    = 0;
      while (buf_pos < len && (buf[buf_pos] & 0x80) != 0)
        {
          *tag_number = (*tag_number << 7) | (buf[buf_pos] & 0x7f);
          buf_pos++;
          tag_bits += 7;
        }

      if (buf_pos >= len)
        return SSH_BER_STATUS_BUFFER_OVERFLOW;

      /* Read also the last length 7-bit part. */
      *tag_number = (*tag_number << 7) | (buf[buf_pos] & 0x7f);
      buf_pos++;
      tag_bits += 7;

      if (tag_bits >= 32)
        return SSH_BER_STATUS_TAG_TOO_LARGE;
    }

  if (buf_pos >= len)
    return SSH_BER_STATUS_BUFFER_OVERFLOW;

  /* Get length of the contents. */
  if (!(buf[buf_pos] & 0x80))
    {
      /* Short form definite, bit 8 is zero. */
      *length_encoding = SSH_ASN1_LENGTH_DEFINITE;
      *length = buf[buf_pos] & 0x7f;
      buf_pos++;
    }
  else
    {
      if (buf[buf_pos] & 0x7f)
        {
          /* Long form definite if any of bits [1-7] is up one. First
             get number of length octets. */
          *length_encoding = SSH_ASN1_LENGTH_DEFINITE;
          i = buf[buf_pos] & 0x7f;
          buf_pos++;

          if (i > 4)
            return SSH_BER_STATUS_DATA_TOO_LONG;

          /* Each length octet encodes 8 bits from length. There may
             be leading zero valued octets. */
          for (*length = 0; i && buf_pos < len; i--)
            {
              *length = ((*length) << 8) | buf[buf_pos];
              buf_pos++;
            }

          /* Check if run out of data before could read in length. */
          if (i)
            return SSH_BER_STATUS_BUFFER_OVERFLOW;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Have an indefinite length node"));
          /* Indefinite form. The length not given and we must later
             look for end-of-contents octets.  */
          *length_encoding = SSH_ASN1_LENGTH_INDEFINITE;
          *length = 0;
          buf_pos++;
        }
    }

  if (*length > (len - buf_pos))
    return SSH_BER_STATUS_DATA_TOO_LONG;

  /* Tag points to start of tag (e.g. to identifier octets, and data
     points to start of contents octets. */
  *tag = buf;
  *tag_length = buf_pos;
  *data = buf + buf_pos;

  return SSH_BER_STATUS_OK;
}

/* Return size (in octets) of the ber content object in the buffer.
   Returns 0 if the length is indefinite, and (size_t)-1 if error
   (buffer too short).

   This used to call ssh_ber_open_element, but this caused problems
   with preserving consts.  I've reinstantiated it below, and
   performed some simplifications on the way. (Cessu) */
size_t ssh_ber_get_size(const unsigned char *buf, size_t len)
{
  size_t buf_pos = 0;
  unsigned int datalen;

  if (len == 0)
    return (size_t) -1;

  if ((buf[buf_pos] & 0x1f) != 0x1f)
    buf_pos++;
  else
    {
      unsigned int tag_bits = 0;

      buf_pos++;
      while ((buf[buf_pos] & 0x80) != 0 && buf_pos < len)
        {
          buf_pos++;
          tag_bits += 7;
        }
      buf_pos++;
      tag_bits += 7;
      if (tag_bits >= 32)
        return (size_t) -1;
    }

  if (buf_pos >= len)
    return (size_t) -1;

  if (!(buf[buf_pos] & 0x80))
    {
      datalen = buf[buf_pos] & 0x7f;
      buf_pos++;
    }
  else
    {
      unsigned int i = buf[buf_pos] & 0x7f;

      if (i == 0)
        return 0;
      if (i > 4)
        return (size_t) -1;

      buf_pos++;
      for (datalen = 0; i && buf_pos < len; i--)
        {
          datalen = (datalen << 8) | buf[buf_pos];
          buf_pos++;
        }

      if (i > 0)
        return (size_t) -1;
    }

  if (datalen > len - buf_pos)
    return (size_t) -1;

  return datalen + buf_pos;
}

SshBerFreeList ssh_ber_freelist_allocate(void)
{
  return NULL;
}
void ssh_ber_freelist_free(SshBerFreeList list, Boolean free_data)
{
  int i;
  Boolean dynamic;

  if (*list == NULL)
    return;

  dynamic =
    ((*list)->num_elements_alloc >
     (sizeof((*list)->elements_static) / sizeof((*list)->elements_static[0])));

  for (i = 0; i < (*list)->num_elements; i++)
    {
      if (free_data)
        {
          unsigned char *data;

          if (dynamic)
            data = (*list)->elements[i];
          else
            data = (*list)->elements_static[i];

          ssh_free(data);
        }
    }
  if (dynamic)
    ssh_free((*list)->elements);
  ssh_free((*list));
}

Boolean ssh_ber_freelist_add(SshBerFreeList list, void *data)
{
  unsigned char **tmp;
  size_t staticsize;

  staticsize = sizeof((*list)->elements_static) /
    sizeof((*list)->elements_static[0]);

  if (*list == NULL)
    {
      if (((*list) = ssh_calloc(1, sizeof(**list))) == NULL)
        {
          ssh_free(data);
          return FALSE;
        }

      (*list)->elements = NULL;
      (*list)->num_elements = 0;
      (*list)->num_elements_alloc = staticsize;
    }

  if ((*list)->num_elements != 0
      && (*list)->num_elements == (*list)->num_elements_alloc)
    {
      /* Expand with 10 new elements */
      if ((tmp =
           ssh_realloc((*list)->elements,
                       (*list)->num_elements_alloc,
                       ((*list)->num_elements_alloc + 10) *
                       sizeof((*list)->elements[0])))
          == NULL)
        {
          ssh_free(data);
          return FALSE;
        }

      /* If using static_array (e.g first time), now its time to copy
         data out from it */
      if ((*list)->num_elements_alloc == staticsize)
        {
          memcpy(tmp,
                 (*list)->elements_static, sizeof((*list)->elements_static));
        }
      (*list)->num_elements_alloc += 10;
      (*list)->elements = tmp;
    }

  if ((*list)->num_elements_alloc == staticsize)
    (*list)->elements_static[(*list)->num_elements++] = data;
  else
    (*list)->elements[(*list)->num_elements++] = data;

  return TRUE;
}

/* These pieces of code are used extensively in encoding, thus making them
   macros make the code a bit easier to write. If these are a problem,
   then perhaps some changes should be made... */

#define ALLOCATE_ENCODE                                                 \
  *tag_length = ssh_ber_compute_tag_length(a_class, encoding,           \
                                           tag_number, length_encoding, \
                                           *length);                    \
  *tag = ssh_obstack_alloc_unaligned(context, (*length)+(*tag_length)); \
  *data = (*tag) + (*tag_length)

#define EXIT_ENCODE                                     \
  return ssh_ber_set_tag(*tag, *tag_length,             \
                         a_class, encoding, tag_number, \
                         length_encoding, *length)


/* Encode types. These functions handle only primitive encodings. For
   constructed you have to build upper-level logic. */

#define SSH_BER_ENCODE_DEFINE(name, arg1, arg2)                         \
  SshBerStatus ssh_ber_encode_##name(SshObStackContext context,         \
                                     SshAsn1Class a_class,              \
                                     SshAsn1Encoding encoding,          \
                                     SshAsn1Tag tag_number,             \
                                     SshAsn1LengthEncoding length_encoding, \
                                     unsigned char **data,              \
                                     size_t *length,                    \
                                     unsigned char **tag,               \
                                     size_t *tag_length,                \
                                     arg1, arg2)


SSH_BER_ENCODE_PROTOTYPE(boolean,
                         void *pbool, void *ignore)
{
  Boolean boolean = *(Boolean *)pbool;

  /* The length of contents. */
  *length = 1;

  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;
  (*data)[0] = ((boolean) != FALSE) ? 0xff : 0;
  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(integer,
                         void *pinteger, void *ignore)
{
  SshMPIntegerStruct temp;
  unsigned int i, byte;
  SshMPInteger integer = *(SshMPInteger *)pinteger;

  if (ssh_mprz_cmp_ui(integer, 0) < 0)
    {
      /* Negative integer */

      /* Init temporary variable. */
      ssh_mprz_init_set_ui(&temp, 0);

      /* Change sign. */
      ssh_mprz_sub(&temp, &temp, integer);

      /* Subtract by 1. Now we have the value in two's complementary form
         but don't yet know where the highest bit will be. */
      ssh_mprz_sub_ui(&temp, &temp, 1);

      /* Compute the actual length of the BER encoded integer (it is also
         DER encoded).

         Problem here is that negative integer -128 is represented
         as 0x80 and positive integer 128 is represented as 0x0080.
         This code solves this dilemma with checking that whether the
         highest bit will be one. */
      *length = ssh_mprz_get_size(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
        {
          *length = (*length + 7) / 8;
          *length = (*length) + 1;
        }
      else
        {
          *length = (*length + 7) / 8;
        }

      ALLOCATE_ENCODE;
      if (*tag == NULL)
        {
          ssh_mprz_clear(&temp);
          return SSH_BER_STATUS_ERROR;
        }

      /* Now build up the octet representation of the integer. Assuming
         that we have the highest bit set. */

      /* Do it the slow way (octet at a time). We supposedly are in no
         hurry. */
      for (i = 0; i < *length; i++)
        {
          byte = ssh_mprz_get_ui(&temp);
          (*data)[(*length) - 1 - i] = (~byte & 0xff);
          ssh_mprz_div_2exp(&temp, &temp, 8);
        }

      /* We now have valid integer encoded in BER. */

      ssh_mprz_clear(&temp);
    }
  else
    {
      /* Positive integer case (which thank fully is somewhat easier). */

      ssh_mprz_init_set(&temp, integer);

      /* Get length. */
      *length = ssh_mprz_get_size(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
        {
          *length = (*length + 7) / 8;
          *length = (*length) + 1;
        }
      else
        {
          *length = (*length + 7) / 8;
        }

      ALLOCATE_ENCODE;
      if (*tag == NULL)
        {
          ssh_mprz_clear(&temp);
          return SSH_BER_STATUS_ERROR;
        }

      /* Encode it as negative (but don't compute one's complement). */
      for (i = 0; i < *length; i++)
        {
          byte = ssh_mprz_get_ui(&temp);
          (*data)[(*length) - 1 - i] = (byte & 0xff);
          ssh_mprz_div_2exp(&temp, &temp, 8);
        }

      /* BER encoding ready. */
      ssh_mprz_clear(&temp);
    }

  EXIT_ENCODE;
}


SSH_BER_ENCODE_PROTOTYPE(bit_string,
                         void *pbit_string, void *pbit_length)
{
  unsigned char *bit_string = *(unsigned char **)pbit_string;
  size_t bit_length = *(size_t *)pbit_length;

  /* Assuming the bit_length is in bits. */
  *length = (bit_length + 7) / 8;

  /* Add also the octet to represent the padding length. */
  (*length)++;

  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;

  /* Set the padding length. What this does is to compute how many unused
     bits are there in the last octet. */
  (*data)[0] = (8 - (bit_length & 7)) & 7;

  if (*length > 1)
    {
      /* Copy the rest of the bit string. */
      memcpy((*data) + 1, bit_string, (*length) - 2);

      /* Set the last octet here, because we cannot be sure that the
         original has all the bits zeroed. */
      (*data)[(*length) - 1] =
        bit_string[(*length) - 2] & ((0xff << (*data)[0]) & 0xff);
    }

  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(octet_string,
                         void *poctet_string, void *poctet_length)
{
  unsigned char *octet_string = *(unsigned char **)poctet_string;
  size_t octet_length = *(size_t *)poctet_length;

  /* Do a simple copy. */
  *length = octet_length;

  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;
  memcpy(*data, octet_string, octet_length);

  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(null, void *ignore1, void *ignore2)
{
  *length = 0;

  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;
  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(empty, void *ignore1, void *ignore2)
{
  *length = 0;
  return SSH_BER_STATUS_OK;
}

SSH_BER_ENCODE_PROTOTYPE(oid_type,
                         void *poid_str, void *ignore)
{
  unsigned long *oid_table;
  size_t         oid_table_len;
  unsigned int i, buf_pos, shift;
  int j;
  unsigned long value;
  const char *oid_str = *(const char **)poid_str;

  SSH_DEBUG(15, ("Encoding OID: %s", oid_str));
  oid_table = ssh_ber_oid_string_decode(oid_str, &oid_table_len);
  if (oid_table == NULL)
    return SSH_BER_STATUS_DECODE_FAILED;

  if (oid_table_len < 2)
    {
      ssh_free(oid_table);
      return SSH_BER_STATUS_TABLE_TOO_SMALL;
    }

  /* Minimum length for OID is 1 octet (atleast this implementation
     assumes this). */
  *length = 1;

  /* Count the length needed for Object Identifier Value */
  for (i = 2; i < oid_table_len; i++)
    {
      if (oid_table[i] == 0)
        (*length)++;
      else
        {
          for (value = oid_table[i]; value; value >>= 7, (*length)++)
            ;
        }
    }

  ALLOCATE_ENCODE;
  if (*tag == NULL)
    {
      ssh_free(oid_table);
      return SSH_BER_STATUS_ERROR;
    }

  /* Set the first octet. */
  (*data)[0] = (unsigned char)(oid_table[0] * 40 + oid_table[1]);

  for (i = 2, buf_pos = 1; i < oid_table_len; i++)
    {
      if (oid_table[i] == 0)
        {
          (*data)[buf_pos] = 0x0;
          buf_pos++;
        }
      else
        {
          /* Count length for the tag_number, this is similar to the
             insertion of tag numbers. */
          for (j = 0, value = oid_table[i]; value; value >>= 7, j++)
            ;

          for (j--, shift = j * 7; j > 0; j--, shift -= 7, buf_pos++)
            {
              (*data)[buf_pos] =
                (unsigned char)(0x80 | ((oid_table[i] >> shift) & 0x7f));
            }

          (*data)[buf_pos] = (unsigned char)(oid_table[i] & 0x7f);
          buf_pos++;
        }
    }

  /* Free the allocated oid table. */
  ssh_free(oid_table);

  EXIT_ENCODE;
}

/* Following are not implemented. */

SSH_BER_ENCODE_PROTOTYPE(ode_type, void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(eti_type, void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(real, void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(embedded, void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(universal_time,
                         void *ptimeval, void *ignore)
{
  unsigned char buffer[128];
  size_t len;
  SshBerTime timeval = *(SshBerTime *)ptimeval;
  /* Encode into an octet string. */
  ssh_snprintf(buffer, sizeof(buffer),
               "%02d"  /* year */
               "%02d"  /* month */
               "%02d"  /* day */
               "%02d"  /* hour */
               "%02d"  /* minute */
               "%02d", /* second */
               timeval->year % 100,
               timeval->month, timeval->day,
               timeval->hour, timeval->minute, timeval->second);

  len = ssh_ustrlen(buffer);

  if (timeval->absolute_hours || timeval->absolute_minutes)
    ssh_snprintf(buffer + len, sizeof(buffer) - len,
                 "%c"    /* local difference */
                 "%02d"  /* hours */
                 "%02d", /* minutes */
                 (timeval->local == TRUE ? '+' : '-'),
                 timeval->absolute_hours, timeval->absolute_minutes);
  else
    ssh_snprintf(buffer + len, sizeof(buffer) - len, "Z");

  *length = ssh_ustrlen(buffer);
  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;

  memcpy(*data, buffer, *length);

  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(generalized_time,
                         void *ptimeval, void *ignore)
{
  unsigned char buffer[128], msecbuf[16];
  SshBerTime timeval = *(SshBerTime *)ptimeval;

  /* Encoding of microseconds omits trailing zeroes */
  if (timeval->msecond)
    {
      int len;

      if ((len =
           ssh_snprintf(msecbuf, sizeof(msecbuf), ".%06d", timeval->msecond))
          < 1)
        msecbuf[0] = '\0'; /* if fail, leave out */
      else
        {
          while (len && msecbuf[len - 1] == '0') len--;
          msecbuf[len] = '\0';
        }
    }
  else
    {
      msecbuf[0] = '\0';
    }

  /* Encode into a octet string.  */
  ssh_snprintf(buffer, sizeof(buffer),
               "%04d"  /* year */
               "%02d"  /* month */
               "%02d"  /* day */
               "%02d"  /* hour */
               "%02d"  /* minute */
               "%02d"  /* second */
               "%s"    /* msec */
               "Z",
               timeval->year,
               timeval->month, timeval->day,
               timeval->hour, timeval->minute, (unsigned int)timeval->second,
               msecbuf);

  *length = ssh_ustrlen(buffer);
  ALLOCATE_ENCODE;
  if (*tag == NULL) return SSH_BER_STATUS_ERROR;

  memcpy(*data, buffer, *length);

  EXIT_ENCODE;
}

SSH_BER_ENCODE_PROTOTYPE(integer_short,
                         void *pword, void *ignore)
{
  SshMPIntegerStruct temp;
  unsigned int i, byte;
  SshWord word = *(SshWord *)pword;

  SSH_DEBUG(15, ("Encoding %lu", (unsigned long)word));

  /* Init temporary variable. */
  ssh_mprz_init(&temp);
  ssh_mprz_set_ui(&temp, word);

  if (ssh_mprz_cmp_ui(&temp, 0) < 0)
    {
      /* Negative integer */

      /* Change sign. */
      ssh_mprz_neg(&temp, &temp);

      /* Subtract by 1. Now we have the value in two's complementary form
         but don't yet know where the highest bit will be. */
      ssh_mprz_sub_ui(&temp, &temp, 1);

      /* Compute the actual length of the BER encoded integer (it is also
         DER encoded).

         Problem here is that negative integer -128 is represented
         as 0x80 and positive integer 128 is represented as 0x0080.
         This code solves this dilemma with checking that whether the
         highest bit will be one. */
      *length = ssh_mprz_get_size(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if (((*length) & 7) == 0)
        {
          *length = (*length + 7) / 8;
          *length = (*length) + 1;
        }
      else
        {
          *length = (*length + 7) / 8;
        }

      ALLOCATE_ENCODE;
      if (*tag == NULL)
        {
          ssh_mprz_clear(&temp);
          return SSH_BER_STATUS_ERROR;
        }

      /* Now build up the octet representation of the integer. Assuming
         that we have the highest bit set. */

      /* Do it the slow way (octet at a time). We supposedly are in no
         hurry. */
      for (i = 0; i < *length; i++)
        {
          byte = ssh_mprz_get_ui(&temp);
          (*data)[*length - 1 - i] = (~byte & 0xff);
          ssh_mprz_div_2exp(&temp, &temp, 8);
        }

      /* We now have valid integer encoded in BER. */

      ssh_mprz_clear(&temp);
    }
  else
    {
      /* Positive integer case (which thank fully is somewhat easier). */

      /* Get length. */
      *length = ssh_mprz_get_size(&temp, 2);

      SSH_DEBUG(15, ("integer-short size: %d", *length));

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
        {
          *length = (*length + 7) / 8;
          *length += 1;
        }
      else
        {
          *length = (*length + 7) / 8;
        }

      ALLOCATE_ENCODE;
      if (*tag == NULL)
        {
          ssh_mprz_clear(&temp);
          return SSH_BER_STATUS_ERROR;
        }

      /* Encode it as negative (but don't compute one's complement). */
      for (i = 0; i < *length; i++)
        {
          byte = ssh_mprz_get_ui(&temp);
          (*data)[*length - 1 - i] = (byte & 0xff);
          ssh_mprz_div_2exp(&temp, &temp, 8);
          SSH_DEBUG(25, ("integer-short  data[%d] = %x", *length  - 1 - i,
                         byte & 0xff));
        }

      /* BER encoding ready. */
      ssh_mprz_clear(&temp);
    }

  EXIT_ENCODE;
}

/* Prototype to ease writing redundant code, this need not be used... */
#define SSH_BER_DECODE_PROTOTYPE(name)                                  \
  SshBerStatus ssh_ber_decode_##name(unsigned char *data, size_t length, \
                                     va_list *ap)

/* Decode BER encodings. Decoded values are probably used by some
   application and thus cannot be allocated with cmalloc, we use directly
   the ssh_xmalloc procedure. */

SshBerStatus ssh_ber_decode_boolean(unsigned char *data, size_t length,
                                    SshBerFreeList list,
                                    void *pboolean, void *ignore)
{
  Boolean *boolean = (Boolean *)pboolean;

  if (length != 1)
    return SSH_BER_STATUS_NOT_AVAILABLE;

  boolean[0] = (data[0] ? TRUE : FALSE);

  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_integer(unsigned char *data, size_t length,
                                    SshBerFreeList list,
                                    void *pinteger, void *ignore)
{
  SshMPIntegerStruct temp;
  SshMPInteger integer = (SshMPInteger)pinteger;
  unsigned int i;

  if (data[0] & 0x80)
    {
      unsigned char *tmp;

      /* Negative integer. */
      ssh_mprz_set_ui(integer, 0);

      if ((tmp = ssh_malloc(length)) == NULL)
        return SSH_BER_STATUS_ERROR;

      for (i = 0; i < length; i++)
        tmp[i] = (~data[i] & 0xff);

      ssh_mprz_set_buf(integer, tmp, length);
      ssh_free(tmp);

      /* Set the correct value (not the best way probably). */
      ssh_mprz_init_set_ui(&temp, 0);
      ssh_mprz_add_ui(integer, integer, 1);
      ssh_mprz_sub(integer, &temp, integer);
      ssh_mprz_clear(&temp);
    }
  else
    {
      /* Positive integer. */
      ssh_mprz_set_ui(integer, 0);

      /* This is rather simple (without one's complement compared to
         negative case. */
      ssh_mprz_set_buf(integer, data, length);
    }

  if (ssh_mprz_isnan(integer))
    return SSH_BER_STATUS_ERROR;
  else
    return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_integer_short(unsigned char *data, size_t length,
                                          SshBerFreeList list,
                                          void *preturn_word, void *ignore)
{

  SshMPIntegerStruct temp, new_int;
  SshMPInteger integer;
  SshWord word_max, *return_word = (SshWord *)preturn_word;
  SshBerStatus return_status = SSH_BER_STATUS_OK;

  unsigned int i;

  ssh_mprz_init(&new_int);
  word_max = -1;

  integer= &new_int;

  if (data[0] & 0x80)
    {
      /* Negative integer. */
      ssh_mprz_set_ui(integer, 0);

      for (i = 0; i < length; i++)
        {
          ssh_mprz_mul_2exp(integer, integer, 8);
          ssh_mprz_add_ui(integer, integer, (~data[i] & 0xff));
        }

      /* Set the correct value (not the best way probably). */
      ssh_mprz_init_set_ui(&temp, 0);
      ssh_mprz_add_ui(integer, integer, 1);
      ssh_mprz_sub(integer, &temp, integer);
      ssh_mprz_clear(&temp);
    }
  else
    {
      /* Positive integer. */
      ssh_mprz_set_ui(integer, 0);

      /* This is rather simple (without one's complement compared to
         negative case. */
      ssh_mprz_set_buf(integer, data, length);
    }

  /* Check if the word fits into SshWord and is not negative. */
  if (ssh_mprz_isnan(integer) ||
      (ssh_mprz_cmp_ui(integer, word_max) == 1 &&
       ssh_mprz_cmp_ui(integer, 0) == -1))
    return_status = SSH_BER_STATUS_ERROR;

  *return_word = ssh_mprz_get_ui(integer);

  /*Clean the memory*/
  ssh_mprz_clear(integer);

  return return_status;
}

SshBerStatus ssh_ber_decode_bit_string(unsigned char *data, size_t length,
                                       SshBerFreeList list,
                                       void *pbit_string,
                                       void *pbit_length)
{
  unsigned char **bit_string = (unsigned char **)pbit_string;
  size_t *bit_length = (size_t *)pbit_length;

  if (length == 0)
    goto error;

  if (length == 1)
    {
      *bit_string = NULL;
      *bit_length = 0;

      if (data[0] == 0)
        return SSH_BER_STATUS_OK;
      else
        return SSH_BER_STATUS_ERROR;
    }

  /* The first octet must be less than 8. */
  if ((data[0] > 7) || (data[0] >= (length - 1) * 8))
    goto error;

  /* Compute bit length of the bit string. */
  *bit_length = (length - 1) * 8 - data[0];

  /* Allocate the bit string, add to the free list, in case error
     occurs later. */
  if ((*bit_string = ssh_memdup(data + 1, length - 1)) == NULL)
    goto error;

  if (ssh_ber_freelist_add(list, *bit_string))
    return SSH_BER_STATUS_OK;
  else
    {
    error:
      *bit_string = NULL;
      *bit_length = 0;
      return SSH_BER_STATUS_ERROR;
    }
}

SshBerStatus
ssh_ber_decode_octet_string(unsigned char *data, size_t length,
                            SshBerFreeList list,
                            void *poctet_string,
                            void *poctet_length)
{
  unsigned char **octet_string = (unsigned char **)poctet_string;
  size_t *octet_length = (size_t *)poctet_length;

  /* Do a simple copy. */
  if (length)
    {
      if ((*octet_string = ssh_memdup(data, length)) == NULL)
        {
          *octet_length = 0;
          return SSH_BER_STATUS_ERROR;
        }

      *octet_length = length;
      if (ssh_ber_freelist_add(list, *octet_string))
        return SSH_BER_STATUS_OK;
      else
        {
          *octet_string = NULL;
          *octet_length = 0;
          return SSH_BER_STATUS_ERROR;
        }
    }
  else
    {
      *octet_string = NULL;
      *octet_length = 0;
    }

  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_null(unsigned char *buf, size_t length,
                                 SshBerFreeList list,
                                 void *ignore1, void *ignore2)
{
  if (length == 0)
    return SSH_BER_STATUS_OK;

  return SSH_BER_STATUS_NOT_AVAILABLE;
}

SshBerStatus ssh_ber_decode_empty(unsigned char *buf, size_t length,
                                  SshBerFreeList list,
                                  void *ignore1, void *ignore2)
{
  if (length == 0)
    return SSH_BER_STATUS_OK;

  return SSH_BER_STATUS_NOT_AVAILABLE;
}

SshBerStatus ssh_ber_decode_oid_type(unsigned char *data, size_t length,
                                     SshBerFreeList list,
                                     void *poid_str, void *ignore)
{
  unsigned long *oid_table;
  size_t         oid_table_len;
  unsigned int value, i, buf_pos, bits;
  char **oid_str = (char **)poid_str;

  /* The minimal length for the oid_table. */
  oid_table_len = 2;

  /* Count OID values. Knowing that the highest bit of octet shall be
     zero if least octet of that OID value. */
  for (buf_pos = 1; buf_pos < length; buf_pos++)
    {
      if ((data[buf_pos] & 0x80) == 0)
        oid_table_len ++;
    }

  /* Allocate some memory for the oid table. */
  if ((oid_table =
       (unsigned long *)ssh_malloc(oid_table_len * sizeof(unsigned long)))
      == NULL)
    return SSH_BER_STATUS_ERROR;

  /* Set the first two. */
  oid_table[0] = (data[0] & 0xff) / 40;
  oid_table[1] = (data[0] & 0xff) % 40;

  for (i = 2, buf_pos = 1; i < oid_table_len; i++)
    {
      for (value = 0, bits = 0; data[buf_pos] & 0x80; buf_pos++, bits += 7)
        {
          value = (value << 7) | (data[buf_pos] & 0x7f);
        }
      value = (value << 7) | (data[buf_pos] & 0x7f);

      if (bits + 7 > (sizeof(unsigned long)*8))
        {
          ssh_free(oid_table);
          return SSH_BER_STATUS_DECODE_FAILED;
        }

      buf_pos++;

      oid_table[i] = value;
    }

  /* Convert to string, this is non-optimal as we could have done that
     previously. */
  if ((*oid_str = ssh_ber_oid_string_encode(oid_table, oid_table_len))
      != NULL)
    {
      ssh_free(oid_table);
      if (ssh_ber_freelist_add(list, *oid_str))
        return SSH_BER_STATUS_OK;
      else
        {
          *oid_str = NULL;
          return SSH_BER_STATUS_ERROR;
        }
    }
  ssh_free(oid_table);
  return SSH_BER_STATUS_ERROR;
}

/* Following are not implemented. */

SshBerStatus ssh_ber_decode_ode_type(unsigned char *data, size_t length,
                                     SshBerFreeList list,
                                     void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_eti_type(unsigned char *data, size_t length,
                                     SshBerFreeList list,
                                     void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_real(unsigned char *data, size_t length,
                                 SshBerFreeList list,
                                 void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_embedded(unsigned char *data, size_t length,
                                     SshBerFreeList list,
                                     void *ignore1, void *ignore2)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

/* Decoding of times. */

#define ASSING_INTERVAL_OR_FAIL(where, value, lower, upper)     \
  do {                                                          \
    int __cmp_value = (int) (value);                            \
    if ((__cmp_value < (lower)) || (__cmp_value > (upper)))     \
      goto failed;                                              \
    else                                                        \
      where = (value);                                          \
  } while (0)


/* read milliseconds from tmp[pos], where pos is offset of dot
   starting the millisecond. return number of bytes consumed, -1 on
   failure. */
static int
ber_read_milliseconds(unsigned char *tmp, size_t length,
                      size_t pos,
                      SshBerTime timeval)
{
  int uplimit, leadzero, npos;

  if (pos >= length) return -1;

  /* Read, first count leading zeroes */
  leadzero = 0; uplimit = 1000000;
  while (tmp[pos + 1 + leadzero] &&
         tmp[pos + 1 + leadzero] == '0')
    {
      uplimit /= 10;
      leadzero++;
    }

  if (sscanf((char *)(tmp + pos), ".%u%n", &timeval->msecond, &npos)
      != 1)
    return -1;

  /* Scale into range [0,999999], first down, then up, and check */
  while (timeval->msecond > 1000000) timeval->msecond /= 10;
  while (timeval->msecond &&
         timeval->msecond * 10 < uplimit) timeval->msecond *= 10;

  if (timeval->msecond > 1000000)
    return -1;

  return npos;
}


SshBerStatus
ssh_ber_decode_universal_time(unsigned char *data, size_t length,
                              SshBerFreeList list,
                              void *ptimeval, void *ignore)
{
  size_t pos;
  int rv;
  unsigned char byte, *tmp;
  unsigned int y, m, d, h, min, sec;
  SshBerTime timeval = (SshBerTime )ptimeval;

  if ((tmp = ssh_malloc(length + 1)) == NULL)
    return SSH_BER_STATUS_ERROR;

  /* Convert to a NUL terminated string. */
  memcpy(tmp, data, length);
  tmp[length] = '\0';

  /* Clear. */
  memset(timeval, 0, sizeof(*timeval));

  /* Get as much of the date as initially needed. */
  min = sec = 0;
  rv = sscanf((char *) tmp,
              "%02u%02u%02u%02u%02u%02u", &y, &m, &d, &h, &min, &sec);

  /* We don't care about minutes if not available, however, we do insist
     that 'data' contains year, month, day and hours. That's at
     least reasonable. */
  if (rv < 4)
    goto failed;

  ASSING_INTERVAL_OR_FAIL(timeval->year, y, 0, 65535);
  ASSING_INTERVAL_OR_FAIL(timeval->month, m, 1, 12);
  ASSING_INTERVAL_OR_FAIL(timeval->day, d, 1, 31);
  ASSING_INTERVAL_OR_FAIL(timeval->hour, h, 0, 24);
  ASSING_INTERVAL_OR_FAIL(timeval->minute, min, 0, 60);
  ASSING_INTERVAL_OR_FAIL(timeval->second, sec, 0, 60);

  pos = rv * 2;

  if (pos >= length)
    goto failed;

  /* Set the year correctly. */
  if (timeval->year < 50)
    timeval->year += 2000;
  else
    timeval->year += 1900;

  rv = sscanf((char *)(tmp + pos), "%c", &byte);
  if (rv != 1)
    goto failed;

  if (byte == '.')
    {
      int npos;

      if ((npos = ber_read_milliseconds(tmp, length, pos, timeval)) < 0)
        goto failed;
      else
        pos += npos;
    }

  if (pos >= length)
    goto failed;

  /* Read again the next byte. */
  rv = sscanf((char *)(tmp + pos), "%c", &byte);
  if (rv != 1)
    goto failed;

  if (byte == '+')
    timeval->local = TRUE;
  else
    timeval->local = FALSE;

  if (byte != 'Z')
    {
      if (pos + 1 >= length)
        goto failed;

      if (sscanf((char *) tmp + pos + 1,
                 "%02d%02d", &h, &min) != 2)
        goto failed;

      ASSING_INTERVAL_OR_FAIL(timeval->absolute_hours, h, 0, 24);
      ASSING_INTERVAL_OR_FAIL(timeval->absolute_minutes, min, 0, 60);
    }
  else
    {
      timeval->absolute_hours = 0;
      timeval->absolute_minutes = 0;
    }

  ssh_free(tmp);
  return SSH_BER_STATUS_OK;

 failed:
  ssh_free(tmp);
  return SSH_BER_STATUS_ERROR;
}

SshBerStatus ssh_ber_decode_generalized_time(unsigned char *data,
                                             size_t length,
                                             SshBerFreeList list,
                                             void *ptimeval, void *ignore)
{
  size_t pos;
  unsigned char byte, *tmp;
  int rv;
  unsigned int h, d, m, y, min, sec;
  SshBerTime timeval = (SshBerTime )ptimeval;

  if ((tmp = ssh_malloc(length + 1)) == NULL)
    return SSH_BER_STATUS_ERROR;

  /* Convert to a NUL terminated string. */
  memcpy(tmp, data, length);
  tmp[length] = '\0';

  memset(timeval, 0, sizeof(*timeval));

  min = sec = 0;
  rv = sscanf((char *) tmp,
              "%04u%02u%02u%02u%02u%02u", &y, &m, &d, &h, &min, &sec);

  /* We don't care about minutes if not available, however, we do insist
     that the data contains year, month, day and hours. That's at
     least reasonable. */
  if (rv < 4)
    goto failed;

  ASSING_INTERVAL_OR_FAIL(timeval->year, y, 0, 65536);
  ASSING_INTERVAL_OR_FAIL(timeval->month, m, 1, 12);
  ASSING_INTERVAL_OR_FAIL(timeval->day, d, 1, 31);
  ASSING_INTERVAL_OR_FAIL(timeval->hour, h, 0, 24);
  ASSING_INTERVAL_OR_FAIL(timeval->minute, min, 0, 60);
  ASSING_INTERVAL_OR_FAIL(timeval->second, sec, 0, 60);

  pos = rv * 2 + 2;

  if (pos >= length)
    goto failed;

  rv = sscanf((char *)(tmp + pos), "%c", &byte);
  if (rv != 1)
    goto failed;

  if (byte == '.')
    {
      int npos;

      if ((npos = ber_read_milliseconds(tmp, length, pos, timeval)) < 0)
        goto failed;
      else
        pos += npos;
    }

  /* And update next character, possibly not changed */
  rv = sscanf((char *)(tmp + pos), "%c", &byte);
  if (rv != 1)
    goto failed;

  if (byte == '+')
    timeval->local = TRUE;
  else
    timeval->local = FALSE;

  if (byte != 'Z')
    {
      if (pos + 1 >= length)
        goto failed;

      if (sscanf((char *) tmp + pos + 1,
                 "%02d%02d", &h, &min) != 2)
        goto failed;

      ASSING_INTERVAL_OR_FAIL(timeval->absolute_hours, h, 0, 24);
      ASSING_INTERVAL_OR_FAIL(timeval->absolute_minutes, min, 0, 60);
    }
  else
    {
      timeval->absolute_hours = 0;
      timeval->absolute_minutes = 0;
    }

  ssh_free(tmp);
  return SSH_BER_STATUS_OK;

 failed:
  ssh_free(tmp);
  return SSH_BER_STATUS_ERROR;
}

/* Following should not be implemented. They are just encoded as
   octet-strings.

   {
   numeric, pritable, teletex, videotex, ia5, graphic, visible,
   generic, univesal, unrestricted, bmp
   } string.
*/

/* ber.c */
#endif /* SSHDIST_ASN1 */
