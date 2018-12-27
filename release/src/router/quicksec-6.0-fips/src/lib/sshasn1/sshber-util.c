/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshber.h"
#include "sshasn1.h"
#include "sshmp.h"

#ifdef SSHDIST_ASN1
Boolean ssh_ber_time_set_from_string(SshBerTime b, const char *str)
{
  size_t i;
  char month_str[4], day_postfix[4];
  unsigned int year, month, day, hour, minute, second, rv;
  const char *month_table[13] =
  { "n/a", "jan", "feb", "mar", "apr",
    "may", "jun", "jul", "aug",
    "sep", "oct", "nov", "dec" };

  if (strlen(str) > 1024)
    return FALSE;

  rv = sscanf(str, "%04d %3s %2d%2s, %02d:%02d:%02d",
              &year, month_str, &day, day_postfix,
              &hour, &minute, &second);

  if (rv != 7)
    {
      /* Alternative format given for those who cannot handle readable
         formats. */
      rv = sscanf(str, "%04d/%02d/%02d/%02d:%02d:%02d",
                 &year, &month, &day, &hour, &minute, &second);
      if (rv != 6)
        return FALSE;
    }
  else
    {
      /* Transform the nice format to usual information. */

      for (i = 0; i < strlen(month_str); i++)
        month_str[i] = tolower(((unsigned char *)month_str)[i]);

      for (month = 1; month < 13; month++)
        {
          if (strcmp(month_str, month_table[month]) == 0)
            break;
        }
      if (i >= 13)
        return FALSE;

      /* This is just knit picking? */
      if ((day % 10) == 1 && day != 11 && strcmp(day_postfix, "st") != 0)
        return FALSE;
      if ((day % 10) == 2 && day != 12 && strcmp(day_postfix, "nd") != 0)
        return FALSE;
      if ((day % 10) == 3 && day != 13 && strcmp(day_postfix, "rd") != 0)
        return FALSE;
      if (((day % 10) > 3 || (day % 10) == 0 || (day > 10 && day < 14)) &&
          strcmp(day_postfix, "th") != 0)
        return FALSE;
    }

  /* Make sure that all basic range constraints are met. */
  if (month < 1 || month > 12)
    return FALSE;
  if (day < 1 || day > 31)
    return FALSE;
  if (hour > 23)
    return FALSE;
  if (minute > 59)
    return FALSE;
  if (second > 59)
    return FALSE;

  /* Set up the Ber time. */
  b->year   = year;
  b->month  = month;
  b->day    = day;
  b->hour   = hour;
  b->minute = minute;
  b->second = second;
  b->msecond = 0;
  b->local  = TRUE;
  b->absolute_hours = 0;
  b->absolute_minutes = 0;

  return 1;
}

void ssh_ber_time_to_string(const SshBerTime b, char **str)
{
  const char *months[13] =
  { "n/a", "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec" };
  char *day_postfix = "  ";
  unsigned char buffer[64], msecbuf[16];

  if ((b->day % 10) == 1)
    day_postfix = "st";
  if ((b->day % 10) == 2)
    day_postfix = "nd";
  if ((b->day % 10) == 3)
    day_postfix = "rd";
  if ((b->day % 10) > 3 || (b->day % 10) == 0 ||
      (b->day >= 11 && b->day <= 13))
    day_postfix = "th";

  if (b->month < 1 || b->month > 12)
    {
      *str = NULL;
      return;
    }

  if (b->msecond)
    ssh_snprintf(msecbuf, sizeof(msecbuf), ".%06d", b->msecond);
  else
    msecbuf[0] = '\0';

  /* Assume GMT. */
  ssh_snprintf(buffer, sizeof(buffer), "%04d %s %2d%s, %02d:%02d:%02d%s GMT",
               b->year, months[b->month],
               b->day, day_postfix,
               b->hour, b->minute, (unsigned int)b->second,
               msecbuf);

  /* Do a copy. */
  *str = ssh_strdup(buffer);
}
#endif /* SSHDIST_ASN1 */
