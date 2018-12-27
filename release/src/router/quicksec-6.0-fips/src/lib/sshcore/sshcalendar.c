/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Calendar time retrieval and manipulation.
*/

#include "sshincludes.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshCalendar"


/* Returns seconds that local timezone is east from the UTC meridian
   and boolean which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
void ssh_get_local_timezone(SshTime tv,
                            SshInt32 *utc_offset,
                            Boolean *dst);

/* Array that tells how many days each month of the year have.
   Variable monthday[1] has to be fixed to 28 or 29 depending
   on the year we are referring to. */
static const SshUInt8 monthdays[12] = { 31, 28, 31, 30, 31, 30,
                                        31, 31, 30, 31, 30, 31 };

/* Arrays of weekday and month names.  These are used by
   ssh_readable_time_string to generate ctime(3) like
   output string from the SshTime value. */
static const SshCharPtr ssh_time_abbr_day[] =
{
  "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", NULL
};

static const SshCharPtr ssh_time_abbr_month[] =
{
  "Jan", "Feb", "Mar", "Apr",
  "May", "Jun", "Jul", "Aug",
  "Sep", "Oct", "Nov", "Dec",
  NULL
};

/* Check if a year is a leap year (i.e. 29 days in February, 366 days in year)
   according to gregorian calendar.
     - Every year divisible by 400 is a leap year.
     - Year divisible by 4 is a leap year, if it is NOT divisible by 100.
     - Otherwise year is not a leap year.
*/
#define SSH_IS_LEAP_YEAR(y) ((((y) % 400) == 0) || \
                             ((((y) % 4) == 0) && (((y) % 100) != 0)))


/* Fills the calendar structure according to ``current_time''.  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void ssh_calendar_time(SshTime input_time,
                       SshCalendarTime calendar_ret,
                       Boolean local_time)
{
  /*
   * Naive implementation of calendar time.  This implementation
   * ignores timezones and leap seconds but is otherwise
   * (way beyond) Y2K compatible.
   * This implementation follows the Gregorian calendar even before
   * the Gregorian calendar was invented.  This is really not right
   * if we want to present dates before the 17th century.
   */
  SshInt64 day;
  SshInt64 sec;

  if (local_time)
    {
      ssh_get_local_timezone(input_time,
                             &(calendar_ret->utc_offset),
                             &(calendar_ret->dst));
      input_time += (SshTime)(calendar_ret->utc_offset);
    }
  else
    {
      calendar_ret->utc_offset = 0;
      calendar_ret->dst = FALSE;
    }
  if (input_time >= 0)
    {
      /* Calculate day of the year and second of the day.  Weekday
         calculation is based on the fact that 1.1.1970 (the epoch day)
         was Thursday. */
      day = input_time / 86400;
      sec = input_time % 86400;
      calendar_ret->weekday = (SshUInt8)((day + 4) % 7);
    }
  else
    {
      /* Ensure that we have positive day of the year, second of the
         day and day of the week also if we have negative time value
         measured from the epoch. */
      day = (-(((-input_time) - 1) / 86400)) - 1;
      sec = 86399 - (((-input_time) - 1) % 86400);
      calendar_ret->weekday = (SshUInt8)(6 - (((-day) + 2) % 7));
    }
  /* Start calculation from the epoch year.  If we are on the negative side
     or more than 400 years beyond 1970, we adjust the year so that we
     need to iterate only years from the last even 400 years.
     146097 is the number of days in each 400 years in Gregorian era. */
  calendar_ret->year = 1970;
  if (day < 0)
    {
      day = -day;
      calendar_ret->year -= (SshUInt32)(((day / 146097) * 400) + 400);
      day = -((day % 146097) - 146097);
    }
  else if (day >= 146097)
    {
      calendar_ret->year += (SshUInt32)((day / 146097) * 400);
      day = day % 146097;
    }
  /* Iterate years until we have number of days that fits in the
     ``current'' year. */
  do {
    if (day < (365 + (SSH_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0)))
      break;
    day -= 365 + (SSH_IS_LEAP_YEAR(calendar_ret->year) ? 1 : 0);
    calendar_ret->year++;
  } while (1);
  /* There is no year 0. */
  if (calendar_ret->year <= 0)
    calendar_ret->year -= 1;
  /* Day of the year we got as a by product of year calculation. */
  calendar_ret->yearday = (SshUInt16)day;
  /* Now we can trivially calculate seconds, minutes and hours. */
  calendar_ret->second = (SshUInt8)(sec % 60);
  calendar_ret->minute = (SshUInt8)((sec % 3600) / 60);
  calendar_ret->hour = (SshUInt8)(sec / 3600);
  /* Now we iterate the month.  Leap years make this a bit bitchy. */
  calendar_ret->month = 0;
  do {
    SSH_ASSERT(calendar_ret->month < 12);
    if (day < (monthdays[calendar_ret->month] +
               (((calendar_ret->month == 1) &&
                 (SSH_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0)))
      break;
    day -= (monthdays[calendar_ret->month] +
            (((calendar_ret->month == 1) &&
              (SSH_IS_LEAP_YEAR(calendar_ret->year))) ? 1 : 0));
    calendar_ret->month++;
  } while(1);
  /* Day of the month is a leftover from the month calculation. */
  calendar_ret->monthday = (SshUInt8)(day + 1);
  return;
}

int ssh_time_format(unsigned char *buf, int buf_size, SshTime input_time)
{
  struct SshCalendarTimeRec calendar[1];

  ssh_calendar_time(input_time, calendar, FALSE);
  return ssh_snprintf(buf, buf_size, "%04d%02d%02d%02d%02d%02d",
                      (int)calendar->year,
                      (int)calendar->month + 1,
                      (int)calendar->monthday,
                      (int)calendar->hour,
                      (int)calendar->minute,
                      (int)calendar->second);
}

/* Return time string in RFC-2550 compatible format.  Returned string
   is allocated with ssh_xmalloc and has to be freed with ssh_xfree by
   the caller.  This implementation is only a subset of RFC-2550 and
   is valid only between years 0-9999.  Fix this before Y10K problem
   is imminent. */
char *ssh_time_string(SshTime input_time)
{
  unsigned char temp[100];

  ssh_time_format(temp, sizeof(temp), input_time);

  return ssh_strdup((char *)temp);
}

/* Format time string in RFC-2550 compatible format as snprintf renderer. The
   datum points to the SshTime. */
int ssh_time_render(unsigned char *buf, int buf_size, int precision,
                    void *datum)
{
  SshTime *t = datum;
  int len;
  len = ssh_time_format(buf, buf_size + 1, *t);
  if (len + 1 >= buf_size)
    return buf_size + 1;
  return len;
}


/* Format time string in RFC-2550 compatible format as snprintf renderer. The
   datum points to the memory buffer having the 32-bit long time in seconds
   from the epoch in the network byte order. */
int ssh_time32buf_render(unsigned char *buf, int buf_size, int precision,
                    void *datum)
{
  unsigned char *ptr = datum;
  int len;

  len = ssh_time_format(buf, buf_size + 1, SSH_GET_32BIT(ptr));
  if (len + 1 >= buf_size)
    return buf_size + 1;
  return len;
}

char *ssh_readable_time_string(SshTime input_time, Boolean local_time)
{
  struct SshCalendarTimeRec calendar[1];
  unsigned char zoneid[8];
  unsigned char temp[100];

  ssh_calendar_time(input_time, calendar, local_time);

  if (calendar->utc_offset == 0)
    {
      zoneid[0] = '\0';
    }
  else if (calendar->utc_offset > 0)
    {
      ssh_snprintf(zoneid, sizeof (zoneid), " +%02d%02d",
                   (int)((calendar->utc_offset / 3600) % 100),
                   (int)((calendar->utc_offset / 60) % 60));
    }
  else
    {
      ssh_snprintf(zoneid, sizeof (zoneid), " -%02d%02d",
                   (int)(((- calendar->utc_offset) / 3600) % 100),
                   (int)(((- calendar->utc_offset) / 60) % 60));
    }

  ssh_snprintf(temp, sizeof(temp), "%s %s %02d %04d %02d:%02d:%02d%s",
               ssh_time_abbr_day[calendar->weekday % 7],
               ssh_time_abbr_month[calendar->month % 12],
               (int)calendar->monthday,
               (int)calendar->year,
               (int)calendar->hour,
               (int)calendar->minute,
               (int)calendar->second,
               zoneid);
  return ssh_strdup(temp);
}

/* Returns seconds that local timezone is east from the UTC meridian
   and boolean which is TRUE if DST is in effect.
   This one is system dependent and yet even vulnerable to Y2K bug.
   Anyway, this is used only to retrieve current timezone.  If
   localtime(3) function freaks out with this call, we return just zero
   and assume that our localtime is UTC. */
void ssh_get_local_timezone(SshTime tv,
                            SshInt32 *utc_offset,
                            Boolean *dst)
{
#if ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME)
  struct tm *tm;
#if defined(_REENTRANT) && defined(__sun__) && defined(__svr4__)
  struct tm tms;
#endif
  time_t t;
  struct SshCalendarTimeRec ct[1];

  /* We trust localtime(3) for dst interpretation 1970-2037.
     Before this timeframe, we just check localtime for
     Jan 1 1998, which should work more or less everywhere.
     After 2037 we normalize this date to year 2037 and
     call system localtime(3) for that. */
  if ((tv > ((SshTime)0)) && (tv < ((SshTime)2145916800)))
    {
      t = (time_t)tv;
    }
  else if (tv >= ((SshTime)2145916800))
    {
      ssh_calendar_time(tv, ct, FALSE);
      if (SSH_IS_LEAP_YEAR(ct->year))
        t = (time_t)2082758400; /* 1.1.2036 */
      else
        t = (time_t)2114380800; /* 1.1.2037 */
      t += ((((time_t)86400) * ((time_t)(ct->yearday))) +
            (((time_t)3600) * ((time_t)(ct->hour))) +
            (((time_t)60) * ((time_t)(ct->minute))) +
            ((time_t)(ct->second)));
    }
  else
    {
      t = (time_t)883656061; /* Thu Jan 1 12:01:01 1998 UTC */
    }
#if defined(_REENTRANT) && defined(__sun__) && defined(__svr4__)
  tm = localtime_r(&t, &tms);
#else
#undef localtime
  tm = localtime(&t);
#endif
#ifdef HAVE_TM_GMTOFF_IN_STRUCT_TM
  if ((tm != NULL) &&
      (tm->tm_gmtoff >= (-50400)) &&
      (tm->tm_gmtoff <= 50400))
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)(tm->tm_gmtoff);
    }
  else
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)0;
    }
#else /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
#ifdef HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM
  if ((tm != NULL) &&
      (tm->__tm_gmtoff__ >= (-50400)) &&
      (tm->__tm_gmtoff__ <= 50400))
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)(tm->__tm_gmtoff__);
    }
  else
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)0;
    }
#else /* HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM */
#ifdef HAVE_EXTERNAL_TIMEZONE
  if ((timezone >= (-50400))  && (timezone <= 50400))
    {
      if (utc_offset != NULL)
      {
        *utc_offset = (SshInt32) - timezone;
#ifdef HAVE_TM_ISDST_IN_STRUCT_TM
        /* 'timezone' is the difference between
           standard time and utc. */
        if (tm != NULL)
          *utc_offset += (tm->tm_isdst != 0 ? 3600 : 0);
        else
          *utc_offset = (SshUInt32)0;
#endif /* HAVE_TM_ISDST_IN_STRUCT_TM */
      }
    }
  else
    {
      if (utc_offset != NULL)
        *utc_offset = (SshInt32)0;
    }
#else /* HAVE_EXTERNAL_TIMEZONE */
  if (utc_offset != NULL)
    *utc_offset = (SshInt32)0;
#endif /* HAVE_EXTERNAL_TIMEZONE */
#endif /* HAVE_OLD_TM_GMTOFF_IN_STRUCT_TM */
#endif /* HAVE_TM_GMTOFF_IN_STRUCT_TM */
#ifdef HAVE_TM_ISDST_IN_STRUCT_TM
  if (tm != NULL)
    {
      if (dst != NULL)
        *dst = (tm->tm_isdst != 0);
    }
  else
    {
      if (dst != NULL)
        *dst = FALSE;
    }
#else /* HAVE_TM_ISDST_IN_STRUCT_TM */
  if (dst != NULL)
    *dst = FALSE;
#endif /* HAVE_TM_ISDST_IN_STRUCT_TM */
#else /* ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME) */
  if (utc_offset != NULL)
    *utc_offset = (SshInt32)0;
  if (dst != NULL)
    *dst = FALSE;
#endif /* ! defined (USE_SSH_INTERNAL_LOCALTIME) && defined (HAVE_LOCALTIME) */
}

/* Convert SshCalendarTime to SshTime. If the dst is set to TRUE then daylight
   saving time is assumed to be set, if dst field is set to FALSE then it is
   assumed to be off. It if it is set to -1 then the function tries to find out
   if the dst was on or off at the time given.

   Weekday and yearday fields are ignored in the conversion, but filled with
   approriate values during the conversion. All other values are normalized to
   their normal range during the conversion.

   If the local_time is set to TRUE then dst and utc_offset values
   are ignored.

   If the time cannot be expressed as SshTime this function returns FALSE,
   otherwise returns TRUE. */
Boolean ssh_make_time(SshCalendarTime calendar_time, SshTime *time_return,
                      Boolean local_time)
{
  SshCalendarTimeStruct test_time;
  SshTime estimate;

  SSH_DEBUG(SSH_D_MIDSTART, ("Original time is %04d-%02d-%02d %02d:%02d:%02d",
                             (int) calendar_time->year,
                             (int) calendar_time->month + 1,
                             (int) calendar_time->monthday,
                             (int) calendar_time->hour,
                             (int) calendar_time->minute,
                             (int) calendar_time->second));

  /* Normalize values first */
  while (calendar_time->second > 59)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Seconds too large, adjusting %d",
                                 calendar_time->second));
      calendar_time->second -= 60;
      calendar_time->minute++;
    }
  while (calendar_time->minute > 59)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Minutes too large, adjusting %d",
                                 calendar_time->minute));
      calendar_time->minute -= 60;
      calendar_time->hour++;
    }
  while (calendar_time->hour > 23)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Hours too large, adjusting %d",
                                 calendar_time->hour));
      calendar_time->hour -= 24;
      calendar_time->monthday++;
    }
  do {
    int days_per_month;

    while (calendar_time->month > 11)
      {
        SSH_DEBUG(SSH_D_UNCOMMON, ("Month too large, adjusting %d",
                                   calendar_time->month));
        calendar_time->month -= 12;
        calendar_time->year++;
      }
    days_per_month = monthdays[calendar_time->month] +
      ((calendar_time->month == 1 &&
        SSH_IS_LEAP_YEAR(calendar_time->year)) ? 1 : 0);
    if (calendar_time->monthday > days_per_month)
      {
        SSH_DEBUG(SSH_D_UNCOMMON, ("Month day too large, adjusting %d",
                                   calendar_time->monthday));
        calendar_time->monthday -= days_per_month;
        calendar_time->month++;
      }
    else if (calendar_time->monthday == 0)
      {
        SSH_DEBUG(SSH_D_UNCOMMON, ("Month day zero, adjusting %d",
                                   calendar_time->monthday));
        if (calendar_time->month == 0)
          {
            calendar_time->month = 11;
            calendar_time->year--;
          }
        else
          {
            calendar_time->month--;
          }
        calendar_time->monthday = monthdays[calendar_time->month] +
          ((calendar_time->month == 1 &&
            SSH_IS_LEAP_YEAR(calendar_time->year)) ? 1 : 0);
      }
    else
      {
        break;
      }
  } while (1);

  SSH_DEBUG(SSH_D_LOWOK, ("Adjusted time is %04d-%02d-%02d %02d:%02d:%02d",
                          (int) calendar_time->year,
                          (int) calendar_time->month + 1,
                          (int) calendar_time->monthday,
                          (int) calendar_time->hour,
                          (int) calendar_time->minute,
                          (int) calendar_time->second));

  /* Calculate estimate */
  estimate = calendar_time->monthday - 1 +
    30 * calendar_time->month +
    365 * ((SshTime)calendar_time->year - 1970) +
    ((calendar_time->year - 1970) / 4);
  estimate *= 24;
  estimate += calendar_time->hour;
  estimate *= 60;
  estimate += calendar_time->minute;
  estimate *= 60;
  estimate += calendar_time->second;

  do {
    SSH_DEBUG(SSH_D_LOWOK, ("Estimate is %ld", (unsigned long) estimate));
    ssh_calendar_time(estimate, &test_time, FALSE);
    SSH_DEBUG(SSH_D_LOWOK, ("Compare time is %04d-%02d-%02d %02d:%02d:%02d",
                            (int) test_time.year,
                            (int) test_time.month + 1,
                            (int) test_time.monthday,
                            (int) test_time.hour,
                            (int) test_time.minute,
                            (int) test_time.second));

    if (test_time.year == calendar_time->year &&
        test_time.month == calendar_time->month &&
        test_time.monthday == calendar_time->monthday &&
        test_time.hour == calendar_time->hour &&
        test_time.minute == calendar_time->minute &&
        test_time.second == calendar_time->second)
      break;
    if (test_time.year == calendar_time->year &&
        test_time.month == calendar_time->month &&
        test_time.monthday == calendar_time->monthday)
      {
        if (test_time.hour != calendar_time->hour)
          estimate += (calendar_time->hour - test_time.hour) * 3600;
        if (test_time.minute != calendar_time->minute)
          estimate += (calendar_time->minute - test_time.minute) * 60;
        if (test_time.hour != calendar_time->hour)
          estimate += (calendar_time->second - test_time.second);
        continue;
      }
    if (test_time.year != calendar_time->year)
      {
        estimate += (calendar_time->year - test_time.year) * 365 * 86400;
        continue;
      }
    if (test_time.month != calendar_time->month)
      {
        estimate += (calendar_time->month - test_time.month) * 28 * 86400;
        continue;
      }
    if (test_time.monthday != calendar_time->monthday)
      {
        estimate += (calendar_time->monthday - test_time.monthday) * 86400;
        continue;
      }
    ssh_fatal("Internal error in ssh_make_time");
  } while (1);

  if (local_time)
    {
      SshInt32 utc_offset;
      Boolean dst;

      ssh_get_local_timezone(estimate, &utc_offset, &dst);
      if (utc_offset != calendar_time->utc_offset && calendar_time->dst == -1)
        {
          SSH_DEBUG(SSH_D_UNCOMMON, ("Utc offset in input does not match "
                                     "current system timezone. Dst rules "
                                     "might be incorrect"));
        }
      SSH_DEBUG(SSH_D_LOWOK, ("Adding timezone informartion %d seconds",
                              (int) calendar_time->utc_offset));
      estimate += calendar_time->utc_offset;
      if (calendar_time->dst == TRUE ||
          (calendar_time->dst == -1 &&
           dst))
        estimate += 3600;
    }
  SSH_DEBUG(SSH_D_MIDSTART, ("Result is %ld", (unsigned long) estimate));
  *time_return =  estimate;
  calendar_time->yearday = test_time.yearday;
  calendar_time->weekday = test_time.weekday;
  return TRUE;
}

