/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Calendar time retrieval and manipulation.
*/

#include "sshincludes.h"
#undef time

#define SSH_DEBUG_MODULE "SshTime"

/* For windows we do not have gettimeofday or anything similar.
   We need to use our own version utilizing the GetSystemTimeAsFileTime. */
#ifdef WINDOWS
void
wingettimeofday(SshInt64 *sec, SshInt64 *usec)
{
  FILETIME ft;
  SshUInt64 result = 0;

  SSH_ASSERT(sec != NULL);
  SSH_ASSERT(usec != NULL);

  GetSystemTimeAsFileTime(&ft);

  result |= ft.dwHighDateTime;
  result <<= 32;

  result |= ft.dwLowDateTime;
  result /= 10;

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  result -= 11644473600000000Ui64;
#else /* defined(_MSC_VER) || defined(_MSC_EXTENSIONS) */
  result -= 11644473600000000ULL;
#endif /* defined(_MSC_VER) || defined(_MSC_EXTENSIONS) */

  *sec = (SshInt64)(result / 1000000UL);
  *usec = (SshInt64)(result % 1000000UL);
}
#endif /* WINDOWS */

/* Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
SshTime ssh_time(void)
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;

  /* This can not fail */
  gettimeofday(&tv, NULL);
  return (SshTime)tv.tv_sec;
#else
  return (SshTime)(time(NULL));
#endif
}

/* Returns seconds and microseconds to 'time' from epoch
   "January 1 1970, 00:00:00 UTC".  This
   implementation is Y2K compatible as far as system provided time_t
   is such.  However, since systems seldomly provide with more than 31
   meaningful bits in time_t integer, there is a strong possibility
   that this function needs to be rewritten before year 2038.  No
   interface changes are needed in reimplementation. */
void ssh_get_time_of_day(SshTimeValue tptr)
{
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;

  /* This can not fail */
  gettimeofday(&tv, NULL);

  tptr->seconds = (SshInt64) tv.tv_sec;
  tptr->microseconds = (SshInt64) tv.tv_usec;

#else /* HAVE_GETTIMEOFDAY */
#ifdef WINDOWS
  wingettimeofday(&tptr->seconds, &tptr->microseconds);
#else /* WINDOWS */
  tptr->seconds = (SshInt64) (time(NULL));
  tptr->microseconds = (SshInt64) 0;
#endif /* WINDOWS */
#endif /* HAVE_GETTIMEOFDAY */
  return;
}


/* eof (sshtime.c) */
