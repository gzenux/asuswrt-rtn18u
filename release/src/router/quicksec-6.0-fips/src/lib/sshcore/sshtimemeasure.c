/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Real time measuring.
*/

#include "sshincludes.h"

#ifdef WIN32
#include <winbase.h>
#include <sys/timeb.h>
#endif /* WIN32 */

#ifdef CHORUS
#include <exec/chTime.h>
#endif

#include "sshtimemeasure.h"

#define SSH_DEBUG_MODULE "SshTimeMeasure"

/*
 * FOLLOWING SECTION HAS CODE TO EMULATE DIFFERENT TIME MEASUREMENT
 * FUNCTIONS WITH UNIX GETTIMEOFDAY.  THIS IS FOR TESTING ONLY.
 */
/* Define this to test Windows specific code in Unix. */
#undef TEST_WIN32
/*#define TEST_WIN32 1*/

/* Define this to test Chorus specific code in Unix. */
#undef TEST_CHORUS
/*#define TEST_CHORUS 1*/

/* Emulate Windows time measurement in Unix (for testing only!) */
#if TEST_WIN32
#if defined (WIN32)
/* No need to emulate Windows in Windows. */
#elif defined (HAVE_GETTIMEOFDAY)
struct _timeb {
  long time;
  long millitm;
};
void _ftime(struct _timeb *tb)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  tb->time = tv.tv_sec;
  tb->millitm = tv.tv_usec / 1000;
  return;
}
#define WIN32 1
#else /* !WIN32 && !HAVE_GETTIMEOFDAY */
#error "Cannot emulate Windows time measurement in this system."
#endif /* !WIN32 && !HAVE_GETTIMEOFDAY */
#endif /* TEST_WIN32 */

/* Emulate Chorus time measurement in Unix (for testing only!) */
#ifdef TEST_CHORUS
#if defined (CHORUS)
/* No need to emulate Chorus in Chorus. */
#elif defined (HAVE_GETTIMEOFDAY)
typedef struct {
  long tmSec;
  long tmNSec;
} KnTimeVal;
#define K_OK 0
int sysTime (KnTimeVal *time)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  time->tmSec = tv.tv_sec;
  time->tmNSec = tv.tv_usec * 1000;
  return K_OK;
}
int sysTimeGetRes(KnTimeVal *time)
{
  time->tmSec = 0;
  time->tmNSec = 1000;
  return K_OK;
}
#define CHORUS 1
#else /* !CHORUS && !HAVE_GETTIMEOFDAY */
#error "Cannot emulate Chorus time measurement in this system."
#endif /* !CHORUS && !HAVE_GETTIMEOFDAY */
#endif /* TEST_CHORUS */
/*
 * THE TEST SECTION ENDS HERE.
 */

#if defined (SSHUINT64_IS_64BITS) && defined (WIN32)

/* Windows compiler can't cast directly from 64-bit unsigned to double. */
#define SSH_UINT64_TO_SSH_TIME_T(x)                                     \
       ((((SshTimeT)((SshUInt32)(((x) >> 32) & 0xffffffff))) *          \
         (((SshTimeT)(65536)) * ((SshTimeT)(65536)))) +                 \
        ((SshTimeT)((SshUInt32)((x) & 0xffffffff))))

#else /* SSHUINT64_IS_64BITS && WIN32 */

/* It should work this way everywhere. */
#define SSH_UINT64_TO_SSH_TIME_T(x) ((SshTimeT)(x))

#endif /* SSHUINT64_IS_64BITS && WIN32 */

/* Return nonzero, if the first second-nanosecond pair is greater (later)
   than the second one. */
#define SSH_TIME_MEASURE_GT(sec1, nsec1, sec2, nsec2) \
             ((sec1) > (sec2)) || (((sec1) == (sec2)) && ((nsec1) > (nsec2)))

/* Return nonzero, if the first second-nanosecond pair is less (earlier)
   than the second one. */
#define SSH_TIME_MEASURE_LT(sec1, nsec1, sec2, nsec2) \
             ((sec1) < (sec2)) || (((sec1) == (sec2)) && ((nsec1) < (nsec2)))

/* Return nonzero, if first second-nanosecond pair is equal to
   the second one. */
#define SSH_TIME_MEASURE_EQ(sec1, nsec1, sec2, nsec2) \
             (((sec1) == (sec2)) && ((nsec1) == (nsec2)))

/*
 * Init time measure structure to initial
 * nonrunning state with zero cumulated time.
 * This can be used instead of ssh_time_measure_allocate,
 * if the timer structure is statically allocated by
 * the application.
 */
void ssh_time_measure_init(SshTimeMeasure timer)
{
  if (timer)
    {
      timer->running = FALSE;
      timer->start.seconds = 0;
      timer->start.nanoseconds = 0;
      timer->cumulated.seconds = 0;
      timer->cumulated.nanoseconds = 0;
    }
  return;
}

/*
 * Allocates and returns a new nonrunning timer object.
 */
SshTimeMeasure ssh_time_measure_allocate(void)
{
  SshTimeMeasure timer = ssh_calloc(1, sizeof (struct SshTimeMeasureRec));

  if (timer)
    {
      ssh_time_measure_init(timer);
    }
  return timer;
}

/*
 * Frees an allocated timer object.
 * Returns the time (in seconds), that timer
 * has been running.
 */
void ssh_time_measure_free(SshTimeMeasure timer)
{
  ssh_free(timer);
  return;
}

/*
 * Start the timer.
 */
void ssh_time_measure_start(SshTimeMeasure timer)
{
  SSH_ASSERT(timer != NULL);
  if (ssh_time_measure_running(timer))
    return;
  ssh_time_measure_system_time(&(timer->start));
  timer->running = TRUE;
  return;
}

/*
 * Stop the timer.
 */
void ssh_time_measure_stop(SshTimeMeasure timer)
{
  struct SshTimeValRec stop;

  SSH_ASSERT(timer != NULL);
  if (! ssh_time_measure_running(timer))
    return;
  ssh_time_measure_system_time(&stop);
  ssh_time_measure_difference(&stop, &(timer->start), &stop);
  ssh_time_measure_add(&(timer->cumulated), &(timer->cumulated), &stop);
  timer->running = FALSE;
  return;
}

/*
 * Return TRUE if timer is running.
 */
Boolean ssh_time_measure_running(SshTimeMeasure timer)
{
  SSH_ASSERT(timer != NULL);
  return timer->running;
}

/*
 * Reset the timer to zero.
 * If timer is running before this call, the timer runs
 * also after reset.
 */
void ssh_time_measure_reset(SshTimeMeasure timer)
{
  ssh_time_measure_set_value(timer, 0, 0);
  return;
}

/*
 * Set the timer to given value in seconds and nanoseconds (10e-9s).
 * If timer is running before this call, the timer runs
 * also after set operation.
 */
void ssh_time_measure_set_value(SshTimeMeasure timer,
                                SshUInt64 seconds,
                                SshUInt32 nanoseconds)
{
  Boolean restart;

  SSH_ASSERT(timer != NULL);
  if (ssh_time_measure_running(timer))
    {
      restart = TRUE;
      ssh_time_measure_stop(timer);
    }
  else
    {
      restart = FALSE;
    }
  ssh_time_measure_init(timer);
  timer->cumulated.seconds = seconds;
  timer->cumulated.nanoseconds = nanoseconds;
  if (restart)
    ssh_time_measure_start(timer);
  return;
}

/*
 * Get the cumulated running time of the timer.
 * Timer can be either runnung or stopped.
 */
void ssh_time_measure_get_value(SshTimeMeasure timer,
                                SshUInt64 *seconds,
                                SshUInt32 *nanoseconds)
{
  struct SshTimeMeasureRec tmp_timer = *timer;

  ssh_time_measure_stop(&tmp_timer);
  if (seconds != NULL)
    *seconds = tmp_timer.cumulated.seconds;
  if (nanoseconds != NULL)
    *nanoseconds = tmp_timer.cumulated.nanoseconds;
  return;
}

/*
 * Return a time stamp from timer.  Values returned by this function
 * never overwrap.  Instead if maximum timer value is exceeded,
 * SSH_TIME_STAMP_MAX is always returned.
 */
SshUInt64 ssh_time_measure_stamp(SshTimeMeasure timer,
                                 SshTimeGranularity granularity)
{
  SshUInt64 seconds;
  SshUInt32 nanoseconds;

  ssh_time_measure_get_value(timer, &seconds, &nanoseconds);
  switch (granularity)
    {
    case SSH_TIME_GRANULARITY_NANOSECOND:
#ifdef SSHUINT64_IS_64BITS



#else /* SSHUINT64_IS_64BITS */
      if (SSH_TIME_MEASURE_GT(seconds, nanoseconds,
                              4, 294967295) > 0)
        return SSH_TIME_STAMP_MAX;
#endif /* SSHUINT64_IS_64BITS */
      return ((((SshUInt64)seconds) * ((SshUInt64)1000000000)) +
              ((SshUInt64)nanoseconds));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MICROSECOND:
#ifdef SSHUINT64_IS_64BITS



#else /* SSHUINT64_IS_64BITS */
      if (SSH_TIME_MEASURE_GT(seconds, nanoseconds,
                              4294, 967295999) > 0)
        return SSH_TIME_STAMP_MAX;
#endif /* SSHUINT64_IS_64BITS */
      return ((((SshUInt64)seconds) * ((SshUInt64)1000000)) +
              (((SshUInt64)nanoseconds) / ((SshUInt64)1000)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MILLISECOND:
#ifdef SSHUINT64_IS_64BITS



#else /* SSHUINT64_IS_64BITS */
      if (SSH_TIME_MEASURE_GT(seconds, nanoseconds,
                              4294967, 295999999) > 0)
        return SSH_TIME_STAMP_MAX;
#endif /* SSHUINT64_IS_64BITS */
      return ((((SshUInt64)seconds) * ((SshUInt64)1000)) +
              (((SshUInt64)nanoseconds) / ((SshUInt64)1000000)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_SECOND:
      return seconds;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MINUTE:
      return seconds / 60;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_HOUR:
      return seconds / (60 * 60);
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_DAY:
      return seconds / (60 * 60 * 24);
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_WEEK:
      return seconds / (60 * 60 * 24 * 7);
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MONTH_SIDEREAL:
      return seconds / 2360592;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MONTH_SYNODIC:
      return seconds / 2551443;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_ANOMALISTIC:
      return seconds / 31558433;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_TROPICAL:
      return seconds / 31556926;
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_SIDEREAL:
      return seconds / 31558149;
      /*NOTREACHED*/

    default:
      ssh_warning("ssh_time_measure_stamp: Bad granularity.");
      return SSH_TIME_STAMP_MAX;
      /*NOTREACHED*/
    }
  /*NOTREACHED*/
}

/*
 * Get the cumulated running time of the timer in seconds.
 * Be aware that depending on SshTimeT, timer can overwrap
 * at some point.
 */
SshTimeT ssh_time_measure_get(SshTimeMeasure timer,
                              SshTimeGranularity granularity)
{
  SshUInt64 seconds;
  SshUInt32 nanoseconds;

  ssh_time_measure_get_value(timer, &seconds, &nanoseconds);
  switch (granularity)
    {
    case SSH_TIME_GRANULARITY_NANOSECOND:
      return (((SSH_UINT64_TO_SSH_TIME_T(seconds)) * (SshTimeT)1000000000) +
              (((SshTimeT)nanoseconds)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MICROSECOND:
      return (((SSH_UINT64_TO_SSH_TIME_T(seconds)) * (SshTimeT)1000000) +
              (((SshTimeT)nanoseconds) / (SshTimeT)1000));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MILLISECOND:
      return (((SSH_UINT64_TO_SSH_TIME_T(seconds)) * (SshTimeT)1000) +
              (((SshTimeT)nanoseconds) / (SshTimeT)1000000));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_SECOND:
      return (((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
              (((SshTimeT)nanoseconds) / (SshTimeT)1000000000));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MINUTE:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)60));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_HOUR:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)(60 * 60)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_DAY:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)(60 * 60 * 24)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_WEEK:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)(60 * 60 * 24 * 7)));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MONTH_SIDEREAL:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)2360592));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_MONTH_SYNODIC:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)2551443));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_ANOMALISTIC:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)31558433));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_TROPICAL:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)31556926));
      /*NOTREACHED*/

    case SSH_TIME_GRANULARITY_YEAR_SIDEREAL:
      return ((((SSH_UINT64_TO_SSH_TIME_T(seconds))) +
               (((SshTimeT)nanoseconds) / (SshTimeT)1000000000)) /
              ((SshTimeT)31558149));
      /*NOTREACHED*/

    default:
      ssh_warning("ssh_time_measure_stamp: Bad granularity.");
      return (SshTimeT)0;
      /*NOTREACHED*/
    }
  /*NOTREACHED*/
}

void ssh_time_measure_granularity(SshUInt64 *seconds,
                                  SshUInt32 *nanoseconds)

{
  struct SshTimeValRec granularity;
  ssh_time_measure_system_granularity_time(&granularity);
  if (seconds)
    *seconds = granularity.seconds;
  if (nanoseconds)
    *nanoseconds = granularity.nanoseconds;
}

/*
 * Calculate difference between time values beg and end and store result
 * to ret.
 */
void ssh_time_measure_difference(SshTimeVal ret,
                                 SshTimeVal beg,
                                 SshTimeVal end)
{
  SSH_ASSERT(beg != NULL);
  SSH_ASSERT(end != NULL);
  if (SSH_TIME_MEASURE_LT(end->seconds, end->nanoseconds,
                          beg->seconds, beg->nanoseconds))
    {
      SSH_DEBUG(5, ("Negative time difference: beg(%lu %lu) > end(%lu %lu).",
                    (unsigned long)beg->seconds,
                    (unsigned long)beg->nanoseconds,
                    (unsigned long)end->seconds,
                    (unsigned long)end->nanoseconds));
      if ((end->seconds + 20) < beg->seconds)
        ssh_warning("ssh_time_measure_difference: Negative difference.");
      if (ret != NULL)
        {
          ret->seconds = 0;
          ret->nanoseconds = 0;
        }
      return;
    }
  if (ret == NULL)
    return;

  if (beg->nanoseconds <= end->nanoseconds)
    {
      ret->seconds = end->seconds - beg->seconds;
      ret->nanoseconds = end->nanoseconds - beg->nanoseconds;
    }
  else
    {
      ret->seconds = end->seconds - beg->seconds - 1;
      ret->nanoseconds = (((SshUInt32)1000000000) +
                          (end->nanoseconds - beg->nanoseconds));
    }
  return;
}

/*
 * Add time values tv1 and tv2 together and store result to
 * ret (if ret != NULL).
 */
void ssh_time_measure_add(SshTimeVal ret,
                          SshTimeVal tv1,
                          SshTimeVal tv2)
{
  SSH_ASSERT(tv1 != NULL);
  SSH_ASSERT(tv2 != NULL);
  if (ret == NULL)
    return;
  ret->seconds = tv1->seconds + tv2->seconds;
  ret->nanoseconds = tv1->nanoseconds + tv2->nanoseconds;
  if (ret->nanoseconds >= (SshUInt32)1000000000)
    {
      ret->nanoseconds -= (SshUInt32)1000000000;
      ret->seconds++;
    }
  return;
}

/*
 * A function implementing system time queries for different platforms.
 * Be aware that granularity of time measurement may vary on different
 * hardware and operating systems.  Returns FALSE, if system time can't
 * be retrieved (i.e. system call fails).  This function returns time
 * measured from arbitrary moment in the past.  This can be time of
 * last boot or some other random epoch.
 */
Boolean ssh_time_measure_system_time(SshTimeVal timeval)
{
#if defined(WIN32)
  struct _timeb tv;
#elif defined(CHORUS)
  KnTimeVal tv;
#elif defined(HAVE_GETTIMEOFDAY)
  struct timeval tv;
#elif defined(VXWORKS)
  struct timespec tp = { 0 };
#else /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */
  SshTime tv;
#endif /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */

#if defined(WIN32)
  _ftime(&tv);
  if (timeval != NULL)
    {
      timeval->seconds = (SshUInt64)tv.time;
      timeval->nanoseconds = ((SshUInt32)tv.millitm) * 1000000;
    }
  return TRUE;
#elif defined(CHORUS)
  if (sysTime(&tv) == K_OK)
    {
      if (timeval != NULL)
        {
          timeval->seconds = (SshUInt64)tv.tmSec;
          timeval->nanoseconds = (SshUInt32)tv.tmNSec;
        }
      return TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_system_time: sysTime failed.");
      if (timeval != NULL)
        {
          timeval->seconds = 0;
          timeval->nanoseconds = 0;
        }
      return FALSE;
    }
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(&tv, NULL) == 0)
    {
      if (timeval != NULL)
        {
          timeval->seconds = (SshUInt64)tv.tv_sec;
          timeval->nanoseconds = ((SshUInt32)tv.tv_usec) * 1000;
        }
      return TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_system_time: gettimeofday failed.");
      if (timeval != NULL)
        {
          timeval->seconds = 0;
          timeval->nanoseconds = 0;
        }
      return FALSE;
    }
#elif defined(VXWORKS)
  if (clock_gettime(CLOCK_REALTIME, &tp) == OK)
    {
      if (timeval != NULL)
        {
          timeval->seconds = (SshUInt64)tp.tv_sec;
          timeval->nanoseconds = (SshUInt32)tp.tv_nsec;
        }
      return TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_system_time: clock_gettime failed.");
      if (timeval != NULL)
        {
          timeval->seconds = 0;
          timeval->nanoseconds = 0;
        }
      return FALSE;
    }
#else /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */
  tv = ssh_time();
  if (timeval != NULL)
    {
      timeval->seconds = (SshUInt64)tv;
      timeval->nanoseconds = (SshUInt32)0;
    }
  return TRUE;
#endif /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */
}

/*
 * Set timeval to the minimum granularity of the time measurement.
 * In some systems this value may be more like guess based
 * on the structure carrying the time information.
 * In any case, significant granularity is not finer than
 * the value returned by this function.
 * Return FALSE if operation failed.  In any case a best guess
 * is stored to timeval.
 */
Boolean ssh_time_measure_system_granularity_time(SshTimeVal timeval)
{
#ifdef CHORUS
  KnTimeVal diff;
#endif
#if defined(VXWORKS)
  struct timespec tp = { 0 };
#endif

#if defined(WIN32)
  /*
   * In Windows, we have milliseconds in struct _timeb.
   */
  if (timeval != NULL)
    {
      timeval->seconds = 0;
      timeval->nanoseconds = 1000000;
    }
  return TRUE;
#elif defined(CHORUS)
  /*
   * In Chorus, we have system call for this.
   */
  if (sysTimeGetRes(&diff) == K_OK)
    {
      if (timeval != NULL)
        {
          timeval->seconds = (SshUInt64)(diff.tmSec);
          timeval->nanoseconds = (SshUInt32)(diff.tmNSec);
        }
      return TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_granularity: "
                  "sysTimeGetRes unexpectedly failed.");
      if (timeval != NULL)
        {
          timeval->seconds = 0;
          timeval->nanoseconds = 1;
        }
      return FALSE;
    }
#elif defined(HAVE_GETTIMEOFDAY)
  /*
   * Gettimeofday(2) returns microseconds.
   */
  if (timeval != NULL)
    {
      timeval->seconds = 0;
      timeval->nanoseconds = 1000;
    }
  return TRUE;
#elif defined(VXWORKS)
  if (clock_getres(CLOCK_REALTIME, &tp) == OK)
    {
      if (timeval != NULL)
        {
          timeval->seconds = (SshUInt64)tp.tv_sec;
          timeval->nanoseconds = (SshUInt32)tp.tv_nsec;
        }
      return TRUE;
    }
  else
    {
      ssh_warning("ssh_time_measure_granularity: clock_getres failed.");
      if (timeval != NULL)
        {
          timeval->seconds = 0;
          /* unexpected failure, assume the default 1/60th second */
          timeval->nanoseconds = 16666666;
        }
      return FALSE;
    }
#else /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */
  /*
   * time(3) returns full seconds.
   */
  if (timeval != NULL)
    {
      timeval->seconds = 1;
      timeval->nanoseconds = 0;
    }
  return TRUE;
#endif /* !WIN32 && !CHORUS && !HAVE_GETTIMEOFDAY && !VXWORKS */
}

/* eof (sshtimemeasure.c) */
