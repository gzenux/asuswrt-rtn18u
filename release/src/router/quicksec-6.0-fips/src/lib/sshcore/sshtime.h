/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Calendar time retrieval and manipulation.

   <keywords calenter time, time, retrieval/time, manipulation/time,
   utility functions/time>
*/

#ifndef SSHTIME_H
#define SSHTIME_H

typedef SshInt64 SshTime;

/** Calendar time. */
typedef struct SshCalendarTimeRec {
  SshUInt8 second;     /** 0-61. */
  SshUInt8 minute;     /** 0-59. */
  SshUInt8 hour;       /** 0-23. */
  SshUInt8 monthday;   /** 1-31. */
  SshUInt8 month;      /** 0-11. */
  SshInt32 year;       /** Absolute value of year, 1999=1999. */
  SshUInt8 weekday;    /** 0-6, 0=sunday. */
  SshUInt16 yearday;   /** 0-365. */
  SshInt32 utc_offset; /** Seconds from UTC (positive=east). */
  Boolean dst;         /** FALSE=non-DST, TRUE=DST. */
} *SshCalendarTime, SshCalendarTimeStruct;

typedef struct SshTimeValueRec {
  SshInt64 seconds;
  SshInt64 microseconds;
} *SshTimeValue, SshTimeValueStruct;


/** Returns seconds from epoch "January 1 1970, 00:00:00 UTC".  */
SshTime ssh_time(void);

/** Returns seconds and microseconds from epoch
    "January 1 1970,00:00:00 UTC". */
void ssh_get_time_of_day(SshTimeValue time);


/** Fills the calendar structure according to ''current_time''. */
void ssh_calendar_time(SshTime current_time,
                       SshCalendarTime calendar_ret,
                       Boolean local_time);




/** Return time string in RFC-2550 compatible format.

    @return
    The returned string is allocated with ssh_malloc and has to be
    freed with ssh_free by the caller.

    */
char *ssh_time_string(SshTime input_time);

/** Format time string in RFC-2550 compatible format as snprintf renderer.
    The datum points to the SshTime. */
int ssh_time_render(unsigned char *buf, int buf_size, int precision,
                    void *datum);

/** Format time string in RFC-2550 compatible format as snprintf renderer.
    The datum points to the memory buffer having the 32-bit long time
    in seconds from the epoch in the network byte order. */
int ssh_time32buf_render(unsigned char *buf, int buf_size, int precision,
                    void *datum);


/** Return a time string that is formatted to be more or less human
    readable.  It is somewhat like the one returned by ctime(3) but
    contains no newline in the end.  Returned string is allocated with
    ssh_malloc and has to be freed with ssh_free by the caller. */
char *ssh_readable_time_string(SshTime input_time, Boolean local_time);

/** Convert SshCalendarTime to SshTime. If the dst is set to TRUE,
    then daylight saving time is assumed to be set, if dst field is
    set to FALSE then it is assumed to be off. It if it is set to -1
    then the function tries to find out if the dst was on or off at
    the time given.

    Weekday and yearday fields are ignored in the conversion, but
    filled with approriate values during the conversion. All other
    values are normalized to their normal range during the conversion.

    @param local_time
    If the local_time is set to TRUE, then dst and utc_offset values
    are ignored.

    @return
    If the time cannot be expressed as SshTime, this function returns
    FALSE, otherwise returns TRUE.

    */
Boolean ssh_make_time(SshCalendarTime calendar_time, SshTime *time_return,
                      Boolean local_time);

#endif /* SSHTIME_H */

/* eof (sshtime.h) */
