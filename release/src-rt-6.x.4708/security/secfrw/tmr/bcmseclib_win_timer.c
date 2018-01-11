/*
 * bcmseclib_win_timer.c -- windows platform dependent timer stuff
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_win_timer.c,v 1.1 2010-12-11 00:53:59 $
 */

#include <bcmseclib_timer.h>
#include <bcmseclib_timer_os.h>
#include <windows.h>


int
bcmseclib_os_get_time(bcmseclib_time_t *time)
{
	FILETIME	file_time;
	ULARGE_INTEGER	ularge_int;

	/* Retrieves the current system date and time in Coordinated Universal
	 * Time (UTC) format. FILETIME contains a 64-bit value representing the
	 * number of 100-nanosecond intervals since January 1, 1601 (UTC).
	 */
	GetSystemTimeAsFileTime(&file_time);

	/* From the MSDN documentation: "It is not recommended that you add and
	 * subtract values from the FILETIME structure to obtain relative times.
	 * Instead, you should copy the low- and high-order parts of the file time
	 * to a ULARGE_INTEGER structure, perform 64-bit arithmetic on the QuadPart
	 * member, and copy the LowPart and HighPart members into the FILETIME structure."
	 */
	ularge_int.LowPart = file_time.dwLowDateTime;
	ularge_int.HighPart = file_time.dwHighDateTime;

	/* Convert to usec units. */
	ularge_int.QuadPart /= 10;

	/* Windows uses an epoch time of Jan 1, 1601, and Unix uses Jan 1, 1970.
	 * Convert from Windows to Unix epoch for consistentcy and to avoid
	 * overflow in the number of seconds. 11644473600000000 is the number of
	 * usec between the Windows and Unix epoc times.
	 */
	ularge_int.QuadPart -= 11644473600000000;

	/* Separate out sec and usec units. */
	time->sec = (long)(ularge_int.QuadPart / 1000000);
	time->usec = (long)(ularge_int.QuadPart % 1000000);

	return (0);
}
