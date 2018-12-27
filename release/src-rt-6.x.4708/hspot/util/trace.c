/*
 * Tracing utility.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#include <stdio.h>
#include <stdarg.h>
#if !defined(BCMDRIVER)
#include <time.h>
#include <sys/time.h>
#endif /* !BCMDRIVER */
#include <ctype.h>
#include <trace.h>

traceLevelE gTraceLevel = TRACE_NONE;

static char *getTimestamp(traceLevelE level)
{
	static char buffer[32] = {0};
#if !defined(BCMDRIVER)
	struct timeval tv;
	struct tm tm;
#endif /* !BCMDRIVER */

	if (level == TRACE_PRINTF) {
		/* no timestamp for printf */
		buffer[0] = 0;
	}
	else {
#if !defined(BCMDRIVER)
		gettimeofday(&tv, NULL);
		localtime_r(&tv.tv_sec, &tm);

		snprintf(buffer, sizeof(buffer), "%d:%02d:%02d.%03d - ",
			tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec / 1000);
#else
		uint32 uptime = OSL_SYSUPTIME();
		uint32 ms, sec, min, hour;

		ms = uptime % 1000;
		uptime /= 1000;
		sec = uptime % 60;
		uptime /= 60;
		min = uptime % 60;
		hour = uptime / 60;
		sprintf(buffer, "%d:%02d:%02d.%03d - ",
			hour, min, sec, ms);
#endif /* !BCMDRIVER */
	}

	return buffer;
}

void trace(const char *file, int line, const char *function,
	traceLevelE level, const char *format, ...)
{
	va_list argp;

	if (level & gTraceLevel || level == TRACE_PRINTF) {
		char *time = getTimestamp(level);

		if (level & TRACE_ERROR)
			dbg("%sERROR!!! %s:%d %s()\n", time, file, line, function);

		dbg("%s", time);
		va_start(argp, format);
#if !defined(BCMDRIVER)
		vprintf(format, argp);
#else
		{
			char buffer[128] = {0};
			vsprintf(buffer, format, argp);
			dbg(buffer);
		}
#endif /* !BCMDRIVER */
		va_end(argp);
	}
}

void traceMacAddr(const char *file, int line, const char *function,
	traceLevelE level, const char *str, struct ether_addr *mac)
{
	if (level & gTraceLevel || level == TRACE_PRINTF) {
		char *time = getTimestamp(level);
		if (level & TRACE_ERROR)
			dbg("%sERROR!!! %s:%d %s()\n", time, file, line, function);

		dbg("%s%s[6] = %02X:%02X:%02X:%02X:%02X:%02X\n", time, str,
			mac->octet[0], mac->octet[1], mac->octet[2],
			mac->octet[3], mac->octet[4], mac->octet[5]);
	}
}

void traceHexDump(const char *file, int line, const char *function,
	traceLevelE level, const char *str, int len, uint8 *buf)
{
	if (level & gTraceLevel || level == TRACE_PRINTF) {
		char *time = getTimestamp(level);
		int i, j;
		int sol, eol;

		if (level & TRACE_ERROR)
			dbg("%sERROR!!! %s:%d %s()\n", time, file, line, function);

		dbg("%s%s[%d] = ", time, str, len);

		sol = eol = 0;
		for (i = 0; i < (int)len; i++) {
			if ((i % 16) == 0) {
				eol = i;

				/* print ascii */
				dbg("   ");
				for (j = sol; j < eol; j++) {
					if (isprint(buf[j]))
						dbg("%c", (char)buf[j]);
					else
						dbg(".");
				}
				dbg("\n   ");
				sol = eol;
			}

			dbg("%02X ", buf[i]);
		}

		if (len > 0) {
			/* pad to EOL */
			for (j = 0; j < 16 - (i - sol); j++)
				dbg("   ");

			/* print ascii */
			dbg("   ");
			for (j = sol; j < i; j++) {
				if (isprint(buf[j]))
					dbg("%c", (char)buf[j]);
				else
					dbg(".");
			}
		}

		dbg("\n");
	}
}
