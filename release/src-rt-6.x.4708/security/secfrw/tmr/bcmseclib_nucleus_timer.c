/*
 * bcmseclib_nucleus_timer.c -- nucleus platform dependent timer stuff
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_nucleus_timer.c,v 1.1 2010-12-11 00:53:59 $
 */

#include <bcmseclib_timer.h>
#include <bcmseclib_timer_os.h>
#include <osl.h>


int
bcmseclib_os_get_time(bcmseclib_time_t *time)
{
	unsigned int	ticks;
	unsigned int	msec;

	OSL_GETCYCLES(ticks);
        msec = (unsigned int) ((1000.0 * (ticks)) / BWL_NU_TICKS_PER_SECOND);

	time->sec = (msec / 1000);
	time->usec = ((msec % 1000) * 1000);

	return (0);
}
