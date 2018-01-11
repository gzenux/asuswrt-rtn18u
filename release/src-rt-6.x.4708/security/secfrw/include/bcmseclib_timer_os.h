/*
 * bcmseclib_timer_os.h -- Operating system abstraction layer for timers.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_timer_os.h,v 1.1 2010-12-11 00:06:34 $
 */

#ifndef _bcmseclib_timer_os_h_
#define _bcmseclib_timer_os_h_

#include <bcmseclib_timer.h>


/* Retrieve the current time.
 *
 * Return 0 on success, -1 on error.
 */
int
bcmseclib_os_get_time(bcmseclib_time_t *tv);

#endif /*  _bcmseclib_timer_os_h_ */
