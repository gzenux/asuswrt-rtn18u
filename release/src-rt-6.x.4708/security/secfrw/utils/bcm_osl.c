/*
 * bcm_linux_osl.c
 * Linux osl functions for user space
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcm_osl.c,v 1.1.1.1 2010-02-04 00:44:37 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcm_osl.h>
#include <bcm_lbuf.h>


/* Begin NEW */
void *osl_pktget(osl_t *osh, uint len)
{
	void *pkt;
#if defined(BCMDBG_MEMFAIL)
	pkt = (void *)lb_alloc(len, __FILE__, __LINE__);
#else
	pkt = (void *)lb_alloc(len);
#endif

	return pkt;
}

void osl_pktfree(osl_t *osh, void *p, bool send)
{
	lb_free((struct lbuf *)p);
}

int
osl_init()
{
	lb_init();
	return 0;
}
