/*
 * bcm_symbian_osl.h -- symbian osl for external supplicant
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcm_symbian_osl.h,v 1.1 2010-11-12 10:53:48 $
 */

#ifndef _bcm_symbian_osl_h_
#define _bcm_symbian_osl_h_

#include <stdlib.h>
#include <assert.h>

/* Minimalist OSL layer */
#define MALLOC(osh, size)		malloc((size))
#define MFREE(osh, ptr, len)		free((ptr))

#define MALLOCED(osh)	(0)

#define ASSERT assert
#define OS_MALLOC(len) malloc(len)
#define OS_FREE(p) free(p)



#endif /* _bcm_symbian_osl_h_ */
