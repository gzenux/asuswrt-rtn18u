/*****************************************************************************
 * Binding stack declarations (private)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *****************************************************************************
*/

#if !defined(__BIND_SKP_H__)
#define __BIND_SKP_H__


struct bind_sk {
	struct bind_sk *next;
	int (*cb)(void *arg, void *data, int sz);
	void *arg;
};


#endif /* !defined(__BIND_SKP_H__) */
