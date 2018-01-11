/*****************************************************************************
 * Binding stack declarations
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

#if !defined(__BIND_SK_H__)
#define __BIND_SK_H__


extern void
bind_sk_init(struct bind_sk *sk, void (*cb)(void *, void *, int), void *arg);

extern void
bind_sk_push(struct bind_sk **top, struct bind_sk *elt);

extern struct bind_sk *
bind_sk_pop(struct bind_sk **top);


#endif /* !defined(__BIND_SK_H__) */
