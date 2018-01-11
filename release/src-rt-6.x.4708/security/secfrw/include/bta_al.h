/*****************************************************************************
 * bta adaptation layer
 * bta_al.h
 * Header file for bta adaptation layer
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: bta_al.h,v 1.1 2010-03-08 22:38:35 $
 *****************************************************************************
*/


#if !defined(__bta_al_h__)
#define __bta_al_h__
extern int
btachild_frame_rx_handler(void *arg, void *pkt, int len);


extern int
btachild_event_rx_handler(void *arg, void *pkt, int len);

extern int
btaparent_event_rx_handler(void *arg, void *pkt, int len);

extern int
btachild_frame_tx_prep(const void *pkt);


#endif /* __bta_al_h__ */
