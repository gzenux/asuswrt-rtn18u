/*
 * Event queue utility.
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _EVENTQ_H_
#define _EVENTQ_H_

typedef struct eventQ eventQT;

/* create event queue */
eventQT *eventQCreate(char *name, int queueDepth, size_t eventSize);

/* delete event queue */
void eventQDelete(eventQT *eventq);

/* post to event queue */
int eventQSend(eventQT *eventq, char *event);

/* retrieve from event queue */
int eventQReceive(eventQT *eventq, char *event);

#endif /* _EVENTQ_H_ */
