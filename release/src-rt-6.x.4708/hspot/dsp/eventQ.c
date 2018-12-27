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

#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <sys/stat.h>
#include <errno.h>
#include "trace.h"
#include "eventQ.h"

#define MAX_NAME_LENGTH		32

struct eventQ
{
	char name[MAX_NAME_LENGTH + 1];
	int queueDepth;
	size_t eventSize;
	mqd_t mq;
};

/* flush event queue */
static void flush(eventQT *eventq)
{
	char *data;

	data = malloc(eventq->eventSize);
	if (data == 0)
		return;

	while (eventQReceive(eventq, data) != -1)
	{}

	free(data);
}

/* create event queue */
static eventQT *create(char *name, int queueDepth, size_t eventSize)
{
	eventQT *eventq;
	struct mq_attr attr;

	eventq = malloc(sizeof(*eventq));
	if (eventq == 0)
		return 0;
	memset(eventq, 0, sizeof(*eventq));
	strncpy(eventq->name, name, MAX_NAME_LENGTH);
	eventq->queueDepth = queueDepth;
	eventq->eventSize = eventSize;

	/* event queue attributes */
	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = eventq->queueDepth;
	attr.mq_msgsize = eventq->eventSize;

	/* create event queue */
	eventq->mq = mq_open(eventq->name,
		O_RDWR | O_NONBLOCK | O_CREAT,
		S_IRWXU | S_IRWXG, &attr);
	if (eventq->mq == (mqd_t)-1) {
		TRACE(TRACE_ERROR, "failed to create event queue\n");
		perror("eventQCreate");
		free(eventq);
		return 0;
	}

	/* queue may not be empty if not a clean shutdown */
	flush(eventq);

	return eventq;
}

/* create event queue */
eventQT *eventQCreate(char *name, int queueDepth, size_t eventSize)
{
	eventQT *eventq;

	/* previous queue may be lingering around if not a clean shutdown */
	/* delete it first */
	eventq = create(name, queueDepth, eventSize);
	eventQDelete(eventq);

	return create(name, queueDepth, eventSize);
}

/* delete event queue */
void eventQDelete(eventQT *eventq)
{
	mq_close(eventq->mq);
	mq_unlink(eventq->name);
	free(eventq);
}

/* post to event queue */
int eventQSend(eventQT *eventq, char *event)
{
	return mq_send(eventq->mq, event, eventq->eventSize, 0);
}

/* retrieve from event queue */
int eventQReceive(eventQT *eventq, char *event)
{
	return mq_receive(eventq->mq, event, eventq->eventSize, 0);
}
