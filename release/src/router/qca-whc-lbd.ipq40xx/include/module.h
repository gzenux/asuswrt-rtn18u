// vim: set et sw=4 sts=4 cindent:
/*
 * @File: module.h
 *
 * @Abstract: central event loop for single-threaded event-driven programs.
 *
 * @Notes:
 *
 * Copyright (c) 2011 Atheros Communications Inc.
 * All rights reserved.
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All rights reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef md__h /*once only*/
#define md__h

#include <sys/time.h>
#include "list.h"
#include "lbd_types.h"

/* There are two priority event queue.
 */
enum mdEventPriority_e
{
    mdEventPriority_High = 0, /* high priority must first. */
    mdEventPriority_Low,
    mdEventPriority_MaxNum
};

/* The ID number of module.
 */
enum mdModuleID_e
{
    mdModuleID_Main = 0,

    // This needs to be here so that the module IDs start at the same offset
    // in all daemons where the modules are used.
#include "lb_module.h"

    mdModuleID_MaxNum
};

/* The structure of one event.
 */
struct mdEventNode
{
    list_head_t list;
    u_int32_t EventID;
    u_int32_t ModuleID; /* who creates the event */
    u_int32_t DataLen;
    void *Data; /* null when there is no data */
};

/* The structure of one listen node of the event.
 */
struct mdEventListenNode
{
    list_head_t list;
    void (*EventCB)(struct mdEventNode *Event); /* callback, register by one service. */
};

typedef void (*mdListenInitCB)(void);

/* The structure for recording the statistics of one event.
 */
struct mdEventStat
{
    u_int32_t Times;              /* Dispatch times. */
    struct timeval AccumulateTime;  /* Accumulate time of this event. */
    struct timeval MaxInterval;  /* Maximum dispatch interval. */
};

struct mdEventTable
{
    list_head_t list;
    struct mdEventStat Stat;
};

/* The structure of module table.
 */
struct mdModuleTable
{
    struct mdEventTable *EventTable; /* Event table of this module. */
    u_int32_t EventNum; /* The event number of this module. */
};

/* The structure for packaging the command.
 */
struct mdCommand
{
    u_int8_t Cmd;      /* Command */
    u_int8_t Priority; /* Priority */
    u_int16_t Length;           /* The length of the data */
    u_int8_t Data[1];  /* first address of data */
}__attribute__ ((packed));


/* Put the event to the Priority Queue.
 * If there is no listener, discard this event.
 */
LBD_STATUS mdCreateEvent(u_int32_t ModuleID, u_int32_t Priority, u_int32_t EventID, const void *Data, u_int32_t DataLen);

/* Register to listen the EventID from ModuleID.
 * Should be invoked by services.
 */
LBD_STATUS mdListenTableRegister(u_int32_t ModuleID, u_int32_t EventID,
        void (*EventCB)(struct mdEventNode *Event));

/* Register event table to the ModuleID slot.
 * Should be invoked by managers.
 */
LBD_STATUS mdEventTableRegister(u_int32_t ModuleID, u_int32_t EventNum);

/* Check the event queue, if event queue is no empty,
 * then dispatch one event.
 * If there are events pending on the queue, return 1.
 */
u_int32_t mdOnce(void);

/*--- mdInit -- first time init.
 * Automatically called as need be.
 */
void mdInit(void);

void mdDoListenInitCB(void);
void mdListenInitCBRegister(u_int32_t ModuleID, void (*CB)(void));

#endif /* md__h */

