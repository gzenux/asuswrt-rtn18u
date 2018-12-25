/*
 * @File: module.c
 *
 * @Abstract: central event loop for single-threaded event-driven programs.
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include <stdlib.h>
#include <string.h>

#include <dbg.h>
#include <evloop.h>
#include "module.h"
#include "lbd_assert.h"

#define MD_QUEUE_THRESHOLD      512
#define MD_QUEUE_DISPATCH_ONCE  12

/*-------------------------------------------------*/

/*--- mdState -- global data for md
 */
static struct mdState_t
{
    u_int32_t IsInit;
    struct dbgModule *DebugModule;
    u_int32_t QueueThreshold;
    u_int32_t QueueDispatchOnce;
    u_int32_t PriorityCounts[mdEventPriority_MaxNum];
    list_head_t PriorityQueues[mdEventPriority_MaxNum];
    struct mdModuleTable ModuleTables[mdModuleID_MaxNum];
    mdListenInitCB ListenInitCBTables[mdModuleID_MaxNum];
    struct evloopTimeout EventDispatchTimer;
} mdS;


/*--- mdDebug -- print debug messages (see dbgf documentation)
 */
#define mdDebug(...) dbgf(mdS.DebugModule, __VA_ARGS__)

void mdInit(void);  /* forward declaration */

void mdListenInitCBRegister(u_int32_t ModuleID, void (*CB)(void))
{
    if( ModuleID >= mdModuleID_MaxNum || !CB ) {
        mdDebug(DBGERR, "%s: Invalid parameters: ModuleID %d, CB %p",
                __func__, ModuleID, CB);
        return;
    }

    mdS.ListenInitCBTables[ModuleID] = CB;
}

void mdDoListenInitCB(void)
{
    u_int32_t IModule;

    for (IModule = 0; IModule < mdModuleID_MaxNum; IModule++) {
        if (mdS.ListenInitCBTables[IModule])
            mdS.ListenInitCBTables[IModule]();
    }
}

/* Initialization priority queue, should be invoked in init state
 */
static void mdPriorityQueueInit(void)
{
    u_int32_t IPri;

    for (IPri = 0; IPri < mdEventPriority_MaxNum; IPri++) {
    	list_set_head( &mdS.PriorityQueues[IPri] );
    }
}

/* Register event table to the ModuleID slot.
 * Should be invoked by managers.
 */
LBD_STATUS mdEventTableRegister(u_int32_t ModuleID, u_int32_t EventNum)
{
    if (!mdS.IsInit) mdInit();

    mdDebug(DBGDEBUG, "Enter %s", __func__);

    if( ModuleID >= mdModuleID_MaxNum || !EventNum || EventNum > 256 ) {
        mdDebug(DBGERR, "%s: Invalid parameters: ModuleID %d, EventNum %d",
                __func__, ModuleID, EventNum);
        return LBD_NOK;
    }

    struct mdModuleTable *ModuleTable = &mdS.ModuleTables[ModuleID];

    if (ModuleTable->EventNum == EventNum) {
        mdDebug(DBGINFO, "%s: Event table is already registered.", __func__);
        return LBD_OK;
    }

    ModuleTable->EventTable = (struct mdEventTable *)malloc(sizeof(struct mdEventTable) * EventNum);
    if (!ModuleTable->EventTable) {
        mdDebug(DBGERR, "%s: Memory allocation failure", __func__);
        return LBD_NOK;
    }

    ModuleTable->EventNum = EventNum;
    {
        u_int32_t IEvent;

        for (IEvent = 0; IEvent < EventNum; IEvent++) {
            list_set_head( &(ModuleTable->EventTable)[IEvent].list );
        }
    }

    return LBD_OK;
}

/* Put the event to the Priority Queue.
 * If there is no listener, discard this event.
 */
LBD_STATUS mdCreateEvent(u_int32_t ModuleID, u_int32_t Priority, u_int32_t EventID, const void *Data, u_int32_t DataLen)
{
    mdDebug(DBGDEBUG, "Enter %s", __func__);

    if( Priority >= mdEventPriority_MaxNum || ModuleID >= mdModuleID_MaxNum ) {
        mdDebug(DBGERR, "%s: Invalid parameters: Priority %d, ModuleID %d",
                __func__, Priority, ModuleID );
        return LBD_NOK;
    }

    /* Event table is not register yet! */
    struct mdModuleTable *ModuleTable = &mdS.ModuleTables[ModuleID];
    if (!ModuleTable->EventNum) return -1;

    /* No listener! */
    if (list_is_empty(&(ModuleTable->EventTable)[EventID].list)) return -1;

    struct mdEventNode *Event =
        (struct mdEventNode *)malloc(sizeof(struct mdEventNode));
    if (!Event) {
        mdDebug(DBGERR, "%s: Failed to allocate memory for event", __func__);
        return LBD_NOK;
    }

    memset(Event, 0, sizeof *Event);
    if (Data && DataLen) {
        Event->Data = malloc(DataLen);
        if (!Event->Data) {
            mdDebug(DBGERR, "%s: Failed to allocate memory for event data",
                    __func__);
            return LBD_NOK;
        }

        Event->DataLen = DataLen;
        memcpy(Event->Data, Data, DataLen);
    }

    Event->EventID = EventID;
    Event->ModuleID = ModuleID;

    /* Add the event to the end of the list. */
    list_insert_entry(&Event->list, &mdS.PriorityQueues[Priority]);
    mdS.PriorityCounts[Priority]++;
    mdDebug(DBGDEBUG,"%s: Priority=%d, QueueLen=%d\n",
            __func__, Priority, mdS.PriorityCounts[Priority]);

    evloopTimeoutRegister(
            &mdS.EventDispatchTimer,
            0,
            0);

    return LBD_OK;
}

/* Get the event from the Priority queue.
 */
static struct mdEventNode *mdGetEvent(u_int32_t Priority)
{
    mdDebug(DBGDEBUG, "Enter %s", __func__);

    if( Priority >= mdEventPriority_MaxNum ) {
        mdDebug(DBGERR, "%s: Invalid parameters: Priority %d",
                __func__, Priority);
        return NULL;
    }

    /* No event on the queue. */
    if (list_is_empty(&mdS.PriorityQueues[Priority])) return NULL;

    /* Get the fist event node from the event list. */
    struct mdEventNode *Event = list_first_entry(&mdS.PriorityQueues[Priority],struct mdEventNode, list);

    if (Event) {
        /* Remove the event on the list. */
    	list_remove_entry( &Event->list );
        return Event;
    }

    return NULL;
}

/* Release the memory for the event.
 */
static void mdEventDestroy(struct mdEventNode **Event, u_int32_t Priority)
{
    mdDebug(DBGDEBUG, "Enter %s", __func__);

    if( !*Event ) {
        mdDebug(DBGERR, "%s: Event is NULL", __func__);
        return;
    }

    mdS.PriorityCounts[Priority]--;
    mdDebug(DBGDEBUG,"%s: Priority=%d, QueueLen=%d\n",
            __func__, Priority, mdS.PriorityCounts[Priority]);

    if( *Event )
    {
        if(((*Event)->Data))
            free((*Event)->Data);

        free(*Event);

        /* Avoid accidental frees */
        *Event = NULL;
    }
}


/* Register to listen the EventID from ModuleID.
 * Should be invoked by services.
 */
LBD_STATUS mdListenTableRegister(u_int32_t ModuleID, u_int32_t EventID,
        void (*EventCB)(struct mdEventNode *Event))
{
    if (!mdS.IsInit) mdInit();

    mdDebug(DBGDEBUG, "Enter %s", __func__);

    if( ModuleID >= mdModuleID_MaxNum || !EventCB ) {
        mdDebug(DBGERR, "%s: Invalid parameters: ModuleID %d, EventCB %p",
                __func__, ModuleID, EventCB);
        return LBD_NOK;
    }

    /* Event table is not register yet! */
    struct mdModuleTable *ModuleTable = &mdS.ModuleTables[ModuleID];
    if( !ModuleTable->EventNum || !(ModuleTable->EventNum > EventID) ) {
        mdDebug(DBGERR, "%s: Event table is not registered yet: "
                        "ModuleID=%d, EventID=%d!",
                __func__, ModuleID, EventID);
        return LBD_NOK;
    }

    struct list_head_t *ListenHead = &(ModuleTable->EventTable)[EventID].list;
    struct mdEventListenNode *ListenNode =
        (struct mdEventListenNode *)malloc(sizeof (struct mdEventListenNode));

    if (!ListenNode) {
        mdDebug(DBGERR, "%s: Failed to allocate memory", __func__);
        return LBD_NOK;
    }

    ListenNode->EventCB = EventCB;
    /* Add the listen node to the end of the list. */
    list_insert_entry(&ListenNode->list, ListenHead);

    return LBD_OK;
}

static void mdEventStat(struct mdEventStat *Stat, struct timeval *PTV)
{
    struct timeval NTV;
    long long USecElapsed, USecAcc;

    gettimeofday(&NTV, NULL);

    USecElapsed = NTV.tv_sec * 1000000LL + NTV.tv_usec -
        (PTV->tv_sec * 1000000LL + PTV->tv_usec);

    USecAcc = Stat->AccumulateTime.tv_sec * 1000000LL +
        Stat->AccumulateTime.tv_usec + USecElapsed;

    Stat->Times++;
    Stat->AccumulateTime.tv_sec = USecAcc / 1000000;
    Stat->AccumulateTime.tv_usec = USecAcc % 1000000;
    if(USecElapsed <= (Stat->MaxInterval.tv_sec * 1000000LL +
                Stat->MaxInterval.tv_usec))
        return;

    Stat->MaxInterval.tv_sec = USecElapsed / 1000000;
    Stat->MaxInterval.tv_usec = USecElapsed % 1000000;
}

/* Dispatch the event to all the listeners.
 */
static void mdEventDispatch(struct mdEventNode *Event)
{
    if (!Event || Event->ModuleID >= mdModuleID_MaxNum) return;

    struct timeval TV;
    struct mdEventTable *EventTable;
    list_head_t *Pos, *ListenHead;
    struct mdModuleTable *ModuleTable = &mdS.ModuleTables[Event->ModuleID];

    if (!ModuleTable->EventNum || /* Event table not be register. */
            ModuleTable->EventNum < Event->EventID) { /* invalid EventID. */
        mdDebug(DBGERR, "%s: Invalid event id!", __func__);
        return;
    }

    EventTable = &(ModuleTable->EventTable)[Event->EventID];

    if(list_is_empty(&EventTable->list)) {
        mdDebug(DBGINFO, "%s: There is no listeners on event %d",
                __func__, Event->EventID);
        return;
    }

    ListenHead = &EventTable->list;

    mdDebug(DBGDEBUG, "%s: Dispatch event %d from module %d",
            __func__, Event->EventID, Event->ModuleID);

    gettimeofday(&TV, NULL);

    list_for_each(Pos, ListenHead) {
        struct mdEventListenNode *Listener =
            list_entry(Pos, struct mdEventListenNode, list);

        if (Listener) Listener->EventCB(Event);
    }

    mdEventStat(&EventTable->Stat, &TV);
}

/* Check the event queue, if event queue is no empty,
 * then dispatch one event.
 * If there are events pending on the queue, return 1.
 */
u_int32_t mdOnce(void)
{
    u_int32_t IPri, Done = 0, Pending = 0;
    struct mdEventNode *Event;

    for (IPri = 0; IPri < mdEventPriority_MaxNum; IPri++) {
        if (!mdS.PriorityCounts[IPri]) continue;

        if (Done && mdS.PriorityCounts[IPri] < mdS.QueueThreshold) {
            Pending = 1;
            continue;
        }

        do {
            Event = mdGetEvent(IPri);
            mdEventDispatch(Event);
            mdEventDestroy(&Event, IPri);
        } while (mdS.PriorityCounts[IPri] > mdS.QueueThreshold - mdS.QueueDispatchOnce);

        Done = 1;

        if (mdS.PriorityCounts[IPri])
            Pending = 1;
    }

    return Pending;
}

void mdEventDispatchTimerHandler(void *Cookie)
{
    if (!mdOnce())
        return;

    evloopTimeoutRegister(
            &mdS.EventDispatchTimer,
            0,
            0);
}

#include <cmd.h>

/* s command */
const char *mdMenuParametersSetHelp[] = {
    "s -- set md queue limit parameters",
    "Usage: s [-l QueueLimitLength] [-d DispatchOnceNumber]",
    NULL
};

static void mdMenuParametersSetHandler(struct cmdContext *Context, const char *Cmd)
{
    char Buf[32];
    int32_t Temp;

    while ((Cmd != NULL) && (*Cmd == '-')) {
        if (cmdWordEq(Cmd, "-l")) {
            Cmd = cmdWordNext(Cmd);
            cmdWordCopy(Buf, Cmd, sizeof Buf);
            Temp = atoi(Buf);
            if (!Temp)
                cmdf(Context,"Invalid queue threshold value\n");
            mdS.QueueThreshold = Temp;
            Cmd = cmdWordNext(Cmd);
        } else if (cmdWordEq(Cmd, "-d")) {
            Cmd = cmdWordNext(Cmd);
            cmdWordCopy(Buf, Cmd, sizeof Buf);
            Temp = atoi(Buf);
            if (Temp >= mdS.QueueThreshold )
                cmdf(Context,"Invalid queue dispatch once number\n");
            mdS.QueueDispatchOnce = Temp;
            Cmd = cmdWordNext(Cmd);
        } else {
            cmdWordCopy(Buf, Cmd, sizeof Buf);
            cmdf(Context,"Not supported option:%s\n", Buf);
            return;
        }
    }

    cmdf(Context, "QueueThreshold = %d QueueDispatchOnce = %d\n",
            mdS.QueueThreshold, mdS. QueueDispatchOnce);
}

/* p command */
const char *mdMenuParametersGetHelp[ ] =
{
        "p -- Print all parameters",
        NULL
};

void mdMenuParametersGetHandler( struct cmdContext *Context, const char *Cmd )
{
    cmdf( Context, "QueueThreshold=%d, QueueDispatchOnce=%d\n",
            mdS.QueueThreshold, mdS.QueueDispatchOnce);
}

/* ------------ md menu (added to main menu) ----------*/

static const struct cmdMenuItem mdMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    {
        "p",                        /* Command */
        mdMenuParametersGetHandler, /* Callback */
        NULL,                       /* Cookie */
        mdMenuParametersGetHelp     /* Help menu */
    },
    {
        "s",                        /* Command */
        mdMenuParametersSetHandler, /* Callback */
        NULL,                       /* Cookie */
        mdMenuParametersSetHelp     /* Help menu */
    },
    CMD_MENU_END()
};

static const char *mdMenuHelp[] = {
    "md -- load balancing core module menu",
    NULL
};

static const struct cmdMenuItem mdMenuItem = {
    "md",
    cmdMenu,
    (struct cmdMenuItem *)mdMenu,
    mdMenuHelp
};

/*--- mdMenuInit -- add menu item for this module
*/
static void mdMenuInit(void)
{
    cmdMainMenuAdd(&mdMenuItem);
}

/*========================================================================*/
/*============ Init ======================================================*/
/*========================================================================*/

/*--- mdInit -- first time init.
 * Automatically called as need be.
 */
void mdInit(void)
{
    if (mdS.IsInit)
        return;

    memset(&mdS, 0, sizeof(mdS) );
    mdS.IsInit = 1;
    mdS.QueueThreshold = MD_QUEUE_THRESHOLD;
    mdS.QueueDispatchOnce = MD_QUEUE_DISPATCH_ONCE;
    mdMenuInit();
    mdS.DebugModule = dbgModuleFind("md");

    mdPriorityQueueInit();

    evloopTimeoutCreate(
            &mdS.EventDispatchTimer,
            "mdS.EventDispatchTimer",
            mdEventDispatchTimerHandler,
            NULL);

    mdDebug(DBGINFO, "mdInit Done.");
}


