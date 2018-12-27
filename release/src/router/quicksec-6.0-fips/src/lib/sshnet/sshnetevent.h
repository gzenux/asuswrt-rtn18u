/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for network interface, IP addressing and routing table
   related events. This API requires the SSH eventloop runtime
   environment.
*/

#ifndef SSHNETEVENT_H
#define SSHNETEVENT_H

#include "sshinet.h"
#include "sshnetconfig.h"


/* **************************** Event listener ******************************/

/** This type defines the event type in event notification callback. */
typedef enum
{
  SSH_NETCONFIG_EVENT_LINK_CHANGED,    /** Link state has changed. */
  SSH_NETCONFIG_EVENT_ADDRESS_CHANGED, /** Address configuration has changed.*/
  SSH_NETCONFIG_EVENT_ROUTES_CHANGED,  /** Routing table has changed. */
  SSH_NETCONFIG_EVENT_LAST
} SshNetconfigEvent;

/** Event notification callback type. This type of function is called to
    indicate events to registered event listeners. The listener may call
    other sshnetconfig API calls from this callback to retrieve and modify
    link, address or routing information.

    @param event
    Specifies the type of event.

    @param ifnum
    Specifies the interface index of the applicable interface - it may
    be SSH_INVALID_IFNUM which means that the event does not relate to
    a single interface (as for example routing table changes).

    @param  context
    The callback context given to
    ssh_netconfig_register_event_callback().

    */
typedef void (*SshNetconfigEventCallback)(SshNetconfigEvent event,
                                          SshUInt32 ifnum,
                                          void *context);

/** Data type for a event listener handle. */
typedef struct SshNetconfigEventHandleRec *SshNetconfigEventHandle;

/** Register an event notification callback.

    @return
    On success this returns an event listener handle which is used for
    unregistering the event callback. On error this returns NULL.

    */
SshNetconfigEventHandle
ssh_netconfig_register_event_callback(SshNetconfigEventCallback callback,
                                      void *context);

/** Unregister an event listener.

    @param handle
    This must be a valid event listener handle created by calling
    ssh_netconfig_register_event_callback().

    */
SshNetconfigError
ssh_netconfig_unregister_event_callback(SshNetconfigEventHandle handle);

#endif /* SSHNETEVENT_H */
