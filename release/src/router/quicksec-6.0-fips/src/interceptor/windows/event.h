/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the definitions for SshEvent object that is
   utilized to synchronize execution of tasks in multi-threaded
   environments.
*/

#ifndef SSH_EVENT_H
#define SSH_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/*-------------------------------------------------------------------------
  DEFINITIONS
  -------------------------------------------------------------------------*/

/* Wait infinite timeout */
#define SSH_EVT_WAIT_INFINITE         -1L

/* Maximum number of multiple events to wait */
#define SSH_EVT_WAIT_MAX_CNT          64

/* Multiple event wait mode flags */
#define SSH_EVT_WAIT_MODE_ANY         0x01
#define SSH_EVT_WAIT_MODE_ALL         0x02

/* Wait "forever" (i.e. until the event gets signaled) */
#define SSH_EVT_WAIT_INFINITE         -1L

/* Typedef for event handling routine that is run when event is fired */
typedef void (*SshEventMethod)(void *);

/* Forward declaration for SshEvent object */
typedef struct SshEventRec SshEventStruct, *SshEvent;

/* Wait Control Block descriptor */
typedef struct SshWCBRec
{
  /* Waiting time in millisecs */
  long wait_time_ms;

  /* Wait mode flags */
  unsigned char mode;

  /* Reserved for OS internal use */
  void *reserved[4];
} SshWCBStruct, *SshWCB;


/* Native OS event object. */
typedef PKEVENT SshOsEvent;

/*-------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  -------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------
  SshEvent constructor.
  -------------------------------------------------------------------------*/
SshEvent
ssh_event_create(unsigned long event_id,
                 SshEventMethod event_cb, 
                 void *context);

/*-------------------------------------------------------------------------
  SshEvent destructor.
  -------------------------------------------------------------------------*/
void
ssh_event_destroy(SshEvent event);

/*-------------------------------------------------------------------------
  Converts native event object 'os_event' to SshEvent. 
  -------------------------------------------------------------------------*/
SshEvent
ssh_event_wrap(unsigned long event_id,
               SshOsEvent os_event,
               SshEventMethod event_cb,
               void *context);

/*-------------------------------------------------------------------------
  Sets the event into signalled state.
  -------------------------------------------------------------------------*/
void __fastcall
ssh_event_signal(SshEvent event);

/*-------------------------------------------------------------------------
  Clears the event state.
  -------------------------------------------------------------------------*/
void __fastcall
ssh_event_reset(SshEvent event);

/*-------------------------------------------------------------------------
  Checks if event has been set to signalled state.
  -------------------------------------------------------------------------*/
Boolean __fastcall
ssh_event_is_signalled(SshEvent event);

/*-------------------------------------------------------------------------
  Returns event ID
  -------------------------------------------------------------------------*/
unsigned long __fastcall
ssh_event_id(SshEvent event);

/*-------------------------------------------------------------------------
  Waits for event(s) to occur and then executes associated event handler(s).
  The Wait Control Block (wcb) contains some attributes for wait operation.
  -------------------------------------------------------------------------*/
Boolean __fastcall
ssh_event_wait(SshUInt8 event_cnt,
               SshEvent *event, 
               SshWCB wcb);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_EVENT_H */
