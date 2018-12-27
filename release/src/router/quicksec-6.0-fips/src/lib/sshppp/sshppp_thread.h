/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_THREAD_H

#define SSH_PPP_THREAD_H 1

/* States of the PPP connection */

#define SSH_PPP_RUNNING 1
#define SSH_PPP_INITIAL 2
#define SSH_PPP_IDLE 3
#define SSH_PPP_SUSPEND 4

/* A thread for working with the PPP main thread */

typedef struct SshPppThreadRec
{
  /* Thread we are running with */
  SshFSMThread thread;

  /* Events from callbacks */
  SshPppEvents events_cb;
  SshPppEventsInput events_cb_input;
  SshPppEventsOutput events_cb_output;

  /* Events from the controlling PPP thread */
  SshPppEvents events_internal;
  SshPppEventsInput events_internal_input;

  /* Event queue for sending events to the main PPP thread */
  SshPppEventsOutput events_output;

  /* Mux we are using for input and output*/
  SshPppMuxProtocol mux;

  /* The input packet that has not yet been processed */
  SshPppPktBuffer input_pkt;

  /* Timer we check for timeout events */
  SshPppTimer timer;

  /* The current event under processing */
  SshPppEvent current_event;

  /* State we are supposed to be in */
  SshUInt8 thread_status;

  /* Should we wake up */
  SshUInt8 is_suspended;

  /* Has a SshStream callback been activated ? */
  SshUInt8 is_polling;

} *SshPppThread, SshPppThreadStruct;

SshPppThread
ssh_ppp_thread_create(struct SshPppStateRec*,
                      SshFSMThread t,
                      SshPppEvents eventq,
                      const char* debug_name);

void
ssh_ppp_thread_attach_mux(SshPppThread tdata,
                          SshPppMuxProtocol mux);

void
ssh_ppp_thread_attach_timer(SshPppThread tdata, SshPppTimer timer);

void
ssh_ppp_thread_destroy(SshPppThread tdata);

void
ssh_ppp_thread_suspend(SshPppThread tdata);

void
ssh_ppp_thread_continue(SshPppThread tdata);

void
ssh_ppp_thread_boot(SshPppThread tdata);

void
ssh_ppp_thread_set_event(SshPppThread tdata, SshPppEvent ev);

SshPppEvent
ssh_ppp_thread_get_event(struct SshPppStateRec *gdata,
                         SshPppThread tdata);

void
ssh_ppp_thread_wakeup(SshPppThread tdata);

SshPppPktBuffer
ssh_ppp_thread_get_input_pkt(SshPppThread tdata);

SshFSMThread
ssh_ppp_thread_get_thread(SshPppThread tdata);

void
ssh_ppp_thread_enter_state(struct SshPppStateRec *gdata,
                           SshPppThread tdata);

SshFSMStepStatus
ssh_ppp_thread_leave_state(struct SshPppStateRec *gdata,
                           SshPppThread tdata);

SshPppEventsInput
ssh_ppp_thread_get_inputq(SshPppThread tdata);

SshPppEventsInput
ssh_ppp_thread_get_cb_inputq(SshPppThread tdata);

SshPppEventsOutput
ssh_ppp_thread_get_outputq(SshPppThread tdata);

SshPppEvents
ssh_ppp_thread_get_events(SshPppThread tdata);

SshPppEventsOutput
ssh_ppp_thread_get_cb_outputq(SshPppThread tdata);

SshPppMuxProtocol
ssh_ppp_thread_get_mux(SshPppThread tdata);

SshPppTimer
ssh_ppp_thread_get_timer(SshPppThread tdata);

void
ssh_ppp_thread_set_next(SshPppThread tdata,
                        SshFSMStepCB next_state);

void
ssh_ppp_thread_cancel_current_event(SshPppThread tdata);
void
ssh_ppp_thread_cancel_event(SshPppThread tdata,
                            SshPppEvent ev);

#define SSH_PPP_THREAD_JUMP_STATE(gdata,t,state)        \
do {                                                    \
  ssh_fsm_set_next((t)->thread, (state));               \
  return SSH_FSM_CONTINUE;                              \
} while (0)

#define SSH_PPP_THREAD_SUSPEND(t)                       \
do {                                                    \
  (t)->is_suspended = TRUE;                             \
  ssh_fsm_set_next((t)->thread,                         \
  ssh_fsm_get_thread_current_state((t)->thread));       \
  return SSH_FSM_SUSPENDED;                             \
} while (0)

#define SSH_PPP_THREAD_IO_BLOCK(t)                              \
do{                                                             \
  if (ssh_ppp_flush_output_pkt_isavail((t)->mux) == FALSE)      \
    {                                                           \
      ssh_ppp_flush_wait((t)->mux);                             \
      SSH_PPP_THREAD_SUSPEND(t);                                \
    }                                                           \
} while (0)


#endif /* SSH_PPP_THREAD_H */

