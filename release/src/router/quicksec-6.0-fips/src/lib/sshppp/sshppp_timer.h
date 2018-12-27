/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHPPP_TIMER_H

#define SSHPPP_TIMER_H 1

#define SSH_PPP_TIMER_RUNNING 1
#define SSH_PPP_TIMER_IDLE 2
#define SSH_PPP_TIMER_TIMEOUT 3

typedef struct SshPppTimerRec {
  /* Thread to wakeup when timer hits*/
  struct SshPppThreadRec *thread;

  /* Timer state */
  SshUInt8 timer_state;
} *SshPppTimer, SshPPPTimerStruct;

void
ssh_ppp_timer_set_timeout(SshPppTimer timer,
                          unsigned long secs,
                          unsigned long usecs);

void
ssh_ppp_timer_cancel_timeout(SshPppTimer timer);

Boolean
ssh_ppp_timer_check_timeout(SshPppTimer timer);

SshPppTimer
ssh_ppp_timer_create(struct SshPppThreadRec *tdata);

void
ssh_ppp_timer_destroy(SshPppTimer timer);

#endif /* SSHPPP_TIMER_H */
