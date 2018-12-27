/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Control connection establishment, initiator.
*/

#ifndef SSHL2TP_ST_CC_INITIATOR_H
#define SSHL2TP_ST_CC_INITIATOR_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_cc_initiator_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_cc_initiator_wait_ctl_reply);

#endif /* not SSHL2TP_ST_CC_INITIATOR_H */
