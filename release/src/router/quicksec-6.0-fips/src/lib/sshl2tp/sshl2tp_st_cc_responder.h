/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Control connection establishment, responder.
*/

#ifndef SSHL2TP_ST_CC_RESPONDER_H
#define SSHL2TP_ST_CC_RESPONDER_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_reject_new);
SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_accept_new);
SSH_FSM_STEP(ssh_l2tp_fsm_cc_responder_wait_ctl_conn);

#endif /* not SSHL2TP_ST_CC_RESPONDER_H */
