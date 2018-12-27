/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LAC incoming call (initiator).
*/

#ifndef SSHL2TP_ST_LAC_IC_H
#define SSHL2TP_ST_LAC_IC_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_lac_ic_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_lac_ic_wait_tunnel);
SSH_FSM_STEP(ssh_l2tp_fsm_lac_ic_wait_reply);

#endif /* not SSHL2TP_ST_LAC_IC_H */
