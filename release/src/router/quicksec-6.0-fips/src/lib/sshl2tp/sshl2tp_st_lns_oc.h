/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LNS outgoing call (initiator).
*/

#ifndef SSHL2TP_ST_LNS_OC_H
#define SSHL2TP_ST_LNS_OC_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_tunnel);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_reply);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_connect);

#endif /* not SSHL2TP_ST_LNS_OC_H */
