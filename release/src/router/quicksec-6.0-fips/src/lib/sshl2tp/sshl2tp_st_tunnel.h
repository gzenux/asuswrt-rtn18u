/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General help states for control connection (tunnel) threads.
*/

#ifndef SSHL2TP_ST_TUNNEL_H
#define SSHL2TP_ST_TUNNEL_H

/********************* Prototypes for state functions. **********************/

SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_established);
SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_closed);
SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_destroyed);
SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_clean_up);
SSH_FSM_STEP(ssh_l2tp_fsm_tunnel_terminate);


/******************* Prototypes for public help functions *******************/

/* Message handler for tunnel threads.  This is used in inter-thread
   communication to notify tunnel thread `thread' about exception
   `exception'.  The argument `exception' is actually
   SshL2tpThreadException. */
void ssh_l2tp_tunnel_message_handler(SshFSMThread thread,
                                     SshUInt32 exception);

#endif /* not SSHL2TP_ST_TUNNEL_H */
