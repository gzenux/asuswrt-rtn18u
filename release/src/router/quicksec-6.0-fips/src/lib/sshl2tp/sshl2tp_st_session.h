/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General help states for session threads.
*/

#ifndef SSHL2TP_ST_SESSION_H
#define SSHL2TP_ST_SESSION_H

/********************* Prototypes for state functions. **********************/

SSH_FSM_STEP(ssh_l2tp_fsm_session_established);
SSH_FSM_STEP(ssh_l2tp_fsm_session_closed);
SSH_FSM_STEP(ssh_l2tp_fsm_session_destroyed);
SSH_FSM_STEP(ssh_l2tp_fsm_session_clean_up);


/******************* Prototypes for public help functions *******************/

/* Message handler of session threads.  This is used in inter-thread
   communication to notify session thread `thread' about exception
   `exception'.  The argument `exception' is actually
   SshL2tpThreadException'. */
void ssh_l2tp_session_message_handler(SshFSMThread thread,
                                      SshUInt32 exception);

#endif /* not SSHL2TP_ST_SESSION_H */
