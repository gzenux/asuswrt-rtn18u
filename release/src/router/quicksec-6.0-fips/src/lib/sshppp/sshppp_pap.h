/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_PAP_H

#define SSH_PPP_PAP_H 1

#define SSH_PPP_PAP_CODE_AUTH_REQ 1
#define SSH_PPP_PAP_CODE_AUTH_ACK 2
#define SSH_PPP_PAP_CODE_AUTH_NAK 3

#define SSH_PPP_PAP_RESEND_MAX 10

typedef struct SshPppPapRec
{
  /* PPP Thread instance */
  struct SshPppThreadRec *ppp_thread;

  /* Secret */
  SshUInt8 *secret_buf;
  unsigned long secret_length;

  /* Peer ID */
  SshUInt8* peer_name_buf;
  unsigned long peer_name_length;

#ifdef SSHDIST_RADIUS
  SshPppRadiusClientStruct radius_client;
#endif /* SSHDIST_RADIUS */

  /* Identifier for matching requests and responses */
  SshPppIdentifierStruct id;

  /* Status */
  SshPppEvent auth_status;

  /* Mode */
  SshPppAuthMode auth_mode;

  /* Resend counter */
  SshPppCounter counter;

#ifdef SSHDIST_RADIUS
  /* Check whether RADIUS is in use */
  SshUInt8 is_radius_used;
#endif /* SSHDIST_RADIUS */
} *SshPppPap, SshPppPapStruct;

#define SSH_PAP_ENTRY() \
SSH_FSM_DATA(SshPppState, SshPppPap);\
ssh_ppp_thread_enter_state(gdata,tdata->ppp_thread);\
ssh_ppp_pap_handle_events(gdata,tdata);

#define SSH_PAP_EXIT() \
return ssh_ppp_thread_leave_state(gdata,tdata->ppp_thread);

SshPppEvents
ssh_ppp_pap_get_eventq(SshPppPap);

void*
ssh_ppp_pap_create(struct SshPppStateRec* gdata,
                   SshPppAuthMode mode,
                   SshPppEvents eventq,
                   SshPppFlush output_mux);

void
ssh_ppp_pap_destroy(void *auth_state);

void
ssh_ppp_pap_boot(void *auth_state);

void
ssh_ppp_pap_return_secret(struct SshPppStateRec *gdata,
                          void *auth_state,
                          SshUInt8* buf,
                          SshUInt32 len,
                          Boolean isvalid);

void
ssh_ppp_pap_get_secret(struct SshPppStateRec *gdata,
                       void *auth_state);

Boolean
ssh_ppp_pap_set_name(void *auth_state,
                     SshUInt8* buf,
                     unsigned long len);

SshPppEvents
ssh_ppp_pap_get_events(void *auth_state);

SshPppEvent
ssh_ppp_pap_get_status(void *auth_state);

SshPppAuthMode
ssh_ppp_pap_get_mode(void *auth_state);

#ifdef SSHDIST_RADIUS
void
ssh_ppp_pap_radius_cb(struct SshPppStateRec *gdata,
                      void *auth_state,
                      SshRadiusClientRequestStatus status,
                      SshRadiusClientRequest request,
                      SshRadiusOperationCode reply_code);
#endif /* SSHDIST_RADIUS */

SSH_FSM_STEP(ssh_ppp_pap_server_initial);
SSH_FSM_STEP(ssh_ppp_pap_server_done);
SSH_FSM_STEP(ssh_ppp_pap_client_initial);
SSH_FSM_STEP(ssh_ppp_pap_client_running);
SSH_FSM_STEP(ssh_ppp_pap_client_done);

#endif /* SSH_PPP_PAP_H */
