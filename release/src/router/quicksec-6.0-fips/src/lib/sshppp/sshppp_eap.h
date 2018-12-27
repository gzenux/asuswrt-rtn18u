/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_EAP_H

#define SSH_PPP_EAP_H 1

typedef struct SshPppEapRec
{
  /* EAP instance */
  SshEapConnection eap_con;
  SshEapConfiguration eap_config;
  SshEap eap;
  SshPppAuthMode auth_mode;
  SshPppEvent auth_status;

  /* Peer name */
  unsigned long peer_name_length;
  SshUInt8 *peer_name;

  /* This is for the EAP library callbacks */
  struct SshPppStateRec *gdata;

  /* Secret buffer */
  SshEapToken token;
  SshEapTokenType token_type;

  /* PPP Thread instance */
  struct SshPppThreadRec *ppp_thread;

  /* Flags */
  unsigned int is_timeout:1;
  unsigned int is_identity:1;
  unsigned int is_auth_ok:1;
  unsigned int is_auth_this_fail:1;
  unsigned int is_auth_peer_fail:1;
  unsigned int is_secret_id:1;
  unsigned int is_radius_used:1;
  unsigned int require_mutual_auth:1;

  SshUInt8 eap_type;
} SshPppEapStruct, *SshPppEap;

#define SSH_EAP_ENTRY() \
SSH_FSM_DATA(SshPppState, SshPppEap);\
ssh_ppp_thread_enter_state(gdata,tdata->ppp_thread);\
ssh_ppp_eap_handle_events(gdata,tdata);

#define SSH_EAP_EXIT() \
return ssh_ppp_thread_leave_state(gdata,tdata->ppp_thread);

/* Build the EAP instance */

SshPppEvents
ssh_ppp_eap_get_eventq(SshPppEap);

void*
ssh_ppp_eap_create(struct SshPppStateRec *gdata,
                   SshPppAuthMode mode,
                   SshPppEvents eventq,
                   SshPppFlush output_mux);

void
ssh_ppp_eap_destroy(void *auth_state);

void
ssh_ppp_eap_boot(void *auth_state);

void
ssh_ppp_eap_return_secret(struct SshPppStateRec *state,
                          void  *auth_state,
                          SshUInt8 *buf,
                          SshUInt32 len, Boolean);

void
ssh_ppp_eap_get_secret(struct SshPppStateRec* state,
                       void *ctx);

#ifdef SSHDIST_EAP
void
ssh_ppp_eap_return_token(struct SshPppStateRec *state,
                         void *auth_state,
                         SshUInt8 eap_type,
                         SshEapToken tok,
                         Boolean isvalid);
void
ssh_ppp_eap_get_token(struct SshPppStateRec* state,
                      void *ctx);
#endif /* SSHDIST_EAP */

Boolean
ssh_ppp_eap_set_name(void *auth_state,
                     SshUInt8 *buf,
                     unsigned long len);

SshPppEvents
ssh_ppp_eap_get_events(void *auth_state);

SshPppAuthMode
ssh_ppp_eap_get_mode(void *auth_state);

SshPppEvent
ssh_ppp_eap_get_status(void *auth_state);

#ifdef SSHDIST_RADIUS
void
ssh_ppp_eap_set_radius(void *auth_state,
                       SshPppRadiusConfiguration radius_config);

void
ssh_ppp_eap_radius_cb(struct SshPppStateRec *gdata,
                      void *auth_state,
                      SshRadiusClientRequestStatus status,
                      SshRadiusClientRequest request,
                      SshRadiusOperationCode reply_code);

#endif /* SSHDIST_RADIUS */

/* State machine prototypes */

SSH_FSM_STEP(ssh_eap_server_initial);
SSH_FSM_STEP(ssh_eap_server_identity);
SSH_FSM_STEP(ssh_eap_server_request);
SSH_FSM_STEP(ssh_eap_server_success);
SSH_FSM_STEP(ssh_eap_server_failure);

SSH_FSM_STEP(ssh_eap_client_initial);
SSH_FSM_STEP(ssh_eap_client_waiting);

#endif /* SSH_PPP_EAP_H */
