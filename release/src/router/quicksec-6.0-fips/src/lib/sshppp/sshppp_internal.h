/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshppp_internal.h
*/

#ifndef SSHPPP_INTERNAL_H

#define SSHPPP_INTERNAL_H 1

/* The definitions of structures not shown in sshppp.h. */

/* A simple aggregate of all the stuff associated with one
   PPP Link. */

struct SshPppLinkRec
{
  SshPppFlush mux_instance;

  struct SshLcpLocalRec *lcp;
  SshPppEventsOutput events_lcp;

  SshPppAuthProtocolStruct auth_server;
  SshPppAuthProtocolStruct auth_client;

  SshUInt8 client_auth_required;
  SshUInt8 server_auth_required;
};


#ifndef SSH_FSM_GDATA
#define SSH_FSM_GDATA(x) \
x gdata = (x)ssh_fsm_get_gdata(thread);
#endif /* SSH_FSM_GDATA */

#ifndef SSH_FSM_TDATA
#define SSH_FSM_TDATA(x) \
x tdata = (x)ssh_fsm_get_tdata(thread);
#endif /* SSH_FSM_TDATA */

#ifndef SSH_FSM_DATA
#define SSH_FSM_DATA(x,y) \
x gdata = (x)ssh_fsm_get_gdata(thread);\
y tdata = (y)ssh_fsm_get_tdata(thread);
#endif /* SSH_FSM_DATA */

typedef struct SshPppStateRec
{
  /* The link control protocols */
  struct SshPppLinkRec link;

  /* The network level protocol */
  struct SshIpcpLocalRec *ipcp;
  SshPppEventsOutput events_ipcp;

  /* The FSM thing */
  SshFSM fsm;

  /* Scheduler state */
  struct SshPppThreadRec *ppp_thread;

  /* Context */
  void *ctx;

  SshPppSignalCB signal_cb;

  SshPPPGetSecretCB get_server_secret_cb;
  SshPPPGetSecretCB get_client_secret_cb;

  SshUInt8 *sys_name;
  unsigned long sys_name_length;

#ifdef SSHDIST_RADIUS
  SshPppRadiusConfiguration radius_config;
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_EAP
  SshPPPGetTokenCB get_server_eap_token_cb;
  SshPPPGetTokenCB get_client_eap_token_cb;





  unsigned int eap_server_md5:1;
  unsigned int eap_client_md5:1;
#endif /* SSHDIST_EAP */
  /* This is a one-bit counter for intra-state "asynchronicity" */
  unsigned int kludge:1;

  /* Are we being called through our own callback? */
  unsigned int cb_mode:1;

  /* Fields copied from SshPppParams */
  unsigned int no_magic_lcp:1;

  /* Has fatal signal been issued? */
  unsigned int fatal_error:1;
} SshPppStateStruct, *SshPppState;

/* Wrapper for callbacks */

#define SSH_PPP_CB(gdata,x)                     \
do {                                            \
  gdata->cb_mode = 1;                           \
  x;                                            \
  gdata->cb_mode = 0;                           \
} while (0)

#ifdef SSHDIST_RADIUS
typedef struct SshPppRadiusClientRec
{
  SshOperationHandle radius_handle;
  SshRadiusClientRequest radius_req;
} SshPppRadiusClientStruct, *SshPppRadiusClient;
#endif /* SSHDIST_RADIUS */

#define SSH_PPP_SIGNAL_CB(gdata,x)                                      \
do {                                                                    \
  if ((gdata)->signal_cb != NULL_FNPTR)                                 \
    {                                                                   \
      SSH_PPP_CB((gdata), (gdata)->signal_cb((gdata)->ctx, (x)));       \
    }                                                                   \
} while (0)

void ssh_ppp_lcp_up(SshPppState ppp);
void ssh_ppp_server_auth_ok(SshPppState ppp);
void ssh_ppp_server_auth_fail(SshPppState ppp);
void ssh_ppp_client_auth_ok(SshPppState ppp);
void ssh_ppp_client_auth_fail(SshPppState ppp);

void ssh_ppp_kill_auth_protocols(SshPppState ppp);
void ssh_ppp_kill_ncp_protocols(SshPppState ppp);
void ssh_ppp_kill_ipcp(SshPppState ppp);
void ssh_ppp_kill_protocols(SshPppState ppp);
void ssh_ppp_cleanup(SshPppState ppp);
void ssh_ppp_fatal(SshPppState ppp);

#ifdef SSHDIST_EAP
void ssh_ppp_get_token(SshPppState ppp,
                       void *auth_ctx,
                       SshPppAuthType auth_type,
                       SshUInt8 auth_protocol,
                       SshEapTokenType token_type,
                       SshUInt8 *buf,
                       unsigned long len);
#endif /* SSHDIST_EAP */

void ssh_ppp_get_secret(SshPppState ppp,
                        void *auth_ctx,
                        SshPppAuthType type,
                        SshUInt8 *user_name,
                        unsigned long user_len);

void ssh_ppp_forget_secret(SshUInt8 *secret_buf,
                           unsigned long secret_len);

void ssh_ppp_free_params(SshPppParams params);

void ssh_ppp_invalidate_config(SshPppState gdata);

/* Prototypes for RADIUS integration */

#ifdef SSHDIST_RADIUS

void
ssh_ppp_radius_init(SshPppRadiusClient radius_client);

void
ssh_ppp_radius_uninit(SshPppRadiusClient radius_client);

void
ssh_ppp_radius_configure_radius(SshPppState gdata,
                                SshPppRadiusConfiguration config);

Boolean
ssh_ppp_radius_make_chap_query(SshPppState gdata,
                               SshPppRadiusClient radius_client,
                               SshUInt8 algorithm,
                               SshUInt8 *user,
                               size_t user_length,
                               SshUInt8 challenge_id,
                               SshUInt8 *challenge,
                               size_t challenge_length,
                               SshUInt8 *response,
                               size_t response_length);

Boolean
ssh_ppp_radius_make_changepw_query(SshPppState gdata,
                                   SshPppRadiusClient radius_client,
                                   SshUInt8 algorithm,
                                   SshUInt8 id,
                                   SshUInt8 *peer_name,
                                   size_t peer_name_length,
                                   SshUInt8 *challenge,
                                   size_t challenge_length,
                                   SshUInt8 *response,
                                   size_t response_length);

Boolean
ssh_ppp_radius_make_pap_query(SshPppState gdata,
                              SshPppRadiusClient radius_client,
                              SshUInt8 *user_buf,
                              SshUInt8 user_length,
                              SshUInt8 *pw_buf,
                              SshUInt8 pw_length);

Boolean
ssh_ppp_radius_parse_nopayload_reply(SshPppState gdata,
                                     SshPppAuthType auth_type,
                                     SshRadiusClientRequestStatus stat,
                                     SshRadiusClientRequest request,
                                     SshRadiusOperationCode reply_code);
/* Avoid warnings */
struct SshPppChapRec;

Boolean
ssh_ppp_radius_parse_chap_reply(SshPppState gdata,
                                SshUInt8 algorithm,
                                SshRadiusClientRequestStatus stat,
                                SshRadiusClientRequest request,
                                SshRadiusOperationCode reply_code,
                                unsigned char **param_return,
                                size_t *param_len_return);


#endif /* SSHDIST_RADIUS */

/* Prototypes for sshppp_fsm.c and sshppp_protocol_fsm.c
   state machines. */

SSH_FSM_STEP(ssh_ppp_dead);
SSH_FSM_STEP(ssh_ppp_waking);
SSH_FSM_STEP(ssh_ppp_up);
SSH_FSM_STEP(ssh_ppp_up_to_authenticate);
SSH_FSM_STEP(ssh_ppp_authenticate);
SSH_FSM_STEP(ssh_ppp_authenticate_to_network);
SSH_FSM_STEP(ssh_ppp_network);
SSH_FSM_STEP(ssh_ppp_terminating);
SSH_FSM_STEP(ssh_ppp_terminate);
SSH_FSM_STEP(ssh_ppp_grave);
SSH_FSM_STEP(ssh_ppp_fatal_error);
SSH_FSM_STEP(ssh_ppp_fatal_wait);

SSH_FSM_STEP(ssh_lcp_initial);
SSH_FSM_STEP(ssh_lcp_starting);
SSH_FSM_STEP(ssh_lcp_closed);
SSH_FSM_STEP(ssh_lcp_stopped);
SSH_FSM_STEP(ssh_lcp_closing);
SSH_FSM_STEP(ssh_lcp_stopping);
SSH_FSM_STEP(ssh_lcp_req_sent);
SSH_FSM_STEP(ssh_lcp_ack_rcvd);
SSH_FSM_STEP(ssh_lcp_ack_sent);
SSH_FSM_STEP(ssh_lcp_opened);
SSH_FSM_STEP(ssh_lcp_opening);

SSH_FSM_STEP(ssh_condition_loop);

#endif /* SSHPPP_INTERNAL_H */
