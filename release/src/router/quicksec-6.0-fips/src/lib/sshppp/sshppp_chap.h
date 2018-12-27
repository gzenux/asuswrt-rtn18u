/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_CHAP_H

#define SSH_PPP_CHAP_H 1

#define SSH_PPP_CHAP_CODE_CHALLENGE 1
#define SSH_PPP_CHAP_CODE_RESPONSE 2
#define SSH_PPP_CHAP_CODE_SUCCESS 3
#define SSH_PPP_CHAP_CODE_FAILURE 4
#define SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv2 6
#define SSH_PPP_CHAP_CODE_MSCHAP_CHANGEPWv3 7

#define SSH_PPP_CHAP_ALGORITHM_NONE 0
#define SSH_PPP_CHAP_ALGORITHM_MD5 5
#define SSH_PPP_CHAP_ALGORITHM_MSCHAPV1 0x80
#define SSH_PPP_CHAP_ALGORITHM_MSCHAPV2 0x81

/* Misc constants regarding CHAP */
#define SSH_PPP_CHAP_MAX_CHALLENGE_LENGTH 255
#define SSH_PPP_CHAP_RESPONSE_LENGTH 16

#define SSH_PPP_MSCHAPV1_LMRESPONSE_LENGTH 24
#define SSH_PPP_MSCHAPV1_NTRESPONSE_LENGTH 24
#define SSH_PPP_MSCHAPV1_RESPONSE_LENGTH 49

#define SSH_PPP_MSCHAPV2_PEER_CHALLENGE_LENGTH 16
#define SSH_PPP_MSCHAPV2_RESERVED_LENGTH 8
#define SSH_PPP_MSCHAPV2_NTRESPONSE_LENGTH 24

/* The sum of the above three + 1 */
#define SSH_PPP_MSCHAPV2_RESPONSE_LENGTH 49

/* The length of "E=xxx R=x C=xxxx V=xxx" for MS-CHAPv2 */
#define SSH_PPP_MSCHAPV2_FAILURE_LENGTH 74

/* Length of the MS-CHAPv2 response authenticator */
#define SSH_PPP_MSCHAPV2_AUTHRESP_LENGTH 20

/* Size of the buffer we use for storing response messages */
#define SSH_PPP_CHAP_MAX_RESPONSE_LENGTH SSH_PPP_MSCHAPV2_FAILURE_LENGTH


typedef struct SshPppChapRec
{
  /* My name in CHAP protocol */
  unsigned long my_name_length;
  SshUInt8 *my_name;

  /* Length of challenges to generate */
  unsigned long challenge_length;

  /* Challenge. Note "challenge_length" above. */
  SshUInt8 *challenge;
  /* Last name field from peer. This is stored
     here due to use in asynch callbacks. */
  unsigned long peer_name_length;
  SshUInt8 *peer_name;

  /* The secret as provided via caller */
  SshUInt8* secret_buf;
  unsigned long secret_length;

  /* New secret for MS-CHAP password changing */
  SshUInt8* new_secret_buf;
  unsigned long new_secret_length;

  /* Length of response */
  unsigned long response_length;
  SshUInt8 response_buf[SSH_PPP_CHAP_MAX_RESPONSE_LENGTH];

  /* Event Queues and Magic Box Scheduling */
  SshPppThread ppp_thread;

#ifdef SSHDIST_RADIUS
  SshPppRadiusClientStruct radius_client;
#endif /* SSHDIST_RADIUS */

  /* CHAP protocol datagram id */
  SshPppIdentifierStruct id;

  /* Timeout counters */
  SshPppCounter counter_current;
  SshPppCounter counter_max;

  /* Algorithm to use */
  SshUInt8 algorithm;

  /* Status */
  SshPppEvent auth_status;
  SshPppAuthMode auth_mode;

  unsigned int is_secret_newpw:1;

#ifdef SSHDIST_RADIUS
  unsigned int is_radius_used:1;
#endif /* SSHDIST_RADIUS */

  unsigned int is_reauth_tmout_set:1;
} *SshPppChap, SshPppChapStruct;

/* Implementation of the authentication protocol interface */

SshPppEvents
ssh_ppp_chap_get_eventq(SshPppChap);

void*
ssh_ppp_chap_create(SshPppState gdata,
                    SshPppAuthMode foo,
                    SshPppEvents events,
                    SshPppFlush output_mux);


void*
ssh_ppp_chap_create_mschapv2(SshPppState gdata,
                             SshPppAuthMode foo,
                             SshPppEvents events,
                             SshPppFlush output_mux);

void*
ssh_ppp_chap_create_mschapv1(SshPppState gdata,
                             SshPppAuthMode foo,
                             SshPppEvents events,
                             SshPppFlush output_mux);

void
ssh_ppp_chap_destroy(void*);

void
ssh_ppp_chap_boot(void* ctx);

Boolean
ssh_ppp_chap_set_name(void*, SshUInt8* buf, unsigned long len);

SshPppEvent
ssh_ppp_chap_get_status(void*);

SshPppEvents
ssh_ppp_chap_get_events(void*);

SshPppAuthMode
ssh_ppp_chap_get_mode(void *auth_state);

void
ssh_ppp_chap_return_secret(SshPppState gdata,
                           void *auth_state,
                           SshUInt8 *sys_name,
                           SshUInt32 sys_name_length,
                           Boolean isvalid);

void
ssh_ppp_chap_get_secret(SshPppState gdata,
                        void* ctx,
                        unsigned int is_changepw);

void
ssh_ppp_chap_get_secret_api(SshPppState gdata,
                            void* ctx);

Boolean
ssh_ppp_chap_nt_oldpwhash_encrypt_with_newpwhash(unsigned char *old_secret,
                                                 size_t old_secret_length,
                                                 unsigned char *new_secret,
                                                 size_t new_secret_length,
                                                 unsigned char *dst,
                                                 size_t dstlen);


#ifdef SSHDIST_RADIUS
void
ssh_ppp_chap_radius_cb(struct SshPppStateRec *gdata,
                       void *auth_state,
                       SshRadiusClientRequestStatus status,
                       SshRadiusClientRequest request,
                       SshRadiusOperationCode reply_code);
#endif /* SSHDIST_RADIUS */

/* Functions called from sshppp_chap_fsm.h */

SshPppPktBuffer
ssh_ppp_chap_get_output_buf(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_output_challenge(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_output_success(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_output_failure(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_output_response(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_build_response(SshPppState gdata, SshPppChap chap);

void
ssh_ppp_chap_build_success(SshPppState gdata, SshPppChap chap,
                           unsigned char *payload, size_t payload_len);

Boolean
ssh_ppp_chap_build_failure(SshPppState gdata, SshPppChap chap,
                           unsigned char *payload, size_t payload_len);


SshPppEvent
ssh_ppp_chap_mschap_failure_to_event(SshPppState gdata,
                                     SshPppChap chap,
                                     unsigned char *ucp,
                                     size_t len);


SshPppEvent
ssh_ppp_chap_input_challenge(SshPppState gdata, SshPppChap chap);

SshPppEvent
ssh_ppp_chap_input_response(SshPppState gdata, SshPppChap chap);

SshPppEvent
ssh_ppp_chap_input_success(SshPppState gdata, SshPppChap chap);

SshPppEvent
ssh_ppp_chap_input_failure(SshPppState gdata, SshPppChap chap);

SshPppEvent
ssh_ppp_chap_input(SshPppState state, SshPppChap chap);

void
ssh_ppp_chap_get_changepw_status(SshPppState gdata, SshPppChap chap);


void
ssh_ppp_chap_inc_id(SshPppState,SshPppChap);

void
ssh_ppp_chap_init_challenge(SshPppState,SshPppChap);

void
ssh_ppp_chap_init_peer_challenge(SshPppState,SshPppChap);

SshPppEvent
ssh_ppp_chap_input_server_secret(SshPppState gdata, SshPppChap chap);

/* This is for t-mschap.c */
Boolean
ssh_ppp_chap_generate_ntresponse(unsigned char *secret,
                                 size_t secret_length,
                                 unsigned char *peer_challenge,
                                 size_t peer_challenge_length,
                                 unsigned char *challenge,
                                 size_t challenge_length,
                                 unsigned char *user_name,
                                 size_t user_name_length,
                                 unsigned char *dst,
                                 size_t dstlen);

Boolean
ssh_ppp_chap_generate_ntresponse_v1(unsigned char *secret,
                                    size_t secret_length,
                                    unsigned char *challenge,
                                    size_t challenge_length,
                                    unsigned char *dst,
                                    size_t dstlen);

void
ssh_ppp_chap_expand_des_key(unsigned char *out, unsigned char *orig_in);

Boolean
ssh_ppp_chap_generate_authenticator_response(unsigned char *secret,
                                             size_t secret_length,
                                             unsigned char *peer_challenge,
                                             size_t peer_challenge_length,
                                             unsigned char *challenge,
                                             size_t challenge_length,
                                             unsigned char *user_name,
                                             size_t user_name_length,
                                             unsigned char *ntresponse,
                                             size_t ntresponse_length,
                                             unsigned char *dst,
                                             size_t dstlen);


/* FSM prototypes */

SSH_FSM_STEP(ssh_chap_server_initial);
SSH_FSM_STEP(ssh_chap_server_auth);
SSH_FSM_STEP(ssh_chap_server_challenge);
SSH_FSM_STEP(ssh_chap_server_verify);
SSH_FSM_STEP(ssh_chap_server_failed);

SSH_FSM_STEP(ssh_chap_client_initial);
SSH_FSM_STEP(ssh_chap_client_wait);
SSH_FSM_STEP(ssh_chap_client_generate);
SSH_FSM_STEP(ssh_chap_client_result);
SSH_FSM_STEP(ssh_chap_client_auth_ok);
SSH_FSM_STEP(ssh_chap_client_auth_peer_fail);
SSH_FSM_STEP(ssh_chap_client_auth_this_fail);
SSH_FSM_STEP(ssh_chap_client_auth_this_fail_rechallenge);
SSH_FSM_STEP(ssh_chap_client_auth_done);

#endif /* SSH_PPP_CHAP_H */
