/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_SIM_H
#define SSH_EAP_SIM_H 1

/* Common client and server functionality */
void *ssh_eap_sim_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_sim_destroy(SshEapProtocol, SshUInt8, void*);
SshEapOpStatus ssh_eap_sim_signal(SshEapProtocolSignalEnum,
                                  SshEap, SshEapProtocol, SshBuffer);
SshEapOpStatus
ssh_eap_sim_key(SshEapProtocol protocol,
                SshEap eap, SshUInt8 type);


#ifdef SSHDIST_EAP_SIM
/* Client only functionality below */

/* Decoding codes for EAP SIM */
#define SSH_EAP_SIM_DEC_OK                  0

/* Error codes. */
#define SSH_EAP_SIM_ERR_GENERAL             50
#define SSH_EAP_SIM_ERR_INVALID_IE          51
#define SSH_EAP_SIM_ERR_PACKET_CORRUPTED    52
#define SSH_EAP_SIM_ERR_MEMALLOC_FAILED     53
#define SSH_EAP_SIM_ERR_INVALID_STATE       54
#define SSH_EAP_SIM_ERR_INVALID_VERSION     55

#define SSH_EAP_SIM_CHALLENGE_REPLY_BASE_LEN 28
#define SSH_EAP_SIM_CLIENT_ERROR_BASE_LEN    12
#define SSH_EAP_SIM_START_REPLY_BASE_LEN     32
#define SSH_EAP_SIM_NOTIF_REPLY_BASE_LEN     8

#define SSH_EAP_SIM_MAX_TRIPLETS       3
#define SSH_EAP_SIM_MAX_START_MESSAGES 3

#define SSH_EAP_SIM_MSK_LEN      64
#define SSH_EAP_SIM_EMSK_LEN     64
#define SSH_EAP_SIM_KENCR_LEN    16
#define SSH_EAP_SIM_KAUT_LEN     16
#define SSH_EAP_SIM_KC_LEN       8
#define SSH_EAP_SIM_NONCE_LEN    16
#define SSH_EAP_SIM_RAND_LEN     16
#define SSH_EAP_SIM_SRES_LEN     4
#define SSH_EAP_SIM_MAC_LEN      16

#define SSH_EAP_SIM_VERSION_1    0x01

#define SSH_EAP_SIM_PKT_NONCE_LEN   20
#define SSH_EAP_SIM_PKT_SEL_VER_LEN 4
#define SSH_EAP_SIM_PKT_AT_LEN_MAX  1024

/* Flags for EAP SIM protocol state. RFC 4186 strictly defines,
   which information elements may exist and what state and
   therefore we'll have to maintain strict state of the
   protocol. */
#define SSH_EAP_SIM_START_RCVD       0x0001
#define SSH_EAP_SIM_CHALLENGE_RCVD   0x0002
#define SSH_EAP_SIM_FULLID_RCVD      0x0004
#define SSH_EAP_SIM_PERMID_RCVD      0x0008
#define SSH_EAP_SIM_ANYID_RCVD       0x0010
#define SSH_EAP_SIM_START_INC_ID     0x0020
#define SSH_EAP_SIM_PROT_SUCCESS     0x0040
#define SSH_EAP_SIM_PROCESSING_RAND  0x0080
#define SSH_EAP_SIM_STATE_FAILED     0x0100

typedef struct SshEapSimTripletRec {

  SshUInt8 rand[SSH_EAP_SIM_RAND_LEN];

  SshUInt8 sres[SSH_EAP_SIM_SRES_LEN];
  SshUInt8 kc[SSH_EAP_SIM_KC_LEN];

} *SshEapSimTriplet, SshEapSimTripletStruct;

typedef struct SshEapSimStateRec {
  SshUInt32 sim_proto_flags;

  SshUInt8  msk[SSH_EAP_SIM_MSK_LEN];
  SshUInt8  emsk[SSH_EAP_SIM_EMSK_LEN];
  SshUInt8  K_encr[SSH_EAP_SIM_KENCR_LEN];
  SshUInt8  K_aut[SSH_EAP_SIM_KAUT_LEN];

  SshUInt8  nonce[SSH_EAP_SIM_NONCE_LEN];

  SshEapSimTripletStruct triplet[SSH_EAP_SIM_MAX_TRIPLETS];
  SshBuffer version_list;
  SshBuffer user;

  SshUInt8  selected_version[2];
  SshUInt8  response_id;
  SshUInt8  triplet_cnt;
  SshUInt8  version_list_len;
  SshUInt8  user_len;
  SshUInt8  start_msg_cnt;

  SshBuffer last_pkt;

} *SshEapSimState, SshEapSimStateStruct;

#endif /* SSHDIST_EAP_SIM */
#endif /** SSH_EAP_SIM_H */
