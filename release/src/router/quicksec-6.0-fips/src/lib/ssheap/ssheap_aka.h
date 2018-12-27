/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ssheap_aka.h
*/

#ifndef SSH_EAP_AKA_H
#define SSH_EAP_AKA_H 1

/* Common client and server functionality */
void *ssh_eap_aka_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_aka_destroy(SshEapProtocol, SshUInt8, void*);
SshEapOpStatus ssh_eap_aka_signal(SshEapProtocolSignalEnum,
                                  SshEap, SshEapProtocol, SshBuffer);
SshEapOpStatus
ssh_eap_aka_key(SshEapProtocol protocol,
                SshEap eap, SshUInt8 type);

#ifdef SSHDIST_EAP_AKA
/* Client only functionality below */

/* Decoding codes for EAP AKA */
#define SSH_EAP_AKA_DEC_OK                  0

/* EAP aka error codes. */
#define SSH_EAP_AKA_ERR_GENERAL             50
#define SSH_EAP_AKA_ERR_INVALID_IE          51
#define SSH_EAP_AKA_ERR_PACKET_CORRUPTED    52
#define SSH_EAP_AKA_ERR_MEMALLOC_FAILED     53
#define SSH_EAP_AKA_ERR_INVALID_STATE       54
#define SSH_EAP_AKA_ERR_USE_AKA_DASH        55 /* Flag for defining that
                                                  server wishes to use the
                                                  AKA-DASH over AKA */
/* EAP aka-dash error codes */

#define SSH_EAP_AKA_MAX_IDENTITY_MSGS      3

#define SSH_EAP_AKA_IDENTITY_REPLY_LEN     8
#define SSH_EAP_AKA_SYNCH_REPLY_LEN        24
#define SSH_EAP_AKA_AUTH_REJ_REPLY_LEN     8
#define SSH_EAP_AKA_NOTIF_REPLY_LEN        8
#define SSH_EAP_AKA_CHALLENGE_REPLY_LEN    48
#define SSH_EAP_AKA_CLIENT_ERROR_REPLY_LEN 12

#define SSH_EAP_AKA_MSK_LEN       64
#define SSH_EAP_AKA_EMSK_LEN      64
#define SSH_EAP_AKA_KENCR_LEN     16
#define SSH_EAP_AKA_KAUT_LEN      16
#define SSH_EAP_AKA_RAND_LEN      16
#define SSH_EAP_AKA_MAC_LEN       16
#define SSH_EAP_AKA_AUTS_LEN      14
#define SSH_EAP_AKA_AUTN_LEN      16
#define SSH_EAP_AKA_CK_LEN        16
#define SSH_EAP_AKA_IK_LEN        16

/* Flags for EAP AKA protocol state. RFC 4187 strictly defines,
   which information elements may exist and what state and
   therefore we'll have to maintain strict state of the
   protocol. */
#define SSH_EAP_AKA_IDENTITY_RCVD    0x0001
#define SSH_EAP_AKA_CHALLENGE_RCVD   0x0002
#define SSH_EAP_AKA_SYNCH_REQ_SENT   0x0004
#define SSH_EAP_AKA_PROT_SUCCESS     0x0008
#define SSH_EAP_AKA_PROCESSING_RAND  0x0010
#define SSH_EAP_AKA_FULLID_RCVD      0x0020
#define SSH_EAP_AKA_PERMID_RCVD      0x0040
#define SSH_EAP_AKA_ANYID_RCVD       0x0080
#define SSH_EAP_AKA_STATE_FAILED     0x0100
/* Flag for keeping the track of the bidding request */
#define SSH_EAP_AKA_BIDDING_REQ_RCVD 0x0200

typedef struct SshEapAkaIdentityRec {
  SshUInt8 rand[SSH_EAP_AKA_RAND_LEN];
  SshUInt8 autn[SSH_EAP_AKA_AUTN_LEN];
  SshUInt8 auts[SSH_EAP_AKA_AUTS_LEN];

  SshUInt8 IK[SSH_EAP_AKA_IK_LEN];
  SshUInt8 CK[SSH_EAP_AKA_CK_LEN];

  SshUInt8 res[16];
  SshUInt8 res_len;

} *SshEapAkaIdentity, SshEapAkaIdentityStruct;

typedef struct SshEapAkaStateRec {
  SshUInt32 aka_proto_flags;

  SshUInt8  msk[SSH_EAP_AKA_MSK_LEN];
  SshUInt8  emsk[SSH_EAP_AKA_EMSK_LEN];
  SshUInt8  K_encr[SSH_EAP_AKA_KENCR_LEN];
  union
    {
      SshUInt8  K_aut[SSH_EAP_AKA_KAUT_LEN];
    } aut;

  SshEapAkaIdentityStruct aka_id;

  SshBuffer user;

  SshUInt8  response_id;
  SshUInt8  user_len;
  SshUInt8  identity_msg_cnt;
  /* Transform value, this transform represents the capability for KDF
     algorithm */
  SshUInt32 transform;

  SshBuffer last_pkt;

} *SshEapAkaState, SshEapAkaStateStruct;

#endif /* SSHDIST_EAP_AKA */
#endif /** SSH_EAP_AKA_H */
