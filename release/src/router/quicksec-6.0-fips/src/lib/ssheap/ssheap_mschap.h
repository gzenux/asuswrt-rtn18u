/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_MSCHAPV2_H

#define SSH_EAP_MSCHAPV2_H 1

#ifdef SSHDIST_EAP_MSCHAPV2

#define SSH_EAP_MSCHAPV2_CHALLENGE 1
#define SSH_EAP_MSCHAPV2_RESPONSE  2
#define SSH_EAP_MSCHAPV2_SUCCESS   3
#define SSH_EAP_MSCHAPV2_FAILURE   4
#define SSH_EAP_MSCHAPV2_CHANGE_PW 7

#define SSH_EAP_MSCHAPV2_MSK_LEN                  64
#define SSH_EAP_MSCHAPV2_KEY_LEN                  16

#define SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH         16
#define SSH_EAP_MSCHAPV2_FAILURE_CHALLENGE_LENGTH 32
#define SSH_EAP_MSCHAPV2_RESERVED_LENGTH          8
#define SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH        24
#define SSH_EAP_MSCHAPV2_RESPONSE_LENGTH          49
/* The length of "E=xxx R=x C=xxxx V=xxx" for MS-CHAPv2 */
#define SSH_EAP_MSCHAPV2_FAILURE_LENGTH           74

/* Length of the MS-CHAPv2 response authenticator */
#define SSH_EAP_MSCHAPV2_AUTHRESP_LENGTH       20
#define SSH_EAP_MSCHAPV2_MAX_RESPONSE_LENGTH   SSH_EAP_MSCHAPV2_FAILURE_LENGTH

/* Peer flags */
#define SSH_EAP_MSCHAPV2_BEGIN                      0x0001
#define SSH_EAP_MSCHAPV2_CHALLENGE_REQUEST_RECEIVED 0x0002
#define SSH_EAP_MSCHAPV2_CHALLENGE_RESPONSE_SENT    0x0004
#define SSH_EAP_MSCHAPV2_SUCCESS_REQUEST_RECEIVED   0x0008
#define SSH_EAP_MSCHAPV2_FAILURE_REQUEST_RECEIVED   0x0010
#define SSH_EAP_MSCHAPV2_FAILURE_RESPONSE_SENT      0x0020
#define SSH_EAP_MSCHAPV2_SUCCESS_STATUS             0x0040
#define SSH_EAP_MSCHAPV2_FAILURE_STATUS             0x0080

typedef struct SshEapMschapv2StateRec {
  /* Peer */
  SshUInt32 flags;
  /** The received challenge */
  SshUInt8 *challenge_buffer;
  SshUInt16 challenge_length;

  /** The peer challenge */
  SshUInt8 peer_challenge_buffer[SSH_EAP_MSCHAPV2_CHALLENGE_LENGTH];

  /** The MS-CHAPv2-ID */
  SshUInt8 identifier;

  /* NT response buffer */
  SshUInt8 nt_response_buffer[SSH_EAP_MSCHAPV2_NTRESPONSE_LENGTH];

  /* The latest peer name used */
  SshUInt16 peer_name_length;
  SshUInt8 *peer_name;

  /* The secret as provided via caller */
  SshUInt8 *secret_buf;
  SshUInt16 secret_length;

  /* New secret for MS-CHAP password changing */
  SshUInt8 *new_secret_buf;
  SshUInt16 new_secret_length;
  unsigned int is_secret_newpw : 1;

  SshUInt8  msk[SSH_EAP_MSCHAPV2_MSK_LEN];

} *SshEapMschapv2State, SshEapMschapv2StateStruct;
#endif /* SSHDIST_EAP_MSCHAPV2 */

void*
ssh_eap_mschap_v2_create(SshEapProtocol protocol,
                         SshEap eap,
                         SshUInt8 type);
void
ssh_eap_mschap_v2_destroy(SshEapProtocol protocol,
                          SshUInt8 type,
                          void *ctx);
SshEapOpStatus
ssh_eap_mschap_v2_signal(SshEapProtocolSignalEnum sig,
                         SshEap eap,
                         SshEapProtocol protocol,
                         SshBuffer buf);
SshEapOpStatus
ssh_eap_mschap_v2_key(SshEapProtocol protocol,
                      SshEap eap,
                      SshUInt8 type);

#endif /* SSH_EAP_MSCHAPV2_H */
