/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_PASS_THROUGH_H
#define SSH_EAP_PASS_THROUGH_H 1

void *ssh_eap_pass_through_create(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshUInt8 type);

void ssh_eap_pass_through_destroy(SshEapProtocol protocol,
                                  SshUInt8 type,
                                  void* state);

SshEapOpStatus ssh_eap_pass_through_signal(SshEapProtocolSignalEnum sig,
                                           SshEap eap,
                                           SshEapProtocol protocol,
                                           SshBuffer buf);

SshEapOpStatus ssh_eap_pass_through_key(SshEapProtocol protocol,
                                        SshEap eap,
                                        SshUInt8 type);

typedef struct SshEapPassThroughStateRec {
  SshUInt32 dummy_data;
} *SshEapPassThroughState, SshEapPassThroughStateStruct;

#endif /** SSH_EAP_PASS_THROUGH_H */
