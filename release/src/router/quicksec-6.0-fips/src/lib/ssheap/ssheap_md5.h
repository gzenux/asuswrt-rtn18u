/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_MD5_H

#define SSH_EAP_MD5_H 1

typedef struct SshEapMd5StateRec {

  /** The challenge sent */
  SshUInt8* challenge_buffer;
  unsigned long challenge_length;

  /** The response received */
  SshUInt8* response_buffer;
  unsigned long response_length;
  SshUInt8 response_id;

} *SshEapMd5State, SshEapMd5StateStruct;

typedef struct SshEapMd5ParamsRec {

  /** Length of challenge to create */
  unsigned long challenge_length;

  /** Name of this instance to use in CHAP authentication */

  SshUInt8* name_buffer;
  unsigned long name_length;

} *SshEapMd5Params, SshEapMd5ParamsStruct;

void* ssh_eap_md5_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_md5_destroy(SshEapProtocol, SshUInt8,void*);
SshEapOpStatus ssh_eap_md5_signal(SshEapProtocolSignalEnum,
                                  SshEap,
                                  SshEapProtocol,
                                  SshBuffer);


#endif
