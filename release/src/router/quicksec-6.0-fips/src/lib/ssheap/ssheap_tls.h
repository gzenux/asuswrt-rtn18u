/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAP_TLS_H
#define SSH_EAP_TLS_H 1

/* Common client and server functionality */
void *ssh_eap_tls_create(SshEapProtocol, SshEap eap, SshUInt8);
void ssh_eap_tls_destroy(SshEapProtocol, SshUInt8, void*);
SshEapOpStatus ssh_eap_tls_signal(SshEapProtocolSignalEnum,
                                  SshEap, SshEapProtocol, SshBuffer);
SshEapOpStatus
ssh_eap_tls_key(SshEapProtocol protocol,
                SshEap eap, SshUInt8 type);
#endif /* SSH_EAP_TLS_H */
