/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"

#include "ssheap.h"
#include "ssheapi.h"

#define SSH_DEBUG_MODULE "SshEapTokencard"

void*
ssh_eap_tokencard_create(SshEapProtocol protocol, SshEap eap, SshUInt8 type)
{
  return NULL;
}

void
ssh_eap_tokencard_destroy(SshEapProtocol protocol, SshUInt8 type, void*state)
{


}

SshEapOpStatus
ssh_eap_tokencard_signal(SshEapProtocolSignalEnum sig,
                         SshEap eap,
                         SshEapProtocol protocol,
                         SshBuffer buf)
{
  return SSH_EAP_OPSTATUS_SUCCESS;
}
