/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_pass_through.h"

#define SSH_DEBUG_MODULE "SshEapPassThrough"

void *ssh_eap_pass_through_create(SshEapProtocol protocol,
                                  SshEap eap,
                                  SshUInt8 type)
{
  SshEapPassThroughState state;

  state = ssh_malloc(sizeof(*state));
  if (state == NULL)
    return NULL;

  memset(state, 0, sizeof(SshEapPassThroughStateStruct));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Created EAP pass through state"));

  return state;

}

void ssh_eap_pass_through_destroy(SshEapProtocol protocol,
                                  SshUInt8 type,
                                  void* state)
{
  if (state == NULL)
    return;

  ssh_free(state);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("EAP pass through state destroyed"));

  return;
}

SshEapOpStatus ssh_eap_pass_through_signal(SshEapProtocolSignalEnum sig,
                                           SshEap eap,
                                           SshEapProtocol protocol,
                                           SshBuffer buf)
{
  /* Implement handling for signals here */

  return SSH_EAP_OPSTATUS_SUCCESS;
}


SshEapOpStatus ssh_eap_pass_through_key(SshEapProtocol protocol,
                                        SshEap eap,
                                        SshUInt8 type)
{
  /* Implement shared key fetching here */

  return SSH_EAP_OPSTATUS_SUCCESS;
}
