/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"

#include "ssheap.h"
#include "ssheapi.h"
#include "ssheap_config.h"

#include "ssheap_md5.h"
#include "ssheap_sim.h"
#include "ssheap_tls.h"
#include "ssheap_aka.h"
#include "ssheap_mschap.h"
#include "ssheap_pass_through.h"






#define SSH_DEBUG_MODULE "SshEapConfig"

/*
  This file contains the configuration related to all protocols
  supported by the SSH EAP library.

  New implementations can be configured here.
*/

const
SshEapProtocolImplStruct ssh_eap_protocols[] = {
  {
    SSH_EAP_TYPE_MD5_CHALLENGE,
    0,
    ssh_eap_md5_create,
    ssh_eap_md5_destroy,
    ssh_eap_md5_signal,
    NULL_FNPTR
  }
#ifdef SSHDIST_EAP_TLS
  , {
    SSH_EAP_TYPE_TLS,
    SSH_EAP_MUTUAL_AUTHENTICATION_SUPPORTED,
    ssh_eap_tls_create,
    ssh_eap_tls_destroy,
    ssh_eap_tls_signal,
    ssh_eap_tls_key
  }
#endif /* SSHDIST_EAP_TLS */
  , {
    SSH_EAP_TYPE_SIM,
    SSH_EAP_PASS_THROUGH_ONLY | SSH_EAP_MUTUAL_AUTHENTICATION_SUPPORTED,
    ssh_eap_sim_create,
    ssh_eap_sim_destroy,
    ssh_eap_sim_signal,
    ssh_eap_sim_key
  }
  , {
    SSH_EAP_TYPE_AKA,
    SSH_EAP_PASS_THROUGH_ONLY | SSH_EAP_MUTUAL_AUTHENTICATION_SUPPORTED,
    ssh_eap_aka_create,
    ssh_eap_aka_destroy,
    ssh_eap_aka_signal,
    ssh_eap_aka_key
  }
  , {
    SSH_EAP_TYPE_MSCHAP_V2,
    SSH_EAP_PASS_THROUGH_ONLY,
    ssh_eap_mschap_v2_create,
    ssh_eap_mschap_v2_destroy,
    ssh_eap_mschap_v2_signal,
    ssh_eap_mschap_v2_key
  }
  , {
    /* Sample EAP pass through method, uses EAP type experimental */
    SSH_EAP_TYPE_EXPERIMENTAL,
    SSH_EAP_PASS_THROUGH_ONLY,
    ssh_eap_pass_through_create,
    ssh_eap_pass_through_destroy,
    ssh_eap_pass_through_signal,
    ssh_eap_pass_through_key
  }


















};

SshEapProtocolImpl
ssh_eap_config_get_impl_by_type(SshUInt8 type)
{
  int i;

  for (i = 0; i < ssh_eap_config_num_of_impl(); i++)
    {
      if (ssh_eap_protocols[i].id == type)
        {
          return (SshEapProtocolImpl)&ssh_eap_protocols[i];
        }
    }
  return NULL;
}

SshEapProtocolImpl
ssh_eap_config_get_impl_by_idx(int idx)
{
  if (idx >= ssh_eap_config_num_of_impl())
    {
      return NULL;
    }

  return (SshEapProtocolImpl)&ssh_eap_protocols[idx];
}

int
ssh_eap_config_num_of_impl(void)
{
  return sizeof(ssh_eap_protocols) / sizeof(SshEapProtocolImplStruct);
}

Boolean ssh_eap_method_supports_mutual_auth(SshUInt8 type)
{
  SshEapProtocolImpl impl = NULL;
  Boolean result;

  impl = ssh_eap_config_get_impl_by_type(type);

  if (impl == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid EAP method type %u", type));
      return FALSE;
    }

  result = (impl->flags & SSH_EAP_MUTUAL_AUTHENTICATION_SUPPORTED);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("EAP method type %u %s mutual authentication",
             type, result ? "supports" : "does not support"));

  return result;
}
