/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppAuthProtocol"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_auth.h"

#ifdef SSHDIST_EAP
#include "sshppp_eap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"
#include "sshppp_pap.h"

static
SSH_RODATA
SshPppAuthProtocolImplStruct ssh_ppp_auth_chap_impl = {
  ssh_ppp_chap_create,
  ssh_ppp_chap_boot,
  ssh_ppp_chap_destroy,
  ssh_ppp_chap_return_secret,
  ssh_ppp_chap_get_secret_api,
#ifdef SSHDIST_EAP
  NULL_FNPTR,
  NULL_FNPTR,
#endif /* SSHDIST_EAP */
  ssh_ppp_chap_set_name,
  ssh_ppp_chap_get_status,
  ssh_ppp_chap_get_events,
  ssh_ppp_chap_get_mode,

#ifdef SSHDIST_RADIUS
  ssh_ppp_chap_radius_cb,
#endif /* SSHDIST_RADIUS */

  SSH_PPP_AUTH_CHAP
};

static
SSH_RODATA
SshPppAuthProtocolImplStruct ssh_ppp_auth_mschapv1_impl = {
  ssh_ppp_chap_create_mschapv1,
  ssh_ppp_chap_boot,
  ssh_ppp_chap_destroy,
  ssh_ppp_chap_return_secret,
  ssh_ppp_chap_get_secret_api,
#ifdef SSHDIST_EAP
  NULL_FNPTR,
  NULL_FNPTR,
#endif /* SSHDIST_EAP */
  ssh_ppp_chap_set_name,
  ssh_ppp_chap_get_status,
  ssh_ppp_chap_get_events,
  ssh_ppp_chap_get_mode,

#ifdef SSHDIST_RADIUS
  ssh_ppp_chap_radius_cb,
#endif /* SSHDIST_RADIUS */

  SSH_PPP_AUTH_MSCHAPv1
};

static
SSH_RODATA
SshPppAuthProtocolImplStruct ssh_ppp_auth_mschapv2_impl = {
  ssh_ppp_chap_create_mschapv2,
  ssh_ppp_chap_boot,
  ssh_ppp_chap_destroy,
  ssh_ppp_chap_return_secret,
  ssh_ppp_chap_get_secret_api,
#ifdef SSHDIST_EAP
  NULL_FNPTR,
  NULL_FNPTR,
#endif /* SSHDIST_EAP */
  ssh_ppp_chap_set_name,
  ssh_ppp_chap_get_status,
  ssh_ppp_chap_get_events,
  ssh_ppp_chap_get_mode,

#ifdef SSHDIST_RADIUS
  ssh_ppp_chap_radius_cb,
#endif /* SSHDIST_RADIUS */

  SSH_PPP_AUTH_MSCHAPv2
};

#ifdef SSHDIST_EAP

static
SSH_RODATA
SshPppAuthProtocolImplStruct ssh_ppp_auth_eap_impl = {
  ssh_ppp_eap_create,
  ssh_ppp_eap_boot,
  ssh_ppp_eap_destroy,
  ssh_ppp_eap_return_secret,
  ssh_ppp_eap_get_secret,
#ifdef SSHDIST_EAP
  ssh_ppp_eap_return_token,
  ssh_ppp_eap_get_token,
#endif /* SSHDIST_EAP */
  ssh_ppp_eap_set_name,
  ssh_ppp_eap_get_status,
  ssh_ppp_eap_get_events,
  ssh_ppp_eap_get_mode,

#ifdef SSHDIST_RADIUS
  ssh_ppp_eap_radius_cb,
#endif /* SSHDIST_RADIUS */

  SSH_PPP_AUTH_EAP
};

#endif /* SSHDIST_EAP */

static
SSH_RODATA SshPppAuthProtocolImplStruct ssh_ppp_auth_pap_impl = {
  ssh_ppp_pap_create,
  ssh_ppp_pap_boot,
  ssh_ppp_pap_destroy,
  ssh_ppp_pap_return_secret,
  ssh_ppp_pap_get_secret,
#ifdef SSHDIST_EAP
  NULL_FNPTR,
  NULL_FNPTR,
#endif /* SSHDIST_EAP */
  ssh_ppp_pap_set_name,
  ssh_ppp_pap_get_status,
  ssh_ppp_pap_get_events,
  ssh_ppp_pap_get_mode,

#ifdef SSHDIST_RADIUS
  ssh_ppp_pap_radius_cb,
#endif /* SSHDIST_RADIUS */
  SSH_PPP_AUTH_PAP
};

SshPppEvent
ssh_ppp_auth_get_status(SshPppAuthProtocol auth)
{
  SSH_PRECOND(auth != NULL);
  SSH_PRECOND(auth->impl != NULL);
  SSH_PRECOND(auth->impl->get_status != NULL_FNPTR);

  return auth->impl->get_status(auth->ctx);
}

SshPppAuthMode
ssh_ppp_auth_get_mode(SshPppAuthProtocol auth)
{
  SSH_PRECOND(auth != NULL);
  SSH_PRECOND(auth->impl != NULL);
  SSH_PRECOND(auth->impl->get_status != NULL_FNPTR);

  return auth->impl->get_mode(auth->ctx);
}

void
ssh_ppp_auth_uninit(SshPppState gdata,
                    SshPppAuthProtocol auth)
{
  SSH_PRECOND(auth != NULL);

  if (auth->impl == NULL)
    {
      return;
    }

  if (auth->impl->destroy != NULL_FNPTR && auth->ctx != NULL)
    {
      auth->impl->destroy(auth->ctx);
      auth->ctx = NULL;
    }

  ssh_ppp_events_detach_output(auth->events_output, gdata->ppp_thread);

  auth->impl = NULL;
  auth->events_output = NULL;
}

void
ssh_ppp_auth_boot(SshPppAuthProtocol auth)
{
  SSH_PRECOND(auth != NULL);

  if (auth->impl != NULL
      && auth->impl->boot != NULL_FNPTR)
    {
      auth->impl->boot(auth->ctx);
    }
}

static Boolean
ssh_ppp_auth_init(SshPppState gdata,
                  SshPppAuthProtocol auth,
                  SshPppAuthProtocolImpl impl,
                  SshPppAuthMode mode,
                  SshPppEvents eventq,
                  SshPppFlush mux)
{
  SshPppEvents evs;

  SSH_PRECOND(impl != NULL);

  auth->impl = impl;
  if (impl->create != NULL_FNPTR)
    {
      auth->ctx = impl->create(gdata, mode, eventq, mux);
      if (auth->ctx == NULL)
        {
          auth->impl = NULL;
          return FALSE;
        }
    }

  evs = impl->get_events(auth->ctx);

  auth->events_output = ssh_ppp_events_attach_output(evs,
                                                     gdata->ppp_thread);

  if (auth->events_output == NULL)
    {
      if (auth->impl->destroy != NULL_FNPTR && auth->ctx != NULL)
        {
          auth->impl->destroy(auth->ctx);
          auth->ctx = NULL;
        }
      auth->impl = NULL;
    }

  /* If a secret was fetched while we had to reinitialize, then
     mark that secret as being invalid upon return. */

  if (auth->get_secret_cb_state != SSH_PPP_AUTH_SECRET_CB_NONE)
    auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_DISCARD;

  return TRUE;
}

#ifdef SSHDIST_EAP
void
ssh_ppp_auth_return_token(SshPppState gdata,
                          SshPppAuthProtocol auth,
                          SshUInt8 eap_type,
                          SshEapToken tok)
{
  SshUInt8 state;
  Boolean isvalid;

  SSH_PRECOND(auth != NULL);
  SSH_PRECOND(auth->impl != NULL);

  state = auth->get_secret_cb_state;

  auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_NONE;

  isvalid = TRUE;

  if (state != SSH_PPP_AUTH_SECRET_CB_PENDING)
    {
      isvalid = FALSE;
    }

  if (auth->impl->return_token != NULL_FNPTR)
    {
      (*auth->impl->return_token)(gdata, auth->ctx, eap_type, tok, isvalid);
    }
  else
    {
      SSH_NOTREACHED;
    }

  if (state == SSH_PPP_AUTH_SECRET_CB_REDO)
    {
      (*auth->impl->get_token)(gdata,auth->ctx);
    }
}
#endif /* SSHDIST_EAP */

void
ssh_ppp_auth_return_secret(SshPppState gdata,
                           SshPppAuthProtocol auth,
                           SshUInt8* buf,
                           unsigned long len)
{
  SshUInt8 state;
  Boolean isvalid;

  SSH_PRECOND(auth != NULL);

  if (auth->impl == NULL)
    return;

  state = auth->get_secret_cb_state;

  auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_NONE;

  isvalid = TRUE;

  if (state != SSH_PPP_AUTH_SECRET_CB_PENDING)
    isvalid = FALSE;

  auth->impl->return_secret(gdata, auth->ctx, buf, len, isvalid);

  if (state == SSH_PPP_AUTH_SECRET_CB_REDO)
    auth->impl->get_secret(gdata,auth->ctx);
}

Boolean
ssh_ppp_auth_set_name(SshPppAuthProtocol auth,
                      SshUInt8* buf,
                      unsigned long len)
{
  SSH_PRECOND(auth != NULL);
  SSH_PRECOND(auth->impl != NULL);

  return auth->impl->set_name(auth->ctx, buf, len);
}

Boolean
ssh_ppp_auth_init_chap(SshPppState gdata,
                       SshPppAuthProtocol auth,
                       SshPppAuthMode mode,
                       SshPppEvents eventq,
                       SshPppFlush mux)
{
  return ssh_ppp_auth_init(gdata,
                           auth,
                           &ssh_ppp_auth_chap_impl,
                           mode,
                           eventq,
                           mux);
}

Boolean
ssh_ppp_auth_init_mschapv1(SshPppState gdata,
                           SshPppAuthProtocol auth,
                           SshPppAuthMode mode,
                           SshPppEvents eventq,
                           SshPppFlush mux)
{
  return ssh_ppp_auth_init(gdata,
                           auth,
                           &ssh_ppp_auth_mschapv1_impl,
                           mode,
                           eventq,
                           mux);
}


Boolean
ssh_ppp_auth_init_mschapv2(SshPppState gdata,
                           SshPppAuthProtocol auth,
                           SshPppAuthMode mode,
                           SshPppEvents eventq,
                           SshPppFlush mux)
{
  return ssh_ppp_auth_init(gdata,
                           auth,
                           &ssh_ppp_auth_mschapv2_impl,
                           mode,
                           eventq,
                           mux);
}


#ifdef SSHDIST_EAP
Boolean
ssh_ppp_auth_init_eap(SshPppState gdata,
                      SshPppAuthProtocol auth,
                      SshPppAuthMode mode,
                      SshPppEvents eventq,
                      SshPppFlush mux)
{
  return ssh_ppp_auth_init(gdata,
                           auth,
                           &ssh_ppp_auth_eap_impl,
                           mode,
                           eventq,
                           mux);
}

#endif /* SSHDIST_EAP */

Boolean
ssh_ppp_auth_init_pap(SshPppState gdata,
                      SshPppAuthProtocol auth,
                      SshPppAuthMode mode,
                      SshPppEvents eventq,
                      SshPppFlush mux)
{
  return ssh_ppp_auth_init(gdata,
                           auth,
                           &ssh_ppp_auth_pap_impl,
                           mode,
                           eventq,
                           mux);
}

void
ssh_ppp_auth_init_none(SshPppAuthProtocol auth)
{
  auth->impl = NULL;
  auth->events_output = NULL;
  auth->ctx = NULL;
  auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_NONE;
}

#ifdef SSHDIST_RADIUS

/* A callback for passing SshRadiusClientRequestCB's to the authentication
   instance, if it is using sshppp_radius.c (as opposed to the ssheap
   library, which has builtin RADIUS support). */

void
ssh_ppp_auth_radius_cb(SshPppState gdata, SshPppAuthProtocol auth,
                       SshRadiusClientRequestStatus status,
                       SshRadiusClientRequest request,
                       SshRadiusOperationCode reply_code)
{
  SSH_PRECOND(auth != NULL);

  auth->impl->radius_cb(gdata, auth->ctx, status, request, reply_code);
}
#endif /* SSHDIST_RADIUS */
