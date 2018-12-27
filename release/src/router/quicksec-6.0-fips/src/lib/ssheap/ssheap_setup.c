/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshcrypt.h"

#include "ssheap.h"
#include "ssheapi.h"

#include "ssheap_packet.h"
#include "ssheap_config.h"
#include "ssheap_connection.h"

#include <stdlib.h>
#include <stdio.h>

#define SSH_DEBUG_MODULE "SshEapSetup"

/* This file contains code for setting up and configuring
   the EAP instance. */

static int
ssh_eap_protocol_cmp(const void *av, const void *bv)
{
  SshEapProtocol a, b;

  a = *((SshEapProtocol*)av);
  b = *((SshEapProtocol*)bv);

  /* Sanity check. */

  SSH_ASSERT(a->impl->id != b->impl->id || a == b);

  /* Sort on base of preference */

  if (a->preference < b->preference)
    {
      return -1;
    }

  if (a->preference > b->preference)
    {
      return 1;
    }

  return 0;
}

static SshEapOpStatus
ssh_eap_accept_impl(SshEap eap, SshEapProtocolImpl impl, SshUInt8 pref)
{
  SshEapProtocol proto;
  SshEapProtocol *prarray;

  proto = ssh_calloc(1, sizeof(SshEapProtocolStruct));

  if (proto == NULL)
    return SSH_EAP_OPSTATUS_INSUFFICIENT_RESOURCES;

  /* Create instance */

  proto->params = NULL;
  proto->state = NULL;
  proto->preference = pref;
  proto->impl = impl;
  proto->is_nak = 0;

  prarray = ssh_malloc((eap->nprotocols + 1) * sizeof(SshEapProtocol));

  if (prarray == NULL)
    {
      ssh_free(proto);
      return SSH_EAP_OPSTATUS_INSUFFICIENT_RESOURCES;
    }

  memcpy(prarray, eap->protocols,
         sizeof(SshEapProtocol) * eap->nprotocols);

  ssh_free(eap->protocols);

  eap->protocols = prarray;
  eap->protocols[eap->nprotocols++] = proto;

  /* Sort the protocols in order of preference */

  qsort(eap->protocols,
        eap->nprotocols,
        sizeof(SshEapProtocol),
        ssh_eap_protocol_cmp);

  SSH_DEBUG(SSH_D_MIDOK,("accepting authentication type %d", impl->id));

  return SSH_EAP_OPSTATUS_SUCCESS;
}

static void
ssh_eap_configure(SshEap eap,
                  SshEapConfiguration params,
                  SshEapConnection con)
{
  SSH_ASSERT(eap != NULL);

  if (eap->params != NULL)
    {
      eap->params->refcount--;
    }

  eap->params = params;

  if (params != NULL)
    {
      params->refcount++;
    }

  if (eap->con != NULL)
    {
      ssh_eap_connection_detach(eap->con);
    }

  eap->con = con;

  if (con != NULL)
    {
      ssh_eap_connection_attach(con, eap);
    }
}

static SshEap
ssh_eap_create(void* ctx,
               SshEapConfiguration params,
               SshEapConnection con,
               Boolean is_authenticator)
{
  SshEap eap;

  SSH_ASSERT(con != NULL);

  eap = ssh_calloc(1, sizeof(*eap));

  if (eap == NULL)
    return NULL;

  eap->params = NULL;
  eap->con = NULL;
  eap->protocols = NULL;
  eap->nprotocols = 0;

  eap->delayed_token = NULL;

  eap->is_authenticator = (is_authenticator == TRUE ? 1 : 0);
  eap->id = ssh_random_get_byte();
  eap->id_isinit = 0;
  eap->id_isrecv = 0;
  eap->auth_timeout_active = 0;

  eap->previous_eap_code = 0;
  eap->previous_eap_type = SSH_EAP_TYPE_NONE;

  eap->ctx = ctx;
  eap->callback_count = 0;

  eap->prev_pkt = NULL;
  eap->num_retransmit = 0;
  eap->retransmit_timer_active = 0;

  eap->waiting_for_callback = 0;
  eap->destroy_pending = 0;

  ssh_eap_configure(eap, params, con);

#ifdef SSHDIST_RADIUS
  ssh_eap_radius_init(eap);
#endif /* SSHDIST_RADIUS */

  return eap;
}

SshEapStatus
ssh_eap_get_status(SshEap eap)
{
  if (eap->destroy_pending == 1)
    {
      return SSH_EAP_STATUS_DYING;
    }

  if (eap->callback_count > 0 || eap->num_retransmit == -1)
    {
      return SSH_EAP_STATUS_PROCESSING;
    }

  if (eap->waiting_for_callback == 1)
    {
      return SSH_EAP_STATUS_WAITING;
    }

  return SSH_EAP_STATUS_IDLE;
}

static void
ssh_eap_destroy_protocol(SshEap eap, SshEapProtocol pr)
{
  if (pr != NULL)
    {
      if (pr->impl->destroy != NULL_FNPTR)
        {
          pr->impl->destroy(pr, pr->impl->id, pr->state);
          pr->state = NULL;
        }

      ssh_free(pr);
    }
}

SshEap
ssh_eap_create_server(void *ctx,
                      SshEapConfiguration params,
                      SshEapConnection con)
{
  SshEap eap = ssh_eap_create(ctx, params, con, TRUE);
  return eap;
}

SshEap
ssh_eap_create_client(void *ctx,
                      SshEapConfiguration params,
                      SshEapConnection con)
{
  SshEap eap = ssh_eap_create(ctx,params,con, FALSE);
  return eap;
}

static void
ssh_eap_destroy_cb(void* ctx)
{
  SshEap eap = (SshEap)ctx;

  SSH_PRECOND(eap->callback_count == 0);

  eap->destroy_pending = 0;

  SSH_DEBUG(SSH_D_LOWOK,("destroying eap instance, as scheduled"));

  ssh_eap_destroy(eap);
}

void
ssh_eap_destroy(SshEap eap)
{
  if (eap == NULL)
    return;

  if (eap->destroy_pending == 1)
    return;

  /* Detach from parameters and connection */

  if (eap->params != NULL)
    {
      eap->params->refcount--;
      eap->params = NULL;
    }

  if (eap->con != NULL)
    {
      ssh_eap_connection_detach(eap->con);
      eap->con = NULL;
    }

  /* Abort any processing in progress */

  if (eap->delayed_token != NULL)
    {
      ssh_eap_free_token(eap->delayed_token);
      eap->delayed_token = NULL;
    }

#ifdef SSHDIST_RADIUS
  ssh_eap_radius_reset(eap);
#endif /* SSHDIST_RADIUS */

  /* Cancel all asynch operations */

  ssh_eap_cancel_resend_timeout(eap);
  ssh_eap_cancel_auth_timeout(eap);

  if (eap->callback_count > 0)
    {
      /* Reset any asynch processing being performed by the individual
         protocol implementations */

      ssh_eap_reset(eap);

      /* Bounce to the bottom of the eventloop, incase we are
         called from a callback */

      SSH_DEBUG(SSH_D_MIDOK,
                ("called from callback, "
                 "scheduling ssh_eap_destroy with timeout"));
      ssh_xregister_timeout(0, 0, ssh_eap_destroy_cb, eap);
      return;
    }

  /* Forget any packets we have cached for resending */

  if (eap->prev_pkt != NULL)
    {
      ssh_buffer_free(eap->prev_pkt);
      eap->prev_pkt = NULL;
    }

  if (eap->msk != NULL)
    {
      ssh_free(eap->msk);
      eap->msk = NULL;
      eap->msk_len = 0;
    }

  if (eap->session_id != NULL)
    {
      ssh_free(eap->session_id);
      eap->session_id = NULL;
      eap->session_id_len = 0;
    }

  /* Destroy state with auth protocols */

  ssh_eap_accept_auth_none(eap);

  /* Free the main structure */

  ssh_free(eap);

  SSH_DEBUG(SSH_D_HIGHOK,("eap instance destroyed"));
}

void
ssh_eap_accept_auth_none(SshEap eap)
{
  int i;

  for (i = 0; i < eap->nprotocols; i++)
    {
      ssh_eap_destroy_protocol(eap,eap->protocols[i]);
      eap->protocols[i] = NULL;
    }

  if (eap->protocols != NULL)
    {
      ssh_free(eap->protocols);
      eap->protocols = NULL;
    }

  eap->nprotocols = 0;
}

SshEapOpStatus
ssh_eap_accept_auth(SshEap eap, SshUInt8 code, SshUInt8 pref)
{
  SshEapProtocolImpl impl;

  impl = ssh_eap_config_get_impl_by_type(code);

  if (impl == NULL)
    return SSH_EAP_OPSTATUS_UNKNOWN_PROTOCOL;

  return ssh_eap_accept_impl(eap, impl, pref);
}

SshEapOpStatus
ssh_eap_configure_protocol(SshEap eap, SshUInt8 type,
                           void* ptr, unsigned long len)
{
  unsigned long i;
  SshBufferStruct buf;
  SshEapOpStatus ret;

  for (i = 0; i < eap->nprotocols; i++)
    {
      if (eap->protocols[i] != NULL)
        {
          if (eap->protocols[i]->impl->id == type)
            {

              buf.buf = ptr;
              buf.offset = 0;
              buf.alloc = len;
              buf.end = len;
              buf.dynamic = FALSE;

              if (eap->protocols[i]->state == NULL)
                {
                  eap->protocols[i]->state =
                    eap->protocols[i]->impl->create(eap->protocols[i],
                                                  eap,
                                                  eap->protocols[i]->impl->id);

                  if (eap->protocols[i]->state == NULL)
                    {
                      ssh_eap_fatal(eap, eap->protocols[i],
                                    "Out of memory. "
                                    "Cannot allocate state for protocol run.");
                      return SSH_EAP_OPSTATUS_INSUFFICIENT_RESOURCES;
                    }
                }

              ret = eap->protocols[i]->impl->handler(
                                           SSH_EAP_PROTOCOL_RECV_PARAMS,
                                           eap, eap->protocols[i],
                                           &buf);
              return ret;
            }
        }
    }
  return SSH_EAP_OPSTATUS_UNKNOWN_PROTOCOL;
}

static void
ssh_eap_single_token(SshEap eap,
                     SshUInt8 type,
                     SshEapToken t)
{
  SshEapProtocol protocol;
  SshBufferStruct buf;

  SSH_PRECOND(eap != NULL);
  SSH_PRECOND(eap->callback_count == 0);

  if (eap->waiting_for_callback == 0)
    {
      ssh_eap_discard_token(eap, NULL, NULL, "unexpected token");
      return;
    }

  /* Handle SSH_EAP_TYPE_IDENTITY request made for an
     identification response */

  if (t->type == SSH_EAP_TOKEN_USERNAME && type == SSH_EAP_TYPE_IDENTITY)
    {
      if (ssh_eap_isauthenticator(eap) == TRUE)
        {
#ifdef SSHDIST_RADIUS
          ssh_eap_radius_send_start(eap, t);
#endif /* SSHDIST_RADIUS */
          ;
        }
      else
        {
          if (ssh_eap_send_id_reply(eap, t->token.buffer.dptr,
                                     t->token.buffer.len) == FALSE)
            {
              ssh_eap_discard_token(eap, NULL, NULL,
                                    "id reply sending failed");
            }
        }
      eap->waiting_for_callback = 0;
      return;
    }

  protocol = ssh_eap_get_protocol(eap, type);

  if (protocol == NULL)
    {
      ssh_eap_discard_token(eap, NULL, NULL,
                            "received token for unknown protocol");
      return;
    }

  eap->waiting_for_callback = 0;

  SSH_DEBUG(SSH_D_MIDOK,("forwarding token to eap type %d",type));

  buf.dynamic = FALSE;
  buf.buf = (unsigned char*)t;
  buf.end = sizeof(*t);
  buf.alloc = sizeof(*t);
  buf.offset = 0;

  SSH_EAP_CB(eap, protocol->impl->handler(SSH_EAP_PROTOCOL_RECV_TOKEN,
                                          eap,
                                          protocol,
                                          &buf));
}

void
ssh_eap_token(SshEap eap, SshUInt8 type, SshEapToken t)
{
  if (eap->callback_count > 0)
    {
      SSH_ASSERT(eap->delayed_token == NULL);

      eap->delayed_token_type = type;
      eap->delayed_token = ssh_eap_dup_token(t);
      return;
    }

  ssh_eap_single_token(eap, type, t);

  ssh_eap_delayed_token(eap);
}

void
ssh_eap_delayed_token(SshEap eap)
{
  SshEapToken t;
  SshUInt8 type;

  while (eap->delayed_token != NULL)
    {
      t = eap->delayed_token;
      type = eap->delayed_token_type;

      eap->delayed_token = NULL;
      eap->delayed_token_type = 0;

      ssh_eap_single_token(eap, type, t);

      ssh_eap_free_token(t);
    }
}

void
ssh_eap_master_session_key(SshEap eap, unsigned char **buffer,
                           size_t *buffer_len,
                           unsigned char **id_buffer,
                           size_t *id_buffer_len)
{
  unsigned char *buf;
  size_t len;

  buf = NULL;
  len = 0;

  if (eap->msk)
    {
      /* Ensure that the MSK is at least 64 bytes. */
      if (eap->msk_len < 64)
        {
          buf = ssh_calloc(1, 64);

          if (buf)
            {
              memcpy(buf, eap->msk, eap->msk_len);
              len = 64;
            }
        }
      else
        {
          buf = ssh_memdup(eap->msk, eap->msk_len);

          if (buf)
            len = eap->msk_len;
        }

      if (id_buffer && id_buffer_len &&
          eap->session_id && eap->session_id_len)
        {
          *id_buffer = ssh_memdup(eap->session_id, eap->session_id_len);

          if (*id_buffer)
            *id_buffer_len = eap->session_id_len;
          else
            *id_buffer_len = 0;
        }
      else if (id_buffer && id_buffer_len)
        {
          *id_buffer = NULL;
          *id_buffer_len = 0;
        }
    }
  *buffer = buf;
  *buffer_len = len;
}


SshEapProtocol
ssh_eap_get_protocol(SshEap eap, SshUInt8 code)
{
  int i;

  for (i = 0; i < eap->nprotocols; i++)
    {
      if (eap->protocols[i]->impl->id == code)
        {
          return eap->protocols[i];
        }
    }
  return NULL;
}

SshEapDestination
ssh_eap_packet_destination(SshUInt8* buffer, unsigned long len)
{
  SshBufferStruct tmp;
  SshUInt8 code;

  tmp.alloc = len;
  tmp.offset = 0;
  tmp.end = len;
  tmp.buf = buffer;
  tmp.dynamic = FALSE;

  if (ssh_eap_packet_isvalid(&tmp) == FALSE)
    {
      return SSH_EAP_NONE;
    }

  code = ssh_eap_packet_get_code(&tmp);

  if (code == SSH_EAP_CODE_REPLY)
    {
      return SSH_EAP_AUTHENTICATOR;
    }

  if (code == SSH_EAP_CODE_REQUEST
      || code == SSH_EAP_CODE_SUCCESS
      || code == SSH_EAP_CODE_FAILURE)
    {
      return SSH_EAP_PEER;
    }

  return SSH_EAP_NONE;
}
