/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshbuffer.h"

#include "ssheap.h"
#include "ssheapi.h"

#define SSH_DEBUG_MODULE "SshEapParams"

SshEapConfiguration
ssh_eap_config_create(void)
{
  SshEapConfiguration params;

  params = ssh_malloc(sizeof(*params));

  if (params == NULL)
    return NULL;

  memset(params,0,sizeof(*params));

  /* Initialize parameter values to defaults */

  params->num_retransmit = ssh_eap_config_get_ulong(NULL,
                              SSH_EAP_PARAM_MAX_RETRANSMIT);

  params->retransmit_delay_sec = ssh_eap_config_get_ulong(NULL,
                         SSH_EAP_PARAM_RETRANSMIT_DELAY_SEC);

  params->auth_timeout_sec = ssh_eap_config_get_ulong(NULL,
                         SSH_EAP_PARAM_AUTH_TIMEOUT_SEC);

  params->signal_cb = NULL_FNPTR;
  params->refcount = 0;
#ifdef SSHDIST_RADIUS
  params->radius_buffer_identity = FALSE;
  params->radius_req_cb =  NULL_FNPTR;
#endif /* SSHDIST_RADIUS */

  return params;
}

void
ssh_eap_config_destroy(SshEapConfiguration params)
{
  SSH_ASSERT(params->refcount == 0);

  ssh_free(params);
}

unsigned long
ssh_eap_config_get_ulong(SshEapConfiguration params, SshEapParamId id)
{
  if (params != NULL)
    {
      switch (id)
        {
        case SSH_EAP_PARAM_MAX_RETRANSMIT:
          return params->num_retransmit;
        case SSH_EAP_PARAM_RETRANSMIT_DELAY_SEC:
          return params->retransmit_delay_sec;
        case SSH_EAP_PARAM_AUTH_TIMEOUT_SEC:
          return params->auth_timeout_sec;
        default:
          SSH_NOTREACHED;
        }
    }
  else
    {
      switch (id)
        {
        case SSH_EAP_PARAM_MAX_RETRANSMIT:
          return 7;
        case SSH_EAP_PARAM_RETRANSMIT_DELAY_SEC:
          return 4;
        case SSH_EAP_PARAM_AUTH_TIMEOUT_SEC:
          return 30;
        default:
          SSH_NOTREACHED;
        }
    }
  return 0;
}

SshEapTokenType
ssh_eap_get_token_type_from_buf(SshBuffer buf)
{
  SshEapToken t;

  if (buf == NULL)
    {
      return SSH_EAP_TOKEN_NONE;
    }

  if (ssh_buffer_len(buf) != sizeof(*t))
    {
      return SSH_EAP_TOKEN_NONE;
    }

  t = (SshEapToken)ssh_buffer_ptr(buf);

  return (t != NULL) ? t->type : SSH_EAP_TOKEN_NONE;
}

SshEapTokenType
ssh_eap_get_token_type(SshEapToken t)
{
  return t->type;
}

void
ssh_eap_get_token_data_from_buf(SshBuffer buf, void **data, size_t *data_len)
{
  SshEapToken t;

  *data = NULL;
  *data_len = 0;

  if (buf == NULL || ssh_buffer_len(buf) != sizeof(*t))
    return;

  t = (SshEapToken)ssh_buffer_ptr(buf);

  if (t != NULL)
    {
      *data = t->token.buffer.dptr;
      *data_len = (size_t)t->token.buffer.len;
    }
}

void
ssh_eap_get_token_data(SshEapToken t, void **data, size_t *data_len)
{
  *data = t->token.buffer.dptr;
  *data_len = (size_t)t->token.buffer.len;
}

void
ssh_eap_init_token_typed(SshEapToken t,
                         SshEapTokenType type,
                         SshUInt8 *dptr,
                         unsigned long len)
{
  t->token.buffer.dptr = dptr;
  t->token.buffer.len = len;
  t->type = type;
}

void
ssh_eap_init_token_counter32(SshEapToken t,
                             SshUInt32 val)
{
  t->type = SSH_EAP_TOKEN_COUNTER32;
  t->token.counter32 = val;
}

SshUInt32
ssh_eap_get_token_counter32(SshEapToken t)
{
  SSH_ASSERT(ssh_eap_get_token_type(t) == SSH_EAP_TOKEN_COUNTER32);
  return t->token.counter32;
}

void
ssh_eap_init_token_secret(SshEapToken t,
                          SshUInt8 *dptr,
                          unsigned long len)
{
  t->token.buffer.dptr = dptr;
  t->token.buffer.len = len;
  t->type = SSH_EAP_TOKEN_SHARED_SECRET;
}

void
ssh_eap_init_token_salt(SshEapToken t,
                        SshUInt8 *dptr,
                        unsigned long len)
{
  t->token.buffer.dptr = dptr;
  t->token.buffer.len = len;
  t->type = SSH_EAP_TOKEN_SALT;
}

void
ssh_eap_init_token_username(SshEapToken t,
                            SshUInt8 *dptr,
                            unsigned long len)
{
  t->token.buffer.dptr = dptr;
  t->token.buffer.len = len;
  t->type = SSH_EAP_TOKEN_USERNAME;
}

void
ssh_eap_init_token_certificate_authority(SshEapToken t, unsigned char **ca)
{
  t->token.cas = ca;
  t->type = SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY;
}

void
ssh_eap_init_token_private_key(SshEapToken t, SshPrivateKey prvkey,
                               unsigned char *id_data, size_t id_data_size)
{
  t->token.prvkey.private_key = prvkey;
  t->token.prvkey.id_data = id_data;
  t->token.prvkey.id_data_size = id_data_size;
  t->type = SSH_EAP_TOKEN_PRIVATE_KEY;
}

void
ssh_eap_init_token(SshEapToken t)
{
  t->type = SSH_EAP_TOKEN_NONE;
}

void
ssh_eap_uninit_token(SshEapToken t)
{
  switch (t->type)
    {
    case SSH_EAP_TOKEN_USERNAME:
    case SSH_EAP_TOKEN_SHARED_SECRET:
    case SSH_EAP_TOKEN_SALT:
#ifdef SSHDIST_EAP_SIM
    case SSH_EAP_TOKEN_SIM_CHALLENGE:
#endif /* SSHDIST_EAP_SIM */
#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TOKEN_AKA_CHALLENGE:
    case SSH_EAP_TOKEN_AKA_SYNCH_REQ:
#endif /* SSHDIST_EAP_AKA */
      ssh_free(t->token.buffer.dptr);
      t->token.buffer.dptr = NULL;
      t->token.buffer.len = 0;
      break;
#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TOKEN_AKA_AUTH_REJECT:
#endif /* SSHDIST_EAP_AKA */
      break;



    case SSH_EAP_TOKEN_PRIVATE_KEY:
      ssh_private_key_free(t->token.prvkey.private_key);
      ssh_free(t->token.prvkey.id_data);
      break;
    case SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY:
      ssh_free(t->token.cas);
      break;
    case SSH_EAP_TOKEN_NONE:
      break;
    default:
      SSH_NOTREACHED;
    }
  t->type = SSH_EAP_TOKEN_NONE;
}

SshEapToken
ssh_eap_dup_token(SshEapToken src)
{
  SshEapToken dst;

  dst = ssh_calloc(1, sizeof(*dst));

  if (dst == NULL)
    return NULL;

  dst->type = src->type;

  switch (src->type)
    {

    case SSH_EAP_TOKEN_PRIVATE_KEY:
   if (src->token.prvkey.private_key != NULL)
     {
       if (ssh_private_key_copy(src->token.prvkey.private_key,
                                &dst->token.prvkey.private_key)
           != SSH_CRYPTO_OK)
         {
           ssh_free(dst);
           return NULL;
         }
       if (src->token.prvkey.id_data != NULL)
         {
           dst->token.prvkey.id_data
             = ssh_memdup(src->token.prvkey.id_data,
                          src->token.prvkey.id_data_size);
           if (dst->token.prvkey.id_data == NULL)
             {
               ssh_private_key_free(dst->token.prvkey.private_key);
               ssh_free(dst);
               return NULL;
             }
           dst->token.prvkey.id_data_size = src->token.prvkey.id_data_size;
         }
     }
   break;

    case SSH_EAP_TOKEN_CERTIFICATE_AUTHORITY:
      {
        int cnt;
        int i;

        /* Count the ca count. */
        for (cnt = 0; src->token.cas && src->token.cas[cnt]; cnt++)
          ;

        if (cnt == 0)
          {
            SSH_DEBUG(SSH_D_ERROR, ("Cannot duplicate token, no"
                                    " CA's to duplicate."));
            ssh_free(dst);
            return NULL;
          }

        dst->token.cas = ssh_calloc(cnt + 1, sizeof(unsigned char *));
        if (dst->token.cas == NULL)
          {
            ssh_free(dst);
            return NULL;
          }

        for (i = 0; i < cnt; i++)
          dst->token.cas[i] = src->token.cas[i];

        break;
      }

#ifdef SSHDIST_EAP_SIM
    case SSH_EAP_TOKEN_SIM_CHALLENGE:
#endif /* SSHDIST_EAP_SIM */
#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TOKEN_AKA_CHALLENGE:
    case SSH_EAP_TOKEN_AKA_SYNCH_REQ:
#endif /* SSHDIST_EAP_AKA */
    case SSH_EAP_TOKEN_USERNAME:
    case SSH_EAP_TOKEN_SHARED_SECRET:
    case SSH_EAP_TOKEN_SALT:

      if (src->token.buffer.dptr != NULL)
        {
          dst->token.buffer.dptr = ssh_malloc(src->token.buffer.len);
          if (dst->token.buffer.dptr == NULL)
            {
              ssh_free(dst);
              return NULL;
            }

          dst->token.buffer.len = src->token.buffer.len;
          memcpy(dst->token.buffer.dptr, src->token.buffer.dptr,
                 src->token.buffer.len);
        }
      else
        {
          dst->token.buffer.dptr = NULL;
          dst->token.buffer.len = 0;
        }
      break;
    case SSH_EAP_TOKEN_COUNTER32:
      dst->token.counter32 = src->token.counter32;
      break;

#ifdef SSHDIST_EAP_AKA
    case SSH_EAP_TOKEN_AKA_AUTH_REJECT:
#endif /* SSHDIST_EAP_AKA */
    case SSH_EAP_TOKEN_NONE:
      break;
    default:
      SSH_NOTREACHED;
    }

  SSH_DEBUG(SSH_D_MY, ("duplicated token at %p", dst));

  return dst;
}

void
ssh_eap_free_token(SshEapToken t)
{
  if (t != NULL)
    {
      ssh_eap_uninit_token(t);
      ssh_free(t);
    }
}

SshEapToken
ssh_eap_create_token(void)
{
  SshEapToken t;

  t = ssh_malloc(sizeof(*t));

  if (t == NULL)
    return NULL;

  ssh_eap_init_token(t);
  return t;
}

SshUInt8*
ssh_eap_get_token_secret_ptr(SshEapToken t)
{
  SSH_ASSERT(ssh_eap_get_token_type(t) == SSH_EAP_TOKEN_SHARED_SECRET);
  return t->token.buffer.dptr;
}

unsigned long
ssh_eap_get_token_secret_len(SshEapToken t)
{
  SSH_ASSERT(ssh_eap_get_token_type(t) == SSH_EAP_TOKEN_SHARED_SECRET);
  return t->token.buffer.len;
}
