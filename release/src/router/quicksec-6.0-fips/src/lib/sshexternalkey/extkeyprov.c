/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Some helper functions for externalkey providers.
*/

#include "sshincludes.h"


#include "sshexternalkey.h"
#include "extkeyprov.h"
#include "sshbase64.h"
#include "sshtimeouts.h"
#include "sshmp.h"

#ifdef SSHDIST_CERT
#include "x509.h"
#endif /* SSHDIST_CERT */

#define SSH_DEBUG_MODULE "SshEKProv"

/* The structure used while performing the auth call */
struct SshEkAuthCallRec
{
  SshOperationHandle op;
  SshOperationHandle sub_op;
  SshEkAuthenticationStatus status;
  SshEkAuthenticationCB auth_cb;
  void *auth_ctx;
  SshEkAuthCallTryCB try_callback;
  void *context;
  const char *keypath;
  const char *label;
  SshUInt32 try_nr;
};

void ssh_ek_auth_call_free(SshEkAuthCall ctx)
{
  if (ctx->op)
    ssh_operation_unregister(ctx->op);
  ssh_free(ctx);
}


/* The reply callback that is called when the code has been acquired
   from the user. We will just deliver this information to the
   callback we were given */
void ssh_ek_auth_call_reply(const unsigned char *buf,
                            size_t len,
                            void *context)
{
  SshOperationHandle sub_op;
  SshEkAuthCall ctx = context;

  ctx->sub_op = NULL;
  sub_op = (*ctx->try_callback)(FALSE, ctx, buf, len, ctx->context);
  if (sub_op)
    ctx->sub_op = sub_op;
}

/* Do the actual call */
void ssh_ek_perform_auth_call_int(void *context)
{
  SshEkAuthCall ctx = context;
  SshOperationHandle sub_op;

  sub_op = (*ctx->auth_cb)(ctx->keypath, ctx->label,
                           ctx->try_nr++,
                           ctx->status,
                           ssh_ek_auth_call_reply,
                           ctx,
                           ctx->auth_ctx);
  if (sub_op)
    ctx->sub_op = sub_op;
}

void ssh_ek_auth_call_abort(void *context)
{
  SshEkAuthCall ctx = context;

  ssh_cancel_timeouts(ssh_ek_auth_call_abort, context);
  ssh_operation_abort(ctx->sub_op);

  /* Inform the upper layer about the abortion. */
  (*ctx->try_callback)(TRUE, NULL, NULL, 0, ctx->context);
  ctx->sub_op = NULL;
  ctx->op = NULL;
  ssh_ek_auth_call_free(ctx);
}

/* Petform an authentication call query from the user.
   The arguments:
   status - the status that is given to  the user authentication call
   auth_cb - the callback which is used to perform the query
   auth_ctx - the context that is provided to the auth_cb
   call_ret - Handle returned that represents the call, which with the call
   can be retried later
   try_callback - The callback which is called when the code has
   been acquired or the call has been cancelled.
   context - context provided to the try_callback */
SshOperationHandle ssh_ek_perform_auth_call(const char *keypath,
                                            const char *label,
                                            SshEkAuthenticationStatus status,
                                            SshEkAuthenticationCB auth_cb,
                                            void *auth_ctx,
                                            SshEkAuthCallTryCB try_callback,
                                            void *context)
{
  SshEkAuthCall ctx;
  SshOperationHandle op;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    return NULL;

  op = ssh_operation_register(ssh_ek_auth_call_abort, ctx);
  if (op == NULL)
    {
      ssh_free(ctx);
      return NULL;
    }
  ctx->op = op;
  ctx->status = status;
  ctx->auth_cb = auth_cb;
  ctx->auth_ctx = auth_ctx;
  ctx->try_callback = try_callback;
  ctx->context = context;
  ctx->keypath = keypath;
  ctx->label = label;

  ssh_xregister_timeout(0, 0, ssh_ek_perform_auth_call_int, ctx);
  return op;
}

/* The call can be retried with this. Other arguments are reused, and
   the same operation handle aborts the whole query */
void ssh_ek_auth_call_retry(SshEkAuthCall call,
                            SshEkAuthenticationStatus status)
{
  if (call)
    {
      call->status = status;
      ssh_ek_perform_auth_call_int(call);
    }
  SSH_DEBUG(SSH_D_FAIL, ("ssh_ek_auth_call_retry called with a "
                         "NULL argument. "));
}

/* Makes a base64 string from a buffer. This is useful for providers
   which need to form printable keypaths from arbitary buffers. */
void ssh_ek_provider_buffer_to_string(const unsigned char *buf,
                                      size_t buf_len,
                                      char **str_result_return)
{
  *str_result_return = (char*)ssh_buf_to_base64(buf, buf_len);
}


/* Hashes a buffer (using SHA-1 hash) and forms a printable string (base64)
   string from the result of the hash.

   This is usefull for providers which need to form printable keypaths
   from long arbitary buffers. */
void ssh_ek_provider_hash_buffer_to_string(const unsigned char *buf,
                                           size_t buf_len,
                                           char **str_result_return)
{
  SshHash hash;
  size_t digest_length;
  unsigned char *digest;
  const static unsigned char dummy[] = {0};

  if (buf == NULL || buf_len == 0)
    {
      *str_result_return = ssh_strdup(dummy);
      return;
    }

  if (ssh_hash_allocate(SSH_EK_PROVIDER_DEFAULT_HASH, &hash) != SSH_CRYPTO_OK)
    {
      *str_result_return = NULL;
    }

  digest_length = ssh_hash_digest_length(ssh_hash_name(hash));
  digest = ssh_malloc(digest_length);

  if (digest == NULL)
    {
      ssh_hash_free(hash);
      *str_result_return = NULL;
      return;
    }

  ssh_hash_reset(hash);
  ssh_hash_update(hash, buf, buf_len);
  ssh_hash_final(hash, digest);
  ssh_ek_provider_buffer_to_string(digest,
                                   digest_length,
                                   str_result_return);

  ssh_free(digest);
  ssh_hash_free(hash);
}

/* Extracts the public key from a binary certificate. */
SshPublicKey
ssh_ek_extract_public_key_from_certificate(const unsigned char *data,
                                           size_t data_len)
{
#ifdef SSHDIST_CERT
  SshX509Certificate cert;
  SshPublicKey key;

  cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(data, data_len, cert))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Could not decode certificate"));
      ssh_x509_cert_free(cert);
      return NULL;
    }

  if (!ssh_x509_cert_get_public_key(cert, &key))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Can not get the public key from certificate."));
      ssh_x509_cert_free(cert);
      return NULL;
    }
  ssh_x509_cert_free(cert);
  return key;
#else /* SSHDIST_CERT */
  return NULL;
#endif /* SSHDIST_CERT */
}

typedef struct SshExternalKeyInitCtxRec
{
  void *context;
} *SshExternalKeyInitCtx;

/* Returns NULL if no memory available. */
void *ssh_external_key_action_init(void)
{
  SSH_DEBUG(SSH_D_HIGHOK, ("Initializing the externalkey init context"));
  return ssh_calloc(1, sizeof(struct SshExternalKeyInitCtxRec));
}

void *ssh_external_key_action_make(void *context)
{
  SshExternalKeyInitCtx ctx = context;

  if (ctx)
    return ctx->context;
  return NULL;
}

void ssh_external_key_action_free(void *context)
{
  ssh_free(context);
}

const char *
ssh_external_key_action_put(void *context,
                            va_list ap, void *input_context,
                            SshPkFormat format)
{
  SshExternalKeyInitCtx ctx = context;

  if (ctx)
    {
      if (format == SSH_PKF_PROXY)
        {
          ctx->context = va_arg(ap, void *);
          return "p";
        }
    }
  return NULL;
}

const char *
ssh_external_key_action_get(void *context,
                            va_list ap, void **output_context,
                            SshPkFormat format)
{
  if (format == SSH_PKF_PROXY)
    {
      void **tmp = va_arg(ap, void **);

      *tmp = context;
      return "p";
    }
  return NULL;
}


SshInt32 ssh_ek_get_pub_key_size(SshPublicKey key)
{
  SshMPIntegerStruct mp;
  SshInt32 size = -1;
  const char *keytype = NULL;

  ssh_mprz_init(&mp);

  if (ssh_public_key_get_info(key, SSH_PKF_KEY_TYPE, &keytype,
                              SSH_PKF_END)
      != SSH_CRYPTO_OK)
    {
      ssh_mprz_clear(&mp);
      return -1;
    }
  if (keytype == NULL)
    return -1;

  if (strcmp(keytype, "if-modn") == 0)
    {
      if (ssh_public_key_get_info(key, SSH_PKF_MODULO_N, &mp,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        return -1;

      size = ssh_mprz_get_size(&mp, 2);

      ssh_mprz_clear(&mp);
      return size;

    }
  if (strcmp(keytype, "dl-modp") == 0)
    {
      if (ssh_public_key_get_info(key, SSH_PKF_PRIME_Q, &mp,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        return -1;

      size = ssh_mprz_get_size(&mp, 2);

      ssh_mprz_clear(&mp);
      return size;

    }
  SSH_DEBUG(SSH_D_FAIL, ("Unknown key type"));

  ssh_mprz_clear(&mp);

  return size;
}
