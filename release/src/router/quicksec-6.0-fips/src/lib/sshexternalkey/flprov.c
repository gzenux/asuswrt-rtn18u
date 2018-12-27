/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshproxykey.h"
#include "extkeyprov.h"
#include "sshmp.h"
#include "sshencode.h"

#include "sshfl.h"

#define SSH_DEBUG_MODULE "SshEKFl"


/* ******************** Private key proxy operations *********************** */


static void
fl_prov_private_proxy_free(void *context)
{
  ssh_fl_private_key_free(context);

  return;
}

static SshOperationHandle
fl_prov_private_proxy_key_op(SshProxyOperationId operation_id,
                             SshProxyRGFId rgf_id,
                             SshProxyKeyHandle handle,
                             const unsigned char *input_data,
                             size_t input_data_len,
                             SshProxyReplyCB reply_cb,
                             void *reply_context,
                             void *context)
{
  SshCryptoStatus status;
  unsigned char *signature_buffer = NULL;
  size_t signature_buffer_len;

  signature_buffer_len = ssh_fl_signature_size(context);

  SSH_ASSERT(signature_buffer_len != 0);

  signature_buffer = ssh_malloc(signature_buffer_len);

  if (signature_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));

      (*reply_cb)(SSH_CRYPTO_NO_MEMORY,
                  NULL,
                  0,
                  reply_context);
      return NULL;
    }

  status = ssh_fl_private_key_sign(operation_id,
                                   rgf_id,
                                   input_data,
                                   input_data_len,
                                   signature_buffer,
                                   signature_buffer_len,
                                   context);

  if (status == SSH_CRYPTO_OK)
    (*reply_cb)(SSH_CRYPTO_OK,
                signature_buffer,
                signature_buffer_len,
                reply_context);
  else
    (*reply_cb)(status,
                NULL,
                0,
                reply_context);

  ssh_free(signature_buffer);

  return NULL;
}

/* *********************** Private proxy key making ************************ */

static void *
fl_prov_private_proxy_fl_make_rsa(SshPrivateKey private_key,
                                  SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct p, q, d, dp, dq, q_inv, temp;
  unsigned char *p_buf = NULL, *q_buf = NULL, *dp_buf = NULL, *dq_buf = NULL,
    *q_inv_buf = NULL;
  size_t parameter_size;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&d);
  ssh_mprz_init(&dp);
  ssh_mprz_init(&dq);
  ssh_mprz_init(&q_inv);
  ssh_mprz_init(&temp);

  /* Get basic information from the key */
  status = ssh_private_key_get_info(private_key,
                                    SSH_PKF_PRIME_P, &p,
                                    SSH_PKF_PRIME_Q, &q,
                                    SSH_PKF_SECRET_D, &d,
                                    SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get private key components"));
      goto end;
    }

  /* FIPS library requires p > q, so swap now if needed */
  if (ssh_mprz_cmp(&p, &q) == -1)
    {
      ssh_mprz_set(&temp, &p);
      ssh_mprz_set(&p, &q);
      ssh_mprz_set(&q, &temp);
    }

  /* Calculate needed CRT-components */
  ssh_mprz_sub_ui(&temp, &p, 1);
  ssh_mprz_mod(&dp, &d, &temp);

  ssh_mprz_sub_ui(&temp, &q, 1);
  ssh_mprz_mod(&dq, &d, &temp);

  /* Calculate the qInv */
  if (ssh_mprz_invert(&q_inv, &q, &p) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to invert integer"));
      goto end;
    }

  if (ssh_mprz_cmp_ui(&q_inv, 0) < 0)
    ssh_mprz_add(&q_inv, &q_inv, &p);

  /* All parameters size equals size of primes */
  parameter_size = ssh_mp_byte_size(&p);

  p_buf = ssh_malloc(parameter_size);
  q_buf = ssh_malloc(parameter_size);
  dp_buf = ssh_malloc(parameter_size);
  dq_buf = ssh_malloc(parameter_size);
  q_inv_buf = ssh_malloc(parameter_size);

  if ((p_buf == NULL) || (q_buf == NULL) || (dp_buf == NULL) ||
      (dq_buf == NULL) || (q_inv_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  if ((ssh_mprz_get_buf_lsb_first(p_buf, parameter_size, &p) == 0 ||
       ssh_mprz_get_buf_lsb_first(q_buf, parameter_size, &q) == 0 ||
       ssh_mprz_get_buf_lsb_first(dp_buf, parameter_size, &dp) == 0||
       ssh_mprz_get_buf_lsb_first(dq_buf, parameter_size, &dq) == 0 ||
       ssh_mprz_get_buf_lsb_first(q_inv_buf, parameter_size, &q_inv) == 0))
    {
    {
      SSH_DEBUG(SSH_D_FAIL, ("Key decode to buffer failed"));
      goto end;
    }
    }

  /* Create the FL library key */
  context = ssh_fl_rsa_private_key_make(p_buf, parameter_size,
                                        q_buf, parameter_size,
                                        dp_buf, parameter_size,
                                        dq_buf, parameter_size,
                                        q_inv_buf, parameter_size,
                                        key_size_in_bits);

 end:
  ssh_free(p_buf);
  ssh_free(q_buf);
  ssh_free(dp_buf);
  ssh_free(dq_buf);
  ssh_free(q_inv_buf);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&dp);
  ssh_mprz_clear(&dq);
  ssh_mprz_clear(&q_inv);
  ssh_mprz_clear(&temp);

  return context;
}

static void *
fl_prov_private_proxy_fl_make_dsa(SshPrivateKey private_key,
                                  SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct p, q, g, x;
  unsigned char *p_buf = NULL, *q_buf = NULL, *g_buf = NULL, *x_buf = NULL;
  size_t p_size, q_size, g_size, x_size;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&x);

  /* Get basic information from the key */
  status = ssh_private_key_get_info(private_key,
                                    SSH_PKF_PRIME_P, &p,
                                    SSH_PKF_PRIME_Q, &q,
                                    SSH_PKF_GENERATOR_G, &g,
                                    SSH_PKF_SECRET_X, &x,
                                    SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get DSA private key components"));
      goto end;
    }

  p_size = ssh_mp_byte_size(&p);
  q_size = ssh_mp_byte_size(&q);
  g_size = ssh_mp_byte_size(&g);
  x_size = ssh_mp_byte_size(&x);

  p_buf = ssh_malloc(p_size);
  q_buf = ssh_malloc(q_size);
  g_buf = ssh_malloc(g_size);
  x_buf = ssh_malloc(x_size);

  if ((p_buf == NULL) || (q_buf == NULL) || (g_buf == NULL) || (x_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(p_buf, p_size, &p);
  ssh_mprz_get_buf_lsb_first(q_buf, q_size, &q);
  ssh_mprz_get_buf_lsb_first(g_buf, g_size, &g);
  ssh_mprz_get_buf_lsb_first(x_buf, x_size, &x);

  /* Create the FL library key */
  context = ssh_fl_dsa_private_key_make(p_buf, p_size,
                                        q_buf, q_size,
                                        g_buf, g_size,
                                        x_buf, x_size,
                                        key_size_in_bits);

 end:
  ssh_free(p_buf);
  ssh_free(q_buf);
  ssh_free(g_buf);
  ssh_free(x_buf);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&x);

  return context;
}

static void *
fl_prov_private_proxy_fl_make_ecdsa(SshPrivateKey private_key,
                                      SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct x;
  unsigned char *x_buf = NULL;
  size_t x_size;

  ssh_mprz_init(&x);

  /* Get basic information from the key */
  status = ssh_private_key_get_info(private_key,
                                    SSH_PKF_SECRET_X, &x,
                                    SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get ECDSA private key components"));
      goto end;
    }

  x_size = ssh_mp_byte_size(&x);
  x_buf = ssh_malloc(x_size);

  if (x_buf == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(x_buf, x_size, &x);

  /* Create the FL library key */
  context = ssh_fl_ecdsa_private_key_make(x_buf, x_size,
                                          key_size_in_bits);

 end:
  ssh_free(x_buf);
  ssh_mprz_clear(&x);

  return context;
}


static SshPrivateKey
fl_prov_private_proxy_make(SshPrivateKey plain_key)
{
  SshCryptoStatus status;
  SshPrivateKey proxy_key;
  const char *key_type_str;
  SshProxyKeyTypeId key_type;
  SshUInt32 key_size_in_bits;
  void *proxy_key_context;

  /* Solve the parameters proxy key API needs */
  status = ssh_private_key_get_info(plain_key,
                                    SSH_PKF_SIZE, &key_size_in_bits,
                                    SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to solve private key size"));
      return NULL;
    }

  status = ssh_private_key_get_info(plain_key,
                                    SSH_PKF_KEY_TYPE, &key_type_str,
                                    SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to solve private key type"));
      return NULL;
    }

  if (strstr(key_type_str, "if-modn"))
    {
      key_type = SSH_PROXY_RSA;
      proxy_key_context =
        fl_prov_private_proxy_fl_make_rsa(plain_key,
                                          key_size_in_bits);
    }
  else if (strstr(key_type_str, "dl-modp"))
    {
      key_type = SSH_PROXY_DSA;
      proxy_key_context =
        fl_prov_private_proxy_fl_make_dsa(plain_key,
                                          key_size_in_bits);
    }
  else if (strstr(key_type_str, "ec-modp"))
    {
      key_type = SSH_PROXY_ECDSA;
      proxy_key_context =
        fl_prov_private_proxy_fl_make_ecdsa(plain_key,
                                            key_size_in_bits);
      key_size_in_bits = (key_size_in_bits + 7) / 8;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown private key type '%s'",
                             key_type_str));
      return NULL;
    }

  if (proxy_key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to create FL private key"));
      return NULL;
    }

  /* Move to create the proxy key */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Creating proxy %u-bit private key of type '%s'",
             key_size_in_bits, key_type_str));

  proxy_key = ssh_private_key_create_proxy(key_type,
                                           key_size_in_bits,
                                           fl_prov_private_proxy_key_op,
                                           fl_prov_private_proxy_free,
                                           proxy_key_context);

  if (proxy_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create proxy key"));
      ssh_fl_private_key_free(proxy_key_context);
      return NULL;
    }

  return proxy_key;
}

/* ******************** Public key proxy operations ************************ */

static void
fl_prov_public_proxy_free(void *context)
{
  ssh_fl_public_key_free(context);

  return;
}

static SshOperationHandle
fl_prov_public_proxy_key_op(SshProxyOperationId operation_id,
                            SshProxyRGFId rgf_id,
                            SshProxyKeyHandle handle,
                            const unsigned char *input_data,
                            size_t input_data_len,
                            SshProxyReplyCB reply_cb,
                            void *reply_context,
                            void *context)
{
  SshCryptoStatus status;
  unsigned char *data_buffer, *signature_buffer;
  size_t data_len, signature_len;

  if (ssh_decode_array(input_data, input_data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&data_buffer,
                                                    &data_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&signature_buffer,
                                                    &signature_len),
                       SSH_FORMAT_END) != input_data_len)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to extract data and signature from buffer"));
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto end;
    }

  status = ssh_fl_public_key_verify(operation_id,
                                    rgf_id,
                                    data_buffer,
                                    data_len,
                                    signature_buffer,
                                    signature_len,
                                    context);

 end:
  (*reply_cb)(status,
              NULL,
              0,
              reply_context);

  return NULL;
}

/* ********************* Public proxy key making *********************** */

static void *
fl_prov_public_proxy_fl_make_rsa(SshPublicKey public_key,
                                 SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct e, m;
  unsigned char *e_buf = NULL, *m_buf = NULL;
  unsigned int e_size_in_bits;
  size_t e_size, m_size;

  ssh_mprz_init(&e);
  ssh_mprz_init(&m);

  /* Get basic information from the key */
  status = ssh_public_key_get_info(public_key,
                                   SSH_PKF_PUBLIC_E, &e,
                                   SSH_PKF_MODULO_N, &m,
                                   SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get public key components"));
      goto end;
    }

  e_size = ssh_mp_byte_size(&e);
  m_size = ssh_mp_byte_size(&m);

  if (e_size > 32)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Too large exponent e: %u-bytes", (unsigned int) e_size));
      goto end;
    }

  /* In FL_RSAPublicKeyXXXX_t e size is static 32 bytes */
  e_size = 32;

  e_buf = ssh_malloc(e_size);
  m_buf = ssh_malloc(m_size);

  if ((e_buf == NULL) || (m_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(e_buf, e_size, &e);
  ssh_mprz_get_buf_lsb_first(m_buf, m_size, &m);

  e_size_in_bits = ssh_mprz_bit_size(&e);

  /* Create the FL library key */
  context = ssh_fl_rsa_public_key_make(e_buf, e_size,
                                       m_buf, m_size,
                                       e_size_in_bits,
                                       key_size_in_bits);

 end:
  if (e_buf != NULL)
    ssh_free(e_buf);
  if (m_buf != NULL)
    ssh_free(m_buf);

  ssh_mprz_clear(&e);
  ssh_mprz_clear(&m);

  return context;
}

static void *
fl_prov_public_proxy_fl_make_dsa(SshPublicKey public_key,
                                    SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct p, q, g, y;
  unsigned char *p_buf = NULL, *q_buf = NULL, *g_buf = NULL, *y_buf = NULL;
  size_t p_size, q_size, g_size, y_size;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&y);

  /* Get basic information from the key */
  status = ssh_public_key_get_info(public_key,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_PRIME_Q, &q,
                                   SSH_PKF_GENERATOR_G, &g,
                                   SSH_PKF_PUBLIC_Y, &y,
                                   SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get DSA public key components"));
      goto end;
    }

  p_size = ssh_mp_byte_size(&p);
  q_size = ssh_mp_byte_size(&q);
  g_size = ssh_mp_byte_size(&g);
  y_size = ssh_mp_byte_size(&y);

  p_buf = ssh_malloc(p_size);
  q_buf = ssh_malloc(q_size);
  g_buf = ssh_malloc(g_size);
  y_buf = ssh_malloc(y_size);

  if ((p_buf == NULL) || (q_buf == NULL) || (g_buf == NULL) || (y_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(p_buf, p_size, &p);
  ssh_mprz_get_buf_lsb_first(q_buf, q_size, &q);
  ssh_mprz_get_buf_lsb_first(g_buf, g_size, &g);
  ssh_mprz_get_buf_lsb_first(y_buf, y_size, &y);

  /* Create the FL library key */
  context = ssh_fl_dsa_public_key_make(p_buf, p_size,
                                       q_buf, q_size,
                                       g_buf, g_size,
                                       y_buf, y_size);

 end:
  if (p_buf != NULL)
    ssh_free(p_buf);
  if (q_buf != NULL)
    ssh_free(q_buf);
  if (g_buf != NULL)
    ssh_free(g_buf);
  if (y_buf != NULL)
    ssh_free(y_buf);

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&y);

  return context;
}

static void *
fl_prov_public_proxy_fl_make_ecdsa(SshPublicKey public_key,
                                   SshUInt32 key_size_in_bits)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct qx ,qy;
  unsigned char *qx_buf = NULL, *qy_buf = NULL;
  size_t qx_size, qy_size;

  ssh_mprz_init(&qx);
  ssh_mprz_init(&qy);

  /* Get basic information from the key */
  status = ssh_public_key_get_info(public_key,
                                   SSH_PKF_PUBLIC_Y, &qx, &qy,
                                   SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get ECDSA public key components"));
      goto end;
    }

  qx_size = ssh_mp_byte_size(&qx);
  qy_size = ssh_mp_byte_size(&qy);

  /* The buffers must be multiples of 4 bytes in FL */
  qx_size = ((qx_size + 3) / 4) * 4;
  qy_size = ((qy_size + 3) / 4) * 4;

  qx_buf = ssh_malloc(qx_size);
  qy_buf = ssh_malloc(qy_size);

  if ((qx_buf == NULL) || (qy_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(qx_buf, qx_size, &qx);
  ssh_mprz_get_buf_lsb_first(qy_buf, qy_size, &qy);

  /* Create the FL library key */
  context = ssh_fl_ecdsa_public_key_make(qx_buf, qx_size,
                                         qy_buf, qy_size,
                                         key_size_in_bits);

 end:
  if (qx_buf != NULL)
    ssh_free(qx_buf);
  if (qy_buf != NULL)
    ssh_free(qy_buf);

  ssh_mprz_clear(&qx);
  ssh_mprz_clear(&qy);

  return context;
}


static SshPublicKey
fl_prov_public_proxy_make(SshPublicKey plain_key)
{
  SshCryptoStatus status;
  SshPublicKey proxy_key;
  const char *key_type_str;
  const char *key_scheme_str;
  SshProxyKeyTypeId key_type;
  SshUInt32 key_size_in_bits;
  void *proxy_key_context;

  /* Solve the parameters proxy key API needs */
  status = ssh_public_key_get_info(plain_key,
                                   SSH_PKF_SIZE, &key_size_in_bits,
                                   SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to solve public key size: %s",
                 ssh_crypto_status_message(status)));
      return NULL;
    }

  status = ssh_public_key_get_info(plain_key,
                                   SSH_PKF_KEY_TYPE, &key_type_str,
                                   SSH_PKF_SIGN, &key_scheme_str,
                                   SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to solve public key type: %s",
                 ssh_crypto_status_message(status)));
      return NULL;
    }

  if (strstr(key_type_str, "if-modn"))
    {
      key_type = SSH_PROXY_RSA;
      proxy_key_context = fl_prov_public_proxy_fl_make_rsa(plain_key,
                                                           key_size_in_bits);
    }
  else if (strstr(key_type_str, "dl-modp"))
    {
      key_type = SSH_PROXY_DSA;
      proxy_key_context = fl_prov_public_proxy_fl_make_dsa(plain_key,
                                                           key_size_in_bits);
    }
  else if (strstr(key_type_str, "ec-modp"))
    {
      key_type = SSH_PROXY_ECDSA;
      proxy_key_context = fl_prov_public_proxy_fl_make_ecdsa(plain_key,
                                                             key_size_in_bits);
      key_size_in_bits = (key_size_in_bits + 7) / 8;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown public key type '%s'",
                             key_type_str));
      return NULL;
    }

  if (proxy_key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to create FL public key"));
      return NULL;
    }

  /* Move to create the proxy key */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Creating proxy %u-bit public key of type '%s' and scheme '%s'",
             key_size_in_bits, key_type_str, key_scheme_str));

  proxy_key = ssh_public_key_create_proxy(key_type,
                                          key_size_in_bits,
                                          fl_prov_public_proxy_key_op,
                                          fl_prov_public_proxy_free,
                                          proxy_key_context);

  if (proxy_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create proxy key"));
      ssh_fl_public_key_free(proxy_key_context);
      return NULL;
    }

  status = ssh_public_key_select_scheme(proxy_key,
                                        SSH_PKF_SIGN, key_scheme_str,
                                        SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to set proxy key scheme: %s",
                             key_scheme_str));
      ssh_fl_public_key_free(proxy_key_context);
      return NULL;
    }

  return proxy_key;
}

/* ********************* Proxy group operations ************************** */

static SshOperationHandle
fl_prov_proxy_group_dh_setup(SshProxyRGFId rgf_id,
                             const unsigned char *input_data,
                             size_t input_data_len,
                             SshProxyReplyCB reply_cb,
                             void *reply_context,
                             void *context)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  unsigned char *exchange_buffer = NULL, *return_buffer = NULL;
  size_t exchange_buffer_len = 0, return_buffer_len = 0;

  SSH_ASSERT(rgf_id == SSH_DH_NONE_NONE);
  SSH_ASSERT(input_data == NULL);
  SSH_ASSERT(input_data_len == 0);

  exchange_buffer_len = ssh_fl_group_exchange_size(context);
  SSH_ASSERT(exchange_buffer_len != 0);

  exchange_buffer = ssh_malloc(exchange_buffer_len);

  if (exchange_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      status = SSH_CRYPTO_NO_MEMORY;
      goto out;
    }

  status = ssh_fl_group_dh_setup(exchange_buffer,
                                 exchange_buffer_len,
                                 context);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to setup DH group"));
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto out;
    }

  return_buffer_len =
    ssh_encode_array_alloc(&return_buffer,
                           SSH_ENCODE_UINT32_STR(exchange_buffer,
                                                 exchange_buffer_len),
                           SSH_ENCODE_UINT32_STR(exchange_buffer,
                                                 exchange_buffer_len),
                           SSH_FORMAT_END);

  if (return_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      status = SSH_CRYPTO_NO_MEMORY;
      goto out;
    }

 out:

  if (status == SSH_CRYPTO_OK)
    {
      (*reply_cb)(status,
                  return_buffer,
                  return_buffer_len,
                  reply_context);
    }
  else
    {
      (*reply_cb)(status,
                  NULL,
                  0,
                  reply_context);
    }

  /* Cleanup */
  if (exchange_buffer != NULL)
    ssh_free(exchange_buffer);

  if (return_buffer != NULL)
    ssh_free(return_buffer);

  return NULL;
}

static SshOperationHandle
fl_prov_proxy_group_dh_agree(SshProxyRGFId rgf_id,
                             const unsigned char *input_data,
                             size_t input_data_len,
                             SshProxyReplyCB reply_cb,
                             void *reply_context,
                             void *context)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  unsigned char *exchange, *secret, *shared_buffer = NULL;
  size_t exchange_len, secret_len, shared_buffer_len;

  SSH_ASSERT(rgf_id == SSH_DH_NONE_NONE);

  shared_buffer_len = ssh_fl_group_shared_secret_size(context);
  SSH_ASSERT(shared_buffer_len != 0);

  shared_buffer = ssh_malloc(shared_buffer_len);

  if (shared_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      status = SSH_CRYPTO_NO_MEMORY;
      goto fail;
    }

  if (ssh_decode_array(input_data, input_data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&exchange, &exchange_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&secret, &secret_len),
                       SSH_FORMAT_END) != input_data_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to decode array"));
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto fail;
    }

  status = ssh_fl_group_dh_agree(exchange, exchange_len,
                                 secret, secret_len,
                                 shared_buffer,
                                 shared_buffer_len,
                                 context);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create shared buffer"));
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto fail;
    }

  (*reply_cb)(SSH_CRYPTO_OK,
              shared_buffer,
              shared_buffer_len,
              reply_context);

  ssh_free(shared_buffer);

  return NULL;

 fail:
  if (shared_buffer != NULL)
    ssh_free(shared_buffer);

  (*reply_cb)(status,
              NULL,
              0,
              reply_context);

  return NULL;
}


static SshOperationHandle
fl_prov_proxy_group_op(SshProxyOperationId operation_id,
                       SshProxyRGFId rgf_id,
                       SshProxyKeyHandle handle,
                       const unsigned char *input_data,
                       size_t input_data_len,
                       SshProxyReplyCB reply_cb,
                       void *reply_context,
                       void *context)
{

  switch (operation_id)
    {
    case SSH_DH_SETUP:
      return fl_prov_proxy_group_dh_setup(rgf_id, input_data,
                                          input_data_len, reply_cb,
                                          reply_context, context);

    case SSH_DH_AGREE:
      return fl_prov_proxy_group_dh_agree(rgf_id, input_data,
                                          input_data_len, reply_cb,
                                          reply_context, context);

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Invalid operation id %d",
                             (int) operation_id));
      (*reply_cb)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
    }

  return NULL;
}

/* *********************** Proxy group creation ************************** */

static void
fl_prov_proxy_group_free(void *context)
{
  ssh_fl_group_free(context);

  return;
}

static void *
fl_prov_proxy_dl_group_make(SshPkGroup plain_group)
{
  SshCryptoStatus status;
  void *context = NULL;
  SshMPIntegerStruct p, q, g;
  unsigned char *p_buf = NULL, *q_buf = NULL, *g_buf = NULL;
  size_t p_size, q_size, g_size;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);

  /* Get basic information from the key */
  status = ssh_pk_group_get_info(plain_group,
                                 SSH_PKF_PRIME_P, &p,
                                 SSH_PKF_PRIME_Q, &q,
                                 SSH_PKF_GENERATOR_G, &g,
                                 SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get DL group components"));
      goto end;
    }

  p_size = ssh_mp_byte_size(&p);
  q_size = ssh_mp_byte_size(&q);
  g_size = ssh_mp_byte_size(&g);

  p_buf = ssh_malloc(p_size);
  q_buf = ssh_malloc(q_size);
  g_buf = ssh_malloc(g_size);

  if ((p_buf == NULL) || (q_buf == NULL) || (g_buf == NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto end;
    }

  ssh_mprz_get_buf_lsb_first(p_buf, p_size, &p);
  ssh_mprz_get_buf_lsb_first(q_buf, q_size, &q);
  ssh_mprz_get_buf_lsb_first(g_buf, g_size, &g);

  /* Create the FL library group */
  context = ssh_fl_dl_group_make(p_buf, p_size,
                                 q_buf, q_size,
                                 g_buf, g_size);

 end:
  if (p_buf != NULL)
    ssh_free(p_buf);
  if (q_buf != NULL)
    ssh_free(q_buf);
  if (g_buf != NULL)
    ssh_free(g_buf);

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&g);

  return context;
}

static void *
fl_prov_proxy_ec_group_make(unsigned int group_size)
{
  void *context = NULL;

  /* Create the FL library group */
  context = ssh_fl_ec_group_make(group_size);

  return context;
}

static SshPkGroup
fl_prov_group_proxy_make(SshPkGroup plain_group)
{
  SshCryptoStatus status;
  SshPkGroup proxy_group = NULL;
  const char *group_type;
  unsigned int group_size;
  char *group_name;
  void *proxy_group_context = NULL;

  status = ssh_pk_group_get_info(plain_group,
                                 SSH_PKF_SIZE, &group_size,
                                 SSH_PKF_KEY_TYPE, &group_type,
                                 SSH_PKF_PREDEFINED_GROUP, &group_name,
                                 SSH_PKF_END);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to get group type and size"));
      goto end;
    }

  if (strstr(group_name, "brainpool"))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Brainpool-type curves are not supported by this provider"));
      goto end;
    }

  if (strstr(group_type, "dl-modp"))
    {
      proxy_group_context = fl_prov_proxy_dl_group_make(plain_group);
    }
  else if (strstr(group_type, "ec-modp"))
    {
      proxy_group_context = fl_prov_proxy_ec_group_make(group_size);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown group type: %s", group_type));
      goto end;
    }

  if (proxy_group_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create %u-bit %s proxy group",
                             group_size, group_type));
      goto end;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Creating %u-bit %s proxy group %s",
                          group_size, group_type, group_name));

  proxy_group = ssh_dh_group_create_proxy(SSH_PROXY_GROUP,
                                          group_size,
                                          fl_prov_proxy_group_op,
                                          fl_prov_proxy_group_free,
                                          proxy_group_context);

  if (proxy_group == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create proxy group"));
      ssh_fl_group_free(proxy_group_context);
    }

 end:
  return proxy_group;
}

/* *********************** Provider operations *************************** */


/* This is the provider object */
typedef struct SshFlProvRec
{
  /* Call to notify the application there are keys available. */
  SshEkNotifyCB notify_cb;

  /* Callback context for the callbacks above. */
  void *notify_context;
} *SshFlProv, SshFlProvStruct;


static SshEkStatus
fl_prov_init(const char *init_info,
                void *init_ptr,
                SshEkNotifyCB notify_cb,
                SshEkAuthenticationCB authentication_cb,
                void *context,
                void **provider_return)
{
  SshFlProv fl = NULL;

  if (notify_cb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Init failed due to missing notify_cb"));
      goto fail;
    }

  /* Build the context. */
  fl = ssh_calloc(1, sizeof(*fl));
  if (fl == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  fl->notify_cb = notify_cb;
  fl->notify_context = context;

  *provider_return = fl;

  if (notify_cb)
    (*notify_cb)(SSH_EK_EVENT_PROVIDER_ENABLED, NULL,
                 "Safezone FL enabled", 0, context);

  return SSH_EK_OK;

 fail:
  /* Cleanup possible allocations */
  ssh_free(fl);

  return SSH_EK_NO_MEMORY;
}

static void
fl_prov_uninit(void *provider)
{
  SshFlProv fl = (SshFlProv) provider;

  if (fl->notify_cb)
    (*fl->notify_cb)(SSH_EK_EVENT_PROVIDER_DISABLED, NULL,
                     "Safezone FL disabled",
                     0, fl->notify_context);

  ssh_free(fl);
}

static const char *fl_prov_get_printable_name(void *provider)
{
  return "FL provider";
}

static SshOperationHandle
fl_prov_gen_acc_private_key(void *provider_context,
                            SshPrivateKey source,
                            SshEkGetPrivateKeyCB get_private_key_cb,
                            void *context)
{
  SshPrivateKey accel_key;

  accel_key = fl_prov_private_proxy_make(source);

  if (accel_key != NULL)
    (*get_private_key_cb)(SSH_EK_OK,
                          accel_key,
                          context);
  else
    (*get_private_key_cb)(SSH_EK_FAILED,
                          NULL,
                          context);

  return NULL;
}


static SshOperationHandle
fl_prov_gen_acc_public_key(void *provider_context,
                           SshPublicKey source,
                           SshEkGetPublicKeyCB get_public_key_cb,
                           void *context)
{
  SshPublicKey accel_key;

  accel_key = fl_prov_public_proxy_make(source);

  if (accel_key != NULL)
    (*get_public_key_cb)(SSH_EK_OK,
                         accel_key,
                         context);
  else
    (*get_public_key_cb)(SSH_EK_FAILED,
                         NULL,
                         context);

  return NULL;
}

static SshOperationHandle
fl_prov_gen_acc_group(void *provider_context,
                         SshPkGroup source,
                         SshEkGetGroupCB get_group_cb,
                         void *context)
{
  SshPkGroup accel_group;

  accel_group = fl_prov_group_proxy_make(source);

  if (accel_group != NULL)
    (*get_group_cb)(SSH_EK_OK,
                    accel_group,
                    context);
  else
    (*get_group_cb)(SSH_EK_FAILED,
                    NULL,
                    context);

  return NULL;
}

const
struct SshEkProviderOpsRec ssh_ek_fl_ops =
  {
    "fl",
    fl_prov_init,
    fl_prov_uninit,
    NULL_FNPTR, /* No public keys */
    NULL_FNPTR, /* No private keys */
    NULL_FNPTR, /* No certificates */
    NULL_FNPTR, /* No trusted certs */
    NULL_FNPTR, /* No groups */
    fl_prov_get_printable_name,
    fl_prov_gen_acc_private_key,
    fl_prov_gen_acc_public_key,
    fl_prov_gen_acc_group,
    NULL_FNPTR, /* No random bytes */
    NULL_FNPTR  /* No messages  */
  };
