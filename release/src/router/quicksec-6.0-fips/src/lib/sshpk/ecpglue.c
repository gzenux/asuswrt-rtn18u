/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Glueing ecp code into ssh crypto library.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "ecpfix.h"
#include "sshbuffer.h"
#include "sshencode.h"
#include "dl-internal.h"
#include "sshglobals.h"

#ifdef SSHDIST_CRYPT_ECP
#define SSH_DEBUG_MODULE "SshEcpGlue"

/*********************** Stack routines ************************/

#define SSH_ECP_STACK_RANDOMIZER  0x1

/* Randomizer */

SSH_CSTACK_BEGIN( SshECPStackRandomizer )
  SshMPIntegerStruct k;
  SshECPPointStruct Q;
SSH_CSTACK_END( SshECPStackRandomizer );

/* Allocate and deletion of stack elements. */

/* Randomizers. */

SSH_CSTACK_DESTRUCTOR_BEGIN( SshECPStackRandomizer, stack )
  ssh_mprz_clear(&stack->k);
  ssh_ecp_clear_point(&stack->Q);
SSH_CSTACK_DESTRUCTOR_END( SshECPStackRandomizer, stack )

SSH_CSTACK_CONSTRUCTOR_BEGIN( SshECPStackRandomizer, stack, E,
                              SSH_ECP_STACK_RANDOMIZER )
  ssh_mprz_init(&stack->k);
  ssh_ecp_init_point(&stack->Q, (SshECPCurve)E);
SSH_CSTACK_CONSTRUCTOR_END( SshECPStackRandomizer, stack )

/************************ Auxliary functions *******************/

void ssh_ecp_curve_encode(SshBuffer buffer, const SshECPCurveStruct *curve)
{
  ssh_encode_buffer(buffer,
                    SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &curve->q),
                    SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &curve->a),
                    SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &curve->b),
                    SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &curve->c),
                    SSH_FORMAT_END);
}

size_t ssh_ecp_curve_decode(const unsigned char *buf, size_t len,
                            SshECPCurve curve)
{
  size_t ret_value;
  SshMPIntegerStruct a, b, c, q;

  /* NOTE: this could be changed if faster modular routines will be
     used. */
  ssh_mprz_init(&q);
  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&c);

  ret_value =
    ssh_decode_array(buf, len,
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered, &q),
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered, &a),
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered, &b),
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered, &c),
                     SSH_FORMAT_END);

  if (ret_value != 0)
    {
      if (!ssh_ecp_set_curve(curve, &q, &a, &b, &c))
        ret_value = 0;
    }

  ssh_mprz_clear(&q);
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&c);

  return ret_value;
}

void ssh_ecp_point_encode(SshBuffer buffer,
                          const SshECPPointStruct *point, Boolean pc)
{
  if (pc)
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,  &point->x),
                      SSH_ENCODE_BOOLEAN(ssh_mprz_get_ui(&point->y) & 0x1),
                      SSH_FORMAT_END);
  else
    ssh_encode_buffer(buffer,
                      SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &point->x),
                      SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &point->y),
                      SSH_FORMAT_END);
}

size_t ssh_ecp_point_decode(const unsigned char *buf, size_t len,
                            SshECPPoint point,
                            Boolean pc,
                            SshECPCurve curve)
{
  Boolean bit;
  size_t ret_value;

  SSH_ASSERT(point != NULL);

  ssh_ecp_init_point(point, curve);
  if (pc)
    {
      ret_value =
        ssh_decode_array(buf, len,
                         SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                    &point->x),
                         SSH_DECODE_BOOLEAN(&bit),
                         SSH_FORMAT_END);
      if (ret_value &&
          ssh_ecp_restore_y(point, curve, bit) == FALSE)
        {
          ssh_ecp_clear_point(point);
          return 0;
        }
    }
  else
    ret_value =
      ssh_decode_array(buf, len,
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &point->x),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &point->y),
                       SSH_FORMAT_END);

  if (ret_value)
    point->z = 1;
  else
    ssh_ecp_clear_point(point);

  return ret_value;
}

/*********************** Discrete Logarithm ********************/

/* Discrete logarithm parameter structures. */

typedef struct SshECPParamRec
{
  struct SshECPParamRec *next, *prev;
  SshCStack stack;
  unsigned int reference_count;

  /* Defined if predefined. */
  const char *predefined;

  /* Actual parameter information. */
  Boolean pc;
  Boolean init_flag;

  SshECPCurveStruct E;
  SshECPPointStruct P;
  SshMPIntegerStruct n;
} SshECPParam;

/* Global parameter list. */
typedef SshECPParam *SshECPParamPtr;
SSH_GLOBAL_DECLARE(SshECPParamPtr, ssh_ecp_param_list);
SSH_GLOBAL_DEFINE_INIT(SshECPParamPtr, ssh_ecp_param_list) = NULL;
#define ssh_ecp_param_list SSH_GLOBAL_USE_INIT(ssh_ecp_param_list)

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#ifdef ENABLE_VXWORKS_RESTART_WATCHDOG
void ssh_ecp_restart(void)
{
  ssh_ecp_param_list = NULL;
}
#endif /* ENABLE_VXWORKS_RESTART_WATCHDOG */
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

void ssh_ecp_init_param(SshECPParam *param)
{
  param->next = NULL;
  param->prev = NULL;
  param->stack = NULL;
  param->reference_count = 0;

  param->predefined = NULL;
  param->pc = FALSE;
  param->init_flag = FALSE;
}

void ssh_ecp_clear_param(SshECPParam *param)
{
  if (param->prev)
    param->prev->next = param->next;
  else
    {
      /* Handle the special case that we are in the global list. */
      if (ssh_ecp_param_list == param)
        ssh_ecp_param_list = param->next;
    }
  if (param->next)
    param->next->prev = param->prev;

  ssh_cstack_free(param->stack);

  param->pc = FALSE;
  if (param->init_flag)
    {
      ssh_ecp_clear_curve(&param->E);
      ssh_ecp_clear_point(&param->P);
      ssh_mprz_clear(&param->n);
    }
  param->init_flag = FALSE;
}

SshECPParam *ssh_ecp_param_list_add(SshECPParam *param)
{
  SshECPParam *temp;

  temp = ssh_ecp_param_list;
  while (temp)
    {
      if (ssh_ecp_compare_points(&temp->P, &param->P) == TRUE &&
          ssh_ecp_compare_curves(&temp->E, &param->E) == TRUE &&
          ssh_mprz_cmp(&temp->n, &param->n) == 0)
        {
          return temp;
        }
      temp = temp->next;
    }

  /* Make first. */
  param->next = ssh_ecp_param_list;
  if (ssh_ecp_param_list)
    ssh_ecp_param_list->prev = param;
  ssh_ecp_param_list = param;
  return NULL;
}

void ssh_ecp_param_add_ref(SshECPParam *param)
{
  param->reference_count++;
}

size_t ssh_ecp_param_decode(const unsigned char *buf, size_t len,
                            SshECPParam *param,
                            SshUInt32 value)
{
  size_t ret_value, parsed;
  char *predefined;

  ret_value = 0;
  if (value == 0)
    {
      ssh_mprz_init(&param->n);

      parsed = ssh_ecp_curve_decode(buf, len, &param->E);
      if (parsed == 0)
        {
          ssh_mprz_clear(&param->n);
          return 0;
        }

      parsed += ssh_decode_array(buf + parsed, len - parsed,
                                 SSH_DECODE_BOOLEAN(&param->pc),
                                 SSH_FORMAT_END);
      parsed += ssh_ecp_point_decode(buf + parsed, len - parsed,
                                     &param->P, param->pc, &param->E);
      parsed +=
        ssh_decode_array(buf + parsed, len - parsed,
                         SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                    &param->n),
                         SSH_FORMAT_END);
      if (parsed != len)
        goto error;

      param->init_flag = TRUE;
    }
  else
    {
      ret_value = ssh_decode_array(buf, len,
                                   SSH_DECODE_UINT32_SSTR(&predefined, NULL),
                                   SSH_FORMAT_END);
      if (!ret_value)
        return 0;

      if (!ssh_ecp_set_param(predefined, &param->predefined,
                             &param->E,
                             &param->P, &param->n, &param->pc))
        {
          ssh_free(predefined);
          return 0;
        }

      param->init_flag = TRUE;
      ssh_free(predefined);
    }
  return ret_value;

 error:
  ssh_mprz_clear(&param->n);
  ssh_ecp_clear_curve(&param->E);
  ssh_ecp_clear_point(&param->P);
  return 0;
}

SshCryptoStatus ssh_ecp_param_import(const unsigned char *buf,
                                     size_t len,
                                     void **parameters)
{
  SshECPParam *param, *temp;
  SshUInt32 value = 0;
  size_t parsed;

  if ((param = ssh_malloc(sizeof(*param))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  ssh_ecp_init_param(param);

  /* Decode. */
  parsed = ssh_decode_array(buf, len,
                            SSH_DECODE_UINT32(&value),
                            SSH_FORMAT_END);
  if (parsed == 0)
    {
    error:
      ssh_ecp_clear_param(param);
      ssh_free(param);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  parsed += ssh_ecp_param_decode(buf + parsed, len - parsed, param, value);
  if (parsed != len)
    goto error;

  temp = ssh_ecp_param_list_add(param);
  if (temp)
    {
      ssh_ecp_clear_param(param);
      ssh_free(param);
      param = temp;
    }
  ssh_ecp_param_add_ref(param);

  *parameters = (void *)param;
  return SSH_CRYPTO_OK;
}

void ssh_ecp_param_encode(SshBuffer buffer, const SshECPParam *param)
{
  if (param->predefined)
    {
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(1),
                        SSH_ENCODE_UINT32_SSTR(param->predefined,
                                               strlen(param->predefined)),
                        SSH_FORMAT_END);
    }
  else
    {
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_UINT32(0),
                        SSH_FORMAT_END);
      ssh_ecp_curve_encode(buffer, &param->E);
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_BOOLEAN(param->pc),
                        SSH_FORMAT_END);
      ssh_ecp_point_encode(buffer, &param->P, param->pc);
      ssh_encode_buffer(buffer,
                        SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                           &param->n),
                        SSH_FORMAT_END);
    }
}

SshCryptoStatus ssh_ecp_param_export(const void *parameters,
                                     unsigned char **buf,
                                     size_t *length_return)
{
  const SshECPParam *param = parameters;
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);
  ssh_ecp_param_encode(&buffer, param);

  if ((*length_return = ssh_buffer_len(&buffer)) != 0)
    {
      *buf = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      if (*buf == NULL)
        *length_return = 0;
    }
  ssh_buffer_uninit(&buffer);
  return (*length_return != 0) ? SSH_CRYPTO_OK : SSH_CRYPTO_OPERATION_FAILED;
}

void ssh_ecp_param_free(void *parameters)
{
  SshECPParam *param = parameters;

  if (param->reference_count == 0)
    ssh_fatal("ssh_ecp_param_free: reference counting failed.");

  if (--param->reference_count > 0)
    return;

  ssh_ecp_clear_param(param);
  ssh_free(parameters);
}

SshCryptoStatus ssh_ecp_param_copy(void *param_src, void **param_dest)
{
  SshECPParam *param = param_src;

  ssh_ecp_param_add_ref(param);
  *param_dest = param_src;
  return SSH_CRYPTO_OK;
}

/* Discrete Logarithm key structures. */

typedef struct SshECPPublicKeyRec
{
  SshECPParam *param;
  SshECPPointStruct Q;
} SshECPPublicKey;

typedef struct SshECPPrivateKeyRec
{
  SshECPParam *param;
  SshECPPointStruct Q;
  SshMPIntegerStruct k;
} SshECPPrivateKey;

/* Discrete Logarithm key control functions. */

void ssh_ecp_init_public_key(SshECPPublicKey *pub_key, SshECPParam *param)
{
  ssh_ecp_param_add_ref(param);
  pub_key->param = param;
  ssh_ecp_init_point(&pub_key->Q, &pub_key->param->E);
}

void ssh_ecp_clear_public_key(SshECPPublicKey *pub_key)
{
  ssh_ecp_clear_point(&pub_key->Q);
  ssh_ecp_param_free(pub_key->param);
}

void ssh_ecp_init_private_key(SshECPPrivateKey *prv_key, SshECPParam *param)
{
  ssh_ecp_param_add_ref(param);
  prv_key->param = param;
  ssh_ecp_init_point(&prv_key->Q, &prv_key->param->E);
  ssh_mprz_init(&prv_key->k);
}

void ssh_ecp_clear_private_key(SshECPPrivateKey *prv_key)
{
  ssh_ecp_clear_point(&prv_key->Q);
  ssh_mprz_clear(&prv_key->k);
  ssh_ecp_param_free(prv_key->param);
}

/* Public key primitives. */

SshCryptoStatus ssh_ecp_public_key_import(const unsigned char *buf,
                                          size_t len,
                                          void **public_key)
{
  SshECPPublicKey *pub_key;
  SshECPParam *param, *temp;
  SshECPPointStruct Q;
  SshUInt32 value = 0;
  size_t parsed;

  if ((param = ssh_malloc(sizeof(*param))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  ssh_ecp_init_param(param);

  parsed = ssh_decode_array(buf, len,
                            SSH_DECODE_UINT32(&value),
                            SSH_FORMAT_END);
  if (parsed == 0)
    {
    error:
      ssh_ecp_clear_param(param);
      ssh_free(param);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  parsed += ssh_ecp_param_decode(buf + parsed, len - parsed, param, value);
  parsed += ssh_ecp_point_decode(buf + parsed, len - parsed,
                                 &Q, param->pc, &param->E);
  if (parsed != len)
    goto error;

  if ((pub_key = ssh_malloc(sizeof(*pub_key))) == NULL)
    goto error;

  temp = ssh_ecp_param_list_add(param);
  if (temp)
    {
      ssh_ecp_clear_param(param);
      ssh_free(param);
      param = temp;
    }
  ssh_ecp_init_public_key(pub_key, param);

  /* We happily have read the public key, and now are able to copy it.
     Also we remember to free the allocated point. */
  ssh_ecp_copy_point(&pub_key->Q, &Q);
  ssh_ecp_clear_point(&Q);

  *public_key = (void *)pub_key;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_ecp_public_key_export(const void *public_key,
                                          unsigned char **buf,
                                          size_t *length_return)
{
  SshECPPublicKey *pub_key = (SshECPPublicKey *)public_key;
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);
  ssh_ecp_param_encode(&buffer, pub_key->param);
  ssh_ecp_point_encode(&buffer, &pub_key->Q, pub_key->param->pc);

  if ((*length_return = ssh_buffer_len(&buffer)) != 0)
    {
      *buf = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      if (*buf == NULL)
        *length_return = 0;
    }

  ssh_buffer_uninit(&buffer);
 return (*length_return != 0) ? SSH_CRYPTO_OK : SSH_CRYPTO_OPERATION_FAILED;
}

void ssh_ecp_public_key_free(void *public_key)
{
  ssh_ecp_clear_public_key((SshECPPublicKey *)public_key);
  ssh_free(public_key);
}

SshCryptoStatus
ssh_ecp_public_key_copy(void *public_key_src, void **public_key_dest)
{
  SshECPPublicKey *pub_src = public_key_src;
  SshECPPublicKey *pub_dest = ssh_malloc(sizeof(*pub_dest));

  if (pub_dest)
    {
      ssh_ecp_init_public_key(pub_dest, pub_src->param);
      ssh_ecp_copy_point(&pub_dest->Q, &pub_src->Q);
      *public_key_dest = (void *)pub_dest;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_ecp_public_key_derive_param(void *public_key,
                                void **parameters)
{
  SshECPPublicKey *pub_key = public_key;
  SshECPParam *param = pub_key->param;

  ssh_ecp_param_add_ref(param);
  *parameters = (void *)param;
  return SSH_CRYPTO_OK;
}

/* Private key primitives. */
SshCryptoStatus
ssh_ecp_private_key_import(const unsigned char *buf,
                           size_t len,
                           void **private_key)
{
  SshECPPrivateKey *prv_key;
  SshECPParam *param, *temp;
  SshECPPointStruct Q;
  SshMPIntegerStruct   k;
  SshUInt32 value = 0;
  size_t parsed;

  if ((param = ssh_malloc(sizeof(*param))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  ssh_mprz_init(&k);
  ssh_ecp_init_param(param);

  parsed = ssh_decode_array(buf, len,
                            SSH_DECODE_UINT32(&value),
                            SSH_FORMAT_END);
  if (parsed == 0)
    {
    error:
      ssh_mprz_clear(&k);
      ssh_ecp_clear_param(param);
      ssh_free(param);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  parsed += ssh_ecp_param_decode(buf + parsed, len - parsed,
                                 param, value);
  parsed += ssh_ecp_point_decode(buf + parsed, len - parsed,
                                 &Q, param->pc, &param->E);
  parsed +=
    ssh_decode_array(buf + parsed, len - parsed,
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered, &k),
                     SSH_FORMAT_END);
  if (parsed != len)
    goto error;

  if ((prv_key = ssh_malloc(sizeof(*prv_key))) == NULL)
    goto error;

  temp = ssh_ecp_param_list_add(param);
  if (temp)
    {
      ssh_ecp_clear_param(param);
      ssh_free(param);
      param = temp;
    }
  ssh_ecp_init_private_key(prv_key, param);

  ssh_ecp_copy_point(&prv_key->Q, &Q);
  ssh_mprz_set(&prv_key->k, &k);

  ssh_mprz_clear(&k);
  /* We must free the point Q here because we succeeded creating one
     with the ssh_decode_array routine. */
  ssh_ecp_clear_point(&Q);

  *private_key = (void *)prv_key;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_ecp_private_key_export(const void *private_key,
                           unsigned char **buf,
                           size_t *length_return)
{
  const SshECPPrivateKey *prv_key = private_key;
  SshBufferStruct buffer;

  ssh_buffer_init(&buffer);
  ssh_ecp_param_encode(&buffer, prv_key->param);
  ssh_ecp_point_encode(&buffer, &prv_key->Q, prv_key->param->pc);
  ssh_encode_buffer(&buffer,
                    SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered, &prv_key->k),
                    SSH_FORMAT_END);

  if ((*length_return = ssh_buffer_len(&buffer)) != 0)
    {
      *buf = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
      if (*buf == NULL)
        *length_return = 0;
    }

  ssh_buffer_uninit(&buffer);
  return (*length_return != 0) ? SSH_CRYPTO_OK : SSH_CRYPTO_OPERATION_FAILED;
}

void ssh_ecp_private_key_free(void *private_key)
{
  ssh_ecp_clear_private_key((SshECPPrivateKey *)private_key);
  ssh_free(private_key);
}

SshCryptoStatus
ssh_ecp_private_key_copy(void *private_key_src,
                         void **private_key_dest)
{
  SshECPPrivateKey *prv_src = private_key_src;
  SshECPPrivateKey *prv_dest = ssh_malloc(sizeof(*prv_dest));

  if (prv_dest)
    {
      ssh_ecp_init_private_key(prv_dest, prv_src->param);
      ssh_ecp_copy_point(&prv_dest->Q, &prv_src->Q);
      ssh_mprz_set(&prv_dest->k, &prv_src->k);
      *private_key_dest = (void *)prv_dest;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_ecp_private_key_derive_public_key(const void *private_key,
                                      void **public_key)
{
  const SshECPPrivateKey *prv_key = private_key;
  SshECPPublicKey *pub_key = ssh_malloc(sizeof(*pub_key));

  if (pub_key)
    {
      ssh_ecp_init_public_key(pub_key, prv_key->param);
      ssh_ecp_copy_point(&pub_key->Q, &prv_key->Q);
      *public_key = (void *)pub_key;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_ecp_private_key_derive_param(void *private_key, void **parameters)
{
  SshECPPrivateKey *prv_key = private_key;
  SshECPParam *param = prv_key->param;

  ssh_ecp_param_add_ref(param);
  *parameters = (void *)param;
  return SSH_CRYPTO_OK;
}

/* Randomizers. */

unsigned int ssh_ecp_param_count_randomizers(void *parameters)
{
  return ssh_cstack_count(&((SshECPParam *)parameters)->stack,
                          SSH_ECP_STACK_RANDOMIZER);
}

SshCryptoStatus
ssh_ecp_param_generate_randomizer(void *parameters)
{
  SshECPStackRandomizer *stack;
  SshECPParam *param = parameters;

  /* Allocate new stack element. */
  stack = ssh_cstack_SshECPStackRandomizer_constructor(&param->E);

retry:

  ssh_mprz_mod_random(&stack->k, &param->n);
  if (ssh_mprz_cmp_ui(&stack->k, 0) == 0)
    goto retry;
  ssh_ecp_mul(&stack->Q, &param->P, &stack->k, &param->E);

  /* Push to stack list. */
  ssh_cstack_push(&param->stack, stack);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_ecp_param_export_randomizer(void *parameters,
                                unsigned char **buf,
                                size_t *length_return)
{
  SshECPStackRandomizer *stack;
  SshECPParam *param = parameters;
  SshBufferStruct buffer;

  stack = (SshECPStackRandomizer *)ssh_cstack_pop(&param->stack,
                                                  SSH_ECP_STACK_RANDOMIZER);
  if (stack)
    {
      ssh_buffer_init(&buffer);
      ssh_encode_buffer(&buffer,
                        SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                           &stack->k),
                        SSH_FORMAT_END);
      ssh_ecp_point_encode(&buffer, &stack->Q, param->pc);

      if ((*length_return = ssh_buffer_len(&buffer)) != 0)
        {
          *buf = ssh_memdup(ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer));
          if (*buf == NULL)
            *length_return = 0;
        }

      ssh_buffer_uninit(&buffer);
      return (*length_return) ? SSH_CRYPTO_OK : SSH_CRYPTO_OPERATION_FAILED;
    }
  *buf = NULL;
  *length_return = 0;
  return SSH_CRYPTO_OPERATION_FAILED;
}

SshCryptoStatus
ssh_ecp_param_import_randomizer(void *parameters,
                                const unsigned char *buf,
                                size_t len)
{
  SshECPStackRandomizer *stack;
  SshECPParam *param = parameters;
  size_t parsed;

  /* Allocate new stack element. */
  stack = ssh_cstack_SshECPStackRandomizer_constructor(&param->E);

  parsed =
    ssh_decode_array(buf, len,
                     SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                &stack->k),
                     SSH_FORMAT_END);

  if (parsed == 0)
    {
    error:
      ssh_cstack_free(stack);
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  parsed += ssh_ecp_point_decode(buf + parsed, len - parsed,
                                 &stack->Q, param->pc, &param->E);
  if (parsed != len)
    goto error;

  ssh_cstack_push(&param->stack, stack);
  return SSH_CRYPTO_OK;
}

/******************** Actions ***************************/

typedef struct SshECPInitCtxRec
{
  SshMPIntegerStruct q, a, b, c, n, k, px, py, qx, qy;
  Boolean pc;
  unsigned int size;
  const char *predefined;
  unsigned int flag;
#define SSH_ECP_FLAG_IGNORE 0
} SshECPInitCtx;

SshCryptoStatus ssh_ecp_action_init(void **context)
{
  SshECPInitCtx *ctx = ssh_malloc(sizeof(*ctx));

  if (ctx)
    {
      ctx->size = 0;
      ctx->flag = SSH_ECP_FLAG_IGNORE;
      ctx->predefined = NULL;
      ctx->pc = FALSE;

      ssh_mprz_init_set_ui(&ctx->q, 0);
      ssh_mprz_init_set_ui(&ctx->a, 0);
      ssh_mprz_init_set_ui(&ctx->b, 0);
      ssh_mprz_init_set_ui(&ctx->c, 0);
      ssh_mprz_init_set_ui(&ctx->n, 0);
      ssh_mprz_init_set_ui(&ctx->k, 0);

      /* NOTE: Due restrictions in ecp library we have to work our way
         like this. */
      ssh_mprz_init_set_ui(&ctx->px, 0);
      ssh_mprz_init_set_ui(&ctx->py, 0);
      ssh_mprz_init_set_ui(&ctx->qx, 0);
      ssh_mprz_init_set_ui(&ctx->qy, 0);
      *context = (void *)ctx;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_ecp_action_public_key_init(void **context)
{
  return ssh_ecp_action_init(context);
}

void ssh_ecp_action_free(void *context)
{
  SshECPInitCtx *ctx = context;
  ssh_mprz_clear(&ctx->q);
  ssh_mprz_clear(&ctx->a);
  ssh_mprz_clear(&ctx->b);
  ssh_mprz_clear(&ctx->c);
  ssh_mprz_clear(&ctx->n);
  ssh_mprz_clear(&ctx->k);

  ssh_mprz_clear(&ctx->px);
  ssh_mprz_clear(&ctx->py);
  ssh_mprz_clear(&ctx->qx);
  ssh_mprz_clear(&ctx->qy);

  ssh_free(ctx);
}

char *ssh_ecp_action_put(void *context, va_list ap,
                         void *input_context,
                         SshCryptoType type,
                         SshPkFormat format)
{
  SshECPInitCtx *ctx = context;
  SshMPInteger temp_mp;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      ctx->size = va_arg(ap, unsigned int);
      r = "i";
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      (void)va_arg(ap, unsigned int);
      r = "i";
      break;
    case SSH_PKF_POINT_COMPRESS:
      ctx->pc = va_arg(ap, Boolean);
      r = "b";
      break;
    case SSH_PKF_PRIME_P:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->q, temp_mp);
      break;
    case SSH_PKF_CARDINALITY:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->c, temp_mp);
      break;
    case SSH_PKF_CURVE_A:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->a, temp_mp);
      break;
    case SSH_PKF_CURVE_B:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->b, temp_mp);
      break;
    case SSH_PKF_PRIME_Q:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->n, temp_mp);
      break;
    case SSH_PKF_GENERATOR_G:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->px, temp_mp);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->py, temp_mp);
      r = "pp";
      break;
    case SSH_PKF_PUBLIC_Y:
      if (type & SSH_CRYPTO_TYPE_PK_GROUP)
        return NULL;
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->qx, temp_mp);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->qy, temp_mp);
      r = "pp";
      break;
    case SSH_PKF_SECRET_X:
      if (type & (SSH_CRYPTO_TYPE_PK_GROUP | SSH_CRYPTO_TYPE_PUBLIC_KEY))
        return 0;
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(&ctx->k, temp_mp);
      break;
    case SSH_PKF_PREDEFINED_GROUP:
      ctx->predefined = va_arg(ap, const char *);
      break;
    default:
      return NULL;
      break;
    }
  return r;
}

char *ssh_ecp_action_private_key_put(void *context, va_list ap,
                                     void *input_context,
                                     SshPkFormat format)
{
  return ssh_ecp_action_put(context,
                            ap, input_context,
                            SSH_CRYPTO_TYPE_PRIVATE_KEY,
                            format);
}

char *ssh_ecp_action_private_key_get(void *context, va_list ap,
                                     void *output_context,
                                     SshPkFormat format)
{
  SshECPPrivateKey *prv = context;
  SshMPInteger temp_mp;
  Boolean *temp_bool;
  unsigned int *temp_int;
  const char **temp_char;
  char *r;

  r = "p";

  switch (format)
    {
    case SSH_PKF_SIZE:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = ssh_mprz_bit_size(&prv->param->E.q);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = 0;
      break;
    case SSH_PKF_POINT_COMPRESS:
      temp_bool = va_arg(ap, Boolean *);
      *temp_bool = prv->param->pc;
      break;
    case SSH_PKF_PRIME_P:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->E.q);
      break;
    case SSH_PKF_CARDINALITY:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->E.c);
      break;
    case SSH_PKF_CURVE_A:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->E.a);
      break;
    case SSH_PKF_CURVE_B:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->E.b);
      break;
    case SSH_PKF_PRIME_Q:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->n);
      break;
    case SSH_PKF_GENERATOR_G:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->P.x);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->param->P.y);
      r = "pp";
      break;
    case SSH_PKF_PUBLIC_Y:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->Q.x);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->Q.y);
      r = "pp";
      break;
    case SSH_PKF_SECRET_X:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &prv->k);
      break;
    case SSH_PKF_PREDEFINED_GROUP:
      temp_char = va_arg(ap, const char **);
      *temp_char = prv->param->predefined;
      break;
    default:
      return NULL;
      break;
    }
  return r;
}

char *ssh_ecp_action_public_key_put(void *context, va_list ap,
                                    void *input_context,
                                    SshPkFormat format)
{
  return ssh_ecp_action_put(context, ap,
                            input_context,
                            SSH_CRYPTO_TYPE_PUBLIC_KEY,
                            format);
}

char *ssh_ecp_action_public_key_get(void *context, va_list ap,
                                    void *output_context,
                                    SshPkFormat format)
{
  SshECPPublicKey *pub = context;
  SshMPInteger temp_mp;
  Boolean *temp_bool;
  unsigned int *temp_int;
  const char ** temp_char;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = ssh_mprz_bit_size(&pub->param->E.q);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = 0;
      break;
    case SSH_PKF_POINT_COMPRESS:
      temp_bool = va_arg(ap, Boolean *);
      *temp_bool = pub->param->pc;
      break;
    case SSH_PKF_PRIME_P:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->E.q);
      break;
    case SSH_PKF_CARDINALITY:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->E.c);
      break;
    case SSH_PKF_CURVE_A:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->E.a);
      break;
    case SSH_PKF_CURVE_B:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->E.b);
      break;
    case SSH_PKF_PRIME_Q:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->n);
      break;
    case SSH_PKF_GENERATOR_G:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->P.x);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->param->P.y);
      r = "pp";
      break;
    case SSH_PKF_PUBLIC_Y:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->Q.x);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &pub->Q.y);
      r = "pp";
      break;
    case SSH_PKF_PREDEFINED_GROUP:
      temp_char = va_arg(ap, const char **);
      *temp_char = pub->param->predefined;
      break;
    default:
      return NULL;
      break;
    }
  return r;
}

char *ssh_ecp_action_param_put(void *context, va_list ap,
                               void *input_context,
                               SshPkFormat format)
{
  return ssh_ecp_action_put(context, ap,
                            input_context,
                            SSH_CRYPTO_TYPE_PK_GROUP,
                            format);
}

char *ssh_ecp_action_param_get(void *context, va_list ap,
                               void *output_context,
                               SshPkFormat format)
{
  SshECPParam *param = context;
  SshMPInteger temp_mp;
  unsigned int *temp_int;
  Boolean *temp_bool;
  const char **temp_name;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = ssh_mprz_bit_size(&param->E.q);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      temp_int = va_arg(ap, unsigned int *);
      *temp_int = 0;
      break;
    case SSH_PKF_POINT_COMPRESS:
      temp_bool = va_arg(ap, Boolean *);
      *temp_bool = param->pc;
      break;
    case SSH_PKF_PRIME_P:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->E.q);
      break;
    case SSH_PKF_CARDINALITY:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->E.c);
      break;
    case SSH_PKF_CURVE_A:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->E.a);
      break;
    case SSH_PKF_CURVE_B:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->E.b);
      break;
    case SSH_PKF_PRIME_Q:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->n);
      break;
    case SSH_PKF_GENERATOR_G:
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->P.x);
      temp_mp = va_arg(ap, SshMPInteger);
      ssh_mprz_set(temp_mp, &param->P.y);
      r = "pp";
      break;
    case SSH_PKF_PREDEFINED_GROUP:
      temp_name = va_arg(ap, const char **);
      *temp_name = param->predefined;
      break;
    default:
      return NULL;
      break;
    }
  return r;
}

SshCryptoStatus
ssh_ecp_action_make(void *context, int type, void **ret_context)
{
  SshECPInitCtx *ctx = context;
  SshECPParam *param, *temp;
  SshECPPrivateKey *prv_key;
  SshECPPublicKey *pub_key;

  /* Check flags (none yet). */
  /* Check contraints of type. */
  switch (type)
    {
    case 0:
      /* None. */
      break;
    case 1:
      /* Verify that the public key was really given! */
      if (ssh_mprz_cmp_ui(&ctx->qx, 0) == 0 &&
          ssh_mprz_cmp_ui(&ctx->qy, 0) == 0)
        return SSH_CRYPTO_KEY_INVALID;
      break;
    case 2:
      /* None. */
      break;
    }

  if (ctx->predefined == NULL)
    {
      if (ssh_mprz_cmp_ui(&ctx->q, 0) == 0 ||
          ssh_mprz_cmp_ui(&ctx->n, 0) == 0 ||
          ssh_mprz_cmp_ui(&ctx->c, 0) == 0)
        {
          /* We cannot generate a parameters set! Would take hours and
             most users don't want to wait that long. */
          return SSH_CRYPTO_KEY_INVALID;
        }
      else
        {
          if ((param = ssh_malloc(sizeof(*param))) == NULL)
            return SSH_CRYPTO_NO_MEMORY;

          ssh_ecp_init_param(param);

          /* Don't bother to check what the application has supplied us. */
          if (!ssh_ecp_set_curve(&param->E,
                                 &ctx->q, &ctx->a, &ctx->b, &ctx->c))
            {
              ssh_ecp_clear_param(param);
              ssh_free(param);
              return SSH_CRYPTO_OPERATION_FAILED;
            }

          ssh_ecp_init_point(&param->P, &param->E);
          ssh_ecp_set_point(&param->P, &ctx->px, &ctx->py, 1);

          ssh_mprz_init_set(&param->n, &ctx->n);

          param->init_flag = TRUE;
          /* Check the list. */
          temp = ssh_ecp_param_list_add(param);
          if (temp)
            {
              ssh_ecp_clear_param(param);
              ssh_free(param);
              param = temp;
            }
        }
    }
  else
    {
      if ((param = ssh_malloc(sizeof(*param))) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      ssh_ecp_init_param(param);

      if (ssh_ecp_set_param(ctx->predefined, &param->predefined,
                            &param->E, &param->P, &param->n, &param->pc)
          == FALSE)
        {
          ssh_ecp_clear_param(param);
          ssh_free(param);
          return SSH_CRYPTO_OPERATION_FAILED;
        }
      param->init_flag = TRUE;
      /* Check the list. */
      temp = ssh_ecp_param_list_add(param);
      if (temp)
        {
          ssh_ecp_clear_param(param);
          ssh_free(param);
          param = temp;
        }
    }

  param->pc = ctx->pc;

  switch (type)
    {
    case 0:
      /* Parameters. */
      ssh_ecp_param_add_ref(param);
      *ret_context = (void *)param;
      return SSH_CRYPTO_OK;

    case 1:
      /* Public key. */
      if ((pub_key = ssh_malloc(sizeof(*pub_key))) != NULL)
        {
          ssh_ecp_init_public_key(pub_key, param);
          ssh_ecp_set_point(&pub_key->Q, &ctx->qx, &ctx->qy, 1);
          *ret_context = (void *)pub_key;
          return SSH_CRYPTO_OK;
        }
      if (temp == NULL)
        {
          ssh_ecp_clear_param(param);
          ssh_free(param);
        }
      return SSH_CRYPTO_NO_MEMORY;

    case 2:
      /* Private key. */
      if ((prv_key = ssh_malloc(sizeof(*prv_key))) != NULL)
        {
          ssh_ecp_init_private_key(prv_key, param);

          /* Set private key and public key. */
          if (ssh_mprz_cmp_ui(&ctx->k, 0) == 0)
            {
              /* Generate secret key and compute public key from that */
              ssh_mprz_mod_random(&prv_key->k, &prv_key->param->n);
              ssh_ecp_mul(&prv_key->Q, &prv_key->param->P, &prv_key->k,
                          &prv_key->param->E);
            }
          else
            {
              ssh_mprz_set(&prv_key->k, &ctx->k);

              if (ssh_mprz_cmp_ui(&ctx->qx, 0) == 0 &&
                  ssh_mprz_cmp_ui(&ctx->qy, 0) == 0)
                ssh_ecp_mul(&prv_key->Q, &prv_key->param->P, &prv_key->k,
                            &prv_key->param->E);
              else
                ssh_ecp_set_point(&prv_key->Q, &ctx->qx, &ctx->qy, 1);
            }
          *ret_context = (void *)prv_key;
          return SSH_CRYPTO_OK;
        }
      if (temp == NULL)
        {
          ssh_ecp_clear_param(param);
          ssh_free(param);
        }
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_fatal("ssh_ec2n_action_make: undefined structure type.");
  return SSH_CRYPTO_UNSUPPORTED;
}

SshCryptoStatus
ssh_ecp_private_key_action_make(void *context, void **ret_context)
{
  return ssh_ecp_action_make(context, 2, ret_context);
}

SshCryptoStatus
ssh_ecp_public_key_action_make(void *context, void **ret_context)
{
  return ssh_ecp_action_make(context, 1, ret_context);
}

SshCryptoStatus
ssh_ecp_param_action_make(void *context, void **ret_context)
{
  return ssh_ecp_action_make(context, 0, ret_context);
}

/********************** Schemes *************************/

/* DSA Signature Scheme */

SshCryptoStatus
ssh_ecp_dsa_public_key_verify(const void *public_key,
                              const unsigned char *signature,
                              size_t signature_len,
                              SshRGF rgf)
{
  const SshECPPublicKey *pub_key = public_key;
  SshECPPointStruct uP, vQ, PQ;
  SshMPIntegerStruct v, s, r, e, invs, u1, u2;
  size_t len = ssh_mprz_byte_size(&pub_key->param->E.q);
  size_t vlen, digest_len;
  unsigned char *digest;
  SshCryptoStatus status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  if (signature_len & 1)
    return status;

  vlen = signature_len / 2;

  if (vlen > len)
    return status;

  /* Compute the digest. */
  if ((status = ssh_rgf_for_signature(rgf, 8 * len,
                                      &digest, &digest_len)) != SSH_CRYPTO_OK)
    return status;

  status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  ssh_mprz_init(&v);
  ssh_mprz_init(&e);
  ssh_mprz_init(&s);
  ssh_mprz_init(&r);
  ssh_mprz_init(&u1);
  ssh_mprz_init(&u2);
  ssh_mprz_init(&invs);

  /* Elliptic curve points. */
  ssh_ecp_init_point(&uP, &pub_key->param->E);
  ssh_ecp_init_point(&vQ, &pub_key->param->E);
  ssh_ecp_init_point(&PQ, &pub_key->param->E);

  /* Unlinearize and point uncompress if neccessary. */
  ssh_mprz_set_buf(&e, digest, digest_len);
  ssh_mprz_mod(&e, &e, &pub_key->param->n);
  ssh_free(digest);

  /* Unlinearize. */
  ssh_mprz_set_buf(&r, signature, vlen);
  if (ssh_mprz_cmp(&r, &pub_key->param->n) >= 0 ||
      ssh_mprz_cmp_ui(&r, 0) <= 0)
    goto failed;

  ssh_mprz_set_buf(&s, signature + vlen, vlen);
  if (ssh_mprz_cmp(&s, &pub_key->param->n) >= 0 ||
      ssh_mprz_cmp_ui(&s, 0) <= 0)
    goto failed;

  /* Check the signature. */

  /* Inversion succeeds because n is prime. */
  ssh_mprz_mod_invert(&invs, &s, &pub_key->param->n);

  ssh_mprz_mul(&u1, &e, &invs);
  ssh_mprz_mod(&u1, &u1, &pub_key->param->n);

  ssh_mprz_mul(&u2, &r, &invs);
  ssh_mprz_mod(&u2, &u2, &pub_key->param->n);

  ssh_ecp_mul(&uP, &pub_key->param->P, &u1, &pub_key->param->E);
  ssh_ecp_mul(&vQ, &pub_key->Q, &u2, &pub_key->param->E);
  ssh_ecp_add(&PQ, &vQ, &uP, &pub_key->param->E);

  ssh_mprz_mod(&v, &PQ.x, &pub_key->param->n);

  status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
  if (ssh_mprz_cmp(&v, &r) == 0)
    {
      status = SSH_CRYPTO_OK;
    }

failed:

  /* Free temporary variables and points. */
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&u1);
  ssh_mprz_clear(&u2);
  ssh_mprz_clear(&invs);

  ssh_ecp_clear_point(&uP);
  ssh_ecp_clear_point(&vQ);
  ssh_ecp_clear_point(&PQ);

  return status;
}

size_t
ssh_ecp_dsa_private_key_max_signature_input_len(const void *private_key,
                                                SshRGF rgf)
{
  return (size_t)-1;
}

size_t
ssh_ecp_dsa_private_key_max_signature_output_len(const void *private_key,
                                                 SshRGF rgf)
{
  const SshECPPrivateKey *prv_key = private_key;
  size_t len = ssh_mprz_byte_size(&prv_key->param->E.q);
  return len * 2;
}

SshCryptoStatus
ssh_ecp_dsa_private_key_sign(const void *private_key,
                             SshRGF rgf,
                             unsigned char *signature_buffer,
                             size_t ssh_buffer_len,
                             size_t *signature_length_return)
{
  const SshECPPrivateKey *prv_key = private_key;
  SshECPPointStruct kP;
  SshECPStackRandomizer *stack;
  SshCryptoStatus status;
  SshMPIntegerStruct t, k, e, r, dr, invk, s;
  size_t len = ssh_mprz_byte_size(&prv_key->param->E.q);
  unsigned char *digest;
  size_t digest_len;

  if (ssh_buffer_len < len * 2)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  /* Compute the digest. */
  if ((status = ssh_rgf_for_signature(rgf, 8 * len,
                                      &digest, &digest_len)) != SSH_CRYPTO_OK)
    return status;

  ssh_mprz_init(&t);
  ssh_mprz_init(&k);
  ssh_mprz_init(&e);
  ssh_mprz_init(&dr);
  ssh_mprz_init(&invk);
  ssh_mprz_init(&s);
  ssh_mprz_init(&r);

  ssh_ecp_init_point(&kP, &prv_key->param->E);

  /* Linearize and reduce. */
  ssh_mprz_set_buf(&e, digest, digest_len);
  ssh_mprz_mod(&e, &e, &prv_key->param->n);
  ssh_free(digest);

  /* Note that n is prime by our definition. */

retry0:

  stack = (SshECPStackRandomizer *)ssh_cstack_pop(&prv_key->param->stack,
                                                  SSH_ECP_STACK_RANDOMIZER);
  if (!stack)
    {
    retry1:
      /* Find a random number k */
      ssh_mprz_mod_random(&k, &prv_key->param->n);
      if (ssh_mprz_cmp_ui(&k, 0) == 0)
        goto retry1;

      ssh_ecp_mul(&kP, &prv_key->param->P, &k, &prv_key->param->E);
    }
  else
    {
      ssh_mprz_set(&k, &stack->k);
      ssh_ecp_copy_point(&kP, &stack->Q);
      ssh_cstack_free(stack);
    }
  ssh_mprz_mod(&r, &kP.x, &prv_key->param->n);

  /* Just in case. */
  if (ssh_mprz_cmp_ui(&r, 0) == 0)
    goto retry0;

  /* Compute e + dr, where d = private key */
  ssh_mprz_mul(&dr, &r, &prv_key->k);
  ssh_mprz_add(&dr, &e, &dr);
  ssh_mprz_mod(&dr, &dr, &prv_key->param->n);

  /* Because n is prime we know we will find inverse of k. */
  ssh_mprz_mod_invert(&invk, &k, &prv_key->param->n);

  /* s = k^-1(e + dr) mod n, where d = private key. */
  ssh_mprz_mul(&s, &dr, &invk);
  ssh_mprz_mod(&s, &s, &prv_key->param->n);

  if (ssh_mprz_cmp_ui(&s, 0) == 0)
    goto retry0;

  /* Linearize to byte buffer */
  ssh_mprz_get_buf(signature_buffer, len, &r);
  ssh_mprz_get_buf(signature_buffer + len, len, &s);
  *signature_length_return = len * 2;

  ssh_mprz_clear(&t);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&invk);
  ssh_mprz_clear(&dr);
  ssh_mprz_clear(&k);
  ssh_ecp_clear_point(&kP);

  return SSH_CRYPTO_OK;
}

/*********************** Key exchange ****************************/

/* Plain Diffie-Hellman scheme. */

#ifdef SSHDIST_CRYPT_DH

size_t
ssh_ecp_diffie_hellman_exchange_length(const void *parameters)
{
  const SshECPParam *param = parameters;
  if (param->pc)
    return ssh_mprz_byte_size(&param->E.q) + 1;
  return ssh_mprz_byte_size(&param->E.q) * 2;
}

size_t
ssh_ecp_diffie_hellman_shared_secret_length(const void *parameters)
{
  const SshECPParam *param = parameters;

  return ssh_mprz_byte_size(&param->E.q);
}


void ssh_ecp_diffie_hellman_internal_generate(SshECPPoint R,
                                              SshECPParam *param,
                                              SshMPInteger k)
{
  SshECPStackRandomizer *stack_r;
  stack_r = (SshECPStackRandomizer *)ssh_cstack_pop(&param->stack,
                                                    SSH_ECP_STACK_RANDOMIZER);
  if (!stack_r)
    {
    retry1:
      ssh_mprz_mod_random(k, &param->n);
      if (ssh_mprz_cmp_ui(k, 0) == 0)
        goto retry1;
      ssh_ecp_mul(R, &param->P, k, &param->E);
    }
  else
    {
      ssh_ecp_copy_point(R, &stack_r->Q);
      ssh_mprz_set(k, &stack_r->k);
      ssh_cstack_free(stack_r);
    }
}

SshCryptoStatus
ssh_ecp_diffie_hellman_generate(const void *parameters,
                                SshPkGroupDHSecret *secret,
                                unsigned char *exchange,
                                size_t exchange_length,
                                size_t *return_length)
{
  const SshECPParam *param = parameters;
  SshECPPointStruct R;
  SshMPIntegerStruct k;
  unsigned int len = ssh_mprz_byte_size(&param->E.q);

  SSH_DEBUG(SSH_D_LOWOK, ("ECP Diffie-Hellman generate"));

  if (exchange_length < ssh_ecp_diffie_hellman_exchange_length(param))
    return SSH_CRYPTO_DATA_TOO_SHORT;

  ssh_mprz_init(&k);
  ssh_ecp_init_point(&R, &param->E);

  ssh_ecp_diffie_hellman_internal_generate(&R, (SshECPParam *)param,
                                           &k);

  /* Linearize. */
  ssh_mprz_get_buf(exchange, len, &R.x);
  if (param->pc)
    {
      exchange[len] = (unsigned char)(ssh_mprz_get_ui(&R.y) & 0x1);
      *return_length = len + 1;
    }
  else
    {
      ssh_mprz_get_buf(exchange + len, len, &R.y);
      *return_length = len * 2;
    }

  ssh_ecp_clear_point(&R);

  *secret = ssh_mprz_to_dh_secret(&k);

  if (*secret == NULL)
    {
      ssh_mprz_clear(&k);
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_mprz_clear(&k);
  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_ecp_diffie_hellman_final(const void *parameters,
                             SshPkGroupDHSecret dh_secret,
                             const unsigned char *exchange,
                             size_t exchange_length,
                             unsigned char *shared_secret,
                             size_t shared_secret_length,
                             size_t *return_length)
{
  const SshECPParam *param = parameters;
  SshMPIntegerStruct k;
  SshECPPointStruct R, P;
  unsigned int len = ssh_mprz_byte_size(&param->E.q);
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  SSH_DEBUG(SSH_D_LOWOK, ("ECP Diffie-Hellman final"));

  if (exchange_length < ssh_ecp_diffie_hellman_exchange_length(param))
    return SSH_CRYPTO_DATA_TOO_SHORT;

  if (shared_secret_length <
      ssh_ecp_diffie_hellman_shared_secret_length(param))
    return SSH_CRYPTO_DATA_TOO_SHORT;

  ssh_mprz_init(&k);

  ssh_ecp_init_point(&R, &param->E);
  ssh_ecp_init_point(&P, &param->E);

  /* Import the secret. */
  ssh_dh_secret_to_mprz(&k, dh_secret);

  ssh_mprz_set_buf(&R.x, exchange, len);
  if (param->pc)
    {
      if (ssh_ecp_restore_y(&R, &param->E,
                            exchange[len] & 0x1) == FALSE)
        goto failed;
    }
  else
    ssh_mprz_set_buf(&R.y, exchange + len, len);
  /* Point exists. */
  R.z = 1;

  /* Compute R further. */
  ssh_ecp_mul(&P, &R, &k, &param->E);

  /* Linearize. */
  ssh_mprz_get_buf(shared_secret, len, &P.x);
  *return_length = len;

  status = SSH_CRYPTO_OK;

 failed:

  /* Free everything. */
  ssh_pk_group_dh_secret_free(dh_secret);
  ssh_mprz_clear(&k);

  /* Clear memory. */
  ssh_ecp_clear_point(&R);
  ssh_ecp_clear_point(&P);
  return status;
}

#endif /* SSHDIST_CRYPT_DH */
#endif /* SSHDIST_CRYPT_ECP */
/* ecpglue.c */
