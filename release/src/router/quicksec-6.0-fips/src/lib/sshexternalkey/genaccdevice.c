/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshexternalkey.h"
#include "genaccdevicei.h"
#include "genaccprovideri.h"

#ifdef DEBUG_LIGHT
#ifndef SSHDIST_VPNCLIENT
#define ENABLE_EXTERNALKEY_DUMMY_PROVIDER 1
#endif /* SSHDIST_VPNCLIENT */
#endif /* DEBUG_LIGHT */









#ifdef ENABLE_EXTERNALKEY_DUMMY_PROVIDER
#include "dummyacc.h"
#endif /* ENABLE_EXTERNALKEY_DUMMY_PROVIDER */

#ifdef HAVE_THREADS
#include "softacc.h"
#endif /* HAVE_THREADS */

#ifdef SSHDIST_IPSEC_HWACCEL_OCF
#ifdef ENABLE_EXTERNALKEY_OCF_SP
#include "ocf_acc.h"
#endif /* ENABLE_EXTERNALKEY_OCF_SP */
#endif /* SSHDIST_IPSEC_HWACCEL_OCF */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_EXTERNALKEY_CAVIUM_OCTEON
#include "octeon_acc.h"
#endif /* ENABLE_EXTERNALKEY_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#define SSH_DEBUG_MODULE "SshEKGenAccDevice"

SSH_DATA_INITONCE
static SshAccDeviceDef ssh_acc_device_def[SSH_ACC_MAX_DEVICES] =
{
#ifdef SSHDIST_IPSEC_HWACCEL_OCF
#ifdef ENABLE_EXTERNALKEY_OCF_SP
  &ssh_acc_dev_ocf_ops,
#endif /* ENABLE_EXTERNALKEY_OCF_SP */
#endif /* SSHDIST_IPSEC_HWACCEL_OCF */
#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_EXTERNALKEY_CAVIUM_OCTEON
  &ssh_acc_dev_octeon_ops,
#endif /* ENABLE_EXTERNALKEY_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#ifdef HAVE_THREADS
  &ssh_acc_dev_soft_ops,
#endif /* HAVE_THREADS */

#ifdef ENABLE_EXTERNALKEY_DUMMY_PROVIDER
  /* Keep this last in the list. */
  &ssh_acc_dev_dummy_ops,
#endif /* ENABLE_EXTERNALKEY_DUMMY_PROVIDER */

   NULL, /* ... continued to the end. */
};


/************************** Modexp operation context ************************/

/* Modexp operation context. */
typedef struct SshAccDeviceModExpContextRec *SshAccDeviceModExpContext;

struct SshAccDeviceModExpContextRec
{
  SshAccDeviceModExpContext next;

  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  unsigned char *data;
  size_t data_size;
  size_t data_len;

  SshAccDeviceReplyCB callback;
  void *context;

  SshAccDevice device;

  unsigned int op_registered : 1;
};

static void
ssh_acc_device_modexp_op_freelist_put(SshAccDeviceModExpContext modexp_ctx)
{
  if (modexp_ctx->device->modexp_op_freelist_length <
      SSH_ACC_MODEXP_OP_FREELIST_SIZE)
    {
      modexp_ctx->device->modexp_op_freelist_length++;

      modexp_ctx->next =
        (SshAccDeviceModExpContext) modexp_ctx->device->modexp_op_freelist;
      modexp_ctx->device->modexp_op_freelist = modexp_ctx;
    }
  else
    {
      ssh_free(modexp_ctx->data);
      ssh_free(modexp_ctx);
    }
}

static SshAccDeviceModExpContext
ssh_acc_device_modexp_op_freelist_get(SshAccDevice device)
{
  SshAccDeviceModExpContext modexp_ctx;

  if (device->modexp_op_freelist != NULL)
    {
      SSH_ASSERT(device->modexp_op_freelist_length > 0);
      device->modexp_op_freelist_length--;

      modexp_ctx = (SshAccDeviceModExpContext) device->modexp_op_freelist;
      device->modexp_op_freelist = modexp_ctx->next;

      return modexp_ctx;
    }
  else
    return NULL;
}

/************************ Rsa crt operation context *************************/

typedef struct SshAccDeviceCRTContextRec *SshAccDeviceCRTContext;

struct SshAccDeviceCRTContextRec
{
  SshAccDeviceCRTContext next;

  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  unsigned char *data;
  size_t data_len;
  size_t data_size;

  SshAccDeviceReplyCB callback;
  void *context;

  SshAccDevice device;

  unsigned int op_registered : 1;
};

static void
ssh_acc_device_crt_op_freelist_put(SshAccDeviceCRTContext crt_ctx)
{
  if (crt_ctx->device->crt_op_freelist_length < SSH_ACC_CRT_OP_FREELIST_SIZE)
    {
      crt_ctx->device->crt_op_freelist_length++;

      crt_ctx->next =
        (SshAccDeviceCRTContext) crt_ctx->device->crt_op_freelist;
      crt_ctx->device->crt_op_freelist = crt_ctx;
    }
  else
    {
      ssh_free(crt_ctx->data);
      ssh_free(crt_ctx);
    }
}

static SshAccDeviceCRTContext
ssh_acc_device_crt_op_freelist_get(SshAccDevice device)
{
  SshAccDeviceCRTContext crt_ctx;

  if (device->crt_op_freelist != NULL)
    {
      SSH_ASSERT(device->crt_op_freelist_length > 0);
      device->crt_op_freelist_length--;

      crt_ctx = (SshAccDeviceCRTContext) device->crt_op_freelist;
      device->crt_op_freelist = crt_ctx->next;

      return crt_ctx;
    }
  else
    return NULL;
}

/************************** Device init / uninit *****************************/

/* Register 'device_def' to the list of supported devices,
   ssh_acc_device_def[] */
SshAccDeviceStatus
ssh_acc_register_device(SshAccDeviceDef device_def)
{
  int i;

  if (device_def == NULL)
    return SSH_ACC_DEVICE_FAIL;

  for (i = 0; i < SSH_ACC_MAX_DEVICES; i++)
    {
      if (ssh_acc_device_def[i] == NULL)
        {
          /* Empty slot detected. */
          ssh_acc_device_def[i] = device_def;
          return SSH_ACC_DEVICE_OK;
        }

      if (ssh_acc_device_def[i] == device_def)
        {
          /* Same device_def added already. */
          return SSH_ACC_DEVICE_OK;
        }
    }

  SSH_DEBUG(SSH_D_FAIL,("Cannot register the device '%s'", device_def->name));
  return SSH_ACC_DEVICE_SLOTS_EXHAUSTED;
}


/* Allocate and initialize a device. */
SshAccDeviceStatus
ssh_acc_device_allocate(const char *name,
                        const char *init_info,
                        void *extra_args,
                        Boolean wait_for_message,
                        SshAccDevice *device)
{
  SshAccDevice dev;
  int i;

  *device = NULL;

  if (name == NULL)
    return SSH_ACC_DEVICE_FAIL;

  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    {
      if (strcmp(ssh_acc_device_def[i]->name, name))
        continue;

      dev = ssh_calloc(1, sizeof(*dev));
      if (dev == NULL)
        return SSH_ACC_DEVICE_NO_MEMORY;

      if (init_info)
        {
          dev->device_info = ssh_strdup(init_info);
          if (dev->device_info == NULL)
            {
              ssh_free(dev);
              return SSH_ACC_DEVICE_NO_MEMORY;
            }
        }

      dev->ops = ssh_acc_device_def[i];
      dev->is_initialized = FALSE;
      dev->max_modexp_size = dev->ops->max_modexp_size;

      /* Delay initialization until the message is recived */
      if (wait_for_message)
        {
          *device = dev;
          return SSH_ACC_DEVICE_OK;
        }

      if (dev->ops->init(init_info, extra_args, &dev->context))
        {
          dev->is_initialized = TRUE;
          *device = dev;
          return SSH_ACC_DEVICE_OK;
        }
      else
        {
          if (dev->device_info)
            ssh_free(dev->device_info);
          ssh_free(dev);
          return SSH_ACC_DEVICE_FAIL;
        }
    }
  return SSH_ACC_DEVICE_UNSUPPORTED;
}

SshAccDeviceStatus
ssh_acc_device_initialize_from_message(SshAccDevice device, void *message)
{
  SshAccDeviceStatus status;

  /* Only initialize once. */
  if (!device || device->is_initialized)
    return SSH_ACC_DEVICE_FAIL;

  status = device->ops->init(device->device_info, message,
                             &device->context);

  if (status == SSH_ACC_DEVICE_OK)
    device->is_initialized = TRUE;

  return status;
}


/* Uninitialize and free a device. */
void ssh_acc_device_free(SshAccDevice device)
{
  SshAccDeviceModExpContext modexp_ctx;
  SshAccDeviceCRTContext crt_ctx;

  if (device)
    {
      /* Free modexp op contexts from freelist. */
      do {
        modexp_ctx = ssh_acc_device_modexp_op_freelist_get(device);
        if (modexp_ctx != NULL)
          {
            ssh_free(modexp_ctx->data);
            ssh_free(modexp_ctx);
          }
      } while (modexp_ctx != NULL);

      /* Free crt op contexts from freelist. */
      do {
        crt_ctx = ssh_acc_device_crt_op_freelist_get(device);
        if (crt_ctx != NULL)
          {
            ssh_free(crt_ctx->data);
            ssh_free(crt_ctx);
          }
      } while (crt_ctx != NULL);

      if (device->is_initialized)
        device->ops->uninit(device->context);

      ssh_free(device->device_info);
      ssh_free(device);
    }
}


/********** The Device Modular Exponentation Operation. ************/

void ssh_acc_device_modexp_op_abort(void *context)
{
  SshAccDeviceModExpContext modexp_ctx = context;

  /* Abort accelerator device sub operation. */
  ssh_operation_abort(modexp_ctx->sub_op);
  modexp_ctx->sub_op = NULL;

  modexp_ctx->op_registered = 0;

  /* Return modexp context to freelist. */
  ssh_acc_device_modexp_op_freelist_put(modexp_ctx);
}

void ssh_acc_device_modexp_op_done(SshCryptoStatus status,
                                   const unsigned char *data,
                                   size_t data_len,
                                   void *context)
{
  SshAccDeviceModExpContext modexp_ctx = context;
  SshMPIntegerStruct base, exponent, modulus, result;
  unsigned char *ret = NULL;
  size_t ret_len;

  modexp_ctx->sub_op = NULL;

  if (status == SSH_CRYPTO_OK)
    {
      /* Pass the result buffer to on to the operation invoker. */
      (*modexp_ctx->callback)(SSH_CRYPTO_OK, data, data_len,
                              modexp_ctx->context);
    }
  else
    {
      /* The accelerated operation has failed, instead perform the operation
         in software. */
      SSH_DEBUG(SSH_D_FAIL, ("Accelerated modexp operation has failed, "
                             "now performing the operation in software"));

      ssh_mprz_init(&base);
      ssh_mprz_init(&exponent);
      ssh_mprz_init(&modulus);
      ssh_mprz_init(&result);

      /* Decode the data buffer to extract the original parameters */
      if (ssh_decode_array(modexp_ctx->data, modexp_ctx->data_len,
                           SSH_DECODE_SPECIAL_NOALLOC
                           (ssh_mprz_decode_uint32_str_noalloc, &base),
                           SSH_DECODE_SPECIAL_NOALLOC
                           (ssh_mprz_decode_uint32_str_noalloc, &exponent),
                           SSH_DECODE_SPECIAL_NOALLOC
                           (ssh_mprz_decode_uint32_str_noalloc, &modulus),
                           SSH_FORMAT_END) != modexp_ctx->data_len)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Decode failed"));
          (*modexp_ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0,
                                  modexp_ctx->context);
          goto out;
        }

      ret_len = ssh_mprz_byte_size(&modulus);

      /* Reuse argument buffer for result. */
      if (ret_len <= modexp_ctx->data_size)
        {
          ret = modexp_ctx->data;
        }
      else
        {
          /* Allocate result buffer. */
          ret = ssh_malloc(ret_len);
          if (ret == NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Failed to allocate memory for result buffer"));
              (*modexp_ctx->callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0,
                                      modexp_ctx->context);
              goto out;
            }
        }

      /* Calculate modexp in software. Note that ssh_mprz_powm() checks
         that the arguments are not nan, thus this check can be omitted
         here although decoding the arguments from the linearized array
         may produce nan mp-integers, if an internal error occurs. */
      ssh_mprz_powm(&result, &base, &exponent, &modulus);

      /* Extract and return result. */
      if (ssh_mprz_get_buf(ret, ret_len, &result))
        {
          (*modexp_ctx->callback)(SSH_CRYPTO_OK, ret, ret_len,
                                  modexp_ctx->context);
        }
      else
        {
          (*modexp_ctx->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0,
                                  modexp_ctx->context);
        }

    out:
      /* Unitialize mp-integers and free result buffer. */
      ssh_mprz_clear(&base);
      ssh_mprz_clear(&exponent);
      ssh_mprz_clear(&modulus);
      ssh_mprz_clear(&result);

      if (ret != NULL && ret != modexp_ctx->data)
        ssh_free(ret);
    }

  /* Unregister operation handle. */
  if (modexp_ctx->op_registered)
    ssh_operation_unregister_no_free(modexp_ctx->op);
  modexp_ctx->op_registered = 0;

  /* Return modexp context to freelist. */
  ssh_acc_device_modexp_op_freelist_put(modexp_ctx);
}


/* The Modular Exponentation operation. */
SshOperationHandle
ssh_acc_device_modexp_op(SshAccDevice device,
                         SshMPIntegerConst base,
                         SshMPIntegerConst exponent,
                         SshMPIntegerConst modulus,
                         SshAccDeviceReplyCB callback,
                         void *reply_context)
{
  SshMPIntegerStruct result;
  size_t b_len, e_len, mod_len;
  SshAccDeviceModExpContext modexp_ctx;
  SshOperationHandle sub_op;

  if (device == NULL || !device->is_initialized)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Device %p is not initialized", device));
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  /* Is acceleration supported for this modulus size? */
  mod_len = ssh_mprz_byte_size(modulus);
  if ((mod_len * 8) > device->max_modexp_size)
    {
      unsigned char *ret;
      size_t ret_len;

      SSH_DEBUG(SSH_D_FAIL, ("Accelerated modexp operation unsupported for "
                             "this modulus size, doing modexp in software."));

      /* Allocate buffer for result. */
      ret_len = mod_len;
      ret = ssh_calloc(1, ret_len);
      if (ret == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to allocate memory for result buffer"));
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }

      /* Calculate modexp in software. */
      ssh_mprz_init(&result);
      ssh_mprz_powm(&result, base, exponent, modulus);

      if (ssh_mprz_get_buf(ret, ret_len, &result))
        {
          (*callback)(SSH_CRYPTO_OK, ret, ret_len, reply_context);
        }
      else
        {
          (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
        }

      ssh_mprz_clear(&result);

      ssh_free(ret);
      return NULL;
    }

  /* Get a modexp operation context. */
  modexp_ctx = ssh_acc_device_modexp_op_freelist_get(device);
  if (modexp_ctx == NULL)
    {
      /* Allocate a new modexp context */
      modexp_ctx = ssh_calloc(1, sizeof(*modexp_ctx));
      if (modexp_ctx == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to allocate memory for modexp operation "
                     "context"));
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
      modexp_ctx->device = device;
    }

  /* Check modexp context workspace size and reallocate is it too small
     for the parameters. */
  b_len = ssh_mprz_byte_size(base);
  e_len = ssh_mprz_byte_size(exponent);
  if (modexp_ctx->data_size < (b_len + e_len + mod_len + 16))
    {
      ssh_free(modexp_ctx->data);
      modexp_ctx->data_size = (b_len + e_len + mod_len + 16);
      modexp_ctx->data = ssh_malloc(modexp_ctx->data_size);
      if (modexp_ctx->data == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to allocate memory for modexp operation "
                     "workspace (%d bytes)",
                     (int) modexp_ctx->data_size));
          modexp_ctx->data_size = 0;
          ssh_acc_device_modexp_op_freelist_put(modexp_ctx);
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
    }

  /* Encode the data. */
  modexp_ctx->data_len =
    ssh_encode_array(modexp_ctx->data, modexp_ctx->data_size,
                     SSH_ENCODE_SPECIAL
                     (ssh_mprz_encode_uint32_str, base),
                     SSH_ENCODE_SPECIAL
                     (ssh_mprz_encode_uint32_str, exponent),
                     SSH_ENCODE_SPECIAL
                     (ssh_mprz_encode_uint32_str, modulus),
                     SSH_FORMAT_END);

  if (modexp_ctx->data_len == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Encode failed"));
      ssh_acc_device_modexp_op_freelist_put(modexp_ctx);
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  modexp_ctx->callback = callback;
  modexp_ctx->context = reply_context;

  ssh_operation_register_no_alloc(modexp_ctx->op,
                                  ssh_acc_device_modexp_op_abort,
                                  modexp_ctx);
  modexp_ctx->op_registered = 1;

  sub_op = device->ops->execute(device->context,
                                SSH_ACC_DEVICE_OP_MODEXP,
                                modexp_ctx->data,
                                modexp_ctx->data_len,
                                ssh_acc_device_modexp_op_done,
                                modexp_ctx);
  if (sub_op)
    {
      modexp_ctx->sub_op = sub_op;
      return modexp_ctx->op;
    }

  return NULL;
}

/************ RSA CRT operation. ************/

void ssh_acc_device_rsa_crt_op_abort(void *context)
{
  SshAccDeviceCRTContext crt_ctx = context;

  /* Abort accelerator device sub operation. */
  ssh_operation_abort(crt_ctx->sub_op);
  crt_ctx->sub_op = NULL;

  crt_ctx->op_registered = 0;

  /* Return crt context to freelist. */
  ssh_acc_device_crt_op_freelist_put(crt_ctx);
}

void ssh_acc_device_rsa_crt_op_done(SshCryptoStatus status,
                                   const unsigned char *data,
                                   size_t data_len,
                                   void *context)
{
  SshAccDeviceCRTContext crt_ctx = context;

  crt_ctx->sub_op = NULL;

  if (status == SSH_CRYPTO_OK)
    (*crt_ctx->callback)(SSH_CRYPTO_OK, data, data_len, crt_ctx->context);
  else
    (*crt_ctx->callback)(status, NULL, 0, crt_ctx->context);

  /* Unregister operation handle. */
  if (crt_ctx->op_registered)
    ssh_operation_unregister_no_free(crt_ctx->op);
  crt_ctx->op_registered = 0;

  /* Return crt context to freelist. */
  ssh_acc_device_crt_op_freelist_put(crt_ctx);
}

SshOperationHandle
ssh_acc_device_rsa_crt_op(SshAccDevice device,
                          SshMPIntegerConst input,
                          SshMPIntegerConst P,
                          SshMPIntegerConst Q,
                          SshMPIntegerConst DP,
                          SshMPIntegerConst DQ,
                          SshMPIntegerConst U,
                          SshAccDeviceReplyCB callback,
                          void *reply_context)
{
  SshOperationHandle sub_op;
  SshAccDeviceCRTContext crt_ctx;
  size_t input_len, p_len, q_len, dp_len, dq_len, u_len;

  if (!device || !device->is_initialized || !device->rsa_crt)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Device %p is not %s",
                                   device,
                                   (device != NULL && !device->rsa_crt ?
                                    "capable to do RSA CRT" : "initialized")));
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  crt_ctx = ssh_acc_device_crt_op_freelist_get(device);
  if (crt_ctx == NULL)
    {
      /* Allocate a new crt context */
      crt_ctx = ssh_calloc(1, sizeof(*crt_ctx));
      if (crt_ctx == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to allocate memory for crt operation context"));
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
      crt_ctx->device = device;
    }

  input_len = ssh_mprz_byte_size(input);
  p_len = ssh_mprz_byte_size(P);
  q_len = ssh_mprz_byte_size(Q);
  dp_len = ssh_mprz_byte_size(DP);
  dq_len = ssh_mprz_byte_size(DQ);
  u_len = ssh_mprz_byte_size(U);

  if (crt_ctx->data_size <
      (input_len + p_len + q_len + dp_len + dq_len + u_len + 28))
    {
      ssh_free(crt_ctx->data);
      crt_ctx->data_size =
        (input_len + p_len + q_len + dp_len + dq_len + u_len + 28);
      crt_ctx->data = ssh_malloc(crt_ctx->data_size);
      if (crt_ctx->data == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to allocate memory for crt operation context "
                     "workspace (%d bytes)", (int) crt_ctx->data_size));
          crt_ctx->data_size = 0;
          ssh_acc_device_crt_op_freelist_put(crt_ctx);
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
    }

  /* Encode the data. */
  crt_ctx->data_len =
    ssh_encode_array(crt_ctx->data, crt_ctx->data_size,
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, input),
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, P),
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, Q),
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, DP),
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, DQ),
                     SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, U),
                     SSH_FORMAT_END);
  if (crt_ctx->data_len == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Encode failed"));
      ssh_acc_device_crt_op_freelist_put(crt_ctx);
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  crt_ctx->callback = callback;
  crt_ctx->context = reply_context;

  ssh_operation_register_no_alloc(crt_ctx->op,
                                  ssh_acc_device_rsa_crt_op_abort,
                                  crt_ctx);
  crt_ctx->op_registered = 1;

  sub_op = device->ops->execute(device->context,
                                SSH_ACC_DEVICE_OP_RSA_CRT,
                                crt_ctx->data,
                                crt_ctx->data_len,
                                ssh_acc_device_rsa_crt_op_done,
                                crt_ctx);

  if (sub_op)
    {
      crt_ctx->sub_op = sub_op;
      return crt_ctx->op;
    }

  return NULL;
}

/************ Get Random Bytes From The Device. ************/

SshOperationHandle
ssh_acc_device_get_random_bytes(SshAccDevice device,
                                SshUInt32 bytes_requested,
                                SshAccDeviceReplyCB callback,
                                void *reply_context)
{
  unsigned char buf[4];

  if (!device || !device->is_initialized)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDOK,("Calling the get random bytes function for %d bytes",
                         (int) bytes_requested));

  /* Encode the requested bytes to the operation buffer */
  ssh_encode_array(buf, 4,
                   SSH_ENCODE_UINT32(bytes_requested),
                   SSH_FORMAT_END);

  return device->ops->execute(device->context,
                              SSH_ACC_DEVICE_OP_GET_RANDOM,
                              buf, 4,
                              callback,
                              reply_context);
}



/*************************************************************************/

/* Returns a comma-separated list of supported device names.
   The caller must free the returned value with ssh_free(). */
char *
ssh_acc_device_get_supported(void)
{
  int i;
  size_t list_len, offset;
  unsigned char *list, *tmp;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    {
      size_t newsize;
      newsize = offset + 1 + !!offset +
        strlen(ssh_acc_device_def[i]->name);

      if (list_len < newsize)
        {
          newsize *= 2;

          tmp = ssh_realloc(list, list_len, newsize);
          if (tmp == NULL)
            {
              ssh_free(list);
              return NULL;
            }
          list = tmp;
          list_len = newsize;
        }

      offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                             offset ? "," : "",
                             ssh_acc_device_def[i]->name);
    }

  return ssh_sstr(list);
}

Boolean
ssh_acc_device_supported(const char *name)
{
  unsigned int i;

  if (name == NULL)
    return FALSE;

  for (i = 0; ssh_acc_device_def[i] != NULL; i++)
    {
      if (strcmp(ssh_acc_device_def[i]->name, name) == 0)
        return TRUE;
    }

  return FALSE;
}
