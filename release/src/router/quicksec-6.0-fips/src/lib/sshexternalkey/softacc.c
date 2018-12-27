/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Example file which configures an accelerated device. The 'accelerated'
   operations are performed here in software. This implementation uses
   threads to offload modexp operations to separate threads.

   This accelerator is only enabled if thread support is present.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshoperation.h"
#include "sshthreadedmbox.h"

#include "sshencode.h"
#include "sshcrypt.h"
#include "genaccdevicei.h"
#include "genaccprov.h"

#define SSH_DEBUG_MODULE "SshEKSoftAcc"

#define SSH_SOFT_ACCEL_MAX_THREADS 32

typedef struct SoftAccelRec
{
  SshThreadedMbox mbox;
  SshUInt8 num_threads;
} *SoftAccel;

/* Device initialization. */
Boolean ssh_soft_acc_init(const char *initialization_info,
                          void *extra_args,
                          void **device_context)
{
#ifndef HAVE_THREADS
  return FALSE;
#else /*  HAVE_THREADS */

  SoftAccel accel;
  int num_threads = SSH_SOFT_ACCEL_MAX_THREADS;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Have called the soft accelerator init function"));

  accel = ssh_calloc(1, sizeof(*accel));
  if (accel == NULL)
    return FALSE;

  if (initialization_info && !strncmp(initialization_info,
                                      "num-threads=",
                                      strlen("num-threads=")))
    {
      num_threads = atoi(initialization_info + strlen("num-threads="));
      if (num_threads < 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid argument value 'num-threads=%d'",
                                 num_threads));
          ssh_free(accel);
          return FALSE;
        }
      else if (num_threads > SSH_SOFT_ACCEL_MAX_THREADS)
        num_threads = SSH_SOFT_ACCEL_MAX_THREADS;
    }
  accel->num_threads = num_threads;

  SSH_DEBUG(SSH_D_HIGHOK, ("Soft accelerator using %u threads", num_threads));

  accel->mbox = ssh_threaded_mbox_create(accel->num_threads);
  if (accel->mbox == NULL)
    {
      ssh_free(accel);
      return FALSE;
    }

  *device_context = accel;
  return TRUE;
#endif /*  HAVE_THREADS */
}

void ssh_soft_acc_uninit(void *device_context)
{
  SoftAccel accel = device_context;

  if (accel->mbox != NULL)
    ssh_threaded_mbox_destroy(accel->mbox);

  ssh_free(accel);
  SSH_DEBUG(SSH_D_LOWSTART, ("Have uninitialized the soft accelerator"));
}


/************************************************************************/

typedef struct SoftModexpCtxRec
{
  SoftAccel accel;

  SshMPIntegerStruct base;
  SshMPIntegerStruct exponent;
  SshMPIntegerStruct modulus;

  SshCryptoStatus status;
  SshAccDeviceReplyCB callback;
  void *reply_context;

  SshOperationHandleStruct op[1];
  size_t buf_len;

  unsigned int aborted : 1;
  unsigned int op_registered : 1;

  /* Workspace buffer follows the context structure. */
  unsigned char buf[0];
} *SoftModexpCtx;

static void soft_acc_modexp_abort(void *context)
{
  SoftModexpCtx ctx = context;
  ctx->aborted = 1;
}

static void soft_acc_modexp_completion(void *context)
{
  SoftModexpCtx ctx = context;

  SSH_DEBUG(SSH_D_LOWOK,("In the modexp completion"));

  if (!ctx->aborted)
    {
      (*ctx->callback)(ctx->status, ctx->buf, ctx->buf_len,
                       ctx->reply_context);

      if (ctx->op_registered)
        ssh_operation_unregister(ctx->op);
    }

  ssh_mprz_clear(&ctx->base);
  ssh_mprz_clear(&ctx->exponent);
  ssh_mprz_clear(&ctx->modulus);

  ssh_free(ctx);
}

static void soft_acc_modexp_thread_cb(void *context)
{
  SoftModexpCtx ctx = context;
  SshMPIntegerStruct ret;

  /* Do the math operation. Note that ssh_mprz_powm() checks that
     the arguments are not nan mp-integers. Thus any memory allocation
     failures that occured during decoding of linearized parameters are
     found here. */
  ssh_mprz_init(&ret);
  ssh_mprz_powm(&ret, &ctx->base, &ctx->exponent, &ctx->modulus);

  /* Linearize the MP integer to the buffer. ssh_mprz_get_buf() returns
     zero if modexp result is nan. Thus this does not need to be tested
     explicitly. */
  if (ssh_mprz_get_buf(ctx->buf, ctx->buf_len, &ret))
    {
      ctx->status = SSH_CRYPTO_OK;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Ctx operation failed"));
      ctx->status = SSH_CRYPTO_OPERATION_FAILED;
    }
  ssh_mprz_clear(&ret);

  /* Pass the message back to the event loop */
  SSH_DEBUG(SSH_D_LOWOK,("In the thread message handler, passing control "
                         "back to eloop"));





  if (!ssh_threaded_mbox_send_to_eloop(ctx->accel->mbox,
                                       soft_acc_modexp_completion, ctx))
    {
      ssh_mprz_clear(&ctx->base);
      ssh_mprz_clear(&ctx->exponent);
      ssh_mprz_clear(&ctx->modulus);
      ssh_free(ctx);
    }
}

SshOperationHandle ssh_soft_acc_modexp(void *device_context,
                                       SshAccDeviceOperationId op_id,
                                       const unsigned char *data,
                                       size_t data_len,
                                       SshAccDeviceReplyCB callback,
                                       void *reply_context)
{
  SoftAccel accel = device_context;
  SoftModexpCtx modexp;
  unsigned char *b, *e, *m;
  size_t b_len, e_len, mod_len;

  /* Decode the data buffer to extract the MP Integers */
  if (ssh_decode_array(data, data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&b, &b_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&e, &e_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&m, &mod_len),
                       SSH_FORMAT_END) != data_len)
    {
      (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  modexp = ssh_malloc(sizeof(*modexp) + mod_len);
  if (modexp == NULL)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Initialize the MP Integers. */
  ssh_mprz_init(&modexp->base);
  ssh_mprz_init(&modexp->exponent);
  ssh_mprz_init(&modexp->modulus);

  ssh_mprz_set_buf(&modexp->base, b, b_len);
  ssh_mprz_set_buf(&modexp->exponent, e, e_len);
  ssh_mprz_set_buf(&modexp->modulus, m, mod_len);

  modexp->buf_len = mod_len;
  modexp->accel = accel;
  modexp->reply_context = reply_context;
  modexp->callback = callback;
  modexp->aborted = 0;
  modexp->op_registered = 0;

  /* If num_threads is zero, then calls via the threaded mbox are
     synchronous. Therefore we do not need to register and return
     any operation handles. */
  if (accel->num_threads > 0)
    {
      ssh_operation_register_no_alloc(modexp->op, soft_acc_modexp_abort,
                                      modexp);
      modexp->op_registered = 1;
    }

  if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
                                        soft_acc_modexp_thread_cb,
                                        modexp))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot send mbox operation to thread"));
      goto error;
    }

  if (accel->num_threads > 0)
    return modexp->op;
  else
    return NULL;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Soft accelerator modexp operation failed"));

  if (modexp != NULL)
    {
      if (modexp->op_registered)
        ssh_operation_unregister(modexp->op);

      ssh_mprz_clear(&modexp->base);
      ssh_mprz_clear(&modexp->exponent);
      ssh_mprz_clear(&modexp->modulus);

      ssh_free(modexp);
    }

  (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
  return NULL;
}

/* The soft operation execute function. This is the entry point to
   the accelerator, when it is requested an operation. */
SshOperationHandle ssh_soft_acc_execute(void *device_context,
                                        SshAccDeviceOperationId operation_id,
                                        const unsigned char *data,
                                        size_t data_len,
                                        SshAccDeviceReplyCB callback,
                                        void *context)
{
  switch(operation_id)
    {
    case SSH_ACC_DEVICE_OP_MODEXP:
      return ssh_soft_acc_modexp(device_context, operation_id, data, data_len,
                                 callback, context);

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Unsupported operation request in soft accelerator: %d",
                 operation_id));
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
      return NULL;
    }
}

/* Device configuration. */
struct SshAccDeviceDefRec ssh_acc_dev_soft_ops =
{
  "soft",
  16384,
  ssh_soft_acc_init,
  ssh_soft_acc_uninit,
  ssh_soft_acc_execute
};
