/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "genaccdevicei.h"
#include "genaccprov.h"

#define SSH_DEBUG_MODULE "SshEKOcfAcc"

#ifdef ENABLE_EXTERNALKEY_OCF_SP

typedef struct SshOcfCtxRec
{
  SshAsyncOpCtx asyncop;
} *SshOcfCtx;


/* Just pass the extra_args pointer to the allocated context. */
Boolean
ssh_ocf_provider_init(const char *initialization_info,
                      void *extra_args,
                      void **device_context)
{
  SshOcfCtx ocf;

  *device_context = NULL;

  if (extra_args == NULL)
    return FALSE;
  if ((ocf = ssh_calloc(1, sizeof(*ocf))) == NULL)
    return FALSE;

  ocf->asyncop = (SshAsyncOpCtx) extra_args;
  *device_context = ocf;

  return TRUE;
}

/* The device uninitializion function. */
void ssh_ocf_provider_uninit(void *device_context)
{
  SshOcfCtx ocf = device_context;

  ssh_free(ocf);
}



typedef struct OcfOperationContextRec {
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;
  SshAccDeviceReplyCB callback;
  void *context;
} *OcfOperationContext;


void ssh_ocf_operation_abort(void *context)
{
  OcfOperationContext ctx = context;

  ssh_operation_abort(ctx->sub_op);
  ssh_free(ctx);
}

void ssh_ocf_operation_free(void *context)
{
  OcfOperationContext ctx = context;

  ssh_operation_unregister(ctx->op);
  ssh_ocf_operation_abort(ctx);
}

static
SshCryptoStatus asyncop_result_to_crypto_status(SshAsyncOpResult result)
{

  switch(result)
    {
    case SSH_ASYNC_OP_SUCCESS:
      return SSH_CRYPTO_OK;
    case SSH_ASYNC_OP_ERROR_MEMORY:
      return SSH_CRYPTO_NO_MEMORY;
    case SSH_ASYNC_OP_ERROR_OPERATION_UNKNOWN:
      return SSH_CRYPTO_UNSUPPORTED;
    case SSH_ASYNC_OP_ERROR_OTHER:
      return SSH_CRYPTO_OPERATION_FAILED;
    default:
      return SSH_CRYPTO_OPERATION_FAILED;
    }
}

void ssh_ocf_operation_done(SshAsyncOpResult result,
                            const unsigned char *data,
                            size_t data_len,
                            void *context)
{
  SshCryptoStatus crypto_status;
  OcfOperationContext ctx = context;

  ctx->sub_op = NULL;

  /* convert the async op status to a crypto status */
  crypto_status = asyncop_result_to_crypto_status(result);

  /* No array decoding is needed. */
  (*ctx->callback)(crypto_status, data, data_len, ctx->context);

  ssh_ocf_operation_free(ctx);
}

SshOperationHandle
ssh_ocf_provider_execute(void *device_context,
                         SshAccDeviceOperationId op_id,
                         const unsigned char *input_data,
                         size_t input_data_len,
                         SshAccDeviceReplyCB callback,
                         void *reply_context)
{
  SshOcfCtx ocf = device_context;
  OcfOperationContext ctx;
  SshOperationHandle sub_op;
  SshUInt32 asyncop_id;

  /* Get the asyncop procedure id. */
  if (op_id == SSH_ACC_DEVICE_OP_MODEXP)
    asyncop_id = SSH_ASYNCOP_MODP;
  else if (op_id == SSH_ACC_DEVICE_OP_GET_RANDOM)
    {
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
      return NULL;
    }
  else
    {
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
      return NULL;
    }

  /* allocate the modexp context */
  if ((ctx = ssh_calloc(1, sizeof(*ctx))) != NULL)
    {
      ctx->callback = callback;
      ctx->context = reply_context;
      ctx->sub_op = NULL;
    }
  else
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  ssh_operation_register_no_alloc(ctx->op, ssh_ocf_operation_abort, ctx);

  sub_op = ssh_async_op_execute(ocf->asyncop,
                                asyncop_id,
                                input_data,
                                input_data_len,
                                ssh_ocf_operation_done,
                                ctx);

  if (sub_op)
    {
      ctx->sub_op = sub_op;
      return ctx->op;
    }

  return NULL;
}


/* The ProviderOps structure. */
struct SshAccDeviceDefRec ssh_acc_dev_ocf_ops =
{
  "ocf",
  2048,
  ssh_ocf_provider_init,
  ssh_ocf_provider_uninit,
  ssh_ocf_provider_execute
};

#endif /* ENABLE_EXTERNALKEY_OCF_SP */
