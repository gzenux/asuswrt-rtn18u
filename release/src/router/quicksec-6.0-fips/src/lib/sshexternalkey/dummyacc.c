/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Example file which configures an accelerated device. The 'accelerated'
   operations are performed here in software.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"
#include "sshoperation.h"
#include "sshgetput.h"
#include "sshthreadedmbox.h"

#include "sshencode.h"
#include "sshcrypt.h"
#include "genaccdevicei.h"
#include "genaccprov.h"

#define SSH_DEBUG_MODULE "DUMMY_ACC"

#define SSH_DUMMY_ACCEL_MAX_THREADS 32

typedef enum
{
  /* Asynchronous software */
  DUMMY_ACCEL_ASYNC,
  /* Multi-threaded software */
  DUMMY_ACCEL_THREADED,
  /* Synchronous no-op */
  DUMMY_ACCEL_NO_OP_SYNC,
  /* Asynchronous no-op */
  DUMMY_ACCEL_NO_OP_ASYNC,
} DummyAccelType;

typedef struct DummyAccelRec
{
  DummyAccelType type;
  SshThreadedMbox mbox;

} *DummyAccel;



/* Device initialisation. */
Boolean ssh_dummy_init(const char *initialization_info,
                       void *extra_args,
                       void **device_context)
{
  DummyAccel accel;
  SshInt32 max_threads;

  /* This function is called when the generic accelerator has been
     added to the externalkey using ssh_ek_add_provider. The
     externalkey provider type is "genacc", and the string
     initialization_info contains other parameters.

     Example initialization strings to ssh_ek_add_provider

     "name(accelerator-name-x), device-info(some-accelerator-specific-string)
      initialize-using-message(no)"

      This string says that:

      1) the generic EK provider will use the code for the accelerator
      "accelerator-name-x" (all installed accelerators can be found
      from genaccdevice.c. The string identifying the accelerator
      can be found in structure of type SshAccDeviceDefRec. (See the
      end of this file).

      2) inside device-info is the string that is passed to this
      function as paramerer "initialization-info".

      3) Initialize-using-message says, when "no", that the void
      pointer passed to ssh_ek_add_provider as initialization_ptr is
      passed directly to this call.

      If initialize-using-message is "yes", the initialization of the
      device is delayed, until a message has been sent to the EK
      provider using ssh_ek_send_message. Message should be
      "Initializing Message" and the message_arg argument to the send
      message is the void pointer that is passed to this function as
      extra_args. Using "initialize-using-message(yes)" can be used to
      delay the initialization until some event has happened.

     This function should return the accelerator specific context in
     *device_context. This context is passed to the other device
     *specific functions.

  */
  SSH_DEBUG(SSH_D_LOWSTART,("%s\n", "Have called the dummy init function"));

  accel = ssh_xcalloc(1, sizeof(*accel));
  accel->type = DUMMY_ACCEL_ASYNC;

  if (initialization_info && !strncmp(initialization_info, "num-threads=",
                                      strlen("num-threads=")))
    {
       accel->type = DUMMY_ACCEL_THREADED;

       max_threads = atoi(initialization_info + strlen("num-threads="));

       if (max_threads > SSH_DUMMY_ACCEL_MAX_THREADS)
         max_threads = SSH_DUMMY_ACCEL_MAX_THREADS;

       accel->mbox = ssh_threaded_mbox_create(max_threads);

       SSH_DEBUG(SSH_D_HIGHOK, ("Using threads (maximum %d)",
                                (int) max_threads));

       if (!accel->mbox)
         {
           ssh_free(accel);
           return FALSE;
         }
     }

  else if (initialization_info && !strcmp(initialization_info, "no-ops"))
    accel->type = DUMMY_ACCEL_NO_OP_SYNC;

  else if (initialization_info && !strcmp(initialization_info, "no-ops-async"))
    accel->type = DUMMY_ACCEL_NO_OP_ASYNC;

  *device_context = accel;
  return TRUE;
}

void ssh_dummy_uninit(void *device_context)
{
  DummyAccel accel = device_context;

  /* This function is called to uninitialize the device initialized in
     the init function. The device_context returned from the init is
     passed as device contexxt here */

  if (accel->mbox)
    ssh_threaded_mbox_destroy(accel->mbox);

  ssh_free(accel);
  SSH_DEBUG(SSH_D_LOWSTART, ("Have uninitialized the dummy device"));
}


/************************************************************************/

typedef struct DummyModexpRec
{
  DummyAccel accel;

  SshMPInteger base, exponent, modulus, ret;

  SshAccDeviceReplyCB callback;
  SshOperationHandleStruct op[1];
  void *reply_context;
  unsigned char *buf;
  size_t buf_len;

} *DummyModexp;


static void modexp_perform(void *context);
static void modexp_finish(void *context);

static void modexp_abort(void *context)
{
  DummyModexp ctx = context;

  ssh_cancel_timeouts(modexp_perform, ctx);
  ssh_cancel_timeouts(modexp_finish, ctx);

  ssh_mprz_free(ctx->ret);
  ssh_mprz_free(ctx->base);
  ssh_mprz_free(ctx->exponent);
  ssh_mprz_free(ctx->modulus);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}


static void modexp_finish(void *context)
{
  DummyModexp ctx = context;

  SSH_DEBUG(SSH_D_LOWOK,("In the modexp completion"));

  if (ctx->accel->type == DUMMY_ACCEL_NO_OP_ASYNC)
    ctx->buf = ssh_xcalloc(1, ctx->buf_len);

  (*ctx->callback)(SSH_CRYPTO_OK, ctx->buf, ctx->buf_len,
                   ctx->reply_context);

  ssh_operation_unregister(ctx->op);

  ssh_mprz_free(ctx->ret);
  ssh_mprz_free(ctx->base);
  ssh_mprz_free(ctx->exponent);
  ssh_mprz_free(ctx->modulus);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}

static void modexp_completion(void *context)
{
  DummyModexp ctx = context;

  ssh_xregister_timeout(0, 0, modexp_finish, ctx);
}

static void modexp_perform(void *context)
{
  DummyModexp modexp = context;

  /* Do the operation synchronously. */
  ssh_mprz_powm(modexp->ret, modexp->base,
                modexp->exponent, modexp->modulus);

  modexp->buf_len = ssh_mprz_byte_size(modexp->modulus);
  modexp->buf = ssh_xmalloc(modexp->buf_len);

  /* Linearize the mp integer 'ret' to the buffer */
  ssh_mprz_get_buf(modexp->buf, modexp->buf_len, modexp->ret);

  if (modexp->accel->type == DUMMY_ACCEL_ASYNC)
    modexp_completion(modexp);
}

static void modexp_thread_cb(void *ctx)
{
  DummyModexp modexp = ctx;

  /* Do the modp operation */
  modexp_perform(modexp);

  /* Pass the message back to the event loop */
  SSH_DEBUG(SSH_D_LOWOK,("In the thread message handler, passing control "
                         "back to eloop"));

  (void)ssh_threaded_mbox_send_to_eloop(modexp->accel->mbox,
                                         modexp_completion, modexp);

}

/* This is the worker function for the accelerators. The
   device_context was returned from the init function. op_id
   identified the operation being used. See genaccprov.h which defines
   the values for this variable. Usually this is
   SSH_ACC_DEVICE_OP_MODEXP. The data is operation specific, and the
   data format for modexp can be found from genaccprov.h. The callback
   should be called with the data when the operation terminates.  */
SshOperationHandle ssh_dummy_modexp(void *device_context,
                                    SshAccDeviceOperationId op_id,
                                    const unsigned char *data,
                                    size_t data_len,
                                    SshAccDeviceReplyCB callback,
                                    void *reply_context)
{
  DummyAccel accel;
  DummyModexp modexp;
  unsigned char *b, *e, *m;
  size_t b_len, e_len, mod_len;

  accel = device_context;

  /* Decode the data buffer to extract the MP Integers */
  SSH_VERIFY(ssh_decode_array(data, data_len,
                              SSH_DECODE_UINT32_STR_NOCOPY(&b, &b_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&e, &e_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&m, &mod_len),
                              SSH_FORMAT_END) == data_len);

  /* Fake a return value of zero. */
  if (accel->type == DUMMY_ACCEL_NO_OP_SYNC)
    {
      unsigned char *zerobuf;
      zerobuf = ssh_xcalloc(1, mod_len);
      (*callback)(SSH_CRYPTO_OK, zerobuf, mod_len, reply_context);
      ssh_xfree(zerobuf);
      return NULL;
    }

  modexp = ssh_xcalloc(1, sizeof(*modexp));

  /* Allocate and set the MP Integers. */
  if (accel->type == DUMMY_ACCEL_ASYNC || accel->type == DUMMY_ACCEL_THREADED)
    {
      modexp->base = ssh_mprz_malloc();
      modexp->exponent = ssh_mprz_malloc();
      modexp->modulus = ssh_mprz_malloc();
      modexp->ret = ssh_mprz_malloc();

      ssh_mprz_set_buf(modexp->base, b, b_len);
      ssh_mprz_set_buf(modexp->exponent, e, e_len);
      ssh_mprz_set_buf(modexp->modulus, m, mod_len);
    }
  else if (accel->type == DUMMY_ACCEL_NO_OP_ASYNC)
    {
      modexp->buf_len = mod_len;
    }

  modexp->accel = accel;
  modexp->reply_context = reply_context;
  modexp->callback = callback;

  ssh_operation_register_no_alloc(modexp->op, modexp_abort, modexp);

  if (accel->type == DUMMY_ACCEL_THREADED)
    {
      if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
                                            modexp_thread_cb,
                                            modexp))
        {
          (*modexp->callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0,
                              modexp->reply_context);

          ssh_operation_unregister(modexp->op);
          /* Free the mp integers */
          ssh_mprz_free(modexp->ret);
          ssh_mprz_free(modexp->base);
          ssh_mprz_free(modexp->exponent);
          ssh_mprz_free(modexp->modulus);

          ssh_free(modexp);
          return NULL;
        }
    }
  else if (accel->type == DUMMY_ACCEL_ASYNC)
    {
      ssh_xregister_timeout(0, 0, modexp_perform, modexp);
    }
  else if (accel->type == DUMMY_ACCEL_NO_OP_ASYNC)
    {
      modexp_completion(modexp);
    }

  return modexp->op;
}


/*************** RSA CRT operation *************************/

typedef struct DummyRSACrtRec
{
  SshAccDeviceReplyCB callback;
  SshOperationHandleStruct op[1];
  void *reply_context;
  unsigned char *buf;
  size_t buf_len;

} *DummyRSACrt;


static void rsa_crt_completion(void *context)
{
  DummyRSACrt ctx = context;

  (*ctx->callback)(SSH_CRYPTO_OK, ctx->buf, ctx->buf_len,
                   ctx->reply_context);

  ssh_operation_unregister(ctx->op);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}

static void rsa_crt_abort(void *context)
{
  DummyRSACrt ctx = context;

  ssh_cancel_timeouts(rsa_crt_completion, ctx);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}

SshOperationHandle ssh_dummy_rsa_crt(void *device_context,
                                     SshAccDeviceOperationId op_id,
                                     const unsigned char *data,
                                     size_t data_len,
                                     SshAccDeviceReplyCB callback,
                                     void *reply_context)
{
  SshMPInteger X, P, Q, U, DP, DQ, ret;
  SshMPIntegerStruct p2, q2, k;
  DummyRSACrt rsa_crt_ctx;
  DummyAccel accel;
  unsigned char *buf, *x, *p, *q, *dp, *dq, *u;
  size_t buf_len, x_len, p_len, q_len, dp_len, dq_len, u_len;

  accel = device_context;
  SSH_DEBUG(SSH_D_MIDOK, ("RSA CRT operation"));

  if (accel->type == DUMMY_ACCEL_NO_OP_SYNC
      || accel->type == DUMMY_ACCEL_NO_OP_ASYNC)
    {
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
      return NULL;
    }

  /* Fail with probability 1/256 so that the dummy_modexp routine also
     gets tested */
  if ((ssh_random_get_byte() & 0xff) == 0)
  {
    SSH_DEBUG(SSH_D_FAIL,
              ("RSA CRT operation failed, will now try using modexp"));
    (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
    return NULL;
  }

  rsa_crt_ctx = ssh_xcalloc(1, sizeof(*rsa_crt_ctx));

  /* Decode the data buffer to extract the MP Integers */
  SSH_VERIFY(ssh_decode_array(data, data_len,
                              SSH_DECODE_UINT32_STR_NOCOPY(&x, &x_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&p, &p_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&q, &q_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&dp, &dp_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&dq, &dq_len),
                              SSH_DECODE_UINT32_STR_NOCOPY(&u, &u_len),
                              SSH_FORMAT_END) == data_len);


  /* Allocate and set the MP Integers. */
  X = ssh_mprz_malloc();
  P = ssh_mprz_malloc();
  Q = ssh_mprz_malloc();
  U = ssh_mprz_malloc();
  DP = ssh_mprz_malloc();
  DQ = ssh_mprz_malloc();
  ret = ssh_mprz_malloc();

  ssh_mprz_set_buf(X, x, x_len);
  ssh_mprz_set_buf(P, p, p_len);
  ssh_mprz_set_buf(Q, q, q_len);
  ssh_mprz_set_buf(U, u, u_len);
  ssh_mprz_set_buf(DP, dp, dp_len);
  ssh_mprz_set_buf(DQ, dq, dq_len);

  /* Initialize temporary variables. */
  ssh_mprz_init(&p2);
  ssh_mprz_init(&q2);
  ssh_mprz_init(&k);

  /* Compute p2 = (input mod p) ^ dp mod p. */
  ssh_mprz_mod(&p2, X, P);
  ssh_mprz_powm(&p2, &p2, DP, P);

  /* Compute q2 = (input mod q) ^ dq mod q. */
  ssh_mprz_mod(&q2, X, Q);
  ssh_mprz_powm(&q2, &q2, DQ, Q);

  /* Compute k = ((q2 - p2) mod q) * u mod q. */
  ssh_mprz_sub(&k, &q2, &p2);
  ssh_mprz_mul(&k, &k, U);
  ssh_mprz_mod(&k, &k, Q);

  /* Compute ret = p2 + p * k. */
  ssh_mprz_mul(ret, P, &k);
  ssh_mprz_add(ret, ret, &p2);

  /* Clear temporary variables. */
  ssh_mprz_clear(&p2);
  ssh_mprz_clear(&q2);
  ssh_mprz_clear(&k);

  buf_len = p_len + q_len;
  rsa_crt_ctx->buf_len = buf_len;

  buf = ssh_xcalloc(1, buf_len);

  /* Linearize the mp integer 'ret' to the buffer */
  ssh_mprz_get_buf(buf, buf_len, ret);
  rsa_crt_ctx->buf = buf;

  /* Free the mp integers */
  ssh_mprz_free(X); ssh_mprz_free(P); ssh_mprz_free(Q); ssh_mprz_free(DP);
  ssh_mprz_free(DQ); ssh_mprz_free(U); ssh_mprz_free(ret);

  rsa_crt_ctx->reply_context = reply_context;
  rsa_crt_ctx->callback = callback;

  ssh_operation_register_no_alloc(rsa_crt_ctx->op, rsa_crt_abort, rsa_crt_ctx);

  ssh_xregister_timeout(0, 0, rsa_crt_completion, rsa_crt_ctx);
  return rsa_crt_ctx->op;
}


typedef struct DummyRandomRec
{
  SshAccDeviceReplyCB callback;
  SshOperationHandleStruct op[1];
  void *reply_context;
  unsigned char *buf;
  size_t buf_len;

} *DummyRandom;

static void get_random_bytes_completion(void *context)
{
  DummyRandom ctx = context;

  (*ctx->callback)(SSH_CRYPTO_OK, ctx->buf, ctx->buf_len,
                   ctx->reply_context);

  ssh_operation_unregister(ctx->op);
  ssh_free(ctx->buf);
  ssh_free(ctx);
}


static void get_random_bytes_abort(void *context)
{
  DummyRandom ctx = context;

  /* Just sugar for this dummy acc implementation. The
     get_random_bytes can be aborted, and this is called when the
     random completion is aborted using ssh_operation_abort. */
  ssh_cancel_timeouts(get_random_bytes_completion, ctx);
  ssh_xfree(ctx->buf);
  ssh_xfree(ctx);
}

/* This simulates getting 'data_len' random bytes from the device. The
   real implementation would of course consult the hardware using the
   device context (returned from the init function. */
SshOperationHandle
ssh_dummy_get_random_bytes(void *device_context,
                           const unsigned char *data,
                           size_t data_len,
                           SshAccDeviceReplyCB callback,
                           void *reply_context)
{
  DummyRandom random_ctx;
  SshUInt32 bytes_requested;
  int i;

  if (data_len != 4)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, reply_context);
      return NULL;
    }

  bytes_requested = SSH_GET_32BIT(data);

  random_ctx = ssh_xcalloc(1, sizeof(*random_ctx));
  random_ctx->buf = ssh_xcalloc(1, bytes_requested);

  for (i = 0; i < bytes_requested; i++)
    random_ctx->buf[i] = ssh_random_get_byte();

  SSH_DEBUG_HEXDUMP(6, ("Random bytes: (%d)", (int) bytes_requested),
                    random_ctx->buf, bytes_requested);

 random_ctx->buf_len = bytes_requested;
 random_ctx->reply_context = reply_context;
 random_ctx->callback = callback;

 ssh_operation_register_no_alloc(random_ctx->op, get_random_bytes_abort,
                                 random_ctx);

  /* Simulate asynchronous operation using a timeout */
  ssh_xregister_timeout(0, 0, get_random_bytes_completion, random_ctx);
  return random_ctx->op;
}


/* The dummy operation execute function. This is the etnry point to
   the accelerator, when it is requested an operation. */
SshOperationHandle ssh_dummy_execute(void *device_context,
                                     SshAccDeviceOperationId operation_id,
                                     const unsigned char *data,
                                     size_t data_len,
                                     SshAccDeviceReplyCB callback,
                                     void *context)
{
  switch(operation_id)
    {
    case SSH_ACC_DEVICE_OP_MODEXP:
      return ssh_dummy_modexp(device_context, operation_id, data, data_len,
                              callback, context);

    case SSH_ACC_DEVICE_OP_GET_RANDOM:
      return ssh_dummy_get_random_bytes(device_context, data, data_len,
                                        callback, context);

    case SSH_ACC_DEVICE_OP_RSA_CRT:
      return ssh_dummy_rsa_crt(device_context, operation_id, data, data_len,
                               callback, context);

    default:
      {
        (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
        return NULL;
      }
    }
}

/* Device configuration. */
const struct SshAccDeviceDefRec ssh_acc_dev_dummy_ops =
{
  "dummy",
  1536,
  ssh_dummy_init,
  ssh_dummy_uninit,
  ssh_dummy_execute
};
