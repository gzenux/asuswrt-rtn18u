/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Accelerator for Octeon.
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

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ENABLE_EXTERNALKEY_CAVIUM_OCTEON

#include "cvmx.h"
#include "cvmx-rng.h"

#define SSH_DEBUG_MODULE "SshEKOcteonAcc"

/* Device generic attributes */
#define SSH_OCTEON_ACC_MAX_THREADS             7
#define SSH_OCTEON_ACC_MAX_OFFLOAD_BYTE_SIZE   256
#define SSH_OCTEON_ACC_MAX_RAND_BYTES          512
#define SSH_OCTEON_ACC_MODEXP_OP_FREELIST_SIZE 32

#ifndef HAVE_THREADS
#undef SSH_OCTEON_ACC_MAX_THREADS
#define SSH_OCTEON_ACC_MAX_THREADS 0
#endif /* !HAVE_THREADS */

typedef struct OcteonAccelRec OcteonAccelStruct, *OcteonAccel;
typedef struct OcteonModexpCtxRec *OcteonModexpCtx;

/* Context structure for ModExp operation. */
struct OcteonModexpCtxRec
{
  OcteonAccel accel;

  OcteonModexpCtx next;

  SshMPIntegerStruct base;
  SshMPIntegerStruct exponent;
  SshMPIntegerStruct modulus;

  SshCryptoStatus status;
  SshAccDeviceReplyCB callback;
  SshOperationHandleStruct op[1];
  void *reply_context;
  unsigned char *buf;
  size_t buf_size;
  size_t buf_len;

  unsigned int aborted : 1;
  unsigned int op_registered : 1;
};

/* Context structure for the accelarator */
struct OcteonAccelRec
{
  SshThreadedMbox mbox;
  OcteonModexpCtx modexp_freelist;
  SshUInt8 modexp_freelist_length;
  SshUInt8 num_threads;
};

/* Modexp operation context freelist operations. */
static OcteonModexpCtx
octeon_acc_modexp_op_freelist_get(OcteonAccel accel)
{
  OcteonModexpCtx modexp;

  if (accel->modexp_freelist != NULL)
    {
      SSH_ASSERT(accel->modexp_freelist_length > 0);
      accel->modexp_freelist_length--;

      modexp = accel->modexp_freelist;
      accel->modexp_freelist = modexp->next;

      return modexp;
    }
  else
    return NULL;
}

static void
octeon_acc_modexp_op_freelist_put(OcteonModexpCtx modexp)
{
  if (modexp->accel->modexp_freelist_length <
      SSH_OCTEON_ACC_MODEXP_OP_FREELIST_SIZE)
    {
      modexp->accel->modexp_freelist_length++;

      modexp->next = modexp->accel->modexp_freelist;
      modexp->accel->modexp_freelist = modexp;
    }
  else
    {
      ssh_free(modexp->buf);
      ssh_free(modexp);
    }
}

/* Initialization function for accelarator */
Boolean ssh_octeon_acc_init(const char *init_string,
                            void *extra_args,
                            void **device_context)
{
  OcteonAccel accel;
  int num_threads;

  SSH_DEBUG(SSH_D_LOWOK, ("Octeon accelerator device initialization called"));

  *device_context = NULL;

  /* Initialize the random number generator hardware */
  cvmx_rng_enable();

  /* After the device has been successfully initialized, create a context for
     further operations. */
  accel = ssh_calloc(1, sizeof(*accel));
  if (accel == NULL)
    return FALSE;

  num_threads = SSH_OCTEON_ACC_MAX_THREADS;
  if (init_string && strncmp(init_string, "num-threads=",
                             strlen("num-threads=")) == 0)
    {
      num_threads = atoi(init_string + strlen("num-threads="));
      if (num_threads < 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid argument value 'num-threads=%d'",
                                 num_threads));
          ssh_free(accel);
          return FALSE;
        }
      else if (num_threads > SSH_OCTEON_ACC_MAX_THREADS)
        num_threads = SSH_OCTEON_ACC_MAX_THREADS;
    }
  accel->num_threads = num_threads;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Octeon accelerator device using %u threads",
             accel->num_threads));

  accel->mbox = ssh_threaded_mbox_create(accel->num_threads);
  if (accel->mbox == NULL)
    {
      ssh_free(accel);
      return FALSE;
    }

  *device_context = accel;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Octeon accelerator device initialization completed"));
  return TRUE;
}

/* Uninitialization function for the accelerator. */
void ssh_octeon_acc_uninit(void *context)
{
  OcteonAccel accel = (OcteonAccel) context;
  OcteonModexpCtx modexp;

  if (accel->mbox)
    ssh_threaded_mbox_destroy(accel->mbox);

  do {
    modexp = octeon_acc_modexp_op_freelist_get(accel);
    if (modexp != NULL)
      {
        ssh_free(modexp->buf);
        ssh_free(modexp);
      }
  } while (modexp != NULL);

  ssh_free(accel);
  SSH_DEBUG(SSH_D_MIDOK, ("Octeon accelerator device uninitialized"));
}

/************************************************************************/

static void octeon_acc_modexp_abort(void *context)
{
  OcteonModexpCtx modexp = context;
  modexp->aborted = 1;
}

static void octeon_acc_modexp_completion(void *context)
{
  OcteonModexpCtx modexp = context;

  SSH_DEBUG(SSH_D_LOWOK,("In the modexp completion"));

  if (!modexp->aborted)
    {
      (*modexp->callback)(modexp->status, modexp->buf, modexp->buf_len,
                          modexp->reply_context);

      if (modexp->op_registered)
        ssh_operation_unregister(modexp->op);
    }

  /* Cleanup modexp operation context and free it to freelist. */
  modexp->aborted = 0;
  modexp->op_registered = 0;

  ssh_mprz_clear(&modexp->base);
  ssh_mprz_clear(&modexp->exponent);
  ssh_mprz_clear(&modexp->modulus);

  octeon_acc_modexp_op_freelist_put(modexp);
}

static void octeon_acc_modexp_thread_cb(void *context)
{
  OcteonModexpCtx modexp = context;
  SshMPIntegerStruct ret;

  /* Do the math operation in software using the cn_mips assembler
     optimized math operations. Note that ssh_mprz_powm() checks that
     the arguments are not nan mp-integers. Thus any memory allocation
     failures that occured during decoding of linearized parameters are
     found here. */
  ssh_mprz_init(&ret);
  ssh_mprz_powm(&ret, &modexp->base, &modexp->exponent, &modexp->modulus);

  /* Linearize the MP integer to the buffer. ssh_mprz_get_buf() returns
     zero if modexp result is nan. Thus this does not need to be tested
     explicitly. */
  if (ssh_mprz_get_buf(modexp->buf, modexp->buf_len, &ret))
    {
      modexp->status = SSH_CRYPTO_OK;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Modexp operation failed"));
      modexp->status = SSH_CRYPTO_OPERATION_FAILED;
    }
  ssh_mprz_clear(&ret);

  /* Pass the message back to the event loop */
  SSH_DEBUG(SSH_D_LOWOK,("In the thread message handler, passing control "
                         "back to eloop"));





  if (!ssh_threaded_mbox_send_to_eloop(modexp->accel->mbox,
                                       octeon_acc_modexp_completion, modexp))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to pass modexp result back to eloop!"));

      /* Free context, as we cannot return it to freelist from
         outside of eloop thread. */
      ssh_mprz_clear(&modexp->base);
      ssh_mprz_clear(&modexp->exponent);
      ssh_mprz_clear(&modexp->modulus);

      ssh_free(modexp->buf);
      ssh_free(modexp);
    }
}

SshOperationHandle ssh_octeon_acc_modexp(void *device_context,
                                         SshAccDeviceOperationId op_id,
                                         const unsigned char *data,
                                         size_t data_len,
                                         SshAccDeviceReplyCB callback,
                                         void *reply_context)
{
  OcteonAccel accel;
  OcteonModexpCtx modexp;
  unsigned char *b, *e, *m;
  size_t b_len, e_len, mod_len;

  accel = device_context;

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

  /* Take a modexp operation context from freelist. */
  modexp = octeon_acc_modexp_op_freelist_get(accel);
  if (modexp == NULL)
    {
      /* No operation contexts in freelist, allocate a new context. */
      modexp = ssh_calloc(1, sizeof(*modexp));
      if (modexp == NULL)
        {
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
          return NULL;
        }
      modexp->accel = accel;
    }

  /* Initialize the MP Integers. */
  ssh_mprz_init(&modexp->base);
  ssh_mprz_init(&modexp->exponent);
  ssh_mprz_init(&modexp->modulus);

  ssh_mprz_set_buf(&modexp->base, b, b_len);
  ssh_mprz_set_buf(&modexp->exponent, e, e_len);
  ssh_mprz_set_buf(&modexp->modulus, m, mod_len);

  if (modexp->buf_size < mod_len)
    {
      ssh_free(modexp->buf);
      modexp->buf_size = mod_len;
      modexp->buf = ssh_malloc(modexp->buf_size);
      if (modexp->buf == NULL)
        {
          modexp->buf_size = 0;
          goto error;
        }
    }
  modexp->buf_len = mod_len;

  modexp->accel = accel;
  modexp->reply_context = reply_context;
  modexp->callback = callback;

  /* If num_threads is zero, then calls via the threaded mbox are
     synchronous. Therefore we do not need to register and return
     any operation handles. */
  if (accel->num_threads > 0)
    {
      ssh_operation_register_no_alloc(modexp->op, octeon_acc_modexp_abort,
                                      modexp);
      modexp->op_registered = 1;
    }

  if (!ssh_threaded_mbox_send_to_thread(accel->mbox,
                                        octeon_acc_modexp_thread_cb,
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
  SSH_DEBUG(SSH_D_FAIL, ("Octeon accelerator modexp operation failed"));

  if (modexp != NULL)
    {
      if (modexp->op_registered)
        ssh_operation_unregister(modexp->op);
      modexp->op_registered = 0;

      ssh_mprz_clear(&modexp->base);
      ssh_mprz_clear(&modexp->exponent);
      ssh_mprz_clear(&modexp->modulus);

      octeon_acc_modexp_op_freelist_put(modexp);
    }

  (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
  return NULL;
}

/**************************************************************************/

SshOperationHandle
ssh_octeon_acc_get_random_bytes(void *device_context,
                                SshAccDeviceOperationId operation_id,
                                const unsigned char *data,
                                size_t data_len,
                                SshAccDeviceReplyCB callback,
                                void *context)
{
  SshUInt32 bytes_requested, bytes_read;
  SshUInt32 status;
  uint64_t buffer[SSH_OCTEON_ACC_MAX_RAND_BYTES/8] = {0};

  /* Parse input arguments. */
  if (data_len != 4)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, context);
      return NULL;
    }

  bytes_requested = SSH_GET_32BIT(data);

  /* Read up to SSH_OCTEON_ACC_MAX_RAND_BYTES from octeon RNG hardware. */
  SSH_DEBUG(SSH_D_LOWOK, ("Get %d random bytes from octeon",
                          (unsigned long) bytes_requested));

  if (bytes_requested == 0)
    {
      (*callback)(SSH_CRYPTO_PROVIDER_ERROR, NULL, 0, context);
      return NULL;
    }
  else if (bytes_requested > SSH_OCTEON_ACC_MAX_RAND_BYTES)
    {
      bytes_requested = SSH_OCTEON_ACC_MAX_RAND_BYTES;
    }

  for (bytes_read = 0; bytes_read < bytes_requested; bytes_read += 8)
    buffer[bytes_read/8] = cvmx_rng_get_random64();

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Get Random bytes op returning %d bytes",
                                  (unsigned long) bytes_requested),
                    (unsigned char *) buffer, bytes_requested);

  (*callback)(SSH_CRYPTO_OK, (unsigned char *) buffer,
              bytes_requested, context);

  return NULL;
}

/**************************************************************************/

/* The operation execution function. This is called when the device is
 asked to perform an operation. */
SshOperationHandle ssh_octeon_acc_execute(void *device_context,
                                          SshAccDeviceOperationId operation_id,
                                          const unsigned char *data,
                                          size_t data_len,
                                          SshAccDeviceReplyCB callback,
                                          void *context)
{
  switch (operation_id)
    {
    case SSH_ACC_DEVICE_OP_GET_RANDOM:
      return ssh_octeon_acc_get_random_bytes(device_context, operation_id,
                                             data, data_len, callback,
                                             context);
    case SSH_ACC_DEVICE_OP_MODEXP:
      return ssh_octeon_acc_modexp(device_context, operation_id,
                                   data, data_len, callback, context);
    case SSH_ACC_DEVICE_OP_RSA_CRT:
    default:
      (*callback)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, context);
    }

  return NULL;
}

/* Device configuration. */
struct SshAccDeviceDefRec ssh_acc_dev_octeon_ops =
  {
    "octeon",
    (SSH_OCTEON_ACC_MAX_OFFLOAD_BYTE_SIZE - 1) * 8,
    ssh_octeon_acc_init,
    ssh_octeon_acc_uninit,
    ssh_octeon_acc_execute
  };
#endif /* ENABLE_EXTERNALKEY_CAVIUM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

