/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header file used to configure new accelerated devices.

   Each new device is configured by defining a structure of the type
   SshAccDeviceDef (defined below). There should be one of these
   structures for each device type. Pointers to data structures of
   this kind should be added to the built-in device array
   ssh_acc_device_def in the file genaccdevice.c.
*/

#ifndef SSH_GENACC_PROV_H
#define SSH_GENACC_PROV_H

/**********************************************************************/


/* This callback returns operated data from the device. Returns
   SSH_ACC_DEVICE_OK on success, otherwise 'status' indicates the
   reason for failure. */
typedef void (*SshAccDeviceReplyCB)(SshCryptoStatus status,
                                    const unsigned char *operated_data,
                                    size_t operated_data_len,
                                    void *reply_context);

/* The operation identification (id) number. The operation id specifies
   to the device execute function (defined below) what type of operation
   is to be performed. Each operation id specifies a format for the
   encoding of 'input_data' to the execute operation and the 'operated_data'
   returned by the operation reply callback. The format is obtained using the
   sshencode.h routines. Encoding and decoding is only relevant when the
   input or output data consists of more than one data buffer.
*/
typedef enum
{
  /* The modular exponentation operation. This computes <return>, as
     <ret> = (<base> ^ <exponent>) % <modulus>),

     where <base>, <exponent>, <modulus> and <return> are positive
     integers.

     'input_data' is a encoded array consisting of <base>, followed
     by <exponent>, followed by <modulus>, each encoded as
     SSH_FORMAT_UINT32_STR, in network byte order (most significant byte
     first).

     'operated_data' is <ret> encoded in network byte order.
     'operated_data_len' must be equal to the byte size of <modulus>
     and 'operated_data' should be padded with zeros if required.

     See dummyacc.c for an example of how this encoding is done. */
  SSH_ACC_DEVICE_OP_MODEXP      = 0,

  /* 'input_data' should be NULL, 'input_data_len' specifies the number of
     requested random bytes. 'operated_data' contains the returned random
     bytes from the device. */
  SSH_ACC_DEVICE_OP_GET_RANDOM  = 1,

  /* RSA private key operations performed using the Chinese Remainder
     Theorem (CRT).

     This computes <ret> as <ret> = (<x> ^ <d>) mod (<p> * <q>) using
     CRT arithmetic.

     'input_data' is a encoded array consisting of <x>, followed
     by the RSA coefficients <p>, <q>, <dp>, <dq>, <u>, each encoded
     as SSH_FORMAT_UINT32_STR, in network byte order (most significant byte
     first). In this notation

     dp = d mod p-1,
     dq = d mod q-1,
     u = p^(-1) mod q, and p < q.

     'operated_data' is <ret> encoded in network byte order.
     'operated_data_len' must be equal to the byte size of <p> added to
     the byte size of <q>, with 'operated_data' should be padded with
     zeros if required.

     See dummyacc.c for an example of how this encoding is done. */
  SSH_ACC_DEVICE_OP_RSA_CRT      = 2

} SshAccDeviceOperationId;


/* The device initialization function. 'initialization_info'
   and 'extra_args' are the input data for the device initialization.

   'device_context' is the pointer to the returned context which is
   passed to all operations the device performs. Returns TRUE if
   initialization succeeds and FALSE otherwise.
*/
typedef  Boolean (*SshAccDeviceInit)(const char *initialization_info,
                                     void *extra_args,
                                     void **device_context);


/* The device uninitializion function. 'device_context' is the context
   returned by the SshAccDeviceInit initialization function.
*/
typedef void (*SshAccDeviceUninit)(void *device_context);


/* Execute an asynchronous operation in the device. 'device_context' is
   the context returned by the SshAccDeviceInit initialization function.
   'op_id' specifies which operation the device should perform, and in
   which format 'input_data' should be encoded. 'input_data_len' is the
   length of the buffer 'input_data'. 'callback' is the operation callback
   that is called on completion of the operation, and 'reply_context' is
   the context that is passed to 'callback'.
*/
typedef SshOperationHandle (*SshAccDeviceExecute)
     (void *device_context,
      SshAccDeviceOperationId op_id,
      const unsigned char *input_data,
      size_t input_data_len,
      SshAccDeviceReplyCB callback,
      void *reply_context);


/* The structure that must be defined to configure new devices. */
typedef struct SshAccDeviceDefRec
{
  /* The name by which the device is known. */
  const char *name;

  /* The maximum modulus size in bits for which the accelerator
     can perform the modexp operation. */
  SshUInt32 max_modexp_size;

  /* Initialize the device. */
  SshAccDeviceInit init;

  /* Uninitialize the device. */
  SshAccDeviceUninit uninit;

  /* Execute an operation in the device. */
  SshAccDeviceExecute execute;

} SshAccDeviceDefStruct, *SshAccDeviceDef;

/* Returns a comma-separated list of supported devices.
   The caller must free the returned string with ssh_free(). */
char * ssh_acc_device_get_supported(void);

/* Checks if the given name is a supported accelerated device. */
Boolean ssh_acc_device_supported(const char *name);

#endif /* SSH_GENACC_PROV_H */


