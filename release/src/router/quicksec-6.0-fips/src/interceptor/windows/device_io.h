/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Device I/O helper functions for Windows device drivers.
*/

#ifndef SSH_DEVICE_IO_H
#define SSH_DEVICE_IO_H

#include "kernel_mutex.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

typedef struct SshDeviceIoContextRec
{
  /* Handle to opened I/O device */
  HANDLE handle;
  /* Pointer to disable count variable */
  LONG *disable_count_ptr;
  /* Pointer to 'requests pending' count variable */
  LONG *requests_pending_ptr;
  /* Pointer to file object */
  FILE_OBJECT   *file_obj;
  /* Pointer to device object */
  DEVICE_OBJECT *dev_obj;
  /* Default timeout (in milliseconds) for I/O control requests */
  SshUInt32 default_timeout;
  /* List of pending requests */
  LIST_ENTRY requests;
  SshKernelMutexStruct req_list_lock;
} SshDeviceIoContextStruct, *SshDeviceIoContext;

typedef struct SshDevicoIoOpenParamsRec
{
  /* Default timeout (in milliseconds) for I/O control requests */
  SshUInt32 default_timeout;
  /* Pointer to disable count variable. Can be initialized to zero 
     (meaning that disable count is not used) */
  LONG *disable_count_ptr;
  /* Pointer to "requests pending" count variable. Can be initialized 
     to zero (meaning that disable count is not used) */
  LONG *requests_pending_ptr;
  /* Flags: */
  unsigned int exclusive_access : 1;
  unsigned int write_access : 1;
} SshDeviceIoOpenParamsStruct, *SshDeviceIoOpenParams;

typedef struct SshDeviceIoRequestRec
{
  /* I/O control code for the request */
  ULONG ioctl_code;
  /* Optional input data for the request */
  VOID *input_buffer;
  ULONG input_buff_len;
  /* Optional output data for the request */
  VOID *output_buffer;
  ULONG output_buff_len;
  /* Size of output data, i.e. the number of bytes written to output_buffer 
     (if ssh_device_io_request() returns STATUS_SUCCESS) or the size of output
     buffer required for the response (if the return value is either 
     STATUS_BUFFER_TOO_SMALL or STATUS_BUFFER_OVERFLOW). */
  ULONG *output_size_return;
  /* specifies whether this is an internal device I/O control request */
  Boolean internal_device_control;
  /* Timeout value (in milliseconds) for the I/O request. Uses default 
     timeout value if this is initialized to zero. */
  SshUInt32 timeout;  
} SshDeviceIoRequestStruct, *SshDeviceIoRequest;

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_device_open()

  Opens handle to an existing I/O device.

  Arguments:

    device_context - pointer to caller-allocated device context structure
                     (will be initialized in ssh_device_open()).
    device_name    - name of the I/O device to be opened.
    params         - pointer to optional parameters. Can be set to zero (in
                     which case default parameters are being used.

  Returns:
    TRUE if device was successully opened or FALSE if an error occurred.

  Notes:
    -
  --------------------------------------------------------------------------*/
Boolean
ssh_device_open(SshDeviceIoContext device_context,
                WCHAR *device_name,
                SshDeviceIoOpenParams params);


/*--------------------------------------------------------------------------
  ssh_device_close()

  Closes handle to the previously opened I/O device. 

  Arguments:
    device_context - pointer to device context structure.

  Returns:
    -

  Notes:
    -
  --------------------------------------------------------------------------*/
void
ssh_device_close(SshDeviceIoContext device_context);


/*--------------------------------------------------------------------------
  ssh_device_ioctl_request()

  Builds a specified device I/O control request, sends it to the previously
  opened I/O device and stores the response data to given output buffer. 

  Arguments:
    device_context - pointer to device context structure.
    request        - specifies the I/O control request.

  Returns:
    STATUS_SUCCESS if I/O control request succeeeded or STATUS_xxx code
    specifying the error occurred (see ntstatus.h for possible error codes).

  Notes:
    -
  --------------------------------------------------------------------------*/
NTSTATUS
ssh_device_ioctl_request(SshDeviceIoContext device_context,
                         SshDeviceIoRequest request);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_DEVICE_IO_H */

