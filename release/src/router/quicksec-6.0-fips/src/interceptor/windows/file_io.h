/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   File I/0 helper functions for Windows device drivers.
   (Currently only write access implemented)
*/

#ifndef SSH_FILE_IO_H
#define SSH_FILE_IO_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

typedef void *SshFileIoHandle;

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_file_create()

  Creates and opens a new file with write RW access. Existing file with the
  same name will be replaced. 

  Arguments:
    filename   - name (possibly including the full directory path) of the file 
                 to be created.
    allow_read - TRUE: file can be simultaneously read by another threads
                 FALSE: file is opened with exclusive access and another 
                 threads can not access it simultaneously.

  Returns:
    Handle to created file or NULL if error occurred.

  Notes:
    -
  --------------------------------------------------------------------------*/
SshFileIoHandle
ssh_file_create(unsigned char *filename,
                Boolean allow_read);


/*--------------------------------------------------------------------------
  ssh_file_write()

  Writes specified data to previously opened/created file. 

  Arguments:
    file     - handle to destination file.
    data     - pointer to data to be written
    data_len - length of data (in bytes).

  Returns:
    TRUE if data successfully written to file or FALSE if an error occurred.

  Notes:
    -
  --------------------------------------------------------------------------*/
Boolean
ssh_file_write(SshFileIoHandle file,
               void *data,
               SshUInt32 data_len);


/*--------------------------------------------------------------------------
  ssh_file_close()

  Closes a previously opened/created file.

  Arguments:
    file - handle to file to be closed.

  Returns:
    -

  Notes:
    -
  --------------------------------------------------------------------------*/
void
ssh_file_close(SshFileIoHandle file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SSH_FILE_IO_H */

