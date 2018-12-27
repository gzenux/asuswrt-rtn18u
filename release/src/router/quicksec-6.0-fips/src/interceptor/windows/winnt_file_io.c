/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent kernel mode file I/O helper functions for Windows NT
   series desktop operating systems.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include <ntifs.h>
#include "sshincludes.h"
#include "file_io.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_FILE_WR_CACHE_SIZE    65536

typedef struct SshFileIoContextRec
{
  /* Native OS handle */
  HANDLE handle;

  /* Write cache */
  SshUInt32 wr_cache_size;
  SshUInt32 wr_cache_left;
  unsigned char *wr_cache_ptr;
  unsigned char *wr_cache;  
} SshFileIoContextStruct, *SshFileIoContext;


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static Boolean
ssh_file_flush_wr_cache(SshFileIoContext io_ctx)
{
  if (io_ctx->wr_cache)
    {
      IO_STATUS_BLOCK iosb;
      NTSTATUS status;

      status = ZwWriteFile(io_ctx->handle, 
                           NULL, 
                           NULL, 
                           NULL, 
                           &iosb, 
                           io_ctx->wr_cache, 
                           io_ctx->wr_cache_size - io_ctx->wr_cache_left,
                           NULL, 
                           NULL);

      io_ctx->wr_cache_ptr = io_ctx->wr_cache;
      io_ctx->wr_cache_left = io_ctx->wr_cache_size;    

      if (!NT_SUCCESS(status))
        return FALSE;
    }

  return TRUE;
}

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

SshFileIoHandle
ssh_file_create(unsigned char *filename,
                Boolean allow_read)
{
  SshFileIoContext io_ctx;
  OBJECT_ATTRIBUTES obj_attr;
  UNICODE_STRING uc_name;
  ANSI_STRING ansi_name;
  IO_STATUS_BLOCK iosb;
  NTSTATUS status;
  ULONG share_access = 0;

  if (allow_read)
    share_access |= FILE_SHARE_READ;

  RtlInitAnsiString(&ansi_name, filename);
  if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uc_name, &ansi_name, TRUE)))
    return NULL;

  io_ctx = ssh_calloc(1, sizeof(*io_ctx));
  if (io_ctx != NULL)
    {
      InitializeObjectAttributes(&obj_attr, &uc_name,
                                 OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                 NULL, NULL);

      status = ZwCreateFile(&io_ctx->handle, GENERIC_WRITE, 
                            &obj_attr, &iosb, NULL,
                            FILE_ATTRIBUTE_NORMAL, share_access, 
                            FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, 
                            NULL, 0);

      RtlFreeUnicodeString(&uc_name);

      if (!NT_SUCCESS(status))
        {
          ssh_free(io_ctx);
          return NULL;
        }

      io_ctx->wr_cache = ssh_calloc(1, SSH_FILE_WR_CACHE_SIZE);
      if (io_ctx->wr_cache)
        {
          io_ctx->wr_cache_size = SSH_FILE_WR_CACHE_SIZE;
          io_ctx->wr_cache_left = io_ctx->wr_cache_size;
          io_ctx->wr_cache_ptr = io_ctx->wr_cache;
        }
    }

  return io_ctx;
}


Boolean
ssh_file_write(SshFileIoContext io_ctx,
               void *data,
               SshUInt32 data_len)
{
  IO_STATUS_BLOCK iosb;

  if (io_ctx->wr_cache)
    {
      Boolean status = TRUE;

      if (io_ctx->wr_cache_left < (data_len + 1))
        status = ssh_file_flush_wr_cache(io_ctx);

      RtlCopyMemory(io_ctx->wr_cache_ptr, data, data_len);
      io_ctx->wr_cache_ptr += data_len;
      io_ctx->wr_cache_left -= data_len;
      *(io_ctx->wr_cache_ptr) = 0;

      return status;      
    }
  else
    {
      if (NT_SUCCESS(ZwWriteFile(io_ctx->handle, NULL, NULL, NULL, 
                                 &iosb, data, data_len, NULL, NULL)))
        return TRUE;
      else
        return FALSE;
    }
}


void
ssh_file_close(SshFileIoContext io_ctx)
{
  if (io_ctx->wr_cache)
    ssh_file_flush_wr_cache(io_ctx);

  CcWaitForCurrentLazyWriterActivity();

  ZwClose(io_ctx->handle);
}

