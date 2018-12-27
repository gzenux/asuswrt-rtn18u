/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Split crypto module top level.
*/

#include "sshdistdefs.h"
#include "sshincludes.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshCryptoModule"
/* Called when fatal error occurs. */
void
ssh_crypto_fatal_callback(const char *buf, void *context)
{
  LARGE_INTEGER address;
  if (buf != NULL)
    DbgPrint("%s\n", buf);
  
  address.QuadPart = (unsigned __int64)buf;
  
#pragma warning(disable : 28159)
  KeBugCheckEx('TNFS', 0xBAD, 0xBAD,
               (LONG)address.HighPart, (LONG)address.LowPart);
#pragma warning(default : 28159)
  return ;
}

/* Called when warning occurs. */
void
ssh_crypto_warning_callback(const char *buf, void *context)
{
  if (buf != NULL)
    DbgPrint("%s\n", buf);
  return ;
}

/* Called when debug message occurs. */
void
ssh_crypto_debug_callback(const char *buf, void *context)
{
 if (buf != NULL)
  DbgPrint("%s\n", buf);
  return ;
}


EXTERN_C NTSTATUS
DriverEntry (
  IN PDRIVER_OBJECT DriverObject,
  IN PUNICODE_STRING RegistryPath
	     )
{
  return STATUS_SUCCESS;
}


NTSTATUS
DllInitialize( IN PUNICODE_STRING pus )
{
  SSH_DEBUG(SSH_D_NICETOKNOW,("In Dll Initialize"));
  
  /* Setup debug callbacks. */
  ssh_debug_register_callbacks(ssh_crypto_fatal_callback,
                               ssh_crypto_warning_callback,
                               ssh_crypto_debug_callback, NULL);
  
  ssh_debug_set_level_string("*=0"); 

  if (ssh_crypto_library_initialize() != SSH_CRYPTO_OK)
    {
      DbgPrint("Crypto library initialization failed.\n");
      return STATUS_UNSUCCESSFUL;
    }

  return STATUS_SUCCESS;
}

NTSTATUS
DllUnload( )
{
  return STATUS_SUCCESS;
}
