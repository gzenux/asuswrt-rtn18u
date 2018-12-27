/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VxWorks implementation of the sshnetevent.h API.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetevent.h"
#include "ssheloop.h"

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS

#define SSH_DEBUG_MODULE "SshVxworksNetevent"

struct SshNetconfigEventHandleRec
{
  SshNetconfigEventCallback callback;
  void *context;
};

SshNetconfigEventHandle
ssh_netconfig_register_event_callback(SshNetconfigEventCallback callback,
                                      void *context)
{
  SshNetconfigEventHandle handle;

  if (!(handle = ssh_calloc(1, sizeof *handle)))
    {
      SSH_DEBUG(
        SSH_D_FAIL, ("Out of memory allocating netconfig event handle"));
      return NULL;
    }

  handle->callback = callback;
  handle->context = context;
  return handle;
}

SshNetconfigError
ssh_netconfig_unregister_event_callback(SshNetconfigEventHandle handle)
{
  if (!handle)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  ssh_free(handle);
  return SSH_NETCONFIG_ERROR_OK;
}

#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */
