/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#define SSH_DEBUG_MODULE "SshPmConnection"

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)

/* Windows Mobile Pocket PC and Smartphone implementation. */

#include "ssheloop.h"
#include <connmgr.h>
#include <connmgr_status.h>
#pragma comment(lib, "cellcore")

typedef struct SshPmConnRequestCtxRec {
  SshIpAddrStruct dst;
  void (*callback)(SshConnection conn_handle, void *context);
  void *callback_context;
  HANDLE conn_handle;
  SshOperationHandleStruct op;
  Boolean new_conn;
  SshTimeoutStruct timeout;
} SshPmConnRequestCtxStruct, *SshPmConnRequestCtx;

static HANDLE
ssh_pm_connection_replace(HANDLE old_handle)
{
  CONNMGR_CONNECTION_DETAILED_STATUS *cdsbuf = NULL, *cds;
  CONNMGR_CONNECTIONINFO ci = { 0 };
  HANDLE new_handle = old_handle, tmp_handle = NULL;
  HRESULT result;
  DWORD size, status;

  /* Get list of all connections. */
  size = 0;
  while ((result = ConnMgrQueryDetailedStatus(cdsbuf, &size)) ==
         HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
    {
      if (cdsbuf)
        ssh_free(cdsbuf);

      cdsbuf = ssh_calloc(1, size);
      if (cdsbuf == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate connection info"));
          goto end;
        }
      memset(cdsbuf, 0, size);
    }
  if (result != S_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get connection info"));
      goto end;
    }

  /* Search for the first connected dial-up connection. */
  for (cds = cdsbuf; cds; cds = cds->pNext)
    {
      /* Search for a connection that is up, has no source network
         (i.e. originates from the device) and has a description. */
      if (cds->dwConnectionStatus == CONNMGR_STATUS_CONNECTED &&
          !(cds->dwParams & CONNMGRDETAILEDSTATUS_PARAM_SOURCENET) &&
          (cds->dwParams & CONNMGRDETAILEDSTATUS_PARAM_DESCRIPTION) &&
          cds->szDescription && cds->szDescription[0] != _T('\0'))
        break;
    }

  /* If no suitable dial-up connection found, use the existing handle. */
  if (!cds)
    goto end;

  /* Map connection description into a GUID. */
  if ((result = ConnMgrMapConRef(ConRefType_NAP, cds->szDescription,
                                 &ci.guidDestNet)) != S_OK)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No description-to-GUID mapping, keeping old connection"));
      goto end;
    }

  /* Setup rest of connection params. */
  ci.cbSize = sizeof ci;
  ci.dwParams = CONNMGR_PARAM_GUIDDESTNET;
  ci.dwFlags = 0;
  ci.dwPriority = CONNMGR_PRIORITY_USERINTERACTIVE;

  /* Start connection setup. */
  result = ConnMgrEstablishConnectionSync(&ci, &tmp_handle, 1000, &status);
  if (result != S_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot request connection"));
      goto end;
    }

  if (status != CONNMGR_STATUS_CONNECTED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot request connection"));
      goto end;
    }

  /* Switch to the new connection. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Switching to connection through a specific interface"));
  ConnMgrReleaseConnection(new_handle, 0);
  new_handle = tmp_handle;
  tmp_handle = NULL;

 end:
  if (tmp_handle)
    ConnMgrReleaseConnection(tmp_handle, 0);
  if (cdsbuf)
    ssh_free(cdsbuf);
  return new_handle;
}

static void
ssh_pm_connection_request_timeout(void *context)
{
  SshPmConnRequestCtx ctx = context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("End delay of connection %p towards %@",
                               ctx->conn_handle,
                               ssh_ipaddr_render, &ctx->dst));

  ssh_operation_unregister(&ctx->op);
  (*ctx->callback)(ctx->conn_handle, ctx->callback_context);
  ssh_free(ctx);
}

static void
ssh_pm_connection_request_callback(void *context)
{
  SshPmConnRequestCtx ctx = context;
  HRESULT result;
  DWORD status;

  /* Get connections status. */
  if ((result = ConnMgrConnectionStatus(ctx->conn_handle, &status)) != S_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get status of connection %p towards %@",
                             ctx->conn_handle, ssh_ipaddr_render, &ctx->dst));
      goto fail;
    }

  /* If the connection did not already exist, the first event is
     status change into `waiting connection'. In this case do nothing
     and wait for additional events. */
  if (status == CONNMGR_STATUS_WAITINGCONNECTION)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Establishing connection %p towards %@",
                                   ctx->conn_handle,
                                   ssh_ipaddr_render, &ctx->dst));
      ctx->new_conn = 1;
      return;
    }

  /* Fail any other state than `connected'. */
  if (status != CONNMGR_STATUS_CONNECTED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Connection towards %@ failed",
                             ssh_ipaddr_render, &ctx->dst));
      goto fail;
    }

  /* Connected. Accept no more events. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Connection %p towards %@ available",
                               ctx->conn_handle,
                               ssh_ipaddr_render, &ctx->dst));
  ssh_event_loop_unregister_handle(ctx->conn_handle);

  /* Possibly replace the connection with a new one that is requested
     using a specific dial-up connection name. This is to prevent
     subsequent connection requests (that possibly resolve to the
     virtual IP interface) from disconnecting the non-specific
     connection. */
  ctx->conn_handle = ssh_pm_connection_replace(ctx->conn_handle);

  /* If this was a new connection, schedule callback to be called
     after one second to give the new local interface some time to be
     set up. In the case of an existing connection clean up call the
     callback now. */
  if (ctx->new_conn)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Begin delay of connection %p towards %@",
                                   ctx->conn_handle,
                                   ssh_ipaddr_render, &ctx->dst));
      ssh_register_timeout(&ctx->timeout, 1, 0,
                           ssh_pm_connection_request_timeout, ctx);
    }
  else
    {
      ssh_operation_unregister(&ctx->op);
      (*ctx->callback)(ctx->conn_handle, ctx->callback_context);
      ssh_free(ctx);
    }
  return;

 fail:
  /* Remove everything allocated or registered and call callback with
     NULL connection handle. */
  ssh_event_loop_unregister_handle(ctx->conn_handle);
  ConnMgrReleaseConnection(ctx->conn_handle, 0);
  ssh_operation_unregister(&ctx->op);
  (*ctx->callback)(NULL, ctx->callback_context);
  ssh_free(ctx);
}

static void
ssh_pm_connection_request_abort(void *context)
{
  SshPmConnRequestCtx ctx = context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Aborting connection %p towards %@",
                               ctx->conn_handle,
                               ssh_ipaddr_render, &ctx->dst));

  ssh_cancel_timeout(&ctx->timeout);
  ssh_event_loop_unregister_handle(ctx->conn_handle);
  ConnMgrReleaseConnection(ctx->conn_handle, 0);
  ssh_free(ctx);
}

SshOperationHandle
ssh_pm_connection_request(SshIpAddr dst,
                          void (*callback)(SshConnection conn_handle,
                                           void *context),
                          void *context)
{
  char addr[SSH_IP_ADDR_STRING_SIZE];
  TCHAR url[64];
  CONNMGR_CONNECTIONINFO ci = { 0 };
  SshPmConnRequestCtx ctx = NULL;
  HRESULT result;

  /* Express destination address as a unicode HTTP URL. */
  ssh_ipaddr_print(dst, addr, sizeof addr);
  _sntprintf(url, sizeof url / sizeof url[0], _T("http://%hs"), addr);
  url[sizeof url / sizeof url[0] - 1] = '\0';

  /* Map URL into a network GUID. */
  if ((result = ConnMgrMapURL(url, &ci.guidDestNet, NULL)) != S_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot map %@ into a network GUID",
                             ssh_ipaddr_render, &ctx->dst));
      goto fail;
    }

  /* Setup rest of connection params. */
  ci.cbSize = sizeof ci;
  ci.dwParams = CONNMGR_PARAM_GUIDDESTNET;
  ci.dwFlags = 0;
  ci.dwPriority = CONNMGR_PRIORITY_USERINTERACTIVE;

  /* Allocate request operation context. */
  ctx = ssh_calloc(1, sizeof *ctx);
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate connection request context"));
      goto fail;
    }

  memcpy(&ctx->dst, dst, sizeof ctx->dst);
  ctx->callback = callback;
  ctx->callback_context = context;

  /* Start connection setup. The returned handle can be used to wait
     for connection status events. */
  if ((result = ConnMgrEstablishConnection(&ci, &ctx->conn_handle)) != S_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot request connection towards %@",
                             ssh_ipaddr_render, &ctx->dst));
      ssh_free(ctx);
      goto fail;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Requesting connection %p towards %@",
                               ctx->conn_handle,
                               ssh_ipaddr_render, &ctx->dst));

  /* Register abort handler. */
  ssh_operation_register_no_alloc(&ctx->op,
                                  ssh_pm_connection_request_abort,
                                  ctx);

  /* Register handle with event loop. */
  ssh_event_loop_register_handle(ctx->conn_handle,
                                 FALSE,
                                 ssh_pm_connection_request_callback,
                                 ctx);

  return &ctx->op;

 fail:
  (*callback)(NULL, context);
  return NULL;
}

void
ssh_pm_connection_release(SshConnection conn_handle)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Releasing connection %p", conn_handle));
  ConnMgrReleaseConnection(conn_handle, 0);
}

#else /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */

/* Placeholder implementation for other platforms. */

SshOperationHandle
ssh_pm_connection_request(SshIpAddr dst,
                          void (*callback)(SshConnection conn_handle,
                                           void *context),
                          void *context)
{
  (*callback)((SshConnection)0x600dbeef, context);
  return NULL;
}

void
ssh_pm_connection_release(SshConnection conn_handle)
{
  return;
}

#endif /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
