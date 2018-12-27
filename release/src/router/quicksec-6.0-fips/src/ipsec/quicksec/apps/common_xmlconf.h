/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML configuration for QuickSec policy manager.
*/

#ifndef SSHIPSECPM_XMLCONF_H
#define SSHIPSECPM_XMLCONF_H

#include "ipsec_params.h"

#include "quicksec_pm.h"
/** Context data for policy manager. */
typedef struct SshIpmContextRec *SshIpmContext;
typedef struct SshIpmParamsRec *SshIpmParams;
/******************* Public functions for XML configuration ******************/

typedef enum {
  /* Get the PM from IPM */
  SSH_IPM_CONTEXT_GET_PM = 0,
  /* PM commit */
  SSH_IPM_CONTEXT_PM_COMMIT = 1
} SshIpmContextEvent;

/* A completion callback for xxx_pm_commit(). */
typedef void
(*SshIpmPmCommitCB)(SshPm pm, Boolean success, void *context);

/* Callback performs action based on the 'SshIpmContextEvent e'. */
typedef void *
(*SshIpmCtxEventCB)(void *ctx, SshIpmContextEvent e,
                     SshIpmPmCommitCB commit_cb,
                     void *commit_cb_ctx);

/** Create a policy manager context for the policy manager object `pm'.
   The function returns a context or NULL if the system run out of
   memory.  The object, pointed by `params' must remain valid as long
   as the returned PM context is valid. */
SshIpmContext
ssh_ipm_context_create(void *pm, SshIpmParams params,
                       SshIpmCtxEventCB cb, void *ctx);

/** Clear all policy manager objects from the context `ctx'.  The
   function is called when the policy manager is shutting down to
   remove all external references to the policy manager object.  The
   function returns TRUE if the context was shut down and FALSE
   otherwise.  If the function returns FALSE, the caller should call
   this function again after a short timeout.  After this call, the
   policy manager is destroyed. */
Boolean ssh_ipm_context_shutdown(SshIpmContext ctx);

/** Destroy the policy manager context `ctx'. */
void ssh_ipm_context_destroy(SshIpmContext ctx);

/** Configure (or reconfigure) the policy manager `ctx' from the
   current XML configuration stream.  The function either configures
   the policy manager or remains in the current configuration if the
   reconfiguration of the policy manager failed.  The function calls
   the status callback `status_cb' to notify the success of the
   operation. */
SshOperationHandle
ssh_ipm_configure(SshIpmContext ctx, SshPmStatusCB status_cb,
                  void *status_cb_context);

/** Get the <engine-flows refresh timeout from the policy manager 'ctx'.
   The function returns the refresh timeout (in seconds) or 0 if no
   automatic policy refreshing has been configured. */
SshUInt32 ssh_ipm_get_refresh_flows_timeout(SshIpmContext ctx);

/** Get the refresh timeout value from the policy manager `ctx'.  The
   function returns the refresh timeout (in seconds) or 0 if no
   automatic policy refreshing has been configured. */
SshUInt32 ssh_ipm_get_refresh_timeout(SshIpmContext ctx);
#endif /* not SSHIPSECPM_XMLCONF_H */
