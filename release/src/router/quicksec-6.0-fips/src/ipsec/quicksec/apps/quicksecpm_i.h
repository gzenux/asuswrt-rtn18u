/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An interface to the generic policy manager code.  This API is used
   from the platform dependent program entry points to perform any
   platform specific initialization and to call the generic policy
   manager functionality.
*/

#ifndef SSHIPSECPM_H
#define SSHIPSECPM_H

#include "ipsec_params.h"
#include "quicksec_pm.h"

typedef struct SshIpmConsoleRec *SshIpmConsole;

/************************* Controlling policy manager ************************/

/** These functions are called from the platform dependent code to
   control the policy manager. */

/** Init the generic policy manager code and SSH libraries.  This must
   be called before the ssh_ipm_start() function is called. */
void ssh_ipm_init(void);

/** Start the policy manager.  The arguments `argc' and `argv' and the
   command line arguments for the program. */
int ssh_ipm_start(int argc, char *argv[]);

/** Stop the policy manager. */
void ssh_ipm_stop(void);

/** Reload the policy file. */
void ssh_ipm_reconfigure(void);

/** Re-evaluate all active flows against the currently configured
   policy. */
void ssh_ipm_redo_flows(void);


































/********************* Callbacks from the policy manager *********************/

/** These functions must be implemented by the platform dependent code.
   These are called from the generic policy manager code. */

/** Make the process a service (e.g. on Unix detach from the
   controlling terminal).  The generic policy manager code calls this
   function if the service mode was requested by a command line
   argument.  The function must return TRUE on success and FALSE
   othewise. */
Boolean ssh_ipm_make_service(void);

/** The possible policy manager states. */
typedef enum
{
  /** The policy manager is starting but is not fully operational
     yet. */
  SSH_IPM_STARTING,

  /** The policy manager is running and fully operational. */
  SSH_IPM_RUNNING,

  /** The policy manager is stopping. */
  SSH_IPM_STOPPING,

  /** The policy manager has been stopped. */
  SSH_IPM_STOPPED
} SshIpmState;

/** Report the state of the policy manager.  The generic policy manager
   code calls this function to report the current state of the policy
   manager. */
void ssh_ipm_report_state(SshIpmState state);

/** Log callback function and context currently registered, or NULL. */
extern SshLogCallback ssh_ipm_registered_log_callback;
extern void *ssh_ipm_registered_log_context;

/** Debug callback functions and context currently registered, or NULL. */
extern SshErrorCallback ssh_ipm_registered_fatal_callback;
extern SshErrorCallback ssh_ipm_registered_warning_callback;
extern SshErrorCallback ssh_ipm_registered_debug_callback;
extern void *ssh_ipm_registered_debug_context;

#endif /* not SSHIPSECPM_H */
