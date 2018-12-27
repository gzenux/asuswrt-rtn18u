/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Printing to Sshbuffer.

   <keywords printing, Sshbuffer, utility functions/printing>

   @internal
*/

#ifndef SSH_BPRINTF_INCLUDED
#define SSH_BPRINTF_INCLUDED

#include "sshbuffer.h"

/** Same as ssh_snprintf or ssh_dsprintf, but prints to SshBuffer. */
int ssh_bprintf(SshBuffer buf, const char *format, ...);

/** Same as ssh_snprintf or ssh_dsprintf, but prints to SshBuffer. */
int ssh_vbprintf(SshBuffer buf, const char *format, va_list ap);

/** Same as ssh_snprintf or ssh_dsprintf, but prints to SshBuffer. */
int ssh_xbprintf(SshBuffer buf, const char *format, ...);

/** Same as ssh_snprintf or ssh_dsprintf, but prints to SshBuffer. */
int ssh_xvbprintf(SshBuffer buf, const char *format, va_list ap);

#endif /* SSH_BPRINTF_INCLUDED */
