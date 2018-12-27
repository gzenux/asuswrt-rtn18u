/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cisco Simple Certificate Enrollment Protocol (SCEP)
   exported (and private) symbols and definitions.
*/

#include "sshincludes.h"

/* Function prototypes for client side. */
SshPkiStatus ssh_pki_scep_session_start(SshPkiSession session);
SshPkiStatus ssh_pki_scep_session_confirm(SshPkiSession session);
Boolean ssh_pki_scep_session_linearize(SshPkiSession session);
Boolean ssh_pki_scep_session_delinarize(SshPkiSession session);
void ssh_pki_scep_session_finish(SshPkiSession session);

/* eof */
